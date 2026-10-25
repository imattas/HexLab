#include "hexlab/debugger/rsp.hpp"
#include "hexlab/debugger/debugger.hpp"
#include "support/checks.hpp"

#include <algorithm>
#include <array>
#include <deque>
#include <string>
#include <thread>
#include <vector>

#ifdef _WIN32
#  define NOMINMAX
#  define WIN32_LEAN_AND_MEAN
#  include <winsock2.h>
#  include <ws2tcpip.h>
using TestSocket = SOCKET;
static constexpr TestSocket invalid_test_socket = INVALID_SOCKET;
static void close_test_socket(TestSocket socket) { closesocket(socket); }
#else
#  include <arpa/inet.h>
#  include <netinet/in.h>
#  include <sys/socket.h>
#  include <unistd.h>
using TestSocket = int;
static constexpr TestSocket invalid_test_socket = -1;
static void close_test_socket(TestSocket socket) { ::close(socket); }
#endif

using namespace hexlab;
using namespace hexlab::debugger::rsp;

namespace {
class FakeTransport final : public ByteTransport {
public:
    Result<std::size_t> read_some(std::span<std::byte> output, Deadline, std::stop_token) override {
        if (input.empty()) return Error{ErrorCode::io, "fake input exhausted"};
        const auto count = std::min(output.size(), std::min(chunk, input.size()));
        for (std::size_t i = 0; i < count; ++i) { output[i] = input.front(); input.pop_front(); }
        return count;
    }
    Result<std::size_t> write_some(std::span<const std::byte> bytes, Deadline, std::stop_token) override {
        const auto count = std::min(bytes.size(), chunk);
        writes.append(reinterpret_cast<const char*>(bytes.data()), count);
        if (on_write) on_write(writes, *this);
        return count;
    }
    void queue(std::string_view bytes) { for (unsigned char c : bytes) input.push_back(static_cast<std::byte>(c)); }
    void reply(std::string_view payload, bool ack = true) {
        unsigned sum = 0;
        std::string frame = "$";
        for (unsigned char c : payload) {
            if (c == '$' || c == '#' || c == '}' || c == '*') { frame += '}'; sum = (sum + '}') & 0xff; c ^= 0x20; }
            frame += static_cast<char>(c); sum = (sum + c) & 0xff;
        }
        constexpr char digits[] = "0123456789abcdef";
        frame += '#'; frame += digits[sum >> 4]; frame += digits[sum & 15];
        queue((ack ? "+" : "") + frame);
    }
    std::deque<std::byte> input;
    std::string writes;
    std::size_t chunk = 3;
    void (*on_write)(const std::string&, FakeTransport&) = nullptr;
};

void queue_feature_document(FakeTransport& wire, std::string_view xml) {
    for (std::size_t offset = 0; offset < xml.size(); offset += 4096) {
        const auto part = xml.substr(offset, 4096);
        wire.reply(std::string(offset + part.size() == xml.size() ? "l" : "m") + std::string(part));
    }
}

std::string raw_rsp_packet(std::string_view payload) {
    unsigned checksum = 0;
    for (const unsigned char byte : payload) checksum = (checksum + byte) & 0xff;
    constexpr char digits[] = "0123456789abcdef";
    std::string packet = "$" + std::string(payload) + "#";
    packet += digits[checksum >> 4];
    packet += digits[checksum & 15];
    return packet;
}

std::string raw_rsp_notification(std::string_view payload) {
    auto packet = raw_rsp_packet(payload);
    packet.front() = '%';
    return packet;
}

void run_split_target_description_tests() {
    {
        auto fake = std::make_unique<FakeTransport>(); auto* wire = fake.get();
        fake->reply("PacketSize=1000;qXfer:features:read+;vContSupported+");
        queue_feature_document(*fake, "<?xml version=\"1.0\"?><!DOCTYPE target SYSTEM \"gdb-target.dtd\">"
            "<target endian=\"big\" xmlns:xi=\"http://www.w3.org/2001/XInclude\">"
            "<architecture>i386:x86-64</architecture><!-- <xi:include href=\"ignored.xml\"/> -->"
            "<xi:include href=\"core.xml\"/><xi:include href=\"extra.xml\"/></target>");
        queue_feature_document(*fake, "<?xml version=\"1.0\"?><!DOCTYPE feature SYSTEM 'gdb-target.dtd'>"
            "<feature name=\"core\"><reg name=\"rax\" bitsize=\"64\"/>"
            "<xi:include href='flags.xml'/></feature>");
        queue_feature_document(*fake, "<reg name=\"eflags\" bitsize=\"32\"/>");
        queue_feature_document(*fake, "<feature name=\"extra\"><reg name=\"rip\" bitsize=\"64\" regnum=\"2\"/></feature>");
        fake->reply("T05thread:p2.3;");
        hexlab::debugger::DebugSession session(hexlab::debugger::make_remote_backend(std::move(fake)));
        auto connected = session.connect_remote("split-target", 1234);
        hexlab_test::check(connected && connected.value().architecture == Architecture::x86_64,
            "split target descriptions connect through nested feature annexes and standard document declarations");
        if (connected) {
            auto stop = session.wait_event(std::chrono::milliseconds(0));
            wire->reply("OK"); wire->reply("0102030405060708112233448877665544332211");
            auto registers = stop ? session.read_registers(stop.value().thread) :
                Result<std::vector<hexlab::debugger::RegisterValue>>(Error{ErrorCode::io, "missing stop"});
            hexlab_test::check(registers && registers.value().size() == 3 &&
                registers.value()[0].name == "rax" && registers.value()[0].group == "core" &&
                registers.value()[1].name == "eflags" && registers.value()[1].number == 1 &&
                registers.value()[1].group == "core" && registers.value()[1].bytes[3] == std::byte{0x44} &&
                registers.value()[2].name == "rip" && registers.value()[2].number == 2 &&
                registers.value()[2].group == "extra" && registers.value()[2].byte_order == ByteOrder::big,
                "included registers retain document order, inherited feature groups, widths, and root byte order");
            if (registers) {
                const std::array<hexlab::debugger::RegisterValue, 1> edit{registers.value()[2]};
                wire->reply("OK"); wire->reply("0000000000000000"); wire->reply("OK");
                auto written = session.write_registers(stop.value().thread, edit);
                hexlab_test::check(written && wire->writes.find(encode_packet("P2=8877665544332211")) != std::string::npos &&
                    wire->writes.find(encode_packet("Hgp2.3")) != std::string::npos,
                    "split-description registers support safe editing on the stopped multiprocess thread");
            }
            wire->queue("+");
            auto stepped = session.single_step_execution(stop.value().sequence);
            wire->reply("T05thread:p2.3;");
            auto next = session.wait_event(std::chrono::milliseconds(0));
            const bool selected_step = wire->writes.find(encode_packet("vCont;s:p2.3")) != std::string::npos;
            const bool fetched_annex = wire->writes.find("ignored.xml") == std::string::npos &&
                wire->writes.find("qXfer:features:read:flags.xml:0,1000") != std::string::npos;
            wire->reply("OK");
            auto detached = session.detach();
            hexlab_test::check(stepped && next && detached && selected_step,
                "a session with included register metadata steps and detaches normally");
            hexlab_test::check(fetched_annex,
                "feature inclusion ignores comments and requests included names as remote annexes");
        }
    }
    const auto rejected = [](const std::vector<std::string>& documents, ErrorCode expected, const char* name) {
        auto fake = std::make_unique<FakeTransport>();
        fake->reply("PacketSize=1000;qXfer:features:read+");
        for (const auto& document : documents) {
            if (document.empty()) fake->reply("");
            else queue_feature_document(*fake, document);
        }
        hexlab::debugger::DebugSession session(hexlab::debugger::make_remote_backend(std::move(fake)));
        auto connected = session.connect_remote("invalid-split-target", 1234);
        hexlab_test::check(!connected && connected.error().code == expected &&
            session.state() == hexlab::debugger::SessionState::idle && !session.process(), name);
    };
    rejected({"<target><xi:include href='target.xml'/></target>"}, ErrorCode::malformed,
        "feature include cycles fail without publishing a partial remote session");
    rejected({"<target><xi:include href='missing.xml'/></target>", ""}, ErrorCode::unsupported,
        "an unavailable included annex fails explicitly instead of exposing incomplete registers");
    rejected({"<target><xi:include/></target>"}, ErrorCode::malformed,
        "feature includes require an annex name");
    rejected({"<target><xi:include href='bad:name'/></target>"}, ErrorCode::invalid_argument,
        "feature include names cannot inject RSP command delimiters");
    rejected({"<target><xi:include href='core.xml'/><xi:include href='core.xml'/></target>",
        "<feature name='core'><reg name='r0' bitsize='32' regnum='0'/></feature>",
        "<feature name='core'><reg name='r0' bitsize='32' regnum='0'/></feature>"}, ErrorCode::malformed,
        "register-number collisions across included features are rejected");
    std::vector<std::string> deep;
    for (unsigned i = 0; i < 17; ++i)
        deep.push_back("<target><xi:include href='depth" + std::to_string(i) + ".xml'/></target>");
    rejected(deep, ErrorCode::resource_limit, "feature include nesting has a finite depth limit");
    std::string wide = "<target>";
    std::vector<std::string> many;
    for (unsigned i = 0; i < 65; ++i) {
        wide += "<xi:include href='part" + std::to_string(i) + ".xml'/>";
        many.push_back("<feature name='empty'/>");
    }
    wide += "</target>"; many.insert(many.begin(), std::move(wide));
    rejected(many, ErrorCode::resource_limit, "feature inclusion limits the total number of annex requests");
    const std::string padding(600000, 'x');
    rejected({"<target><!--" + padding + "--><xi:include href='large.xml'/></target>",
        "<feature name='large'><!--" + padding + "--><reg name='r0' bitsize='32'/></feature>"},
        ErrorCode::resource_limit, "feature metadata has an aggregate size budget across all annexes");
}

void run_tests() {
    run_split_target_description_tests();
    {
        auto fake = std::make_unique<FakeTransport>(); auto* wire = fake.get();
        fake->reply("PacketSize=1000;vContSupported+");
        fake->reply("T05thread:1;pc:401000;");
        hexlab::debugger::DebugSession session(hexlab::debugger::make_remote_backend(std::move(fake)));
        const auto connected = session.connect_remote("trap-stop", 1234);
        const auto initial = session.wait_event(std::chrono::milliseconds(0));
        wire->queue("+");
        const auto resumed = initial ? session.continue_execution(initial.value().sequence,
            hexlab::debugger::ContinueStatus::handled) :
            hexlab::debugger::Status{hexlab::Error{hexlab::ErrorCode::invalid_argument, "missing stop"}};
        wire->reply("T05thread:1;swbreak:;");
        const auto breakpoint = session.wait_event(std::chrono::milliseconds(0));
        hexlab_test::check(connected && initial && initial.value().kind == hexlab::debugger::EventKind::exception &&
            resumed && breakpoint && breakpoint.value().kind == hexlab::debugger::EventKind::breakpoint,
            "RSP SIGTRAP is not mislabeled as single-step, while swbreak stop reasons identify breakpoints");
    }
    {
        auto fake = std::make_unique<FakeTransport>(); auto* wire = fake.get();
        fake->reply("PacketSize=1000;vContSupported+");
        fake->reply("T05thread:1;");
        hexlab::debugger::DebugSession session(hexlab::debugger::make_remote_backend(std::move(fake)));
        const auto connected = session.connect_remote("step-stop", 1234);
        const auto initial = session.wait_event(std::chrono::milliseconds(0));
        wire->queue("+");
        const auto stepped = initial ? session.single_step_execution(initial.value().sequence) :
            hexlab::debugger::Status{hexlab::Error{hexlab::ErrorCode::invalid_argument, "missing stop"}};
        wire->reply("T05thread:1;pc:401001;");
        const auto result = session.wait_event(std::chrono::milliseconds(0));
        hexlab_test::check(connected && initial && stepped && result &&
            result.value().kind == hexlab::debugger::EventKind::single_step && result.value().address == 0x401001,
            "RSP SIGTRAP is classified as single-step only after a requested step");
    }
    {
        auto fake = std::make_unique<FakeTransport>(); auto* wire = fake.get();
        fake->reply("PacketSize=1000;vContSupported+");
        fake->reply("T02thread:1;");
        hexlab::debugger::DebugSession session(hexlab::debugger::make_remote_backend(std::move(fake)));
        const auto connected = session.connect_remote("watch-stop", 1234);
        const auto initial = session.wait_event(std::chrono::milliseconds(0));
        wire->queue("+");
        const auto resumed = initial ? session.continue_execution(initial.value().sequence,
            hexlab::debugger::ContinueStatus::handled) :
            hexlab::debugger::Status{hexlab::Error{hexlab::ErrorCode::invalid_argument, "missing stop"}};
        wire->reply("T05thread:1;watch:deadbeef;");
        const auto watchpoint = session.wait_event(std::chrono::milliseconds(0));
        hexlab_test::check(connected && initial && resumed && watchpoint &&
            watchpoint.value().kind == hexlab::debugger::EventKind::breakpoint &&
            watchpoint.value().address == 0xdeadbeef &&
            watchpoint.value().message.find("watchpoint") != std::string::npos,
            "RSP watchpoint replies become breakpoint events with their address and reason");
    }
    hexlab_test::check(encode_packet("m$#}*") == "$m}\x04}\x03}\x5d}\x0a#cf",
        "packet encoding escapes reserved characters and checksums escaped bytes");
    {
        const auto packet = encode_packet("m$#}*");
        auto decoded = decode_packet(packet);
        hexlab_test::check(decoded && decoded.value() == "m$#}*", "escaped payload decodes including escaped hash delimiter");
        auto corrupt = packet; corrupt.back() = corrupt.back() == '0' ? '1' : '0';
        auto invalid = decode_packet(corrupt);
        hexlab_test::check(!invalid && invalid.error().code == ErrorCode::integrity, "packet checksum corruption is rejected");
    }
    {
        const auto compressed = decode_packet(raw_rsp_packet("0* "));
        const auto literal_star = decode_packet(encode_packet("a*b"));
        const auto short_count = decode_packet(raw_rsp_packet("0*\x1f"));
        const auto missing_source = decode_packet(raw_rsp_packet("* "));
        const auto bounded = decode_packet(raw_rsp_packet("0* "), 3);
        hexlab_test::check(compressed && compressed.value() == "0000",
            "RSP reply run-length encoding expands the encoded number of additional copies");
        hexlab_test::check(literal_star && literal_star.value() == "a*b",
            "escaped RSP asterisk remains literal instead of starting run-length encoding");
        hexlab_test::check(!short_count && short_count.error().code == ErrorCode::malformed &&
            !missing_source && missing_source.error().code == ErrorCode::malformed,
            "RSP run-length decoding rejects invalid counts and missing source bytes");
        hexlab_test::check(!bounded && bounded.error().code == ErrorCode::resource_limit,
            "RSP run-length expansion respects the decoded payload limit");
    }
    {
        FakeTransport fake;
        fake.reply("T05thread:2;threads:1,2;watch:0x41;");
        Client client(fake);
        auto stop = client.read_stop_reply();
        hexlab_test::check(stop && stop.value().signal == 5 && stop.value().thread == 2 &&
            stop.value().fields.at("watch") == "0x41", "stop reply fields decode");
    }
    {
        FakeTransport fake;
        fake.queue("+");
        fake.reply("T05thread:2;");
        Client client(fake);
        auto resumed = client.send_resume("vCont;c");
        auto stopped = client.wait_stop_reply(std::chrono::seconds(1));
        hexlab_test::check(resumed && stopped && stopped.value().signal == 5 && stopped.value().thread == 2 &&
            fake.writes.find(encode_packet("vCont;c")) != std::string::npos,
            "resume acknowledges the command without blocking and later consumes an asynchronous stop reply");
    }
    {
        FakeTransport fake;
        fake.queue("+");
        fake.queue(raw_rsp_notification("Stop:T05thread:p2.3;swbreak:;"));
        Client client(fake);
        const auto resumed = client.send_resume("vCont;c");
        const auto stopped = client.wait_stop_reply(std::chrono::seconds(1));
        hexlab_test::check(resumed && stopped && stopped.value().thread == 3 &&
            stopped.value().fields.at("thread") == "p2.3" && stopped.value().fields.contains("swbreak") &&
            fake.writes == encode_packet("vCont;c"),
            "non-stop %Stop notifications decode as stop replies without sending packet acknowledgements");
    }
    {
        FakeTransport fake;
        fake.queue("+");
        fake.queue(raw_rsp_notification("Stop:T02thread:4;"));
        fake.reply("OK");
        Client client(fake);
        const auto response = client.request("qExample");
        const auto stopped = client.wait_stop_reply(std::chrono::seconds(1));
        hexlab_test::check(response && response.value() == "OK" && stopped &&
            stopped.value().signal == 2 && stopped.value().thread == 4 &&
            fake.writes.find(encode_packet("qExample")) == 0,
            "RSP command transactions preserve asynchronous stop notifications received before their response");
    }
    {
        FakeTransport fake;
        fake.queue("+");
        for (int i=0;i<3;++i)fake.queue(raw_rsp_notification("Stop:T05thread:1;"));
        fake.reply("OK");
        Client client(fake,std::chrono::seconds(3),32);
        const auto response=client.request("qExample");
        hexlab_test::check(!response && response.error().code==ErrorCode::resource_limit,
            "queued asynchronous stop payload bytes remain within the configured packet budget");
    }
    {
        FakeTransport fake;
        fake.queue("+");
        for (std::size_t i=0;i<4097;++i)fake.queue(raw_rsp_notification("Stop:"));
        Client client(fake);
        const auto response=client.request("qExample");
        hexlab_test::check(!response && response.error().code==ErrorCode::resource_limit,
            "empty asynchronous notifications cannot bypass the bounded queue entry limit");
    }
    {
        auto fake = std::make_unique<FakeTransport>();
        auto* wire = fake.get();
        fake->reply("PacketSize=1000;vContSupported+");
        fake->reply("T05thread:1;");
        hexlab::debugger::DebugSession session(hexlab::debugger::make_remote_backend(std::move(fake)));
        const auto connected = session.connect_remote("notification-test", 1234);
        const auto initial = session.wait_event(std::chrono::milliseconds(0));
        wire->queue("+");
        const auto resumed = initial ? session.continue_execution(initial.value().sequence,
            hexlab::debugger::ContinueStatus::handled) : hexlab::debugger::Status{Error{ErrorCode::invalid_argument, "missing initial stop"}};
        wire->queue(raw_rsp_notification("Stop:T05thread:p2.3;swbreak:;"));
        const auto event = session.wait_event(std::chrono::seconds(1));
        hexlab_test::check(connected && resumed && event && event.value().kind == hexlab::debugger::EventKind::breakpoint &&
            event.value().thread != 0 && event.value().message == "remote software breakpoint",
            "DebugSession turns an unsolicited RSP stop notification into a breakpoint event");
    }
    {
        FakeTransport fake;
        Client client(fake);
        const auto interrupted = client.interrupt();
        hexlab_test::check(static_cast<bool>(interrupted) && fake.writes == std::string(1, '\x03'),
            "RSP interrupt sends the out-of-band Ctrl-C byte");
    }
    {
        FakeTransport fake;
        fake.reply("OK");
        fake.reply("OK");
        Client client(fake);
        const std::byte value{0x5a};
        auto wrote = client.write_memory(0x1000, std::span(&value, 1));
        auto selected = client.select_thread(0x2a);
        hexlab_test::check(wrote && selected && fake.writes.find(encode_packet("M1000,1:5a")) != std::string::npos &&
            fake.writes.find(encode_packet("Hg2a")) != std::string::npos,
            "remote writes are hex encoded and register selection uses the requested RSP thread");
    }
    {
#ifdef _WIN32
        WSADATA winsock{};
        hexlab_test::check(WSAStartup(MAKEWORD(2, 2), &winsock) == 0, "test Winsock startup");
#endif
        const auto listener = ::socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
        hexlab_test::check(listener != invalid_test_socket, "loopback RSP listener socket created");
        sockaddr_in address{}; address.sin_family = AF_INET; address.sin_addr.s_addr = htonl(INADDR_LOOPBACK); address.sin_port = 0;
        hexlab_test::check(::bind(listener, reinterpret_cast<sockaddr*>(&address), sizeof(address)) == 0 &&
            ::listen(listener, 1) == 0, "loopback RSP listener bound");
#ifdef _WIN32
        int address_size = sizeof(address);
#else
        socklen_t address_size = sizeof(address);
#endif
        hexlab_test::check(getsockname(listener, reinterpret_cast<sockaddr*>(&address), &address_size) == 0,
                           "loopback RSP ephemeral port obtained");
        std::thread server([listener] {
            const auto peer = ::accept(listener, nullptr, nullptr);
            if (peer != invalid_test_socket) {
                char request[4]{};
                std::size_t received = 0;
                while (received < sizeof(request)) {
#ifdef _WIN32
                    const int count = recv(peer, request + received, static_cast<int>(sizeof(request) - received), 0);
#else
                    const auto count = recv(peer, request + received, sizeof(request) - received, 0);
#endif
                    if (count <= 0) break;
                    received += static_cast<std::size_t>(count);
                }
                if (received == 4) {
#ifdef _WIN32
                    (void)send(peer, "PONG", 4, 0);
#else
                    (void)send(peer, "PONG", 4, 0);
#endif
                }
                close_test_socket(peer);
            }
        });
        auto transport = connect_tcp("127.0.0.1", ntohs(address.sin_port), std::chrono::seconds(2));
        bool exchanged = false;
        if (transport) {
            const std::string ping = "PING";
            auto sent = transport.value()->write_some(std::as_bytes(std::span(ping)),
                std::chrono::steady_clock::now() + std::chrono::seconds(2), {});
            std::array<std::byte, 4> pong{};
            auto read = transport.value()->read_some(pong,
                std::chrono::steady_clock::now() + std::chrono::seconds(2), {});
            exchanged = sent && sent.value() == 4 && read && read.value() == 4 &&
                std::string(reinterpret_cast<const char*>(pong.data()), pong.size()) == "PONG";
        }
        close_test_socket(listener);
        server.join();
#ifdef _WIN32
        WSACleanup();
#endif
        hexlab_test::check(exchanged, "bounded TCP transport connects and exchanges stream data with the remote endpoint");
    }
    {
        FakeTransport fake;
        fake.reply("414243");
        Client client(fake);
        auto bytes = client.read_memory(0x1000, 3);
        hexlab_test::check(bytes && bytes.value() == std::vector<std::byte>{std::byte{'A'},std::byte{'B'},std::byte{'C'}},
            "memory command decodes response bytes across short transport reads");
        hexlab_test::check(fake.writes.find("$m1000,3#") != std::string::npos, "memory read command sent");
    }
    {
        FakeTransport fake;
        fake.reply("m0g");
        Client client(fake);
        auto bytes = client.read_memory(0, 1);
        hexlab_test::check(!bytes && bytes.error().code == ErrorCode::malformed, "invalid memory hex rejected");
    }
    {
        FakeTransport fake;
        fake.reply("OK");
        Client client(fake);
        auto set = client.set_breakpoint(0x401000, BreakpointType::software, 1, true);
        hexlab_test::check(set && fake.writes.find("$Z0,401000,1#") != std::string::npos,
            "software breakpoint insertion uses Z0 command");
    }
    {
        FakeTransport fake;
        fake.queue("-+");
        fake.reply("OK");
        Client client(fake);
        auto response = client.request("qAttached");
        const auto first = fake.writes.find(encode_packet("qAttached"));
        const auto second = fake.writes.find(encode_packet("qAttached"), first + 1);
        hexlab_test::check(response && response.value() == "OK" && first != std::string::npos && second != std::string::npos,
            "negative acknowledgment retransmits the complete request packet");
    }
    {
        FakeTransport fake;
        fake.reply("PacketSize=1000;QStartNoAckMode+;multiprocess+");
        fake.reply("OK");
        fake.reply("ready", false);
        Client client(fake);
        auto caps = client.negotiate();
        auto response = client.request("qAttached");
        hexlab_test::check(caps && caps.value().no_ack_mode && client.no_ack_mode() &&
            caps.value().features.at("multiprocess") == "+" && response && response.value() == "ready",
            "feature negotiation enables no-ack mode after the acknowledged transition reply");
    }
    {
        FakeTransport fake;
        fake.reply("mabcd"); fake.reply("lef");
        Client client(fake);
        auto xml = client.read_feature_annex("target.xml", 16, 4);
        hexlab_test::check(xml && xml.value() && *xml.value() == "abcdef" &&
            fake.writes.find(encode_packet("qXfer:features:read:target.xml:0,4")) != std::string::npos &&
            fake.writes.find(encode_packet("qXfer:features:read:target.xml:4,4")) != std::string::npos,
            "target feature annex is fetched in bounded offset chunks until the final marker");
    }
    {
        FakeTransport fake; fake.reply("m<lib"); fake.reply("l/one");
        Client client(fake);
        auto xml = client.read_libraries_annex(8, 4);
        hexlab_test::check(xml && xml.value() && *xml.value() == "<lib/one" &&
            fake.writes.find(encode_packet("qXfer:libraries:read::0,4")) != std::string::npos,
            "shared-library XML is fetched in bounded qXfer libraries chunks");
    }
    {
        FakeTransport fake; fake.reply("m<memory-"); fake.reply("lmap>");
        Client client(fake);
        auto xml = client.read_memory_map_annex(256, 8);
        hexlab_test::check(xml && xml.value() && *xml.value() == "<memory-map>" &&
            fake.writes.find(encode_packet("qXfer:memory-map:read::0,8")) != std::string::npos,
            "remote memory-map annex is fetched using bounded qXfer chunks");
    }
    {
        FakeTransport fake; fake.reply("m<threads"); fake.reply("m><thread"); fake.reply("m id=\"1\""); fake.reply("l/>");
        Client client(fake);
        auto xml = client.read_threads_annex(64, 8);
        hexlab_test::check(xml && xml.value() && *xml.value() == "<threads><thread id=\"1\"/>" &&
            fake.writes.find(encode_packet("qXfer:threads:read::0,8")) != std::string::npos &&
            fake.writes.find(encode_packet("qXfer:threads:read::8,8")) != std::string::npos &&
            fake.writes.find(encode_packet("qXfer:threads:read::10,8")) != std::string::npos &&
            fake.writes.find(encode_packet("qXfer:threads:read::17,8")) != std::string::npos,
            "thread XML annex is fetched in bounded offset chunks");
    }
    {
        FakeTransport fake; fake.reply("m");
        Client client(fake);
        auto xml = client.read_threads_annex(64, 8);
        hexlab_test::check(!xml && xml.error().code == ErrorCode::malformed,
            "thread XML transfer rejects a continuation chunk that makes no progress");
    }
    {
        FakeTransport fake; fake.reply("m");
        Client client(fake);
        auto xml = client.read_memory_map_annex(8, 4);
        hexlab_test::check(!xml && xml.error().code == ErrorCode::malformed,
            "memory-map transfer rejects a truncated chunk that makes no progress");
    }
    {
        FakeTransport fake; fake.reply("m12345");
        Client client(fake);
        auto xml = client.read_memory_map_annex(16, 4);
        hexlab_test::check(!xml && xml.error().code == ErrorCode::resource_limit,
            "memory-map transfer rejects chunks larger than the requested bound");
    }
    {
        FakeTransport fake; fake.reply("");
        Client client(fake);
        auto xml = client.read_memory_map_annex();
        hexlab_test::check(xml && !xml.value(), "empty memory-map transfer is represented as unsupported");
    }
    {
        FakeTransport fake; fake.reply("OK");
        Client client(fake);
        const std::array<std::byte, 2> bytes{std::byte{0x12}, std::byte{0xab}};
        auto written = client.write_register(7, bytes);
        hexlab_test::check(written && fake.writes.find(encode_packet("P7=12ab")) != std::string::npos,
            "single-register writes use the RSP P command and hexadecimal target bytes");
    }
    {
        FakeTransport fake; fake.reply("m12345");
        Client client(fake);
        auto xml = client.read_feature_annex("target.xml", 4, 4);
        hexlab_test::check(!xml && xml.error().code == ErrorCode::resource_limit,
            "target feature annex rejects a chunk that exceeds its configured size limit");
    }
    {
        FakeTransport fake; fake.reply("");
        Client client(fake);
        auto xml = client.read_feature_annex();
        hexlab_test::check(xml && !xml.value(), "empty unsupported target feature response remains distinct from malformed annex data");
    }
    {
        FakeTransport fake; fake.reply("xbroken");
        Client client(fake);
        auto xml = client.read_feature_annex();
        hexlab_test::check(!xml && xml.error().code == ErrorCode::malformed, "malformed target feature marker is rejected");
    }
    {
        FakeTransport fake;
        fake.reply("mp1.1,p1.2");
        fake.reply("l");
        fake.reply("0102");
        fake.reply("aabb");
        Client client(fake);
        auto threads = client.enumerate_threads();
        auto registers = client.read_registers();
        auto reg = client.read_register(10);
        hexlab_test::check(threads && threads.value() == std::vector<std::uint64_t>{1,2},
            "thread pagination accepts multiprocess thread identifiers");
        hexlab_test::check(registers && registers.value().size() == 2 && registers.value()[0] == std::byte{1},
            "bulk register read returns decoded target bytes");
        hexlab_test::check(reg && reg.value().size() == 2 && fake.writes.find("$pa#") != std::string::npos,
            "single register read emits p-register command");
    }
    {
        FakeTransport fake;
        std::stop_source source; source.request_stop();
        Client client(fake);
        auto response = client.request("qAttached", source.get_token());
        hexlab_test::check(!response && response.error().code == ErrorCode::canceled && fake.writes.empty(),
            "pre-canceled request performs no transport writes");
    }
    {
        auto fake = std::make_unique<FakeTransport>();
        auto* wire = fake.get();
        fake->reply("PacketSize=1000;multiprocess+;vContSupported+");
        fake->reply("T05thread:p1.2;");
        hexlab::debugger::DebugSession session(hexlab::debugger::make_remote_backend(std::move(fake)));
        const auto connected = session.connect_remote("multiprocess-inspection", 1234);
        const auto stopped = session.wait_event(std::chrono::milliseconds(1));
        wire->reply("mp1.2,p2.2");
        wire->reply("l");
        const auto threads = session.threads();
        wire->reply("OK"); wire->reply("0102");
        wire->reply("OK"); wire->reply("0304");
        const auto first = threads && !threads.value().empty() ? session.read_registers(threads.value()[0].id)
            : Result<std::vector<hexlab::debugger::RegisterValue>>(Error{ErrorCode::malformed, "thread list missing"});
        const auto second = threads && threads.value().size() > 1 ? session.read_registers(threads.value()[1].id)
            : Result<std::vector<hexlab::debugger::RegisterValue>>(Error{ErrorCode::malformed, "thread list incomplete"});
        hexlab_test::check(connected && stopped && threads && threads.value().size() == 2 &&
                threads.value()[0].id != threads.value()[1].id && threads.value()[0].id == stopped.value().thread &&
                threads.value()[0].name == "thread p1.2" && threads.value()[1].name == "thread p2.2" &&
                threads.value()[0].state == hexlab::debugger::ThreadState::unknown &&
                first && second && first.value()[0].bytes == std::vector<std::byte>{std::byte{1}, std::byte{2}} &&
                second.value()[0].bytes == std::vector<std::byte>{std::byte{3}, std::byte{4}} &&
                wire->writes.find(encode_packet("Hgp1.2")) != std::string::npos &&
                wire->writes.find(encode_packet("Hgp2.2")) != std::string::npos,
                "remote session preserves process-qualified IDs through thread listing, stop events, and register selection");
    }
    {
        auto fake = std::make_unique<FakeTransport>();
        auto* wire = fake.get();
        fake->reply("PacketSize=1000;multiprocess+;qXfer:threads:read+;vContSupported+");
        fake->reply("T05thread:p1.2;");
        hexlab::debugger::DebugSession session(hexlab::debugger::make_remote_backend(std::move(fake)));
        auto connected = session.connect_remote("thread-xml-test", 1234);
        auto stop = session.wait_event(std::chrono::milliseconds(0));
        wire->reply("l<threads><thread id=\"p1.2\" name=\"main &amp; worker\" state=\"stopped\"/>"
                    "<thread id=\"p2.2\" name=\"background &#x77;orker\"><state>running</state></thread></threads>");
        auto threads = session.threads();
        hexlab_test::check(connected && stop && threads && threads.value().size() == 2 &&
                threads.value()[0].id == stop.value().thread && threads.value()[0].name == "main & worker" &&
                threads.value()[0].state == hexlab::debugger::ThreadState::stopped &&
                threads.value()[1].name == "background worker" &&
                threads.value()[1].state == hexlab::debugger::ThreadState::running &&
                wire->writes.find(encode_packet("qXfer:threads:read::0,1000")) != std::string::npos,
                "advertised thread XML preserves process-qualified handles, names and running/stopped state in DebugSession");
    }
    {
        auto fake = std::make_unique<FakeTransport>();
        auto* wire = fake.get();
        fake->reply("PacketSize=1000;qXfer:threads:read+;vContSupported+");
        fake->reply("T05thread:1;");
        hexlab::debugger::DebugSession session(hexlab::debugger::make_remote_backend(std::move(fake)));
        (void)session.connect_remote("duplicate-thread-xml", 1234);
        wire->reply("l<threads><thread id=\"1\"/><thread id=\"1\"/></threads>");
        auto threads = session.threads();
        hexlab_test::check(!threads && threads.error().code == ErrorCode::malformed,
                "thread XML rejects duplicate wire IDs instead of aliasing a session handle");
    }
    {
        auto fake = std::make_unique<FakeTransport>();
        auto* wire = fake.get();
        fake->reply("PacketSize=1000;qXfer:threads:read+;vContSupported+");
        fake->reply("T05thread:1;");
        hexlab::debugger::DebugSession session(hexlab::debugger::make_remote_backend(std::move(fake)));
        (void)session.connect_remote("bad-thread-name-xml", 1234);
        wire->reply("l<threads><thread id=\"1\" name=\"bad &#0; name\"/></threads>");
        auto threads = session.threads();
        hexlab_test::check(!threads && threads.error().code == ErrorCode::malformed,
                "thread XML rejects invalid numeric entities instead of returning corrupted display text");
    }
    {
        FakeTransport fake;
        std::stop_source source; source.request_stop();
        Client client(fake);
        auto xml = client.read_memory_map_annex(64, 16, source.get_token());
        hexlab_test::check(!xml && xml.error().code == ErrorCode::canceled && fake.writes.empty(),
            "pre-canceled memory-map transfer performs no transport writes");
    }
    {
        auto fake = std::make_unique<FakeTransport>();
        auto* wire = fake.get();
        fake->reply("PacketSize=1000;qXfer:memory-map:read+;vContSupported+");
        fake->reply("T05thread:1;");
        hexlab::debugger::DebugSession session(hexlab::debugger::make_remote_backend(std::move(fake)));
        const auto connected = session.connect_remote("memory-map-test", 1234);
        wire->reply("l<memory-map><memory type=\"ram\" start=\"0x1000\" length=\"0x2000\"/>"
                    "<memory type=\"rom\" start=\"0x8000\" length=\"0x1000\"/>"
                    "<memory type=\"ram\" start=\"0xffffffffffffffff\" length=\"1\"/></memory-map>");
        const auto regions = session.memory_regions();
        hexlab_test::check(connected && regions && regions.value().size() == 3 &&
              regions.value()[0].start == 0x1000 && regions.value()[0].length == 0x2000 &&
              regions.value()[0].readable && regions.value()[0].writable &&
              !regions.value()[0].executable && regions.value()[0].type == "ram" &&
              regions.value()[1].start == 0x8000 && regions.value()[1].length == 0x1000 &&
              regions.value()[1].readable && !regions.value()[1].writable &&
              regions.value()[1].type == "rom" &&
              regions.value()[2].start == UINT64_MAX && regions.value()[2].length == 1,
              "remote memory-map XML becomes bounded memory regions with type-derived permissions");
        hexlab_test::check(wire->writes.find(encode_packet("qXfer:memory-map:read::0,1000")) != std::string::npos,
              "remote memory regions are queried only after qSupported advertises the annex");
    }
    {
        auto fake = std::make_unique<FakeTransport>();
        auto* wire = fake.get();
        fake->reply("PacketSize=1000;qXfer:memory-map:read+");
        fake->reply("T05thread:1;");
        hexlab::debugger::DebugSession session(hexlab::debugger::make_remote_backend(std::move(fake)));
        (void)session.connect_remote("overlap-memory-map", 1234);
        wire->reply("l<memory-map><memory type=\"ram\" start=\"0x1000\" length=\"0x1000\"/>"
                    "<memory type=\"rom\" start=\"0x1800\" length=\"0x1000\"/></memory-map>");
        const auto regions = session.memory_regions();
        hexlab_test::check(!regions && regions.error().code == ErrorCode::malformed,
              "remote memory-map parser rejects overlapping regions");
    }
    {
        auto fake = std::make_unique<FakeTransport>();
        auto* wire = fake.get();
        fake->reply("PacketSize=1000;qXfer:memory-map:read+");
        fake->reply("T05thread:1;");
        hexlab::debugger::DebugSession session(hexlab::debugger::make_remote_backend(std::move(fake)));
        (void)session.connect_remote("bad-root-memory-map", 1234);
        wire->reply("l<not-a-memory-map><memory type=\"ram\" start=\"0x1000\" length=\"0x1000\"/></not-a-memory-map>");
        const auto regions = session.memory_regions();
        hexlab_test::check(!regions && regions.error().code == ErrorCode::malformed,
              "remote memory-map parser requires the protocol root element");
    }
    {
        auto fake = std::make_unique<FakeTransport>();
        auto* wire = fake.get();
        fake->reply("PacketSize=1000;qXfer:memory-map:read+");
        fake->reply("T05thread:1;");
        hexlab::debugger::DebugSession session(hexlab::debugger::make_remote_backend(std::move(fake)));
        (void)session.connect_remote("bad-memory-map", 1234);
        wire->reply("l<memory-map><memory type=\"ram\" start=\"0xffffffffffffffff\" length=\"2\"/></memory-map>");
        const auto regions = session.memory_regions();
        hexlab_test::check(!regions && regions.error().code == ErrorCode::malformed,
              "remote memory-map regions reject overflowing address ranges");
    }
    {
        auto fake = std::make_unique<FakeTransport>();
        fake->reply("PacketSize=1000;vContSupported+");
        fake->reply("T05thread:1;");
        hexlab::debugger::DebugSession session(hexlab::debugger::make_remote_backend(std::move(fake)));
        (void)session.connect_remote("no-memory-map", 1234);
        const auto regions = session.memory_regions();
        hexlab_test::check(!regions && regions.error().code == ErrorCode::unsupported,
              "remote memory regions report unsupported when qSupported omits the annex");
    }
    {
        auto fake = std::make_unique<FakeTransport>();
        auto* wire = fake.get();
        fake->reply("PacketSize=1000;swbreak+;vContSupported+");
        fake->reply("T05thread:1;");
        hexlab::debugger::DebugSession session(hexlab::debugger::make_remote_backend(std::move(fake)));
        auto process = session.connect_remote("loopback-test", 1234);
        auto initial = session.wait_event(std::chrono::milliseconds(0));
        hexlab_test::check(process && process.value().name == "loopback-test:1234" && initial &&
            session.state() == hexlab::debugger::SessionState::stopped,
            "remote connect negotiates RSP and exposes the initial target stop through DebugSession");
        wire->reply("m1,p1.2"); wire->reply("l");
        auto threads = session.threads();
        wire->reply("OK"); wire->reply("01020304");
        auto registers = session.read_registers(1);
        wire->reply("4142");
        auto memory = session.read_memory(0x1000, 2);
        std::array<std::byte, 1> patch{std::byte{0xcc}};
        wire->reply("OK");
        auto written = session.write_memory(0x1000, patch);
        wire->reply("OK");
        auto breakpoint = session.add_breakpoint(0x401000);
        hexlab_test::check(threads && threads.value().size() == 2 && registers && registers.value().size() == 1 &&
            registers.value()[0].bytes.size() == 4 && memory && memory.value().size() == 2 && written && breakpoint,
            "remote session exposes bounded threads, raw registers, memory read/write, and software breakpoints");
        wire->reply("OK");
        auto removed = session.remove_breakpoint(breakpoint.value().id);
        wire->queue("+"); wire->reply("T05thread:1;swbreak:;");
        auto continued = session.continue_execution(initial.value().sequence, hexlab::debugger::ContinueStatus::handled);
        auto stopped = session.wait_event(std::chrono::milliseconds(0));
        wire->reply("OK");
        auto detached = session.detach();
        hexlab_test::check(static_cast<bool>(removed), "remote breakpoint removal succeeds");
        hexlab_test::check(static_cast<bool>(continued), "remote continue command succeeds");
        hexlab_test::check(static_cast<bool>(stopped), stopped ? "remote next stop arrives" : stopped.error().message.c_str());
        hexlab_test::check(stopped && stopped.value().kind == hexlab::debugger::EventKind::breakpoint,
            "remote stop reply is classified as a breakpoint");
        hexlab_test::check(static_cast<bool>(detached) && session.state() == hexlab::debugger::SessionState::detached,
            "remote disconnect succeeds and clears target state");
    }
    {
        auto fake = std::make_unique<FakeTransport>(); auto* wire = fake.get();
        fake->reply("PacketSize=1000;vContSupported+");
        fake->reply("T05thread:p1.2;");
        hexlab::debugger::DebugSession session(hexlab::debugger::make_remote_backend(std::move(fake)));
        auto connected = session.connect_remote("thread-step", 1234);
        auto stop = session.wait_event(std::chrono::milliseconds(0));
        wire->queue("+");
        auto stepped = stop ? session.single_step_execution(stop.value().sequence) :
            hexlab::debugger::Status{hexlab::Error{hexlab::ErrorCode::invalid_argument, "no stop"}};
        hexlab_test::check(connected && stop && stepped &&
            wire->writes.find(encode_packet("vCont;s:p1.2")) != std::string::npos,
            "RSP single-step targets only the stopped multiprocess thread and preserves its full thread ID");
    }
    {
        auto fake = std::make_unique<FakeTransport>(); auto* wire = fake.get();
        fake->reply("PacketSize=1000;vContSupported+");
        fake->reply("T05thread:1;");
        hexlab::debugger::DebugSession session(hexlab::debugger::make_remote_backend(std::move(fake)));
        const auto connected = session.connect_remote("interrupt-test", 1234);
        const auto initial = session.wait_event(std::chrono::milliseconds(0));
        wire->queue("+");
        const auto resumed = initial ? session.continue_execution(initial.value().sequence,
            hexlab::debugger::ContinueStatus::handled) : hexlab::debugger::Status{hexlab::Error{hexlab::ErrorCode::invalid_argument, "missing initial stop"}};
        const auto interrupt = session.request_interrupt();
        wire->reply("T02thread:1;");
        const auto stopped = session.wait_event(std::chrono::milliseconds(0));
        hexlab_test::check(connected && initial && resumed && interrupt && stopped &&
            session.state() == hexlab::debugger::SessionState::stopped &&
            wire->writes.find(std::string(1, '\x03')) != std::string::npos,
            "remote session interruption sends Ctrl-C and reports the asynchronous stop through the event API");
    }
    {
        auto fake = std::make_unique<FakeTransport>(); auto* wire = fake.get();
        fake->reply("PacketSize=1000;vContSupported+");
        fake->reply("T05");
        hexlab::debugger::DebugSession session(hexlab::debugger::make_remote_backend(std::move(fake)));
        auto connected = session.connect_remote("thread-step-unknown", 1234);
        auto stop = session.wait_event(std::chrono::milliseconds(0));
        wire->queue("+");
        auto stepped = stop ? session.single_step_execution(stop.value().sequence) :
            hexlab::debugger::Status{hexlab::Error{hexlab::ErrorCode::invalid_argument, "no stop"}};
        hexlab_test::check(connected && stop && stepped &&
            wire->writes.find(encode_packet("vCont;s")) != std::string::npos,
            "RSP single-step retains the all-thread fallback when the stop reply omits a thread ID");
    }
    {
        auto fake = std::make_unique<FakeTransport>();
        auto* wire = fake.get();
        fake->reply("PacketSize=1000;vContSupported+");
        fake->reply("T05thread:1;");
        hexlab::debugger::DebugSession session(hexlab::debugger::make_remote_backend(std::move(fake)));
        auto connected = session.connect_remote("detach-retry", 1234);
        auto initial_stop = session.wait_event(std::chrono::milliseconds(0));
        wire->reply("");
        auto unsupported_detach = session.detach();
        hexlab_test::check(connected && initial_stop && !unsupported_detach &&
                unsupported_detach.error().code == ErrorCode::unsupported &&
                session.state() == hexlab::debugger::SessionState::stopped && session.process().has_value(),
            "empty RSP detach reply preserves the connected session as unsupported");
        wire->reply("OK");
        auto retried_detach = session.detach();
        hexlab_test::check(static_cast<bool>(retried_detach) &&
                session.state() == hexlab::debugger::SessionState::detached && !session.process(),
            "RSP detach can be retried and clears session state only after an OK reply");
    }
    {
        auto fake = std::make_unique<FakeTransport>(); auto* wire = fake.get();
        fake->reply("PacketSize=1000;qXfer:features:read+;vContSupported+");
        const std::string xml = "<?xml version=\"1.0\"?><target endian=\"big\"><architecture>i386:x86-64</architecture>"
            "<feature name=\"org.gnu.gdb.core\"><reg name=\"rax\" bitsize=\"64\" regnum=\"0\" group=\"general\"/>"
            "<reg name=\"eflags\" bitsize=\"32\"/></feature></target>";
        fake->reply("l" + xml); fake->reply("T05thread:1;");
        hexlab::debugger::DebugSession session(hexlab::debugger::make_remote_backend(std::move(fake)));
        auto process = session.connect_remote("xml-target", 1234);
        wire->reply("OK"); wire->reply("010203040506070811223344");
        auto registers = session.read_registers(1);
        hexlab_test::check(process && process.value().architecture == Architecture::x86_64,
            "target XML architecture maps onto the process architecture");
        hexlab_test::check(registers && registers.value().size() == 2 && registers.value()[0].name == "rax" &&
            registers.value()[0].bytes.size() == 8 && registers.value()[0].bytes[0] == std::byte{1} &&
            registers.value()[0].group == "general" && registers.value()[0].number == 0 &&
            registers.value()[0].byte_order == ByteOrder::big &&
            registers.value()[1].name == "eflags" && registers.value()[1].bytes.size() == 4 &&
            registers.value()[1].group == "org.gnu.gdb.core" && registers.value()[1].number == 1 &&
            registers.value()[1].bytes[3] == std::byte{0x44},
            "target XML exposes named, correctly sized registers with group/number metadata and preserves target byte order");
    }
    {
        auto fake = std::make_unique<FakeTransport>(); auto* wire = fake.get();
        fake->reply("PacketSize=1000;qXfer:features:read+;qXfer:libraries:read+;vContSupported+");
        const std::string xml = "<target endian=\"little\"><architecture>i386:x86-64</architecture><feature name=\"core\">"
            "<reg name=\"rax\" bitsize=\"64\" regnum=\"0\"/><reg name=\"rip\" bitsize=\"64\" regnum=\"1\"/>"
            "</feature></target>";
        fake->reply("l" + xml); fake->reply("T05thread:1;");
        hexlab::debugger::DebugSession session(hexlab::debugger::make_remote_backend(std::move(fake)));
        auto process = session.connect_remote("write-target", 1234);
        auto initial = session.wait_event(std::chrono::milliseconds(0));
        const std::string libs = "<library-list><library name=\"/lib/libc.so\"><segment address=\"400000\"/>"
            "</library><library name=\"/app/main\" text_addr=\"500000\"/></library-list>";
        wire->reply("l" + libs);
        auto modules = session.modules();
        std::array<std::byte, 8> value{}; value[0] = std::byte{0x34};
        std::array<hexlab::debugger::RegisterValue, 1> regs{hexlab::debugger::RegisterValue{"rax", std::vector<std::byte>(value.begin(), value.end()), "core", 0, ByteOrder::little}};
        wire->reply("OK"); wire->reply("0000000000000000"); wire->reply("OK");
        auto write = session.write_registers(1, regs);
        hexlab_test::check(process && initial && modules && modules.value().size() == 2 && modules.value()[0].name == "libc.so" &&
            modules.value()[0].path == "/lib/libc.so" && modules.value()[0].base == 0x400000 && modules.value()[1].base == 0x500000,
            "remote library XML yields bounded module names, paths, and load bases");
        hexlab_test::check(write && wire->writes.find(encode_packet("P0=3400000000000000")) != std::string::npos,
            "remote register writes select the thread and apply the named target-XML register");
        std::array<hexlab::debugger::RegisterValue, 1> bad{hexlab::debugger::RegisterValue{"rax", {std::byte{1}}, "core", 0, ByteOrder::little}};
        auto invalid = session.write_registers(1, bad);
        hexlab_test::check(!invalid && invalid.error().code == ErrorCode::invalid_argument,
            "remote register write validates width before issuing any protocol command");
        std::array<hexlab::debugger::RegisterValue, 2> two_regs{
            regs[0], hexlab::debugger::RegisterValue{"rip", std::vector<std::byte>(8, std::byte{0x11}), "core", 1, ByteOrder::little}};
        wire->reply("OK"); wire->reply("0000000000000000"); wire->reply("2222222222222222");
        wire->reply("OK"); wire->reply("E01"); wire->reply("OK");
        auto rolled_back = session.write_registers(1, two_regs);
        hexlab_test::check(!rolled_back && wire->writes.find(encode_packet("P0=0000000000000000")) != std::string::npos,
            "remote multi-register write attempts to restore earlier values after a later write fails");
    }
    {
        auto fake = std::make_unique<FakeTransport>();
        fake->reply("qXfer:features:read+;PacketSize=1000");
        fake->reply("l<target><architecture>riscv:rv64</architecture><feature name=\"bad\"><reg name=\"x0\" bitsize=\"nope\"/></feature></target>");
        hexlab::debugger::DebugSession session(hexlab::debugger::make_remote_backend(std::move(fake)));
        auto process = session.connect_remote("bad-xml", 1234);
        hexlab_test::check(!process && process.error().code == ErrorCode::malformed,
            "malformed target register metadata fails explicitly instead of exposing opaque register data");
    }
}
}
int main() { return hexlab_test::run(run_tests); }
