#include "hexlab/debugger/debugger.hpp"

#include <algorithm>
#include <array>
#include <charconv>
#include <chrono>
#include <climits>
#include <cstddef>
#include <cstdint>
#include <deque>
#include <filesystem>
#include <iostream>
#include <limits>
#include <map>
#include <memory>
#include <optional>
#include <set>
#include <span>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

#ifdef _WIN32
#  define NOMINMAX
#  define WIN32_LEAN_AND_MEAN
#  include <winsock2.h>
#  include <ws2tcpip.h>
#  include <windows.h>
#else
#  include <cerrno>
#  include <csignal>
#  include <cstring>
#  include <netdb.h>
#  include <poll.h>
#  include <sys/socket.h>
#  include <unistd.h>
#endif

namespace {
using namespace std::chrono_literals;
using hexlab::debugger::DebugEvent;
using hexlab::debugger::DebugSession;
using hexlab::debugger::EventKind;
using hexlab::debugger::RegisterValue;
using hexlab::debugger::ThreadId;

constexpr std::size_t max_packet = 16 * 1024;
constexpr std::size_t max_memory = 4096;
constexpr std::size_t max_registers = 1024;
constexpr std::size_t max_memory_map_xml = 1024 * 1024;

#ifdef _WIN32
using Socket = SOCKET;
constexpr Socket invalid_socket = INVALID_SOCKET;
void close_socket(Socket value) { if (value != invalid_socket) closesocket(value); }
std::string socket_error(std::string_view action) {
    return std::string(action) + " failed (Winsock error " + std::to_string(WSAGetLastError()) + ")";
}
class SocketRuntime {
public:
    SocketRuntime() { WSADATA data{}; ready_ = WSAStartup(MAKEWORD(2, 2), &data) == 0; }
    ~SocketRuntime() { if (ready_) WSACleanup(); }
    explicit operator bool() const { return ready_; }
private:
    bool ready_ = false;
};
#else
using Socket = int;
constexpr Socket invalid_socket = -1;
void close_socket(Socket value) { if (value != invalid_socket) ::close(value); }
std::string socket_error(std::string_view action) {
    return std::string(action) + " failed: " + std::strerror(errno);
}
class SocketRuntime {
public:
    SocketRuntime() { std::signal(SIGPIPE, SIG_IGN); }
    explicit operator bool() const { return true; }
};
#endif

class SocketOwner {
public:
    SocketOwner() = default;
    explicit SocketOwner(Socket socket) : socket_(socket) {}
    ~SocketOwner() { close_socket(socket_); }
    SocketOwner(SocketOwner&& other) noexcept : socket_(std::exchange(other.socket_, invalid_socket)) {}
    SocketOwner& operator=(SocketOwner&& other) noexcept {
        if (this != &other) { close_socket(socket_); socket_ = std::exchange(other.socket_, invalid_socket); }
        return *this;
    }
    SocketOwner(const SocketOwner&) = delete;
    SocketOwner& operator=(const SocketOwner&) = delete;
    Socket get() const { return socket_; }
    explicit operator bool() const { return socket_ != invalid_socket; }
private:
    Socket socket_ = invalid_socket;
};

bool parse_u64(std::string_view value, std::uint64_t& output, int base = 16) {
    if (value.empty()) return false;
    const auto [end, error] = std::from_chars(value.data(), value.data() + value.size(), output, base);
    return error == std::errc{} && end == value.data() + value.size();
}
std::string hex_u64(std::uint64_t value) {
    std::array<char, 16> out{};
    const auto [end, error] = std::to_chars(out.data(), out.data() + out.size(), value, 16);
    return error == std::errc{} ? std::string(out.data(), end) : std::string{};
}
std::string absolute_utf8_path(std::string_view path) {
    std::error_code error;
    const std::u8string input(reinterpret_cast<const char8_t*>(path.data()), path.size());
    const auto absolute = std::filesystem::absolute(std::filesystem::path(input), error);
    if (error) return {};
    const auto utf8 = absolute.lexically_normal().u8string();
    return std::string(reinterpret_cast<const char*>(utf8.data()), utf8.size());
}
int hex_digit(char c) {
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}
std::string hex_bytes(std::span<const std::byte> bytes) {
    static constexpr char digits[] = "0123456789abcdef";
    std::string result;
    result.reserve(bytes.size() * 2);
    for (const auto byte : bytes) {
        const auto value = std::to_integer<unsigned char>(byte);
        result.push_back(digits[value >> 4]); result.push_back(digits[value & 15]);
    }
    return result;
}
bool decode_hex(std::string_view input, std::vector<std::byte>& output, std::size_t limit) {
    if ((input.size() & 1u) != 0 || input.size() / 2 > limit) return false;
    output.clear(); output.reserve(input.size() / 2);
    for (std::size_t i = 0; i < input.size(); i += 2) {
        const int high = hex_digit(input[i]), low = hex_digit(input[i + 1]);
        if (high < 0 || low < 0) return false;
        output.push_back(static_cast<std::byte>((high << 4) | low));
    }
    return true;
}
std::string xml_escape(std::string_view text) {
    std::string output;
    for (const char c : text) {
        switch (c) {
        case '&': output += "&amp;"; break;
        case '<': output += "&lt;"; break;
        case '>': output += "&gt;"; break;
        case '"': output += "&quot;"; break;
        case '\'': output += "&apos;"; break;
        default: output.push_back(c); break;
        }
    }
    return output;
}

struct Options {
    std::string bind = "127.0.0.1";
    bool bind_explicit = false;
    std::uint16_t port = 1234;
    std::optional<std::string> executable;
    std::optional<std::uint64_t> attach;
    std::vector<std::string> arguments;
    std::string working_directory;
};
void usage(std::ostream& out) {
    out << "HexLab GDB Remote Serial Protocol server\n"
        << "Usage: hexlab_debug_server (--launch FILE [-- ARGS...] | --attach PID) [options]\n"
        << "  --bind ADDRESS       TCP bind address (default 127.0.0.1)\n"
        << "  --port PORT          TCP port (default 1234)\n"
        << "  --working-dir DIR    Working directory for --launch\n"
        << "  --help               Show this help\n";
}
bool parse_options(int argc, char** argv, Options& options, bool& help) {
    bool target_args = false;
    for (int i = 1; i < argc; ++i) {
        const std::string_view item(argv[i]);
        if (target_args) { options.arguments.emplace_back(item); continue; }
        if (item == "--") { target_args = true; continue; }
        if (item == "--help" || item == "-h") { help = true; return true; }
        auto value = [&](std::string_view name) -> std::optional<std::string_view> {
            if (item != name) return {};
            if (i + 1 >= argc) return std::string_view{};
            return std::string_view(argv[++i]);
        };
        if (auto v = value("--bind")) {
            if (v->empty() || options.bind_explicit) return false;
            options.bind = *v; options.bind_explicit = true; continue;
        }
        if (auto v = value("--port")) {
            std::uint64_t port{};
            if (v->empty() || !parse_u64(*v, port, 10) || !port || port > UINT16_MAX) return false;
            options.port = static_cast<std::uint16_t>(port); continue;
        }
        if (auto v = value("--launch")) { if (v->empty() || options.executable || options.attach) return false; options.executable = std::string(*v); continue; }
        if (auto v = value("--attach")) {
            std::uint64_t pid{};
            if (v->empty() || options.executable || options.attach || !parse_u64(*v, pid, 10) || !pid) return false;
            options.attach = pid; continue;
        }
        if (auto v = value("--working-dir")) { if (v->empty()) return false; options.working_directory = *v; continue; }
        return false;
    }
    return static_cast<bool>(options.executable) != static_cast<bool>(options.attach) &&
        (options.arguments.empty() || options.executable.has_value());
}

SocketOwner listen_tcp(const Options& options) {
    addrinfo hints{}; hints.ai_family = AF_UNSPEC; hints.ai_socktype = SOCK_STREAM;
    hints.ai_protocol = IPPROTO_TCP; hints.ai_flags = AI_PASSIVE;
    addrinfo* addresses = nullptr;
    if (getaddrinfo(options.bind.c_str(), std::to_string(options.port).c_str(), &hints, &addresses) != 0)
        return {};
    SocketOwner listener;
    for (auto* address = addresses; address; address = address->ai_next) {
        Socket socket = ::socket(address->ai_family, address->ai_socktype, address->ai_protocol);
        if (socket == invalid_socket) continue;
        int reuse = 1;
        setsockopt(socket, SOL_SOCKET, SO_REUSEADDR, reinterpret_cast<const char*>(&reuse), sizeof(reuse));
        if (::bind(socket, address->ai_addr, static_cast<int>(address->ai_addrlen)) == 0 && ::listen(socket, 1) == 0) {
            listener = SocketOwner(socket); break;
        }
        close_socket(socket);
    }
    freeaddrinfo(addresses);
    return listener;
}

int wait_socket(Socket socket, bool writing, std::chrono::milliseconds timeout) {
#ifdef _WIN32
    fd_set ready; FD_ZERO(&ready); FD_SET(socket, &ready);
    timeval tv{static_cast<long>(timeout.count() / 1000), static_cast<long>((timeout.count() % 1000) * 1000)};
    return select(0, writing ? nullptr : &ready, writing ? &ready : nullptr, nullptr, &tv);
#else
    pollfd descriptor{socket, static_cast<short>(writing ? POLLOUT : POLLIN), 0};
    return poll(&descriptor, 1, static_cast<int>(timeout.count()));
#endif
}
bool write_all(Socket socket, std::string_view data) {
    std::size_t offset = 0;
    while (offset < data.size()) {
        const auto ready = wait_socket(socket, true, 10s);
        if (ready <= 0) return false;
#ifdef _WIN32
        const int count = send(socket, data.data() + offset,
            static_cast<int>(std::min<std::size_t>(data.size() - offset, INT_MAX)), 0);
#else
#  ifdef MSG_NOSIGNAL
        const auto count = send(socket, data.data() + offset, data.size() - offset, MSG_NOSIGNAL);
#  else
        const auto count = send(socket, data.data() + offset, data.size() - offset, 0);
#  endif
#endif
        if (count <= 0) return false;
        offset += static_cast<std::size_t>(count);
    }
    return true;
}
bool recv_one(Socket socket, char& value) {
#ifdef _WIN32
    const int count = recv(socket, &value, 1, 0);
#else
    const auto count = recv(socket, &value, 1, 0);
#endif
    return count == 1;
}

std::string encode_packet(std::string_view payload) {
    std::string packet;
    packet.reserve(payload.size() + 4); packet.push_back('$');
    unsigned checksum = 0;
    for (const unsigned char c : payload) {
        if (c == '$' || c == '#' || c == '}' || c == '*') {
            packet.push_back('}'); checksum = (checksum + static_cast<unsigned char>('}')) & 0xff;
            const auto escaped = static_cast<char>(c ^ 0x20);
            packet.push_back(escaped); checksum = (checksum + static_cast<unsigned char>(escaped)) & 0xff;
        } else { packet.push_back(static_cast<char>(c)); checksum = (checksum + c) & 0xff; }
    }
    static constexpr char digits[] = "0123456789abcdef";
    packet.push_back('#'); packet.push_back(digits[(checksum >> 4) & 15]); packet.push_back(digits[checksum & 15]);
    return packet;
}

class RspConnection {
public:
    explicit RspConnection(Socket socket) : socket_(socket) {}
    bool no_ack() const { return no_ack_; }
    void set_no_ack() { no_ack_ = true; }
    bool send_ack(char byte) { return write_all(socket_, std::string_view(&byte, 1)); }
    bool send_packet(std::string_view payload) {
        if (payload.size() > max_packet) return false;
        const auto packet = encode_packet(payload);
        for (unsigned attempt = 0; attempt < 4; ++attempt) {
            if (!write_all(socket_, packet)) return false;
            if (no_ack_) return true;
            const auto deadline = std::chrono::steady_clock::now() + 10s;
            while (std::chrono::steady_clock::now() < deadline) {
                if (wait_socket(socket_, false, 100ms) <= 0) continue;
                char byte{}; if (!recv_one(socket_, byte)) return false;
                if (byte == '+') return true;
                if (byte == '-') break;
                if (byte == 3) return false;
            }
        }
        return false;
    }
    std::optional<std::string> receive_packet() {
        for (;;) {
            char marker{};
            if (!read_byte(marker)) return {};
            if (marker == 3) { interrupted_ = true; return std::string{}; }
            if (marker == '+' || marker == '-') continue;
            if (marker != '$') continue;
            std::string encoded; encoded.reserve(256); bool escaped = false;
            unsigned checksum = 0;
            for (;;) {
                char byte{}; if (!read_byte(byte)) return {};
                if (!escaped && byte == '#') break;
                if (encoded.size() >= max_packet) { if (!no_ack_) send_ack('-'); return {}; }
                encoded.push_back(byte); checksum = (checksum + static_cast<unsigned char>(byte)) & 0xff;
                if (!escaped && byte == '}') escaped = true; else escaped = false;
            }
            char a{}, b{}; if (!read_byte(a) || !read_byte(b)) return {};
            const int high = hex_digit(a), low = hex_digit(b);
            if (high < 0 || low < 0 || ((high << 4) | low) != static_cast<int>(checksum) || escaped) {
                if (!no_ack_) send_ack('-');
                continue;
            }
            std::string decoded; decoded.reserve(encoded.size());
            for (std::size_t i = 0; i < encoded.size(); ++i) {
                if (encoded[i] == '}') {
                    if (++i >= encoded.size()) { decoded.clear(); break; }
                    decoded.push_back(static_cast<char>(encoded[i] ^ 0x20));
                } else decoded.push_back(encoded[i]);
            }
            if (!no_ack_ && !send_ack('+')) return {};
            return decoded;
        }
    }
    bool interrupted() const { return interrupted_; }
    void clear_interrupt() { interrupted_ = false; }
    bool poll_interrupt() {
        if (wait_socket(socket_, false, 0ms) <= 0) return false;
        char byte{}; if (!recv_one(socket_, byte)) { disconnected_ = true; return false; }
        if (byte == 3) { interrupted_ = true; return true; }
        if (byte == '+') return false;
        // Commands while the target is running are not supported. Preserve no
        // more than one command prefix and terminate the active run cleanly.
        if (byte == '$') { buffered_ = '$'; return false; }
        return false;
    }
    bool disconnected() const { return disconnected_; }
private:
    bool read_byte(char& byte) {
        if (buffered_) { byte = *buffered_; buffered_.reset(); return true; }
        int ready = 0;
        while ((ready = wait_socket(socket_, false, 1s)) == 0) {}
        if (ready < 0) { disconnected_ = true; return false; }
        if (!recv_one(socket_, byte)) { disconnected_ = true; return false; }
        return true;
    }
    Socket socket_;
    bool no_ack_ = false;
    bool interrupted_ = false;
    bool disconnected_ = false;
    std::optional<char> buffered_;
};

struct RegisterInfo { std::string name, group; std::size_t bytes = 0; };
enum class ThreadSelectionKind { any, all, specific };
struct ThreadSelection {
    ThreadSelectionKind kind = ThreadSelectionKind::any;
    ThreadId id = 0;
};
struct ResumeAction {
    hexlab::debugger::ThreadResumeKind kind = hexlab::debugger::ThreadResumeKind::continue_execution;
    ThreadSelection thread;
    std::optional<unsigned> signal;
};
struct ResumeRequest {
    bool step = false;
    bool continue_thread = false;
    ThreadId selected_thread = 0;
    std::optional<unsigned> signal;
    // vCont selectors are independent of the legacy Hc selection.
    bool vcont = false;
    ThreadSelection thread;
    std::optional<std::uint64_t> address;
    std::vector<ResumeAction> actions;
};
struct ServerState {
    DebugSession& session;
    RspConnection& connection;
    bool attached_existing_process = false;
    std::string executable_path;
    std::vector<RegisterInfo> registers;
    std::vector<hexlab::debugger::ThreadInfo> thread_page;
    std::size_t next_thread = 0;
    std::optional<DebugEvent> event;
    ThreadId selected_thread = 0;
    ThreadSelection continue_thread;
    bool target_exited = false;
    bool libraries_supported = false;
    std::optional<std::string> libraries_snapshot;
    bool threads_xml_supported = false;
    std::optional<std::string> threads_xml_snapshot;
    bool memory_map_supported = false;
    std::optional<std::string> memory_map_snapshot;
};

std::optional<ThreadSelection> parse_thread_selection(std::string_view id) {
    if (id == "0") return ThreadSelection{};
    if (id == "-1") return ThreadSelection{ThreadSelectionKind::all};
    std::uint64_t value{};
    // This server does not negotiate multiprocess IDs (pPID.TID). Keep IDs
    // unsigned and bounded; do not truncate a process component or overflow.
    if (id.empty() || id.size() > 16 || !parse_u64(id, value) || !value) return {};
    return ThreadSelection{ThreadSelectionKind::specific, value};
}

std::optional<ResumeRequest> parse_resume(std::string_view command, ThreadSelection legacy_thread) {
    ResumeRequest request;
    const auto parse_signal = [](std::string_view value) -> std::optional<unsigned> {
        if (value.size() != 2) return {};
        std::uint64_t signal{};
        if (!parse_u64(value, signal) || signal > 255) return {};
        return static_cast<unsigned>(signal);
    };
    if (command == "vCont" || command.starts_with("vCont;")) {
        request.vcont = true;
        if (!command.starts_with("vCont;") || command.size() < 7) return {};
        auto remaining = command.substr(6);
        while (!remaining.empty()) {
            if (request.actions.size() == hexlab::debugger::max_inspection_threads) return {};
            const auto end = remaining.find(';');
            const auto action = remaining.substr(0, end);
            if (action.empty()) return {};
            ResumeAction parsed;
            std::size_t selector_offset = 1;
            if (action[0] == 'c' || action[0] == 's' || action[0] == 't') {
                parsed.kind = action[0] == 't' ? hexlab::debugger::ThreadResumeKind::stop :
                    action[0] == 's' ? hexlab::debugger::ThreadResumeKind::single_step :
                    hexlab::debugger::ThreadResumeKind::continue_execution;
            } else if (action[0] == 'C' || action[0] == 'S') {
                const auto colon = action.find(':');
                const auto signal_text = action.substr(1, colon == std::string_view::npos
                    ? std::string_view::npos : colon - 1);
                parsed.signal = parse_signal(signal_text);
                if (!parsed.signal) return {};
                parsed.kind = action[0] == 'S' ? hexlab::debugger::ThreadResumeKind::single_step :
                    hexlab::debugger::ThreadResumeKind::continue_execution;
                selector_offset = colon == std::string_view::npos ? action.size() : colon;
            } else return {};
            if (selector_offset < action.size()) {
                if (action[selector_offset] != ':') return {};
                auto thread = parse_thread_selection(action.substr(selector_offset + 1));
                if (!thread) return {};
                parsed.thread = *thread;
            } else parsed.thread = {ThreadSelectionKind::all};
            request.actions.push_back(parsed);
            if (end == std::string_view::npos) break;
            remaining.remove_prefix(end + 1);
            if (remaining.empty()) return {};
        }
    } else {
        if (command.empty()) return {};
        std::size_t address_offset = 1;
        if (command[0] == 'c' || command[0] == 's') {
            request.step = command[0] == 's';
        } else if (command[0] == 'C' || command[0] == 'S') {
            if (command.size() < 3) return {};
            request.signal = parse_signal(command.substr(1, 2));
            if (!request.signal) return {};
            request.step = command[0] == 'S';
            if (command.size() > 3) {
                if (command[3] != ';' || command.size() == 4) return {};
                address_offset = 4;
            } else address_offset = command.size();
        } else return {};
        request.thread = legacy_thread;
        if (command.size() > address_offset) {
            std::uint64_t address{};
            if (command.size() - address_offset > 16 || !parse_u64(command.substr(address_offset), address)) return {};
            request.address = address;
        }
    }
    return request;
}

const char* target_arch(hexlab::Architecture architecture) {
    switch (architecture) {
    case hexlab::Architecture::x86: return "i386";
    case hexlab::Architecture::x86_64: return "i386:x86-64";
    case hexlab::Architecture::arm: return "arm";
    case hexlab::Architecture::arm64: return "aarch64";
    default: return nullptr;
    }
}
bool initialize_registers(ServerState& state) {
    const auto process = state.session.process();
    if (!process || !target_arch(process->architecture)) return false;
    auto threads = state.session.threads();
    if (!threads || threads.value().empty() || threads.value().size() > 4096) return false;
    state.selected_thread = threads.value().front().id;
    auto registers = state.session.read_registers(state.selected_thread);
    if (!registers || registers.value().empty() || registers.value().size() > max_registers) return false;
    for (const auto& reg : registers.value()) {
        if (reg.name.empty() || reg.name.size() > 128 || reg.bytes.empty() || reg.bytes.size() > 512) return false;
        state.registers.push_back({reg.name, reg.group, reg.bytes.size()});
    }
    return true;
}
std::string target_xml(const ServerState& state) {
    const auto process = state.session.process();
    if (!process || !target_arch(process->architecture)) return {};
    std::string xml = "<?xml version=\"1.0\"?><target version=\"1.0\" endian=\"little\"><architecture>";
    xml += target_arch(process->architecture); xml += "</architecture><feature name=\"org.gnu.gdb.hexlab.core\">";
    for (std::size_t i = 0; i < state.registers.size(); ++i) {
        const auto& reg = state.registers[i];
        xml += "<reg name=\"" + xml_escape(reg.name) + "\" bitsize=\"" + std::to_string(reg.bytes * 8) +
            "\" regnum=\"" + std::to_string(i) + "\" type=\"int\"";
        if (!reg.group.empty()) xml += " group=\"" + xml_escape(reg.group) + "\"";
        xml += "/>";
    }
    xml += "</feature></target>";
    return xml;
}
std::string libraries_xml(const std::vector<hexlab::debugger::ModuleInfo>& modules) {
    if (modules.size() > hexlab::debugger::max_inspection_modules) return {};
    std::string xml = "<?xml version=\"1.0\"?><library-list version=\"1.1\">";
    for (const auto& module : modules) {
        const auto& path = module.path.empty() ? module.name : module.path;
        if (path.empty() || path.size() > 32 * 1024) return {};
        xml += "<library name=\"" + xml_escape(path) + "\"><segment address=\"0x" + hex_u64(module.base) + "\"/></library>";
        if (xml.size() > 1024 * 1024) return {};
    }
    xml += "</library-list>";
    return xml.size() <= 1024 * 1024 ? xml : std::string{};
}
std::string threads_xml(const std::vector<hexlab::debugger::ThreadInfo>& threads) {
    if (threads.size() > hexlab::debugger::max_inspection_threads) return {};
    std::string xml = "<?xml version=\"1.0\"?><threads>";
    std::set<ThreadId> seen;
    for (const auto& thread : threads) {
        if (!thread.id || !seen.insert(thread.id).second || thread.name.size() > 32 * 1024) return {};
        if (std::any_of(thread.name.begin(), thread.name.end(), [](unsigned char c) {
                return c < 0x20 && c != '\t' && c != '\r' && c != '\n';
            })) return {};
        xml += "<thread id=\"" + hex_u64(thread.id) + "\"";
        if (!thread.name.empty()) xml += " name=\"" + xml_escape(thread.name) + "\"";
        xml += "/>";
        if (xml.size() > max_memory_map_xml) return {};
    }
    xml += "</threads>";
    return xml.size() <= max_memory_map_xml ? xml : std::string{};
}
std::string memory_map_xml(std::vector<hexlab::debugger::MemoryRegion> regions) {
    if (regions.empty() || regions.size() > hexlab::debugger::max_inspection_memory_regions) return {};
    std::sort(regions.begin(), regions.end(), [](const auto& a, const auto& b) { return a.start < b.start; });
    std::string xml = "<?xml version=\"1.0\"?><memory-map>";
    std::optional<std::uint64_t> previous_last;
    for (const auto& region : regions) {
        if (!region.length || region.length - 1 > UINT64_MAX - region.start ||
            (previous_last && region.start <= *previous_last) || region.type.size() > 32 * 1024 ||
            (region.flash_block_size && (region.type != "flash" || !*region.flash_block_size ||
                *region.flash_block_size > region.length || region.start % *region.flash_block_size != 0 ||
                region.length % *region.flash_block_size != 0)))
            return {};
        previous_last = region.start + region.length - 1;
        // XML 1.0 cannot represent these characters, even as numeric entities.
        if (std::any_of(region.type.begin(), region.type.end(), [](unsigned char c) {
                return c < 0x20 && c != '\t' && c != '\r' && c != '\n';
            })) return {};
        const std::string permissions{region.readable ? 'r' : '-', region.writable ? 'w' : '-',
                                      region.executable ? 'x' : '-'};
        // Standard RSP memory types provide a useful fallback for peers that
        // do not understand the permission and native-label properties.
        const auto standard_type = region.type == "flash" ? "flash" : (region.writable ? "ram" : "rom");
        xml += "<memory type=\"" + std::string(standard_type) +
            "\" start=\"0x" + hex_u64(region.start) + "\" length=\"0x" + hex_u64(region.length) +
            "\"><property name=\"permissions\">" + permissions + "</property>";
        if (region.flash_block_size)
            xml += "<property name=\"blocksize\">0x" + hex_u64(*region.flash_block_size) + "</property>";
        xml += "<property name=\"hexlab-type\">" + xml_escape(region.type) + "</property>";
        xml += "</memory>";
        if (xml.size() > max_memory_map_xml) return {};
    }
    xml += "</memory-map>";
    return xml.size() <= max_memory_map_xml ? xml : std::string{};
}
std::optional<std::size_t> register_index(const ServerState& state, std::string_view hex_number) {
    std::uint64_t number{};
    if (!parse_u64(hex_number, number) || number >= state.registers.size()) return {};
    return static_cast<std::size_t>(number);
}
std::vector<RegisterValue> read_registers(ServerState& state) {
    auto result = state.session.read_registers(state.selected_thread);
    if (!result || result.value().size() != state.registers.size()) return {};
    return std::move(result.value());
}
std::string register_packet(ServerState& state) {
    auto registers = read_registers(state); if (registers.empty()) return {};
    std::string output;
    for (std::size_t i = 0; i < registers.size(); ++i) {
        if (registers[i].bytes.size() != state.registers[i].bytes) return {};
        output += hex_bytes(registers[i].bytes);
    }
    return output;
}
unsigned rsp_signal(const DebugEvent& event) {
    if (event.kind == EventKind::breakpoint || event.kind == EventKind::single_step) return 5; // SIGTRAP
    if (event.kind != EventKind::exception) return 5;
#ifdef _WIN32
    switch (event.code) {
    case EXCEPTION_ACCESS_VIOLATION: return 11; // SIGSEGV
    case EXCEPTION_ILLEGAL_INSTRUCTION: return 4; // SIGILL
    case EXCEPTION_INT_DIVIDE_BY_ZERO:
    case EXCEPTION_INT_OVERFLOW:
    case EXCEPTION_FLT_DIVIDE_BY_ZERO:
    case EXCEPTION_FLT_INVALID_OPERATION:
    case EXCEPTION_FLT_OVERFLOW: return 8; // SIGFPE
    case EXCEPTION_BREAKPOINT:
    case EXCEPTION_SINGLE_STEP: return 5; // SIGTRAP
    default: return 6; // SIGABRT for an otherwise unmapped fatal exception
    }
#else
    // Linux and Darwin backends put the native stop signal in event.code.
    return event.code > 0 && event.code <= 64 ? event.code : 6;
#endif
}
std::string stop_reply(const ServerState& state, const DebugEvent& event) {
    if (event.kind == EventKind::process_exited) return "W" + hex_u64(event.code & 0xff);
    const unsigned signal = rsp_signal(event);
    std::string reply = "T" + (signal < 16 ? std::string("0") : std::string{}) + hex_u64(signal);
    reply += "thread:" + hex_u64(event.thread) + ";";
    bool software = false, hardware_execute = false, write_watch = false, read_watch = false, access_watch = false;
    const auto breakpoints = state.session.breakpoints();
    for (const auto id : event.breakpoint_ids) {
        const auto found = std::find_if(breakpoints.begin(), breakpoints.end(),
            [id](const auto& breakpoint) { return breakpoint.id == id; });
        if (found == breakpoints.end()) continue;
        switch (found->kind) {
        case hexlab::debugger::BreakpointKind::software: software = true; break;
        case hexlab::debugger::BreakpointKind::hardware:
        case hexlab::debugger::BreakpointKind::execute: hardware_execute = true; break;
        case hexlab::debugger::BreakpointKind::write: write_watch = true; break;
        case hexlab::debugger::BreakpointKind::read: read_watch = true; break;
        case hexlab::debugger::BreakpointKind::access: access_watch = true; break;
        }
    }
    if (!software && event.kind == EventKind::breakpoint) {
        software = std::any_of(breakpoints.begin(), breakpoints.end(), [&](const auto& breakpoint) {
            return breakpoint.kind == hexlab::debugger::BreakpointKind::software &&
                breakpoint.enabled && breakpoint.address == event.address;
        });
    }
    if (software) reply += "swbreak:;";
    if (hardware_execute) reply += "hwbreak:;";
    if (write_watch) reply += "watch:" + hex_u64(event.address) + ";";
    if (read_watch) reply += "rwatch:" + hex_u64(event.address) + ";";
    if (access_watch) reply += "awatch:" + hex_u64(event.address) + ";";
    return reply;
}
bool thread_exists(ServerState& state, std::string_view id, ThreadId& value) {
    if (id == "0" || id == "-1") { value = 0; return true; }
    std::uint64_t parsed{};
    if (!parse_u64(id, parsed) || !parsed) return false;
    auto threads = state.session.threads();
    if (!threads) return false;
    const auto found = std::find_if(threads.value().begin(), threads.value().end(),
        [parsed](const auto& thread) {
            return thread.id == parsed && thread.state != hexlab::debugger::ThreadState::exited;
        });
    if (found == threads.value().end()) return false;
    value = found->id;
    return true;
}
bool select_general_thread(ServerState& state, std::string_view id) {
    ThreadId value{};
    if (!thread_exists(state, id, value)) return false;
    state.selected_thread = value ? value : state.selected_thread;
    return state.selected_thread != 0;
}
bool hardware_breakpoints_supported(const ServerState& state) {
    const auto& process = state.session.process();
    if (!process) return false;
#if defined(_WIN32) && defined(_M_ARM64)
    return process->architecture == hexlab::Architecture::arm64;
#elif defined(_WIN32)
    return process->architecture == hexlab::Architecture::x86 ||
           process->architecture == hexlab::Architecture::x86_64;
#elif defined(__linux__) && defined(__x86_64__)
    return process->architecture == hexlab::Architecture::x86_64;
#else
    return false;
#endif
}
bool single_step_supported(const ServerState& state) {
    const auto& process = state.session.process();
    if (!process) return false;
#ifdef _WIN32
    return process->architecture == hexlab::Architecture::x86 ||
           process->architecture == hexlab::Architecture::x86_64 ||
           process->architecture == hexlab::Architecture::arm64;
#elif defined(__linux__) && defined(__x86_64__)
    return process->architecture == hexlab::Architecture::x86 ||
           process->architecture == hexlab::Architecture::x86_64;
#elif defined(__linux__) && defined(__aarch64__)
    return process->architecture == hexlab::Architecture::arm64;
#elif defined(__APPLE__)
    return process->architecture == hexlab::Architecture::x86_64 ||
           process->architecture == hexlab::Architecture::arm64;
#else
    return false;
#endif
}
bool only_event_thread(ServerState& state) {
    if (!state.event || !state.event->thread) return false;
    auto threads = state.session.threads();
    if (!threads) return false;
    bool found = false;
    for (const auto& thread : threads.value()) {
        if (thread.state == hexlab::debugger::ThreadState::exited) continue;
        if (thread.id != state.event->thread || found) return false;
        found = true;
    }
    return found;
}
// Resolve the complete list before touching registers or consuming the event.
// RSP applies the leftmost matching action; unmatched threads remain stopped.
// Keep the resolved schedule intact: a backend must reject unsupported
// combinations, never silently widen them to process-wide continuation.
struct ResolvedResume {
    bool process_continue = false;
    hexlab::debugger::ContinueStatus process_disposition = hexlab::debugger::ContinueStatus::handled;
    std::vector<hexlab::debugger::ThreadResumeAction> schedule;
};
std::optional<ResolvedResume> resolve_resume_actions(ServerState& state, const std::vector<ResumeAction>& actions) {
    auto snapshot = state.session.threads();
    if (!snapshot || !state.event) return {};
    auto& threads = snapshot.value();
    std::erase_if(threads, [](const auto& thread) { return thread.state == hexlab::debugger::ThreadState::exited; });
    if (threads.empty() || threads.size() > hexlab::debugger::max_inspection_threads) return {};
    for (const auto& action : actions) {
        if (action.signal && action.thread.kind == ThreadSelectionKind::all && threads.size() != 1)
            return {};
        const auto id = action.thread.kind == ThreadSelectionKind::any ? state.event->thread : action.thread.id;
        if (action.thread.kind != ThreadSelectionKind::all &&
            (id == 0 || std::none_of(threads.begin(), threads.end(),
                [id](const auto& thread) { return thread.id == id; }))) return {};
    }
    ResolvedResume resolved;
    std::size_t continued = 0, stepped = 0;
    bool includes_owner = false;
    for (const auto& thread : threads) {
        if (!thread.id || std::any_of(resolved.schedule.begin(), resolved.schedule.end(), [&](const auto &known) {
                return known.thread == thread.id;
            })) return {};
        auto kind = hexlab::debugger::ThreadResumeKind::stop;
        const ResumeAction* matched = nullptr;
        for (const auto& action : actions) {
            const auto id = action.thread.kind == ThreadSelectionKind::any ? state.event->thread : action.thread.id;
            if (action.thread.kind != ThreadSelectionKind::all && id != thread.id) continue;
            matched = &action;
            kind = action.kind;
            if (kind == hexlab::debugger::ThreadResumeKind::single_step) {
                ++stepped;
            } else if (kind == hexlab::debugger::ThreadResumeKind::continue_execution) {
                ++continued;
            }
            break;
        }
        includes_owner = includes_owner || thread.id == state.event->thread;
        resolved.schedule.push_back({thread.id, kind});
        auto& resolved_action = resolved.schedule.back();
        if (thread.id == state.event->thread) {
            if (matched && matched->signal) {
                if (*matched->signal == 0) {
                    if (state.session.supports_scheduled_signal_disposition())
                        resolved_action.signal_disposition = hexlab::debugger::ContinueStatus::handled;
                } else if (state.event->kind == EventKind::exception &&
                           *matched->signal == state.event->code &&
                           state.session.supports_scheduled_signal_disposition()) {
                    resolved_action.signal_disposition = hexlab::debugger::ContinueStatus::not_handled;
                } else return {};
            } else if (kind != hexlab::debugger::ThreadResumeKind::stop &&
                       state.session.supports_scheduled_signal_disposition()) {
                // RSP c/s without an explicit signal suppresses the signal
                // associated with this stop. Native schedules preserve it by
                // default, so make the protocol's zero-signal choice explicit.
                resolved_action.signal_disposition = hexlab::debugger::ContinueStatus::handled;
            }
        } else if (matched && matched->signal) {
            return {};
        }
    }
    if (continued == threads.size() && stepped == 0) {
        resolved.process_continue = true;
        for (const auto& action : resolved.schedule)
            if (action.thread == state.event->thread && action.signal_disposition)
                resolved.process_disposition = *action.signal_disposition;
        resolved.schedule.clear();
        return resolved;
    }
    if (!includes_owner || continued + stepped == 0 || (stepped && !single_step_supported(state))) return {};
    return resolved;
}
bool set_pc(ServerState& state, ThreadId thread, std::uint64_t address) {
    auto result = state.session.read_registers(thread);
    if (!result) return false;
    for (auto& reg : result.value()) {
        if (reg.name == "rip" || reg.name == "eip" || reg.name == "pc") {
            const auto count = reg.bytes.size();
            if (count > sizeof(address) || count == 0) return false;
            if (count < sizeof(address) && address >> (count * 8)) return false;
            for (std::size_t b = 0; b < count; ++b) reg.bytes[b] = static_cast<std::byte>((address >> (b * 8)) & 0xff);
            return static_cast<bool>(state.session.write_registers(thread, std::span(&reg, 1)));
        }
    }
    return false;
}
bool process_running(ServerState& state) {
    for (;;) {
        auto event = state.session.wait_event(50ms);
        if (event) {
            state.event = std::move(event.value());
            state.target_exited = state.event->kind == EventKind::process_exited;
            return true;
        }
        if (event.error().code != hexlab::ErrorCode::busy) return false;
        if (state.connection.disconnected()) return false;
        if (state.connection.poll_interrupt()) {
            state.connection.clear_interrupt();
            auto requested = state.session.request_interrupt();
            if (!requested && requested.error().code != hexlab::ErrorCode::busy) return false;
        }
        if (state.connection.disconnected()) return false;
    }
}

std::string handle_command(ServerState& state, std::string_view command, bool& close_connection,
                           bool& toggle_no_ack) {
    close_connection = false; toggle_no_ack = false;
    if (command == "?") return state.event ? stop_reply(state, *state.event) : "S05";
    if (command.starts_with("qSupported")) {
        std::string features = "PacketSize=2000;swbreak+;QStartNoAckMode+;qXfer:features:read+;vContSupported+";
        if (!state.executable_path.empty() && state.executable_path.size() <= 64 * 1024)
            features += ";qXfer:exec-file:read+";
        const auto modules = state.session.modules();
        state.libraries_supported = static_cast<bool>(modules) &&
            modules.value().size() <= hexlab::debugger::max_inspection_modules;
        state.libraries_snapshot.reset();
        if (state.libraries_supported) features += ";qXfer:libraries:read+";
        auto threads = state.session.threads();
        state.threads_xml_snapshot.reset();
        if (threads) {
            auto xml = threads_xml(threads.value());
            if (!xml.empty()) state.threads_xml_snapshot = std::move(xml);
        }
        state.threads_xml_supported = state.threads_xml_snapshot.has_value();
        if (state.threads_xml_supported) features += ";qXfer:threads:read+";
        auto regions = state.session.memory_regions();
        state.memory_map_snapshot.reset();
        if (regions) {
            auto xml = memory_map_xml(std::move(regions.value()));
            if (!xml.empty()) state.memory_map_snapshot = std::move(xml);
        }
        state.memory_map_supported = state.memory_map_snapshot.has_value();
        if (state.memory_map_supported) features += ";qXfer:memory-map:read+";
        // hwbreak+ promises a hardware stop reason, not merely Z1 support.
        // Windows ARM64 can program slots but cannot identify their hits yet.
        if (hardware_breakpoints_supported(state) && state.session.process()->architecture != hexlab::Architecture::arm64)
            features += ";hwbreak+";
        return features;
    }
    if (command == "QStartNoAckMode") { toggle_no_ack = true; return "OK"; }
    if (command == "vCont?") {
        std::string actions = "vCont;c;t";
        if (single_step_supported(state)) actions += ";s";
        if (state.session.supports_scheduled_signal_disposition()) {
            actions += ";C";
            if (single_step_supported(state)) actions += ";S";
        }
        return actions;
    }
    if (command == "qAttached") return state.attached_existing_process ? "1" : "0";
    if (command == "qC") return "QC" + hex_u64(state.event && state.event->thread ? state.event->thread : state.selected_thread);
    if (command == "qfThreadInfo") {
        auto threads = state.session.threads(); if (!threads) return "E01";
        state.thread_page = std::move(threads.value()); state.next_thread = 0;
        if (state.thread_page.empty()) return "l";
        std::string result = "m";
        while (state.next_thread < state.thread_page.size()) {
            const auto token = hex_u64(state.thread_page[state.next_thread].id);
            const auto extra = token.size() + (result.size() > 1 ? 1u : 0u);
            if (result.size() + extra > max_packet) break;
            if (result.size() > 1) result.push_back(',');
            result += token; ++state.next_thread;
        }
        return result;
    }
    if (command == "qsThreadInfo") {
        if (state.next_thread >= state.thread_page.size()) return "l";
        std::string result = "m";
        while (state.next_thread < state.thread_page.size()) {
            const auto token = hex_u64(state.thread_page[state.next_thread].id);
            const auto extra = token.size() + (result.size() > 1 ? 1u : 0u);
            if (result.size() + extra > max_packet) break;
            if (result.size() > 1) result.push_back(',');
            result += token; ++state.next_thread;
        }
        return result;
    }
    if (command.starts_with("qXfer:features:read:target.xml:")) {
        const auto range = command.substr(std::string_view("qXfer:features:read:target.xml:").size());
        const auto comma = range.find(','); std::uint64_t offset{}, length{};
        if (comma == std::string_view::npos || !parse_u64(range.substr(0, comma), offset) ||
            !parse_u64(range.substr(comma + 1), length) || !length || length > max_packet - 2 ||
            offset > std::numeric_limits<std::size_t>::max()) return "E01";
        const auto xml = target_xml(state);
        if (offset >= xml.size()) return "l";
        const auto amount = std::min<std::uint64_t>(length, xml.size() - static_cast<std::size_t>(offset));
        return std::string(offset + amount < xml.size() ? "m" : "l") + xml.substr(static_cast<std::size_t>(offset), static_cast<std::size_t>(amount));
    }
    if (command.starts_with("qXfer:exec-file:read::")) {
        if (state.executable_path.empty() || state.executable_path.size() > 64 * 1024) return {};
        const auto range = command.substr(std::string_view("qXfer:exec-file:read::").size());
        const auto comma = range.find(','); std::uint64_t offset{}, length{};
        if (comma == std::string_view::npos || !parse_u64(range.substr(0, comma), offset) ||
            !parse_u64(range.substr(comma + 1), length) || !length || length > max_packet - 2 ||
            offset > state.executable_path.size()) return "E01";
        const auto amount = std::min<std::uint64_t>(length, state.executable_path.size() - static_cast<std::size_t>(offset));
        const bool more = offset + amount < state.executable_path.size();
        return std::string(more ? "m" : "l") + state.executable_path.substr(
            static_cast<std::size_t>(offset), static_cast<std::size_t>(amount));
    }
    if (command.starts_with("qXfer:libraries:read::")) {
        if (!state.libraries_supported) return {};
        const auto range = command.substr(std::string_view("qXfer:libraries:read::").size());
        const auto comma = range.find(','); std::uint64_t offset{}, length{};
        if (comma == std::string_view::npos || !parse_u64(range.substr(0, comma), offset) ||
            !parse_u64(range.substr(comma + 1), length) || !length || length > max_packet - 2 ||
            offset > 1024 * 1024) return "E01";
        if (offset == 0 || !state.libraries_snapshot) {
            auto modules = state.session.modules();
            if (!modules) return {};
            auto xml = libraries_xml(modules.value());
            if (xml.empty()) return "E01";
            state.libraries_snapshot = std::move(xml);
        }
        const auto& xml = *state.libraries_snapshot;
        if (offset >= xml.size()) return "l";
        const auto amount = std::min<std::uint64_t>(length, xml.size() - static_cast<std::size_t>(offset));
        const bool more = offset + amount < xml.size();
        if (!more) state.libraries_snapshot.reset();
        return std::string(more ? "m" : "l") + xml.substr(static_cast<std::size_t>(offset), static_cast<std::size_t>(amount));
    }
    if (command.starts_with("qXfer:threads:read::")) {
        if (!state.threads_xml_supported) return {};
        const auto range = command.substr(std::string_view("qXfer:threads:read::").size());
        const auto comma = range.find(','); std::uint64_t offset{}, length{};
        if (comma == std::string_view::npos || !parse_u64(range.substr(0, comma), offset) ||
            !parse_u64(range.substr(comma + 1), length) || !length || length > max_packet - 2 ||
            offset > max_memory_map_xml) return "E01";
        if (offset == 0 || !state.threads_xml_snapshot) {
            auto threads = state.session.threads();
            if (!threads) return "E01";
            auto xml = threads_xml(threads.value());
            if (xml.empty()) return "E01";
            state.threads_xml_snapshot = std::move(xml);
        }
        const auto& xml = *state.threads_xml_snapshot;
        if (offset >= xml.size()) return "l";
        // PacketSize=2000 is 8 KiB. Reserve a marker and worst-case escaping
        // for every XML byte returned to the peer.
        const auto amount = std::min<std::uint64_t>({length, max_memory - 1,
            xml.size() - static_cast<std::size_t>(offset)});
        const bool more = offset + amount < xml.size();
        if (!more) state.threads_xml_snapshot.reset();
        return std::string(more ? "m" : "l") +
            xml.substr(static_cast<std::size_t>(offset), static_cast<std::size_t>(amount));
    }
    if (command.starts_with("qXfer:memory-map:read::")) {
        if (!state.memory_map_supported) return {};
        const auto range = command.substr(std::string_view("qXfer:memory-map:read::").size());
        const auto comma = range.find(','); std::uint64_t offset{}, length{};
        if (comma == std::string_view::npos || !parse_u64(range.substr(0, comma), offset) ||
            !parse_u64(range.substr(comma + 1), length) || !length || offset > max_memory_map_xml)
            return "E01";
        // Offset zero starts a fresh snapshot. Later chunks retain that exact
        // snapshot until execution changes the map, including retransmissions.
        if (offset == 0 || !state.memory_map_snapshot) {
            state.memory_map_snapshot.reset();
            auto regions = state.session.memory_regions();
            if (!regions) return "E01";
            auto xml = memory_map_xml(std::move(regions.value()));
            if (xml.empty()) return "E01";
            state.memory_map_snapshot = std::move(xml);
        }
        const auto& xml = *state.memory_map_snapshot;
        if (offset >= xml.size()) return "l";
        // PacketSize=2000 is 8192 wire bytes. Reserve the m/l marker and
        // worst-case two-byte escaping for every XML byte.
        const auto amount = std::min<std::uint64_t>({length, max_memory - 1,
            xml.size() - static_cast<std::size_t>(offset)});
        return std::string(offset + amount < xml.size() ? "m" : "l") +
            xml.substr(static_cast<std::size_t>(offset), static_cast<std::size_t>(amount));
    }
    if (command.starts_with("Hg") || command.starts_with("Hc")) {
        const auto id = command.substr(2);
        if (command[1] == 'g') return select_general_thread(state, id) ? "OK" : "E01";
        auto selection = parse_thread_selection(id);
        if (!selection) return "E01";
        if (selection->kind == ThreadSelectionKind::specific) {
            ThreadId value{};
            if (!thread_exists(state, id, value)) return "E01";
        }
        state.continue_thread = *selection;
        return "OK";
    }
    if (command.size() >= 2 && command[0] == 'T') {
        ThreadId ignored{};
        return thread_exists(state, command.substr(1), ignored) ? "OK" : "E01";
    }
    if (command == "g") return register_packet(state);
    if (command.starts_with("p")) {
        const auto index = register_index(state, command.substr(1)); if (!index) return "E01";
        auto registers = read_registers(state); if (registers.empty()) return "E01";
        return hex_bytes(registers[*index].bytes);
    }
    if (command.starts_with("P")) {
        const auto equal = command.find('='); const auto index = equal == std::string_view::npos ? std::optional<std::size_t>{} : register_index(state, command.substr(1, equal - 1));
        if (!index) return "E01";
        auto registers = read_registers(state); if (registers.empty()) return "E01";
        std::vector<std::byte> bytes;
        if (!decode_hex(command.substr(equal + 1), bytes, 512) || bytes.size() != state.registers[*index].bytes) return "E01";
        registers[*index].bytes = std::move(bytes);
        return state.session.write_registers(state.selected_thread, std::span(&registers[*index], 1)) ? "OK" : "E01";
    }
    if (command.starts_with("G")) {
        auto registers = read_registers(state); if (registers.empty()) return "E01";
        const auto bytes = command.substr(1); std::size_t expected = 0;
        for (const auto& reg : state.registers) expected += reg.bytes;
        if (bytes.size() != expected * 2) return "E01";
        std::size_t cursor = 0;
        for (std::size_t i = 0; i < registers.size(); ++i) {
            std::vector<std::byte> value;
            const auto chars = state.registers[i].bytes * 2;
            if (!decode_hex(bytes.substr(cursor, chars), value, 512) || value.size() != state.registers[i].bytes) return "E01";
            registers[i].bytes = std::move(value); cursor += chars;
        }
        return state.session.write_registers(state.selected_thread, registers) ? "OK" : "E01";
    }
    if (command.starts_with("m")) {
        const auto comma = command.find(','); std::uint64_t address{}, length{};
        if (comma == std::string_view::npos || !parse_u64(command.substr(1, comma - 1), address) ||
            !parse_u64(command.substr(comma + 1), length) || length > max_memory || address > UINT64_MAX - length) return "E01";
        auto memory = state.session.read_memory(address, static_cast<std::size_t>(length));
        return memory ? hex_bytes(memory.value()) : "E01";
    }
    if (command.starts_with("M")) {
        const auto comma = command.find(','); const auto colon = command.find(':'); std::uint64_t address{}, length{};
        if (comma == std::string_view::npos || colon == std::string_view::npos || comma > colon ||
            !parse_u64(command.substr(1, comma - 1), address) || !parse_u64(command.substr(comma + 1, colon - comma - 1), length) ||
            length > max_memory || address > UINT64_MAX - length) return "E01";
        std::vector<std::byte> bytes;
        if (!decode_hex(command.substr(colon + 1), bytes, max_memory) || bytes.size() != length) return "E01";
        return state.session.write_memory(address, bytes) ? "OK" : "E01";
    }
    if (command.starts_with("X")) {
        const auto comma = command.find(',');
        const auto colon = command.find(':');
        std::uint64_t address{}, length{};
        if (comma == std::string_view::npos || colon == std::string_view::npos || comma > colon ||
            !parse_u64(command.substr(1, comma - 1), address) ||
            !parse_u64(command.substr(comma + 1, colon - comma - 1), length) ||
            !length || length > max_memory || length > std::numeric_limits<std::size_t>::max() ||
            address > UINT64_MAX - length || command.size() - colon - 1 != length)
            return "E01";
        const auto* data = reinterpret_cast<const std::byte*>(command.data() + colon + 1);
        return state.session.write_memory(address, std::span<const std::byte>(data, static_cast<std::size_t>(length)))
            ? "OK" : "E01";
    }
    if (command.size() >= 2 && (command[0] == 'Z' || command[0] == 'z') &&
        command[1] >= '0' && command[1] <= '4') {
        const bool insert = command[0] == 'Z';
        const auto first = command.find(','); const auto second = command.find(',', first + 1);
        std::uint64_t address{}, size{};
        if (first != 2 || second == std::string_view::npos || command.find(',', second + 1) != std::string_view::npos ||
            !parse_u64(command.substr(first + 1, second - first - 1), address) ||
            !parse_u64(command.substr(second + 1), size) || !size || size > 16 ||
            address > UINT64_MAX - (size - 1)) return "E01";
        auto kind = hexlab::debugger::BreakpointKind::software;
        switch (command[1]) {
        case '0': kind = hexlab::debugger::BreakpointKind::software; break;
        case '1': kind = hexlab::debugger::BreakpointKind::execute; break;
        case '2': kind = hexlab::debugger::BreakpointKind::write; break;
        case '3': kind = hexlab::debugger::BreakpointKind::read; break;
        case '4': kind = hexlab::debugger::BreakpointKind::access; break;
        }
        if (command[1] != '0' && !hardware_breakpoints_supported(state)) return {};
        const auto process = state.session.process();
        if (!process) return "E01";
        const bool arm64 = process->architecture == hexlab::Architecture::arm64;
        // Z0/Z1's kind is the instruction size on AArch64. DebugSession's
        // execute API instead uses size 1 for one hardware instruction slot.
        if (command[1] == '0' || command[1] == '1') {
            if (size != (arm64 ? 4u : 1u) || (arm64 && address % 4 != 0)) return "E01";
            if (command[1] == '1' && arm64) size = 1;
        }
        if (process->architecture == hexlab::Architecture::x86 && address > UINT32_MAX - (size - 1)) return "E01";
        const auto owned = state.session.breakpoints();
        if (insert) {
            if (std::any_of(owned.begin(), owned.end(), [&](const auto& breakpoint) {
                    return breakpoint.address == address && breakpoint.kind == kind && breakpoint.size == size;
                })) return "OK";
            auto breakpoint = state.session.add_breakpoint(address, kind, static_cast<std::uint8_t>(size));
            if (!breakpoint)
                return breakpoint.error().code == hexlab::ErrorCode::unsupported ? std::string{} : std::string("E01");
            if (breakpoint.value().size != size) {
                (void)state.session.remove_breakpoint(breakpoint.value().id);
                return "E01";
            }
            return "OK";
        }
        for (const auto& breakpoint : owned)
            if (breakpoint.address == address && breakpoint.kind == kind && breakpoint.size == size)
                return state.session.remove_breakpoint(breakpoint.id) ? "OK" : "E01";
        return "OK";
    }
    if (command == "D") {
        const bool detached = static_cast<bool>(state.session.detach());
        close_connection = detached; return detached ? "OK" : "E01";
    }
    if (command == "vKill" || command == "k")
        return {};
    if (command.starts_with("qSymbol")) return "OK";
    if (command == "vMustReplyEmpty") return {};
    return {};
}

std::optional<std::string> resume_and_wait(ServerState& state, std::string_view command) {
    auto request = parse_resume(command, state.continue_thread);
    if (!request) return std::string("E01");
    if (!state.event) return std::string("E01");
    if (state.target_exited) return stop_reply(state, *state.event);
    if (state.session.state() != hexlab::debugger::SessionState::stopped) return std::string("E01");
    auto disposition = hexlab::debugger::ContinueStatus::handled;
    if (request->signal && *request->signal != 0) {
        if (!state.session.supports_scheduled_signal_disposition() ||
            state.event->kind != EventKind::exception || *request->signal != state.event->code)
            return std::string("E01");
        disposition = hexlab::debugger::ContinueStatus::not_handled;
    }
    const auto& selection = request->thread;
    ResolvedResume resolved{};
    if (request->vcont) {
        auto schedule = resolve_resume_actions(state, request->actions);
        if (!schedule) return std::string("E01");
        resolved = std::move(*schedule);
    } else if (request->step) {
        if (!single_step_supported(state) || !state.event->thread) return std::string("E01");
        if (selection.kind == ThreadSelectionKind::specific && selection.id != state.event->thread)
            return std::string("E01");
        // The default vCont action and -1 match every thread. A single
        // event-thread operation only implements that request for a target
        // known to have exactly that one live thread. Selector 0 lets us
        // choose the event thread explicitly; it does not mean all threads.
        if (selection.kind == ThreadSelectionKind::all && !only_event_thread(state))
            return std::string("E01");
    } else {
        // Continue acknowledges the pending event and resumes the session.
        // Never reinterpret a thread-only request as this global operation.
        if (selection.kind == ThreadSelectionKind::specific) {
            if (selection.id != state.event->thread) return std::string("E01");
            request->continue_thread = true;
            request->selected_thread = selection.id;
        }
    }
    // Legacy resume addresses belong to the execution thread. Hg may point
    // at another register context and must never redirect this write.
    if (request->address && (!state.event->thread || !set_pc(state, state.event->thread, *request->address)))
        return std::string("E01");
    const auto sequence = state.event->sequence;
    auto resumed = request->vcont && !resolved.process_continue
        ? state.session.resume_threads(sequence, resolved.schedule) :
        request->step ? state.session.single_step_execution(sequence, disposition) :
        request->continue_thread ? state.session.continue_thread_execution(sequence, request->selected_thread,
            disposition) :
        state.session.continue_execution(sequence, disposition);
    // A one-thread schedule is equivalent to legacy stepping only after a
    // fresh listing proves that no peer could run. This retains the narrow
    // Darwin backend without making unsupported multi-thread plans global.
    if (!resumed && request->vcont && !resolved.process_continue &&
        resumed.error().code == hexlab::ErrorCode::unsupported && resolved.schedule.size() == 1 &&
        resolved.schedule.front().thread == state.event->thread &&
        resolved.schedule.front().kind == hexlab::debugger::ThreadResumeKind::single_step && only_event_thread(state))
        resumed = state.session.single_step_execution(sequence, disposition);
    // A process-wide continue is exactly equivalent when the selected event
    // thread is the target's only live thread, preserving older backends that
    // do not need a distinct thread-qualified operation in that case.
    if (!resumed && request->continue_thread && resumed.error().code == hexlab::ErrorCode::unsupported &&
        only_event_thread(state))
        resumed = state.session.continue_execution(sequence, disposition);
    if (!resumed) return "E01";
    state.memory_map_snapshot.reset();
    state.event.reset();
    if (!process_running(state)) return std::string("E01");
    return stop_reply(state, *state.event);
}

int serve(Socket socket, DebugSession& session, DebugEvent initial, bool attached_existing_process,
          std::string executable_path = {}) {
    RspConnection connection(socket);
    ServerState state{session, connection, attached_existing_process, std::move(executable_path)}; state.event = std::move(initial);
    state.target_exited = state.event->kind == EventKind::process_exited;
    if (!initialize_registers(state)) {
        std::cerr << "Debugger backend has no usable target thread/register context.\n";
        return 1;
    }
    bool running = true;
    while (running) {
        auto packet = connection.receive_packet();
        if (!packet) break;
        if (connection.interrupted()) {
            connection.clear_interrupt();
            if (session.state() == hexlab::debugger::SessionState::stopped && state.event)
                (void)connection.send_packet(stop_reply(state, *state.event));
            else if (session.state() == hexlab::debugger::SessionState::running) {
                auto requested = session.request_interrupt();
                if (requested || requested.error().code == hexlab::ErrorCode::busy) {
                    if (process_running(state) && state.event) (void)connection.send_packet(stop_reply(state, *state.event));
                    else (void)connection.send_packet("E01");
                } else (void)connection.send_packet("E01");
            }
            continue;
        }
        bool close_connection = false, toggle_no_ack = false;
        std::string response;
        if (packet->starts_with("c") || packet->starts_with("s") ||
            packet->starts_with("C") || packet->starts_with("S") ||
            *packet == "vCont" || packet->starts_with("vCont;")) {
            auto stop = resume_and_wait(state, *packet);
            if (!stop) continue;
            response = std::move(*stop);
        } else response = handle_command(state, *packet, close_connection, toggle_no_ack);
        if (!connection.send_packet(response)) break;
        if (toggle_no_ack) connection.set_no_ack();
        if (close_connection) running = false;
    }
    if (session.state() == hexlab::debugger::SessionState::running || session.state() == hexlab::debugger::SessionState::stopped)
        (void)session.detach();
    return 0;
}

int run(int argc, char** argv) {
    Options options; bool help = false;
    if (!parse_options(argc, argv, options, help)) { usage(std::cerr); return 2; }
    if (help) { usage(std::cout); return 0; }
    SocketRuntime runtime;
    if (!runtime) { std::cerr << "Winsock initialization failed.\n"; return 1; }
    auto listener = listen_tcp(options);
    if (!listener) { std::cerr << socket_error("TCP listener"); return 1; }
    std::cout << "HexLab debug server listening on " << options.bind << ':' << options.port
              << " (loopback is the default; clients control the target).\n";
    Socket accepted = invalid_socket;
    for (;;) {
#ifdef _WIN32
        fd_set ready; FD_ZERO(&ready); FD_SET(listener.get(), &ready);
        timeval timeout{1, 0}; const int selected = select(0, &ready, nullptr, nullptr, &timeout);
#else
        pollfd descriptor{listener.get(), POLLIN, 0}; const int selected = poll(&descriptor, 1, 1000);
#endif
        if (selected < 0) { std::cerr << socket_error("TCP accept wait"); return 1; }
        if (!selected) continue;
        accepted = ::accept(listener.get(), nullptr, nullptr);
        if (accepted != invalid_socket) break;
    }
    SocketOwner client(accepted);
    auto backend = hexlab::debugger::make_backend_router(hexlab::debugger::make_native_backend());
    if (!backend) { std::cerr << "Native debugger backend is unavailable on this platform.\n"; return 1; }
    DebugSession session(std::move(backend));
    hexlab::Result<hexlab::debugger::ProcessInfo> target = options.executable
        ? session.launch({*options.executable, options.arguments, options.working_directory})
        : session.attach(*options.attach);
    if (!target) { std::cerr << "Unable to start debug target: " << target.error().message << '\n'; return 1; }
    auto initial = session.wait_event(30s);
    if (!initial) { std::cerr << "No initial debug stop: " << initial.error().message << '\n'; (void)session.detach(); return 1; }
    std::cout << "Client connected; target " << target.value().name << " (pid " << target.value().id << ") is stopped.\n";
    return serve(client.get(), session, std::move(initial.value()), options.attach.has_value(),
        options.executable ? absolute_utf8_path(*options.executable) : std::string{});
}
} // namespace

#ifdef _WIN32
std::string utf8(const wchar_t* text) {
    const int length = WideCharToMultiByte(CP_UTF8, WC_ERR_INVALID_CHARS, text, -1, nullptr, 0, nullptr, nullptr);
    if (length <= 1) return {};
    std::string result(static_cast<std::size_t>(length), '\0');
    if (WideCharToMultiByte(CP_UTF8, WC_ERR_INVALID_CHARS, text, -1, result.data(), length, nullptr, nullptr) <= 0) return {};
    result.pop_back();
    return result;
}
int wmain(int argc, wchar_t** argv) {
    std::vector<std::string> converted; converted.reserve(static_cast<std::size_t>(argc));
    for (int i = 0; i < argc; ++i) converted.push_back(utf8(argv[i]));
    std::vector<char*> pointers; pointers.reserve(converted.size());
    for (auto& value : converted) pointers.push_back(value.data());
    return run(argc, pointers.data());
}
#else
int main(int argc, char** argv) { return run(argc, argv); }
#endif
