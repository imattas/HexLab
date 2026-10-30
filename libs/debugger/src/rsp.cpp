#include "hexlab/debugger/rsp.hpp"

#include <algorithm>
#include <array>
#include <bit>
#include <charconv>
#include <iterator>
#include <limits>
#include <new>
#include <set>
#include <stdexcept>

namespace hexlab::debugger::rsp {
namespace {
constexpr std::size_t max_pending_notifications = 4096;
constexpr std::size_t max_pending_console_output = 1024 * 1024;
Error io_error(std::string message) { return {ErrorCode::io, std::move(message)}; }
int hex_digit(char c) {
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}
bool is_console_output_payload(std::string_view payload) {
    if (payload.size() < 3 || payload.front() != 'O' || (payload.size() - 1) % 2 != 0)
        return false;
    return std::all_of(payload.begin() + 1, payload.end(), [](char c) { return hex_digit(c) >= 0; });
}
template<class T> bool parse_hex(std::string_view value, T& out) {
    if (value.empty()) return false;
    const auto [end, ec] = std::from_chars(value.data(), value.data() + value.size(), out, 16);
    return ec == std::errc{} && end == value.data() + value.size();
}
bool parse_thread_id(std::string_view value, std::uint64_t& out) {
    if (value.starts_with('p')) {
        value.remove_prefix(1);
        const auto dot = value.find('.');
        if (dot == std::string_view::npos || dot == 0 || dot + 1 == value.size()) return false;
        std::uint64_t process = 0;
        if (!parse_hex(value.substr(0, dot), process)) return false;
        value.remove_prefix(dot + 1);
    } else if (value.find('.') != std::string_view::npos) {
        return false;
    }
    return parse_hex(value, out);
}
std::optional<std::uint64_t> process_id_from_thread_id(std::string_view value) {
    if (!value.starts_with('p')) return std::nullopt;
    value.remove_prefix(1);
    const auto dot = value.find('.');
    if (dot == std::string_view::npos || dot == 0 || dot + 1 == value.size()) return std::nullopt;
    std::uint64_t process = 0;
    if (!parse_hex(value.substr(0, dot), process) || process == 0) return std::nullopt;
    return process;
}
bool valid_thread_selection_id(std::string_view value) {
    if (value == "-1" || value == "0") return true;
    if (!value.starts_with('p')) {
        std::uint64_t thread = 0;
        return parse_hex(value, thread) && (thread != 0 || value == "0");
    }
    value.remove_prefix(1);
    const auto dot = value.find('.');
    if (dot == std::string_view::npos || dot == 0 || dot + 1 == value.size()) return false;
    std::uint64_t process = 0;
    if (!parse_hex(value.substr(0, dot), process) || process == 0) return false;
    const auto thread_id = value.substr(dot + 1);
    if (thread_id == "-1" || thread_id == "0") return true;
    std::uint64_t thread = 0;
    return parse_hex(thread_id, thread) && thread != 0;
}
std::string hex_u64(std::uint64_t value) {
    std::array<char, 16> buffer{};
    auto [end, ec] = std::to_chars(buffer.data(), buffer.data() + buffer.size(), value, 16);
    return ec == std::errc{} ? std::string(buffer.data(), end) : std::string{};
}
Result<std::vector<std::byte>> decode_hex(std::string_view data) {
    if ((data.size() & 1U) != 0) return Error{ErrorCode::malformed, "RSP hex payload has odd length"};
    std::vector<std::byte> result;
    result.reserve(data.size() / 2);
    for (std::size_t i = 0; i < data.size(); i += 2) {
        const int hi = hex_digit(data[i]), lo = hex_digit(data[i + 1]);
        if (hi < 0 || lo < 0) return Error{ErrorCode::malformed, "RSP payload contains non-hex byte"};
        result.push_back(static_cast<std::byte>((hi << 4) | lo));
    }
    return result;
}
struct FileIoReply {
    std::int64_t result = 0;
    std::optional<std::uint64_t> error_number;
    std::string_view attachment;
    bool has_attachment = false;
};
Result<FileIoReply> parse_file_io_reply(std::string_view response) {
    if (response.empty() || response.front() != 'F')
        return Error{ErrorCode::malformed, "invalid RSP vFile reply"};
    response.remove_prefix(1);
    const auto attachment_at = response.find(';');
    const auto fields = response.substr(0, attachment_at);
    const auto separator = fields.find(',');
    const auto raw_result = fields.substr(0, separator);
    if (raw_result.empty()) return Error{ErrorCode::malformed, "RSP vFile reply has no result"};
    const bool negative = raw_result.front() == '-';
    const auto digits = negative ? raw_result.substr(1) : raw_result;
    std::uint64_t magnitude = 0;
    if (digits.empty() || !parse_hex(digits, magnitude) ||
        magnitude > static_cast<std::uint64_t>(INT64_MAX) + (negative ? 1u : 0u))
        return Error{ErrorCode::malformed, "invalid RSP vFile result"};
    FileIoReply parsed;
    parsed.result = negative
        ? (magnitude == static_cast<std::uint64_t>(INT64_MAX) + 1 ? INT64_MIN : -static_cast<std::int64_t>(magnitude))
        : static_cast<std::int64_t>(magnitude);
    if (separator != std::string_view::npos) {
        if (fields.find(',', separator + 1) != std::string_view::npos)
            return Error{ErrorCode::malformed, "invalid RSP vFile errno"};
        std::uint64_t error_number = 0;
        if (!parse_hex(fields.substr(separator + 1), error_number))
            return Error{ErrorCode::malformed, "invalid RSP vFile errno"};
        parsed.error_number = error_number;
    }
    parsed.has_attachment = attachment_at != std::string_view::npos;
    if (parsed.has_attachment) parsed.attachment = response.substr(attachment_at + 1);
    return parsed;
}
Result<RemoteFileStat> parse_remote_file_stat(std::string_view response, std::string_view operation) {
    auto reply = parse_file_io_reply(response);
    if (!reply) return reply.error();
    if (reply.value().result < 0)
        return Error{ErrorCode::io, "remote " + std::string(operation) + " failed with errno " +
            std::to_string(reply.value().error_number.value_or(0))};
    constexpr std::size_t stat_bytes = 64;
    if (reply.value().result != static_cast<std::int64_t>(stat_bytes) ||
        !reply.value().has_attachment || reply.value().attachment.size() != stat_bytes)
        return Error{ErrorCode::malformed, "RSP " + std::string(operation) + " must return exactly 64 attachment bytes"};
    const auto bytes = std::as_bytes(std::span(reply.value().attachment.data(), reply.value().attachment.size()));
    const auto read_u32 = [&](std::size_t offset) {
        std::uint32_t value = 0;
        for (std::size_t i = 0; i < 4; ++i)
            value = (value << 8) | std::to_integer<std::uint8_t>(bytes[offset + i]);
        return value;
    };
    const auto read_u64 = [&](std::size_t offset) {
        std::uint64_t value = 0;
        for (std::size_t i = 0; i < 8; ++i)
            value = (value << 8) | std::to_integer<std::uint8_t>(bytes[offset + i]);
        return value;
    };
    return RemoteFileStat{
        read_u32(0), read_u32(4), read_u32(8), read_u32(12),
        read_u32(16), read_u32(20), read_u32(24),
        read_u64(28), read_u64(36), read_u64(44),
        std::bit_cast<std::int32_t>(read_u32(52)),
        std::bit_cast<std::int32_t>(read_u32(56)),
        std::bit_cast<std::int32_t>(read_u32(60))};
}
std::string encode_hex(std::span<const std::byte> bytes) {
    constexpr char digits[] = "0123456789abcdef";
    std::string out; out.reserve(bytes.size() * 2);
    for (auto b : bytes) { auto c = std::to_integer<unsigned>(b); out += digits[c >> 4]; out += digits[c & 15]; }
    return out;
}
Result<StopReply> parse_stop(std::string_view s) {
    if (s.empty()) return Error{ErrorCode::malformed, "empty RSP stop reply"};
    StopReply result; result.kind = s[0];
    if (s[0] == 'W' || s[0] == 'X') {
        if (s.size() < 3 || !parse_hex(s.substr(1, 2), result.exit_code)) return Error{ErrorCode::malformed, "invalid RSP exit reply"};
        if (s.size() > 3 && s[3] != ';') return Error{ErrorCode::malformed, "invalid RSP exit fields"};
    } else {
        if (s[0] != 'T' && s[0] != 'S') return Error{ErrorCode::malformed, "unsupported RSP stop reply"};
        if (s.size() < 3 || !parse_hex(s.substr(1, 2), result.signal)) return Error{ErrorCode::malformed, "invalid RSP stop signal"};
    }
    std::string_view fields = s.substr(3);
    while (!fields.empty()) {
        auto end = fields.find(';'); auto item = fields.substr(0, end);
        auto colon = item.find(':');
        if (colon != std::string_view::npos) {
            std::string key(item.substr(0, colon)), val(item.substr(colon + 1));
            if (key == "thread" && !parse_thread_id(val, result.thread)) return Error{ErrorCode::malformed, "invalid RSP stop thread"};
            // Watchpoint reasons carry an address, not arbitrary opaque text.
            // Validate here so malformed stop packets cannot be mistaken for
            // owned watchpoint hits later in the backend.
            if (key == "watch" || key == "rwatch" || key == "awatch") {
                std::uint64_t address = 0;
                if (val.empty() || val.size() > 16 || !parse_hex(val, address) || result.fields.contains(key))
                    return Error{ErrorCode::malformed, "invalid or duplicate RSP watchpoint stop address"};
            }
            if (key == "process") {
                std::uint64_t process = 0;
                if (val.size() > 16 || !parse_hex(val, process) || !process || result.fields.contains(key))
                    return Error{ErrorCode::malformed, "invalid RSP stop process"};
            }
            if (!result.fields.emplace(std::move(key), std::move(val)).second)
                return Error{ErrorCode::malformed, "duplicate RSP stop field"};
        }
        if (end == std::string_view::npos) break; fields.remove_prefix(end + 1);
    }
    return result;
}
}

std::string encode_packet(std::string_view payload) {
    constexpr char digits[] = "0123456789abcdef";
    std::string frame; frame.reserve(payload.size() + 4); frame += '$';
    unsigned checksum = 0;
    for (unsigned char c : payload) {
        if (c == '$' || c == '#' || c == '}' || c == '*') { frame += '}'; checksum = (checksum + '}') & 0xff; c ^= 0x20; }
        frame += static_cast<char>(c); checksum = (checksum + c) & 0xff;
    }
    frame += '#'; frame += digits[checksum >> 4]; frame += digits[checksum & 15];
    return frame;
}
Result<std::string> decode_packet(std::string_view frame, std::size_t max_decoded_payload) {
    if (frame.size() < 4 || frame.front() != '$') return Error{ErrorCode::malformed, "invalid RSP packet framing"};
    std::size_t hash = std::string_view::npos;
    bool escaped = false;
    for (std::size_t i = 1; i < frame.size(); ++i) {
        if (!escaped && frame[i] == '#') { hash = i; break; }
        if (!escaped && frame[i] == '}') escaped = true; else escaped = false;
    }
    if (hash == std::string_view::npos || hash + 3 != frame.size()) return Error{ErrorCode::malformed, "truncated RSP checksum"};
    const int hi = hex_digit(frame[hash + 1]), lo = hex_digit(frame[hash + 2]);
    if (hi < 0 || lo < 0) return Error{ErrorCode::malformed, "invalid RSP checksum digits"};
    unsigned checksum = 0;
    for (std::size_t i = 1; i < hash; ++i) checksum = (checksum + static_cast<unsigned char>(frame[i])) & 0xff;
    if (checksum != static_cast<unsigned>((hi << 4) | lo)) return Error{ErrorCode::integrity, "RSP checksum mismatch"};
    std::string unescaped; unescaped.reserve(hash - 1);
    std::vector<bool> escaped_bytes;
    escaped_bytes.reserve(hash - 1);
    escaped = false;
    for (std::size_t i = 1; i < hash; ++i) {
        unsigned char c = static_cast<unsigned char>(frame[i]);
        if (c == '}') {
            if (++i >= hash) return Error{ErrorCode::malformed, "truncated RSP escape"};
            c = static_cast<unsigned char>(frame[i]) ^ 0x20;
            unescaped += static_cast<char>(c);
            escaped_bytes.push_back(true);
            continue;
        }
        unescaped += static_cast<char>(c);
        escaped_bytes.push_back(false);
    }
    std::string payload;
    payload.reserve(std::min(unescaped.size(), max_decoded_payload));
    for (std::size_t i = 0; i < unescaped.size(); ++i) {
        const auto byte = static_cast<unsigned char>(unescaped[i]);
        if (byte != '*' || escaped_bytes[i]) {
            if (payload.size() == max_decoded_payload)
                return Error{ErrorCode::resource_limit, "decoded RSP payload exceeds configured limit"};
            payload += static_cast<char>(byte);
            continue;
        }
        if (payload.empty() || i + 1 >= unescaped.size() || escaped_bytes[i + 1])
            return Error{ErrorCode::malformed, "invalid RSP run-length sequence"};
        const auto count_byte = static_cast<unsigned char>(unescaped[++i]);
        // GDB encodes the number of additional copies as n + 29. Values below
        // three are not useful compression and reserved wire delimiters are invalid.
        if (count_byte < 32 || count_byte > 126 || count_byte == '$' || count_byte == '#' ||
            count_byte == '+' || count_byte == '-')
            return Error{ErrorCode::malformed, "invalid RSP run-length count"};
        const auto additional = static_cast<std::size_t>(count_byte - 29);
        if (additional < 3 || additional > max_decoded_payload - std::min(payload.size(), max_decoded_payload))
            return Error{additional < 3 ? ErrorCode::malformed : ErrorCode::resource_limit,
                additional < 3 ? "RSP run-length count is below the encoding threshold" :
                                 "decoded RSP payload exceeds configured limit"};
        payload.append(additional, payload.back());
    }
    return payload;
}

Client::Client(ByteTransport& transport, std::chrono::milliseconds timeout, std::size_t max_packet)
    : transport_(transport), timeout_(timeout), max_packet_(max_packet),
      peer_packet_size_(std::min<std::size_t>(max_packet, 4096)) {}
Status Client::write_all(std::string_view bytes, Deadline deadline, std::stop_token stop) {
    std::size_t offset = 0;
    while (offset < bytes.size()) {
        if (stop.stop_requested()) return Error{ErrorCode::canceled, "RSP operation canceled"};
        if (std::chrono::steady_clock::now() >= deadline) return io_error("RSP write timed out");
        auto wrote = transport_.write_some(std::as_bytes(std::span(bytes.data() + offset, bytes.size() - offset)), deadline, stop);
        if (!wrote) return wrote.error();
        if (wrote.value() == 0 || wrote.value() > bytes.size() - offset) return io_error("RSP transport made invalid write progress");
        offset += wrote.value();
    }
    return std::monostate{};
}
Result<unsigned char> Client::read_byte(Deadline deadline, std::stop_token stop) {
    std::byte b{};
    while (true) {
        if (stop.stop_requested()) return Error{ErrorCode::canceled, "RSP operation canceled"};
        auto n = transport_.read_some(std::span(&b, 1), deadline, stop);
        if (!n) return n.error();
        if (n.value() != 1) return io_error("RSP transport returned no data");
        return std::to_integer<unsigned char>(b);
    }
}
Result<std::pair<bool, std::string>> Client::read_packet_after_start(
    unsigned char marker, Deadline deadline, std::stop_token stop) {
    if (marker != '$' && marker != '%')
        return Error{ErrorCode::invalid_argument, "RSP packet start marker is invalid"};
    const bool notification = marker == '%';
    std::string frame(1, static_cast<char>(marker));
    bool escaped = false;
    for (;;) {
        auto byte = read_byte(deadline, stop); if (!byte) return byte.error();
        const char c = static_cast<char>(byte.value()); frame += c;
        if (frame.size() > max_packet_ + 4)
            return Error{ErrorCode::resource_limit, "RSP packet exceeds configured limit"};
        if (!escaped && c == '#') {
            for (int i = 0; i < 2; ++i) {
                auto digit = read_byte(deadline, stop); if (!digit) return digit.error();
                frame += static_cast<char>(digit.value());
            }
            if (notification) frame.front() = '$';
            auto payload = decode_packet(frame, max_packet_);
            if (!payload) return payload.error();
            return std::pair{notification, std::move(payload.value())};
        }
        if (!escaped && c == '}') escaped = true; else escaped = false;
    }
}
Status Client::queue_stop_notification(std::string payload) {
    if (pending_notifications_.size() >= max_pending_notifications ||
        pending_notification_bytes_ > max_packet_ ||
        payload.size() > max_packet_ - pending_notification_bytes_)
        return Error{ErrorCode::resource_limit, "RSP pending stop notifications exceed configured limit"};
    pending_notification_bytes_ += payload.size();
    pending_notifications_.push_back(std::move(payload));
    return std::monostate{};
}
Status Client::queue_console_output(std::string_view payload) {
    if (payload.empty() || payload.front() != 'O')
        return Error{ErrorCode::malformed, "invalid RSP console-output packet"};
    auto decoded = decode_hex(payload.substr(1));
    if (!decoded) return decoded.error();
    if (decoded.value().size() > max_pending_console_output -
        std::min(pending_console_output_.size(), max_pending_console_output))
        return Error{ErrorCode::resource_limit, "RSP pending console output exceeds 1 MiB"};
    pending_console_output_.insert(pending_console_output_.end(), decoded.value().begin(), decoded.value().end());
    return std::monostate{};
}
std::vector<std::byte> Client::take_console_output(std::size_t limit) {
    const auto count = std::min(limit, pending_console_output_.size());
    std::vector<std::byte> result;
    result.reserve(count);
    for (std::size_t i = 0; i < count; ++i) {
        result.push_back(pending_console_output_.front());
        pending_console_output_.pop_front();
    }
    return result;
}
Result<bool> Client::read_ack(Deadline deadline, std::stop_token stop) {
    for (;;) {
        auto byte = read_byte(deadline, stop); if (!byte) return byte.error();
        if (byte.value() == '+') return true;
        if (byte.value() == '-') return false;
        if (byte.value() != '%' && byte.value() != '$') continue;
        const auto start = byte.value();
        auto packet = read_packet_after_start(start, deadline, stop);
        if (!packet) {
            if (start == '%' && packet.error().code != ErrorCode::resource_limit &&
                packet.error().code != ErrorCode::canceled && packet.error().code != ErrorCode::io)
                continue;
            return packet.error();
        }
        if (!packet.value().first) {
            auto payload = std::move(packet.value().second);
            if (!is_console_output_payload(payload))
                return Error{ErrorCode::malformed, "RSP response packet arrived before its acknowledgement"};
            auto queued = queue_console_output(payload);
            if (!queued) return queued.error();
            const char response = '+';
            auto sent = write_all(std::string_view(&response, 1), deadline, stop);
            if (!sent) return sent.error();
            continue;
        }
        auto payload = std::move(packet.value().second);
        if (payload.starts_with("Stop:")) {
            payload.erase(0, 5);
            auto queued = queue_stop_notification(std::move(payload));
            if (!queued) return queued.error();
        }
    }
}
Result<std::string> Client::receive_packet(Deadline deadline, std::stop_token stop, bool accept_notifications,
                                           bool *was_notification) {
    if (was_notification) *was_notification = false;
    for (;;) {
        auto start = read_byte(deadline, stop); if (!start) return start.error();
        if (start.value() != '$' && start.value() != '%') continue;
        auto packet = read_packet_after_start(start.value(), deadline, stop);
        const bool notification = start.value() == '%';
        if (!packet) {
            if (packet.error().code == ErrorCode::resource_limit ||
                packet.error().code == ErrorCode::canceled ||
                packet.error().code == ErrorCode::io ||
                packet.error().code == ErrorCode::busy)
                return packet.error();
            if (notification) continue;
            if (no_ack_mode_) return packet.error();
            const char response = '-';
            const auto ack_deadline = std::max(deadline, std::chrono::steady_clock::now() + timeout_);
            auto sent = write_all(std::string_view(&response, 1), ack_deadline, stop); if (!sent) return sent.error();
            continue;
        }
        auto payload = std::move(packet.value().second);
        if (notification) {
            if (!payload.starts_with("Stop:")) continue;
            payload.erase(0, 5);
            if (accept_notifications) {
                if (was_notification) *was_notification = true;
                return payload;
            }
            auto queued = queue_stop_notification(std::move(payload));
            if (!queued) return queued.error();
            continue;
        }
        if (is_console_output_payload(payload)) {
            auto queued = queue_console_output(payload);
            if (!queued) return queued.error();
            if (!no_ack_mode_) {
                const char response = '+';
                const auto ack_deadline = std::max(deadline, std::chrono::steady_clock::now() + timeout_);
                auto sent = write_all(std::string_view(&response, 1), ack_deadline, stop);
                if (!sent) return sent.error();
            }
            continue;
        }
        if (no_ack_mode_) return payload;
        const char response = '+';
        const auto ack_deadline = std::max(deadline, std::chrono::steady_clock::now() + timeout_);
        auto sent = write_all(std::string_view(&response, 1), ack_deadline, stop); if (!sent) return sent.error();
        return payload;
    }
}
Result<std::string> Client::transact(std::string_view command, std::stop_token stop) {
    return transact_until(command, std::chrono::steady_clock::now() + timeout_, stop);
}
Result<std::string> Client::transact_until(std::string_view command, Deadline deadline, std::stop_token stop) {
    if (command.size() > max_packet_) return Error{ErrorCode::resource_limit, "RSP command exceeds configured limit"};
    const auto packet = encode_packet(command);
    // PacketSize limits the transmitted payload, after RSP escaping. Escaping
    // can double bytes such as '$', '#', '}' and '*', so checking only the
    // caller's unescaped command can exceed either negotiated ceiling.
    const auto encoded_payload_size = packet.size() - 4; // '$' + payload + '#' + checksum
    if (encoded_payload_size > max_packet_ || encoded_payload_size > peer_packet_size_)
        return Error{ErrorCode::resource_limit, "encoded RSP command exceeds the negotiated packet limit"};
    for (unsigned attempt = 0; attempt < 3; ++attempt) {
        auto sent = write_all(packet, deadline, stop); if (!sent) return sent.error();
        if (!no_ack_mode_) {
            auto ack = read_ack(deadline, stop); if (!ack) return ack.error();
            if (!ack.value()) continue;
        }
        return receive_packet(deadline, stop);
    }
    return io_error("RSP peer rejected packet after three attempts");
}
Result<std::string> Client::request(std::string_view command, std::stop_token stop) { return transact(command, stop); }

Result<Capabilities> Client::negotiate(std::stop_token stop) {
    return negotiate(stop, true);
}
Result<Capabilities> Client::negotiate(std::stop_token stop, bool request_no_ack) {
    memory_tagging_supported_ = false;
    auto supported = transact("qSupported:multiprocess+;swbreak+;hwbreak+;vContSupported+;QThreadEvents+;QPassSignals+;memory-tagging+", stop);
    if (!supported) return supported.error();
    Capabilities result;
    std::string_view rest = supported.value();
    while (!rest.empty()) {
        auto end = rest.find(';'); auto token = rest.substr(0, end);
        if (token.empty()) return Error{ErrorCode::malformed, "qSupported contains an empty feature token"};
        auto split = token.find('=');
        auto name = token.substr(0, split);
        auto value = split == std::string_view::npos ? std::string{} : std::string(token.substr(split + 1));
        bool boolean_feature = false;
        if (split == std::string_view::npos && !name.empty() && (name.back() == '+' || name.back() == '-')) {
            value = name.back(); name.remove_suffix(1);
            boolean_feature = true;
        }
        if (name.empty() || name.find_first_not_of("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789_.:-") !=
                                std::string_view::npos)
            return Error{ErrorCode::malformed, "qSupported contains an invalid feature name"};
        if (split == std::string_view::npos && !boolean_feature)
            return Error{ErrorCode::malformed, "qSupported feature lacks a value or support marker"};
        if (split != std::string_view::npos &&
            (value.empty() || value.find_first_of("=\r\n") != std::string::npos ||
             std::any_of(value.begin(), value.end(), [](unsigned char ch) { return ch < 0x21 || ch > 0x7e; })))
            return Error{ErrorCode::malformed, "qSupported contains an invalid feature value"};
        if ((name == "QNonStop" || name == "QThreadEvents" || name == "QPassSignals" || name == "QStartNoAckMode" ||
             name == "memory-tagging" ||
             name == "QSetWorkingDir" || name == "QEnvironmentReset" ||
             name == "QEnvironmentHexEncoded" || name == "QEnvironmentUnset") && !boolean_feature)
            return Error{ErrorCode::malformed, "qSupported boolean feature has no support marker"};
        if (name == "PacketSize") {
            std::size_t advertised = 0;
            if (boolean_feature || split == std::string_view::npos || !parse_hex(value, advertised) || advertised == 0)
                return Error{ErrorCode::malformed, "qSupported PacketSize is not a nonzero hexadecimal value"};
        }
        if (!result.features.emplace(std::string(name), std::move(value)).second)
            return Error{ErrorCode::malformed, "qSupported repeats a feature token"};
        if (end == std::string_view::npos) break; rest.remove_prefix(end + 1);
    }
    if (const auto feature = result.features.find("QNonStop"); feature != result.features.end())
        result.non_stop_supported = feature->second == "+";
    if (const auto feature = result.features.find("QThreadEvents"); feature != result.features.end())
        result.thread_events_supported = feature->second == "+";
    if (const auto feature = result.features.find("QPassSignals"); feature != result.features.end())
        result.pass_signals_supported = feature->second == "+";
    thread_events_supported_ = result.thread_events_supported;
    pass_signals_supported_ = result.pass_signals_supported;
    non_stop_supported_ = result.non_stop_supported;
    const auto working_directory = result.features.find("QSetWorkingDir");
    working_directory_supported_ = working_directory != result.features.end() && working_directory->second == "+";
    const auto feature_enabled = [&](std::string_view name) {
        const auto feature = result.features.find(name);
        return feature != result.features.end() && feature->second == "+";
    };
    memory_tagging_supported_ = feature_enabled("memory-tagging");
    result.memory_tagging_supported = memory_tagging_supported_;
    environment_reset_supported_ = feature_enabled("QEnvironmentReset");
    environment_set_supported_ = feature_enabled("QEnvironmentHexEncoded");
    environment_unset_supported_ = feature_enabled("QEnvironmentUnset");
    peer_packet_size_ = std::min<std::size_t>(max_packet_, 4096);
    if (const auto feature = result.features.find("PacketSize"); feature != result.features.end()) {
        std::size_t advertised = 0;
        // PacketSize was fully validated while parsing the feature list.
        (void)parse_hex(feature->second, advertised);
        peer_packet_size_ = std::min(max_packet_, advertised);
    }
    if (request_no_ack) if (const auto feature = result.features.find("QStartNoAckMode");
        feature != result.features.end() && feature->second != "-") {
        auto response = transact("QStartNoAckMode", stop);
        if (!response) return response.error();
        if (response.value() == "OK") { no_ack_mode_ = true; result.no_ack_mode = true; }
    }
    return result;
}
Status Client::set_non_stop_mode(bool enabled, std::stop_token stop) {
    if (enabled && !non_stop_supported_)
        return Error{ErrorCode::unsupported, "remote did not advertise QNonStop support"};
    if (enabled == non_stop_mode_) return std::monostate{};
    auto response = transact(enabled ? "QNonStop:1" : "QNonStop:0", stop);
    if (!response) return response.error();
    if (response.value() != "OK")
        return response.value().empty()
            ? Status{Error{ErrorCode::unsupported, "remote rejected non-stop mode negotiation"}}
            : Status{Error{ErrorCode::io, "remote rejected non-stop mode change: " + response.value()}};
    non_stop_mode_ = enabled;
    stop_reply_sequence_active_ = false;
    return std::monostate{};
}
Status Client::set_thread_events(bool enabled, std::stop_token stop) {
    if (enabled && !thread_events_supported_)
        return Error{ErrorCode::unsupported, "remote did not advertise QThreadEvents support"};
    if (enabled == thread_events_enabled_) return std::monostate{};
    auto response = transact(enabled ? "QThreadEvents:1" : "QThreadEvents:0", stop);
    if (!response) return response.error();
    if (response.value() != "OK")
        return response.value().empty()
            ? Status{Error{ErrorCode::unsupported, "remote rejected thread-event notifications"}}
            : Status{Error{ErrorCode::io, "remote rejected thread-event mode change: " + response.value()}};
    thread_events_enabled_ = enabled;
    return std::monostate{};
}
Status Client::set_pass_signals(std::span<const unsigned> signals, std::stop_token stop) {
    if (!pass_signals_supported_)
        return Error{ErrorCode::unsupported, "remote did not advertise QPassSignals support"};
    if (signals.empty() || signals.size() > 256)
        return Error{ErrorCode::invalid_argument, "QPassSignals requires 1 to 256 signal numbers"};
    std::string command = "QPassSignals:";
    unsigned previous = 0;
    bool first = true;
    for (const auto signal : signals) {
        if (signal > 255 || (!first && signal <= previous))
            return Error{ErrorCode::invalid_argument,
                         "QPassSignals values must be strictly increasing 8-bit signal numbers"};
        if (!first) command.push_back(';');
        command += hex_u64(signal);
        previous = signal;
        first = false;
    }
    if (command.size() > peer_packet_size_)
        return Error{ErrorCode::resource_limit, "QPassSignals list exceeds the negotiated PacketSize"};
    auto response = transact(command, stop);
    if (!response) return response.error();
    if (response.value() != "OK")
        return response.value().empty()
            ? Status{Error{ErrorCode::unsupported, "remote rejected QPassSignals"}}
            : Status{Error{ErrorCode::io, "remote rejected QPassSignals: " + response.value()}};
    return std::monostate{};
}
Result<StopReply> Client::read_stop_reply(std::stop_token stop) {
    auto response = read_stop_reply_optional(stop);
    if (!response) return response.error();
    if (!response.value()) return Error{ErrorCode::unsupported, "remote reports no stopped thread"};
    return std::move(*response.value());
}
Result<std::optional<StopReply>> Client::read_stop_reply_optional(std::stop_token stop) {
    auto response = transact("?", stop); if (!response) return response.error();
    if (response.value() == "OK") return std::optional<StopReply>{};
    auto parsed = parse_stop(response.value());
    if (!parsed) return parsed.error();
    if (non_stop_mode_) stop_reply_sequence_active_ = true;
    return std::optional<StopReply>{std::move(parsed.value())};
}
Result<StopReply> Client::wait_stop_reply(std::chrono::milliseconds timeout, std::stop_token stop) {
    if (timeout.count() < 0) return Error{ErrorCode::invalid_argument, "RSP stop wait timeout cannot be negative"};
    const auto deadline = std::chrono::steady_clock::now() + timeout;
    for (;;) {
        if (non_stop_mode_ && stop_reply_sequence_active_) {
            if (std::chrono::steady_clock::now() >= deadline)
                return Error{ErrorCode::busy, "remote target has not stopped yet"};
            auto response = transact_until("vStopped", deadline, stop);
            if (!response) return response.error();
            if (response.value() == "OK") {
                stop_reply_sequence_active_ = false;
                continue;
            }
            auto parsed = parse_stop(response.value());
            if (!parsed) return parsed.error();
            return parsed;
        }
        if (!pending_notifications_.empty()) {
            auto response = std::move(pending_notifications_.front()); pending_notifications_.pop_front();
            pending_notification_bytes_ -= response.size();
            if (non_stop_mode_) stop_reply_sequence_active_ = true;
            return parse_stop(response);
        }
        bool notification = false;
        auto response = receive_packet(deadline, stop, true, &notification);
        if (!response) return response.error();
        if (notification && non_stop_mode_) stop_reply_sequence_active_ = true;
        return parse_stop(response.value());
    }
}
Status Client::send_resume(std::string_view command, std::stop_token stop) {
    const auto hex_digits = [](std::string_view value) {
        return !value.empty() && value.find_first_not_of("0123456789abcdefABCDEF") == std::string_view::npos;
    };
    const bool legacy_continue_or_step = (command == "c" || command == "s") ||
        ((command.starts_with('c') || command.starts_with('s')) && command.size() <= 17 && hex_digits(command.substr(1)));
    const bool legacy_signal_prefix = command.size() >= 3 &&
        (command.front() == 'C' || command.front() == 'S') && hex_digits(command.substr(1, 2));
    const bool legacy_signal_resume = legacy_signal_prefix && (command.size() == 3 ||
        (command[3] == ';' && command.size() > 4 && command.size() - 4 <= 16 && hex_digits(command.substr(4))));
    if (command.empty() || command.size() > max_packet_ ||
        !(legacy_continue_or_step || legacy_signal_resume || command.starts_with("vCont;")))
        return Error{ErrorCode::invalid_argument, "invalid RSP resume command"};
    if (command.starts_with("vCont;")) {
        auto actions = command.substr(6);
        if (actions.empty()) return Error{ErrorCode::invalid_argument, "empty RSP vCont action list"};
        std::set<std::string_view, std::less<>> selectors;
        while (!actions.empty()) {
            const auto end = actions.find(';');
            const auto action = actions.substr(0, end);
            if (action.empty() || (action.front() != 'c' && action.front() != 's' && action.front() != 't' &&
                action.front() != 'C' && action.front() != 'S'))
                return Error{ErrorCode::invalid_argument, "invalid RSP vCont action list"};
            const auto colon = action.find(':');
            const auto kind = colon == std::string_view::npos ? action : action.substr(0, colon);
            const bool signal_action = kind.size() == 3 && (kind.front() == 'C' || kind.front() == 'S') &&
                hex_digits(kind.substr(1));
            if (kind != "c" && kind != "s" && kind != "t" && !signal_action)
                return Error{ErrorCode::invalid_argument, "invalid RSP vCont action kind"};
            if (colon == std::string_view::npos) {
                if (kind != "c" && kind != "s" && !signal_action)
                    return Error{ErrorCode::invalid_argument, "unqualified RSP vCont action is not supported"};
            } else {
                const auto selector = action.substr(colon + 1);
                const auto valid_hex_id = [](std::string_view value) {
                    std::uint64_t parsed = 0;
                    return !value.empty() && value.size() <= 16 &&
                        value.find_first_not_of("0123456789abcdefABCDEF") == std::string_view::npos &&
                        parse_hex(value, parsed) && parsed != 0;
                };
                bool valid_selector = false;
                if (selector.starts_with('p')) {
                    const auto qualified = selector.substr(1);
                    const auto dot = qualified.find('.');
                    if (dot != std::string_view::npos && valid_hex_id(qualified.substr(0, dot))) {
                        const auto thread = qualified.substr(dot + 1);
                        valid_selector = (thread == "-1" && (kind == "c" || kind == "C")) || valid_hex_id(thread);
                    }
                } else {
                    valid_selector = valid_hex_id(selector);
                }
                if (!valid_selector)
                    return Error{ErrorCode::invalid_argument, "invalid RSP vCont thread selector"};
                if (!selectors.insert(selector).second)
                    return Error{ErrorCode::invalid_argument, "duplicate thread selector in RSP vCont schedule"};
            }
            if (end == std::string_view::npos) break;
            if (end + 1 == actions.size())
                return Error{ErrorCode::invalid_argument, "trailing separator in RSP vCont action list"};
            actions.remove_prefix(end + 1);
        }
    }
    const auto deadline = std::chrono::steady_clock::now() + timeout_;
    const auto packet = encode_packet(command);
    // In non-stop mode a resume request has an ordinary packet reply (OK),
    // even though it does not wait for the target to stop. Consume that reply
    // here so it cannot be mistaken for a later stop reply. receive_packet()
    // queues any interleaved %Stop notifications while waiting.
    if (non_stop_mode_ && command.starts_with("vCont;")) {
        for (unsigned attempt = 0; attempt < 3; ++attempt) {
            auto sent = write_all(packet, deadline, stop); if (!sent) return sent;
            if (!no_ack_mode_) {
                auto ack = read_ack(deadline, stop); if (!ack) return ack.error();
                if (!ack.value()) continue;
            }
            auto response = receive_packet(deadline, stop);
            if (!response) return response.error();
            if (response.value() == "OK") return std::monostate{};
            return Error{ErrorCode::io, "remote rejected non-stop vCont resume: " + response.value()};
        }
        return io_error("RSP peer rejected non-stop resume after three attempts");
    }
    for (unsigned attempt = 0; attempt < 3; ++attempt) {
        auto sent = write_all(packet, deadline, stop); if (!sent) return sent;
        if (no_ack_mode_) return std::monostate{};
        auto ack = read_ack(deadline, stop); if (!ack) return ack.error();
        if (ack.value()) return std::monostate{};
    }
    return io_error("RSP peer rejected resume after three attempts");
}
Status Client::send_vcont(std::string_view action, std::stop_token stop) {
    if (action.empty() || action.find(';') != std::string_view::npos ||
        (action.front() != 'c' && action.front() != 's' && action.front() != 'C' && action.front() != 'S'))
        return Error{ErrorCode::invalid_argument, "vCont resume requires one continue or step action"};
    const auto colon = action.find(':');
    if (colon == std::string_view::npos || colon == 0 || colon + 1 == action.size())
        return Error{ErrorCode::invalid_argument, "thread-qualified vCont action requires an exact thread ID"};
    auto id = action.substr(colon + 1);
    const auto valid_hex_id = [](std::string_view value) {
        std::uint64_t parsed = 0;
        return !value.empty() && value.size() <= 16 &&
            value.find_first_not_of("0123456789abcdefABCDEF") == std::string_view::npos &&
            parse_thread_id(value, parsed) && parsed != 0;
    };
    if (id.starts_with('p')) {
        id.remove_prefix(1);
        const auto dot = id.find('.');
        if (dot == std::string_view::npos || !valid_hex_id(id.substr(0, dot)) ||
            !valid_hex_id(id.substr(dot + 1)))
            return Error{ErrorCode::invalid_argument, "invalid multiprocess thread ID in vCont action"};
    } else if (!valid_hex_id(id)) {
        return Error{ErrorCode::invalid_argument, "invalid thread ID in vCont action"};
    }
    const auto kind = action.substr(0, colon);
    if (kind != "c" && kind != "s" &&
        !(kind.size() == 3 && (kind.front() == 'C' || kind.front() == 'S') &&
          kind.substr(1).find_first_not_of("0123456789abcdefABCDEF") == std::string_view::npos))
        return Error{ErrorCode::invalid_argument, "unsupported vCont action"};
    return send_resume("vCont;" + std::string(action), stop);
}
Status Client::send_vcont_actions(std::span<const std::string> actions, std::stop_token stop) {
    if (actions.empty() || actions.size() > 4096)
        return Error{ErrorCode::invalid_argument, "vCont schedule must contain 1 to 4096 actions"};
    std::string command = "vCont;";
    std::set<std::string> selected_threads;
    for (const auto& action : actions) {
        if (action.empty() || action.find(';') != std::string::npos || action.find(':') == std::string::npos)
            return Error{ErrorCode::invalid_argument, "vCont schedule actions must identify one exact thread"};
        if (action.front() != 'c' && action.front() != 's' && action.front() != 't' &&
            action.front() != 'C' && action.front() != 'S')
            return Error{ErrorCode::invalid_argument, "unsupported vCont schedule action"};
        const auto colon = action.find(':');
        const auto kind = std::string_view(action).substr(0, colon);
        const bool signal_action = kind.size() == 3 && (kind.front() == 'C' || kind.front() == 'S') &&
            kind.substr(1).find_first_not_of("0123456789abcdefABCDEF") == std::string_view::npos;
        if (kind != "c" && kind != "s" && kind != "t" && !signal_action)
            return Error{ErrorCode::invalid_argument, "invalid vCont schedule action"};
        const auto id = std::string_view(action).substr(colon + 1);
        const auto valid_hex_id = [](std::string_view value) {
            std::uint64_t parsed = 0;
            return !value.empty() && value.size() <= 16 &&
                value.find_first_not_of("0123456789abcdefABCDEF") == std::string_view::npos &&
                parse_thread_id(value, parsed) && parsed != 0;
        };
        std::string canonical_id;
        if (id.starts_with('p')) {
            const auto qualified = id.substr(1);
            const auto dot = qualified.find('.');
            if (dot == std::string_view::npos || !valid_hex_id(qualified.substr(0, dot)) ||
                !valid_hex_id(qualified.substr(dot + 1)))
                return Error{ErrorCode::invalid_argument, "invalid multiprocess thread ID in vCont schedule"};
            std::uint64_t process = 0, thread = 0;
            if (!parse_thread_id(qualified.substr(0, dot), process) ||
                !parse_thread_id(qualified.substr(dot + 1), thread))
                return Error{ErrorCode::invalid_argument, "invalid multiprocess thread ID in vCont schedule"};
            canonical_id = "p" + hex_u64(process) + "." + hex_u64(thread);
        } else if (!valid_hex_id(id)) {
            return Error{ErrorCode::invalid_argument, "invalid thread ID in vCont schedule"};
        } else {
            std::uint64_t thread = 0;
            if (!parse_thread_id(id, thread))
                return Error{ErrorCode::invalid_argument, "invalid thread ID in vCont schedule"};
            canonical_id = hex_u64(thread);
        }
        if (!selected_threads.insert(std::move(canonical_id)).second)
            return Error{ErrorCode::invalid_argument, "duplicate thread ID in vCont schedule"};
        if (command.size() + action.size() + 1 > max_packet_)
            return Error{ErrorCode::resource_limit, "vCont schedule exceeds the packet size limit"};
        if (command.size() > 6) command.push_back(';');
        command += action;
    }
    return send_resume(command, stop);
}
Status Client::kill(std::stop_token stop) {
    if (stop.stop_requested()) return Error{ErrorCode::canceled, "RSP operation canceled"};
    // The `k` packet has no protocol reply. In particular, the peer may close
    // the transport as soon as it has accepted the request, so waiting for an
    // ACK or response would turn a successful termination into a false error.
    const auto packet = encode_packet("k");
    return write_all(packet, std::chrono::steady_clock::now() + timeout_, stop);
}
Status Client::kill_process(std::uint64_t process, std::stop_token stop) {
    if (process == 0) return Error{ErrorCode::invalid_argument, "RSP process ID must be nonzero"};
    auto response = transact("vKill;" + hex_u64(process), stop);
    if (!response) return response.error();
    if (response.value() == "OK") return std::monostate{};
    if (response.value().empty()) return Error{ErrorCode::unsupported, "remote does not support vKill"};
    return Error{ErrorCode::io, "remote rejected vKill: " + response.value()};
}
Result<std::optional<StopReply>> Client::attach_process(std::uint64_t process, std::stop_token stop) {
    if (process == 0) return Error{ErrorCode::invalid_argument, "RSP process ID must be nonzero"};
    auto response = transact("vAttach;" + hex_u64(process), stop);
    if (!response) return response.error();
    if (response.value().empty()) return Error{ErrorCode::unsupported, "remote does not support vAttach"};
    if (response.value() == "OK") {
        if (!non_stop_mode_)
            return Error{ErrorCode::malformed, "all-stop vAttach must return an initial stop reply"};
        return std::optional<StopReply>{};
    }
    auto stopped = parse_stop(response.value());
    if (!stopped) return stopped.error();
    if (stopped.value().kind != 'T' && stopped.value().kind != 'S')
        return Error{ErrorCode::malformed, "vAttach did not return an initial stop reply"};
    return std::optional<StopReply>{std::move(stopped.value())};
}
Result<StopReply> Client::run_program(std::string_view executable,
    std::span<const std::string> arguments, std::stop_token stop) {
    if (executable.empty() || executable.find('\0') != std::string_view::npos)
        return Error{ErrorCode::invalid_argument, "RSP vRun executable path must be nonempty and contain no NUL"};
    if (arguments.size() > 4096)
        return Error{ErrorCode::resource_limit, "RSP vRun argument count exceeds 4096"};
    std::string command = "vRun;";
    const auto append_hex_argument = [&](std::string_view value, bool first) -> Status {
        if (value.find('\0') != std::string_view::npos)
            return Error{ErrorCode::invalid_argument, "RSP vRun arguments cannot contain NUL"};
        const std::size_t separator = first ? 0 : 1;
        if (command.size() > peer_packet_size_ || separator > peer_packet_size_ - command.size() ||
            value.size() > (peer_packet_size_ - command.size() - separator) / 2)
            return Error{ErrorCode::resource_limit, "RSP vRun packet exceeds the negotiated packet size"};
        if (!first) command.push_back(';');
        constexpr char digits[] = "0123456789abcdef";
        for (const unsigned char byte : value) {
            command.push_back(digits[byte >> 4]);
            command.push_back(digits[byte & 0x0f]);
        }
        return std::monostate{};
    };
    auto path_status = append_hex_argument(executable, true);
    if (!path_status) return path_status.error();
    for (const auto &argument : arguments) {
        auto argument_status = append_hex_argument(argument, false);
        if (!argument_status) return argument_status.error();
    }
    auto response = transact(command, stop);
    if (!response) return response.error();
    if (response.value().empty())
        return Error{ErrorCode::unsupported, "remote does not support the vRun launch packet"};
    auto stopped = parse_stop(response.value());
    if (!stopped) return stopped.error();
    if (stopped.value().kind != 'T' && stopped.value().kind != 'S')
        return Error{ErrorCode::malformed, "vRun did not return an initial stopped reply"};
    if (non_stop_mode_) stop_reply_sequence_active_ = true;
    return stopped;
}
Status Client::set_working_directory(std::string_view directory, std::stop_token stop) {
    if (directory.find('\0') != std::string_view::npos)
        return Error{ErrorCode::invalid_argument, "RSP working directory cannot contain NUL"};
    if (!working_directory_supported_)
        return Error{ErrorCode::unsupported, "remote did not advertise QSetWorkingDir support"};
    constexpr std::string_view prefix = "QSetWorkingDir:";
    if (directory.size() > 16 * 1024 || prefix.size() > peer_packet_size_ ||
        directory.size() > (peer_packet_size_ - prefix.size()) / 2)
        return Error{ErrorCode::resource_limit, "RSP working directory exceeds the path or negotiated packet limit"};
    auto response = transact(std::string(prefix) + encode_hex(std::as_bytes(std::span(directory.data(), directory.size()))), stop);
    // There is no standard query for the active target directory. If the
    // reply is lost, the setting may have changed even though we cannot prove it.
    known_working_directory_.reset();
    if (!response) return response.error();
    if (response.value() == "OK") {
        known_working_directory_ = std::string(directory);
        return std::monostate{};
    }
    if (response.value().empty())
        return Error{ErrorCode::unsupported, "remote does not support QSetWorkingDir"};
    return Error{ErrorCode::io, "remote rejected working directory: " + response.value()};
}
Status Client::apply_environment_batch(std::span<const RemoteEnvironmentChange> changes, std::stop_token stop) {
    constexpr std::string_view reset = "QEnvironmentReset";
    if (changes.size() > 256)
        return Error{ErrorCode::resource_limit, "RSP launch environment exceeds the 256-change limit"};
    if (!environment_reset_supported_)
        return Error{ErrorCode::unsupported, "remote did not advertise QEnvironmentReset support"};
    if (reset.size() > peer_packet_size_)
        return Error{ErrorCode::resource_limit, "RSP environment reset exceeds negotiated packet limit"};
    std::set<std::string_view, std::less<>> names;
    std::vector<std::string> commands;
    commands.reserve(changes.size());
    std::size_t bytes = 0;
    for (const auto& change : changes) {
        if (stop.stop_requested())return Error{ErrorCode::canceled, "RSP environment configuration canceled"};
        if (change.name.size() > 4096 || (change.value && change.value->size() > 16 * 1024))
            return Error{ErrorCode::resource_limit, "RSP environment name or value exceeds its byte limit"};
        if (change.name.empty() || change.name.find('=') != std::string::npos || change.name.find('\0') != std::string::npos ||
            (change.value && change.value->find('\0') != std::string::npos))
            return Error{ErrorCode::invalid_argument, "RSP environment names must be nonempty without '=' or NUL, and values cannot contain NUL"};
        if (!names.insert(change.name).second)
            return Error{ErrorCode::invalid_argument, "RSP launch environment repeats a variable name"};
        const auto cost = change.name.size() + (change.value ? change.value->size() : 0);
        if (cost > 64 * 1024 - bytes)
            return Error{ErrorCode::resource_limit, "RSP launch environment exceeds the 64 KiB byte limit"};
        bytes += cost;
        if ((change.value && !environment_set_supported_) || (!change.value && !environment_unset_supported_))
            return Error{ErrorCode::unsupported, "remote did not advertise the required environment set/unset packet"};
        const std::string_view prefix = change.value ? "QEnvironmentHexEncoded:" : "QEnvironmentUnset:";
        const auto encoded_bytes = cost + (change.value ? 1 : 0); // NAME=VALUE, including empty VALUE.
        if (prefix.size() > peer_packet_size_ || encoded_bytes > (peer_packet_size_ - prefix.size()) / 2)
            return Error{ErrorCode::resource_limit, "RSP environment change exceeds negotiated packet limit"};
        std::string value = change.name;
        if (change.value) { value.push_back('='); value += *change.value; }
        commands.push_back(std::string(prefix) + encode_hex(std::as_bytes(std::span(value.data(), value.size()))));
    }
    const auto send = [&](std::string_view command) -> Status {
        auto response = transact(command, stop);
        if (!response) return response.error();
        if (response.value() == "OK") return std::monostate{};
        if (response.value().empty())return Error{ErrorCode::unsupported, "remote does not support the advertised environment packet"};
        // Keep peer diagnostics useful without echoing the hex-encoded command
        // (which may contain environment values) or allowing control bytes into
        // UI/log messages. GDB error replies are commonly short `E..` values.
        std::string diagnostic;
        constexpr std::size_t diagnostic_limit = 96;
        const auto count = std::min(response.value().size(), diagnostic_limit);
        constexpr char digits[] = "0123456789abcdef";
        for (std::size_t i = 0; i < count; ++i) {
            const auto byte = static_cast<unsigned char>(response.value()[i]);
            if (byte >= 0x20 && byte <= 0x7e) diagnostic.push_back(static_cast<char>(byte));
            else {
                diagnostic += "\\x";
                diagnostic.push_back(digits[byte >> 4]);
                diagnostic.push_back(digits[byte & 0x0f]);
            }
        }
        if (response.value().size() > count) diagnostic += "...";
        return Error{ErrorCode::io, "remote rejected launch environment configuration (reply: " + diagnostic + ")"};
    };
    // Reset is the only standard way to establish a known baseline, but it
    // cannot reveal the server's original environment. Clear our cache before
    // sending because a lost response can leave the peer in either state.
    known_environment_changes_.reset();
    auto restored = send(reset);
    if (!restored) return restored;
    std::vector<RemoteEnvironmentChange> applied_changes;
    known_environment_changes_ = applied_changes;
    for (std::size_t index = 0; index < commands.size(); ++index) {
        Status packet_result = stop.stop_requested()
            ? Status{Error{ErrorCode::canceled, "RSP environment configuration canceled"}}
            : send(commands[index]);
        if (!packet_result) {
            // The protocol has no transaction primitive and no way to read
            // back the launch environment. If a command fails, best-effort
            // reset the batch so a retry cannot inherit a silently partial
            // configuration. Ignore the caller's stop request for cleanup.
            known_environment_changes_.reset();
            auto cleanup = transact(reset, {});
            if (!cleanup || cleanup.value() != "OK") {
                const auto cleanup_detail = !cleanup
                    ? cleanup.error().message
                    : cleanup.value().empty()
                        ? std::string("remote no longer accepts QEnvironmentReset")
                        : std::string("remote rejected QEnvironmentReset: ") + cleanup.value();
                return Error{packet_result.error().code,
                    packet_result.error().message + "; launch environment cleanup failed: " + cleanup_detail};
            }
            known_environment_changes_ = std::vector<RemoteEnvironmentChange>{};
            return packet_result;
        }
        applied_changes.push_back(changes[index]);
        known_environment_changes_ = applied_changes;
    }
    known_environment_changes_ = std::vector<RemoteEnvironmentChange>(changes.begin(), changes.end());
    return std::monostate{};
}
Status Client::set_environment(std::span<const RemoteEnvironmentChange> changes, std::stop_token stop) {
    const auto previous = known_environment_changes_;
    auto configured = apply_environment_batch(changes, stop);
    if (configured) return std::monostate{};

    // The server has no standard environment readback. Restore an earlier
    // state only when this Client established it from successful replies.
    if (!previous) {
        std::string detail = configured.error().message +
            "; prior server environment could not be queried";
        if (known_environment_changes_ && known_environment_changes_->empty())
            detail += "; target-default baseline was restored";
        else
            detail += "; remote environment state is unknown";
        return Error{configured.error().code, std::move(detail)};
    }
    if (known_environment_changes_ == previous) {
        return Error{configured.error().code,
            configured.error().message + "; prior client-known environment remains active"};
    }
    auto rollback = apply_environment_batch(*previous, {});
    if (rollback)
        return Error{configured.error().code,
            configured.error().message + "; restored prior client-known environment"};
    return Error{configured.error().code,
        configured.error().message + "; restoring prior client-known environment failed: " +
        rollback.error().message + "; remote environment state is unknown"};
}
Status Client::configure_launch_settings(std::span<const RemoteEnvironmentChange> changes,
    std::string_view working_directory, std::stop_token stop) {
    if (!working_directory.empty() && !working_directory_supported_)
        return Error{ErrorCode::unsupported, "remote did not advertise working-directory support for inferior launch"};
    if (working_directory.find('\0') != std::string_view::npos || working_directory.size() > 16 * 1024)
        return Error{ErrorCode::resource_limit, "remote working directory is invalid or exceeds 16 KiB"};
    constexpr std::string_view working_directory_prefix = "QSetWorkingDir:";
    if (working_directory_supported_ && (working_directory_prefix.size() > peer_packet_size_ ||
        working_directory.size() > (peer_packet_size_ - working_directory_prefix.size()) / 2))
        return Error{ErrorCode::resource_limit, "remote working directory exceeds negotiated packet limit"};
    const auto previous_environment = known_environment_changes_;
    const auto previous_directory = known_working_directory_;
    const bool configure_environment = !changes.empty() || environment_reset_supported_;
    if (configure_environment) {
        auto environment = set_environment(changes, stop);
        if (!environment) return environment.error();
    }
    auto directory = working_directory_supported_ ? set_working_directory(working_directory, stop) : Status{std::monostate{}};
    if (directory) return std::monostate{};
    std::string detail = directory.error().message + "; launch-settings rollback: ";
    bool rollback_complete = true;
    if (configure_environment) {
        const std::span<const RemoteEnvironmentChange> restore = previous_environment
            ? std::span<const RemoteEnvironmentChange>(*previous_environment)
            : std::span<const RemoteEnvironmentChange>{};
        auto environment_rollback = set_environment(restore, {});
        if (environment_rollback) {
            if (previous_environment) detail += "prior client-known environment restored";
            else detail += "prior environment could not be queried; target-default baseline restored";
        } else {
            rollback_complete = false;
            detail += "environment rollback failed: " + environment_rollback.error().message;
        }
    } else {
        detail += "environment unchanged";
    }
    detail += "; ";
    if (working_directory_supported_) {
        const auto restore_directory = previous_directory.value_or(std::string{});
        auto directory_rollback = set_working_directory(restore_directory, {});
        if (directory_rollback) {
            if (previous_directory) detail += "prior client-known working directory restored";
            else detail += "prior working directory could not be queried; target-default directory restored";
        } else {
            rollback_complete = false;
            detail += "working-directory rollback failed: " + directory_rollback.error().message;
        }
    } else {
        detail += "working directory unchanged";
    }
    if (!rollback_complete) detail += "; remote launch settings may be unknown";
    return Error{directory.error().code, std::move(detail)};
}
Status Client::detach_process(std::uint64_t process, std::stop_token stop) {
    if (process == 0) return Error{ErrorCode::invalid_argument, "RSP process ID must be nonzero"};
    auto response = transact("D;" + hex_u64(process), stop);
    if (!response) return response.error();
    if (response.value() == "OK") {
        for (auto it = pending_notifications_.begin(); it != pending_notifications_.end();) {
            auto parsed = parse_stop(*it);
            bool belongs = false;
            if (parsed) {
                if (const auto thread = parsed.value().fields.find("thread");
                    thread != parsed.value().fields.end())
                    belongs = process_id_from_thread_id(thread->second) == std::optional<std::uint64_t>(process);
                if (const auto process_field = parsed.value().fields.find("process");
                    process_field != parsed.value().fields.end()) {
                    std::uint64_t notified_process = 0;
                    belongs |= parse_hex(process_field->second, notified_process) && notified_process == process;
                }
            }
            if (belongs) {
                pending_notification_bytes_ -= it->size();
                it = pending_notifications_.erase(it);
            } else ++it;
        }
        return std::monostate{};
    }
    if (response.value().empty()) return Error{ErrorCode::unsupported, "remote does not support process-specific detach"};
    return Error{ErrorCode::io, "remote rejected process-specific detach: " + response.value()};
}
Status Client::interrupt(std::stop_token stop) {
    if (non_stop_mode_) {
        auto response = transact("vCtrlC", stop);
        if (!response) return response.error();
        if (response.value() == "OK") return std::monostate{};
        if (response.value().empty())
            return Error{ErrorCode::unsupported, "remote does not support packet-based non-stop interrupt"};
        return Error{ErrorCode::io, "remote rejected non-stop interrupt: " + response.value()};
    }
    const char interrupt_byte = 3;
    return write_all(std::string_view(&interrupt_byte, 1), std::chrono::steady_clock::now() + timeout_, stop);
}
Result<std::vector<std::uint64_t>> Client::enumerate_threads(std::stop_token stop) {
    auto ids = enumerate_thread_ids(stop);
    if (!ids) return ids.error();
    std::vector<std::uint64_t> result; result.reserve(ids.value().size());
    for (const auto& id : ids.value()) {
        std::uint64_t thread = 0;
        if (!parse_thread_id(id, thread)) return Error{ErrorCode::malformed, "invalid RSP thread id"};
        result.push_back(thread);
    }
    return result;
}
Result<std::vector<std::string>> Client::enumerate_thread_ids(std::stop_token stop) {
    std::vector<std::string> result; std::set<std::string, std::less<>> seen; std::string command = "qfThreadInfo";
    for (std::size_t pages = 0; pages < 65536; ++pages) {
        auto response = transact(command, stop); if (!response) return response.error();
        if (response.value() == "l") return result;
        if (response.value().empty() || response.value()[0] != 'm') return Error{ErrorCode::malformed, "invalid RSP thread enumeration reply"};
        std::string_view ids(response.value().data() + 1, response.value().size() - 1);
        while (!ids.empty()) {
            const auto end = ids.find(',');
            const auto id = ids.substr(0, end);
            std::uint64_t value = 0;
            if (!parse_thread_id(id, value)) return Error{ErrorCode::malformed, "invalid RSP thread id"};
            if (result.size() >= 65536) return Error{ErrorCode::resource_limit, "RSP thread count exceeds limit"};
            if (!seen.emplace(id).second)
                return Error{ErrorCode::malformed, "duplicate RSP thread id"};
            result.emplace_back(id);
            if (end == std::string_view::npos) break;
            ids.remove_prefix(end + 1);
        }
        command = "qsThreadInfo";
    }
    return Error{ErrorCode::resource_limit, "RSP thread enumeration page limit exceeded"};
}
Result<std::optional<std::string>> Client::read_thread_extra_info(std::string_view thread_id,
    std::size_t limit, std::chrono::milliseconds timeout, std::stop_token stop) {
    if (limit == 0 || limit > 64 * 1024 || timeout <= std::chrono::milliseconds::zero() ||
        timeout > std::chrono::minutes(1) || thread_id.empty() || thread_id.size() > 34)
        return Error{ErrorCode::invalid_argument, "invalid RSP thread-info bounds or ID"};
    std::uint64_t thread = 0;
    if (!parse_thread_id(thread_id, thread) || thread == 0 ||
        thread_id.find_first_not_of("p.0123456789abcdefABCDEF") != std::string_view::npos)
        return Error{ErrorCode::invalid_argument, "qThreadExtraInfo requires a concrete thread ID"};
    if (thread_id.starts_with('p')) {
        const auto dot = thread_id.find('.');
        std::uint64_t process = 0;
        if (dot == std::string_view::npos || !parse_hex(thread_id.substr(1, dot - 1), process) || process == 0)
            return Error{ErrorCode::invalid_argument, "qThreadExtraInfo requires a concrete process ID"};
    }
    auto response = transact_until("qThreadExtraInfo," + std::string(thread_id),
                                   std::chrono::steady_clock::now() + timeout, stop);
    if (!response) return response.error();
    if (response.value().empty()) return std::optional<std::string>{};
    if (response.value().size() > limit * 2)
        return Error{ErrorCode::resource_limit, "RSP thread extra-info exceeds configured limit"};
    auto bytes = decode_hex(response.value());
    if (!bytes) return bytes.error();
    std::string description;
    description.reserve(bytes.value().size());
    for (const auto byte : bytes.value()) {
        const auto value = std::to_integer<unsigned char>(byte);
        if (value < 0x20 || value == 0x7f) {
            if (value == 0) return Error{ErrorCode::malformed, "RSP thread extra-info contains an embedded NUL"};
            description.push_back(' ');
        } else {
            description.push_back(static_cast<char>(value));
        }
    }
    return std::optional<std::string>(std::move(description));
}
Result<std::vector<std::byte>> Client::read_registers(std::stop_token stop) {
    auto response = read_registers_raw(stop); if (!response) return response.error(); return decode_hex(response.value());
}
Result<std::string> Client::read_registers_raw(std::stop_token stop) { return transact("g", stop); }
Status Client::write_registers_raw(std::string_view hex_registers, std::stop_token stop) {
    if (hex_registers.empty() || hex_registers.size() % 2 != 0 ||
        hex_registers.size() >= max_packet_ ||
        !std::all_of(hex_registers.begin(), hex_registers.end(), [](unsigned char c) {
            return (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F');
        }))
        return Error{ErrorCode::invalid_argument, "RSP G packet must contain bounded, complete hexadecimal register bytes"};
    auto response = transact("G" + std::string(hex_registers), stop);
    if (!response) return response.error();
    if (response.value() == "OK") return std::monostate{};
    if (response.value().empty()) return Error{ErrorCode::unsupported, "remote does not support bulk register writes"};
    return Error{ErrorCode::io, "remote rejected bulk register write: " + response.value()};
}
Result<std::optional<std::string>> Client::read_feature_annex(std::string_view annex, std::size_t limit,
    std::size_t chunk, std::stop_token stop) {
    if (annex.empty() || annex.size() > 256 || annex.find_first_of(":,;#$\r\n") != std::string_view::npos ||
        limit == 0 || limit > 1024 * 1024 || chunk == 0 || chunk > 64 * 1024)
        return Error{ErrorCode::invalid_argument, "invalid RSP feature annex bounds or name"};
    const auto packet_limit = std::min(max_packet_, peer_packet_size_);
    if (packet_limit < 3)
        return Error{ErrorCode::resource_limit, "RSP packet limit cannot hold a feature annex response"};
    // Treat `chunk` as a maximum. Leave room for worst-case RSP escaping and
    // the mandatory qXfer reply marker under both local and peer ceilings.
    const auto response_chunk = std::min(chunk, (packet_limit - 1) / 2);
    std::string result;
    for (std::size_t offset = 0; offset <= limit;) {
        const auto request_size = std::min(response_chunk, limit - std::min(offset, limit));
        if (offset == limit && request_size == 0) return Error{ErrorCode::resource_limit, "RSP feature annex exceeds configured limit"};
        const auto command = "qXfer:features:read:" + std::string(annex) + ":" +
            hex_u64(offset) + "," + hex_u64(request_size);
        if (command.size() > packet_limit)
            return Error{ErrorCode::resource_limit, "RSP feature annex request exceeds the negotiated packet limit"};
        auto response = transact(command, stop);
        if (!response) return response.error();
        if (response.value().empty()) {
            if (offset == 0) return std::optional<std::string>{};
            return Error{ErrorCode::malformed, "RSP feature annex ended without final marker"};
        }
        const char marker = response.value().front();
        if (marker != 'm' && marker != 'l') {
            return Error{ErrorCode::malformed, "invalid RSP feature annex marker"};
        }
        const auto count = response.value().size() - 1;
        if (count > request_size || count > limit - result.size())
            return Error{ErrorCode::resource_limit, "RSP feature annex chunk exceeds configured limit"};
        result.append(response.value().data() + 1, count);
        if (marker == 'l') return std::optional<std::string>(std::move(result));
        if (count == 0 || offset > std::numeric_limits<std::size_t>::max() - count)
            return Error{ErrorCode::malformed, "RSP feature annex made no progress"};
        offset += count;
    }
    return Error{ErrorCode::resource_limit, "RSP feature annex exceeds configured limit"};
}
Result<std::optional<std::string>> Client::read_libraries_annex(std::size_t limit, std::size_t chunk, std::stop_token stop) {
    if (limit == 0 || limit > 1024 * 1024 || chunk == 0 || chunk > 64 * 1024)
        return Error{ErrorCode::invalid_argument, "invalid RSP libraries annex bounds"};
    const auto packet_limit = std::min(max_packet_, peer_packet_size_);
    if (packet_limit < 3)
        return Error{ErrorCode::resource_limit, "RSP packet limit cannot hold a libraries annex response"};
    const auto bounded_chunk = std::min(chunk, (packet_limit - 1) / 2);
    auto read_object = [&](std::string_view object) -> Result<std::optional<std::string>> {
        std::string result;
        for (std::size_t offset = 0; offset <= limit;) {
            const auto request_size = std::min(bounded_chunk, limit - std::min(offset, limit));
            if (offset == limit && request_size == 0)
                return Error{ErrorCode::resource_limit, "RSP libraries annex exceeds configured limit"};
            const auto command = "qXfer:" + std::string(object) + ":read::" + hex_u64(offset) + "," + hex_u64(request_size);
            if (command.size() > packet_limit)
                return Error{ErrorCode::resource_limit, "RSP libraries annex request exceeds the negotiated packet limit"};
            auto response = transact(command, stop);
            if (!response) return response.error();
            if (response.value().empty()) {
                if (offset == 0) return std::optional<std::string>{};
                return Error{ErrorCode::malformed, "RSP libraries annex ended without final marker"};
            }
            const char marker = response.value().front();
            if (marker != 'm' && marker != 'l') return Error{ErrorCode::malformed, "invalid RSP libraries annex marker"};
            const auto count = response.value().size() - 1;
            if (count > request_size || count > limit - result.size())
                return Error{ErrorCode::resource_limit, "RSP libraries annex chunk exceeds configured limit"};
            result.append(response.value().data() + 1, count);
            if (marker == 'l') return std::optional<std::string>(std::move(result));
            if (count == 0 || offset > std::numeric_limits<std::size_t>::max() - count)
                return Error{ErrorCode::malformed, "RSP libraries annex made no progress"};
            offset += count;
        }
        return Error{ErrorCode::resource_limit, "RSP libraries annex exceeds configured limit"};
    };
    auto standard = read_object("libraries");
    if (!standard || standard.value()) return standard;
    return read_object("libraries-svr4");
}
Result<std::optional<std::string>> Client::read_memory_map_annex(std::size_t limit, std::size_t chunk, std::stop_token stop) {
    if (limit == 0 || limit > 1024 * 1024 || chunk == 0 || chunk > 64 * 1024)
        return Error{ErrorCode::invalid_argument, "invalid RSP memory-map annex bounds"};
    const auto packet_limit = std::min(max_packet_, peer_packet_size_);
    if (packet_limit < 3)
        return Error{ErrorCode::resource_limit, "RSP packet limit cannot hold a memory-map annex response"};
    const auto bounded_chunk = std::min(chunk, (packet_limit - 1) / 2);
    std::string result;
    for (std::size_t offset = 0; offset <= limit;) {
        const auto request_size = std::min(bounded_chunk, limit - std::min(offset, limit));
        if (offset == limit && request_size == 0) return Error{ErrorCode::resource_limit, "RSP memory-map annex exceeds configured limit"};
        const auto command = "qXfer:memory-map:read::" + hex_u64(offset) + "," + hex_u64(request_size);
        if (command.size() > packet_limit)
            return Error{ErrorCode::resource_limit, "RSP memory-map request exceeds the negotiated packet limit"};
        auto response = transact(command, stop);
        if (!response) return response.error();
        if (response.value().empty()) {
            if (offset == 0) return std::optional<std::string>{};
            return Error{ErrorCode::malformed, "RSP memory-map annex ended without final marker"};
        }
        const char marker = response.value().front();
        if (marker != 'm' && marker != 'l') return Error{ErrorCode::malformed, "invalid RSP memory-map annex marker"};
        const auto count = response.value().size() - 1;
        if (count > request_size || count > limit - result.size())
            return Error{ErrorCode::resource_limit, "RSP memory-map annex chunk exceeds configured limit"};
        result.append(response.value().data() + 1, count);
        if (marker == 'l') return std::optional<std::string>(std::move(result));
        if (count == 0 || offset > std::numeric_limits<std::size_t>::max() - count)
            return Error{ErrorCode::malformed, "RSP memory-map annex made no progress"};
        offset += count;
    }
    return Error{ErrorCode::resource_limit, "RSP memory-map annex exceeds configured limit"};
}
Result<std::optional<std::string>> Client::read_threads_annex(std::size_t limit, std::size_t chunk, std::stop_token stop) {
    if (limit == 0 || limit > 1024 * 1024 || chunk == 0 || chunk > 64 * 1024)
        return Error{ErrorCode::invalid_argument, "invalid RSP thread annex bounds"};
    const auto packet_limit = std::min(max_packet_, peer_packet_size_);
    if (packet_limit < 3)
        return Error{ErrorCode::resource_limit, "RSP packet limit cannot hold a thread annex response"};
    const auto bounded_chunk = std::min(chunk, (packet_limit - 1) / 2);
    std::string result;
    for (std::size_t offset = 0; offset <= limit;) {
        const auto request_size = std::min(bounded_chunk, limit - std::min(offset, limit));
        if (offset == limit && request_size == 0)
            return Error{ErrorCode::resource_limit, "RSP thread annex exceeds configured limit"};
        const auto command = "qXfer:threads:read::" + hex_u64(offset) + "," + hex_u64(request_size);
        if (command.size() > packet_limit)
            return Error{ErrorCode::resource_limit, "RSP thread-list request exceeds the negotiated packet limit"};
        auto response = transact(command, stop);
        if (!response) return response.error();
        if (response.value().empty()) {
            if (offset == 0) return std::optional<std::string>{};
            return Error{ErrorCode::malformed, "RSP thread annex ended without final marker"};
        }
        const char marker = response.value().front();
        if (marker != 'm' && marker != 'l') return Error{ErrorCode::malformed, "invalid RSP thread annex marker"};
        const auto count = response.value().size() - 1;
        if (count > request_size || count > limit - result.size())
            return Error{ErrorCode::resource_limit, "RSP thread annex chunk exceeds configured limit"};
        result.append(response.value().data() + 1, count);
        if (marker == 'l') return std::optional<std::string>(std::move(result));
        if (count == 0 || offset > std::numeric_limits<std::size_t>::max() - count)
            return Error{ErrorCode::malformed, "RSP thread annex made no progress"};
        offset += count;
    }
    return Error{ErrorCode::resource_limit, "RSP thread annex exceeds configured limit"};
}
Result<std::optional<std::string>> Client::read_processes_annex(std::size_t limit, std::size_t chunk,
    std::stop_token stop) {
    return read_osdata_annex("processes", limit, chunk, stop);
}
Result<std::optional<std::string>> Client::read_osdata_annex(std::string_view type,
    std::size_t limit, std::size_t chunk, std::stop_token stop) {
    const bool valid_type = !type.empty() && type.size() <= 64 &&
        std::all_of(type.begin(), type.end(), [](unsigned char c) {
            return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
                   (c >= '0' && c <= '9') || c == '-' || c == '_';
        });
    if (!valid_type || limit == 0 || limit > 1024 * 1024 || chunk == 0 || chunk > 64 * 1024)
        return Error{ErrorCode::invalid_argument, "invalid RSP OS-data annex type or bounds"};
    const auto packet_limit = std::min(max_packet_, peer_packet_size_);
    if (packet_limit < 3)
        return Error{ErrorCode::resource_limit, "RSP packet limit cannot hold an OS-data annex response"};
    const auto bounded_chunk = std::min(chunk, (packet_limit - 1) / 2);
    std::string result;
    for (std::size_t offset = 0; offset <= limit;) {
        const auto request_size = std::min(bounded_chunk, limit - std::min(offset, limit));
        if (offset == limit && request_size == 0)
            return Error{ErrorCode::resource_limit, "RSP OS-data annex exceeds configured limit"};
        const auto command = "qXfer:osdata:read:" + std::string(type) + ":" + hex_u64(offset) + "," + hex_u64(request_size);
        if (command.size() > packet_limit)
            return Error{ErrorCode::resource_limit, "RSP OS-data request exceeds the negotiated packet limit"};
        auto response = transact(command, stop);
        if (!response) return response.error();
        if (response.value().empty()) {
            if (offset == 0) return std::optional<std::string>{};
            return Error{ErrorCode::malformed, "RSP OS-data annex ended without final marker"};
        }
        const char marker = response.value().front();
        if (marker != 'm' && marker != 'l') return Error{ErrorCode::malformed, "invalid RSP OS-data annex marker"};
        const auto count = response.value().size() - 1;
        if (count > request_size || count > limit - result.size())
            return Error{ErrorCode::resource_limit, "RSP OS-data annex chunk exceeds configured limit"};
        result.append(response.value().data() + 1, count);
        if (marker == 'l') return std::optional<std::string>(std::move(result));
        if (count == 0 || offset > std::numeric_limits<std::size_t>::max() - count)
            return Error{ErrorCode::malformed, "RSP OS-data annex made no progress"};
        offset += count;
    }
    return Error{ErrorCode::resource_limit, "RSP OS-data annex exceeds configured limit"};
}
Result<std::optional<std::string>> Client::read_exec_file_annex(std::optional<std::uint64_t> process,
    std::size_t limit, std::size_t chunk, std::stop_token stop) {
    const auto packet_limit = std::min(max_packet_, peer_packet_size_);
    if ((process && *process == 0) || limit == 0 || limit > 1024 * 1024 || chunk == 0 ||
        chunk > 64 * 1024 || packet_limit < 64)
        return Error{ErrorCode::invalid_argument, "invalid RSP executable-file annex bounds or process ID"};
    const auto bounded_chunk = std::min(chunk, (packet_limit - 1) / 2);
    const auto process_token = process ? hex_u64(*process) : std::string{};
    std::string result;
    for (std::size_t offset = 0; offset <= limit;) {
        const auto request_size = std::min(bounded_chunk, limit - std::min(offset, limit));
        if (offset == limit && request_size == 0)
            return Error{ErrorCode::resource_limit, "RSP executable-file path exceeds configured limit"};
        const auto command = "qXfer:exec-file:read:" + process_token + ":" +
            hex_u64(offset) + "," + hex_u64(request_size);
        if (command.size() > packet_limit)
            return Error{ErrorCode::resource_limit, "RSP executable-file request exceeds the negotiated packet limit"};
        auto response = transact(command, stop);
        if (!response) return response.error();
        if (response.value().empty()) {
            if (offset == 0) return std::optional<std::string>{};
            return Error{ErrorCode::malformed, "RSP executable-file annex ended without final marker"};
        }
        const char marker = response.value().front();
        if (marker != 'm' && marker != 'l')
            return Error{ErrorCode::malformed, "invalid RSP executable-file annex marker"};
        const auto count = response.value().size() - 1;
        if (count > request_size || count > limit - result.size())
            return Error{ErrorCode::resource_limit, "RSP executable-file chunk exceeds configured limit"};
        if (response.value().find('\0', 1) != std::string::npos)
            return Error{ErrorCode::malformed, "RSP executable-file path contains an embedded NUL"};
        result.append(response.value().data() + 1, count);
        if (marker == 'l') return std::optional<std::string>(std::move(result));
        if (count == 0 || offset > std::numeric_limits<std::size_t>::max() - count)
            return Error{ErrorCode::malformed, "RSP executable-file annex made no progress"};
        offset += count;
    }
    return Error{ErrorCode::resource_limit, "RSP executable-file path exceeds configured limit"};
}
Result<std::optional<std::vector<std::byte>>> Client::read_auxv_annex(
    std::size_t limit, std::size_t chunk, std::stop_token stop) {
    const auto packet_limit = std::min(max_packet_, peer_packet_size_);
    if (limit == 0 || limit > 1024 * 1024 || chunk == 0 || chunk > 64 * 1024 || packet_limit < 32)
        return Error{ErrorCode::invalid_argument, "invalid RSP auxiliary-vector annex bounds"};
    const auto bounded_chunk = std::min(chunk, (packet_limit - 1) / 2);
    std::vector<std::byte> result;
    result.reserve(std::min(limit, bounded_chunk));
    for (std::size_t offset = 0; offset <= limit;) {
        const auto request_size = std::min(bounded_chunk, limit - std::min(offset, limit));
        if (offset == limit && request_size == 0)
            return Error{ErrorCode::resource_limit, "RSP auxiliary-vector annex exceeds configured limit"};
        const auto command = "qXfer:auxv:read::" + hex_u64(offset) + "," + hex_u64(request_size);
        if (command.size() > packet_limit)
            return Error{ErrorCode::resource_limit, "RSP auxiliary-vector request exceeds the negotiated packet limit"};
        auto response = transact(command, stop);
        if (!response) return response.error();
        if (response.value().empty()) {
            if (offset == 0) return std::optional<std::vector<std::byte>>{};
            return Error{ErrorCode::malformed, "RSP auxiliary-vector annex ended without final marker"};
        }
        const char marker = response.value().front();
        if (marker != 'm' && marker != 'l')
            return Error{ErrorCode::malformed, "invalid RSP auxiliary-vector annex marker"};
        const auto count = response.value().size() - 1;
        if (count > request_size || count > limit - result.size())
            return Error{ErrorCode::resource_limit, "RSP auxiliary-vector chunk exceeds configured limit"};
        for (std::size_t i = 1; i < response.value().size(); ++i)
            result.push_back(static_cast<std::byte>(static_cast<unsigned char>(response.value()[i])));
        if (marker == 'l') return std::optional<std::vector<std::byte>>(std::move(result));
        if (count == 0 || offset > std::numeric_limits<std::size_t>::max() - count)
            return Error{ErrorCode::malformed, "RSP auxiliary-vector annex made no progress"};
        offset += count;
    }
    return Error{ErrorCode::resource_limit, "RSP auxiliary-vector annex exceeds configured limit"};
}
Result<std::optional<std::vector<std::byte>>> Client::read_siginfo_annex(
    std::size_t limit, std::size_t chunk, std::stop_token stop) {
    const auto packet_limit = std::min(max_packet_, peer_packet_size_);
    if (limit == 0 || limit > 64 * 1024 || chunk == 0 || chunk > 64 * 1024 || packet_limit < 32)
        return Error{ErrorCode::invalid_argument, "invalid RSP siginfo annex bounds"};
    const auto bounded_chunk = std::min(chunk, (packet_limit - 1) / 2);
    std::vector<std::byte> result;
    result.reserve(std::min(limit, bounded_chunk));
    for (std::size_t offset = 0; offset <= limit;) {
        const auto request_size = std::min(bounded_chunk, limit - std::min(offset, limit));
        if (offset == limit && request_size == 0)
            return Error{ErrorCode::resource_limit, "RSP siginfo annex exceeds configured limit"};
        const auto command = "qXfer:siginfo:read::" + hex_u64(offset) + "," + hex_u64(request_size);
        if (command.size() > packet_limit)
            return Error{ErrorCode::resource_limit, "RSP siginfo request exceeds the negotiated packet limit"};
        auto response = transact(command, stop);
        if (!response) return response.error();
        if (response.value().empty()) {
            if (offset == 0) return std::optional<std::vector<std::byte>>{};
            return Error{ErrorCode::malformed, "RSP siginfo annex ended without final marker"};
        }
        const char marker = response.value().front();
        if (marker != 'm' && marker != 'l')
            return Error{ErrorCode::malformed, "invalid RSP siginfo annex marker"};
        const auto count = response.value().size() - 1;
        if (count > request_size || count > limit - result.size())
            return Error{ErrorCode::resource_limit, "RSP siginfo chunk exceeds configured limit"};
        for (std::size_t i = 1; i < response.value().size(); ++i)
            result.push_back(static_cast<std::byte>(static_cast<unsigned char>(response.value()[i])));
        if (marker == 'l') return std::optional<std::vector<std::byte>>(std::move(result));
        if (count == 0 || offset > std::numeric_limits<std::size_t>::max() - count)
            return Error{ErrorCode::malformed, "RSP siginfo annex made no progress"};
        offset += count;
    }
    return Error{ErrorCode::resource_limit, "RSP siginfo annex exceeds configured limit"};
}
Result<std::vector<std::byte>> Client::read_register(std::uint64_t number, std::stop_token stop) {
    auto response = read_register_raw(number, stop); if (!response) return response.error(); return decode_hex(response.value());
}
Result<std::string> Client::read_register_raw(std::uint64_t number, std::stop_token stop) {
    return transact("p" + hex_u64(number), stop);
}
Status Client::write_register(std::uint64_t number, std::span<const std::byte> bytes, std::stop_token stop) {
    if (bytes.empty() || bytes.size() > max_packet_ / 2)
        return Error{ErrorCode::invalid_argument, "RSP register write is empty or exceeds packet limit"};
    auto response = transact("P" + hex_u64(number) + "=" + encode_hex(bytes), stop);
    if (!response) return response.error();
    if (response.value() == "OK") return std::monostate{};
    if (response.value().empty()) return Error{ErrorCode::unsupported, "remote does not support single-register writes"};
    return Error{ErrorCode::io, "remote rejected register write: " + response.value()};
}
Result<std::vector<std::byte>> Client::read_memory(std::uint64_t address, std::size_t size, std::stop_token stop) {
    constexpr std::size_t max_transfer = 16 * 1024 * 1024;
    if (size == 0) return std::vector<std::byte>{};
    if (size > max_transfer || size > std::numeric_limits<std::uint64_t>::max() ||
        address > UINT64_MAX - size)
        return Error{ErrorCode::invalid_argument, "RSP memory range is invalid or exceeds the 16 MiB limit"};
    const auto packet_limit = std::min(max_packet_, peer_packet_size_);

    std::vector<std::byte> result;
    result.reserve(size);
    std::size_t offset = 0;
    while (offset < size) {
        if (stop.stop_requested()) return Error{ErrorCode::canceled, "RSP memory read canceled"};
        const auto current = address + offset;
        const auto prefix = "m" + hex_u64(current) + ",";
        // The request size itself contributes at most 16 hexadecimal digits.
        // Bound the reply by the negotiated packet size and leave room for the
        // actual request header before choosing each chunk.
        if (prefix.size() + 1 >= packet_limit)
            return Error{ErrorCode::resource_limit, "RSP peer packet limit cannot fit a memory-read header"};
        const auto reply_capacity = packet_limit / 2;
        auto count = std::min({size - offset, reply_capacity, std::size_t{64 * 1024}});
        while (count != 0 && prefix.size() + hex_u64(count).size() > packet_limit) --count;
        if (count == 0)
            return Error{ErrorCode::resource_limit, "RSP peer packet limit cannot fit memory-read data"};
        auto response = transact(prefix + hex_u64(count), stop);
        if (!response) return response.error();
        auto bytes = decode_hex(response.value());
        if (!bytes) return bytes.error();
        if (bytes.value().size() != count)
            return Error{ErrorCode::malformed, "RSP memory reply has unexpected length"};
        result.insert(result.end(), bytes.value().begin(), bytes.value().end());
        offset += count;
    }
    return result;
}
Result<std::optional<std::uint64_t>> Client::search_memory(std::uint64_t address,
    std::uint64_t length, std::span<const std::byte> pattern, std::stop_token stop) {
    if (length == 0 || address > UINT64_MAX - length || pattern.empty())
        return Error{ErrorCode::invalid_argument, "RSP memory search range or pattern is empty or overflows"};
    std::string command = "qSearch:memory:" + hex_u64(address) + ";" + hex_u64(length) + ";";
    command.append(reinterpret_cast<const char*>(pattern.data()), pattern.size());
    const auto packet_limit = std::min(max_packet_, peer_packet_size_);
    // RSP escaping can double every pattern byte ($, #, }, *).
    std::size_t wire_size = command.size();
    for (const auto byte : pattern) {
        const auto value = std::to_integer<unsigned char>(byte);
        if (value == '$' || value == '#' || value == '}' || value == '*') {
            if (wire_size == std::numeric_limits<std::size_t>::max())
                return Error{ErrorCode::resource_limit, "RSP memory search packet exceeds limit"};
            ++wire_size;
        }
    }
    if (wire_size > packet_limit)
        return Error{ErrorCode::resource_limit, "RSP memory search packet exceeds negotiated limit"};
    auto response = transact(command, stop);
    if (!response) return response.error();
    if (response.value().empty())
        return Error{ErrorCode::unsupported, "remote does not support qSearch:memory"};
    if (response.value() == "0") return std::optional<std::uint64_t>{};
    constexpr std::string_view found = "1,";
    std::uint64_t match = 0;
    if (!std::string_view(response.value()).starts_with(found) ||
        !parse_hex(std::string_view(response.value()).substr(found.size()), match))
        return Error{ErrorCode::malformed, "invalid RSP qSearch:memory reply"};
    const auto last_start = address + length - std::min<std::uint64_t>(length, pattern.size());
    if (pattern.size() > length || match < address || match > last_start)
        return Error{ErrorCode::malformed, "RSP qSearch:memory returned an address outside the range"};
    return std::optional<std::uint64_t>(match);
}
Result<std::uint32_t> Client::memory_crc32(std::uint64_t address, std::uint64_t length, std::stop_token stop) {
    if (length == 0 || address > UINT64_MAX - (length - 1))
        return Error{ErrorCode::invalid_argument, "RSP CRC range is empty or overflows the address space"};
    auto response = transact("qCRC:" + hex_u64(address) + "," + hex_u64(length), stop);
    if (!response) return response.error();
    if (response.value().empty())
        return Error{ErrorCode::unsupported, "remote does not support qCRC"};
    if (response.value().front() != 'C' || response.value().size() < 2 || response.value().size() > 9)
        return Error{ErrorCode::malformed, "invalid RSP qCRC reply"};
    std::uint32_t crc = 0;
    if (!parse_hex(std::string_view(response.value()).substr(1), crc))
        return Error{ErrorCode::malformed, "invalid hexadecimal RSP qCRC value"};
    return crc;
}
Result<std::vector<std::byte>> Client::read_memory_tags(std::uint64_t address,
    std::uint64_t length, std::int32_t type, std::size_t max_tag_bytes, std::stop_token stop) {
    if (length == 0 || address > UINT64_MAX - (length - 1))
        return Error{ErrorCode::invalid_argument, "RSP memory-tag range is empty or overflows the address space"};
    if (!memory_tagging_supported_)
        return Error{ErrorCode::unsupported, "remote did not advertise memory-tagging support"};
    const auto packet_limit = std::min(max_packet_, peer_packet_size_);
    if (max_packet_ < 3)
        return Error{ErrorCode::resource_limit, "RSP local packet limit cannot hold a memory-tag reply"};
    if (max_tag_bytes == 0 || max_tag_bytes > 1024 * 1024 ||
        max_tag_bytes > (std::numeric_limits<std::size_t>::max() - 1) / 2)
        return Error{ErrorCode::invalid_argument, "RSP memory-tag reply limit must be 1 byte to 1 MiB"};
    const auto reply_limit = std::min(max_tag_bytes, (max_packet_ - 1) / 2);
    if (reply_limit == 0)
        return Error{ErrorCode::resource_limit, "RSP local packet limit cannot hold a memory-tag reply"};
    const auto type_value = static_cast<std::uint64_t>(static_cast<std::int64_t>(type));
    const auto command = "qMemTags:" + hex_u64(address) + "," + hex_u64(length) + ":" + hex_u64(type_value);
    if (command.size() > packet_limit)
        return Error{ErrorCode::resource_limit, "RSP qMemTags request exceeds the negotiated packet limit"};
    auto response = transact(command, stop);
    if (!response) return response.error();
    if (response.value().empty())
        return Error{ErrorCode::unsupported, "remote rejected qMemTags despite advertising memory-tagging"};
    if (response.value().front() != 'm')
        return Error{ErrorCode::malformed, "RSP qMemTags reply must begin with the memory-tag marker"};
    const auto encoded = std::string_view(response.value()).substr(1);
    if (encoded.size() > reply_limit * 2)
        return Error{ErrorCode::resource_limit, "RSP qMemTags reply exceeds the configured tag-byte limit"};
    auto tags = decode_hex(encoded);
    if (!tags) return tags.error();
    return tags;
}
Result<bool> Client::is_address_tagged(std::uint64_t address, std::stop_token stop) {
    const auto command = "qIsAddressTagged:" + hex_u64(address);
    if (command.size() > std::min(max_packet_, peer_packet_size_))
        return Error{ErrorCode::resource_limit, "RSP qIsAddressTagged request exceeds the negotiated packet limit"};
    auto response = transact(command, stop);
    if (!response) return response.error();
    if (response.value().empty())
        return Error{ErrorCode::unsupported, "remote does not support qIsAddressTagged"};
    if (response.value() == "00") return false;
    if (response.value() == "01") return true;
    return Error{ErrorCode::malformed, "RSP qIsAddressTagged reply must be exactly 00 or 01"};
}
Result<std::vector<std::byte>> Client::read_remote_file(std::string_view path,
    std::size_t maximum_size, std::stop_token stop) {
    return read_remote_file_impl(path, 0, maximum_size, true, stop);
}
Result<std::vector<std::byte>> Client::read_remote_file_range(std::string_view path,
    std::uint64_t offset, std::size_t size, std::stop_token stop) {
    if (size == 0 || size > 256 * 1024 * 1024 || offset > UINT64_MAX - size)
        return Error{ErrorCode::invalid_argument,
            "RSP remote file range must be non-empty, at most 256 MiB, and not overflow"};
    return read_remote_file_impl(path, offset, size, false, stop);
}
Result<std::vector<std::byte>> Client::run_monitor_command(std::string_view command, std::stop_token stop) {
    if (command.empty() || command.size() > 4096 || command.find('\0') != std::string_view::npos)
        return Error{ErrorCode::invalid_argument, "RSP monitor command must contain 1 to 4096 non-NUL bytes"};
    for (const unsigned char byte : command) {
        if (byte < 0x20 || byte == 0x7f)
            return Error{ErrorCode::invalid_argument, "RSP monitor command must contain printable bytes only"};
    }
    const auto packet_limit = std::min(max_packet_, peer_packet_size_);
    constexpr std::size_t command_prefix_size = sizeof("qRcmd,") - 1;
    if (command.size() > (packet_limit > command_prefix_size ?
            (packet_limit - command_prefix_size) / 2 : 0))
        return Error{ErrorCode::resource_limit, "RSP monitor command exceeds the negotiated packet limit"};
    const auto request = "qRcmd," + encode_hex(std::as_bytes(std::span(command.data(), command.size())));
    const auto queued_before = pending_console_output_.size();
    auto response = transact(request, stop);
    if (!response) return response.error();
    if (response.value().empty())
        return Error{ErrorCode::unsupported, "remote does not support qRcmd monitor commands"};
    std::vector<std::byte> output;
    const auto first_new = std::next(pending_console_output_.begin(), static_cast<std::ptrdiff_t>(queued_before));
    output.assign(first_new, pending_console_output_.end());
    if (response.value() != "OK") {
        auto final_output = decode_hex(response.value());
        if (!final_output)
            return Error{ErrorCode::malformed, "RSP qRcmd reply must be OK or a hex-encoded output string"};
        if (final_output.value().size() > max_pending_console_output -
            std::min(output.size(), max_pending_console_output))
            return Error{ErrorCode::resource_limit, "RSP qRcmd output exceeds the 1 MiB command limit"};
        output.insert(output.end(), final_output.value().begin(), final_output.value().end());
    }
    pending_console_output_.erase(first_new, pending_console_output_.end());
    return output;
}
Result<RemoteFileStat> Client::stat_remote_file(std::uint64_t descriptor, std::stop_token stop) {
    if (descriptor > static_cast<std::uint64_t>(INT64_MAX))
        return Error{ErrorCode::invalid_argument, "RSP vFile descriptor exceeds the signed protocol range"};
    const auto command = "vFile:fstat:" + hex_u64(descriptor);
    if (command.size() > std::min(max_packet_, peer_packet_size_))
        return Error{ErrorCode::resource_limit, "RSP vFile:fstat request exceeds the negotiated packet limit"};
    auto response = transact(command, stop);
    if (!response) return response.error();
    if (response.value().empty())
        return Error{ErrorCode::unsupported, "remote does not support vFile:fstat"};
    return parse_remote_file_stat(response.value(), "vFile:fstat");
}
Result<RemoteFileStat> Client::stat_remote_file_path(std::string_view path,
    bool follow_symlinks, std::stop_token stop) {
    if (path.empty() || path.size() > 16 * 1024 || path.find('\0') != std::string_view::npos)
        return Error{ErrorCode::invalid_argument, "RSP vFile stat path must contain 1..16384 non-NUL bytes"};
    const auto operation = follow_symlinks ? std::string_view("stat") : std::string_view("lstat");
    const auto command = "vFile:" + std::string(operation) + ":" +
        encode_hex(std::as_bytes(std::span(path.data(), path.size())));
    if (command.size() > std::min(max_packet_, peer_packet_size_))
        return Error{ErrorCode::resource_limit, "RSP vFile stat request exceeds the negotiated packet limit"};
    auto response = transact(command, stop);
    if (!response) return response.error();
    if (response.value().empty())
        return Error{ErrorCode::unsupported, "remote does not support vFile:" + std::string(operation)};
    return parse_remote_file_stat(response.value(), "vFile:" + std::string(operation));
}
Status Client::write_remote_file_range(std::string_view path, std::uint64_t offset,
    std::span<const std::byte> bytes, std::uint64_t flags, std::uint64_t mode, std::stop_token stop) {
    if (path.empty() || path.size() > 16 * 1024 || path.find('\0') != std::string_view::npos ||
        bytes.empty() || bytes.size() > 256 * 1024 * 1024 || offset > UINT64_MAX - bytes.size())
        return Error{ErrorCode::invalid_argument, "RSP remote file write requires a valid path and 1..256 MiB non-overflowing range"};
    const auto packet_limit = std::min(max_packet_, peer_packet_size_);
    const auto open = "vFile:open:" + encode_hex(std::as_bytes(std::span(path.data(), path.size()))) +
        "," + hex_u64(flags) + "," + hex_u64(mode);
    if (open.size() > packet_limit) return Error{ErrorCode::resource_limit, "RSP remote file open packet exceeds negotiated limit"};
    auto response = transact(open, stop);
    if (!response) return response.error();
    if (response.value().empty()) return Error{ErrorCode::unsupported, "remote does not support vFile:open"};
    const auto parse_result = [](std::string_view reply, std::int64_t& result, std::uint64_t& error_number) {
        if (reply.empty() || reply.front() != 'F') return false;
        reply.remove_prefix(1);
        auto fields = reply.substr(0, reply.find(';'));
        auto comma = fields.find(',');
        auto value = fields.substr(0, comma);
        bool negative = !value.empty() && value.front() == '-';
        if (negative) value.remove_prefix(1);
        std::uint64_t magnitude = 0;
        if (!parse_hex(value, magnitude) || magnitude > static_cast<std::uint64_t>(INT64_MAX) + (negative ? 1u : 0u)) return false;
        result = negative ? (magnitude == static_cast<std::uint64_t>(INT64_MAX) + 1
            ? INT64_MIN : -static_cast<std::int64_t>(magnitude)) : static_cast<std::int64_t>(magnitude);
        error_number = 0;
        return comma == std::string_view::npos || parse_hex(fields.substr(comma + 1), error_number);
    };
    std::int64_t opened = 0; std::uint64_t remote_errno = 0;
    if (!parse_result(response.value(), opened, remote_errno)) return Error{ErrorCode::malformed, "invalid RSP vFile:open reply"};
    if (opened < 0) return Error{ErrorCode::io, "remote vFile:open failed with errno " + std::to_string(remote_errno)};
    const auto fd = static_cast<std::uint64_t>(opened);
    bool open_fd = true;
    const auto close_fd = [&]() -> Status {
        if (!open_fd) return std::monostate{};
        open_fd = false;
        auto closed = transact("vFile:close:" + hex_u64(fd), {});
        if (!closed) return closed.error();
        std::int64_t n = 0; std::uint64_t e = 0;
        if (closed.value().empty()) return Error{ErrorCode::unsupported, "remote does not support vFile:close"};
        if (!parse_result(closed.value(), n, e)) return Error{ErrorCode::malformed, "invalid RSP vFile:close reply"};
        if (n != 0) return Error{ErrorCode::io, "remote vFile:close failed with errno " + std::to_string(e)};
        return std::monostate{};
    };
    const auto fail = [&](Error error) -> Status {
        auto closed = close_fd();
        if (!closed) error.message += "; remote file close also failed: " + closed.error().message;
        return error;
    };
    std::size_t written = 0;
    while (written < bytes.size()) {
        if (stop.stop_requested()) return fail({ErrorCode::canceled, "RSP remote file write canceled"});
        const auto at = offset + static_cast<std::uint64_t>(written);
        const auto prefix = "vFile:pwrite:" + hex_u64(fd) + "," + hex_u64(at) + ",";
        if (prefix.size() + 1 > packet_limit) return fail({ErrorCode::resource_limit, "RSP peer packet limit cannot fit vFile:pwrite header"});
        const auto count = std::min({bytes.size() - written, (packet_limit - prefix.size()) / 2, std::size_t{64 * 1024}});
        if (!count) return fail({ErrorCode::resource_limit, "RSP peer packet limit cannot fit vFile:pwrite data"});
        auto command = prefix;
        command.append(reinterpret_cast<const char*>(bytes.data() + written), count);
        auto written_reply = transact(command, stop);
        if (!written_reply) return fail(written_reply.error());
        if (written_reply.value().empty()) return fail({ErrorCode::unsupported, "remote does not support vFile:pwrite"});
        std::int64_t actual = 0; std::uint64_t e = 0;
        if (!parse_result(written_reply.value(), actual, e)) return fail({ErrorCode::malformed, "invalid RSP vFile:pwrite reply"});
        if (actual < 0) return fail({ErrorCode::io, "remote vFile:pwrite failed with errno " + std::to_string(e)});
        if (static_cast<std::uint64_t>(actual) != count) return fail({ErrorCode::io, "remote vFile:pwrite completed a short write"});
        written += count;
    }
    return close_fd();
}
Result<std::vector<std::byte>> Client::read_remote_file_impl(std::string_view path,
    std::uint64_t file_offset, std::size_t maximum_size, bool probe_limit, std::stop_token stop) {
    if (path.empty() || path.size() > 16 * 1024 || path.find('\0') != std::string_view::npos)
        return Error{ErrorCode::invalid_argument, "RSP remote file path is empty, contains NUL, or exceeds 16 KiB"};
    if (maximum_size == 0 || maximum_size > 256 * 1024 * 1024)
        return Error{ErrorCode::invalid_argument, "RSP remote file limit must be between 1 byte and 256 MiB"};

    const auto packet_limit = std::min(max_packet_, peer_packet_size_);
    const auto open_command = "vFile:open:" + encode_hex(std::as_bytes(std::span(path.data(), path.size()))) + ",0,0";
    if (open_command.size() > packet_limit)
        return Error{ErrorCode::resource_limit, "RSP remote file open packet exceeds negotiated limit"};
    auto opened = transact(open_command, stop);
    if (!opened) return opened.error();
    if (opened.value().empty())
        return Error{ErrorCode::unsupported, "remote does not support vFile:open"};

    auto open_reply = parse_file_io_reply(opened.value());
    if (!open_reply) return open_reply.error();
    if (open_reply.value().result < 0)
        return Error{ErrorCode::io, "remote vFile:open failed with errno " +
            std::to_string(open_reply.value().error_number.value_or(0))};
    const auto descriptor = static_cast<std::uint64_t>(open_reply.value().result);
    bool is_open = true;
    const auto close_file = [&]() -> Status {
        if (!is_open) return std::monostate{};
        is_open = false;
        auto response = transact("vFile:close:" + hex_u64(descriptor), {});
        if (!response) return response.error();
        if (response.value().empty()) return Error{ErrorCode::unsupported, "remote stopped supporting vFile:close"};
        auto parsed = parse_file_io_reply(response.value());
        if (!parsed) return parsed.error();
        if (parsed.value().result != 0)
            return Error{ErrorCode::io, "remote vFile:close failed with errno " +
                std::to_string(parsed.value().error_number.value_or(0))};
        return std::monostate{};
    };
    const auto finish = [&](Error primary) -> Result<std::vector<std::byte>> {
        auto closed = close_file();
        if (!closed) primary.message += "; remote file close also failed: " + closed.error().message;
        return primary;
    };

    std::vector<std::byte> bytes;
    try { bytes.reserve(std::min<std::size_t>(maximum_size, 64 * 1024)); }
    catch (const std::bad_alloc &) { return finish({ErrorCode::resource_limit, "Cannot allocate RSP remote-file buffer"}); }
    catch (const std::length_error &) { return finish({ErrorCode::resource_limit, "RSP remote-file buffer exceeds host limits"}); }
    while (true) {
        if (!probe_limit && bytes.size() == maximum_size) break;
        if (stop.stop_requested()) return finish({ErrorCode::canceled, "RSP remote file read canceled"});
        const bool at_limit = bytes.size() == maximum_size;
        const auto prefix = "vFile:pread:" + hex_u64(descriptor) + ",";
        const auto offset = file_offset + static_cast<std::uint64_t>(bytes.size());
        const auto tail = "," + hex_u64(offset);
        if (prefix.size() + 1 + tail.size() > packet_limit)
            return finish({ErrorCode::resource_limit, "RSP peer packet limit cannot fit a vFile:pread header"});
        const auto request_capacity = packet_limit - prefix.size() - 1 - tail.size();
        const auto response_capacity = packet_limit > 40 ? (packet_limit - 40) / 2 : 0;
        const auto wire_capacity = std::min(request_capacity, response_capacity);
        auto request_size = at_limit ? std::size_t{1} : std::min({maximum_size - bytes.size(), wire_capacity, std::size_t{64 * 1024}});
        while (request_size != 0 && prefix.size() + hex_u64(request_size).size() + tail.size() > packet_limit)
            --request_size;
        if (request_size == 0)
            return finish({ErrorCode::resource_limit, "RSP peer packet limit cannot fit vFile:pread data"});
        auto response = transact(prefix + hex_u64(request_size) + tail, stop);
        if (!response) return finish(response.error());
        if (response.value().empty()) return finish({ErrorCode::unsupported, "remote does not support vFile:pread"});
        auto reply = parse_file_io_reply(response.value());
        if (!reply) return finish(reply.error());
        if (reply.value().result < 0)
            return finish({ErrorCode::io, "remote vFile:pread failed with errno " +
                std::to_string(reply.value().error_number.value_or(0))});
        if (!reply.value().has_attachment || static_cast<std::uint64_t>(reply.value().result) > request_size ||
            reply.value().attachment.size() != static_cast<std::size_t>(reply.value().result))
            return finish({ErrorCode::malformed, "RSP vFile:pread count and binary attachment disagree"});
        const auto count = static_cast<std::size_t>(reply.value().result);
        if (at_limit && count != 0)
            return finish({ErrorCode::resource_limit, "RSP remote file exceeds configured read limit"});
        if (count == 0) break;
        const auto *first = reinterpret_cast<const std::byte *>(reply.value().attachment.data());
        try { bytes.insert(bytes.end(), first, first + count); }
        catch (const std::bad_alloc &) { return finish({ErrorCode::resource_limit, "Cannot grow RSP remote-file buffer"}); }
        catch (const std::length_error &) { return finish({ErrorCode::resource_limit, "RSP remote-file buffer exceeds host limits"}); }
    }
    auto closed = close_file();
    if (!closed) return closed.error();
    return bytes;
}
Status Client::set_breakpoint(std::uint64_t address, BreakpointType type, std::uint8_t size, bool insert, std::stop_token stop) {
    if (size == 0 || address > UINT64_MAX - (static_cast<std::uint64_t>(size) - 1))
        return Error{ErrorCode::invalid_argument, "RSP breakpoint range is empty or overflows the address space"};
    const char* kind = nullptr;
    switch (type) {
    case BreakpointType::software: kind = "0"; break;
    case BreakpointType::hardware: kind = "1"; break;
    case BreakpointType::write_watch: kind = "2"; break;
    case BreakpointType::read_watch: kind = "3"; break;
    case BreakpointType::access_watch: kind = "4"; break;
    default: return Error{ErrorCode::invalid_argument, "invalid RSP breakpoint type"};
    }
    auto response = transact(std::string(insert ? "Z" : "z") + kind + "," + hex_u64(address) + "," + hex_u64(size), stop);
    if (!response) return response.error();
    if (response.value() == "OK") return std::monostate{};
    if (response.value().empty()) return Error{ErrorCode::unsupported, "remote does not support requested breakpoint"};
    return Error{ErrorCode::io, "remote rejected breakpoint command: " + response.value()};
}
Status Client::write_memory(std::uint64_t address, std::span<const std::byte> bytes, std::stop_token stop) {
    if (bytes.empty() || address > UINT64_MAX - bytes.size())
        return Error{ErrorCode::invalid_argument, "RSP memory write range is empty or overflows the address space"};
    const auto packet_limit = std::min(max_packet_, peer_packet_size_);
    if (packet_limit < 48)
        return Error{ErrorCode::resource_limit, "RSP peer packet limit is too small for a memory write"};

    // Try the binary X packet first. It avoids hex expansion for the normal
    // case. Bound each chunk for the worst case, where every byte needs RSP
    // escaping; the packet-size feature counts encoded data characters.
    std::size_t offset = 0;
    while (offset < bytes.size()) {
        const auto current = address + offset;
        const auto x_prefix = "X" + hex_u64(current) + ",";
        const auto remaining = bytes.size() - offset;
        // Reserve the full 64-bit length field so the chosen data count is
        // safe before its hexadecimal width is known.
        const auto x_header_size = x_prefix.size() + 16 + 1;
        if (x_header_size >= packet_limit)
            return Error{ErrorCode::resource_limit, "RSP peer packet limit cannot fit a binary memory-write header"};
        const auto x_capacity = (packet_limit - x_header_size) / 2;
        const auto x_count = std::min(remaining, x_capacity);
        if (x_count == 0)
            return Error{ErrorCode::resource_limit, "RSP peer packet limit cannot fit binary memory-write data"};
        const auto prefix = x_prefix + hex_u64(x_count) + ":";
        std::string command = prefix;
        command.append(reinterpret_cast<const char*>(bytes.data() + offset), x_count);
        auto response = transact(command, stop);
        if (!response) return response.error();
        if (response.value() == "OK") {
            offset += x_count;
            continue;
        }
        if (response.value().empty()) {
            // Empty is the protocol's unsupported-packet reply. Falling back
            // to M keeps older stubs usable; no bytes from this X packet were
            // accepted.
            break;
        }
        return Error{ErrorCode::io, "remote rejected binary memory write: " + response.value()};
    }
    if (offset == bytes.size()) return std::monostate{};

    // Hex M data expands by exactly two characters per byte, so it can use
    // the remaining advertised packet capacity without the binary worst-case
    // escape allowance.
    while (offset < bytes.size()) {
        const auto current = address + offset;
        const auto remaining = bytes.size() - offset;
        const auto m_prefix = "M" + hex_u64(current) + ",";
        if (m_prefix.size() + 16 + 1 >= packet_limit)
            return Error{ErrorCode::resource_limit, "RSP peer packet limit cannot fit a hex memory-write header"};
        const auto count = std::min(remaining, (packet_limit - (m_prefix.size() + 16 + 1)) / 2);
        if (count == 0)
            return Error{ErrorCode::resource_limit, "RSP peer packet limit cannot fit hex memory-write data"};
        const auto prefix = m_prefix + hex_u64(count) + ":";
        auto response = transact(prefix + encode_hex(bytes.subspan(offset, count)), stop);
        if (!response) return response.error();
        if (response.value() != "OK")
            return Error{ErrorCode::io, "remote rejected memory write: " + response.value()};
        offset += count;
    }
    return std::monostate{};
}
Status Client::program_flash(std::uint64_t address, std::span<const std::byte> bytes, std::stop_token stop) {
    constexpr std::size_t maximum_flash_bytes = 256 * 1024 * 1024;
    if (bytes.empty() || address > UINT64_MAX - (static_cast<std::uint64_t>(bytes.size()) - 1))
        return Error{ErrorCode::invalid_argument, "RSP flash range is empty or overflows the address space"};
    if (bytes.size() > maximum_flash_bytes)
        return Error{ErrorCode::resource_limit, "RSP flash programming exceeds the 256 MiB limit"};
    const auto packet_limit = std::min(max_packet_, peer_packet_size_);
    const auto erase = "vFlashErase:" + hex_u64(address) + "," + hex_u64(bytes.size());
    if (erase.size() > packet_limit)
        return Error{ErrorCode::resource_limit, "RSP flash erase packet exceeds the negotiated packet limit"};
    if (stop.stop_requested()) return Error{ErrorCode::canceled, "RSP flash programming canceled before erase"};

    const auto finish = [&](Error failure) -> Status {
        // vFlashDone closes the current flash operation. Make a best-effort
        // attempt even after an ambiguous erase, cancellation, or failed write.
        auto completed = transact("vFlashDone", {});
        std::string detail = std::move(failure.message);
        if (!completed) detail += "; vFlashDone failed: " + completed.error().message;
        else if (completed.value().empty()) detail += "; remote no longer accepts vFlashDone";
        else if (completed.value() != "OK") detail += "; remote rejected vFlashDone: " + completed.value();
        detail += "; flash contents may be partially erased or programmed";
        return Error{failure.code, std::move(detail)};
    };

    auto erased = transact(erase, stop);
    if (!erased) return finish(erased.error());
    if (erased.value().empty()) return Error{ErrorCode::unsupported, "remote does not support vFlashErase"};
    if (erased.value() != "OK")
        return Error{ErrorCode::io, "remote rejected vFlashErase: " + erased.value()};

    std::size_t offset = 0;
    while (offset < bytes.size()) {
        if (stop.stop_requested())
            return finish(Error{ErrorCode::canceled, "RSP flash programming canceled"});
        const auto current = address + offset;
        const auto prefix = "vFlashWrite:" + hex_u64(current) + ":";
        if (prefix.size() >= packet_limit)
            return finish(Error{ErrorCode::resource_limit, "RSP peer packet limit cannot fit a flash-write header"});
        const auto count = std::min(bytes.size() - offset, (packet_limit - prefix.size()) / 2);
        if (count == 0)
            return finish(Error{ErrorCode::resource_limit, "RSP peer packet limit cannot fit flash-write data"});
        std::string command = prefix;
        command.append(reinterpret_cast<const char *>(bytes.data() + offset), count);
        auto written = transact(command, stop);
        if (!written) return finish(written.error());
        if (written.value().empty())
            return finish(Error{ErrorCode::unsupported, "remote does not support vFlashWrite"});
        if (written.value() != "OK")
            return finish(Error{ErrorCode::io, "remote rejected vFlashWrite: " + written.value()});
        offset += count;
    }

    if (stop.stop_requested())
        return finish(Error{ErrorCode::canceled, "RSP flash programming canceled before vFlashDone"});
    auto completed = transact("vFlashDone", stop);
    if (!completed) return Error{completed.error().code,
        completed.error().message + "; flash contents may be partially erased or programmed"};
    if (completed.value().empty())
        return Error{ErrorCode::unsupported, "remote does not support vFlashDone; flash contents may be partially erased or programmed"};
    if (completed.value() != "OK")
        return Error{ErrorCode::io, "remote rejected vFlashDone: " + completed.value() +
            "; flash contents may be partially erased or programmed"};
    return std::monostate{};
}
Status Client::program_flash_in_regions(std::uint64_t address, std::span<const std::byte> bytes,
                                        std::span<const MemoryRegion> regions, std::stop_token stop) {
    if (bytes.empty() || address > UINT64_MAX - (static_cast<std::uint64_t>(bytes.size()) - 1))
        return Error{ErrorCode::invalid_argument, "RSP flash range is empty or overflows the address space"};
    const auto last = address + static_cast<std::uint64_t>(bytes.size()) - 1;
    std::size_t containing_flash_regions = 0;
    const MemoryRegion* containing_flash_region = nullptr;
    for (const auto& region : regions) {
        if (region.type != "flash" || region.length == 0 ||
            region.start > UINT64_MAX - (region.length - 1)) continue;
        const auto region_last = region.start + region.length - 1;
        if (address >= region.start && last <= region_last) {
            ++containing_flash_regions;
            containing_flash_region = &region;
        }
    }
    if (containing_flash_regions == 0)
        return Error{ErrorCode::invalid_argument, "RSP flash range is not wholly contained in a flash memory-map region"};
    if (containing_flash_regions != 1)
        return Error{ErrorCode::invalid_argument, "RSP flash range is ambiguously covered by multiple flash regions"};
    if (containing_flash_region->flash_block_size) {
        const auto block_size = *containing_flash_region->flash_block_size;
        if (!block_size || block_size > containing_flash_region->length ||
            containing_flash_region->start % block_size != 0 ||
            containing_flash_region->length % block_size != 0)
            return Error{ErrorCode::invalid_argument, "RSP memory map contains an invalid flash erase block size"};
        if ((address - containing_flash_region->start) % block_size != 0 ||
            static_cast<std::uint64_t>(bytes.size()) % block_size != 0)
            return Error{ErrorCode::invalid_argument,
                "RSP flash range is not aligned to the memory-map erase block size"};
    }
    if (stop.stop_requested())
        return Error{ErrorCode::canceled, "RSP flash programming canceled before map-validated erase"};
    return program_flash(address, bytes, stop);
}
Status Client::program_flash_verified_in_regions(std::uint64_t address,
    std::span<const std::byte> bytes, std::span<const MemoryRegion> regions, std::stop_token stop) {
    if (bytes.empty() || bytes.size() > 256 * 1024 * 1024 ||
        address > UINT64_MAX - (static_cast<std::uint64_t>(bytes.size()) - 1))
        return Error{ErrorCode::invalid_argument,
            "RSP verified flash range must be 1..256 MiB and not overflow the address space"};
    const auto last = address + static_cast<std::uint64_t>(bytes.size()) - 1;
    std::size_t containing_flash_regions = 0;
    const MemoryRegion* containing_flash_region = nullptr;
    for (const auto& region : regions) {
        if (region.type != "flash" || region.length == 0 ||
            region.start > UINT64_MAX - (region.length - 1)) continue;
        const auto region_last = region.start + region.length - 1;
        if (address >= region.start && last <= region_last) {
            ++containing_flash_regions;
            containing_flash_region = &region;
        }
    }
    if (containing_flash_regions != 1)
        return Error{ErrorCode::invalid_argument, containing_flash_regions == 0
            ? "RSP flash range is not wholly contained in a flash memory-map region"
            : "RSP flash range is ambiguously covered by multiple flash regions"};
    if (containing_flash_region->flash_block_size) {
        const auto block_size = *containing_flash_region->flash_block_size;
        if (!block_size || block_size > containing_flash_region->length ||
            containing_flash_region->start % block_size != 0 ||
            containing_flash_region->length % block_size != 0)
            return Error{ErrorCode::invalid_argument, "RSP memory map contains an invalid flash erase block size"};
        if ((address - containing_flash_region->start) % block_size != 0 ||
            static_cast<std::uint64_t>(bytes.size()) % block_size != 0)
            return Error{ErrorCode::invalid_argument,
                "RSP verified flash range is not aligned to the memory-map erase block size"};
    }
    if (stop.stop_requested())
        return Error{ErrorCode::canceled, "RSP verified flash programming canceled before preflight"};

    // Confirm the peer can answer qCRC before beginning the destructive flash sequence.
    auto capability_probe = memory_crc32(address, static_cast<std::uint64_t>(bytes.size()), stop);
    if (!capability_probe) return capability_probe.error();

    std::uint32_t expected_crc = 0xffffffffu;
    for (const auto byte : bytes) {
        expected_crc ^= std::to_integer<std::uint8_t>(byte);
        for (unsigned bit = 0; bit < 8; ++bit)
            expected_crc = (expected_crc >> 1) ^ (0xedb88320u & (0u - (expected_crc & 1u)));
    }
    expected_crc ^= 0xffffffffu;

    auto programmed = program_flash(address, bytes, stop);
    if (!programmed) return programmed.error();
    auto actual_crc = memory_crc32(address, static_cast<std::uint64_t>(bytes.size()), stop);
    if (!actual_crc)
        return Error{actual_crc.error().code, actual_crc.error().message +
            "; flash was programmed but readback verification did not complete"};
    if (actual_crc.value() != expected_crc)
        return Error{ErrorCode::conflict,
            "RSP flash CRC-32 verification mismatch; flash was programmed but contents differ"};
    return std::monostate{};
}
Status Client::select_thread(std::uint64_t thread, std::stop_token stop) {
    return select_thread(hex_u64(thread), stop);
}
Status Client::select_thread(std::string_view thread_id, std::stop_token stop) {
    if (!valid_thread_selection_id(thread_id))
        return Error{ErrorCode::invalid_argument, "invalid RSP thread selector"};
    auto response = transact("Hg" + std::string(thread_id), stop);
    if (!response) return response.error();
    if (response.value() == "OK") return std::monostate{};
    if (response.value().empty()) return Error{ErrorCode::unsupported, "remote does not support thread selection"};
    return Error{ErrorCode::io, "remote rejected thread selection: " + response.value()};
}
} // namespace hexlab::debugger::rsp
