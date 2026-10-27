#include "hexlab/debugger/rsp.hpp"

#include <algorithm>
#include <array>
#include <charconv>
#include <limits>
#include <set>

namespace hexlab::debugger::rsp {
namespace {
constexpr std::size_t max_pending_notifications = 4096;
Error io_error(std::string message) { return {ErrorCode::io, std::move(message)}; }
int hex_digit(char c) {
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
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
        if (!packet.value().first)
            return Error{ErrorCode::malformed, "RSP response packet arrived before its acknowledgement"};
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
    auto supported = transact("qSupported:multiprocess+;swbreak+;hwbreak+;vContSupported+;QThreadEvents+", stop);
    if (!supported) return supported.error();
    Capabilities result;
    std::string_view rest = supported.value();
    while (!rest.empty()) {
        auto end = rest.find(';'); auto token = rest.substr(0, end);
        auto split = token.find('=');
        auto name = token.substr(0, split);
        auto value = split == std::string_view::npos ? std::string{} : std::string(token.substr(split + 1));
        if (split == std::string_view::npos && !name.empty() && (name.back() == '+' || name.back() == '-')) {
            value = name.back(); name.remove_suffix(1);
        }
        result.features.emplace(std::string(name), std::move(value));
        if (end == std::string_view::npos) break; rest.remove_prefix(end + 1);
    }
    if (const auto feature = result.features.find("QNonStop"); feature != result.features.end())
        result.non_stop_supported = feature->second == "+";
    if (const auto feature = result.features.find("QThreadEvents"); feature != result.features.end())
        result.thread_events_supported = feature->second == "+";
    thread_events_supported_ = result.thread_events_supported;
    non_stop_supported_ = result.non_stop_supported;
    peer_packet_size_ = std::min<std::size_t>(max_packet_, 4096);
    if (const auto feature = result.features.find("PacketSize"); feature != result.features.end()) {
        std::size_t advertised = 0;
        if (parse_hex(feature->second, advertised) && advertised != 0)
            peer_packet_size_ = std::min(max_packet_, advertised);
    }
    if (const auto feature = result.features.find("QStartNoAckMode");
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
        if (id.starts_with('p')) {
            const auto qualified = id.substr(1);
            const auto dot = qualified.find('.');
            if (dot == std::string_view::npos || !valid_hex_id(qualified.substr(0, dot)) ||
                !valid_hex_id(qualified.substr(dot + 1)))
                return Error{ErrorCode::invalid_argument, "invalid multiprocess thread ID in vCont schedule"};
        } else if (!valid_hex_id(id)) {
            return Error{ErrorCode::invalid_argument, "invalid thread ID in vCont schedule"};
        }
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
    auto response = transact("g", stop); if (!response) return response.error(); return decode_hex(response.value());
}
Result<std::optional<std::string>> Client::read_feature_annex(std::string_view annex, std::size_t limit,
    std::size_t chunk, std::stop_token stop) {
    if (annex.empty() || annex.size() > 256 || annex.find_first_of(":,;#$\r\n") != std::string_view::npos ||
        limit == 0 || limit > 1024 * 1024 || chunk == 0 || chunk > 64 * 1024 || chunk > max_packet_ / 2)
        return Error{ErrorCode::invalid_argument, "invalid RSP feature annex bounds or name"};
    std::string result;
    for (std::size_t offset = 0; offset <= limit;) {
        const auto request_size = std::min(chunk, limit - std::min(offset, limit));
        if (offset == limit && request_size == 0) return Error{ErrorCode::resource_limit, "RSP feature annex exceeds configured limit"};
        auto response = transact("qXfer:features:read:" + std::string(annex) + ":" +
            hex_u64(offset) + "," + hex_u64(request_size), stop);
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
    if (limit == 0 || limit > 1024 * 1024 || chunk == 0 || chunk > 64 * 1024 || chunk > max_packet_ / 2)
        return Error{ErrorCode::invalid_argument, "invalid RSP libraries annex bounds"};
    std::string result;
    for (std::size_t offset = 0; offset <= limit;) {
        const auto request_size = std::min(chunk, limit - std::min(offset, limit));
        if (offset == limit && request_size == 0) return Error{ErrorCode::resource_limit, "RSP libraries annex exceeds configured limit"};
        auto response = transact("qXfer:libraries:read::" + hex_u64(offset) + "," + hex_u64(request_size), stop);
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
}
Result<std::optional<std::string>> Client::read_memory_map_annex(std::size_t limit, std::size_t chunk, std::stop_token stop) {
    if (limit == 0 || limit > 1024 * 1024 || chunk == 0 || chunk > 64 * 1024 || chunk > max_packet_ / 2)
        return Error{ErrorCode::invalid_argument, "invalid RSP memory-map annex bounds"};
    std::string result;
    for (std::size_t offset = 0; offset <= limit;) {
        const auto request_size = std::min(chunk, limit - std::min(offset, limit));
        if (offset == limit && request_size == 0) return Error{ErrorCode::resource_limit, "RSP memory-map annex exceeds configured limit"};
        auto response = transact("qXfer:memory-map:read::" + hex_u64(offset) + "," + hex_u64(request_size), stop);
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
    if (limit == 0 || limit > 1024 * 1024 || chunk == 0 || chunk > 64 * 1024 || chunk > max_packet_ / 2)
        return Error{ErrorCode::invalid_argument, "invalid RSP thread annex bounds"};
    std::string result;
    for (std::size_t offset = 0; offset <= limit;) {
        const auto request_size = std::min(chunk, limit - std::min(offset, limit));
        if (offset == limit && request_size == 0)
            return Error{ErrorCode::resource_limit, "RSP thread annex exceeds configured limit"};
        auto response = transact("qXfer:threads:read::" + hex_u64(offset) + "," + hex_u64(request_size), stop);
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
    if (!valid_type || limit == 0 || limit > 1024 * 1024 || chunk == 0 ||
        chunk > 64 * 1024 || chunk > max_packet_ / 2)
        return Error{ErrorCode::invalid_argument, "invalid RSP OS-data annex type or bounds"};
    std::string result;
    for (std::size_t offset = 0; offset <= limit;) {
        const auto request_size = std::min(chunk, limit - std::min(offset, limit));
        if (offset == limit && request_size == 0)
            return Error{ErrorCode::resource_limit, "RSP OS-data annex exceeds configured limit"};
        auto response = transact("qXfer:osdata:read:" + std::string(type) + ":" + hex_u64(offset) + "," + hex_u64(request_size), stop);
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
    const auto bounded_chunk = std::min(chunk, packet_limit / 2);
    const auto process_token = process ? hex_u64(*process) : std::string{};
    std::string result;
    for (std::size_t offset = 0; offset <= limit;) {
        const auto request_size = std::min(bounded_chunk, limit - std::min(offset, limit));
        if (offset == limit && request_size == 0)
            return Error{ErrorCode::resource_limit, "RSP executable-file path exceeds configured limit"};
        auto response = transact("qXfer:exec-file:read:" + process_token + ":" +
            hex_u64(offset) + "," + hex_u64(request_size), stop);
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
    const auto bounded_chunk = std::min(chunk, packet_limit / 2);
    std::vector<std::byte> result;
    result.reserve(std::min(limit, bounded_chunk));
    for (std::size_t offset = 0; offset <= limit;) {
        const auto request_size = std::min(bounded_chunk, limit - std::min(offset, limit));
        if (offset == limit && request_size == 0)
            return Error{ErrorCode::resource_limit, "RSP auxiliary-vector annex exceeds configured limit"};
        auto response = transact("qXfer:auxv:read::" + hex_u64(offset) + "," + hex_u64(request_size), stop);
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
    const auto bounded_chunk = std::min(chunk, packet_limit / 2);
    std::vector<std::byte> result;
    result.reserve(std::min(limit, bounded_chunk));
    for (std::size_t offset = 0; offset <= limit;) {
        const auto request_size = std::min(bounded_chunk, limit - std::min(offset, limit));
        if (offset == limit && request_size == 0)
            return Error{ErrorCode::resource_limit, "RSP siginfo annex exceeds configured limit"};
        auto response = transact("qXfer:siginfo:read::" + hex_u64(offset) + "," + hex_u64(request_size), stop);
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
    auto response = transact("p" + hex_u64(number), stop); if (!response) return response.error(); return decode_hex(response.value());
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
    if (size > std::numeric_limits<std::uint64_t>::max() || address > UINT64_MAX - size || size > max_packet_ / 2)
        return Error{ErrorCode::invalid_argument, "RSP memory range is invalid or exceeds limit"};
    auto response = transact("m" + hex_u64(address) + "," + hex_u64(size), stop); if (!response) return response.error();
    auto bytes = decode_hex(response.value()); if (!bytes) return bytes.error();
    if (bytes.value().size() != size) return Error{ErrorCode::malformed, "RSP memory reply has unexpected length"};
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
