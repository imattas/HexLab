#include "hexlab/debugger/debugger.hpp"
#include "hexlab/debugger/rsp.hpp"

#include <charconv>
#include <algorithm>
#include <array>
#include <cctype>
#include <limits>
#include <map>
#include <set>
#include <utility>

namespace hexlab::debugger {
namespace {
using namespace std::chrono_literals;

bool parse_hex_value(std::string_view value, std::uint64_t& out) {
    if (value.starts_with("0x") || value.starts_with("0X")) value.remove_prefix(2);
    if (value.empty()) return false;
    const auto [end, error] = std::from_chars(value.data(), value.data() + value.size(), out, 16);
    return error == std::errc{} && end == value.data() + value.size();
}
std::string hex_thread_token(std::uint64_t value) {
    std::array<char, 16> buffer{};
    const auto [end, error] = std::to_chars(buffer.data(), buffer.data() + buffer.size(), value, 16);
    return error == std::errc{} ? std::string(buffer.data(), end) : std::string{};
}

struct TargetRegister { std::string name, group; std::size_t number = 0, bits = 0; };
struct TargetDescription { Architecture architecture = Architecture::unknown; bool big_endian = false; std::vector<TargetRegister> registers; };
struct RemoteThreadDescription { std::string id, name; ThreadState state = ThreadState::unknown; };
struct RemoteProcessDescription { std::uint64_t id = 0; std::string command; };
bool xml_name_char(char c) { return std::isalnum(static_cast<unsigned char>(c)) || c == '_' || c == '-' || c == ':' || c == '.'; }
bool valid_thread_wire_id(std::string_view value) {
    const auto positive_id = [](std::string_view text) {
        std::uint64_t id = 0;
        return !text.empty() && text.size() <= 16 &&
            text.find_first_not_of("0123456789abcdefABCDEF") == std::string_view::npos &&
            parse_hex_value(text, id) && id != 0;
    };
    if (value.starts_with('p')) {
        value.remove_prefix(1);
        const auto dot = value.find('.');
        if (dot == std::string_view::npos || dot == 0 || dot + 1 == value.size()) return false;
        return positive_id(value.substr(0, dot)) && positive_id(value.substr(dot + 1));
    }
    return positive_id(value);
}
std::optional<std::uint64_t> thread_process_id(std::string_view value) {
    if (!value.starts_with('p')) return std::nullopt;
    value.remove_prefix(1);
    const auto dot = value.find('.');
    if (dot == std::string_view::npos || dot == 0 || dot + 1 == value.size()) return std::nullopt;
    std::uint64_t process = 0;
    if (!parse_hex_value(value.substr(0, dot), process) || process == 0) return std::nullopt;
    return process;
}
Result<std::string> decode_xml_text(std::string_view value) {
    std::string decoded;
    decoded.reserve(value.size());
    while (!value.empty()) {
        if (value.front() != '&') { decoded.push_back(value.front()); value.remove_prefix(1); continue; }
        const auto entity_end = value.find(';');
        if (entity_end == std::string_view::npos) return Error{ErrorCode::malformed, "unterminated XML entity in thread metadata"};
        const auto entity = value.substr(0, entity_end + 1);
        if (entity == "&amp;") decoded.push_back('&');
        else if (entity == "&lt;") decoded.push_back('<');
        else if (entity == "&gt;") decoded.push_back('>');
        else if (entity == "&quot;") decoded.push_back('"');
        else if (entity == "&apos;") decoded.push_back('\'');
        else if (entity.starts_with("&#") && entity.size() > 3) {
            auto digits = entity.substr(2, entity.size() - 3);
            int base = 10;
            if (digits.starts_with('x') || digits.starts_with('X')) { base = 16; digits.remove_prefix(1); }
            std::uint32_t codepoint = 0;
            const auto [end, error] = std::from_chars(digits.data(), digits.data() + digits.size(), codepoint, base);
            if (digits.empty() || error != std::errc{} || end != digits.data() + digits.size() ||
                codepoint == 0 || codepoint > 0x10ffff || (codepoint >= 0xd800 && codepoint <= 0xdfff))
                return Error{ErrorCode::malformed, "invalid numeric XML entity in thread metadata"};
            if (codepoint <= 0x7f) decoded.push_back(static_cast<char>(codepoint));
            else if (codepoint <= 0x7ff) {
                decoded.push_back(static_cast<char>(0xc0 | (codepoint >> 6)));
                decoded.push_back(static_cast<char>(0x80 | (codepoint & 0x3f)));
            } else if (codepoint <= 0xffff) {
                decoded.push_back(static_cast<char>(0xe0 | (codepoint >> 12)));
                decoded.push_back(static_cast<char>(0x80 | ((codepoint >> 6) & 0x3f)));
                decoded.push_back(static_cast<char>(0x80 | (codepoint & 0x3f)));
            } else {
                decoded.push_back(static_cast<char>(0xf0 | (codepoint >> 18)));
                decoded.push_back(static_cast<char>(0x80 | ((codepoint >> 12) & 0x3f)));
                decoded.push_back(static_cast<char>(0x80 | ((codepoint >> 6) & 0x3f)));
                decoded.push_back(static_cast<char>(0x80 | (codepoint & 0x3f)));
            }
        } else return Error{ErrorCode::unsupported, "unsupported XML entity in thread metadata"};
            value.remove_prefix(entity_end + 1);
    }
    return decoded;
}
Result<std::vector<RemoteProcessDescription>> parse_processes_xml(std::string_view xml) {
    if (xml.empty() || xml.size() > 1024 * 1024)
        return Error{ErrorCode::resource_limit, "RSP process XML is empty or exceeds 1 MiB"};
    std::vector<RemoteProcessDescription> processes;
    std::set<std::uint64_t> seen;
    std::vector<std::string> stack;
    std::map<std::string, std::string, std::less<>> fields;
    std::string column_name, column_text;
    bool root_seen = false, root_closed = false, item_open = false, column_open = false;
    std::size_t position = 0;
    const auto parse_attributes = [](std::string_view body,
        std::map<std::string, std::string, std::less<>> &attributes) -> Status {
        while (!body.empty()) {
            while (!body.empty() && std::isspace(static_cast<unsigned char>(body.front()))) body.remove_prefix(1);
            if (body.empty()) break;
            std::size_t key_size = 0;
            while (key_size < body.size() && xml_name_char(body[key_size])) ++key_size;
            if (!key_size) return Error{ErrorCode::malformed, "invalid RSP process XML attribute"};
            std::string key(body.substr(0, key_size)); body.remove_prefix(key_size);
            while (!body.empty() && std::isspace(static_cast<unsigned char>(body.front()))) body.remove_prefix(1);
            if (body.empty() || body.front() != '=') return Error{ErrorCode::malformed, "invalid RSP process XML attribute"};
            body.remove_prefix(1);
            while (!body.empty() && std::isspace(static_cast<unsigned char>(body.front()))) body.remove_prefix(1);
            if (body.empty() || (body.front() != '\'' && body.front() != '"'))
                return Error{ErrorCode::malformed, "invalid RSP process XML attribute value"};
            const char quote = body.front(); body.remove_prefix(1);
            const auto value_end = body.find(quote);
            if (value_end == std::string_view::npos)
                return Error{ErrorCode::malformed, "unterminated RSP process XML attribute"};
            auto value = decode_xml_text(body.substr(0, value_end));
            if (!value) return value.error();
            if (!attributes.emplace(std::move(key), std::move(value.value())).second)
                return Error{ErrorCode::malformed, "duplicate RSP process XML attribute"};
            body.remove_prefix(value_end + 1);
        }
        return std::monostate{};
    };
    while (position < xml.size()) {
        const auto open = xml.find('<', position);
        const auto text_end = open == std::string_view::npos ? xml.size() : open;
        const auto text = xml.substr(position, text_end - position);
        if (column_open) {
            auto decoded = decode_xml_text(text);
            if (!decoded) return decoded.error();
            if (decoded.value().size() > 4096 - std::min<std::size_t>(column_text.size(), 4096))
                return Error{ErrorCode::resource_limit, "RSP process column exceeds 4096 bytes"};
            column_text += decoded.value();
        } else if (text.find_first_not_of(" \t\r\n") != std::string_view::npos) {
            return Error{ErrorCode::malformed, "unexpected text in RSP process XML"};
        }
        if (open == std::string_view::npos) { position = xml.size(); break; }
        position = open;
        if (xml.substr(position).starts_with("<!--")) {
            const auto end = xml.find("-->", position + 4);
            if (end == std::string_view::npos) return Error{ErrorCode::malformed, "unterminated RSP process XML comment"};
            position = end + 3; continue;
        }
        if (xml.substr(position).starts_with("<?")) {
            const auto end = xml.find("?>", position + 2);
            if (end == std::string_view::npos) return Error{ErrorCode::malformed, "unterminated RSP process XML declaration"};
            position = end + 2; continue;
        }
        const auto close = xml.find('>', position + 1);
        if (close == std::string_view::npos) return Error{ErrorCode::malformed, "unterminated RSP process XML tag"};
        auto body = xml.substr(position + 1, close - position - 1);
        position = close + 1;
        if (body.starts_with("!DOCTYPE")) {
            auto declaration = body.substr(8);
            while (!declaration.empty() && std::isspace(static_cast<unsigned char>(declaration.front()))) declaration.remove_prefix(1);
            while (!declaration.empty() && std::isspace(static_cast<unsigned char>(declaration.back()))) declaration.remove_suffix(1);
            if (!stack.empty() || (declaration != "target SYSTEM \"osdata.dtd\"" &&
                                   declaration != "target SYSTEM 'osdata.dtd'" &&
                                   declaration != "osdata SYSTEM \"osdata.dtd\"" &&
                                   declaration != "osdata SYSTEM 'osdata.dtd'"))
                return Error{ErrorCode::unsupported, "unsupported RSP process XML document type"};
            continue;
        }
        if (body.empty() || body.front() == '!')
            return Error{ErrorCode::unsupported, "unsupported RSP process XML declaration"};
        const bool closing = body.front() == '/';
        if (closing) body.remove_prefix(1);
        while (!body.empty() && std::isspace(static_cast<unsigned char>(body.front()))) body.remove_prefix(1);
        std::size_t name_size = 0;
        while (name_size < body.size() && xml_name_char(body[name_size])) ++name_size;
        if (!name_size) return Error{ErrorCode::malformed, "invalid RSP process XML tag name"};
        const std::string tag(body.substr(0, name_size));
        body.remove_prefix(name_size);
        if (closing) {
            while (!body.empty() && std::isspace(static_cast<unsigned char>(body.back()))) body.remove_suffix(1);
            if (!body.empty() || stack.empty() || stack.back() != tag)
                return Error{ErrorCode::malformed, "mismatched RSP process XML closing tag"};
            stack.pop_back();
            if (tag == "column") {
                column_open = false;
                auto value = column_text;
                while (!value.empty() && std::isspace(static_cast<unsigned char>(value.front()))) value.erase(value.begin());
                while (!value.empty() && std::isspace(static_cast<unsigned char>(value.back()))) value.pop_back();
                if (!fields.emplace(column_name, std::move(value)).second)
                    return Error{ErrorCode::malformed, "duplicate RSP process column"};
            } else if (tag == "item") {
                item_open = false;
                const auto pid = fields.find("pid");
                if (pid == fields.end() || pid->second.empty())
                    return Error{ErrorCode::malformed, "RSP process item has no PID column"};
                std::uint64_t id = 0;
                const auto [end, error] = std::from_chars(pid->second.data(), pid->second.data() + pid->second.size(), id, 10);
                if (error != std::errc{} || end != pid->second.data() + pid->second.size() || id == 0)
                    return Error{ErrorCode::malformed, "invalid RSP process PID"};
                if (!seen.insert(id).second) return Error{ErrorCode::malformed, "duplicate RSP process PID"};
                if (processes.size() >= max_inspection_processes)
                    return Error{ErrorCode::resource_limit, "RSP process count exceeds limit"};
                processes.push_back({id, fields.contains("command") ? fields.at("command") : std::string{}});
                fields.clear();
            } else if (tag == "osdata") root_closed = true;
            continue;
        }
        bool self_closing = false;
        auto tail = body;
        while (!tail.empty() && std::isspace(static_cast<unsigned char>(tail.back()))) tail.remove_suffix(1);
        if (!tail.empty() && tail.back() == '/') { self_closing = true; body = tail.substr(0, tail.size() - 1); }
        std::map<std::string, std::string, std::less<>> attributes;
        auto parsed = parse_attributes(body, attributes);
        if (!parsed) return parsed.error();
        if (tag == "osdata") {
            const auto type = attributes.find("type");
            if (root_seen || !stack.empty() || type == attributes.end() || type->second != "processes")
                return Error{ErrorCode::malformed, "invalid RSP process XML root"};
            root_seen = true;
        } else if (tag == "item") {
            if (!root_seen || root_closed || stack.size() != 1 || stack.back() != "osdata" ||
                item_open || processes.size() >= max_inspection_processes)
                return Error{ErrorCode::malformed, "RSP process item is outside its root"};
            item_open = true; fields.clear();
        } else if (tag == "column") {
            if (!item_open || column_open || stack.size() != 2 || stack.back() != "item")
                return Error{ErrorCode::malformed, "RSP process column is outside an item"};
            if (fields.size() >= 64)
                return Error{ErrorCode::resource_limit, "RSP process item has too many columns"};
            const auto name = attributes.find("name");
            if (name == attributes.end() || name->second.empty())
                return Error{ErrorCode::malformed, "RSP process column has no name"};
            column_name = name->second; column_text.clear(); column_open = true;
        } else return Error{ErrorCode::unsupported, "unsupported RSP process XML element"};
        if (!self_closing) stack.push_back(tag);
        else if (tag == "osdata") root_closed = true;
        else if (tag == "item") {
            // A self-closing item cannot provide the mandatory PID column.
            return Error{ErrorCode::malformed, "empty RSP process item has no PID column"};
        } else if (tag == "column") {
            column_open = false;
            if (!fields.emplace(column_name, std::string{}).second)
                return Error{ErrorCode::malformed, "duplicate RSP process column"};
        }
    }
    if (!root_seen || !root_closed || !stack.empty() || item_open || column_open)
        return Error{ErrorCode::malformed, "incomplete RSP process XML document"};
    if (processes.empty()) return Error{ErrorCode::malformed, "RSP process XML contains no process items"};
    return processes;
}
Result<std::vector<RemoteThreadDescription>> parse_threads_xml(std::string_view xml) {
    if (xml.empty() || xml.size() > 1024 * 1024)
        return Error{ErrorCode::resource_limit, "RSP threads XML is empty or exceeds 1 MiB"};
    std::vector<RemoteThreadDescription> threads;
    std::set<std::string, std::less<>> seen;
    std::vector<std::string> stack;
    bool root_seen = false, root_closed = false;
    std::size_t position = 0;
    while (position < xml.size()) {
        const auto open = xml.find('<', position);
        if (open == std::string_view::npos) {
            const auto tail = xml.substr(position);
            if (tail.find_first_not_of(" \t\r\n") != std::string_view::npos &&
                (stack.empty() || stack.back() != "state"))
                return Error{ErrorCode::malformed, "unexpected text after threads XML tag"};
            if (!stack.empty() && stack.back() == "state") {
                auto state = tail;
                while (!state.empty() && std::isspace(static_cast<unsigned char>(state.front()))) state.remove_prefix(1);
                while (!state.empty() && std::isspace(static_cast<unsigned char>(state.back()))) state.remove_suffix(1);
                if (!threads.empty()) {
                    if (state == "running") threads.back().state = ThreadState::running;
                    else if (state == "stopped") threads.back().state = ThreadState::stopped;
                    else if (state == "exited") threads.back().state = ThreadState::exited;
                }
            }
            position = xml.size();
            break;
        }
        const auto text = xml.substr(position, open - position);
        if (text.find_first_not_of(" \t\r\n") != std::string_view::npos &&
            (stack.empty() || stack.back() != "state" || text.find('&') != std::string_view::npos))
            return Error{ErrorCode::malformed, "unexpected text in threads XML"};
        if (!stack.empty() && stack.back() == "state") {
            auto state = text;
            while (!state.empty() && std::isspace(static_cast<unsigned char>(state.front()))) state.remove_prefix(1);
            while (!state.empty() && std::isspace(static_cast<unsigned char>(state.back()))) state.remove_suffix(1);
            if (!threads.empty()) {
                if (state == "running") threads.back().state = ThreadState::running;
                else if (state == "stopped") threads.back().state = ThreadState::stopped;
                else if (state == "exited") threads.back().state = ThreadState::exited;
                else if (!state.empty()) return Error{ErrorCode::unsupported, "unknown RSP thread state"};
            }
        }
        position = open;
        if (xml.substr(position).starts_with("<!--")) {
            const auto end = xml.find("-->", position + 4);
            if (end == std::string_view::npos) return Error{ErrorCode::malformed, "unterminated threads XML comment"};
            position = end + 3; continue;
        }
        if (xml.substr(position).starts_with("<?")) {
            const auto end = xml.find("?>", position + 2);
            if (end == std::string_view::npos) return Error{ErrorCode::malformed, "unterminated threads XML declaration"};
            position = end + 2; continue;
        }
        const auto close = xml.find('>', position + 1);
        if (close == std::string_view::npos) return Error{ErrorCode::malformed, "unterminated threads XML tag"};
        auto body = xml.substr(position + 1, close - position - 1);
        position = close + 1;
        if (body.empty() || body.front() == '!') return Error{ErrorCode::unsupported, "threads XML declarations are unsupported"};
        const bool closing = body.front() == '/';
        if (closing) body.remove_prefix(1);
        while (!body.empty() && std::isspace(static_cast<unsigned char>(body.front()))) body.remove_prefix(1);
        std::size_t name_size = 0;
        while (name_size < body.size() && xml_name_char(body[name_size])) ++name_size;
        if (!name_size) return Error{ErrorCode::malformed, "invalid threads XML tag name"};
        const std::string tag(body.substr(0, name_size));
        body.remove_prefix(name_size);
        if (closing) {
            while (!body.empty() && std::isspace(static_cast<unsigned char>(body.back()))) body.remove_suffix(1);
            if (!body.empty() || stack.empty() || stack.back() != tag)
                return Error{ErrorCode::malformed, "mismatched threads XML closing tag"};
            stack.pop_back();
            if (tag == "threads") root_closed = true;
            continue;
        }
        bool self_closing = false;
        auto tail = body;
        while (!tail.empty() && std::isspace(static_cast<unsigned char>(tail.back()))) tail.remove_suffix(1);
        if (!tail.empty() && tail.back() == '/') { self_closing = true; body = tail.substr(0, tail.size() - 1); }
        std::map<std::string, std::string, std::less<>> attrs;
        while (!body.empty()) {
            while (!body.empty() && std::isspace(static_cast<unsigned char>(body.front()))) body.remove_prefix(1);
            if (body.empty()) break;
            std::size_t key_size = 0;
            while (key_size < body.size() && xml_name_char(body[key_size])) ++key_size;
            if (!key_size) return Error{ErrorCode::malformed, "invalid threads XML attribute"};
            std::string key(body.substr(0, key_size)); body.remove_prefix(key_size);
            while (!body.empty() && std::isspace(static_cast<unsigned char>(body.front()))) body.remove_prefix(1);
            if (body.empty() || body.front() != '=') return Error{ErrorCode::malformed, "invalid threads XML attribute"};
            body.remove_prefix(1);
            while (!body.empty() && std::isspace(static_cast<unsigned char>(body.front()))) body.remove_prefix(1);
            if (body.empty() || (body.front() != '\'' && body.front() != '"')) return Error{ErrorCode::malformed, "invalid threads XML attribute value"};
            const char quote = body.front(); body.remove_prefix(1);
            const auto value_end = body.find(quote);
            if (value_end == std::string_view::npos) return Error{ErrorCode::malformed, "unterminated threads XML attribute"};
            const auto value = body.substr(0, value_end);
            auto decoded_value = decode_xml_text(value);
            if (!decoded_value) return decoded_value.error();
            if (!attrs.emplace(std::move(key), std::move(decoded_value.value())).second)
                return Error{ErrorCode::malformed, "invalid or duplicate threads XML attribute"};
            body.remove_prefix(value_end + 1);
        }
        if (tag == "threads") {
            if (root_seen || closing || !stack.empty()) return Error{ErrorCode::malformed, "invalid threads XML root"};
            root_seen = true;
        } else if (tag == "thread") {
            if (!root_seen || root_closed || stack.size() != 1 || stack.back() != "threads")
                return Error{ErrorCode::malformed, "thread entry is outside the threads root"};
            const auto id = attrs.find("id");
            if (id == attrs.end() || !valid_thread_wire_id(id->second))
                return Error{ErrorCode::malformed, "invalid or missing RSP thread ID in XML"};
            if (!seen.emplace(id->second).second) return Error{ErrorCode::malformed, "duplicate RSP thread ID in XML"};
            if (threads.size() >= 65536) return Error{ErrorCode::resource_limit, "RSP thread count exceeds limit"};
            RemoteThreadDescription value{id->second, "thread " + id->second, ThreadState::unknown};
            if (const auto name = attrs.find("name"); name != attrs.end() && !name->second.empty()) value.name = name->second;
            if (const auto state = attrs.find("state"); state != attrs.end()) {
                if (state->second == "running") value.state = ThreadState::running;
                else if (state->second == "stopped") value.state = ThreadState::stopped;
                else if (state->second == "exited") value.state = ThreadState::exited;
                else return Error{ErrorCode::unsupported, "unknown RSP thread state"};
            }
            threads.push_back(std::move(value));
        } else if (tag == "state") {
            if (stack.size() != 2 || stack.back() != "thread")
                return Error{ErrorCode::malformed, "thread state is outside a thread entry"};
        } else return Error{ErrorCode::unsupported, "unsupported RSP threads XML element"};
        if (!self_closing) stack.push_back(tag);
        else if (tag == "threads") root_closed = true;
    }
    if (!root_seen || !root_closed || !stack.empty()) return Error{ErrorCode::malformed, "incomplete threads XML document"};
    if (threads.empty()) return Error{ErrorCode::malformed, "threads XML contains no thread entries"};
    return threads;
}
// Annexes are interpreted as remote object names, never local paths or URLs.
// Parse inclusions in place so implicit register numbering and feature groups
// follow the same order as an equivalent single-document description.
struct TargetXmlContext {
    rsp::Client& client;
    TargetDescription target{};
    std::size_t next_regnum = 0;
    std::size_t bytes = 0;
    std::size_t documents = 1;
    std::set<std::string, std::less<>> active_annexes{"target.xml"};
};
bool standard_target_doctype(std::string_view body) {
    const auto whitespace = [&body] {
        while (!body.empty() && std::isspace(static_cast<unsigned char>(body.front()))) body.remove_prefix(1);
    };
    const auto token = [&body, &whitespace]() {
        whitespace();
        const auto end = body.find_first_of(" \t\r\n");
        const auto value = body.substr(0, end);
        body.remove_prefix(end == std::string_view::npos ? body.size() : end);
        return value;
    };
    if (token() != "!DOCTYPE") return false;
    const auto root = token();
    if ((root != "target" && root != "feature") || token() != "SYSTEM") return false;
    whitespace();
    if (body.empty() || (body.front() != '\'' && body.front() != '"')) return false;
    const char quote = body.front(); body.remove_prefix(1);
    const auto end = body.find(quote);
    if (end == std::string_view::npos || body.substr(0, end) != "gdb-target.dtd") return false;
    body.remove_prefix(end + 1); whitespace();
    return body.empty();
}
Status parse_target_xml_document(std::string_view xml, TargetXmlContext& context,
    std::size_t depth, std::string current_feature = {}) {
    if (xml.empty() || xml.size() > 1024 * 1024) return Error{ErrorCode::resource_limit, "target XML is empty or exceeds 1 MiB"};
    if (xml.size() > 1024 * 1024 - context.bytes)
        return Error{ErrorCode::resource_limit, "target XML annexes exceed the aggregate 1 MiB limit"};
    context.bytes += xml.size();
    auto& out = context.target;
    auto& next_regnum = context.next_regnum;
    std::vector<std::string> stack;
    std::size_t pos = 0;
    while (pos < xml.size()) {
        const auto open = xml.find('<', pos);
        if (open == std::string_view::npos) {
            if (xml.find('>', pos) != std::string_view::npos) return Error{ErrorCode::malformed, "malformed target XML text"};
            break;
        }
        pos = open;
        if (xml.substr(pos).starts_with("<!--")) {
            const auto end = xml.find("-->", pos + 4); if (end == std::string_view::npos) return Error{ErrorCode::malformed, "unterminated target XML comment"};
            pos = end + 3; continue;
        }
        if (xml.substr(pos).starts_with("<?")) {
            const auto end = xml.find("?>", pos + 2); if (end == std::string_view::npos) return Error{ErrorCode::malformed, "unterminated target XML declaration"};
            pos = end + 2; continue;
        }
        const auto end = xml.find('>', pos + 1); if (end == std::string_view::npos) return Error{ErrorCode::malformed, "unterminated target XML tag"};
        auto body = xml.substr(pos + 1, end - pos - 1); pos = end + 1;
        if (body.starts_with("!DOCTYPE")) {
            // Recognize GDB's conventional declaration without resolving its DTD.
            // Internal subsets and other external identifiers remain unsupported.
            if (!stack.empty() || !standard_target_doctype(body))
                return Error{ErrorCode::unsupported, "unsupported target XML document declaration"};
            continue;
        }
        if (body.empty() || body.front() == '!') return Error{ErrorCode::unsupported, "target XML declarations are unsupported"};
        bool closing = body.front() == '/'; if (closing) body.remove_prefix(1);
        while (!body.empty() && std::isspace(static_cast<unsigned char>(body.front()))) body.remove_prefix(1);
        std::size_t n = 0; while (n < body.size() && xml_name_char(body[n])) ++n;
        if (!n) return Error{ErrorCode::malformed, "invalid target XML tag name"};
        const std::string tag(body.substr(0, n)); body.remove_prefix(n);
        auto parse_attrs = [](std::string_view text, std::map<std::string, std::string, std::less<>>& attrs) -> bool {
            while (!text.empty()) {
                while (!text.empty() && std::isspace(static_cast<unsigned char>(text.front()))) text.remove_prefix(1);
                if (text.empty() || text == "/") return true;
                std::size_t k = 0; while (k < text.size() && xml_name_char(text[k])) ++k;
                if (!k) return false;
                std::string key(text.substr(0, k)); text.remove_prefix(k);
                while (!text.empty() && std::isspace(static_cast<unsigned char>(text.front()))) text.remove_prefix(1);
                if (text.empty() || text.front() != '=') return false; text.remove_prefix(1);
                while (!text.empty() && std::isspace(static_cast<unsigned char>(text.front()))) text.remove_prefix(1);
                if (text.empty() || (text.front() != '\'' && text.front() != '"')) return false;
                const char quote = text.front(); text.remove_prefix(1); const auto close = text.find(quote);
                if (close == std::string_view::npos) return false;
                auto value = text.substr(0, close); if (value.find('&') != std::string_view::npos || value.find('<') != std::string_view::npos) return false;
                if (!attrs.emplace(std::move(key), std::string(value)).second) return false;
                text.remove_prefix(close + 1);
            }
            return true;
        };
        std::map<std::string, std::string, std::less<>> attrs;
        if (closing) {
            while (!body.empty() && std::isspace(static_cast<unsigned char>(body.back()))) body.remove_suffix(1);
            if (!body.empty() || stack.empty() || stack.back() != tag) return Error{ErrorCode::malformed, "mismatched target XML closing tag"};
            stack.pop_back(); if (tag == "feature") current_feature.clear(); continue;
        }
        bool self_closing = false;
        auto tail = body; while (!tail.empty() && std::isspace(static_cast<unsigned char>(tail.back()))) tail.remove_suffix(1);
        if (!tail.empty() && tail.back() == '/') { self_closing = true; body = tail.substr(0, tail.size() - 1); }
        if (!parse_attrs(body, attrs)) return Error{ErrorCode::malformed, "invalid target XML attributes"};
        if (tag == "xi:include") {
            const auto href = attrs.find("href");
            if (!self_closing || href == attrs.end() || href->second.empty())
                return Error{ErrorCode::malformed, "target XML include requires a self-closing element and href"};
            for (const auto& [name, value] : attrs) {
                if (name != "href" && (name != "xmlns:xi" || value != "http://www.w3.org/2001/XInclude"))
                    return Error{ErrorCode::unsupported, "unsupported target XML include attribute"};
            }
            if (context.active_annexes.contains(href->second))
                return Error{ErrorCode::malformed, "target XML feature inclusion cycle"};
            if (depth + 1 >= 16 || context.documents >= 64 || context.bytes >= 1024 * 1024)
                return Error{ErrorCode::resource_limit, "target XML inclusion depth, count, or aggregate size limit exceeded"};
            ++context.documents;
            auto included = context.client.read_feature_annex(href->second, 1024 * 1024 - context.bytes);
            if (!included) return included.error();
            if (!included.value())
                return Error{ErrorCode::unsupported, "remote does not provide included target XML annex: " + href->second};
            context.active_annexes.insert(href->second);
            auto parsed = parse_target_xml_document(*included.value(), context, depth + 1, current_feature);
            context.active_annexes.erase(href->second);
            if (!parsed) return parsed.error();
            continue;
        }
        if (tag == "include" || tag.ends_with(":include"))
            return Error{ErrorCode::unsupported, "unsupported target XML include namespace"};
        if (tag == "target") {
            if (const auto endian = attrs.find("endian"); endian != attrs.end()) {
                if (endian->second == "big") out.big_endian = true;
                else if (endian->second != "little") return Error{ErrorCode::malformed, "unknown target XML byte order"};
            }
        } else if (tag == "feature") {
            const auto name = attrs.find("name"); if (name == attrs.end() || name->second.empty()) return Error{ErrorCode::malformed, "target XML feature has no name"};
            current_feature = name->second;
        } else if (tag == "reg") {
            if (out.registers.size() >= 1024) return Error{ErrorCode::resource_limit, "target XML register count exceeds 1024"};
            const auto name = attrs.find("name"), bits = attrs.find("bitsize");
            if (name == attrs.end() || name->second.empty() || bits == attrs.end()) return Error{ErrorCode::malformed, "target XML register lacks name or bitsize"};
            std::size_t bit_count = 0; auto [bit_end, bit_err] = std::from_chars(bits->second.data(), bits->second.data() + bits->second.size(), bit_count);
            if (bit_err != std::errc{} || bit_end != bits->second.data() + bits->second.size() || bit_count == 0 || bit_count > 4096)
                return Error{ErrorCode::malformed, "invalid target XML register bitsize"};
            std::size_t regnum = next_regnum;
            if (const auto number = attrs.find("regnum"); number != attrs.end()) {
                auto [num_end, num_err] = std::from_chars(number->second.data(), number->second.data() + number->second.size(), regnum);
                if (num_err != std::errc{} || num_end != number->second.data() + number->second.size() || regnum > 4095)
                    return Error{ErrorCode::malformed, "invalid target XML register number"};
            }
            if (std::any_of(out.registers.begin(), out.registers.end(), [regnum](const auto& r) { return r.number == regnum; }))
                return Error{ErrorCode::malformed, "duplicate target XML register number"};
            if (regnum != next_regnum) return Error{ErrorCode::unsupported, "target XML register numbering contains gaps or reordering"};
            const auto group = attrs.find("group");
            out.registers.push_back({name->second, group == attrs.end() ? current_feature : group->second, regnum, bit_count});
            next_regnum = regnum + 1;
        } else if (tag == "architecture") {
            const auto close = xml.find("</architecture>", pos);
            if (close == std::string_view::npos) return Error{ErrorCode::malformed, "unterminated target architecture"};
            auto name = xml.substr(pos, close - pos);
            while (!name.empty() && std::isspace(static_cast<unsigned char>(name.front()))) name.remove_prefix(1);
            while (!name.empty() && std::isspace(static_cast<unsigned char>(name.back()))) name.remove_suffix(1);
            if (name == "i386:x86-64" || name == "i386:x86_64") out.architecture = Architecture::x86_64;
            else if (name == "i386" || name == "i386:x86-32") out.architecture = Architecture::x86;
            else if (name == "aarch64" || name == "aarch64: little endian") out.architecture = Architecture::arm64;
            else if (name == "arm" || name.starts_with("armv")) out.architecture = Architecture::arm;
            else if (name.starts_with("riscv:rv64") || name == "riscv64") out.architecture = Architecture::riscv64;
            else out.architecture = Architecture::unknown;
            if (stack.size() >= 64) return Error{ErrorCode::resource_limit, "target XML nesting exceeds 64"};
            stack.push_back(tag);
            pos = close; continue;
        }
        if (!self_closing) { if (stack.size() >= 64) return Error{ErrorCode::resource_limit, "target XML nesting exceeds 64"}; stack.push_back(tag); }
    }
    if (!stack.empty()) return Error{ErrorCode::malformed, "unclosed target XML element"};
    return std::monostate{};
}
Result<TargetDescription> parse_target_xml(std::string_view xml, rsp::Client& client) {
    TargetXmlContext context{client};
    auto parsed = parse_target_xml_document(xml, context, 0);
    if (!parsed) return parsed.error();
    auto& out = context.target;
    if (out.registers.empty()) return Error{ErrorCode::unsupported, "target XML contains no usable registers"};
    std::size_t total = 0; for (const auto& reg : out.registers) { const auto bytes = (reg.bits + 7) / 8; if (bytes > 512 || total > 64 * 1024 - bytes) return Error{ErrorCode::resource_limit, "target XML register storage exceeds limit"}; total += bytes; }
    return std::move(out);
}

Result<std::vector<ModuleInfo>> parse_libraries_xml(std::string_view xml) {
    if (xml.empty() || xml.size() > 1024 * 1024) return Error{ErrorCode::resource_limit, "libraries XML is empty or exceeds 1 MiB"};
    std::vector<ModuleInfo> modules;
    std::size_t pos = 0;
    bool in_library = false;
    while (pos < xml.size()) {
        auto open = xml.find('<', pos);
        if (open == std::string_view::npos) break;
        auto close = xml.find('>', open + 1);
        if (close == std::string_view::npos) return Error{ErrorCode::malformed, "unterminated libraries XML tag"};
        auto tag = xml.substr(open + 1, close - open - 1); pos = close + 1;
        if (tag.starts_with("?")) continue;
        if (tag.starts_with("!")) return Error{ErrorCode::unsupported, "libraries XML declarations are unsupported"};
        const bool closing = tag.starts_with("/"); if (closing) tag.remove_prefix(1);
        const bool self_closing = !tag.empty() && tag.back() == '/'; if (self_closing) tag.remove_suffix(1);
        while (!tag.empty() && std::isspace(static_cast<unsigned char>(tag.front()))) tag.remove_prefix(1);
        std::size_t n = 0; while (n < tag.size() && xml_name_char(tag[n])) ++n;
        if (!n) return Error{ErrorCode::malformed, "invalid libraries XML tag"};
        const auto name = tag.substr(0, n); auto attrs_text = tag.substr(n);
        if (closing) {
            while (!attrs_text.empty() && std::isspace(static_cast<unsigned char>(attrs_text.back()))) attrs_text.remove_suffix(1);
            if (!attrs_text.empty() || (name == "library" && !in_library)) return Error{ErrorCode::malformed, "mismatched libraries XML closing tag"};
            if (name == "library") in_library = false;
            continue;
        }
        std::map<std::string, std::string, std::less<>> attrs;
        while (!attrs_text.empty()) {
            while (!attrs_text.empty() && std::isspace(static_cast<unsigned char>(attrs_text.front()))) attrs_text.remove_prefix(1);
            if (attrs_text.empty() || attrs_text == "/") break;
            std::size_t k = 0; while (k < attrs_text.size() && xml_name_char(attrs_text[k])) ++k;
            if (!k) return Error{ErrorCode::malformed, "invalid libraries XML attribute"};
            std::string key(attrs_text.substr(0, k)); attrs_text.remove_prefix(k);
            while (!attrs_text.empty() && std::isspace(static_cast<unsigned char>(attrs_text.front()))) attrs_text.remove_prefix(1);
            if (attrs_text.empty() || attrs_text.front() != '=') return Error{ErrorCode::malformed, "invalid libraries XML attribute"};
            attrs_text.remove_prefix(1); while (!attrs_text.empty() && std::isspace(static_cast<unsigned char>(attrs_text.front()))) attrs_text.remove_prefix(1);
            if (attrs_text.empty() || (attrs_text.front() != '\'' && attrs_text.front() != '"')) return Error{ErrorCode::malformed, "invalid libraries XML attribute value"};
            const char quote = attrs_text.front(); attrs_text.remove_prefix(1); const auto end = attrs_text.find(quote);
            if (end == std::string_view::npos || attrs_text.substr(0, end).find('<') != std::string_view::npos)
                return Error{ErrorCode::malformed, "invalid library attribute"};
            auto decoded = decode_xml_text(attrs_text.substr(0, end));
            if (!decoded) return decoded.error();
            if (!attrs.emplace(std::move(key), std::move(decoded.value())).second) return Error{ErrorCode::malformed, "duplicate libraries XML attribute"};
            attrs_text.remove_prefix(end + 1);
        }
        if (name == "library") {
            if (in_library) return Error{ErrorCode::malformed, "nested libraries XML library element"};
            if (modules.size() >= max_inspection_modules) return Error{ErrorCode::resource_limit, "remote module count exceeds limit"};
            const auto path = attrs.find("name"); if (path == attrs.end() || path->second.empty()) return Error{ErrorCode::malformed, "library has no name"};
            auto base = std::uint64_t{};
            if (const auto addr = attrs.find("text_addr"); addr != attrs.end() && !parse_hex_value(addr->second, base))
                return Error{ErrorCode::malformed, "invalid library text_addr"};
            auto display = path->second;
            const auto slash = display.find_last_of("/\\"); if (slash != std::string::npos) display.erase(0, slash + 1);
            modules.push_back({std::move(display), path->second, base, 0});
            in_library = !self_closing;
        } else if (name == "segment" && in_library) {
            const auto addr = attrs.find("address");
            if (addr == attrs.end() || !parse_hex_value(addr->second, modules.back().base)) return Error{ErrorCode::malformed, "invalid library segment address"};
        }
    }
    if (in_library) return Error{ErrorCode::malformed, "unclosed libraries XML library element"};
    return modules;
}

Result<std::vector<MemoryRegion>> parse_memory_map_xml(std::string_view xml) {
    if (xml.empty() || xml.size() > 1024 * 1024)
        return Error{ErrorCode::resource_limit, "memory-map XML is empty or exceeds 1 MiB"};
    std::vector<MemoryRegion> regions;
    std::vector<std::string> stack;
    bool root_seen = false, root_closed = false;
    std::size_t position = 0;
    std::string property_name, property_text;
    bool permissions_seen = false, native_type_seen = false;
    auto finish_property = [&]() -> Status {
        auto decoded = decode_xml_text(property_text);
        if (!decoded) return decoded.error();
        if (property_name == "permissions") {
            if (permissions_seen) return Error{ErrorCode::malformed, "duplicate memory-map permissions property"};
            std::string_view value = decoded.value();
            const auto first = value.find_first_not_of(" \t\r\n");
            if (first == std::string_view::npos)
                return Error{ErrorCode::malformed, "empty memory-map permissions property"};
            value = value.substr(first, value.find_last_not_of(" \t\r\n") - first + 1);
            if (value.size() != 3 || (value[0] != 'r' && value[0] != '-') ||
                (value[1] != 'w' && value[1] != '-') || (value[2] != 'x' && value[2] != '-'))
                return Error{ErrorCode::malformed, "invalid memory-map permissions property"};
            auto& region = regions.back();
            region.readable = value[0] == 'r';
            region.writable = value[1] == 'w';
            region.executable = value[2] == 'x';
            permissions_seen = true;
        } else if (property_name == "hexlab-type") {
            if (native_type_seen) return Error{ErrorCode::malformed, "duplicate memory-map native type property"};
            if (decoded.value().size() > 32 * 1024)
                return Error{ErrorCode::resource_limit, "memory-map native type exceeds 32 KiB"};
            regions.back().type = std::move(decoded.value());
            native_type_seen = true;
        }
        property_name.clear(); property_text.clear();
        return std::monostate{};
    };
    auto attributes = [](std::string_view text,
                         std::map<std::string, std::string, std::less<>>& result) -> bool {
        while (!text.empty()) {
            while (!text.empty() && std::isspace(static_cast<unsigned char>(text.front()))) text.remove_prefix(1);
            if (text.empty() || text == "/") return true;
            std::size_t key_size = 0;
            while (key_size < text.size() && xml_name_char(text[key_size])) ++key_size;
            if (!key_size) return false;
            std::string key(text.substr(0, key_size));
            text.remove_prefix(key_size);
            while (!text.empty() && std::isspace(static_cast<unsigned char>(text.front()))) text.remove_prefix(1);
            if (text.empty() || text.front() != '=') return false;
            text.remove_prefix(1);
            while (!text.empty() && std::isspace(static_cast<unsigned char>(text.front()))) text.remove_prefix(1);
            if (text.empty() || (text.front() != '\'' && text.front() != '"')) return false;
            const char quote = text.front();
            text.remove_prefix(1);
            const auto end = text.find(quote);
            if (end == std::string_view::npos || text.substr(0, end).find_first_of("&<") != std::string_view::npos)
                return false;
            if (!result.emplace(std::move(key), std::string(text.substr(0, end))).second) return false;
            text.remove_prefix(end + 1);
        }
        return true;
    };
    while (position < xml.size()) {
        const auto open = xml.find('<', position);
        if (open == std::string_view::npos) {
            auto text = xml.substr(position);
            if (text.find_first_not_of(" \t\r\n") != std::string_view::npos || !stack.empty())
                return Error{ErrorCode::malformed, "unexpected text after memory-map XML root"};
            position = xml.size();
            break;
        }
        auto text = xml.substr(position, open - position);
        if (!stack.empty() && stack.back() == "property") property_text.append(text);
        else if (text.find_first_not_of(" \t\r\n") != std::string_view::npos)
            return Error{ErrorCode::malformed, "unexpected text in memory-map XML"};
        position = open;
        if (xml.substr(position).starts_with("<!--")) {
            const auto end = xml.find("-->", position + 4);
            if (end == std::string_view::npos) return Error{ErrorCode::malformed, "unterminated memory-map XML comment"};
            position = end + 3;
            continue;
        }
        if (xml.substr(position).starts_with("<?")) {
            const auto end = xml.find("?>", position + 2);
            if (end == std::string_view::npos) return Error{ErrorCode::malformed, "unterminated memory-map XML declaration"};
            position = end + 2;
            continue;
        }
        const auto close = xml.find('>', position + 1);
        if (close == std::string_view::npos) return Error{ErrorCode::malformed, "unterminated memory-map XML tag"};
        auto body = xml.substr(position + 1, close - position - 1);
        position = close + 1;
        if (body.empty() || body.front() == '!') return Error{ErrorCode::unsupported, "memory-map XML declarations are unsupported"};
        const bool closing = body.front() == '/';
        if (closing) body.remove_prefix(1);
        while (!body.empty() && std::isspace(static_cast<unsigned char>(body.front()))) body.remove_prefix(1);
        std::size_t name_size = 0;
        while (name_size < body.size() && xml_name_char(body[name_size])) ++name_size;
        if (!name_size) return Error{ErrorCode::malformed, "invalid memory-map XML tag name"};
        const std::string name(body.substr(0, name_size));
        body.remove_prefix(name_size);
        if (closing) {
            while (!body.empty() && std::isspace(static_cast<unsigned char>(body.back()))) body.remove_suffix(1);
            if (!body.empty() || stack.empty() || stack.back() != name)
                return Error{ErrorCode::malformed, "mismatched memory-map XML closing tag"};
            if (name == "property") {
                auto parsed = finish_property();
                if (!parsed) return parsed.error();
            }
            stack.pop_back();
            if (name == "memory-map") root_closed = true;
            continue;
        }
        bool self_closing = false;
        auto tail = body;
        while (!tail.empty() && std::isspace(static_cast<unsigned char>(tail.back()))) tail.remove_suffix(1);
        if (!tail.empty() && tail.back() == '/') {
            self_closing = true;
            body = tail.substr(0, tail.size() - 1);
        }
        std::map<std::string, std::string, std::less<>> attrs;
        if (!attributes(body, attrs)) return Error{ErrorCode::malformed, "invalid memory-map XML attributes"};
        if ((!root_seen && name != "memory-map") || root_closed)
            return Error{ErrorCode::malformed, "unexpected memory-map XML root element"};
        if (name == "memory-map") {
            if (root_seen || !stack.empty() || root_closed || !attrs.empty())
                return Error{ErrorCode::malformed, "invalid memory-map XML root"};
            root_seen = true;
        } else if (name == "memory") {
            if (stack.size() != 1 || stack.back() != "memory-map" || regions.size() >= max_inspection_memory_regions)
                return Error{regions.size() >= max_inspection_memory_regions ? ErrorCode::resource_limit : ErrorCode::malformed,
                             "invalid or excessive memory-map region"};
            const auto type = attrs.find("type"), start_text = attrs.find("start"), length_text = attrs.find("length");
            std::uint64_t start = 0, length = 0;
            if (type == attrs.end() || start_text == attrs.end() || length_text == attrs.end() ||
                !parse_hex_value(start_text->second, start) || !parse_hex_value(length_text->second, length) ||
                length == 0 || length - 1 > std::numeric_limits<std::uint64_t>::max() - start ||
                (type->second != "ram" && type->second != "rom" && type->second != "flash"))
                return Error{ErrorCode::malformed, "invalid memory-map region type or extent"};
            MemoryRegion region{start, length, true, type->second == "ram", false, type->second};
            regions.push_back(std::move(region));
            permissions_seen = false; native_type_seen = false;
        } else if (name == "property") {
            if (stack.size() != 2 || stack.back() != "memory" || !attrs.contains("name"))
                return Error{ErrorCode::malformed, "invalid memory-map property"};
            property_name = attrs.at("name"); property_text.clear();
            if (self_closing) {
                auto parsed = finish_property();
                if (!parsed) return parsed.error();
            }
        } else {
            return Error{ErrorCode::unsupported, "unsupported memory-map XML element"};
        }
        if (!self_closing) {
            if (stack.size() >= 3) return Error{ErrorCode::resource_limit, "memory-map XML nesting exceeds limit"};
            stack.push_back(name);
        } else if (name == "memory-map") {
            root_closed = true;
        }
    }
    if (!root_seen || !root_closed || !stack.empty())
        return Error{ErrorCode::malformed, "incomplete memory-map XML document"};
    if (regions.empty()) return Error{ErrorCode::malformed, "memory-map XML contains no regions"};
    auto sorted = regions;
    std::sort(sorted.begin(), sorted.end(), [](const auto& a, const auto& b) { return a.start < b.start; });
    for (std::size_t i = 1; i < sorted.size(); ++i)
        if (sorted[i].start <= sorted[i - 1].start + sorted[i - 1].length - 1)
            return Error{ErrorCode::malformed, "overlapping memory-map regions"};
    return regions;
}

class RemoteBackend final : public Backend {
    struct InferiorState {
        std::optional<rsp::StopReply> pending_stop;
        std::map<std::string, ThreadState, std::less<>> thread_states;
        bool known_attached = false;
    };
public:
    explicit RemoteBackend(std::unique_ptr<rsp::ByteTransport> transport = {}) : transport_(std::move(transport)) {}
    bool supports_scheduled_signal_disposition() const noexcept override { return true; }
    Result<ProcessInfo> launch(const Target&) override { return unsupported("RSP targets must be connected by host and port"); }
    Result<ProcessInfo> attach(ProcessId) override { return unsupported("RSP attach is performed during host connection"); }
    Result<ProcessInfo> connect_remote(std::string_view host, std::uint16_t port) override {
        if (client_) return Error{ErrorCode::conflict, "remote debugger is already connected"};
        terminated_ = false;
        current_process_detach_rejected_ = false;
        remote_process_id_.reset();
        pending_event_signal_ = 0;
        if (!transport_) {
            auto transport = rsp::connect_tcp(host, port, 5s);
            if (!transport) return transport.error();
            transport_ = std::move(transport.value());
        }
        client_ = std::make_unique<rsp::Client>(*transport_, 3s, 1024 * 1024);
        auto features = client_->negotiate();
        if (!features) { client_.reset(); transport_.reset(); return features.error(); }
        multiprocess_supported_ = false;
        if (const auto multiprocess = features.value().features.find("multiprocess");
            multiprocess != features.value().features.end() && multiprocess->second != "-")
            multiprocess_supported_ = true;
        extended_mode_supported_ = false;
        if (multiprocess_supported_) {
            // vAttach is defined only after the server accepts the extended
            // remote mode request. Keep process enumeration available when a
            // stub advertises multiprocess but declines extended mode.
            auto extended = client_->request("!");
            if (!extended) { client_.reset(); transport_.reset(); return extended.error(); }
            extended_mode_supported_ = extended.value() == "OK";
        }
        non_stop_mode_ = false;
        if (features.value().non_stop_supported) {
            auto enabled = client_->set_non_stop_mode(true);
            if (enabled) non_stop_mode_ = true;
            else if (enabled.error().code != ErrorCode::unsupported) {
                client_.reset(); transport_.reset(); return enabled.error();
            }
        }
        supports_vcont_continue_ = false;
        supports_vcont_continue_signal_ = false;
        supports_vcont_thread_step_signal_ = false;
        supports_vcont_thread_continue_ = false;
        supports_vcont_thread_step_ = false;
        supports_vcont_thread_stop_ = false;
        const auto vcont = features.value().features.find("vContSupported");
        if (vcont != features.value().features.end() && vcont->second != "-") {
            auto actions = client_->request("vCont?");
            if (!actions) { client_.reset(); transport_.reset(); return actions.error(); }
            auto reply = std::string_view(actions.value());
            if (reply.starts_with("vCont;")) {
                reply.remove_prefix(6);
                while (!reply.empty()) {
                    const auto end = reply.find(';');
                    const auto action = reply.substr(0, end);
                    if (action == "c") { supports_vcont_continue_ = true; supports_vcont_thread_continue_ = true; }
                    else if (action.starts_with("c:") && action.size() > 2) supports_vcont_thread_continue_ = true;
                    else if (action == "C") supports_vcont_continue_signal_ = true;
                    else if (action.starts_with("C:") && action.size() > 2) supports_vcont_continue_signal_ = true;
                    // vCont? advertises action kinds (normally just "s"). The
                    // packet grammar allows an action to be qualified with a
                    // thread ID, so an advertised unqualified "s" also permits
                    // the backend to target the stopped thread precisely.
                    else if (action == "s" || (action.starts_with("s:") && action.size() > 2))
                        supports_vcont_thread_step_ = true;
                    else if (action == "S" || (action.starts_with("S:") && action.size() > 2)) {
                        supports_vcont_thread_step_signal_ = true;
                    }
                    else if (action == "t" || (action.starts_with("t:") && action.size() > 2))
                        supports_vcont_thread_stop_ = true;
                    if (end == std::string_view::npos) break;
                    reply.remove_prefix(end + 1);
                }
            }
        }
        target_.reset();
        remote_thread_tokens_.clear();
        thread_token_ids_.clear();
        thread_run_states_.clear();
        inferiors_.clear();
        next_thread_token_ = 1;
        target_xml_advertised_ = false;
        libraries_advertised_ = false;
        memory_map_advertised_ = false;
        threads_xml_advertised_ = false;
        osdata_advertised_ = false;
        const auto xml_feature = features.value().features.find("qXfer:features:read");
        if (xml_feature != features.value().features.end() && xml_feature->second != "-") {
            target_xml_advertised_ = true;
            auto target_xml = client_->read_feature_annex();
            if (!target_xml) { client_.reset(); transport_.reset(); return target_xml.error(); }
            if (target_xml.value()) {
                auto parsed = parse_target_xml(*target_xml.value(), *client_);
                if (!parsed) { client_.reset(); transport_.reset(); return parsed.error(); }
                target_ = std::move(parsed.value());
            }
        }
        const auto libraries = features.value().features.find("qXfer:libraries:read");
        libraries_advertised_ = libraries != features.value().features.end() && libraries->second != "-";
        const auto memory_map = features.value().features.find("qXfer:memory-map:read");
        memory_map_advertised_ = memory_map != features.value().features.end() && memory_map->second != "-";
        const auto threads_xml = features.value().features.find("qXfer:threads:read");
        threads_xml_advertised_ = threads_xml != features.value().features.end() && threads_xml->second != "-";
        const auto osdata = features.value().features.find("qXfer:osdata:read");
        osdata_advertised_ = osdata != features.value().features.end() && osdata->second != "-";
        auto initial = client_->read_stop_reply_optional();
        if (!initial) { client_.reset(); transport_.reset(); return initial.error(); }
        remote_process_id_.reset();
        if (initial.value()) {
            if (const auto thread = initial.value()->fields.find("thread"); thread != initial.value()->fields.end()) {
                if (!valid_thread_wire_id(thread->second)) {
                    client_.reset(); transport_.reset();
                    return Error{ErrorCode::malformed, "remote initial stop has an invalid thread ID"};
                }
                remote_process_id_ = thread_process_id(thread->second);
            }
            if (non_stop_mode_ && (initial.value()->kind == 'T' || initial.value()->kind == 'S') &&
                !initial.value()->fields.contains("thread")) {
                client_.reset(); transport_.reset();
                return unsupported("non-stop mode requires an exact thread ID in the initial stop reply");
            }
        }
        if (multiprocess_supported_ && !remote_process_id_) {
            client_.reset(); transport_.reset();
            return unsupported("multiprocess remote initial state must identify its exact pPID.TID");
        }
        if (!multiprocess_supported_ && remote_process_id_) {
            client_.reset(); transport_.reset();
            return Error{ErrorCode::malformed, "remote used a process-qualified thread ID without multiprocess negotiation"};
        }
        pending_stop_ = std::move(initial.value());
        if (const auto thread = pending_stop_->fields.find("thread"); thread != pending_stop_->fields.end())
            thread_run_states_[thread->second] = ThreadState::stopped;
        if (remote_process_id_) {
            auto& inferior = inferiors_[*remote_process_id_];
            inferior.known_attached = true;
            inferior.pending_stop = pending_stop_;
            for (const auto& [wire, state] : thread_run_states_)
                if (thread_process_id(wire) == remote_process_id_) inferior.thread_states[wire] = state;
        }
        host_ = std::string(host);
        const auto id = remote_process_id_.value_or(pending_stop_ && pending_stop_->thread ? pending_stop_->thread : 1);
        return ProcessInfo{id, host_ + ":" + std::to_string(port), target_ ? target_->architecture : Architecture::unknown};
    }
    Result<ProcessInfo> attach_remote_process(ProcessId process) override {
        if (!client_) return Error{ErrorCode::invalid_argument, "remote debugger is not connected"};
        if (!multiprocess_supported_)
            return unsupported("remote process attach requires negotiated multiprocess support");
        if (!extended_mode_supported_)
            return unsupported("remote process attach requires accepted extended-remote mode");
        if (process == 0) return Error{ErrorCode::invalid_argument, "remote process ID must be nonzero"};
        auto listed = processes();
        if (!listed) return listed.error();
        const auto found = std::find_if(listed.value().begin(), listed.value().end(),
            [process](const ProcessInfo& item) { return item.id == process; });
        if (found == listed.value().end())
            return Error{ErrorCode::out_of_bounds, "remote process ID is not in the current process list"};

        if (remote_process_id_) {
            auto& previous = inferiors_[*remote_process_id_];
            previous.known_attached = true;
            previous.pending_stop = pending_stop_;
            previous.thread_states.clear();
            for (const auto& [wire, state] : thread_run_states_)
                if (thread_process_id(wire) == remote_process_id_) previous.thread_states[wire] = state;
        }
        auto& selected = inferiors_[process];
        std::optional<rsp::StopReply> selected_stop;
        if (selected.known_attached) {
            auto selected_thread = client_->select_thread("p" + hex_thread_token(process) + ".-1");
            if (!selected_thread) return selected_thread.error();
            selected_stop = selected.pending_stop;
        } else {
            auto stopped = client_->attach_process(process);
            if (!stopped) return stopped.error();
            selected_stop = std::move(stopped.value());
        }
        remote_process_id_ = process;
        pending_stop_.reset();
        pending_event_.reset();
        pending_event_signal_ = 0;
        pending_event_thread_.clear();
        expected_step_threads_.clear();
        legacy_expected_step_ = false;
        // Restore only this inferior's cached thread states; other inferiors
        // remain resident in the map and are never rewritten by its stops.
        for (auto it = thread_run_states_.begin(); it != thread_run_states_.end();) {
            if (thread_process_id(it->first) == remote_process_id_) it = thread_run_states_.erase(it);
            else ++it;
        }
        for (const auto& [wire, state] : selected.thread_states) thread_run_states_[wire] = state;
        if (selected_stop) {
            const auto thread = selected_stop->fields.find("thread");
            if (thread == selected_stop->fields.end() || !valid_thread_wire_id(thread->second) ||
                thread_process_id(thread->second) != std::optional<std::uint64_t>(process)) {
                remote_process_id_.reset();
                return Error{ErrorCode::malformed, "vAttach stop reply does not identify a thread in the requested process"};
            }
            const auto wire_thread = thread->second;
            pending_stop_ = std::move(*selected_stop);
            thread_run_states_[wire_thread] = ThreadState::stopped;
        } else if (!non_stop_mode_ && !selected.known_attached) {
            remote_process_id_.reset();
            return Error{ErrorCode::malformed, "all-stop vAttach returned no initial stop"};
        }
        selected.known_attached = true;
        selected.pending_stop = pending_stop_;
        selected.thread_states = {};
        for (const auto& [wire, state] : thread_run_states_)
            if (thread_process_id(wire) == remote_process_id_) selected.thread_states[wire] = state;
        auto result = *found;
        if (result.name.empty()) result.name = "process " + std::to_string(process);
        return result;
    }
    Status detach_remote_process(ProcessId process) override {
        if (!client_) return Error{ErrorCode::invalid_argument, "remote debugger is not connected"};
        if (!multiprocess_supported_)
            return unsupported("remote secondary-process detach requires negotiated multiprocess support");
        if (process == 0 || (remote_process_id_ && process == *remote_process_id_))
            return Error{ErrorCode::invalid_argument, "secondary detach requires a nonzero process other than the selected process"};
        auto listed = processes();
        if (!listed) return listed.error();
        const auto found = std::find_if(listed.value().begin(), listed.value().end(),
            [process](const ProcessInfo& item) { return item.id == process; });
        if (found == listed.value().end())
            return Error{ErrorCode::out_of_bounds, "remote process ID is not in the current process list"};
        auto detached = client_->detach_process(process);
        if (!detached) return detached.error();

        const auto belongs_to_process = [process](std::string_view wire_id) {
            return thread_process_id(wire_id) == std::optional<std::uint64_t>(process);
        };
        for (auto it = thread_run_states_.begin(); it != thread_run_states_.end();) {
            if (belongs_to_process(it->first)) it = thread_run_states_.erase(it);
            else ++it;
        }
        for (auto it = remote_thread_tokens_.begin(); it != remote_thread_tokens_.end();) {
            if (belongs_to_process(it->first)) {
                thread_token_ids_.erase(it->second);
                it = remote_thread_tokens_.erase(it);
            } else ++it;
        }
        for (auto it = expected_step_threads_.begin(); it != expected_step_threads_.end();) {
            if (belongs_to_process(*it)) it = expected_step_threads_.erase(it);
            else ++it;
        }
        inferiors_.erase(process);
        return std::monostate{};
    }
    bool supports_remote_current_process_detach() const noexcept override {
        return client_ && multiprocess_supported_ && extended_mode_supported_ && remote_process_id_.has_value();
    }
    Status detach_remote_current_process(ProcessId process) override {
        if (!supports_remote_current_process_detach())
            return unsupported("independent selected-process detach requires an active multiprocess extended-remote session");
        if (process == 0 || process != *remote_process_id_)
            return Error{ErrorCode::invalid_argument, "selected-process detach ID does not match the active inferior"};
        auto listed = processes();
        if (!listed) return listed.error();
        if (std::none_of(listed.value().begin(), listed.value().end(),
                [process](const ProcessInfo& item) { return item.id == process; }))
            return Error{ErrorCode::out_of_bounds, "selected remote process ID is not in the current process list"};
        auto detached = client_->detach_process(process);
        if (!detached) {
            if (detached.error().code == ErrorCode::unsupported) current_process_detach_rejected_ = true;
            return detached.error();
        }
        const auto belongs_to_process = [process](std::string_view wire_id) {
            return thread_process_id(wire_id) == std::optional<std::uint64_t>(process);
        };
        for (auto it = thread_run_states_.begin(); it != thread_run_states_.end();) {
            if (belongs_to_process(it->first)) it = thread_run_states_.erase(it); else ++it;
        }
        for (auto it = remote_thread_tokens_.begin(); it != remote_thread_tokens_.end();) {
            if (belongs_to_process(it->first)) {
                thread_token_ids_.erase(it->second); it = remote_thread_tokens_.erase(it);
            } else ++it;
        }
        for (auto it = expected_step_threads_.begin(); it != expected_step_threads_.end();) {
            if (belongs_to_process(*it)) it = expected_step_threads_.erase(it); else ++it;
        }
        inferiors_.erase(process);
        pending_stop_.reset(); pending_event_.reset(); pending_event_thread_.clear(); pending_event_signal_ = 0;
        legacy_expected_step_ = false; remote_process_id_.reset(); breakpoints_.clear();
        return std::monostate{};
    }
    Status terminate() override {
        if (!client_) return Error{ErrorCode::invalid_argument, "remote debugger is not connected"};
        Status result = std::monostate{};
        if (multiprocess_supported_) {
            if (!remote_process_id_)
                return unsupported("remote advertised multiprocess mode but the stopped thread did not identify a process");
            result = client_->kill_process(*remote_process_id_);
        } else {
            result = client_->kill();
        }
        if (result) {
            if (multiprocess_supported_) {
                const auto killed_process = remote_process_id_;
                for (auto& [thread, state] : thread_run_states_)
                    if (killed_process && thread_process_id(thread) == killed_process)
                        state = ThreadState::exited;
                if (killed_process) {
                    auto& inferior = inferiors_[*killed_process];
                    inferior.pending_stop.reset();
                    inferior.thread_states.clear();
                    inferior.known_attached = false;
                }
                pending_stop_.reset(); pending_event_.reset(); pending_event_thread_.clear(); pending_event_signal_ = 0;
                expected_step_threads_.clear(); legacy_expected_step_ = false;
                breakpoints_.clear();
                // vKill;pid affects only that inferior. Keep the negotiated
                // connection alive so the caller can list or attach another.
                return std::monostate{};
            }
            for (auto& [thread, state] : thread_run_states_) state = ThreadState::exited;
            client_.reset(); transport_.reset(); pending_stop_.reset(); pending_event_.reset(); pending_event_thread_.clear(); pending_event_signal_ = 0;
            expected_step_threads_.clear(); legacy_expected_step_ = false; terminated_ = true; remote_process_id_.reset();
            breakpoints_.clear(); target_.reset(); target_xml_advertised_ = false; libraries_advertised_ = false;
            memory_map_advertised_ = false; threads_xml_advertised_ = false; multiprocess_supported_ = false;
            extended_mode_supported_ = false;
            non_stop_mode_ = false;
        }
        return result;
    }
    Status detach() override {
        if (!client_ && terminated_) { terminated_ = false; return std::monostate{}; }
        if (!client_) return Error{ErrorCode::invalid_argument, "remote debugger is not connected"};
        if (multiprocess_supported_ && !current_process_detach_rejected_) {
            if (remote_process_id_) {
                auto result = client_->detach_process(*remote_process_id_);
                if (!result) return result.error();
            } else {
                auto result = client_->request("D");
                if (!result) return result.error();
                if (result.value() != "OK")
                    return result.value().empty()
                        ? Status{Error{ErrorCode::unsupported, "remote does not support whole-session detach"}}
                        : Status{Error{ErrorCode::io, "remote rejected whole-session detach: " + result.value()}};
            }
        } else {
            auto result = client_->request("D");
            if (!result) return result.error();
            if (result.value() != "OK")
                return result.value().empty()
                    ? Status{Error{ErrorCode::unsupported, "remote does not support detach"}}
                    : Status{Error{ErrorCode::io, "remote rejected detach: " + result.value()}};
        }
        client_.reset(); transport_.reset(); pending_stop_.reset(); pending_event_.reset(); pending_event_thread_.clear(); pending_event_signal_ = 0;
        expected_step_threads_.clear(); legacy_expected_step_ = false;
        remote_thread_tokens_.clear(); thread_token_ids_.clear(); thread_run_states_.clear(); next_thread_token_ = 1;
        inferiors_.clear();
        breakpoints_.clear(); target_.reset(); target_xml_advertised_ = false; libraries_advertised_ = false;
        memory_map_advertised_ = false; threads_xml_advertised_ = false; multiprocess_supported_ = false;
        extended_mode_supported_ = false;
        non_stop_mode_ = false;
        remote_process_id_.reset(); terminated_ = false;
        current_process_detach_rejected_ = false;
        return std::monostate{};
    }
    Status request_interrupt() override {
        if (!client_) return Error{ErrorCode::invalid_argument, "remote debugger is not connected"};
        return client_->interrupt();
    }
    Result<DebugEvent> wait_event(std::chrono::milliseconds timeout) override {
        if (!client_) return Error{ErrorCode::invalid_argument, "remote debugger is not connected"};
        Result<rsp::StopReply> stopped = pending_stop_ ? Result<rsp::StopReply>(std::move(*pending_stop_)) :
            client_->wait_stop_reply(timeout);
        pending_stop_.reset();
        if (!stopped) {
            if (stopped.error().code == ErrorCode::busy) return stopped.error();
            if (stopped.error().code == ErrorCode::io && stopped.error().message.find("timed out") != std::string::npos)
                return Error{ErrorCode::busy, "remote target has not stopped yet"};
            return stopped.error();
        }
        DebugEvent event;
        event.sequence = ++sequence_;
        const auto stopped_thread = stopped.value().fields.find("thread");
        pending_event_thread_ = stopped_thread == stopped.value().fields.end() ? std::string{} : stopped_thread->second;
        pending_event_signal_ = stopped.value().signal;
        if (!pending_event_thread_.empty() && !valid_thread_wire_id(pending_event_thread_))
            return Error{ErrorCode::malformed, "remote stop does not identify a concrete thread"};
        if (non_stop_mode_ && (stopped.value().kind == 'T' || stopped.value().kind == 'S') &&
            pending_event_thread_.empty())
            return Error{ErrorCode::malformed, "non-stop stop reply does not identify its thread"};
        const auto stopped_process = thread_process_id(pending_event_thread_);
        event.process = stopped_process.value_or(
            multiprocess_supported_ ? 0 : remote_process_id_.value_or(0));
        if (stopped.value().kind == 'W' || stopped.value().kind == 'X') {
            const auto process = stopped.value().fields.find("process");
            std::uint64_t exit_process = 0;
            if (process != stopped.value().fields.end()) {
                if (!parse_hex_value(process->second, exit_process) || !exit_process)
                    return Error{ErrorCode::malformed, "remote exit has an invalid process ID"};
                event.process = exit_process;
            }
            if (multiprocess_supported_ && (!remote_process_id_ || event.process != *remote_process_id_))
                return unsupported("remote exit does not identify the session process");
        } else if (multiprocess_supported_ &&
                   (!remote_process_id_ || stopped_process != remote_process_id_ || pending_event_thread_.empty())) {
            return unsupported("remote stop does not identify a thread in the session process");
        } else if (!multiprocess_supported_ && stopped_process) {
            return Error{ErrorCode::malformed, "remote used a process-qualified thread ID without multiprocess negotiation"};
        }
        // A peer can stop a different thread before the requested step
        // completes. Do not label its trap as completion of our step, or lose
        // the process component of a multiprocess wire thread ID.
        const bool expected_step = legacy_expected_step_ || expected_step_threads_.contains(pending_event_thread_);
        if (expected_step && !legacy_expected_step_) expected_step_threads_.erase(pending_event_thread_);
        if (legacy_expected_step_) legacy_expected_step_ = false;
        event.thread = pending_event_thread_.empty() ? stopped.value().thread : thread_token(pending_event_thread_);
        if (stopped.value().kind == 'W' || stopped.value().kind == 'X') {
            event.kind = EventKind::process_exited;
            event.code = static_cast<std::uint32_t>(stopped.value().exit_code);
            event.message = "remote process exited";
            for (auto& [thread, state] : thread_run_states_)
                if (!multiprocess_supported_ || thread_process_id(thread) == std::optional<std::uint64_t>(event.process))
                    state = ThreadState::exited;
        } else {
            const auto& fields = stopped.value().fields;
            const auto lifecycle_reason = fields.find("reason");
            const bool watchpoint = fields.contains("watch") || fields.contains("rwatch") || fields.contains("awatch");
            const bool breakpoint = fields.contains("swbreak") || fields.contains("hwbreak") || watchpoint;
            event.kind = lifecycle_reason != fields.end() && lifecycle_reason->second == "thread-created" ? EventKind::thread_created :
                         lifecycle_reason != fields.end() && lifecycle_reason->second == "thread-exited" ? EventKind::thread_exited :
                         breakpoint ? EventKind::breakpoint :
                         stopped.value().signal == 5 && expected_step ? EventKind::single_step : EventKind::exception;
            event.code = stopped.value().signal;
            if (watchpoint) {
                const auto reason = fields.contains("rwatch") ? "read watchpoint" :
                                    fields.contains("awatch") ? "access watchpoint" : "watchpoint";
                event.message = "remote " + std::string(reason);
            } else if (fields.contains("swbreak")) event.message = "remote software breakpoint";
            else if (fields.contains("hwbreak")) event.message = "remote hardware breakpoint";
            else if (lifecycle_reason != fields.end() && lifecycle_reason->second == "thread-created") event.message = "remote thread created";
            else if (lifecycle_reason != fields.end() && lifecycle_reason->second == "thread-exited") event.message = "remote thread exited";
            else if (expected_step && event.kind == EventKind::single_step) event.message = "remote single-step completed";
            else event.message = "remote stop signal " + std::to_string(stopped.value().signal);
            for (const auto name : {"watch", "rwatch", "awatch", "pc"}) {
                const auto it = stopped.value().fields.find(name);
                std::uint64_t address = 0;
                if (it != stopped.value().fields.end() && parse_hex_value(it->second, address)) { event.address = address; break; }
            }
            // Only attach owned IDs when the stub supplied both the reason
            // and address. A generic SIGTRAP is not evidence of a breakpoint.
            for (const auto& [id, owned] : breakpoints_) {
                if (!owned.enabled) continue;
                if (multiprocess_supported_ && (!remote_process_id_ ||
                    thread_process_id(pending_event_thread_) != remote_process_id_)) continue;
                const char* reason = nullptr;
                switch (owned.kind) {
                case BreakpointKind::write: reason = "watch"; break;
                case BreakpointKind::read: reason = "rwatch"; break;
                case BreakpointKind::access: reason = "awatch"; break;
                case BreakpointKind::software: if (fields.contains("swbreak")) reason = "pc"; break;
                case BreakpointKind::hardware: case BreakpointKind::execute:
                    if (fields.contains("hwbreak")) reason = "pc"; break;
                }
                if (!reason) continue;
                const auto at = fields.find(reason);
                std::uint64_t address = 0;
                if (at == fields.end() || !parse_hex_value(at->second, address)) continue;
                const bool data = owned.kind == BreakpointKind::write || owned.kind == BreakpointKind::read ||
                    owned.kind == BreakpointKind::access;
                if (address >= owned.address && (data ? address - owned.address < owned.size : address == owned.address))
                    event.breakpoint_ids.push_back(id);
            }
            if (!non_stop_mode_)
                for (auto& [thread, state] : thread_run_states_)
                    if ((!multiprocess_supported_ || thread_process_id(thread) == remote_process_id_) &&
                        state != ThreadState::exited) state = ThreadState::stopped;
            if (!pending_event_thread_.empty()) {
                thread_run_states_[pending_event_thread_] = event.kind == EventKind::thread_exited
                    ? ThreadState::exited : ThreadState::stopped;
            }
        }
        pending_event_ = event.sequence;
        if (multiprocess_supported_ && remote_process_id_) {
            auto& inferior = inferiors_[*remote_process_id_];
            inferior.known_attached = true;
            inferior.pending_stop.reset();
            inferior.thread_states.clear();
            for (const auto& [wire, state] : thread_run_states_)
                if (thread_process_id(wire) == remote_process_id_) inferior.thread_states[wire] = state;
        }
        return event;
    }
    Status continue_event(std::uint64_t sequence, ContinueStatus disposition) override {
        if (!client_ || !pending_event_ || *pending_event_ != sequence) return Error{ErrorCode::invalid_argument, "remote event sequence is stale"};
        const auto signal_action = pending_event_signal_ != 0 && disposition == ContinueStatus::not_handled;
        const bool use_vcont_signal = signal_action && supports_vcont_continue_signal_;
        if (signal_action && (non_stop_mode_ || multiprocess_supported_) && !use_vcont_signal)
            return unsupported("remote does not advertise a thread-qualified continue-with-signal action");
        if (signal_action && multiprocess_supported_ && !supports_vcont_continue_)
            return unsupported("remote cannot target a multiprocess continue-with-signal action");
        std::string action = signal_action ? "C" + hex_signal(pending_event_signal_) : "c";
        std::string command = supports_vcont_continue_ && (!signal_action || use_vcont_signal) ? "vCont;" + action :
            (signal_action ? "C" + hex_signal(pending_event_signal_) : "c");
        bool qualified_signal_schedule = false;
        if (signal_action && use_vcont_signal && supports_vcont_continue_ && !non_stop_mode_ &&
            !pending_event_thread_.empty() && pending_event_thread_ != "0") {
            command = "vCont;" + action + ":" + pending_event_thread_ + ";c";
            qualified_signal_schedule = true;
        }
        if (non_stop_mode_) {
            // A stop event is owned by its stopped thread. Resume only that
            // thread; non-stop peers continue independently and may report
            // their own queued stop notifications later.
            if ((!signal_action && !supports_vcont_thread_continue_) ||
                (signal_action && !supports_vcont_continue_signal_) || pending_event_thread_.empty() || pending_event_thread_ == "0")
                return unsupported("non-stop continue requires an exact thread-qualified vCont action");
            command = "vCont;" + action + ":" + pending_event_thread_;
        } else if (multiprocess_supported_) {
            if ((signal_action ? (!use_vcont_signal || !supports_vcont_continue_) : !supports_vcont_continue_) || !remote_process_id_ ||
                thread_process_id(pending_event_thread_) != remote_process_id_)
                return unsupported("remote cannot continue the session process without resuming an ambiguous process selection");
            if (signal_action) {
                if (!qualified_signal_schedule)
                    return unsupported("remote cannot target the pending signal to one multiprocess thread");
                command = "vCont;" + action + ":" + pending_event_thread_ + ";c:p" +
                    hex_thread_token(*remote_process_id_) + ".-1";
            } else command += ":p" + hex_thread_token(*remote_process_id_) + ".-1";
        }
        auto result = client_->send_resume(command);
        if (result) {
            if (non_stop_mode_) expected_step_threads_.erase(pending_event_thread_);
            else expected_step_threads_.clear();
            legacy_expected_step_ = false;
            if (non_stop_mode_) {
                if (!pending_event_thread_.empty()) thread_run_states_[pending_event_thread_] = ThreadState::running;
            } else {
                for (auto& [thread, state] : thread_run_states_)
                    if (state != ThreadState::exited) state = ThreadState::running;
            }
            pending_event_.reset(); pending_event_thread_.clear(); pending_event_signal_ = 0;
        }
        return result;
    }
    Status continue_thread_event(std::uint64_t sequence, ThreadId thread, ContinueStatus disposition) override {
        if (!client_ || !pending_event_ || *pending_event_ != sequence)
            return Error{ErrorCode::invalid_argument, "remote event sequence is stale"};
        const bool redeliver_signal = pending_event_signal_ != 0 && disposition == ContinueStatus::not_handled;
        if (!redeliver_signal && !supports_vcont_thread_continue_)
            return unsupported("remote does not advertise thread-qualified continue");
        const auto wire_thread = thread_id(thread);
        if (wire_thread.empty() || !valid_thread_wire_id(wire_thread))
            return Error{ErrorCode::invalid_argument, "thread token is unknown or stale"};
        if (!pending_event_thread_.empty() && wire_thread != pending_event_thread_)
            return Error{ErrorCode::invalid_argument, "event continuation must resume the thread that owns the pending stop"};
        if (const auto state = thread_run_states_.find(wire_thread);
            state != thread_run_states_.end() && state->second == ThreadState::exited)
            return Error{ErrorCode::invalid_argument, "cannot resume an exited remote thread"};
        if (non_stop_mode_ && wire_thread != pending_event_thread_)
            return Error{ErrorCode::invalid_argument,
                         "non-stop event continuation must resume the thread that owns the stop"};
        const auto target_process = thread_process_id(wire_thread);
        if (multiprocess_supported_ && (!remote_process_id_ || target_process != remote_process_id_ ||
            thread_process_id(pending_event_thread_) != remote_process_id_))
            return unsupported("thread-qualified continue requires exact thread IDs in the session process");
        const auto action = redeliver_signal
            ? "C" + hex_signal(pending_event_signal_) : "c";
        if (action.front() == 'c' && !supports_vcont_thread_continue_)
            return unsupported("remote does not advertise thread-qualified continue");
        if (action.front() == 'C' && !supports_vcont_continue_signal_)
            return unsupported("remote does not advertise vCont continue-with-signal");
        const auto command = action + ":" + wire_thread;
        auto result = client_->send_vcont(command);
        if (result) {
            pending_event_.reset(); pending_event_thread_.clear(); pending_event_signal_ = 0; expected_step_threads_.erase(wire_thread); legacy_expected_step_ = false;
            thread_run_states_[wire_thread] = ThreadState::running;
        }
        return result;
    }
    Status resume_threads_event(std::uint64_t sequence, std::span<const ThreadResumeAction> actions) override {
        if (!client_ || !pending_event_ || *pending_event_ != sequence)
            return Error{ErrorCode::invalid_argument, "remote event sequence is stale"};
        if (actions.empty() || actions.size() > max_inspection_threads)
            return Error{ErrorCode::invalid_argument, "thread resume schedule must contain 1 to 4096 actions"};
        std::set<std::string, std::less<>> selected;
        std::vector<std::string> wire_actions;
        wire_actions.reserve(actions.size());
        bool resumes_any_thread = false;
        for (const auto& action : actions) {
            const auto wire = thread_id(action.thread);
            if (wire.empty() || !valid_thread_wire_id(wire) || !selected.insert(wire).second)
                return Error{ErrorCode::invalid_argument, "resume schedule contains an unknown or duplicate thread token"};
            if (const auto state = thread_run_states_.find(wire);
                state != thread_run_states_.end() && state->second == ThreadState::exited)
                return Error{ErrorCode::invalid_argument, "resume schedule includes an exited thread"};
            if (multiprocess_supported_ && (!remote_process_id_ || thread_process_id(wire) != remote_process_id_))
                return unsupported("resume schedule requires exact thread IDs in the session process");
            const bool owns_pending_signal = wire == pending_event_thread_;
            if (action.signal_disposition && !owns_pending_signal)
                return Error{ErrorCode::invalid_argument, "signal disposition is valid only for the thread that owns the pending stop"};
            if (action.kind == ThreadResumeKind::stop && owns_pending_signal && pending_event_signal_ != 0)
                return unsupported("RSP cannot preserve or disposition a pending signal in a stop action");
            if (action.kind == ThreadResumeKind::continue_execution) {
                resumes_any_thread = true;
                const bool redeliver = owns_pending_signal && pending_event_signal_ != 0 &&
                    action.signal_disposition != std::optional<ContinueStatus>(ContinueStatus::handled);
                if (redeliver && !supports_vcont_continue_signal_)
                    return unsupported("remote does not advertise vCont continue-with-signal");
                if (!redeliver && !supports_vcont_thread_continue_)
                    return unsupported("remote does not advertise thread-qualified continue");
                wire_actions.push_back((redeliver ? "C" + hex_signal(pending_event_signal_) : "c") + ":" + wire);
            } else if (action.kind == ThreadResumeKind::single_step) {
                resumes_any_thread = true;
                const bool redeliver = owns_pending_signal && pending_event_signal_ != 0 &&
                    action.signal_disposition != std::optional<ContinueStatus>(ContinueStatus::handled);
                if (redeliver && !supports_vcont_thread_step_signal_)
                    return unsupported("remote does not advertise vCont step-with-signal");
                if (!redeliver && !supports_vcont_thread_step_)
                    return unsupported("remote does not advertise thread-qualified single-step");
                wire_actions.push_back((redeliver ? "S" + hex_signal(pending_event_signal_) : "s") + ":" + wire);
            } else if (action.kind == ThreadResumeKind::stop) {
                if (!supports_vcont_thread_stop_) return unsupported("remote does not advertise thread-qualified stop");
                wire_actions.push_back("t:" + wire);
            } else {
                return Error{ErrorCode::invalid_argument, "resume schedule contains an unknown action"};
            }
        }
        if (!resumes_any_thread)
            return Error{ErrorCode::invalid_argument, "resume schedule must resume or step at least one thread"};
        if (!pending_event_thread_.empty() && !selected.contains(pending_event_thread_))
            return Error{ErrorCode::invalid_argument, "resume schedule must include the thread that owns the pending stop"};
        auto result = client_->send_vcont_actions(wire_actions);
        if (result) {
            for (const auto& wire : selected) expected_step_threads_.erase(wire);
            for (const auto& action : actions)
                if (action.kind == ThreadResumeKind::single_step) expected_step_threads_.insert(thread_id(action.thread));
            for (const auto& action : actions) {
                const auto wire = thread_id(action.thread);
                thread_run_states_[wire] = action.kind == ThreadResumeKind::stop
                    ? ThreadState::stopped : ThreadState::running;
            }
            pending_event_.reset();
            pending_event_thread_.clear();
            pending_event_signal_ = 0;
            legacy_expected_step_ = false;
        }
        return result;
    }
    Status single_step_event(std::uint64_t sequence, ContinueStatus disposition) override {
        if (!client_ || !pending_event_ || *pending_event_ != sequence) return Error{ErrorCode::invalid_argument, "remote event sequence is stale"};
        if (multiprocess_supported_ && (!remote_process_id_ || thread_process_id(pending_event_thread_) != remote_process_id_))
            return unsupported("remote stop does not identify a thread in the session process");
        const bool has_stopped_thread = !pending_event_thread_.empty() && pending_event_thread_ != "0";
        std::string command;
        if (has_stopped_thread) {
            const auto action = pending_event_signal_ != 0 && disposition == ContinueStatus::not_handled
                ? "S" + hex_signal(pending_event_signal_) : "s";
            if (action.front() == 'S' && !supports_vcont_thread_step_signal_)
                return unsupported("remote does not advertise vCont step-with-signal");
            if (action.front() == 's' && !supports_vcont_thread_step_)
                return unsupported("remote does not advertise thread-qualified single-step");
            command = "vCont;" + action + ":" + pending_event_thread_;
        } else {
            // An unqualified vCont;s matches all threads. Without an exact
            // stop thread, keep the legacy operation on the stub's current
            // selection instead of introducing an all-thread step.
            command = pending_event_signal_ != 0 && disposition == ContinueStatus::not_handled
                ? "S" + hex_signal(pending_event_signal_) : "s";
        }
        auto result = client_->send_resume(command);
        if (result) {
            if (has_stopped_thread) expected_step_threads_.insert(pending_event_thread_);
            else legacy_expected_step_ = true;
            if (has_stopped_thread) thread_run_states_[pending_event_thread_] = ThreadState::running;
            else for (auto& [thread, state] : thread_run_states_)
                if (state != ThreadState::exited) state = ThreadState::unknown;
            pending_event_.reset(); pending_event_thread_.clear(); pending_event_signal_ = 0;
        }
        return result;
    }
    Result<std::vector<std::byte>> read_memory(std::uint64_t address, std::size_t size) override {
        if (!client_) return Error{ErrorCode::invalid_argument, "remote debugger is not connected"};
        return client_->read_memory(address, size);
    }
    Status write_memory(std::uint64_t address, std::span<const std::byte> bytes) override {
        if (!client_) return Error{ErrorCode::invalid_argument, "remote debugger is not connected"};
        return client_->write_memory(address, bytes);
    }
    Result<std::vector<ThreadInfo>> threads() override {
        if (!client_) return Error{ErrorCode::invalid_argument, "remote debugger is not connected"};
        if (threads_xml_advertised_) {
            auto xml = client_->read_threads_annex();
            if (!xml) return xml.error();
            if (xml.value()) {
                auto descriptions = parse_threads_xml(*xml.value());
                if (!descriptions) return descriptions.error();
                std::vector<ThreadInfo> result;
                result.reserve(descriptions.value().size());
                for (const auto& thread : descriptions.value()) {
                    if (!thread_belongs_to_session(thread.id)) continue;
                    const auto state = thread_run_states_.try_emplace(thread.id, thread.state).first;
                    if (thread.state != ThreadState::unknown) state->second = thread.state;
                    result.push_back({thread_token(thread.id), thread.name, state->second});
                }
                if (result.empty()) return unsupported("remote thread list contains no threads in the session process");
                return result;
            }
        }
        auto ids = client_->enumerate_thread_ids(); if (!ids) return ids.error();
        std::vector<ThreadInfo> result; result.reserve(ids.value().size());
        for (const auto& id : ids.value()) {
            if (!valid_thread_wire_id(id)) return Error{ErrorCode::malformed, "remote thread list contains a non-concrete thread ID"};
            if (!thread_belongs_to_session(id)) continue;
            const auto token = thread_token(id);
            const auto state = thread_run_states_.try_emplace(id, ThreadState::unknown).first;
            result.push_back({token, "thread " + id, state->second});
        }
        if (result.empty()) return unsupported("remote thread list contains no threads in the session process");
        return result;
    }
    Result<std::vector<ThreadRunState>> thread_run_states() override {
        if (!client_ && !terminated_) return Error{ErrorCode::invalid_argument, "remote debugger is not connected"};
        std::vector<ThreadRunState> result;
        result.reserve(thread_run_states_.size());
        for (const auto& [wire, state] : thread_run_states_) {
            if (!thread_belongs_to_session(wire)) continue;
            result.push_back({thread_token(wire), state});
        }
        return result;
    }
    Result<std::vector<ModuleInfo>> modules() override {
        if (!client_) return Error{ErrorCode::invalid_argument, "remote debugger is not connected"};
        if (!libraries_advertised_) return unsupported("remote did not advertise qXfer:libraries:read");
        auto xml = client_->read_libraries_annex(); if (!xml) return xml.error();
        if (!xml.value()) return unsupported("remote advertised qXfer:libraries:read but returned no libraries annex");
        return parse_libraries_xml(*xml.value());
    }
    Result<std::vector<ProcessInfo>> processes() override {
        if (!client_) return Error{ErrorCode::invalid_argument, "remote debugger is not connected"};
        if (!osdata_advertised_) return unsupported("remote did not advertise qXfer:osdata:read");
        auto xml = client_->read_processes_annex();
        if (!xml) return xml.error();
        if (!xml.value()) return unsupported("remote advertised qXfer:osdata:read but returned no process list");
        auto descriptions = parse_processes_xml(*xml.value());
        if (!descriptions) return descriptions.error();
        std::vector<ProcessInfo> result;
        result.reserve(descriptions.value().size());
        for (const auto &process : descriptions.value()) {
            auto name = process.command.empty() ? "process " + std::to_string(process.id) : process.command;
            result.push_back({process.id, std::move(name), target_ ? target_->architecture : Architecture::unknown});
        }
        return result;
    }
    Result<std::vector<MemoryRegion>> memory_regions() override {
        if (!client_) return Error{ErrorCode::invalid_argument, "remote debugger is not connected"};
        if (!memory_map_advertised_) return unsupported("remote did not advertise qXfer:memory-map:read");
        auto xml = client_->read_memory_map_annex();
        if (!xml) return xml.error();
        if (!xml.value()) return unsupported("remote advertised qXfer:memory-map:read but returned no memory map");
        return parse_memory_map_xml(*xml.value());
    }
    Result<std::vector<RegisterValue>> read_registers(ThreadId thread) override {
        if (!client_) return Error{ErrorCode::invalid_argument, "remote debugger is not connected"};
        const auto wire_id = thread_id(thread);
        if (wire_id.empty()) return Error{ErrorCode::invalid_argument, "remote thread token is unknown"};
        if (!thread_belongs_to_session(wire_id))
            return Error{ErrorCode::invalid_argument, "remote thread token belongs to another process"};
        auto selected = client_->select_thread(wire_id); if (!selected) return selected.error();
        if (!target_ && target_xml_advertised_)
            return Error{ErrorCode::unsupported, "remote advertised target XML but did not provide usable register metadata"};
        auto bytes = client_->read_registers(); if (!bytes) return bytes.error();
        if (!target_) {
            return std::vector<RegisterValue>{{"g (target register packet)", std::move(bytes.value())}};
        }
        std::size_t expected = 0;
        for (const auto& reg : target_->registers) expected += (reg.bits + 7) / 8;
        if (bytes.value().size() != expected)
            return Error{ErrorCode::unsupported, "remote register packet length does not match target XML metadata"};
        std::vector<RegisterValue> result; result.reserve(target_->registers.size());
        std::size_t offset = 0;
        for (const auto& reg : target_->registers) {
            const auto size = (reg.bits + 7) / 8;
            result.push_back({reg.name, std::vector<std::byte>(bytes.value().begin() + static_cast<std::ptrdiff_t>(offset),
                bytes.value().begin() + static_cast<std::ptrdiff_t>(offset + size)), reg.group, reg.number,
                target_->big_endian ? ByteOrder::big : ByteOrder::little});
            offset += size;
        }
        return result;
    }
    Status write_registers(ThreadId thread, std::span<const RegisterValue> registers) override {
        if (!client_) return Error{ErrorCode::invalid_argument, "remote debugger is not connected"};
        if (!target_) return unsupported("remote register writes require usable target XML register metadata");
        if (registers.empty()) return std::monostate{};
        if (registers.size() > target_->registers.size()) return Error{ErrorCode::invalid_argument, "too many remote registers supplied"};
        std::set<std::size_t> seen;
        std::vector<std::pair<std::uint64_t, std::vector<std::byte>>> originals;
        originals.reserve(registers.size());
        for (const auto& value : registers) {
            const auto found = std::find_if(target_->registers.begin(), target_->registers.end(), [&](const auto& reg) {
                return reg.name == value.name && reg.number == value.number;
            });
            if (found == target_->registers.end()) return Error{ErrorCode::invalid_argument, "unknown remote register name or number"};
            if (!seen.insert(found->number).second) return Error{ErrorCode::invalid_argument, "duplicate remote register write"};
            if (value.bytes.size() != (found->bits + 7) / 8) return Error{ErrorCode::invalid_argument, "remote register write has incorrect width"};
            const auto order = target_->big_endian ? ByteOrder::big : ByteOrder::little;
            if (value.byte_order && *value.byte_order != order) return Error{ErrorCode::invalid_argument, "remote register write byte order disagrees with target XML"};
        }
        const auto wire_id = thread_id(thread);
        if (wire_id.empty()) return Error{ErrorCode::invalid_argument, "remote thread token is unknown"};
        if (!thread_belongs_to_session(wire_id))
            return Error{ErrorCode::invalid_argument, "remote thread token belongs to another process"};
        auto selected = client_->select_thread(wire_id); if (!selected) return selected;
        for (const auto& value : registers) {
            const auto original = client_->read_register(value.number);
            if (!original) return original.error();
            const auto metadata = std::find_if(target_->registers.begin(), target_->registers.end(), [&](const auto& reg) { return reg.number == value.number; });
            if (metadata == target_->registers.end() || original.value().size() != (metadata->bits + 7) / 8)
                return unsupported("remote does not expose readable p-registers for safe write rollback");
            originals.emplace_back(value.number, std::move(original.value()));
        }
        std::size_t applied = 0;
        for (const auto& value : registers) {
            auto written = client_->write_register(value.number, value.bytes);
            if (!written) {
                auto failure = written.error();
                while (applied > 0) {
                    --applied;
                    auto rollback = client_->write_register(originals[applied].first, originals[applied].second);
                    if (!rollback) failure.message += "; rollback also failed: " + rollback.error().message;
                }
                return failure;
            }
            ++applied;
        }
        return std::monostate{};
    }
    Result<Breakpoint> add_breakpoint(std::uint64_t address, BreakpointKind kind) override {
        const std::uint8_t size = kind == BreakpointKind::software && target_ &&
            target_->architecture == Architecture::arm64 ? 4 : 1;
        return add_hardware_breakpoint(address, kind, size);
    }
    Result<Breakpoint> add_hardware_breakpoint(std::uint64_t address, BreakpointKind kind, std::uint8_t size) override {
        if (!client_) return Error{ErrorCode::invalid_argument, "remote debugger is not connected"};
        if (size == 0 || address > UINT64_MAX - (size - 1))
            return Error{ErrorCode::invalid_argument, "remote breakpoint range is empty or overflows"};
        if ((kind == BreakpointKind::hardware || kind == BreakpointKind::execute) && size != 1)
            return Error{ErrorCode::invalid_argument, "remote execute breakpoint requires one instruction slot"};
        if (target_ && target_->architecture == Architecture::arm64 &&
            (kind == BreakpointKind::software || kind == BreakpointKind::hardware || kind == BreakpointKind::execute) &&
            (address % 4 != 0 || address > UINT64_MAX - 3 || (kind == BreakpointKind::software && size != 4)))
            return Error{ErrorCode::invalid_argument, "AArch64 instruction breakpoint requires an aligned four-byte instruction"};
        const auto canonical_kind = [](BreakpointKind value) {
            return value == BreakpointKind::hardware ? BreakpointKind::execute : value;
        };
        // Z packets are idempotent: separate local owners of the same wire
        // tuple would let removing either owner silently remove both traps.
        for (const auto& [id, owned] : breakpoints_) {
            (void)id;
            if (owned.address == address && owned.size == size && canonical_kind(owned.kind) == canonical_kind(kind))
                return Error{ErrorCode::conflict, "remote breakpoint tuple is already owned"};
        }
        auto type = rsp::BreakpointType::software;
        switch (kind) {
        case BreakpointKind::software: type = rsp::BreakpointType::software; break;
        case BreakpointKind::hardware: case BreakpointKind::execute: type = rsp::BreakpointType::hardware; break;
        case BreakpointKind::write: type = rsp::BreakpointType::write_watch; break;
        case BreakpointKind::read: type = rsp::BreakpointType::read_watch; break;
        case BreakpointKind::access: type = rsp::BreakpointType::access_watch; break;
        default: return Error{ErrorCode::invalid_argument, "invalid remote breakpoint kind"};
        }
        auto selection = select_breakpoint_process(); if (!selection) return selection.error();
        auto result = client_->set_breakpoint(address, type, breakpoint_packet_size(kind, size), true); if (!result) return result.error();
        Breakpoint breakpoint{next_breakpoint_++, address, kind, true, size};
        breakpoints_.emplace(breakpoint.id, breakpoint);
        return breakpoint;
    }
    Status remove_breakpoint(BreakpointId id) override {
        const auto it = breakpoints_.find(id);
        if (it == breakpoints_.end()) return Error{ErrorCode::out_of_bounds, "remote breakpoint ID is unknown"};
        if (!client_) return Error{ErrorCode::invalid_argument, "remote debugger is not connected"};
        auto type = rsp::BreakpointType::software;
        switch (it->second.kind) {
        case BreakpointKind::software: type = rsp::BreakpointType::software; break;
        case BreakpointKind::hardware: case BreakpointKind::execute: type = rsp::BreakpointType::hardware; break;
        case BreakpointKind::write: type = rsp::BreakpointType::write_watch; break;
        case BreakpointKind::read: type = rsp::BreakpointType::read_watch; break;
        case BreakpointKind::access: type = rsp::BreakpointType::access_watch; break;
        }
        if (!it->second.enabled) { breakpoints_.erase(it); return std::monostate{}; }
        auto selection = select_breakpoint_process(); if (!selection) return selection;
        auto result = client_->set_breakpoint(it->second.address, type,
            breakpoint_packet_size(it->second.kind, it->second.size), false);
        if (result) breakpoints_.erase(it);
        return result;
    }
    Status set_breakpoint_enabled(BreakpointId id, bool enabled) override {
        const auto it = breakpoints_.find(id);
        if (it == breakpoints_.end()) return Error{ErrorCode::out_of_bounds, "remote breakpoint ID is unknown"};
        if (it->second.enabled == enabled) return std::monostate{};
        if (!client_) return Error{ErrorCode::invalid_argument, "remote debugger is not connected"};
        auto type = rsp::BreakpointType::software;
        switch (it->second.kind) {
        case BreakpointKind::software: type = rsp::BreakpointType::software; break;
        case BreakpointKind::hardware: case BreakpointKind::execute: type = rsp::BreakpointType::hardware; break;
        case BreakpointKind::write: type = rsp::BreakpointType::write_watch; break;
        case BreakpointKind::read: type = rsp::BreakpointType::read_watch; break;
        case BreakpointKind::access: type = rsp::BreakpointType::access_watch; break;
        }
        auto selection = select_breakpoint_process(); if (!selection) return selection;
        auto result = client_->set_breakpoint(it->second.address, type,
            breakpoint_packet_size(it->second.kind, it->second.size), enabled);
        if (result) it->second.enabled = enabled;
        return result;
    }
private:
    static std::string hex_signal(unsigned signal) {
        constexpr char digits[] = "0123456789abcdef";
        return {digits[(signal >> 4) & 0xf], digits[signal & 0xf]};
    }
    bool thread_belongs_to_session(std::string_view wire_id) const {
        if (!valid_thread_wire_id(wire_id)) return false;
        const auto process = thread_process_id(wire_id);
        if (multiprocess_supported_)
            return remote_process_id_ && process && *process == *remote_process_id_;
        return !process;
    }
    Status select_breakpoint_process() {
        if (!multiprocess_supported_) return std::monostate{};
        if (!remote_process_id_ || !pending_event_ || thread_process_id(pending_event_thread_) != remote_process_id_)
            return unsupported("remote breakpoint changes require a stopped thread in the session process");
        // Register inspection may have selected another inferior. Z/z packets
        // have no PID, so restore the session's process explicitly first.
        return client_->select_thread(pending_event_thread_);
    }
    std::uint8_t breakpoint_packet_size(BreakpointKind kind, std::uint8_t size) const {
        // RSP uses the instruction byte width; the shared hardware execute
        // API uses one instruction slot regardless of target instruction size.
        return target_ && target_->architecture == Architecture::arm64 &&
            (kind == BreakpointKind::hardware || kind == BreakpointKind::execute) ? 4 : size;
    }
    static Error unsupported(std::string message) { return {ErrorCode::unsupported, std::move(message)}; }
    ThreadId thread_token(std::string_view wire_id) {
        const auto found = remote_thread_tokens_.find(wire_id);
        if (found != remote_thread_tokens_.end()) return found->second;
        const auto token = next_thread_token_++;
        remote_thread_tokens_.emplace(wire_id, token);
        thread_token_ids_.emplace(token, wire_id);
        return token;
    }
    std::string thread_id(ThreadId token) const {
        const auto found = thread_token_ids_.find(token);
        return found == thread_token_ids_.end() ? std::string{} : found->second;
    }
    std::unique_ptr<rsp::ByteTransport> transport_;
    std::unique_ptr<rsp::Client> client_;
    std::optional<rsp::StopReply> pending_stop_;
    std::optional<std::uint64_t> pending_event_;
    std::string pending_event_thread_;
    unsigned pending_event_signal_ = 0;
    std::set<std::string, std::less<>> expected_step_threads_;
    bool legacy_expected_step_ = false;
    std::optional<TargetDescription> target_;
    bool target_xml_advertised_ = false;
    bool libraries_advertised_ = false;
    bool memory_map_advertised_ = false;
    bool threads_xml_advertised_ = false;
    bool osdata_advertised_ = false;
    bool multiprocess_supported_ = false;
    bool extended_mode_supported_ = false;
    bool non_stop_mode_ = false;
    bool terminated_ = false;
    bool current_process_detach_rejected_ = false;
    std::optional<std::uint64_t> remote_process_id_;
    std::map<BreakpointId, Breakpoint> breakpoints_;
    std::map<std::string, ThreadId, std::less<>> remote_thread_tokens_;
    std::map<ThreadId, std::string> thread_token_ids_;
    std::map<std::string, ThreadState, std::less<>> thread_run_states_;
    std::map<std::uint64_t, InferiorState> inferiors_;
    std::string host_;
    std::uint64_t sequence_ = 0, next_breakpoint_ = 1, next_thread_token_ = 1;
    bool supports_vcont_continue_ = false;
    bool supports_vcont_continue_signal_ = false;
    bool supports_vcont_thread_continue_ = false;
    bool supports_vcont_thread_step_ = false;
    bool supports_vcont_thread_step_signal_ = false;
    bool supports_vcont_thread_stop_ = false;
};

class BackendRouter final : public Backend {
public:
    explicit BackendRouter(std::unique_ptr<Backend> native) : native_(std::move(native)) {}
    Result<std::vector<ProcessInfo>> processes() override {
        return remote_ ? remote_->processes() : native_->processes();
    }
    Result<ProcessInfo> launch(const Target& target) override { return active().launch(target); }
    Result<ProcessInfo> attach(ProcessId id) override { return active().attach(id); }
    Result<ProcessInfo> attach_remote_process(ProcessId id) override {
        return remote_ ? remote_->attach_remote_process(id) : unsupported("no remote debugger session is active");
    }
    Status detach_remote_process(ProcessId id) override {
        return remote_ ? remote_->detach_remote_process(id) : unsupported("no remote debugger session is active");
    }
    bool supports_remote_current_process_detach() const noexcept override {
        return remote_ && remote_->supports_remote_current_process_detach();
    }
    Status detach_remote_current_process(ProcessId id) override {
        return remote_ ? remote_->detach_remote_current_process(id) : unsupported("no remote debugger session is active");
    }
    Result<ProcessInfo> connect_remote(std::string_view host, std::uint16_t port) override {
        if (remote_) return Error{ErrorCode::conflict, "remote debugger is already connected"};
        auto remote = make_remote_backend();
        auto result = remote->connect_remote(host, port);
        if (result) remote_ = std::move(remote);
        return result;
    }
    Status detach() override {
        if (remote_) {
            auto result = remote_->detach();
            if (result) remote_.reset();
            return result;
        }
        return active().detach();
    }
    Status terminate() override { return active().terminate(); }
    Status request_interrupt() override { return active().request_interrupt(); }
    Result<DebugEvent> wait_event(std::chrono::milliseconds timeout) override { return active().wait_event(timeout); }
    Status continue_event(std::uint64_t sequence, ContinueStatus status) override { return active().continue_event(sequence, status); }
    Status continue_thread_event(std::uint64_t sequence, ThreadId thread, ContinueStatus status) override { return active().continue_thread_event(sequence, thread, status); }
    Status resume_threads_event(std::uint64_t sequence, std::span<const ThreadResumeAction> actions) override { return active().resume_threads_event(sequence, actions); }
    Status single_step_event(std::uint64_t sequence, ContinueStatus status) override { return active().single_step_event(sequence, status); }
    Result<std::vector<std::byte>> read_memory(std::uint64_t address, std::size_t size) override { return active().read_memory(address, size); }
    Status write_memory(std::uint64_t address, std::span<const std::byte> bytes) override { return active().write_memory(address, bytes); }
    Result<std::vector<ThreadInfo>> threads() override { return active().threads(); }
    Result<std::vector<ThreadRunState>> thread_run_states() override { return active().thread_run_states(); }
    Result<std::vector<ModuleInfo>> modules() override { return active().modules(); }
    Result<std::vector<MemoryRegion>> memory_regions() override { return active().memory_regions(); }
    Result<std::vector<RegisterValue>> read_registers(ThreadId thread) override { return active().read_registers(thread); }
    Status write_registers(ThreadId thread, std::span<const RegisterValue> registers) override { return active().write_registers(thread, registers); }
    Result<Breakpoint> add_breakpoint(std::uint64_t address, BreakpointKind kind) override { return active().add_breakpoint(address, kind); }
    Result<Breakpoint> add_hardware_breakpoint(std::uint64_t address, BreakpointKind kind, std::uint8_t size) override { return active().add_hardware_breakpoint(address, kind, size); }
    Status remove_breakpoint(BreakpointId id) override { return active().remove_breakpoint(id); }
    Status set_breakpoint_enabled(BreakpointId id, bool enabled) override { return active().set_breakpoint_enabled(id, enabled); }
private:
    static Error unsupported(std::string message) { return {ErrorCode::unsupported, std::move(message)}; }
    Backend& active() { return remote_ ? *remote_ : *native_; }
    std::unique_ptr<Backend> native_;
    std::unique_ptr<Backend> remote_;
};
}

std::unique_ptr<Backend> make_remote_backend() { return std::make_unique<RemoteBackend>(); }
std::unique_ptr<Backend> make_remote_backend(std::unique_ptr<rsp::ByteTransport> transport) {
    return std::make_unique<RemoteBackend>(std::move(transport));
}
std::unique_ptr<Backend> make_backend_router(std::unique_ptr<Backend> native) {
    return std::make_unique<BackendRouter>(std::move(native));
}
} // namespace hexlab::debugger
