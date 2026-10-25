#include "hexlab/types/enum_authoring.hpp"
#include <algorithm>
#include <bit>
#include <charconv>
#include <limits>
#include <string>
#include <unordered_set>

namespace hexlab::types {
namespace {
hexlab::Error invalid(std::string message) { return {hexlab::ErrorCode::invalid_argument, std::move(message)}; }
std::uint64_t value_bits(const Type &type) { return std::min<std::uint64_t>(type.size().value_or(0), 8) * 8; }
std::string_view trim(std::string_view value) {
    const auto first = value.find_first_not_of(" \t\r\n");
    if (first == std::string_view::npos) return {};
    return value.substr(first, value.find_last_not_of(" \t\r\n") - first + 1);
}
bool unsigned_number(std::string_view input, std::uint64_t &value) {
    int base = 10;
    if (input.size() > 2 && input[0] == '0' && (input[1] == 'x' || input[1] == 'X')) {
        input.remove_prefix(2);
        base = 16;
    }
    if (input.empty()) return false;
    const auto result = std::from_chars(input.data(), input.data() + input.size(), value, base);
    return result.ec == std::errc{} && result.ptr == input.data() + input.size();
}
bool parse_value(std::string_view input, const Type &underlying, std::uint64_t &raw) {
    const auto bits = value_bits(underlying);
    if (bits == 0) return false;
    bool negative = !input.empty() && input.front() == '-';
    if (negative) input.remove_prefix(1);
    else if (!input.empty() && input.front() == '+') input.remove_prefix(1);
    std::uint64_t magnitude = 0;
    if (!unsigned_number(input, magnitude)) return false;
    if (!underlying.is_signed()) {
        if (negative || (bits < 64 && magnitude >= (std::uint64_t{1} << bits))) return false;
        raw = magnitude;
        return true;
    }
    if (bits >= 64) {
        if (negative) {
            if (magnitude > (std::uint64_t{1} << 63)) return false;
            raw = std::uint64_t{0} - magnitude;
        } else {
            if (magnitude > static_cast<std::uint64_t>(std::numeric_limits<std::int64_t>::max())) return false;
            raw = magnitude;
        }
        return true;
    }
    const auto limit = std::uint64_t{1} << (bits - 1);
    if (negative) {
        if (magnitude > limit) return false;
        raw = std::uint64_t{0} - magnitude;
    } else {
        if (magnitude >= limit) return false;
        raw = magnitude;
    }
    return true;
}
bool fits(const Enumerator &value, const Type &underlying) {
    const auto bits = value_bits(underlying);
    if (bits == 0 || bits >= 64) return true;
    const auto mask = (std::uint64_t{1} << bits) - 1;
    if (!underlying.is_signed()) return (value.value & ~mask) == 0;
    const auto sign = std::uint64_t{1} << (bits - 1);
    const auto expected = (value.value & sign) ? ~mask : 0;
    return (value.value & ~mask) == expected;
}
}

hexlab::Result<std::vector<Enumerator>> parse_enumerators(std::string_view text, TypePtr underlying) {
    if (!underlying || underlying->kind() != Kind::integer)
        return invalid("enum requires an integer underlying type");
    if (text.empty()) return invalid("at least one enumerator is required");
    std::vector<Enumerator> result;
    std::unordered_set<std::string> names;
    std::size_t start = 0;
    while (start <= text.size()) {
        const auto comma = text.find(',', start);
        const auto token = trim(text.substr(start, comma == std::string_view::npos ? text.size() - start : comma - start));
        if (token.empty()) return invalid("enumerator entries cannot be empty");
        const auto equals = token.find('=');
        const auto name_view = trim(token.substr(0, equals));
        if (name_view.empty()) return invalid("enumerator names cannot be empty");
        std::string name(name_view);
        if (!names.insert(name).second) return invalid("enumerator names must be unique");
        std::uint64_t value = 0;
        if (equals != std::string_view::npos) {
            if (!parse_value(trim(token.substr(equals + 1)), *underlying, value))
                return invalid("enumerator value is invalid or does not fit its underlying type");
        } else if (!result.empty()) {
            const auto bits = value_bits(*underlying);
            if (underlying->is_signed()) {
                auto previous = std::bit_cast<std::int64_t>(result.back().value);
                if (bits < 64) {
                    const auto sign = std::uint64_t{1} << (bits - 1);
                    previous = static_cast<std::int64_t>(result.back().value & ((std::uint64_t{1} << bits) - 1));
                    if (result.back().value & sign) previous -= static_cast<std::int64_t>(std::uint64_t{1} << bits);
                }
                if (previous == std::numeric_limits<std::int64_t>::max() ||
                    (bits < 64 && previous == (std::int64_t{1} << (bits - 1)) - 1))
                    return invalid("implicit enumerator value overflows its underlying type");
                value = static_cast<std::uint64_t>(previous + 1);
            } else {
                if (result.back().value == std::numeric_limits<std::uint64_t>::max() ||
                    (bits < 64 && result.back().value == (std::uint64_t{1} << bits) - 1))
                    return invalid("implicit enumerator value overflows its underlying type");
                value = result.back().value + 1;
            }
        }
        if (!fits({name, value}, *underlying)) return invalid("enumerator value does not fit its underlying type");
        result.push_back({std::move(name), value});
        if (comma == std::string_view::npos) break;
        start = comma + 1;
    }
    return result;
}

hexlab::Result<std::string> format_enumerators(const Type &enumeration) {
    if (enumeration.kind() != Kind::enumeration || !enumeration.element())
        return invalid("enumerator formatting requires an enum type");
    std::string result;
    for (const auto &value : enumeration.enumerator_values()) {
        if (!result.empty()) result += ", ";
        result += value.name + " = ";
        result += enumeration.element()->is_signed()
            ? std::to_string(std::bit_cast<std::int64_t>(value.value)) : std::to_string(value.value);
    }
    return result;
}
}
