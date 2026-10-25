#include "hexlab/analysis/macho_objc_types.hpp"
#include <algorithm>
#include <limits>
#include <new>
#include <utility>

namespace hexlab {
namespace {
class Parser {
  public:
    Parser(std::string_view input, const MachOObjCEncodingLimits &limits) : input_(input), limits_(limits) {}

    Result<MachOObjCMethodEncoding> run() {
        MachOObjCMethodEncoding result;
        if (!limits_.max_input_bytes || !limits_.max_depth || !limits_.max_types ||
            (limits_.pointer_bytes != 4 && limits_.pointer_bytes != 8))
            return Error{ErrorCode::invalid_argument, "Objective-C encoding limits are invalid"};
        if (input_.size() > limits_.max_input_bytes)
            return Error{ErrorCode::resource_limit, "Objective-C type encoding exceeds the input limit"};
        if (input_.empty()) {
            result.status = "empty-encoding";
            return result;
        }

        auto return_type = parse_type(0);
        if (!return_type) return incomplete();
        skip_number(); // Optional frame size.

        std::vector<types::Parameter> parameters;
        while (position_ < input_.size()) {
            if (types_seen_ >= limits_.max_types)
                return Error{ErrorCode::resource_limit, "Objective-C encoding type count exceeds the limit"};
            auto parameter = parse_type(0);
            if (!parameter) return incomplete();
            parameters.push_back({"arg" + std::to_string(parameters.size()), std::move(*parameter)});
            skip_number(); // Optional stack/register offset.
        }
        auto signature = types::Type::function(std::move(*return_type), std::move(parameters), false);
        if (!signature) {
            result.status = "function-type-invalid:" + signature.error().message;
            return result;
        }
        result.signature = std::move(signature.value());
        result.status = "parsed";
        result.encoded_types = types_seen_;
        return result;
    }

    Result<MachOObjCPropertyEncoding> run_property() {
        MachOObjCPropertyEncoding result;
        if (!limits_.max_input_bytes || !limits_.max_depth || !limits_.max_types ||
            (limits_.pointer_bytes != 4 && limits_.pointer_bytes != 8))
            return Error{ErrorCode::invalid_argument, "Objective-C encoding limits are invalid"};
        if (input_.size() > limits_.max_input_bytes)
            return Error{ErrorCode::resource_limit, "Objective-C property encoding exceeds the input limit"};
        if (input_.empty()) {
            result.status = "empty-encoding";
            return result;
        }
        auto type = parse_type(0);
        if (!type) {
            result.status = failure_.empty() ? "malformed-or-unsupported-encoding" : failure_;
            result.encoded_types = types_seen_;
            return result;
        }
        if (position_ != input_.size()) {
            result.status = "trailing-property-encoding-data";
            result.encoded_types = types_seen_;
            return result;
        }
        result.type = std::move(*type);
        result.status = "parsed";
        result.encoded_types = types_seen_;
        return result;
    }

  private:
    std::string_view input_;
    const MachOObjCEncodingLimits &limits_;
    std::size_t position_ = 0;
    std::size_t types_seen_ = 0;
    std::string failure_;

    MachOObjCMethodEncoding incomplete() const {
        MachOObjCMethodEncoding result;
        result.status = failure_.empty() ? "malformed-or-unsupported-encoding" : failure_;
        result.encoded_types = types_seen_;
        return result;
    }

    bool at_end() const { return position_ >= input_.size(); }
    char peek() const { return at_end() ? '\0' : input_[position_]; }

    void skip_number() {
        if (peek() == '+' || peek() == '-') ++position_;
        const auto start = position_;
        while (peek() >= '0' && peek() <= '9') ++position_;
        if (position_ == start && (position_ == 0 || (input_[position_ - 1] != '+' && input_[position_ - 1] != '-'))) {
            // No numeric suffix was present; leave the cursor untouched.
            return;
        }
        if (position_ == start) --position_;
    }

    std::string parse_name_until(char terminator) {
        const auto begin = position_;
        while (!at_end() && peek() != terminator) ++position_;
        if (at_end()) {
            failure_ = "unterminated-aggregate-name";
            return {};
        }
        std::string name(input_.substr(begin, position_ - begin));
        ++position_;
        return name;
    }

    bool skip_quoted_name() {
        if (peek() != '"') return true;
        ++position_;
        while (!at_end() && peek() != '"') ++position_;
        if (at_end()) {
            failure_ = "unterminated-field-name";
            return false;
        }
        ++position_;
        return true;
    }

    std::optional<types::TypePtr> parse_type(std::size_t depth) {
        if (depth > limits_.max_depth) {
            failure_ = "encoding-recursion-limit";
            return {};
        }
        if (types_seen_ >= limits_.max_types) {
            failure_ = "encoding-type-count-limit";
            return {};
        }
        if (at_end()) {
            failure_ = "missing-type";
            return {};
        }
        ++types_seen_;
        std::uint8_t qualifiers = 0;
        while (true) {
            switch (peek()) {
            case 'r': qualifiers |= static_cast<std::uint8_t>(types::Qualifier::const_); ++position_; continue;
            case 'V': qualifiers |= static_cast<std::uint8_t>(types::Qualifier::volatile_); ++position_; continue;
            case 'n': case 'N': case 'o': case 'O': case 'R': // direction/ownership qualifiers
                ++position_; continue;
            default: break;
            }
            break;
        }
        if (at_end()) {
            failure_ = "qualifier-without-type";
            return {};
        }

        const char code = input_[position_++];
        types::TypePtr type;
        auto integer = [&](const char *name, std::uint64_t bytes, bool sign) -> std::optional<types::TypePtr> {
            auto made = types::Type::integer(name, bytes, std::min<std::uint64_t>(bytes, 8), sign);
            if (!made) {
                failure_ = "integer-type-invalid";
                return {};
            }
            return made.value();
        };
        switch (code) {
        case 'v': type = types::Type::void_type(); break;
        case 'c': { auto v = integer("signed char", 1, true); if (!v) return {}; type = *v; break; }
        case 'C': { auto v = integer("unsigned char", 1, false); if (!v) return {}; type = *v; break; }
        case 's': { auto v = integer("short", 2, true); if (!v) return {}; type = *v; break; }
        case 'S': { auto v = integer("unsigned short", 2, false); if (!v) return {}; type = *v; break; }
        case 'i': { auto v = integer("int", 4, true); if (!v) return {}; type = *v; break; }
        case 'I': { auto v = integer("unsigned int", 4, false); if (!v) return {}; type = *v; break; }
        case 'l': { auto v = integer("long", limits_.pointer_bytes, true); if (!v) return {}; type = *v; break; }
        case 'L': { auto v = integer("unsigned long", limits_.pointer_bytes, false); if (!v) return {}; type = *v; break; }
        case 'q': { auto v = integer("long long", 8, true); if (!v) return {}; type = *v; break; }
        case 'Q': { auto v = integer("unsigned long long", 8, false); if (!v) return {}; type = *v; break; }
        case 'B': {
            auto made = types::Type::boolean(1, 1);
            if (!made) { failure_ = "boolean-type-invalid"; return {}; }
            type = made.value();
            break;
        }
        case 'f': case 'd': {
            const auto bytes = code == 'f' ? 4u : 8u;
            auto made = types::Type::floating(code == 'f' ? "float" : "double", bytes, bytes);
            if (!made) { failure_ = "floating-type-invalid"; return {}; }
            type = made.value();
            break;
        }
        case '@': {
            std::string pointee = "objc_object";
            if (peek() == '?') {
                ++position_;
                pointee = "objc_block";
            } else if (peek() == '"') {
                ++position_;
                const auto begin = position_;
                while (!at_end() && peek() != '"') ++position_;
                if (at_end()) { failure_ = "unterminated-object-class"; return {}; }
                const auto annotation = input_.substr(begin, position_ - begin);
                ++position_;
                if (!annotation.empty()) pointee = std::string(annotation);
            }
            auto named = types::Type::named_reference(std::move(pointee));
            if (!named) { failure_ = "object-reference-invalid"; return {}; }
            auto made = types::Type::pointer(named.value(), limits_.pointer_bytes, limits_.pointer_bytes);
            if (!made) { failure_ = "object-pointer-invalid"; return {}; }
            type = made.value();
            break;
        }
        case '#': case ':': case '*': {
            const char *name = code == '#' ? "objc_class" : code == ':' ? "objc_selector" : "signed char";
            types::TypePtr pointee;
            if (code == '*') {
                auto made = types::Type::integer(name, 1, 1, true);
                if (!made) { failure_ = "cstring-pointee-invalid"; return {}; }
                pointee = made.value();
            } else {
                auto made = types::Type::named_reference(name);
                if (!made) { failure_ = "opaque-pointer-invalid"; return {}; }
                pointee = made.value();
            }
            auto made = types::Type::pointer(std::move(pointee), limits_.pointer_bytes, limits_.pointer_bytes);
            if (!made) { failure_ = "pointer-type-invalid"; return {}; }
            type = made.value();
            break;
        }
        case '^': {
            auto pointee = parse_type(depth + 1);
            if (!pointee) return {};
            auto made = types::Type::pointer(std::move(*pointee), limits_.pointer_bytes, limits_.pointer_bytes);
            if (!made) { failure_ = "pointer-type-invalid"; return {}; }
            type = made.value();
            break;
        }
        case '[': {
            const auto count_begin = position_;
            std::uint64_t count = 0;
            while (peek() >= '0' && peek() <= '9') {
                const auto digit = static_cast<std::uint64_t>(peek() - '0');
                if (count > (UINT64_MAX - digit) / 10) { failure_ = "array-count-overflow"; return {}; }
                count = count * 10 + digit;
                ++position_;
            }
            if (position_ == count_begin || !count || count > 1'000'000) {
                failure_ = "unsupported-array-count";
                return {};
            }
            auto element = parse_type(depth + 1);
            if (!element) return {};
            if (peek() != ']') { failure_ = "unterminated-array"; return {}; }
            ++position_;
            auto made = types::Type::array(std::move(*element), count);
            if (!made) { failure_ = "array-type-invalid"; return {}; }
            type = made.value();
            break;
        }
        case '{': case '(': {
            const char close = code == '{' ? '}' : ')';
            const auto begin = position_;
            while (!at_end() && peek() != '=' && peek() != close) ++position_;
            if (at_end()) { failure_ = "unterminated-aggregate"; return {}; }
            std::string name(input_.substr(begin, position_ - begin));
            if (name.empty()) name = code == '{' ? "objc_anonymous_struct" : "objc_anonymous_union";
            if (peek() == close) {
                ++position_;
            } else {
                ++position_; // '='
                std::size_t fields = 0;
                while (!at_end() && peek() != close) {
                    if (++fields > limits_.max_types) { failure_ = "aggregate-field-limit"; return {}; }
                    if (!skip_quoted_name()) return {};
                    if (!parse_type(depth + 1)) return {};
                }
                if (peek() != close) { failure_ = "unterminated-aggregate"; return {}; }
                ++position_;
            }
            auto made = types::Type::incomplete_aggregate(code == '{' ? types::Kind::structure : types::Kind::union_type,
                                                           std::move(name));
            if (!made) { failure_ = "aggregate-type-invalid"; return {}; }
            type = made.value();
            break;
        }
        default:
            failure_ = std::string("unsupported-type-code:") + code;
            return {};
        }
        if (qualifiers) {
            auto qualified = types::Type::qualified(std::move(type), qualifiers);
            if (!qualified) { failure_ = "qualified-type-invalid"; return {}; }
            type = qualified.value();
        }
        return type;
    }
};
} // namespace

Result<MachOObjCMethodEncoding> parse_macho_objc_method_encoding(
    std::string_view encoding, const MachOObjCEncodingLimits &limits) {
    try {
        return Parser(encoding, limits).run();
    } catch (const std::bad_alloc &) {
        return Error{ErrorCode::resource_limit, "Objective-C encoding allocation limit"};
    }
}

Result<MachOObjCPropertyEncoding> parse_macho_objc_property_encoding(
    std::string_view encoding, const MachOObjCEncodingLimits &limits) {
    try {
        return Parser(encoding, limits).run_property();
    } catch (const std::bad_alloc &) {
        return Error{ErrorCode::resource_limit, "Objective-C property encoding allocation limit"};
    }
}

} // namespace hexlab
