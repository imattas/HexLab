#include "header_preprocessor.hpp"

#include <algorithm>
#include <bit>
#include <charconv>
#include <cctype>
#include <limits>
#include <set>
#include <vector>

namespace hexlab::types::detail {
namespace {
struct Macro {
    bool function_like = false;
    bool variadic = false;
    std::vector<std::string> parameters;
    std::string replacement;
};
using Macros = std::map<std::string, Macro, std::less<>>;
[[noreturn]] void error(hexlab::ErrorCode code, std::string message);

std::string_view trim(std::string_view s) {
    while (!s.empty() && std::isspace(static_cast<unsigned char>(s.front()))) s.remove_prefix(1);
    while (!s.empty() && std::isspace(static_cast<unsigned char>(s.back()))) s.remove_suffix(1);
    return s;
}
std::string remove_comments(std::string_view source) {
    std::string output;
    output.reserve(source.size());
    bool line_comment=false,block_comment=false;
    char quote=0;
    for(std::size_t i=0;i<source.size();++i){
        const char c=source[i];
        if(line_comment){
            if(c=='\n'){output.push_back(c);line_comment=false;}
            continue;
        }
        if(block_comment){
            if(c=='*' && i+1<source.size() && source[i+1]=='/'){
                ++i;block_comment=false;
            }else if(c=='\n')output.push_back(c);
            continue;
        }
        if(quote){
            output.push_back(c);
            if(c=='\\' && i+1<source.size())output.push_back(source[++i]);
            else if(c==quote)quote=0;
            continue;
        }
        if(c=='"' || c=='\''){quote=c;output.push_back(c);continue;}
        if(c=='/' && i+1<source.size() && source[i+1]=='/'){
            output.push_back(' ');++i;line_comment=true;continue;
        }
        if(c=='/' && i+1<source.size() && source[i+1]=='*'){
            output.push_back(' ');++i;block_comment=true;continue;
        }
        output.push_back(c);
    }
    if(block_comment)error(hexlab::ErrorCode::malformed,"unterminated block comment in header");
    return output;
}
bool id_start(char c) { return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || c == '_'; }
bool id_char(char c) { return id_start(c) || (c >= '0' && c <= '9'); }
[[noreturn]] void error(hexlab::ErrorCode code, std::string message) {
    throw hexlab::Error{code, std::move(message)};
}

class ConditionalExpression {
public:
    explicit ConditionalExpression(std::string_view text) : text_(text) {}
    std::uint64_t evaluate() {
        const auto value = conditional(true);
        skip_space();
        if (position_ != text_.size())
            error(hexlab::ErrorCode::unsupported, "unsupported token in #if expression: " + std::string(text_.substr(position_)));
        return value.bits;
    }
private:
    struct Integer {
        std::uint64_t bits = 0;
        bool is_unsigned = false;
    };
    std::string_view text_;
    std::size_t position_ = 0;

    void skip_space() {
        while (position_ < text_.size() && std::isspace(static_cast<unsigned char>(text_[position_]))) ++position_;
    }
    bool consume(std::string_view token) {
        skip_space();
        if (text_.substr(position_).starts_with(token)) { position_ += token.size(); return true; }
        return false;
    }
    static std::int64_t signed_value(Integer value) { return std::bit_cast<std::int64_t>(value.bits); }
    static Integer signed_result(std::int64_t value) { return {std::bit_cast<std::uint64_t>(value), false}; }
    static Integer bool_result(bool value) { return {value ? 1u : 0u, false}; }
    static std::int64_t checked_add(std::int64_t a, std::int64_t b) {
        if ((b > 0 && a > std::numeric_limits<std::int64_t>::max() - b) ||
            (b < 0 && a < std::numeric_limits<std::int64_t>::min() - b))
            error(hexlab::ErrorCode::overflow, "signed overflow in #if expression");
        return a + b;
    }
    static std::int64_t checked_sub(std::int64_t a, std::int64_t b) {
        if ((b < 0 && a > std::numeric_limits<std::int64_t>::max() + b) ||
            (b > 0 && a < std::numeric_limits<std::int64_t>::min() + b))
            error(hexlab::ErrorCode::overflow, "signed overflow in #if expression");
        return a - b;
    }
    static std::int64_t checked_mul(std::int64_t a, std::int64_t b) {
        if (a == 0 || b == 0) return 0;
        if ((a == -1 && b == std::numeric_limits<std::int64_t>::min()) ||
            (b == -1 && a == std::numeric_limits<std::int64_t>::min()))
            error(hexlab::ErrorCode::overflow, "signed overflow in #if expression");
        if (a > 0 ? (b > 0 ? a > std::numeric_limits<std::int64_t>::max() / b
                            : b < std::numeric_limits<std::int64_t>::min() / a)
                  : (b > 0 ? a < std::numeric_limits<std::int64_t>::min() / b
                            : a < std::numeric_limits<std::int64_t>::max() / b))
            error(hexlab::ErrorCode::overflow, "signed overflow in #if expression");
        return a * b;
    }
    Integer integer_literal() {
        skip_space();
        const auto begin = position_;
        int base = 10;
        if (text_.substr(position_).starts_with("0x") || text_.substr(position_).starts_with("0X")) {
            base = 16; position_ += 2;
        } else if (text_[position_] == '0') base = 8;
        const auto digits_begin = position_;
        while (position_ < text_.size() &&
            ((text_[position_] >= '0' && text_[position_] <= '9') ||
             (base == 16 && ((text_[position_] >= 'a' && text_[position_] <= 'f') ||
                             (text_[position_] >= 'A' && text_[position_] <= 'F'))))) ++position_;
        if (digits_begin == position_ && base == 16)
            error(hexlab::ErrorCode::malformed, "hexadecimal #if literal has no digits");
        if (digits_begin == position_ && base != 16) ++position_;
        auto digits = text_.substr(digits_begin, position_ - digits_begin);
        std::string suffix;
        while (position_ < text_.size() && (text_[position_] == 'u' || text_[position_] == 'U' || text_[position_] == 'l' || text_[position_] == 'L')) {
            suffix.push_back(static_cast<char>(std::tolower(static_cast<unsigned char>(text_[position_++]))));
        }
        const bool has_unsigned = suffix.find('u') != std::string::npos;
        if ((suffix.find('u') != std::string::npos && suffix.find('u') != suffix.rfind('u')) ||
            (suffix != "" && suffix != "u" && suffix != "l" && suffix != "ll" &&
             suffix != "ul" && suffix != "ull" && suffix != "lu" && suffix != "llu"))
            error(hexlab::ErrorCode::malformed, "invalid integer suffix in #if expression");
        std::uint64_t value = 0;
        const auto [end, ec] = std::from_chars(digits.data(), digits.data() + digits.size(), value, base);
        if (ec != std::errc{} || end != digits.data() + digits.size())
            error(hexlab::ErrorCode::overflow, "#if integer literal exceeds 64-bit range");
        if (position_ == begin) error(hexlab::ErrorCode::malformed, "invalid integer literal in #if expression");
        const bool nondecimal = base != 10;
        if (!has_unsigned && value > static_cast<std::uint64_t>(std::numeric_limits<std::int64_t>::max()) && !nondecimal)
            error(hexlab::ErrorCode::overflow, "decimal #if integer literal exceeds signed 64-bit range");
        return {value, has_unsigned || (nondecimal && value > static_cast<std::uint64_t>(std::numeric_limits<std::int64_t>::max()))};
    }
    Integer character_literal(bool evaluate) {
        skip_space();
        if (position_ >= text_.size() || text_[position_] != '\'')
            error(hexlab::ErrorCode::malformed, "invalid character constant in #if expression");
        ++position_;
        std::uint64_t packed = 0;
        std::size_t count = 0;
        while (position_ < text_.size() && text_[position_] != '\'') {
            std::uint32_t value = 0;
            const char c = text_[position_++];
            if (c != '\\') value = static_cast<unsigned char>(c);
            else {
                if (position_ == text_.size()) error(hexlab::ErrorCode::malformed, "unterminated escape in #if character constant");
                const char escape = text_[position_++];
                switch (escape) {
                case '\\' : value = '\\'; break; case '\'' : value = '\''; break;
                case '"' : value = '"'; break; case '?' : value = '?'; break;
                case 'a' : value = 7; break; case 'b' : value = 8; break; case 'f' : value = 12; break;
                case 'n' : value = 10; break; case 'r' : value = 13; break; case 't' : value = 9; break; case 'v' : value = 11; break;
                case 'x': {
                    const auto first = position_;
                    std::uint32_t hex = 0;
                    while (position_ < text_.size()) {
                        const char d = text_[position_];
                        unsigned digit;
                        if (d >= '0' && d <= '9') digit = static_cast<unsigned>(d - '0');
                        else if (d >= 'a' && d <= 'f') digit = static_cast<unsigned>(d - 'a' + 10);
                        else if (d >= 'A' && d <= 'F') digit = static_cast<unsigned>(d - 'A' + 10);
                        else break;
                        if (hex > (UINT32_MAX - digit) / 16) error(hexlab::ErrorCode::overflow, "hex escape exceeds 32-bit character range");
                        hex = hex * 16 + digit; ++position_;
                    }
                    if (position_ == first) error(hexlab::ErrorCode::malformed, "hex escape has no digits in #if character constant");
                    value = hex; break;
                }
                default:
                    if (escape >= '0' && escape <= '7') {
                        value = static_cast<unsigned>(escape - '0');
                        for (unsigned n = 1; n < 3 && position_ < text_.size() && text_[position_] >= '0' && text_[position_] <= '7'; ++n)
                            value = value * 8 + static_cast<unsigned>(text_[position_++] - '0');
                    } else error(hexlab::ErrorCode::unsupported, "unsupported escape in #if character constant");
                }
            }
            if (value > 0xff) error(hexlab::ErrorCode::unsupported, "character constant value exceeds the supported execution-character byte range");
            if (count == 4) error(hexlab::ErrorCode::unsupported, "multi-character #if constants are limited to four bytes");
            packed = (packed << 8) | value;
            ++count;
        }
        if (position_ == text_.size()) error(hexlab::ErrorCode::malformed, "unterminated #if character constant");
        ++position_;
        if (!count) error(hexlab::ErrorCode::malformed, "empty #if character constant");
        if (!evaluate) return {};
        return {packed, false};
    }
    Integer primary(bool evaluate) {
        skip_space();
        if (position_ == text_.size()) error(hexlab::ErrorCode::malformed, "missing operand in #if expression");
        if (consume("(")) {
            const auto value = conditional(evaluate);
            if (!consume(")")) error(hexlab::ErrorCode::malformed, "missing ')' in #if expression");
            return value;
        }
        skip_space();
        const char c = text_[position_];
        if (c >= '0' && c <= '9') return integer_literal();
        if (c == '\'') return character_literal(evaluate);
        if ((c == 'L' || c == 'u' || c == 'U') && position_ + 1 < text_.size() && text_[position_ + 1] == '\'')
            error(hexlab::ErrorCode::unsupported, "wide and UTF-prefixed character constants are unsupported in #if expressions");
        if (id_start(c)) {
            ++position_;
            while (position_ < text_.size() && id_char(text_[position_])) ++position_;
            return {}; // Remaining identifiers are undefined after macro expansion.
        }
        error(hexlab::ErrorCode::unsupported, "unsupported primary expression in #if");
    }
    Integer unary(bool evaluate) {
        skip_space();
        if (consume("+")) return unary(evaluate);
        if (consume("-")) {
            const auto value = unary(evaluate);
            if (!evaluate) return {};
            if (value.is_unsigned) return {std::uint64_t{0} - value.bits, true};
            const auto signed_number = signed_value(value);
            if (signed_number == std::numeric_limits<std::int64_t>::min())
                error(hexlab::ErrorCode::overflow, "signed overflow in #if unary negation");
            return signed_result(-signed_number);
        }
        if (consume("!")) { const auto v=unary(evaluate); return evaluate ? bool_result(v.bits==0) : Integer{}; }
        if (consume("~")) { const auto v=unary(evaluate); return evaluate ? Integer{~v.bits,v.is_unsigned} : Integer{}; }
        return primary(evaluate);
    }
    static int precedence(std::string_view op) {
        if (op == "||") return 1; if (op == "&&") return 2;
        if (op == "|") return 3; if (op == "^") return 4; if (op == "&") return 5;
        if (op == "==" || op == "!=") return 6;
        if (op == "<" || op == "<=" || op == ">" || op == ">=") return 7;
        if (op == "<<" || op == ">>") return 8;
        if (op == "+" || op == "-") return 9;
        if (op == "*" || op == "/" || op == "%") return 10;
        return 0;
    }
    std::string_view next_operator() {
        skip_space();
        for (auto op : {"||", "&&", "==", "!=", "<=", ">=", "<<", ">>", "|", "^", "&", "<", ">", "+", "-", "*", "/", "%"})
            if (text_.substr(position_).starts_with(op)) return op;
        return {};
    }
    Integer apply(std::string_view op, Integer a, Integer b, bool evaluate) {
        if (!evaluate) return {};
        if (op == "||") return bool_result(a.bits != 0 || b.bits != 0);
        if (op == "&&") return bool_result(a.bits != 0 && b.bits != 0);
        const bool uns = a.is_unsigned || b.is_unsigned;
        if (op == "|") return {a.bits | b.bits,uns}; if (op == "^") return {a.bits ^ b.bits,uns}; if (op == "&") return {a.bits & b.bits,uns};
        if (op == "==") return bool_result(a.bits == b.bits); if (op == "!=") return bool_result(a.bits != b.bits);
        if (op == "<") return bool_result(uns ? a.bits < b.bits : signed_value(a) < signed_value(b));
        if (op == "<=") return bool_result(uns ? a.bits <= b.bits : signed_value(a) <= signed_value(b));
        if (op == ">") return bool_result(uns ? a.bits > b.bits : signed_value(a) > signed_value(b));
        if (op == ">=") return bool_result(uns ? a.bits >= b.bits : signed_value(a) >= signed_value(b));
        if (op == "+") return uns ? Integer{a.bits + b.bits,true} : signed_result(checked_add(signed_value(a),signed_value(b)));
        if (op == "-") return uns ? Integer{a.bits - b.bits,true} : signed_result(checked_sub(signed_value(a),signed_value(b)));
        if (op == "*") return uns ? Integer{a.bits * b.bits,true} : signed_result(checked_mul(signed_value(a),signed_value(b)));
        if (op == "/" || op == "%") {
            if (b.bits == 0) error(hexlab::ErrorCode::malformed, "division by zero in #if expression");
            if (uns) return {op == "/" ? a.bits / b.bits : a.bits % b.bits,true};
            const auto left=signed_value(a), right=signed_value(b);
            if (left == std::numeric_limits<std::int64_t>::min() && right == -1)
                error(hexlab::ErrorCode::overflow, "signed overflow in #if division");
            return signed_result(op == "/" ? left / right : left % right);
        }
        if (op == "<<" || op == ">>") {
            const auto shift = b.is_unsigned ? (b.bits > 63 ? -1 : static_cast<std::int64_t>(b.bits)) : signed_value(b);
            if (shift < 0 || shift >= 64) error(hexlab::ErrorCode::malformed, "shift count outside supported #if range");
            if (op == ">>") return a.is_unsigned ? Integer{a.bits >> shift,true} : signed_result(signed_value(a) >> shift);
            if (a.is_unsigned) return {a.bits << shift,true};
            const auto left=signed_value(a);
            if (left < 0 || left > (std::numeric_limits<std::int64_t>::max() >> shift))
                error(hexlab::ErrorCode::overflow, "left shift overflows signed #if range");
            return signed_result(left << shift);
        }
        error(hexlab::ErrorCode::unsupported, "unsupported operator in #if expression");
    }
    Integer binary(int min_precedence, bool evaluate) {
        auto left = unary(evaluate);
        for (;;) {
            const auto op = next_operator();
            const int current_precedence = precedence(op);
            if (op.empty() || current_precedence < min_precedence) break;
            position_ += op.size();
            bool evaluate_right = evaluate;
            if (op == "&&" && left.bits == 0) evaluate_right = false;
            if (op == "||" && left.bits != 0) evaluate_right = false;
            const auto right = binary(current_precedence + 1, evaluate_right);
            left = apply(op, left, right, evaluate);
        }
        return left;
    }
    Integer conditional(bool evaluate) {
        const auto condition_value = binary(1, evaluate);
        if (!consume("?")) return condition_value;
        const auto when_true = conditional(evaluate && condition_value.bits != 0);
        if (!consume(":")) error(hexlab::ErrorCode::malformed, "missing ':' in #if conditional expression");
        const auto when_false = conditional(evaluate && condition_value.bits == 0);
        if (!evaluate) return {};
        return condition_value.bits ? when_true : when_false;
    }
};

struct State {
    const HeaderImportOptions &options;
    Macros macros;
    std::set<std::string, std::less<>> active;
    std::set<std::string, std::less<>> once_headers;
    std::uint64_t expanded_bytes = 0;
    std::uint32_t files = 0;
    std::uint32_t macro_expansions = 0;

    std::pair<std::vector<std::string>, std::size_t> parse_arguments(
        std::string_view line, std::size_t open) {
        std::vector<std::string> arguments;
        std::size_t start = open + 1;
        std::size_t i = start;
        unsigned nested = 0;
        while (i < line.size()) {
            if (line[i] == '"' || line[i] == '\'') {
                const char quote = line[i++];
                while (i < line.size()) {
                    if (line[i] == '\\' && i + 1 < line.size()) i += 2;
                    else if (line[i++] == quote) break;
                }
            } else if (line[i] == '(') { ++nested; ++i; }
            else if (line[i] == ')') {
                if (nested) { --nested; ++i; }
                else {
                    const auto final = trim(line.substr(start, i - start));
                    if (!arguments.empty() || !final.empty()) arguments.emplace_back(final);
                    if (arguments.size() > options.max_macro_arguments)
                        error(hexlab::ErrorCode::resource_limit, "macro argument count exceeds configured limit");
                    return {std::move(arguments), i + 1};
                }
            } else if (line[i] == ',' && nested == 0) {
                arguments.emplace_back(trim(line.substr(start, i - start)));
                if (arguments.size() > options.max_macro_arguments)
                    error(hexlab::ErrorCode::resource_limit, "macro argument count exceeds configured limit");
                start = ++i;
            } else ++i;
        }
        error(hexlab::ErrorCode::malformed, "unterminated function-like macro invocation");
    }

    std::string select_va_opt(std::string_view text, bool variadic_macro,
        bool variadic_nonempty,
        std::uint16_t depth = 0) {
        if (depth > options.max_macro_expansion_depth)
            error(hexlab::ErrorCode::resource_limit, "nested __VA_OPT__ exceeds configured macro expansion depth");
        std::string result;
        for (std::size_t i = 0; i < text.size();) {
            if (text[i] == '"' || text[i] == '\'') {
                const char quote = text[i];
                result.push_back(text[i++]);
                while (i < text.size()) {
                    const char c = text[i++]; result.push_back(c);
                    if (c == '\\' && i < text.size()) result.push_back(text[i++]);
                    else if (c == quote) break;
                }
                continue;
            }
            if (id_start(text[i])) {
                const auto begin = i++;
                while (i < text.size() && id_char(text[i])) ++i;
                const auto token = text.substr(begin, i - begin);
                if (token != "__VA_OPT__") {
                    result.append(token);
                    continue;
                }
                if (!variadic_macro)
                    error(hexlab::ErrorCode::unsupported, "__VA_OPT__ is only supported in variadic macro replacements");
                auto open = i;
                while (open < text.size() && std::isspace(static_cast<unsigned char>(text[open]))) ++open;
                if (open == text.size() || text[open] != '(')
                    error(hexlab::ErrorCode::malformed, "__VA_OPT__ must be followed by a parenthesized token sequence");
                std::size_t close = open + 1;
                unsigned nesting = 0;
                for (; close < text.size(); ++close) {
                    if (text[close] == '"' || text[close] == '\'') {
                        const char quote = text[close++];
                        while (close < text.size()) {
                            if (text[close] == '\\' && close + 1 < text.size()) close += 2;
                            else if (text[close++] == quote) break;
                        }
                        if (close) --close;
                    } else if (text[close] == '(') ++nesting;
                    else if (text[close] == ')') {
                        if (nesting == 0) break;
                        --nesting;
                    }
                }
                if (close == text.size())
                    error(hexlab::ErrorCode::malformed, "unterminated __VA_OPT__ token sequence");
                auto contents = select_va_opt(text.substr(open + 1, close - open - 1), true,
                    variadic_nonempty, static_cast<std::uint16_t>(depth + 1));
                if (variadic_nonempty) result += contents;
                i = close + 1;
            } else {
                result.push_back(text[i++]);
            }
            if (result.size() > options.max_expanded_bytes)
                error(hexlab::ErrorCode::resource_limit, "__VA_OPT__ substitution exceeds configured expanded byte limit");
        }
        return result;
    }

    std::string substitute(const Macro &macro, const std::vector<std::string> &raw_arguments,
        const std::vector<std::string> &arguments) {
        std::map<std::string, std::string, std::less<>> replacements, raw_replacements;
        for (std::size_t i = 0; i < macro.parameters.size(); ++i) {
            replacements.emplace(macro.parameters[i], arguments[i]);
            raw_replacements.emplace(macro.parameters[i], raw_arguments[i]);
        }
        if (macro.variadic) {
            std::string variadic;
            for (std::size_t i = macro.parameters.size(); i < arguments.size(); ++i) {
                if (i != macro.parameters.size()) variadic += ", ";
                variadic += arguments[i];
            }
            replacements.emplace("__VA_ARGS__", std::move(variadic));
            std::string raw_variadic;
            for (std::size_t i = macro.parameters.size(); i < raw_arguments.size(); ++i) {
                if (i != macro.parameters.size()) raw_variadic += ", ";
                raw_variadic += raw_arguments[i];
            }
            raw_replacements.emplace("__VA_ARGS__", std::move(raw_variadic));
        }
        bool variadic_nonempty = false;
        if (macro.variadic) {
            const auto variadic_begin = macro.parameters.size();
            for (std::size_t i = variadic_begin; i < arguments.size(); ++i)
                variadic_nonempty = variadic_nonempty || !trim(arguments[i]).empty();
        }
        const auto selected_text = select_va_opt(macro.replacement, macro.variadic, variadic_nonempty);
        std::string result;
        const auto text = std::string_view(selected_text);
        for (std::size_t i = 0; i < text.size();) {
            if (text[i] == '#' && i + 1 < text.size() && text[i + 1] == '#') {
                i += 2;
                while (!result.empty() && std::isspace(static_cast<unsigned char>(result.back()))) result.pop_back();
                while (i < text.size() && std::isspace(static_cast<unsigned char>(text[i]))) ++i;
                const auto begin = i;
                if (i < text.size() && id_start(text[i])) { ++i; while (i < text.size() && id_char(text[i])) ++i; }
                else if (i < text.size() && text[i] != '"' && text[i] != '\'') ++i;
                if (begin == i || result.empty()) error(hexlab::ErrorCode::malformed, "invalid token-paste operands in macro replacement");
                const auto operand = text.substr(begin, i - begin);
                std::string rhs(operand);
                if (id_start(operand.front())) {
                    const auto parameter = raw_replacements.find(std::string(operand));
                    if (parameter != raw_replacements.end()) rhs = trim(parameter->second);
                }
                std::size_t lhs = result.size();
                while (lhs && !std::isspace(static_cast<unsigned char>(result[lhs - 1]))) --lhs;
                const std::string pasted = result.substr(lhs) + rhs;
                if (pasted.empty() || pasted.find_first_of(" \t\r\n\"'") != std::string::npos)
                    error(hexlab::ErrorCode::unsupported, "token paste does not form one supported preprocessing token");
                result.resize(lhs); result += pasted;
                continue;
            }
            if (text[i] == '#' && (i + 1 == text.size() || text[i + 1] != '#')) {
                if (i + 1 == text.size()) error(hexlab::ErrorCode::malformed, "# in a macro replacement must precede a parameter");
                ++i; while (i < text.size() && std::isspace(static_cast<unsigned char>(text[i]))) ++i;
                const auto begin = i;
                if (i < text.size() && id_start(text[i])) { ++i; while (i < text.size() && id_char(text[i])) ++i; }
                const auto parameter = raw_replacements.find(std::string(text.substr(begin, i - begin)));
                if (parameter == raw_replacements.end()) error(hexlab::ErrorCode::malformed, "# in a macro replacement must precede a parameter");
                std::string spelling;
                bool space = false;
                for (char c : trim(parameter->second)) {
                    if (std::isspace(static_cast<unsigned char>(c))) space = !spelling.empty();
                    else { if (space) spelling.push_back(' '); space = false; spelling.push_back(c); }
                }
                result.push_back('"');
                for (char c : spelling) { if (c == '\\' || c == '"') result.push_back('\\'); result.push_back(c); }
                result.push_back('"');
                continue;
            }
            if (text[i] == '"' || text[i] == '\'') {
                const char quote = text[i];
                result.push_back(text[i++]);
                while (i < text.size()) {
                    const char c = text[i++]; result.push_back(c);
                    if (c == '\\' && i < text.size()) result.push_back(text[i++]);
                    else if (c == quote) break;
                }
            } else if (id_start(text[i])) {
                const auto begin = i++;
                while (i < text.size() && id_char(text[i])) ++i;
                const auto found = replacements.find(std::string(text.substr(begin, i - begin)));
                if (found == replacements.end()) result.append(text.substr(begin, i - begin));
                else result += found->second;
            } else result.push_back(text[i++]);
            if (result.size() > options.max_expanded_bytes)
                error(hexlab::ErrorCode::resource_limit, "macro substitution exceeds configured expanded byte limit");
        }
        return result;
    }

    void count_expansion() {
        if (++macro_expansions > options.max_macro_expansions)
            error(hexlab::ErrorCode::resource_limit, "macro invocation count exceeds configured limit");
    }

    std::string expand(std::string_view line, std::uint16_t depth = 0,
        std::set<std::string, std::less<>> disabled = {}) {
        if (depth > options.max_macro_expansion_depth)
            error(hexlab::ErrorCode::resource_limit, "macro expansion exceeds configured depth");
        std::string out;
        for (std::size_t i = 0; i < line.size();) {
            if (line[i] == '"' || line[i] == '\'') {
                const char quote = line[i];
                out.push_back(line[i++]);
                while (i < line.size()) {
                    const char c = line[i++]; out.push_back(c);
                    if (c == '\\' && i < line.size()) out.push_back(line[i++]);
                    else if (c == quote) break;
                }
            } else if (id_start(line[i])) {
                const auto begin = i++;
                while (i < line.size() && id_char(line[i])) ++i;
                std::string name(line.substr(begin, i - begin));
                const auto found = macros.find(name);
                if (found == macros.end() || disabled.contains(name)) out += name;
                else if (!found->second.function_like) {
                    count_expansion();
                    auto nested = disabled; nested.insert(name);
                    out += expand(found->second.replacement, static_cast<std::uint16_t>(depth + 1), std::move(nested));
                } else {
                    auto open = i;
                    while (open < line.size() && std::isspace(static_cast<unsigned char>(line[open]))) ++open;
                    if (open == line.size() || line[open] != '(') out += name;
                    else {
                        auto [arguments, end] = parse_arguments(line, open);
                        const auto &macro = found->second;
                        // The C preprocessing rules represent F() as one empty
                        // argument when F has one named parameter.
                        if (arguments.empty() && macro.parameters.size() == 1) arguments.emplace_back();
                        if (arguments.size() > options.max_macro_arguments)
                            error(hexlab::ErrorCode::resource_limit, "macro argument count exceeds configured limit");
                        const bool arity_ok = macro.variadic
                            ? arguments.size() >= macro.parameters.size()
                            : arguments.size() == macro.parameters.size();
                        if (!arity_ok)
                            error(hexlab::ErrorCode::malformed, "macro '" + name + "' expects " +
                                (macro.variadic ? "at least " : "") + std::to_string(macro.parameters.size()) +
                                " arguments, received " + std::to_string(arguments.size()));
                        count_expansion();
                        auto raw_arguments = arguments;
                        for (auto &argument : arguments)
                            argument = expand(argument, static_cast<std::uint16_t>(depth + 1), disabled);
                        auto replacement = substitute(macro, raw_arguments, arguments);
                        auto nested = disabled; nested.insert(name);
                        out += expand(replacement, static_cast<std::uint16_t>(depth + 1), std::move(nested));
                        i = end;
                    }
                }
            } else out.push_back(line[i++]);
            if (out.size() > options.max_expanded_bytes)
                error(hexlab::ErrorCode::resource_limit, "macro expansion exceeds configured expanded byte limit");
        }
        return out;
    }

    std::string expand_defined_operators(std::string_view expression) {
        std::string output;
        for (std::size_t i = 0; i < expression.size();) {
            if (expression[i] == '"' || expression[i] == '\'') {
                const char quote = expression[i];
                output.push_back(expression[i++]);
                while (i < expression.size()) {
                    const char c = expression[i++]; output.push_back(c);
                    if (c == '\\' && i < expression.size()) output.push_back(expression[i++]);
                    else if (c == quote) break;
                }
            } else if (id_start(expression[i])) {
                const auto begin = i++;
                while (i < expression.size() && id_char(expression[i])) ++i;
                const auto name = expression.substr(begin, i - begin);
                if (name != "defined") output.append(name);
                else {
                    auto operand = i;
                    while (operand < expression.size() && std::isspace(static_cast<unsigned char>(expression[operand]))) ++operand;
                    bool parenthesized = operand < expression.size() && expression[operand] == '(';
                    if (parenthesized) {
                        ++operand;
                        while (operand < expression.size() && std::isspace(static_cast<unsigned char>(expression[operand]))) ++operand;
                    }
                    if (operand == expression.size() || !id_start(expression[operand]))
                        error(hexlab::ErrorCode::malformed, "defined in #if requires a macro identifier");
                    const auto macro_begin = operand++;
                    while (operand < expression.size() && id_char(expression[operand])) ++operand;
                    const auto macro_name = expression.substr(macro_begin, operand - macro_begin);
                    while (operand < expression.size() && std::isspace(static_cast<unsigned char>(expression[operand]))) ++operand;
                    if (parenthesized) {
                        if (operand == expression.size() || expression[operand] != ')')
                            error(hexlab::ErrorCode::malformed, "malformed defined(NAME) in #if expression");
                        ++operand;
                    }
                    output += macros.contains(std::string(macro_name)) ? "1" : "0";
                    i = operand;
                }
            } else output.push_back(expression[i++]);
        }
        return output;
    }

    bool condition(std::string_view expression) {
        auto with_defined = expand_defined_operators(expression);
        auto expanded = expand(with_defined);
        return ConditionalExpression(expanded).evaluate() != 0;
    }

    std::string process(std::string_view source, std::string id, std::uint16_t include_depth) {
        // #pragma once is keyed by the caller-supplied stable identity rather
        // than spelling, so aliases resolved to the same file are suppressed.
        if (once_headers.contains(id)) return {};
        const bool recursive_include = active.contains(id);
        if (include_depth > options.max_include_depth)
            error(hexlab::ErrorCode::resource_limit, recursive_include
                ? "unguarded recursive include exceeds configured include depth: " + id
                : "header include depth exceeds configured limit");
        if (++files > options.max_include_files)
            error(hexlab::ErrorCode::resource_limit, "header include count exceeds configured limit");
        if (source.size() > options.max_input_bytes)
            error(hexlab::ErrorCode::resource_limit, "header input exceeds configured byte limit: " + id);
        active.insert(id);
        struct Pop { State &s; std::string id; ~Pop() { s.active.erase(id); } } pop{*this, id};

        // C translation phase 2 removes a backslash-newline pair before
        // directives and macro bodies are interpreted.
        std::string spliced;
        spliced.reserve(source.size());
        for (std::size_t i = 0; i < source.size(); ++i) {
            if (source[i] == '\\' && i + 1 < source.size() && source[i + 1] == '\n') {
                ++i;
            } else if (source[i] == '\\' && i + 2 < source.size() &&
                source[i + 1] == '\r' && source[i + 2] == '\n') {
                i += 2;
            } else {
                spliced.push_back(source[i]);
            }
        }
        source = spliced;
        const auto uncommented=remove_comments(source);
        source=uncommented;

        struct Conditional { bool parent; bool taken; bool in_else; };
        std::vector<Conditional> conditions;
        bool enabled = true;
        std::string output;
        auto append_local = [&](std::string_view text) {
            output.append(text);
            expanded_bytes += text.size();
            if (expanded_bytes > options.max_expanded_bytes)
                error(hexlab::ErrorCode::resource_limit, "preprocessed header exceeds configured expanded byte limit");
        };
        std::size_t offset = 0;
        while (offset < source.size()) {
            auto end = source.find('\n', offset);
            if (end == std::string_view::npos) end = source.size();
            auto line = source.substr(offset, end - offset);
            offset = end == source.size() ? end : end + 1;
            const auto stripped = trim(line);
            if (stripped.starts_with("#")) {
                auto directive = trim(stripped.substr(1));
                const auto space = directive.find_first_of(" \t");
                const auto command = directive.substr(0, space);
                auto rest = space == std::string_view::npos ? std::string_view{} : trim(directive.substr(space));
                if (command == "if" || command == "ifdef" || command == "ifndef") {
                    bool test;
                    if (command == "if") test = enabled ? condition(rest) : false;
                    else {
                        const auto name = std::string(trim(rest));
                        if (name.empty() || !id_start(name.front()) || !std::all_of(name.begin(), name.end(), id_char))
                            error(hexlab::ErrorCode::malformed, "malformed #" + std::string(command) + " directive");
                        test = enabled && macros.contains(name);
                        if (command == "ifndef") test = !test;
                    }
                    conditions.push_back({enabled, enabled && test, false});
                    enabled = enabled && test;
                } else if (command == "else") {
                    if (conditions.empty() || conditions.back().in_else) error(hexlab::ErrorCode::malformed, "unmatched or repeated #else");
                    auto &c = conditions.back(); c.in_else = true;
                    enabled = c.parent && !c.taken; c.taken = c.taken || enabled;
                } else if (command == "elif") {
                    if (conditions.empty() || conditions.back().in_else) error(hexlab::ErrorCode::malformed, "unmatched #elif");
                    auto &c = conditions.back();
                    const bool test = c.parent && !c.taken ? condition(rest) : false;
                    enabled = c.parent && !c.taken && test;
                    c.taken = c.taken || enabled;
                } else if (command == "endif") {
                    if (conditions.empty()) error(hexlab::ErrorCode::malformed, "unmatched #endif");
                    enabled = conditions.back().parent; conditions.pop_back();
                } else if (!enabled) {
                    // Inactive branches do not define macros or resolve includes.
                } else if (command == "define") {
                    const auto name_end = rest.find_first_of(" \t(");
                    const auto name = std::string(rest.substr(0, name_end));
                    if (name.empty() || !id_start(name.front()) || !std::all_of(name.begin(), name.end(), id_char))
                        error(hexlab::ErrorCode::malformed, "malformed #define directive");
                    const auto after = name_end == std::string_view::npos ? std::string_view{} : rest.substr(name_end);
                    Macro macro;
                    if (after.starts_with("(")) {
                        macro.function_like = true;
                        const auto close = after.find(')');
                        if (close == std::string_view::npos)
                            error(hexlab::ErrorCode::malformed, "unterminated parameter list in function-like macro '" + name + "'");
                        auto parameters = trim(after.substr(1, close - 1));
                        std::set<std::string, std::less<>> unique;
                        while (!parameters.empty()) {
                            const auto comma = parameters.find(',');
                            const auto parameter = trim(parameters.substr(0, comma));
                            if (parameter == "...") {
                                if (comma != std::string_view::npos)
                                    error(hexlab::ErrorCode::malformed, "ellipsis must be the final parameter in macro '" + name + "'");
                                macro.variadic = true;
                                break;
                            }
                            if (parameter.empty() || !id_start(parameter.front()) || !std::all_of(parameter.begin(), parameter.end(), id_char))
                                error(hexlab::ErrorCode::malformed, "invalid parameter in function-like macro '" + name + "'");
                            std::string parameter_name(parameter);
                            if (parameter_name == "__VA_ARGS__")
                                error(hexlab::ErrorCode::malformed, "'__VA_ARGS__' is reserved in macro parameter lists");
                            if (!unique.insert(parameter_name).second)
                                error(hexlab::ErrorCode::malformed, "duplicate parameter in function-like macro '" + name + "'");
                            macro.parameters.push_back(std::move(parameter_name));
                            if (macro.parameters.size() > options.max_macro_arguments)
                                error(hexlab::ErrorCode::resource_limit, "macro parameter count exceeds configured limit");
                            if (comma == std::string_view::npos) break;
                            if (trim(parameters.substr(comma + 1)).empty())
                                error(hexlab::ErrorCode::malformed, "empty trailing parameter in function-like macro '" + name + "'");
                            parameters = trim(parameters.substr(comma + 1));
                        }
                        macro.replacement = std::string(trim(after.substr(close + 1)));
                    } else {
                        macro.replacement = std::string(trim(after));
                    }
                    if (!macros.contains(name) && macros.size() >= options.max_macros)
                        error(hexlab::ErrorCode::resource_limit, "macro count exceeds configured limit");
                    macros[name] = std::move(macro);
                } else if (command == "undef") {
                    macros.erase(std::string(trim(rest)));
                } else if (command == "include") {
                    auto include = trim(rest);
                    std::string expanded_include_storage;
                    // A directly formed header-name is already a single
                    // preprocessing token. Other operands are macro-expanded
                    // first, allowing common forms such as #define H "api.h"
                    // followed by #include H.
                    if (include.empty() || (include.front() != '<' && include.front() != '"')) {
                        expanded_include_storage = expand(include);
                        include = trim(expanded_include_storage);
                    }
                    const bool angled = !include.empty() && include.front() == '<';
                    if (!options.include_resolver)
                        error(hexlab::ErrorCode::unsupported, "#include requires a configured include_resolver");
                    if (include.size() < 3 || (angled ? include.back() != '>' : include.front() != '"' || include.back() != '"'))
                        error(hexlab::ErrorCode::malformed, "malformed #include directive");
                    const auto name = include.substr(1, include.size() - 2);
                    const auto resolved = options.include_resolver(name, id, angled);
                    if (!resolved) error(hexlab::ErrorCode::unsupported, "unable to resolve include '" + std::string(name) + "' from " + id);
                    output += process(resolved->contents, resolved->id.empty() ? std::string(name) : resolved->id,
                        static_cast<std::uint16_t>(include_depth + 1));
                } else if (command == "pragma") {
                    if (trim(rest) == "once") {
                        once_headers.insert(id);
                    } else {
                        append_local(line); append_local("\n");
                    }
                } else if (command == "" || command == "line") {
                    // Empty lines and source-location directives have no type semantics.
                } else {
                    error(hexlab::ErrorCode::unsupported, "unsupported preprocessor directive: #" + std::string(command));
                }
            } else if (enabled) {
                append_local(expand(line)); append_local("\n");
            }
        }
        if (!conditions.empty()) error(hexlab::ErrorCode::malformed, "unterminated conditional preprocessor block in " + id);
        return output;
    }
};
}

hexlab::Result<std::string> preprocess_header(std::string_view source, const HeaderImportOptions &options) {
    try {
        State state{options};
        if (options.predefined_macros.size() > options.max_macros)
            return hexlab::Error{hexlab::ErrorCode::resource_limit, "predefined macro count exceeds configured limit"};
        for (const auto &[name, replacement] : options.predefined_macros) {
            if (name.empty() || !id_start(name.front()) || !std::all_of(name.begin(), name.end(), id_char))
                return hexlab::Error{hexlab::ErrorCode::invalid_argument, "predefined macro names must be valid identifiers"};
            state.macros.emplace(name, Macro{false, false, {}, replacement});
        }
        return state.process(source, "<input>", 0);
    } catch (const hexlab::Error &e) { return e; }
}
}
