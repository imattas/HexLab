#include "hexlab/types/header_import.hpp"
#include "header_preprocessor.hpp"

#include <algorithm>
#include <charconv>
#include <cctype>
#include <functional>
#include <limits>
#include <set>
#include <stdexcept>
#include <utility>
#include <vector>

namespace hexlab::types {
namespace {
struct Token { std::string text; std::uint32_t line=1; friend bool operator==(const Token &left, const Token &right) { return left.text == right.text; } };
[[noreturn]] void fail(ErrorCode code, const std::string &message) { throw Error{code,message}; }

bool ident_start(char c) { return (c>='a'&&c<='z')||(c>='A'&&c<='Z')||c=='_'; }
bool ident_continue(char c) { return ident_start(c)||(c>='0'&&c<='9'); }
std::vector<Token> lex(std::string_view text, const HeaderImportOptions &o) {
    if(text.size()>o.max_input_bytes) fail(ErrorCode::resource_limit,"header input exceeds configured byte limit");
    std::vector<Token> out; std::size_t i=0; std::uint32_t line=1;
    auto push=[&](std::string s){ if(out.size()>=o.max_tokens) fail(ErrorCode::resource_limit,"header token count exceeds configured limit"); out.push_back({std::move(s),line}); };
    while(i<text.size()) {
        char c=text[i];
        if(c=='\n'){++line;++i;continue;}
        if(c==' '||c=='\t'||c=='\r'||c=='\f'||c=='\v'){++i;continue;}
        if(c=='#') {
            const auto begin=i;
            while(i<text.size()&&text[i]!='\n')++i;
            auto directive=text.substr(begin,i-begin);
            auto trim=[](std::string_view value){
                while(!value.empty()&&(value.front()==' '||value.front()=='\t'||value.front()=='\r'))value.remove_prefix(1);
                while(!value.empty()&&(value.back()==' '||value.back()=='\t'||value.back()=='\r'))value.remove_suffix(1);
                return value;
            };
            directive=trim(directive);
            if(!directive.starts_with("#pragma"))
                fail(ErrorCode::unsupported,"preprocessor directives are not expanded; remove directives before importing");
            auto body=trim(directive.substr(7));
            if(!body.starts_with("pack"))
                fail(ErrorCode::unsupported,"unsupported C pragma; only #pragma pack is recognized");
            body=trim(body.substr(4));
            if(body.size()<2||body.front()!='('||body.back()!=')')
                fail(ErrorCode::malformed,"malformed #pragma pack directive at line "+std::to_string(line));
            auto arg=trim(body.substr(1,body.size()-2));
            std::string marker;
            auto parse_cap=[&](std::string_view value){
                value=trim(value);
                unsigned cap=0;
                const auto [end,error]=std::from_chars(value.data(),value.data()+value.size(),cap);
                if(value.empty()||error!=std::errc{}||end!=value.data()+value.size()||
                   (cap!=0&&cap!=1&&cap!=2&&cap!=4&&cap!=8&&cap!=16))
                    fail(ErrorCode::malformed,"#pragma pack alignment must be 0, 1, 2, 4, 8, or 16");
                return cap;
            };
            auto split_args=[&](std::string_view value){
                std::vector<std::string> args;
                while(true){auto comma=value.find(',');auto part=trim(value.substr(0,comma));args.emplace_back(part);
                    if(comma==std::string_view::npos)break;value.remove_prefix(comma+1);}
                return args;
            };
            if(arg.empty()||arg=="0"||arg=="default") marker="@pack_set_0";
            else if(arg=="show") marker="@pack_show";
            else if(arg=="pop") marker="@pack_pop";
            else if(arg.starts_with("pop,")) {
                auto args=split_args(arg);
                if(args.empty()||args[0]!="pop"||args.size()>3)
                    fail(ErrorCode::malformed,"malformed #pragma pack(pop) directive");
                if(args.size()==1) marker="@pack_pop";
                else if(args[1].empty()) fail(ErrorCode::malformed,"malformed #pragma pack(pop) directive");
                else if(std::all_of(args[1].begin(),args[1].end(),[](char c){return c>='0'&&c<='9';})) {
                    if(args.size()!=2) fail(ErrorCode::malformed,"numeric #pragma pack(pop, n) cannot have a third argument");
                    marker="@pack_pop_value_"+std::to_string(parse_cap(args[1]));
                } else if(ident_start(args[1].front())&&std::all_of(args[1].begin(),args[1].end(),ident_continue)) {
                    if(args.size()==2) marker="@pack_pop_named|"+args[1];
                    else marker="@pack_pop_named_value|"+args[1]+"|"+std::to_string(parse_cap(args[2]));
                } else fail(ErrorCode::malformed,"malformed #pragma pack(pop) argument");
            }
            else if(arg.starts_with("push")) {
                auto rest=trim(arg.substr(4));
                if(rest.empty()) marker="@pack_push_current";
                else if(rest.front()==',') {
                    auto args=split_args(rest.substr(1));
                    if(args.size()==1) {
                        const auto &arg_value=args[0];
                        if(!arg_value.empty()&&std::all_of(arg_value.begin(),arg_value.end(),[](char c){return c>='0'&&c<='9';}))
                            marker="@pack_push_"+std::to_string(parse_cap(arg_value));
                        else if(!arg_value.empty()&&ident_start(arg_value.front())&&std::all_of(arg_value.begin(),arg_value.end(),ident_continue))
                            marker="@pack_push_named_current|"+arg_value;
                        else fail(ErrorCode::malformed,"malformed #pragma pack push directive");
                    }
                    else if(args.size()==2&& !args[0].empty()&&ident_start(args[0].front())&&
                            std::all_of(args[0].begin(),args[0].end(),ident_continue))
                        marker="@pack_push_named|"+args[0]+"|"+std::to_string(parse_cap(args[1]));
                    else fail(ErrorCode::malformed,"malformed #pragma pack push directive");
                }
                else fail(ErrorCode::malformed,"malformed #pragma pack push directive");
            } else marker="@pack_set_"+std::to_string(parse_cap(arg));
            push(std::move(marker));
            continue;
        }
        if(c=='/' && i+1<text.size() && text[i+1]=='/') { i+=2;while(i<text.size()&&text[i]!='\n')++i;continue; }
        if(c=='/' && i+1<text.size() && text[i+1]=='*') { i+=2;bool closed=false;while(i+1<text.size()){if(text[i]=='\n')++line;if(text[i]=='*'&&text[i+1]=='/'){i+=2;closed=true;break;}++i;}if(!closed)fail(ErrorCode::malformed,"unterminated block comment");continue; }
        if(c=='"') {
            const auto begin=i++;
            bool closed=false;
            while(i<text.size()) {
                if(text[i]=='\n') fail(ErrorCode::malformed,"newline in string literal at line "+std::to_string(line));
                if(text[i]=='\\') {
                    if(i+1>=text.size()||text[i+1]=='\n')
                        fail(ErrorCode::malformed,"unterminated escape in string literal at line "+std::to_string(line));
                    i+=2;
                    continue;
                }
                if(text[i++]=='"') { closed=true; break; }
            }
            if(!closed) fail(ErrorCode::malformed,"unterminated string literal at line "+std::to_string(line));
            push(std::string(text.substr(begin,i-begin)));
            continue;
        }
        if(ident_start(c)){std::size_t b=i++;while(i<text.size()&&ident_continue(text[i]))++i;push(std::string(text.substr(b,i-b)));continue;}
        if(c>='0'&&c<='9'){std::size_t b=i++;while(i<text.size()&&((text[i]>='0'&&text[i]<='9')||(text[i]>='a'&&text[i]<='z')||(text[i]>='A'&&text[i]<='Z')||text[i]=='x'||text[i]=='X'))++i;push(std::string(text.substr(b,i-b)));continue;}
        if(c==':'&&i+1<text.size()&&text[i+1]==':'){push("::");i+=2;continue;}
        if(c=='.'&&i+2<text.size()&&text.substr(i,3)=="..."){push("...");i+=3;continue;}
        if(std::string_view("{}[]();,*=&+-/%|^~!<>?:.").find(c)!=std::string_view::npos){push(std::string(1,c));++i;continue;}
        fail(ErrorCode::unsupported,"unsupported character in C header at line "+std::to_string(line));
    }
    out.push_back({"<eof>",line});return out;
}

struct Decl { std::string name; TypePtr type; std::vector<Parameter> params; bool function=false; bool variadic=false; FunctionConvention convention=FunctionConvention::platform_default; };
struct Base { TypePtr type; bool is_typedef=false; bool is_static=false; bool is_inline=false; };
struct TemplateParameter {
    std::string name;
    std::vector<Token> default_type;
    bool value_parameter = false;
    bool template_parameter = false;
    bool pack = false;
    TypePtr value_type;
    std::vector<Token> default_value_expression;
    std::string default_template;
    std::vector<TemplateParameter> nested_parameters;
};
struct TemplateArgument { TypePtr type; std::optional<std::uint64_t> value; std::string template_name; };
struct TemplateBindings {
    std::map<std::string, TypePtr, std::less<>> types;
    std::map<std::string, std::uint64_t, std::less<>> values;
    std::map<std::string, std::string, std::less<>> templates;
    std::map<std::string, std::vector<TemplateArgument>, std::less<>> packs;
};
struct TemplateAlias { std::vector<TemplateParameter> parameters; std::vector<Token> target; };
struct AggregateSpecialization {
    std::vector<TemplateParameter> parameters;
    std::vector<std::vector<Token>> patterns;
    std::vector<Token> definition;
};
struct AggregateTemplate {
    bool is_union = false;
    std::vector<TemplateParameter> parameters;
    std::vector<Token> definition;
    std::vector<AggregateSpecialization> specializations;
};

std::uint64_t integer_token_magnitude(std::string text, std::uint64_t limit) {
    while (!text.empty() && (text.back() == 'u' || text.back() == 'U' ||
                             text.back() == 'l' || text.back() == 'L'))
        text.pop_back();
    if (text.empty()) fail(ErrorCode::malformed, "invalid integer constant expression literal");
    int base = 10;
    std::string_view digits = text;
    if (digits.size() > 2 && digits[0] == '0' && (digits[1] == 'x' || digits[1] == 'X')) {
        base = 16;
        digits.remove_prefix(2);
    } else if (digits.size() > 1 && digits[0] == '0') {
        base = 8;
        digits.remove_prefix(1);
    }
    std::uint64_t value = 0;
    const auto [end, error] = std::from_chars(digits.data(), digits.data() + digits.size(), value, base);
    if (error != std::errc{} || end != digits.data() + digits.size() || value > limit)
        fail(ErrorCode::overflow, "integer constant expression literal is outside the supported range");
    return value;
}

class IntegerExpressionParser {
public:
    using NameResolver = std::function<std::optional<std::int64_t>(std::string_view)>;

    IntegerExpressionParser(const std::vector<Token> &tokens,
                            const std::map<std::string, std::uint64_t, std::less<>> &bindings,
                            std::uint16_t max_nesting,
                            const std::map<std::string, std::vector<TemplateArgument>, std::less<>> &packs,
                            NameResolver name_resolver = {})
        : tokens_(tokens), max_nesting_(max_nesting), name_resolver_(std::move(name_resolver)) {
        for (const auto &[name, value] : bindings) {
            if (value > static_cast<std::uint64_t>(INT64_MAX))
                fail(ErrorCode::overflow, "bound integer exceeds the signed expression range");
            bindings_.emplace(name, static_cast<std::int64_t>(value));
        }
        for (const auto &[name, arguments] : packs)
            pack_sizes_.emplace(name, static_cast<std::int64_t>(arguments.size()));
    }

    IntegerExpressionParser(const std::vector<Token> &tokens,
                            const std::map<std::string, std::int64_t, std::less<>> &bindings,
                            std::uint16_t max_nesting,
                            const std::map<std::string, std::vector<TemplateArgument>, std::less<>> &packs,
                            NameResolver name_resolver = {})
        : tokens_(tokens), bindings_(bindings), max_nesting_(max_nesting),
          name_resolver_(std::move(name_resolver)) {
        for (const auto &[name, arguments] : packs)
            pack_sizes_.emplace(name, static_cast<std::int64_t>(arguments.size()));
    }

    std::int64_t parse() {
        if (tokens_.empty()) fail(ErrorCode::malformed, "empty integer constant expression");
        if (tokens_.size() > max_tokens)
            fail(ErrorCode::resource_limit, "integer constant expression exceeds its token limit");
        const auto value = parse_binary(1, 0, true);
        if (position_ != tokens_.size())
            fail(ErrorCode::unsupported, "unsupported token in integer constant expression");
        return value;
    }

private:
    static constexpr std::size_t max_tokens = 4096;
    static constexpr std::size_t max_operations = 4096;

    static int precedence(std::string_view op) {
        if (op == "||") return 1;
        if (op == "&&") return 2;
        if (op == "|") return 3;
        if (op == "^") return 4;
        if (op == "&") return 5;
        if (op == "==" || op == "!=") return 6;
        if (op == "<" || op == ">" || op == "<=" || op == ">=") return 7;
        if (op == "<<" || op == ">>") return 8;
        if (op == "+" || op == "-") return 9;
        if (op == "*" || op == "/" || op == "%") return 10;
        return 0;
    }

    bool done() const { return position_ >= tokens_.size(); }
    std::string_view peek() const { return done() ? std::string_view{} : tokens_[position_].text; }
    bool take(std::string_view value) {
        if (peek() != value) return false;
        ++position_;
        return true;
    }

    std::int64_t parse_binary(int minimum, unsigned depth, bool evaluate) {
        enter(depth);
        auto left = parse_unary(depth + 1, evaluate);
        for (;;) {
            std::string op(peek());
            if (!done() && position_ + 1 < tokens_.size()) {
                const auto pair = op + tokens_[position_ + 1].text;
                if (pair == "||" || pair == "&&" || pair == "==" || pair == "!=" ||
                    pair == "<=" || pair == ">=" || pair == "<<" || pair == ">>") op = pair;
            }
            const auto op_precedence = precedence(op);
            if (op_precedence < minimum) break;
            if (++operations_ > max_operations)
                fail(ErrorCode::resource_limit, "integer constant expression exceeds its operation limit");
            position_ += op.size();
            const bool shorted = evaluate &&
                ((op == "&&" && left == 0) || (op == "||" && left != 0));
            const auto right = parse_binary(op_precedence + 1, depth + 1, evaluate && !shorted);
            if (evaluate) left = shorted ? (op == "||" ? 1 : 0) : apply(op, left, right);
        }
        return left;
    }

    std::int64_t parse_unary(unsigned depth, bool evaluate) {
        enter(depth);
        if (take("+")) return parse_unary(depth + 1, evaluate);
        if (take("-")) {
            const auto value = parse_unary(depth + 1, evaluate);
            if (!evaluate) return 0;
            if (value == INT64_MIN) fail(ErrorCode::overflow, "integer constant expression negation overflows");
            return -value;
        }
        if (take("~")) { const auto value = parse_unary(depth + 1, evaluate); return evaluate ? ~value : 0; }
        return parse_primary(depth + 1, evaluate);
    }

    std::int64_t parse_primary(unsigned depth, bool evaluate) {
        enter(depth);
        if (take("(")) {
            const auto value = parse_binary(1, depth + 1, evaluate);
            if (!take(")")) fail(ErrorCode::malformed, "unclosed parenthesis in integer constant expression");
            return value;
        }
        if (done()) fail(ErrorCode::malformed, "missing operand in integer constant expression");
        auto token = tokens_[position_++].text;
        if (token == "sizeof") {
            if (!take("(") || !take("..."))
                fail(ErrorCode::unsupported, "only sizeof...(Pack) is supported in integer constant expressions");
            if (done() || !ident_start(tokens_[position_].text.front()) ||
                !std::all_of(tokens_[position_].text.begin(), tokens_[position_].text.end(), ident_continue))
                fail(ErrorCode::malformed, "sizeof... requires a template parameter pack name");
            const auto name = tokens_[position_++].text;
            if (!take(")")) fail(ErrorCode::malformed, "unclosed sizeof... expression");
            const auto pack = pack_sizes_.find(name);
            if (pack == pack_sizes_.end())
                fail(ErrorCode::unsupported, "sizeof... refers to an unbound template parameter pack: '" + name + "'");
            return evaluate ? pack->second : 0;
        }
        if (token == "true") return evaluate ? 1 : 0;
        if (token == "false") return 0;
        bool global_qualified = false;
        if (token == "::") {
            if (done() || !ident_start(tokens_[position_].text.front()))
                fail(ErrorCode::malformed, "global-qualified enumerator name is incomplete");
            global_qualified = true;
            token = tokens_[position_++].text;
        } else if (!token.empty() && ident_start(token.front()) &&
                   std::all_of(token.begin(), token.end(), ident_continue)) {
            // Start from one identifier and consume a complete C++ qualified
            // name before looking it up in the source-ordered constant map.
        } else {
            const auto value=static_cast<std::int64_t>(integer_token_magnitude(token, static_cast<std::uint64_t>(INT64_MAX)));
            return evaluate ? value : 0;
        }
        while (position_ + 1 < tokens_.size() && tokens_[position_].text == "::" &&
               !tokens_[position_ + 1].text.empty() && ident_start(tokens_[position_ + 1].text.front()) &&
               std::all_of(tokens_[position_ + 1].text.begin(), tokens_[position_ + 1].text.end(), ident_continue)) {
            token += "::" + tokens_[position_ + 1].text;
            position_ += 2;
        }
        const auto lookup_name = global_qualified ? "::" + token : token;
        if (const auto binding = bindings_.find(lookup_name); binding != bindings_.end())
            return evaluate ? binding->second : 0;
        if (name_resolver_)
            if (const auto value = name_resolver_(lookup_name)) return evaluate ? *value : 0;
        fail(ErrorCode::unsupported, "unbound name in integer constant expression: '" + lookup_name + "'");
    }

    std::int64_t apply(std::string_view op, std::int64_t left, std::int64_t right) {
        constexpr auto minimum = std::numeric_limits<std::int64_t>::min();
        constexpr auto maximum = std::numeric_limits<std::int64_t>::max();
        if (op == "+") {
            if ((right > 0 && left > maximum - right) || (right < 0 && left < minimum - right))
                fail(ErrorCode::overflow, "integer constant expression addition overflows");
            return left + right;
        }
        if (op == "-") {
            if ((right < 0 && left > maximum + right) || (right > 0 && left < minimum + right))
                fail(ErrorCode::overflow, "integer constant expression subtraction overflows");
            return left - right;
        }
        if (op == "*") {
            if (left == 0 || right == 0) return 0;
            const bool negative = (left < 0) != (right < 0);
            const auto magnitude = [](std::int64_t value) {
                return value < 0 ? static_cast<std::uint64_t>(-(value + 1)) + 1
                                 : static_cast<std::uint64_t>(value);
            };
            const auto lhs = magnitude(left), rhs = magnitude(right);
            const auto limit = negative ? (std::uint64_t{1} << 63) : static_cast<std::uint64_t>(maximum);
            if (rhs > limit / lhs) fail(ErrorCode::overflow, "integer constant expression multiplication overflows");
            const auto product = lhs * rhs;
            if (!negative) return static_cast<std::int64_t>(product);
            if (product == (std::uint64_t{1} << 63)) return minimum;
            return -static_cast<std::int64_t>(product);
        }
        if (op == "/" || op == "%") {
            if (!right) fail(ErrorCode::malformed, "division by zero in integer constant expression");
            if (left == minimum && right == -1)
                fail(ErrorCode::overflow, "integer constant expression division overflows");
            return op == "/" ? left / right : left % right;
        }
        if (op == "&") return left & right;
        if (op == "^") return left ^ right;
        if (op == "|") return left | right;
        if (op == "<<" || op == ">>") {
            if (right < 0 || right >= 64) fail(ErrorCode::malformed, "invalid shift count in integer constant expression");
            if (op == ">>") return left >> right;
            if (left < 0 || (right && static_cast<std::uint64_t>(left) > (static_cast<std::uint64_t>(maximum) >> right)))
                fail(ErrorCode::overflow, "integer constant expression left shift overflows");
            return static_cast<std::int64_t>(static_cast<std::uint64_t>(left) << right);
        }
        if (op == "<") return left < right;
        if (op == ">") return left > right;
        if (op == "<=") return left <= right;
        if (op == ">=") return left >= right;
        if (op == "==") return left == right;
        if (op == "!=") return left != right;
        if (op == "&&") return left && right;
        if (op == "||") return left || right;
        fail(ErrorCode::unsupported, "unsupported operator in integer constant expression");
    }

    void enter(unsigned depth) const {
        if (depth > max_nesting_)
            fail(ErrorCode::resource_limit, "integer constant expression exceeds the nesting limit");
    }

    const std::vector<Token> &tokens_;
    std::map<std::string, std::int64_t, std::less<>> bindings_;
    NameResolver name_resolver_;
    std::map<std::string, std::int64_t, std::less<>> pack_sizes_;
    std::uint16_t max_nesting_;
    std::size_t position_ = 0;
    std::size_t operations_ = 0;
};

const Type *unqualified(const Type *type) {
    while (type && type->kind() == Kind::qualified)
        type = type->element().get();
    return type;
}

class Parser {
public:
    Parser(std::vector<Token> tokens, HeaderImportOptions options): t_(std::move(tokens)), o_(options) { install_scalars(); }
    Parser(std::vector<Token> tokens, HeaderImportOptions options, const Parser &context)
        : t_(std::move(tokens)), o_(options), pack_cap_(context.pack_cap_), pack_stack_(context.pack_stack_),
          namespace_stack_(context.namespace_stack_), aggregate_scopes_(context.aggregate_scopes_), namespace_aliases_(context.namespace_aliases_),
          anonymous_namespace_components_(context.anonymous_namespace_components_),
          next_anonymous_namespace_id_(context.next_anonymous_namespace_id_),
          next_anonymous_aggregate_id_(context.next_anonymous_aggregate_id_),
          inline_namespace_children_(context.inline_namespace_children_),
          inline_namespace_paths_(context.inline_namespace_paths_),
          using_namespaces_(context.using_namespaces_), namespaces_(context.namespaces_), names_(context.names_),
          template_aliases_(context.template_aliases_), aggregate_templates_(context.aggregate_templates_),
          template_instances_(context.template_instances_), active_template_aliases_(context.active_template_aliases_),
          template_type_bindings_(context.template_type_bindings_),
          template_value_bindings_(context.template_value_bindings_),
          template_template_bindings_(context.template_template_bindings_),
          template_pack_bindings_(context.template_pack_bindings_),
          template_depth_(static_cast<std::uint16_t>(context.template_depth_ + 1)) {
        install_scalars();
        for (const auto &[name, type] : context.names_) names_.insert_or_assign(name, type);
    }
    HeaderImportResult parse() {
        while(!at("<eof>")) parse_external();
        return std::move(result_);
    }
private:
    std::vector<Token> t_; HeaderImportOptions o_; std::size_t pos_=0; std::uint16_t depth_=0;
    struct PackEntry { std::uint64_t cap=0; std::string name; };
    std::uint64_t pack_cap_=0; std::vector<PackEntry> pack_stack_;
    std::optional<std::uint64_t> pending_aggregate_alignment_;
    std::optional<FunctionConvention> pending_function_convention_;
    std::optional<std::uint64_t> pending_vector_size_;
    bool prefix_packed_ = false;
    std::vector<std::string> namespace_stack_;
    std::vector<std::string> aggregate_scopes_;
    struct UsingNamespace { std::string scope; std::string target; };
    std::map<std::string, std::string, std::less<>> namespace_aliases_;
    // C++ declarations in the same unnamed namespace at the same lexical
    // namespace scope share one internal namespace. The synthetic component
    // cannot collide with source identifiers and never claims external linkage.
    std::map<std::string, std::string, std::less<>> anonymous_namespace_components_;
    std::uint32_t next_anonymous_namespace_id_ = 0;
    // Anonymous aggregate tags need stable internal identities so their layout
    // can still be represented by the shared named-reference type graph.
    std::uint32_t next_anonymous_aggregate_id_ = 0;
    std::map<std::string, std::vector<std::string>, std::less<>> inline_namespace_children_;
    std::set<std::string, std::less<>> inline_namespace_paths_;
    std::vector<UsingNamespace> using_namespaces_;
    std::set<std::string, std::less<>> namespaces_{""};
    HeaderImportResult result_; std::map<std::string,TypePtr,std::less<>> names_;
    std::map<std::string, std::int64_t, std::less<>> enum_value_bindings_;
    std::map<std::string, std::vector<std::pair<std::string, std::int64_t>>, std::less<>>
        enum_unqualified_bindings_;
    struct ScopedEnumeratorBinding { std::string scope, name; std::int64_t value = 0; };
    std::vector<ScopedEnumeratorBinding> enum_qualified_bindings_;
    std::map<std::string, TemplateAlias, std::less<>> template_aliases_;
    std::map<std::string, AggregateTemplate, std::less<>> aggregate_templates_;
    std::map<std::string, TypePtr, std::less<>> template_instances_;
    std::set<std::string, std::less<>> active_template_aliases_;
    std::map<std::string, TypePtr, std::less<>> template_type_bindings_;
    std::map<std::string, std::uint64_t, std::less<>> template_value_bindings_;
    std::map<std::string, std::string, std::less<>> template_template_bindings_;
    std::map<std::string, std::vector<TemplateArgument>, std::less<>> template_pack_bindings_;
    std::string template_instance_name_;
    std::string template_instance_base_name_;
    std::uint16_t template_depth_ = 0;
    HeaderTemplateParameter export_template_parameter(const TemplateParameter &parameter) const {
        HeaderTemplateParameter result;
        result.name = parameter.name;
        result.kind = parameter.template_parameter ? HeaderTemplateParameterKind::template_template
                     : parameter.value_parameter ? HeaderTemplateParameterKind::non_type
                                                 : HeaderTemplateParameterKind::type;
        result.pack = parameter.pack;
        result.value_type = parameter.value_type;
        if (!parameter.default_value_expression.empty()) {
            for (const auto &token : parameter.default_value_expression) {
                if (!result.default_argument.empty() && identifier(token.text)) {
                    const auto previous = static_cast<unsigned char>(result.default_argument.back());
                    if ((previous >= 'a' && previous <= 'z') || (previous >= 'A' && previous <= 'Z') ||
                        (previous >= '0' && previous <= '9') || previous == '_')
                        result.default_argument += ' ';
                }
                result.default_argument += token.text;
            }
        }
        else if (!parameter.default_template.empty()) result.default_argument = parameter.default_template;
        else for (const auto &token : parameter.default_type) {
            if (!result.default_argument.empty() && identifier(token.text)) {
                const auto previous = static_cast<unsigned char>(result.default_argument.back());
                if ((previous >= 'a' && previous <= 'z') || (previous >= 'A' && previous <= 'Z') ||
                    (previous >= '0' && previous <= '9') || previous == '_')
                    result.default_argument += ' ';
            }
            result.default_argument += token.text;
        }
        result.nested_parameters.reserve(parameter.nested_parameters.size());
        for (const auto &nested : parameter.nested_parameters)
            result.nested_parameters.push_back(export_template_parameter(nested));
        return result;
    }
    bool same_template_parameter_shape(const TemplateParameter &left, const TemplateParameter &right) const {
        if (left.value_parameter != right.value_parameter || left.template_parameter != right.template_parameter ||
            left.pack != right.pack || left.nested_parameters.size() != right.nested_parameters.size())
            return false;
        if (left.value_parameter && (!left.value_type || !right.value_type || format(*left.value_type) != format(*right.value_type)))
            return false;
        for (std::size_t i = 0; i < left.nested_parameters.size(); ++i)
            if (!same_template_parameter_shape(left.nested_parameters[i], right.nested_parameters[i])) return false;
        return true;
    }
    const Token &peek(std::size_t n=0) const { return t_[std::min(pos_+n,t_.size()-1)]; }
    bool at(std::string_view s)const{return peek().text==s;}
    bool take(std::string_view s){if(at(s)){++pos_;return true;}return false;}
    Token next(){if(at("<eof>"))fail(ErrorCode::malformed,"unexpected end of header");return t_[pos_++];}
    void need(std::string_view s){if(!take(s)) syntax("expected '"+std::string(s)+"'");}
    [[noreturn]] void syntax(const std::string &m)const{fail(ErrorCode::malformed,m+" at line "+std::to_string(peek().line));}
    void consume_standard_attributes() {
        while (at("[") && peek(1).text == "[") {
            ++pos_; ++pos_;
            bool any=false;
            while (!(at("]") && peek(1).text == "]")) {
                if (at("<eof>")) syntax("unterminated standard attribute specifier");
                if (!any) {
                    const auto name=next().text;
                    if (name!="maybe_unused" && name!="nodiscard" && name!="deprecated")
                        fail(ErrorCode::unsupported,"unsupported standard attribute '"+name+"'");
                    if ((name=="deprecated" || name=="nodiscard") && take("(")) {
                        if (peek().text.empty() || peek().text.front()!='\"')
                            syntax("deprecated attribute message must be a string literal");
                        ++pos_; need(")");
                    }
                    any=true;
                } else if (take(",")) {
                    // Multiple attributes are checked by the next iteration.
                    any=false;
                } else syntax("unsupported standard attribute arguments");
            }
            if (!any) syntax("empty or trailing-comma standard attribute list");
            need("]"); need("]");
        }
    }
    void skip_parameter_default() {
        need("=");
        std::size_t parens=0, brackets=0, braces=0;
        bool consumed=false;
        while (!at("<eof>")) {
            if (!parens && !brackets && !braces && (at(",") || at(")"))) break;
            if (at("(") ) ++parens;
            else if (at(")")) { if (!parens) break; --parens; }
            else if (at("[")) ++brackets;
            else if (at("]")) { if (!brackets) syntax("unmatched ']' in parameter default"); --brackets; }
            else if (at("{")) ++braces;
            else if (at("}")) { if (!braces) syntax("unmatched '}' in parameter default"); --braces; }
            consumed=true;
            ++pos_;
        }
        if (!consumed) syntax("expected a parameter default value");
        if (parens || brackets || braces) syntax("unclosed delimiter in parameter default");
    }
    void enter(){if(++depth_>o_.max_nesting)fail(ErrorCode::resource_limit,"header nesting exceeds configured limit");}
    void leave(){--depth_;}
    bool identifier(std::string_view s)const{return !s.empty()&&ident_start(s.front());}
    std::string current_namespace() const {
        std::string name;
        for(const auto &part:namespace_stack_){if(!name.empty())name+="::";name+=part;}
        return name;
    }
    std::string qualify_name(std::string name) const {
        if(name.starts_with("::"))return name.substr(2);
        const auto scope=current_namespace();
        return scope.empty()?name:scope+"::"+name;
    }
    std::string parse_qualified_name() {
        const bool global=take("::");
        if(!identifier(peek().text))syntax("expected an identifier in qualified name");
        std::string name=next().text;
        while(take("::")){if(!identifier(peek().text))syntax("expected an identifier after '::'");name+="::"+next().text;}
        return expand_namespace_aliases(global?std::move(name):qualify_name(std::move(name)));
    }
    std::string parse_lookup_name() {
        const bool global=take("::");
        if(!identifier(peek().text))syntax("expected an identifier in qualified name");
        std::string name=next().text;
        while(take("::")){if(!identifier(peek().text))syntax("expected an identifier after '::'");name+="::"+next().text;}
        return global?"::"+name:name;
    }
    static bool path_prefix(std::string_view path, std::string_view prefix) {
        return path == prefix || (path.size() > prefix.size() && path.starts_with(prefix) &&
                                  path.substr(prefix.size(), 2) == "::");
    }
    std::string expand_namespace_aliases(std::string path) const {
        for (std::size_t hop = 0; hop < 64; ++hop) {
            const std::pair<const std::string, std::string> *best = nullptr;
            for (const auto &entry : namespace_aliases_)
                if (path_prefix(path, entry.first) && (!best || entry.first.size() > best->first.size()))
                    best = &entry;
            if (!best) return path;
            path.replace(0, best->first.size(), best->second);
        }
        fail(ErrorCode::conflict, "namespace alias expansion exceeded its bounded depth");
    }
    std::string resolve_namespace_name(std::string spelling) const {
        const bool global = spelling.starts_with("::");
        if (global) spelling.erase(0, 2);
        auto check = [&](std::string candidate) -> std::optional<std::string> {
            candidate = expand_namespace_aliases(std::move(candidate));
            if (namespaces_.contains(candidate)) return candidate;
            return {};
        };
        if (global) {
            if (auto found = check(spelling)) return *found;
        } else {
            for (std::size_t depth = namespace_stack_.size() + 1; depth-- > 0;) {
                std::string candidate;
                for (std::size_t i = 0; i < depth; ++i) {
                    if (!candidate.empty()) candidate += "::";
                    candidate += namespace_stack_[i];
                }
                if (!candidate.empty()) candidate += "::";
                candidate += spelling;
                if (auto found = check(std::move(candidate))) return *found;
            }
        }
        fail(ErrorCode::malformed, "unknown namespace '" + spelling + "'");
    }
    std::vector<std::string> inline_namespace_candidates(std::string path) const {
        path=expand_namespace_aliases(std::move(path));
        std::vector<std::string> candidates{path};
        std::set<std::string,std::less<>> seen{path};
        for(std::size_t index=0;index<candidates.size();++index){
            if(candidates.size()>o_.max_tokens)
                fail(ErrorCode::resource_limit,"inline-namespace lookup exceeded its configured token bound");
            const auto current=candidates[index];
            if(const auto global_children=inline_namespace_children_.find("");global_children!=inline_namespace_children_.end())
                for(const auto &child:global_children->second){
                    if(current==child||current.starts_with(child+"::"))continue;
                    auto expanded=child+"::"+current;
                    if(seen.insert(expanded).second){
                        if(candidates.size()>=o_.max_tokens)
                            fail(ErrorCode::resource_limit,"inline-namespace lookup exceeded its configured token bound");
                        candidates.push_back(std::move(expanded));
                    }
                }
            for(std::size_t separator=current.find("::");separator!=std::string::npos;
                separator=current.find("::",separator+2)){
                const auto parent=current.substr(0,separator);
                const auto children=inline_namespace_children_.find(parent);
                if(children==inline_namespace_children_.end())continue;
                const auto suffix=current.substr(separator);
                for(const auto &child:children->second){
                    const auto child_name=child.substr(parent.size()+2);
                    if(suffix.starts_with("::"+child_name))continue;
                    auto expanded=child+suffix;
                    if(seen.insert(expanded).second){
                        if(candidates.size()>=o_.max_tokens)
                            fail(ErrorCode::resource_limit,"inline-namespace lookup exceeded its configured token bound");
                        candidates.push_back(std::move(expanded));
                    }
                }
            }
        }
        return candidates;
    }
    TypePtr lookup_qualified_type(std::string path) const {
        std::vector<TypePtr> matches;
        auto candidates=inline_namespace_candidates(std::move(path));
        std::set<std::string,std::less<>> seen(candidates.begin(),candidates.end());
        for(std::size_t index=0;index<candidates.size();++index){
            const auto candidate=candidates[index];
            if(auto found=names_.find(candidate);found!=names_.end()&&
               std::none_of(matches.begin(),matches.end(),[&](const TypePtr &type){return type->id()==found->second->id();}))
                matches.push_back(found->second);
            // A class typedef or a bound template type may qualify a member
            // alias. Resolve its actual aggregate identity without creating a
            // namespace alias or changing ordinary C tag-name lookup.
            for(auto separator=candidate.rfind("::");separator!=std::string::npos;
                separator=separator?candidate.rfind("::",separator-1):std::string::npos){
                const auto prefix=candidate.substr(0,separator);
                TypePtr owner;
                if(auto found=template_type_bindings_.find(prefix);found!=template_type_bindings_.end())owner=found->second;
                if(!owner)if(auto found=names_.find(prefix);found!=names_.end())owner=found->second;
                if(!owner)for(const auto keyword:{"struct ","union "})
                    if(auto found=names_.find(std::string(keyword)+prefix);found!=names_.end()){owner=found->second;break;}
                const auto *aggregate=unqualified(owner.get());
                if(aggregate&&aggregate->kind()==Kind::named_reference){
                    auto found=names_.find(aggregate->name());
                    aggregate=found==names_.end()?nullptr:unqualified(found->second.get());
                }
                if(!aggregate||(aggregate->kind()!=Kind::structure&&aggregate->kind()!=Kind::union_type))continue;
                auto expanded=aggregate->name()+candidate.substr(separator);
                if(seen.insert(expanded).second){
                    if(candidates.size()>=o_.max_tokens)fail(ErrorCode::resource_limit,"class-member type lookup exceeded its token bound");
                    candidates.push_back(std::move(expanded));
                }
            }
        }
        if(matches.size()>1)fail(ErrorCode::conflict,"ambiguous qualified type name through namespace or class aliases");
        return matches.empty()?TypePtr{}:matches.front();
    }
    std::string lookup_qualified_template(std::string path) const {
        std::vector<std::string> matches;
        for(const auto &candidate:inline_namespace_candidates(std::move(path)))
            if((template_aliases_.contains(candidate)||aggregate_templates_.contains(candidate))&&
               std::find(matches.begin(),matches.end(),candidate)==matches.end())
                matches.push_back(candidate);
        if(matches.size()>1)
            fail(ErrorCode::conflict,"ambiguous template name through inline namespace lookup");
        return matches.empty()?std::string{}:matches.front();
    }
    static std::string injected_aggregate_name(std::string_view name){
        std::size_t begin=0,depth=0;
        for(std::size_t i=0;i<name.size();++i){
            if(name[i]=='<')++depth;else if(name[i]=='>'&&depth)--depth;
            else if(!depth&&name[i]==':'&&i+1<name.size()&&name[i+1]==':'){begin=i+2;++i;}
        }
        auto result=std::string(name.substr(begin));
        if(const auto arguments=result.find('<');arguments!=std::string::npos)result.resize(arguments);
        return result;
    }
    TypePtr lookup_type(std::string name) const {
        if(!name.starts_with("::"))for(auto scope=aggregate_scopes_.rbegin();scope!=aggregate_scopes_.rend();++scope){
            if(auto found=lookup_qualified_type(*scope+"::"+name))return found;
            const auto injected=injected_aggregate_name(*scope);
            if(name==injected)for(const auto keyword:{"struct ","union "})
                if(auto found=names_.find(std::string(keyword)+*scope);found!=names_.end())return found->second;
        }
        if(name.starts_with("::"))return lookup_qualified_type(name.substr(2));
        if(name.find("::")!=std::string::npos){
            for(std::size_t depth=namespace_stack_.size();depth>0;--depth){
                std::string candidate;
                for(std::size_t i=0;i<depth;++i){if(!candidate.empty())candidate+="::";candidate+=namespace_stack_[i];}
                candidate+="::"+name;
                if(auto found=lookup_qualified_type(std::move(candidate)))return found;
            }
            return lookup_qualified_type(std::move(name));
        }
        for(std::size_t depth=namespace_stack_.size();depth>0;--depth){
            std::string candidate;
            for(std::size_t i=0;i<depth;++i){if(!candidate.empty())candidate+="::";candidate+=namespace_stack_[i];}
            candidate+="::"+name;
            if(auto found=lookup_qualified_type(std::move(candidate)))return found;
        }
        if(auto found=lookup_qualified_type(name))return found;
        for(std::size_t depth=namespace_stack_.size()+1;depth-- > 0;){
            std::string scope;
            for(std::size_t i=0;i<depth;++i){if(!scope.empty())scope+="::";scope+=namespace_stack_[i];}
            std::vector<std::string> pending;
            for(const auto &directive:using_namespaces_)
                if(directive.scope==scope)pending.push_back(directive.target);
            std::set<std::string,std::less<>> visited;
            std::vector<TypePtr> matches;
            for(std::size_t index=0;index<pending.size();++index){
                auto imported=std::move(pending[index]);
                if(!visited.insert(imported).second)continue;
                const auto key=imported.empty()?name:imported+"::"+name;
                if(auto found=lookup_qualified_type(key))matches.push_back(std::move(found));
                for(const auto &directive:using_namespaces_)
                    if(directive.scope==imported)pending.push_back(directive.target);
                if(pending.size()>o_.max_tokens)
                    fail(ErrorCode::resource_limit,"using-namespace lookup exceeded its configured token bound");
            }
            if(!matches.empty()){
                const auto identity=matches.front()->id();
                if(std::any_of(matches.begin()+1,matches.end(),[identity](const TypePtr &type){return type->id()!=identity;}))
                    fail(ErrorCode::conflict,"ambiguous type name '"+name+"' from using-namespace directives");
                return matches.front();
            }
        }
        return {};
    }
    std::string resolve_template_name(std::string name) const {
        const bool global = name.starts_with("::");
        if (global) name.erase(0, 2);
        if (global) {
            return lookup_qualified_template(std::move(name));
        } else {
            for (std::size_t depth = namespace_stack_.size() + 1; depth-- > 0;) {
                std::string candidate;
                for (std::size_t i = 0; i < depth; ++i) {
                    if (!candidate.empty()) candidate += "::";
                    candidate += namespace_stack_[i];
                }
                if (!candidate.empty()) candidate += "::";
                candidate += name;
                if(auto found=lookup_qualified_template(std::move(candidate));!found.empty())return found;
            }
        }
        if (!global && name.find("::") == std::string::npos) {
            for (std::size_t depth = namespace_stack_.size() + 1; depth-- > 0;) {
                std::string scope;
                for (std::size_t i = 0; i < depth; ++i) {
                    if (!scope.empty()) scope += "::";
                    scope += namespace_stack_[i];
                }
                std::vector<std::string> pending;
                for (const auto &directive : using_namespaces_)
                    if (directive.scope == scope) pending.push_back(directive.target);
                std::set<std::string, std::less<>> visited;
                std::set<std::string, std::less<>> matches;
                for (std::size_t index = 0; index < pending.size(); ++index) {
                    auto imported = std::move(pending[index]);
                    if (!visited.insert(imported).second) continue;
                    const auto candidate = imported.empty() ? name : imported + "::" + name;
                    if (auto found = lookup_qualified_template(candidate); !found.empty())
                        matches.insert(std::move(found));
                    for (const auto &directive : using_namespaces_)
                        if (directive.scope == imported) pending.push_back(directive.target);
                    if (pending.size() > o_.max_tokens)
                        fail(ErrorCode::resource_limit, "using-namespace template lookup exceeded its configured token bound");
                }
                if (matches.size() > 1)
                    fail(ErrorCode::conflict, "ambiguous template name '" + name + "' from using-namespace directives");
                if (!matches.empty()) return *matches.begin();
            }
        }
        return {};
    }
    std::vector<Token> take_until_semicolon() {
        std::vector<Token> out;
        while (!at(";") && !at("<eof>")) out.push_back(next());
        need(";");
        if (out.empty()) syntax("expected a template type expression");
        return out;
    }
    std::vector<Token> take_aggregate_definition() {
        std::vector<Token> out;
        std::size_t braces = 0;
        bool saw_body = false;
        while (!at("<eof>")) {
            if (at(";") && !saw_body) {
                out.push_back(next());
                fail(ErrorCode::unsupported, "template aggregate forward declarations are unsupported");
            }
            auto token = next();
            if (token.text == "{") {
                ++braces;
                saw_body = true;
            } else if (token.text == "}") {
                if (!braces) syntax("unmatched closing brace in template aggregate");
                --braces;
            }
            out.push_back(std::move(token));
            if (saw_body && braces == 0) {
                if (!take(";")) syntax("expected ';' after template aggregate");
                out.push_back({";", peek().line});
                return out;
            }
        }
        syntax("unterminated template aggregate");
    }
    std::vector<Token> tokens_with_eof(std::vector<Token> tokens) const {
        const auto line = tokens.empty() ? peek().line : tokens.back().line;
        tokens.push_back({"<eof>", line});
        return tokens;
    }
    TypePtr parse_type_tokens(const std::vector<Token> &tokens,
                              const std::map<std::string, TypePtr, std::less<>> &bindings,
                              const std::map<std::string, std::uint64_t, std::less<>> &value_bindings = {},
                              const std::map<std::string, std::string, std::less<>> &template_bindings = {},
                              const std::map<std::string, std::vector<TemplateArgument>, std::less<>> &pack_bindings = {}) {
        if (template_depth_ >= o_.max_nesting)
            fail(ErrorCode::resource_limit, "template type expansion exceeds configured nesting limit");
        Parser nested(tokens_with_eof(tokens), o_, *this);
        nested.template_type_bindings_ = template_type_bindings_;
        for (const auto &[name, type] : bindings) nested.template_type_bindings_.insert_or_assign(name, type);
        nested.template_value_bindings_ = template_value_bindings_;
        for (const auto &[name, value] : value_bindings) nested.template_value_bindings_.insert_or_assign(name, value);
        for (const auto &[name, value] : template_bindings) nested.template_template_bindings_.insert_or_assign(name, value);
        for (const auto &[name, value] : pack_bindings) nested.template_pack_bindings_.insert_or_assign(name, value);
        auto base = nested.parse_base();
        if (base.is_typedef || base.is_static) syntax("storage specifiers are invalid in a template type argument");
        auto declaration = nested.parse_declarator(base.type, true);
        if (!declaration.name.empty()) syntax("template argument must be an abstract type");
        declaration.type = nested.apply_pending_function_convention(std::move(declaration.type));
        if (!nested.at("<eof>")) nested.syntax("unexpected token after template type");
        return declaration.type;
    }
    std::optional<std::vector<Token>> take_compound_pack_pattern() {
        std::size_t angle=0,paren=0,bracket=0,cursor=pos_;
        for(;cursor<t_.size()&&t_[cursor].text!="<eof>";++cursor){
            const auto &token=t_[cursor].text;
            if(!angle&&!paren&&!bracket&&(token==","||token==">"))break;
            if(token=="(")++paren;
            else if(token==")"){if(!paren)syntax("unmatched ')' in template argument");--paren;}
            else if(token=="[")++bracket;
            else if(token=="]"){if(!bracket)syntax("unmatched ']' in template argument");--bracket;}
            // Within parentheses/brackets, relational and shift operators do
            // not delimit an enclosing template argument list.
            else if(!paren&&!bracket&&token=="<")++angle;
            else if(!paren&&!bracket&&token==">"){if(!angle)break;--angle;}
            if(angle+paren+bracket>o_.max_nesting)
                fail(ErrorCode::resource_limit,"template expansion pattern exceeds configured nesting limit");
        }
        if(cursor==pos_||t_[cursor-1].text!="...")return {};
        if(angle||paren||bracket)syntax("unclosed delimiter in template expansion pattern");
        std::vector<Token> pattern(t_.begin()+static_cast<std::ptrdiff_t>(pos_),
                                   t_.begin()+static_cast<std::ptrdiff_t>(cursor-1));
        if(pattern.empty())syntax("template pack expansion requires a pattern");
        if(std::any_of(pattern.begin(),pattern.end(),[](const auto &token){return token.text=="...";}))
            fail(ErrorCode::unsupported,"nested ellipses inside a compound template pack expansion are unsupported");
        pos_=cursor;
        return pattern;
    }
    TemplateArgument expand_template_pack_argument(const std::vector<Token> &pattern,const std::string &pack_name,
                                                   const TemplateArgument &element,const TemplateParameter &parameter) {
        if(template_depth_>=o_.max_nesting)
            fail(ErrorCode::resource_limit,"compound template pack expansion exceeds configured nesting limit");
        Parser expanded(tokens_with_eof(pattern),o_,*this);
        // A pack occurrence in the pattern becomes one ordinary argument for
        // this substitution. Keep other packs bound for normal nested lookup.
        expanded.template_pack_bindings_.erase(pack_name);
        if(element.type)expanded.template_type_bindings_.insert_or_assign(pack_name,element.type);
        else if(element.value)expanded.template_value_bindings_.insert_or_assign(pack_name,*element.value);
        else if(!element.template_name.empty())
            expanded.template_template_bindings_.insert_or_assign(pack_name,element.template_name);
        else fail(ErrorCode::malformed,"parameter pack contains an argument without a kind");
        if(parameter.template_parameter){
            auto name=expanded.parse_lookup_name();
            if(!expanded.at("<eof>"))
                fail(ErrorCode::unsupported,"template-name expansion must produce one supported template name");
            const auto bound=expanded.template_template_bindings_.find(name);
            auto resolved=bound!=expanded.template_template_bindings_.end()?bound->second:expanded.resolve_template_name(name);
            if(resolved.empty())fail(ErrorCode::unsupported,"expanded argument does not name a supported template");
            return {{},{},std::move(resolved)};
        }
        if(parameter.value_parameter){
            const auto value=expanded.evaluate_integer_expression(pattern,expanded.template_value_bindings_);
            if(value<0)fail(ErrorCode::unsupported,"negative expanded non-type template arguments are unsupported");
            return {{},static_cast<std::uint64_t>(value),{}};
        }
        auto base=expanded.parse_base();
        if(base.is_typedef||base.is_static||base.is_inline)
            fail(ErrorCode::malformed,"storage specifiers are invalid in an expanded template argument");
        auto declaration=expanded.parse_declarator(base.type,true);
        if(!declaration.name.empty())expanded.syntax("expanded template arguments must be abstract types");
        declaration.type=expanded.apply_pending_function_convention(std::move(declaration.type));
        if(!expanded.at("<eof>"))expanded.syntax("unexpected token after expanded template argument");
        return {std::move(declaration.type),{},{}};
    }
    std::vector<TemplateArgument> parse_template_arguments(const std::vector<TemplateParameter> &parameters) {
        need("<");
        if (take(">")) return {};
        std::vector<TemplateArgument> arguments;
        std::size_t parameter_index = 0;
        auto append = [&](TemplateArgument argument) {
            if (arguments.size() >= 32)
                fail(ErrorCode::resource_limit, "expanded template argument count exceeds 32");
            if (parameter_index >= parameters.size()) fail(ErrorCode::malformed, "too many template arguments");
            arguments.push_back(std::move(argument));
            if (!parameters[parameter_index].pack) ++parameter_index;
        };
        for (;;) {
            // Direct forwarding of an entire Pack... argument keeps the pack's
            // concrete arguments retain their kinds, then the destination
            // template validates every expanded argument against its parameters.
            if (identifier(peek().text) && peek(1).text == "...") {
                const auto name = next().text;
                need("...");
                auto pack = template_pack_bindings_.find(name);
                if (pack == template_pack_bindings_.end())
                    fail(ErrorCode::unsupported, "template argument expansion requires a bound parameter pack '" + name + "'");
                for (const auto &argument : pack->second) append(argument);
                if (take(">")) break;
                need(",");
                continue;
            }
            if(auto pattern=take_compound_pack_pattern()){
                std::string pack_name;
                for(std::size_t index=0;index<pattern->size();++index){
                    const auto &name=(*pattern)[index].text;
                    // api::Types is a qualified member name, not the local
                    // parameter pack Types. Types::member still expands Types.
                    if((index&&(*pattern)[index-1].text=="::")||!template_pack_bindings_.contains(name))continue;
                    if(!pack_name.empty()&&pack_name!=name)
                        fail(ErrorCode::unsupported,"compound template expansion patterns support one distinct bound pack");
                    pack_name=name;
                }
                if(pack_name.empty())
                    fail(ErrorCode::unsupported,"compound template expansion requires a bound parameter pack in its pattern");
                // Nested parser instantiations operate on copies, so the
                // source pack remains stable through every element expansion.
                const auto &pack=template_pack_bindings_.at(pack_name);
                for(const auto &element:pack){
                    if(parameter_index>=parameters.size())fail(ErrorCode::malformed,"too many expanded template arguments");
                    if(arguments.size()>=32)fail(ErrorCode::resource_limit,"expanded template argument count exceeds 32");
                    append(expand_template_pack_argument(*pattern,pack_name,element,parameters[parameter_index]));
                }
                if(take(">"))break;
                need(",");
                continue;
            }
            const TemplateParameter *parameter = parameter_index < parameters.size()
                ? &parameters[parameter_index] : nullptr;
            if (!parameter) fail(ErrorCode::malformed, "too many template arguments");
            if (parameter->template_parameter) {
                auto template_path = parse_lookup_name();
                const auto bound = template_template_bindings_.find(template_path);
                auto template_name = bound != template_template_bindings_.end()
                    ? bound->second : resolve_template_name(std::move(template_path));
                if (template_name.empty()) fail(ErrorCode::unsupported, "template argument does not name a supported class or alias template");
                append({{}, {}, std::move(template_name)});
            } else if (parameter->value_parameter) {
                const auto expression = take_integer_expression_until_template_delimiter();
                const auto evaluated = evaluate_integer_expression(expression, template_value_bindings_);
                if (evaluated < 0)
                    fail(ErrorCode::unsupported, "negative non-type template arguments are unsupported");
                append({{}, static_cast<std::uint64_t>(evaluated), {}});
            } else {
                auto base = parse_base();
                if (base.is_typedef || base.is_static) syntax("storage specifiers are invalid in template arguments");
                auto declaration = parse_declarator(base.type, true);
                if (!declaration.name.empty()) syntax("template arguments must be types");
                declaration.type = apply_pending_function_convention(std::move(declaration.type));
                append({std::move(declaration.type), {}, {}});
            }
            if (at("...")) fail(ErrorCode::unsupported, "unsupported template pack expansion pattern");
            if (take(">")) break;
            need(",");
        }
        return arguments;
    }
    void validate_template_template_argument(const TemplateParameter &parameter, const std::string &name) const {
        const std::vector<TemplateParameter> *actual_parameters = nullptr;
        if (auto actual = aggregate_templates_.find(name); actual != aggregate_templates_.end())
            actual_parameters = &actual->second.parameters;
        else if (auto alias = template_aliases_.find(name); alias != template_aliases_.end())
            actual_parameters = &alias->second.parameters;
        if (!actual_parameters || actual_parameters->size() != parameter.nested_parameters.size())
            fail(ErrorCode::malformed, "template argument arity does not match template-template parameter '" + parameter.name + "'");
        for (std::size_t nested = 0; nested < actual_parameters->size(); ++nested)
            if (!same_template_parameter_shape(parameter.nested_parameters[nested], (*actual_parameters)[nested]))
                fail(ErrorCode::malformed, "template argument parameter kinds do not match template-template parameter '" + parameter.name + "'");
    }
    TemplateBindings bind_template_parameters(const std::vector<TemplateParameter> &parameters,
                                               const std::vector<TemplateArgument> &arguments) {
        TemplateBindings bindings;
        std::size_t argument_index = 0;
        for (std::size_t i = 0; i < parameters.size(); ++i) {
            const auto &parameter = parameters[i];
            if (parameter.pack) {
                auto &pack = bindings.packs[parameter.name];
                while (argument_index < arguments.size()) {
                    const auto &argument = arguments[argument_index++];
                    if (parameter.value_parameter != argument.value.has_value() ||
                        parameter.template_parameter != !argument.template_name.empty() ||
                        (!parameter.value_parameter && !parameter.template_parameter && !argument.type))
                        fail(ErrorCode::malformed, "template argument kind does not match parameter pack '" + parameter.name + "'");
                    if (parameter.value_parameter) {
                        const auto *integer = unqualified(parameter.value_type.get());
                        if (!integer || integer->kind() != Kind::integer || !integer->size() || *integer->size() > 8)
                            fail(ErrorCode::unsupported, "template non-type parameter pack must use an integer type no wider than 64 bits");
                        const auto bits = static_cast<unsigned>(*integer->size() * 8);
                        const auto maximum = integer->is_signed() && bits < 64
                            ? (std::uint64_t{1} << (bits - 1)) - 1
                            : bits == 64 ? static_cast<std::uint64_t>(INT64_MAX) : (std::uint64_t{1} << bits) - 1;
                        if (*argument.value > maximum)
                            fail(ErrorCode::malformed, "template integer argument is outside its parameter type");
                    }
                    if (parameter.template_parameter)
                        validate_template_template_argument(parameter, argument.template_name);
                    pack.push_back(argument);
                }
                continue;
            }
            const bool has_argument = argument_index < arguments.size();
            const TemplateArgument *argument = has_argument ? &arguments[argument_index++] : nullptr;
            if (parameter.value_parameter) {
                std::optional<std::uint64_t> value = argument ? argument->value : std::nullopt;
                if (!argument && !parameter.default_value_expression.empty()) {
                    const auto evaluated = evaluate_integer_expression(parameter.default_value_expression, bindings.values);
                    if (evaluated < 0)
                        fail(ErrorCode::unsupported, "negative non-type template defaults are unsupported");
                    value = static_cast<std::uint64_t>(evaluated);
                }
                if (!value) fail(ErrorCode::malformed, "template requires an integer argument for '" + parameter.name + "'");
                if (argument && (argument->type || !argument->template_name.empty()))
                    fail(ErrorCode::malformed, "template argument '" + parameter.name + "' must be an integer");
                const auto *integer = unqualified(parameter.value_type.get());
                if (!integer || integer->kind() != Kind::integer || !integer->size() || *integer->size() > 8)
                    fail(ErrorCode::unsupported, "template non-type parameter must use an integer type no wider than 64 bits");
                const auto bits = static_cast<unsigned>(*integer->size() * 8);
                const auto maximum = integer->is_signed() && bits < 64
                    ? (std::uint64_t{1} << (bits - 1)) - 1
                    : bits == 64 ? static_cast<std::uint64_t>(INT64_MAX) : (std::uint64_t{1} << bits) - 1;
                if (*value > maximum)
                    fail(ErrorCode::malformed, "template integer argument is outside its parameter type");
                bindings.values.emplace(parameter.name, *value);
            } else if (parameter.template_parameter) {
                std::string template_name = argument ? argument->template_name : parameter.default_template;
                if (template_name.empty() || (argument && (argument->type || argument->value)))
                    fail(ErrorCode::malformed, "template requires a template argument for '" + parameter.name + "'");
                validate_template_template_argument(parameter, template_name);
                bindings.templates.emplace(parameter.name, std::move(template_name));
            } else {
                TypePtr type;
                if (argument) type = argument->type;
                else if (!parameter.default_type.empty())
                    type = parse_type_tokens(parameter.default_type, bindings.types, bindings.values, bindings.templates, bindings.packs);
                else fail(ErrorCode::malformed, "too few type arguments for template");
                if (!type || (argument && (argument->value || !argument->template_name.empty())))
                    fail(ErrorCode::malformed, "template argument '" + parameter.name + "' must be a type");
                bindings.types.emplace(parameter.name, std::move(type));
            }
        }
        if (argument_index != arguments.size()) fail(ErrorCode::malformed, "too many template arguments");
        return bindings;
    }
    std::string template_instance_key(std::string_view name, const std::vector<TemplateParameter> &parameters,
                                     const TemplateBindings &bindings) const {
        std::string key(name);
        key += '<';
        bool first = true;
        auto append = [&](std::string value) {
            if (!first) key += ',';
            first = false;
            key += std::move(value);
        };
        for (const auto &parameter : parameters) {
            if (parameter.pack) {
                auto found = bindings.packs.find(parameter.name);
                if (found == bindings.packs.end()) continue;
                for (const auto &argument : found->second) {
                    if (argument.type) append(format(*argument.type));
                    else if (argument.value) append('#' + std::to_string(*argument.value));
                    else append(argument.template_name);
                }
            } else if (parameter.value_parameter) {
                append('#' + std::to_string(bindings.values.at(parameter.name)));
            } else if (parameter.template_parameter) {
                append(bindings.templates.at(parameter.name));
            } else {
                append(format(*bindings.types.at(parameter.name)));
            }
        }
        key += '>';
        return key;
    }
    TypePtr instantiate_template_alias(const std::string &name, const std::vector<TemplateArgument> &arguments) {
        const auto definition = template_aliases_.find(name);
        if (definition == template_aliases_.end()) return {};
        const auto &parameters = definition->second.parameters;
        const auto bindings = bind_template_parameters(parameters, arguments);
        const auto key = template_instance_key(name, parameters, bindings);
        if (!active_template_aliases_.insert(key).second)
            fail(ErrorCode::conflict, "recursive type alias template instantiation '" + key + "'");
        auto type = parse_type_tokens(definition->second.target, bindings.types, bindings.values,
                                      bindings.templates, bindings.packs);
        active_template_aliases_.erase(key);
        return type;
    }
    std::vector<TemplateParameter> parse_template_parameters(bool allow_unnamed = false) {
        enter();
        need("<");
        std::vector<TemplateParameter> parameters;
        if (take(">")) { leave(); return parameters; }
        bool saw_default = false;
        for (;;) {
            TemplateParameter parameter;
            if (take("template")) {
                parameter.template_parameter = true;
                parameter.nested_parameters = parse_template_parameters(true);
                if (!(take("class") || take("typename")))
                    fail(ErrorCode::unsupported, "template-template parameters must be declared with class or typename");
                parameter.pack = take("...");
                if (identifier(peek().text)) parameter.name = next().text;
                else if (allow_unnamed) parameter.name = "$template" + std::to_string(parameters.size());
                else syntax("expected a template-template parameter name");
                parameter.pack = take("...") || parameter.pack;
            } else if (take("typename") || take("class")) {
                parameter.pack = take("...");
                if (identifier(peek().text)) parameter.name = next().text;
                else if (allow_unnamed) parameter.name = "$type" + std::to_string(parameters.size());
                else syntax("expected a template type parameter name");
                parameter.pack = take("...") || parameter.pack;
            } else {
                auto base = parse_base();
                if (base.is_typedef || base.is_static) syntax("storage specifiers are invalid in a template parameter");
                const bool pack_before_name = take("...");
                auto declaration = parse_declarator(base.type, allow_unnamed);
                if (declaration.function || !declaration.type || !unqualified(declaration.type.get()) ||
                    unqualified(declaration.type.get())->kind() != Kind::integer)
                    fail(ErrorCode::unsupported, "only integral non-type template parameters are supported");
                parameter.pack = take("...") || pack_before_name;
                parameter.value_parameter = true;
                parameter.value_type = std::move(declaration.type);
                parameter.name = std::move(declaration.name);
                if (parameter.name.empty() && allow_unnamed)
                    parameter.name = "$value" + std::to_string(parameters.size());
            }
            if (!parameters.empty() && parameters.back().pack)
                fail(ErrorCode::malformed, "a template parameter pack must be last");
            if (std::any_of(parameters.begin(), parameters.end(), [&](const auto &item) { return item.name == parameter.name; }))
                fail(ErrorCode::conflict, "duplicate template parameter '" + parameter.name + "'");
            if (take("=")) {
                if (parameter.pack) fail(ErrorCode::malformed, "a template parameter pack cannot have a default");
                saw_default = true;
                if (parameter.value_parameter) {
                    parameter.default_value_expression = take_integer_expression_until_template_delimiter();
                } else {
                std::size_t angle = 0, paren = 0, bracket = 0;
                while (!at("<eof>")) {
                    if (at(",") && angle == 0 && paren == 0 && bracket == 0) break;
                    if (at(">")) {
                        if (angle == 0 && paren == 0 && bracket == 0) break;
                        if (angle) --angle;
                    } else if (at("<")) ++angle;
                    else if (at("(")) ++paren;
                    else if (at(")") && paren) --paren;
                    else if (at("[")) ++bracket;
                    else if (at("]") && bracket) --bracket;
                    parameter.default_type.push_back(next());
                }
                if (parameter.default_type.empty()) syntax("template default must be a type");
                if (parameter.template_parameter) {
                    std::string default_name;
                    for (const auto &token : parameter.default_type) default_name += token.text;
                    parameter.default_template = resolve_template_name(default_name);
                    if (parameter.default_template.empty())
                        fail(ErrorCode::unsupported, "template-template default must name a previously declared template");
                }
                }
            } else if (saw_default && !parameter.pack) {
                fail(ErrorCode::malformed, "template parameters without defaults cannot follow a defaulted parameter");
            }
            parameters.push_back(std::move(parameter));
            if (parameters.size() > 32) fail(ErrorCode::resource_limit, "template parameter count exceeds 32");
            if (take(">")) break;
            need(",");
        }
        leave();
        return parameters;
    }
    std::vector<std::vector<Token>> parse_template_patterns() {
        need("<");
        if (take(">")) return {};
        std::vector<std::vector<Token>> patterns;
        for (;;) {
            std::vector<Token> pattern;
            std::size_t angle = 0, paren = 0, bracket = 0;
            while (!at("<eof>")) {
                if (at(",") && angle == 0 && paren == 0 && bracket == 0) break;
                if (at(">")) {
                    if (angle == 0 && paren == 0 && bracket == 0) break;
                    if (angle) --angle;
                } else if (at("<")) ++angle;
                else if (at("(")) ++paren;
                else if (at(")") && paren) --paren;
                else if (at("[")) ++bracket;
                else if (at("]") && bracket) --bracket;
                pattern.push_back(next());
            }
            if (pattern.empty()) syntax("empty template specialization argument");
            patterns.push_back(std::move(pattern));
            if (take(">")) break;
            need(",");
        }
        return patterns;
    }
    bool template_parameter_pattern(const std::vector<Token> &pattern,
                                    const std::vector<TemplateParameter> &parameters,
                                    std::map<std::string, TypePtr, std::less<>> &bindings,
                                    const TypePtr &argument, unsigned &strength) {
        auto parameter = [&](std::size_t index) -> const TemplateParameter * {
            if (index >= pattern.size() || !identifier(pattern[index].text)) return nullptr;
            const auto found = std::find_if(parameters.begin(), parameters.end(), [&](const auto &item) {
                return item.name == pattern[index].text && !item.value_parameter &&
                       !item.template_parameter && !item.pack;
            });
            return found == parameters.end() ? nullptr : &*found;
        };
        const TemplateParameter *deduced = parameter(0);
        TypePtr value = argument;
        if (deduced && pattern.size() == 1) {
            strength = 0;
        } else if (deduced && pattern.size() == 2 && pattern[1].text == "*") {
            if (argument->kind() != Kind::pointer) return false;
            value = argument->element();
            strength = 2;
        } else if (pattern.size() == 3 && pattern[0].text == "const" &&
                   (deduced = parameter(1)) && pattern[2].text == "*") {
            if (argument->kind() != Kind::pointer || !argument->element() ||
                argument->element()->kind() != Kind::qualified ||
                !(argument->element()->qualifiers() & static_cast<std::uint8_t>(Qualifier::const_))) return false;
            value = argument->element()->element();
            strength = 3;
        } else {
            for (const auto &token : pattern)
                if (std::any_of(parameters.begin(), parameters.end(), [&](const auto &item) { return item.name == token.text; }))
                    fail(ErrorCode::unsupported, "partial specialization pattern is outside the supported type, T*, and const T* forms");
            auto fixed = parse_type_tokens(pattern, {});
            if (fixed->id() != argument->id()) return false;
            strength = 8;
            return true;
        }
        auto found = bindings.find(deduced->name);
        if (found != bindings.end()) return found->second->id() == value->id();
        bindings.emplace(deduced->name, std::move(value));
        return true;
    }
    bool template_value_parameter_pattern(const std::vector<Token> &pattern,
                                          const std::vector<TemplateParameter> &parameters,
                                          std::map<std::string, std::uint64_t, std::less<>> &bindings,
                                          std::uint64_t argument, unsigned &strength) {
        if (pattern.size() != 1) {
            const auto value = evaluate_integer_expression(
                pattern, std::map<std::string, std::uint64_t, std::less<>>{});
            if (value < 0) fail(ErrorCode::unsupported, "negative non-type specialization patterns are unsupported");
            strength = 8;
            return static_cast<std::uint64_t>(value) == argument;
        }
        const auto &token = pattern.front().text;
        const auto parameter = std::find_if(parameters.begin(), parameters.end(), [&](const auto &item) {
            return item.name == token;
        });
        if (parameter != parameters.end()) {
            if (!parameter->value_parameter || parameter->template_parameter || parameter->pack)
                fail(ErrorCode::unsupported, "non-type specialization patterns can bind only integral parameters");
            if (auto found = bindings.find(parameter->name); found != bindings.end())
                return found->second == argument;
            bindings.emplace(parameter->name, argument);
            return true;
        }
        if (token.empty() || token.front() < '0' || token.front() > '9')
            fail(ErrorCode::unsupported, "non-type specialization patterns must use integer literals or direct parameter names");
        // Non-type template arguments are stored as uint64_t after the primary
        // parameter's width check. Keep the same full unsigned range here;
        // signed-only parsing incorrectly rejected valid high-bit unsigned
        // specialization arguments before they could be compared.
        const auto value = integer_magnitude(token, std::numeric_limits<std::uint64_t>::max());
        strength = 8;
        return value == argument;
    }
    bool is_dependent_value_expression_pattern(
        const std::vector<Token> &pattern,
        const std::vector<TemplateParameter> &parameters) const {
        if (pattern.size() <= 1) return false;
        bool dependent = false;
        for (const auto &token : pattern) {
            if (!identifier(token.text) || token.text == "true" || token.text == "false") continue;
            const auto parameter = std::find_if(parameters.begin(), parameters.end(), [&](const auto &item) {
                return item.name == token.text;
            });
            if (parameter == parameters.end()) continue;
            if (!parameter->value_parameter || parameter->template_parameter || parameter->pack)
                fail(ErrorCode::unsupported, "non-type specialization expressions can reference only integral parameters");
            dependent = true;
        }
        return dependent;
    }
    bool template_template_parameter_pattern(const std::vector<Token> &pattern,
                                            const std::vector<TemplateParameter> &parameters,
                                            std::map<std::string, std::string, std::less<>> &bindings,
                                            const TemplateParameter &primary_parameter,
                                            const std::string &argument, unsigned &strength) {
        std::string template_path;
        for (const auto &token : pattern) {
            if (!identifier(token.text) && token.text != "::")
                fail(ErrorCode::unsupported, "template-template specialization patterns must be a template name or parameter name");
            template_path += token.text;
        }
        if (template_path.empty())
            fail(ErrorCode::unsupported, "template-template specialization patterns must be one template name or parameter name");
        const auto &name = template_path;
        if (pattern.size() == 1) {
            const auto parameter = std::find_if(parameters.begin(), parameters.end(), [&](const auto &item) {
                return item.name == name;
            });
            if (parameter != parameters.end()) {
                if (!parameter->template_parameter || parameter->pack)
                    fail(ErrorCode::unsupported, "template-template specialization patterns can bind only template parameters");
                validate_template_template_argument(*parameter, argument);
                if (auto found = bindings.find(name); found != bindings.end()) return found->second == argument;
                bindings.emplace(name, argument);
                return true;
            }
        }
        const auto fixed_name = resolve_template_name(name);
        if (fixed_name.empty())
            fail(ErrorCode::unsupported, "fixed template-template specialization pattern names an unsupported template");
        const std::vector<TemplateParameter> *actual_parameters = nullptr;
        if (auto actual = aggregate_templates_.find(fixed_name); actual != aggregate_templates_.end())
            actual_parameters = &actual->second.parameters;
        else if (auto alias = template_aliases_.find(fixed_name); alias != template_aliases_.end())
            actual_parameters = &alias->second.parameters;
        if (!actual_parameters || actual_parameters->size() != primary_parameter.nested_parameters.size())
            fail(ErrorCode::malformed, "fixed template-template pattern arity does not match primary template parameter");
        for (std::size_t nested = 0; nested < actual_parameters->size(); ++nested)
            if (!same_template_parameter_shape(primary_parameter.nested_parameters[nested], (*actual_parameters)[nested]))
                fail(ErrorCode::malformed, "fixed template-template pattern parameter kinds do not match primary template parameter");
        if (fixed_name != argument) return false;
        strength = 8;
        return true;
    }
    static bool dominates(const std::vector<unsigned> &left, const std::vector<unsigned> &right) {
        if (left.size() != right.size()) return false;
        bool strictly_better = false;
        for (std::size_t i = 0; i < left.size(); ++i) {
            if (left[i] < right[i]) return false;
            strictly_better = strictly_better || left[i] > right[i];
        }
        return strictly_better;
    }
    TypePtr instantiate_template_aggregate(const std::string &name, const std::vector<TemplateArgument> &arguments) {
        if (template_depth_ >= o_.max_nesting)
            fail(ErrorCode::resource_limit, "template aggregate expansion exceeds configured nesting limit");
        auto definition = aggregate_templates_.find(name);
        if (definition == aggregate_templates_.end()) return {};
        auto primary_bindings = bind_template_parameters(definition->second.parameters, arguments);
        const auto instance_name = template_instance_key(name, definition->second.parameters, primary_bindings);
        if (auto existing = template_instances_.find(instance_name); existing != template_instances_.end())
            return existing->second;
        std::vector<TemplateArgument> complete_arguments;
        const bool primary_single_type_pack = definition->second.parameters.size() == 1 &&
            definition->second.parameters.front().pack &&
            !definition->second.parameters.front().value_parameter &&
            !definition->second.parameters.front().template_parameter;
        const bool supported_specialization_parameters = std::all_of(
            definition->second.parameters.begin(), definition->second.parameters.end(),
            [](const auto &parameter) { return !parameter.pack; });
        if (!definition->second.specializations.empty() && !supported_specialization_parameters &&
            !primary_single_type_pack)
            fail(ErrorCode::unsupported, "specializations with primary template parameter packs are unsupported");
        if (!definition->second.specializations.empty()) {
            if (primary_single_type_pack) {
                const auto pack = primary_bindings.packs.find(definition->second.parameters.front().name);
                if (pack != primary_bindings.packs.end()) complete_arguments = pack->second;
            } else {
                complete_arguments.reserve(definition->second.parameters.size());
                for (const auto &parameter : definition->second.parameters) {
                    if (parameter.value_parameter)
                        complete_arguments.push_back({{}, primary_bindings.values.at(parameter.name), {}});
                    else if (parameter.template_parameter)
                        complete_arguments.push_back({{}, {}, primary_bindings.templates.at(parameter.name)});
                    else
                        complete_arguments.push_back({primary_bindings.types.at(parameter.name), {}, {}});
                }
            }
        }

        struct MatchingSpecialization {
            const AggregateSpecialization *specialization = nullptr;
            TemplateBindings bindings;
            std::vector<unsigned> strengths;
        };
        std::vector<MatchingSpecialization> matches_found;
        for (const auto &specialization : definition->second.specializations) {
            if (primary_single_type_pack) {
                // Support one trailing type-pack expansion over one primary
                // type pack. Each argument is matched independently and the
                // deduced elements are retained as a pack for body expansion.
                if (specialization.patterns.size() != 1) continue;
                if (specialization.parameters.size() != 1 || !specialization.parameters.front().pack ||
                    specialization.parameters.front().value_parameter ||
                    specialization.parameters.front().template_parameter ||
                    specialization.patterns.front().empty() ||
                    specialization.patterns.front().back().text != "...")
                    fail(ErrorCode::unsupported,
                         "primary type-pack specializations require one type-pack expansion pattern");
                auto element_pattern = specialization.patterns.front();
                element_pattern.pop_back();
                if (element_pattern.empty())
                    fail(ErrorCode::malformed, "type-pack specialization expansion has an empty pattern");
                const bool pointer_pattern = element_pattern.size() == 2 &&
                    identifier(element_pattern[0].text) && element_pattern[1].text == "*";
                const bool const_pointer_pattern = element_pattern.size() == 3 &&
                    element_pattern[0].text == "const" && identifier(element_pattern[1].text) &&
                    element_pattern[2].text == "*";
                if (!pointer_pattern && !const_pointer_pattern)
                    fail(ErrorCode::unsupported,
                         "type-pack specialization patterns support T*... and const T*... only");
                auto element_parameter = specialization.parameters.front();
                element_parameter.pack = false;
                const std::vector<TemplateParameter> element_parameters{element_parameter};
                MatchingSpecialization candidate;
                candidate.specialization = &specialization;
                candidate.strengths.push_back(const_pointer_pattern ? 3u : 2u);
                auto &deduced_pack = candidate.bindings.packs[element_parameter.name];
                bool matches = true;
                for (const auto &argument : complete_arguments) {
                    if (!argument.type) {
                        matches = false;
                        break;
                    }
                    std::map<std::string, TypePtr, std::less<>> element_bindings;
                    unsigned strength = 0;
                    if (!template_parameter_pattern(element_pattern, element_parameters,
                                                    element_bindings, argument.type, strength)) {
                        matches = false;
                        break;
                    }
                    const auto bound = element_bindings.find(element_parameter.name);
                    if (bound == element_bindings.end())
                        fail(ErrorCode::unsupported,
                             "type-pack specialization pattern must deduce its pack element");
                    deduced_pack.push_back({bound->second, {}, {}});
                    if (strength != candidate.strengths.front())
                        fail(ErrorCode::conflict, "type-pack specialization specificity changed between elements");
                }
                if (matches) matches_found.push_back(std::move(candidate));
                continue;
            }
            if (specialization.patterns.size() != complete_arguments.size()) continue;
            TemplateBindings candidate_bindings;
            std::vector<unsigned> strengths(complete_arguments.size(), specialization.parameters.empty() ? 10000u : 0u);
            std::vector<std::size_t> dependent_value_expressions;
            bool matches = true;
            for (std::size_t i = 0; i < complete_arguments.size(); ++i) {
                const auto &primary_parameter = definition->second.parameters[i];
                const auto &pattern = specialization.patterns[i];
                unsigned pattern_strength = 0;
                bool matched = false;
                if (primary_parameter.value_parameter && complete_arguments[i].value) {
                    if (is_dependent_value_expression_pattern(pattern, specialization.parameters)) {
                        dependent_value_expressions.push_back(i);
                        matched = true;
                        // Dependent expressions are checked for equality, but
                        // do not claim a specificity advantage over a direct
                        // parameter pattern. This keeps overlapping or
                        // equivalent arithmetic patterns ambiguous.
                        pattern_strength = 0;
                    } else {
                        matched = template_value_parameter_pattern(pattern, specialization.parameters,
                                                                   candidate_bindings.values,
                                                                   *complete_arguments[i].value, pattern_strength);
                    }
                } else if (!primary_parameter.value_parameter && !primary_parameter.template_parameter &&
                           complete_arguments[i].type) {
                    matched = template_parameter_pattern(pattern, specialization.parameters,
                                                         candidate_bindings.types,
                                                         complete_arguments[i].type, pattern_strength);
                } else if (primary_parameter.template_parameter && !complete_arguments[i].template_name.empty()) {
                    matched = template_template_parameter_pattern(pattern, specialization.parameters,
                                                                 candidate_bindings.templates,
                                                                 primary_parameter,
                                                                 complete_arguments[i].template_name, pattern_strength);
                } else {
                    fail(ErrorCode::unsupported, "specialization argument kind is unsupported");
                }
                if (!matched) {
                    matches = false;
                    break;
                }
                strengths[i] = specialization.parameters.empty() ? 10000u : pattern_strength;
            }
            if (!matches) continue;
            for (const auto &parameter : specialization.parameters)
                if ((parameter.value_parameter && !candidate_bindings.values.contains(parameter.name)) ||
                    (parameter.template_parameter && !candidate_bindings.templates.contains(parameter.name)) ||
                    (!parameter.value_parameter && !parameter.template_parameter &&
                     !candidate_bindings.types.contains(parameter.name)))
                    fail(ErrorCode::unsupported,
                         "partial specialization contains a parameter that cannot be deduced");
            for (const auto index : dependent_value_expressions) {
                const auto evaluated = evaluate_integer_expression(specialization.patterns[index],
                                                                   candidate_bindings.values);
                if (evaluated < 0)
                    fail(ErrorCode::unsupported, "negative non-type specialization patterns are unsupported");
                if (static_cast<std::uint64_t>(evaluated) != *complete_arguments[index].value) {
                    matches = false;
                    break;
                }
            }
            if (!matches) continue;
            matches_found.push_back({&specialization, std::move(candidate_bindings), std::move(strengths)});
        }

        const AggregateSpecialization *selected = nullptr;
        TemplateBindings selected_bindings;
        if (!matches_found.empty()) {
            std::vector<std::size_t> dominant;
            for (std::size_t candidate = 0; candidate < matches_found.size(); ++candidate) {
                bool is_dominated = false;
                for (std::size_t other = 0; other < matches_found.size(); ++other)
                    if (candidate != other && dominates(matches_found[other].strengths, matches_found[candidate].strengths)) {
                        is_dominated = true;
                        break;
                    }
                if (!is_dominated) dominant.push_back(candidate);
            }
            if (dominant.size() != 1)
                fail(ErrorCode::conflict, "ambiguous partial specialization for '" + instance_name + "'");
            auto &winner = matches_found[dominant.front()];
            selected = winner.specialization;
            selected_bindings = std::move(winner.bindings);
        }

        const auto &body = selected ? selected->definition : definition->second.definition;
        TemplateBindings bindings = primary_bindings;
        if (selected) bindings = selected_bindings;
        auto incomplete = Type::incomplete_aggregate(definition->second.is_union ? Kind::union_type : Kind::structure,
                                                     instance_name);
        if (!incomplete) fail(incomplete.error().code, incomplete.error().message);
        template_instances_.emplace(instance_name, incomplete.value());
        const auto tag_key = std::string(definition->second.is_union ? "union " : "struct ") + instance_name;
        names_.insert_or_assign(tag_key, incomplete.value());
        names_.insert_or_assign(instance_name, incomplete.value());

        Parser nested(tokens_with_eof(body), o_, *this);
        nested.template_type_bindings_ = template_type_bindings_;
        for (const auto &[parameter, type] : bindings.types) nested.template_type_bindings_.insert_or_assign(parameter, type);
        for (const auto &[parameter, value] : bindings.values) nested.template_value_bindings_.insert_or_assign(parameter, value);
        for (const auto &[parameter, template_name] : bindings.templates) nested.template_template_bindings_.insert_or_assign(parameter, template_name);
        for (const auto &[parameter, pack] : bindings.packs) nested.template_pack_bindings_.insert_or_assign(parameter, pack);
        nested.template_instances_.insert_or_assign(instance_name, incomplete.value());
        // Class templates are stored at namespace scope; instantiation from a
        // member alias is not a nested aggregate definition in the caller.
        nested.aggregate_scopes_.clear();
        nested.template_instance_name_ = instance_name;
        nested.template_instance_base_name_ = name;
        auto base = nested.parse_base();
        if (base.is_typedef || base.is_static) syntax("template aggregate definition has invalid storage specifiers");
        if (nested.at(";")) nested.need(";");
        if (!nested.at("<eof>")) nested.syntax("unexpected token after template aggregate definition");
        auto completed = nested.names_.find(tag_key);
        if (completed == nested.names_.end() || !completed->second->size())
            fail(ErrorCode::malformed, "template aggregate did not produce a complete type");
        template_instances_.insert_or_assign(instance_name, completed->second);
        for (const auto &[key, type] : nested.names_) names_.insert_or_assign(key, type);
        for (auto &[key, symbol] : nested.result_.symbols) result_.symbols.insert_or_assign(key, std::move(symbol));
        for (auto &[key, value] : nested.result_.enum_constants) result_.enum_constants.insert_or_assign(key, value);
        for (auto &[key, line] : nested.result_.enum_constant_source_lines) result_.enum_constant_source_lines.insert_or_assign(key, line);
        for (const auto &[key, value] : nested.enum_value_bindings_) enum_value_bindings_.insert_or_assign(key, value);
        for (const auto &[name, values] : nested.enum_unqualified_bindings_) {
            auto &merged = enum_unqualified_bindings_[name];
            merged.insert(merged.end(), values.begin(), values.end());
        }
        enum_qualified_bindings_.insert(enum_qualified_bindings_.end(),
            nested.enum_qualified_bindings_.begin(), nested.enum_qualified_bindings_.end());
        result_.diagnostics.insert(result_.diagnostics.end(), nested.result_.diagnostics.begin(), nested.result_.diagnostics.end());
        result_.symbols.insert_or_assign(tag_key, HeaderSymbol{HeaderSymbolKind::tag, completed->second});
        result_.symbols.insert_or_assign(instance_name, HeaderSymbol{HeaderSymbolKind::tag, completed->second});
        return completed->second;
    }
    void parse_template_declaration() {
        need("template");
        auto parameters = parse_template_parameters();
        const bool explicit_specialization = parameters.empty();
        if (take("using")) {
            if (explicit_specialization) fail(ErrorCode::unsupported, "explicit alias-template specializations are unsupported");
            if (!identifier(peek().text)) syntax("expected alias-template name");
            const auto alias_name = qualify_name(next().text);
            need("=");
            auto target = take_until_semicolon();
            if (template_aliases_.contains(alias_name) || names_.contains(alias_name))
                fail(ErrorCode::conflict, "duplicate template name '" + alias_name + "'");
            HeaderTemplateDeclaration exposed;
            exposed.name = alias_name;
            exposed.is_alias = true;
            for (const auto &parameter : parameters) exposed.parameters.push_back(export_template_parameter(parameter));
            result_.templates.insert_or_assign(alias_name, std::move(exposed));
            template_aliases_.emplace(alias_name, TemplateAlias{std::move(parameters), std::move(target)});
            return;
        }
        if (!at("class") && !at("struct") && !at("union")) {
            if (explicit_specialization)
                fail(ErrorCode::unsupported, "explicit function-template specializations are unsupported");
            if (std::any_of(parameters.begin(), parameters.end(), [](const auto &parameter) {
                    return parameter.value_parameter || parameter.template_parameter || parameter.pack;
                }))
                fail(ErrorCode::unsupported, "function templates currently support type parameters only");
            const auto original_bindings = template_type_bindings_;
            for (const auto &parameter : parameters) {
                auto reference = Type::named_reference(parameter.name);
                if (!reference) fail(reference.error().code, reference.error().message);
                template_type_bindings_.insert_or_assign(parameter.name, reference.value());
            }
            auto base = parse_base();
            if (base.is_typedef || base.is_static) syntax("function template has invalid storage specifiers");
            auto declaration = parse_declarator(base.type, false);
            if (!declaration.function)
                fail(ErrorCode::unsupported, "only function templates and class templates are retained");
            if (at("{")) fail(ErrorCode::unsupported, "function template definitions and bodies are unsupported");
            need(";");
            const auto function_name = qualify_name(declaration.name);
            HeaderTemplateDeclaration exposed;
            exposed.name = function_name;
            exposed.is_function = true;
            exposed.function_type = declaration.type;
            for (const auto &parameter : parameters) exposed.parameters.push_back(export_template_parameter(parameter));
            if (result_.templates.contains(function_name))
                fail(ErrorCode::unsupported, "overloaded function-template declarations are not yet distinguished");
            result_.templates.emplace(function_name, std::move(exposed));
            template_type_bindings_ = original_bindings;
            return;
        }
        const auto declaration_start = pos_;
        bool is_union = false;
        if (take("union")) is_union = true;
        else if (!take("class") && !take("struct"))
            fail(ErrorCode::unsupported, "only class/struct/union templates and alias templates are supported");
        if (!identifier(peek().text)) syntax("expected template aggregate name");
        const auto base_name = qualify_name(next().text);
        std::vector<std::vector<Token>> patterns;
        const bool has_specialization_argument_list = at("<");
        if (has_specialization_argument_list) patterns = parse_template_patterns();
        (void)take_aggregate_definition();
        std::vector<Token> full_definition(t_.begin() + static_cast<std::ptrdiff_t>(declaration_start),
                                           t_.begin() + static_cast<std::ptrdiff_t>(pos_ - 1));
        full_definition.push_back({";", peek().line});
        if (patterns.empty() && !has_specialization_argument_list) {
            if (explicit_specialization)
                fail(ErrorCode::malformed, "explicit template specialization requires a template argument list");
            if (aggregate_templates_.contains(base_name) || template_aliases_.contains(base_name))
                fail(ErrorCode::conflict, "duplicate class template '" + base_name + "'");
            AggregateTemplate definition;
            definition.is_union = is_union;
            HeaderTemplateDeclaration exposed;
            exposed.name = base_name;
            exposed.is_union = is_union;
            for (const auto &parameter : parameters) exposed.parameters.push_back(export_template_parameter(parameter));
            result_.templates.insert_or_assign(base_name, std::move(exposed));
            definition.parameters = std::move(parameters);
            definition.definition = std::move(full_definition);
            aggregate_templates_.emplace(base_name, std::move(definition));
            return;
        }
        auto primary = aggregate_templates_.find(base_name);
        if (primary == aggregate_templates_.end())
            fail(ErrorCode::unsupported, "template specializations require a previously declared primary template");
        const bool primary_single_type_pack = primary->second.parameters.size() == 1 &&
            primary->second.parameters.front().pack &&
            !primary->second.parameters.front().value_parameter &&
            !primary->second.parameters.front().template_parameter;
        if (primary_single_type_pack && explicit_specialization)
            fail(ErrorCode::unsupported,
                 "full specializations of a primary type pack are unsupported");
        const bool pack_pattern_shape = patterns.size() == 1 && !patterns.front().empty() &&
            patterns.front().back().text == "..." &&
            ((patterns.front().size() == 3 && identifier(patterns.front()[0].text) &&
              patterns.front()[1].text == "*" && patterns.front()[2].text == "...") ||
             (patterns.front().size() == 4 && patterns.front()[0].text == "const" &&
              identifier(patterns.front()[1].text) && patterns.front()[2].text == "*" &&
              patterns.front()[3].text == "..."));
        const bool supported_type_pack_specialization = !explicit_specialization && primary_single_type_pack &&
            parameters.size() == 1 && parameters.front().pack &&
            !parameters.front().value_parameter && !parameters.front().template_parameter &&
            parameters.front().default_type.empty() && parameters.front().default_template.empty() &&
            parameters.front().default_value_expression.empty() && pack_pattern_shape;
        if (primary_single_type_pack && !supported_type_pack_specialization)
            fail(ErrorCode::unsupported,
                 "primary type-pack specializations require one trailing T*... or const T*... pattern");
        if (std::any_of(parameters.begin(), parameters.end(), [&](const auto &parameter) {
                return (!supported_type_pack_specialization && parameter.pack) ||
                       !parameter.default_value_expression.empty() || !parameter.default_type.empty() ||
                       !parameter.default_template.empty();
            }))
            fail(ErrorCode::unsupported,
                 "class-template specializations support non-pack parameters, or one T*.../const T*... type-pack pattern without defaults");
        if (explicit_specialization && patterns.size() < primary->second.parameters.size()) {
            if (std::any_of(primary->second.parameters.begin(), primary->second.parameters.end(),
                            [](const auto &parameter) { return parameter.pack; }))
                fail(ErrorCode::unsupported, "full specializations using primary parameter packs are unsupported");
            std::vector<TemplateArgument> supplied;
            supplied.reserve(patterns.size());
            for (std::size_t index = 0; index < patterns.size(); ++index) {
                const auto &parameter = primary->second.parameters[index];
                if (parameter.value_parameter) {
                    const auto value = evaluate_integer_expression(patterns[index], enum_value_bindings_,
                        [&](std::string_view name) { return resolve_enum_expression_name(name, enum_value_bindings_); });
                    if (value < 0) fail(ErrorCode::unsupported, "negative explicit specialization arguments are unsupported");
                    supplied.push_back({{}, static_cast<std::uint64_t>(value), {}});
                } else if (parameter.template_parameter) {
                    std::string spelling;
                    for (const auto &token : patterns[index]) spelling += token.text;
                    auto template_name = resolve_template_name(spelling);
                    if (template_name.empty()) fail(ErrorCode::unsupported, "explicit specialization argument must name a supported template");
                    supplied.push_back({{}, {}, std::move(template_name)});
                } else {
                    supplied.push_back({parse_type_tokens(patterns[index], {}), {}, {}});
                }
            }
            const auto completed = bind_template_parameters(primary->second.parameters, supplied);
            patterns.clear();
            for (const auto &parameter : primary->second.parameters) {
                std::vector<Token> pattern;
                if (parameter.value_parameter) {
                    pattern.push_back({std::to_string(completed.values.at(parameter.name)), peek().line});
                } else if (parameter.template_parameter) {
                    pattern = lex(completed.templates.at(parameter.name), o_);
                    if (!pattern.empty() && pattern.back().text == "<eof>") pattern.pop_back();
                } else {
                    const auto &type = completed.types.at(parameter.name);
                    const auto marker = "__hexlab_spec_default_type_" + std::to_string(type->id());
                    if (auto existing = names_.find(marker); existing != names_.end() &&
                        existing->second->id() != type->id())
                        fail(ErrorCode::conflict, "internal specialization default type identity collision");
                    names_.insert_or_assign(marker, type);
                    pattern.push_back({marker, peek().line});
                }
                if (pattern.empty()) syntax("empty default in explicit template specialization");
                patterns.push_back(std::move(pattern));
            }
        }
        if (!explicit_specialization && !patterns.empty() && patterns.size() < primary->second.parameters.size()) {
            std::map<std::string, std::string, std::less<>> prior_pattern_bindings;
            for (std::size_t index = 0; index < patterns.size(); ++index) {
                if (patterns[index].size() != 1 || !identifier(patterns[index].front().text)) continue;
                const auto candidate = std::find_if(parameters.begin(), parameters.end(), [&](const auto &parameter) {
                    return parameter.name == patterns[index].front().text;
                });
                if (candidate != parameters.end())
                    prior_pattern_bindings.insert_or_assign(primary->second.parameters[index].name, candidate->name);
            }
            for (std::size_t index = patterns.size(); index < primary->second.parameters.size(); ++index) {
                const auto &parameter = primary->second.parameters[index];
                if (parameter.pack || (parameter.default_type.empty() && parameter.default_value_expression.empty() &&
                                       parameter.default_template.empty()))
                    fail(ErrorCode::malformed, "partial specialization omits a primary template argument without a default");
                std::vector<Token> pattern = parameter.value_parameter ? parameter.default_value_expression :
                    parameter.template_parameter ? lex(parameter.default_template, o_) : parameter.default_type;
                if (!pattern.empty() && pattern.back().text == "<eof>") pattern.pop_back();
                for (auto &token : pattern) {
                    const auto primary_parameter = std::find_if(primary->second.parameters.begin(),
                        primary->second.parameters.begin() + static_cast<std::ptrdiff_t>(index),
                        [&](const auto &prior) { return prior.name == token.text; });
                    if (primary_parameter == primary->second.parameters.begin() + static_cast<std::ptrdiff_t>(index)) continue;
                    const auto replacement = prior_pattern_bindings.find(token.text);
                    if (replacement == prior_pattern_bindings.end())
                        fail(ErrorCode::unsupported, "omitted specialization default depends on a non-direct earlier pattern");
                    token.text = replacement->second;
                }
                if (pattern.empty()) syntax("empty default in partial specialization argument list");
                patterns.push_back(std::move(pattern));
            }
        }
        if (patterns.empty()) fail(ErrorCode::malformed,"a partial specialization requires explicit template arguments");
        if (patterns.size() != primary->second.parameters.size())
            fail(ErrorCode::malformed, "class-template specialization argument count does not match the primary template");
        if (primary->second.is_union != is_union)
            fail(ErrorCode::conflict, "template specialization changes struct/union kind");
        // Canonicalize integral literals before conflict detection. Equivalent
        // decimal/octal/hex spellings (and U/ L suffixes) denote the same
        // specialization and must not defer an ambiguity until instantiation.
        for (std::size_t index = 0; index < patterns.size(); ++index) {
            if (!primary->second.parameters[index].value_parameter || patterns[index].size() != 1)
                continue;
            const auto &token = patterns[index].front().text;
            if (token.empty() || token.front() < '0' || token.front() > '9') continue;
            patterns[index].front().text = std::to_string(
                integer_magnitude(token, std::numeric_limits<std::uint64_t>::max()));
        }
        AggregateSpecialization specialization{std::move(parameters), std::move(patterns), std::move(full_definition)};
        if (std::any_of(primary->second.specializations.begin(), primary->second.specializations.end(),
                        [&](const auto &item) { return item.patterns == specialization.patterns; }))
            fail(ErrorCode::conflict, "duplicate template specialization for '" + base_name + "'");
        primary->second.specializations.push_back(std::move(specialization));
    }
    void register_tag_type(std::string_view tag_kind,const std::string &qualified,TypePtr type,bool inject_ordinary=false) {
        const auto tag_key=std::string(tag_kind)+" "+qualified;
        const bool inject=inject_ordinary||!current_namespace().empty();
        if(inject)if(auto ordinary=names_.find(qualified);ordinary!=names_.end()){
            const auto previous=names_.find(tag_key);
            if(ordinary->second->id()!=type->id()&&(previous==names_.end()||previous->second->id()!=ordinary->second->id()))
                fail(ErrorCode::conflict,"duplicate C++ type name '"+qualified+"'");
        }
        names_[tag_key]=type;
        result_.symbols[tag_key]=HeaderSymbol{HeaderSymbolKind::tag,type};
        if(inject){names_[qualified]=type;result_.symbols[qualified]=HeaderSymbol{HeaderSymbolKind::tag,std::move(type)};}
    }
    void register_member_alias(const std::string &owner,const std::string &name,TypePtr type,
                               std::set<std::string> &member_names,const std::set<std::string> &method_names){
        if(name.empty())syntax("aggregate type alias requires a name");
        const auto injected=injected_aggregate_name(owner);
        if(name==injected||template_type_bindings_.contains(name)||template_value_bindings_.contains(name)||
           template_template_bindings_.contains(name)||template_pack_bindings_.contains(name)||
           method_names.contains(name)||!member_names.insert(name).second)
            fail(ErrorCode::conflict,"duplicate aggregate type or member '"+name+"'");
        const auto qualified=owner+"::"+name;
        if(names_.contains(qualified)||result_.symbols.contains(qualified)||result_.enum_constants.contains(qualified))
            fail(ErrorCode::conflict,"duplicate aggregate type name '"+qualified+"'");
        names_.emplace(qualified,type);
        result_.symbols.emplace(qualified,HeaderSymbol{HeaderSymbolKind::typedef_name,std::move(type)});
    }
    void parse_namespace(bool inline_namespace=false) {
        need("namespace");
        if (take("{")) {
            if (inline_namespace)
                fail(ErrorCode::malformed, "an inline namespace must have a name");
            const auto parent = current_namespace();
            auto found = anonymous_namespace_components_.find(parent);
            if (found == anonymous_namespace_components_.end()) {
                if (next_anonymous_namespace_id_ == std::numeric_limits<std::uint32_t>::max())
                    fail(ErrorCode::resource_limit, "anonymous namespace count exceeds its identity limit");
                const auto component = "@anonymous_" + std::to_string(next_anonymous_namespace_id_++);
                found = anonymous_namespace_components_.emplace(parent, component).first;
            }
            namespace_stack_.push_back(found->second);
            const auto target = current_namespace();
            namespaces_.insert(target);
            while (!take("}")) {
                if (at("<eof>")) syntax("unterminated anonymous namespace definition");
                parse_external();
            }
            namespace_stack_.pop_back();
            // An unnamed namespace injects an implicit using-directive into
            // its enclosing namespace. Publish it after the body, matching
            // source-order visibility for following declarations.
            const auto duplicate = std::find_if(using_namespaces_.begin(), using_namespaces_.end(),
                [&](const UsingNamespace &entry) { return entry.scope == parent && entry.target == target; });
            if (duplicate == using_namespaces_.end())
                using_namespaces_.push_back({parent, target});
            return;
        }
        if(!identifier(peek().text))
            fail(ErrorCode::malformed,"expected a namespace name or '{'");
        const auto first_name=next().text;
        if(take("=")) {
            if(inline_namespace)
                fail(ErrorCode::malformed,"an inline namespace cannot be a namespace alias");
            auto target=resolve_namespace_name(parse_lookup_name());
            need(";");
            const auto alias=qualify_name(first_name);
            if(namespace_aliases_.contains(alias)||namespaces_.contains(alias)||result_.symbols.contains(alias))
                fail(ErrorCode::conflict,"duplicate namespace alias '"+alias+"'");
            namespace_aliases_.emplace(alias,std::move(target));
            return;
        }
        std::vector<std::string> parts{first_name};
        while(take("::")){if(!identifier(peek().text))syntax("expected namespace name after '::'");parts.push_back(next().text);}
        if(inline_namespace&&parts.size()!=1)
            fail(ErrorCode::unsupported,"inline namespace definitions must name one namespace component");
        need("{");
        const auto original_size=namespace_stack_.size();
        for(const auto &part:parts){
            const auto parent=current_namespace();
            namespace_stack_.push_back(part);
            const auto path=current_namespace();
            if(namespace_aliases_.contains(path))
                fail(ErrorCode::conflict,"a namespace alias cannot be reopened as namespace '"+path+"'");
            if(inline_namespace){
                if(namespaces_.contains(path)&&!inline_namespace_paths_.contains(path))
                    fail(ErrorCode::conflict,"namespace '"+path+"' was already declared without inline");
                inline_namespace_paths_.insert(path);
                auto &children=inline_namespace_children_[parent];
                if(std::find(children.begin(),children.end(),path)==children.end())
                    children.push_back(path);
            }
            namespaces_.insert(path);
        }
        while(!take("}")){
            if(at("<eof>"))syntax("unterminated namespace definition");
            parse_external();
        }
        namespace_stack_.resize(original_size);
    }
    FunctionConvention consume_calling_convention(){
        FunctionConvention keyword=FunctionConvention::platform_default;
        for(;;){
            auto found=FunctionConvention::platform_default;
            if(take("__cdecl"))found=FunctionConvention::c_decl;
            else if(take("__stdcall"))found=FunctionConvention::stdcall;
            else if(take("__fastcall"))found=FunctionConvention::fastcall;
            else if(take("__thiscall"))found=FunctionConvention::thiscall;
            else if(take("__vectorcall"))found=FunctionConvention::vectorcall;
            if(found==FunctionConvention::platform_default)break;
            if(keyword!=FunctionConvention::platform_default&&keyword!=found)
                fail(ErrorCode::conflict,"conflicting function calling-convention keywords");
            keyword=found;
        }
        if(pending_function_convention_){
            if(keyword!=FunctionConvention::platform_default&&keyword!=*pending_function_convention_)
                fail(ErrorCode::conflict,"conflicting function calling conventions");
            keyword=*pending_function_convention_;
            pending_function_convention_.reset();
        }
        return keyword;
    }
    void set_function_convention(FunctionConvention convention){
        if(pending_function_convention_&&*pending_function_convention_!=convention)
            fail(ErrorCode::conflict,"conflicting GNU/Clang function calling-convention attributes");
        pending_function_convention_=convention;
    }
    std::uint64_t parse_vector_size(const std::string &value) const {
        std::uint64_t size=0;const auto [end,error]=std::from_chars(value.data(),value.data()+value.size(),size);
        if(error!=std::errc{}||end!=value.data()+value.size()||!size||size>4096||(size&(size-1))!=0)
            fail(ErrorCode::malformed,"vector_size must be a power of two from 1 through 4096 bytes");
        return size;
    }
    TypePtr make_vector_type(TypePtr base,std::uint64_t bytes){
        std::uint8_t qualifiers=0;
        if(base->kind()==Kind::qualified){qualifiers=base->qualifiers();base=base->element();}
        if((base->kind()!=Kind::integer&&base->kind()!=Kind::floating)||!base->size()||
           bytes%*base->size()!=0)
            fail(ErrorCode::unsupported,"vector_size requires a complete integer or floating scalar base with an evenly divisible byte size");
        const auto lanes=bytes/ *base->size();
        if(!lanes)fail(ErrorCode::malformed,"vector_size is smaller than its scalar base type");
        auto vector=Type::vector(base,lanes,bytes);
        if(!vector)fail(vector.error().code,vector.error().message);
        if(qualifiers){auto qualified=Type::qualified(vector.value(),qualifiers);if(!qualified)fail(qualified.error().code,qualified.error().message);return qualified.value();}
        return vector.value();
    }
    TypePtr apply_function_convention(TypePtr type,FunctionConvention convention){
        if(type->kind()==Kind::qualified){
            auto element=apply_function_convention(type->element(),convention);
            auto qualified=Type::qualified(std::move(element),type->qualifiers());
            if(!qualified)fail(qualified.error().code,qualified.error().message);
            return qualified.value();
        }
        if(type->kind()==Kind::pointer){
            auto element=apply_function_convention(type->element(),convention);
            auto pointer=Type::pointer(std::move(element),*type->size(),type->alignment());
            if(!pointer)fail(pointer.error().code,pointer.error().message);
            return pointer.value();
        }
        if(type->kind()!=Kind::function)
            fail(ErrorCode::unsupported,"calling-convention attributes require a function or pointer-to-function declarator");
        if(type->function_convention()!=FunctionConvention::platform_default&&type->function_convention()!=convention)
            fail(ErrorCode::conflict,"conflicting function calling conventions");
        auto function=Type::function(type->result_type(),type->parameters(),type->variadic(),convention);
        if(!function)fail(function.error().code,function.error().message);
        return function.value();
    }
    TypePtr apply_pending_vector_size(TypePtr type,bool is_typedef){
        if(!pending_vector_size_)return type;
        const auto bytes=*pending_vector_size_;pending_vector_size_.reset();
        if(!is_typedef)fail(ErrorCode::unsupported,"vector_size is currently supported only on typedef declarations");
        return make_vector_type(std::move(type),bytes);
    }
    TypePtr apply_pending_function_convention(TypePtr type){
        if(!pending_function_convention_)return type;
        const auto convention=*pending_function_convention_;pending_function_convention_.reset();
        return apply_function_convention(std::move(type),convention);
    }
    bool parse_attribute(){
        if(take("__declspec")){
            need("(");const auto name=next().text;
            if(name=="align"){
                need("(");const auto value=next().text;need(")");need(")");
                pending_aggregate_alignment_=parse_alignment(value,"__declspec(align)");return false;
            }
            if(name=="dllimport"||name=="dllexport"||name=="noinline"||name=="noreturn"||
               name=="deprecated"||name=="restrict"||name=="selectany") {
                need(")");
                return false;
            }
            fail(ErrorCode::unsupported,"unsupported Microsoft declaration attribute '__declspec("+name+")'");
        }
        if(!take("__attribute__"))return false;
        need("(");need("(");bool packed=false;
        for(;;) {
            const auto name=next().text;
            if(name=="packed"||name=="__packed__") packed=true;
            else if(name=="aligned"||name=="__aligned__") {
                if(!take("(")) fail(ErrorCode::unsupported,"aligned attribute requires an explicit alignment");
                if(take(")")) fail(ErrorCode::unsupported,"aligned attribute requires an explicit alignment");
                const auto value=next().text;need(")");
                const auto alignment=parse_alignment(value,"aligned");
                pending_aggregate_alignment_=std::max(pending_aggregate_alignment_.value_or(0),alignment);
            } else if(name=="vector_size"||name=="__vector_size__") {
                need("(");const auto bytes=parse_vector_size(next().text);need(")");
                if(pending_vector_size_&&*pending_vector_size_!=bytes)
                    fail(ErrorCode::conflict,"conflicting vector_size attributes");
                pending_vector_size_=bytes;
            } else if(name=="visibility"||name=="__visibility__"||name=="section"||
                      name=="__section__"||name=="alias"||name=="__alias__") {
                need("(");
                const auto argument=next().text;
                if(argument.size()<2||argument.front()!='\"'||argument.back()!='\"')
                    fail(ErrorCode::malformed,"attribute '"+name+"' requires one string-literal argument");
                if(name=="visibility"||name=="__visibility__") {
                    if(argument!="\"default\""&&argument!="\"hidden\""&&argument!="\"internal\""&&
                       argument!="\"protected\"")
                        fail(ErrorCode::unsupported,"unsupported visibility attribute value");
                } else if(argument=="\"\"") {
                    fail(ErrorCode::malformed,"attribute '"+name+"' requires a nonempty string-literal argument");
                }
                need(")");
            } else if(name=="weakref"||name=="__weakref__") {
                if(take("(")) {
                    const auto argument=next().text;
                    if(argument.size()<2||argument.front()!='\"'||argument.back()!='\"')
                        fail(ErrorCode::malformed,"weakref attribute requires one string-literal argument");
                    need(")");
                }
            } else if(name=="weak"||name=="__weak__"||name=="used"||name=="__used__"||
                      name=="unused"||name=="__unused__"||name=="retain"||name=="__retain__"||
                      name=="noinline"||name=="__noinline__"||name=="always_inline"||
                      name=="__always_inline__"||name=="cold"||name=="__cold__"||
                      name=="hot"||name=="__hot__"||name=="flatten"||name=="__flatten__"||
                      name=="artificial"||name=="__artificial__"||name=="nothrow"||
                      name=="__nothrow__"||name=="leaf"||name=="__leaf__"||name=="pure"||
                      name=="__pure__"||name=="const"||name=="__const__"||name=="malloc"||
                      name=="__malloc__"||name=="returns_nonnull"||name=="__returns_nonnull__"||
                      name=="warn_unused_result"||name=="__warn_unused_result__"||
                      name=="deprecated"||name=="__deprecated__") {
                if(take("(")) {
                    if(name=="deprecated"||name=="__deprecated__") {
                        const auto message=next().text;
                        if(message.size()<2||message.front()!='\"'||message.back()!='\"')
                            fail(ErrorCode::malformed,"deprecated attribute message must be a string literal");
                    } else if(!take(")")) {
                        fail(ErrorCode::unsupported,"arguments to type-neutral attribute '"+name+"' are unsupported");
                    }
                    if(name=="deprecated"||name=="__deprecated__") need(")");
                }
            } else if(name=="cdecl"||name=="__cdecl__") set_function_convention(FunctionConvention::c_decl);
            else if(name=="stdcall"||name=="__stdcall__") set_function_convention(FunctionConvention::stdcall);
            else if(name=="fastcall"||name=="__fastcall__") set_function_convention(FunctionConvention::fastcall);
            else if(name=="thiscall"||name=="__thiscall__") set_function_convention(FunctionConvention::thiscall);
            else if(name=="vectorcall"||name=="__vectorcall__") set_function_convention(FunctionConvention::vectorcall);
            else if(name=="sysv_abi"||name=="__sysv_abi__") set_function_convention(FunctionConvention::sysv_abi);
            else if(name=="ms_abi"||name=="__ms_abi__") set_function_convention(FunctionConvention::ms_abi);
            else if(name=="pcs") {
                need("(");
                const auto value=next().text;
                need(")");
                if(value!="\"aapcs-vfp\"")
                    fail(ErrorCode::unsupported,"unsupported Arm PCS attribute '"+value+"'");
                set_function_convention(FunctionConvention::aapcs32_vfp);
            }
            else fail(ErrorCode::unsupported,"unsupported declaration attribute '"+name+"'");
            if(!take(",")) break;
        }
        need(")");need(")");return packed;
    }
    bool alignment_specifier() const { return at("alignas") || at("_Alignas"); }
    void parse_alignment_specifier() {
        const auto spelling = next().text;
        need("(");
        const auto token = next().text;
        if (!std::all_of(token.begin(), token.end(), [](char c) {
                return (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F') ||
                       c == 'x' || c == 'X' || c == 'u' || c == 'U' || c == 'l' || c == 'L';
            }))
            fail(ErrorCode::unsupported, spelling + " currently requires an integer constant literal");
        need(")");
        auto value = token;
        while (!value.empty() && (value.back() == 'u' || value.back() == 'U' || value.back() == 'l' || value.back() == 'L')) value.pop_back();
        std::uint64_t alignment = 0;
        int radix = 10;
        std::string_view digits(value);
        if (digits.size() > 2 && digits[0] == '0' && (digits[1] == 'x' || digits[1] == 'X')) { radix = 16; digits.remove_prefix(2); }
        const auto [end, error] = std::from_chars(digits.data(), digits.data() + digits.size(), alignment, radix);
        if (error != std::errc{} || end != digits.data() + digits.size() || alignment > 4096 ||
            (alignment && (alignment & (alignment - 1)) != 0))
            fail(ErrorCode::malformed, spelling + " alignment must be zero or a power of two through 4096");
        if (alignment) pending_aggregate_alignment_ = std::max(pending_aggregate_alignment_.value_or(0), alignment);
    }
    TypePtr apply_alignment(TypePtr type, std::optional<std::uint64_t> alignment) {
        if (!alignment) return type;
        if (type->kind() == Kind::qualified) {
            auto base = apply_alignment(type->element(), alignment);
            auto qualified = Type::qualified(std::move(base), type->qualifiers());
            if (!qualified) fail(qualified.error().code, qualified.error().message);
            return qualified.value();
        }
        if (type->kind() == Kind::array)
            fail(ErrorCode::unsupported, "over-aligned array typedefs are unsupported by the current type record model");
        auto aligned = Type::with_alignment(std::move(type), *alignment);
        if (!aligned) fail(aligned.error().code, aligned.error().message);
        return aligned.value();
    }
    std::uint64_t parse_alignment(const std::string &value,const char *attribute) const {
        std::uint64_t alignment=0;const auto [end,error]=std::from_chars(value.data(),value.data()+value.size(),alignment);
        if(error!=std::errc{}||end!=value.data()+value.size()||alignment==0||alignment>4096||(alignment&(alignment-1))!=0)
            fail(ErrorCode::malformed,std::string(attribute)+" alignment must be a power of two from 1 through 4096");
        return alignment;
    }
    void install_scalars(){
        auto put=[&](std::string n,TypePtr p){names_.emplace(std::move(n),std::move(p));};
        put("void",Type::void_type());
        auto add_int=[&](const std::string& n,std::uint8_t bytes,bool sign){auto v=Type::integer(n,bytes,bytes,sign);if(!v)fail(v.error().code,v.error().message);put(n,v.value());};
        add_int("char",o_.char_bytes,true); add_int("signed char",o_.char_bytes,true); add_int("unsigned char",o_.char_bytes,false);
        add_int("short",o_.short_bytes,true); add_int("short int",o_.short_bytes,true); add_int("signed short",o_.short_bytes,true); add_int("signed short int",o_.short_bytes,true); add_int("unsigned short",o_.short_bytes,false); add_int("unsigned short int",o_.short_bytes,false);
        add_int("int",o_.int_bytes,true); add_int("signed",o_.int_bytes,true); add_int("signed int",o_.int_bytes,true); add_int("unsigned",o_.int_bytes,false); add_int("unsigned int",o_.int_bytes,false);
        add_int("long",o_.long_bytes,true); add_int("long int",o_.long_bytes,true); add_int("signed long",o_.long_bytes,true); add_int("signed long int",o_.long_bytes,true); add_int("unsigned long",o_.long_bytes,false); add_int("unsigned long int",o_.long_bytes,false);
        add_int("long long",o_.long_long_bytes,true); add_int("long long int",o_.long_long_bytes,true); add_int("signed long long",o_.long_long_bytes,true); add_int("signed long long int",o_.long_long_bytes,true); add_int("unsigned long long",o_.long_long_bytes,false); add_int("unsigned long long int",o_.long_long_bytes,false);
        const auto natural_float_alignment = [](std::uint8_t size, std::uint8_t requested) {
            return static_cast<std::uint64_t>(requested ? requested : size);
        };
        auto f=Type::floating("float",o_.float_bytes,natural_float_alignment(o_.float_bytes,o_.float_alignment));
        auto d=Type::floating("double",o_.double_bytes,natural_float_alignment(o_.double_bytes,o_.double_alignment));
        auto ld=Type::floating("long double",o_.long_double_bytes,natural_float_alignment(o_.long_double_bytes,o_.long_double_alignment));
        if(!f||!d||!ld)fail(ErrorCode::invalid_argument,"invalid floating-point ABI sizes or alignments");
        put("float",f.value());put("double",d.value());put("long double",ld.value());
        auto b=Type::boolean(1,1); if(!b)fail(b.error().code,b.error().message); put("_Bool",b.value());put("bool",b.value());
        names_.emplace("size_t",Type::integer("size_t",o_.pointer_bytes,o_.pointer_bytes,false).value());
        names_.emplace("ssize_t",Type::integer("ssize_t",o_.pointer_bytes,o_.pointer_bytes,true).value());
        names_.emplace("ptrdiff_t",Type::integer("ptrdiff_t",o_.pointer_bytes,o_.pointer_bytes,true).value());
        names_.emplace("intptr_t",Type::integer("intptr_t",o_.pointer_bytes,o_.pointer_bytes,true).value());
        names_.emplace("uintptr_t",Type::integer("uintptr_t",o_.pointer_bytes,o_.pointer_bytes,false).value());
        for (const auto [bits,bytes] : {std::pair<unsigned,std::uint8_t>{8,o_.char_bytes},{16,o_.short_bytes},{32,o_.int_bytes},{64,o_.long_long_bytes}}) {
            auto si=Type::integer("int"+std::to_string(bits)+"_t",bytes,bytes,true);
            auto ui=Type::integer("uint"+std::to_string(bits)+"_t",bytes,bytes,false);
            if(!si||!ui)fail(ErrorCode::invalid_argument,"invalid standard integer alias sizes");
            names_.emplace("int"+std::to_string(bits)+"_t",si.value());
            names_.emplace("uint"+std::to_string(bits)+"_t",ui.value());
        }
    }
    bool qualifier_or_storage()const{return at("const")||at("volatile")||at("restrict")||at("__restrict")||at("__restrict__")||at("_Atomic")||at("typedef")||at("extern")||at("static")||at("inline");}
    Base parse_base(bool allow_member_alignment=false){
        enter(); consume_standard_attributes(); bool is_typedef=false,is_static=false,is_inline=false; std::uint8_t qualifiers=0;
        while(at("__declspec")||at("__attribute__")||alignment_specifier()) { if(alignment_specifier())parse_alignment_specifier();else if(parse_attribute())prefix_packed_=true; }
        while(qualifier_or_storage()||at("__declspec")||at("__attribute__")||alignment_specifier()) {
            if(alignment_specifier()){parse_alignment_specifier();continue;}
            if(at("__declspec")||at("__attribute__")){if(parse_attribute())prefix_packed_=true;continue;}
            if(take("typedef"))is_typedef=true;
            else if(take("static")){is_static=true;}
            else if(take("inline"))is_inline=true;
            else if(take("extern")){}
            else if(take("const"))qualifiers|=static_cast<std::uint8_t>(Qualifier::const_);
            else if(take("volatile"))qualifiers|=static_cast<std::uint8_t>(Qualifier::volatile_);
            else if(take("restrict")||take("__restrict")||take("__restrict__"))qualifiers|=static_cast<std::uint8_t>(Qualifier::restrict_);
            else if(take("_Atomic"))qualifiers|=static_cast<std::uint8_t>(Qualifier::atomic_);
            else ++pos_;
        }
        const bool dependent_typename=take("typename");
        if(dependent_typename&&(!identifier(peek().text)&&!at("::")))syntax("typename requires a qualified type name");
        TypePtr base;
        bool typename_resolved=false;
        if(take("struct")||take("union")||take("class")) {
            const auto aggregate_keyword=t_[pos_-1].text;
            base=parse_aggregate(aggregate_keyword=="union",aggregate_keyword=="class");
        }
        else if(take("enum")) base=parse_enum();
        else if(at("unsigned")||at("signed")||at("short")||at("long")||at("int")||at("char")||at("float")||at("double")||at("void")||at("_Bool")||at("bool")) base=parse_builtin();
        else if(identifier(peek().text)||at("::")) {
            auto type_name=parse_lookup_name();
            if (template_pack_bindings_.contains(type_name))
                fail(ErrorCode::unsupported, "parameter packs require a template argument pack expansion");
            if (auto binding = template_type_bindings_.find(type_name); binding != template_type_bindings_.end()) {
                base = binding->second;
                if (at("<")) fail(ErrorCode::unsupported, "template parameters cannot be used as template names");
            } else if (auto template_binding = template_template_bindings_.find(type_name);
                       template_binding != template_template_bindings_.end()) {
                if (!at("<")) fail(ErrorCode::malformed, "template-template parameter requires a template argument list");
                const auto &bound_name = template_binding->second;
                if (auto definition = aggregate_templates_.find(bound_name); definition != aggregate_templates_.end()) {
                    auto arguments = parse_template_arguments(definition->second.parameters);
                    base = instantiate_template_aggregate(bound_name, arguments);
                } else if (template_aliases_.contains(bound_name)) {
                    base = instantiate_template_alias(bound_name, parse_template_arguments(template_aliases_.at(bound_name).parameters));
                } else {
                    fail(ErrorCode::unsupported, "bound template-template argument is not an instantiable template");
                }
            } else if (at("<")) {
                const auto template_name = resolve_template_name(type_name);
                if (template_name.empty())
                    fail(ErrorCode::unsupported, "unknown class or alias template '" + type_name + "'");
                if (template_aliases_.contains(template_name))
                    base = instantiate_template_alias(template_name, parse_template_arguments(template_aliases_.at(template_name).parameters));
                else {
                    auto definition = aggregate_templates_.find(template_name);
                    if (definition == aggregate_templates_.end()) fail(ErrorCode::unsupported, "unknown class template '" + type_name + "'");
                    auto arguments = parse_template_arguments(definition->second.parameters);
                    base = instantiate_template_aggregate(template_name, arguments);
                }
            } else base=lookup_type(type_name);
            if(!base)syntax("unknown type name '"+type_name+"'");
            bool member_qualified=type_name.find("::")!=std::string::npos;
            while(take("::")){
                member_qualified=true;
                if(take("template"))fail(ErrorCode::unsupported,"member alias templates are unsupported");
                if(!identifier(peek().text))syntax("expected a member type name after '::'");
                const auto member=next().text;
                const auto *owner=unqualified(base.get());
                if(owner&&owner->kind()==Kind::named_reference){
                    auto found=names_.find(owner->name());owner=found==names_.end()?nullptr:unqualified(found->second.get());
                }
                if(!owner||(owner->kind()!=Kind::structure&&owner->kind()!=Kind::union_type))
                    fail(ErrorCode::unsupported,"qualified member type requires a known aggregate");
                base=lookup_qualified_type(owner->name()+"::"+member);
                if(!base)fail(ErrorCode::unsupported,"unknown aggregate member type '"+member+"'");
            }
            if(dependent_typename&&!member_qualified)syntax("typename requires a qualified member type");
            typename_resolved=member_qualified;
            if(base->kind()==Kind::named_reference){auto target=names_.find(base->name());if(target!=names_.end()&&target->second->size())base=target->second;}
            if((base->kind()==Kind::structure||base->kind()==Kind::union_type)&&!base->size()){
                auto reference=Type::named_reference(std::string(base->kind()==Kind::union_type?"union ":"struct ")+base->name());
                if(!reference)fail(reference.error().code,reference.error().message);
                base=reference.value();
            }
        }
        else syntax("expected a supported type specifier");
        if(dependent_typename&&!typename_resolved)syntax("typename requires a qualified member type");
        if(pending_vector_size_){
            if(!is_typedef)fail(ErrorCode::unsupported,"prefix vector_size attributes require a typedef declaration");
            const auto bytes=*pending_vector_size_;pending_vector_size_.reset();base=make_vector_type(std::move(base),bytes);
        }
        if(prefix_packed_&&base->kind()!=Kind::structure&&base->kind()!=Kind::union_type&&!allow_member_alignment){prefix_packed_=false;fail(ErrorCode::unsupported,"packed attributes are supported only on aggregate types or aggregate members");}
        if(qualifiers){auto qualified=Type::qualified(std::move(base),qualifiers);if(!qualified)fail(qualified.error().code,qualified.error().message);base=qualified.value();}
        leave();return {std::move(base),is_typedef,is_static,is_inline};
    }
    TypePtr parse_builtin(){
        std::vector<std::string> words;
        while(at("unsigned")||at("signed")||at("short")||at("long")||at("int")||at("char")||at("float")||at("double")||at("void")||at("_Bool")||at("bool")) words.push_back(next().text);
        if(words.empty())syntax("expected scalar type");
        if(words.size()==1){auto it=names_.find(words[0]);if(it!=names_.end())return it->second;}
        const auto float_count = static_cast<unsigned>(std::count(words.begin(), words.end(), "float"));
        const auto double_count = static_cast<unsigned>(std::count(words.begin(), words.end(), "double"));
        if (float_count || double_count) {
            const bool is_float = words.size() == 1 && words.front() == "float";
            const bool is_double = words.size() == 1 && words.front() == "double";
            const bool is_long_double = words.size() == 2 && words[0] == "long" && words[1] == "double";
            if (is_float) return names_.at("float");
            if (is_double) return names_.at("double");
            if (is_long_double) return names_.at("long double");
            syntax("invalid floating type specifiers");
        }
        if(std::find(words.begin(),words.end(),"void")!=words.end()||std::find(words.begin(),words.end(),"char")!=words.end()||std::find(words.begin(),words.end(),"_Bool")!=words.end()||std::find(words.begin(),words.end(),"bool")!=words.end()){
            std::string spelling;for(auto&w:words){if(!spelling.empty())spelling+=' ';spelling+=w;}auto it=names_.find(spelling);if(it!=names_.end())return it->second;syntax("invalid scalar type spelling '"+spelling+"'");
        }
        unsigned longs=static_cast<unsigned>(std::count(words.begin(),words.end(),"long")), shorts=static_cast<unsigned>(std::count(words.begin(),words.end(),"short")), signs=static_cast<unsigned>(std::count(words.begin(),words.end(),"signed")+std::count(words.begin(),words.end(),"unsigned"));
        if(longs>2||shorts>1||longs&&shorts||signs>1)syntax("invalid integer type specifiers");
        std::uint8_t bytes=longs==2?o_.long_long_bytes:longs?o_.long_bytes:shorts?o_.short_bytes:o_.int_bytes;
        bool sign=std::find(words.begin(),words.end(),"unsigned")==words.end();
        std::string name=(sign?"signed ":"unsigned ")+(longs==2?std::string("long long"):longs?std::string("long"):shorts?std::string("short"):std::string("int"));
        auto p=Type::integer(name,bytes,bytes,sign);if(!p)fail(p.error().code,p.error().message);return p.value();
    }
    TypePtr parse_aggregate(bool is_union, bool is_class=false){
        // GCC and Clang accept this placement between the aggregate keyword
        // and its tag. Keep the accepted attribute grammar deliberately small
        // so unknown layout attributes cannot silently produce a wrong ABI.
        bool packed=prefix_packed_;prefix_packed_=false;std::uint64_t requested_alignment=pending_aggregate_alignment_.value_or(0);pending_aggregate_alignment_.reset();
        while(at("__declspec")||at("__attribute__")){
            if(parse_attribute())packed=true;
            if(pending_aggregate_alignment_){requested_alignment=std::max(requested_alignment,*pending_aggregate_alignment_);pending_aggregate_alignment_.reset();}
        }
        const bool anonymous_tag = !identifier(peek().text) && !at("::");
        std::string tag;
        if (anonymous_tag) {
            if (!at("{"))
                fail(ErrorCode::malformed, "an anonymous struct/union requires a definition body");
            if (next_anonymous_aggregate_id_ == std::numeric_limits<std::uint32_t>::max())
                fail(ErrorCode::resource_limit, "anonymous aggregate count exceeds its identity limit");
            tag = "@anonymous_aggregate_" + std::to_string(next_anonymous_aggregate_id_++);
            if (!aggregate_scopes_.empty()) tag = aggregate_scopes_.back() + "::" + tag;
            else if (!current_namespace().empty()) tag = current_namespace() + "::" + tag;
        } else tag=parse_qualified_name();
        if (at("<")) {
            if (template_instance_name_.empty()) {
                const auto template_name = resolve_template_name(tag);
                if (template_name.empty())
                    fail(ErrorCode::unsupported, "unknown class template '" + tag + "'");
                auto definition = aggregate_templates_.find(template_name);
                if (definition == aggregate_templates_.end())
                    fail(ErrorCode::unsupported, "struct/union declaration cannot instantiate an alias template");
                auto arguments = parse_template_arguments(definition->second.parameters);
                return instantiate_template_aggregate(template_name, arguments);
            }
            std::size_t depth = 0;
            do {
                if (take("<")) ++depth;
                else if (take(">")) --depth;
                else if (at("<eof>")) syntax("unterminated template specialization name");
                else ++pos_;
            } while (depth);
            if (tag != template_instance_base_name_)
                fail(ErrorCode::unsupported, "nested template aggregate names are unsupported in a specialization body");
            tag = template_instance_name_;
        } else if (!template_instance_name_.empty() && tag == template_instance_base_name_) {
            tag = template_instance_name_;
        }
        std::string key=(is_union?"union ":"struct ")+tag;
        while(at("__declspec")||at("__attribute__")){
            if(parse_attribute())packed=true;
            if(pending_aggregate_alignment_){requested_alignment=std::max(requested_alignment,*pending_aggregate_alignment_);pending_aggregate_alignment_.reset();}
        }
        if(!take("{")){
            if(packed||requested_alignment)fail(ErrorCode::unsupported,"layout attributes on forward aggregate references are unsupported");
            auto existing=names_.find(key);
            if(!aggregate_scopes_.empty()&&existing==names_.end())
                fail(ErrorCode::unsupported,"new nested aggregate declarations are unsupported");
            if(existing!=names_.end()&&existing->second->size())return existing->second;
            if(existing==names_.end()) {
                auto incomplete=Type::incomplete_aggregate(is_union?Kind::union_type:Kind::structure,tag);
                if(!incomplete)fail(incomplete.error().code,incomplete.error().message);
                register_tag_type(is_union?"union":"struct",tag,incomplete.value(),is_class);
            }
            auto reference=Type::named_reference(key);if(!reference)fail(reference.error().code,reference.error().message);
            return reference.value();
        }
        if(!aggregate_scopes_.empty()&&!anonymous_tag)
            fail(ErrorCode::unsupported,"nested named aggregate definitions are unsupported");
        if(auto existing=names_.find(key);existing!=names_.end()&&existing->second->size())
            fail(ErrorCode::conflict,"duplicate aggregate tag '"+key+"'");
        if(!names_.contains(key)){
            auto incomplete=Type::incomplete_aggregate(is_union?Kind::union_type:Kind::structure,tag);
            if(!incomplete)fail(incomplete.error().code,incomplete.error().message);
            register_tag_type(is_union?"union":"struct",tag,incomplete.value(),is_class);
        }
        aggregate_scopes_.push_back(tag);
        bool cpp_declarations=is_class;
        std::uint32_t declaration_ordinal=0;
        std::vector<StaticDataMember> static_members;
        std::vector<Member> members;std::vector<Method> methods;std::set<std::string> member_names;std::uint64_t offset=0,max_size=0,max_align=1;
        auto access=is_class?MemberAccess::private_:MemberAccess::public_;
        std::set<std::string> method_names;
        struct BitfieldUnit { std::uint64_t type_id=0,size=0,alignment=1,offset=0,used=0; };
        std::optional<BitfieldUnit> bitfield_unit;
        while(!take("}")){
            if(at("<eof>"))syntax("unterminated aggregate");
            consume_standard_attributes();
            if(at("static_assert")||at("_Static_assert")){
                if(at("static_assert"))cpp_declarations=true;
                parse_static_assert();
                ++declaration_ordinal;
                continue;
            }
            // Consume prefix layout attributes before pack detection. Ordinary
            // declarations use the same pending state below; this also lets a
            // direct type-pack member expansion apply those attributes per field.
            while(at("__declspec")||at("__attribute__")||alignment_specifier()) {
                if(alignment_specifier())parse_alignment_specifier();
                else if(parse_attribute())prefix_packed_=true;
            }
            if((at("public")||at("protected")||at("private"))&&peek(1).text==":") {
                cpp_declarations=true;
                const auto label=next().text;next();
                access=label=="public"?MemberAccess::public_:label=="protected"?MemberAccess::protected_:MemberAccess::private_;
                continue;
            }
            if(identifier(peek().text)&&peek(1).text=="..."&&template_pack_bindings_.contains(peek().text)) {
                const auto pack_name=next().text;need("...");
                if(!identifier(peek().text))syntax("data-member pack expansion requires a member name");
                const auto member_name=next().text;
                if(!at(";"))fail(ErrorCode::unsupported,"data-member pack expansion supports only a direct type pack followed by one member name");
                need(";");
                const bool packed_member=prefix_packed_;
                prefix_packed_=false;
                const auto member_alignment=pending_aggregate_alignment_;
                pending_aggregate_alignment_.reset();
                if(pending_vector_size_)
                    fail(ErrorCode::unsupported,"vector_size attributes on data-member pack expansions are unsupported");
                const auto &pack=template_pack_bindings_.at(pack_name);
                if(pack.size()>32)fail(ErrorCode::resource_limit,"data-member pack expansion exceeds 32 fields");
                cpp_declarations=true;
                for(std::size_t pack_index=0;pack_index<pack.size();++pack_index) {
                    const auto &argument=pack[pack_index];
                    if(!argument.type||argument.value||!argument.template_name.empty())
                        fail(ErrorCode::unsupported,"data-member pack expansion supports type arguments only");
                    const auto *object=unqualified(argument.type.get());
                    if(!object||object->kind()==Kind::void_type||object->kind()==Kind::function||!argument.type->size())
                        fail(ErrorCode::unsupported,"data-member pack elements must be complete object types");
                    const auto expanded_name=member_name+"__pack"+std::to_string(pack_index);
                    if(method_names.contains(expanded_name)||!member_names.insert(expanded_name).second)
                        fail(ErrorCode::conflict,"duplicate expanded data member '"+expanded_name+"'");
                    bitfield_unit.reset();
                    const auto size=*argument.type->size();
                    auto alignment=packed?std::uint64_t{1}:argument.type->alignment();
                    if(packed_member)alignment=member_alignment.value_or(1);
                    else if(member_alignment)alignment=std::max(alignment,*member_alignment);
                    if(pack_cap_&&!member_alignment)alignment=std::min(alignment,pack_cap_);
                    max_align=std::max(max_align,alignment);
                    std::uint64_t field_offset=0;
                    if(is_union)max_size=std::max(max_size,size);
                    else {
                        const auto remainder=offset%alignment;
                        if(remainder&&offset>UINT64_MAX-(alignment-remainder))fail(ErrorCode::overflow,"aggregate layout overflows");
                        field_offset=remainder?offset+(alignment-remainder):offset;
                        if(field_offset>UINT64_MAX-size)fail(ErrorCode::overflow,"aggregate layout overflows");
                        offset=field_offset+size;
                    }
                    std::optional<std::uint64_t> effective_alignment;
                    if(alignment!=argument.type->alignment()||member_alignment||packed_member||packed)
                        effective_alignment=alignment;
                    members.push_back({expanded_name,argument.type,field_offset,std::nullopt,std::nullopt,effective_alignment,{},access});
                    ++declaration_ordinal;
                }
                continue;
            }
            if(take("using")){
                cpp_declarations=true;
                if(at("namespace")||at("typename")||peek(1).text!="=")
                    fail(ErrorCode::unsupported,"class using declarations require an ordinary 'using Name = Type' alias");
                const auto alias=next().text;
                if(!identifier(alias))syntax("expected a class alias name");
                need("=");auto base=parse_base();
                if(base.is_typedef||base.is_static||base.is_inline)syntax("storage specifiers are invalid in a member type alias");
                auto declaration=parse_declarator(base.type,true);
                if(!declaration.name.empty())syntax("member using alias requires an abstract type");
                declaration.type=apply_pending_function_convention(std::move(declaration.type));
                if(prefix_packed_||pending_aggregate_alignment_||pending_vector_size_)
                    fail(ErrorCode::unsupported,"layout attributes on member using aliases are unsupported");
                need(";");register_member_alias(tag,alias,std::move(declaration.type),member_names,method_names);
                ++declaration_ordinal;
                continue;
            }
            consume_standard_attributes();
            const bool virtual_specifier = take("virtual");
            auto b=parse_base(true);
            consume_standard_attributes();
            if(virtual_specifier&&b.is_static)fail(ErrorCode::malformed,"static member functions cannot be virtual");
            if(b.is_typedef&&(b.is_static||b.is_inline))syntax("member typedef cannot have static or inline storage");
            if(take(";")) {
                if(b.is_typedef||b.is_static||b.is_inline)
                    syntax("anonymous aggregate member cannot have typedef or storage specifiers");
                if(is_class)
                    fail(ErrorCode::unsupported,"C++ class anonymous aggregate members are unsupported");
                if(prefix_packed_||pending_aggregate_alignment_||pending_vector_size_)
                    fail(ErrorCode::unsupported,"layout attributes on anonymous aggregate members are unsupported");
                const auto *anonymous_type=unqualified(b.type.get());
                if(!anonymous_type||(anonymous_type->kind()!=Kind::structure&&anonymous_type->kind()!=Kind::union_type))
                    fail(ErrorCode::malformed,"declaration without a member name requires a struct or union type");
                if(!b.type->size())
                    fail(ErrorCode::unsupported,"anonymous aggregate members require a complete child type");

                std::set<std::string> promoted_names;
                std::function<void(const Type &,unsigned)> collect_promoted = [&](const Type &aggregate,unsigned depth) {
                    if(depth>64)fail(ErrorCode::resource_limit,"anonymous aggregate promotion nesting exceeds 64");
                    if(aggregate.kind()!=Kind::structure&&aggregate.kind()!=Kind::union_type)return;
                    for(const auto &nested:aggregate.members()) {
                        if(nested.anonymous) {
                            const Type *child=unqualified(nested.type.get());
                            if(child&&child->kind()==Kind::named_reference) {
                                const auto found=names_.find(child->name());
                                child=found==names_.end()?nullptr:unqualified(found->second.get());
                            }
                            if(!child)fail(ErrorCode::malformed,"anonymous aggregate member has an unresolved child type");
                            collect_promoted(*child,depth+1);
                        } else if(!nested.name.empty()&&!promoted_names.insert(nested.name).second) {
                            fail(ErrorCode::conflict,"ambiguous promoted member '"+nested.name+"' in anonymous aggregate");
                        }
                    }
                };
                collect_promoted(*anonymous_type,0);
                for(const auto &name:promoted_names)
                    if(member_names.contains(name)||method_names.contains(name))
                        fail(ErrorCode::conflict,"anonymous aggregate promotes duplicate member '"+name+"'");

                bitfield_unit.reset();
                auto member_alignment=anonymous_type->alignment();
                if(packed)member_alignment=1;
                else if(pack_cap_)member_alignment=std::min(member_alignment,pack_cap_);
                max_align=std::max(max_align,member_alignment);
                std::uint64_t field_offset=0;
                if(is_union)max_size=std::max(max_size,*b.type->size());
                else {
                    const auto remainder=offset%member_alignment;
                    if(remainder&&offset>UINT64_MAX-(member_alignment-remainder))
                        fail(ErrorCode::overflow,"anonymous aggregate member alignment overflows");
                    field_offset=remainder?offset+(member_alignment-remainder):offset;
                    if(field_offset>UINT64_MAX-*b.type->size())
                        fail(ErrorCode::overflow,"anonymous aggregate member extent overflows");
                    offset=field_offset+*b.type->size();
                }
                std::optional<std::uint64_t> effective_alignment;
                if(member_alignment!=b.type->alignment())effective_alignment=member_alignment;
                members.push_back({{},b.type,field_offset,std::nullopt,std::nullopt,effective_alignment,{},access,true});
                member_names.insert(promoted_names.begin(),promoted_names.end());
                ++declaration_ordinal;
                continue;
            }
            bool declaration_packed = prefix_packed_;
            prefix_packed_ = false;
            auto declaration_alignment = pending_aggregate_alignment_;
            pending_aggregate_alignment_.reset();
            for(;;){
                const auto source_ordinal=declaration_ordinal++;
                bool packed_member=declaration_packed;
                std::optional<std::uint64_t> member_alignment=declaration_alignment;
                declaration_packed=false;
                declaration_alignment.reset();
                while(at("__attribute__")||at("__declspec"))packed_member=parse_attribute()||packed_member;
                if(pending_aggregate_alignment_){member_alignment=std::max(member_alignment.value_or(0),*pending_aggregate_alignment_);pending_aggregate_alignment_.reset();}
                consume_standard_attributes();
                auto d=parse_declarator(b.type,true);
                consume_standard_attributes();
                while(at("__attribute__")||at("__declspec"))packed_member=parse_attribute()||packed_member;
                if(pending_aggregate_alignment_){member_alignment=std::max(member_alignment.value_or(0),*pending_aggregate_alignment_);pending_aggregate_alignment_.reset();}
                d.type=apply_pending_vector_size(std::move(d.type),b.is_typedef);
                d.type=apply_pending_function_convention(std::move(d.type));
                if(virtual_specifier&&!d.function)fail(ErrorCode::malformed,"virtual specifier requires a member function declaration");
                if(b.is_typedef){
                    cpp_declarations=true;
                    if(packed_member)fail(ErrorCode::unsupported,"packed member typedefs are unsupported");
                    if(at(":")||at("=")||at("{"))fail(ErrorCode::unsupported,"member typedefs cannot have bitfields, initializers or bodies");
                    d.type=apply_alignment(std::move(d.type),member_alignment);
                    register_member_alias(tag,d.name,std::move(d.type),member_names,method_names);
                    if(!take(","))break;
                    continue;
                }
                if(d.function) {
                    if(packed_member||member_alignment)fail(ErrorCode::unsupported,"layout attributes cannot be applied to method declarations");
                    bool pure_virtual = false;
                    if(take("=")) {
                        if(next().text!="0")fail(ErrorCode::unsupported,"only pure-virtual '= 0' method declarations are supported");
                        if(!virtual_specifier)fail(ErrorCode::malformed,"pure-specifier requires the virtual keyword");
                        if(b.is_static)fail(ErrorCode::malformed,"static member functions cannot be pure virtual");
                        need("0");
                        need(";");
                        pure_virtual = true;
                    }
                    else if(virtual_specifier)fail(ErrorCode::unsupported,"only pure virtual methods are supported");
                    else if(at("{"))fail(ErrorCode::unsupported,"C++ method definitions and bodies are unsupported");
                    if(member_names.contains(d.name))fail(ErrorCode::conflict,"duplicate aggregate field or method '"+d.name+"'");
                    method_names.insert(d.name);
                    cpp_declarations=true;
                    Method method;method.name=d.name;method.signature=d.type;method.access=access;method.is_static=b.is_static;
                    if(pure_virtual)method.dispatch=MemberDispatch::pure_virtual;
                    method.declaration_ordinal=source_ordinal;
                    if(!method.is_static) {
                        auto owner=Type::named_reference(key);if(!owner)fail(owner.error().code,owner.error().message);
                        auto self=Type::pointer(owner.value(),o_.pointer_bytes,o_.pointer_bytes);if(!self)fail(self.error().code,self.error().message);
                        method.this_type=self.value();
                    }
                    methods.push_back(std::move(method));
                    break;
                }
                if(b.is_inline&&!b.is_static)fail(ErrorCode::unsupported,"inline data-member declarations are unsupported");
                if(b.is_static){
                    cpp_declarations=true;
                    if(b.is_inline)fail(ErrorCode::unsupported,"inline static variable definitions are unsupported");
                    if(d.name.empty())syntax("static data member requires a name");
                    if(packed_member||member_alignment)fail(ErrorCode::unsupported,"static data alignment attributes cannot be retained by the member metadata");
                    if(at(":")||at("=")||at("{"))fail(ErrorCode::unsupported,"static data bitfields and in-class initializers are unsupported");
                    const auto *object=unqualified(d.type.get());
                    if(!object||object->kind()==Kind::void_type||object->kind()==Kind::function)
                        fail(ErrorCode::malformed,"static data member requires an object type");
                    if(d.name==injected_aggregate_name(tag)||template_type_bindings_.contains(d.name)||
                       template_value_bindings_.contains(d.name)||template_template_bindings_.contains(d.name)||
                       template_pack_bindings_.contains(d.name)||method_names.contains(d.name)||!member_names.insert(d.name).second)
                        fail(ErrorCode::conflict,"duplicate aggregate type or member '"+d.name+"'");
                    const auto qualified=tag+"::"+d.name;
                    if(names_.contains(qualified)||result_.symbols.contains(qualified)||result_.enum_constants.contains(qualified))
                        fail(ErrorCode::conflict,"duplicate static data member '"+qualified+"'");
                    StaticDataMember member;member.name=d.name;member.type=d.type;member.access=access;
                    member.declaration_ordinal=source_ordinal;
                    static_members.push_back(std::move(member));
                    result_.symbols.emplace(qualified,HeaderSymbol{HeaderSymbolKind::object,d.type});
                    // No bitfield-unit reset: a static declaration introduces
                    // no instance member between adjacent allocation-unit fields.
                    if(!take(","))break;
                    continue;
                }
                std::optional<std::uint32_t> bit_width, bit_offset;
                if(take(":")) {
                    if(!o_.target_abi)fail(ErrorCode::unsupported,"bitfield layout requires an explicit target ABI");
                    const auto width_expression = take_integer_expression_until_bitfield_delimiter();
                    auto width_bindings = enum_value_bindings_;
                    for (const auto &[name, value] : template_value_bindings_)
                        if (value <= static_cast<std::uint64_t>(INT64_MAX))
                            width_bindings.insert_or_assign(name, static_cast<std::int64_t>(value));
                    const auto width_value = evaluate_integer_expression(
                        width_expression, width_bindings, [&](std::string_view name) {
                            if (const auto value = resolve_enum_expression_name(name, width_bindings)) return value;
                            const auto parameter = template_value_bindings_.find(std::string(name));
                            if (parameter != template_value_bindings_.end() && parameter->second >
                                static_cast<std::uint64_t>(INT64_MAX))
                                fail(ErrorCode::overflow, "bitfield width template value exceeds the supported signed expression range");
                            return std::optional<std::int64_t>{};
                        });
                    if(width_value<0||static_cast<std::uint64_t>(width_value)>UINT32_MAX)
                        fail(ErrorCode::unsupported,"bitfield width is outside the supported range");
                    const auto width=static_cast<std::uint32_t>(width_value);
                    const auto *storage=unqualified(d.type.get());
                    const Type *integer_storage=storage;
                    if(storage&&storage->kind()==Kind::enumeration&&storage->element())integer_storage=unqualified(storage->element().get());
                    if(!integer_storage||(integer_storage->kind()!=Kind::integer&&integer_storage->kind()!=Kind::boolean)||!d.type->size())
                        fail(ErrorCode::unsupported,"bitfield base type must have integer storage");
                    if(*d.type->size()>UINT64_MAX/8)
                        fail(ErrorCode::overflow,"bitfield storage width overflows");
                    const auto storage_bits=*d.type->size()*8;
                    if(!width) {
                        if(!d.name.empty())fail(ErrorCode::unsupported,"zero-width bitfields must be unnamed");
                        if(is_union)fail(ErrorCode::unsupported,"zero-width union bitfields are unsupported");
                        auto al=packed?std::uint64_t{1}:d.type->alignment();
                        if(packed_member)al=member_alignment.value_or(1);else if(member_alignment)al=std::max(al,*member_alignment);
                        if(pack_cap_&&!member_alignment)al=std::min(al,pack_cap_);
                        const auto rem=offset%al;if(rem&&offset>UINT64_MAX-(al-rem))fail(ErrorCode::overflow,"bitfield barrier alignment overflows");
                        if(rem)offset+=al-rem;
                        bitfield_unit.reset();
                        if(!take(","))break;
                        continue;
                    }
                    if(width>storage_bits)fail(ErrorCode::unsupported,"bitfield width exceeds its declared storage type");
                    if(!d.name.empty()&&!member_names.insert(d.name).second)fail(ErrorCode::conflict,"duplicate aggregate field '"+d.name+"'");
                    auto al=packed?std::uint64_t{1}:d.type->alignment();
                    if(packed_member)al=member_alignment.value_or(1);else if(member_alignment)al=std::max(al,*member_alignment);
                    if(pack_cap_&&!member_alignment)al=std::min(al,pack_cap_);
                    max_align=std::max(max_align,al);
                    std::uint64_t field_off=0;
                    if(is_union){field_off=0;bit_offset=0;max_size=std::max(max_size,*d.type->size());}
                    else {
                        const bool can_share=bitfield_unit&&bitfield_unit->type_id==d.type->id()&&
                            bitfield_unit->size==*d.type->size()&&bitfield_unit->alignment==al&&
                            width<=storage_bits-bitfield_unit->used;
                        if(can_share){field_off=bitfield_unit->offset;bit_offset=static_cast<std::uint32_t>(bitfield_unit->used);bitfield_unit->used+=width;}
                        else {
                            const auto rem=offset%al;if(rem&&offset>UINT64_MAX-(al-rem))fail(ErrorCode::overflow,"bitfield storage alignment overflows");
                            field_off=rem?offset+(al-rem):offset;
                            if(field_off>UINT64_MAX-*d.type->size())fail(ErrorCode::overflow,"bitfield storage extent overflows");
                            offset=field_off+*d.type->size();
                            bit_offset=0;
                            bitfield_unit=BitfieldUnit{d.type->id(),*d.type->size(),al,field_off,width};
                        }
                    }
                    std::optional<std::uint64_t> effective_alignment;
                    if(al!=d.type->alignment()||member_alignment||packed_member||packed)effective_alignment=al;
                    members.push_back({d.name,d.type,field_off,width,bit_offset,effective_alignment,{},access});
                    if(!take(","))break;
                    continue;
                }
                if(d.function)fail(ErrorCode::unsupported,"function-valued aggregate fields are unsupported");
                if(d.name.empty())syntax("aggregate field requires a name");
                if(method_names.contains(d.name))fail(ErrorCode::conflict,"duplicate aggregate field or method '"+d.name+"'");
                bitfield_unit.reset();
                if(!member_names.insert(d.name).second)fail(ErrorCode::conflict,"duplicate aggregate field '"+d.name+"'");
                const bool flexible=d.type->kind()==Kind::array&&d.type->count()==0&&!d.type->size();
                if(!d.type->size()&&!flexible)fail(ErrorCode::unsupported,"aggregate fields must have a complete object type");
                if(flexible&&is_union)fail(ErrorCode::unsupported,"flexible array members are invalid in unions");
                const auto sz=d.type->size().value_or(0);
                auto al=packed?std::uint64_t{1}:d.type->alignment();
                if(packed_member)al=member_alignment.value_or(1);
                else if(member_alignment)al=std::max(al,*member_alignment);
                if(pack_cap_&&!member_alignment)al=std::min(al,pack_cap_);
                max_align=std::max(max_align,al);std::uint64_t field_off=0;
                if(!is_union){auto rem=offset%al;if(rem&&offset>UINT64_MAX-(al-rem))fail(ErrorCode::overflow,"aggregate layout overflows");field_off=rem?offset+(al-rem):offset;if(field_off>UINT64_MAX-sz)fail(ErrorCode::overflow,"aggregate layout overflows");offset=field_off+sz;}else max_size=std::max(max_size,sz);
                std::optional<std::uint64_t> effective_alignment;
                if(al!=d.type->alignment()||member_alignment||packed_member||packed)
                    effective_alignment=al;
                members.push_back({d.name,d.type,field_off,std::nullopt,std::nullopt,effective_alignment,{},access});if(!take(","))break;
            } need(";");
        }
        aggregate_scopes_.pop_back();
        while(at("__attribute__")||at("__declspec")){
            if(parse_attribute())packed=true;
            if(pending_aggregate_alignment_){requested_alignment=std::max(requested_alignment,*pending_aggregate_alignment_);pending_aggregate_alignment_.reset();}
        }
        if(members.empty()&&methods.empty()&&static_members.empty()&&!cpp_declarations)fail(ErrorCode::unsupported,"empty aggregates are unsupported");
        max_align=std::max(max_align,requested_alignment);std::uint64_t size=is_union?max_size:offset;
        // Methods, aliases and static data introduce no object subobjects;
        // retain the existing one-byte C++ empty-object representation.
        if(members.empty()&&!size)size=1;
        auto rem=size%max_align;if(rem){if(size>UINT64_MAX-(max_align-rem))fail(ErrorCode::overflow,"aggregate size overflows");size+=max_align-rem;}
        const auto aggregate_pack=packed?std::optional<std::uint64_t>{1}:(pack_cap_?std::optional<std::uint64_t>{pack_cap_}:std::nullopt);
        auto p=is_union?Type::union_type(tag,std::move(members),size,max_align,aggregate_pack):Type::structure(tag,std::move(members),size,max_align,aggregate_pack);if(!p)fail(p.error().code,p.error().message);
        auto completed=p.value();
        if(!methods.empty()){auto with_methods=Type::with_methods(completed,std::move(methods));if(!with_methods)fail(with_methods.error().code,with_methods.error().message);completed=with_methods.value();}
        if(!static_members.empty()){auto with_static=Type::with_static_data_members(completed,std::move(static_members));if(!with_static)fail(with_static.error().code,with_static.error().message);completed=with_static.value();}
        register_tag_type(is_union?"union":"struct",tag,completed,cpp_declarations);return completed;
    }
    std::vector<Token> take_integer_expression_until(std::string_view delimiter, bool template_delimiters) {
        std::vector<Token> expression;
        std::size_t parentheses = 0;
        while (!at("<eof>")) {
            const bool terminal = at(delimiter) || (template_delimiters && (at(",") || at(">")));
            if (!parentheses && terminal) break;
            if (at(")") && !parentheses)
                fail(ErrorCode::malformed, "unmatched closing parenthesis in integer constant expression");
            if (at("(")) ++parentheses;
            else if (at(")")) --parentheses;
            expression.push_back(next());
            if (expression.size() > 4096)
                fail(ErrorCode::resource_limit, "integer constant expression exceeds its token limit");
        }
        if (parentheses) fail(ErrorCode::malformed, "unclosed parenthesis in integer constant expression");
        if (expression.empty()) fail(ErrorCode::malformed, "empty integer constant expression");
        return expression;
    }
    std::vector<Token> take_integer_expression_until_template_delimiter() {
        return take_integer_expression_until(">", true);
    }
    std::vector<Token> take_integer_expression_until_array_delimiter() {
        return take_integer_expression_until("]", false);
    }
    std::vector<Token> take_integer_expression_until_bitfield_delimiter() {
        std::vector<Token> expression;
        std::size_t parentheses = 0;
        while (!at("<eof>")) {
            if (!parentheses && (at(",") || at(";") || at("}"))) break;
            if (at(")") && !parentheses)
                fail(ErrorCode::malformed, "unmatched closing parenthesis in bitfield width expression");
            if (at("(")) ++parentheses;
            else if (at(")")) --parentheses;
            expression.push_back(next());
            if (expression.size() > 4096)
                fail(ErrorCode::resource_limit, "bitfield width expression exceeds its token limit");
        }
        if (parentheses)
            fail(ErrorCode::malformed, "unclosed parenthesis in bitfield width expression");
        if (expression.empty())
            fail(ErrorCode::malformed, "empty bitfield width expression");
        return expression;
    }
    std::int64_t evaluate_integer_expression(
        const std::vector<Token> &expression,
        const std::map<std::string, std::uint64_t, std::less<>> &bindings) const {
        return IntegerExpressionParser(expression, bindings, o_.max_nesting, template_pack_bindings_).parse();
    }
    std::int64_t evaluate_integer_expression(
        const std::vector<Token> &expression,
        const std::map<std::string, std::int64_t, std::less<>> &bindings,
        IntegerExpressionParser::NameResolver name_resolver = {}) const {
        return IntegerExpressionParser(expression, bindings, o_.max_nesting, template_pack_bindings_,
                                       std::move(name_resolver)).parse();
    }
    std::optional<std::int64_t> resolve_enum_expression_name(
        std::string_view spelling,
        const std::map<std::string, std::int64_t, std::less<>> &bindings) const {
        const auto find = [&](std::string_view name) -> std::optional<std::int64_t> {
            const auto binding = bindings.find(name);
            return binding == bindings.end() ? std::optional<std::int64_t>{} : binding->second;
        };
        const auto find_expanded = [&](std::string name) -> std::optional<std::int64_t> {
            if (const auto value = find(name)) return value;
            name = expand_namespace_aliases(std::move(name));
            if (const auto value = find(name)) return value;
            return find("::" + name);
        };
        if (spelling.starts_with("::"))
            return find_expanded(std::string(spelling.substr(2)));

        auto scope = current_namespace();
        for (;;) {
            auto candidate = scope.empty() ? std::string(spelling) : scope + "::" + std::string(spelling);
            if (const auto value = find_expanded(std::move(candidate))) return value;
            if (scope.empty()) break;
            const auto separator = scope.rfind("::");
            scope = separator == std::string::npos ? std::string{} : scope.substr(0, separator);
        }
        return {};
    }
    std::uint64_t integer_magnitude(std::string s,std::uint64_t limit){
        while(!s.empty()&&(s.back()=='u'||s.back()=='U'||s.back()=='l'||s.back()=='L'))s.pop_back();if(s.empty())syntax("invalid enum integer");
        int base=10;std::string_view v=s;if(v.size()>2&&v[0]=='0'&&(v[1]=='x'||v[1]=='X')){base=16;v.remove_prefix(2);}else if(v.size()>1&&v[0]=='0'){base=8;v.remove_prefix(1);}std::uint64_t val=0;auto [end,ec]=std::from_chars(v.data(),v.data()+v.size(),val,base);if(ec!=std::errc{}||end!=v.data()+v.size()||val>limit)syntax("integer is outside the supported range");return val;
    }
    std::int64_t integer_literal(std::string s){return static_cast<std::int64_t>(integer_magnitude(std::move(s),std::uint64_t(INT64_MAX)));}
    TypePtr parse_enum(){
        const bool scoped=take("class")||take("struct");
        if(!identifier(peek().text)&&!at("::"))syntax("named enum tags are required");std::string tag=parse_qualified_name();
        if(at("<"))fail(ErrorCode::unsupported,"templated enum declarations and specializations are unsupported");
        std::string key="enum "+tag;
        TypePtr fixed_underlying;
        if(take(":")) {
            auto underlying = parse_base();
            if (underlying.is_typedef || underlying.is_static || underlying.is_inline)
                syntax("storage specifiers are invalid in an enum underlying type");
            if (!underlying.type || underlying.type->kind() != Kind::integer || !underlying.type->size() ||
                *underlying.type->size() == 0 || *underlying.type->size() > 8)
                fail(ErrorCode::unsupported,
                     "fixed enum underlying types must be unqualified integers from 1 through 8 bytes");
            fixed_underlying = std::move(underlying.type);
        }
        if(!aggregate_scopes_.empty()&&at("{"))fail(ErrorCode::unsupported,"nested enum definitions are unsupported");
        if(!take("{")){auto it=names_.find(key);if(it==names_.end())fail(ErrorCode::unsupported,"forward enum reference is unsupported");return it->second;}
        std::vector<Enumerator> values;std::int64_t next_value=0,min_value=0,max_value=0;bool auto_overflow=false;std::set<std::string> unique;
        auto prior_enumerators = enum_value_bindings_;
        const auto namespace_scope = current_namespace();
        std::vector<std::string> lookup_scopes;
        auto lookup_scope = namespace_scope;
        for (;;) {
            lookup_scopes.push_back(lookup_scope);
            if (lookup_scope.empty()) break;
            const auto separator = lookup_scope.rfind("::");
            lookup_scope = separator == std::string::npos ? std::string{} : lookup_scope.substr(0, separator);
        }
        for (const auto &scope : lookup_scopes) {
            std::map<std::string, std::int64_t, std::less<>> local_unqualified, local_qualified;
            for (const auto &[name, scoped_values] : enum_unqualified_bindings_)
                for (const auto &[declaring_scope, value] : scoped_values)
                    if (declaring_scope == scope && !local_unqualified.emplace(name, value).second)
                        fail(ErrorCode::unsupported, "ambiguous unqualified enumerator name: '" + name + "'");
            for (const auto &binding : enum_qualified_bindings_)
                if (binding.scope == scope && !local_qualified.emplace(binding.name, binding.value).second)
                    fail(ErrorCode::unsupported, "ambiguous qualified enumerator name: '" + binding.name + "'");
            for (const auto &[name, value] : local_unqualified) prior_enumerators.try_emplace(name, value);
            for (const auto &[name, value] : local_qualified) prior_enumerators.try_emplace(name, value);
        }
        const auto relative_tag = !namespace_scope.empty() && tag.starts_with(namespace_scope + "::")
            ? tag.substr(namespace_scope.size() + 2) : tag;
        do {
            if(at("}"))break;
            const auto enumerator_token = next();
            auto name=enumerator_token.text;if(!identifier(name))syntax("expected enum constant name");
            const auto constant_name=scoped?tag+"::"+name:qualify_name(name);
            if(!unique.insert(name).second||result_.enum_constants.contains(constant_name)||result_.symbols.contains(constant_name)||names_.contains(constant_name))
                fail(ErrorCode::conflict,"duplicate enum constant '"+constant_name+"'");
            if(take("=")){
                std::vector<Token> expression;
                std::size_t parentheses=0;
                while(!at("<eof>")){
                    if(!parentheses&&(at(",")||at("}")))break;
                    if(at("("))++parentheses;
                    else if(at(")")){if(!parentheses)fail(ErrorCode::malformed,"unmatched parenthesis in enum value");--parentheses;}
                    expression.push_back(next());
                    if(expression.size()>4096)fail(ErrorCode::resource_limit,"enum value expression exceeds its token limit");
                }
                if(parentheses)fail(ErrorCode::malformed,"unclosed parenthesis in enum value");
                if(expression.size()==2&&expression[0].text=="-"&&
                   !expression[1].text.empty()&&expression[1].text.front()>='0'&&expression[1].text.front()<='9'&&
                   integer_token_magnitude(expression[1].text,std::uint64_t{1}<<63)==(std::uint64_t{1}<<63))
                    next_value=INT64_MIN;
                else next_value=evaluate_integer_expression(expression, prior_enumerators,
                    [&](std::string_view spelling) {
                        return resolve_enum_expression_name(spelling, prior_enumerators);
                    });
                auto_overflow=false;
            } else if(auto_overflow)fail(ErrorCode::overflow,"enum auto-increment overflows; provide an explicit value");
            values.push_back({name,static_cast<std::uint64_t>(next_value)});result_.enum_constants.emplace(constant_name,next_value);
            result_.enum_constant_source_lines.emplace(constant_name,enumerator_token.line);
            prior_enumerators.insert_or_assign(constant_name,next_value);
            prior_enumerators.insert_or_assign(tag+"::"+name,next_value);
            prior_enumerators.insert_or_assign("::"+constant_name,next_value);
            prior_enumerators.insert_or_assign("::"+tag+"::"+name,next_value);
            if(relative_tag!=tag)prior_enumerators.insert_or_assign(relative_tag+"::"+name,next_value);
            if(!scoped)prior_enumerators.insert_or_assign(name,next_value);
            enum_value_bindings_.insert_or_assign(constant_name,next_value);
            enum_value_bindings_.insert_or_assign(tag+"::"+name,next_value);
            enum_value_bindings_.insert_or_assign("::"+constant_name,next_value);
            enum_value_bindings_.insert_or_assign("::"+tag+"::"+name,next_value);
            if(!scoped)enum_unqualified_bindings_[name].emplace_back(namespace_scope,next_value);
            enum_qualified_bindings_.push_back({namespace_scope,relative_tag+"::"+name,next_value});
            min_value=std::min(min_value,next_value);max_value=std::max(max_value,next_value);
            if(next_value==INT64_MAX)auto_overflow=true;else{++next_value;auto_overflow=false;}
        } while(take(","));
        need("}");if(values.empty())fail(ErrorCode::unsupported,"empty enums are unsupported");
        if (fixed_underlying) {
            auto p = Type::enumeration_with_values(tag, std::move(fixed_underlying), std::move(values));
            if (!p) fail(p.error().code, p.error().message);
            register_tag_type("enum",tag,p.value());return p.value();
        }
        std::uint8_t enum_bytes=0;std::string enum_base;
        for(const auto [name,bytes] : {std::pair<std::string_view,std::uint8_t>{"int",o_.int_bytes},{"long",o_.long_bytes},{"long long",o_.long_long_bytes}}){
            const unsigned bits=unsigned(bytes)*8;const auto max=bits>=64?INT64_MAX:(std::int64_t{1}<<(bits-1))-1;const auto min=bits>=64?INT64_MIN:-(std::int64_t{1}<<(bits-1));
            if((!scoped||name=="int")&&min_value>=min&&max_value<=max){enum_bytes=bytes;enum_base=std::string(name);break;}
        }
        if(!enum_bytes)fail(ErrorCode::unsupported,"enum values exceed supported signed integer types");
        auto base=Type::integer(enum_base,enum_bytes,enum_bytes,true);if(!base)fail(base.error().code,base.error().message);
        auto p=Type::enumeration_with_values(tag,base.value(),std::move(values));if(!p)fail(p.error().code,p.error().message);
        register_tag_type("enum",tag,p.value());return p.value();
    }
    struct Derived {
        enum class Kind { pointer, array, function } kind;
        std::uint64_t count=0;
        std::vector<Parameter> parameters;
        bool variadic=false;
        FunctionConvention convention=FunctionConvention::platform_default;
        std::uint8_t qualifiers=0;
    };
    Decl parse_declarator(TypePtr base,bool allow_abstract,std::vector<Derived>* parsed_ops=nullptr){
        enter();
        auto convention=consume_calling_convention();
        std::vector<std::uint8_t> pointer_qualifiers;
        while(take("*")){std::uint8_t qualifiers=0;while(at("const")||at("volatile")||at("restrict")||at("__restrict")||at("__restrict__")||at("_Atomic")){if(take("const"))qualifiers|=static_cast<std::uint8_t>(Qualifier::const_);else if(take("volatile"))qualifiers|=static_cast<std::uint8_t>(Qualifier::volatile_);else if(take("_Atomic"))qualifiers|=static_cast<std::uint8_t>(Qualifier::atomic_);else {++pos_;qualifiers|=static_cast<std::uint8_t>(Qualifier::restrict_);}}pointer_qualifiers.push_back(qualifiers);if(pointer_qualifiers.size()>o_.max_nesting)fail(ErrorCode::resource_limit,"pointer declarator nesting exceeds limit");}
        if(pointer_qualifiers.empty()) {
            std::uint8_t base_qualifiers=0;
            if(base->kind()==Kind::qualified) {base_qualifiers=base->qualifiers();base=base->element();}
            if(base->kind()==Kind::named_reference) {
                const auto found=names_.find(base->name());
                if(found!=names_.end()&&found->second->size())base=found->second;
            }
            if(base_qualifiers) {
                auto qualified=Type::qualified(base,base_qualifiers);if(!qualified)fail(qualified.error().code,qualified.error().message);base=qualified.value();
            }
        }
        std::string name;std::vector<Derived> derived;
        if(take("(")){
            auto inner=parse_declarator(base,true,&derived);name=std::move(inner.name);if(convention==FunctionConvention::platform_default)convention=inner.convention;need(")");
        } else if(identifier(peek().text)) name=next().text;
        else if(!allow_abstract)syntax("declarator requires an identifier");
        for(;;){
            if(take("[")){std::uint64_t count=0;if(!take("]")){const auto expression=take_integer_expression_until_array_delimiter();const auto extent=evaluate_integer_expression(expression,template_value_bindings_);if(extent<0)fail(ErrorCode::unsupported,"negative array extents are unsupported");count=static_cast<std::uint64_t>(extent);if(!count||count>o_.max_array_elements)fail(ErrorCode::resource_limit,"array extent is invalid or exceeds configured limit");need("]");}derived.push_back({Derived::Kind::array,count,{},false});continue;}
            if(!take("("))break;
            enter();std::vector<Parameter> params;bool variadic=false;
            if(!take(")")){
                if(at("void")&&peek(1).text==")"){++pos_;need(")");}
                else {std::size_t index=0;for(;;){if(take("...")){variadic=true;need(")");break;}
                    if(identifier(peek().text)&&peek(1).text=="..."&&template_pack_bindings_.contains(peek().text)) {
                        const auto pack_name=next().text;need("...");
                        if(!identifier(peek().text))syntax("type-pack parameter expansion requires a parameter name");
                        const auto parameter_name=next().text;
                        if(at("="))fail(ErrorCode::unsupported,"default arguments on parameter-pack expansions are unsupported");
                        const auto &pack=template_pack_bindings_.at(pack_name);
                        if(pack.size()>32)fail(ErrorCode::resource_limit,"function parameter-pack expansion exceeds 32 parameters");
                        for(std::size_t pack_index=0;pack_index<pack.size();++pack_index) {
                            if(!pack[pack_index].type||pack[pack_index].value||!pack[pack_index].template_name.empty())
                                fail(ErrorCode::unsupported,"function parameter-pack expansion supports type arguments only");
                            auto expanded_type=pack[pack_index].type;
                            if(expanded_type->kind()==Kind::array) {
                                auto pointer=Type::pointer(expanded_type->element(),o_.pointer_bytes,o_.pointer_bytes);
                                if(!pointer)fail(pointer.error().code,pointer.error().message);
                                expanded_type=pointer.value();
                            }
                            if(expanded_type->kind()==Kind::function)
                                fail(ErrorCode::unsupported,"function parameter-pack expansion cannot contain function types");
                            params.push_back({parameter_name+"__pack"+std::to_string(pack_index),expanded_type});
                            ++index;
                        }
                        if(take(")"))break;
                        need(",");
                        continue;
                    }
                    auto pb=parse_base();consume_standard_attributes();auto pd=parse_declarator(pb.type,true);
                    consume_standard_attributes();
                    if(at("="))skip_parameter_default();
                    pd.type=apply_pending_function_convention(std::move(pd.type));
                    if(pd.type->kind()==Kind::array){auto p=Type::pointer(pd.type->element(),o_.pointer_bytes,o_.pointer_bytes);if(!p)fail(p.error().code,p.error().message);pd.type=p.value();}
                    if(pd.type->kind()==Kind::function)fail(ErrorCode::unsupported,"function parameters must be declared as pointers");
                    std::string pname=pd.name.empty()?"arg"+std::to_string(index):pd.name;params.push_back({pname,pd.type});++index;if(take(")"))break;need(",");}
                }
            }
            if(variadic&&params.empty())fail(ErrorCode::malformed,"variadic prototypes require at least one fixed parameter");
            leave();derived.push_back({Derived::Kind::function,0,std::move(params),variadic,convention});
        }
        for(auto it=pointer_qualifiers.rbegin();it!=pointer_qualifiers.rend();++it){Derived pointer{Derived::Kind::pointer};pointer.qualifiers=*it;derived.push_back(std::move(pointer));}
        for(auto it=derived.rbegin();it!=derived.rend();++it){
            if(it->kind==Derived::Kind::pointer){auto p=Type::pointer(base,o_.pointer_bytes,o_.pointer_bytes);if(!p)fail(p.error().code,p.error().message);base=p.value();if(it->qualifiers){auto qualified=Type::qualified(base,it->qualifiers);if(!qualified)fail(qualified.error().code,qualified.error().message);base=qualified.value();}}
            else if(it->kind==Derived::Kind::array){if(base->kind()==Kind::function)fail(ErrorCode::unsupported,"arrays of functions are invalid");auto p=Type::array(base,it->count);if(!p)fail(p.error().code,p.error().message);base=p.value();}
            else {if(base->kind()==Kind::array||base->kind()==Kind::function)fail(ErrorCode::unsupported,"functions cannot return arrays or functions");auto p=Type::function(base,it->parameters,it->variadic,it->convention);if(!p)fail(p.error().code,p.error().message);base=p.value();}
        }
        if(convention!=FunctionConvention::platform_default){
            const auto function_layers=std::count_if(derived.begin(),derived.end(),[](const auto &item){return item.kind==Derived::Kind::function;});
            if(function_layers!=1)fail(ErrorCode::unsupported,"calling-convention attributes require an unambiguous single function declarator layer");
        }
        const bool function=base->kind()==Kind::function;const auto retained=base->kind()==Kind::function?base->function_convention():convention;if(parsed_ops)*parsed_ops=std::move(derived);leave();return {std::move(name),std::move(base),{},function,false,retained};
    }
    void parse_static_assert() {
        (void)next(); // static_assert or _Static_assert
        const auto line = peek().line;
        need("(");
        std::vector<Token> expression;
        std::size_t parentheses = 0;
        while (!at("<eof>")) {
            if (!parentheses && (at(",") || at(")"))) break;
            if (at("(")) ++parentheses;
            else if (at(")")) {
                if (!parentheses) break;
                --parentheses;
            }
            expression.push_back(next());
            if (expression.size() > 4096)
                fail(ErrorCode::resource_limit, "static assertion exceeds its expression token limit");
        }
        if (parentheses)
            fail(ErrorCode::malformed, "unclosed parenthesis in static assertion");
        if (expression.empty())
            fail(ErrorCode::malformed, "static assertion expression is empty");
        const auto resolver = [&](std::string_view name) {
            return resolve_enum_expression_name(name, enum_value_bindings_);
        };
        const auto value = IntegerExpressionParser(expression, template_value_bindings_,
            o_.max_nesting, template_pack_bindings_, resolver).parse();
        std::string message;
        if (take(",")) {
            bool found_literal = false;
            while (!at(")")) {
                const auto &literal = peek().text;
                if (literal.size() < 2 || literal.front() != '\"' || literal.back() != '\"')
                    fail(ErrorCode::malformed, "static assertion message must be a string literal");
                if (literal.size() > 4096 - std::min<std::size_t>(4096, message.size()))
                    fail(ErrorCode::resource_limit, "static assertion message exceeds its byte limit");
                message.append(literal);
                found_literal = true;
                ++pos_;
            }
            if (!found_literal)
                fail(ErrorCode::malformed, "static assertion message is empty");
        }
        need(")");
        need(";");
        if (!value) {
            std::string detail = "static assertion failed at line " + std::to_string(line);
            if (!message.empty()) detail += ": " + message;
            fail(ErrorCode::conflict, detail);
        }
    }
    void parse_external(){
        if(take(";"))return;
        if(at("static_assert")||at("_Static_assert")){parse_static_assert();return;}
        if(at("extern") && peek(1).text.size() >= 2 && peek(1).text.front() == '"') {
            ++pos_;
            const auto linkage = next().text;
            if (linkage != "\"C\"" && linkage != "\"C++\"")
                fail(ErrorCode::unsupported, "only C and C++ linkage specifications are supported");
            if (take("{")) {
                while (!take("}")) {
                    if (at("<eof>")) syntax("unterminated linkage specification");
                    parse_external();
                }
                return;
            }
            parse_external();
            return;
        }
        if(at("inline")&&peek(1).text=="namespace"){
            ++pos_;
            parse_namespace(true);
            return;
        }
        if(at("namespace")){parse_namespace();return;}
        if(at("template")){parse_template_declaration();return;}
        if(take("using")){
            if(take("namespace")){
                auto target=resolve_namespace_name(parse_lookup_name());
                need(";");
                const auto scope=current_namespace();
                const auto duplicate=std::find_if(using_namespaces_.begin(),using_namespaces_.end(),
                    [&](const UsingNamespace &entry){return entry.scope==scope&&entry.target==target;});
                if(duplicate==using_namespaces_.end())using_namespaces_.push_back({scope,std::move(target)});
                return;
            }
            if(take("enum")) {
                const auto target = parse_lookup_name();
                need(";");
                auto type = lookup_type(target);
                if (!type) type = lookup_type("enum " + target);
                if (!type || type->kind() != Kind::enumeration)
                    fail(ErrorCode::unsupported, "using enum target '" + target + "' is not a known enum type");
                for (const auto &enumerator : type->enumerator_values()) {
                    const auto imported = qualify_name(enumerator.name);
                    if (result_.symbols.contains(imported) || names_.contains(imported) ||
                        result_.enum_constants.contains(imported))
                        fail(ErrorCode::conflict, "using enum conflicts with existing name '" + imported + "'");
                    const auto value = static_cast<std::int64_t>(enumerator.value);
                    result_.enum_constants.emplace(imported, value);
                    const auto scoped_source = type->name() + "::" + enumerator.name;
                    auto line = result_.enum_constant_source_lines.find(scoped_source);
                    if (line == result_.enum_constant_source_lines.end()) {
                        const auto separator = type->name().rfind("::");
                        const auto scope = separator == std::string::npos ? std::string{}
                                                                          : type->name().substr(0, separator);
                        line = result_.enum_constant_source_lines.find(
                            scope.empty() ? enumerator.name : scope + "::" + enumerator.name);
                    }
                    if (line != result_.enum_constant_source_lines.end())
                        result_.enum_constant_source_lines.emplace(imported, line->second);
                    enum_value_bindings_.insert_or_assign(imported, value);
                    enum_value_bindings_.insert_or_assign("::" + imported, value);
                    enum_unqualified_bindings_[enumerator.name].emplace_back(current_namespace(), value);
                }
                return;
            }
            // A using-declaration introduces the final name of a qualified
            // type into the current namespace. The shared symbol model has
            // no distinct using-declaration kind, so retain it as a typedef
            // name pointing at the exact same immutable type identity.
            if(peek(1).text=="::"||at("::")) {
                const auto target=parse_lookup_name();
                need(";");
                auto type=lookup_type(target);
                if(!type)fail(ErrorCode::unsupported,"using-declaration target '"+target+"' is not a known type");
                const auto separator=target.rfind("::");
                const auto imported=qualify_name(separator==std::string::npos?target:target.substr(separator+2));
                if(result_.enum_constants.contains(imported))
                    fail(ErrorCode::conflict,"duplicate C++ type name '"+imported+"'");
                if(auto existing=names_.find(imported);existing!=names_.end()) {
                    if(existing->second->id()!=type->id())
                        fail(ErrorCode::conflict,"using-declaration conflicts with existing C++ type '"+imported+"'");
                    return;
                }
                if(auto existing=result_.symbols.find(imported);existing!=result_.symbols.end())
                    fail(ErrorCode::conflict,"using-declaration conflicts with existing header symbol '"+imported+"'");
                names_[imported]=type;
                result_.symbols.emplace(imported,HeaderSymbol{HeaderSymbolKind::typedef_name,type});
                return;
            }
            if(!identifier(peek().text))syntax("expected alias name after 'using'");
            const auto alias=next().text;
            need("=");
            auto base=parse_base();
            if(base.is_typedef)syntax("typedef storage is not valid in a using-alias target");
            auto declaration=parse_declarator(base.type,true);
            if(!declaration.name.empty())syntax("using-alias target must be an abstract type declarator");
            declaration.type=apply_pending_function_convention(std::move(declaration.type));
            need(";");
            const auto qualified=qualify_name(alias);
            if(result_.enum_constants.contains(qualified))
                fail(ErrorCode::conflict,"duplicate C++ type name '"+qualified+"'");
            bool aliases_existing_tag=false;
            if(auto existing=names_.find(qualified);existing!=names_.end()){
                aliases_existing_tag=existing->second->id()==declaration.type->id();
                for(const auto tag_prefix:{"struct ","union ","enum "}){
                    auto tag=names_.find(std::string(tag_prefix)+qualified);
                    if(tag!=names_.end()&&(tag->second->id()==declaration.type->id()||
                       (declaration.type->kind()==Kind::named_reference&&
                        declaration.type->name()==std::string(tag_prefix)+qualified)))aliases_existing_tag=true;
                }
                if(!aliases_existing_tag)
                    fail(ErrorCode::conflict,"duplicate C++ type name '"+qualified+"'");
            }
            if(auto existing=result_.symbols.find(qualified);existing!=result_.symbols.end()){
                if(!aliases_existing_tag||existing->second.kind!=HeaderSymbolKind::tag)
                    fail(ErrorCode::conflict,"duplicate C++ type name '"+qualified+"'");
                existing->second=HeaderSymbol{HeaderSymbolKind::typedef_name,declaration.type};
            } else result_.symbols.emplace(qualified,HeaderSymbol{HeaderSymbolKind::typedef_name,declaration.type});
            names_[qualified]=declaration.type;
            return;
        }
        if(peek().text.starts_with("@pack_")) {
            const auto marker=next().text;
            if(marker=="@pack_pop") {
                if(pack_stack_.empty())fail(ErrorCode::malformed,"#pragma pack(pop) has no matching push");
                pack_cap_=pack_stack_.back().cap;pack_stack_.pop_back();
            } else if(marker=="@pack_show") {
                result_.diagnostics.push_back(pack_cap_ ? "#pragma pack(show): current packing alignment is "+std::to_string(pack_cap_)
                                                        : "#pragma pack(show): current packing alignment is default");
            } else if(marker.starts_with("@pack_pop_value_")) {
                if(pack_stack_.empty())fail(ErrorCode::malformed,"#pragma pack(pop, n) has no matching push");
                pack_stack_.pop_back();
                pack_cap_=std::stoull(marker.substr(16));
            } else if(marker.starts_with("@pack_pop_named|")) {
                const auto name=marker.substr(16);
                auto found=std::find_if(pack_stack_.rbegin(),pack_stack_.rend(),[&](const PackEntry &entry){return entry.name==name;});
                if(found==pack_stack_.rend())fail(ErrorCode::malformed,"#pragma pack(pop, "+name+") has no matching named push");
                const auto index=static_cast<std::size_t>(std::distance(found,pack_stack_.rend())-1);
                pack_cap_=pack_stack_[index].cap;pack_stack_.erase(pack_stack_.begin()+static_cast<std::ptrdiff_t>(index),pack_stack_.end());
            } else if(marker.starts_with("@pack_pop_named_value|")) {
                const auto delimiter=marker.rfind('|');
                const auto name=marker.substr(22,delimiter-22);
                auto found=std::find_if(pack_stack_.rbegin(),pack_stack_.rend(),[&](const PackEntry &entry){return entry.name==name;});
                if(found==pack_stack_.rend())fail(ErrorCode::malformed,"#pragma pack(pop, "+name+") has no matching named push");
                const auto index=static_cast<std::size_t>(std::distance(found,pack_stack_.rend())-1);
                pack_stack_.erase(pack_stack_.begin()+static_cast<std::ptrdiff_t>(index),pack_stack_.end());
                pack_cap_=std::stoull(marker.substr(delimiter+1));
            } else if(marker=="@pack_push_current") pack_stack_.push_back({pack_cap_,{}});
            else if(marker.starts_with("@pack_push_named_current|")) {
                pack_stack_.push_back({pack_cap_,marker.substr(25)});
            } else if(marker.starts_with("@pack_push_named|")) {
                const auto delimiter=marker.rfind('|');
                const auto name=marker.substr(17,delimiter-17);
                pack_stack_.push_back({pack_cap_,name});
                pack_cap_=std::stoull(marker.substr(delimiter+1));
            } else if(marker.starts_with("@pack_push_")) {
                pack_stack_.push_back({pack_cap_,{}});
                pack_cap_=std::stoull(marker.substr(11));
            } else if(marker.starts_with("@pack_set_")) pack_cap_=std::stoull(marker.substr(10));
            else fail(ErrorCode::malformed,"invalid internal #pragma pack token");
            return;
        }
        auto b=parse_base();
        consume_standard_attributes();
        auto declaration_alignment = pending_aggregate_alignment_;
        pending_aggregate_alignment_.reset();
        if(at("__attribute__")||at("__declspec")) {
            if(parse_attribute())fail(ErrorCode::unsupported,"packed attribute placement on a top-level declaration is unsupported");
            if(pending_aggregate_alignment_){declaration_alignment=std::max(declaration_alignment.value_or(0),*pending_aggregate_alignment_);pending_aggregate_alignment_.reset();}
        }
        if(pending_vector_size_){
            const auto bytes=*pending_vector_size_;pending_vector_size_.reset();
            if(!b.is_typedef)fail(ErrorCode::unsupported,"vector_size is currently supported only on typedef declarations");
            b.type=make_vector_type(std::move(b.type),bytes);
        }
        if(take(";"))return;
        for(;;){consume_standard_attributes();auto d=parse_declarator(b.type,false);consume_standard_attributes();auto effective_alignment=declaration_alignment;if(at("__attribute__")||at("__declspec")){if(parse_attribute())fail(ErrorCode::unsupported,"packed attribute placement on a top-level declaration is unsupported");if(pending_aggregate_alignment_){effective_alignment=std::max(effective_alignment.value_or(0),*pending_aggregate_alignment_);pending_aggregate_alignment_.reset();}}while(alignment_specifier())parse_alignment_specifier();if(pending_aggregate_alignment_){effective_alignment=std::max(effective_alignment.value_or(0),*pending_aggregate_alignment_);pending_aggregate_alignment_.reset();}d.type=apply_pending_vector_size(std::move(d.type),b.is_typedef);d.type=apply_pending_function_convention(std::move(d.type));if(effective_alignment&&!d.function&&!(d.type->kind()==Kind::array&&!b.is_typedef))d.type=apply_alignment(std::move(d.type),effective_alignment);else if(effective_alignment&&d.function)fail(ErrorCode::unsupported,"alignment cannot be applied to function declarations");if(take(":"))fail(ErrorCode::unsupported,"bitfield declarations are unsupported");if(d.function&&at("{"))fail(ErrorCode::unsupported,"function definitions and bodies are unsupported");if(take("="))fail(ErrorCode::unsupported,"initialized declarations are unsupported");
            if(!d.function&&(d.type->kind()==Kind::void_type||d.type->kind()==Kind::function))fail(ErrorCode::malformed,"object declaration has a non-object type");
            if(!d.function&&!b.is_typedef&&!d.type->size())fail(ErrorCode::unsupported,"object declaration requires a complete object type");
            if(d.function){if(d.type->result_type()->kind()!=Kind::void_type&&!d.type->result_type()->size())fail(ErrorCode::unsupported,"function result requires a complete object type");for(const auto &parameter:d.type->parameters())if(!parameter.type->size())fail(ErrorCode::unsupported,"function parameter requires a complete object type");}
            const auto symbol_name=qualify_name(d.name);
            if(result_.enum_constants.contains(symbol_name))fail(ErrorCode::conflict,"duplicate header symbol '"+symbol_name+"'");
            const auto symbol_alignment = (!b.is_typedef && !d.function && d.type->kind()==Kind::array) ? effective_alignment : std::nullopt;
            HeaderSymbol symbol{b.is_typedef?HeaderSymbolKind::typedef_name:d.function?HeaderSymbolKind::function:HeaderSymbolKind::object,d.type,symbol_alignment};
            bool aliases_existing_tag=false;
            if(b.is_typedef){
                if(auto existing=names_.find(symbol_name);existing!=names_.end()){
                    bool same_tag=existing->second->id()==d.type->id();
                    for(const auto tag_prefix:{"struct ","union ","enum "}){
                        auto tag=names_.find(std::string(tag_prefix)+symbol_name);
                        if(tag!=names_.end()&&(tag->second->id()==d.type->id()||
                           (d.type->kind()==Kind::named_reference&&d.type->name()==std::string(tag_prefix)+symbol_name)))same_tag=true;
                    }
                    if(!same_tag)fail(ErrorCode::conflict,"duplicate C++ type name '"+symbol_name+"'");
                    aliases_existing_tag=true;
                }
                names_[symbol_name]=d.type;
            }
            if(auto existing=result_.symbols.find(symbol_name);existing!=result_.symbols.end()){
                if(!aliases_existing_tag||existing->second.kind!=HeaderSymbolKind::tag)
                    fail(ErrorCode::conflict,"duplicate header symbol '"+symbol_name+"'");
                existing->second=std::move(symbol);
            } else result_.symbols.emplace(symbol_name,std::move(symbol));
            if(!take(","))break;
        }need(";");
    }
};
} // namespace

Result<HeaderImportResult> import_c_header(std::string_view source,const HeaderImportOptions &options) {
    if(!options.pointer_bytes||!options.char_bytes||!options.short_bytes||!options.int_bytes||!options.long_bytes||!options.long_long_bytes||!options.float_bytes||!options.double_bytes||!options.long_double_bytes||!options.max_input_bytes||!options.max_tokens||!options.max_nesting||!options.max_array_elements||!options.max_include_depth||!options.max_include_files||!options.max_expanded_bytes||!options.max_macros||!options.max_macro_expansion_depth||!options.max_macro_expansions||!options.max_macro_arguments)
        return Error{ErrorCode::invalid_argument,"header import options must be nonzero"};
    if(options.max_macro_expansion_depth>256)
        return Error{ErrorCode::invalid_argument,"macro expansion depth cannot exceed the hard safety ceiling of 256"};
    for (auto size : {options.pointer_bytes,options.char_bytes,options.short_bytes,options.int_bytes,options.long_bytes,options.long_long_bytes})
        if ((size & (size - 1)) != 0) return Error{ErrorCode::invalid_argument,"scalar and pointer sizes must be powers of two for supported ABI layout"};
    for (auto alignment : {options.float_alignment, options.double_alignment, options.long_double_alignment})
        if (alignment && (alignment & (alignment - 1)) != 0)
            return Error{ErrorCode::invalid_argument,"floating-point alignments must be powers of two"};
    try {
        auto preprocessed=detail::preprocess_header(source,options);
        if(!preprocessed)return preprocessed.error();
        Parser parser(lex(preprocessed.value(),options),options);return parser.parse();
    }
    catch(const Error &e){return e;} catch(const std::exception &e){return Error{ErrorCode::malformed,std::string("header parser failed: ")+e.what()};}
}
} // namespace hexlab::types
