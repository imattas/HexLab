#include "hexlab/decompiler/decompiler.hpp"
#include "hexlab/loaders/cil.hpp"
#include <algorithm>
#include <array>
#include <bit>
#include <deque>
#include <iomanip>
#include <iterator>
#include <set>
#include <sstream>
#include <tuple>
#include <unordered_map>
#include <variant>

namespace hexlab::decompiler {
namespace {
using Stack = std::vector<ExpressionPtr>;
std::string quoted_metadata_name(std::string_view name) {
    constexpr char digits[] = "0123456789abcdef";
    std::string quoted = "\"";
    for (const unsigned char ch : name) {
        if (ch == '"' || ch == '\\') {
            quoted.push_back('\\');
            quoted.push_back(static_cast<char>(ch));
        } else if (ch == '\n') quoted += "\\n";
        else if (ch == '\r') quoted += "\\r";
        else if (ch == '\t') quoted += "\\t";
        else if (ch < 0x20 || ch == 0x7f) {
            quoted += "\\u00";
            quoted.push_back(digits[ch >> 4]);
            quoted.push_back(digits[ch & 0x0f]);
        } else quoted.push_back(static_cast<char>(ch));
    }
    quoted.push_back('"');
    return quoted;
}
std::string managed_string_literal(std::u16string_view value) {
    constexpr char digits[] = "0123456789abcdef";
    std::string result = "\"";
    const auto append_escape = [&](std::uint32_t codepoint, unsigned digits_count, char prefix) {
        result.push_back('\\');
        result.push_back(prefix);
        for (unsigned shift = digits_count * 4; shift > 0; shift -= 4)
            result.push_back(digits[(codepoint >> (shift - 4)) & 0x0f]);
    };
    for (std::size_t i = 0; i < value.size(); ++i) {
        const auto unit = static_cast<std::uint16_t>(value[i]);
        if (unit == '"' || unit == '\\') { result.push_back('\\'); result.push_back(static_cast<char>(unit)); }
        else if (unit == '\n') result += "\\n";
        else if (unit == '\r') result += "\\r";
        else if (unit == '\t') result += "\\t";
        else if (unit >= 0x20 && unit <= 0x7e) result.push_back(static_cast<char>(unit));
        else if (unit >= 0xd800 && unit <= 0xdbff && i + 1 < value.size() &&
                 static_cast<std::uint16_t>(value[i + 1]) >= 0xdc00 &&
                 static_cast<std::uint16_t>(value[i + 1]) <= 0xdfff) {
            const auto low = static_cast<std::uint16_t>(value[++i]);
            const auto codepoint = 0x10000u + ((std::uint32_t{unit - 0xd800u} << 10) | (low - 0xdc00u));
            append_escape(codepoint, 8, 'U');
        } else if (unit > 0x7e) append_escape(unit, 4, 'u');
        else append_escape(unit, 4, 'u');
    }
    result.push_back('"');
    return result;
}
ValueType managed_reference_type() { return {TypeKind::pointer, 0, false}; }
ExpressionPtr managed_string_expression(std::u16string_view value) {
    return std::make_shared<Expression>(Expression{managed_reference_type(),
        VariableValue{managed_string_literal(value)}});
}
ValueType managed_signature_type(const ManagedTypeSignature &signature,
                                 const ManagedMethodSignature &context,
                                 unsigned depth = 0) {
    if (depth > 16) return {};
    if (!context.declaring_type_generic_arguments_valid) return {};
    if (signature.element_type == 0x15 && !signature.generic_instance_arity_valid) return {};
    if (signature.type_spec_signature)
        return managed_signature_type(*signature.type_spec_signature, context, depth + 1);
    const auto integer = [](std::uint16_t bits, bool is_signed) {
        return ValueType{TypeKind::integer, bits, is_signed};
    };
    switch (signature.element_type) {
    case 0x02: return {TypeKind::boolean, 1, false};
    case 0x03: return integer(16, false);
    case 0x04: return integer(8, true);
    case 0x05: return integer(8, false);
    case 0x06: return integer(16, true);
    case 0x07: return integer(16, false);
    case 0x08: return integer(32, true);
    case 0x09: return integer(32, false);
    case 0x0a: return integer(64, true);
    case 0x0b: return integer(64, false);
    case 0x0c: return {TypeKind::floating, 32, false};
    case 0x0d: return {TypeKind::floating, 64, false};
    case 0x0e: case 0x0f: case 0x10: case 0x14: case 0x18: case 0x19: case 0x1c: case 0x1d:
        return managed_reference_type();
    case 0x11: return {};
    case 0x12: return managed_reference_type();
    case 0x13:
        return signature.generic_index < context.declaring_type_arguments.size()
            ? managed_signature_type(context.declaring_type_arguments[signature.generic_index], context, depth + 1)
            : ValueType{};
    case 0x15: return signature.generic_instance_is_value_type ? ValueType{} : managed_reference_type();
    case 0x16: return {};
    case 0x1e:
        return signature.generic_index < context.method_spec_arguments.size()
            ? managed_signature_type(context.method_spec_arguments[signature.generic_index], context, depth + 1)
            : ValueType{};
    default: return {};
    }
}
ExpressionPtr retag_managed_expression(ExpressionPtr expression, ValueType type) {
    if (!expression || type.kind == TypeKind::unknown || expression->type == type) return expression;
    return std::make_shared<Expression>(Expression{type, expression->value});
}
ExpressionPtr typed_variable(std::string name, ValueType type) {
    return std::make_shared<Expression>(Expression{type, VariableValue{std::move(name)}});
}
ValueType managed_call_result_type(const ManagedMethodSignature &signature, bool construct) {
    if (construct)
        return signature.declaring_type_generic_arguments_valid &&
               signature.declaring_type_is_value_type == std::optional<bool>{false}
            ? managed_reference_type() : ValueType{};
    return signature.returns_value ? managed_signature_type(signature.return_type, signature) : ValueType{};
}
std::optional<ValueType> managed_array_element_type(std::string_view op) {
    if (op == "ldelem.i1") return ValueType{TypeKind::integer, 32, true};
    if (op == "ldelem.u1") return ValueType{TypeKind::integer, 32, false};
    if (op == "ldelem.i2") return ValueType{TypeKind::integer, 32, true};
    if (op == "ldelem.u2") return ValueType{TypeKind::integer, 32, false};
    if (op == "ldelem.i4" || op == "ldelem.u4") return ValueType{TypeKind::integer, 32, op == "ldelem.i4"};
    if (op == "ldelem.i8") return ValueType{TypeKind::integer, 64, true};
    if (op == "ldelem.i") return ValueType{TypeKind::integer, 0, true};
    if (op == "ldelem.r4") return ValueType{TypeKind::floating, 32, false};
    if (op == "ldelem.r8") return ValueType{TypeKind::floating, 64, false};
    if (op == "ldelem.ref") return managed_reference_type();
    return {};
}
bool managed_array_load(std::string_view op) { return op.starts_with("ldelem."); }
bool managed_array_store(std::string_view op) { return op.starts_with("stelem."); }
std::optional<ValueType> managed_indirect_load_type(std::string_view op) {
    if (op == "ldind.i1" || op == "ldind.i2" || op == "ldind.i4")
        return ValueType{TypeKind::integer, 32, true};
    if (op == "ldind.u1" || op == "ldind.u2" || op == "ldind.u4")
        return ValueType{TypeKind::integer, 32, false};
    if (op == "ldind.i8") return ValueType{TypeKind::integer, 64, true};
    if (op == "ldind.i") return ValueType{TypeKind::integer, 0, true};
    if (op == "ldind.r4") return ValueType{TypeKind::floating, 32, false};
    if (op == "ldind.r8") return ValueType{TypeKind::floating, 64, false};
    if (op == "ldind.ref") return managed_reference_type();
    return {};
}
bool managed_indirect_store(std::string_view op) {
    return op == "stind.i1" || op == "stind.i2" || op == "stind.i4" || op == "stind.i8" ||
           op == "stind.i" || op == "stind.r4" || op == "stind.r8" || op == "stind.ref";
}
ValueType int_type(std::uint16_t bits = 32) { return {TypeKind::integer, bits, true}; }
ExpressionPtr typed_unary(std::string operation, ExpressionPtr value, ValueType type);
struct IntegerConversion { std::uint16_t target_bits; bool is_signed; };
std::optional<IntegerConversion> integer_conversion(std::string_view op) {
    if (op == "conv.i1") return IntegerConversion{8, true};
    if (op == "conv.u1") return IntegerConversion{8, false};
    if (op == "conv.i2") return IntegerConversion{16, true};
    if (op == "conv.u2") return IntegerConversion{16, false};
    if (op == "conv.i4") return IntegerConversion{32, true};
    if (op == "conv.u4") return IntegerConversion{32, false};
    if (op == "conv.i8") return IntegerConversion{64, true};
    if (op == "conv.u8") return IntegerConversion{64, false};
    return {};
}
std::optional<std::uint16_t> floating_conversion(std::string_view op) {
    if (op == "conv.r4") return std::uint16_t{32};
    if (op == "conv.r8" || op == "conv.r.un") return std::uint16_t{64};
    return {};
}
ValueType floating_type(std::uint16_t bits) { return {TypeKind::floating, bits, false}; }
ValueType conversion_stack_type(IntegerConversion conversion) {
    return {TypeKind::integer, static_cast<std::uint16_t>(conversion.target_bits < 32 ? 32 : conversion.target_bits),
            conversion.is_signed};
}
ExpressionPtr floating_constant(std::uint64_t bits, std::uint16_t width) {
    const auto bit_type = int_type(width);
    auto raw = std::make_shared<Expression>(Expression{bit_type, ConstantValue{bits, bit_type}});
    return typed_unary(width == 32 ? "bitcast_f32" : "bitcast_f64", std::move(raw), floating_type(width));
}
ExpressionPtr convert_floating(std::string_view opcode, std::uint16_t target_bits, ExpressionPtr value) {
    if (!value || (value->type.kind != TypeKind::integer && value->type.kind != TypeKind::floating) ||
        value->type.bits == 0 || value->type.bits > 64)
        return typed_unary("cil_" + std::string(opcode), std::move(value), floating_type(target_bits));
    std::string operation;
    if (value->type.kind == TypeKind::integer) {
        const bool unsigned_source = opcode == "conv.r.un" || !value->type.is_signed;
        operation = unsigned_source ? "uitofp" : "sitofp";
        operation += std::to_string(target_bits);
    } else if (value->type.bits < target_bits) operation = "fpext";
    else if (value->type.bits > target_bits) operation = "fptrunc";
    else return retag_managed_expression(std::move(value), floating_type(target_bits));
    return typed_unary(std::move(operation), std::move(value), floating_type(target_bits));
}
ExpressionPtr typed_unary(std::string operation, ExpressionPtr value, ValueType type) {
    return std::make_shared<Expression>(Expression{type, UnaryValue{std::move(operation), std::move(value)}});
}
ExpressionPtr convert_integer(std::string_view opcode, IntegerConversion conversion, ExpressionPtr value) {
    const auto output_type = conversion_stack_type(conversion);
    const auto opaque_operation = "cil_conv_" + std::string(opcode.substr(5));
    if (!value || value->type.kind != TypeKind::integer || value->type.bits == 0 || value->type.bits > 64)
        return typed_unary(opaque_operation, std::move(value), output_type);

    ExpressionPtr converted = std::move(value);
    if (conversion.target_bits < 32) {
        const ValueType narrow_type{TypeKind::integer, conversion.target_bits, conversion.is_signed};
        converted = typed_unary("trunc" + std::to_string(conversion.target_bits), std::move(converted), narrow_type);
        converted = typed_unary(conversion.is_signed ? "sext" : "zext", std::move(converted), output_type);
    } else if (conversion.target_bits == 32) {
        if (converted->type.bits > 32)
            converted = typed_unary("trunc32", std::move(converted), output_type);
        else
            converted = typed_unary(opaque_operation, std::move(converted), output_type);
    } else if (converted->type.bits < 64) {
        converted = typed_unary(conversion.is_signed ? "sext" : "zext", std::move(converted), output_type);
    } else {
        converted = typed_unary(opaque_operation, std::move(converted), output_type);
    }
    return converted;
}
ExpressionPtr variable(std::string name) {
    return std::make_shared<Expression>(Expression{{TypeKind::unknown, 0, false}, VariableValue{std::move(name)}});
}
ExpressionPtr constant(std::uint64_t value, std::uint16_t bits = 32) {
    auto type = int_type(bits);
    return std::make_shared<Expression>(Expression{type, ConstantValue{value, type}});
}
ExpressionPtr unary(std::string op, ExpressionPtr value) {
    auto type = value ? value->type : int_type();
    return std::make_shared<Expression>(Expression{type, UnaryValue{std::move(op), std::move(value)}});
}
ExpressionPtr binary(std::string op, ExpressionPtr left, ExpressionPtr right, bool boolean = false) {
    const auto type = boolean ? ValueType{TypeKind::boolean, 1, false} : (left ? left->type : int_type());
    return std::make_shared<Expression>(Expression{type, BinaryValue{std::move(op), std::move(left), std::move(right)}});
}
Error failure(ErrorCode code, const char *message) { return {code, message}; }
std::uint32_t index_operand(const CilInstruction &instruction, std::size_t short_base = 0) {
    if (instruction.opcode >= short_base && instruction.opcode < short_base + 4)
        return instruction.opcode - static_cast<std::uint16_t>(short_base);
    if (const auto *value = std::get_if<std::uint8_t>(&instruction.operand)) return *value;
    if (const auto *value = std::get_if<std::uint16_t>(&instruction.operand)) return *value;
    return UINT32_MAX;
}
std::optional<std::uint32_t> call_token(const CilInstruction &instruction) {
    if (const auto *token = std::get_if<CilTokenOperand>(&instruction.operand)) return token->token;
    return {};
}
bool valid_type_token(const std::optional<std::uint32_t> &token) {
    if (!token || (*token & 0x00ffffffu) == 0) return false;
    const auto table = *token >> 24;
    return table == 0x01 || table == 0x02 || table == 0x1b;
}
std::optional<std::uint32_t> directly_constructed_throw_type(
    const ManagedMethodAnalysis &method, std::size_t instruction_index,
    const std::map<std::uint32_t, ManagedCallSignature> &signatures,
    const std::set<std::uint32_t> &block_leaders) {
    if (instruction_index >= method.instructions.size() ||
        std::string_view(method.instructions[instruction_index].mnemonic) != "throw" ||
        method.instructions[instruction_index].status != CilInstructionStatus::decoded ||
        block_leaders.contains(method.instructions[instruction_index].offset))
        return {};
    while (instruction_index > 0) {
        const auto &previous = method.instructions[--instruction_index];
        const auto operation = std::string_view(previous.mnemonic);
        if (operation == "nop") {
            if (block_leaders.contains(previous.offset)) return {};
            continue;
        }
        if (operation != "newobj" || previous.status != CilInstructionStatus::decoded) return {};
        const auto token = call_token(previous);
        if (!token) return {};
        const auto signature = signatures.find(*token);
        if (signature == signatures.end() || !signature->second.declaring_type_token) return {};
        return signature->second.declaring_type_token;
    }
    return {};
}
bool proven_exception_match(const ManagedMethodAnalysis &method, std::uint32_t thrown_type,
                            std::uint32_t catch_type) {
    if (!thrown_type || !catch_type) return false;
    if (thrown_type == catch_type) return true;
    return method.resolved_exception_types &&
           managed_type_is_assignable(*method.resolved_exception_types, thrown_type, catch_type);
}
Address il_address(std::uint32_t offset) { return Address{{0}, offset}; }
std::string token_name(std::uint32_t token) {
    std::ostringstream out;
    out << "call_0x" << std::hex << std::setfill('0') << std::setw(8) << token;
    return out.str();
}
// Validate the interval topology once before using it to invent any dispatch
// order. Equal try intervals are one ordered handler group; other equal or
// crossing intervals do not have an unambiguous lexical model here.
Result<std::vector<ManagedCilExceptionRegion>> exception_regions(const CilMethodBody &body) {
    struct Scope {
        std::uint32_t begin, end;
        std::size_t clause;
        unsigned kind; // 0 = try, 1 = filter, 2 = handler
    };
    std::vector<Scope> scopes;
    std::map<std::pair<std::uint32_t, std::uint32_t>, std::vector<std::uint32_t>> groups;
    for (std::size_t i = 0; i < body.exception_clauses.size(); ++i) {
        const auto &clause = body.exception_clauses[i];
        const auto try_end = clause.try_offset + clause.try_length;
        const auto handler_end = clause.handler_offset + clause.handler_length;
        const auto overlaps_try = [&](std::uint32_t begin, std::uint32_t end) {
            return begin < try_end && clause.try_offset < end;
        };
        if (overlaps_try(clause.handler_offset, handler_end) ||
            (clause.kind == CilExceptionKind::filter && overlaps_try(clause.filter_offset, clause.handler_offset)))
            return failure(ErrorCode::malformed, "CIL exception handler or filter overlaps its own protected try");
        groups[{clause.try_offset, clause.try_length}].push_back(static_cast<std::uint32_t>(i));
        scopes.push_back({clause.try_offset, try_end, i, 0});
        scopes.push_back({clause.handler_offset, handler_end, i, 2});
        if (clause.kind == CilExceptionKind::filter)
            scopes.push_back({clause.filter_offset, clause.handler_offset, i, 1});
    }
    std::sort(scopes.begin(), scopes.end(), [](const auto &a, const auto &b) {
        if (a.begin != b.begin) return a.begin < b.begin;
        if (a.end != b.end) return a.end > b.end;
        if (a.kind != b.kind) return a.kind < b.kind;
        return a.clause < b.clause;
    });
    std::vector<Scope> nesting;
    using ScopeKey = std::tuple<std::uint32_t, std::uint32_t, unsigned>;
    std::map<ScopeKey, std::optional<ScopeKey>> scope_parents;
    for (const auto &scope : scopes) {
        while (!nesting.empty() && scope.begin >= nesting.back().end) nesting.pop_back();
        if (!nesting.empty()) {
            const auto &parent = nesting.back();
            if (scope.end > parent.end)
                return failure(ErrorCode::unsupported, "CIL exception scopes overlap without lexical containment");
            if (scope.begin == parent.begin && scope.end == parent.end) {
                if (scope.kind == 0 && parent.kind == 0) continue;
                return failure(ErrorCode::unsupported, "CIL exception scopes alias a handler or filter range");
            }
            if (parent.kind == 1)
                return failure(ErrorCode::unsupported, "Nested exception regions inside CIL filter code are not modeled");
            const auto parent_kind = body.exception_clauses[parent.clause].kind;
            if (parent.kind == 2 && (parent_kind == CilExceptionKind::finally_clause ||
                                     parent_kind == CilExceptionKind::fault_clause))
                return failure(ErrorCode::unsupported, "Nested exception regions inside finally or fault require saved unwind state");
        }
        const auto parent = nesting.empty() ? std::optional<ScopeKey>{} :
            std::optional<ScopeKey>{ScopeKey{nesting.back().begin, nesting.back().end, nesting.back().kind}};
        scope_parents.emplace(ScopeKey{scope.begin, scope.end, scope.kind}, parent);
        nesting.push_back(scope);
    }
    // A nested EH construct must fit as a whole in one enclosing scope.
    // A try nested in an outer try with its handler outside that outer try
    // cannot be interpreted by simply sorting the protected interval lengths.
    for (const auto &clause : body.exception_clauses) {
        const auto &parent = scope_parents.at({clause.try_offset, clause.try_offset + clause.try_length, 0});
        if (parent != scope_parents.at({clause.handler_offset, clause.handler_offset + clause.handler_length, 2}) ||
            (clause.kind == CilExceptionKind::filter &&
             parent != scope_parents.at({clause.filter_offset, clause.handler_offset, 1})))
            return failure(ErrorCode::unsupported, "CIL nested try and handlers do not share one enclosing exception scope");
    }
    std::vector<ManagedCilExceptionRegion> result;
    result.reserve(groups.size());
    for (auto &[range, clauses] : groups)
        result.push_back({range.first, range.second, std::move(clauses)});
    return result;
}

std::string exception_region_legend(const ManagedCilDecompilation &method, bool structured = false) {
    std::ostringstream out;
    out << "// CLR exception regions: half-open IL ranges; nested tries search first.\n";
    const auto range = [&](std::uint32_t begin, std::uint32_t length) {
        out << "[IL_" << std::hex << std::setfill('0') << std::setw(4) << begin
            << ", IL_" << std::setw(4) << begin + length << ")" << std::dec;
    };
    for (const auto &region : method.exception_regions) {
        out << "// try "; range(region.try_offset, region.try_length); out << '\n';
        for (const auto index : region.clause_indices) {
            const auto &clause = method.exception_clauses[index];
            out << "//   clause " << index << ": ";
            if (clause.kind == CilExceptionKind::catch_clause)
                out << "catch (type_token(0x" << std::hex << clause.class_token << std::dec << ") exception) ";
            else if (clause.kind == CilExceptionKind::filter) {
                out << "filter "; range(clause.filter_offset, clause.handler_offset - clause.filter_offset);
                out << " -> catch (exception) ";
            } else out << (clause.kind == CilExceptionKind::finally_clause ? "finally " : "fault ");
            range(clause.handler_offset, clause.handler_length);
            out << "; entry stack = " << ((clause.kind == CilExceptionKind::catch_clause ||
                clause.kind == CilExceptionKind::filter) ? "[exception reference]" : "[]") << '\n';
        }
    }
    out << (structured
        ? "// Structured lexical EH; CLR runtime type matching and exceptional propagation remain opaque. Full dispatch/unwind CFG is retained.\n"
        : "// Dispatch and unwind below are explicit; runtime type matching remains opaque.\n");
    return out.str();
}
}

Result<ManagedCilDecompilation> decompile_managed_method(
    const ManagedMethodAnalysis &method,
    const std::map<std::uint32_t, ManagedCallSignature> &call_signatures) try {
    const auto &resolved_signatures = call_signatures.empty() ? method.resolved_call_signatures : call_signatures;
    if (method.status == ManagedMethodStatus::malformed)
        return failure(ErrorCode::malformed, "Cannot decompile malformed managed method body");
    if (method.status != ManagedMethodStatus::decoded || !method.body)
        return failure(ErrorCode::unsupported, "Managed method has no decoded IL body");
    if (method.body->has_more_sections && method.body->exception_clauses.empty())
        return failure(ErrorCode::unsupported, "Managed method has extra data sections that are not supported");
    if (std::any_of(method.body->data_sections.begin(), method.body->data_sections.end(),
                    [](const auto &section) { return section.kind != 1; }))
        return failure(ErrorCode::unsupported, "Managed method contains a non-EH data section with unmodeled semantics");
    if (method.body->exception_clauses.size() > 4096)
        return Error{ErrorCode::resource_limit, "Managed method exception-clause limit exceeded"};
    if (method.body->code_size > 16 * 1024 * 1024)
        return failure(ErrorCode::resource_limit, "Managed CIL method exceeds the 16 MiB inspection limit");
    if (method.instructions.empty()) return failure(ErrorCode::malformed, "Managed method has an empty IL instruction stream");
    if (method.instructions.size() > 1'000'000) return failure(ErrorCode::resource_limit, "Managed method instruction limit exceeded");

    std::unordered_map<std::uint32_t, std::size_t> instruction_at;
    std::set<std::uint32_t> leaders{method.instructions.front().offset};
    for (const auto &clause : method.body->exception_clauses) {
        const auto valid_range = [&](std::uint32_t start, std::uint32_t length) {
            return length != 0 && start <= method.body->code_size && length <= method.body->code_size - start;
        };
        if (!valid_range(clause.try_offset, clause.try_length) || !valid_range(clause.handler_offset, clause.handler_length))
            return failure(ErrorCode::malformed, "CIL exception region range is empty or outside the method body");
        if (clause.kind != CilExceptionKind::catch_clause && clause.kind != CilExceptionKind::filter &&
            clause.kind != CilExceptionKind::finally_clause && clause.kind != CilExceptionKind::fault_clause)
            return failure(ErrorCode::malformed, "CIL exception clause has an invalid kind");
        if (clause.kind == CilExceptionKind::catch_clause && !valid_type_token(clause.class_token))
            return failure(ErrorCode::malformed, "CIL catch clause has an invalid exception type token");
        if (clause.kind == CilExceptionKind::filter) {
            if (clause.filter_offset >= clause.handler_offset || clause.handler_offset > method.body->code_size)
                return failure(ErrorCode::malformed, "CIL filter region is empty or outside the method body");
            leaders.insert(clause.filter_offset);
            if (!std::any_of(method.instructions.begin(), method.instructions.end(), [&](const auto &candidate) {
                    return candidate.offset >= clause.filter_offset && candidate.offset < clause.handler_offset &&
                           std::string_view(candidate.mnemonic) == "endfilter";
                }))
                return failure(ErrorCode::unsupported, "CIL filter region has no modeled endfilter instruction");
        }
        leaders.insert(clause.try_offset);
        if (clause.try_offset + clause.try_length < method.body->code_size) leaders.insert(clause.try_offset + clause.try_length);
        leaders.insert(clause.handler_offset);
        if (clause.handler_offset + clause.handler_length < method.body->code_size) leaders.insert(clause.handler_offset + clause.handler_length);
    }
    const auto in_region = [](std::uint32_t offset, std::uint32_t start, std::uint32_t length) {
        return offset >= start && offset - start < length;
    };
    auto regions = exception_regions(*method.body);
    if (!regions) return regions.error();
    for (std::size_t i = 0; i < method.body->exception_clauses.size(); ++i) {
        const auto &filter = method.body->exception_clauses[i];
        if (filter.kind != CilExceptionKind::filter) continue;
        if (filter.filter_offset == method.instructions.front().offset)
            return failure(ErrorCode::unsupported, "CIL filter code cannot be the method entry");
        const auto filter_end = filter.handler_offset;
        const auto overlaps = [&](std::uint32_t start, std::uint32_t length) {
            const auto end = std::uint64_t{start} + length;
            return start < filter_end && filter.filter_offset < end;
        };
        if (overlaps(filter.try_offset, filter.try_length))
            return failure(ErrorCode::malformed, "CIL filter code overlaps its protected try region");
        for (std::size_t j = 0; j < method.body->exception_clauses.size(); ++j) {
            if (i == j) continue;
            const auto &other = method.body->exception_clauses[j];
            const auto nested_or_crossing = [&](std::uint32_t start, std::uint32_t length) {
                return overlaps(start, length) &&
                       !(start <= filter.filter_offset && std::uint64_t{start} + length >= filter_end);
            };
            if (nested_or_crossing(other.try_offset, other.try_length) ||
                nested_or_crossing(other.handler_offset, other.handler_length) ||
                (other.kind == CilExceptionKind::filter &&
                 nested_or_crossing(other.filter_offset, other.handler_offset - other.filter_offset)))
                return failure(ErrorCode::unsupported, "Nested exception regions inside CIL filter code are not modeled");
        }
    }
    for (std::size_t i = 0; i < method.instructions.size(); ++i) {
        const auto &instruction = method.instructions[i];
        const auto expected_offset = i == 0 ? 0u :
            method.instructions[i - 1].offset + method.instructions[i - 1].size;
        if (instruction.offset != expected_offset || instruction.size == 0 ||
            instruction.offset > method.body->code_size || instruction.size > method.body->code_size - instruction.offset)
            return failure(ErrorCode::malformed, "Managed IL instructions do not form a contiguous bounded method body");
        if (!instruction_at.emplace(instruction.offset, i).second)
            return failure(ErrorCode::malformed, "Managed IL instruction offsets overlap");
        if (instruction.offset > UINT32_MAX - instruction.size)
            return failure(ErrorCode::malformed, "Managed IL instruction extent overflows");
        const auto mnemonic = std::string_view(instruction.mnemonic);
        if (!method.body->exception_clauses.empty()) {
            const auto covered = [&](const CilExceptionClause &clause) {
                return in_region(instruction.offset, clause.try_offset, clause.try_length) ||
                       in_region(instruction.offset, clause.handler_offset, clause.handler_length) ||
                       (clause.kind == CilExceptionKind::filter &&
                        in_region(instruction.offset, clause.filter_offset,
                                  clause.handler_offset - clause.filter_offset));
            };
            if (std::any_of(method.body->exception_clauses.begin(), method.body->exception_clauses.end(), covered)) {
                // Exceptional state is instruction-specific. Keep every covered
                // IL instruction in its own source block so SSA cannot collapse
                // several possible throws onto one normal-exit predecessor.
                leaders.insert(instruction.offset);
                const auto next = instruction.offset + instruction.size;
                if (next < method.body->code_size) leaders.insert(next);
            }
        }
        const bool terminal = mnemonic == "ret" || mnemonic == "throw" || mnemonic == "rethrow" ||
                              mnemonic == "endfinally" || mnemonic == "endfilter";
        if (terminal && i + 1 < method.instructions.size()) leaders.insert(instruction.offset + instruction.size);
        // Continuation tables use the actual endfinally as their source.
        // Its block may follow a nontrivial handler body.
        if (mnemonic == "endfinally") leaders.insert(instruction.offset);
        const CilExceptionClause *innermost_handler = nullptr;
        bool inside_try = false;
        for (const auto &clause : method.body->exception_clauses) {
            inside_try |= in_region(instruction.offset, clause.try_offset, clause.try_length);
            if (in_region(instruction.offset, clause.handler_offset, clause.handler_length) &&
                (!innermost_handler || clause.handler_length < innermost_handler->handler_length))
                innermost_handler = &clause;
        }
        if (i == 0 && innermost_handler)
            return failure(ErrorCode::malformed, "CIL method entry cannot be an exception handler");
        if (mnemonic == "ret" && (inside_try || innermost_handler))
            return failure(ErrorCode::malformed, "CIL ret cannot exit a protected try or exception handler; leave is required");
        if (mnemonic == "endfinally" && (!innermost_handler ||
            (innermost_handler->kind != CilExceptionKind::finally_clause &&
             innermost_handler->kind != CilExceptionKind::fault_clause)))
            return failure(ErrorCode::malformed, "CIL endfinally is outside a finally or fault handler");
        if ((mnemonic == "leave" || mnemonic == "leave.s") && innermost_handler &&
            (innermost_handler->kind == CilExceptionKind::finally_clause ||
             innermost_handler->kind == CilExceptionKind::fault_clause))
            return failure(ErrorCode::malformed, "CIL leave cannot exit a finally or fault handler");
        if (mnemonic == "rethrow" && innermost_handler &&
            innermost_handler->kind != CilExceptionKind::catch_clause && innermost_handler->kind != CilExceptionKind::filter)
            return failure(ErrorCode::malformed, "CIL rethrow is inside a non-catch handler");
        if (std::string_view(instruction.mnemonic) == "endfilter") {
            const auto filter = std::find_if(method.body->exception_clauses.begin(), method.body->exception_clauses.end(),
                [&](const auto &clause) {
                    return clause.kind == CilExceptionKind::filter &&
                           in_region(instruction.offset, clause.filter_offset, clause.handler_offset - clause.filter_offset);
                });
            if (filter == method.body->exception_clauses.end())
                return failure(ErrorCode::malformed, "CIL endfilter is outside a filter region");
            if (i + 1 < method.instructions.size()) leaders.insert(instruction.offset + instruction.size);
        }
        const bool inside_filter_code = std::any_of(method.body->exception_clauses.begin(), method.body->exception_clauses.end(),
            [&](const auto &clause) {
                return clause.kind == CilExceptionKind::filter &&
                       in_region(instruction.offset, clause.filter_offset, clause.handler_offset - clause.filter_offset);
            });
        if (inside_filter_code && std::string_view(instruction.mnemonic) == "rethrow")
            return failure(ErrorCode::unsupported, "CIL rethrow is not valid or modeled inside filter code");
        if (inside_filter_code && (std::string_view(instruction.mnemonic) == "ret" ||
                                   std::string_view(instruction.mnemonic) == "endfinally"))
            return failure(ErrorCode::malformed, "CIL filter code ends with an opcode other than endfilter");
        if (std::string_view(instruction.mnemonic) == "rethrow" &&
            std::none_of(method.body->exception_clauses.begin(), method.body->exception_clauses.end(), [&](const auto &clause) {
                return (clause.kind == CilExceptionKind::catch_clause || clause.kind == CilExceptionKind::filter) &&
                       in_region(instruction.offset, clause.handler_offset, clause.handler_length);
            }))
            return failure(ErrorCode::malformed, "CIL rethrow is not enclosed by a catch handler");
        const auto next = instruction.offset + instruction.size;
        const bool unconditional = terminal || mnemonic == "br" || mnemonic == "br.s" ||
                                   mnemonic == "leave" || mnemonic == "leave.s";
        if (!unconditional && next == method.body->code_size && !method.body->exception_clauses.empty())
            return failure(ErrorCode::malformed, "CIL exception method falls through the end of its instruction stream");
        if (!unconditional && next < method.body->code_size) {
            for (const auto &clause : method.body->exception_clauses) {
                const bool source_try = in_region(instruction.offset, clause.try_offset, clause.try_length);
                const bool target_try = in_region(next, clause.try_offset, clause.try_length);
                const bool source_handler = in_region(instruction.offset, clause.handler_offset, clause.handler_length);
                const bool target_handler = in_region(next, clause.handler_offset, clause.handler_length);
                const bool source_filter = clause.kind == CilExceptionKind::filter &&
                    in_region(instruction.offset, clause.filter_offset, clause.handler_offset - clause.filter_offset);
                const bool target_filter = clause.kind == CilExceptionKind::filter &&
                    in_region(next, clause.filter_offset, clause.handler_offset - clause.filter_offset);
                if ((source_try && !target_try) || source_handler != target_handler || source_filter != target_filter)
                    return failure(ErrorCode::malformed, "CIL fallthrough crosses an exception-region exit or handler entry");
            }
        }
        for (const auto &clause : method.body->exception_clauses) {
            if (clause.kind != CilExceptionKind::filter ||
                (next != clause.filter_offset && next != clause.handler_offset)) continue;
            const auto mnemonic = std::string_view(instruction.mnemonic);
            const bool unconditional = mnemonic == "br" || mnemonic == "br.s" ||
                                      mnemonic == "leave" || mnemonic == "leave.s" ||
                                      mnemonic == "ret" || mnemonic == "throw" || mnemonic == "rethrow" ||
                                      mnemonic == "endfinally" || mnemonic == "endfilter";
            if (!unconditional && next == clause.filter_offset)
                return failure(ErrorCode::unsupported, "Normal CIL control flow falls into filter code");
            if (!unconditional && next == clause.handler_offset)
                return failure(ErrorCode::unsupported, "CIL filter code falls into its catch handler without endfilter");
        }
        if (const auto *branch = std::get_if<CilBranchOperand>(&instruction.operand)) {
            leaders.insert(branch->target_offset);
            if (i + 1 < method.instructions.size()) leaders.insert(next);
        } else if (const auto *table = std::get_if<CilSwitchOperand>(&instruction.operand)) {
            for (const auto target : table->target_offsets) leaders.insert(target);
            if (i + 1 < method.instructions.size()) leaders.insert(next);
        }
    }
    if (method.instructions.back().offset + method.instructions.back().size != method.body->code_size)
        return failure(ErrorCode::malformed, "Managed IL instruction stream does not cover the method body");
    for (const auto &clause : method.body->exception_clauses) {
        std::vector<std::uint32_t> boundaries{clause.try_offset, clause.try_offset + clause.try_length,
            clause.handler_offset, clause.handler_offset + clause.handler_length};
        if (clause.kind == CilExceptionKind::filter) boundaries.push_back(clause.filter_offset);
        for (const auto boundary : boundaries) {
            if (boundary != method.body->code_size && !instruction_at.contains(boundary))
                return failure(ErrorCode::malformed, "CIL exception region boundary is not an instruction boundary");
        }
    }
    for (const auto &instruction : method.instructions) {
        if (const auto *table = std::get_if<CilSwitchOperand>(&instruction.operand)) {
            for (const auto target_offset : table->target_offsets) {
                for (const auto &clause : method.body->exception_clauses) {
                    const bool source_in_try = in_region(instruction.offset, clause.try_offset, clause.try_length);
                    const bool target_in_try = in_region(target_offset, clause.try_offset, clause.try_length);
                    const bool source_in_handler = in_region(instruction.offset, clause.handler_offset, clause.handler_length);
                    const bool target_in_handler = in_region(target_offset, clause.handler_offset, clause.handler_length);
                    const bool source_in_filter = clause.kind == CilExceptionKind::filter &&
                        in_region(instruction.offset, clause.filter_offset, clause.handler_offset - clause.filter_offset);
                    const bool target_in_filter = clause.kind == CilExceptionKind::filter &&
                        in_region(target_offset, clause.filter_offset, clause.handler_offset - clause.filter_offset);
                    if (source_in_try != target_in_try || source_in_handler != target_in_handler ||
                        source_in_filter != target_in_filter)
                        return failure(ErrorCode::unsupported,
                            "CIL switch target crosses an exception-region boundary without leave");
                }
            }
        }
        const auto *branch = std::get_if<CilBranchOperand>(&instruction.operand);
        if (!branch) continue;
        const std::string_view mnemonic = instruction.mnemonic;
        const bool is_leave = mnemonic == "leave" || mnemonic == "leave.s";
        for (const auto &clause : method.body->exception_clauses) {
            const bool source_in_try = in_region(instruction.offset, clause.try_offset, clause.try_length);
            const bool target_in_try = in_region(branch->target_offset, clause.try_offset, clause.try_length);
            const bool source_in_handler = in_region(instruction.offset, clause.handler_offset, clause.handler_length);
            const bool target_in_handler = in_region(branch->target_offset, clause.handler_offset, clause.handler_length);
            const bool source_in_filter = clause.kind == CilExceptionKind::filter &&
                in_region(instruction.offset, clause.filter_offset, clause.handler_offset - clause.filter_offset);
            const bool target_in_filter = clause.kind == CilExceptionKind::filter &&
                in_region(branch->target_offset, clause.filter_offset, clause.handler_offset - clause.filter_offset);
            if (source_in_filter != target_in_filter)
                return failure(ErrorCode::unsupported, "CIL branch crosses a filter boundary");
            if (source_in_filter && is_leave)
                return failure(ErrorCode::unsupported, "CIL leave inside filter code is not modeled");
            if (is_leave) {
                if ((!source_in_try && target_in_try) || (!source_in_handler && target_in_handler))
                    return failure(ErrorCode::unsupported, "CIL leave enters a protected region or handler");
            } else if (source_in_try != target_in_try || source_in_handler != target_in_handler) {
                return failure(ErrorCode::unsupported, "CIL branch crosses an exception-region boundary without leave");
            }
        }
    }
    if (leaders.size() > 100'000) return failure(ErrorCode::resource_limit, "Managed method basic-block limit exceeded");
    std::vector<std::uint32_t> starts(leaders.begin(), leaders.end());
    std::unordered_map<std::uint32_t, std::size_t> block_for_offset;
    ManagedCilDecompilation result;
    result.exception_clauses = method.body->exception_clauses;
    result.exception_regions = std::move(regions.value());
    result.declaring_type_generic_parameters = method.method.declaring_type_generic_parameters;
    result.method_generic_parameters = method.method.generic_parameters;
    if (!method.body->exception_clauses.empty()) {
        result.complete = false;
        result.lifted.diagnostics.push_back(
            "CIL exception regions expose ordered catch/filter dispatch and explicit finally/fault continuations; type matching is proven only for direct newobj throws with validated in-module assignability, while other runtime exception types, filter throwability, and full unwind semantics remain incomplete");
    }
    result.lifted.id = {method.method.token};
    result.lifted.entry = il_address(starts.front());
    result.lifted.blocks.reserve(starts.size());
    for (const auto &clause : method.body->exception_clauses)
        if (clause.kind == CilExceptionKind::catch_clause && clause.class_token)
            result.referenced_tokens.push_back(clause.class_token);
    for (std::size_t i = 0; i < starts.size(); ++i) {
        auto found = instruction_at.find(starts[i]);
        if (found == instruction_at.end()) return failure(ErrorCode::malformed, "CIL control-flow target is not an instruction boundary");
        block_for_offset.emplace(starts[i], i);
        result.lifted.blocks.push_back({BlockId{std::uint64_t{starts[i]} + 1}, il_address(starts[i])});
    }
    auto block_index_for = [&](std::uint32_t offset) -> std::optional<std::size_t> {
        auto it = block_for_offset.find(offset);
        if (it == block_for_offset.end()) return {};
        return it->second;
    };
    using AddressKey = std::pair<std::uint32_t, std::uint64_t>;
    std::vector<LiftedBlock> synthetic_blocks;
    std::map<AddressKey, BlockId> synthetic_block_ids;
    bool synthetic_block_limit_exceeded = false;
    constexpr std::size_t max_exception_dispatch_blocks = 100'000;
    std::uint64_t next_synthetic_address = 1;
    std::uint64_t next_synthetic_id = 0x8000000000000000ULL;
    auto make_synthetic_block = [&]() {
        LiftedBlock block;
        if (synthetic_blocks.size() >= max_exception_dispatch_blocks) {
            synthetic_block_limit_exceeded = true;
            return block;
        }
        block.id = BlockId{next_synthetic_id++};
        block.begin = Address{{UINT32_MAX}, next_synthetic_address++};
        synthetic_block_ids.emplace(AddressKey{block.begin.space.value, block.begin.offset}, block.id);
        return block;
    };
    auto synthetic_id_for = [&](const Address &address) -> std::optional<BlockId> {
        const auto found = synthetic_block_ids.find({address.space.value, address.offset});
        if (found == synthetic_block_ids.end()) return {};
        return found->second;
    };
    auto block_id_for_address = [&](const Address &address) -> std::optional<BlockId> {
        if (address.space.value == 0) {
            if (address.offset > UINT32_MAX) return {};
            const auto index = block_index_for(static_cast<std::uint32_t>(address.offset));
            if (!index) return {};
            return result.lifted.blocks[*index].id;
        }
        return synthetic_id_for(address);
    };
    struct FinallyContinuation {
        std::uint32_t id = 0;
        std::uint32_t source = 0;
        std::uint32_t target = 0;
        std::vector<std::uint32_t> handlers;
    };
    struct FinallyDispatchRoute {
        std::uint32_t id = 0;
        Address target;
        bool exceptional = false;
    };
    std::map<std::uint32_t, FinallyContinuation> finally_continuations;
    std::map<std::uint32_t, std::vector<FinallyDispatchRoute>> endfinally_routes;
    std::size_t endfinally_route_count = 0;
    constexpr std::size_t max_endfinally_routes = 1'000'000;
    struct FilterDispatchRoute {
        std::uint32_t id = 0;
        Address decision;
    };
    std::map<std::uint32_t, std::vector<FilterDispatchRoute>> endfilter_routes;
    std::size_t endfilter_route_count = 0;
    constexpr std::size_t max_endfilter_routes = 1'000'000;
    for (const auto &instruction : method.instructions) {
        const std::string_view mnemonic = instruction.mnemonic;
        if (mnemonic != "leave" && mnemonic != "leave.s") continue;
        const auto *branch = std::get_if<CilBranchOperand>(&instruction.operand);
        if (!branch) return failure(ErrorCode::malformed, "Missing CIL leave target");
        FinallyContinuation continuation;
        continuation.id = static_cast<std::uint32_t>(finally_continuations.size() + 1);
        continuation.source = instruction.offset;
        continuation.target = branch->target_offset;
        std::vector<const CilExceptionClause *> exited;
        for (const auto &clause : method.body->exception_clauses) {
            if (clause.kind != CilExceptionKind::finally_clause) continue;
            const auto try_end = clause.try_offset + clause.try_length;
            if (instruction.offset >= clause.try_offset && instruction.offset < try_end &&
                !(branch->target_offset >= clause.try_offset && branch->target_offset < try_end))
                exited.push_back(&clause);
        }
        std::sort(exited.begin(), exited.end(), [](const auto *a, const auto *b) {
            if (a->try_length != b->try_length) return a->try_length < b->try_length;
            return a->try_offset > b->try_offset;
        });
        for (std::size_t i = 1; i < exited.size(); ++i) {
            const auto *inner = exited[i - 1];
            const auto *outer = exited[i];
            const auto inner_end = inner->try_offset + inner->try_length;
            const auto outer_end = outer->try_offset + outer->try_length;
            if (inner->try_offset < outer->try_offset || inner_end > outer_end ||
                (inner->try_offset == outer->try_offset && inner->try_length == outer->try_length))
                return failure(ErrorCode::unsupported, "CIL leave crosses overlapping or ambiguous finally regions");
        }
        for (const auto *clause : exited) continuation.handlers.push_back(clause->handler_offset);
        if (continuation.handlers.empty()) continue;
        for (std::size_t h = 0; h < continuation.handlers.size(); ++h) {
            const auto handler_offset = continuation.handlers[h];
            const auto clause = std::find_if(exited.begin(), exited.end(), [&](const auto *candidate) {
                return candidate->handler_offset == handler_offset;
            });
            if (clause == exited.end()) return failure(ErrorCode::malformed, "CIL finally continuation lost its clause");
            const auto handler_end = (*clause)->handler_offset + (*clause)->handler_length;
            bool found_endfinally = false;
            for (const auto &candidate : method.instructions) {
                if (candidate.offset >= handler_offset && candidate.offset < handler_end && std::string_view(candidate.mnemonic) == "endfinally") {
                    const auto next_address = il_address(h + 1 < continuation.handlers.size()
                        ? continuation.handlers[h + 1] : continuation.target);
                    if (++endfinally_route_count > max_endfinally_routes)
                        return Error{ErrorCode::resource_limit, "CIL finally continuation-route limit exceeded"};
                    endfinally_routes[candidate.offset].push_back({continuation.id, next_address, false});
                    found_endfinally = true;
                }
            }
            if (!found_endfinally) return failure(ErrorCode::unsupported, "CIL finally handler has no modeled endfinally continuation");
        }
        finally_continuations.emplace(continuation.source, std::move(continuation));
    }

    struct ExceptionProfile {
        std::vector<std::size_t> catches;
        std::vector<std::vector<std::size_t>> finalies_before_catch;
        std::vector<std::size_t> finalies_unhandled;
    };
    const auto active_exception_profile = [&](const std::vector<std::size_t> &active_clauses) -> Result<ExceptionProfile> {
        ExceptionProfile profile;
        std::vector<std::size_t> active_finalies;
        for (const auto i : active_clauses) {
            const auto &clause = method.body->exception_clauses[i];
            if (clause.kind == CilExceptionKind::catch_clause || clause.kind == CilExceptionKind::filter)
                profile.catches.push_back(i);
            else if (clause.kind == CilExceptionKind::finally_clause || clause.kind == CilExceptionKind::fault_clause)
                active_finalies.push_back(i);
        }
        std::stable_sort(profile.catches.begin(), profile.catches.end(), [&](auto a, auto b) {
            return method.body->exception_clauses[a].try_length < method.body->exception_clauses[b].try_length;
        });
        std::sort(active_finalies.begin(), active_finalies.end(), [&](auto a, auto b) {
            const auto &left = method.body->exception_clauses[a];
            const auto &right = method.body->exception_clauses[b];
            if (left.try_length != right.try_length) return left.try_length < right.try_length;
            return left.try_offset > right.try_offset;
        });
        for (std::size_t i = 1; i < active_finalies.size(); ++i) {
            const auto &inner = method.body->exception_clauses[active_finalies[i - 1]];
            const auto &outer = method.body->exception_clauses[active_finalies[i]];
            const auto inner_end = inner.try_offset + inner.try_length;
            const auto outer_end = outer.try_offset + outer.try_length;
            if (inner.try_offset < outer.try_offset || inner_end > outer_end ||
                (inner.try_offset == outer.try_offset && inner.try_length == outer.try_length))
                return Error{ErrorCode::unsupported, "CIL exception unwind has overlapping or ambiguous finally regions"};
        }
        profile.finalies_unhandled = active_finalies;
        for (const auto catch_index : profile.catches) {
            const auto handler_offset = method.body->exception_clauses[catch_index].handler_offset;
            std::vector<std::size_t> exiting;
            for (const auto finally_index : active_finalies) {
                const auto &finally_clause = method.body->exception_clauses[finally_index];
                if (!in_region(handler_offset, finally_clause.try_offset, finally_clause.try_length))
                    exiting.push_back(finally_index);
            }
            profile.finalies_before_catch.push_back(std::move(exiting));
        }
        return profile;
    };
    std::optional<Address> unhandled_exception_address;
    const auto ensure_unhandled_exception_block = [&]() -> Result<Address> {
        if (unhandled_exception_address) return *unhandled_exception_address;
        auto block = make_synthetic_block();
        if (synthetic_block_limit_exceeded)
            return Error{ErrorCode::resource_limit, "CIL exception dispatcher block limit exceeded"};
        block.instructions.push_back({{block.begin, (std::uint64_t{method.method.token} << 32) | block.begin.offset},
            Intrinsic{"exception_unhandled", {}, IntrinsicMemoryEffect::none}});
        unhandled_exception_address = block.begin;
        synthetic_blocks.push_back(std::move(block));
        return *unhandled_exception_address;
    };
    std::uint64_t next_exception_continuation = finally_continuations.size() + 1;
    const auto route_through_finally = [&](const std::vector<std::size_t> &finally_indices,
                                           Address target) -> Result<Address> {
        if (finally_indices.empty()) return target;
        if (next_exception_continuation > UINT32_MAX)
            return Error{ErrorCode::resource_limit, "CIL exception continuation limit exceeded"};
        const auto id = static_cast<std::uint32_t>(next_exception_continuation++);
        std::vector<std::uint32_t> handlers;
        handlers.reserve(finally_indices.size());
        for (const auto index : finally_indices)
            handlers.push_back(method.body->exception_clauses[index].handler_offset);
        for (std::size_t h = 0; h < finally_indices.size(); ++h) {
            const auto &clause = method.body->exception_clauses[finally_indices[h]];
            const auto handler_end = clause.handler_offset + clause.handler_length;
            bool found_endfinally = false;
            for (const auto &instruction : method.instructions) {
                if (instruction.offset < clause.handler_offset || instruction.offset >= handler_end ||
                    std::string_view(instruction.mnemonic) != "endfinally") continue;
                const auto next = h + 1 < handlers.size() ? il_address(handlers[h + 1]) : target;
                if (++endfinally_route_count > max_endfinally_routes)
                    return Error{ErrorCode::resource_limit, "CIL finally continuation-route limit exceeded"};
                endfinally_routes[instruction.offset].push_back({id, next, true});
                found_endfinally = true;
            }
            if (!found_endfinally)
                return Error{ErrorCode::unsupported, "CIL exceptional unwind requires a finally handler with a modeled endfinally"};
        }
        auto route = make_synthetic_block();
        if (synthetic_block_limit_exceeded)
            return Error{ErrorCode::resource_limit, "CIL exception dispatcher block limit exceeded"};
        const RegisterOperand continuation_reg{RegisterBank::cil_continuation, 0, 32, false};
        const auto first_handler = il_address(handlers.front());
        const auto first_handler_index = block_index_for(handlers.front());
        if (!first_handler_index)
            return Error{ErrorCode::malformed, "CIL finally handler has no basic block"};
        route.instructions.push_back({{route.begin, (std::uint64_t{method.method.token} << 32) | route.begin.offset},
            Assign{continuation_reg,
                std::make_shared<Expression>(Expression{int_type(32), ConstantValue{id, int_type(32)}}), {}}});
        route.instructions.push_back({{route.begin, (std::uint64_t{method.method.token} << 32) | route.begin.offset},
            Branch{"true", first_handler, {}, {}}});
        route.successors.push_back({route.begin, first_handler,
            result.lifted.blocks[*first_handler_index].id, BlockEdgeKind::jump});
        const auto address = route.begin;
        synthetic_blocks.push_back(std::move(route));
        return address;
    };
    std::map<std::string, Address> exception_profile_entries;
    std::vector<std::pair<std::size_t, Address>> instruction_exception_entries;
    instruction_exception_entries.reserve(method.instructions.size());
    struct ClauseEvent { std::uint32_t offset = 0; std::size_t clause = 0; bool enter = false; };
    std::vector<ClauseEvent> clause_events;
    clause_events.reserve(method.body->exception_clauses.size() * 2);
    for (std::size_t i = 0; i < method.body->exception_clauses.size(); ++i) {
        const auto &clause = method.body->exception_clauses[i];
        clause_events.push_back({clause.try_offset, i, true});
        clause_events.push_back({clause.try_offset + clause.try_length, i, false});
    }
    std::sort(clause_events.begin(), clause_events.end(), [](const auto &a, const auto &b) {
        if (a.offset != b.offset) return a.offset < b.offset;
        if (a.enter != b.enter) return !a.enter; // half-open range ends before a range starts at the same offset
        return a.clause < b.clause;
    });
    std::set<std::size_t> active_clause_set;
    std::vector<std::size_t> active_clause_indices;
    std::string active_clause_key;
    std::size_t next_clause_event = 0;
    for (std::size_t ii = 0; ii < method.instructions.size(); ++ii) {
        const auto &instruction = method.instructions[ii];
        const bool explicit_throw = std::string_view(instruction.mnemonic) == "throw" || std::string_view(instruction.mnemonic) == "rethrow";
        bool active_changed = false;
        while (next_clause_event < clause_events.size() && clause_events[next_clause_event].offset <= instruction.offset) {
            const auto &event = clause_events[next_clause_event++];
            if (event.enter) active_clause_set.insert(event.clause);
            else active_clause_set.erase(event.clause);
            active_changed = true;
        }
        if (active_changed) {
            active_clause_indices.assign(active_clause_set.begin(), active_clause_set.end());
            std::ostringstream key;
            for (const auto index : active_clause_indices) key << index << ',';
            active_clause_key = key.str();
        }
        const bool inside_protected_try = !active_clause_indices.empty();
        const bool inside_handler = std::any_of(method.body->exception_clauses.begin(), method.body->exception_clauses.end(),
            [&](const auto &clause) { return in_region(instruction.offset, clause.handler_offset, clause.handler_length); });
        const bool inside_filter_code = std::any_of(method.body->exception_clauses.begin(), method.body->exception_clauses.end(),
            [&](const auto &clause) {
                return clause.kind == CilExceptionKind::filter &&
                       in_region(instruction.offset, clause.filter_offset, clause.handler_offset - clause.filter_offset);
            });
        // Filter failures are wired to the filter's false continuation below.
        // They must not escape through the ordinary method-level dispatcher.
        if (inside_filter_code) continue;
        if (!inside_protected_try && !inside_handler && !explicit_throw) continue;
        const auto direct_thrown_type = directly_constructed_throw_type(method, ii, resolved_signatures, leaders);
        auto key = active_clause_key;
        if (direct_thrown_type)
            key += "|newobj:" + std::to_string(*direct_thrown_type);
        auto existing = exception_profile_entries.find(key);
        if (existing != exception_profile_entries.end()) {
            instruction_exception_entries.emplace_back(ii, existing->second);
            continue;
        }
        auto profile_result = active_exception_profile(active_clause_indices);
        if (!profile_result) return profile_result.error();
        auto profile = std::move(profile_result.value());
        auto unhandled_result = ensure_unhandled_exception_block();
        if (!unhandled_result) return unhandled_result.error();
        auto unhandled_route = route_through_finally(profile.finalies_unhandled, unhandled_result.value());
        if (!unhandled_route) return unhandled_route.error();
        Address next_test = unhandled_route.value();
        for (std::size_t reverse = profile.catches.size(); reverse > 0; --reverse) {
            const auto catch_slot = reverse - 1;
            const auto clause_index = profile.catches[catch_slot];
            const auto &clause = method.body->exception_clauses[clause_index];
            auto match_route = route_through_finally(profile.finalies_before_catch[catch_slot], il_address(clause.handler_offset));
            if (!match_route) return match_route.error();
            if (direct_thrown_type && clause.kind == CilExceptionKind::catch_clause &&
                proven_exception_match(method, *direct_thrown_type, clause.class_token)) {
                // This dispatcher profile is unique to the proven constructed
                // type, so later clauses cannot be reached for this throw.
                next_test = match_route.value();
                continue;
            }
            if (clause.kind == CilExceptionKind::filter) {
                if (next_exception_continuation > UINT32_MAX)
                    return Error{ErrorCode::resource_limit, "CIL filter continuation limit exceeded"};
                const auto id = static_cast<std::uint32_t>(next_exception_continuation++);
                const auto filter_result_reg = RegisterOperand{RegisterBank::cil_continuation, 1, 32, false};
                auto decision = make_synthetic_block();
                if (synthetic_block_limit_exceeded)
                    return Error{ErrorCode::resource_limit, "CIL exception dispatcher block limit exceeded"};
                const auto accepted = match_route.value();
                const auto rejected = next_test;
                auto predicate = binary("!=", std::make_shared<Expression>(Expression{
                    int_type(32), RegisterValue{filter_result_reg, {}}}), constant(0), true);
                decision.instructions.push_back({{decision.begin,
                    (std::uint64_t{method.method.token} << 32) | decision.begin.offset},
                    Branch{"filter_result != 0", accepted, rejected, std::move(predicate)}});
                const auto accepted_id = block_id_for_address(accepted);
                const auto rejected_id = block_id_for_address(rejected);
                if (!accepted_id || !rejected_id)
                    return Error{ErrorCode::malformed, "CIL filter dispatch target has no block"};
                decision.successors.push_back({decision.begin, accepted, *accepted_id, BlockEdgeKind::conditional_true});
                decision.successors.push_back({decision.begin, rejected, *rejected_id, BlockEdgeKind::conditional_false});
                const auto decision_address = decision.begin;
                synthetic_blocks.push_back(std::move(decision));
                std::size_t filter_ends = 0;
                for (const auto &candidate : method.instructions) {
                    if (candidate.offset < clause.filter_offset || candidate.offset >= clause.handler_offset ||
                        std::string_view(candidate.mnemonic) != "endfilter") continue;
                    if (++filter_ends > 4096)
                        return Error{ErrorCode::resource_limit, "CIL filter endfilter-route limit exceeded"};
                    if (++endfilter_route_count > max_endfilter_routes)
                        return Error{ErrorCode::resource_limit, "CIL filter continuation-route limit exceeded"};
                    endfilter_routes[candidate.offset].push_back({id, decision_address});
                }
                auto filter_entry = make_synthetic_block();
                if (synthetic_block_limit_exceeded)
                    return Error{ErrorCode::resource_limit, "CIL exception dispatcher block limit exceeded"};
                const auto filter_begin = il_address(clause.filter_offset);
                const auto filter_block = block_id_for_address(filter_begin);
                if (!filter_block)
                    return Error{ErrorCode::malformed, "CIL filter has no basic block"};
                const auto continuation_reg = RegisterOperand{RegisterBank::cil_continuation, 0, 32, false};
                filter_entry.instructions.push_back({{filter_entry.begin,
                    (std::uint64_t{method.method.token} << 32) | filter_entry.begin.offset},
                    Assign{continuation_reg, std::make_shared<Expression>(Expression{
                        int_type(32), ConstantValue{id, int_type(32)}}), {}}});
                filter_entry.instructions.push_back({{filter_entry.begin,
                    (std::uint64_t{method.method.token} << 32) | filter_entry.begin.offset},
                    Branch{"true", filter_begin, {}, {}}});
                filter_entry.successors.push_back({filter_entry.begin, filter_begin, *filter_block, BlockEdgeKind::jump});
                next_test = filter_entry.begin;
                synthetic_blocks.push_back(std::move(filter_entry));
                continue;
            }
            std::ostringstream condition;
            if (const auto type_name = method.resolved_exception_type_names.find(clause.class_token);
                type_name != method.resolved_exception_type_names.end()) {
                condition << "exception_matches_type_name(" << quoted_metadata_name(type_name->second)
                          << ", 0x" << std::hex << clause.class_token << ')';
            } else {
                condition << "exception_matches_type_token(0x" << std::hex << clause.class_token << ')';
            }
            auto predicate = std::make_shared<Expression>(Expression{{TypeKind::boolean, 1, false},
                UnknownValue{"opaque CLR exception assignability predicate for token " + condition.str()}});
            auto dispatch = make_synthetic_block();
            if (synthetic_block_limit_exceeded)
                return Error{ErrorCode::resource_limit, "CIL exception dispatcher block limit exceeded"};
            dispatch.instructions.push_back({{dispatch.begin,
                (std::uint64_t{method.method.token} << 32) | dispatch.begin.offset},
                Branch{condition.str(), match_route.value(), next_test, std::move(predicate)}});
            const auto true_id = synthetic_id_for(match_route.value());
            const auto false_id = synthetic_id_for(next_test);
            const auto true_il = match_route.value().space.value == 0
                ? block_index_for(static_cast<std::uint32_t>(match_route.value().offset)) : std::nullopt;
            const auto false_il = next_test.space.value == 0
                ? block_index_for(static_cast<std::uint32_t>(next_test.offset)) : std::nullopt;
            const auto true_target_id = true_id ? true_id :
                (true_il ? std::optional<BlockId>{result.lifted.blocks[*true_il].id} : std::nullopt);
            const auto false_target_id = false_id ? false_id :
                (false_il ? std::optional<BlockId>{result.lifted.blocks[*false_il].id} : std::nullopt);
            if (!true_target_id || !false_target_id)
                return Error{ErrorCode::malformed, "CIL exception dispatch branch target has no block"};
            dispatch.successors.push_back({dispatch.begin, match_route.value(),
                *true_target_id, BlockEdgeKind::conditional_true});
            dispatch.successors.push_back({dispatch.begin, next_test,
                *false_target_id, BlockEdgeKind::conditional_false});
            next_test = dispatch.begin;
            synthetic_blocks.push_back(std::move(dispatch));
        }
        exception_profile_entries.emplace(key, next_test);
        instruction_exception_entries.emplace_back(ii, next_test);
    }
    // CLR treats an exception raised while evaluating a filter as though that
    // filter returned false. Preserve the original exception-search
    // continuation by resetting the filter result and redispatching using the
    // active filter continuation ID. Multiple filter profiles may share one
    // physical endfilter region, so the synthetic reject block covers every
    // continuation recorded for every endfilter in that region.
    for (const auto &clause : method.body->exception_clauses) {
        if (clause.kind != CilExceptionKind::filter) continue;
        std::map<std::uint32_t, Address> rejected_targets;
        for (const auto &instruction : method.instructions) {
            if (!in_region(instruction.offset, clause.filter_offset, clause.handler_offset - clause.filter_offset) ||
                std::string_view(instruction.mnemonic) != "endfilter") continue;
            const auto routes = endfilter_routes.find(instruction.offset);
            if (routes == endfilter_routes.end())
                return failure(ErrorCode::malformed, "CIL filter endfilter has no rejection continuation");
            for (const auto &route : routes->second) {
                const auto [found, inserted] = rejected_targets.emplace(route.id, route.decision);
                if (!inserted && found->second != route.decision)
                    return failure(ErrorCode::malformed, "CIL filter continuation ID has conflicting rejection targets");
            }
        }
        if (rejected_targets.empty())
            return failure(ErrorCode::unsupported, "CIL filter has no reachable rejection continuation");
        auto rejected = make_synthetic_block();
        if (synthetic_block_limit_exceeded)
            return Error{ErrorCode::resource_limit, "CIL exception dispatcher block limit exceeded"};
        const RegisterOperand continuation_reg{RegisterBank::cil_continuation, 0, 32, false};
        const RegisterOperand filter_result_reg{RegisterBank::cil_continuation, 1, 32, false};
        rejected.instructions.push_back({{rejected.begin,
            (std::uint64_t{method.method.token} << 32) | rejected.begin.offset},
            Assign{filter_result_reg, constant(0), {}}});
        LiftedBlock::SwitchDispatch dispatch;
        dispatch.selector = std::make_shared<Expression>(Expression{
            int_type(32), RegisterValue{continuation_reg, {}}});
        dispatch.complete = true;
        for (const auto &[id, target] : rejected_targets) {
            dispatch.cases.push_back({id, target});
            const auto target_id = block_id_for_address(target);
            if (!target_id)
                return failure(ErrorCode::malformed, "CIL filter rejection target has no block");
            rejected.successors.push_back({rejected.begin, target, *target_id, BlockEdgeKind::exception});
        }
        rejected.switch_dispatch = std::move(dispatch);
        rejected.instructions.push_back({{rejected.begin,
            (std::uint64_t{method.method.token} << 32) | rejected.begin.offset},
            Intrinsic{"filter_exception_rejected", {}, IntrinsicMemoryEffect::none}});
        const auto rejected_address = rejected.begin;
        synthetic_blocks.push_back(std::move(rejected));
        for (std::size_t ii = 0; ii < method.instructions.size(); ++ii) {
            const auto &instruction = method.instructions[ii];
            if (!in_region(instruction.offset, clause.filter_offset, clause.handler_offset - clause.filter_offset) ||
                std::string_view(instruction.mnemonic) == "endfilter") continue;
            instruction_exception_entries.emplace_back(ii, rejected_address);
        }
    }
    std::vector<std::vector<std::size_t>> predecessors(starts.size());
    auto add_predecessor = [&](std::size_t from, std::uint32_t target) -> bool {
        const auto to = block_index_for(target);
        if (!to) return false;
        predecessors[*to].push_back(from);
        return true;
    };
    for (std::size_t bi = 0; bi < starts.size(); ++bi) {
        const auto begin = instruction_at.at(starts[bi]);
        const auto end = bi + 1 < starts.size() ? instruction_at.at(starts[bi + 1]) : method.instructions.size();
        if (begin == end) continue;
        const auto &last = method.instructions[end - 1];
        const auto next = last.offset + last.size;
        const std::string_view op = last.mnemonic;
        if (op == "switch") {
            const auto *table = std::get_if<CilSwitchOperand>(&last.operand);
            if (!table) return failure(ErrorCode::malformed, "Missing CIL switch target table");
            for (const auto target : table->target_offsets)
                if (!add_predecessor(bi, target)) return failure(ErrorCode::malformed, "CIL switch target has no basic block");
            if (bi + 1 >= starts.size() || !add_predecessor(bi, next))
                return failure(ErrorCode::malformed, "CIL switch has no default fallthrough block");
        } else if (const auto *branch = std::get_if<CilBranchOperand>(&last.operand)) {
            const auto continuation = finally_continuations.find(last.offset);
            const auto predecessor_target = continuation == finally_continuations.end()
                ? branch->target_offset : continuation->second.handlers.front();
            if (!add_predecessor(bi, predecessor_target))
                return failure(ErrorCode::malformed, "CIL branch target has no basic block");
            const bool conditional = op.starts_with("brtrue") || op.starts_with("brfalse") || op.starts_with("beq") ||
                                    op.starts_with("bne") || op.starts_with("bge") || op.starts_with("bgt") ||
                                    op.starts_with("ble") || op.starts_with("blt");
            if (conditional && !add_predecessor(bi, next))
                return failure(ErrorCode::malformed, "CIL conditional branch has no fallthrough block");
        } else if (op != "ret" && op != "throw" && op != "rethrow" && op != "endfinally" &&
                   op != "endfilter" && bi + 1 < starts.size()) {
            bool crosses_region_end = false;
            for (const auto &clause : method.body->exception_clauses) {
                crosses_region_end |= next == clause.try_offset + clause.try_length ||
                                      next == clause.handler_offset + clause.handler_length;
                if (clause.kind == CilExceptionKind::filter)
                    crosses_region_end |= next == clause.filter_offset || next == clause.handler_offset;
            }
            if (!crosses_region_end) predecessors[bi + 1].push_back(bi);
        }
    }
    for (const auto &[endfinally_offset, routes] : endfinally_routes) {
        const auto source = block_index_for(endfinally_offset);
        if (!source) return failure(ErrorCode::malformed, "CIL endfinally has no basic block");
        for (const auto &route : routes) {
            if (route.exceptional) continue;
            if (route.target.space.value != 0 || route.target.offset > UINT32_MAX ||
                !add_predecessor(*source, static_cast<std::uint32_t>(route.target.offset)))
                return failure(ErrorCode::malformed, "CIL finally continuation target has no basic block");
        }
    }
    for (auto &block_predecessors : predecessors) {
        std::sort(block_predecessors.begin(), block_predecessors.end());
        block_predecessors.erase(std::unique(block_predecessors.begin(), block_predecessors.end()),
                                 block_predecessors.end());
    }
    // First solve only stack shape over reachable control flow. Values are
    // represented by types here; the second pass assigns block edge values and
    // loop-header phis. This makes backedges ordinary fixed-point inputs
    // instead of requiring the target block to have been visited first.
    using StackShape = std::vector<ValueType>;
    std::vector<std::optional<StackShape>> entry_shapes(starts.size());
    std::vector<std::optional<StackShape>> exit_shapes(starts.size());
    bool nonempty_leave_stack = false;
    std::vector<std::vector<std::size_t>> successors(starts.size());
    std::size_t cfg_edge_count = 0;
    for (std::size_t target = 0; target < predecessors.size(); ++target)
        for (const auto pred : predecessors[target]) {
            if (++cfg_edge_count > 1'000'000)
                return Error{ErrorCode::resource_limit, "CIL stack-shape CFG edge limit exceeded"};
            successors[pred].push_back(target);
        }
    std::vector<std::vector<std::size_t>> reachable_predecessors(starts.size());
    std::deque<std::size_t> worklist;
    std::vector<bool> queued(starts.size(), false), processed(starts.size(), false);
    std::size_t stack_cells = 0;
    constexpr std::size_t max_stack_cells = 4'000'000;
    const auto stack_limit = method.body->max_stack ? std::min<std::size_t>(method.body->max_stack, 1024) : 1024;
    auto merge_shape = [&](std::size_t target, const StackShape &shape) -> Result<std::monostate> {
        if (!shape.empty() && std::any_of(result.exception_regions.begin(), result.exception_regions.end(),
                [&](const auto &region) { return region.try_offset == starts[target]; }))
            return Error{ErrorCode::malformed, "CIL protected try entry requires an empty evaluation stack"};
        if (shape.size() > stack_limit || shape.size() > 256)
            return Error{ErrorCode::resource_limit, "CIL evaluation stack exceeds its bounded virtual-register limit"};
        if (!entry_shapes[target]) {
            if (shape.size() > max_stack_cells - stack_cells)
                return Error{ErrorCode::resource_limit, "CIL stack-shape analysis exceeds its aggregate cell limit"};
            stack_cells += shape.size();
            entry_shapes[target] = shape;
            if (!queued[target]) { worklist.push_back(target); queued[target] = true; }
            return std::monostate{};
        }
        if (entry_shapes[target]->size() != shape.size())
            return Error{ErrorCode::malformed, "CIL control-flow merge has inconsistent evaluation-stack depth"};
        for (std::size_t i = 0; i < shape.size(); ++i)
            if ((*entry_shapes[target])[i] != shape[i])
                return Error{ErrorCode::malformed, "CIL control-flow merge has incompatible evaluation-stack types"};
        return std::monostate{};
    };
    if (const auto entry = block_index_for(static_cast<std::uint32_t>(result.lifted.entry.offset))) {
        auto seeded = merge_shape(*entry, {});
        if (!seeded) return seeded.error();
    }
    for (const auto &clause : method.body->exception_clauses) {
        const auto handler = block_index_for(clause.handler_offset);
        if (!handler) return failure(ErrorCode::malformed, "CIL exception handler has no basic block");
        StackShape seed;
        if (clause.kind == CilExceptionKind::catch_clause || clause.kind == CilExceptionKind::filter)
            seed.push_back(managed_reference_type());
        if (!seed.empty() && method.body->max_stack == 0)
            return failure(ErrorCode::malformed, "CIL exception entry exceeds the declared max_stack");
        auto seeded = merge_shape(*handler, seed);
        if (!seeded) return seeded.error();
        if (clause.kind == CilExceptionKind::filter) {
            const auto filter = block_index_for(clause.filter_offset);
            if (!filter) return failure(ErrorCode::malformed, "CIL filter has no basic block");
            auto filter_seeded = merge_shape(*filter, StackShape{managed_reference_type()});
            if (!filter_seeded) return filter_seeded.error();
        }
    }

    std::size_t shape_transfers = 0;
    constexpr std::size_t max_shape_transfers = 2'000'000;
    for (;;) {
        if (worklist.empty()) {
            const auto disconnected = std::find(processed.begin(), processed.end(), false);
            if (disconnected == processed.end()) break;
            const auto index = static_cast<std::size_t>(disconnected - processed.begin());
            auto seeded = merge_shape(index, {});
            if (!seeded) return seeded.error();
        }
        const auto bi = worklist.front(); worklist.pop_front(); queued[bi] = false;
        if (processed[bi]) continue;
        processed[bi] = true;
        if (++shape_transfers > max_shape_transfers)
            return Error{ErrorCode::resource_limit, "CIL stack-shape fixed-point transfer limit exceeded"};
        StackShape shape = *entry_shapes[bi];
        const auto begin = instruction_at.at(starts[bi]);
        const auto end = bi + 1 < starts.size() ? instruction_at.at(starts[bi + 1]) : method.instructions.size();
        bool has_exit = true;
        auto shape_pop = [&](std::size_t count) -> bool {
            if (shape.size() < count) return false;
            shape.resize(shape.size() - count); return true;
        };
        auto shape_push = [&](ValueType type) -> bool {
            if (shape.size() >= stack_limit || shape.size() >= 256) return false;
            shape.push_back(type); return true;
        };
        for (std::size_t ii = begin; ii < end; ++ii) {
            const auto &ins = method.instructions[ii];
            if (ins.status != CilInstructionStatus::decoded) { has_exit = false; break; }
            const std::string_view op = ins.mnemonic;
            if (op == "nop") continue;
            if (op.starts_with("ldarg.") || op == "ldarg.s" || op == "ldarg" ||
                op.starts_with("ldloc.") || op == "ldloc.s" || op == "ldloc") {
                if (!shape_push({TypeKind::unknown, 0, false})) return failure(ErrorCode::malformed, "CIL max_stack exceeded");
                continue;
            }
            if (op.starts_with("stloc.") || op == "stloc.s" || op == "stloc" || op == "starg.s" || op == "starg") {
                if (!shape_pop(1)) return failure(ErrorCode::malformed, "CIL local or argument store underflows evaluation stack");
                continue;
            }
            if (op.starts_with("ldc.i4.")) {
                if (op != "ldc.i4.m1" && (op.back() < '0' || op.back() > '8'))
                    return failure(ErrorCode::unsupported, "Unsupported CIL integer constant form");
                if (!shape_push(int_type())) return failure(ErrorCode::malformed, "CIL max_stack exceeded");
                continue;
            }
            if (op == "ldc.i4.s" || op == "ldc.i4") {
                if (!shape_push(int_type())) return failure(ErrorCode::malformed, "CIL max_stack exceeded");
                continue;
            }
            if (op == "ldc.i8") { if (!shape_push(int_type(64))) return failure(ErrorCode::malformed, "CIL max_stack exceeded"); continue; }
            if (op == "ldc.r4") { if (!shape_push(floating_type(32))) return failure(ErrorCode::malformed, "CIL max_stack exceeded"); continue; }
            if (op == "ldc.r8") { if (!shape_push(floating_type(64))) return failure(ErrorCode::malformed, "CIL max_stack exceeded"); continue; }
            if (op == "ldnull") { if (!shape_push(managed_reference_type())) return failure(ErrorCode::malformed, "CIL max_stack exceeded"); continue; }
            if (op == "ldftn" || op == "ldvirtftn") {
                const auto token = call_token(ins);
                const auto table = token ? (*token >> 24) : 0;
                if (!token || ((*token & 0x00ffffffu) == 0) ||
                    (table != 0x06 && table != 0x0a && table != 0x2b))
                    return failure(ErrorCode::malformed, "CIL function-pointer load has an invalid method token");
                const auto signature = resolved_signatures.find(*token);
                if (signature == resolved_signatures.end())
                    return failure(ErrorCode::unsupported, "CIL function-pointer target signature is unavailable");
                if (op == "ldvirtftn" && !signature->second.has_this)
                    return failure(ErrorCode::malformed, "CIL ldvirtftn target signature has no instance receiver");
                if (op == "ldvirtftn" && !shape_pop(1))
                    return failure(ErrorCode::malformed, "CIL ldvirtftn underflows evaluation stack");
                if (!shape_push(managed_reference_type())) return failure(ErrorCode::malformed, "CIL max_stack exceeded");
                continue;
            }
            if (op == "ldstr") {
                const auto token = call_token(ins);
                if (!token || (*token >> 24) != 0x70)
                    return failure(ErrorCode::malformed, "CIL ldstr has an invalid user-string token");
                if (!method.resolved_user_strings || !method.resolved_user_strings->contains(*token))
                    return failure(ErrorCode::unsupported, "CIL ldstr user-string metadata is unavailable");
                if (!shape_push(managed_reference_type())) return failure(ErrorCode::malformed, "CIL max_stack exceeded");
                continue;
            }
            if (op == "box" || op == "unbox" || op == "unbox.any" || op == "castclass" || op == "isinst") {
                const auto token = call_token(ins);
                if (!valid_type_token(token))
                    return failure(ErrorCode::malformed, "CIL type operation has an invalid type token");
                if (!shape_pop(1)) return failure(ErrorCode::malformed, "CIL type operation underflows evaluation stack");
                const auto result_type = op == "unbox.any" ? ValueType{} : managed_reference_type();
                if (!shape_push(result_type)) return failure(ErrorCode::malformed, "CIL max_stack exceeded");
                continue;
            }
            if (op == "ldfld" || op == "stfld" || op == "ldsfld" || op == "stsfld") {
                const auto token = call_token(ins);
                if (!token || ((*token >> 24) != 0x04 && (*token >> 24) != 0x0a))
                    return failure(ErrorCode::malformed, "CIL field access has neither a FieldDef nor MemberRef token");
                const auto field = method.resolved_fields.find(*token);
                if (field == method.resolved_fields.end())
                    return failure(ErrorCode::unsupported, "CIL field token is unresolved");
                const bool opcode_static = op == "ldsfld" || op == "stsfld";
                const bool is_field_definition=(*token>>24)==0x04;
                const bool is_static = (field->second.flags & 0x0010) != 0;
                if (is_field_definition && is_static != opcode_static)
                    return failure(ErrorCode::malformed, "CIL field opcode staticness disagrees with FieldDef flags");
                const auto count = opcode_static ? (op.starts_with("ld") ? 0u : 1u) : (op.starts_with("ld") ? 1u : 2u);
                if (!shape_pop(count)) return failure(ErrorCode::malformed, "CIL field access underflows evaluation stack");
                if (op.starts_with("ld")) {
                ManagedMethodSignature field_context;
                field_context.declaring_type_arguments=field->second.declaring_type_arguments;
                field_context.declaring_type_generic_arguments_valid=field->second.declaring_type_generic_arguments_valid;
                const auto type = field->second.type_signature
                    ? managed_signature_type(*field->second.type_signature, field_context) : ValueType{};
                    if (!shape_push(type)) return failure(ErrorCode::malformed, "CIL max_stack exceeded");
                }
                continue;
            }
            if (op == "newarr") {
                const auto token = call_token(ins);
                if (!token || ((*token >> 24) != 0x01 && (*token >> 24) != 0x02 && (*token >> 24) != 0x1b))
                    return failure(ErrorCode::malformed, "CIL newarr has an invalid element type token");
                if (!shape_pop(1)) return failure(ErrorCode::malformed, "CIL newarr underflows evaluation stack");
                if (!shape_push(managed_reference_type())) return failure(ErrorCode::malformed, "CIL max_stack exceeded");
                continue;
            }
            if (op == "ldlen") {
                if (!shape_pop(1)) return failure(ErrorCode::malformed, "CIL ldlen underflows evaluation stack");
                if (!shape_push({TypeKind::integer, 0, false})) return failure(ErrorCode::malformed, "CIL max_stack exceeded");
                continue;
            }
            if (op == "ldelema") {
                const auto token = call_token(ins);
                if (!token || ((*token >> 24) != 0x01 && (*token >> 24) != 0x02 && (*token >> 24) != 0x1b))
                    return failure(ErrorCode::malformed, "CIL ldelema has an invalid element type token");
                if (!shape_pop(2)) return failure(ErrorCode::malformed, "CIL ldelema underflows evaluation stack");
                if (!shape_push(managed_reference_type())) return failure(ErrorCode::malformed, "CIL max_stack exceeded");
                continue;
            }
            if (op == "cpblk" || op == "initblk") {
                if (!shape_pop(3)) return failure(ErrorCode::malformed, "CIL block-memory instruction underflows evaluation stack");
                continue;
            }
            if (op == "initobj" || op == "ldobj" || op == "stobj" || op == "cpobj") {
                const auto token = call_token(ins);
                if (!token || ((*token >> 24) != 0x01 && (*token >> 24) != 0x02 && (*token >> 24) != 0x1b) || !(*token & 0x00ffffff))
                    return failure(ErrorCode::malformed, "CIL object-memory instruction has an invalid type token");
                const std::size_t pop_count = op == "initobj" || op == "ldobj" ? 1 : 2;
                if (!shape_pop(pop_count)) return failure(ErrorCode::malformed, "CIL object-memory instruction underflows evaluation stack");
                if (op == "ldobj" && !shape_push({})) return failure(ErrorCode::malformed, "CIL max_stack exceeded");
                continue;
            }
            if (op.starts_with("ldind.")) {
                const auto type = managed_indirect_load_type(op);
                if (!type) return failure(ErrorCode::unsupported, "CIL indirect load type is unsupported");
                if (!shape_pop(1)) return failure(ErrorCode::malformed, "CIL indirect load underflows evaluation stack");
                if (!shape_push(*type)) return failure(ErrorCode::malformed, "CIL max_stack exceeded");
                continue;
            }
            if (managed_indirect_store(op)) {
                if (!shape_pop(2)) return failure(ErrorCode::malformed, "CIL indirect store underflows evaluation stack");
                continue;
            }
            if (managed_array_load(op)) {
                const auto type = managed_array_element_type(op);
                if (!type) return failure(ErrorCode::unsupported, "CIL array element type is unsupported");
                if (!shape_pop(2)) return failure(ErrorCode::malformed, "CIL array load underflows evaluation stack");
                if (!shape_push(*type)) return failure(ErrorCode::malformed, "CIL max_stack exceeded");
                continue;
            }
            if (managed_array_store(op)) {
                if (!shape_pop(3)) return failure(ErrorCode::malformed, "CIL array store underflows evaluation stack");
                continue;
            }
            if (op == "dup") {
                if (shape.empty()) return failure(ErrorCode::malformed, "CIL dup underflows evaluation stack");
                if (!shape_push(shape.back())) return failure(ErrorCode::malformed, "CIL max_stack exceeded");
                continue;
            }
            if (op == "pop") { if (!shape_pop(1)) return failure(ErrorCode::malformed, "CIL pop underflows evaluation stack"); continue; }
            if (op == "neg" || op == "not") {
                if (shape.empty()) return failure(ErrorCode::malformed, "CIL unary operation underflows evaluation stack");
                continue;
            }
            if (const auto conversion = integer_conversion(op)) {
                if (!shape_pop(1)) return failure(ErrorCode::malformed, "CIL conversion underflows evaluation stack");
                if (!shape_push(conversion_stack_type(*conversion)))
                    return failure(ErrorCode::malformed, "CIL max_stack exceeded");
                continue;
            }
            if (const auto conversion_bits = floating_conversion(op)) {
                if (!shape_pop(1)) return failure(ErrorCode::malformed, "CIL floating conversion underflows evaluation stack");
                if (!shape_push(floating_type(*conversion_bits)))
                    return failure(ErrorCode::malformed, "CIL max_stack exceeded");
                continue;
            }
            const bool binary_value = op == "add" || op == "sub" || op == "mul" || op == "div" || op == "div.un" ||
                op == "rem" || op == "rem.un" || op == "and" || op == "or" || op == "xor" || op == "shl" ||
                op == "shr" || op == "shr.un";
            const bool comparison = op == "ceq" || op == "cgt" || op == "cgt.un" || op == "clt" || op == "clt.un";
            if (binary_value || comparison) {
                if (shape.size() < 2) return failure(ErrorCode::malformed, "CIL binary operation underflows evaluation stack");
                const auto type = comparison ? ValueType{TypeKind::boolean, 1, false} : shape[shape.size() - 2];
                shape.resize(shape.size() - 2);
                if (!shape_push(type)) return failure(ErrorCode::malformed, "CIL max_stack exceeded");
                continue;
            }
            if (op == "ret") {
                if (shape.size() > 1) return failure(ErrorCode::malformed, "CIL ret leaves extra evaluation-stack values");
                shape.clear(); has_exit = false; break;
            }
            if (op == "throw") {
                if (!shape_pop(1) || !shape.empty()) return failure(ErrorCode::malformed, "CIL throw has invalid evaluation-stack shape");
                shape.clear(); has_exit = false; break;
            }
            if (op == "rethrow") {
                if (!shape.empty()) return failure(ErrorCode::malformed, "CIL rethrow requires an empty evaluation stack");
                has_exit = false; break;
            }
            if (op == "endfinally") {
                if (!shape.empty()) return failure(ErrorCode::malformed, "CIL endfinally has a nonempty evaluation stack");
                break;
            }
            if (op == "endfilter") {
                if (!shape.empty() && shape.back().kind != TypeKind::unknown &&
                    shape.back().kind != TypeKind::boolean &&
                    (shape.back().kind != TypeKind::integer || shape.back().bits != 32))
                    return failure(ErrorCode::malformed, "CIL endfilter result is not an int32 stack value");
                if (!shape_pop(1) || !shape.empty())
                    return failure(ErrorCode::malformed, "CIL endfilter requires exactly one result on the evaluation stack");
                has_exit = false; break;
            }
            if (op == "leave" || op == "leave.s") {
                nonempty_leave_stack |= !shape.empty();
                shape.clear(); break;
            }
            if (op == "br" || op == "br.s") break;
            if (op.starts_with("brtrue") || op.starts_with("brfalse")) {
                if (!shape_pop(1)) return failure(ErrorCode::malformed, "CIL conditional branch underflows evaluation stack");
                break;
            }
            if (op.starts_with("beq") || op.starts_with("bne") || op.starts_with("bge") || op.starts_with("bgt") ||
                op.starts_with("ble") || op.starts_with("blt")) {
                if (!shape_pop(2)) return failure(ErrorCode::malformed, "CIL comparison branch underflows evaluation stack");
                break;
            }
            if (op == "switch") { if (!shape_pop(1)) return failure(ErrorCode::malformed, "CIL switch underflows evaluation stack"); break; }
            if (op == "call" || op == "callvirt" || op == "newobj" || op == "calli") {
                const auto token = call_token(ins);
                if (!token) return failure(ErrorCode::malformed, "CIL call is missing metadata token");
                const auto signature = resolved_signatures.find(*token);
                if (signature == resolved_signatures.end()) return failure(ErrorCode::unsupported, "CIL call signature is unavailable; stack effects cannot be inferred");
                const bool construct = op == "newobj", indirect = op == "calli";
                if ((op == "callvirt" || construct) && !signature->second.has_this)
                    return failure(ErrorCode::malformed, op == "callvirt"
                        ? "CIL callvirt target signature has no instance receiver"
                        : "CIL newobj target signature has no instance receiver");
                if (construct && signature->second.returns_value)
                    return failure(ErrorCode::malformed, "CIL newobj target signature returns a value");
                const auto count = signature->second.parameter_count + (signature->second.has_this && !construct ? 1u : 0u) + (indirect ? 1u : 0u);
                if (!shape_pop(count)) return failure(ErrorCode::malformed, "CIL call arguments underflow evaluation stack");
                if (construct || signature->second.returns_value)
                    if (!shape_push(managed_call_result_type(signature->second, construct)))
                        return failure(ErrorCode::malformed, "CIL max_stack exceeded");
                continue;
            }
            // Known-but-unsupported instructions retain the lifter's existing
            // incomplete/termination behavior; no guessed stack shape flows.
            has_exit = false; break;
        }
        if (!has_exit) continue;
        if (shape.size() > max_stack_cells - stack_cells)
            return Error{ErrorCode::resource_limit, "CIL stack-shape analysis exceeds its aggregate cell limit"};
        stack_cells += shape.size();
        exit_shapes[bi] = shape;
        for (const auto target : successors[bi]) {
            reachable_predecessors[target].push_back(bi);
            auto merged = merge_shape(target, shape);
            if (!merged) return merged.error();
        }
    }
    for (auto &inputs : reachable_predecessors) {
        std::sort(inputs.begin(), inputs.end());
        inputs.erase(std::unique(inputs.begin(), inputs.end()), inputs.end());
    }

    std::array<std::uint32_t, 256> stack_versions{};
    std::vector<std::vector<std::uint32_t>> output_versions(starts.size()), phi_versions(starts.size());
    for (std::size_t bi = 0; bi < starts.size(); ++bi) {
        if (exit_shapes[bi]) {
            output_versions[bi].reserve(exit_shapes[bi]->size());
            for (std::size_t slot = 0; slot < exit_shapes[bi]->size(); ++slot)
                output_versions[bi].push_back(++stack_versions[slot]);
        }
        if (reachable_predecessors[bi].size() > 1 && entry_shapes[bi]) {
            phi_versions[bi].resize(entry_shapes[bi]->size());
            for (std::size_t slot = 0; slot < phi_versions[bi].size(); ++slot)
                phi_versions[bi][slot] = ++stack_versions[slot];
        }
    }
    auto pop = [](Stack &stack) -> ExpressionPtr {
        if (stack.empty()) return {};
        auto result = stack.back(); stack.pop_back(); return result;
    };
    std::size_t instruction_index = 0;
    for (std::size_t bi = 0; bi < starts.size(); ++bi) {
        auto &block = result.lifted.blocks[bi];
        for (const auto &clause : method.body->exception_clauses) {
            if (starts[bi] == clause.try_offset)
                block.instructions.push_back({{il_address(starts[bi]), (std::uint64_t{method.method.token} << 32) | starts[bi]},
                    Intrinsic{"try_region_begin", {}, IntrinsicMemoryEffect::none}});
            if (clause.kind == CilExceptionKind::filter && starts[bi] == clause.filter_offset)
                block.instructions.push_back({{il_address(starts[bi]), (std::uint64_t{method.method.token} << 32) | starts[bi]},
                    Intrinsic{"filter_region_begin", {variable("exception")}, IntrinsicMemoryEffect::none}});
            if (clause.kind == CilExceptionKind::filter && starts[bi] == clause.handler_offset)
                block.instructions.push_back({{il_address(starts[bi]), (std::uint64_t{method.method.token} << 32) | starts[bi]},
                    Intrinsic{"filter_region_end", {}, IntrinsicMemoryEffect::none}});
            if (starts[bi] == clause.handler_offset) {
                std::string name;
                if (clause.kind == CilExceptionKind::catch_clause) {
                    const auto type_name = method.resolved_exception_type_names.find(clause.class_token);
                    name = type_name == method.resolved_exception_type_names.end()
                        ? "catch_handler_begin token " + std::to_string(clause.class_token)
                        : "catch_handler_begin " + quoted_metadata_name(type_name->second) +
                              " token " + std::to_string(clause.class_token);
                } else if (clause.kind == CilExceptionKind::filter) name = "catch_handler_begin filter";
                else if (clause.kind == CilExceptionKind::fault_clause) name = "fault_handler_begin";
                else name = "finally_handler_begin";
                block.instructions.push_back({{il_address(starts[bi]), (std::uint64_t{method.method.token} << 32) | starts[bi]},
                    Intrinsic{name, {}, IntrinsicMemoryEffect::none}});
            }
            if (starts[bi] == clause.try_offset + clause.try_length || starts[bi] == clause.handler_offset + clause.handler_length)
                block.instructions.push_back({{il_address(starts[bi]), (std::uint64_t{method.method.token} << 32) | starts[bi]},
                    Intrinsic{"exception_region_end", {}, IntrinsicMemoryEffect::none}});
        }
        const auto next_start = bi + 1 < starts.size() ? starts[bi + 1] : UINT32_MAX;
        while (instruction_index < method.instructions.size() && method.instructions[instruction_index].offset < starts[bi]) ++instruction_index;
        Stack stack;
        const auto &known_inputs = reachable_predecessors[bi];
        if (entry_shapes[bi]) {
            if (known_inputs.size() > 1) {
                if (phi_versions[bi].size() != entry_shapes[bi]->size())
                    return failure(ErrorCode::malformed, "CIL stack-shape merge is missing loop/join phis");
                for (std::size_t slot = 0; slot < phi_versions[bi].size(); ++slot) {
                    const auto type = (*entry_shapes[bi])[slot];
                    const RegisterOperand reg{RegisterBank::cil_stack, static_cast<std::uint8_t>(slot), type.bits, false};
                    LiftedBlock::Phi phi{reg, phi_versions[bi][slot], {}};
                    for (const auto pred : known_inputs) {
                        if (slot >= output_versions[pred].size())
                            return failure(ErrorCode::malformed, "CIL predecessor has no edge value for a merged stack slot");
                        phi.inputs.push_back({result.lifted.blocks[pred].id, output_versions[pred][slot]});
                    }
                    block.phis.push_back(std::move(phi));
                    stack.push_back(std::make_shared<Expression>(Expression{type,
                        RegisterValue{reg, phi_versions[bi][slot]}}));
                }
            } else if (known_inputs.size() == 1) {
                const auto pred = known_inputs.front();
                if (!exit_shapes[pred] || exit_shapes[pred]->size() != entry_shapes[bi]->size())
                    return failure(ErrorCode::malformed, "CIL predecessor stack shape is unavailable");
                for (std::size_t slot = 0; slot < entry_shapes[bi]->size(); ++slot) {
                    if (slot >= output_versions[pred].size())
                        return failure(ErrorCode::malformed, "CIL predecessor has no edge value for a stack slot");
                    const auto type = (*entry_shapes[bi])[slot];
                    const RegisterOperand reg{RegisterBank::cil_stack, static_cast<std::uint8_t>(slot), type.bits, false};
                    stack.push_back(std::make_shared<Expression>(Expression{type,
                        RegisterValue{reg, output_versions[pred][slot]}}));
                }
            } else if (!entry_shapes[bi]->empty()) {
                bool catch_entry = false;
                bool filter_entry = false;
                for (const auto &clause : method.body->exception_clauses)
                    catch_entry |= (clause.kind == CilExceptionKind::catch_clause || clause.kind == CilExceptionKind::filter) &&
                                   starts[bi] == clause.handler_offset;
                for (const auto &clause : method.body->exception_clauses)
                    filter_entry |= clause.kind == CilExceptionKind::filter && starts[bi] == clause.filter_offset;
                if ((!catch_entry && !filter_entry) || entry_shapes[bi]->size() != 1)
                    return failure(ErrorCode::unsupported, "CIL non-empty stack has no modeled predecessor value");
                stack.push_back(typed_variable("exception", managed_reference_type()));
            }
        }
        const auto emission_stack_limit = method.body->max_stack ? std::min<std::size_t>(method.body->max_stack, 1024) : 1024;
        auto push = [&](ExpressionPtr value) {
            if (stack.size() >= emission_stack_limit) return false;
            stack.push_back(std::move(value));
            return true;
        };
        bool terminated = false;
        std::uint32_t last_end = starts[bi];
        for (; instruction_index < method.instructions.size() && method.instructions[instruction_index].offset < next_start;
             ++instruction_index) {
            const auto &ins = method.instructions[instruction_index];
            const auto next = ins.offset + ins.size;
            last_end = next;
            if (ins.status != CilInstructionStatus::decoded) {
                std::ostringstream name; name << "unsupported_cil_0x" << std::hex << ins.opcode;
                block.instructions.push_back({{il_address(ins.offset), (std::uint64_t{method.method.token} << 32) | ins.offset},
                    Intrinsic{name.str(), {}, IntrinsicMemoryEffect::unknown}});
                result.lifted.diagnostics.push_back(std::string("Unsupported CIL at IL+") + std::to_string(ins.offset) + ": " + ins.mnemonic);
                result.complete = false; terminated = true; break;
            }
            const auto origin = InstructionOrigin{il_address(ins.offset), (std::uint64_t{method.method.token} << 32) | ins.offset};
            const std::string_view op = ins.mnemonic;
            auto push_arg = [&](std::uint32_t index) { return push(variable("arg_" + std::to_string(index))); };
            auto push_local = [&](std::uint32_t index) { return push(variable("local_" + std::to_string(index))); };
            auto store = [&](std::string name) -> bool {
                auto value = pop(stack); if (!value) return false;
                block.instructions.push_back({origin, Intrinsic{std::move(name) + " = ", {std::move(value)}, IntrinsicMemoryEffect::none}});
                return true;
            };
            if (op == "nop") continue;
            if (op == "ldarg.0" || op == "ldarg.1" || op == "ldarg.2" || op == "ldarg.3") { if(!push_arg(index_operand(ins,0x02)))return failure(ErrorCode::malformed,"CIL max_stack exceeded"); continue; }
            if (op == "ldarg.s" || op == "ldarg") { const auto index=index_operand(ins); if(index==UINT32_MAX)return failure(ErrorCode::malformed,"Invalid CIL argument index"); if(!push_arg(index))return failure(ErrorCode::malformed,"CIL max_stack exceeded"); continue; }
            if (op == "ldloc.0" || op == "ldloc.1" || op == "ldloc.2" || op == "ldloc.3") { if(!push_local(index_operand(ins,0x06)))return failure(ErrorCode::malformed,"CIL max_stack exceeded"); continue; }
            if (op == "ldloc.s" || op == "ldloc") { const auto index=index_operand(ins); if(index==UINT32_MAX)return failure(ErrorCode::malformed,"Invalid CIL local index"); if(!push_local(index))return failure(ErrorCode::malformed,"CIL max_stack exceeded"); continue; }
            if (op == "stloc.0" || op == "stloc.1" || op == "stloc.2" || op == "stloc.3") { if(!store("local_"+std::to_string(index_operand(ins,0x0a))))return failure(ErrorCode::malformed,"CIL local store underflows evaluation stack"); continue; }
            if (op == "stloc.s" || op == "stloc") { const auto index=index_operand(ins); if(index==UINT32_MAX)return failure(ErrorCode::malformed,"Invalid CIL local index"); if(!store("local_"+std::to_string(index)))return failure(ErrorCode::malformed,"CIL local store underflows evaluation stack"); continue; }
            if (op == "starg.s" || op == "starg") { const auto index=index_operand(ins); if(index==UINT32_MAX)return failure(ErrorCode::malformed,"Invalid CIL argument index"); if(!store("arg_"+std::to_string(index)))return failure(ErrorCode::malformed,"CIL argument store underflows evaluation stack"); continue; }
            if (op.starts_with("ldc.i4.")) {
                if (op == "ldc.i4.m1") { if(!push(constant(UINT32_MAX)))return failure(ErrorCode::malformed,"CIL max_stack exceeded"); }
                else { const auto suffix=op.back(); if(suffix<'0'||suffix>'8')return failure(ErrorCode::unsupported,"Unsupported CIL integer constant form"); if(!push(constant(suffix-'0')))return failure(ErrorCode::malformed,"CIL max_stack exceeded"); }
                continue;
            }
            if (op == "ldc.i4.s") { const auto *value=std::get_if<std::int8_t>(&ins.operand); if(!value)return failure(ErrorCode::malformed,"Invalid ldc.i4.s operand"); if(!push(constant(static_cast<std::uint32_t>(*value))))return failure(ErrorCode::malformed,"CIL max_stack exceeded"); continue; }
            if (op == "ldc.i4") { const auto *value=std::get_if<std::int32_t>(&ins.operand); if(!value)return failure(ErrorCode::malformed,"Invalid ldc.i4 operand"); if(!push(constant(static_cast<std::uint32_t>(*value))))return failure(ErrorCode::malformed,"CIL max_stack exceeded"); continue; }
            if (op == "ldc.i8") { const auto *value=std::get_if<std::int64_t>(&ins.operand); if(!value)return failure(ErrorCode::malformed,"Invalid ldc.i8 operand"); if(!push(constant(static_cast<std::uint64_t>(*value),64)))return failure(ErrorCode::malformed,"CIL max_stack exceeded"); continue; }
            if (op == "ldc.r4") {
                const auto *value = std::get_if<float>(&ins.operand);
                if (!value) return failure(ErrorCode::malformed, "Invalid ldc.r4 operand");
                if (!push(floating_constant(std::bit_cast<std::uint32_t>(*value), 32)))
                    return failure(ErrorCode::malformed, "CIL max_stack exceeded");
                continue;
            }
            if (op == "ldc.r8") {
                const auto *value = std::get_if<double>(&ins.operand);
                if (!value) return failure(ErrorCode::malformed, "Invalid ldc.r8 operand");
                if (!push(floating_constant(std::bit_cast<std::uint64_t>(*value), 64)))
                    return failure(ErrorCode::malformed, "CIL max_stack exceeded");
                continue;
            }
            if (op == "ldftn" || op == "ldvirtftn") {
                const auto token = call_token(ins);
                const auto signature = token ? resolved_signatures.find(*token) : resolved_signatures.end();
                if (!token || signature == resolved_signatures.end())
                    return failure(ErrorCode::unsupported, "CIL function-pointer target signature is unavailable");
                const auto name = std::string(op) + "_0x" + [&] {
                    std::ostringstream out; out << std::hex << *token; return out.str();
                }();
                if (op == "ldvirtftn") {
                    auto receiver = pop(stack);
                    if (!receiver) return failure(ErrorCode::malformed, "CIL ldvirtftn underflows evaluation stack");
                    block.instructions.push_back({origin, Intrinsic{name + " = ", {std::move(receiver)}, IntrinsicMemoryEffect::unknown}});
                }
                if (!push(typed_variable(name, managed_reference_type())))
                    return failure(ErrorCode::malformed, "CIL max_stack exceeded");
                result.referenced_tokens.push_back(*token);
                continue;
            }
            if (op == "ldnull") {
                const auto type=managed_reference_type();
                if(!push(std::make_shared<Expression>(Expression{type,ConstantValue{0,type}})))
                    return failure(ErrorCode::malformed,"CIL max_stack exceeded");
                continue;
            }
            if (op == "ldstr") {
                const auto token=call_token(ins);
                if(!token || (*token>>24)!=0x70)return failure(ErrorCode::malformed,"CIL ldstr has an invalid user-string token");
                if(!method.resolved_user_strings)return failure(ErrorCode::unsupported,"CIL ldstr user-string metadata is unavailable");
                const auto text=method.resolved_user_strings->find(*token);
                if(text==method.resolved_user_strings->end())return failure(ErrorCode::malformed,"CIL ldstr token is absent from the CLR #US heap");
                if(!push(managed_string_expression(text->second)))return failure(ErrorCode::malformed,"CIL max_stack exceeded");
                result.referenced_tokens.push_back(*token);
                continue;
            }
            if (op == "box" || op == "unbox" || op == "unbox.any" || op == "castclass" || op == "isinst") {
                const auto token = call_token(ins);
                if (!valid_type_token(token))
                    return failure(ErrorCode::malformed, "CIL type operation has an invalid type token");
                auto value = pop(stack);
                if (!value) return failure(ErrorCode::malformed, "CIL type operation underflows evaluation stack");
                const auto result_type = op == "unbox.any" ? ValueType{} : managed_reference_type();
                const std::string suffix = op == "unbox.any" ? "unbox_any" : std::string(op);
                const auto name = "cil_" + suffix + "_" + std::to_string(origin.instruction_id);
                const auto effect = op == "unbox" ? IntrinsicMemoryEffect::none : IntrinsicMemoryEffect::unknown;
                Intrinsic operation{name + " = ", {std::move(value), constant(*token)}, effect};
                operation.result_type = result_type;
                block.instructions.push_back({origin, std::move(operation)});
                if (!push(typed_variable(name, result_type))) return failure(ErrorCode::malformed, "CIL max_stack exceeded");
                result.referenced_tokens.push_back(*token);
                result.complete = false;
                result.lifted.diagnostics.push_back("CIL type operation preserves its metadata token, but CLR type compatibility and exception behavior remain opaque");
                continue;
            }
            if (op == "ldfld" || op == "stfld" || op == "ldsfld" || op == "stsfld") {
                const auto token = call_token(ins);
                if (!token || ((*token >> 24) != 0x04 && (*token >> 24) != 0x0a))
                    return failure(ErrorCode::malformed, "CIL field access has neither a FieldDef nor MemberRef token");
                const auto field = method.resolved_fields.find(*token);
                if (field == method.resolved_fields.end())
                    return failure(ErrorCode::unsupported, "CIL field token is unresolved");
                const bool opcode_static = op == "ldsfld" || op == "stsfld";
                const bool is_field_definition=(*token>>24)==0x04;
                const bool is_static = (field->second.flags & 0x0010) != 0;
                if (is_field_definition && is_static != opcode_static)
                    return failure(ErrorCode::malformed, "CIL field opcode staticness disagrees with FieldDef flags");
                const bool load = op.starts_with("ld");
                ExpressionPtr object, value;
                if (!opcode_static && load) object = pop(stack);
                else if (!opcode_static) { value = pop(stack); object = pop(stack); }
                else if (!load) value = pop(stack);
                if ((!opcode_static && !object) || (!load && !value))
                    return failure(ErrorCode::malformed, "CIL field access underflows evaluation stack");
                ManagedMethodSignature empty_context;
                empty_context.declaring_type_arguments=field->second.declaring_type_arguments;
                empty_context.declaring_type_generic_arguments_valid=field->second.declaring_type_generic_arguments_valid;
                const auto type = field->second.type_signature
                    ? managed_signature_type(*field->second.type_signature, empty_context) : ValueType{};
                const auto field_name = field->second.declaring_type + "::" + field->second.name;
                if (load) {
                    const auto name = "cil_field_load_" + std::to_string(origin.instruction_id);
                    Intrinsic access{name + " = ", {std::move(object), typed_variable(field_name, {})}, IntrinsicMemoryEffect::read};
                    access.result_type = type;
                    block.instructions.push_back({origin, std::move(access)});
                    if (!push(typed_variable(name, type))) return failure(ErrorCode::malformed, "CIL max_stack exceeded");
                } else {
                    block.instructions.push_back({origin, Intrinsic{"cil_field_store " + field_name, {std::move(object), std::move(value)}, IntrinsicMemoryEffect::write}});
                }
                result.referenced_tokens.push_back(*token);
                continue;
            }
            if (op == "newarr") {
                const auto token = call_token(ins);
                auto length = pop(stack);
                if (!token || ((*token >> 24) != 0x01 && (*token >> 24) != 0x02 && (*token >> 24) != 0x1b))
                    return failure(ErrorCode::malformed, "CIL newarr has an invalid element type token");
                if (!length) return failure(ErrorCode::malformed, "CIL newarr underflows evaluation stack");
                const auto name = "cil_newarr_" + std::to_string(origin.instruction_id);
                Intrinsic allocation{name + " = ", {std::move(length), constant(*token)}, IntrinsicMemoryEffect::write};
                allocation.result_type = managed_reference_type();
                block.instructions.push_back({origin, std::move(allocation)});
                if (!push(typed_variable(name, managed_reference_type()))) return failure(ErrorCode::malformed, "CIL max_stack exceeded");
                result.referenced_tokens.push_back(*token);
                continue;
            }
            if (op == "ldlen") {
                auto array = pop(stack);
                if (!array) return failure(ErrorCode::malformed, "CIL ldlen underflows evaluation stack");
                const ValueType length_type{TypeKind::integer, 0, false};
                const auto name = "cil_array_length_" + std::to_string(origin.instruction_id);
                Intrinsic length{name + " = ", {std::move(array)}, IntrinsicMemoryEffect::read};
                length.result_type = length_type;
                block.instructions.push_back({origin, std::move(length)});
                if (!push(typed_variable(name, length_type))) return failure(ErrorCode::malformed, "CIL max_stack exceeded");
                continue;
            }
            if (op == "ldelema") {
                const auto token = call_token(ins);
                auto index = pop(stack), array = pop(stack);
                if (!token || (*token >> 24) != 0x01 && (*token >> 24) != 0x02 && (*token >> 24) != 0x1b)
                    return failure(ErrorCode::malformed, "CIL ldelema has an invalid element type token");
                if (!index || !array) return failure(ErrorCode::malformed, "CIL ldelema underflows evaluation stack");
                const auto name = "cil_array_element_address_" + std::to_string(origin.instruction_id);
                Intrinsic address{name + " = ", {std::move(array), std::move(index), constant(*token)}, IntrinsicMemoryEffect::none};
                address.result_type = managed_reference_type();
                block.instructions.push_back({origin, std::move(address)});
                if (!push(typed_variable(name, managed_reference_type()))) return failure(ErrorCode::malformed, "CIL max_stack exceeded");
                result.referenced_tokens.push_back(*token);
                continue;
            }
            if (op == "cpblk" || op == "initblk") {
                auto size = pop(stack), value_or_source = pop(stack), destination = pop(stack);
                if (!size || !value_or_source || !destination)
                    return failure(ErrorCode::malformed, "CIL block-memory instruction underflows evaluation stack");
                const auto effect = op == "cpblk" ? IntrinsicMemoryEffect::unknown : IntrinsicMemoryEffect::write;
                block.instructions.push_back({origin, Intrinsic{"cil_" + std::string(op),
                    {std::move(destination), std::move(value_or_source), std::move(size)}, effect}});
                result.complete = false;
                result.lifted.diagnostics.push_back("CIL block-memory operation retains its explicit operands, but dynamic extent and alias behavior are unresolved");
                continue;
            }
            if (op == "initobj" || op == "ldobj" || op == "stobj" || op == "cpobj") {
                const auto token = call_token(ins);
                if (!token || ((*token >> 24) != 0x01 && (*token >> 24) != 0x02 && (*token >> 24) != 0x1b) || !(*token & 0x00ffffff))
                    return failure(ErrorCode::malformed, "CIL object-memory instruction has an invalid type token");
                auto token_value = constant(*token);
                if (op == "initobj") {
                    auto address = pop(stack);
                    if (!address) return failure(ErrorCode::malformed, "CIL initobj underflows evaluation stack");
                    block.instructions.push_back({origin, Intrinsic{"cil_initobj", {std::move(address), std::move(token_value)}, IntrinsicMemoryEffect::write}});
                } else if (op == "ldobj") {
                    auto address = pop(stack);
                    if (!address) return failure(ErrorCode::malformed, "CIL ldobj underflows evaluation stack");
                    const auto name = "cil_ldobj_" + std::to_string(origin.instruction_id);
                    Intrinsic load{name + " = ", {std::move(address), std::move(token_value)}, IntrinsicMemoryEffect::read};
                    load.result_type = {};
                    block.instructions.push_back({origin, std::move(load)});
                    if (!push(typed_variable(name, {}))) return failure(ErrorCode::malformed, "CIL max_stack exceeded");
                } else if (op == "stobj") {
                    auto value = pop(stack), address = pop(stack);
                    if (!value || !address) return failure(ErrorCode::malformed, "CIL stobj underflows evaluation stack");
                    block.instructions.push_back({origin, Intrinsic{"cil_stobj", {std::move(address), std::move(value), std::move(token_value)}, IntrinsicMemoryEffect::write}});
                } else {
                    auto source = pop(stack), destination = pop(stack);
                    if (!source || !destination) return failure(ErrorCode::malformed, "CIL cpobj underflows evaluation stack");
                    block.instructions.push_back({origin, Intrinsic{"cil_cpobj", {std::move(destination), std::move(source), std::move(token_value)}, IntrinsicMemoryEffect::unknown}});
                }
                result.referenced_tokens.push_back(*token);
                result.complete = false;
                result.lifted.diagnostics.push_back("CIL object-memory operation retains its type token, but aggregate size, exact value type, and aliasing are unresolved");
                continue;
            }
            if (op.starts_with("ldind.")) {
                const auto type = managed_indirect_load_type(op);
                if (!type) return failure(ErrorCode::unsupported, "CIL indirect load type is unsupported");
                auto address = pop(stack);
                if (!address) return failure(ErrorCode::malformed, "CIL indirect load underflows evaluation stack");
                const auto name = "cil_" + std::string(op) + "_" + std::to_string(origin.instruction_id);
                Intrinsic load{name + " = ", {std::move(address)}, IntrinsicMemoryEffect::read};
                load.result_type = *type;
                block.instructions.push_back({origin, std::move(load)});
                if (!push(typed_variable(name, *type))) return failure(ErrorCode::malformed, "CIL max_stack exceeded");
                continue;
            }
            if (managed_indirect_store(op)) {
                auto value = pop(stack), address = pop(stack);
                if (!value || !address)
                    return failure(ErrorCode::malformed, "CIL indirect store underflows evaluation stack");
                const auto name = "cil_" + std::string(op) + "_" + std::to_string(origin.instruction_id);
                block.instructions.push_back({origin, Intrinsic{name, {std::move(address), std::move(value)},
                                                                 IntrinsicMemoryEffect::write}});
                continue;
            }
            if (managed_array_load(op)) {
                const auto type = managed_array_element_type(op);
                if (!type) return failure(ErrorCode::unsupported, "CIL array element type is unsupported");
                auto index = pop(stack), array = pop(stack);
                if (!index || !array) return failure(ErrorCode::malformed, "CIL array load underflows evaluation stack");
                const auto name = "cil_" + std::string(op) + "_" + std::to_string(origin.instruction_id);
                Intrinsic load{name + " = ", {std::move(array), std::move(index)}, IntrinsicMemoryEffect::read};
                load.result_type = *type;
                block.instructions.push_back({origin, std::move(load)});
                if (!push(typed_variable(name, *type))) return failure(ErrorCode::malformed, "CIL max_stack exceeded");
                continue;
            }
            if (managed_array_store(op)) {
                auto value = pop(stack), index = pop(stack), array = pop(stack);
                if (!value || !index || !array) return failure(ErrorCode::malformed, "CIL array store underflows evaluation stack");
                const auto name = "cil_" + std::string(op) + "_" + std::to_string(origin.instruction_id);
                block.instructions.push_back({origin, Intrinsic{name, {std::move(array), std::move(index), std::move(value)}, IntrinsicMemoryEffect::write}});
                continue;
            }
            if (op == "dup") { if(stack.empty())return failure(ErrorCode::malformed,"CIL dup underflows evaluation stack"); if(!push(stack.back()))return failure(ErrorCode::malformed,"CIL max_stack exceeded"); continue; }
            if (op == "pop") { if(!pop(stack))return failure(ErrorCode::malformed,"CIL pop underflows evaluation stack"); continue; }
            if (op == "neg" || op == "not") { auto value=pop(stack); if(!value)return failure(ErrorCode::malformed,"CIL unary operation underflows evaluation stack"); if(!push(unary(op=="neg"?"-":"~",std::move(value))))return failure(ErrorCode::malformed,"CIL max_stack exceeded"); continue; }
            if (const auto conversion = integer_conversion(op)) {
                auto value = pop(stack);
                if (!value) return failure(ErrorCode::malformed, "CIL conversion underflows evaluation stack");
                if (!push(convert_integer(op, *conversion, std::move(value))))
                    return failure(ErrorCode::malformed, "CIL max_stack exceeded");
                continue;
            }
            if (const auto conversion_bits = floating_conversion(op)) {
                auto value = pop(stack);
                if (!value) return failure(ErrorCode::malformed, "CIL floating conversion underflows evaluation stack");
                if (!push(convert_floating(op, *conversion_bits, std::move(value))))
                    return failure(ErrorCode::malformed, "CIL max_stack exceeded");
                continue;
            }
            const std::map<std::string, std::string, std::less<>> binary_ops{
                {"add","+"},{"sub","-"},{"mul","*"},{"div","/"},{"div.un","udiv"},{"rem","%"},{"rem.un","urem"},
                {"and","&"},{"or","|"},{"xor","^"},{"shl","<<"},{"shr",">>"},{"shr.un",">>"},
                {"ceq","=="},{"cgt",">"},{"cgt.un","ugt"},{"clt","<"},{"clt.un","ult"}};
            if (op == "shr.un") { auto right=pop(stack),left=pop(stack);if(!left||!right)return failure(ErrorCode::malformed,"CIL binary operation underflows evaluation stack");if(!push(binary("lshr",std::move(left),std::move(right))))return failure(ErrorCode::malformed,"CIL max_stack exceeded");continue; }
            if (auto it=binary_ops.find(op);it!=binary_ops.end()) {
                auto right=pop(stack),left=pop(stack);
                if(!left||!right)return failure(ErrorCode::malformed,"CIL binary operation underflows evaluation stack");
                const bool cmp=op=="ceq"||op.starts_with("cgt")||op.starts_with("clt");
                const bool left_float=left->type.kind==TypeKind::floating;
                const bool right_float=right->type.kind==TypeKind::floating;
                if(left_float||right_float) {
                    if(!left_float||!right_float||left->type.bits!=right->type.bits||
                       (left->type.bits!=32&&left->type.bits!=64))
                        return failure(ErrorCode::unsupported,"CIL floating operation has incompatible or unknown operand types");
                    std::string operation;
                    if(op=="add")operation="+";
                    else if(op=="sub")operation="-";
                    else if(op=="mul")operation="*";
                    else if(op=="div"||op=="div.un")operation="/";
                    else if(op=="rem"||op=="rem.un")operation="frem";
                    else if(op=="ceq")operation="==";
                    else if(op=="cgt")operation=">";
                    else if(op=="clt")operation="<";
                    else if(op=="cgt.un")operation="fcgt_un";
                    else if(op=="clt.un")operation="fclt_un";
                    else return failure(ErrorCode::unsupported,"CIL floating bitwise or shift operation is invalid");
                    if(!push(binary(std::move(operation),std::move(left),std::move(right),cmp)))
                        return failure(ErrorCode::malformed,"CIL max_stack exceeded");
                    continue;
                }
                if(!push(binary(it->second,std::move(left),std::move(right),cmp)))return failure(ErrorCode::malformed,"CIL max_stack exceeded");
                continue;
            }
            if (op == "ret") {
                ExpressionPtr value;
                if (!stack.empty()) value=pop(stack);
                if (!stack.empty()) return failure(ErrorCode::malformed,"CIL ret leaves extra evaluation-stack values");
                block.instructions.push_back({origin, Return{std::move(value)}});
                block.successors.clear(); terminated=true; break;
            }
            if (op == "throw") {
                auto exception = pop(stack);
                if (!exception) return failure(ErrorCode::malformed, "CIL throw underflows evaluation stack");
                if (!stack.empty()) return failure(ErrorCode::malformed, "CIL throw leaves extra evaluation-stack values");
                block.instructions.push_back({origin, Intrinsic{"throw", {std::move(exception)}, IntrinsicMemoryEffect::none}});
                terminated = true; break;
            }
            if (op == "rethrow") {
                if (!stack.empty()) return failure(ErrorCode::malformed, "CIL rethrow requires an empty evaluation stack");
                block.instructions.push_back({origin, Intrinsic{"rethrow_current_exception", {}, IntrinsicMemoryEffect::none}});
                stack.clear();
                terminated = true; break;
            }
            if (op == "endfilter") {
                auto filter_result = pop(stack);
                if (!filter_result || !stack.empty())
                    return failure(ErrorCode::malformed, "CIL endfilter requires exactly one result on the evaluation stack");
                const auto routes = endfilter_routes.find(ins.offset);
                if (routes == endfilter_routes.end() || routes->second.empty())
                    return failure(ErrorCode::malformed, "CIL endfilter has no ordered exception-dispatch continuation");
                const RegisterOperand continuation_reg{RegisterBank::cil_continuation, 0, 32, false};
                const RegisterOperand filter_result_reg{RegisterBank::cil_continuation, 1, 32, false};
                block.instructions.push_back({origin, Assign{filter_result_reg, std::move(filter_result), {}}});
                LiftedBlock::SwitchDispatch dispatch;
                dispatch.selector = std::make_shared<Expression>(Expression{
                    int_type(32), RegisterValue{continuation_reg, {}}});
                dispatch.complete = true;
                std::set<std::uint32_t> emitted_routes;
                for (const auto &route : routes->second) {
                    if (!emitted_routes.insert(route.id).second) continue;
                    dispatch.cases.push_back({route.id, route.decision});
                    const auto target_id = block_id_for_address(route.decision);
                    if (!target_id) return failure(ErrorCode::malformed, "CIL endfilter decision block is missing");
                    block.successors.push_back({origin.address, route.decision, *target_id, BlockEdgeKind::exception});
                }
                block.switch_dispatch = std::move(dispatch);
                block.instructions.push_back({origin, Intrinsic{"endfilter_resume", {}, IntrinsicMemoryEffect::none}});
                terminated = true; break;
            }
            if (op == "endfinally") {
                if (!stack.empty()) return failure(ErrorCode::malformed, "CIL endfinally has a nonempty evaluation stack");
                block.instructions.push_back({origin, Intrinsic{"endfinally_resume", {}, IntrinsicMemoryEffect::none}});
                const auto routes = endfinally_routes.find(ins.offset);
                if (routes != endfinally_routes.end() && !routes->second.empty()) {
                    const RegisterOperand continuation_reg{RegisterBank::cil_continuation, 0, 32, false};
                    LiftedBlock::SwitchDispatch dispatch;
                    dispatch.selector = std::make_shared<Expression>(Expression{
                        int_type(32), RegisterValue{continuation_reg, {}}});
                    dispatch.complete = true;
                    std::map<std::uint32_t, Address> id_targets;
                    for (const auto &route : routes->second) {
                        const auto [found, inserted] = id_targets.emplace(route.id, route.target);
                        if (!inserted && found->second != route.target)
                            return failure(ErrorCode::malformed, "CIL finally continuation ID has conflicting destinations");
                        if (!inserted) continue;
                        dispatch.cases.push_back({route.id, route.target});
                        const auto target_address = route.target;
                        const auto target_id = block_id_for_address(target_address);
                        if (!target_id) return failure(ErrorCode::malformed, "CIL finally continuation target has no block");
                        if (std::none_of(block.successors.begin(), block.successors.end(), [&](const auto &edge) {
                                return edge.target == std::optional<Address>{target_address};
                            }))
                            block.successors.push_back({origin.address, target_address, *target_id,
                                route.exceptional ? BlockEdgeKind::exception : BlockEdgeKind::jump});
                    }
                    if (dispatch.cases.empty()) return failure(ErrorCode::malformed, "CIL endfinally has no continuation cases");
                    block.switch_dispatch = std::move(dispatch);
                }
                terminated = true; break;
            }
            if (op == "br" || op == "br.s" || op == "leave" || op == "leave.s") {
                const auto *branch=std::get_if<CilBranchOperand>(&ins.operand); if(!branch)return failure(ErrorCode::malformed,"Missing CIL branch target");
                auto target_offset = branch->target_offset;
                if (op == "leave" || op == "leave.s") {
                    const auto continuation = finally_continuations.find(ins.offset);
                    if (continuation != finally_continuations.end()) {
                        const RegisterOperand continuation_reg{RegisterBank::cil_continuation, 0, 32, false};
                        block.instructions.push_back({origin, Assign{continuation_reg,
                            std::make_shared<Expression>(Expression{int_type(32), ConstantValue{continuation->second.id, int_type(32)}}), {}}});
                        target_offset = continuation->second.handlers.front();
                    }
                    stack.clear();
                }
                const auto target=il_address(target_offset);const auto target_block=block_index_for(target_offset);if(!target_block)return failure(ErrorCode::malformed,"CIL branch target has no block");
                block.instructions.push_back({origin,Branch{"true",target,{}, {}}});
                block.successors.push_back({origin.address,target,result.lifted.blocks[*target_block].id,BlockEdgeKind::jump});
                terminated=true;break;
            }
            if (op == "switch") {
                const auto *table = std::get_if<CilSwitchOperand>(&ins.operand);
                if (!table) return failure(ErrorCode::malformed, "Missing CIL switch target table");
                auto selector = pop(stack);
                if (!selector) return failure(ErrorCode::malformed, "CIL switch underflows evaluation stack");
                LiftedBlock::SwitchDispatch dispatch;
                dispatch.selector = std::move(selector);
                dispatch.complete = true;
                for (std::size_t case_index = 0; case_index < table->target_offsets.size(); ++case_index) {
                    const auto target_offset = table->target_offsets[case_index];
                    const auto target_block = block_index_for(target_offset);
                    if (!target_block) return failure(ErrorCode::malformed, "CIL switch target has no block");
                    const auto target = il_address(target_offset);
                    dispatch.cases.push_back({case_index, target});
                    if (std::none_of(block.successors.begin(), block.successors.end(), [&](const auto &edge) { return edge.target == std::optional<Address>{target}; }))
                        block.successors.push_back({origin.address, target, result.lifted.blocks[*target_block].id, BlockEdgeKind::jump});
                }
                const auto default_block = block_index_for(next);
                if (!default_block) return failure(ErrorCode::malformed, "CIL switch has no default fallthrough block");
                dispatch.default_target = il_address(next);
                const auto default_target = *dispatch.default_target;
                if (std::none_of(block.successors.begin(), block.successors.end(), [&](const auto &edge) {
                        return edge.target == std::optional<Address>{default_target};
                    }))
                    block.successors.push_back({origin.address, default_target,
                        result.lifted.blocks[*default_block].id, BlockEdgeKind::jump});
                block.switch_dispatch = std::move(dispatch);
                terminated = true; break;
            }
            if (op.starts_with("brtrue") || op.starts_with("brfalse") || op.starts_with("beq") || op.starts_with("bne") ||
                op.starts_with("bge") || op.starts_with("bgt") || op.starts_with("ble") || op.starts_with("blt")) {
                const auto *branch=std::get_if<CilBranchOperand>(&ins.operand);if(!branch)return failure(ErrorCode::malformed,"Missing conditional CIL branch target");
                ExpressionPtr predicate;
                if(op.starts_with("brtrue")||op.starts_with("brfalse")){auto value=pop(stack);if(!value)return failure(ErrorCode::malformed,"Conditional branch underflows evaluation stack");predicate=op.starts_with("brfalse")?unary("!",std::move(value)):std::move(value);}
                else {
                    auto right=pop(stack),left=pop(stack);
                    if(!left||!right)return failure(ErrorCode::malformed,"Comparison branch underflows evaluation stack");
                    const bool uns=op.ends_with(".un")||op.ends_with(".un.s");
                    const bool left_float=left->type.kind==TypeKind::floating;
                    const bool right_float=right->type.kind==TypeKind::floating;
                    std::string cmp;
                    if(left_float||right_float) {
                        if(!left_float||!right_float||left->type.bits!=right->type.bits||
                           (left->type.bits!=32&&left->type.bits!=64))
                            return failure(ErrorCode::unsupported,"CIL floating comparison branch has incompatible or unknown operand types");
                        if(op.starts_with("beq"))cmp="==";
                        else if(op.starts_with("bne"))cmp="!=";
                        else if(op.starts_with("bge"))cmp=uns?"fbge_un":">=";
                        else if(op.starts_with("bgt"))cmp=uns?"fcgt_un":">";
                        else if(op.starts_with("ble"))cmp=uns?"fble_un":"<=";
                        else cmp=uns?"fclt_un":"<";
                    } else {
                        cmp=op.starts_with("beq")?"==":op.starts_with("bne")?"!=":op.starts_with("bge")?(uns?"uge":"sge"):op.starts_with("bgt")?(uns?"ugt":"sgt"):op.starts_with("ble")?(uns?"ule":"sle"):(uns?"ult":"slt");
                    }
                    predicate=binary(std::move(cmp),std::move(left),std::move(right),true);
                }
                const auto target=il_address(branch->target_offset);const auto target_block=block_index_for(branch->target_offset);if(!target_block)return failure(ErrorCode::malformed,"CIL conditional target has no block");
                auto false_block=block_index_for(next);if(!false_block)return failure(ErrorCode::malformed,"CIL conditional branch has no fallthrough block");
                block.instructions.push_back({origin,Branch{"predicate",target,il_address(next),std::move(predicate)}});
                block.successors.push_back({origin.address,target,result.lifted.blocks[*target_block].id,BlockEdgeKind::conditional_true});
                block.successors.push_back({origin.address,il_address(next),result.lifted.blocks[*false_block].id,BlockEdgeKind::conditional_false});
                terminated=true;break;
            }
            if (op == "call" || op == "callvirt" || op == "newobj" || op == "calli") {
                const auto token=call_token(ins);if(!token)return failure(ErrorCode::malformed,"CIL call is missing metadata token");
                const auto signature=resolved_signatures.find(*token);if(signature==resolved_signatures.end())return failure(ErrorCode::unsupported,"CIL call signature is unavailable; stack effects cannot be inferred");
                const bool construct=op=="newobj", indirect=op=="calli";
                if ((op=="callvirt" || construct) && !signature->second.has_this)
                    return failure(ErrorCode::malformed, op=="callvirt"
                        ? "CIL callvirt target signature has no instance receiver"
                        : "CIL newobj target signature has no instance receiver");
                if (construct && signature->second.returns_value)
                    return failure(ErrorCode::malformed,"CIL newobj target signature returns a value");
                const auto count=signature->second.parameter_count+(signature->second.has_this&&!construct?1u:0u);
                if(count>stack.size() || (indirect && stack.size()-count<1))return failure(ErrorCode::malformed,"CIL call arguments or function pointer underflow evaluation stack");
                std::vector<ExpressionPtr> arguments;
                arguments.reserve(count + (indirect ? 1u : 0u));
                if(indirect){auto target=pop(stack);arguments.push_back(std::move(target));}
                const auto first_argument=arguments.size();arguments.resize(first_argument+count);
                for(std::size_t i=0;i<count;++i)arguments[first_argument+count-i-1]=pop(stack);
                auto name=std::string(construct?"newobj_":op=="callvirt"?"callvirt_":indirect?"calli_":"call_")+token_name(*token).substr(5);
                const auto receiver_offset=indirect?1u:0u;
                const auto explicit_parameter_offset=receiver_offset+(signature->second.has_this&&!construct?1u:0u);
                if(signature->second.has_this&&!construct&&!arguments.empty())
                    arguments[receiver_offset]=retag_managed_expression(arguments[receiver_offset],managed_reference_type());
                if(indirect&& !arguments.empty())arguments[0]=retag_managed_expression(arguments[0],managed_reference_type());
                if(signature->second.parameter_types.size()==signature->second.parameter_count){
                    for(std::size_t i=0;i<signature->second.parameter_types.size();++i){
                        const auto index=explicit_parameter_offset+i;
                        if(index>=arguments.size())return failure(ErrorCode::malformed,"CIL call signature parameter mapping exceeds argument list");
                        const auto type=managed_signature_type(signature->second.parameter_types[i],signature->second);
                        arguments[index]=retag_managed_expression(arguments[index],type);
                    }
                }
                const auto result_type=managed_call_result_type(signature->second,construct);
                Intrinsic call{name,std::move(arguments),IntrinsicMemoryEffect::unknown};
                if(result_type.kind!=TypeKind::unknown)call.result_type=result_type;
                block.instructions.push_back({origin,std::move(call)});
                result.referenced_tokens.push_back(*token);
                if((construct||signature->second.returns_value)&&!push(typed_variable(name+"(/* return value */)",result_type)))
                    return failure(ErrorCode::malformed,"CIL max_stack exceeded");
                continue;
            }
            return failure(ErrorCode::unsupported,"CIL opcode has no stack-lifting rule");
        }
        if (!terminated) {
            bool region_exit = false;
            for (const auto &clause : method.body->exception_clauses)
                region_exit |= last_end == clause.try_offset + clause.try_length || last_end == clause.handler_offset + clause.handler_length;
            if (bi + 1 < starts.size() && !region_exit) {
                const auto target=il_address(starts[bi+1]);
                block.successors.push_back({il_address(last_end),target,result.lifted.blocks[bi+1].id,BlockEdgeKind::fallthrough});
            }
        }
        if (exit_shapes[bi]) {
            if (stack.size() != exit_shapes[bi]->size())
                return failure(ErrorCode::malformed, "CIL stack-shape and expression passes disagree on stack depth");
            for (std::size_t slot = 0; slot < stack.size(); ++slot)
                if (!stack[slot] || stack[slot]->type != (*exit_shapes[bi])[slot])
                    return failure(ErrorCode::malformed, "CIL stack-shape and expression passes disagree on stack type");
        }
        if (!stack.empty() && block.successors.empty())
            return failure(ErrorCode::unsupported, "CIL block exits with values but has no modeled successor");
        if (!stack.empty()) {
            if (stack.size() > stack_versions.size())
                return failure(ErrorCode::resource_limit, "CIL evaluation stack exceeds virtual-register limit");
            if (output_versions[bi].size() != stack.size())
                return failure(ErrorCode::unsupported, "CIL unreachable or unsupported block has an unmodeled outgoing stack");
            std::vector<LiftedInstruction> edge_definitions;
            edge_definitions.reserve(stack.size());
            auto edge_origin = InstructionOrigin{il_address(last_end),
                                                 (std::uint64_t{method.method.token} << 32) | last_end};
            if (!block.instructions.empty()) edge_origin = block.instructions.back().origin;
            for (std::size_t slot = 0; slot < stack.size(); ++slot) {
                const auto type = stack[slot]->type;
                const RegisterOperand reg{RegisterBank::cil_stack, static_cast<std::uint8_t>(slot), type.bits, false};
                const auto version = output_versions[bi][slot];
                edge_definitions.push_back({edge_origin, Assign{reg, stack[slot], version}});
                stack[slot] = std::make_shared<Expression>(Expression{type, RegisterValue{reg, version}});
            }
            auto insertion = block.instructions.end();
            if (insertion != block.instructions.begin() && std::holds_alternative<Branch>((insertion - 1)->statement)) --insertion;
            block.instructions.insert(insertion, edge_definitions.begin(), edge_definitions.end());
        }
    }
    // Exceptional dispatch uses conservative possible-throw edges from every
    // instruction in a protected try or filter. The synthetic dispatcher
    // preserves metadata clause order and represents type assignability as
    // opaque tests; filter exceptions target a false-result continuation.
    for (const auto &[source_instruction_index, dispatch_address] : instruction_exception_entries) {
        const auto &instruction = method.instructions[source_instruction_index];
        const auto upper = std::upper_bound(starts.begin(), starts.end(), instruction.offset);
        if (upper == starts.begin()) return failure(ErrorCode::malformed, "CIL exceptional source has no basic block");
        const auto block_index = static_cast<std::size_t>(std::distance(starts.begin(), upper) - 1);
        const auto dispatch_id = synthetic_id_for(dispatch_address);
        if (!dispatch_id) return failure(ErrorCode::malformed, "CIL exception dispatcher has no synthetic block");
        auto &edges = result.lifted.blocks[block_index].successors;
        if (std::none_of(edges.begin(), edges.end(), [&](const auto &edge) {
                return edge.kind == BlockEdgeKind::exception && edge.target == std::optional<Address>{dispatch_address};
            }))
            edges.push_back({il_address(instruction.offset), dispatch_address, *dispatch_id, BlockEdgeKind::exception});
        auto &source_block = result.lifted.blocks[block_index];
        LiftedBlock::ExceptionMemoryTiming memory_timing =
            LiftedBlock::ExceptionMemoryTiming::before_instruction;
        bool found_source = false;
        for (auto &lifted : source_block.instructions) {
            if (lifted.origin.address != il_address(instruction.offset)) continue;
            found_source = true;
            if (auto *intrinsic = std::get_if<Intrinsic>(&lifted.statement)) {
                if (intrinsic->memory_effect == IntrinsicMemoryEffect::write ||
                    intrinsic->memory_effect == IntrinsicMemoryEffect::unknown) {
                    // A managed store/call may partially complete before a
                    // runtime fault. Preserve an explicit unknown memory
                    // version for the exceptional path instead of claiming its
                    // pre-instruction input is still current.
                    intrinsic->memory_effect = IntrinsicMemoryEffect::unknown;
                    memory_timing = LiftedBlock::ExceptionMemoryTiming::opaque_effect;
                }
            } else if (std::holds_alternative<Store>(lifted.statement) ||
                       std::holds_alternative<Call>(lifted.statement)) {
                return failure(ErrorCode::unsupported,
                    "CIL exceptional memory state cannot be represented for this opaque statement");
            }
            break;
        }
        if (!found_source)
            return failure(ErrorCode::malformed, "CIL exceptional edge has no lifted source instruction");
        if (std::none_of(source_block.exception_memory_edges.begin(), source_block.exception_memory_edges.end(),
                [&](const auto &edge) {
                    return edge.source == il_address(instruction.offset) && edge.target == dispatch_address;
                }))
            source_block.exception_memory_edges.push_back(
                {il_address(instruction.offset), dispatch_address, memory_timing});
    }
    result.lifted.blocks.insert(result.lifted.blocks.end(),
        std::make_move_iterator(synthetic_blocks.begin()), std::make_move_iterator(synthetic_blocks.end()));
    std::sort(result.referenced_tokens.begin(), result.referenced_tokens.end());
    result.referenced_tokens.erase(std::unique(result.referenced_tokens.begin(), result.referenced_tokens.end()), result.referenced_tokens.end());
    std::string eh_fallback_reason;
    const auto simple_exception_pseudocode = [&]() -> std::optional<StructuredPseudocode> {
        const auto reject = [&](const char* reason) -> std::optional<StructuredPseudocode> {
            eh_fallback_reason = reason;
            return {};
        };
        if (result.exception_clauses.size() != 1 || result.exception_regions.size() != 1)
            return reject("CIL EH structuring requires one protected region and one handler; nested or multiple clauses retain explicit CFG");
        const auto& clause = result.exception_clauses.front();
        const bool catching = clause.kind == CilExceptionKind::catch_clause;
        if (!catching && clause.kind != CilExceptionKind::finally_clause)
            return reject("CIL filters and faults retain explicit exception dispatch and unwind CFG");
        const auto try_end = clause.try_offset + clause.try_length;
        const auto handler_end = clause.handler_offset + clause.handler_length;
        if (try_end != clause.handler_offset || handler_end >= method.body->code_size)
            return reject("CIL EH structuring requires an adjacent try/handler followed by a common continuation");
        if (nonempty_leave_stack)
            return reject("CIL leave discards a nonempty stack; structured EH requires empty leave stacks");

        // Require exactly one lexical exit from each body and a straight-line
        // return continuation. The original CFG, including exceptional edges,
        // is kept intact; only this presentation consumes the proven leaves.
        std::size_t try_leaves = 0, handler_exits = 0, returns = 0;
        std::map<std::uint32_t, std::string_view> omitted_transfers;
        for (const auto& instruction : method.instructions) {
            if (instruction.status != CilInstructionStatus::decoded)
                return reject("CIL EH contains an unsupported instruction requiring explicit CFG");
            const std::string_view op = instruction.mnemonic;
            const auto end = instruction.offset + instruction.size;
            if (op == "leave" || op == "leave.s") {
                const auto* branch = std::get_if<CilBranchOperand>(&instruction.operand);
                if (!branch || branch->target_offset != handler_end)
                    return reject("CIL EH leaves do not share the handler-end continuation");
                if (end == try_end && instruction.offset >= clause.try_offset) ++try_leaves;
                else if (catching && end == handler_end && instruction.offset >= clause.handler_offset) ++handler_exits;
                else return reject("CIL EH contains a nonterminal or unsupported leave");
                omitted_transfers.emplace(instruction.offset, op);
            } else if (op == "endfinally") {
                if (catching || end != handler_end || instruction.offset < clause.handler_offset)
                    return reject("CIL EH contains a nonterminal or unsupported endfinally");
                ++handler_exits;
                omitted_transfers.emplace(instruction.offset, op);
            } else if (op == "ret") {
                if (instruction.offset < handler_end || end != method.body->code_size)
                    return reject("CIL EH requires a single final return outside the region");
                ++returns;
            } else if (std::holds_alternative<CilBranchOperand>(instruction.operand) ||
                       std::holds_alternative<CilSwitchOperand>(instruction.operand) ||
                       op == "throw" || op == "rethrow" || op == "endfilter") {
                return reject("CIL EH contains internal branching, throw/rethrow, or unsupported handler control flow");
            }
        }
        if (try_leaves != 1 || handler_exits != 1 || returns != 1)
            return reject("CIL EH requires one terminal try leave, one terminal handler exit, and one return");

        std::array<std::vector<LiftedInstruction>, 4> statements;
        for (std::size_t bi = 0; bi < starts.size(); ++bi) {
            const auto& block = result.lifted.blocks[bi];
            if (block.begin != il_address(starts[bi]) || !entry_shapes[bi] || !block.phis.empty() ||
                block.memory_phi || !block.memory_partition_phis.empty())
                return reject("CIL EH has unreachable blocks or stack/memory phis requiring explicit CFG");
            const auto expected_depth = catching && starts[bi] == clause.handler_offset ? 1u : 0u;
            if (entry_shapes[bi]->size() != expected_depth ||
                (exit_shapes[bi] && !exit_shapes[bi]->empty()))
                return reject("CIL EH carries evaluation-stack values across lexical block boundaries");
            const auto group = starts[bi] < clause.try_offset ? 0u : starts[bi] < try_end ? 1u :
                               starts[bi] < handler_end ? 2u : 3u;
            for (const auto& item : block.instructions) {
                const auto transfer = omitted_transfers.find(static_cast<std::uint32_t>(item.origin.address.offset));
                if (const auto* intrinsic = std::get_if<Intrinsic>(&item.statement)) {
                    if (intrinsic->name.starts_with("unsupported_cil_"))
                        return reject("CIL EH contains an opaque instruction requiring explicit CFG");
                    if (intrinsic->name == "try_region_begin" || intrinsic->name.starts_with("catch_handler_begin") ||
                        intrinsic->name == "finally_handler_begin" || intrinsic->name == "exception_region_end") continue;
                    if (intrinsic->name == "endfinally_resume" && transfer != omitted_transfers.end() &&
                        transfer->second == "endfinally") continue;
                }
                if (std::holds_alternative<Branch>(item.statement)) {
                    if (transfer == omitted_transfers.end())
                        return reject("CIL EH includes a lifted branch without a proven lexical exit");
                    continue;
                }
                if (const auto* assignment = std::get_if<Assign>(&item.statement);
                    assignment && assignment->destination.bank == RegisterBank::cil_continuation) {
                    if (catching || transfer == omitted_transfers.end() || transfer->second == "endfinally")
                        return reject("CIL EH continuation state is used outside the proven finally leave");
                    continue;
                }
                statements[group].push_back(item);
            }
        }

        // Reuse the common statement formatter without reconstructing or
        // rewriting expressions. Strip only its fixed function/label wrapper.
        LiftedFunction fragment;
        fragment.id = result.lifted.id;
        fragment.entry = result.lifted.entry;
        fragment.blocks.push_back({BlockId{1}, fragment.entry});
        std::array<std::string, 4> bodies;
        std::string header;
        for (std::size_t group = 0; group < statements.size(); ++group) {
            fragment.blocks.front().instructions = std::move(statements[group]);
            const auto formatted = format_pseudocode(fragment);
            const auto first = formatted.find('\n');
            const auto second = first == std::string::npos ? first : formatted.find('\n', first + 1);
            if (first == std::string::npos || second == std::string::npos || !formatted.ends_with("}\n") ||
                second + 1 > formatted.size() - 2)
                return reject("CIL EH statement formatter did not produce a bounded lexical fragment");
            if (header.empty()) header = formatted.substr(0, first + 1);
            bodies[group] = formatted.substr(second + 1, formatted.size() - 2 - (second + 1));
        }
        std::ostringstream out;
        out << header << bodies[0] << "    try {\n";
        const auto emit_indented = [&](const std::string& body) {
            std::istringstream lines(body);
            std::string line;
            while (std::getline(lines, line)) out << "    " << line << '\n';
        };
        emit_indented(bodies[1]);
        if (catching) {
            out << "    } catch (type_token(0x" << std::hex << clause.class_token << std::dec << ") exception) {";
            const auto name = method.resolved_exception_type_names.find(clause.class_token);
            if (name != method.resolved_exception_type_names.end()) out << " // " << quoted_metadata_name(name->second);
            out << '\n';
        } else out << "    } finally {\n";
        emit_indented(bodies[2]);
        out << "    }\n" << bodies[3] << "}\n";
        return StructuredPseudocode{out.str(), false, {}};
    };
    if (!result.exception_regions.empty()) {
        if (auto structured = simple_exception_pseudocode()) {
            result.pseudocode = std::move(*structured);
            result.pseudocode.text = exception_region_legend(result, true) + result.pseudocode.text;
        } else {
            result.pseudocode = format_structured_pseudocode(result.lifted);
            result.pseudocode.used_fallback = true;
            result.pseudocode.fallback_reason = std::move(eh_fallback_reason);
            result.pseudocode.text = exception_region_legend(result) + result.pseudocode.text;
        }
    } else result.pseudocode = format_structured_pseudocode(result.lifted);
    return result;
} catch (const std::bad_alloc &) {
    return failure(ErrorCode::resource_limit, "Cannot allocate managed CIL decompilation");
}

} // namespace hexlab::decompiler
