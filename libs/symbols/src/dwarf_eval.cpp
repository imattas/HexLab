#include "hexlab/symbols/dwarf.hpp"
#include "hexlab/symbols/dwarf_location_values.hpp"

#include <algorithm>
#include <bit>

namespace hexlab::symbols {
namespace {
hexlab::Error malformed_eval(const char *message) { return {hexlab::ErrorCode::malformed, message}; }
hexlab::Error unsupported_eval(const char *message) { return {hexlab::ErrorCode::unsupported, message}; }
hexlab::Result<EvaluatedLocation> evaluate_location_expression_impl(
    std::span<const LocationOperation>,const LocationEvaluationContext&,std::size_t,std::size_t&,std::size_t&);
}

hexlab::Result<EvaluatedLocation> evaluate_location_expression(
    std::span<const LocationOperation> operations, const LocationEvaluationContext &context) {
    std::size_t remaining_operations=65536;
    std::size_t remaining_memory_reads=4096;
    return evaluate_location_expression_impl(operations,context,0,remaining_operations,remaining_memory_reads);
}

namespace {
hexlab::Result<EvaluatedLocation> evaluate_location_expression_impl(
    std::span<const LocationOperation> operations,const LocationEvaluationContext &context,
    std::size_t depth,std::size_t& remaining_operations,std::size_t& remaining_memory_reads) {
    if(depth>16)return hexlab::Error{hexlab::ErrorCode::resource_limit,"DWARF entry-value evaluation exceeds 16 nested expressions"};
    if (context.address_size != 1 && context.address_size != 2 &&
        context.address_size != 4 && context.address_size != 8)
        return hexlab::Error{hexlab::ErrorCode::invalid_argument, "DWARF location address size must be 1, 2, 4, or 8"};
    if (operations.empty()) return malformed_eval("DWARF location expression is empty");
    if (operations.size() > 4096) return hexlab::Error{hexlab::ErrorCode::resource_limit, "DWARF location expression exceeds 4096 operations"};
    struct Cell { std::uint64_t value; bool register_location = false; };
    std::vector<Cell> stack;
    stack.reserve(16);
    const auto mask = context.address_size == 8 ? UINT64_MAX : ((std::uint64_t{1} << (context.address_size * 8)) - 1);
    const auto address_width_bits = static_cast<unsigned>(context.address_size) * 8;
    const auto sign_bit = std::uint64_t{1} << (address_width_bits - 1);
    auto signed_value = [&](std::uint64_t value) {
        value &= mask;
        if (address_width_bits == 64) return std::bit_cast<std::int64_t>(value);
        if (value & sign_bit) value |= ~mask;
        return static_cast<std::int64_t>(value);
    };
    bool stack_value = false;
    bool stack_limit = false;
    auto push = [&](std::uint64_t value, bool reg = false) {
        if (stack.size() >= 64) { stack_limit = true; return; }
        stack.push_back({value & mask, reg});
    };
    auto pop = [&]() -> hexlab::Result<Cell> {
        if (stack.empty()) return malformed_eval("DWARF location expression stack underflow");
        auto v = stack.back(); stack.pop_back(); return v;
    };
    std::size_t pc = 0, executed = 0;
    auto branch_to = [&](std::uint64_t offset) -> bool {
        if (offset > operations.back().expression_offset) { pc = operations.size(); return true; }
        const auto it = std::lower_bound(operations.begin(), operations.end(), offset,
            [](const auto &candidate, std::uint64_t target) { return candidate.expression_offset < target; });
        if (it == operations.end() || it->expression_offset != offset) return false;
        pc = static_cast<std::size_t>(it - operations.begin()); return true;
    };
    while (pc < operations.size()) {
        if (++executed > 65536 || !remaining_operations) return hexlab::Error{hexlab::ErrorCode::resource_limit, "DWARF nested expressions exceed 65536 executed operations"};
        --remaining_operations;
        const auto &op = operations[pc++];
        switch (op.kind) {
        case LocationOperationKind::address: case LocationOperationKind::literal:
        case LocationOperationKind::unsigned_constant:
            push(op.unsigned_operand); break;
        case LocationOperationKind::signed_constant:
            push(static_cast<std::uint64_t>(op.signed_operand)); break;
        case LocationOperationKind::register_location:
            push(op.unsigned_operand, true); break;
        case LocationOperationKind::base_register_plus_offset: {
            if (!context.read_register) return unsupported_eval("DWARF location requires a register reader");
            auto base = context.read_register(op.unsigned_operand);
            if (!base) return unsupported_eval("DWARF location references an unavailable register");
            push(*base + static_cast<std::uint64_t>(op.signed_operand)); break;
        }
        case LocationOperationKind::frame_base_relative:
            if (!context.frame_base) return unsupported_eval("DW_OP_fbreg requires a frame base");
            push(*context.frame_base + static_cast<std::uint64_t>(op.signed_operand)); break;
        case LocationOperationKind::call_frame_cfa:
            if (!context.call_frame_cfa) return unsupported_eval("DW_OP_call_frame_cfa requires a CFA value");
            push(*context.call_frame_cfa); break;
        case LocationOperationKind::dereference: case LocationOperationKind::dereference_sized: {
            auto address = pop(); if (!address) return address.error();
            if (address.value().register_location) return malformed_eval("DWARF dereference uses an unmaterialized register location");
            if (!context.read_memory) return unsupported_eval("DWARF dereference requires a memory reader");
            if (!remaining_memory_reads) return hexlab::Error{hexlab::ErrorCode::resource_limit, "DWARF expression exceeds 4096 memory reads"};
            --remaining_memory_reads;
            const auto width = op.kind == LocationOperationKind::dereference ? context.address_size : static_cast<std::uint8_t>(op.unsigned_operand);
            if (!width || width > 8) return malformed_eval("DWARF dereference width is invalid");
            auto value = context.read_memory(address.value().value, width); if (!value) return value.error();
            push(value.value()); break;
        }
        case LocationOperationKind::plus: {
            auto rhs = pop(); if (!rhs) return rhs.error(); auto lhs = pop(); if (!lhs) return lhs.error();
            if (lhs.value().register_location || rhs.value().register_location) return malformed_eval("DWARF arithmetic uses an unmaterialized register location");
            push(lhs.value().value + rhs.value().value); break;
        }
        case LocationOperationKind::plus_unsigned: {
            auto lhs = pop(); if (!lhs) return lhs.error();
            if (lhs.value().register_location) return malformed_eval("DWARF arithmetic uses an unmaterialized register location");
            push(lhs.value().value + op.unsigned_operand); break;
        }
        case LocationOperationKind::stack_operation: {
            const auto code = op.unsigned_operand;
            if (code == 0x96) { // DW_OP_nop
                break;
            } else if (code == 0x12) { // DW_OP_dup
                if (stack.empty()) return malformed_eval("DW_OP_dup requires one stack item");
                push(stack.back().value, stack.back().register_location);
            } else if (code == 0x13) { // DW_OP_drop
                auto ignored = pop(); if (!ignored) return ignored.error();
            } else if (code == 0x14) { // DW_OP_over
                if (stack.size() < 2) return malformed_eval("DW_OP_over requires two stack items");
                push(stack[stack.size() - 2].value, stack[stack.size() - 2].register_location);
            } else if (code == 0x15) { // DW_OP_pick
                const auto depth = op.second_unsigned_operand;
                if (depth >= stack.size()) return malformed_eval("DW_OP_pick index is outside the expression stack");
                const auto &cell = stack[stack.size() - 1 - static_cast<std::size_t>(depth)];
                push(cell.value, cell.register_location);
            } else if (code == 0x16) { // DW_OP_swap
                if (stack.size() < 2) return malformed_eval("DW_OP_swap requires two stack items");
                std::swap(stack[stack.size() - 1], stack[stack.size() - 2]);
            } else if (code == 0x17) { // DW_OP_rot, Forth ordering: a b c -> b c a
                if (stack.size() < 3) return malformed_eval("DW_OP_rot requires three stack items");
                const auto first = stack[stack.size() - 3];
                stack[stack.size() - 3] = stack[stack.size() - 2];
                stack[stack.size() - 2] = stack[stack.size() - 1];
                stack.back() = first;
            } else if (code == 0x19 || code == 0x1f || code == 0x20) { // abs, neg, not
                auto value = pop(); if (!value) return value.error();
                if (value.value().register_location) return malformed_eval("DWARF arithmetic uses an unmaterialized register location");
                const auto scalar = value.value().value;
                if (code == 0x19 && signed_value(scalar) < 0) push(std::uint64_t{0} - scalar);
                else if (code == 0x1f) push(std::uint64_t{0} - scalar);
                else if (code == 0x20) push(~scalar);
                else push(scalar);
            } else {
                auto rhs = pop(); if (!rhs) return rhs.error();
                auto lhs = pop(); if (!lhs) return lhs.error();
                if (lhs.value().register_location || rhs.value().register_location)
                    return malformed_eval("DWARF arithmetic uses an unmaterialized register location");
                const auto a = lhs.value().value & mask;
                const auto b = rhs.value().value & mask;
                std::uint64_t value = 0;
                switch (code) {
                case 0x1a: value = a & b; break; // and
                case 0x1b: { // signed div
                    const auto divisor = signed_value(b);
                    if (divisor == 0) return malformed_eval("DW_OP_div divides by zero");
                    const auto dividend = signed_value(a);
                    value = (dividend == INT64_MIN && divisor == -1) ? a : static_cast<std::uint64_t>(dividend / divisor);
                    break;
                }
                case 0x1c: value = a - b; break; // minus
                case 0x1d: { // signed mod
                    const auto divisor = signed_value(b);
                    if (divisor == 0) return malformed_eval("DW_OP_mod divides by zero");
                    const auto dividend = signed_value(a);
                    value = (dividend == INT64_MIN && divisor == -1) ? 0 : static_cast<std::uint64_t>(dividend % divisor);
                    break;
                }
                case 0x1e: value = a * b; break; // mul
                case 0x21: value = a | b; break; // or
                case 0x24: case 0x25: case 0x26: { // shl, logical shr, arithmetic shr
                    if (b >= address_width_bits) return malformed_eval("DWARF shift count is outside the address width");
                    const auto shift = static_cast<unsigned>(b);
                    if (code == 0x24) value = a << shift;
                    else if (code == 0x25) value = a >> shift;
                    else {
                        value = a >> shift;
                        if (shift && (a & sign_bit)) value |= mask ^ (mask >> shift);
                    }
                    break;
                }
                case 0x27: value = a ^ b; break; // xor
                case 0x29: value = a == b; break; // eq
                case 0x2a: value = signed_value(a) >= signed_value(b); break; // ge
                case 0x2b: value = signed_value(a) > signed_value(b); break; // gt
                case 0x2c: value = signed_value(a) <= signed_value(b); break; // le
                case 0x2d: value = signed_value(a) < signed_value(b); break; // lt
                case 0x2e: value = a != b; break; // ne
                default: return unsupported_eval("unknown DWARF stack operation");
                }
                push(value);
            }
            break;
        }
        case LocationOperationKind::stack_value:
            if (stack.empty()) return malformed_eval("DW_OP_stack_value requires a stack item");
            if (stack.back().register_location) {
                if (!context.read_register) return unsupported_eval("DW_OP_stack_value on a register requires a register reader");
                auto value = context.read_register(stack.back().value);
                if (!value) return unsupported_eval("DW_OP_stack_value references an unavailable register");
                stack.back() = {*value & mask, false};
            }
            stack_value = true; break;
        case LocationOperationKind::branch:
            if (!branch_to(op.second_unsigned_operand)) return malformed_eval("DWARF branch target is not an operation boundary");
            break;
        case LocationOperationKind::branch_if_nonzero: {
            auto condition = pop(); if (!condition) return condition.error();
            if (condition.value().register_location) return malformed_eval("DWARF branch uses an unmaterialized register location");
            if (condition.value().value && !branch_to(op.second_unsigned_operand)) return malformed_eval("DWARF branch target is not an operation boundary");
            break;
        }
        case LocationOperationKind::entry_value: {
            if(op.nested_operations.empty())return malformed_eval("DW_OP_entry_value block is empty");
            auto entry_context=context;
            entry_context.read_register=context.read_entry_register;
            entry_context.frame_base.reset();
            entry_context.call_frame_cfa.reset();
            entry_context.read_memory=context.read_entry_memory;
            auto entry=evaluate_location_expression_impl(op.nested_operations,entry_context,depth+1,remaining_operations,remaining_memory_reads);
            if(!entry)return entry.error();
            if(entry.value().kind==EvaluatedLocationKind::register_location){
                if(!context.read_entry_register)return unsupported_eval("DW_OP_entry_value register requires an entry-register reader");
                auto value=context.read_entry_register(entry.value().value);
                if(!value)return unsupported_eval("DW_OP_entry_value references an unavailable entry register");
                push(*value);
            }else if(entry.value().kind==EvaluatedLocationKind::value){
                push(entry.value().value);
            }else{
                if(!context.read_entry_memory)return unsupported_eval("DW_OP_entry_value memory locations require an entry-memory reader");
                if(!remaining_memory_reads)return hexlab::Error{hexlab::ErrorCode::resource_limit,"DWARF expression exceeds 4096 memory reads"};
                --remaining_memory_reads;
                auto value=context.read_entry_memory(entry.value().value,context.address_size);
                if(!value)return value.error();
                push(value.value());
            }
            stack_value=true;
            break;
        }
        case LocationOperationKind::piece: case LocationOperationKind::bit_piece:
            return unsupported_eval("DWARF composite pieces are not supported by the scalar evaluator");
        default:
            return unsupported_eval("unknown DWARF location operation kind");
        }
        if (stack_limit) return hexlab::Error{hexlab::ErrorCode::resource_limit, "DWARF location stack exceeds 64 entries"};
    }
    if (stack.size() != 1) return malformed_eval("DWARF location expression must leave exactly one stack item");
    if (stack.back().register_location) return EvaluatedLocation{EvaluatedLocationKind::register_location, stack.back().value};
    return EvaluatedLocation{stack_value ? EvaluatedLocationKind::value : EvaluatedLocationKind::memory, stack.back().value};
}
}

hexlab::Result<EvaluatedLocation> evaluate_imported_variable_location(
    const ImportedVariable &variable, std::uint64_t pc, const LocationEvaluationContext &context) {
    if (!variable.location_ranges.empty()) {
        const auto is_default = [](const LocationRange &range) {
            return range.begin == UINT64_MAX && range.end == UINT64_MAX;
        };
        auto selected = std::find_if(variable.location_ranges.begin(), variable.location_ranges.end(),
            [pc, &is_default](const auto &range) { return !is_default(range) && range.begin <= pc && pc < range.end; });
        if (selected == variable.location_ranges.end())
            selected = std::find_if(variable.location_ranges.begin(), variable.location_ranges.end(), is_default);
        if (selected == variable.location_ranges.end()) return unsupported_eval("DWARF variable has no location covering this PC");
        if (selected->operations.empty()) return unsupported_eval("DWARF variable has no usable location expression at this PC");
        return evaluate_location_expression(selected->operations, context);
    }
    if (!variable.location_operations.empty())
        return evaluate_location_expression(variable.location_operations, context);
    if (variable.address)
        return EvaluatedLocation{EvaluatedLocationKind::memory, *variable.address};
    if (variable.cfa_offset && context.call_frame_cfa) {
        if (context.address_size != 1 && context.address_size != 2 &&
            context.address_size != 4 && context.address_size != 8)
            return hexlab::Error{hexlab::ErrorCode::invalid_argument, "DWARF location address size must be 1, 2, 4, or 8"};
        const auto mask = context.address_size == 8 ? UINT64_MAX
            : (std::uint64_t{1} << (context.address_size * 8)) - 1;
        return EvaluatedLocation{EvaluatedLocationKind::memory,
            (*context.call_frame_cfa + static_cast<std::uint64_t>(*variable.cfa_offset)) & mask};
    }
    return unsupported_eval("DWARF variable has no available location");
}

hexlab::Result<EvaluatedLocationSequence> evaluate_location_expression_sequence(
    std::span<const LocationOperation> operations, const LocationEvaluationContext &context) {
    if (operations.size() > 4096)
        return hexlab::Error{hexlab::ErrorCode::resource_limit, "DWARF location expression exceeds 4096 operations"};
    // A composite expression consists of multiple scalar subexpressions. Keep
    // one budget across all pieces so an expression with many individually
    // small pieces cannot multiply the scalar evaluator's work and read caps.
    std::size_t remaining_operations = 65536;
    std::size_t remaining_memory_reads = 4096;
    const auto is_piece = [](LocationOperationKind kind) {
        return kind == LocationOperationKind::piece || kind == LocationOperationKind::bit_piece;
    };
    const auto first = std::find_if(operations.begin(), operations.end(), [&](const auto &op) { return is_piece(op.kind); });
    EvaluatedLocationSequence result;
    if (first == operations.end()) {
        auto location = evaluate_location_expression_impl(
            operations, context, 0, remaining_operations, remaining_memory_reads);
        if (!location) return location.error();
        result.location = std::move(location.value());
        return result;
    }

    result.composite = true;
    std::size_t expression_begin = 0;
    std::uint64_t destination_bit = 0;
    for (std::size_t index = 0; index < operations.size(); ++index) {
        const auto &boundary = operations[index];
        if (!is_piece(boundary.kind)) continue;
        if (result.pieces.size() >= 4096)
            return hexlab::Error{hexlab::ErrorCode::resource_limit, "DWARF composite location exceeds 4096 pieces"};
        std::uint64_t bit_size = boundary.unsigned_operand;
        if (boundary.kind == LocationOperationKind::piece) {
            if (bit_size > UINT64_MAX / 8)
                return hexlab::Error{hexlab::ErrorCode::resource_limit, "DW_OP_piece size overflows bits"};
            bit_size *= 8;
        }
        if (bit_size > UINT64_MAX - destination_bit)
            return hexlab::Error{hexlab::ErrorCode::resource_limit, "DWARF composite location bit size overflows"};
        EvaluatedLocationPiece piece;
        piece.bit_size = bit_size;
        piece.source_bit_offset = boundary.kind == LocationOperationKind::bit_piece
            ? boundary.second_unsigned_operand : 0;
        piece.destination_bit_offset = destination_bit;
        if (index > expression_begin) {
            auto location = evaluate_location_expression_impl(
                operations.subspan(expression_begin, index - expression_begin), context,
                0, remaining_operations, remaining_memory_reads);
            if (!location) return location.error();
            piece.available = true;
            piece.kind = location.value().kind;
            piece.value = location.value().value;
        }
        result.pieces.push_back(piece);
        destination_bit += bit_size;
        expression_begin = index + 1;
    }
    if (expression_begin != operations.size())
        return malformed_eval("DWARF composite location has an unbounded trailing piece");
    return result;
}

hexlab::Result<EvaluatedLocationSequence> evaluate_imported_variable_location_sequence(
    const ImportedVariable &variable, std::uint64_t pc, const LocationEvaluationContext &context) {
    if (!variable.location_ranges.empty()) {
        const auto is_default = [](const LocationRange &range) {
            return range.begin == UINT64_MAX && range.end == UINT64_MAX;
        };
        auto selected = std::find_if(variable.location_ranges.begin(), variable.location_ranges.end(),
            [pc, &is_default](const auto &range) { return !is_default(range) && range.begin <= pc && pc < range.end; });
        if (selected == variable.location_ranges.end())
            selected = std::find_if(variable.location_ranges.begin(), variable.location_ranges.end(), is_default);
        if (selected == variable.location_ranges.end()) return unsupported_eval("DWARF variable has no location covering this PC");
        if (selected->operations.empty()) return unsupported_eval("DWARF variable has no usable location expression at this PC");
        return evaluate_location_expression_sequence(selected->operations, context);
    }
    if (!variable.location_operations.empty())
        return evaluate_location_expression_sequence(variable.location_operations, context);
    if (variable.address) {
        EvaluatedLocationSequence result;
        result.location = {EvaluatedLocationKind::memory, *variable.address};
        return result;
    }
    if (variable.cfa_offset && context.call_frame_cfa) {
        if (context.address_size != 1 && context.address_size != 2 &&
            context.address_size != 4 && context.address_size != 8)
            return hexlab::Error{hexlab::ErrorCode::invalid_argument, "DWARF location address size must be 1, 2, 4, or 8"};
        const auto mask = context.address_size == 8 ? UINT64_MAX
            : (std::uint64_t{1} << (context.address_size * 8)) - 1;
        EvaluatedLocationSequence result;
        result.location = {EvaluatedLocationKind::memory,
            (*context.call_frame_cfa + static_cast<std::uint64_t>(*variable.cfa_offset)) & mask};
        return result;
    }
    return unsupported_eval("DWARF variable has no available location");
}
} // namespace hexlab::symbols
