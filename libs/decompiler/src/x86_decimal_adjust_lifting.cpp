#include "x86_decimal_adjust_lifting.hpp"
#include "hexlab/processors/x86_decimal_adjust_semantics.hpp"

namespace hexlab::decompiler {
namespace {
ValueType integer(std::uint16_t width) { return {TypeKind::integer, width, false}; }
ExpressionPtr constant(std::uint64_t value, std::uint16_t width) {
    const auto type = integer(width);
    return std::make_shared<Expression>(Expression{type, ConstantValue{value, type}});
}
ExpressionPtr reg(RegisterOperand value) {
    return std::make_shared<Expression>(Expression{integer(value.width), RegisterValue{value, {}}});
}
ExpressionPtr unary(std::string operation, ExpressionPtr value, std::uint16_t width) {
    return std::make_shared<Expression>(Expression{integer(width), UnaryValue{std::move(operation), std::move(value)}});
}
ExpressionPtr binary(std::string operation, ExpressionPtr left, ExpressionPtr right, std::uint16_t width) {
    return std::make_shared<Expression>(Expression{integer(width),
        BinaryValue{std::move(operation), std::move(left), std::move(right)}});
}
ExpressionPtr predicate(std::string operation, ExpressionPtr left, ExpressionPtr right) {
    return std::make_shared<Expression>(Expression{{TypeKind::boolean, 1, false},
        BinaryValue{std::move(operation), std::move(left), std::move(right)}});
}
ExpressionPtr select(ExpressionPtr condition, ExpressionPtr yes, ExpressionPtr no, std::uint16_t width) {
    return binary("select_if", std::move(condition), binary("pair", std::move(yes), std::move(no), width), width);
}
ExpressionPtr bit(ExpressionPtr flags, std::uint64_t mask, std::uint16_t width) {
    return predicate("ne", binary("and", std::move(flags), constant(mask, width), width), constant(0, width));
}
ExpressionPtr flag_value(ExpressionPtr value, unsigned shift, std::uint16_t width) {
    return binary("shl", unary("zext", std::move(value), width), constant(shift, width), width);
}
} // namespace

std::optional<Statement> lift_x86_decimal_adjust(const Instruction &i) {
    const bool unpacked = i.opcode == Opcode::aaa || i.opcode == Opcode::aas;
    if (!unpacked && i.opcode != Opcode::daa && i.opcode != Opcode::das) return std::nullopt;
    const auto operation = x86_decimal_adjust_operation(i);
    if (!operation) {
        Intrinsic malformed{"x86_decimal_adjust_malformed", {}, IntrinsicMemoryEffect::unknown};
        malformed.register_writes = i.register_writes;
        return malformed;
    }
    const bool subtract = *operation == X86DecimalAdjust::aas || *operation == X86DecimalAdjust::das;
    const char *name = unpacked ? (subtract ? "x86_aas" : "x86_aaa") : (subtract ? "x86_das" : "x86_daa");
    const RegisterOperand al_register{RegisterBank::gpr, 0, 8, false};
    const RegisterOperand ah_register{RegisterBank::gpr, 0, 8, true};
    const RegisterOperand ax_register{RegisterBank::gpr, 0, 16, false};
    const RegisterOperand eax_register{RegisterBank::gpr, 0, 32, false};
    const auto flags_register = i.register_reads.back();
    const auto width = flags_register.width;
    const auto al = reg(al_register), flags = reg(flags_register);
    const auto low = predicate("bool_or",
        predicate("ugt", binary("and", al, constant(15, 8), 8), constant(9, 8)), bit(flags, 0x10, width));
    ExpressionPtr output_al, output_ah, carry;
    if (unpacked) {
        const auto ax = binary("or", unary("zext", al, 16),
            binary("shl", unary("zext", reg(ah_register), 16), constant(8, 16), 16), 16);
        const auto adjusted = select(low, binary(subtract ? "sub" : "add", ax, constant(0x106, 16), 16), ax, 16);
        output_al = binary("and", unary("trunc", adjusted, 8), constant(15, 8), 8);
        output_ah = unary("trunc", binary("shr", adjusted, constant(8, 16), 16), 8);
        carry = low;
    } else {
        const auto high = predicate("bool_or", predicate("ugt", al, constant(0x99, 8)), bit(flags, 1, width));
        const auto adjusted_low = select(low, binary(subtract ? "sub" : "add", al, constant(6, 8), 8), al, 8);
        output_al = select(high, binary(subtract ? "sub" : "add", adjusted_low, constant(0x60, 8), 8), adjusted_low, 8);
        carry = subtract ? predicate("bool_or", high,
            predicate("bool_and", low, predicate("ult", al, constant(6, 8)))) : high;
    }
    // Register SSA keys include width and high-byte identity, so AL/AH writes
    // alone do not invalidate AX/EAX reads. Publish explicit merged aliases:
    // AAA/AAS update both bytes of AX, while DAA/DAS preserve AH; all four
    // preserve EAX[31:16] in legacy modes.
    ExpressionPtr output_ax;
    if (unpacked) {
        const auto ax = binary("or", unary("zext", al, 16),
            binary("shl", unary("zext", reg(ah_register), 16), constant(8, 16), 16), 16);
        output_ax = binary("and",
            select(low, binary(subtract ? "sub" : "add", ax, constant(0x106, 16), 16), ax, 16),
            constant(0xff0f, 16), 16);
    } else {
        output_ax = binary("or", unary("zext", output_al, 16),
            binary("shl", unary("zext", reg(ah_register), 16), constant(8, 16), 16), 16);
    }
    auto defined_flags = binary("or", flag_value(carry, 0, width), flag_value(low, 4, width), width);
    const auto defined_mask = unpacked ? UINT64_C(0x11) : UINT64_C(0xd5);
    if (!unpacked) {
        auto parity = std::make_shared<Expression>(Expression{{TypeKind::boolean, 1, false},
            UnaryValue{"parity8", output_al}});
        defined_flags = binary("or", defined_flags, flag_value(std::move(parity), 2, width), width);
        defined_flags = binary("or", defined_flags,
            flag_value(predicate("eq", output_al, constant(0, 8)), 6, width), width);
        defined_flags = binary("or", defined_flags, flag_value(bit(output_al, 0x80, 8), 7, width), width);
    }
    const auto unknown = std::make_shared<Expression>(Expression{integer(width),
        UnknownValue{std::string(name) + "_undefined_arithmetic_flags"}});
    auto output_flags = binary("or", binary("and", flags, constant(~UINT64_C(0x8d5), width), width),
        binary("or", defined_flags, binary("and", unknown, constant(0x8d5u & ~defined_mask, width), width), width), width);
    Intrinsic effect{name, {al}, IntrinsicMemoryEffect::none};
    if (unpacked) effect.operands.push_back(reg(ah_register));
    effect.operands.push_back(flags);
    effect.register_writes = i.register_writes;
    effect.register_output_values.push_back(std::move(output_al));
    if (unpacked) effect.register_output_values.push_back(std::move(output_ah));
    effect.register_output_values.push_back(std::move(output_flags));
    effect.register_writes.push_back(ax_register);
    effect.register_output_values.push_back(output_ax);
    effect.register_writes.push_back(eax_register);
    effect.register_output_values.push_back(binary("or",
        binary("and", reg(eax_register), constant(UINT64_C(0xffff0000), 32), 32),
        unary("zext", std::move(output_ax), 32), 32));
    return effect;
}
} // namespace hexlab::decompiler
