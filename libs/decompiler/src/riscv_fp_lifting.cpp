#include "riscv_fp_lifting.hpp"

namespace hexlab::decompiler {
namespace {
ValueType integer(std::uint16_t bits, bool sign = false) { return {TypeKind::integer, bits, sign}; }
ValueType floating(std::uint16_t bits) { return {TypeKind::floating, bits, false}; }
ExpressionPtr constant(std::uint64_t value, std::uint16_t bits) {
    const auto type = integer(bits);
    return std::make_shared<Expression>(Expression{type, ConstantValue{value, type}});
}
ExpressionPtr typed(ExpressionPtr value, ValueType type) {
    auto result = *value;
    result.type = type;
    if (auto *literal = std::get_if<ConstantValue>(&result.value)) literal->type = type;
    return std::make_shared<Expression>(std::move(result));
}
ExpressionPtr unary(std::string name, ExpressionPtr value, ValueType type) {
    return std::make_shared<Expression>(Expression{type, UnaryValue{std::move(name), std::move(value)}});
}
ExpressionPtr binary(std::string name, ExpressionPtr left, ExpressionPtr right, ValueType type) {
    return std::make_shared<Expression>(Expression{type, BinaryValue{std::move(name), std::move(left), std::move(right)}});
}
ExpressionPtr status(unsigned index, std::uint8_t width) {
    return std::make_shared<Expression>(Expression{integer(width),
        RegisterValue{{RegisterBank::riscv_fstatus, static_cast<std::uint8_t>(index), width, false}, {}}});
}
struct Conversion {
    const char *name;
    ValueType source, result;
    bool classify = false;
    // NV=16, OF=4, UF=2, NX=1. No conversion raises DZ.
    std::uint8_t exception_mask = 0;
    bool uses_rounding = true;
};
std::optional<Conversion> conversion(Opcode op) {
    switch (op) {
#define FP_TO_INT(OP, NAME, FP, INT, SIGN) case Opcode::rv_##OP: return Conversion{NAME, floating(FP), integer(INT, SIGN), false, 17}
    FP_TO_INT(fcvt_w_s, "fcvt.w.s", 32, 32, true);
    FP_TO_INT(fcvt_wu_s, "fcvt.wu.s", 32, 32, false);
    FP_TO_INT(fcvt_l_s, "fcvt.l.s", 32, 64, true);
    FP_TO_INT(fcvt_lu_s, "fcvt.lu.s", 32, 64, false);
    FP_TO_INT(fcvt_w_d, "fcvt.w.d", 64, 32, true);
    FP_TO_INT(fcvt_wu_d, "fcvt.wu.d", 64, 32, false);
    FP_TO_INT(fcvt_l_d, "fcvt.l.d", 64, 64, true);
    FP_TO_INT(fcvt_lu_d, "fcvt.lu.d", 64, 64, false);
    case Opcode::rv_fcvtmod_w_d: return Conversion{"fcvtmod.w.d", floating(64), integer(32, true), false, 17, false};
    case Opcode::rv_fround_s: return Conversion{"fround.s", floating(32), floating(32), false, 16};
    case Opcode::rv_froundnx_s: return Conversion{"froundnx.s", floating(32), floating(32), false, 17};
    case Opcode::rv_fround_d: return Conversion{"fround.d", floating(64), floating(64), false, 16};
    case Opcode::rv_froundnx_d: return Conversion{"froundnx.d", floating(64), floating(64), false, 17};
#undef FP_TO_INT
#define INT_TO_FP(OP, NAME, INT, SIGN, FP, MASK) case Opcode::rv_##OP: return Conversion{NAME, integer(INT, SIGN), floating(FP), false, MASK}
    INT_TO_FP(fcvt_s_w, "fcvt.s.w", 32, true, 32, 1);
    INT_TO_FP(fcvt_s_wu, "fcvt.s.wu", 32, false, 32, 1);
    INT_TO_FP(fcvt_s_l, "fcvt.s.l", 64, true, 32, 1);
    INT_TO_FP(fcvt_s_lu, "fcvt.s.lu", 64, false, 32, 1);
    case Opcode::rv_fcvt_d_w: return Conversion{"fcvt.d.w", integer(32, true), floating(64), false, 0, false};
    case Opcode::rv_fcvt_d_wu: return Conversion{"fcvt.d.wu", integer(32, false), floating(64), false, 0, false};
    INT_TO_FP(fcvt_d_l, "fcvt.d.l", 64, true, 64, 1);
    INT_TO_FP(fcvt_d_lu, "fcvt.d.lu", 64, false, 64, 1);
#undef INT_TO_FP
    case Opcode::rv_fcvt_s_d: return Conversion{"fcvt.s.d", floating(64), floating(32), false, 23};
    case Opcode::rv_fcvt_d_s: return Conversion{"fcvt.d.s", floating(32), floating(64), false, 16, false};
    case Opcode::rv_fclass_s: return Conversion{"fclass.s", floating(32), integer(10), true};
    case Opcode::rv_fclass_d: return Conversion{"fclass.d", floating(64), integer(10), true};
    default: return {};
    }
}
} // namespace

std::optional<Statement> lift_riscv_fp_conversion(const Instruction &instruction,
                                                std::span<const ExpressionPtr> operands) {
    const auto shape = conversion(instruction.opcode);
    if (!shape || operands.size() != 2 || instruction.operands.size() != 2) return {};
    const auto *destination = std::get_if<RegisterOperand>(&instruction.operands[0]);
    if (!destination || (!shape->classify && !instruction.rounding_mode)) return {};

    auto source = operands[1];
    if (shape->source.kind == TypeKind::integer && source->type.bits > shape->source.bits)
        source = unary("trunc32", source, shape->source);
    else source = typed(source, shape->source);

    Intrinsic effect{shape->name, {source}, IntrinsicMemoryEffect::none};
    effect.register_writes = instruction.register_writes;
    ExpressionPtr value, mode;
    if (shape->classify) {
        // FCLASS returns exactly one of ten bits, zeroing all higher bits.
        value = unary(shape->name, source, shape->result);
    } else if (shape->uses_rounding) {
        mode = *instruction.rounding_mode == 7 ? status(1, 3) : constant(*instruction.rounding_mode, 3);
        effect.operands.push_back(mode);
        // These named operations retain clipping, NaN and rounding semantics;
        // they are deliberately opaque to ordinary integer constant folding.
        value = binary(shape->name, source, mode, shape->result);
    } else {
        // The rm field remains validated/retained by decode, but exact integer
        // widening and FCVT.D.S do not semantically depend on rounding mode.
        value = unary(shape->name, source, shape->result);
    }
    auto result_type = shape->result;
    if (result_type.kind == TypeKind::integer && result_type.bits < destination->width) {
        result_type.bits = destination->width;
        // WU conversions also sign-extend their 32-bit result on RV64.
        value = unary(shape->classify ? "zext" : "sext", value, result_type);
    }
    if (!(destination->bank == RegisterBank::riscv_gpr && destination->index == 0))
        effect.result_type = result_type;

    ExpressionPtr flags;
    if (instruction.writes_fflags) {
        const auto old_flags = status(0, 5);
        effect.operands.push_back(old_flags);
        auto raised = mode
            ? binary(std::string(shape->name) + ".exceptions", source, mode, integer(5))
            : unary(std::string(shape->name) + ".exceptions", source, integer(5));
        raised = binary("and", raised, constant(shape->exception_mask, 5), integer(5));
        flags = binary("or", old_flags, raised, integer(5));
    }
    for (const auto &output : effect.register_writes) {
        if (output == *destination) effect.register_output_values.push_back(value);
        else if (output.bank == RegisterBank::riscv_fstatus && output.index == 0 && flags)
            effect.register_output_values.push_back(flags);
        else return {}; // Do not manufacture values for an unrecognized output.
    }
    return Statement{std::move(effect)};
}

std::optional<Statement> lift_riscv_fstatus_csr(const Instruction &instruction,
                                               std::span<const ExpressionPtr> operands) {
    const auto op = instruction.opcode;
    if (op < Opcode::rv_csrrw || op > Opcode::rv_csrrci) return {};
    if (instruction.operands.size() != 3 || operands.size() != 3) return {};
    const auto *destination = std::get_if<RegisterOperand>(&instruction.operands[0]);
    const auto *csr = std::get_if<ImmediateOperand>(&instruction.operands[1]);
    if (!destination || destination->bank != RegisterBank::riscv_gpr ||
        (destination->width != 32 && destination->width != 64) || !csr || csr->is_signed ||
        csr->encoded_width != 12 || (csr->value != 0x001 && csr->value != 0x002 && csr->value != 0x003))
        return {};

    const bool immediate_source = op >= Opcode::rv_csrrwi;
    const bool write_only = op == Opcode::rv_csrrw || op == Opcode::rv_csrrwi;
    const bool set_bits = op == Opcode::rv_csrrs || op == Opcode::rv_csrrsi;
    const bool clear_bits = op == Opcode::rv_csrrc || op == Opcode::rv_csrrci;
    if (!write_only && !set_bits && !clear_bits) return {};
    if (!instruction.csr_read && !write_only) return {};
    const auto *source_register = std::get_if<RegisterOperand>(&instruction.operands[2]);
    const auto *source_immediate = std::get_if<ImmediateOperand>(&instruction.operands[2]);
    if (immediate_source) {
        if (!source_immediate || source_immediate->is_signed || source_immediate->encoded_width != 5 ||
            source_immediate->value > 31) return {};
    } else if (!source_register || source_register->bank != RegisterBank::riscv_gpr ||
               source_register->width != destination->width) {
        return {};
    }
    const auto source_index = 2u;
    if (!operands[source_index] || operands[source_index]->type.kind != TypeKind::integer)
        return {};
    auto source = typed(operands[source_index], integer(destination->width));

    const RegisterOperand flags_register{RegisterBank::riscv_fstatus, 0, 5, false};
    const RegisterOperand rounding_register{RegisterBank::riscv_fstatus, 1, 3, false};
    const auto flags = [&] { return status(0, 5); };
    const auto rounding = [&] { return status(1, 3); };
    const auto zero_extend = [&](ExpressionPtr value, std::uint16_t width) {
        return unary("zext", std::move(value), integer(width));
    };
    const auto compose_fcsr = [&] {
        auto high = binary("shl", zero_extend(rounding(), 8), constant(5, 8), integer(8));
        auto low = zero_extend(flags(), 8);
        return binary("or", std::move(high), std::move(low), integer(8));
    };
    ExpressionPtr old_csr;
    if (csr->value == 0x001) old_csr = flags();
    else if (csr->value == 0x002) old_csr = rounding();
    else old_csr = compose_fcsr();

    Intrinsic effect{"riscv.csr.fstatus", {source}, IntrinsicMemoryEffect::none};
    if (instruction.csr_read && destination->index != 0) {
        effect.register_writes.push_back(*destination);
        effect.register_output_values.push_back(zero_extend(old_csr, destination->width));
    }
    if (instruction.csr_write) {
        const std::uint16_t state_width = csr->value == 0x001 ? 5 : csr->value == 0x002 ? 3 : 8;
        const auto mask = (UINT64_C(1) << state_width) - 1;
        const auto masked_source = binary("and", source, constant(mask, destination->width),
                                          integer(destination->width));
        const auto source_bits = typed(std::move(masked_source), integer(state_width));
        const auto update = [&](ExpressionPtr old_value) {
            if (write_only) return source_bits;
            if (set_bits) return binary("or", std::move(old_value), source_bits, integer(state_width));
            auto selected = binary("and", source_bits, constant(mask, state_width), integer(state_width));
            auto inverse = binary("xor", std::move(selected), constant(mask, state_width), integer(state_width));
            return binary("and", std::move(old_value), std::move(inverse), integer(state_width));
        };
        if (csr->value == 0x001) {
            effect.register_writes.push_back(flags_register);
            effect.register_output_values.push_back(update(flags()));
        } else if (csr->value == 0x002) {
            effect.register_writes.push_back(rounding_register);
            effect.register_output_values.push_back(update(rounding()));
        } else {
            auto updated_fcsr = update(compose_fcsr());
            effect.register_writes.push_back(flags_register);
            effect.register_output_values.push_back(typed(
                binary("and", updated_fcsr, constant(0x1f, 8), integer(8)), integer(5)));
            effect.register_writes.push_back(rounding_register);
            auto shifted = binary("shr", std::move(updated_fcsr), constant(5, 8), integer(8));
            effect.register_output_values.push_back(typed(
                binary("and", std::move(shifted), constant(7, 8), integer(8)), integer(3)));
        }
    }
    if (effect.register_writes.size() != effect.register_output_values.size()) return {};
    return Statement{std::move(effect)};
}
} // namespace hexlab::decompiler
