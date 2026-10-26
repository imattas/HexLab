#include "ppc_lifting.hpp"

#include <algorithm>
#include <type_traits>

namespace hexlab::decompiler {
namespace {
using R = RegisterOperand;
ValueType integer(std::uint16_t bits) { return {TypeKind::integer, bits, false}; }
ValueType floating(std::uint16_t bits) { return {TypeKind::floating, bits, false}; }
ValueType vmx_vector_type(std::uint16_t lane_bits) {
    return {TypeKind::vector, 128, false, lane_bits ? TypeKind::integer : TypeKind::unknown,
            lane_bits, static_cast<std::uint8_t>(lane_bits ? 128 / lane_bits : 0)};
}
ExpressionPtr constant(std::uint64_t value, std::uint16_t bits) {
    const auto type = integer(bits);
    return std::make_shared<Expression>(Expression{type, ConstantValue{value, type}});
}
ExpressionPtr reg(R value) {
    const auto type = value.bank == RegisterBank::ppc_fpr ? floating(value.width) :
                      value.bank == RegisterBank::ppc_vr ? vmx_vector_type(0) : integer(value.width);
    return std::make_shared<Expression>(Expression{type, RegisterValue{value, {}}});
}
ExpressionPtr typed_vmx_reg(R value, ValueType type) {
    return std::make_shared<Expression>(Expression{type, RegisterValue{value, {}}});
}
struct VmxOperation { const char *mnemonic; std::uint16_t lane_bits; };
std::optional<VmxOperation> vmx_operation(Opcode opcode) {
    switch (opcode) {
    case Opcode::ppc_vaddubm: return VmxOperation{"vaddubm", 8};
    case Opcode::ppc_vadduhm: return VmxOperation{"vadduhm", 16};
    case Opcode::ppc_vadduwm: return VmxOperation{"vadduwm", 32};
    case Opcode::ppc_vsububm: return VmxOperation{"vsububm", 8};
    case Opcode::ppc_vsubuhm: return VmxOperation{"vsubuhm", 16};
    case Opcode::ppc_vsubuwm: return VmxOperation{"vsubuwm", 32};
    case Opcode::ppc_vand: return VmxOperation{"vand", 0};
    case Opcode::ppc_vandc: return VmxOperation{"vandc", 0};
    case Opcode::ppc_vor: return VmxOperation{"vor", 0};
    case Opcode::ppc_vxor: return VmxOperation{"vxor", 0};
    case Opcode::ppc_vnor: return VmxOperation{"vnor", 0};
    default: return std::nullopt;
    }
}
ExpressionPtr binary(std::string operation, ExpressionPtr left, ExpressionPtr right, std::uint16_t bits) {
    return std::make_shared<Expression>(Expression{integer(bits), BinaryValue{std::move(operation), std::move(left), std::move(right)}});
}
ExpressionPtr unary(std::string operation, ExpressionPtr value, std::uint16_t bits) {
    return std::make_shared<Expression>(Expression{integer(bits), UnaryValue{std::move(operation), std::move(value)}});
}
ExpressionPtr operand(const Operand &value) {
    return std::visit([](const auto &item) -> ExpressionPtr {
        using T = std::decay_t<decltype(item)>;
        if constexpr (std::is_same_v<T, R>) return reg(item);
        else if constexpr (std::is_same_v<T, ImmediateOperand>) return constant(item.value, item.effective_width);
        else if constexpr (std::is_same_v<T, RelativeOperand>) return constant(item.displacement, item.effective_width);
        else if constexpr (std::is_same_v<T, MemoryOperand>) {
            MemoryValue memory;
            memory.type = integer(item.data_width); memory.base = item.base; memory.index = item.index;
            memory.scale = item.scale; memory.displacement = item.displacement; memory.absolute = item.resolved_address;
            return std::make_shared<Expression>(Expression{memory.type, std::move(memory)});
        } else return std::make_shared<Expression>(Expression{integer(0), UnknownValue{"unsupported-ppc-operand"}});
    }, value);
}
std::optional<Statement> effect(const Instruction &i, const char *name) {
    Intrinsic result{name, {}, i.memory_read && i.memory_write ? IntrinsicMemoryEffect::unknown :
        i.memory_read ? IntrinsicMemoryEffect::read : i.memory_write ? IntrinsicMemoryEffect::write : IntrinsicMemoryEffect::none};
    for (const auto &item : i.operands) result.operands.push_back(operand(item));
    result.register_writes = i.register_writes;
    return Statement{std::move(result)};
}
ExpressionPtr predicate(std::string operation, ExpressionPtr left, ExpressionPtr right) {
    return std::make_shared<Expression>(Expression{{TypeKind::boolean, 1, false},
        BinaryValue{std::move(operation), std::move(left), std::move(right)}});
}
ExpressionPtr ppc_xer_so() {
    return unary("ppc_xer_so", reg({RegisterBank::ppc_xer, 0, 32, false}), 1);
}
ExpressionPtr pack_ppc_cr_field(ExpressionPtr lt, ExpressionPtr gt, ExpressionPtr eq, ExpressionPtr so) {
    auto result = binary("shl", unary("zext", std::move(lt), 4), constant(3, 4), 4);
    result = binary("or", std::move(result),
                    binary("shl", unary("zext", std::move(gt), 4), constant(2, 4), 4), 4);
    result = binary("or", std::move(result),
                    binary("shl", unary("zext", std::move(eq), 4), constant(1, 4), 4), 4);
    return binary("or", std::move(result), unary("zext", std::move(so), 4), 4);
}
ExpressionPtr ppc_compare_cr_field(ExpressionPtr left, ExpressionPtr right, bool is_signed) {
    auto lt = predicate(is_signed ? "slt" : "ult", left, right);
    auto gt = predicate(is_signed ? "sgt" : "ugt", left, right);
    auto eq = predicate("eq", std::move(left), std::move(right));
    return pack_ppc_cr_field(std::move(lt), std::move(gt), std::move(eq), ppc_xer_so());
}
ExpressionPtr ppc_compare_fp_field(ExpressionPtr left, ExpressionPtr right) {
    // PPC floating compares write LT, GT, EQ, and unordered into the selected
    // four-bit CR field. Keep ordered predicates distinct from NaN handling.
    auto lt = predicate("ppc_fcmp_lt", left, right);
    auto gt = predicate("ppc_fcmp_gt", left, right);
    auto eq = predicate("ppc_fcmp_eq", left, right);
    auto un = predicate("ppc_fcmp_unordered", std::move(left), std::move(right));
    return pack_ppc_cr_field(std::move(lt), std::move(gt), std::move(eq), std::move(un));
}
ExpressionPtr ppc_fpscr_record_cr1(ExpressionPtr fpscr) {
    // Rc copies FPSCR's summary nibble into CR1 after the floating operation.
    // Keep the dependency explicit even when the operation's exception state
    // is not statically known.
    return unary("ppc_fpscr_cr1", std::move(fpscr), 4);
}
ExpressionPtr ppc_record_cr0(ExpressionPtr result, std::uint16_t bits) {
    const auto zero = constant(0, bits);
    auto lt = predicate("slt", result, zero);
    auto gt = predicate("sgt", result, zero);
    auto eq = predicate("eq", std::move(result), zero);
    return pack_ppc_cr_field(std::move(lt), std::move(gt), std::move(eq), ppc_xer_so());
}
std::optional<Statement> effect_with_outputs(const Instruction &i, const char *name,
                                             std::vector<ExpressionPtr> outputs) {
    auto statement = effect(i, name);
    auto *intrinsic = statement ? std::get_if<Intrinsic>(&*statement) : nullptr;
    if (intrinsic && outputs.size() == intrinsic->register_writes.size())
        intrinsic->register_output_values = std::move(outputs);
    return statement;
}
ExpressionPtr boolean(bool value) {
    const ValueType type{TypeKind::boolean, 1, false};
    return std::make_shared<Expression>(Expression{type, ConstantValue{value ? 1u : 0u, type}});
}
std::optional<Statement> lift_control(const Instruction &i, std::uint16_t width,
                                     std::vector<Statement> *before) {
    const bool direct = i.opcode == Opcode::ppc_b || i.opcode == Opcode::ppc_bc;
    const bool conditional_form = i.opcode != Opcode::ppc_b;
    const R ctr{RegisterBank::ppc_ctr, 0, width, false};
    const R lr{RegisterBank::ppc_lr, 0, width, false};
    const auto unmodeled = [&](const char *name) {
        auto statement = effect(i, name);
        auto &intrinsic = std::get<Intrinsic>(*statement);
        if (i.flow == FlowKind::call || std::any_of(i.register_writes.begin(), i.register_writes.end(),
            [](R written) { return written.bank == RegisterBank::ppc_lr; }))
            intrinsic.memory_effect = IntrinsicMemoryEffect::unknown;
        for (const auto read : i.register_reads) intrinsic.operands.push_back(reg(read));
        return statement;
    };
    unsigned bo = 20, bi = 0;
    if (i.length != 4 || (i.address.offset & 3) || (width == 32 && i.address.offset > UINT32_MAX) ||
        (direct && i.direct_target && width == 32 && i.direct_target->offset > UINT32_MAX) ||
        (direct && (!i.direct_target || i.direct_target->space != i.address.space)))
        return unmodeled("ppc_unmodeled_branch_shape");
    if (conditional_form) {
        const auto *options = i.operands.size() >= 2 ? std::get_if<ImmediateOperand>(&i.operands[0]) : nullptr;
        const auto *bit = i.operands.size() >= 2 ? std::get_if<ImmediateOperand>(&i.operands[1]) : nullptr;
        if (!options || !bit || options->value > 31 || bit->value > 31 || options->is_signed || bit->is_signed)
            return unmodeled("ppc_unmodeled_bo_bi");
        bo = static_cast<unsigned>(options->value);
        bi = static_cast<unsigned>(bit->value);
    }
    const bool ignore_cr = (bo & 16) != 0, ignore_ctr = (bo & 4) != 0;
    const bool cr_set = (bo & 8) != 0, ctr_zero = (bo & 2) != 0;
    const bool decrements = !ignore_ctr;
    const bool linked = std::find(i.register_writes.begin(), i.register_writes.end(), lr) != i.register_writes.end();
    if (i.opcode == Opcode::ppc_bcctr && decrements)
        return unmodeled("ppc_invalid_bcctr_count_test");
    const bool conditional = !ignore_cr || !ignore_ctr;
    const bool canonical_return = i.opcode == Opcode::ppc_bclr && !linked && !conditional && bi == 0;
    if ((conditional && i.flow != FlowKind::conditional_branch) ||
        (!conditional && linked && i.flow != FlowKind::call) ||
        (!conditional && !linked && i.flow != FlowKind::jump && !(canonical_return && i.flow == FlowKind::ret)))
        return unmodeled("ppc_unmodeled_branch_flow");
    // Register writes must exactly match this architectural transfer. Unknown
    // or extra writes remain attached to the conservative fallback effect.
    if (i.register_writes.size() != static_cast<std::size_t>(decrements) + static_cast<std::size_t>(linked) ||
        (decrements && std::count(i.register_writes.begin(), i.register_writes.end(), ctr) != 1))
        return unmodeled("ppc_unmodeled_branch_effects");
    for (const auto written : i.register_writes)
        if (written != ctr && written != lr) return unmodeled("ppc_unmodeled_branch_effects");

    ExpressionPtr cr_ok = boolean(true);
    if (!ignore_cr) {
        const R field{RegisterBank::ppc_cr, static_cast<std::uint8_t>(bi / 4), 4, false};
        if (std::find(i.register_reads.begin(), i.register_reads.end(), field) == i.register_reads.end())
            return unmodeled("ppc_unmodeled_cr_input");
        auto tested = binary("and", reg(field), constant(1u << (3 - bi % 4), 4), 4);
        cr_ok = predicate(cr_set ? "ne" : "eq", std::move(tested), constant(0, 4));
    }
    auto next_ctr = binary("sub", reg(ctr), constant(1, width), width);
    if (width == 32) next_ctr = binary("and", std::move(next_ctr), constant(UINT32_MAX, width), width);
    const auto link_value = constant((i.address.offset + 4) & (width == 32 ? UINT32_MAX : UINT64_MAX), width);
    const auto count_condition = [&](bool after_update) -> ExpressionPtr {
        return ignore_ctr ? boolean(true) : predicate(ctr_zero ? "eq" : "ne",
            after_update ? reg(ctr) : next_ctr, constant(0, width));
    };
    const auto condition = [&](bool after_update) -> ExpressionPtr {
        if (ignore_ctr) return cr_ok;
        if (ignore_cr) return count_condition(after_update);
        return predicate("bool_and", cr_ok, count_condition(after_update));
    };
    const auto target_register = i.opcode == Opcode::ppc_bclr ? lr : ctr;
    auto target = direct ? constant(i.direct_target->offset, width)
        : binary("and", reg(target_register), constant(width == 32 ? UINT32_C(0xfffffffc) : UINT64_C(0xfffffffffffffffc), width), width);
    // A generic conditional Call has no predicate, and writing LR before an
    // LR-target call would overwrite its target. Keep both in one parallel
    // effect with all target/predicate inputs evaluated before the outputs.
    const bool explicit_effect = (linked && (conditional || i.opcode == Opcode::ppc_bclr)) ||
                                 (!before && (decrements || linked));
    if (explicit_effect) {
        Intrinsic result{linked ? "ppc_linked_branch_effect" : "ppc_counted_branch_effect",
            {constant(bo, 5), constant(bi, 5), boolean(ignore_cr), boolean(cr_set),
             boolean(ignore_ctr), boolean(ctr_zero), boolean((bo & 1) != 0),
             condition(false), std::move(target), constant(i.address.space.value, 32)},
            linked ? IntrinsicMemoryEffect::unknown : IntrinsicMemoryEffect::none};
        result.register_writes = i.register_writes;
        for (const auto written : result.register_writes)
            result.register_output_values.push_back(written == ctr ? next_ctr : link_value);
        return Statement{std::move(result)};
    }
    if (decrements) before->push_back(Assign{ctr, next_ctr});
    if (linked) before->push_back(Assign{lr, link_value});
    if (canonical_return && i.flow == FlowKind::ret) return Statement{Return{}};
    if (linked) return Statement{Call{direct ? i.direct_target : std::optional<Address>{}, direct ? ExpressionPtr{} : std::move(target)}};
    const auto name = conditional ? "ppc-bo" + std::to_string(bo) + "-bi" + std::to_string(bi) +
        (ignore_cr ? "-ignore-cr" : cr_set ? "-cr-set" : "-cr-clear") +
        (ignore_ctr ? "-ignore-ctr" : ctr_zero ? "-ctr-zero" : "-ctr-nonzero") : std::string("true");
    return Statement{Branch{name, direct ? i.direct_target : std::optional<Address>{}, {},
        conditional ? condition(decrements) : ExpressionPtr{}, direct ? ExpressionPtr{} : std::move(target)}};
}
std::uint32_t ppc_word_mask(unsigned mb, unsigned me) {
    std::uint32_t mask = 0;
    for (unsigned bit = mb; ; bit = (bit + 1) & 31) {
        mask |= std::uint32_t{1} << (31 - bit);
        if (bit == me) break;
    }
    return mask;
}
std::uint64_t ppc_doubleword_mask(unsigned mb, unsigned me) {
    std::uint64_t mask = 0;
    for (unsigned bit = mb; ; bit = (bit + 1) & 63) {
        mask |= std::uint64_t{1} << (63 - bit);
        if (bit == me) break;
    }
    return mask;
}
}

std::optional<Statement> lift_ppc_instruction(const Instruction &i, std::vector<Statement> *before) {
    if (i.context.architecture != Architecture::powerpc ||
        (i.context.mode != ExecutionMode::ppc32 && i.context.mode != ExecutionMode::ppc64)) return {};
    const auto width = static_cast<std::uint16_t>(i.context.mode == ExecutionMode::ppc32 ? 32 : 64);
    const auto &ops = i.operands;
    const auto *dst = ops.empty() ? nullptr : std::get_if<R>(&ops[0]);
    const auto assign = [&](ExpressionPtr value) -> Statement {
        return dst && (dst->bank == RegisterBank::ppc_gpr || dst->bank == RegisterBank::ppc_fpr) ? Statement{Assign{*dst, std::move(value)}} :
            Statement{Intrinsic{"ppc_malformed", {}, IntrinsicMemoryEffect::unknown}};
    };

    if (i.opcode == Opcode::ppc_b || i.opcode == Opcode::ppc_bc ||
        i.opcode == Opcode::ppc_bclr || i.opcode == Opcode::ppc_bcctr)
        return lift_control(i, width, before);

    if (const auto vmx = vmx_operation(i.opcode)) {
        const auto *left = ops.size() == 3 ? std::get_if<R>(&ops[1]) : nullptr;
        const auto *right = ops.size() == 3 ? std::get_if<R>(&ops[2]) : nullptr;
        const auto valid_vr = [](const R *value) {
            return value && value->bank == RegisterBank::ppc_vr && value->width == 128 && value->index < 32;
        };
        if (!valid_vr(dst) || !valid_vr(left) || !valid_vr(right) ||
            i.vector_bits != 128 || i.vector_element_bits != vmx->lane_bits ||
            i.access != std::vector<OperandAccess>{OperandAccess::write, OperandAccess::read, OperandAccess::read} ||
            i.register_reads != std::vector<R>{*left, *right} || i.register_writes != std::vector<R>{*dst} ||
            i.memory_read || i.memory_write)
            return effect(i, "ppc_malformed_vmx");
        const auto type = vmx_vector_type(vmx->lane_bits);
        const auto suffix = vmx->lane_bits ? "_i" + std::to_string(vmx->lane_bits) + "x" +
            std::to_string(type.lanes) : std::string{"_bits128"};
        Intrinsic result{"ppc_" + std::string(vmx->mnemonic) + suffix,
                         {typed_vmx_reg(*left, type), typed_vmx_reg(*right, type)},
                         IntrinsicMemoryEffect::none};
        result.register_writes = {*dst};
        result.result_type = type;
        return result;
    }

    if ((i.opcode == Opcode::ppc_lfs || i.opcode == Opcode::ppc_lfd ||
         i.opcode == Opcode::ppc_stfs || i.opcode == Opcode::ppc_stfd) && ops.size() == 2 && dst &&
        dst->bank == RegisterBank::ppc_fpr) {
        const auto bits = dst->width;
        auto address = operand(ops[1]);
        const auto *memory = std::get_if<MemoryValue>(&address->value);
        if (!memory || (bits != 32 && bits != 64) || memory->type.bits != bits)
            return effect(i, "ppc_fp_memory_unmodeled");
        auto typed_memory = *memory;
        typed_memory.type = floating(bits);
        address = std::make_shared<Expression>(Expression{floating(bits), std::move(typed_memory)});
        if (i.opcode == Opcode::ppc_lfs || i.opcode == Opcode::ppc_lfd)
            return Assign{*dst, std::move(address)};
        return Store{std::move(address), reg(*dst)};
    }
    if ((i.opcode == Opcode::ppc_fcmpu || i.opcode == Opcode::ppc_fcmpo) && ops.size() == 3) {
        const auto *field = std::get_if<R>(&ops[0]);
        const auto *left = std::get_if<R>(&ops[1]);
        const auto *right = std::get_if<R>(&ops[2]);
        if (!field || field->bank != RegisterBank::ppc_cr || field->width != 4 || field->index >= 8 ||
            !left || left->bank != RegisterBank::ppc_fpr || left->width != 64 ||
            !right || right->bank != RegisterBank::ppc_fpr || right->width != 64 ||
            i.register_writes != std::vector<R>{*field, {RegisterBank::ppc_fpscr, 0, 32, false}})
            return effect(i, "ppc_malformed_fp_compare");
        auto compare = ppc_compare_fp_field(reg(*left), reg(*right));
        auto fpscr = std::make_shared<Expression>(Expression{integer(32),
            UnknownValue{i.opcode == Opcode::ppc_fcmpo ? "ppc_fpscr_after_fcmpo" : "ppc_fpscr_after_fcmpu"}});
        return effect_with_outputs(i, i.opcode == Opcode::ppc_fcmpo ? "ppc_fcmpo" : "ppc_fcmpu",
                                   {std::move(compare), std::move(fpscr)});
    }
    if ((i.opcode == Opcode::ppc_fmr || i.opcode == Opcode::ppc_fneg ||
         i.opcode == Opcode::ppc_fabs || i.opcode == Opcode::ppc_frsp) && ops.size() == 2 && dst &&
        dst->bank == RegisterBank::ppc_fpr) {
        const auto *source = std::get_if<R>(&ops[1]);
        if (!source || source->bank != RegisterBank::ppc_fpr || source->width != 64 || dst->width != 64)
            return effect(i, "ppc_malformed_fp_unary");
        const R status{RegisterBank::ppc_fpscr, 0, 32, false};
        const R record{RegisterBank::ppc_cr, 1, 4, false};
        const bool single_round = i.opcode == Opcode::ppc_frsp;
        const bool writes_record = std::find(i.register_writes.begin(), i.register_writes.end(), record) !=
                                   i.register_writes.end();
        std::vector<R> expected_reads{*source};
        std::vector<R> expected_writes{*dst};
        if (single_round) {
            expected_reads.push_back(status);
            expected_writes.push_back(status);
        }
        if (writes_record) {
            if (!single_round) expected_reads.push_back(status);
            expected_writes.push_back(record);
        }
        if (i.register_reads != expected_reads || i.register_writes != expected_writes)
            return effect(i, "ppc_malformed_fp_unary_effects");
        auto input = reg(*source);
        ExpressionPtr result;
        if (i.opcode == Opcode::ppc_fmr) result = std::move(input);
        else if (i.opcode == Opcode::ppc_fneg)
            result = std::make_shared<Expression>(Expression{floating(64), UnaryValue{"-", std::move(input)}});
        else if (i.opcode == Opcode::ppc_fabs)
            result = std::make_shared<Expression>(Expression{floating(64), UnaryValue{"fabs", std::move(input)}});
        else
            result = std::make_shared<Expression>(Expression{floating(64), UnaryValue{"ppc_frsp_to_f64", std::move(input)}});
        if (!single_round && !writes_record) return Assign{*dst, std::move(result)};
        ExpressionPtr next_status = single_round
            ? std::make_shared<Expression>(Expression{integer(32), UnknownValue{"ppc_fpscr_after_frsp"}})
            : reg(status);
        std::vector<ExpressionPtr> outputs{std::move(result)};
        if (single_round) outputs.push_back(next_status);
        if (writes_record) outputs.push_back(ppc_fpscr_record_cr1(next_status));
        auto statement = effect_with_outputs(i, single_round ? "ppc_frsp" : "ppc_fp_record_move",
                                             std::move(outputs));
        auto *intrinsic = statement ? std::get_if<Intrinsic>(&*statement) : nullptr;
        if (intrinsic && (single_round || writes_record)) intrinsic->operands.push_back(reg(status));
        return statement;
    }
    if (ops.size() == 3 && dst && dst->bank == RegisterBank::ppc_fpr &&
        (i.opcode == Opcode::ppc_fadds || i.opcode == Opcode::ppc_fsubs ||
         i.opcode == Opcode::ppc_fmuls || i.opcode == Opcode::ppc_fdivs ||
         i.opcode == Opcode::ppc_fadd || i.opcode == Opcode::ppc_fsub ||
         i.opcode == Opcode::ppc_fmul || i.opcode == Opcode::ppc_fdiv)) {
        const char *operation = i.opcode == Opcode::ppc_fadds || i.opcode == Opcode::ppc_fadd ? "fadd" :
            i.opcode == Opcode::ppc_fsubs || i.opcode == Opcode::ppc_fsub ? "fsub" :
            i.opcode == Opcode::ppc_fmuls || i.opcode == Opcode::ppc_fmul ? "fmul" : "fdiv";
        const R status{RegisterBank::ppc_fpscr, 0, 32, false};
        const R record{RegisterBank::ppc_cr, 1, 4, false};
        const auto *left = ops.size() > 1 ? std::get_if<R>(&ops[1]) : nullptr;
        const auto *right = ops.size() > 2 ? std::get_if<R>(&ops[2]) : nullptr;
        if (!left || !right || left->bank != RegisterBank::ppc_fpr || right->bank != RegisterBank::ppc_fpr ||
            left->width != dst->width || right->width != dst->width ||
            (dst->width != 32 && dst->width != 64))
            return effect(i, "ppc_malformed_fp_arithmetic_operands");
        const bool writes_record = std::find(i.register_writes.begin(), i.register_writes.end(), record) !=
                                   i.register_writes.end();
        std::vector<R> expected_reads{*left, *right, status};
        std::vector<R> expected_writes{*dst, status};
        if (writes_record) expected_writes.push_back(record);
        if (i.register_reads != expected_reads || i.register_writes != expected_writes)
            return effect(i, "ppc_malformed_fp_arithmetic_effects");
        const auto type = floating(dst->width);
        auto value = std::make_shared<Expression>(Expression{type,
            BinaryValue{operation, operand(ops[1]), operand(ops[2])}});
        auto next_status = std::make_shared<Expression>(Expression{integer(32),
            UnknownValue{std::string("ppc_fpscr_after_") + operation}});
        std::vector<ExpressionPtr> outputs{std::move(value), next_status};
        if (writes_record) outputs.push_back(ppc_fpscr_record_cr1(next_status));
        auto statement = effect_with_outputs(i, "ppc_fp_arithmetic", std::move(outputs));
        auto *intrinsic = statement ? std::get_if<Intrinsic>(&*statement) : nullptr;
        if (intrinsic) intrinsic->operands.push_back(reg(status));
        return statement;
    }
    if (i.opcode == Opcode::ppc_nop) return Intrinsic{"nop", {}, IntrinsicMemoryEffect::none};
    if ((i.opcode == Opcode::ppc_addi || i.opcode == Opcode::ppc_addis) && ops.size() == 3) {
        auto value = operand(ops[2]);
        if (const auto *base = std::get_if<R>(&ops[1]); base && base->index != 0)
            value = binary("add", reg(*base), std::move(value), width);
        return assign(std::move(value));
    }
    if ((i.opcode == Opcode::ppc_ori || i.opcode == Opcode::ppc_oris || i.opcode == Opcode::ppc_xori ||
         i.opcode == Opcode::ppc_xoris || i.opcode == Opcode::ppc_andi_dot || i.opcode == Opcode::ppc_andis_dot) && ops.size() == 3) {
        if (i.opcode == Opcode::ppc_andi_dot || i.opcode == Opcode::ppc_andis_dot) {
            auto value = binary("and", operand(ops[1]), operand(ops[2]), width);
            return effect_with_outputs(i, "ppc_record_logical", {value, ppc_record_cr0(value, width)});
        }
        const bool shifted = i.opcode == Opcode::ppc_oris || i.opcode == Opcode::ppc_xoris;
        auto imm = operand(ops[2]);
        if (shifted) imm = binary("shl", std::move(imm), constant(16, width), width);
        return assign(binary((i.opcode == Opcode::ppc_ori || i.opcode == Opcode::ppc_oris) ? "or" : "xor",
                             operand(ops[1]), std::move(imm), width));
    }
    if (i.opcode == Opcode::ppc_add || i.opcode == Opcode::ppc_add_dot ||
        i.opcode == Opcode::ppc_subf || i.opcode == Opcode::ppc_subf_dot || i.opcode == Opcode::ppc_or ||
        i.opcode == Opcode::ppc_or_dot || i.opcode == Opcode::ppc_xor || i.opcode == Opcode::ppc_xor_dot ||
        i.opcode == Opcode::ppc_and || i.opcode == Opcode::ppc_and_dot) {
        if (ops.size() < 3) return effect(i, "ppc_malformed");
        const bool subf = i.opcode == Opcode::ppc_subf || i.opcode == Opcode::ppc_subf_dot;
        const bool record = i.opcode == Opcode::ppc_add_dot || i.opcode == Opcode::ppc_subf_dot ||
                            i.opcode == Opcode::ppc_or_dot || i.opcode == Opcode::ppc_xor_dot || i.opcode == Opcode::ppc_and_dot;
        const char *name = (i.opcode == Opcode::ppc_add || i.opcode == Opcode::ppc_add_dot) ? "add" :
                           subf ? "sub" : (i.opcode == Opcode::ppc_or || i.opcode == Opcode::ppc_or_dot) ? "or" :
                           (i.opcode == Opcode::ppc_xor || i.opcode == Opcode::ppc_xor_dot) ? "xor" : "and";
        auto value = subf ? binary(name, operand(ops[2]), operand(ops[1]), width)
                          : binary(name, operand(ops[1]), operand(ops[2]), width);
        if (record) return effect_with_outputs(i, "ppc_record_integer", {value, ppc_record_cr0(value, width)});
        return assign(std::move(value));
    }
    if (ops.size() >= 3 && dst && dst->bank == RegisterBank::ppc_gpr) {
        const auto op = i.opcode;
        const bool logical = op == Opcode::ppc_andc || op == Opcode::ppc_nand || op == Opcode::ppc_nor ||
            op == Opcode::ppc_orc || op == Opcode::ppc_eqv;
        const bool record = op == Opcode::ppc_andc_dot || op == Opcode::ppc_nand_dot || op == Opcode::ppc_nor_dot ||
            op == Opcode::ppc_orc_dot || op == Opcode::ppc_eqv_dot;
        if (logical || record) {
            auto left = operand(ops[1]), right = operand(ops[2]);
            const bool andc = op == Opcode::ppc_andc || op == Opcode::ppc_andc_dot;
            const bool orc = op == Opcode::ppc_orc || op == Opcode::ppc_orc_dot;
            const bool nand = op == Opcode::ppc_nand || op == Opcode::ppc_nand_dot;
            const bool nor = op == Opcode::ppc_nor || op == Opcode::ppc_nor_dot;
            const bool eqv = op == Opcode::ppc_eqv || op == Opcode::ppc_eqv_dot;
            if (andc || orc) right = unary("bitnot", std::move(right), width);
            const char *name = (andc || nand) ? "and" : (nor || orc) ? "or" : "xor";
            auto value = binary(name, std::move(left), std::move(right), width);
            if (nand || nor || eqv)
                value = unary("bitnot", std::move(value), width);
            if (record) return effect_with_outputs(i, "ppc_record_logical", {value, ppc_record_cr0(value, width)});
            return assign(std::move(value));
        }
    }
    if (ops.size() >= 2 && dst && dst->bank == RegisterBank::ppc_gpr) {
        const auto op = i.opcode;
        const bool record = op == Opcode::ppc_cntlzw_dot || op == Opcode::ppc_cntlzd_dot ||
            op == Opcode::ppc_extsb_dot || op == Opcode::ppc_extsh_dot || op == Opcode::ppc_extsw_dot;
        std::uint16_t source_bits = width;
        const char *operation = nullptr;
        switch (op) {
        case Opcode::ppc_cntlzw: case Opcode::ppc_cntlzw_dot: source_bits = 32; operation = "clz"; break;
        case Opcode::ppc_cntlzd: case Opcode::ppc_cntlzd_dot: source_bits = 64; operation = "clz"; break;
        case Opcode::ppc_extsb: case Opcode::ppc_extsb_dot: source_bits = 8; operation = "sext"; break;
        case Opcode::ppc_extsh: case Opcode::ppc_extsh_dot: source_bits = 16; operation = "sext"; break;
        case Opcode::ppc_extsw: case Opcode::ppc_extsw_dot: source_bits = 32; operation = "sext"; break;
        default: break;
        }
        if (operation) {
            const auto *source = std::get_if<R>(&ops[1]);
            if (!source) return effect(i, "ppc_malformed");
            auto input = reg({source->bank, source->index, source_bits, false});
            auto value = unary(operation, std::move(input), width);
            if (record) return effect_with_outputs(i, "ppc_record_integer", {value, ppc_record_cr0(value, width)});
            return assign(std::move(value));
        }
    }
    if (i.opcode == Opcode::ppc_mulli && ops.size() == 3)
        return assign(binary("mul", operand(ops[1]), operand(ops[2]), width));
    // The word multiply/divide instructions operate on 32-bit operands even
    // in PPC64 mode and sign- or zero-extend their 32-bit result. Keep the
    // architectural divide operations named so their divide-by-zero and
    // signed-overflow behavior is not confused with host-language division.
    if (ops.size() == 3 && dst && dst->bank == RegisterBank::ppc_gpr &&
        (i.opcode == Opcode::ppc_mullw || i.opcode == Opcode::ppc_mulld ||
         i.opcode == Opcode::ppc_divw || i.opcode == Opcode::ppc_divwu ||
         i.opcode == Opcode::ppc_divd || i.opcode == Opcode::ppc_divdu)) {
        const bool word = i.opcode == Opcode::ppc_mullw || i.opcode == Opcode::ppc_divw ||
                          i.opcode == Opcode::ppc_divwu;
        const bool division = i.opcode != Opcode::ppc_mullw && i.opcode != Opcode::ppc_mulld;
        const bool unsigned_operation = i.opcode == Opcode::ppc_divwu || i.opcode == Opcode::ppc_divdu;
        const auto operation_width = static_cast<std::uint16_t>(word ? 32 : 64);
        if ((word && width != 32 && width != 64) || (!word && width != 64) ||
            dst->width != width || i.register_writes.empty() || i.register_writes.front() != *dst)
            return effect(i, "ppc_malformed_mul_div");
        const auto *left = std::get_if<R>(&ops[1]);
        const auto *right = std::get_if<R>(&ops[2]);
        if (!left || !right || left->bank != RegisterBank::ppc_gpr || right->bank != RegisterBank::ppc_gpr ||
            left->width != width || right->width != width)
            return effect(i, "ppc_malformed_mul_div");
        auto lhs = reg({left->bank, left->index, operation_width, false});
        auto rhs = reg({right->bank, right->index, operation_width, false});
        ExpressionPtr value;
        if (!division) {
            value = binary("mul", std::move(lhs), std::move(rhs), operation_width);
        } else {
            const auto name = std::string("ppc_") + (unsigned_operation ? "udiv" : "sdiv") +
                              (word ? "w" : "d");
            value = std::make_shared<Expression>(Expression{integer(operation_width),
                BinaryValue{name, std::move(lhs), std::move(rhs)}});
        }
        if (word && width == 64)
            value = unary(unsigned_operation ? "zext32" : "sext", std::move(value), 64);
        const bool record = i.register_writes.size() == 2 &&
                            i.register_writes[1] == R{RegisterBank::ppc_cr, 0, 4, false};
        if (i.register_writes.size() != (record ? 2u : 1u))
            return effect(i, "ppc_malformed_mul_div");
        if (record)
            return effect_with_outputs(i, "ppc_record_mul_div", {value, ppc_record_cr0(value, width)});
        return assign(std::move(value));
    }
    if (i.opcode == Opcode::ppc_cmpi || i.opcode == Opcode::ppc_cmpli || i.opcode == Opcode::ppc_cmp || i.opcode == Opcode::ppc_cmpl) {
        if (ops.size() < 3 || i.register_writes.size() != 1) return effect(i, "ppc_malformed_compare");
        const auto *field = std::get_if<R>(&ops[0]);
        const auto *left = std::get_if<R>(&ops[1]);
        if (!field || field->bank != RegisterBank::ppc_cr || field->width != 4 || field->index >= 8 || !left ||
            (left->width != 32 && left->width != 64) || i.register_writes.front() != *field)
            return effect(i, "ppc_malformed_compare");
        const bool signed_compare = i.opcode == Opcode::ppc_cmpi || i.opcode == Opcode::ppc_cmp;
        auto value = ppc_compare_cr_field(reg(*left), operand(ops[2]), signed_compare);
        return effect_with_outputs(i, "ppc_compare", {std::move(value)});
    }

    const bool byte_reverse_load = i.opcode == Opcode::ppc_lwbrx || i.opcode == Opcode::ppc_lhbrx ||
                                   i.opcode == Opcode::ppc_ldbrx;
    const bool byte_reverse_store = i.opcode == Opcode::ppc_stwbrx || i.opcode == Opcode::ppc_sthbrx ||
                                    i.opcode == Opcode::ppc_stdbrx;
    if ((byte_reverse_load || byte_reverse_store) && ops.size() >= 2) {
        auto address = operand(ops[1]);
        const auto *memory = std::get_if<MemoryValue>(&address->value);
        if (!memory || (memory->type.bits != 16 && memory->type.bits != 32 && memory->type.bits != 64) ||
            memory->type.bits > width)
            return effect(i, "ppc_malformed");
        const auto bits = memory->type.bits;
        const auto reverse = [&](ExpressionPtr value) {
            return unary("bswap" + std::to_string(bits), std::move(value), bits);
        };
        if (byte_reverse_load && dst && dst->bank == RegisterBank::ppc_gpr) {
            auto value = reverse(std::move(address));
            if (bits < width) value = unary("zext", std::move(value), width);
            return assign(std::move(value));
        }
        if (byte_reverse_store && dst && dst->bank == RegisterBank::ppc_gpr) {
            ExpressionPtr value = reg(*dst);
            if (bits < width) value = unary("trunc" + std::to_string(bits), std::move(value), bits);
            return Store{std::move(address), reverse(std::move(value))};
        }
        return effect(i, "ppc_malformed");
    }

    if (i.opcode == Opcode::ppc_lwzu || i.opcode == Opcode::ppc_lbzu || i.opcode == Opcode::ppc_lhzu ||
        i.opcode == Opcode::ppc_lhau || i.opcode == Opcode::ppc_stwu || i.opcode == Opcode::ppc_stbu ||
        i.opcode == Opcode::ppc_sthu || i.opcode == Opcode::ppc_ldu || i.opcode == Opcode::ppc_stdu)
        return effect(i, "ppc_update_load_store");
    if (dst && ops.size() >= 2 && i.memory_read && dst->bank == RegisterBank::ppc_gpr) {
        auto value = operand(ops[1]);
        const auto *mem = std::get_if<MemoryValue>(&value->value);
        if (mem && mem->type.bits < width) {
            const bool sign = i.opcode == Opcode::ppc_lha;
            value = std::make_shared<Expression>(Expression{integer(width), UnaryValue{sign ? "sext" : "zext", std::move(value)}});
        }
        return assign(std::move(value));
    }
    if (dst && ops.size() >= 2 && i.memory_write && dst->bank == RegisterBank::ppc_gpr)
        return Store{operand(ops[1]), reg(*dst)};

    if (i.opcode == Opcode::ppc_mflr || i.opcode == Opcode::ppc_mfctr)
        return assign(reg({i.opcode == Opcode::ppc_mflr ? RegisterBank::ppc_lr : RegisterBank::ppc_ctr, 0, width, false}));
    if (i.opcode == Opcode::ppc_mtlr || i.opcode == Opcode::ppc_mtctr) return effect(i, "ppc_special_register_write");
    if (i.opcode == Opcode::ppc_rlwimi || i.opcode == Opcode::ppc_rlwimi_dot ||
        i.opcode == Opcode::ppc_rlwinm || i.opcode == Opcode::ppc_rlwinm_dot ||
        i.opcode == Opcode::ppc_rlwnm || i.opcode == Opcode::ppc_rlwnm_dot) {
        if (ops.size() != 5 || !dst || dst->bank != RegisterBank::ppc_gpr)
            return effect(i, "ppc_malformed");
        const bool insert = i.opcode == Opcode::ppc_rlwimi || i.opcode == Opcode::ppc_rlwimi_dot;
        const bool variable = i.opcode == Opcode::ppc_rlwnm || i.opcode == Opcode::ppc_rlwnm_dot;
        const bool record = i.opcode == Opcode::ppc_rlwimi_dot || i.opcode == Opcode::ppc_rlwinm_dot ||
                            i.opcode == Opcode::ppc_rlwnm_dot;
        constexpr std::size_t mask_index = 3;
        const auto *mb = std::get_if<ImmediateOperand>(&ops[mask_index]);
        const auto *me = std::get_if<ImmediateOperand>(&ops[mask_index + 1]);
        if (!mb || !me || mb->value > 31 || me->value > 31)
            return effect(i, "ppc_malformed");
        const auto mask = ppc_word_mask(static_cast<unsigned>(mb->value), static_cast<unsigned>(me->value));
        const auto *source_register = std::get_if<R>(&ops[1]);
        if (!source_register) return effect(i, "ppc_malformed");
        auto source = reg({source_register->bank, source_register->index, 32, false});
        ExpressionPtr amount;
        if (variable) {
            const auto *shift_register = std::get_if<R>(&ops[2]);
            if (!shift_register) return effect(i, "ppc_malformed");
            amount = reg(*shift_register);
        } else {
            const auto *shift_immediate = std::get_if<ImmediateOperand>(&ops[2]);
            if (!shift_immediate || shift_immediate->value > 31) return effect(i, "ppc_malformed");
            amount = constant(shift_immediate->value, 32);
        }
        auto rotated = binary("ppc_rol32", std::move(source), std::move(amount), 32);
        auto value = binary("and", std::move(rotated), constant(mask, 32), 32);
        if (insert) {
            auto preserved = binary("and", reg(*dst), constant(~static_cast<std::uint64_t>(mask), width), width);
            if (width == 64) value = unary("zext", std::move(value), 64);
            value = binary("or", std::move(preserved), std::move(value), width);
        } else if (width == 64) {
            value = unary("zext", std::move(value), 64);
        }
        if (record) return effect_with_outputs(i, "ppc_record_rotate_mask", {value, ppc_record_cr0(value, width)});
        return assign(std::move(value));
    }
    const bool ppc64_rotate = i.opcode == Opcode::ppc_rldicl || i.opcode == Opcode::ppc_rldicl_dot ||
        i.opcode == Opcode::ppc_rldicr || i.opcode == Opcode::ppc_rldicr_dot ||
        i.opcode == Opcode::ppc_rldic || i.opcode == Opcode::ppc_rldic_dot ||
        i.opcode == Opcode::ppc_rldimi || i.opcode == Opcode::ppc_rldimi_dot ||
        i.opcode == Opcode::ppc_rldcl || i.opcode == Opcode::ppc_rldcl_dot ||
        i.opcode == Opcode::ppc_rldcr || i.opcode == Opcode::ppc_rldcr_dot;
    if (ppc64_rotate) {
        if (width != 64 || ops.size() != 5 || !dst || dst->bank != RegisterBank::ppc_gpr)
            return effect(i, "ppc_malformed");
        const bool insert = i.opcode == Opcode::ppc_rldimi || i.opcode == Opcode::ppc_rldimi_dot;
        const bool variable = i.opcode == Opcode::ppc_rldcl || i.opcode == Opcode::ppc_rldcl_dot ||
                              i.opcode == Opcode::ppc_rldcr || i.opcode == Opcode::ppc_rldcr_dot;
        const bool record = i.opcode == Opcode::ppc_rldicl_dot || i.opcode == Opcode::ppc_rldicr_dot ||
                            i.opcode == Opcode::ppc_rldic_dot || i.opcode == Opcode::ppc_rldimi_dot ||
                            i.opcode == Opcode::ppc_rldcl_dot || i.opcode == Opcode::ppc_rldcr_dot;
        const auto *mb = std::get_if<ImmediateOperand>(&ops[3]);
        const auto *me = std::get_if<ImmediateOperand>(&ops[4]);
        const auto *source_register = std::get_if<R>(&ops[1]);
        if (!mb || !me || mb->value > 63 || me->value > 63 || !source_register)
            return effect(i, "ppc_malformed");
        auto source = reg({source_register->bank, source_register->index, 64, false});
        ExpressionPtr amount;
        if (variable) {
            const auto *shift_register = std::get_if<R>(&ops[2]);
            if (!shift_register) return effect(i, "ppc_malformed");
            amount = reg(*shift_register);
        } else {
            const auto *shift_immediate = std::get_if<ImmediateOperand>(&ops[2]);
            if (!shift_immediate || shift_immediate->value > 63) return effect(i, "ppc_malformed");
            amount = constant(shift_immediate->value, 64);
        }
        const auto mask = ppc_doubleword_mask(static_cast<unsigned>(mb->value), static_cast<unsigned>(me->value));
        auto rotated = binary("ppc_rol64", std::move(source), std::move(amount), 64);
        auto value = binary("and", std::move(rotated), constant(mask, 64), 64);
        if (insert) {
            auto preserved = binary("and", reg(*dst), constant(~mask, 64), 64);
            value = binary("or", std::move(preserved), std::move(value), 64);
        }
        if (record) return effect_with_outputs(i, "ppc_record_rotate_mask", {value, ppc_record_cr0(value, 64)});
        return assign(std::move(value));
    }
    return effect(i, "ppc_instruction");
}
}
