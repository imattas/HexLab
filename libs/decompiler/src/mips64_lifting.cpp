#include "mips64_lifting.hpp"

#include <type_traits>
#include <string>

namespace hexlab::decompiler {
namespace {
ValueType integer(std::uint16_t bits) { return {TypeKind::integer, bits, false}; }
ValueType floating(std::uint16_t bits) { return {TypeKind::floating, bits, false}; }
ExpressionPtr constant(std::uint64_t value, std::uint16_t bits) {
    const auto type = integer(bits);
    return std::make_shared<Expression>(Expression{type, ConstantValue{value, type}});
}
ExpressionPtr reg(RegisterOperand value) {
    if (value.bank == RegisterBank::mips_gpr && value.index == 0) return constant(0, value.width);
    const auto type = value.bank == RegisterBank::mips_fpr ? floating(value.width) : integer(value.width);
    return std::make_shared<Expression>(Expression{type, RegisterValue{value, {}}});
}
ExpressionPtr unary(std::string operation, ExpressionPtr value, std::uint16_t width) {
    return std::make_shared<Expression>(Expression{integer(width), UnaryValue{std::move(operation), std::move(value)}});
}
ExpressionPtr typed_unary(std::string operation, ExpressionPtr value, ValueType type) {
    return std::make_shared<Expression>(Expression{type, UnaryValue{std::move(operation), std::move(value)}});
}
ExpressionPtr binary(std::string operation, ExpressionPtr left, ExpressionPtr right, std::uint16_t width) {
    return std::make_shared<Expression>(Expression{integer(width), BinaryValue{std::move(operation), std::move(left), std::move(right)}});
}
ExpressionPtr operand(const Operand &value) {
    return std::visit([](const auto &item) -> ExpressionPtr {
        using T = std::decay_t<decltype(item)>;
        if constexpr (std::is_same_v<T, RegisterOperand>) return reg(item);
        else if constexpr (std::is_same_v<T, ImmediateOperand>) return constant(item.value, item.effective_width);
        else if constexpr (std::is_same_v<T, RelativeOperand>)
            return constant(static_cast<std::uint64_t>(item.displacement), item.effective_width);
        else if constexpr (std::is_same_v<T, MemoryOperand>) {
            MemoryValue memory;
            memory.type = integer(item.data_width);
            memory.base = item.base; memory.index = item.index;
            memory.scale = item.scale; memory.displacement = item.displacement;
            memory.absolute = item.resolved_address; memory.index_extend = item.index_extend;
            memory.index_shift_amount = item.index_shift_amount;
            if (item.index_shift_amount) memory.index_shift = "lsl";
            return std::make_shared<Expression>(Expression{memory.type, std::move(memory)});
        } else return std::make_shared<Expression>(Expression{integer(0), UnknownValue{"unsupported-mips64-operand"}});
    }, value);
}
std::optional<Statement> intrinsic(const Instruction &instruction, std::string name,
                                   IntrinsicMemoryEffect memory_effect) {
    Intrinsic result{std::move(name), {}, memory_effect};
    for (const auto &item : instruction.operands) result.operands.push_back(operand(item));
    result.register_writes = instruction.register_writes;
    return Statement{std::move(result)};
}
} // namespace

std::optional<Statement> lift_mips64_instruction(const Instruction &instruction) {
    if (instruction.context.architecture != Architecture::mips64 ||
        instruction.context.mode != ExecutionMode::mips64)
        return std::nullopt;
    const auto &items = instruction.operands;
    const auto op = instruction.opcode;
    const auto destination = !items.empty() ? std::get_if<RegisterOperand>(&items[0]) : nullptr;
    const auto assign = [&](ExpressionPtr value) -> Statement {
        if (!destination || destination->bank != RegisterBank::mips_gpr) return Intrinsic{"mips64_malformed", {}, IntrinsicMemoryEffect::unknown};
        if (destination->index == 0) return Intrinsic{"nop", {}, IntrinsicMemoryEffect::none};
        return Assign{*destination, std::move(value)};
    };

    if (op == Opcode::mips_jr && instruction.flow == FlowKind::ret)
        return Return{items.empty() ? ExpressionPtr{} : operand(items.front())};
    if (op == Opcode::mips_jr && instruction.flow == FlowKind::jump) {
        Branch branch{"true", {}, {}};
        if (!items.empty()) branch.indirect_target = operand(items.front());
        return branch;
    }
    if (op == Opcode::mips64_tge || op == Opcode::mips64_tgeu ||
        op == Opcode::mips64_tlt || op == Opcode::mips64_tltu ||
        op == Opcode::mips64_teq || op == Opcode::mips64_tne ||
        op == Opcode::mips64_tgei || op == Opcode::mips64_tgeiu ||
        op == Opcode::mips64_tlti || op == Opcode::mips64_tltiu ||
        op == Opcode::mips64_teqi || op == Opcode::mips64_tnei) {
        const char *name = op == Opcode::mips64_tge ? "mips64_tge_conditional_trap" :
            op == Opcode::mips64_tgeu ? "mips64_tgeu_conditional_trap" :
            op == Opcode::mips64_tlt ? "mips64_tlt_conditional_trap" :
            op == Opcode::mips64_tltu ? "mips64_tltu_conditional_trap" :
            op == Opcode::mips64_teq ? "mips64_teq_conditional_trap" :
            op == Opcode::mips64_tne ? "mips64_tne_conditional_trap" :
            op == Opcode::mips64_tgei ? "mips64_tgei_conditional_trap" :
            op == Opcode::mips64_tgeiu ? "mips64_tgeiu_conditional_trap" :
            op == Opcode::mips64_tlti ? "mips64_tlti_conditional_trap" :
            op == Opcode::mips64_tltiu ? "mips64_tltiu_conditional_trap" :
            op == Opcode::mips64_teqi ? "mips64_teqi_conditional_trap" : "mips64_tnei_conditional_trap";
        return intrinsic(instruction, name, IntrinsicMemoryEffect::none);
    }

    const auto fp_memory = [](ExpressionPtr address, std::uint16_t bits) -> ExpressionPtr {
        if (!address || !std::holds_alternative<MemoryValue>(address->value)) return address;
        auto memory = std::get<MemoryValue>(address->value);
        memory.type = floating(bits);
        return std::make_shared<Expression>(Expression{floating(bits), std::move(memory)});
    };
    if ((op == Opcode::mips_lwc1 || op == Opcode::mips_ldc1) && items.size() >= 2 && destination &&
        destination->bank == RegisterBank::mips_fpr)
        return Assign{*destination, fp_memory(operand(items[1]), destination->width)};
    if ((op == Opcode::mips_swc1 || op == Opcode::mips_sdc1) && items.size() >= 2 && destination &&
        destination->bank == RegisterBank::mips_fpr)
        return Store{fp_memory(operand(items[1]), destination->width), operand(items[0])};

    const bool unaligned_load = op == Opcode::mips64_lwl || op == Opcode::mips64_lwr ||
        op == Opcode::mips64_ldl || op == Opcode::mips64_ldr;
    const bool unaligned_store = op == Opcode::mips64_swl || op == Opcode::mips64_swr ||
        op == Opcode::mips64_sdl || op == Opcode::mips64_sdr;
    if ((unaligned_load || unaligned_store) && items.size() == 2) {
        const bool word = op == Opcode::mips64_lwl || op == Opcode::mips64_lwr ||
                          op == Opcode::mips64_swl || op == Opcode::mips64_swr;
        const bool left = op == Opcode::mips64_lwl || op == Opcode::mips64_ldl ||
                          op == Opcode::mips64_swl || op == Opcode::mips64_sdl;
        const char *mnemonic = word ? (left ? "lwl" : "lwr") : (left ? "ldl" : "ldr");
        if (unaligned_store) mnemonic = word ? (left ? "swl" : "swr") : (left ? "sdl" : "sdr");
        std::string name = "mips64." + std::string(mnemonic);
        name += instruction.context.order == ByteOrder::big ? ".be" : ".le";
        name += unaligned_load ? (word ? ".merge-sext32" : ".merge64") : ".partial-store";
        auto source = operand(items[0]);
        if (unaligned_store) {
            auto typed = std::make_shared<Expression>(*source);
            typed->type = integer(word ? 32 : 64);
            source = std::move(typed);
        }
        Intrinsic effect{std::move(name), {std::move(source), operand(items[1])},
            unaligned_load ? IntrinsicMemoryEffect::read : IntrinsicMemoryEffect::unknown};
        effect.register_writes = instruction.register_writes;
        if (unaligned_load) effect.result_type = integer(64);
        return effect;
    }

    if (op >= Opcode::mips64_dextm && op <= Opcode::mips64_dins) {
        if (items.size() != 4 || !destination || destination->bank != RegisterBank::mips_gpr)
            return std::nullopt;
        const auto *source_register = std::get_if<RegisterOperand>(&items[1]);
        const auto *position_operand = std::get_if<ImmediateOperand>(&items[2]);
        const auto *size_operand = std::get_if<ImmediateOperand>(&items[3]);
        if (!source_register || source_register->bank != RegisterBank::mips_gpr ||
            !position_operand || !size_operand || position_operand->value >= 64 ||
            size_operand->value == 0 || size_operand->value > 64 ||
            position_operand->value + size_operand->value > 64)
            return std::nullopt;
        const auto position = static_cast<unsigned>(position_operand->value);
        const auto size = static_cast<unsigned>(size_operand->value);
        const std::uint64_t low_mask = size == 64 ? UINT64_MAX : ((std::uint64_t{1} << size) - 1);
        if (op == Opcode::mips64_dext || op == Opcode::mips64_dextm || op == Opcode::mips64_dextu) {
            auto shifted = binary("shr", operand(items[1]), constant(position, 64), 64);
            return assign(binary("and", std::move(shifted), constant(low_mask, 64), 64));
        }
        const std::uint64_t field_mask = size == 64 ? UINT64_MAX : (low_mask << position);
        const auto preserved = binary("and", operand(items[0]), constant(~field_mask, 64), 64);
        auto inserted = binary("shl", operand(items[1]), constant(position, 64), 64);
        inserted = binary("and", std::move(inserted), constant(field_mask, 64), 64);
        return assign(binary("or", preserved, std::move(inserted), 64));
    }

    // Bit-preserving GPR/FPR transfers are ordinary SSA values. FCSR control
    // views map to fields in the aggregate FCSR word below.
    if (op >= Opcode::mips64_mfc1 && op <= Opcode::mips64_ctc1) {
        if (items.size() == 2) {
            const auto *general = std::get_if<RegisterOperand>(&items[0]);
            const auto *cop = std::get_if<RegisterOperand>(&items[1]);
            const RegisterOperand fcsr_register{RegisterBank::mips_fcsr, 0, 32, false};
            const auto fcsr_value = [&] { return reg(fcsr_register); };
            const auto sign_extend_control = [&](ExpressionPtr value) {
                return unary("sext", std::move(value), 64);
            };
            const auto extract_control_view = [&](std::uint8_t index) -> ExpressionPtr {
                auto value = fcsr_value();
                if (index == 25) {
                    // FCCR[7:1] aliases FCSR[31:25], and FCCR[0]
                    // aliases FCSR[23].
                    auto upper = binary("and", binary("shr", value, constant(24, 32), 32), constant(0xfe, 32), 32);
                    auto zero = binary("and", binary("shr", fcsr_value(), constant(23, 32), 32), constant(1, 32), 32);
                    return binary("or", std::move(upper), std::move(zero), 32);
                }
                if (index == 26) {
                    // FEXR exposes Cause[17:12] and Flags[6:2].
                    return binary("and", std::move(value), constant(0x0003f07c, 32), 32);
                }
                if (index == 28) {
                    // FENR exposes Enables[11:7], FS at bit 2, and RM[1:0].
                    auto enabled = binary("and", value, constant(0x00000f80, 32), 32);
                    auto flush = binary("and", binary("shr", fcsr_value(), constant(22, 32), 32), constant(4, 32), 32);
                    auto rounding = binary("and", fcsr_value(), constant(3, 32), 32);
                    return binary("or", binary("or", std::move(enabled), std::move(flush), 32),
                                  std::move(rounding), 32);
                }
                return {};
            };
            const auto update_control_view = [&](std::uint8_t index, ExpressionPtr source) -> ExpressionPtr {
                source = unary("trunc32", std::move(source), 32);
                auto old = fcsr_value();
                if (index == 25) {
                    constexpr std::uint64_t mask = UINT64_C(0xfe800000);
                    auto preserved = binary("and", old, constant(static_cast<std::uint32_t>(~mask), 32), 32);
                    auto upper = binary("and", source, constant(0xfe, 32), 32);
                    upper = binary("shl", std::move(upper), constant(24, 32), 32);
                    auto zero = binary("and", source, constant(1, 32), 32);
                    zero = binary("shl", std::move(zero), constant(23, 32), 32);
                    return binary("or", std::move(preserved),
                                  binary("or", std::move(upper), std::move(zero), 32), 32);
                }
                if (index == 26) {
                    constexpr std::uint32_t mask = 0x0003f07c;
                    return binary("or", binary("and", old, constant(static_cast<std::uint32_t>(~mask), 32), 32),
                                  binary("and", source, constant(mask, 32), 32), 32);
                }
                if (index == 28) {
                    constexpr std::uint32_t mask = 0x01000f83;
                    auto preserved = binary("and", old, constant(static_cast<std::uint32_t>(~mask), 32), 32);
                    auto enabled = binary("and", source, constant(0x00000f80, 32), 32);
                    auto flush = binary("and", source, constant(4, 32), 32);
                    flush = binary("shl", std::move(flush), constant(22, 32), 32);
                    auto rounding = binary("and", source, constant(3, 32), 32);
                    return binary("or", std::move(preserved),
                                  binary("or", binary("or", std::move(enabled), std::move(flush), 32),
                                         std::move(rounding), 32), 32);
                }
                return {};
            };
            if (general && cop && general->bank == RegisterBank::mips_gpr && general->width == 64) {
                if (op == Opcode::mips64_mfc1 && cop->bank == RegisterBank::mips_fpr && cop->width == 32)
                    return assign(unary("sext", unary("bitcast_f32", operand(items[1]), 32), 64));
                if (op == Opcode::mips64_dmfc1 && cop->bank == RegisterBank::mips_fpr && cop->width == 64)
                    return assign(unary("bitcast_f64", operand(items[1]), 64));
                if (op == Opcode::mips64_cfc1 && cop->bank == RegisterBank::mips_fcsr && cop->index == 0 &&
                    cop->width == 32)
                    return assign(unary("sext", operand(items[1]), 64));
                if (op == Opcode::mips64_cfc1 && cop->bank == RegisterBank::mips_fcsr &&
                    (cop->index == 25 || cop->index == 26 || cop->index == 28) && cop->width == 32) {
                    auto view = extract_control_view(cop->index);
                    if (!view) return std::nullopt;
                    return assign(sign_extend_control(std::move(view)));
                }
            }
            if (general && cop && general->bank == RegisterBank::mips_gpr && general->width == 64) {
                if (op == Opcode::mips64_mtc1 && cop->bank == RegisterBank::mips_fpr && cop->width == 32) {
                    auto raw = unary("trunc32", operand(items[0]), 32);
                    return Assign{*cop, typed_unary("bitcast_f32", std::move(raw), floating(32))};
                }
                if (op == Opcode::mips64_dmtc1 && cop->bank == RegisterBank::mips_fpr && cop->width == 64)
                    return Assign{*cop, typed_unary("bitcast_f64", operand(items[0]), floating(64))};
                if (op == Opcode::mips64_ctc1 && cop->bank == RegisterBank::mips_fcsr && cop->index == 0 &&
                    cop->width == 32)
                    return Assign{*cop, unary("trunc32", operand(items[0]), 32)};
                if (op == Opcode::mips64_ctc1 && cop->bank == RegisterBank::mips_fcsr &&
                    (cop->index == 25 || cop->index == 26 || cop->index == 28) && cop->width == 32) {
                    auto updated = update_control_view(cop->index, operand(items[0]));
                    if (!updated) return std::nullopt;
                    return Assign{fcsr_register, std::move(updated)};
                }
            }
        }
        static constexpr const char *names[]{"mips64.mfc1.sext32", "mips64.dmfc1", "mips64.cfc1.sext32",
            "mips64.mtc1", "mips64.dmtc1", "mips64.ctc1"};
        std::string name = names[static_cast<std::size_t>(op) - static_cast<std::size_t>(Opcode::mips64_mfc1)];
        if ((op == Opcode::mips64_cfc1 || op == Opcode::mips64_ctc1) && items.size() > 1) {
            if (const auto *control = std::get_if<RegisterOperand>(&items[1]); control && control->bank == RegisterBank::mips_fcsr && control->index != 0)
                name += control->index == 25 ? ".fccr" : control->index == 26 ? ".fexr" : ".fenr";
        }
        Intrinsic effect{std::move(name), {}, IntrinsicMemoryEffect::none};
        for (const auto &item : items) {
            auto value = operand(item);
            if (const auto *reg_operand = std::get_if<RegisterOperand>(&item);
                reg_operand && reg_operand->bank != RegisterBank::mips_gpr) {
                auto typed = std::make_shared<Expression>(*value);
                typed->type = integer(reg_operand->width);
                value = std::move(typed);
            }
            effect.operands.push_back(std::move(value));
        }
        effect.register_writes = instruction.register_writes;
        return effect;
    }
    if (op >= Opcode::mips_cvt_s_d && op <= Opcode::mips_floor_w_d) {
        const char *name = nullptr;
        switch (op) {
        case Opcode::mips_cvt_s_d: name = "mips.cvt.s.d"; break;
        case Opcode::mips_cvt_d_s: name = "mips.cvt.d.s"; break;
        case Opcode::mips_cvt_w_s: name = "mips.cvt.w.s"; break;
        case Opcode::mips_cvt_w_d: name = "mips.cvt.w.d"; break;
        case Opcode::mips_cvt_s_w: name = "mips.cvt.s.w"; break;
        case Opcode::mips_cvt_d_w: name = "mips.cvt.d.w"; break;
        case Opcode::mips_round_w_s: name = "mips.round.w.s"; break;
        case Opcode::mips_trunc_w_s: name = "mips.trunc.w.s"; break;
        case Opcode::mips_ceil_w_s: name = "mips.ceil.w.s"; break;
        case Opcode::mips_floor_w_s: name = "mips.floor.w.s"; break;
        case Opcode::mips_round_w_d: name = "mips.round.w.d"; break;
        case Opcode::mips_trunc_w_d: name = "mips.trunc.w.d"; break;
        case Opcode::mips_ceil_w_d: name = "mips.ceil.w.d"; break;
        case Opcode::mips_floor_w_d: name = "mips.floor.w.d"; break;
        default: break;
        }
        if (!name) return std::nullopt;
        Intrinsic effect{name, {}, IntrinsicMemoryEffect::none};
        for (std::size_t index = 0; index < items.size(); ++index) {
            auto value = operand(items[index]);
            const bool word_source = op == Opcode::mips_cvt_s_w || op == Opcode::mips_cvt_d_w;
            if (index == 1 && word_source) {
                auto typed = std::make_shared<Expression>(*value);
                typed->type = integer(32);
                value = std::move(typed);
            }
            effect.operands.push_back(std::move(value));
        }
        effect.result_type = (op == Opcode::mips_cvt_w_s || op == Opcode::mips_cvt_w_d ||
            (op >= Opcode::mips_round_w_s && op <= Opcode::mips_floor_w_d)) ? integer(32) :
            floating(op == Opcode::mips_cvt_s_d || op == Opcode::mips_cvt_s_w ? 32 : 64);
        effect.register_writes = instruction.register_writes;
        return effect;
    }
    if (op >= Opcode::mips64_cvt_l_s && op <= Opcode::mips64_floor_l_d) {
        static constexpr const char *names[]{"mips64.cvt.l.s", "mips64.cvt.l.d", "mips64.cvt.s.l", "mips64.cvt.d.l",
            "mips64.round.l.s", "mips64.trunc.l.s", "mips64.ceil.l.s", "mips64.floor.l.s",
            "mips64.round.l.d", "mips64.trunc.l.d", "mips64.ceil.l.d", "mips64.floor.l.d"};
        Intrinsic effect{names[static_cast<std::size_t>(op) - static_cast<std::size_t>(Opcode::mips64_cvt_l_s)], {}, IntrinsicMemoryEffect::none};
        for (std::size_t index = 0; index < items.size(); ++index) {
            auto value = operand(items[index]);
            const bool long_source = op == Opcode::mips64_cvt_s_l || op == Opcode::mips64_cvt_d_l;
            if (index == 1 && long_source) {
                auto typed = std::make_shared<Expression>(*value);
                typed->type = integer(64);
                value = std::move(typed);
            }
            effect.operands.push_back(std::move(value));
        }
        effect.result_type = (op == Opcode::mips64_cvt_l_s || op == Opcode::mips64_cvt_l_d ||
            (op >= Opcode::mips64_round_l_s && op <= Opcode::mips64_floor_l_d)) ? integer(64) :
            floating(op == Opcode::mips64_cvt_s_l ? 32 : 64);
        effect.register_writes = instruction.register_writes;
        return effect;
    }

    if (op >= Opcode::mips_add_s && op <= Opcode::mips_c_le_s) {
        static constexpr const char *names[]{"mips.add.s", "mips.sub.s", "mips.mul.s", "mips.div.s",
            "mips.sqrt.s", "mips.abs.s", "mips.mov.s", "mips.neg.s", "mips.c.eq.s", "mips.c.lt.s", "mips.c.le.s"};
        std::string name = names[static_cast<std::size_t>(op) - static_cast<std::size_t>(Opcode::mips_add_s)];
        if (op >= Opcode::mips_c_eq_s && instruction.condition) name += ".fcc" + std::to_string(instruction.condition);
        Intrinsic effect{std::move(name), {}, IntrinsicMemoryEffect::none};
        for (const auto &item : items) effect.operands.push_back(operand(item));
        if (op <= Opcode::mips_neg_s) effect.result_type = floating(32);
        effect.register_writes = instruction.register_writes;
        return effect;
    }
    if (op >= Opcode::mips_add_d && op <= Opcode::mips_c_le_d) {
        static constexpr const char *names[]{"mips.add.d", "mips.sub.d", "mips.mul.d", "mips.div.d",
            "mips.sqrt.d", "mips.abs.d", "mips.mov.d", "mips.neg.d", "mips.c.eq.d", "mips.c.lt.d", "mips.c.le.d"};
        std::string name = names[static_cast<std::size_t>(op) - static_cast<std::size_t>(Opcode::mips_add_d)];
        if (op >= Opcode::mips_c_eq_d && instruction.condition) name += ".fcc" + std::to_string(instruction.condition);
        Intrinsic effect{std::move(name), {}, IntrinsicMemoryEffect::none};
        for (const auto &item : items) effect.operands.push_back(operand(item));
        if (op <= Opcode::mips_neg_d) effect.result_type = floating(64);
        effect.register_writes = instruction.register_writes;
        return effect;
    }
    if (op == Opcode::mips64_c_cond_s || op == Opcode::mips64_c_cond_d) {
        static constexpr const char *conditions[]{"f", "un", "eq", "ueq", "olt", "ult", "ole", "ule",
            "sf", "ngle", "seq", "ngl", "lt", "nge", "le", "ngt"};
        const auto predicate = static_cast<std::size_t>(instruction.condition & 0x0f);
        const auto condition_code = static_cast<std::uint8_t>((instruction.condition >> 4) & 7);
        std::string name = std::string("mips.c.") + conditions[predicate] +
                           (op == Opcode::mips64_c_cond_s ? ".s" : ".d");
        if (condition_code) name += ".fcc" + std::to_string(condition_code);
        Intrinsic effect{std::move(name), {}, IntrinsicMemoryEffect::none};
        for (const auto &item : items) effect.operands.push_back(operand(item));
        effect.register_writes = instruction.register_writes;
        return effect;
    }
    if ((op == Opcode::mips_bc1t || op == Opcode::mips_bc1f ||
         op == Opcode::mips64_bc1tl || op == Opcode::mips64_bc1fl) &&
        instruction.flow == FlowKind::conditional_branch) {
        auto fcc = std::make_shared<Expression>(Expression{integer(32),
            RegisterValue{{RegisterBank::mips_fcsr, 0, 32, false}, {}}});
        auto predicate = std::make_shared<Expression>(Expression{{TypeKind::boolean, 1, false},
            UnaryValue{"mips.fcc" + std::to_string(instruction.condition), std::move(fcc)}});
        if (op == Opcode::mips_bc1f || op == Opcode::mips64_bc1fl)
            predicate = std::make_shared<Expression>(Expression{{TypeKind::boolean, 1, false}, UnaryValue{"not", std::move(predicate)}});
        return Branch{"mips-fcc" + std::to_string(instruction.condition), instruction.direct_target, {}, std::move(predicate)};
    }

    if (op == Opcode::mips64_movz || op == Opcode::mips64_movn) {
        if (items.size() != 3 || !destination || destination->bank != RegisterBank::mips_gpr)
            return std::nullopt;
        Intrinsic effect{op == Opcode::mips64_movz ? "mips64.movz" : "mips64.movn",
                         {operand(items[0]), operand(items[1]), operand(items[2])}, IntrinsicMemoryEffect::none};
        effect.register_writes = instruction.register_writes;
        effect.result_type = integer(64);
        return effect;
    }
    if (op == Opcode::mips64_sc && items.size() == 2) {
        Intrinsic effect{"mips64.sc_reservation_conditional_store", {operand(items[0]), operand(items[1])},
                         IntrinsicMemoryEffect::write};
        effect.register_writes = instruction.register_writes;
        effect.result_type = integer(64);
        return effect;
    }

    if (op == Opcode::mips64_dmult || op == Opcode::mips64_dmultu ||
        op == Opcode::mips64_ddiv || op == Opcode::mips64_ddivu) {
        const char *name = op == Opcode::mips64_dmult ? "mips64.dmult.s64" :
                           op == Opcode::mips64_dmultu ? "mips64.dmult.u64" :
                           op == Opcode::mips64_ddiv ? "mips64.ddiv.s64" : "mips64.ddiv.u64";
        return intrinsic(instruction, name, IntrinsicMemoryEffect::none);
    }
    if (op == Opcode::mips64_mult || op == Opcode::mips64_multu ||
        op == Opcode::mips64_div || op == Opcode::mips64_divu) {
        const char *name = op == Opcode::mips64_mult ? "mips64.mult.w.s32" :
                           op == Opcode::mips64_multu ? "mips64.mult.w.u32" :
                           op == Opcode::mips64_div ? "mips64.div.w.s32" : "mips64.div.w.u32";
        Intrinsic effect{ name, {}, IntrinsicMemoryEffect::none };
        for (const auto &item : items) {
            auto value = operand(item);
            auto typed = std::make_shared<Expression>(*value);
            typed->type = integer(32);
            effect.operands.push_back(std::move(typed));
        }
        effect.register_writes = instruction.register_writes;
        return effect;
    }
    if ((op == Opcode::mips64_mfhi || op == Opcode::mips64_mflo) && destination && items.size() == 1) {
        const RegisterOperand source{RegisterBank::mips_hilo,
            static_cast<std::uint8_t>(op == Opcode::mips64_mfhi ? 0 : 1), 64, false};
        return assign(reg(source));
    }
    if ((op == Opcode::mips64_mthi || op == Opcode::mips64_mtlo) && items.size() == 1) {
        const RegisterOperand target{RegisterBank::mips_hilo,
            static_cast<std::uint8_t>(op == Opcode::mips64_mthi ? 0 : 1), 64, false};
        return Assign{target, operand(items[0])};
    }

    if (instruction.flow == FlowKind::conditional_branch && !items.empty()) {
        ExpressionPtr predicate;
        const auto left = operand(items[0]);
        if ((op == Opcode::mips_beq || op == Opcode::mips_bne || op == Opcode::mips_beql || op == Opcode::mips_bnel) && items.size() >= 2)
            predicate = std::make_shared<Expression>(Expression{{TypeKind::boolean, 1, false},
                BinaryValue{op == Opcode::mips_beq || op == Opcode::mips_beql ? "eq" : "ne", left, operand(items[1])}});
        else {
            std::string relation;
            if (op == Opcode::mips_blez || op == Opcode::mips_blezl) relation = "sle";
            if (op == Opcode::mips_bgtz || op == Opcode::mips_bgtzl) relation = "sgt";
            if (op == Opcode::mips_bltz || op == Opcode::mips_bltzl ||
                op == Opcode::mips64_bltzal || op == Opcode::mips64_bltzall) relation = "slt";
            if (op == Opcode::mips_bgez || op == Opcode::mips_bgezl ||
                op == Opcode::mips64_bgezal || op == Opcode::mips64_bgezall) relation = "sge";
            if (!relation.empty())
                predicate = std::make_shared<Expression>(Expression{{TypeKind::boolean, 1, false},
                    BinaryValue{std::move(relation), left, constant(0, 64)}});
        }
        if (predicate) return Branch{"predicate", instruction.direct_target, {}, std::move(predicate)};
    }

    if (items.size() == 2 && destination && destination->bank == RegisterBank::mips_gpr &&
        (op == Opcode::mips_clz || op == Opcode::mips_clo ||
         op == Opcode::mips64_dclz || op == Opcode::mips64_dclo)) {
        const bool word = op == Opcode::mips_clz || op == Opcode::mips_clo;
        const bool ones = op == Opcode::mips_clo || op == Opcode::mips64_dclo;
        auto source = operand(items[1]);
        if (word) source = unary("trunc32", std::move(source), 32);
        auto count = unary(ones ? "clo" : "clz", std::move(source), word ? 32 : 64);
        // Counts are nonnegative and fit in six bits, so word and doubleword
        // forms have the same positive value in the 64-bit destination GPR.
        return assign(unary("zext", std::move(count), 64));
    }

    if (items.size() >= 2 && destination && destination->bank == RegisterBank::mips_gpr) {
        const auto src1 = operand(items[1]);
        const auto src2 = items.size() >= 3 ? operand(items[2]) : ExpressionPtr{};
        const auto word_result = [&](std::string operation, ExpressionPtr left, ExpressionPtr right) {
            auto narrow = binary(std::move(operation), unary("trunc32", std::move(left), 32),
                                 unary("trunc32", std::move(right), 32), 32);
            return unary("sext", std::move(narrow), 64);
        };
        switch (op) {
        case Opcode::mips64_add:
            return intrinsic(instruction, "mips64.add_word_overflow", IntrinsicMemoryEffect::none);
        case Opcode::mips64_sub:
            return intrinsic(instruction, "mips64.sub_word_overflow", IntrinsicMemoryEffect::none);
        case Opcode::mips64_addi:
            return intrinsic(instruction, "mips64.addi_word_overflow", IntrinsicMemoryEffect::none);
        case Opcode::mips64_addu: case Opcode::mips64_addiu:
            if (src2) return assign(word_result("add", src1, src2));
            break;
        case Opcode::mips64_subu:
            if (src2) return assign(word_result("sub", src1, src2));
            break;
        case Opcode::mips64_slt: case Opcode::mips64_sltu:
        case Opcode::mips64_slti: case Opcode::mips64_sltiu:
            if (src2) {
                const bool unsigned_compare = op == Opcode::mips64_sltu || op == Opcode::mips64_sltiu;
                auto predicate = std::make_shared<Expression>(Expression{{TypeKind::boolean, 1, false},
                    BinaryValue{unsigned_compare ? "ult" : "slt", src1, src2}});
                return assign(unary("zext", std::move(predicate), 64));
            }
            break;
        case Opcode::mips64_dadd:
            return intrinsic(instruction, "mips64_dadd_overflow", IntrinsicMemoryEffect::none);
        case Opcode::mips64_daddi:
            return intrinsic(instruction, "mips64_daddi_overflow", IntrinsicMemoryEffect::none);
        case Opcode::mips64_daddu:
            if (src2) return assign(binary("add", src1, src2, 64));
            break;
        case Opcode::mips64_dsub:
            return intrinsic(instruction, "mips64_dsub_overflow", IntrinsicMemoryEffect::none);
        case Opcode::mips64_dsubu:
            if (src2) return assign(binary("sub", src1, src2, 64));
            break;
        case Opcode::mips64_daddiu:
            if (src2) return assign(binary("add", src1, src2, 64));
            break;
        case Opcode::mips_addi:
            return intrinsic(instruction, "mips64_addi_overflow", IntrinsicMemoryEffect::none);
        case Opcode::mips_addiu:
            if (src2) return assign(word_result("add", src1, src2));
            break;
        case Opcode::mips_addu:
            if (src2) return assign(word_result("add", src1, src2));
            break;
        case Opcode::mips_subu:
            if (src2) return assign(word_result("sub", src1, src2));
            break;
        case Opcode::mips_and: case Opcode::mips_andi:
            if (src2) return assign(binary("and", src1, src2, 64));
            break;
        case Opcode::mips_or: case Opcode::mips_ori:
            if (src2) return assign(binary("or", src1, src2, 64));
            break;
        case Opcode::mips_xor: case Opcode::mips_xori:
            if (src2) return assign(binary("xor", src1, src2, 64));
            break;
        case Opcode::mips_nor:
            if (src2) return assign(unary("bitnot", binary("or", src1, src2, 64), 64));
            break;
        case Opcode::mips_slt: case Opcode::mips_slti: case Opcode::mips_sltu: case Opcode::mips_sltiu:
            if (src2) {
                const bool unsigned_compare = op == Opcode::mips_sltu || op == Opcode::mips_sltiu;
                auto predicate = std::make_shared<Expression>(Expression{{TypeKind::boolean, 1, false},
                    BinaryValue{unsigned_compare ? "ult" : "slt", src1, src2}});
                return assign(unary("zext", std::move(predicate), 64));
            }
            break;
        case Opcode::mips_lui:
            return assign(unary("sext", binary("shl", unary("zext", src1, 32), constant(16, 32), 32), 64));
        case Opcode::mips64_dsll: case Opcode::mips64_dsrl: case Opcode::mips64_dsra:
        case Opcode::mips64_dsll32: case Opcode::mips64_dsrl32: case Opcode::mips64_dsra32:
            if (src2) {
                const auto *amount = std::get_if<ImmediateOperand>(&items[2]);
                if (!amount) break;
                const char *shift = op == Opcode::mips64_dsll || op == Opcode::mips64_dsll32 ? "shl" :
                                    op == Opcode::mips64_dsra || op == Opcode::mips64_dsra32 ? "sar" : "shr";
                return assign(binary(shift, src1, src2, 64));
            }
            break;
        case Opcode::mips64_dsllv: case Opcode::mips64_dsrlv: case Opcode::mips64_dsrav:
            if (src2) {
                const auto amount = binary("and", src2, constant(63, 64), 64);
                const char *shift = op == Opcode::mips64_dsllv ? "shl" :
                                    op == Opcode::mips64_dsrlv ? "shr" : "sar";
                return assign(binary(shift, src1, amount, 64));
            }
            break;
        case Opcode::mips_sll: case Opcode::mips_srl: case Opcode::mips_sra:
            if (src2) {
                const auto *amount = std::get_if<ImmediateOperand>(&items[2]);
                if (!amount) break;
                const char *shift = op == Opcode::mips_sll ? "shl" : op == Opcode::mips_sra ? "sar" : "shr";
                return assign(word_result(shift, src1, src2));
            }
            break;
        case Opcode::mips64_sll: case Opcode::mips64_srl: case Opcode::mips64_sra:
            if (src2) {
                const auto *amount = std::get_if<ImmediateOperand>(&items[2]);
                if (!amount) break;
                const char *shift = op == Opcode::mips64_sll ? "shl" : op == Opcode::mips64_sra ? "sar" : "shr";
                return assign(word_result(shift, src1, src2));
            }
            break;
        case Opcode::mips_sllv: case Opcode::mips_srlv: case Opcode::mips_srav:
            if (src2) {
                const auto value = unary("trunc32", src1, 32);
                const auto amount = binary("and", src2, constant(31, 64), 64);
                const char *shift = op == Opcode::mips_sllv ? "shl" :
                                    op == Opcode::mips_srlv ? "shr" : "sar";
                return assign(unary("sext", binary(shift, value, amount, 32), 64));
            }
            break;
        case Opcode::mips64_sllv: case Opcode::mips64_srlv: case Opcode::mips64_srav:
            if (src2) {
                const auto value = unary("trunc32", src1, 32);
                const auto amount = binary("and", src2, constant(31, 64), 64);
                const char *shift = op == Opcode::mips64_sllv ? "shl" :
                                    op == Opcode::mips64_srlv ? "shr" : "sar";
                return assign(unary("sext", binary(shift, value, amount, 32), 64));
            }
            break;
        default: break;
        }
    }

    if (!items.empty() && destination && destination->bank == RegisterBank::mips_gpr) {
        const bool load = op == Opcode::mips_lb || op == Opcode::mips_lh || op == Opcode::mips_lw ||
            op == Opcode::mips_lbu || op == Opcode::mips_lhu || op == Opcode::mips64_lwu || op == Opcode::mips64_ld;
        if (op == Opcode::mips64_ll && items.size() >= 2) {
            auto value = operand(items[1]);
            return assign(unary("sext", std::move(value), 64));
        }
        if (load && items.size() >= 2) {
            const auto value = operand(items[1]);
            if (value->type.bits == destination->width) return assign(value);
            const bool sign_extend = op == Opcode::mips_lb || op == Opcode::mips_lh || op == Opcode::mips_lw;
            return assign(unary(sign_extend ? "sext" : "zext", value, destination->width));
        }
        if (op == Opcode::mips64_lld)
            return intrinsic(instruction, "mips64_lld_reservation", IntrinsicMemoryEffect::read);
        if (op == Opcode::mips64_scd)
            return intrinsic(instruction, "mips64_scd_conditional_store", IntrinsicMemoryEffect::write);
        if ((op == Opcode::mips_sb || op == Opcode::mips_sh || op == Opcode::mips_sw || op == Opcode::mips64_sd) &&
            items.size() >= 2)
            return Store{operand(items[1]), operand(items[0])};
    }
    return std::nullopt;
}
} // namespace hexlab::decompiler
