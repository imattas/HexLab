#include "arm32_internal.hpp"
#include <sstream>
namespace hexlab::arm32_detail {
namespace {
std::string hex(std::uint64_t value) {
    std::ostringstream out;
    out << "0x" << std::hex << value;
    return out.str();
}
std::string reg_name(RegisterOperand r) {
    return r.index == 13 ? "sp" : r.index == 14 ? "lr" : r.index == 15 ? "pc" : register_name(r);
}
std::string shifted_text(const ArmShiftedRegisterOperand &value) {
    auto text = reg_name(value.source);
    if (value.amount_register || value.amount) {
        static constexpr const char *names[]{"lsl", "lsr", "asr", "ror", "rrx"};
        const auto kind = static_cast<unsigned>(value.shift);
        text += ", " + std::string(kind < std::size(names) ? names[kind] : "?shift");
        if (value.amount_register)
            text += " " + reg_name(*value.amount_register);
        else if (value.shift != ArmShift::rrx)
            text += " #" + std::to_string(value.amount);
    }
    return text;
}
} // namespace
std::string mnemonic(Opcode opcode, std::uint8_t condition) {
    const char *reverse_name = opcode == Opcode::a32_rev ? "rev" :
        opcode == Opcode::a32_rev16 ? "rev16" : opcode == Opcode::a32_revsh ? "revsh" :
        opcode == Opcode::a32_rbit ? "rbit" : nullptr;
    if (reverse_name) {
        static constexpr const char *conditions[]{"eq", "ne", "hs", "lo", "mi", "pl", "vs", "vc",
                                                   "hi", "ls", "ge", "lt", "gt", "le", "", "?"};
        return std::string(reverse_name) + conditions[condition & 15];
    }
    if (opcode == Opcode::a32_mrs || opcode == Opcode::a32_msr) {
        static constexpr const char *conditions[]{"eq", "ne", "hs", "lo", "mi", "pl", "vs", "vc", "hi", "ls", "ge", "lt", "gt", "le", "", "?"};
        return std::string(opcode == Opcode::a32_mrs ? "mrs" : "msr") + conditions[condition & 15];
    }
    if (opcode == Opcode::t32_addw || opcode == Opcode::t32_subw) {
        static constexpr const char *conditions[]{"eq", "ne", "hs", "lo", "mi", "pl", "vs", "vc",
                                                   "hi", "ls", "ge", "lt", "gt", "le", "", "?"};
        return std::string(opcode == Opcode::t32_addw ? "addw" : "subw") + conditions[condition & 15];
    }
    if (opcode == Opcode::t32_movw) return "movw";
    if (opcode == Opcode::t32_movt) return "movt";
    const char *bitfield_name = opcode == Opcode::arm_sbfx ? "sbfx" :
        opcode == Opcode::arm_ubfx ? "ubfx" : opcode == Opcode::arm_bfi ? "bfi" :
        opcode == Opcode::arm_bfc ? "bfc" : nullptr;
    if (bitfield_name) {
        static constexpr const char *conditions[]{"eq", "ne", "hs", "lo", "mi", "pl", "vs", "vc",
                                                   "hi", "ls", "ge", "lt", "gt", "le", "", "?"};
        return std::string(bitfield_name) + conditions[condition & 15];
    }
    const char *saturating_name = opcode == Opcode::arm_qadd ? "qadd" :
        opcode == Opcode::arm_qsub ? "qsub" : opcode == Opcode::arm_qdadd ? "qdadd" :
        opcode == Opcode::arm_qdsub ? "qdsub" : nullptr;
    if (saturating_name) {
        static constexpr const char *conditions[]{"eq", "ne", "hs", "lo", "mi", "pl", "vs", "vc",
                                                   "hi", "ls", "ge", "lt", "gt", "le", "", "?"};
        return std::string(saturating_name) + conditions[condition & 15];
    }
    const char *exclusive_name = opcode == Opcode::arm_ldrex ? "ldrex" :
        opcode == Opcode::arm_ldrexb ? "ldrexb" : opcode == Opcode::arm_ldrexh ? "ldrexh" :
        opcode == Opcode::arm_strex ? "strex" : opcode == Opcode::arm_strexb ? "strexb" :
        opcode == Opcode::arm_strexh ? "strexh" : nullptr;
    if (exclusive_name) {
        static constexpr const char *conditions[]{"eq", "ne", "hs", "lo", "mi", "pl", "vs", "vc",
                                                   "hi", "ls", "ge", "lt", "gt", "le", "", "?"};
        return std::string(exclusive_name) + conditions[condition & 15];
    }
    const char *multiply_name = nullptr;
    switch (opcode) {
    case Opcode::a32_mul: multiply_name = "mul"; break;
    case Opcode::a32_mla: multiply_name = "mla"; break;
    case Opcode::a32_mls: multiply_name = "mls"; break;
    case Opcode::a32_umull: multiply_name = "umull"; break;
    case Opcode::a32_umlal: multiply_name = "umlal"; break;
    case Opcode::a32_smull: multiply_name = "smull"; break;
    case Opcode::a32_smlal: multiply_name = "smlal"; break;
    default: break;
    }
    if (multiply_name) {
        static constexpr const char *multiply_conditions[]{"eq", "ne", "hs", "lo", "mi", "pl", "vs", "vc",
                                                            "hi", "ls", "ge", "lt", "gt", "le", "", "?"};
        return std::string(multiply_name) + multiply_conditions[condition & 15];
    }
    const char *extend_name = nullptr;
    switch (opcode) {
    case Opcode::a32_sxtb: extend_name = "sxtb"; break;
    case Opcode::a32_sxth: extend_name = "sxth"; break;
    case Opcode::a32_sxtab: extend_name = "sxtab"; break;
    case Opcode::a32_sxtah: extend_name = "sxtah"; break;
    case Opcode::a32_uxtb: extend_name = "uxtb"; break;
    case Opcode::a32_uxth: extend_name = "uxth"; break;
    case Opcode::a32_uxtab: extend_name = "uxtab"; break;
    case Opcode::a32_uxtah: extend_name = "uxtah"; break;
    case Opcode::t32_sxtb16: extend_name = "sxtb16"; break;
    case Opcode::t32_sxtab16: extend_name = "sxtab16"; break;
    case Opcode::t32_uxtb16: extend_name = "uxtb16"; break;
    case Opcode::t32_uxtab16: extend_name = "uxtab16"; break;
    case Opcode::a32_sxtb16: extend_name = "sxtb16"; break;
    case Opcode::a32_sxtab16: extend_name = "sxtab16"; break;
    case Opcode::a32_uxtb16: extend_name = "uxtb16"; break;
    case Opcode::a32_uxtab16: extend_name = "uxtab16"; break;
    default: break;
    }
    if (extend_name) {
        static constexpr const char *conditions[]{"eq", "ne", "hs", "lo", "mi", "pl", "vs", "vc",
                                                   "hi", "ls", "ge", "lt", "gt", "le", "", "?"};
        return std::string(extend_name) + conditions[condition & 15];
    }
    if (opcode == Opcode::arm_tbb || opcode == Opcode::arm_tbh) {
        static constexpr const char *condition_names[]{"eq", "ne", "hs", "lo", "mi", "pl", "vs", "vc",
                                                       "hi", "ls", "ge", "lt", "gt", "le", "", "?"};
        return std::string(opcode == Opcode::arm_tbb ? "tbb" : "tbh") + condition_names[condition & 15];
    }
    static constexpr const char *names[]{"b",    "bl",   "bx",    "blx",   "nop", "bkpt", "svc", "and",  "eor",
                                         "sub",  "rsb",  "add",   "adc",   "sbc", "rsc",  "tst", "teq",  "cmp",
                                         "cmn",  "orr",  "mov",   "bic",   "mvn", "ldr",  "str", "ldrb", "strb",
                                         "ldrh", "strh", "ldrsb", "ldrsh", "ldm", "stm",  "b",   "bl",   "bx",
                                         "blx",  "cbz",  "cbnz",  "it",    "nop", "bkpt", "svc", "adr",  "mul"};
    static constexpr const char *conditions[]{"eq", "ne", "hs", "lo", "mi", "pl", "vs", "vc",
                                              "hi", "ls", "ge", "lt", "gt", "le", "",   "?"};
    const auto index = static_cast<unsigned>(opcode) - static_cast<unsigned>(Opcode::a32_b);
    return index < std::size(names) ? std::string(names[index]) + conditions[condition & 15] : "?a32";
}
std::string format(const Instruction &i) {
    const bool unknown = i.arm && i.arm->predicate == ArmPredicate::unknown_it;
    const bool narrow = i.context.mode == ExecutionMode::thumb && i.length == 2;
    const auto half = std::to_integer<unsigned>(i.bytes[0]) | (std::to_integer<unsigned>(i.bytes[1]) << 8);
    if (i.opcode == Opcode::t32_it && i.operands.size() == 2 &&
        std::holds_alternative<ImmediateOperand>(i.operands[0]) &&
        std::holds_alternative<ImmediateOperand>(i.operands[1])) {
        const auto condition = std::get<ImmediateOperand>(i.operands[0]).value & 15;
        auto state = static_cast<unsigned>((condition << 4) | (std::get<ImmediateOperand>(i.operands[1]).value & 15));
        std::string text = "it";
        const auto advance = [](unsigned s) { return (s & 7) ? (s & 0xe0) | ((s << 1) & 31) : 0; };
        for (unsigned n = 0; n < 3 && (state = advance(state)); ++n)
            text += (state >> 4) == condition ? 't' : 'e';
        return text + " " +
               (condition == 14 ? std::string("al")
                                : mnemonic(Opcode::t32_b, static_cast<std::uint8_t>(condition)).substr(1));
    }
    if (i.context.mode == ExecutionMode::thumb && i.opcode == Opcode::a32_mov && i.operands.size() == 2 &&
        std::holds_alternative<RegisterOperand>(i.operands[0])) {
        if (const auto shift = std::get_if<ArmShiftedRegisterOperand>(&i.operands[1]);
            shift && (shift->amount_register || shift->amount)) {
            static constexpr const char *names[]{"lsl", "lsr", "asr", "ror", "rrx"};
            const auto kind = static_cast<unsigned>(shift->shift);
            std::string text = kind < std::size(names) ? names[kind] : "?shift";
            if (i.arm && i.arm->flags_written)
                text += "s";
            text += mnemonic(Opcode::a32_mov, unknown ? 14 : i.condition).substr(3);
            text += " " + reg_name(std::get<RegisterOperand>(i.operands[0]));
            if (!(narrow && (half & 0xfc00) == 0x4000 && shift->amount_register))
                text += ", " + reg_name(shift->source);
            if (shift->amount_register)
                text += ", " + reg_name(*shift->amount_register);
            else if (shift->shift != ArmShift::rrx)
                text += ", #" + std::to_string(shift->amount);
            return unknown ? text + " ; IT state unknown" : text;
        }
    }
    const bool compare = i.opcode >= Opcode::a32_tst && i.opcode <= Opcode::a32_cmn;
    const bool data = (i.opcode >= Opcode::a32_and && i.opcode <= Opcode::a32_mvn) ||
                      i.opcode == Opcode::t32_addw || i.opcode == Opcode::t32_subw || i.opcode == Opcode::t32_mul ||
                      i.opcode == Opcode::t32_movw || i.opcode == Opcode::t32_movt ||
                      i.opcode == Opcode::a32_mul || i.opcode == Opcode::a32_mla ||
                      i.opcode == Opcode::a32_mls ||
                      i.opcode == Opcode::a32_umull || i.opcode == Opcode::a32_umlal ||
                      i.opcode == Opcode::a32_smull || i.opcode == Opcode::a32_smlal;
    auto result = mnemonic(i.opcode, 14);
    const bool stack = narrow && (half & 0xf600) == 0xb400;
    if (stack)
        result = (half & 0x800) ? "pop" : "push";
    const bool multiple = i.opcode == Opcode::a32_ldm || i.opcode == Opcode::a32_stm;
    if (multiple && i.arm && !stack && !(narrow && i.arm->multiple_mode == ArmMultipleMode::ia)) {
        static constexpr const char *modes[]{"ia", "ib", "da", "db"};
        const auto mode = static_cast<unsigned>(i.arm->multiple_mode);
        result += mode < std::size(modes) ? modes[mode] : "?mode";
    }
    if (data && !compare && i.arm && i.arm->flags_written)
        result += "s";
    const auto qualified = mnemonic(i.opcode, unknown ? 14 : i.condition), plain = mnemonic(i.opcode, 14);
    result += qualified.substr(plain.size());
    if (i.context.mode == ExecutionMode::thumb && i.length == 4 &&
        (i.opcode == Opcode::a32_add || i.opcode == Opcode::a32_sub))
        result += ".w";
    const auto short_op = (half >> 6) & 15;
    const bool short_binary =
        narrow && (((half & 0xe000) == 0x2000 && ((half >> 11) & 3) >= 2) ||
                   ((half & 0xfc00) == 0x4000 && (short_op == 0 || short_op == 1 || short_op == 5 || short_op == 6 ||
                                                  short_op == 12 || short_op == 14)) ||
                   (half & 0xff00) == 0x4400 || (half & 0xff00) == 0xb000);
    bool first_operand = true;
    for (std::size_t n = 0; n < i.operands.size(); ++n) {
        if ((stack && n == 0) || (short_binary && n == 1))
            continue;
        result += first_operand ? " " : ", ";
        first_operand = false;
        const auto &operand = i.operands[n];
        if (auto r = std::get_if<RegisterOperand>(&operand)) {
            result += reg_name(*r);
            if (multiple && n == 0 && i.arm && i.arm->writeback)
                result += "!";
        } else if (auto immediate = std::get_if<ImmediateOperand>(&operand))
            result += "#" + hex(immediate->value);
        else if (auto shifted = std::get_if<ArmShiftedRegisterOperand>(&operand)) {
            result += shifted_text(*shifted);
        } else if (auto table = std::get_if<MemoryOperand>(&operand)) {
            if (table->base && table->index) {
                result += "[" + reg_name(*table->base) + ", " + reg_name(*table->index);
                if (table->scale == 2)
                    result += ", lsl #1";
                result += "]";
            } else {
                result += "[?]";
            }
        } else if (auto memory = std::get_if<ArmMemoryOperand>(&operand)) {
            if (i.opcode == Opcode::t32_adr) {
                result += memory->resolved_address ? "#" + hex(memory->resolved_address->offset)
                                                   : "align(pc+4,4) + #" + hex(std::get<std::uint32_t>(memory->offset));
                continue;
            }
            std::string offset;
            if (auto memory_immediate = std::get_if<std::uint32_t>(&memory->offset))
                offset = "#" + std::string(memory->add ? "" : "-") + hex(*memory_immediate);
            else
                offset = std::string(memory->add ? "" : "-") +
                         shifted_text(std::get<ArmShiftedRegisterOperand>(memory->offset));
            const bool zero =
                std::holds_alternative<std::uint32_t>(memory->offset) && std::get<std::uint32_t>(memory->offset) == 0;
            result += "[" + reg_name(memory->base);
            if (memory->pre_index && (!zero || memory->writeback))
                result += ", " + offset;
            result += "]";
            if (!memory->pre_index)
                result += ", " + offset;
            else if (memory->writeback)
                result += "!";
        } else if (auto list = std::get_if<ArmRegisterListOperand>(&operand)) {
            result += "{";
            bool first = true;
            for (unsigned bit = 0; bit < 16; ++bit)
                if (list->mask & (1u << bit)) {
                    if (!first)
                        result += ", ";
                    result += reg_name({RegisterBank::arm32_gpr, static_cast<std::uint8_t>(bit), 32, false});
                    first = false;
                }
            result += "}";
            if (i.arm && i.arm->exchange == ArmExchange::saved_status)
                result += "^";
        } else if (auto thumb_relative = std::get_if<ThumbRelativeOperand>(&operand))
            result += i.direct_target
                          ? hex(i.direct_target->offset)
                          : "rel " + std::string(thumb_relative->displacement < 0 ? "-" : "") +
                                hex(thumb_relative->displacement < 0 ? static_cast<std::uint64_t>(-(thumb_relative->displacement + 1)) + 1
                                                                     : static_cast<std::uint64_t>(thumb_relative->displacement));
        else if (auto relative = std::get_if<RelativeOperand>(&operand))
            result += i.direct_target ? hex(i.direct_target->offset)
                                      : "rel " + std::string(relative->displacement < 0 ? "-" : "") +
                                            hex(static_cast<std::uint64_t>(relative->displacement < 0 ? -relative->displacement
                                                                                                      : relative->displacement));
    }
    if (i.opcode == Opcode::t32_mul && !i.operands.empty())
        result += ", " + reg_name(std::get<RegisterOperand>(i.operands[0]));
    return unknown ? result + " ; IT state unknown" : result;
}
} // namespace hexlab::arm32_detail
