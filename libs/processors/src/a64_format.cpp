#include "a64_internal.hpp"
#include <sstream>
namespace hexlab::a64_detail {
namespace {
std::string hex(std::uint64_t value) {
    std::ostringstream out;
    out << "0x" << std::hex << value;
    return out.str();
}
} // namespace
std::string mnemonic(Opcode opcode, std::uint8_t condition) {
    if (opcode == Opcode::a64_adc) return "adc";
    if (opcode == Opcode::a64_adcs) return "adcs";
    if (opcode == Opcode::a64_sbc) return "sbc";
    if (opcode == Opcode::a64_sbcs) return "sbcs";
    if (opcode == Opcode::a64_bic) return "bic";
    if (opcode == Opcode::a64_orn) return "orn";
    if (opcode == Opcode::a64_eon) return "eon";
    if (opcode == Opcode::a64_bics) return "bics";
    if (opcode == Opcode::a64_rbit) return "rbit";
    if (opcode == Opcode::a64_rev16) return "rev16";
    if (opcode == Opcode::a64_rev32) return "rev32";
    if (opcode == Opcode::a64_rev) return "rev";
    if (opcode == Opcode::a64_clz) return "clz";
    if (opcode == Opcode::a64_cls) return "cls";
    if (opcode == Opcode::a64_extr) return "extr";
    if (opcode == Opcode::a64_ldrsw) return "ldrsw";
    if (opcode == Opcode::a64_madd) return "madd";
    if (opcode == Opcode::a64_msub) return "msub";
    if (opcode == Opcode::a64_csel) return "csel";
    if (opcode == Opcode::a64_csinc) return "csinc";
    if (opcode == Opcode::a64_csinv) return "csinv";
    if (opcode == Opcode::a64_csneg) return "csneg";
    if (opcode == Opcode::a64_udiv) return "udiv";
    if (opcode == Opcode::a64_sdiv) return "sdiv";
    if (opcode == Opcode::a64_ccmp) return "ccmp";
    if (opcode == Opcode::a64_ccmn) return "ccmn";
    if (opcode == Opcode::a64_vadd) return "add";
    if (opcode == Opcode::a64_vsub) return "sub";
    if (opcode == Opcode::a64_vand) return "and";
    if (opcode == Opcode::a64_vorr) return "orr";
    if (opcode == Opcode::a64_veor) return "eor";
    if (opcode == Opcode::a64_vsmax) return "smax";
    if (opcode == Opcode::a64_vsmin) return "smin";
    if (opcode == Opcode::a64_vumax) return "umax";
    if (opcode == Opcode::a64_vumin) return "umin";
    if (opcode == Opcode::a64_fadd) return "fadd";
    if (opcode == Opcode::a64_fsub) return "fsub";
    if (opcode == Opcode::a64_fmul) return "fmul";
    if (opcode == Opcode::a64_fdiv) return "fdiv";
    if (opcode == Opcode::a64_fmax) return "fmax";
    if (opcode == Opcode::a64_fmin) return "fmin";
    if (opcode == Opcode::a64_ldp) return "ldp";
    if (opcode == Opcode::a64_stp) return "stp";
    if (opcode == Opcode::a64_sbfm) return "sbfm";
    if (opcode == Opcode::a64_ubfm) return "ubfm";
    if (opcode == Opcode::a64_bfm) return "bfm";
    static constexpr const char *names[]{"b",    "bl",  "b.cond", "cbz",  "cbnz", "tbz",  "tbnz", "br",   "blr",
                                         "ret",  "brk", "nop",    "movn", "movz", "movk", "add",  "adds", "sub",
                                         "subs", "and", "orr", "eor", "ands", "adr", "adrp", "ldr", "str", "ldrb", "strb", "ldrh", "strh", "sbfm", "ubfm"};
    static constexpr const char *conditions[]{"eq", "ne", "cs", "cc", "mi", "pl", "vs", "vc",
                                              "hi", "ls", "ge", "lt", "gt", "le", "al", "nv"};
    const auto index = static_cast<unsigned>(opcode) - static_cast<unsigned>(Opcode::a64_b);
    std::string result = index < std::size(names) ? names[index] : "?a64";
    if (opcode == Opcode::a64_b_cond)
        result = std::string("b.") + conditions[condition & 15];
    return result;
}
std::string format(const Instruction &i) {
    if (i.opcode == Opcode::a64_extr && i.operands.size() == 4) {
        const auto *dst = std::get_if<RegisterOperand>(&i.operands[0]);
        const auto *low = std::get_if<RegisterOperand>(&i.operands[1]);
        const auto *high = std::get_if<RegisterOperand>(&i.operands[2]);
        const auto *lsb = std::get_if<ImmediateOperand>(&i.operands[3]);
        if (dst && low && high && lsb)
            return "extr " + register_name(*dst) + ", " + register_name(*low) + ", " +
                register_name(*high) + ", #" + hex(lsb->value);
    }
    if ((i.opcode == Opcode::a64_ccmp || i.opcode == Opcode::a64_ccmn) && i.operands.size() == 3) {
        static constexpr const char *conditions[]{"eq", "ne", "cs", "cc", "mi", "pl", "vs", "vc",
                                                   "hi", "ls", "ge", "lt", "gt", "le", "al", "nv"};
        const auto *left = std::get_if<RegisterOperand>(&i.operands[0]);
        const auto *right_reg = std::get_if<RegisterOperand>(&i.operands[1]);
        const auto *right_imm = std::get_if<ImmediateOperand>(&i.operands[1]);
        const auto *fallback = std::get_if<ImmediateOperand>(&i.operands[2]);
        if (!left || (!right_reg && !right_imm) || !fallback)
            return "?a64-conditional-compare";
        return mnemonic(i.opcode, i.condition) + " " + register_name(*left) + ", " +
            (right_reg ? register_name(*right_reg) : "#" + hex(right_imm->value)) + ", #" +
            hex(fallback->value) + ", " + conditions[i.condition & 15];
    }
    if ((i.opcode == Opcode::a64_csel || i.opcode == Opcode::a64_csinc ||
         i.opcode == Opcode::a64_csinv || i.opcode == Opcode::a64_csneg) && i.operands.size() == 3) {
        static constexpr const char *conditions[]{"eq", "ne", "cs", "cc", "mi", "pl", "vs", "vc",
                                                   "hi", "ls", "ge", "lt", "gt", "le", "al", "nv"};
        const auto *destination = std::get_if<RegisterOperand>(&i.operands[0]);
        const auto *left = std::get_if<RegisterOperand>(&i.operands[1]);
        const auto *right = std::get_if<RegisterOperand>(&i.operands[2]);
        if (!destination || !left || !right) return "?a64-csel";
        // CSET/CSETM are aliases for CSINC/CSINV with both sources ZR and
        // the condition inverted. Restrict the alias to real predicates;
        // AL/NV are retained in their architectural instruction spelling.
        if (i.condition < 14 && left->bank == RegisterBank::arm64_zero &&
            right->bank == RegisterBank::arm64_zero &&
            (i.opcode == Opcode::a64_csinc || i.opcode == Opcode::a64_csinv)) {
            const auto alias = i.opcode == Opcode::a64_csinc ? "cset " : "csetm ";
            return std::string(alias) + register_name(*destination) + ", " +
                   conditions[i.condition ^ 1];
        }
        std::string result = mnemonic(i.opcode, i.condition);
        for (const auto *reg : {destination, left, right}) {
            result += result.find(' ') == std::string::npos ? " " : ", ";
            result += register_name(*reg);
        }
        result += ", ";
        result += conditions[i.condition & 15];
        return result;
    }
    if ((i.opcode == Opcode::a64_madd || i.opcode == Opcode::a64_msub) && i.operands.size() == 4) {
        const auto *destination = std::get_if<RegisterOperand>(&i.operands[0]);
        const auto *left = std::get_if<RegisterOperand>(&i.operands[1]);
        const auto *right = std::get_if<RegisterOperand>(&i.operands[2]);
        const auto *accumulator = std::get_if<RegisterOperand>(&i.operands[3]);
        if (destination && left && right && accumulator && accumulator->bank == RegisterBank::arm64_zero) {
            const auto alias = i.opcode == Opcode::a64_madd ? "mul " : "mneg ";
            return std::string(alias) + register_name(*destination) + ", " + register_name(*left) + ", " +
                   register_name(*right);
        }
    }
    const bool vector_fp = i.opcode == Opcode::a64_fadd || i.opcode == Opcode::a64_fsub ||
        i.opcode == Opcode::a64_fmul || i.opcode == Opcode::a64_fdiv ||
        i.opcode == Opcode::a64_fmax || i.opcode == Opcode::a64_fmin;
    const bool vector_integer = i.opcode == Opcode::a64_vadd || i.opcode == Opcode::a64_vsub ||
        i.opcode == Opcode::a64_vand || i.opcode == Opcode::a64_vorr || i.opcode == Opcode::a64_veor ||
        i.opcode == Opcode::a64_vsmax || i.opcode == Opcode::a64_vsmin ||
        i.opcode == Opcode::a64_vumax || i.opcode == Opcode::a64_vumin;
    if (vector_fp && (i.vector_bits == 32 || i.vector_bits == 64) &&
        i.vector_bits == i.vector_element_bits && i.operands.size() == 3) {
        std::string result = mnemonic(i.opcode, i.condition);
        for (std::size_t n = 0; n < i.operands.size(); ++n) {
            result += n ? ", " : " ";
            const auto *reg = std::get_if<RegisterOperand>(&i.operands[n]);
            if (!reg || reg->bank != RegisterBank::arm64_simd || reg->width != i.vector_bits)
                return "?a64-scalar-fp";
            result += register_name(*reg);
        }
        return result;
    }
    if ((vector_integer || vector_fp) && (i.vector_bits == 64 || i.vector_bits == 128) && i.vector_element_bits) {
        const char suffix = i.vector_element_bits == 8 ? 'b' : i.vector_element_bits == 16 ? 'h' :
            i.vector_element_bits == 32 ? 's' : i.vector_element_bits == 64 ? 'd' : '?';
        const auto lanes = suffix == '?' ? 0 : i.vector_bits / i.vector_element_bits;
        if (lanes) {
            std::string result = mnemonic(i.opcode, i.condition);
            for (std::size_t n = 0; n < i.operands.size(); ++n) {
                result += n ? ", " : " ";
                const auto *reg = std::get_if<RegisterOperand>(&i.operands[n]);
                if (!reg || reg->bank != RegisterBank::arm64_simd || reg->width != i.vector_bits)
                    return "?a64-vector";
                result += register_name(*reg) + "." + std::to_string(lanes) + suffix;
            }
            return result;
        }
    }
    if (i.opcode == Opcode::a64_bfm && i.operands.size() == 4) {
        const auto *dst = std::get_if<RegisterOperand>(&i.operands[0]);
        const auto *src = std::get_if<RegisterOperand>(&i.operands[1]);
        const auto *r = std::get_if<ImmediateOperand>(&i.operands[2]);
        const auto *s = std::get_if<ImmediateOperand>(&i.operands[3]);
        if (dst && src && r && s && (dst->width == 32 || dst->width == 64) &&
            src->width == dst->width && r->value < dst->width && s->value < dst->width) {
            if (s->value >= r->value)
                return "bfxil " + register_name(*dst) + ", " + register_name(*src) + ", #" +
                    hex(r->value) + ", #" + hex(s->value - r->value + 1);
            const auto field = ", #" + hex(dst->width - r->value) + ", #" + hex(s->value + 1);
            if (src->bank == RegisterBank::arm64_zero)
                return "bfc " + register_name(*dst) + field;
            return "bfi " + register_name(*dst) + ", " + register_name(*src) + field;
        }
    }
    if ((i.opcode == Opcode::a64_ubfm || i.opcode == Opcode::a64_sbfm) && i.operands.size() == 4) {
        const auto *dst = std::get_if<RegisterOperand>(&i.operands[0]);
        const auto *src = std::get_if<RegisterOperand>(&i.operands[1]);
        const auto *r = std::get_if<ImmediateOperand>(&i.operands[2]);
        const auto *s = std::get_if<ImmediateOperand>(&i.operands[3]);
        if (dst && src && r && s) {
            const auto width = static_cast<unsigned>(dst->width);
            const auto immr = static_cast<unsigned>(r->value);
            const auto imms = static_cast<unsigned>(s->value);
            std::string name = i.opcode == Opcode::a64_ubfm ? "ubfm" : "sbfm";
            unsigned first = immr, second = imms;
            if (imms == width - 1) {
                name = i.opcode == Opcode::a64_ubfm ? "lsr" : "asr";
            } else if (imms >= immr) {
                name = i.opcode == Opcode::a64_ubfm ? "ubfx" : "sbfx";
                second = imms - immr + 1;
            } else if (i.opcode == Opcode::a64_ubfm && imms + 1 == immr) {
                name = "lsl";
                first = width - immr;
            }
            return name + " " + register_name(*dst) + ", " + register_name(*src) + ", #" + hex(first) +
                   (name == "ubfx" || name == "sbfx" ? ", #" + hex(second) : "");
        }
    }
    std::string result = mnemonic(i.opcode, i.condition);
    std::uint32_t encoded_word = 0;
    if (i.bytes.size() == 4)
        for (unsigned byte = 0; byte < 4; ++byte)
            encoded_word |= std::uint32_t(std::to_integer<unsigned>(i.bytes[byte])) << (byte * 8);
    const bool extended_add_sub = i.bytes.size() == 4 &&
        (encoded_word & 0x1f200000u) == 0x0b200000u;
    for (std::size_t n = 0; n < i.operands.size(); ++n) {
        result += n ? ", " : " ";
        const auto &value = i.operands[n];
        if (auto r = std::get_if<RegisterOperand>(&value)) {
            result += register_name(*r);
            if (n == 2 && (i.opcode == Opcode::a64_add || i.opcode == Opcode::a64_adds ||
                           i.opcode == Opcode::a64_sub || i.opcode == Opcode::a64_subs) &&
                extended_add_sub) {
                if (((encoded_word >> 10) & 7u) == 0) {
                    static constexpr const char *extensions[] = {
                        "uxtb", "uxth", "uxtw", "uxtx", "sxtb", "sxth", "sxtw", "sxtx"};
                    result += ", ";
                    result += extensions[(encoded_word >> 13) & 7u];
                }
            }
        } else if (auto immediate = std::get_if<ImmediateOperand>(&value)) {
            if (n == 3 && (i.opcode == Opcode::a64_add || i.opcode == Opcode::a64_adds ||
                           i.opcode == Opcode::a64_sub || i.opcode == Opcode::a64_subs) &&
                           extended_add_sub) {
                    static constexpr const char *extensions[] = {
                        "uxtb", "uxth", "uxtw", "uxtx", "sxtb", "sxth", "sxtw", "sxtx"};
                    result += std::string(extensions[(encoded_word >> 13) & 7u]) + " ";
            }
            if (n == 3 && !extended_add_sub && (i.opcode == Opcode::a64_add || i.opcode == Opcode::a64_adds || i.opcode == Opcode::a64_sub || i.opcode == Opcode::a64_subs || i.opcode == Opcode::a64_and || i.opcode == Opcode::a64_orr || i.opcode == Opcode::a64_eor || i.opcode == Opcode::a64_ands || i.opcode == Opcode::a64_bic || i.opcode == Opcode::a64_orn || i.opcode == Opcode::a64_eon || i.opcode == Opcode::a64_bics)) {
                static constexpr const char *shifts[]{"lsl", "lsr", "asr", "ror"};
                const auto shift = (std::to_integer<unsigned>(i.bytes[2]) >> 6) & 3;
                result += std::string(shifts[shift]) + " ";
            }

            if (n == 2 &&
                (i.opcode == Opcode::a64_movn || i.opcode == Opcode::a64_movz || i.opcode == Opcode::a64_movk))
                result += "lsl ";
            result += "#" + hex(immediate->value);
        } else if (auto rel = std::get_if<RelativeOperand>(&value)) {
            if (i.direct_target)
                result += hex(i.direct_target->offset);
            else
                result += "rel " + std::string(rel->displacement < 0 ? "-" : "") +
                          hex(rel->displacement < 0 ? static_cast<std::uint64_t>(-(rel->displacement + 1)) + 1
                                                    : static_cast<std::uint64_t>(rel->displacement));
        } else if (auto memory = std::get_if<MemoryOperand>(&value)) {
            if (i.opcode == Opcode::a64_adr || i.opcode == Opcode::a64_adrp) {
                if (memory->resolved_address)
                    result += "#" + hex(memory->resolved_address->offset);
                else
                    result += std::string(i.opcode == Opcode::a64_adrp ? "page(pc)" : "pc") +
                              (memory->displacement < 0 ? " - #" : " + #") +
                              hex(memory->displacement < 0 ? static_cast<std::uint64_t>(-(memory->displacement + 1)) + 1
                                                           : static_cast<std::uint64_t>(memory->displacement));
                continue;
            }
            if (memory->ip_relative) {
                result += memory->resolved_address ? "[" + hex(memory->resolved_address->offset) + "]"
                                                   : "[pc" + std::string(memory->displacement < 0 ? " - #" : " + #") +
                                                         hex(memory->displacement < 0
                                                                 ? static_cast<std::uint64_t>(-(memory->displacement + 1)) + 1
                                                                 : static_cast<std::uint64_t>(memory->displacement)) + "]";
                continue;
            }
            result += "[" + (memory->base ? register_name(*memory->base) : std::string("?base"));
            if (memory->index) {
                result += ", ";
                if (!memory->index_extend.empty()) result += memory->index_extend + " ";
                result += register_name(*memory->index);
                if (memory->index_shift_amount)
                    result += ", lsl #" + hex(memory->index_shift_amount);
            }
            if (memory->displacement) {
                const auto displacement = memory->displacement;
                const auto magnitude = displacement < 0
                    ? static_cast<std::uint64_t>(-(displacement + 1)) + 1
                    : static_cast<std::uint64_t>(displacement);
                result += ", #" + std::string(displacement < 0 ? "-" : "") + hex(magnitude);
            }
            result += "]";
            if (memory->post_index) {
                const auto displacement = memory->writeback_displacement;
                const auto magnitude = displacement < 0
                    ? static_cast<std::uint64_t>(-(displacement + 1)) + 1
                    : static_cast<std::uint64_t>(displacement);
                result += ", #" + std::string(displacement < 0 ? "-" : "") + hex(magnitude);
            } else if (memory->writeback) {
                result += "!";
            }
        }
    }
    return result;
}
} // namespace hexlab::a64_detail

