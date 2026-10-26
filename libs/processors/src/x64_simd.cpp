#include "x64_simd_internal.hpp"
#include "hexlab/processors/x86_avx_semantics.hpp"

namespace hexlab::x64_detail {
namespace {
RegisterOperand xmm(RegisterOperand value) {
    value.bank = RegisterBank::xmm;
    value.width = 128;
    value.high_byte = false;
    return value;
}

struct VectorModRM {
    RegisterOperand reg;
    Operand rm;
};

VectorModRM vector_modrm(State &state, std::uint16_t memory_width) {
    auto decoded = modrm(state, 128, 128);
    Operand rm = std::move(decoded.rm);
    if (auto *reg = std::get_if<RegisterOperand>(&rm))
        *reg = xmm(*reg);
    if (auto *memory = std::get_if<MemoryOperand>(&rm))
        memory->data_width = memory_width;
    return {xmm(decoded.reg), std::move(rm)};
}

enum class PrefixForm { packed, move_unaligned, scalar_single, scalar_double };

void require_prefix(State &state, PrefixForm form) {
    const bool has_66 = state.operand_override;
    const auto group1 = state.group1;
    if (has_66 && (group1 == 0xf2 || group1 == 0xf3))
        invalid("Conflicting mandatory SIMD prefixes");

    switch (form) {
    case PrefixForm::packed:
        if (!has_66) {
            if (group1 == 0xf2 || group1 == 0xf3)
                invalid("Packed SSE2 operation has the wrong mandatory prefix");
            unsupported("Packed SSE2 integer operation requires the 66 prefix");
        }
        if (group1 != 0)
            invalid("Packed SSE2 integer operation has an incompatible group-one prefix");
        break;
    case PrefixForm::move_unaligned:
        if (group1 == 0xf3 && !has_66)
            break;
        if (!has_66 && group1 == 0)
            unsupported("MMX move form is outside the enabled SIMD subset");
        unsupported("This packed move prefix form is not covered");
    case PrefixForm::scalar_single:
        if (group1 == 0xf3 && !has_66)
            break;
        if ((group1 == 0xf2 || group1 == 0xf3) && has_66)
            invalid("Scalar single-precision operation has conflicting mandatory prefixes");
        unsupported("This packed or scalar SIMD prefix form is not covered");
    case PrefixForm::scalar_double:
        if (group1 == 0xf2 && !has_66)
            break;
        if ((group1 == 0xf2 || group1 == 0xf3) && has_66)
            invalid("Scalar double-precision operation has conflicting mandatory prefixes");
        unsupported("This packed or scalar SIMD prefix form is not covered");
    }
}

bool immediate_packed_shift(State &state, std::uint8_t opcode) {
    if (opcode != 0x71 && opcode != 0x72 && opcode != 0x73)
        return false;
    require_prefix(state, PrefixForm::packed);
    auto decoded = modrm(state, 128, 128);
    auto *destination = std::get_if<RegisterOperand>(&decoded.rm);
    if (!destination)
        invalid("Immediate packed shift requires an XMM register destination");
    destination->bank = RegisterBank::xmm;
    destination->width = 128;
    destination->high_byte = false;
    Opcode operation{};
    if (opcode == 0x71) {
        if (decoded.group == 2) operation = Opcode::psrlw;
        else if (decoded.group == 4) operation = Opcode::psraw;
        else if (decoded.group == 6) operation = Opcode::psllw;
        else invalid("Reserved immediate packed word-shift group");
    } else if (opcode == 0x72) {
        if (decoded.group == 2) operation = Opcode::psrld;
        else if (decoded.group == 4) operation = Opcode::psrad;
        else if (decoded.group == 6) operation = Opcode::pslld;
        else invalid("Reserved immediate packed dword-shift group");
    } else {
        if (decoded.group == 2) operation = Opcode::psrlq;
        else if (decoded.group == 6) operation = Opcode::psllq;
        else invalid("Reserved immediate packed qword-shift group");
    }
    state.i.opcode = operation;
    if (opcode == 0x58 || opcode == 0x5c || opcode == 0x59) {
        // Packed FP arithmetic consumes MXCSR control bits and may set its
        // sticky exception flags. Keep the whole architectural register as
        // an implicit read/write dependency until bit-level MXCSR semantics
        // are available.
        constexpr RegisterOperand mxcsr{RegisterBank::mxcsr, 0, 32, false};
        state.i.register_reads.push_back(mxcsr);
        state.i.register_writes.push_back(mxcsr);
    }
    state.operand(std::move(decoded.rm), OperandAccess::read_write);
    state.operand(state.immediate(8, 8, false), OperandAccess::read);
    return true;
}
} // namespace

bool simd(State &state, std::uint8_t opcode, bool extended) {
    if (!extended)
        return false;
    if (immediate_packed_shift(state, opcode))
        return true;
    if (opcode == 0x70) {
        require_prefix(state, PrefixForm::packed);
        auto decoded = vector_modrm(state, 128);
        state.i.opcode = Opcode::pshufd;
        state.operand(decoded.reg, OperandAccess::write);
        state.operand(std::move(decoded.rm), OperandAccess::read);
        state.operand(state.immediate(8, 8, false), OperandAccess::read);
        return true;
    }

    Opcode operation{};
    PrefixForm prefix{};
    std::uint16_t memory_width = 128;
    bool move = false;
    bool store = false;

    switch (opcode) {
    case 0x6f:
        move = true;
        prefix = state.group1 == 0xf3 ? PrefixForm::move_unaligned : PrefixForm::packed;
        operation = state.group1 == 0xf3 ? Opcode::movdqu : Opcode::movdqa;
        break;
    case 0x7f:
        move = true;
        store = true;
        prefix = state.group1 == 0xf3 ? PrefixForm::move_unaligned : PrefixForm::packed;
        operation = state.group1 == 0xf3 ? Opcode::movdqu : Opcode::movdqa;
        break;
    case 0xd4: operation = Opcode::paddq; prefix = PrefixForm::packed; break;
    case 0xfc: operation = Opcode::paddb; prefix = PrefixForm::packed; break;
    case 0xfd: operation = Opcode::paddw; prefix = PrefixForm::packed; break;
    case 0xec: operation = Opcode::paddsb; prefix = PrefixForm::packed; break;
    case 0xed: operation = Opcode::paddsw; prefix = PrefixForm::packed; break;
    case 0xdc: operation = Opcode::paddusb; prefix = PrefixForm::packed; break;
    case 0xdd: operation = Opcode::paddusw; prefix = PrefixForm::packed; break;
    case 0xda: operation = Opcode::pminub; prefix = PrefixForm::packed; break;
    case 0xde: operation = Opcode::pmaxub; prefix = PrefixForm::packed; break;
    case 0xea: operation = Opcode::pminsw; prefix = PrefixForm::packed; break;
    case 0xee: operation = Opcode::pmaxsw; prefix = PrefixForm::packed; break;
    case 0xd5: operation = Opcode::pmullw; prefix = PrefixForm::packed; break;
    case 0xe5: operation = Opcode::pmulhw; prefix = PrefixForm::packed; break;
    case 0xe4: operation = Opcode::pmulhuw; prefix = PrefixForm::packed; break;
    case 0xf4: operation = Opcode::pmuludq; prefix = PrefixForm::packed; break;
    case 0xf5: operation = Opcode::pmaddwd; prefix = PrefixForm::packed; break;
    case 0xfe: operation = Opcode::paddd; prefix = PrefixForm::packed; break;
    case 0xf8: operation = Opcode::psubb; prefix = PrefixForm::packed; break;
    case 0xf9: operation = Opcode::psubw; prefix = PrefixForm::packed; break;
    case 0xe8: operation = Opcode::psubsb; prefix = PrefixForm::packed; break;
    case 0xe9: operation = Opcode::psubsw; prefix = PrefixForm::packed; break;
    case 0xd8: operation = Opcode::psubusb; prefix = PrefixForm::packed; break;
    case 0xd9: operation = Opcode::psubusw; prefix = PrefixForm::packed; break;
    case 0xfa: operation = Opcode::psubd; prefix = PrefixForm::packed; break;
    case 0xfb: operation = Opcode::psubq; prefix = PrefixForm::packed; break;
    case 0xdb: operation = Opcode::pand; prefix = PrefixForm::packed; break;
    case 0xdf: operation = Opcode::pandn; prefix = PrefixForm::packed; break;
    case 0x74: operation = Opcode::pcmpeqb; prefix = PrefixForm::packed; break;
    case 0x75: operation = Opcode::pcmpeqw; prefix = PrefixForm::packed; break;
    case 0x76: operation = Opcode::pcmpeqd; prefix = PrefixForm::packed; break;
    case 0x64: operation = Opcode::pcmpgtb; prefix = PrefixForm::packed; break;
    case 0x65: operation = Opcode::pcmpgtw; prefix = PrefixForm::packed; break;
    case 0x66: operation = Opcode::pcmpgtd; prefix = PrefixForm::packed; break;
    case 0xeb: operation = Opcode::por; prefix = PrefixForm::packed; break;
    case 0xef: operation = Opcode::pxor; prefix = PrefixForm::packed; break;
    case 0xf1: operation = Opcode::psllw; prefix = PrefixForm::packed; break;
    case 0xf2: operation = Opcode::pslld; prefix = PrefixForm::packed; break;
    case 0xf3: operation = Opcode::psllq; prefix = PrefixForm::packed; break;
    case 0xd1: operation = Opcode::psrlw; prefix = PrefixForm::packed; break;
    case 0xd2: operation = Opcode::psrld; prefix = PrefixForm::packed; break;
    case 0xd3: operation = Opcode::psrlq; prefix = PrefixForm::packed; break;
    case 0xe1: operation = Opcode::psraw; prefix = PrefixForm::packed; break;
    case 0xe2: operation = Opcode::psrad; prefix = PrefixForm::packed; break;
    case 0x10:
        move = true;
        prefix = state.group1 == 0xf2 ? PrefixForm::scalar_double : PrefixForm::scalar_single;
        operation = state.group1 == 0xf2 ? Opcode::movsd : Opcode::movss;
        memory_width = state.group1 == 0xf2 ? 64 : 32;
        break;
    case 0x11:
        move = true;
        store = true;
        prefix = state.group1 == 0xf2 ? PrefixForm::scalar_double : PrefixForm::scalar_single;
        operation = state.group1 == 0xf2 ? Opcode::movsd : Opcode::movss;
        memory_width = state.group1 == 0xf2 ? 64 : 32;
        break;
    case 0x58:
    case 0x5c:
    case 0x59:
    case 0x5e: {
        prefix = state.group1 == 0xf2 ? PrefixForm::scalar_double : PrefixForm::scalar_single;
        const bool is_double = state.group1 == 0xf2;
        memory_width = is_double ? 64 : 32;
        if (opcode == 0x58)
            operation = is_double ? Opcode::addsd : Opcode::addss;
        else if (opcode == 0x5c)
            operation = is_double ? Opcode::subsd : Opcode::subss;
        else if (opcode == 0x59)
            operation = is_double ? Opcode::mulsd : Opcode::mulss;
        else
            operation = is_double ? Opcode::divsd : Opcode::divss;
        break;
    }
    default: return false;
    }

    require_prefix(state, prefix);
    auto decoded = vector_modrm(state, memory_width);
    state.i.opcode = operation;
    if (move) {
        if (store) {
            state.operand(std::move(decoded.rm), OperandAccess::write);
            state.operand(decoded.reg, OperandAccess::read);
        } else {
            state.operand(decoded.reg, OperandAccess::write);
            state.operand(std::move(decoded.rm), OperandAccess::read);
        }
    } else {
        state.operand(decoded.reg, OperandAccess::read_write);
        state.operand(std::move(decoded.rm), OperandAccess::read);
    }
    return true;
}

bool vex_simd(State &state, std::uint8_t opcode, unsigned map, unsigned pp, unsigned vvvv, bool l, bool w) {
    if (map != 1 && map != 2)
        unsupported("VEX opcode map is outside the enabled AVX subset");
    const auto vector_width = static_cast<std::uint16_t>(l ? 256 : 128);
    const auto bank = l ? RegisterBank::ymm : RegisterBank::xmm;
    if (map == 1 && (opcode == 0x71 || opcode == 0x72 || opcode == 0x73)) {
        if (pp != 1)
            invalid("AVX2 immediate packed shifts require VEX.pp=66");
        auto decoded = modrm(state, vector_width, vector_width);
        Opcode operation{};
        if (opcode == 0x71) {
            if (decoded.group == 2) operation = Opcode::vpsrlw;
            else if (decoded.group == 4) operation = Opcode::vpsraw;
            else if (decoded.group == 6) operation = Opcode::vpsllw;
            else invalid("Reserved AVX2 immediate word-shift group");
        } else if (opcode == 0x72) {
            if (decoded.group == 2) operation = Opcode::vpsrld;
            else if (decoded.group == 4) operation = Opcode::vpsrad;
            else if (decoded.group == 6) operation = Opcode::vpslld;
            else invalid("Reserved AVX2 immediate dword-shift group");
        } else {
            if (decoded.group == 2) operation = Opcode::vpsrlq;
            else if (decoded.group == 3) operation = Opcode::vpsrldq;
            else if (decoded.group == 6) operation = Opcode::vpsllq;
            else if (decoded.group == 7) operation = Opcode::vpslldq;
            else invalid("Reserved AVX2 immediate qword/byte-shift group");
        }
        Operand source = std::move(decoded.rm);
        if (auto *reg = std::get_if<RegisterOperand>(&source)) {
            reg->bank = bank;
            reg->width = vector_width;
            reg->high_byte = false;
        } else if (auto *memory = std::get_if<MemoryOperand>(&source)) {
            memory->data_width = vector_width;
        }
        const RegisterOperand destination{bank, static_cast<std::uint8_t>(vvvv), vector_width, false};
        state.i.opcode = operation;
        state.i.vector_bits = vector_width;
        if (const auto shape = x86_avx_detail::immediate_shift_shape(operation))
            state.i.vector_element_bits = shape->result_bits;
        if (!l)
            state.i.register_writes.push_back({RegisterBank::ymm, destination.index, 256, false});
        state.operand(destination, OperandAccess::write);
        state.operand(std::move(source), OperandAccess::read);
        state.operand(state.immediate(8, 8, false), OperandAccess::read);
        return true;
    }
    const bool move = map == 1 && (opcode == 0x10 || opcode == 0x11);
    // Dispatch each opcode map independently: identical bytes in 0F and 0F38
    // do not describe interchangeable operations.
    std::optional<Opcode> integer_dataflow;
    if (map == 1) {
        switch (opcode) {
        case 0xdf: integer_dataflow = Opcode::vpandn; break;
        case 0xe0: integer_dataflow = Opcode::vpavgb; break;
        case 0xe3: integer_dataflow = Opcode::vpavgw; break;
        case 0xf4: integer_dataflow = Opcode::vpmuludq; break;
        case 0xf5: integer_dataflow = Opcode::vpmaddwd; break;
        case 0xf6: integer_dataflow = Opcode::vpsadbw; break;
        case 0x60: integer_dataflow = Opcode::vpunpcklbw; break;
        case 0x61: integer_dataflow = Opcode::vpunpcklwd; break;
        case 0x62: integer_dataflow = Opcode::vpunpckldq; break;
        case 0x6c: integer_dataflow = Opcode::vpunpcklqdq; break;
        case 0x68: integer_dataflow = Opcode::vpunpckhbw; break;
        case 0x69: integer_dataflow = Opcode::vpunpckhwd; break;
        case 0x6a: integer_dataflow = Opcode::vpunpckhdq; break;
        case 0x6d: integer_dataflow = Opcode::vpunpckhqdq; break;
        case 0x63: integer_dataflow = Opcode::vpacksswb; break;
        case 0x6b: integer_dataflow = Opcode::vpackssdw; break;
        case 0x67: integer_dataflow = Opcode::vpackuswb; break;
        default: break;
        }
    } else {
        switch (opcode) {
        case 0x00: integer_dataflow = Opcode::vpshufb; break;
        case 0x01: integer_dataflow = Opcode::vphaddw; break;
        case 0x02: integer_dataflow = Opcode::vphaddd; break;
        case 0x03: integer_dataflow = Opcode::vphaddsw; break;
        case 0x04: integer_dataflow = Opcode::vpmaddubsw; break;
        case 0x05: integer_dataflow = Opcode::vphsubw; break;
        case 0x06: integer_dataflow = Opcode::vphsubd; break;
        case 0x07: integer_dataflow = Opcode::vphsubsw; break;
        case 0x08: integer_dataflow = Opcode::vpsignb; break;
        case 0x09: integer_dataflow = Opcode::vpsignw; break;
        case 0x0a: integer_dataflow = Opcode::vpsignd; break;
        case 0x28: integer_dataflow = Opcode::vpmuldq; break;
        case 0x2b: integer_dataflow = Opcode::vpackusdw; break;
        case 0x38: integer_dataflow = Opcode::vpminsb; break;
        case 0x39: integer_dataflow = Opcode::vpminsd; break;
        case 0x3a: integer_dataflow = Opcode::vpminuw; break;
        case 0x3b: integer_dataflow = Opcode::vpminud; break;
        case 0x3c: integer_dataflow = Opcode::vpmaxsb; break;
        case 0x3d: integer_dataflow = Opcode::vpmaxsd; break;
        case 0x3e: integer_dataflow = Opcode::vpmaxuw; break;
        case 0x3f: integer_dataflow = Opcode::vpmaxud; break;
        case 0x40: integer_dataflow = Opcode::vpmulld; break;
        case 0x45: integer_dataflow = w ? Opcode::vpsrlvq : Opcode::vpsrlvd; break;
        case 0x46: integer_dataflow = Opcode::vpsravd; break; // VEX.W is ignored; qword form is EVEX-only.
        case 0x47: integer_dataflow = w ? Opcode::vpsllvq : Opcode::vpsllvd; break;
        case 0x29: case 0x37: break; // Existing qword comparisons below.
        default: unsupported("VEX 0F38 opcode is outside the enabled AVX2 subset");
        }
    }
    Opcode operation{};
    if (integer_dataflow) {
        if (pp != 1)
            invalid("Packed AVX2 integer dataflow requires VEX.pp=66");
        operation = *integer_dataflow;
    } else if (move) {
        if (pp != 0)
            invalid("VMOVUPS requires VEX.pp=0");
        if (vvvv != 0)
            invalid("VMOVUPS requires the reserved VEX.vvvv encoding");
        operation = Opcode::vmovups;
    } else {
        if (pp != 0 && pp != 1)
            invalid("Packed AVX floating operation has a reserved VEX.pp value");
        switch (opcode) {
        case 0x58: operation = pp == 0 ? Opcode::vaddps : Opcode::vaddpd; break;
        case 0x5c: operation = pp == 0 ? Opcode::vsubps : Opcode::vsubpd; break;
        case 0x59: operation = pp == 0 ? Opcode::vmulps : Opcode::vmulpd; break;
        case 0x5e:
            if (map != 1) return false;
            operation = pp == 0 ? Opcode::vdivps : Opcode::vdivpd;
            break;
        case 0x57: operation = pp == 0 ? Opcode::vxorps : Opcode::vxorpd; break;
        case 0x54: operation = pp == 0 ? Opcode::vandps : Opcode::vandpd; break;
        case 0x74:
            if (map != 1 || pp != 1) invalid("VPCMPEQB requires map 1 and VEX.pp=66");
            operation = Opcode::vpcmpeqb;
            break;
        case 0x75:
            if (map != 1 || pp != 1) invalid("VPCMPEQW requires map 1 and VEX.pp=66");
            operation = Opcode::vpcmpeqw;
            break;
        case 0x76:
            if (map != 1 || pp != 1) invalid("VPCMPEQD requires map 1 and VEX.pp=66");
            operation = Opcode::vpcmpeqd;
            break;
        case 0x29:
            if (map != 2) return false;
            if (pp != 1) invalid("VPCMPEQQ requires VEX.pp=66");
            operation = Opcode::vpcmpeqq;
            break;
        case 0x64:
            if (map != 1 || pp != 1) invalid("VPCMPGTB requires map 1 and VEX.pp=66");
            operation = Opcode::vpcmpgtb;
            break;
        case 0x65:
            if (map != 1 || pp != 1) invalid("VPCMPGTW requires map 1 and VEX.pp=66");
            operation = Opcode::vpcmpgtw;
            break;
        case 0x66:
            if (map != 1 || pp != 1) invalid("VPCMPGTD requires map 1 and VEX.pp=66");
            operation = Opcode::vpcmpgtd;
            break;
        case 0x37:
            if (map != 2) return false;
            if (pp != 1) invalid("VPCMPGTQ requires VEX.pp=66");
            operation = Opcode::vpcmpgtq;
            break;
        case 0xfc:
            if (pp != 1) invalid("Packed AVX integer operation requires VEX.pp=66");
            operation = Opcode::vpaddb;
            break;
        case 0xfd:
            if (pp != 1) invalid("Packed AVX integer operation requires VEX.pp=66");
            operation = Opcode::vpaddw;
            break;
        case 0xec:
            if (pp != 1) invalid("VPADDSB requires VEX.pp=66");
            operation = Opcode::vpaddsb;
            break;
        case 0xed:
            if (pp != 1) invalid("VPADDSW requires VEX.pp=66");
            operation = Opcode::vpaddsw;
            break;
        case 0xdc:
            if (pp != 1) invalid("VPADDUSB requires VEX.pp=66");
            operation = Opcode::vpaddusb;
            break;
        case 0xdd:
            if (pp != 1) invalid("VPADDUSW requires VEX.pp=66");
            operation = Opcode::vpaddusw;
            break;
        case 0xfe:
            if (pp != 1) invalid("Packed AVX integer operation requires VEX.pp=66");
            operation = Opcode::vpaddd;
            break;
        case 0xd4:
            if (pp != 1) invalid("Packed AVX integer operation requires VEX.pp=66");
            operation = Opcode::vpaddq;
            break;
        case 0xdb:
            if (pp != 1) invalid("Packed AVX integer operation requires VEX.pp=66");
            operation = Opcode::vpand;
            break;
        case 0xeb:
            if (pp != 1) invalid("Packed AVX integer operation requires VEX.pp=66");
            operation = Opcode::vpor;
            break;
        case 0xef:
            if (pp != 1) invalid("Packed AVX integer operation requires VEX.pp=66");
            operation = Opcode::vpxor;
            break;
        case 0xf8:
            if (pp != 1) invalid("Packed AVX2 integer operation requires VEX.pp=66");
            operation = Opcode::vpsubb;
            break;
        case 0xf9:
            if (pp != 1) invalid("Packed AVX2 integer operation requires VEX.pp=66");
            operation = Opcode::vpsubw;
            break;
        case 0xfa:
            if (pp != 1) invalid("Packed AVX2 integer operation requires VEX.pp=66");
            operation = Opcode::vpsubd;
            break;
        case 0xfb:
            if (pp != 1) invalid("Packed AVX2 integer operation requires VEX.pp=66");
            operation = Opcode::vpsubq;
            break;
        case 0xe8:
            if (pp != 1) invalid("VPSUBSB requires VEX.pp=66");
            operation = Opcode::vpsubsb;
            break;
        case 0xe9:
            if (pp != 1) invalid("VPSUBSW requires VEX.pp=66");
            operation = Opcode::vpsubsw;
            break;
        case 0xd8:
            if (pp != 1) invalid("VPSUBUSB requires VEX.pp=66");
            operation = Opcode::vpsubusb;
            break;
        case 0xd9:
            if (pp != 1) invalid("VPSUBUSW requires VEX.pp=66");
            operation = Opcode::vpsubusw;
            break;
        case 0xda:
            if (pp != 1) invalid("VPMINUB requires VEX.pp=66");
            operation = Opcode::vpminub;
            break;
        case 0xea:
            if (pp != 1) invalid("VPMINSW requires VEX.pp=66");
            operation = Opcode::vpminsw;
            break;
        case 0xde:
            if (pp != 1) invalid("VPMAXUB requires VEX.pp=66");
            operation = Opcode::vpmaxub;
            break;
        case 0xee:
            if (pp != 1) invalid("VPMAXSW requires VEX.pp=66");
            operation = Opcode::vpmaxsw;
            break;
        case 0xd5:
            if (pp != 1) invalid("VPMULLW requires VEX.pp=66");
            operation = Opcode::vpmullw;
            break;
        case 0xe5:
            if (pp != 1) invalid("VPMULHW requires VEX.pp=66");
            operation = Opcode::vpmulhw;
            break;
        case 0xe4:
            if (pp != 1) invalid("VPMULHUW requires VEX.pp=66");
            operation = Opcode::vpmulhuw;
            break;
        default: return false;
        }
    }
    if (map == 1 && (opcode == 0x10 || opcode == 0x11) && pp != 0)
        invalid("VMOVUPS requires VEX.pp=0");
    auto decoded = modrm(state, vector_width, vector_width);
    auto dst = decoded.reg;
    dst.bank = bank;
    dst.width = vector_width;
    Operand rm = std::move(decoded.rm);
    if (auto *reg = std::get_if<RegisterOperand>(&rm)) {
        reg->bank = bank;
        reg->width = vector_width;
    } else if (auto *memory = std::get_if<MemoryOperand>(&rm)) {
        memory->data_width = vector_width;
    }
    // VEX.128 destinations clear bits 255:128 of the physical YMM register.
    // Keep the legacy XMM write from the explicit operand and add the full
    // YMM definition so the lifted effect can model both architectural views.
    if (!l) {
        const auto *written_register = opcode == 0x11 ? std::get_if<RegisterOperand>(&rm) : &dst;
        if (written_register)
            state.i.register_writes.push_back(
                {RegisterBank::ymm, written_register->index, 256, false});
    }
    state.i.opcode = operation;
    state.i.vector_bits = vector_width;
    if (operation == Opcode::vaddps || operation == Opcode::vaddpd ||
        operation == Opcode::vsubps || operation == Opcode::vsubpd ||
        operation == Opcode::vmulps || operation == Opcode::vmulpd ||
        operation == Opcode::vdivps || operation == Opcode::vdivpd) {
        // Packed FP operations depend on MXCSR controls and update sticky
        // exception flags; retain the whole register until bit-level effects
        // are modeled.
        constexpr RegisterOperand mxcsr{RegisterBank::mxcsr, 0, 32, false};
        state.i.register_reads.push_back(mxcsr);
        state.i.register_writes.push_back(mxcsr);
    }
    if (const auto shape = x86_avx_detail::integer_dataflow_shape(operation))
        state.i.vector_element_bits = shape->result_bits;
    if (move && opcode == 0x11) {
        state.operand(std::move(rm), OperandAccess::write);
        state.operand(dst, OperandAccess::read);
    } else {
        state.operand(dst, OperandAccess::write);
        if (!move)
            state.operand(RegisterOperand{bank, static_cast<std::uint8_t>(vvvv), vector_width, false}, OperandAccess::read);
        state.operand(std::move(rm), OperandAccess::read);
    }
    return true;
}

bool evex_simd(State &state, std::uint8_t opcode, unsigned map, unsigned pp, unsigned vvvv, bool w,
               unsigned vector_bits, unsigned mask, bool zeroing, bool reg_high, bool rm_high, bool broadcast) {
    if (map != 1 && map != 2 && map != 3)
        unsupported("EVEX opcode map is outside the enabled AVX-512 subset");
    if (vector_bits != 128 && vector_bits != 256 && vector_bits != 512)
        unsupported("EVEX vector length is outside the modeled 128/256/512-bit forms");
    if (broadcast)
        unsupported("EVEX broadcast and embedded-rounding forms are not covered");
    if (zeroing && mask == 0)
        invalid("EVEX zeroing requires a nonzero opmask register");

    if (map == 3) {
        if (opcode != 0x1e && opcode != 0x1f && opcode != 0x3e && opcode != 0x3f)
            return false;
        if (pp != 1)
            invalid("EVEX VPCMP requires pp=66");
        if (zeroing)
            unsupported("EVEX VPCMP does not model the EVEX.z encoding");
        auto decoded = modrm(state, static_cast<std::uint16_t>(vector_bits), 64);
        // ModRM.reg addresses K0-K7; neither R nor R' extends this field.
        if (reg_high || decoded.reg.index >= 8)
            invalid("EVEX VPCMP destination must encode K0-K7 without register extension");
        const auto vector_bank = vector_bits == 128 ? RegisterBank::xmm :
                                 vector_bits == 256 ? RegisterBank::ymm : RegisterBank::zmm;
        Operand rm = std::move(decoded.rm);
        if (auto *reg = std::get_if<RegisterOperand>(&rm)) {
            reg->bank = vector_bank;
            reg->width = static_cast<std::uint16_t>(vector_bits);
            reg->high_byte = false;
            if (rm_high)
                reg->index = static_cast<std::uint8_t>(reg->index + 16);
        } else if (auto *memory = std::get_if<MemoryOperand>(&rm)) {
            memory->data_width = static_cast<std::uint16_t>(vector_bits);
            if (memory->displacement_encoding && memory->displacement_encoding->size == 1)
                memory->displacement *= static_cast<std::int64_t>(vector_bits / 8);
        }
        const auto predicate = state.immediate(8, 8, false);
        if (predicate.value > 7)
            invalid("EVEX VPCMP immediate has reserved upper predicate bits");
        const bool words = (opcode & 0x20) != 0;
        const bool is_unsigned = (opcode & 1) == 0;
        state.i.opcode = words ? (w ? (is_unsigned ? Opcode::vpcmpuw : Opcode::vpcmpw)
                                    : (is_unsigned ? Opcode::vpcmpub : Opcode::vpcmpb))
                               : (w ? (is_unsigned ? Opcode::vpcmpuq : Opcode::vpcmpq)
                                    : (is_unsigned ? Opcode::vpcmpud : Opcode::vpcmpd));
        state.i.x86_evex = true;
        state.i.vector_bits = static_cast<std::uint16_t>(vector_bits);
        state.i.vector_element_bits = words ? (w ? 16 : 8) : (w ? 64 : 32);
        if (mask) {
            state.i.x86_opmask = static_cast<std::uint8_t>(mask);
            state.i.register_reads.push_back({RegisterBank::opmask, static_cast<std::uint8_t>(mask), 64, false});
        }
        state.operand(RegisterOperand{RegisterBank::opmask, decoded.reg.index, 64, false}, OperandAccess::write);
        state.operand(RegisterOperand{vector_bank, static_cast<std::uint8_t>(vvvv),
                                      static_cast<std::uint16_t>(vector_bits), false}, OperandAccess::read);
        state.operand(std::move(rm), OperandAccess::read);
        state.operand(predicate, OperandAccess::read);
        return true;
    }

    const bool move_load = map == 1 && opcode == 0x10;
    const bool move_store = map == 1 && opcode == 0x11;
    Opcode operation{};
    std::optional<Opcode> integer_operation;
    // Full-vector, non-broadcast tuples only. A missing required_w means WIG;
    // W-selected qword min/max and low-qword multiply are deliberately absent.
    std::optional<bool> required_w;
    if (map == 1) switch (opcode) {
    case 0xfc: integer_operation=Opcode::vpaddb; break;
    case 0xfd: integer_operation=Opcode::vpaddw; break;
    case 0xfe: integer_operation=Opcode::vpaddd; required_w=false; break;
    case 0xd4: integer_operation=Opcode::vpaddq; required_w=true; break;
    case 0xf8: integer_operation=Opcode::vpsubb; break;
    case 0xf9: integer_operation=Opcode::vpsubw; break;
    case 0xfa: integer_operation=Opcode::vpsubd; required_w=false; break;
    case 0xfb: integer_operation=Opcode::vpsubq; required_w=true; break;
    case 0xec: integer_operation=Opcode::vpaddsb; break;
    case 0xed: integer_operation=Opcode::vpaddsw; break;
    case 0xdc: integer_operation=Opcode::vpaddusb; break;
    case 0xdd: integer_operation=Opcode::vpaddusw; break;
    case 0xe8: integer_operation=Opcode::vpsubsb; break;
    case 0xe9: integer_operation=Opcode::vpsubsw; break;
    case 0xd8: integer_operation=Opcode::vpsubusb; break;
    case 0xd9: integer_operation=Opcode::vpsubusw; break;
    case 0x63: integer_operation=Opcode::vpacksswb; break;
    case 0x67: integer_operation=Opcode::vpackuswb; break;
    case 0x6b: integer_operation=Opcode::vpackssdw; required_w=false; break;
    case 0xda: integer_operation=Opcode::vpminub; break;
    case 0xea: integer_operation=Opcode::vpminsw; break;
    case 0xde: integer_operation=Opcode::vpmaxub; break;
    case 0xee: integer_operation=Opcode::vpmaxsw; break;
    case 0xe0: integer_operation=Opcode::vpavgb; break;
    case 0xe3: integer_operation=Opcode::vpavgw; break;
    case 0xd5: integer_operation=Opcode::vpmullw; break;
    case 0xe5: integer_operation=Opcode::vpmulhw; break;
    case 0xe4: integer_operation=Opcode::vpmulhuw; break;
    case 0xdb: integer_operation=w ? Opcode::vpandq : Opcode::vpandd; break;
    case 0xeb: integer_operation=w ? Opcode::vporq : Opcode::vpord; break;
    case 0xef: integer_operation=w ? Opcode::vpxorq : Opcode::vpxord; break;
    case 0xf4: integer_operation=Opcode::vpmuludq; required_w=true; break;
    case 0xf5: integer_operation=Opcode::vpmaddwd; break;
    default: break;
    }
    else switch (opcode) {
    case 0x10: integer_operation=Opcode::vpsrlvw; required_w=false; break;
    case 0x11: integer_operation=Opcode::vpsravw; required_w=false; break;
    case 0x12: integer_operation=Opcode::vpsllvw; required_w=false; break;
    case 0x45: integer_operation=w ? Opcode::vpsrlvq : Opcode::vpsrlvd; required_w=w; break;
    case 0x46: integer_operation=w ? Opcode::vpsravq : Opcode::vpsravd; required_w=w; break;
    case 0x47: integer_operation=w ? Opcode::vpsllvq : Opcode::vpsllvd; required_w=w; break;
    case 0x04: integer_operation=Opcode::vpmaddubsw; break;
    case 0x28: integer_operation=Opcode::vpmuldq; required_w=true; break;
    case 0x2b: integer_operation=Opcode::vpackusdw; required_w=false; break;
    case 0x38: integer_operation=Opcode::vpminsb; break;
    case 0x39: integer_operation=Opcode::vpminsd; required_w=false; break;
    case 0x3a: integer_operation=Opcode::vpminuw; break;
    case 0x3b: integer_operation=Opcode::vpminud; required_w=false; break;
    case 0x3c: integer_operation=Opcode::vpmaxsb; break;
    case 0x3d: integer_operation=Opcode::vpmaxsd; required_w=false; break;
    case 0x3e: integer_operation=Opcode::vpmaxuw; break;
    case 0x3f: integer_operation=Opcode::vpmaxud; required_w=false; break;
    case 0x40: integer_operation=Opcode::vpmulld; required_w=false; break;
    default: break;
    }
    std::optional<x86_avx_detail::IntegerDataflowShape> integer_shape;
    if (move_load || move_store) {
        if (pp != 0 || w)
            invalid("EVEX VMOVUPS requires map 1, pp=0, and W=0");
        // The reserved encoded all-ones vvvv/V' fields decode to zero.
        if (vvvv != 0)
            invalid("EVEX VMOVUPS requires the reserved vvvv and V' encoding");
        if (move_store && zeroing)
            invalid("EVEX VMOVUPS stores do not support zeroing masking");
        operation = Opcode::vmovups;
    } else if (integer_operation) {
        if (pp != 1)
            invalid("EVEX packed integer operations require pp=66");
        if (required_w && w != *required_w)
            unsupported("EVEX W-selected packed integer form is outside the enabled subset");
        operation = *integer_operation;
        integer_shape = x86_avx_detail::evex_integer_shape(operation);
        if (!integer_shape) unsupported("EVEX packed integer result shape is not modeled");
    } else {
        if (map != 1 || (opcode != 0x58 && opcode != 0x5c && opcode != 0x59 && opcode != 0x5e))
            return false;
        if (pp == 0 && !w)
            operation = opcode == 0x58 ? Opcode::vaddps : opcode == 0x5c ? Opcode::vsubps :
                        opcode == 0x59 ? Opcode::vmulps : Opcode::vdivps;
        else if (pp == 1 && w)
            operation = opcode == 0x58 ? Opcode::vaddpd : opcode == 0x5c ? Opcode::vsubpd :
                        opcode == 0x59 ? Opcode::vmulpd : Opcode::vdivpd;
        else
            invalid("EVEX packed floating arithmetic has an unsupported pp/W combination");
    }

    auto decoded = modrm(state, static_cast<std::uint16_t>(vector_bits), static_cast<std::uint16_t>(vector_bits));
    const auto vector_bank = vector_bits == 128 ? RegisterBank::xmm :
                             vector_bits == 256 ? RegisterBank::ymm : RegisterBank::zmm;
    auto vector_register = [&](RegisterOperand reg) {
        reg.bank = vector_bits == 128 ? RegisterBank::xmm :
                   vector_bits == 256 ? RegisterBank::ymm : RegisterBank::zmm;
        reg.width = static_cast<std::uint16_t>(vector_bits);
        reg.high_byte = false;
        return reg;
    };
    auto destination = vector_register(decoded.reg);
    if (reg_high)
        destination.index = static_cast<std::uint8_t>(destination.index + 16);
    Operand rm = std::move(decoded.rm);
    if (auto *reg = std::get_if<RegisterOperand>(&rm)) {
        *reg = vector_register(*reg);
        if (rm_high)
            reg->index = static_cast<std::uint8_t>(reg->index + 16);
    } else if (auto *memory = std::get_if<MemoryOperand>(&rm)) {
        memory->data_width = static_cast<std::uint16_t>(vector_bits);
        // All currently accepted EVEX forms use a full-width, non-broadcast
        // tuple; compressed disp8 therefore scales by the vector size.
        if (memory->displacement_encoding && memory->displacement_encoding->size == 1)
            memory->displacement *= static_cast<std::int64_t>(vector_bits / 8);
    }

    state.i.opcode = operation;
    state.i.x86_evex = true;
    state.i.vector_bits = static_cast<std::uint16_t>(vector_bits);
    auto add_upper_zero_writes = [&](RegisterOperand reg) {
        if (vector_bits == 128)
            state.i.register_writes.push_back({RegisterBank::ymm, reg.index, 256, false});
        if (vector_bits < 512)
            state.i.register_writes.push_back({RegisterBank::zmm, reg.index, 512, false});
    };
    if (mask) {
        state.i.x86_opmask = static_cast<std::uint8_t>(mask);
        state.i.x86_opmask_zeroing = zeroing;
        state.i.register_reads.push_back({RegisterBank::opmask, static_cast<std::uint8_t>(mask), 64, false});
    }

    if (move_load) {
        state.operand(destination, mask && !zeroing ? OperandAccess::read_write : OperandAccess::write);
        add_upper_zero_writes(destination);
        state.operand(std::move(rm), OperandAccess::read);
        return true;
    }
    if (move_store) {
        if (auto *reg = std::get_if<RegisterOperand>(&rm)) {
            state.operand(*reg, mask ? OperandAccess::read_write : OperandAccess::write);
            add_upper_zero_writes(*reg);
        } else
            state.operand(std::move(rm), OperandAccess::write);
        state.operand(destination, OperandAccess::read);
        return true;
    }

    if (integer_shape) {
        state.i.vector_element_bits = integer_shape->result_bits;
        state.operand(destination, mask && !zeroing ? OperandAccess::read_write : OperandAccess::write);
        add_upper_zero_writes(destination);
        state.operand(RegisterOperand{vector_bank, static_cast<std::uint8_t>(vvvv), static_cast<std::uint16_t>(vector_bits), false},
                      OperandAccess::read);
        state.operand(std::move(rm), OperandAccess::read);
        return true;
    }

    state.i.vector_element_bits = (operation == Opcode::vaddps || operation == Opcode::vsubps ||
                                   operation == Opcode::vmulps || operation == Opcode::vdivps) ? 32 : 64;
    constexpr RegisterOperand mxcsr{RegisterBank::mxcsr, 0, 32, false};
    state.i.register_reads.push_back(mxcsr);
    state.i.register_writes.push_back(mxcsr);
    state.operand(destination, mask && !zeroing ? OperandAccess::read_write : OperandAccess::write);
    add_upper_zero_writes(destination);
    state.operand(RegisterOperand{vector_bank, static_cast<std::uint8_t>(vvvv), static_cast<std::uint16_t>(vector_bits), false},
                  OperandAccess::read);
    state.operand(std::move(rm), OperandAccess::read);
    return true;
}
} // namespace hexlab::x64_detail
