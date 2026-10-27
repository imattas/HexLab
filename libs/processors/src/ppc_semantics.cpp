#include "hexlab/processors/ppc_semantics.hpp"

namespace hexlab {

std::optional<PpcVectorBits> evaluate_ppc_vmx_integer_operation(Opcode opcode,
                                                               const PpcVectorBits &va,
                                                               const PpcVectorBits &vb) noexcept {
    switch (opcode) {
    case Opcode::ppc_vand:
    case Opcode::ppc_vandc:
    case Opcode::ppc_vor:
    case Opcode::ppc_vxor:
    case Opcode::ppc_vnor: {
        PpcVectorBits result{};
        for (std::size_t i = 0; i < result.size(); ++i) {
            switch (opcode) {
            case Opcode::ppc_vand: result[i] = va[i] & vb[i]; break;
            case Opcode::ppc_vandc: result[i] = va[i] & static_cast<std::uint8_t>(~vb[i]); break;
            case Opcode::ppc_vor: result[i] = va[i] | vb[i]; break;
            case Opcode::ppc_vxor: result[i] = va[i] ^ vb[i]; break;
            case Opcode::ppc_vnor: result[i] = static_cast<std::uint8_t>(~(va[i] | vb[i])); break;
            default: break;
            }
        }
        return result;
    }
    default: break;
    }

    unsigned lane_bits = 0;
    bool subtract = false;
    switch (opcode) {
    case Opcode::ppc_vaddubm: lane_bits = 8; break;
    case Opcode::ppc_vadduhm: lane_bits = 16; break;
    case Opcode::ppc_vadduwm: lane_bits = 32; break;
    case Opcode::ppc_vsububm: lane_bits = 8; subtract = true; break;
    case Opcode::ppc_vsubuhm: lane_bits = 16; subtract = true; break;
    case Opcode::ppc_vsubuwm: lane_bits = 32; subtract = true; break;
    default: return {};
    }

    PpcVectorBits result{};
    const unsigned lane_bytes = lane_bits / 8;
    const std::uint64_t mask = (UINT64_C(1) << lane_bits) - 1;
    for (unsigned offset = 0; offset < result.size(); offset += lane_bytes) {
        std::uint64_t a = 0, b = 0;
        for (unsigned byte = 0; byte < lane_bytes; ++byte) {
            a = (a << 8) | va[offset + byte];
            b = (b << 8) | vb[offset + byte];
        }
        const auto lane = (subtract ? a - b : a + b) & mask;
        for (unsigned byte = 0; byte < lane_bytes; ++byte)
            result[offset + lane_bytes - 1 - byte] = static_cast<std::uint8_t>(lane >> (byte * 8));
    }
    return result;
}

} // namespace hexlab
