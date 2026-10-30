#pragma once

#include "hexlab/image/image.hpp"
#include "hexlab/processors/instruction.hpp"

#include <algorithm>
#include <optional>
#include <utility>

namespace hexlab::reference_detail {

// Call and REGIMM link branches write the address after their classic delay
// slot. Retain that PC value only when representable in the image's address
// space and pointing to initialized executable code.
inline std::optional<std::pair<std::uint8_t, Address>> mips64_link_value(
    const Image &image, const Instruction &instruction) {
    if (instruction.context.architecture != Architecture::mips64 ||
        instruction.context.mode != ExecutionMode::mips64 || instruction.address.offset > UINT64_MAX - 8)
        return {};

    const bool regimm_link = instruction.opcode == Opcode::mips64_bltzal ||
        instruction.opcode == Opcode::mips64_bgezal || instruction.opcode == Opcode::mips64_bltzall ||
        instruction.opcode == Opcode::mips64_bgezall;
    const bool jump_link = instruction.opcode == Opcode::mips_jal || instruction.opcode == Opcode::mips_jalr ||
        instruction.opcode == Opcode::mips64_jalr_hb;
    if (!regimm_link && !jump_link)
        return {};
    std::optional<std::uint8_t> destination;
    for (const auto &written : instruction.register_writes)
        if (written.bank == RegisterBank::mips_gpr && written.index != 0 && written.width == 64) {
            if (destination) return {}; // Malformed multiple-link write: keep it unknown.
            destination = written.index;
        }
    if (!destination || (regimm_link && *destination != 31))
        return {};

    const auto *space = image.space(instruction.address.space);
    if (!space || (space->width_bits != 32 && space->width_bits != 64))
        return {};
    const auto offset = instruction.address.offset + 8;
    if (space->width_bits == 32 && offset > UINT32_MAX)
        return {};
    const Address target{instruction.address.space, offset};
    const auto *segment = image.segment_at(target);
    if (!segment || !segment->executable || target.offset < segment->begin.offset)
        return {};
    const auto relative = target.offset - segment->begin.offset;
    if (relative > segment->file_size || 4 > segment->file_size - relative)
        return {};
    return std::pair{*destination, target};
}

} // namespace hexlab::reference_detail
