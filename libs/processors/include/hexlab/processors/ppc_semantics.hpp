#pragma once

#include "hexlab/processors/instruction.hpp"
#include "hexlab/processors/processors_export.hpp"
#include <array>
#include <cstdint>
#include <optional>

namespace hexlab {

// Vector bytes are in architectural register order: byte 0 is the most
// significant byte of the 128-bit VMX register, independent of file byte order.
using PpcVectorBits = std::array<std::uint8_t, 16>;

// Evaluates the decoded VMX wrapping add/subtract and logical integer forms.
// Add/subtract lanes are interpreted big-endian within each architectural
// lane, and arithmetic wraps modulo the lane width. Unknown opcodes return no
// value.
HEXLAB_PROCESSORS_EXPORT std::optional<PpcVectorBits>
evaluate_ppc_vmx_integer_operation(Opcode opcode, const PpcVectorBits &va,
                                   const PpcVectorBits &vb) noexcept;

} // namespace hexlab
