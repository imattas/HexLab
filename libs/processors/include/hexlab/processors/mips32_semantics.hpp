#pragma once

#include "hexlab/processors/instruction.hpp"
#include "hexlab/processors/processors_export.hpp"
#include <cstdint>
#include <optional>

namespace hexlab {

enum class Mips32HiLoOperation { mult, multu, div, divu };

struct Mips32HiLoResult {
    std::uint32_t hi = 0;
    std::uint32_t lo = 0;
    bool operator==(const Mips32HiLoResult &) const = default;
};

// Evaluate one MIPS32 MULT/MULTU/DIV/DIVU operation from GPR bit patterns.
// Division by zero and signed quotient overflow return no result because the
// architecture leaves those HI/LO values unpredictable/undefined.
HEXLAB_PROCESSORS_EXPORT std::optional<Mips32HiLoResult>
evaluate_mips32_hilo(Mips32HiLoOperation operation, std::uint32_t lhs, std::uint32_t rhs) noexcept;

// Exact bounded single-precision DIV.S result for gradual-underflow mode
// (FCSR.FS=0). exception_bits uses canonical IEEE order I/U/O/Z/V in bits
// 0..4. fcsr_after applies the MIPS Cause replacement and sticky Flag rules;
// an enabled exception suppresses both flag accrual and the destination write.
struct Mips32DivSResult {
    std::uint32_t value_bits = 0;
    std::uint32_t fcsr_after = 0;
    std::uint8_t exception_bits = 0;
    bool exception_taken = false;
    bool writes_destination = true;
    bool operator==(const Mips32DivSResult &) const = default;
};

// Operands are IEEE binary32 bit patterns. FCSR RM, enable, cause, and flag
// fields are interpreted architecturally. Returns no value when FCSR.FS is
// set, because flush-subnormal behavior is not modeled by this evaluator.
HEXLAB_PROCESSORS_EXPORT std::optional<Mips32DivSResult>
evaluate_mips32_div_s(std::uint32_t lhs_bits, std::uint32_t rhs_bits, std::uint32_t fcsr) noexcept;

enum class Mips32FpSignOperation { abs, mov, neg };

// Evaluate the bit-exact MIPS32 COP1 ABS/MOV/NEG operation for an S or D
// operand. Single-precision inputs and results use the low 32 bits. These
// operations only alter or preserve the sign bit and do not update FCSR.
HEXLAB_PROCESSORS_EXPORT std::uint64_t
evaluate_mips32_fp_sign_operation(Mips32FpSignOperation operation, bool double_precision,
                                 std::uint64_t operand_bits) noexcept;

} // namespace hexlab
