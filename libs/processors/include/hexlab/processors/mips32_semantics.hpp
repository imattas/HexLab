#pragma once

#include "hexlab/processors/instruction.hpp"
#include "hexlab/processors/processors_export.hpp"
#include <cstdint>
#include <optional>

namespace hexlab {

enum class Mips32HiLoOperation { mult, multu, div, divu };

// MIPS32 SPECIAL2 MUL returns the low word of the 32x32-bit product. Signed
// and unsigned products have identical low-word bits modulo 2^32.
HEXLAB_PROCESSORS_EXPORT std::uint32_t
evaluate_mips32_mul_low(std::uint32_t lhs_bits, std::uint32_t rhs_bits) noexcept;

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

struct Mips32HiLoMoveResult {
    std::uint32_t hi = 0;
    std::uint32_t lo = 0;
    std::uint32_t gpr_value = 0;
    bool writes_hi = false;
    bool writes_lo = false;
    bool writes_gpr = false;
    bool operator==(const Mips32HiLoMoveResult &) const = default;
};

// Evaluate decoded MFHI/MFLO/MTHI/MTLO register transfers.
HEXLAB_PROCESSORS_EXPORT std::optional<Mips32HiLoMoveResult>
evaluate_mips32_hilo_move_instruction(const Instruction &instruction,
                                      std::uint32_t hi, std::uint32_t lo,
                                      std::uint32_t gpr_value = 0) noexcept;

// Exact bounded single-precision DIV.S result. exception_bits uses canonical
// IEEE order I/U/O/Z/V in bits
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

// Operands are IEEE binary32 bit patterns. FCSR RM, enable, cause, flag, and
// FS fields are interpreted architecturally. FS follows Release 5+ input
// flushing and alternate flush-to-zero underflow handling.
HEXLAB_PROCESSORS_EXPORT std::optional<Mips32DivSResult>
evaluate_mips32_div_s(std::uint32_t lhs_bits, std::uint32_t rhs_bits, std::uint32_t fcsr) noexcept;

// Bind the exact DIV.S evaluator to the decoder's COP1 operand and FCSR facts.
// Callers still supply the FPR/FCSR values and commit the returned state.
HEXLAB_PROCESSORS_EXPORT std::optional<Mips32DivSResult>
evaluate_mips32_div_s_instruction(const Instruction &instruction,
                                  std::uint32_t lhs_bits, std::uint32_t rhs_bits,
                                  std::uint32_t fcsr) noexcept;

enum class Mips32SArithmeticOperation { add, subtract, multiply };

struct Mips32ArithmeticSResult {
    std::uint32_t value_bits = 0;
    std::uint32_t fcsr_after = 0;
    std::uint8_t exception_bits = 0;
    bool exception_taken = false;
    bool writes_destination = true;
    bool operator==(const Mips32ArithmeticSResult &) const = default;
};

// Exact binary32 ADD.S/SUB.S/MUL.S for finite operands. Addition and
// subtraction conservatively return no result when the exact operand
// significands cannot be represented together in binary64. NaN/Infinity
// propagation is also left to the caller. FCSR rounding, FS input/output
// flushing, exception causes/flags/enables, and destination suppression are
// modeled for returned results.
HEXLAB_PROCESSORS_EXPORT std::optional<Mips32ArithmeticSResult>
evaluate_mips32_arithmetic_s(Mips32SArithmeticOperation operation,
                             std::uint32_t lhs_bits, std::uint32_t rhs_bits,
                             std::uint32_t fcsr) noexcept;

// Validate and bind the arithmetic evaluator to decoded MIPS32 COP1 effects.
HEXLAB_PROCESSORS_EXPORT std::optional<Mips32ArithmeticSResult>
evaluate_mips32_arithmetic_s_instruction(const Instruction &instruction,
                                         std::uint32_t lhs_bits, std::uint32_t rhs_bits,
                                         std::uint32_t fcsr) noexcept;

// Evaluate BC1T/F and likely variants from the selected caller-supplied FCC
// value. The branch target and delay-slot execution remain caller-owned.
HEXLAB_PROCESSORS_EXPORT std::optional<bool>
evaluate_mips32_fcc_branch_instruction(const Instruction &instruction,
                                      bool condition_code_value) noexcept;

// Evaluate classic MIPS32 integer conditional branches from caller-supplied
// GPR bit patterns. The adapter validates delay-slot and decoded operand facts.
HEXLAB_PROCESSORS_EXPORT std::optional<bool>
evaluate_mips32_integer_branch_instruction(const Instruction &instruction,
                                           std::uint32_t lhs, std::uint32_t rhs = 0) noexcept;

struct Mips32AddImmediateResult {
    std::uint32_t value = 0;
    bool overflow_exception = false;
    bool writes_destination = false;
    bool operator==(const Mips32AddImmediateResult &) const = default;
};

// Evaluate decoded ADDI/ADDIU. ADDI reports signed overflow; ADDIU wraps
// modulo 2^32. Writes to $zero are suppressed.
HEXLAB_PROCESSORS_EXPORT std::optional<Mips32AddImmediateResult>
evaluate_mips32_add_immediate_instruction(const Instruction &instruction,
                                          std::uint32_t source) noexcept;

struct Mips32AddSubResult {
    std::uint32_t value = 0;
    bool overflow_exception = false;
    bool writes_destination = false;
    bool operator==(const Mips32AddSubResult &) const = default;
};

// Evaluate decoded R-type ADD/ADDU/SUB/SUBU. Trapping forms report overflow;
// unsigned forms wrap modulo 2^32.
HEXLAB_PROCESSORS_EXPORT std::optional<Mips32AddSubResult>
evaluate_mips32_add_sub_instruction(const Instruction &instruction,
                                    std::uint32_t lhs, std::uint32_t rhs) noexcept;

// Evaluate decoded SLTI/SLTIU. Both use the sign-extended immediate; the
// opcode selects signed or unsigned comparison of the two 32-bit values.
HEXLAB_PROCESSORS_EXPORT std::optional<std::uint32_t>
evaluate_mips32_set_less_than_immediate_instruction(const Instruction &instruction,
                                                    std::uint32_t source) noexcept;

// Evaluate decoded R-type SLT/SLTU from caller-supplied source GPR values.
HEXLAB_PROCESSORS_EXPORT std::optional<std::uint32_t>
evaluate_mips32_set_less_than_instruction(const Instruction &instruction,
                                          std::uint32_t lhs, std::uint32_t rhs) noexcept;

// Evaluate decoded R-type AND/OR/XOR/NOR on caller-supplied GPR values.
HEXLAB_PROCESSORS_EXPORT std::optional<std::uint32_t>
evaluate_mips32_logical_instruction(const Instruction &instruction,
                                    std::uint32_t lhs, std::uint32_t rhs) noexcept;

struct Mips32LogicalImmediateResult {
    std::uint32_t value = 0;
    bool writes_destination = false;
    bool operator==(const Mips32LogicalImmediateResult &) const = default;
};

// Evaluate decoded ANDI/ORI/XORI. Their 16-bit immediates are zero-extended.
HEXLAB_PROCESSORS_EXPORT std::optional<Mips32LogicalImmediateResult>
evaluate_mips32_logical_immediate_instruction(const Instruction &instruction,
                                              std::uint32_t source) noexcept;

struct Mips32MergeLoadResult {
    std::uint32_t value = 0;
    bool writes_destination = false;
    bool operator==(const Mips32MergeLoadResult &) const = default;
};

// Evaluate decoded LWL/LWR from the aligned memory word and prior rt value.
// The aligned word is an integer decoded using the instruction's byte order;
// address_offset is the effective address's low two bits.
HEXLAB_PROCESSORS_EXPORT std::optional<Mips32MergeLoadResult>
evaluate_mips32_merge_load_instruction(const Instruction &instruction,
                                       std::uint32_t aligned_memory_word,
                                       std::uint32_t prior_gpr,
                                       std::uint8_t address_offset) noexcept;

// Evaluate decoded SPECIAL3 EXT/INS from caller-supplied source and prior
// destination GPR values. The decoder's position/size immediates are checked.
HEXLAB_PROCESSORS_EXPORT std::optional<std::uint32_t>
evaluate_mips32_bitfield_instruction(const Instruction &instruction,
                                     std::uint32_t source,
                                     std::uint32_t prior_destination = 0) noexcept;

// Evaluate MIPS32 SPECIAL2 CLZ/CLO on a source GPR bit pattern. The decoded
// adapter checks register facts and treats $zero as the architectural zero.
HEXLAB_PROCESSORS_EXPORT std::optional<std::uint32_t>
evaluate_mips32_count_leading(Opcode opcode, std::uint32_t source) noexcept;
HEXLAB_PROCESSORS_EXPORT std::optional<std::uint32_t>
evaluate_mips32_count_leading_instruction(const Instruction &instruction,
                                          std::uint32_t source) noexcept;

// Evaluate MIPS32 fixed and variable word shifts from caller-supplied GPR
// values. Variable amounts use the low five bits of the amount register.
HEXLAB_PROCESSORS_EXPORT std::optional<std::uint32_t>
evaluate_mips32_shift_instruction(const Instruction &instruction,
                                  std::uint32_t source,
                                  std::uint32_t amount_value = 0) noexcept;

enum class Mips32WordRounding { nearest_even, toward_zero, toward_positive, toward_negative };

struct Mips32WordConversionResult {
    // Signed 32-bit integer result encoded in the low word of the FPR value.
    std::uint32_t value_bits = 0;
    std::uint32_t fcsr_after = 0;
    // Canonical IEEE exception order I/U/O/Z/V in bits 0..4.
    std::uint8_t exception_bits = 0;
    bool exception_taken = false;
    bool writes_destination = true;
    bool operator==(const Mips32WordConversionResult &) const = default;
};

// Evaluate ROUND.W/TRUNC.W/CEIL.W/FLOOR.W for an IEEE binary32 or binary64
// source bit pattern. These operations select their named rounding mode
// independently of FCSR.RM. Infinity, NaNs, and rounded results outside the
// signed-word range produce the architectural default INT32_MAX and Invalid.
// With FCSR.FS set, a subnormal source is replaced by signed zero and raises
// Inexact (Release 5+ behavior).
HEXLAB_PROCESSORS_EXPORT std::optional<Mips32WordConversionResult>
evaluate_mips32_word_conversion(bool double_precision, Mips32WordRounding,
                                std::uint64_t source_bits, std::uint32_t fcsr) noexcept;

enum class Mips32FpSignOperation { abs, mov, neg };

// Evaluate the bit-exact MIPS32 COP1 ABS/MOV/NEG operation for an S or D
// operand. Single-precision inputs and results use the low 32 bits. These
// operations only alter or preserve the sign bit and do not update FCSR.
HEXLAB_PROCESSORS_EXPORT std::uint64_t
evaluate_mips32_fp_sign_operation(Mips32FpSignOperation operation, bool double_precision,
                                 std::uint64_t operand_bits) noexcept;

struct Mips32FpConditionalMoveResult {
    std::uint64_t value_bits = 0;
    bool condition_true = false;
    bool operator==(const Mips32FpConditionalMoveResult &) const = default;
};

// Evaluate decoded MOVF.S/MOVT.S/MOVF.D/MOVT.D from caller-supplied source,
// prior destination, and selected FCC value. FCSR is read-only for these moves.
HEXLAB_PROCESSORS_EXPORT std::optional<Mips32FpConditionalMoveResult>
evaluate_mips32_fp_conditional_move_instruction(const Instruction &instruction,
                                                std::uint64_t source_bits,
                                                std::uint64_t prior_destination_bits,
                                                bool fcc_value) noexcept;

} // namespace hexlab
