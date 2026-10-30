#pragma once

#include "hexlab/core/byte_reader.hpp"
#include "hexlab/processors/instruction.hpp"
#include "hexlab/processors/processors_export.hpp"
#include <cstdint>
#include <optional>

namespace hexlab {

// Evaluate the MIPS64 SPECIAL2 DCLZ/DCLO count over the full 64-bit GPR.
HEXLAB_PROCESSORS_EXPORT std::optional<std::uint64_t>
evaluate_mips64_count_leading(Opcode opcode, std::uint64_t source) noexcept;

// Validate and evaluate a decoded DCLZ/DCLO instruction. The caller supplies
// the sampled source register; architectural zero must be passed as zero.
HEXLAB_PROCESSORS_EXPORT std::optional<std::uint64_t>
evaluate_mips64_count_leading_instruction(const Instruction &instruction,
                                          std::uint64_t source) noexcept;

enum class Mips64MergeOperation {
    load_left_word, load_right_word, store_left_word, store_right_word,
    load_left_doubleword, load_right_doubleword, store_left_doubleword, store_right_doubleword,
};

struct Mips64MergeResult {
    // For loads this is the merged, sign-extended GPR value. For stores this is
    // the updated aligned memory word. The caller performs the actual memory
    // access after validating the touched range.
    std::uint64_t value = 0;
    // Bit i is one when numeric byte i (0 is the least-significant byte) of
    // the GPR was changed by the load. Word loads include bits 4-7 because
    // they sign-extend their result.
    std::uint64_t register_byte_mask = 0;
    // Bit i is one when address-order byte i of the aligned memory word is
    // read by a load or written by a store.
    std::uint64_t memory_byte_mask = 0;
    std::uint8_t bytes_touched = 0;
    bool writes_register = false;
    bool operator==(const Mips64MergeResult &) const = default;
};

enum class Mips64MultiplyAccumulateOperation { madd, maddu, msub, msubu };

enum class Mips64MultiplyOperation { mult, multu, dmult, dmultu };

struct Mips64AddSubResult {
    std::uint64_t value = 0;
    bool overflow_exception = false;
    bool writes_destination = false;
    bool operator==(const Mips64AddSubResult &) const = default;
};

// Evaluate decoded DADD/DADDU/DSUB/DSUBU/DADDI/DADDIU. Trapping forms report
// signed overflow; unsigned forms wrap modulo 2^64.
HEXLAB_PROCESSORS_EXPORT std::optional<Mips64AddSubResult>
evaluate_mips64_add_sub_instruction(const Instruction &instruction,
                                    std::uint64_t lhs, std::uint64_t rhs = 0) noexcept;

struct Mips64MultiplyResult {
    std::uint64_t hi = 0;
    std::uint64_t lo = 0;
    bool operator==(const Mips64MultiplyResult &) const = default;
};

struct Mips64MultiplyAccumulateResult {
    std::uint32_t hi = 0;
    std::uint32_t lo = 0;
    bool operator==(const Mips64MultiplyAccumulateResult &) const = default;
};

// Evaluate MADD/MADDU/MSUB/MSUBU using the low 32 bits of each GPR source and
// the prior HI:LO accumulator. The product is signed only for MADD/MSUB;
// accumulator addition/subtraction wraps modulo 2^64. No architectural state
// is read or written by this helper.
HEXLAB_PROCESSORS_EXPORT std::optional<Mips64MultiplyAccumulateResult>
evaluate_mips64_multiply_accumulate(Mips64MultiplyAccumulateOperation operation,
                                    std::uint64_t lhs, std::uint64_t rhs,
                                    std::uint32_t hi, std::uint32_t lo) noexcept;

// Evaluate MULT/MULTU/DMULT/DMULTU. Word forms require sign-extended 32-bit
// GPR inputs and sign-extend each 32-bit HI/LO result into 64 bits. Doubleword
// forms return the full 128-bit product split across 64-bit HI and LO values.
HEXLAB_PROCESSORS_EXPORT std::optional<Mips64MultiplyResult>
evaluate_mips64_multiply(Mips64MultiplyOperation operation,
                         std::uint64_t lhs, std::uint64_t rhs) noexcept;

// Decoded adapters bind MIPS64 SPECIAL multiply forms to their architectural
// operand and HI/LO effects. Callers supply sampled GPR values; register zero
// must be passed as zero. Malformed or non-MIPS64 instructions fail closed.
HEXLAB_PROCESSORS_EXPORT std::optional<Mips64MultiplyResult>
evaluate_mips64_multiply_instruction(const Instruction &instruction,
                                     std::uint64_t lhs, std::uint64_t rhs) noexcept;

HEXLAB_PROCESSORS_EXPORT std::optional<Mips64MultiplyAccumulateResult>
evaluate_mips64_multiply_accumulate_instruction(const Instruction &instruction,
                                                std::uint64_t lhs, std::uint64_t rhs,
                                                std::uint32_t hi, std::uint32_t lo) noexcept;

enum class Mips64DivisionOperation { div, divu, ddiv, ddivu };
enum class Mips64DivisionOutcome {
    defined,
    unpredictable_word_operand,
    unpredictable_divide_by_zero,
    unpredictable_signed_overflow,
};

struct Mips64DivisionResult {
    // HI and LO are architectural destinations for each decoded operation.
    // They are absent when the classic ISA profile leaves the arithmetic
    // result unpredictable for the supplied operands.
    std::optional<std::uint64_t> hi;
    std::optional<std::uint64_t> lo;
    Mips64DivisionOutcome outcome = Mips64DivisionOutcome::defined;
    bool writes_hilo = true;
};

// Evaluate DIV/DIVU/DDIV/DDIVU with caller-supplied GPR values. Word forms
// require sign-extended 32-bit operands and sign-extend quotient/remainder
// results. Divide-by-zero results are unpredictable; signed minimum / -1 is
// also returned without concrete HI/LO values because this profile does not
// specify a result for that overflow case.
HEXLAB_PROCESSORS_EXPORT std::optional<Mips64DivisionResult>
evaluate_mips64_division(Mips64DivisionOperation operation,
                         std::uint64_t lhs, std::uint64_t rhs) noexcept;

HEXLAB_PROCESSORS_EXPORT std::optional<Mips64DivisionResult>
evaluate_mips64_division_instruction(const Instruction &instruction,
                                     std::uint64_t lhs, std::uint64_t rhs) noexcept;

struct Mips64FpConditionalMoveResult {
    std::uint64_t value_bits = 0;
    bool condition_true = false;
    bool operator==(const Mips64FpConditionalMoveResult &) const = default;
};

// Evaluate decoded MOVF.S/MOVT.S/MOVF.D/MOVT.D from caller-supplied source,
// prior destination, and selected FCC value. These moves leave FCSR unchanged.
HEXLAB_PROCESSORS_EXPORT std::optional<Mips64FpConditionalMoveResult>
evaluate_mips64_fp_conditional_move_instruction(const Instruction &instruction,
                                                 std::uint64_t source_bits,
                                                 std::uint64_t prior_destination_bits,
                                                 bool fcc_value) noexcept;

// Evaluate one MIPS64 LWL/LWR/LDL/LDR/SWL/SWR/SDL/SDR byte-lane merge.
// address_offset is the effective address modulo the operation width;
// memory_word is the aligned 4- or 8-byte word interpreted in `order`;
// register_value is the prior GPR for a load or source GPR for a store.
// Invalid operation offsets return no result. No memory access is performed.
HEXLAB_PROCESSORS_EXPORT std::optional<Mips64MergeResult>
evaluate_mips64_merge(Mips64MergeOperation operation, ByteOrder order,
                      std::uint8_t address_offset, std::uint64_t register_value,
                      std::uint64_t memory_word) noexcept;

} // namespace hexlab
