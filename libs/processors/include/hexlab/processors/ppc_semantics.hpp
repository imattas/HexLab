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

struct PpcBranchPredicateResult {
    bool taken = false;
    // Present when BO requests a CTR test; the counter is decremented before
    // its zero/nonzero predicate is evaluated.
    std::optional<std::uint64_t> ctr_after;
    bool operator==(const PpcBranchPredicateResult &) const = default;
};

// Evaluate the BO/BI condition of bc, bclr, or bcctr. `cr_field` is the
// selected four-bit CR field; `counter_width` must be 32 or 64. CTR is ignored
// when BO disables its test, and otherwise wraps at the selected width.
HEXLAB_PROCESSORS_EXPORT std::optional<PpcBranchPredicateResult>
evaluate_ppc_branch_predicate(std::uint8_t bo, std::uint8_t bi, std::uint8_t cr_field,
                              std::uint64_t ctr, unsigned counter_width) noexcept;

// Evaluate decoded PPC32/PPC64 register and immediate compare forms to a CR
// field nibble (LT/GT/EQ/SO); XER.SO is supplied by the caller.
HEXLAB_PROCESSORS_EXPORT std::optional<std::uint8_t>
evaluate_ppc_compare_instruction(const Instruction &instruction,
                                 std::uint64_t lhs, std::uint64_t rhs,
                                 bool xer_so) noexcept;

struct PpcCrTransferResult {
    std::uint32_t gpr_value = 0;
    std::array<std::uint8_t, 8> cr_fields{};
    std::uint8_t cr_fields_written = 0;
    bool writes_gpr = false;
    bool operator==(const PpcCrTransferResult &) const = default;
};

// Evaluate decoded MFCR/MTCRF using CR fields in architectural field order
// (CR0 first); MTCRF source is a caller-supplied 32-bit GPR value.
HEXLAB_PROCESSORS_EXPORT std::optional<PpcCrTransferResult>
evaluate_ppc_cr_transfer_instruction(const Instruction &instruction,
                                     std::array<std::uint8_t, 8> cr_fields,
                                     std::uint32_t gpr_source = 0) noexcept;

struct PpcMcrxrResult {
    std::array<std::uint8_t, 8> cr_fields{};
    std::uint32_t xer_value = 0;
    std::uint8_t cr_fields_written = 0;
    bool operator==(const PpcMcrxrResult &) const = default;
};

// Evaluate decoded MCRXR from the caller-supplied CR fields and XER value.
// The selected CR field receives SO/OV/CA/0 and only those XER bits clear.
HEXLAB_PROCESSORS_EXPORT std::optional<PpcMcrxrResult>
evaluate_ppc_mcrxr_instruction(const Instruction &instruction,
                               std::array<std::uint8_t, 8> cr_fields,
                               std::uint32_t xer_value) noexcept;

struct PpcFpUnaryBitsResult {
    std::uint64_t fpr_bits = 0;
    std::optional<std::uint8_t> cr1;
    bool operator==(const PpcFpUnaryBitsResult &) const = default;
};

// Evaluate bit-preserving FMR/FNEG/FABS forms, including Rc's CR1 copy from
// the caller-supplied pre-instruction FPSCR. No FP exception state is changed.
HEXLAB_PROCESSORS_EXPORT std::optional<PpcFpUnaryBitsResult>
evaluate_ppc_fp_unary_bits_instruction(const Instruction &instruction,
                                       std::uint64_t source_bits,
                                       std::uint32_t fpscr_before = 0) noexcept;

// Evaluates the decoded VMX wrapping add/subtract and logical integer forms.
// Add/subtract lanes are interpreted big-endian within each architectural
// lane, and arithmetic wraps modulo the lane width. Unknown opcodes return no
// value.
HEXLAB_PROCESSORS_EXPORT std::optional<PpcVectorBits>
evaluate_ppc_vmx_integer_operation(Opcode opcode, const PpcVectorBits &va,
                                   const PpcVectorBits &vb) noexcept;

// Evaluate PPC32/PPC64 POPCNTB over a 32- or 64-bit GPR value. Each output
// byte is the population count (0..8) of the corresponding input byte.
HEXLAB_PROCESSORS_EXPORT std::optional<std::uint64_t>
evaluate_ppc_popcntb(Opcode opcode, std::uint64_t value, unsigned register_width) noexcept;

// Evaluate PPC32/64 POPCNTW and PPC64 POPCNTD. POPCNTW counts only the low
// word even when its GPR is 64 bits; result is the mode-width GPR value.
HEXLAB_PROCESSORS_EXPORT std::optional<std::uint64_t>
evaluate_ppc_popcnt_word_operation(Opcode opcode, std::uint64_t value,
                                   unsigned register_width) noexcept;
HEXLAB_PROCESSORS_EXPORT std::optional<std::uint64_t>
evaluate_ppc_popcnt_word_instruction(const Instruction &instruction,
                                     std::uint64_t source) noexcept;

// Evaluate ISEL using caller-supplied RA/RB values and the selected CR bit.
// A set CR bit selects RA; a clear bit selects RB.
HEXLAB_PROCESSORS_EXPORT std::optional<std::uint64_t>
evaluate_ppc_isel_instruction(const Instruction &instruction,
                              std::uint64_t ra_value, std::uint64_t rb_value,
                              bool condition_bit) noexcept;

// Evaluate one decoded CR logical bit operation from caller-supplied BA/BB.
HEXLAB_PROCESSORS_EXPORT std::optional<bool>
evaluate_ppc_cr_logical_instruction(const Instruction &instruction,
                                    bool ba, bool bb) noexcept;

// Evaluate CNTLZW/CNTLZD, including record-form opcodes for their GPR result.
// CNTLZW observes the low 32 bits; CNTLZD requires a 64-bit register profile.
HEXLAB_PROCESSORS_EXPORT std::optional<std::uint64_t>
evaluate_ppc_count_leading_zeros(Opcode opcode, std::uint64_t value,
                                 unsigned register_width) noexcept;

struct PpcSignExtendResult {
    std::uint64_t value = 0;
    std::optional<std::uint8_t> cr0;
    bool operator==(const PpcSignExtendResult &) const = default;
};

// Evaluate decoded EXTSB/EXTSH/EXTSW, including Rc forms. XER.SO is supplied
// by the caller when the instruction records the result into CR0.
HEXLAB_PROCESSORS_EXPORT std::optional<PpcSignExtendResult>
evaluate_ppc_sign_extend_instruction(const Instruction &instruction,
                                    std::uint64_t source, bool xer_so = false) noexcept;

struct PpcCarryArithmeticResult {
    std::uint64_t value = 0;
    std::uint32_t xer_after = 0;
    std::optional<std::uint8_t> cr0;
    bool operator==(const PpcCarryArithmeticResult &) const = default;
};

// Evaluate decoded ADDZE/ADDME, including Rc forms, from a GPR value and XER.
HEXLAB_PROCESSORS_EXPORT std::optional<PpcCarryArithmeticResult>
evaluate_ppc_addze_addme_instruction(const Instruction &instruction,
                                    std::uint64_t source, std::uint32_t xer) noexcept;

struct PpcNegateResult {
    std::uint64_t value = 0;
    std::optional<std::uint8_t> cr0;
    bool operator==(const PpcNegateResult &) const = default;
};

// Evaluate decoded PPC32/PPC64 NEG with optional Rc CR0 update. XER.SO is
// supplied by the caller for the record form.
HEXLAB_PROCESSORS_EXPORT std::optional<PpcNegateResult>
evaluate_ppc_negate_instruction(const Instruction &instruction,
                                std::uint64_t source, bool xer_so = false) noexcept;

struct PpcRotateMaskResult {
    std::uint64_t value = 0;
    std::optional<std::uint8_t> cr0;
    bool operator==(const PpcRotateMaskResult &) const = default;
};

// Evaluate decoded RLWINM/RLWIMI/RLWNM, including record forms. For RLWNM,
// `variable_shift_value` supplies RB; RLWIMI also consumes prior RA.
HEXLAB_PROCESSORS_EXPORT std::optional<PpcRotateMaskResult>
evaluate_ppc_rotate_mask_instruction(const Instruction &instruction,
                                     std::uint64_t source,
                                     std::optional<std::uint64_t> variable_shift_value = {},
                                     std::uint64_t prior_destination = 0,
                                     bool xer_so = false) noexcept;

// Evaluate decoded ADDIC/ADDIC./SUBFIC from the source GPR and XER state.
HEXLAB_PROCESSORS_EXPORT std::optional<PpcCarryArithmeticResult>
evaluate_ppc_immediate_carry_instruction(const Instruction &instruction,
                                         std::uint64_t source, std::uint32_t xer) noexcept;

} // namespace hexlab
