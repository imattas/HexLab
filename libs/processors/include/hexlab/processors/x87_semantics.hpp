#pragma once

#include "hexlab/processors/processors_export.hpp"
#include "hexlab/processors/instruction.hpp"

#include <cstdint>
#include <optional>
#include <array>

namespace hexlab {

enum class X87Tag : std::uint8_t { valid, zero, special, empty };

// Abstract architectural stack state. A missing TOP or tag is deliberately
// unknown; tags describe physical registers, while ST(i) is TOP-relative.
struct X87StackState {
    std::optional<std::uint8_t> top;
    std::array<std::optional<X87Tag>, 8> tags{};
    bool operator==(const X87StackState &) const = default;
};

HEXLAB_PROCESSORS_EXPORT X87StackState join_x87_stack_states(const X87StackState &left,
                                                              const X87StackState &right) noexcept;
HEXLAB_PROCESSORS_EXPORT X87StackState transfer_x87_stack_state(const X87StackState &input,
                                                                 const Instruction &instruction) noexcept;
HEXLAB_PROCESSORS_EXPORT std::optional<std::uint8_t> x87_physical_register(const X87StackState &state,
                                                                          std::uint8_t logical_st) noexcept;

// Canonical x87 80-bit extended value fields. The explicit integer bit is
// bit 63 of significand; exponent is the raw 15-bit biased field.
struct X87Binary80 {
    std::uint64_t significand = 0;
    std::uint16_t sign_exponent = 0;
    bool operator==(const X87Binary80 &) const = default;
};

enum class X87Relation : std::uint8_t { less, equal, greater, unordered };
enum class X87CompareKind : std::uint8_t { fcom, fucom, fcomi, fucomi };

struct X87CompareRequest {
    X87Binary80 left, right;
    std::uint16_t control_word = 0x037f;
    std::uint16_t status_word = 0;
    std::uint32_t eflags = 0;
    X87CompareKind kind = X87CompareKind::fcom;
};

struct X87CompareResult {
    X87Relation relation = X87Relation::unordered;
    std::uint16_t status_word = 0;
    std::optional<std::uint32_t> eflags;
    // False means an unmasked invalid-operation exception prevents the
    // comparison condition outputs and any instruction stack pop from retiring.
    bool completed = true;
    bool invalid_operation = false;
    bool operator==(const X87CompareResult &) const = default;
};

// Compare canonical 80-bit operands exactly without relying on host floating
// point. Noncanonical unnormal/pseudo-special encodings return no result.
HEXLAB_PROCESSORS_EXPORT std::optional<X87Relation> compare_x87_binary80(X87Binary80 left,
                                                                       X87Binary80 right) noexcept;

// Evaluate FCOM/FUCOM and FCOMI/FUCOMI condition effects. FCOM variants are
// ordered; FUCOM variants raise invalid only for signaling NaNs. The caller
// remains responsible for x87 stack tags/TOP and instruction-specific pops.
HEXLAB_PROCESSORS_EXPORT std::optional<X87CompareResult>
evaluate_x87_compare(const X87CompareRequest &request) noexcept;

struct X87IntegerConvertRequest {
    X87Binary80 value;
    std::uint16_t control_word = 0x037f;
    std::uint16_t status_word = 0;
    std::uint8_t destination_width = 32; // FIST/FISTP support 16, 32, or 64 bits.
    bool truncate = false; // FISTTP ignores RC and truncates toward zero.
};

struct X87IntegerConvertResult {
    std::optional<std::uint64_t> destination_bits;
    std::uint16_t status_word = 0;
    bool completed = true;
    bool invalid_operation = false;
    bool precision = false;
    bool operator==(const X87IntegerConvertResult &) const = default;
};

// Evaluate FIST/FISTP/FISTTP's numeric conversion, integer-indefinite result,
// precision/invalid sticky bits, and masked/unmasked exception retirement.
// A missing destination value means an unmasked exception prevented the store.
HEXLAB_PROCESSORS_EXPORT std::optional<X87IntegerConvertResult>
evaluate_x87_to_integer(const X87IntegerConvertRequest &request) noexcept;

struct X87RoundToIntegralRequest {
    X87Binary80 value;
    std::uint16_t control_word = 0x037f;
    std::uint16_t status_word = 0;
};

struct X87RoundToIntegralResult {
    std::optional<X87Binary80> value;
    std::uint16_t status_word = 0;
    // FSW condition codes C0/C2/C3 are architecturally undefined for FRNDINT.
    std::uint16_t status_word_defined_mask = 0xffff;
    bool completed = true;
    bool precision = false;
    bool operator==(const X87RoundToIntegralResult &) const = default;
};

// Evaluate FRNDINT for finite normal/subnormal and pseudo-denormal binary80
// inputs, plus infinities. NaNs and unsupported encodings return no result so
// their special-value behavior is not guessed.
HEXLAB_PROCESSORS_EXPORT std::optional<X87RoundToIntegralResult>
evaluate_x87_round_to_integral(const X87RoundToIntegralRequest &request) noexcept;

struct X87MultiplyRequest {
    X87Binary80 left, right;
    std::uint16_t control_word = 0x037f;
    std::uint16_t status_word = 0;
};
struct X87ArithmeticResult {
    std::optional<X87Binary80> value;
    std::uint16_t status_word = 0;
    // False means an unmasked exception requires delivery. For unmasked PE,
    // x87 register arithmetic still commits the rounded value before delivery.
    bool completed = true;
    bool overflow = false;
    bool precision = false;
    bool invalid_operation = false;
    bool operator==(const X87ArithmeticResult &) const = default;
};
// Evaluate binary80 FMUL finite, signed-zero, infinity, and NaN operands with
// x87 precision control and exception masks. Gradual-underflow results fail closed.
HEXLAB_PROCESSORS_EXPORT std::optional<X87ArithmeticResult>
evaluate_x87_multiply(const X87MultiplyRequest &request) noexcept;

enum class X87BinaryArithmetic : std::uint8_t { add, subtract };
struct X87AddSubtractRequest {
    X87Binary80 left, right;
    X87BinaryArithmetic operation = X87BinaryArithmetic::add;
    std::uint16_t control_word = 0x037f;
    std::uint16_t status_word = 0;
};
// Evaluate binary80 FADD/FSUB finite, signed-zero, infinity, and NaN operands
// with x87 precision control and exception masks. Reserved PC and gradual-
// underflow results fail closed.
HEXLAB_PROCESSORS_EXPORT std::optional<X87ArithmeticResult>
evaluate_x87_add_subtract(const X87AddSubtractRequest &request) noexcept;

enum class X87UnaryArithmetic : std::uint8_t { change_sign, absolute };
struct X87UnaryResult {
    X87Binary80 value;
    std::uint16_t status_word = 0;
    bool operator==(const X87UnaryResult &) const = default;
};

// Exact bit-level FCHS/FABS operations. On a valid nonempty ST(0), these
// change only the sign bit and leave the supplied status word unchanged.
HEXLAB_PROCESSORS_EXPORT X87UnaryResult
evaluate_x87_unary(X87Binary80 value, std::uint16_t status_word,
                   X87UnaryArithmetic operation) noexcept;

} // namespace hexlab
