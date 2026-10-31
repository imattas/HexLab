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

enum class X87ExceptionDelivery { none, math_fault, external_irq13 };
struct X87PendingExceptionRequest {
    std::uint16_t control_word = 0x037f;
    std::uint16_t status_word = 0;
    // CR0.NE selects native #MF instead of legacy FERR#/IRQ13 reporting.
    bool native_mode = true;
};
struct X87PendingExceptionResult {
    std::uint8_t unmasked_exception_flags = 0; // IE/DE/ZE/OE/UE/PE bits 0..5.
    std::uint16_t status_word = 0;
    X87ExceptionDelivery delivery = X87ExceptionDelivery::none;
    bool pending() const noexcept { return delivery != X87ExceptionDelivery::none; }
    bool operator==(const X87PendingExceptionResult &) const = default;
};

// Resolve pending delivery from caller-owned FCW/FSW state. Sticky exception
// flags only cause delivery when their corresponding control-word masks are
// clear. When pending, the returned FSW includes ES and B. This identifies
// #MF versus the legacy IRQ13 path; it does not deliver a host exception or
// emulate task-switch/interrupt-controller state.
HEXLAB_PROCESSORS_EXPORT X87PendingExceptionResult evaluate_x87_pending_exception(
    const X87PendingExceptionRequest &) noexcept;

struct X87StackFaultRequest {
    std::uint16_t control_word = 0x037f;
    std::uint16_t status_word = 0;
    bool overflow = false;
    bool native_mode = true;
};
struct X87StackFaultResult {
    std::uint16_t status_word = 0;
    bool instruction_completed = true; // Masked faults complete with operation-specific indefinite behavior.
    X87PendingExceptionResult pending;
    bool operator==(const X87StackFaultResult &) const = default;
};
// Record the x87 invalid-operation/stack-fault flags and C1 direction for a
// detected stack overflow or underflow. This does not detect tag faults or
// generate an operation-specific indefinite value; the caller supplies the
// fault direction and commits stack state only when instruction_completed.
HEXLAB_PROCESSORS_EXPORT X87StackFaultResult evaluate_x87_stack_fault(
    const X87StackFaultRequest &) noexcept;

struct X87ClearExceptionsResult {
    std::uint16_t status_word = 0;
    bool operator==(const X87ClearExceptionsResult &) const = default;
};
struct X87InitializeResult {
    std::uint16_t control_word = 0x037f;
    std::uint16_t status_word = 0;
    X87StackState stack;
    bool operator==(const X87InitializeResult &) const = default;
};

// Model FNCLEX's exact status-word mask and FNINIT's architectural control,
// status, TOP, and tag defaults. FIP/FDP/FOP and register payload bits are
// deliberately outside this abstract result.
HEXLAB_PROCESSORS_EXPORT X87ClearExceptionsResult evaluate_x87_clear_exceptions(
    std::uint16_t status_word) noexcept;
HEXLAB_PROCESSORS_EXPORT X87InitializeResult evaluate_x87_initialize() noexcept;

// Apply the stack/TOP/tag portion of a decoded instruction only when it was
// allowed to execute past any prior pending exception and its own semantics
// completed. This preserves input stack state for an unmasked exception or a
// pending delivery before a waiting instruction. The simpler transfer helper
// above remains the normal-completion transfer.
HEXLAB_PROCESSORS_EXPORT X87StackState retire_x87_stack_state(
    const X87StackState &, const Instruction &, const X87PendingExceptionResult &,
    bool instruction_completed) noexcept;

// Canonical x87 80-bit extended value fields. The explicit integer bit is
// bit 63 of significand; exponent is the raw 15-bit biased field.
struct X87Binary80 {
    std::uint64_t significand = 0;
    std::uint16_t sign_exponent = 0;
    bool operator==(const X87Binary80 &) const = default;
};

enum class X87SignOperation : std::uint8_t { change, clear };
struct X87SignOperationRequest {
    X87Binary80 value;
    std::uint16_t status_word = 0;
    X87SignOperation operation = X87SignOperation::change;
};
struct X87SignOperationResult {
    X87Binary80 value;
    std::uint16_t status_word = 0;
    // C0/C2/C3 are undefined for FCHS and FABS; all other FSW bits are defined.
    std::uint16_t status_word_defined_mask = 0xbaff;
    bool operator==(const X87SignOperationResult &) const = default;
};
// Apply FCHS (change) or FABS (clear) to the binary80 sign bit without
// decoding or canonicalizing the significand/exponent. This models the
// normal nonempty-ST(0) path, sets C1 to zero, and preserves other defined FSW
// bits. Stack-underflow exception handling is separate.
HEXLAB_PROCESSORS_EXPORT std::optional<X87SignOperationResult> evaluate_x87_sign_operation(
    const X87SignOperationRequest &) noexcept;

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
    bool denormal_operand = false;
    bool operator==(const X87CompareResult &) const = default;
};

// Compare canonical 80-bit operands exactly without relying on host floating
// point. Noncanonical unnormal/pseudo-special encodings return no result.
HEXLAB_PROCESSORS_EXPORT std::optional<X87Relation> compare_x87_binary80(X87Binary80 left,
                                                                       X87Binary80 right) noexcept;

// Evaluate FCOM/FUCOM and FCOMI/FUCOMI condition effects, including denormal
// operand status. FCOM variants are ordered; FUCOM variants raise invalid only
// for signaling NaNs. The caller remains responsible for x87 stack tags/TOP
// and instruction-specific pops.
HEXLAB_PROCESSORS_EXPORT std::optional<X87CompareResult>
evaluate_x87_compare(const X87CompareRequest &request) noexcept;

struct X87TestRequest {
    X87Binary80 value;
    std::uint16_t control_word = 0x037f;
    std::uint16_t status_word = 0;
};
// Evaluate FTST as an ordered comparison of ST(0) with positive zero. The
// caller supplies a nonempty ST(0) and owns any stack-underflow handling.
HEXLAB_PROCESSORS_EXPORT std::optional<X87CompareResult>
evaluate_x87_test(const X87TestRequest &request) noexcept;

enum class X87ConditionalMoveCondition : std::uint8_t {
    below, equal, below_or_equal, unordered,
    not_below, not_equal, not_below_or_equal, ordered
};
struct X87ConditionalMoveRequest {
    X87Binary80 destination;
    X87Binary80 source;
    std::uint32_t eflags = 0;
    X87ConditionalMoveCondition condition = X87ConditionalMoveCondition::below;
};
struct X87ConditionalMoveResult {
    X87Binary80 destination;
    std::uint32_t eflags = 0;
    bool condition_met = false;
    bool operator==(const X87ConditionalMoveResult &) const = default;
};

// Evaluate the value and condition-code portion of FCMOVcc. Both x87 stack
// operands must be non-empty; stack-underflow exception/tag handling remains
// caller-owned. For valid operands FCMOV copies the source bits conditionally
// and leaves EFLAGS and FSW unchanged.
HEXLAB_PROCESSORS_EXPORT X87ConditionalMoveResult evaluate_x87_conditional_move(
    const X87ConditionalMoveRequest &request) noexcept;

enum class X87ExamineClass : std::uint8_t { unsupported, nan, normal, infinity, zero, empty, denormal };
struct X87ExamineRequest {
    X87Binary80 value;
    std::uint16_t status_word = 0;
    bool empty = false; // Supplied from the caller's x87 tag state.
};
struct X87ExamineResult {
    X87ExamineClass classification = X87ExamineClass::unsupported;
    std::uint16_t status_word = 0;
    bool negative = false;
    bool operator==(const X87ExamineResult &) const = default;
};

// Evaluate FXAM's binary80 class and FSW C0/C1/C2/C3 outputs. The caller
// supplies the physical ST(0) value and its empty-tag state; no exceptions are
// raised and all unrelated status-word bits are preserved.
HEXLAB_PROCESSORS_EXPORT X87ExamineResult evaluate_x87_examine(
    const X87ExamineRequest &request) noexcept;

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
    // True when the operation raises UE under the current mask/tininess rules.
    bool underflow = false;
    bool precision = false;
    bool invalid_operation = false;
    bool operator==(const X87ArithmeticResult &) const = default;
};
// Evaluate binary80 FMUL finite, signed-zero, infinity, and NaN operands with
// x87 precision control, gradual underflow, and exception masks.
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
// with x87 precision control, gradual underflow, and exception masks. Reserved
// PC settings or unrepresentable rounding cases fail closed.
HEXLAB_PROCESSORS_EXPORT std::optional<X87ArithmeticResult>
evaluate_x87_add_subtract(const X87AddSubtractRequest &request) noexcept;

enum class X87DivisionOperation : std::uint8_t { divide, reverse };
struct X87DivideRequest {
    X87Binary80 left, right;
    X87DivisionOperation operation = X87DivisionOperation::divide;
    std::uint16_t control_word = 0x037f;
    std::uint16_t status_word = 0;
};
// Evaluate binary80 FDIV/FDIVR finite, zero, infinity, and NaN operands using
// exact quotient bits, x87 precision/rounding control, gradual underflow, and
// invalid/zero-divide/denormal exception masks. Unsupported encodings fail
// closed.
HEXLAB_PROCESSORS_EXPORT std::optional<X87ArithmeticResult>
evaluate_x87_divide(const X87DivideRequest &request) noexcept;

struct X87SquareRootRequest {
    X87Binary80 value;
    std::uint16_t control_word = 0x037f;
    std::uint16_t status_word = 0;
};
// Evaluate nonnegative finite binary80 FSQRT inputs and signed zero using an
// exact integer square-root with guard/round/sticky bits and the shared x87
// precision, rounding, denormal, and exception handling. NaN/infinity and
// negative nonzero inputs are handled only where their exact result is known.
HEXLAB_PROCESSORS_EXPORT std::optional<X87ArithmeticResult>
evaluate_x87_square_root(const X87SquareRootRequest &request) noexcept;

struct X87ScaleRequest {
    X87Binary80 value;
    X87Binary80 scale;
    std::uint16_t status_word = 0;
    std::uint16_t control_word = 0x037f;
};
struct X87ScaleResult {
    X87Binary80 value;
    std::uint16_t status_word = 0;
    // C0/C2/C3 are undefined for FSCALE; C1 is zero on the normal path.
    std::uint16_t status_word_defined_mask = 0xbaff;
    // False means normal completion was interrupted by an unmasked exception.
    // `value` is meaningful only when value_valid is true; an unmasked
    // precision exception can retain a valid rounded result.
    bool value_valid = true;
    bool completed = true;
    bool invalid_operation = false;
    bool denormal_operand = false;
    bool overflow = false;
    bool underflow = false;
    bool precision = false;
    bool operator==(const X87ScaleResult &) const = default;
};
// Evaluate FSCALE from raw binary80 operands, including denormal operands,
// special values, and masked/unmasked numeric exceptions. ST(1) is truncated
// toward zero. Caller-owned stack tags/TOP and exception delivery remain
// separate; consult `value_valid` to determine whether ST(0) has a value to
// commit after an exception.
HEXLAB_PROCESSORS_EXPORT std::optional<X87ScaleResult>
evaluate_x87_scale(const X87ScaleRequest &request) noexcept;

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

struct X87ExtractRequest {
    X87Binary80 value;
    std::uint16_t control_word = 0x037f;
    std::uint16_t status_word = 0;
};
struct X87ExtractResult {
    // Values after FXTRACT pushes the significand: new ST(0), then ST(1).
    std::optional<X87Binary80> significand;
    std::optional<X87Binary80> exponent;
    std::uint16_t status_word = 0;
    bool completed = true;
    bool denormal_operand = false;
    bool zero_divide = false;
    bool invalid_operation = false;
    bool operator==(const X87ExtractResult &) const = default;
};
// Evaluate FXTRACT's numeric outputs for finite values, signed zero,
// infinities and NaNs, with DE/ZE/IE mask handling and masked SNaN quieting.
// Stack push/TOP/tag handling and stack-fault condition codes remain caller-
// owned; unsupported binary80 encodings fail closed.
HEXLAB_PROCESSORS_EXPORT std::optional<X87ExtractResult>
evaluate_x87_extract(const X87ExtractRequest &request) noexcept;

struct X87RealLoadRequest {
    std::uint64_t source_bits = 0;
    std::uint8_t source_width = 32; // FLD m32real or m64real.
    std::uint16_t control_word = 0x037f;
    std::uint16_t status_word = 0;
};
struct X87RealLoadResult {
    std::optional<X87Binary80> value;
    std::uint16_t status_word = 0;
    bool completed = true;
    bool denormal_operand = false;
    bool invalid_operation = false;
    bool operator==(const X87RealLoadResult &) const = default;
};
// Expand an IEEE binary32/binary64 memory value into exact x87 binary80,
// including signed zero and NaN payload mapping, while applying FLD's DE/IE
// sticky and unmasked-exception retirement rules. Stack push/tag handling is
// the caller's responsibility.
HEXLAB_PROCESSORS_EXPORT std::optional<X87RealLoadResult>
evaluate_x87_load_real(const X87RealLoadRequest &request) noexcept;

struct X87RealStoreRequest {
    X87Binary80 value;
    std::uint8_t destination_width = 32; // FST/FSTP m32real or m64real.
    std::uint16_t control_word = 0x037f;
    std::uint16_t status_word = 0;
};
struct X87RealStoreResult {
    std::optional<std::uint64_t> destination_bits;
    std::uint16_t status_word = 0;
    bool completed = true;
    bool denormal_operand = false;
    bool invalid_operation = false;
    bool overflow = false;
    bool underflow = false;
    bool precision = false;
    bool operator==(const X87RealStoreResult &) const = default;
};
// Round an x87 binary80 value to IEEE binary32/binary64 using FCW.RC and
// produce sticky exception/status effects. An absent result means an unmasked
// exception suppressed the memory store. Memory access and FSTP's stack pop
// are the caller's responsibility.
HEXLAB_PROCESSORS_EXPORT std::optional<X87RealStoreResult>
evaluate_x87_store_real(const X87RealStoreRequest &request) noexcept;

struct X87PackedBcdLoadRequest {
    std::array<std::uint8_t, 10> source{};
};
// An invalid packed-BCD digit has an undefined FBLD result and returns no
// value. Reserved bits in the high byte are ignored as on the processor.
HEXLAB_PROCESSORS_EXPORT std::optional<X87Binary80>
evaluate_x87_load_packed_bcd(const X87PackedBcdLoadRequest &request) noexcept;

struct X87PackedBcdStoreRequest {
    X87Binary80 value;
    std::uint16_t control_word = 0x037f;
    std::uint16_t status_word = 0;
};
struct X87PackedBcdStoreResult {
    std::optional<std::array<std::uint8_t, 10>> destination;
    std::uint16_t status_word = 0;
    bool completed = true;
    bool invalid_operation = false;
    bool precision = false;
    bool rounded_up = false;
    bool operator==(const X87PackedBcdStoreResult &) const = default;
};
// Evaluate FBSTP's 18-digit packed-BCD conversion using FCW.RC. Masked invalid
// operations store the architectural BCD indefinite; unmasked exceptions and
// precision exceptions suppress the memory output. The caller owns the pop.
HEXLAB_PROCESSORS_EXPORT std::optional<X87PackedBcdStoreResult>
evaluate_x87_store_packed_bcd(const X87PackedBcdStoreRequest &request) noexcept;

} // namespace hexlab
