#pragma once

#include "hexlab/decompiler/decompiler.hpp"
#include "hexlab/types/types.hpp"

#include <optional>
#include <span>
#include <string>
#include <vector>

namespace hexlab::decompiler {

enum class AbiValueClass { integer, floating, vector };

struct AbiArgumentSlot {
    AbiValueClass value_class = AbiValueClass::integer;
    std::optional<RegisterOperand> reg;
    // Stack offset relative to the incoming value of stack_argument_base.
    // Null means register slot.
    std::optional<std::int64_t> stack_offset;
    // When one source parameter occupies multiple physical registers (for
    // example an AAPCS64 HFA or a split SysV AMD64 aggregate), each slot points
    // back to the same parameter. `component_index` identifies the physical
    // component; ordinary one-register slots leave it unset.
    std::optional<std::uint16_t> parameter_index;
    std::optional<std::uint8_t> component_index;
    // Byte range carried by this register when the ABI splits one source
    // aggregate. Unset for ordinary scalar slots and whole-parameter HFA slots.
    std::optional<std::uint8_t> component_offset;
    std::optional<std::uint8_t> component_size;
    // False placeholders preserve declared parameter positions when the
    // classifier cannot establish a location.
    bool supported = true;
};

// ABI positions are explicit and ordered. Stack locations are offsets from
// the incoming stack_argument_base value; supported constant stack-pointer
// adjustments are normalized back to it. Return registers are classed
// independently.
struct AbiDescription {
    std::string name;
    std::uint16_t pointer_bits = 0;
    std::vector<RegisterOperand> integer_argument_registers;
    std::optional<RegisterOperand> integer_return_register;
    std::vector<AbiArgumentSlot> arguments;
    std::optional<RegisterOperand> stack_argument_base;
    std::vector<std::int64_t> stack_argument_offsets;
    // Bytes removed from the caller's stack offset by call mechanics when
    // mapping a callee entry-relative stack slot to the caller's stack base.
    // x86 calls use the implicit return-address width; link-register ABIs use 0.
    std::int64_t call_stack_adjustment = 0;
    std::vector<RegisterOperand> floating_argument_registers;
    std::vector<RegisterOperand> vector_argument_registers;
    std::optional<RegisterOperand> floating_return_register;
    std::optional<RegisterOperand> vector_return_register;
    // Some ABIs select the integer or FP register at one shared source
    // argument position (for example Windows x64); others allocate each
    // register class independently (for example System V AMD64).
    bool shared_integer_float_argument_positions = false;
    std::vector<RegisterOperand> caller_saved_registers;
};

// A stable prototype for a callable address whose body is outside the
// recovered function set. Multiple entries for one address are treated as
// ambiguous unless both ABI maps and function types agree.
struct ExternalFunctionPrototype {
    Address entry;
    AbiDescription abi;
    types::TypePtr prototype;
};

// Annotates call outputs before SSA, preserving represented overlapping aliases.
// An empty caller-saved map leaves existing call semantics unchanged.
HEXLAB_DECOMPILER_EXPORT Result<LiftedFunction> prepare_call_effects(
    const LiftedFunction &, const AbiDescription &);

// Common calling-convention profiles. Slot widths remain supplied by the
// lifted IR or an explicit prototype; profiles document unsupported classes.
HEXLAB_DECOMPILER_EXPORT AbiDescription x86_64_windows_abi();
HEXLAB_DECOMPILER_EXPORT AbiDescription x86_64_system_v_abi();
HEXLAB_DECOMPILER_EXPORT AbiDescription x86_32_cdecl_abi();
HEXLAB_DECOMPILER_EXPORT AbiDescription aarch64_abi();
HEXLAB_DECOMPILER_EXPORT AbiDescription arm32_aapcs_abi();
HEXLAB_DECOMPILER_EXPORT AbiDescription riscv32_ilp32_abi();
HEXLAB_DECOMPILER_EXPORT AbiDescription riscv64_lp64_abi();
HEXLAB_DECOMPILER_EXPORT AbiDescription mips32_o32_abi();
HEXLAB_DECOMPILER_EXPORT AbiDescription mips64_n64_abi();

struct RecoveredVariable {
    RegisterOperand reg;
    std::optional<std::uint32_t> version;
    types::TypePtr type;
    // True when the type came from an explicit prototype or ABI argument slot.
    bool prototype_constrained = false;
    // Stable source-facing identity for this machine value. Incoming ABI values
    // use argN; other values use a deterministic register/version name.
    std::string name;
    std::optional<std::size_t> parameter_index;
    // Actual read, explicit parameter constraint, or known callee use. ABI
    // snapshot liveness by itself is insufficient for argument propagation.
    bool argument_evidence = false;
};

struct RecoveredStackVariable {
    std::string name;
    RegisterOperand frame_register;
    std::optional<std::uint32_t> frame_version;
    std::int64_t offset = 0;
    std::uint16_t bits = 0;
    types::TypePtr type;
};

struct TypeRecoveryResult {
    std::vector<RecoveredVariable> variables;
    std::vector<RecoveredStackVariable> stack_variables;
    types::TypePtr return_type;
    // Candidate signature inferred from observed ABI register use and return
    // statements. This is a heuristic proposal, not a proven source prototype.
    types::TypePtr inferred_prototype;
    std::vector<std::string> diagnostics;
};

// Explicit project type assignments can constrain a recovered stack local
// when every assignment for its recovered access sites agrees. `ambiguous`
// suppresses a declaration when those assignments conflict.
struct StackLocalTypeEvidence {
    std::string name;
    types::TypePtr type;
    bool ambiguous = false;
};

// Propagates widths and signedness through the decompiler IR, recognizes
// pointer values used as memory bases or formed by address arithmetic, and
// applies optional ABI/prototype constraints. Input is not mutated.
HEXLAB_DECOMPILER_EXPORT Result<TypeRecoveryResult>
recover_types(const LiftedFunction &, const AbiDescription &,
              types::TypePtr prototype = {});

// Recovers a set of functions together. Exact direct calls within the supplied
// set exchange unanimous register-argument types and modeled ABI return types
// through a bounded fixed point. Inputs and outputs use the same ordering; a
// null prototype leaves that function eligible for conservative inference.
HEXLAB_DECOMPILER_EXPORT Result<std::vector<TypeRecoveryResult>>
recover_interprocedural_types(std::span<const LiftedFunction>,
                              std::span<const AbiDescription>,
                              std::span<const types::TypePtr> prototypes = {},
                              std::uint32_t max_iterations = 16);
HEXLAB_DECOMPILER_EXPORT Result<std::vector<TypeRecoveryResult>>
recover_interprocedural_types(std::span<const LiftedFunction>,
                              std::span<const AbiDescription>,
                              std::span<const types::TypePtr> prototypes,
                              std::span<const ExternalFunctionPrototype> external_prototypes,
                              std::uint32_t max_iterations = 16);

// Emits structured pseudocode with declarations for stack variables whose
// recovered types are concrete. Uncertain or unsupported declarators are left
// out rather than printed with an invented type.
HEXLAB_DECOMPILER_EXPORT Result<std::string>
format_pseudocode_with_types(const LiftedFunction &, const AbiDescription &,
                             types::TypePtr prototype = {});
HEXLAB_DECOMPILER_EXPORT Result<std::string>
format_pseudocode_with_types(const LiftedFunction &, const AbiDescription &,
                             types::TypePtr prototype,
                             std::span<const StackLocalTypeEvidence> local_types);

} // namespace hexlab::decompiler
