#pragma once

#include "hexlab/analysis/functions.hpp"
#include "hexlab/analysis/switches.hpp"
#include "hexlab/decompiler/decompiler_export.hpp"
#include "hexlab/image/dex_metadata.hpp"
#include "hexlab/image/jvm_metadata.hpp"
#include "hexlab/image/wasm_metadata.hpp"
#include "hexlab/loaders/managed.hpp"
#include "hexlab/processors/x87_semantics.hpp"
#include "hexlab/types/types.hpp"

#include <memory>
#include <functional>
#include <map>
#include <optional>
#include <span>
#include <string>
#include <variant>
#include <vector>

namespace hexlab { struct ManagedMethodAnalysis; }
namespace hexlab::decompiler {

enum class TypeKind { unknown, boolean, integer, pointer, floating, vector };
struct ValueType {
    TypeKind kind = TypeKind::unknown;
    std::uint16_t bits = 0;
    bool is_signed = false;
    // For vectors, element_kind/element_bits describe the lane type and lanes
    // gives its count. Zero lanes means an opaque bit vector whose lane
    // interpretation is deliberately unspecified.
    TypeKind element_kind = TypeKind::unknown;
    std::uint16_t element_bits = 0;
    std::uint8_t lanes = 0;
    bool operator==(const ValueType &) const = default;
};

struct RegisterValue {
    RegisterOperand reg;
    std::optional<std::uint32_t> version;
    bool operator==(const RegisterValue &) const = default;
};
struct ConstantValue {
    std::uint64_t value = 0;
    ValueType type;
    bool operator==(const ConstantValue &) const = default;
};
struct X87Binary80Value {
    X87Binary80 value;
    bool operator==(const X87Binary80Value &) const = default;
};
struct MemoryValue {
    ValueType type;
    std::optional<RegisterOperand> base, index;
    std::optional<std::uint32_t> base_version, index_version;
    std::string index_shift;
    std::uint8_t index_shift_amount = 0;
    bool index_add = true;
    std::uint8_t scale = 1;
    std::int64_t displacement = 0;
    std::optional<Address> absolute;
    // Memory state observed by this load after SSA conversion. Version zero
    // denotes the incoming state before any modeled store.
    std::optional<std::uint32_t> memory_version;
    // Present only for a proven stack slot, bounded absolute range, or bounded
    // same-root dynamic range. This state supplements whole-memory SSA.
    std::optional<std::string> memory_partition;
    std::optional<std::uint32_t> memory_partition_version;
    // Set by source-level stack recovery when a frame-relative byte range has
    // a stable, non-overlapping local-variable identity.
    std::optional<std::string> stack_variable;
    // Canonical frame-relative location associated with stack_variable.
    std::optional<RegisterOperand> stack_frame_register;
    std::optional<std::uint32_t> stack_frame_version;
    std::optional<std::int64_t> stack_frame_offset;
    std::string index_extend;
};
struct UnaryValue;
struct BinaryValue;
struct UnknownValue {
    std::string description;
};
struct VariableValue {
    std::string name;
};
struct Expression;
using ExpressionPtr = std::shared_ptr<const Expression>;
struct UnaryValue { std::string operation; ExpressionPtr operand; };
struct BinaryValue { std::string operation; ExpressionPtr left, right; };
struct Expression {
    ValueType type;
    std::variant<RegisterValue, ConstantValue, X87Binary80Value, MemoryValue, UnaryValue, BinaryValue,
                 UnknownValue, VariableValue> value;
};

struct Assign { RegisterOperand destination; ExpressionPtr value; std::optional<std::uint32_t> destination_version; };
struct MemoryPartitionEffect {
    std::string partition;
    std::uint32_t input_version = 0;
    std::uint32_t output_version = 0;
};
struct Store {
    ExpressionPtr address, value;
    std::optional<std::uint32_t> memory_input_version, memory_output_version;
    std::optional<std::string> memory_partition;
    std::vector<MemoryPartitionEffect> memory_partition_effects;
};
enum class X86StackControlAction : std::uint8_t { push_return_address, pop_return_address };
// Explicit architectural stack behavior for near x86 CALL/RET. CALL's
// memory_output_version still includes unknown callee effects; this record
// identifies the transfer's own return-address slot and temporary SP delta.
struct X86StackControlEffect {
    X86StackControlAction action = X86StackControlAction::push_return_address;
    RegisterOperand stack_pointer;
    std::optional<RegisterOperand> stack_segment;
    std::uint16_t stack_address_width = 0;
    std::uint16_t value_width = 0;
    std::int64_t slot_displacement = 0;
    std::int64_t stack_pointer_delta = 0;
    std::uint32_t caller_cleanup_bytes = 0;
    std::optional<Address> return_address;
    // Whole-memory SSA state observed by this implicit stack access.
    std::optional<std::uint32_t> memory_input_version;
};
struct Call {
    std::optional<Address> direct_target;
    ExpressionPtr indirect_target;
    std::optional<std::uint32_t> memory_input_version, memory_output_version;
    std::vector<MemoryPartitionEffect> memory_partition_effects;
    // Set when a delayed transfer's target is evaluated in an earlier block.
    // SSA uses this point-in-time source state rather than the state after its slot.
    std::optional<BlockId> delay_slot_snapshot_block;
    std::optional<std::uint64_t> delay_slot_snapshot_instruction;
    // ABI argument-register state at the call site. Populated only by the
    // overload of to_ssa that receives the registers to track.
    std::vector<RegisterValue> register_inputs;
    // A batch type-recovery pass may annotate a known direct call with its
    // modeled ABI result. SSA gives that ABI result a new version at the call.
    std::optional<RegisterOperand> return_register;
    std::optional<std::uint32_t> return_version;
    types::TypePtr result_type;
    // ABI outputs, including represented overlapping register views. Versions
    // are parallel to register_writes after SSA; arguments precede these writes.
    std::vector<RegisterOperand> register_writes;
    std::vector<std::uint32_t> register_output_versions;
    // Provenance for Windows ABI-generated whole-YMM unknown values whose
    // low XMM halves remain preserved. Explicit writes are not listed here.
    std::vector<RegisterOperand> abi_upper_half_writes;
    std::optional<X86StackControlEffect> x86_stack_effect;
};
struct Branch {
    std::string condition;
    std::optional<Address> true_target, false_target;
    ExpressionPtr predicate;
    ExpressionPtr indirect_target;
    std::optional<BlockId> delay_slot_snapshot_block;
    std::optional<std::uint64_t> delay_slot_snapshot_instruction;
    // MIPS branch-likely conditions select whether execution enters the
    // delay-slot block; a false result annuls that slot.
    bool annuls_delay_slot_on_false = false;
};
struct Return {
    ExpressionPtr value;
    std::optional<BlockId> delay_slot_snapshot_block;
    std::optional<std::uint64_t> delay_slot_snapshot_instruction;
    std::optional<X86StackControlEffect> x86_stack_effect;
};
enum class IntrinsicMemoryEffect { none, read, write, unknown };
struct Intrinsic {
    std::string name;
    std::vector<ExpressionPtr> operands;
    IntrinsicMemoryEffect memory_effect = IntrinsicMemoryEffect::unknown;
    std::optional<std::uint32_t> memory_input_version, memory_output_version;
    std::vector<MemoryPartitionEffect> memory_partition_effects;
    std::vector<RegisterOperand> register_writes;
    std::vector<std::uint32_t> register_output_versions;
    std::optional<ValueType> result_type;
    // x87 uses logical ST(i) indexes relative to TOP. Preserve push/pop depth
    // even when concrete stack rotation remains opaque in this IR.
    std::int8_t x87_stack_delta = 0;
    // Abstract architectural TOP and physical tag state at this operation.
    // Unknown fields remain empty when an environment restore or CFG join is opaque.
    std::optional<X87StackState> x87_stack_state;
    // Optional explicit value formulas aligned with register_writes. When
    // present, each expression reads the pre-instruction state and defines
    // the corresponding output register in parallel.
    std::vector<ExpressionPtr> register_output_values;
};
using Statement = std::variant<Assign, Store, Call, Branch, Return, Intrinsic>;

struct InstructionOrigin { Address address; std::uint64_t instruction_id = 0; };
struct LiftedInstruction { InstructionOrigin origin; Statement statement; };
enum class TrapEdgeKind { unconditional, may_trap };
struct TrapEdge {
    Address source;
    TrapEdgeKind kind;
    std::string operation;
    // When available, the exact i32 condition that selects the trap edge.
    // Opaque but spec-defined predicates are represented as typed expressions.
    ExpressionPtr condition;
};
struct LiftedBlock {
    BlockId id;
    Address begin;
    std::vector<LiftedInstruction> instructions;
    std::vector<BlockSuccessor> successors;
    // Possible terminal traps are kept separate from normal successors so
    // control-flow structuring does not mistake them for ordinary exits.
    std::vector<TrapEdge> trap_edges;
    struct ExceptionHandlerDispatch {
        Address target{{0}, 0};
        std::optional<std::string> catch_type;
        bool catch_all = false;
        // Decoded instructions in this block whose exception-table coverage
        // routes to this handler clause. The CFG edge is block-level, while
        // this preserves the bytecode-level source sites without pretending
        // their local states are interchangeable.
        std::vector<Address> protected_throw_sites;
    };
    std::vector<ExceptionHandlerDispatch> exception_handlers;
    enum class ExceptionMemoryTiming { before_instruction, opaque_effect };
    struct ExceptionMemoryEdge {
        Address source;
        Address target;
        ExceptionMemoryTiming timing;
    };
    // The handler's memory input is selected at the throwing bytecode, not
    // from the block's normal exit. Opaque effects must define unknown memory.
    std::vector<ExceptionMemoryEdge> exception_memory_edges;
    struct PhiInput { BlockId predecessor; std::uint32_t version = 0; };
    struct Phi { RegisterOperand destination; std::uint32_t version = 0; std::vector<PhiInput> inputs; };
    std::vector<Phi> phis;
    struct MemoryPhiInput { BlockId predecessor; std::uint32_t version = 0; };
    struct MemoryPhi { std::uint32_t version = 0; std::vector<MemoryPhiInput> inputs; };
    std::optional<MemoryPhi> memory_phi;
    struct MemoryPartitionPhiInput { BlockId predecessor; std::uint32_t version = 0; };
    struct MemoryPartitionPhi {
        std::string partition;
        std::uint32_t version = 0;
        std::vector<MemoryPartitionPhiInput> inputs;
    };
    std::vector<MemoryPartitionPhi> memory_partition_phis;
    struct SwitchCase { std::uint64_t value = 0; Address target{{0}, 0}; };
    struct SwitchDispatch {
        ExpressionPtr selector;
        std::vector<SwitchCase> cases;
        std::optional<Address> default_target;
        bool complete = true;
    };
    // Populated by clients that have authoritative switch analysis metadata.
    // A CFG with multiple successors and no complete dispatch remains ambiguous.
    std::optional<SwitchDispatch> switch_dispatch;
};
struct LiftedFunction {
    FunctionId id;
    Address entry;
    std::vector<LiftedBlock> blocks;
    std::vector<std::string> diagnostics;
};
struct StructuredPseudocode {
    std::string text;
    bool used_fallback = false;
    std::string fallback_reason;
};

using ManagedCallSignature = ManagedMethodSignature;
struct ManagedCilExceptionRegion {
    std::uint32_t try_offset = 0, try_length = 0;
    // Indexes into exception_clauses, retaining metadata order for one try.
    // Nested tries are searched before containing tries, independently of
    // where their clauses occur in the metadata section chain.
    std::vector<std::uint32_t> clause_indices;
};
struct ManagedCilDecompilation {
    LiftedFunction lifted;
    StructuredPseudocode pseudocode;
    std::vector<std::uint32_t> referenced_tokens;
    std::vector<ManagedGenericParameter> declaring_type_generic_parameters;
    std::vector<ManagedGenericParameter> method_generic_parameters;
    bool complete = true;
    std::vector<CilExceptionClause> exception_clauses;
    std::vector<ManagedCilExceptionRegion> exception_regions;
};
// Lifts the supported evaluation-stack subset of one decoded managed method
// into the common IR. Signatures resolved by inspect_managed_methods are used
// automatically; an explicit map can override that metadata for callers that
// have independently resolved tokens. Unresolved calls fail rather than guess.
HEXLAB_DECOMPILER_EXPORT Result<ManagedCilDecompilation> decompile_managed_method(
    const ManagedMethodAnalysis &, const std::map<std::uint32_t, ManagedCallSignature> &call_signatures = {});

// Lifts the blocks owned by a recovered analysis function. The input snapshot
// is immutable; lifting neither mutates analysis facts nor reads the image.
HEXLAB_DECOMPILER_EXPORT Result<LiftedFunction>
lift_function(const FunctionRecord &, const FunctionSnapshot &);
// JVM field and invocation semantics require classfile constant-pool metadata.
// Other architectures ignore this optional pointer.
HEXLAB_DECOMPILER_EXPORT Result<LiftedFunction>
lift_function(const FunctionRecord &, const FunctionSnapshot &, const JvmMetadata *jvm_metadata);
// WebAssembly memory instructions are validated against the module memory
// index space; other architectures ignore this optional metadata pointer.
HEXLAB_DECOMPILER_EXPORT Result<LiftedFunction>
lift_function(const FunctionRecord &, const FunctionSnapshot &, const JvmMetadata *jvm_metadata,
              const WasmMetadata *wasm_metadata);
HEXLAB_DECOMPILER_EXPORT Result<LiftedFunction>
lift_function(const FunctionRecord &, const FunctionSnapshot &, const JvmMetadata *jvm_metadata,
              const WasmMetadata *wasm_metadata, const DexMetadata *dex_metadata);
// Optional host-only hook for validated opaque instruction semantics. The
// callback is consulted only for Opcode::opaque; it cannot alter decoded CFG.
// Decline preserves the existing opaque fallback. Errors abort the lift.
using OpaqueInstructionLifter = std::function<Result<std::optional<Intrinsic>>(const Instruction &)>;
HEXLAB_DECOMPILER_EXPORT Result<LiftedFunction>
lift_function(const FunctionRecord &, const FunctionSnapshot &, const JvmMetadata *, const WasmMetadata *,
              const OpaqueInstructionLifter &);
// DEX invoke results use validated method/prototype return shapes retained by
// the loader. Other architectures ignore this optional metadata pointer.
HEXLAB_DECOMPILER_EXPORT Result<LiftedFunction>
lift_function(const FunctionRecord &, const FunctionSnapshot &, const JvmMetadata *, const WasmMetadata *,
              const DexMetadata *, const OpaqueInstructionLifter &);
// Attaches recovered switch selectors and case indexes to matching lifted
// dispatch blocks. A default is populated only when a complete analysis and
// CFG identify exactly one additional successor beyond the table targets.
HEXLAB_DECOMPILER_EXPORT void attach_switch_analysis(LiftedFunction &, const SwitchAnalysis &);
// Converts explicit register assignments and modeled memory effects into
// deterministic SSA versions and inserts register/memory phi nodes at joins.
// Calls and unknown intrinsics conservatively define a new whole-memory state;
// intrinsic memory behavior can be classified with IntrinsicMemoryEffect.
// Explicit call register_writes define fresh versions after argument snapshots;
// a matching return_register shares its output version.
// Unknown instructions remain explicit and do not define register versions.
// The optional overload snapshots only selected ABI argument registers.
// Duplicate registers are ignored.
HEXLAB_DECOMPILER_EXPORT Result<LiftedFunction> to_ssa(const LiftedFunction &);
HEXLAB_DECOMPILER_EXPORT Result<LiftedFunction> to_ssa(
    const LiftedFunction &, std::span<const RegisterOperand> call_argument_registers);
// Propagates proven SSA constants and folds supported fixed-width integer
// expressions. Unsupported operations remain unchanged.
HEXLAB_DECOMPILER_EXPORT Result<LiftedFunction> simplify_constants(const LiftedFunction &);
// Applies local, width-aware identities to integer/boolean bit-vector expressions.
// It does not infer values, reorder operations, or rewrite memory expressions.
HEXLAB_DECOMPILER_EXPORT Result<LiftedFunction> simplify_identities(const LiftedFunction &);
// Applies local, width-aware identities to integer/boolean bit-vector expressions.
// It does not infer values, reorder operations, or rewrite memory expressions.
HEXLAB_DECOMPILER_EXPORT Result<LiftedFunction> simplify_identities(const LiftedFunction &);
// Removes unused SSA register definitions and dead phi nodes when their value
// expressions are pure. Memory reads and all explicit side effects are kept.
HEXLAB_DECOMPILER_EXPORT Result<LiftedFunction> eliminate_dead_code(const LiftedFunction &);
// Names non-overlapping, constant-offset locals addressed through a recognized
// frame pointer. Dynamic and ambiguous accesses retain ordinary memory form.
HEXLAB_DECOMPILER_EXPORT Result<LiftedFunction> recover_stack_variables(const LiftedFunction &);
HEXLAB_DECOMPILER_EXPORT std::string format_pseudocode(const LiftedFunction &);
// Emits C-like control flow for reachable acyclic CFGs with nested two-way
// conditionals, edge-lowered phis and explicit terminal returns, plus canonical
// loops and simple conditional early returns. Ambiguous or unsupported CFGs retain the
// label/goto formatter with an explicit fallback reason.
HEXLAB_DECOMPILER_EXPORT StructuredPseudocode format_structured_pseudocode(const LiftedFunction &);

} // namespace hexlab::decompiler
