# Plugin scalar instruction IR (ABI 1.22–1.24)

ABI 1.22 appends `HexLabProcessorExtension::decode_ir`, preserving every previous descriptor prefix and the existing V1/V2/V3 semantic-record layouts. The host reads the callback only when `struct_size` covers it. The host advertises `processor.ir.scalar` v1.24; modules using the original operators may require v1.22, comparisons require v1.23, and shifts require v1.24. A module should check host ABI minor/table size in `start` and retain the required legacy display callback (a clean-decline stub is sufficient). The [C-only example](../examples/plugins/scalar-ir/README.md) includes matching binary and package capability declarations.

ABI 1.23 extends the accepted operation set without changing any record
layout or existing enum value. It appends exact integer comparison operations.
ABI 1.24 appends `SHL`, logical `LSHR`, and arithmetic `ASHR`; the host
advertises `processor.ir.scalar` v1.24. Modules should require the capability
minor that introduced every operator they use.

This slice covers custom native instructions with unconditional fallthrough and pure full-register integer results. It neither maps a mnemonic to a built-in opcode nor changes decoded control flow. The callback supplies a fixed host-owned `HexLabInstructionIR`: the existing `HexLabSemanticInstructionV3`, up to 32 `HexLabScalarIRNode` records, and up to eight `HexLabScalarIROutput` records. It returns 1 to claim, 0 to decline, or a negative failure status. Scalar-IR callbacks are tried before semantic V3/V2/V1 callbacks, in plugin/extension registration order. A malformed claimed record, exception, invalid status or callback failure quarantines the whole processor extension, changes semantic generation, and returns an explicit error instead of silently substituting another meaning.

## Expressions and exact effects

Nodes describe 8/16/32/64-bit integer constants, register reads, add/subtract/multiply, AND/OR/XOR, bitwise NOT, and shifts. Arithmetic wraps to its declared width; `is_signed` retains interpretation metadata rather than changing modular arithmetic. Every operation's input width and signedness must exactly match its result. ABI 1.23 adds `EQ`, `NE`, unsigned `ULT`/`UGE`/`ULE`/`UGT`, and signed `SLT`/`SGE`/`SLE`/`SGT`. A comparison yields a same-width integer containing exactly zero or one; the operation selects the ordering interpretation regardless of `is_signed`. ABI 1.24 adds `SHL` (left shift with zero fill), `LSHR` (logical right shift), and `ASHR` (arithmetic right shift with sign extension). Shift counts must be less than operand width; constant counts outside that range are rejected. For a dynamic count, plugins should claim the instruction only when they can guarantee in-range counts and matching architectural semantics. Masked or otherwise special out-of-range behavior is unsupported unless modeled with supported nodes. This models set-on-condition instructions without claiming flag-register effects. Constant comparisons fold through the existing exact bit-vector optimizer; dynamic predicates remain typed expressions. There are no implicit casts, loads/stores, divisions, floating values, vectors, traps, calls, or branch nodes.

This comparison slice follows the same explicit signed/unsigned predicate
separation used by Ghidra's P-code integer comparison operations, adapted to
HexLab's same-width integer outputs and exact register-output model rather
than importing Ghidra's implementation. See the [P-code operation reference](https://ghidra.re/ghidra_docs/languages/html/pcodedescription.html).

Each used node/output must have its complete `struct_size` and zero reserved fields. `value` is meaningful only for constants and must fit the declared bit width. `reg` is meaningful only for register leaves; it must be all zero otherwise. Unused child references are `HEXLAB_SCALAR_IR_NO_NODE`. Used references must point to preceding nodes, so forward links and cycles fail. Every node must contribute to an output. Output destinations must be unique and match their root width. DAG depth is capped at 16; the sum of expanded node visits across every output is capped at 1024, preventing a small shared DAG from causing exponential formatter/optimizer work.

The semantic record must have a length of 1?15 bytes, at least one explicit register/immediate operand, no memory/writeback, no delay slot, condition or transfer, and no flags/IP/hidden-state effects. Existing semantic limits still apply: four explicit operands and bounded implicit register lists. The union of decoded explicit/implicit register reads must equal the DAG register-leaf set, and the decoded write set must equal the output destination set. Extra declared effects, missing input dependencies, extra outputs and unsupported state all fail validation. All outputs read the instruction's incoming state and are defined in parallel; an output may also be an input.

Registers must pass the existing architecture/mode register validator and this slice's stricter native-width filter. Supported cases are x86 GPRs at the current 16/32/64-bit mode width, AArch64 X0?X30, nonzero RISC-V/MIPS GPRs at native width, PowerPC GPRs at native width, and 6502 A/X/Y. Partial-register writes, x86 high-byte views, stack/status/vector register banks, architectural zero-register references and special registers are excluded. The x86 stack pointer remains an ordinary full-width GPR in the existing register model. A32/Thumb and managed bytecode are outside this path; A32/Thumb automatic analysis currently does not delegate processor decoding. Authors can use a constant-zero node instead of a zero-register leaf.

## Host integration

`PluginManager::analysis_options` includes scalar-IR providers in the existing semantic-decoder identity. Analysis retains the validated instruction bytes, operands and effects in its existing derived facts; it does not serialize plugin pointers, C++ expressions or a new instruction payload. Automatic recovery continues to consult plugins only where the built-in decoder reports unsupported with no decoded instruction. This API does not override a successfully decoded built-in instruction. The direct `decode_with_extensions` helper retains its existing extension-first dispatch policy.

Native hosts explicitly opt into typed lifting with `plugins::lift_function_with_extensions` from `hexlab/plugins/runtime.hpp`. Existing `decompiler::lift_function` overloads preserve their behavior. The new host-only opaque-instruction hook is consulted only for `Opcode::opaque`; clean declines retain the existing opaque fallback. CLI, desktop and automation callers do not automatically switch to the new adapter in this slice.

The adapter requires a keyed `FunctionSnapshot` recovered with `manager.analysis_options(options)`, using the same analysis budget/configuration values supplied to lifting. Its engine fingerprint must match the current semantic generation and those exact options. Unkeyed snapshots or snapshots from stale/different provider sets return conflict. The host requests the IR again from the same immutable instruction bytes and verifies context, address, length, mnemonic, operands and effects against the analyzed fact before accepting formulas. Modules must be deterministic for a given address/encoded instruction and provider version; behavior must not depend on trailing lookahead bytes. Lifting passes only the instruction's own bytes, whereas analysis may provide a longer bounded prefix. Change the provider version when behavior/configuration changes.

```cpp
// `snapshot` is a keyed result recovered with manager.analysis_options(options).
auto lifted = hexlab::plugins::lift_function_with_extensions(
    manager, function, snapshot, options, stop);
if (!lifted) return lifted.error();
auto ssa = hexlab::decompiler::to_ssa(lifted.value());
if (!ssa) return ssa.error();
return hexlab::decompiler::format_pseudocode(ssa.value());
```

Conversion creates a host-owned `Intrinsic` with typed `register_output_values`, exact `register_writes`, and no memory effect. Existing SSA renames every formula before defining any output. Both pseudocode formatters show the formulas; multiple outputs use explicit `parallel { ... }` syntax so a swap is not misrepresented as sequential assignment. The example custom-0 RISC-V instruction produces a formula equivalent to `x10 = x12 + 5` with 64-bit modular arithmetic. Existing architecture flag-predicate recovery remains conservative across opaque instructions.

## Lifecycle and bounds

The manager lock covers each callback, validation and conversion. Unload on another thread waits until that work returns. Same-thread load/unload and recursive semantic/IR dispatch during a scalar-IR callback return busy, avoiding invalidation of active module/context references. Quarantine, load, unload and rollback all participate in the existing generation changes; scalar-only providers now count as semantic providers. The adapter checks generation on each instruction request and again before returning a function, so it never publishes a function assembled across provider generations.

No callback/context pointer escapes conversion. Already-returned IR is an owned immutable value and remains readable after unload; future requests against its former generation are stale. Reopening cached facts requires the expected semantic-provider identity and a live matching provider to obtain fresh formulas. The low-level `PluginManager::instruction_ir` additionally validates the caller-supplied semantic identity and exact instruction fact; callers needing snapshot provenance should use the runtime adapter.

At most 256 matching scalar providers are attempted per instruction and 4096 opaque instruction requests are made per function. Callback input is capped at 32 bytes and the accepted native instruction extent at 15. Cancellation is checked before/between instruction requests and after lifting. In-process callback execution cannot be preempted; a module must return promptly and avoid recursive dispatch. Resource limits, unsupported shapes and lifecycle conflicts are explicit results. The ABI 1.23 host `hexlab_plugins` Debug target and the standalone C example Debug target compiled and linked; no tests were run.
