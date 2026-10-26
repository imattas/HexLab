# WebAssembly function lifting

`lift_wasm_function` is a bounded, fail-closed scalar stack lifter. It consumes a recovered function snapshot, uses each instruction's function-relative address, and constructs typed common-IR expressions from stack constants and scalar numeric operators. It splits the flat function stream into blocks at structured-control operators, branch targets, and fallthroughs. Operand stacks are propagated across reachable CFG edges; matching stack shapes at joins become explicit `wasm_stack` phi values, including loop backedges. A function with a supported return can be represented as a common-IR `Return`.

## Supported instructions

- `nop`, `end`, `return`, `drop`
- `block` and `loop` with an empty or single MVP result type (`i32`, `i64`, `f32`, or `f64`)
- `if`/`else` with an empty or single MVP result type, lowered to conditional/unconditional CFG branches; a result-typed `if` must have an `else` arm
- `br` and `br_if` when their lexical label depths resolve to a block/loop/if label and the complete live stack shape is preserved at the target
- `br_table` with up to eight explicit cases, when every case and default depth resolves to an explicit block/loop/if label and preserves the target stack shape; this becomes a common-IR switch dispatch
- `select` on same-typed values, emitted as a typed conditional expression
- `i32.const`, `i64.const`, `f32.const`, `f64.const`
- Numeric comparisons and scalar operators in opcodes `0x45..0xa6` when the exact operand types are known. Comparisons produce a 32-bit Wasm integer containing 0 or 1, so their results can feed `if`, `eqz`, or further integer operations. Signed and unsigned integer comparisons retain distinct `slt`/`ult`-style operations.
- Integer division and remainder use width- and signedness-specific operations: signed division is named `wasm_i32_div_s_trap_zero_or_overflow` (or the i64 form); unsigned division and signed/unsigned remainder are named `wasm_i32_*_trap_zero` (or the i64 form). Each adds a conditional trap edge in `LiftedBlock::trap_edges` while preserving the normal continuation. The pseudocode formatter renders these `wasm_*` operations as named calls, retaining may-trap semantics.
- `unreachable` terminates its block, emits an explicit `wasm_unreachable()` intrinsic, and adds an unconditional trap edge without a normal successor.
- Core numeric conversions and reinterpret operations in opcodes `0xa7..0xbf`. Each conversion retains exact input/output types and signedness in a named IR operator; float-to-integer truncations are marked as trapping conversions.
- Scalar `i32.load`, `i64.load`, `f32.load`, `f64.load`, sign/zero-extending narrow integer loads, and the matching scalar stores in opcodes `0x28..0x3e`. These require loader metadata proving exactly one module memory, check the natural alignment exponent and Wasm32 offset, and lower the effective address with a 32-bit addition into common memory SSA.

The CFG builder accepts at most 100,000 instructions, 16,384 blocks, 128 nested labels, and 128 operand-stack values. At every reachable join, stack height and each slot's type must match exactly; values are carried with stack pseudo-registers and explicit phis. For a single-result block or `if`, its normal end and branches to that label must carry the declared result value. MVP loop labels have no branch parameters, so branches back to the loop header must preserve the entry stack exactly. Indexed block types, multi-value signatures, branch stack trimming, and incompatible shapes are rejected. The processor decoder currently caps a single `br_table` at eight cases.

## Explicit unsupported cases

The loader now type-checks complete MVP function bodies against module signatures, locals, globals, calls, and structured labels before mapping them. The current decompiler function snapshot still does not carry module function signatures or expanded local declarations. Therefore `local.*`, `global.*`, direct/indirect calls, indexed block types, and multi-value signatures fail as unsupported during lifting, even when the loader accepted the body. Scalar memory operations require the module metadata pointer supplied by the CLI or desktop decompiler adapter; without it, or unless exactly one memory is declared/imported, they fail closed. Memory size/grow, multiple memories, out-of-bounds trap behavior, and exception edges remain unmodeled; the emitted memory operations describe normal-path reads/writes. Branches to the implicit function label, other trap behavior, malformed control nesting, stack underflow/type mismatch, branch stack trimming, and incompatible stack joins fail closed. `br_table` targeting the implicit function label is unsupported. Integer division/remainder edges identify the may-trap site but do not encode the exact divisor-zero or signed-overflow predicate. Float-to-integer conversions retain trapping operators but do not yet contribute trap edges.

No type is inferred for an unknown stack value. Unmodeled opcodes and unavailable immediates return `ErrorCode::unsupported`.
