# Decompiler control-flow formatting

## Typed x86 scalar arithmetic

Scalar `ADD`, `SUB`, `AND`, `OR`, `XOR`, `CMP`, and `TEST` in x86-32 and
x86-64 with decoder-reported FLAGS writes retain the decoded destination width
in their IR operands and operation name (`x86_add_i64`, for example). The
explicit intrinsic carries decoded GPR and FLAGS definitions; compare/test do
not claim a destination result. Incomplete synthetic instruction facts fall
back to the generic lift path. Memory
sources are marked read-only, while memory destinations of modifying
operations remain conservative read-modify-write effects. This preserves
architectural effects alongside the separate same-block Jcc predicate model
documented below. It does not claim a complete FLAGS SSA model for arbitrary
control flow or undefined flag states.

## Typed x86 SIMD lifting

The lifted IR models the decoder's initial SSE2 slice with `ValueType::vector`
and typed intrinsic results. `PADDD`/`PSUBD` and dword comparisons carry
`i32x4`; `PADDQ`/`PSUBQ` carry `i64x2`; word and byte comparisons carry
`i16x8` and `i8x16`. Packed bitwise
operations carry a 128-bit bit-vector shape. `MOVDQA` and `MOVDQU` remain opaque
128-bit vectors because those moves do not establish an element interpretation.
`ADD/SUB/MUL/DIVSS` and `...SD` retain the full XMM destination type, and the
source lane is explicitly identified as `x86_low_f32` or `x86_low_f64`.
`MOVSS`/`MOVSD` use the same source typing and retain their decoded register
writes or memory effects. Pseudocode names the operation and type shape, while
the IR preserves the decoded XMM writes and memory read/write classification.
Diagnostic and structured pseudocode render XMM, YMM, ZMM, and opmask registers
as `xmmN`, `ymmN`, `zmmN`, and `kN`, including SSA versions and phi edge copies.
These names keep vector and mask values distinct from `rN` general registers.

This layer does not claim complete SSE semantics: it does not model MXCSR,
floating-point exception flags, NaN behavior, or exact upper-lane merge/zero
rules for scalar moves and arithmetic. Those details stay inside explicit
operation names and full-register inputs/outputs instead of guessed lane
assignments. This section describes the initial SSE2 layer; later VEX/EVEX
slices have their own bounded coverage.

EVEX.128/.256/.512 `VPACKSSWB`, `VPACKSSDW`, `VPACKUSWB`, and `VPACKUSDW`
lift through typed intrinsics with signed word/dword inputs and narrowed
signed/unsigned byte/word results. Packing repeats independently within each
128-bit group, with source-one results before source-two results. Intrinsic
names retain both input shapes, the active result shape, merge/zero masking,
and upper-ZMM clearing for VL forms. Merge forms include the old destination
and K-register inputs; memory sources retain read effects. Broadcast and
unmodeled encodings remain unsupported. See [x64 SIMD coverage](../../docs/x64-simd-coverage.md)
for the exact opcode and width whitelist and the caller-owned pure evaluator.

`format_pseudocode` is the lossless diagnostic formatter: it prints each lifted
basic block with labels and preserves control transfers as gotos.

For x86 and x86-64, `lift_function` carries a same-block `CMP` or `TEST`
predicate into a following conditional branch when both operands are registers
or immediates and neither flags nor a compared register is overwritten first.
Equality and signed/unsigned relational conditions retain their bit-vector
meaning through SSA. It also carries supported flag producers across acyclic
CFG edges when the destination block has one in-function predecessor. Joins,
loop components, calls, opaque instructions, memory comparisons and overwritten
flags or operands retain explicit condition identifiers.

The same-block flag model also covers register/immediate `ADD`, `SUB`, `AND`,
`OR`, `XOR`, and immediate-count `SHL`, `SHR`, and `SAR` in x86-32 and x86-64.
These instructions lift a width-typed result assignment and preserve the
implicit carry, zero, sign, overflow, and parity facts needed by a following
Jcc. Addition carry and signed overflow, subtraction borrow and signed
overflow, logical-operation cleared carry/overflow, and one-bit shift carry/
overflow use explicit bit-vector predicates. A shift count of zero does not
produce a guessed condition; undefined or unsupported shift flags leave that
Jcc opaque. A later instruction that overwrites the relevant flags or captured
source registers invalidates the predicate. Memory destinations,
carry-dependent arithmetic, `INC`/`DEC` carry preservation, and flag propagation
through joins or loops are still not reconstructed.

For AArch64, scalar lifting models `ADD`/`SUB` register and immediate forms,
the result of their flag-setting variants, and `MOVN`/`MOVZ`/`MOVK` move-wide
values. NZCV is not yet a first-class SSA value.
Register 31 is treated as `SP`/`WSP` where the decoded operand selects the
stack pointer and as a constant-zero source/discarded destination where it
selects `XZR`/`WZR`. `CBZ`, `CBNZ`, `TBZ`, and `TBNZ` become explicit
bit-vector predicates. A same-block `SUBS` to `XZR` (the `CMP` alias) can feed
all modeled `B.cond` conditions, including signed and unsigned relations, and
those predicates retain their SSA versions. Predicate propagation stops if a
compared register or NZCV is overwritten, or if a call intervenes. Other flag
producers and cross-block flag state remain opaque conditions. Floating point,
SIMD, system state, carry-dependent arithmetic, and complete architectural
flag-state SSA are outside this scalar lifting slice; unsupported instructions
remain explicit intrinsics rather than guessed expressions.

Scalar A64 `BFM` also lifts to typed field masks, shifts, and a merge with the
old destination. This covers `BFI`, `BFXIL`, and zero-source `BFC`, including
W-form zero extension into the X view; malformed forms retain an intrinsic.
See [preserving bitfield moves](../../docs/a64-preserving-bitfields.md) for the
accepted encoding and operand bounds.

`simplify_constants` is an optional SSA pass. It propagates proven constant
versions across blocks and folds fixed-width add/subtract/multiply, bitwise,
shift, zero-extension, and sign-extension expressions. Arithmetic wraps at the
result width. Unsupported operations, unknown values, memory effects, and
out-of-range shifts remain explicit. In call-containing functions, propagation
stays within each block and clears at each unknown call; facts do not
cross blocks until register clobbers are modeled.
For JVM integer constants, `i2b` and `i2s` now fold with signed extension from
8 and 16 bits, while `i2c` folds with zero extension from 16 bits. Each keeps
the JVM-required 32-bit stack result.
When a terminal branch has a constant boolean predicate and both CFG edges are
validated, the pass selects the feasible edge, removes unreachable blocks, and
removes phi inputs from the discarded paths. Other branch shapes remain
unchanged. Invalid duplicate SSA definitions are rejected.

For small pure expressions, the same pass can also prove opaque predicates by
exhaustively evaluating all assignments to at most eight total symbolic input
bits. It requires every valuation to produce the same boolean result, and
then uses the normal CFG cleanup. Only preceding assignments in the same block
are expanded. Calls, stores, intrinsics, memory expressions,
unknown values, cycles, and expressions outside fixed node/depth/work caps are
barriers. Phi values are independent inputs, so path-sensitive correlations
are not inferred. See
[`docs/decompiler-opaque-predicates.md`](../../docs/decompiler-opaque-predicates.md).

`simplify_identities` is a separate local bit-vector cleanup pass. It
substitutes bounded pure SSA definitions within a block and across acyclic CFG
edges with exactly one predecessor, then applies width-matched identities such
as `x & 0`, `x | width_mask`, `x ^ x`, and addition or shifts by zero. Joins,
cycles, delay-slot edges, duplicate block identities, opaque calls, and
intrinsics stop inherited facts. It also simplifies idempotent `x & x` and
`x | x` for pure matching expressions, cancels `(x + c) - c` or `(c + x) - c`
when fixed-width types and masked constants match, and rewrites `(x << k) >>
k` to the equivalent low-bit mask for a nonzero in-range logical shift. The
cancellation relies on modular bit-vector arithmetic, so wraparound is
preserved. Substitution and expression size are bounded; the pass returns a
copied function, checks that operands have the result width, and leaves
unsupported or ill-typed operations explicit. It does not reorder expressions,
rewrite memory reads, or model processor-specific undefined behavior; memory
and unknown values are excluded from structural rewrites that could erase or
duplicate their evaluation. The desktop pseudocode pipeline applies this pass
after SSA constant propagation.

The pass also recognizes the fixed-width identity `(x << k) >> k` for a
nonzero in-range logical shift and rewrites it to `x & ((1 << (width-k)) - 1)`.
This exposes the surviving low-bit mask in common bit-clearing obfuscation
sequences. It requires a pure operand and equal, valid shift counts; arithmetic
right shifts and out-of-range counts are left unchanged.

The identity pass also cancels opposite constant rotations of the same pure
SSA bit-vector, such as `rotr(rotl(x, k), k)`, when both counts agree modulo
the operand width. This follows the IR's fixed-width rotate semantics and is
bounded to expressions of at most 256 nodes; nonconstant counts and expressions
that may read memory remain unchanged.

The pass also flattens a nested `select_if` when its outer and inner selectors
are the same exact SSA expression. Branch values and the selector must be pure,
total integer/boolean bitvectors within the 256-node cap; division, memory,
unknown values, and unversioned registers are excluded. This handles true-arm
and false-arm nesting without inferring predicate equivalence across CFG paths.
See [`docs/decompiler-opaque-predicates.md`](../../docs/decompiler-opaque-predicates.md).

`eliminate_dead_code` removes unused SSA assignments and phi nodes when their
right-hand sides use registers/constants and a whitelist of total integer or
Boolean bit-vector operations. Potentially trapping division/remainder,
floating-point, memory, and unrecognized unary/binary operators remain. It
iterates to a fixed point, so deleting a dead consumer can expose a dead
definition chain. Stores, calls, and intrinsics remain because their effects
are observable or unknown. The pass leaves unversioned assignments alone and
rejects duplicate SSA definitions.

Memory SSA keeps a coarse whole-memory chain as the fallback for all accesses.
It also attaches partitions to proven stack slots, explicit absolute byte
ranges, and bounded byte ranges reached through one proven pointer root.
Pointer-relative ranges require checked constant pointer offsets (or a finite
supported index range). A pointer phi may also use one range when all incoming
values prove the same root; the pass joins their offsets into a bounded
interval and treats every byte in that interval as potentially accessed.
Phis joining different roots retain opaque provenance, and unrelated roots
are never treated as disjoint. Unbounded or wrapping address arithmetic stays
on whole-memory SSA. Stores advance the target partition and any other
partition that may overlap; unclassified stores, calls, and writing or
unknown intrinsics clobber the partitions that may be reached. CFG joins carry
partition phis. The coarse chain still advances for every write, so existing
consumers remain conservative while partition-aware passes can use the
additional alias facts. Intrinsics carry an `IntrinsicMemoryEffect` classification for no
memory, read-only, write, or unknown behavior. Unknown intrinsics default to a
memory clobber, while known pure `nop` and read-only `cmp` facts preserve the
incoming versions. The CLI `--decompile` path performs
bounded interprocedural summaries over recovered direct calls. It keeps ABI
boundary register and memory effects unknown, excludes incomplete and
exported/interposable bodies from summary providers, and still uses exact
return constants when the callee body proves them. For a complete, locally
bound candidate set, it also runs bounded interprocedural ABI type recovery and
formats inferred prototypes and typed stack locals. Otherwise it uses
conservative per-function type recovery. If summary analysis exceeds its
budget, the CLI reports that fact and continues with the local optimizer
pipeline.

`format_structured_pseudocode` recognizes reachable acyclic CFGs
with nested two-way conditionals. It uses nearest common post-dominators as
region joins, finds blocks by address rather than storage order, and lowers SSA
phi nodes into assignments on the corresponding incoming edges. Multiple
explicit terminal returns use an analysis-only virtual exit, allowing shared
SSA joins before a return choice and early returns around nested regions.
Return-decision trees can reuse a terminal decision block across incoming
paths when each path supplies a complete, predecessor-specific SSA phi input;
the formatter emits that block in each guarded arm so the corresponding input
copy stays on its original edge. Shared nonterminal blocks outside this bounded
return shape still use the fallback.
Shared instructions are emitted once, and straight-line setup can precede the
first conditional. It also emits
a simple one-arm `if` for a conditional early return, preserving the inverted
condition when the return is on the false edge. Post-dominator analysis is
bounded to 1,024 blocks.

`attach_switch_analysis` transfers recovered `SwitchAnalysis` sites into lifted
blocks. It uses the analysis selector register and case indexes. It assigns a
default only when complete analysis and the dispatch CFG expose exactly one
additional destination beyond all table targets; otherwise the dispatch stays
incomplete and formatting falls back.

Lifted blocks can carry `SwitchDispatch` metadata containing the selector
expression, case values and destinations, an explicit default destination,
and a completeness flag. The formatter validates that metadata against the
dispatch block's CFG edges before emitting a C-like `switch`. It structures
disjoint straight-line arms that return, and arms that converge on one terminal
return join. Shared joins receive edge-specific SSA phi assignments and
explicit `break` statements. Duplicate labels, unresolved or mismatched
destinations, missing defaults, incomplete tables, fallthrough, conditional or
nested arms retain the explicit label/goto formatter with a reason. The
metadata is separate from instruction lifting because switch table recovery
requires image analysis and is not part of `lift_function`'s current inputs.

The formatter also handles two reducible loop shapes: a pre-tested `while`
with one condition header, a single-successor chain of straight-line body
blocks, and one terminal exit; and a post-tested `do ... while` whose latch
branches back to its body or exits.
For a post-tested loop with the back edge on the false branch, it inverts the
rendered condition. The `while` form lowers header phis with exactly one
preheader input and one back-edge input into assignments before and at the end
of the loop body. For a multi-block body, the recurrent phi value is selected
from the final latch block regardless of block storage order. Other loop
phis, multiple latches, side exits, internal branches, and nested loop bodies
remain on the explicit label/goto path until their edge copies can be
represented faithfully.

Every unsupported shape returns `format_pseudocode` output with
`used_fallback == true` and a reason. Switch destinations without complete
selector, case-index, and default-edge metadata retain gotos rather than
receiving guessed case labels. Cycles,
irreducible flow, cross-region sharing that would require code duplication,
unterminated multi-exit arms, and unsupported phi shapes also retain the
fallback, keeping the CFG readable without claiming semantics the structurer
does not currently model.

The opt-in `recover_stack_variables` pass names proven non-overlapping local
slots reached through frame pointers or uniquely adjusted stack pointers. It
follows constant aliases across blocks and keeps stack-derived addresses raw
when they escape or cross conflicting phi inputs. `recover_types` exposes the
same locals as named typed records, and assigns stable names and ABI parameter
indices to register values for client variable views. Indexed, overlapping,
and ambiguous accesses stay in memory form. See
[`docs/decompiler-stack-variables.md`](../../docs/decompiler-stack-variables.md)
for recognized frame registers and the limits of the analysis.

## Interactive annotations

The desktop pseudocode pane can rename a recovered function, rename a recovered
stack slot at its first observed access, and attach a comment to a selected
instruction. These operations use the workspace's shared address annotations,
so they participate in project undo/redo and persistence and appear in the
disassembly, reference labels, and annotation browser. A stack-slot name is
currently anchored to an instruction address; it does not rewrite lifted IR
register expressions or infer a variable's type. Comments appear alongside
their instruction origins in the pseudocode pane.

## Structured SSA edits

Library clients can use `replace_register_uses` to create an edited copy of a
lifted function by substituting one versioned SSA register use with a typed
expression. The operation visits nested unary and binary expressions,
instruction expression operands, switch selectors, and trap conditions. It
also visits the SSA base and index registers carried by memory-address
expressions. Those address components can only be replaced with a register
expression of the same register width; an arbitrary expression cannot be
represented in the current memory-address IR and is rejected. For ordinary
expression uses, the replacement's full `ValueType` must match. Call
register-input snapshots are updated when the replacement is a versioned
register expression of the same width; an arbitrary expression cannot be
represented by the snapshot and is rejected. Phi inputs are updated when the
replacement is a new version of the phi's same logical register; expressions
and versions of other registers cannot be represented by the current phi-input
IR and are rejected. The operation does not alter definitions, edges, or
instruction origins. The edit is rejected
without a versioned target, when the target is absent, or when a replacement
is incompatible; callers receive either the complete edited function or an
error, never a partially edited input.
This is a caller-directed IR transformation and does not establish that the
replacement is semantically equivalent. Format the returned function with
`format_pseudocode` or `format_structured_pseudocode` to inspect the edited
result. Project persistence and undo/redo for arbitrary IR edits are not
provided by this library operation.

## Type recovery

The opt-in `recover_types` pass propagates register widths, signedness, pointer
evidence, and observed constant-offset pointee fields, and returns stable
source-facing variable identities. When the caller supplies
an ordered `AbiDescription::arguments` map, it also proposes a candidate
prototype from the contiguous prefix of observed ABI slots, including mixed
integer and floating register classes and exact stack slots. It stops at a
missing or unsupported slot rather than skipping it. The candidate is
heuristic metadata, not a confirmed source signature. See
[`docs/decompiler-type-recovery.md`](../../docs/decompiler-type-recovery.md)
for the inference rules and limits. Three or more contiguous same-width
observed fields may be grouped as an array member; the result is an access
shape heuristic and can conflate adjacent record members with an array.

## Virtual-call evidence

`analyze_virtual_call` provides a deliberately non-resolving annotation step
for x86 and x64 native virtual calls. A caller must already prove the
receiver's concrete aggregate type, the pointer-aligned vtable slot byte
offset, and the complete function type. When it also supplies the proven
vfptr offset, candidates must have an imported CodeView `LF_VFTABLE` entry at
that exact vfptr and slot index. The legacy introduction-slot path remains
available when no vfptr offset is supplied. Both paths require an exact
function signature: return and parameter types, qualifiers, variadic state,
and calling convention must match, while parameter display names are ignored.
Multiple declarations are preserved as ambiguous candidates; no match remains
untyped. Every candidate carries the
caller-supplied provenance string (for example, the receiver assignment and
PDB vftable symbol used to
establish the facts).

This is not a vtable reader and does not resolve a call target. The current PDB
symbol model retains data-symbol identity and address but does not describe
individual vftable entries. Therefore callers must not use this annotation to
rewrite an indirect call or create a direct call edge. Overridden or inherited
slots without an explicit method slot, uncertain receiver classes, uncertain
slot arithmetic, and ABI-adjustor thunks remain indirect and unannotated.

## x87 numeric operations and compare branches

FADD/FMUL/FSUB/FSUBR/FDIV/FDIVR real forms lift to 80-bit SSA arithmetic;
FCHS/FABS lift to unary ST(0) updates. FCOMI/FUCOMI and popping variants
remain effectful intrinsics with SSA-versioned EFLAGS, and a following Jcc
uses CF/PF/ZF/SF/OF to retain unordered outcomes. Legacy FCOM/FUCOM forms also
propagate C0/C2/C3 through FNSTSW AX and SAHF to Jcc conditions that depend
only on CF/PF/ZF. These facts survive acyclic CFG edges only when every path
agrees. Floating exception state, x87 TOP/stack rotation, arithmetic rounding,
and SAHF predicates involving SF/OF remain opaque. See
[`docs/decompiler-x87.md`](../../docs/decompiler-x87.md).

The identity pass also removes `~~x` and folds `x & ~x`, `x | ~x`, and
`x ^ ~x` for structurally equal, pure integer bitvectors of the same width.
It detects these complements across same-operation associative groups without
reordering effects or crossing SSA versions.
