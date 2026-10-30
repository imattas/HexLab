# Decompiler memory SSA

`to_ssa` versions the abstract memory state alongside register values. Each
modeled `Store` records the memory version it consumes and the version it
produces. Each lifted `MemoryValue` records the state observed by that load.
At a control-flow join where stores can reach the block, a `MemoryPhi` names
the predecessor-specific states; reads in the block then refer to the merged
version. This prevents dataflow consumers from treating a load as though it
were independent of earlier stores or branch choice.

Memory SSA retains a coarse whole-memory variable for ordering and as a
fallback. In addition, `to_ssa` creates bounded byte-range partitions for
explicit absolute ranges and pointer-relative accesses whose address has a
proven root and checked offset. Overlapping ranges in the same address space
or under the same pointer root share one partition; disjoint ranges can keep
independent versions. The partition identifies a byte range, not a named
source object. Unclassified stores and write-capable intrinsics still
invalidate every partition that may be affected, so a possible pointer alias
keeps its dependency.
Calls invalidate absolute-address and dynamic-address partitions, but preserve
stack partitions for slots that stack recovery has proven nonescaping and
nonoverlapping: those slots cannot be reached by an unknown callee. Escaped,
dynamic, or otherwise unclassified stack memory has no such partition and
continues to depend on whole-memory SSA. If more than 4,096 distinct absolute
ranges are present, global range partitioning is skipped while proven stack
partitions remain available.

The pointer-relative partitioner tracks a single base register's SSA origin.
Origins propagate through same-width copies, checked constant `add`/`sub`
offsets (including proven constant registers), and phis whose incoming origins
and offsets agree. A flat architecture address proven as a numeric constant
can also identify the same root and byte offset across registers. An indexed
access is partitioned only when its index is an exact constant or a finite
supported interval; interval accesses cover every possible byte. Unsupported
extensions, unbounded indices, nonconstant pointer arithmetic, or offset
overflow stay on whole-memory SSA. Accesses rooted at the same origin are
grouped by overlapping byte ranges, so stores at one constant offset preserve
facts for nonoverlapping ranges under that same root. Different roots are
always treated as potentially aliasing: a store through one root clobbers
every other root's partition, along with absolute and stack partitions. Calls
and unknown writes clobber all dynamic partitions. Conflicting phis receive an
opaque root, which remains may-alias with every other root.
This is a local must-alias refinement; it does not discover heap
allocation sites, prove distinct pointer roots disjoint, or model interprocedural
points-to facts.

Calls record the memory version they consume and define a new
version afterward, conservatively representing unknown callee writes. An
intrinsic records an `IntrinsicMemoryEffect`: `none` has no memory dependency,
`read` observes the current version, and `write` or `unknown` both observe and
define memory. Unknown is the default for opaque instructions; known `nop` and
`cmp` lowering use `none` and `read`, respectively. A later load therefore
depends on calls and opaque operations, and the memory-phi placement includes
their possible writes.
Unreachable blocks remain outside SSA renaming, matching register SSA.
Pseudocode formatting keeps the ordinary source-like load/store spelling;
version metadata is intended for analysis passes and inspection.

## Bounded call summaries

`hexlab/decompiler/optimizer.hpp` exposes `optimize_with_call_summaries` for
clients that own a batch of lifted bodies. The original `simplify_constants`
and `to_ssa` APIs keep their conservative behavior. This batch pass returns
optimized copies and one inspectable `FunctionCallSummary` per input, in the
original order; it does not mutate analysis facts or remove calls.

Each `CallSummaryInput` defaults to ineligible. The analysis owner must attest
that the body includes every possible effect and normal exit, and must exclude
imports, interposable symbols, unresolved bindings and incomplete recovery.
Duplicate entry addresses invalidate every candidate at that exact address;
address-space identity is part of the lookup key. Diagnostics, unresolved CFG
exits, indirect or delayed transfers, opaque values and intrinsics other than
the canonical `nop` prevent a proven summary. Direct calls are summarized
bottom-up only when their unique callees are also eligible. Recursive edges
and their dependent summaries stay unknown.

Architectural call/return bookkeeping is separate from the lifted body. The
client must provide `boundary_register_effects_known` and the complete
`boundary_register_writes` list before register preservation can be inferred.
`boundary_memory_effect` defaults to `unknown`. For example, a leaf body with
no stores does not by itself prove that an x86 call preserves the coarse
whole-memory state: pushing the return address is a boundary write. A caller
must explicitly establish a boundary memory effect of `none` or `read` before
a store-free body can yield a no-write summary. These contracts describe the
complete callable boundary, including any ABI or architecture-specific effects
omitted from the body IR.

The summary unions register writes and possible memory reads/writes across
all modeled blocks and known callees. Caller-side constant propagation remains
within each basic block. A known register-effect summary discards facts for
every alias of a written register, including width/high-byte variants and
overlapping XMM/YMM registers, while preserving other facts. Unknown calls
clear the environment. If every explicit return locally proves the same
integer, boolean or pointer constant, that fact can populate an existing,
width-matched `Call::return_register`/`return_version`; the pass does not guess
an ABI return register or an unstated native return value. Delayed transfers
retain their point-in-time expressions. Constant substitutions require an
exact match with the register expression's IR value type.

For a proven no-write call, its output memory version becomes an alias of its
input. The pass resolves those aliases through subsequent loads, stores,
calls, intrinsics, switch selectors and memory-phi inputs throughout the caller.
The retained call records equal input/output memory versions. Memory-phi
definitions remain intact, and calls that may write retain distinct states.
This improves memory dependency information without forwarding loads or
claiming address-level alias precision. Running ordinary `to_ssa` again
conservatively reintroduces call memory definitions.

`CallSummaryOptions` bounds functions, blocks, instructions, visited expression
nodes, expression depth, call depth and total work. Shared validation checks
SSA definition uniqueness before any rewriting. Expression depth is capped at
256 and call depth at 128 even if larger limits are requested. A call-depth
cutoff yields an unknown summary; exhausted work/size budgets, cancellation,
allocation failure and malformed SSA return an error without publishing a
partial result. This pass does not infer argument-dependent return formulas,
constants across blocks, recursive fixed points, read-only opaque intrinsics,
or external library effects. Integration is opt-in through the batch API.
