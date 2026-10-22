# Decompiler control-flow formatting

`format_pseudocode` is the lossless diagnostic formatter: it prints each lifted
basic block with labels and preserves control transfers as gotos.

`simplify_constants` is an optional SSA pass. It propagates proven constant
versions across blocks and folds fixed-width add/subtract/multiply, bitwise,
shift, zero-extension, and sign-extension expressions. Arithmetic wraps at the
result width. Unsupported operations, unknown values, memory effects, and
out-of-range shifts remain explicit; when the function contains a call,
register substitution is disabled until call-clobber modeling is available.
Invalid duplicate SSA definitions are rejected.

`simplify_identities` is a separate local bit-vector cleanup pass. It applies
width-matched identities such as `x & 0`, `x | width_mask`, `x ^ x`, and
addition or shifts by zero. It also simplifies idempotent `x & x` and `x | x`
for pure matching expressions, and cancels `(x + c) - c` or `(c + x) - c`
when the fixed-width types and masked constants match. The cancellation relies
on modular bit-vector arithmetic, so wraparound is preserved. It returns a
copied function, checks that all operands have the result width, and leaves
unsupported or ill-typed operations explicit. It does not reorder expressions,
rewrite memory reads, or model processor-specific undefined behavior; memory
and unknown values are excluded from structural rewrites that could erase or
duplicate their evaluation.

`eliminate_dead_code` removes unused SSA assignments and phi nodes when their
right-hand sides are pure register, constant, unary, or binary expressions.
It iterates to a fixed point, so deleting a dead consumer can expose a dead
definition chain. Assignments that read memory and all stores, calls, and
intrinsics remain in the IR because their effects are observable or unknown.
The pass leaves unversioned assignments alone and rejects duplicate SSA
definitions.

`format_structured_pseudocode` recognizes canonical two-way conditionals whose
arms are straight-line chains ending at a shared join. It finds blocks by their
addresses rather than assuming a particular storage order, and lowers
join-block SSA phi nodes to edge-specific register-version assignments after
the matching arm. It also emits a simple one-arm `if` for a conditional early
return, preserving the inverted condition when the return is on the false edge.

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
`used_fallback == true` and a reason. Nested branches, switches, irreducible
control flow, multiple joins, and unsupported phi shapes retain this fallback.
It keeps the CFG readable without claiming semantics the structurer does not
currently model.

## Interactive annotations

The desktop pseudocode pane can rename a recovered function, rename a recovered
stack slot at its first observed access, and attach a comment to a selected
instruction. These operations use the workspace's shared address annotations,
so they participate in project undo/redo and persistence and appear in the
disassembly, reference labels, and annotation browser. A stack-slot name is
currently anchored to an instruction address; it does not rewrite lifted IR
register expressions or infer a variable's type. Comments appear alongside
their instruction origins in the pseudocode pane.
