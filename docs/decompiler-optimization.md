# Decompiler optimization

Decompiler optimization is performed over the typed SSA lifted function. It does
not rewrite source bytes or analysis ownership. The constant pass folds supported
fixed-width binary operations, boolean negation, integer bitwise complement,
sign-bit/even-parity predicates, and fixed immediate shifts/rotates when their
width and shift-count constraints are explicit; it also folds constant predicates.
Unsigned `udiv` and `urem` fold when both operands and the result have the same
unsigned integer type and the divisor is nonzero. A zero divisor remains
unfolded so its architecture- or runtime-specific behavior is preserved.
The identity pass applies
width-aware bit-vector identities, substitutes bounded SSA expressions along
single-predecessor acyclic paths, and reuses duplicate pure expressions within a
basic block or from a dominating block. Dead-code elimination removes unused pure
register definitions and phis after those rewrites.

For pure, SSA-qualified integer and boolean expressions up to 256 nodes and
depth 64, the identity pass also flattens same-width associative `and`, `or`,
and `xor` trees. It combines constants, removes duplicate terms from `and` and
`or`, cancels pairs of identical terms from `xor`, and rebuilds the remaining
tree in a bounded balanced form. It applies the bitwise absorption identities
`x & (x | y) = x` and `x | (x & y) = x` when the repeated term is structurally
identical. Register leaves must carry SSA versions; memory reads, floating
values, unversioned registers, and opaque effects are left alone. These rules
operate on the shared typed IR, so they apply to any architecture that lifts to
the same fixed-width operations.

Same-width pure integer multiplication by a nonzero power-of-two constant is
rewritten to a left shift when the shift amount is less than the value width.
The rewrite works for either operand order and uses the same fixed-width result
type, so signed and unsigned multiplication retain their modulo-2^width result.
It requires every register input to have an SSA version; unknown values and
effectful expressions remain untouched. A zero factor and factor one continue
to use their existing identities.

For call-free lifted functions, the constant pass also resolves loop-carried
phis whose concrete incoming values prove the same typed constant and whose
remaining back-edges are exact SSA register copies. This handles invariant
values carried through copy-only loop paths without treating a changing
induction variable as constant. A phi is considered only when its unique
incoming predecessor set exactly matches the CFG. The resolver distinguishes
cycles from unknown inputs: memory values, missing definitions, conflicting
constants, and unsupported expressions block inference. This copy-only loop
resolver is used for call-free functions; the separate SCCP pass below tracks
versioned constants across calls while treating call output versions as
overdefined. Loop
analysis indexes at most 250,000 SSA definitions, spends at most 1,000,000
resolution steps, and stops at recursion depth 128; exceeding a limit leaves
unresolved loop facts untouched. Proven constants feed the existing expression
folding and branch simplification, which preserve instruction origins and
remove unreachable blocks only after a branch edge is proven.

The pass also runs bounded sparse conditional constant propagation (SCCP) over
executable CFG edges. It tracks typed constants through register SSA definitions
and reachable phi inputs, evaluates supported fixed-width bit-vector operations
using the same width-aware folding rules, and selects an edge only for an exact
two-way boolean branch whose targets match the CFG. Once an edge is proven, it
removes entry-reachable blocks reachable only through infeasible edges and
drops those predecessors from register and memory phis. Structurally disconnected
blocks and their incoming phi inputs are retained because they may represent
separate function chunks or secondary entries. Unresolved predicates are opened in
both directions after the value fixed point, so a cycle or missing fact cannot
make a path disappear. Calls and intrinsics make their modeled register output
versions overdefined; memory reads, unknowns, unversioned registers, indirect
branches, delay-slot branches, and switch dispatches are not guessed. The pass
preserves each instruction's origin and leaves unsupported multiway or malformed
control flow in place.

SCCP considers at most one million blocks, phis, and instructions combined, at
most eight million propagation steps, and expression depth 128. Exceeding a
work budget abandons the SCCP rewrite and returns the original lifted function,
so it never leaves a partially pruned CFG.

Common-subexpression elimination accepts only pure integer and boolean
register/constant expressions whose every register leaf carries an SSA version.
An unversioned physical-register reference is ineligible because an intervening
assignment could change its value. It uses both a block-local table and the
dominator tree, so an expression from a dominating block can be reused through a
single path or at a join, while an expression from only one side of a branch is
not available on the other side. Reuse requires an exact structural and type
match, keeps each `LiftedInstruction` and its original address/instruction ID in
place, and replaces only the duplicate assignment's expression with a reference
to the earlier SSA result. It does not commute operands or reuse memory reads,
unknown expressions, floating/vector expressions, calls, or intrinsic results.
Calls, intrinsics, and stores clear block-local expression availability and create a
barrier for later expressions in their dominator subtree. Calls and intrinsics can
have implicit register effects that the IR does not fully model, so cross-block
reuse does not carry an expression through those barriers. Unrelated sibling paths
remain eligible when they do not pass through a barrier.
Structural hashes are only an index; equality is checked before reuse. The
dominator computation visits only blocks reachable from the function entry,
skips dominator analysis above 100,000 blocks or 500,000 edges, and uses bounded
expression trees (at most 256 nodes and depth 64).

These limits preserve unknown effects and avoid choosing an ordering for
operations whose semantics are not represented as pure bit-vector expressions.
The passes are conservative rewrites rather than a claim of complete
semantics-preserving deobfuscation for every processor family.

The exact opaque-predicate prover can exhaustively evaluate a pure boolean
predicate over at most 12 symbolic input bits (up to 4,096 assignments per
predicate), with a shared budget of 65,536 assignments per function. Symbolic
inputs are versioned integer registers no wider than 12 bits; their defining
expressions must expand to bounded register, constant, unary, and binary trees
supported by the fixed-width folder. A branch is simplified only when every
assignment evaluates to the same valid boolean result. Memory, unknown values,
unversioned registers, unsupported operators, mixed results, and exhausted
budgets leave the predicate unchanged. This is exhaustive finite-domain proof,
not a solver for predicates over wider values or stateful effects.
