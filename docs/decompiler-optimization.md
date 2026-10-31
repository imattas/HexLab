# Decompiler optimization

Decompiler optimization is performed over the typed SSA lifted function. It does
not rewrite source bytes or analysis ownership. The constant pass folds supported
fixed-width binary operations, boolean negation, integer bitwise complement,
integer two's-complement negation, sign-bit/even-parity predicates, and fixed immediate shifts/rotates when their
width and shift-count constraints are explicit; it also folds constant predicates.
Unsigned `udiv` and `urem` fold when both operands and the result have the same
unsigned integer type and the divisor is nonzero. A zero divisor remains
unfolded so its architecture- or runtime-specific behavior is preserved.
Signed `sdiv` and `srem` also fold same-typed signed integer constants when the
divisor is nonzero and the result is representable. Signed division truncates
toward zero; minimum-value divided by negative one stays unfolded to avoid
imposing host overflow behavior on the IR. Architecture-specific division
operators remain explicit unless their own semantics are modeled by a separate
pass.
The CIL unary `neg`/`not` forms fold as width-masked integer negation and bitwise
complement. The known-bit pass also propagates both operations through unknown
SSA integer bits using independent per-bit possibilities and a bounded carry
state; any lost cross-bit correlation only reduces precision.
The identity pass applies
width-aware bit-vector identities, substitutes bounded SSA expressions along
single-predecessor acyclic paths, and reuses duplicate pure expressions within a
basic block or from a dominating block. Dead-code elimination removes unused pure
register definitions and phis after those rewrites.

Dead assignment elimination now uses an explicit whitelist for total integer
and Boolean bit-vector unary/binary operators. Division/remainder,
floating-point operations, memory reads, and unrecognized operations stay in
the IR because they may trap or have target-visible behavior. Calls, stores,
and intrinsics are also retained.

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

Multiplication by an exact same-width canonical constant of the form `2^k + 1`
rewrites to `(x << k) + x` for either operand order and `0 < k < width`. This
is exact modulo `2^width`, including signed integer bitvectors, and requires
the nonconstant operand to be a pure, versioned expression within the 256-node
limit. Mismatched or noncanonical constants, unversioned registers, and
effectful or oversized operands are left unchanged.

Multiplication by an exact same-type all-ones integer constant also rewrites to
fixed-width unary `neg`, in either operand order. This is the modular identity
`x * (2^width - 1) == -x`; the constant must be canonical for the expression
width, and the nonconstant operand must be pure with versioned register leaves.

Unsigned division by an exact same-width power-of-two constant is rewritten as
a logical right shift by the constant's bit index; division by one returns the
dividend expression directly. The result and both operands must have the same unsigned
integer type, the dividend must be a pure versioned bit-vector expression
within the 256-node simplifier bound, and the divisor must be a canonical
typed constant. Signed division, zero or non-power-of-two divisors, mismatched
types, unversioned registers, and effectful or oversized expressions are left
unchanged.

Unsigned remainder by an exact same-width power-of-two constant is rewritten
as a bitwise `and` with the divisor minus one (including divisor one, which
becomes zero). The result type must be an unsigned integer of at least two
bits, operands must have that exact type, the dividend must be a pure versioned
bit-vector expression within the 256-node simplifier bound, and the divisor
must be a canonical typed constant. Signed remainder, zero or non-power-of-two
divisors, mismatched types, unversioned registers, and effectful or oversized
expressions are left unchanged. This exposes low-bit remainder masks without
changing fixed-width unsigned remainder behavior.

Signed remainder by a positive same-width power of two is rewritten using a
sign-derived correction bias: `bias = (x sar (width - 1)) & (divisor - 1)`,
then `((x + bias) & (divisor - 1)) - bias`. This preserves the IR's
round-toward-zero remainder sign for negative dividends. Divisor one becomes
zero. The divisor must be canonical, nonzero, positive in the signed type, and
a power of two. The dividend must be same-typed, pure, total, and at most 48
expression nodes, with versioned register leaves; this keeps duplicated
evaluation free of memory effects and partial division/remainder operations.
Zero, negative, non-power-of-two, mismatched, unversioned, partial, or oversized
cases remain explicit.

The identity pass also simplifies `(x >> k) << k` to `x & high_mask` when both
shifts use the same nonzero, in-range constant count and `x` is a pure,
same-width SSA integer expression. This exposes low-bit clearing written as a
shift pair. Arithmetic right shift, mismatched or out-of-range counts,
unversioned inputs, and effectful or unknown expressions remain unchanged.

The shift simplifier also composes adjacent same-direction constant `shl`,
logical `shr`, and signed `sar` operations with exact same-width integer types.
Counts must be canonical, nonzero, and individually in range; combined left
and logical-right shifts become one operation, while a combined signed-right
count is capped at `width - 1`. A left shift followed by an equal logical
right shift becomes a low-bit mask; the reverse order becomes a high-bit mask.
When combined left/logical-right counts would clear the entire value, the
expression becomes zero only if the source is a total expression, so a
possibly trapping division is not discarded. All rewrites require versioned
SSA register inputs and bounded pure bitvectors; unsupported counts and
effectful or partial inputs remain explicit.

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
branches, and delay-slot branches are not guessed. A switch edge is pruned only
when its dispatch metadata is complete, its typed integer/Boolean selector is
constant, and the selected case or default target matches a CFG successor.
Ambiguous case values, missing targets, and incomplete dispatches retain every
edge. The dispatch metadata is narrowed to the selected case/default as well.
The pass preserves each instruction's origin and leaves unsupported multiway
or malformed control flow in place.

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

The fixed-width constant folder evaluates JVM `lcmp`, `fcmpl`, `fcmpg`,
`dcmpl`, and `dcmpg` when both operands are constants of their exact JVM type.
Integer comparison uses signed 64-bit values; floating comparison treats both
signed zeroes as equal and returns the opcode-specific `-1` or `+1` for NaN.

For CIL floating constants, ordinary equality and ordered greater/less-than
comparisons fold by their IEEE-754 bit patterns. The `cgt.un` and `clt.un`
forms also fold, returning true for unordered NaN comparisons as required by
the CIL operation. Floating values of different widths or non-constant
operands remain unchanged.

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

Known-bit propagation also handles binary `shl`, `shr`, `sar`, `rotl`, and
`rotr` operations when the shift/count operand is proven to one exact value by
constant or known-bit facts. Shifts require an in-range count; rotates reduce
the exact count modulo the value width. Inserted shift bits and sign extension
are tracked explicitly, while unknown counts and out-of-range shifts retain
their prior unresolved state. This improves subsequent mask/comparison proofs
without rewriting the original operation or assuming a value for a variable
count.

The known-bit engine also propagates facts through fixed-width multiplication.
It models each partial product and carry as a set of possible values, treating
operand bits independently; lost correlations can reduce precision, while any
emitted bit fact holds for every concrete operand consistent with the inputs.
This allows low product bits (for example, the low zero bits implied by factors
divisible by powers of two) to simplify later masks and predicates. Arithmetic
remains modulo the expression width, and the analysis makes no signed-overflow
assumptions.

The identity pass folds comparisons of the same pure, versioned integer or
boolean value: equality and non-strict order comparisons become true, while
inequality and strict order comparisons become false. It requires an exact
operand type and structural match and does not rewrite floating-point
comparisons, unversioned register reads, memory expressions, or effectful
values.

The identity pass also removes two nested integer negations when both
operations have the exact same fixed-width integer type and their operand is a
pure bit-vector expression. This follows modular negation semantics, including
the signed minimum value, and leaves floating-point negation and unversioned
register inputs unchanged.

For matching pure fixed-width integer expressions, the identity pass folds
`x + ~x` (in either operand order) to the all-ones value of that width. The
rewrite uses modular bit-vector arithmetic and does not apply to floating-point
values, mismatched types, or unversioned reads.

The identity pass also recombines two masked copies of the same pure,
versioned integer value: `(x & a) | (x & b)` becomes `x & (a | b)`, and
`(x | a) & (x | b)` becomes `x | (a & b)`. Both masks must be integer
constants of exactly the result type, and the two copies of `x` must be
structurally identical. This exact-type, pure bit-vector rewrite does not
distribute through arbitrary expressions, cross SSA versions, or remove
memory reads and effects.

For exact-type, pure integer bit-vectors, the identity pass also rewrites
`x - (x & y)` and `x ^ (x & y)` (with the XOR operands in either order) as
`x & ~y`. The subtracted/masked term must contain the same structurally
identical value as `x`; all operands must be pure and within the 256-node
expression bound.
This uses modular fixed-width subtraction where the subtrahend only clears set
bits already present in `x`. It does not apply across different SSA versions,
to signed-overflow-sensitive source arithmetic, floating-point values, or
effectful expressions.

The identity pass also recognizes the exact branchless select form
`(yes & sext(condition)) | (no & ~sext(condition))` and rewrites it to the
typed `select_if` IR. The condition must be a pure, versioned one-bit boolean;
both arms must be same-width pure total bitvectors within the simplifier's
expression budget; and both masks must use the exact same predicate SSA value.
The reversed arm/mask ordering is handled as well. Arbitrary integer masks,
zero-extended booleans, memory values, effectful values, and mismatched types
remain unchanged because they do not prove a 0-or-all-ones condition mask.

The equivalent XOR-mask form `base ^ ((base ^ other) & mask)` is also rewritten
to `select_if`. The mask must be the exact sign extension of a pure one-bit
predicate whose register leaves carry SSA versions, optionally complemented
with bitwise not; complementing the mask swaps the true and false arms. Both
value arms must be exact-width pure, total bitvectors within the same 256-node
bound. Arbitrary masks, unversioned values, effects, and mismatched types remain
explicit.
