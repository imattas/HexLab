# Bounded opaque-predicate proofs

The constant simplifier proves pure branch predicates in two stages. It first
propagates known-zero and known-one bits through integer `and`, `or`, and `xor`,
constant shifts and rotations, sign/zero extension, truncation, sign-bit/parity operations,
and fixed-width comparisons. Unsigned and signed comparisons use conservative
minimum/maximum ranges derived from those known bits. This can prove predicates
over 64-bit inputs without enumerating every input value, for example that
`(x & 7) == 8` is always false. Unsupported operations produce no proof.

If abstract facts do not settle the predicate, the pass expands it through
preceding same-block, versioned SSA assignments and assignments in a bounded
unique-predecessor chain of entry-reachable blocks. It treats unresolved SSA
values as independent inputs and exhaustively evaluates all assignments only
when there are at most 12 total symbolic bits (4,096 valuations). A predicate
is folded only when every valuation yields the same well-typed boolean result.
The ordinary CFG cleanup then removes unreachable blocks and stale phi inputs.

The proof envelope is intentionally bounded: 512 expanded expression nodes,
32 levels of definition expansion, a shared 65,536 abstract-step/valuation
budget per simplification pass, and the separate 12-bit cap for exhaustive
enumeration. Cycles, unversioned registers, inconsistent types, unsupported
expressions, and exhausted limits produce no proof. Cross-block expansion
stops at joins, secondary or disconnected chunks, and the function entry; phi
outputs remain independent symbolic inputs. The predecessor walk is capped at
256 blocks.

The pass is disabled for a function containing any call, store, or intrinsic.
Memory expressions and unknown or named values are rejected during expansion.
Phi outputs are treated as independent symbolic inputs rather than reasoning
about path correlation, which can miss proofs but does not assume a particular
incoming path. Predicates needing unsupported arithmetic or correlation
reasoning remain unchanged.

This is a conservative control-flow simplification, not a general SAT solver,
symbolic executor, or semantic deobfuscator. It neither rewrites instructions
nor changes instruction origins.

The identity pass additionally recognizes nested integer bitwise complements.
It removes `~~x`, proves `x & ~x` to be zero, and proves `x | ~x` and
`x ^ ~x` to be the width mask. These rules also apply when the pair occurs
among same-operation associative operands, such as `(x & y) & ~x`. They require
equal fixed-width integer types and structurally identical, pure SSA expressions;
memory reads, unknown values, and side effects cannot be erased. Constant
propagation and branch cleanup can then consume the resulting predicate. This
does not reason about algebraic correlations across distinct SSA versions.

Known-bit propagation also rotates both known-zero and known-one masks through
fixed-count rotate-right unary operations and binary `rotl`/`rotr` operations
whose count is fully known. The rotation uses the operand width (including
32-bit WebAssembly values) and does not infer any facts from a partially known
count. This allows later masks and comparisons to prove predicates around
rotate-based obfuscation while preserving the same conservative proof rule.

The identity pass also applies the Boolean consensus identities
`(x | y) & (x | ~y) = x` and `(x & y) | (x & ~y) = x`. All inner operands
and the outer expression must have the exact same fixed-width integer type.
Both copies of `x` must be structurally equal, and the other operands must be
exact bitwise complements. Inputs must be pure, versioned integer SSA
expressions, and the whole expression is limited to 256 nodes. Memory reads,
unknown values, unversioned registers, side effects, and cross-version
correlations are rejected. This removes a common two-arm bitwise opaque-predicate
shape without distributing general expressions.

The pass also recognizes `x - (x & (x - 1))` and rewrites it to
`x & (0 - x)`, a compact least-significant-set-bit idiom. This uses fixed-width
modular integer arithmetic, so the identity also holds for zero and at
wraparound. It requires an exact same-type integer SSA value for both copies of
`x`, an exact integer constant one in the decrement, pure operands, and at most
256 expression nodes. Other arithmetic and shift-width behaviors are left
alone.

The identity pass also cancels repeated, structurally identical versioned SSA
terms in fixed-width integer arithmetic: `(x + y) - x` and `(x + y) - y`,
`x - (x - y)`, and `(x - y) + y` (including either ordering of the outer
addition) reduce to the surviving term. These are modular bit-vector
identities, so they remain valid at width overflow. They require exact operand
types, pure versioned inputs, and at most 256 expression nodes. Floating-point,
memory, unknown, side-effecting, unversioned, and cross-version expressions
are left unchanged.

The pass also recognizes `(x + y) - (x ^ y)` and rewrites it to
`(x & y) << 1`, using `x + y = (x ^ y) + 2 * (x & y)` modulo the fixed integer
width. Both source expressions must contain the same exact, pure, same-width
SSA values; either operand order is accepted independently by the addition and
XOR. The rewrite is bounded to 256 expression nodes and preserves wraparound,
including the one-bit case where the shifted result is zero. No floating-point,
memory, unknown, effectful, unversioned, or cross-version input is rewritten.

Explicit `select_if(predicate, pair(yes, no))` expressions also flatten a
nested select when both selects use the exact same structurally identical
predicate. For example, `predicate ? (predicate ? a : b) : c` becomes
`predicate ? a : c`, with the symmetric false-arm case handled as well. The
predicate and arms must be versioned pure integer/boolean bitvectors and use
only a bounded whitelist of total operations. Division/remainder, memory,
unknown values, intrinsics, and unversioned registers are excluded so the
rewrite cannot erase an observable effect or arithmetic fault. The complete
expression is capped at 256 nodes. It does not infer predicate equivalence
across different SSA values, branches, joins, or loops.

The inverse carry-recombination form is also recognized:
`(x ^ y) + ((x & y) << 1)` becomes `x + y`, including when the two outer
addition terms or either inner operand pair are reversed. The match requires
same-width integer operands, exact structurally equal SSA values in both
subexpressions, a literal one-bit shift, pure versioned inputs, and at most 256
expression nodes. The rewrite preserves fixed-width modular addition and does
not generalize through other shift counts or rearranged expression trees.
