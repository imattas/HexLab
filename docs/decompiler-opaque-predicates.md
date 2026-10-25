# Bounded opaque-predicate proofs

The constant simplifier proves pure branch predicates in two stages. It first
propagates known-zero and known-one bits through supported bitwise operations,
constant shifts, sign/zero extension, truncation, sign-bit/parity operations,
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
