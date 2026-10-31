# XOR mask select simplification

## Intent

Recognize a common branchless selection identity in typed SSA so the pseudocode
uses an explicit `select_if` expression instead of opaque XOR/AND operations.

## Approaches

- Keep the arithmetic explicit. This is safe but misses a common deobfuscation
  idiom.
- Recognize the identity in the shared bit-vector simplifier. This improves all
  architectures that produce the same IR and can validate the predicate, types,
  and effects before rewriting. **Chosen.**
- Add architecture-specific rewrites in individual lifters. This duplicates
  logic and misses equivalent expressions produced by other architectures.

## Design

Recognize `base ^ ((base ^ other) & mask)` in either commutative operand order
and rewrite it to `select_if predicate (yes, no)`. `mask` must be exactly
`sext(predicate)` or `bitnot(sext(predicate))`; the predicate must be a pure,
one-bit boolean with versioned register leaves; the bit-vector expressions must
have one exact type, be pure and total, and remain within the existing
256-node simplifier bound.
The complemented mask swaps the selected arms. Other masks, types, effects,
unversioned reads, or oversized expressions remain unchanged.

## Constraints and non-goals

- Preserve fixed-width bit-vector semantics and the existing `select_if` IR.
- Do not infer arbitrary masks, path facts, or effect behavior.
- Keep the expression budget at 256 nodes and use the existing total-value
  whitelist.
- Do not add or run tests in this workspace; verify the Debug decompiler
  compile instead.
