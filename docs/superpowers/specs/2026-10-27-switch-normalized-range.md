# Normalized signed switch range proof

## Intent

Recover bounded jump tables whose selector is first checked against a nonzero signed lower bound and upper bound, then normalized by subtracting that lower bound before indexing. This is a compiler lowering commonly used for dense switches over enum-like signed ranges. Current switch recovery proves only the zero-based signed shape and can mistake the upper value for the table entry count when the table selector has been normalized.

## Goals

- Recognize one exact x86 signed interval: `cmp selector, low; jl default; cmp selector, high; jg default; sub selector, low; ... indexed dispatch`.
- Require nonnegative bounds, exact register/width agreement (except the explicit zero-extending x86-64 pair below), a positive count no greater than the existing 4096-entry cap, and `high >= low`.
- Permit the explicit x86-64 compare/SUB W-register to 64-bit table-index pairing only where the architectural 32-bit write zero-extends the exact same register.
- Prove known CFG predecessor/dominance conditions and that the normalized selector is unchanged between subtraction and dispatch.
- Preserve existing executable, file-backed target validation, verified-prefix behavior, and conservative fallbacks.
- Document the shape and rejection conditions.

## Non-goals

- General symbolic register propagation or arbitrary normalization expressions.
- New architectures, tests, runtime execution, or guessed bounds for indirect control flow.
- Changing the existing switch result format or table entry encodings.

## Approaches considered

1. Add general value tracking for all selector arithmetic. This could recognize more compiler output but expands alias, merge, loop, and arithmetic-proof complexity substantially.
2. Recognize the exact same-register `SUB reg, reg, low` normalization behind the existing bounded CFG proof. This supports the common dense nonzero signed interval while retaining existing conservative graph and executable-byte checks.
3. Treat the upper signed bound as an entry count and scan. This can over-read tables and accept indices outside the normalized range.

Approach 2 is selected by the parent task scope and current code structure. It gives a sound count for a bounded pattern without broadening register propagation.

## Constraints and acceptance

The recognizer must fail closed on unknown/ambiguous predecessors, bypasses, wrong branch conditions/defaults, selector width or alias mismatch, negative/unrepresentable immediates, in-place subtraction mismatch, arithmetic/count overflow, or a failed CFG proof. Runtime behavior is not verified because the repository-level task explicitly prohibits adding/running tests; the root agent owns compile-only verification and independent review.
