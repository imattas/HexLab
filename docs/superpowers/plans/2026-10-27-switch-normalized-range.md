# Normalized signed switch range plan

## Task 1: Recognize the exact normalized interval

- Extend signed guard analysis in `libs/analysis/src/switches.cpp` to capture a nonzero lower bound and corresponding upper bound.
- Require adjacent `CMP/JL` lower guard and `CMP/JG` upper guard with one shared default, exact original selector and width.
- Require an in-place immediate `SUB selector, selector, low` immediately after the upper guard; require its output register exactly equal to the indexed dispatch selector.
- Allow only the x86-64 32-bit compare/SUB register paired with its matching 64-bit indexed-memory register, relying on defined zero-extension.
- Derive `case_count = high - low + 1` with checked ordering and the existing 4096-entry cap.
- Reuse the shared CFG graph to require the upper compare has only the lower branch as predecessor, the lower branch has only the lower compare as predecessor, and the upper in-range edge reaches normalization and dispatch without selector writes or bypasses.
- Preserve target decoding/file-backed executable checks and the unbounded verified-prefix fallback whenever the proof is incomplete.

## Task 2: Document and inspect

- Add supported shape, proof requirements, and unsupported variants to `docs/switch-analysis-validation.md`.
- Source-review integer signedness/width, bounds, address graph traversal, selector mutation, default target validation, and budget/cancellation behavior.
- Do not add or run tests, and do not access build trees; the root agent performs compile-only integration.

## Verification

The root integration agent should compile `hexlab_analysis` Debug. Independent review should inspect the new shape and fail-closed paths. No runtime or fixture verification is claimed.
