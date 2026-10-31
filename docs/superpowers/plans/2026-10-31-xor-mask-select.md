# XOR mask select implementation plan

> **For agentic workers:** Execute inline using the current C++ optimizer and existing project conventions. Do not add or run tests.

**Goal:** Convert the exact XOR-mask form of a conditional select into typed `select_if` IR.

**Architecture:** Add a bounded pure-expression recognizer beside the existing boolean-mask select simplifier. Require exact `sext` mask provenance, and swap arms for the complemented mask.

**Tech Stack:** C++20 typed SSA optimizer.

**Spec:** `docs/superpowers/specs/2026-10-31-xor-mask-select-design.md`

## Global Constraints

- Preserve exact bit-vector types, SSA versions, purity, totality, and existing expression limits.
- Do not add or run tests; compile the changed decompiler source/target.
- Leave unrelated dirty files untouched and make a local commit only.

## Review Focus

- Direct and complemented masks choose opposite true/false arms correctly.
- Mismatched widths, non-boolean predicates, unversioned reads, effects, and over-budget expressions remain unchanged.

---

### Task 1: Recognize the XOR-mask select

**Files:**
- Modify: `libs/decompiler/src/identity_simplifier.cpp`
- Modify: `docs/decompiler-optimization.md`

**Interfaces:**
- Consumes: `ExpressionPtr`, `BinaryValue`, `pure_bitvector`, `total_select_value`, and `structurally_equal`.
- Produces: an existing `BinaryValue{"select_if", predicate, pair(yes,no)}` expression when the exact identity is proven.

- [x] Implement recognition with a 256-node cap and both outer XOR operand orders.
- [x] Document the supported equation, its exact mask forms, and unsupported cases.
- [x] Debug `hexlab_decompiler` `ClCompile` passed (MSBuild exit 0); no tests run. Commit only the scoped source and documentation.
