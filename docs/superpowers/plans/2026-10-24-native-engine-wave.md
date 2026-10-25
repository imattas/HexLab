# Native engine expansion wave plan

## Tasks

- [x] Inspect existing subsystem APIs and assign disjoint ownership.
- [x] Extend decompiler control-flow structuring and document supported shapes.
- [x] Extend type/header representations for incomplete and flexible layouts.
- [x] Extend Apple-Silicon Darwin register access for NEON state and document limits.
- [x] Reconcile capability ledger and CMake source selection.
- [x] Run one serial integrated Debug build; inspect `git diff --check` and verify `out/` is untouched.

## Validation limits

Per the session instruction, do not add or run tests. Darwin runtime validation
is unavailable on this Windows host; record that limitation explicitly.
