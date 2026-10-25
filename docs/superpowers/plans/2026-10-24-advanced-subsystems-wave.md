# Advanced Subsystems Work Plan

**Goal:** Advance multiple large, independent HexLab subsystems within the existing C++20 monorepo.

**Workstreams:**

1. Header preprocessor and C/C++ type import (`libs/types/src/header_preprocessor.*`, importer docs).
2. Mach-O unwind analysis (`libs/loaders/src/macho_unwind.cpp`, related unwind docs).
3. GDB remote debugging (`libs/debugger/src/rsp_backend.cpp`, RSP interface/docs).
4. Function discovery and Mach-O FDE integration (`libs/analysis/src/functions.cpp`, function recovery docs).
5. Managed metadata/token resolution (`libs/loaders/src/managed.cpp` or `cil.cpp`, managed loader docs).
6. Binary comparison (`libs/compare/src/compare.cpp`, comparison API/docs).

Each worker owns its source and focused documentation. Do not edit shared capability ledgers, tests, CMake, or each other's files. No tests are to be added or run. Compile supported Windows library sources if feasible. Do not launch or activate the desktop app, and do not clean `out/`.

Integration will review bounded parsing and protocol semantics, update capability evidence after source review, run `git diff --check`, and compile affected Windows-supported libraries without linking into the running app.

This is one increment toward the full IDA-scale product goal; it does not complete that goal.

## Progress

- Header preprocessing: bounded C++20 `__VA_OPT__` selection and rescanning; source compilation passed.
- Mach-O unwind: bounded `DW_CFA_def_cfa_expression` and expression operators; source compilation passed.
- Remote RSP: corrected advertised action-kind negotiation for thread-specific stepping; source compilation passed. Thread-specific continue/restart remain open because the session API currently provides only process-wide continue and no extended-mode restart contract.
- Function recovery: validated Mach-O FDE ranges now seed function roots and constrain ownership; source compilation passed.
- No tests were added or run; no GUI interaction or `out/` cleanup.
- Managed metadata/token resolution and binary comparison are now underway as additional independent workstreams.

- Managed metadata: bounded ECMA-335 `NestedClass` validation and nested TypeDef names; source compilation passed.
- Binary comparison: configurable bounded anchor length (1–64 bytes) for byte resynchronization; source compilation passed.
