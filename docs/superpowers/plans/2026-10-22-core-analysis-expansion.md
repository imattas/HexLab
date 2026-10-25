# Core Analysis Expansion Implementation Plan

> **For agentic workers:** Implement only the assigned subsystem. Use test-driven development and finish with focused verification; root owns cross-track integration and capability-ledger edits.

**Goal:** Improve arithmetic semantics, imported type fidelity, and architecture-aware decompilation as independent steps toward a complete reverse-engineering workbench.

**Architecture:** Preserve the existing shared-library monorepo boundaries. Processor semantics stay pure and reusable; CodeView metadata is normalized into the shared immutable type model; the decompiler consumes typed instruction effects without changing decoder ownership.

**Tech Stack:** C++20, CMake, CTest, wxWidgets desktop, Zydis/Capstone processor stack, SQLite-backed project model.

**Spec:** `docs/superpowers/specs/2026-10-19-hexlab-design.md`

## Global Constraints

- Preserve serialized enum/opcode ordinals; append new enum values only.
- Keep malformed or unsupported input explicit and bounded; do not invent semantic facts.
- Keep existing public APIs source-compatible where practical; version persisted encodings when representations change.
- Add focused regression tests before implementation and update subsystem documentation.
- Root owns `docs/capabilities.csv` and performs final integration verification.

## Review Focus

- Signed division overflow and zero divisors must not create a fabricated result.
- Bitfield base types, bit positions, widths, storage bounds, and layout padding must agree.
- MIPS HI/LO dependencies must flow through SSA without confusing GPRs or delay-slot order.
- UI graph work must not block the GUI thread or make CTest silently hang.

---

### Task 1: x86 Multiply and Divide Semantics

**Files:** `libs/processors/include/hexlab/processors/x64_semantics.hpp`, `libs/processors/src/x64_arithmetic.cpp` or a focused new semantics source, processor semantic tests and docs.

- [x] Add regression tests for unsigned/signed full-width products, high/low halves, truncation overflow flags, quotient/remainder, divide-by-zero, and signed minimum divided by -1 at supported widths.
- [x] Implement pure helpers and a decoded-instruction adapter using the existing `Opcode::mul`, `imul`, `div`, and `idiv` effects.
- [x] Verify focused processor semantic tests and document which x86 flags are defined, cleared, or undefined.

### Task 2: CodeView Bitfield Type Fidelity

**Files:** `libs/types/include/hexlab/types/types.hpp`, `libs/types/src/types.cpp`, layout sources, PDB parser/importer, PDB and layout tests, type-authoring documentation.

- [x] Add regression tests for parsed `LF_BITFIELD` records, aggregate member import, shared storage units, boundary validation, and layout output.
- [x] Represent bitfield width and bit offset in the immutable member model and preserve them through PDB conversion and layout.
- [x] Verify focused PDB/type/layout tests; reject malformed or unsupported bitfield records without losing neighboring valid records.

### Task 3: MIPS32 HI/LO Decompiler Semantics

**Files:** `libs/decompiler/src/decompiler.cpp`, decompiler SSA/types as needed, MIPS decompiler tests, MIPS/decompiler documentation.

- [x] Add regression tests for MULT/MULTU/DIV/DIVU writes to HI/LO, MFHI/MFLO reads, MTHI/MTLO writes, and SSA version flow.
- [x] Lift these operations as explicit typed values/effects with correct special-register dependencies; retain opaque behavior where the architecture leaves results undefined.
- [x] Verify decompiler and SSA tests and document that branch-delay-slot execution remains a separate limitation.

### Task 4: wx Graph UI Test Integration

**Files:** `tests/desktop_graph_tests.cpp`, `apps/desktop/graph_view.cpp`, and related graph session code only if evidence identifies a product bug.

- [x] Recheck the 30-second `desktop_graph` timeout after a clean integrated build; the rebuilt test passed in 2.96 seconds, so no phase diagnostics or product change were warranted.
- [x] Confirm function-neighborhood coverage already exists in `tests/graph_tests.cpp` and `tests/project_graph_tests.cpp`, with UI graph startup covered by `desktop_graph`.
- [x] Build the wx target and verify `desktop_smoke` and `desktop_graph` without changing the existing timeout.

---

## Follow-on Major Subsystems

Each follow-on is owned end to end by one agent; the root performs cross-area build, CTest, and ledger integration.

### Task 5: Linux Debugger Target Identity

- [x] Parse bounded ELF class and machine metadata and use it for Linux process enumeration, launch, and attach.
- [x] Cover x86-64/i386 and malformed or unsupported ELF headers with host-independent tests.
- [x] Document that target identity does not expand the backend's x86-64 register support.

### Task 6: Bounded Python Project Iterators

- [x] Add page iterators for functions, instructions, segments, strings, and references.
- [x] Bound page sizes and verify multi-page traversal plus invalid input behavior.
- [x] Document that pages avoid materializing complete native tables in Python.

### Task 7: Loop Exit Continuation Structuring

- [x] Extend pre-tested while formatting through a validated branch-free exit chain ending in return.
- [x] Add regression coverage for an assignment continuation followed by a terminal return.
- [x] Preserve goto fallback for branches, phis, cycles, side exits, missing returns, and incomplete CFG coverage.

### Task 8: COFF Static Archive Summaries

- [x] Add bounded COFF relocatable-member symbol summaries with validated section and auxiliary-record handling.
- [x] Feed COFF summaries into fixed-point archive member selection and verify selected-member provenance.
- [x] Verify malformed auxiliary bounds, string-table limits, cancellation, and synthetic COFF object fixtures.

### Task 9: Function-Level Binary Correspondence

- [x] Add bounded, cancellable matching over architecture-compatible functions with normalized fingerprint evidence and explicit ambiguity.
- [x] Extract address-independent fingerprints from fully typed desktop instructions and test that register allocation, encoding, and branch relocation do not affect matching while literal constants do.
- [x] Integrate multi-function correspondences into the desktop comparison and saved-session workflow; focused core/desktop tests pass.

### Task 10: Managed Method Analysis and Pseudocode

- [x] Lift supported managed CIL method bodies into recoverable control flow and pseudocode while preserving metadata-token identity.
- [x] Cover arguments, locals, arithmetic, branches, calls, returns, malformed stacks, and explicit unsupported operations.
- [x] Verify integrated managed-loader and decompiler tests; document unsupported runtime semantics.

### Task 11: Headless Automation Batch Export

- [x] Add deterministic versioned JSON analysis export through bounded automation pages, including progress, cancellation, and atomic output.
- [x] Support cancellation during native analysis and prove that failed/canceled exports leave no published output.
- [x] Verify read-only use, multi-page output, callback errors, and integrated automation tests.

### Task 12: Managed Method Signatures and Call Effects

- [x] Decode a bounded ECMA-335 method-signature subset from metadata blobs, preserving calling-convention and instance information.
- [x] Resolve supported CIL call stack effects from metadata and lower typed calls without caller-supplied signature maps.
- [x] Reject malformed or unsupported signatures explicitly and verify focused loader/decompiler tests.

### Task 13: ABI Argument and Return Classification

- [x] Add a reusable ABI classifier for x86-64 System V, Windows x64, and x86-32 cdecl scalar, pointer, and floating arguments.
- [x] Model register/stack locations, alignment, Windows shadow space, and return locations; reject unsupported aggregate/vector cases.
- [x] Add focused tests and document exact support boundaries for decompiler and type-recovery consumers.

### Task 14: ELF Unwind Function Roots

- [x] Parse bounded `.eh_frame` CIE/FDE records and validate encoded pointers and function extents.
- [x] Expose unwind ranges as provenance-bearing function roots for ELF analysis without replacing other root sources.
- [x] Add malformed and positive synthetic fixtures, document architecture/encoding limits, and run ELF/function tests.

### Task 15: Cross-Block AArch64 Comparison Flags

- [x] Add a regression for `SUBS` in one basic block and a conditional branch in its successor.
- [x] Propagate comparison facts over acyclic AArch64 CFG edges, requiring predecessor agreement and dropping facts on clobbers.
- [x] Keep loops and unsupported flag producers conservative; verify decompiler and CIL-independent integration tests.

### Task 16: AMD64 PE Unwind Operations

**Files:** `libs/image/include/hexlab/image/pe_metadata.hpp`, `libs/loaders/src/pe_exceptions.cpp`, `tests/pe_exception_tests.cpp`, and PE unwind documentation.

- [x] Add test-first decoding for AMD64 `UNWIND_INFO` version 1 prolog slots: PUSH_NONVOL, ALLOC_LARGE/SMALL, SET_FPREG, SAVE_NONVOL/FAR, SAVE_XMM128/FAR, and PUSH_MACHFRAME.
- [x] Validate header flags, prolog offsets, operand-slot counts, alignment, frame metadata, handlers/chains, and all RVA/file-backed bounds atomically; preserve source provenance for decoded records.
- [x] Verify valid and malformed fixtures plus function-root/cache consumers; document that runtime context evaluation and ARM64 packed unwind remain unsupported.

### Task 17: Conservative x86-64 Register-Indirect References

- [x] Resolve register-indirect calls and jumps from same-basic-block full-width `mov reg, imm64` and RIP-relative `lea` address facts when the target lies in an executable segment.
- [x] Invalidate facts on any subsequent write to the register and retain unresolved expressions for unsupported or clobbered values.
- [x] Cover resolved and clobbered targets in `tests/reference_tests.cpp`; document the conservative boundary in `docs/binary-analysis-validation.md`.
