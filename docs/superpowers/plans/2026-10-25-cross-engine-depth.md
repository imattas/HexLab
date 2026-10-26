# Cross-Engine Depth Expansion Implementation Plan

> **For agentic workers:** Use isolated worktrees per task and keep ownership inside the assigned subsystem. Do not add or run tests in this wave.

**Goal:** Extend HexLab pseudocode structuring, RISC-V reference provenance, and managed type-forwarder resolution in three independent engine paths.

**Architecture:** Reuse the current bounded models: loop-region validation and edge-copy lowering in the decompiler, address propagation and versioned producer graphs in analysis, and exact supplied-catalog assembly binding in the managed loader. Unsupported shapes keep their current fallback or unresolved state.

**Tech Stack:** C++20, existing HexLab decompiler/analysis/loader libraries, CMake, Windows Debug builds.

**Spec:** `docs/superpowers/specs/2026-10-25-cross-engine-depth.md`

## Global Constraints

- Do not add or run tests; compile affected Debug targets only.
- Do not access, clean, or build `out/`.
- Keep all work headless.
- Preserve cancellation, resource bounds, source provenance, and conservative fallback behavior.
- Do not read assemblies from disk; cross-catalog matching uses exact identities supplied by the caller.
- The root agent owns changes to `docs/capabilities.csv` and integrated builds.

## Review Focus

- Post-tested nested branches must not duplicate blocks or execute phi assignments on the wrong edge.
- RISC-V producer ancestry must not survive conflicting address values at CFG joins or cross calls/unknown writes.
- ExportedType forwarding must not bind on name alone when assembly identity is missing, duplicated, or mismatched.
- Cycles, malformed records, and traversal-budget exhaustion must remain explicit and bounded.

## Tasks

### Task 1: Nested SSA joins in post-tested loops

**Files:** `libs/decompiler/src/decompiler.cpp` and `docs/decompiler-structuring.md`.

- [ ] Inspect the post-tested-loop recognizer and its current diamond validation.
- [ ] Add a bounded nested conditional diamond with validated disjoint arms and exact register-phi predecessor coverage at consumed joins.
- [ ] Emit parallel phi copies on the exact predecessor edges; keep side exits, memory-phi ambiguity, overlaps, and deeper nesting on the existing fallback.
- [ ] Document limits and compile `hexlab_decompiler` Debug.

### Task 2: RISC-V reference producer graphs

**Files:** `libs/analysis/src/references.cpp` and `docs/reference-producer-provenance.md` or a focused RISC-V xref page.

- [ ] Inspect the existing producer graph storage and RISC-V register-value propagation.
- [ ] Carry bounded producer sets/dependency edges through RISC-V address construction, pointer loads, and CFG joins for references the pass already resolves.
- [ ] Preserve exact value agreement, relocation rejection, address-space checks, and call clobbers; do not invent facts at conflicting joins.
- [ ] Compile `hexlab_analysis` and `hexlab_cli` Debug.

### Task 3: Managed ExportedType forwarding

**Files:** `libs/loaders/include/hexlab/loaders/managed.hpp`, `libs/loaders/src/managed.cpp`, and managed metadata documentation.

- [ ] Inspect the current TypeRef binding and metadata-table index helpers.
- [ ] Parse and retain bounded ExportedType identity and implementation records.
- [ ] Resolve assembly-scoped forwarders through exact supplied-catalog AssemblyRef identities, including nested ExportedType chains; retain unsupported File/Module cases as unresolved.
- [ ] Reject duplicate or cyclic forwarding paths and preserve deterministic unresolved diagnostics; compile `hexlab_loaders` and dependent `hexlab_cli` Debug.

### Integration

- [ ] Review workstream diffs for bounds, edge correctness, provenance, and exact identity.
- [ ] Compile integrated Debug targets serially; do not run tests or launch the desktop.
- [ ] Update the capability ledger from source/build evidence, commit the integration record, and push `feat/foundation`.
