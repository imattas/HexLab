# Capability Expansion Implementation Plan

> **For agentic workers:** Implement the three independent slices in parallel as requested by the user. Do not dispatch additional agents.

**Goal:** Extend HexLab's RISC-V ABI analysis, Mach-O exception metadata, and PDB type-server analysis while preserving the original C++ engine and modular monorepo architecture.

**Architecture:** Each slice extends its existing library boundary and reuses the current immutable project/type/loader models. Unsupported ABI classes, exception encodings, or PDB namespace references remain explicit rather than being guessed. The primary agent reviews all changes and runs one serialized Windows Debug build after integration.

**Tech Stack:** C++20, CMake, existing HexLab libraries and wxWidgets desktop; no new runtime dependency.

**Spec:** `docs/superpowers/specs/2026-10-19-hexlab-design.md`

## Global Constraints

- Implement HexLab's analysis, decoding, lifting, and decompilation engines in this repository; do not substitute an embedded reverse-engineering application.
- Keep wxWidgets types out of analysis and loader libraries.
- Use explicit errors, stable identifiers, cancellation, bounded input, and documented ownership.
- The desktop and headless applications continue to use the same services.
- Preserve the multi-tool, shared-library monorepo distribution; no standalone-executable redesign.
- Keep the desktop closed during this batch.
- Do not add or run tests in this batch; compile the integrated `hexlab` target once after review.

## Review Focus

- **ABI**: unsupported values must not receive guessed register/stack locations; stack overflow and RV32/RV64 widths must agree with the selected psABI.
- **Mach-O LSDA**: every variable-length record, action displacement, and referenced table must stay within its mapped section and configured bounds.
- **PDB type servers**: local and server TPI indexes are separate namespaces; identities must match exactly and cross-namespace cycles must fail safely.
- **Integration**: preserve existing import, decompilation, project, and desktop behavior; no source in the active decompiler-structuring worktree is changed by this batch.

---

### Task 1: RISC-V psABI scalar classification

**Files:** Existing ABI interfaces and implementation under `libs/analysis/`; `docs/abi-classification.md`; the `analysis.abi` row in `docs/capabilities.csv` (primary agent integration only).

**Produces:** Base integer-convention RV32/RV64 argument and return locations using a0-a7 and the 16-byte-aligned entry stack. Support scalar values through 2×XLEN, aggregate values through 2×XLEN, mixed register/stack placement for a partially available register pair, indirect values larger than 2×XLEN, and return placement following the first-argument rules. Unsupported hardware floating-point or vector conventions remain explicitly incomplete with a reason.

**Review:** Confirm narrow-value extension policy, XLEN and 2×XLEN splitting, aggregate memory-order chunks, partial register/stack placement, variadic pair alignment/stack forcing where representable, hidden result pointers, and stack offsets against the repository's existing ABI result model.

### Task 2: Mach-O LSDA action metadata

**Files:** Existing Mach-O unwind parser and metadata structures under `libs/loaders/`; `docs/macho-eh-frame.md`; the `loader.macho` capability row (primary agent integration only).

**Produces:** Bounded action-chain interpretation for the supported LSDA pointer formats, stored as metadata associated with the FDE/call-site rows. This does not invoke personality routines or perform language-level exception dispatch.

**Review:** Confirm action offsets and type-table references are signed/relative as required, bounded to the LSDA, and marked incomplete on unsupported forms.

### Task 3: PDB DBI type-server namespace integration

**Files:** Existing PDB parser and type graph/import pipeline under `libs/types/` and `libs/symbols/`; `docs/pdb-validation.md`; the `types.debug` capability row (primary agent integration only).

**Produces:** Bounded parsing of DBI type-server maps and identity-verified resolution of mapped type references into distinct server TPI namespaces. No raw TPI index is interpreted as belonging to the local stream unless its namespace is known.

**Review:** Confirm map ranges, stream indexes, GUID/age identity, nested-server policy, duplicate identities, and unresolved cross-namespace references fail closed.

## Integration

- Review each subsystem diff and its stated support boundaries before merging it into the shared worktree.
- Update capability rows sequentially after agent edits are complete.
- Run `cmake --build out/build/windows-desktop --target hexlab --config Debug -- /m:1 /v:minimal` once; do not launch the GUI or run tests.

## Integration record

- Implemented and reviewed all three slices; the RISC-V classifier rejects vectors and unsupported variadic/hardware-FP conventions explicitly.
- Connected the desktop PDB importer to the DBI-map combined graph path, retaining the legacy `LF_TYPESERVER2` fallback.
- Added an 85-row processor variant obligation matrix; every child remains `not_assessed` pending implementation evidence.
- Serialized Windows Debug `hexlab` build passed on 2026-10-24. No tests were added or run, and no desktop window was opened.
