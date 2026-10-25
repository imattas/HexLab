# DWARF Project Symbols and Types Plan

> **For agentic workers:** Implement this subsystem end to end. Keep DWARF parsing bounded and preserve unsupported data explicitly. Use focused test-first changes; root owns integrated build and capability-ledger updates.

**Goal:** Make DWARF debug information useful in HexLab projects by importing supported functions, types, prototypes, and scoped variables from real executable images.

**Architecture:** Extend the existing standalone `hexlab::symbols` DWARF importer and connect its records to the existing project symbol/type model. Keep parsing independent of wxWidgets and never evaluate location expressions without runtime context. Unsupported DWARF forms must return explicit diagnostics without corrupting unrelated symbols.

**Tech Stack:** C++20, CMake, CTest, existing `libs/symbols`, `libs/loaders`, `libs/types`, and workspace project APIs.

**Spec:** `docs/superpowers/specs/2026-10-19-hexlab-design.md`

## Global Constraints

- Bound all unit, DIE, recursion, string, and expression work; honor cancellation where existing APIs expose it.
- Keep malformed and unsupported data explicit; do not invent addresses or runtime variable locations.
- Preserve source provenance and stable project persistence semantics.
- Keep GUI dependencies out of symbol parsing and model layers.

## Review Focus

- Multiple compilation units with cross-unit references must not resolve to the wrong type.
- DWARF v5 forms and indexed strings must respect contribution bounds and endian/address-size metadata.
- Optimized variables may have location lists; do not flatten a time-varying location to a false constant address.
- Recursive types and forward declarations must preserve graph identity without unbounded recursion.
- Missing or malformed debug sections must not prevent normal binary loading or symbol analysis.

## Deliverable

Extend the v4-only `.debug_info` parser toward DWARF v5 type/symbol coverage, with a real project import path that persists functions, prototypes, named types, and scoped variable records where supported. Add generated binary/debug fixtures and tests for malformed bounds, references, recursion, and optimized location expressions. Document the supported DWARF versions/forms and remaining gaps in `docs/capabilities.csv` evidence and the DWARF documentation.

## Implemented Milestone: ELF v4 Project Import

- [x] Load supported little-endian ELF `.debug_info`, `.debug_abbrev`, and optional `.debug_str` through the bounded image metadata reader.
- [x] Retain imported DIE/type/function/variable records and source provenance in `ElfMetadata::dwarf_info`; keep runtime location expressions descriptive and unevaluated.
- [x] Keep the ELF load successful when DWARF sections are malformed or unsupported, while recording an incomplete-metadata diagnostic.
- [x] Add stop-token checks during v4 unit, DIE, attribute, and type traversal.
- [x] Add a Types & Symbols action and reversible workspace transaction that persists named types, function prototypes/assignments, mapped subprogram names, and validated executable function roots.
- [x] Verify generated valid/malformed ELF DWARF fixtures and project persistence through reopen.
- [x] Persist scoped variables in the project database and expose them in a variable view.
- [ ] Add DWARF v5 `.debug_info` forms/contribution handling, Mach-O `.debug_info`, relocations, and cross-unit reference resolution.
- [x] Preserve DIE provenance in persisted type records, user-state/history codecs, SQLite rows, and project exchange.

### Verified follow-up

- A bounded unit-header pass records each supported DWARF32 unit boundary and type-unit kind, then processes type units before compile units while preserving order inside each group. This lets a compile unit resolve `DW_FORM_ref_sig8` to a later type unit. The `dwarf_extended` test covers CU-before-TU order. Cross-unit `DW_FORM_ref_addr` targets beyond previously processed types and forward signature references between type units remain unsupported.
- The already-landed scoped-variable persistence/view milestone was verified with the `project_commands` test, including source provenance, raw/decoded locations, unknown locations, undo/redo, and project reopen.
- Named type and function-prototype records retain their source identity, section, unit offset, DIE offset, and DIE size. SQLite schema v7 adds nullable provenance columns and migrates older projects with empty origins; user-state codec v6 and exchange v4 preserve origins. Focused evidence covers type codec and project reopen, history undo/redo, exchange round trip, and schema migration.
