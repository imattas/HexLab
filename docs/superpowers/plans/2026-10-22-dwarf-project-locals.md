# DWARF Project Local Variables Implementation Plan

> **For agentic workers:** Implement this plan end to end with test-first changes. Keep DWARF parsing bounded and preserve location descriptions without evaluating them. Root owns integrated verification and capability-ledger updates.

**Goal:** Persist imported DWARF parameters and local variables in analysis projects and make their declared names, types, scopes, and unevaluated locations inspectable in the desktop workspace.

**Architecture:** Reuse `symbols::ImportResult::variables` from the existing ELF DWARF v4 reader. Resolve each variable's `scope_offset` against the subprogram `SourceOrigin::record_offset`, then require that the subprogram address maps into the loaded image. Persist a `DebugVariable` with a project entity ID, function entry, optional `TypeDefinition` ID, parameter/local kind, DIE scope offset, optional direct address, bounded raw expression bytes, decoded operation tuples, and full `SourceOrigin`. Deduplicate by `(source_id, section, unit_offset, record_offset)` so re-import is idempotent and different source files remain distinct. Store rows in a dedicated v4 SQLite table and in the canonical `UserState` codec; add a reversible history change kind. The Types & Symbols view gets a virtual Variables page that formats locations as direct address, absent/optimized-out, or unevaluated expression operations. No location expression is evaluated.

**Tech Stack:** C++20, SQLite project database, existing workspace command/delta model, wxWidgets Types & Symbols view, CMake/CTest.

**Spec:** `docs/superpowers/specs/2026-10-19-hexlab-design.md`

## Global Constraints

- Do not evaluate DWARF location expressions without a live frame, registers, and memory context.
- Preserve stable project IDs, reversible command history, and schema migration behavior.
- Keep the DWARF parser and project model independent of wxWidgets.
- Bound imported names, locations, rows, and expression sizes; malformed debug data must not corrupt other project metadata.
- Skip unresolved scope-to-subprogram mappings, cross-image function matches, invalid UTF-8/oversized names, and rows/expressions/operation vectors beyond project bounds. The existing DWARF reader rejects malformed type DIE references at the import-result boundary; ELF metadata remains usable without DWARF, and this milestone does not weaken that parser contract.

## Review Focus

- Variables whose location is absent or optimized out remain visible without fabricated addresses.
- `DW_OP_fbreg`, `DW_OP_reg*`, pieces, and runtime-dependent expressions remain descriptive and typed.
- A variable DIE maps only to the correct enclosing subprogram and loaded image.
- Import, undo/redo, save/reopen, and schema migration preserve the same variable records.
- Name/type collisions and repeated imports do not create duplicate persistent records.

## Tasks

- [ ] Add `DebugVariable` to database `UserState`, validate entity IDs/source origins/function/type references, encode it in the canonical user-state codec, and add schema v4 table + migration + snapshot load/write + budget accounting.
- [ ] Add `DebugVariableChange` to transaction deltas and history tags; verify deterministic undo/redo and reject malformed/unmapped scope references without fabricated owners.
- [ ] Extend `ImportDwarfInfo` to map each imported variable's enclosing subprogram DIE to a loaded-image function entry, link any already-imported named type, keep direct addresses separate from expression bytes, and deduplicate repeated imports by source DIE identity.
- [ ] Add a Types & Symbols `Variables` virtual page with function/name/kind/type/scope/location columns; label raw and decoded expressions as unevaluated and display missing locations as unavailable/optimized-out.
- [ ] Add generated ELF DWARF fixtures and end-to-end tests for parameter/local scoping, `DW_OP_fbreg`, register locations, pieces, absent locations, malformed scope/type references, deduplication, and source-origin retention.
- [ ] Verify transaction history, undo/redo, save/reopen, migration from schema v3, focused CTests, and project-wide tests; document exact parser/model/UI limits.

**Implementation ownership:** `libs/database/**`, `libs/workspace/**` variable-related command files, `apps/desktop/type_symbols_view.*`, `tests/project_command_tests.cpp`, `tests/support/elf_dwarf_fixture.hpp`, and DWARF/project docs. Existing DWARF parsing in `libs/symbols/**` is consumed as-is unless a concrete importer shape defect blocks the milestone. Use a fresh isolated build directory and do not edit the capability ledger.
