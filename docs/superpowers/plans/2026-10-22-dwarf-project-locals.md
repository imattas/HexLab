# DWARF Project Local Variables Implementation Plan

> **For agentic workers:** Keep DWARF parsing bounded and preserve source location descriptions. Explicit evaluation is allowed only through a caller-supplied machine context; never acquire registers or memory from a process in the parser/importer. Root owns integrated verification and capability-ledger updates.

**Goal:** Persist imported DWARF parameters and local variables in analysis projects and make their declared names, types, scopes, and unevaluated locations inspectable in the desktop workspace.

**Architecture:** Reuse `symbols::ImportResult::variables` from the existing ELF DWARF v4/v5 reader. Resolve each variable's `scope_offset` against the subprogram `SourceOrigin::record_offset`, then require that the subprogram address maps into the loaded image. Persist a `DebugVariable` with a project entity ID, function entry, optional `TypeDefinition` ID, parameter/local kind, DIE scope offset, optional direct address, bounded raw expression bytes, decoded operation tuples, location ranges, CFA-relative offset, and full `SourceOrigin`. Deduplicate by `(source_id, section, unit_offset, record_offset)` so re-import is idempotent and different source files remain distinct. Store rows in SQLite and in the canonical `UserState` codec; add a reversible history change kind. The Types & Symbols view gets a virtual Variables page that formats locations as direct address, unavailable, or decoded expression operations. A separate workspace API evaluates a bounded operation subset only from an explicit caller-provided `LocationEvaluationContext`; it does not attach to a process.

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

- [x] Add `DebugVariable` to database `UserState`, validate entity IDs/source origins/function/type references, encode it in the canonical user-state codec, and add the schema v4 table + migration + snapshot load/write + budget accounting. Later schema v5/v6 migrations add CFA offsets and location ranges.
- [x] Add `DebugVariableChange` to transaction deltas and history tags; source tests cover undo/redo, save/reopen, and malformed/unmapped ownership behavior.
- [x] Extend `ImportDwarfInfo` to map each imported variable's enclosing subprogram DIE to a loaded-image function entry, link imported named types, keep direct addresses separate from expression bytes, and deduplicate imports by source DIE identity.
- [x] Add the Types & Symbols `Variables` virtual page with function/name/kind/type/scope/location columns; raw and decoded operations retain their source form, and missing locations are shown as unavailable.
- [x] Add generated ELF DWARF fixtures for parameter/local scoping, `DW_OP_fbreg`, register locations, pieces, absent locations, unscoped variables, malformed type references, deduplication, source-origin retention, location ranges, and explicit caller-context evaluation.
- [ ] Add direct malformed or nonexistent `scope_offset` fixture coverage; the importer currently skips unresolved scopes and unscoped variables are covered.
- [x] Source review confirms transaction history, undo/redo, save/reopen, schema migrations, and documented parser/model/UI limits. Windows Debug `hexlab_database`, `hexlab_workspace`, and integrated `hexlab_desktop_components` builds passed. No tests were run in this turn.
- [ ] Run focused and project-wide CTests.

**Implementation ownership:** `libs/database/**`, `libs/workspace/**` variable-related command files, `apps/desktop/type_symbols_view.*`, `tests/project_command_tests.cpp`, `tests/support/elf_dwarf_fixture.hpp`, and DWARF/project docs. Existing DWARF parsing in `libs/symbols/**` is consumed as-is unless a concrete importer shape defect blocks the milestone. Use a fresh isolated build directory and do not edit the capability ledger.
