# Portable Debug Variable Exchange Plan

Design: `docs/superpowers/specs/2026-10-24-project-exchange-debug-variables.md`.

## Task 1: Workspace import command

**Files:** `libs/workspace/include/hexlab/workspace/commands.hpp`, `libs/workspace/src/commands.cpp`.

**Interface:** Add `PortableDebugVariable` with function entry, name, optional type name, parameter flag, scope offset, optional direct address, expression bytes and operations, source origin, optional CFA offset, and ordered location ranges. Add `ImportPortableDebugVariables { std::vector<PortableDebugVariable> variables; }` to `ProjectCommand`.

- [x] Validate row limits, UTF-8/lengths, supported operation kinds, expression offsets, aggregate location bounds, function-owner existence, optional type-name resolution, and unique provenance keys before staging changes.
- [x] Resolve optional type names against the projected user state; allocate destination IDs for new rows and preserve IDs for replacements.
- [x] Emit ordinary `DebugVariableChange` rows so batch import remains atomic and undoable.
- [x] Review command validation against persisted `DebugVariable` invariants. Do not add or run tests.

## Task 2: HXEX v6 export/import

**Files:** `libs/workspace/include/hexlab/workspace/project_exchange.hpp`, `libs/workspace/src/project_exchange.cpp`, `docs/project-exchange.md`.

**Interface:** Append `debug_variable` to `ExchangeRecordKind`; append a `debug_variables` count to `ExchangeImport`.

- [x] Extend the parser to accept v6 with one appended count while preserving v1-v5 layouts; parse bounded operation/range payloads and validate source origins, sentinels, enum values, offsets, and canonical duplicate-free ordering.
- [x] Export all persisted debug variables canonically, replacing type IDs with names and mapping function/direct-address/PC-range addresses through contiguous source-file extents.
- [x] Import v6 debug variables after function and type records, map file offsets back to destination addresses, and apply `fail`/`skip`/`replace` by source-origin identity with deterministic conflict records.
- [x] Ensure total row accounting includes debug variables and all new payloads remain within 16 MiB and existing database-level budgets.
- [x] Document v6 layout, identity, mapping, merge behavior, and limits. Keep v1-v5 import behavior intact.
- [ ] Run whitespace checks and root compile-only Debug builds for workspace/CLI/desktop; do not add or run tests.

## Review focus

- New version count/header parsing does not shift legacy record offsets.
- Half-open PC ranges round-trip at segment boundaries without overflow; the default sentinel is preserved.
- Type and function references resolve after preceding commands in the same projected batch.
- Replace preserves the existing entity ID while conflicting imports remain all-or-nothing.
- Operation order and range order remain unchanged because they are semantic.
