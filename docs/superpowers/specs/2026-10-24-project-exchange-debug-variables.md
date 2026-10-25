# Portable Debug Variable Exchange

## Intent

Move already-imported scoped debug variable metadata between HexLab projects that were opened from identical original input bytes. This helps when one workspace has richer PDB/DWARF variable metadata or locally available type information and another workspace needs the same inspection view.

## Goals

- Add debug variables to the portable `HXEX` exchange format as version 6.
- Preserve variable names, parameter status, scope offsets, optional type names, source provenance, direct addresses, CFA locations, raw expressions, decoded operations, and PC-scoped location ranges.
- Translate all image virtual addresses through source-file offsets. Never serialize project/entity/type IDs.
- Import through one transactional workspace command after portable types and function decisions are applied.
- Apply the existing `fail`, `skip`, and `replace` conflict policy by stable debug-origin identity.
- Keep imports bounded by the existing 16 MiB exchange and 100,000-row limits plus the database's per-variable expression/range limits.
- Preserve v1-v5 import compatibility; new exports use v6.

## Non-goals

- No new debug-info parser, PDB transfer, external source-file contents, binary bytes, process state, runtime addresses, or user UI changes.
- No project schema migration or serialization of database IDs.
- No changes to annotation, bookmark, function, type, or type-assignment merge behavior.
- No tests may be added or run under the active workspace instruction; root owns compile-only verification.

## Approaches

1. Export only names/types and regenerate locations from the destination's local debug files. This fails when the destination does not have the source PDB/DWARF files.
2. Export only function-entry locations and simple direct addresses. This loses register/CFA expressions and PC-specific location lists, which are the core value of scoped variables.
3. Export the complete persisted `DebugVariable` record, replacing IDs with portable type names and virtual PCs with file-relative mapped ranges. This is selected because it preserves the current debugger inspection model while remaining bound to identical image bytes.

## Format and mapping

Version 6 appends one debug-variable count after the existing seven counts and appends canonical debug-variable records after type assignments. Each row is ordered by `(source_id, section, unit_offset, record_offset)` and contains a mapped function entry, UTF-8 name, parameter flag, scope offset, optional type name, optional mapped direct address, expression bytes, decoded operations, source origin, optional CFA offset, and ordered location ranges.

Function entries, direct addresses, and non-default half-open PC ranges are represented through the same portable file-offset mapping used elsewhere. Range ends are exclusive: encode the first byte and `end - begin`, require the full interval to map contiguously, then reconstruct `end` with checked address arithmetic. The existing `(UINT64_MAX, UINT64_MAX)` default-location sentinel remains unchanged. Expression bytes and operation order are preserved exactly. Operation operands use fixed-width little-endian fields. Type references resolve by definition name; IDs are newly assigned by the destination project.

Debug-variable identity is the existing database key `(source_id, section, unit_offset, record_offset)`. An identical existing row is idempotently skipped. A different row with the same origin uses the selected conflict policy and reports the mapped function entry. All rows and type references are validated before one `ImportPortableDebugVariables` command is staged; project batch execution applies it after imported type definitions, assignments, and function decisions in the same transaction/history step.

## Bounds and validation

- Total rows across all exchange record kinds, including debug variables: 100,000.
- Exchange bytes: at most 16 MiB.
- Names and provenance must satisfy persisted database UTF-8 and length limits.
- A variable may contain at most 65,536 expression bytes, 4,096 operations, and 4,096 location ranges. Across ranges, expression bytes and operations retain the existing aggregate user-state limits; encoded range payload is capped at 1 MiB.
- Every operation kind is in the persisted evaluator's supported enum range and every operation offset is within its corresponding nonempty expression.
- Non-default ranges must be nonempty, ordered as stored, source-file-backed, contiguous intervals. At most one default sentinel range is permitted.
- Every function entry must exist as an imported or destination function decision. Optional types must resolve by name after the type command is applied.
- Unsupported address mappings, incomplete ranges, malformed UTF-8, invalid enums, overflow, dangling type/function references, duplicate origins, truncation, and trailing bytes reject the whole exchange before commit.

## Implementation choices

- New command `ImportPortableDebugVariables` carries portable variables with type names and no IDs. Validation resolves names against the projected state, allocates local IDs, and emits ordinary `DebugVariableChange` history rows.
- Debug variables are appended as the final canonical v6 record class so old v1-v5 layouts are unchanged.
- Existing command batching supplies atomic commit and undo/redo; no new database format is needed.
- The default conflict policy remains fail. `skip` retains destination rows; `replace` updates the matching origin while retaining its local entity ID.
- Root integration owns builds and any review-driven correction. No test code or execution is included.
