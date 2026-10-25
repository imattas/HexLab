# Core Coverage Expansion Plan

## Goal

Advance three more independent IDA-scale areas in HexLab: Mach-O exception metadata, dependency-aware incremental analysis, and static COFF library linking.

## Constraints

- Preserve the approved original C++20 shared-library monorepo and wxWidgets frontend.
- Keep the desktop closed while the user is gaming.
- Do not edit the active decompiler worktree (`libs/decompiler/src/decompiler.cpp`, its current docs or tests).
- Keep each implementation inside its listed subsystem and avoid shared build-list or ledger edits.
- Do not add or run tests in this wave; use source review and the integrated build for verification.
- Do not delete or clean artifacts from `out/`.

## Independent workstreams

1. **Mach-O exceptions** — extend bounded LSDA/type-table and personality metadata interpretation without executing handlers or guessing unsupported ABI encodings.
2. **Incremental analysis** — improve dependency-aware invalidation and selective reanalysis across byte, decision, context, and derived-fact changes.
3. **Static COFF linking** — broaden the existing bounded archive linker toward ordinary object files and initialized/uninitialized data while preserving deterministic symbol resolution and explicit unsupported errors.

## Integration

- Review ownership, bounds, cancellation, stale-fact behavior, and unsupported cases for each change.
- Update capability evidence after the source review.
- Run one serialized Windows Debug `hexlab` build; do not launch the application.

## Integration record

- Mach-O exception import recognizes bounded positive Itanium C++ LSDA type-table references without executing personalities; reference-only user edits reuse CFG/function facts and strings when byte/mapping evidence matches; AMD64 COFF linking now handles bounded long names, `$` subsections, `.rdata`, and `.bss`.
- Integrated Windows Debug `hexlab` build passed on 2026-10-24. No tests were added or run, and no GUI was opened.
