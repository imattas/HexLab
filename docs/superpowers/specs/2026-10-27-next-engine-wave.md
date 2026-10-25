# Next Engine Subsystems Wave

## Objective

Advance three independent, user-facing HexLab capabilities while keeping all work headless and preserving `out/`.

## Workstreams

1. **Pseudocode editing:** inspect current edit commands and persistence, then implement a substantial missing capability around stable ABI-aware variable identity or related durable editing. Preserve undo/redo and avoid reworking already working annotation comments. Owner: decompiler editing agent.
2. **Debugger inspection:** inspect current register writes, symbolication, stack frames, and module handling; deliver a substantial missing workflow in debugger inspection. Do not duplicate existing controls. Owner: debugger agent.
3. **String analysis:** expand bounded string discovery beyond current UTF-8/16/32 classification with a useful, explicitly labeled encoding strategy; maintain range, cancellation, and budget constraints. Owner: strings agent.

## Constraints

- No GUI launch, foreground window, or CUA. The user is playing a game.
- Do not read, write, clean, or build in `out/`.
- Do not add or run tests. Focused Debug target compilation is allowed.
- Keep source ownership separate. Each agent should report exact files and compile evidence.
- Update only capability ledger claims supported by inspected source/build evidence.
