# Next Engine Subsystems Wave Plan

1. Re-inspect each capability gap against current source, correcting stale ledger assumptions.
2. Implement three independently owned workstreams: pseudocode editing, debugger inspection, and string analysis.
3. Review each change for bounded behavior, persistence compatibility, and ownership conflicts.
4. Compile affected Debug targets when possible; do not add or run tests.
5. Update `docs/capabilities.csv` and subsystem docs only where evidence supports the change.
6. Confirm `out/` remains untouched and no GUI was opened.

## Progress

- Pseudocode stack locals with recovered stable slot names now enter the existing edit model. Rename/type assignments bind to the first stack access and use durable address annotations/type records. Inferred type labels remain visible without an override. Parameters remain read-only because entry-address type assignment is shared with function prototypes.
- Debugger view now exposes `Continue selected thread`. It requires a pending event and a selected thread matching the event's thread ID, then calls the existing per-thread resume API. Pending thread ownership is cleared on continue, step, and session lifecycle transitions.
- String discovery now emits deterministic Windows-1252 heuristic candidates with fixed C1 mapping, rejects undefined C1 bytes, requires non-ASCII content to avoid duplicate ASCII rows, and retains explicit encoding identity through derived-cache validation. Added `docs/string-encodings.md` and the desktop encoding label. Public enum value 6 is `windows1252`.
- Verification: `cmake --build switch-desktop-build --target hexlab_desktop_components --config Debug --parallel 3` completed successfully, compiling analysis, decompiler, workspace, debugger view, pseudocode view, and main frame. Existing compiler warnings remain. No tests were added or run, no GUI was opened, and `out/` remained untouched.
