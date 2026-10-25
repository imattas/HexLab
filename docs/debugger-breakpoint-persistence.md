# Project breakpoint hit counters

Project breakpoints store their runtime hit counter in the project database.
When a project breakpoint is applied to a debug session, the saved count is
restored alongside its condition, logpoint, and ignore threshold. While the
session runs, desktop event polling writes changed counts back to the project.
This includes hits consumed by an ignore count or logpoint.

Counter updates use the project actor's metadata operation. They are committed
atomically without changing the user edit revision or adding undo-history
entries. Editing a breakpoint rule updates its definition while retaining the
counter. Removing the breakpoint removes its persisted count. Projects at
schema version 10 migrate by adding a zero-initialized counter column; older
project record and history encodings remain readable.

Counts are currently persisted by the desktop debugger when it can uniquely
map a live breakpoint's runtime address back to a saved project image address.
Standalone debugger sessions and unmapped breakpoints remain session-only.
