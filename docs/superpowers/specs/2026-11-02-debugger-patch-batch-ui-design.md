# Debugger memory patch batch UI

Expose guarded multi-range patches in a modal desktop editor, opened beside the existing single-range Write controls. Provide an editable address / optional expected hex / replacement hex grid with add/remove rows, apply, cancel, guarded undo/redo, and a read-only report with per-range original/replacement snapshots and rollback failures. Keep the editor and latest report for the current attachment between openings.

## Constraints
Use existing inspection worker and backend_mutex; never call the batch APIs on the UI thread. A modal dialog excludes conflicting main-window actions; polling pauses only during the batch. Check session and stop generations again under the backend lock before executing queued mutations. Ignore stale callbacks. Clear retained undo/report on attachment changes and request cancellation on destruction. Cancellation follows core semantics: cannot interrupt a backend call and never suppresses rollback.

Core API remains authoritative for 1..256 ranges, at most 1 MiB, non-overlap, expected sizes, no wrapping, pending whole-process stop and breakpoint restrictions. Validate editable byte syntax and core bounds before queueing. Retain successful reports for guarded undo; a successful undo becomes the next undo report (redo), a preflight failure keeps the prior undo report, and incomplete recovery clears it. Show complete recovery information for deliberate inspection; do not auto-continue.

## Approaches
A permanent tab would require broad changes to every synchronous mutation control to avoid locking the UI during an async batch. A blocking API call would prevent cancellation. Chosen implementation is a modal grid using the existing async worker; modal main-window exclusion gives a narrow, reviewable change with responsive cancellation.

## Scope and validation
Only debugger_view.cpp/.hpp, this spec/plan, and narrowly scoped desktop documentation. User authorized implementation without further design approvals; no tests, CI, push, cleanup, or extra agents. Build Windows desktop with BUILD_TESTING=OFF and inspect the diff. Runtime debugger interaction is a remaining manual validation step.
