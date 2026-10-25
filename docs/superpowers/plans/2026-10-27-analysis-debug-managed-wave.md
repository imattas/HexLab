# Analysis, Debugger, and Managed-Code Wave Plan

1. Confirm each documented gap against current source and public APIs.
2. Implement distinct end-to-end improvements in analysis, debugger inspection, and managed exception flow.
3. Review bounded behavior, stale-state safety, malformed-input handling, and subsystem compatibility.
4. Compile affected Debug targets; add or run no tests.
5. Update the capability ledger from source/build evidence.
6. Confirm `out/` remains untouched; use GUI only if needed for visual inspection.
