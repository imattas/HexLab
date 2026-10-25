# Next capability wave plan

## Tasks

- [x] Extend C header import for GNU/Clang function-convention and vector type attributes.
- [x] Add exact lane semantics and supported lifting for the existing AVX/AVX2 decoder subset.
- [x] Improve managed CIL exception-flow recovery using bounded metadata-backed dispatch.
- [x] Reconcile capability evidence and focused subsystem documentation.
- [x] Ensure the current debugger documentation is installed with the multi-file package.
- [x] Run one serial integrated Debug build; inspect whitespace and confirm `out/` is unchanged.

## Validation limits

Do not add or run tests. Darwin/macOS behavior is outside this wave; all three
workstreams must be checked in the Windows Debug build where their sources are
platform-neutral.

## Integration evidence

`cmake --build switch-desktop-build --target hexlab_desktop_components --config Debug --parallel 1`
completed with exit code 0 after the final source changes. No tests were run.
The 80-row capability ledger parses, trailing-whitespace scans are clean, and
`out/` remains untouched. MSVC reports existing exported-`Type` DLL-interface
warnings; the CIL build also emitted a local-shadow warning that was corrected
before the final build.
