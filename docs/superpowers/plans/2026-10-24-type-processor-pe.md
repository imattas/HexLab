# Type, Processor, and PE Coverage Plan

## Goal

Advance three separate core areas toward the approved IDA-scale HexLab destination: C/C++ header type import, MIPS64 processor semantics, and PE exception metadata.

## Constraints

- Preserve the approved C++20 monorepo and wxWidgets frontend.
- Keep the HexLab window on DISPLAY2, launched without activation; do not interact with its UI while the user is gaming.
- Preserve the active common decompiler edits; do not edit `libs/decompiler/src/decompiler.cpp`, `docs/decompiler-structuring.md`, or the active decompiler tests.
- Each workstream owns its subsystem end to end and must not edit the capability ledger or shared build lists.
- Do not add or run tests in this wave; review source and verify with one integrated build.
- Do not clean or delete anything from `out/`.

## Independent workstreams

1. **C/C++ header import** — advance the bounded source parser toward real-world macro/preprocessor behavior, including rescanning, stringification/token pasting, and explicit unsupported directives where needed.
2. **MIPS64 processor** — advance one coherent MIPS64 decoder-and-lifting slice, including COP1 conversions/transfers and condition-code branches where the existing interfaces permit; preserve delay-slot and architectural state semantics.
3. **PE exceptions** — extend bounded Windows exception metadata interpretation, including language-specific scope/handler records where their exact format and bounds are supported; do not execute target handlers.

## Integration

- Review arithmetic, extent, register/state, and malformed-input bounds, plus the exact support boundary in docs.
- Update capability evidence only after integration review.
- Build without bringing the GUI to the foreground. If loaded modules block relinking, compile the affected library sources and record the limitation.

## Integration update — 2026-10-24

- Header import gained bounded function-like macro stringification (`#`) and token pasting (`##`) using raw arguments; pasted replacements are rescanned through the existing expansion guards. Empty placemarkers and complex multi-token pastes remain unsupported. Details: `libs/types/src/header_preprocessor.cpp`, `docs/header-import.md`.
- AMD64 PE exception-directory parsing now rejects runtime-function entries whose starts are not strictly increasing or whose ranges overlap. Rejection happens before committing the parsed table. Language payloads remain uninterpreted unless handler identity and bounds can be established. Details: `libs/loaders/src/pe_exceptions.cpp`, `docs/pe-exception-directory.md`, `docs/pe-unwind-info.md`.
- MIPS64 already had the proposed COP1 transfers, conversions, FCC comparisons/branches, and delay-slot metadata; no MIPS64 changes were needed. Likely branches, compare variants beyond EQ/LT/LE, and precise FCC aliasing remain gaps.
- Build verification: `cmake --build out/build/windows-desktop --target hexlab_core --config Debug -- /m:1 /v:minimal` passed. The HexLab window remained open on the second monitor, so the executable target was not rebuilt. No tests were run.

- Follow-up verification: MSBuild `ClCompile` succeeded for `hexlab_types` and `hexlab_loaders`. Relinking `hexlab_types.dll` was blocked with LNK1168 because the currently open HexLab process has that DLL loaded; the UI remained responsive and non-foreground on DISPLAY2.
