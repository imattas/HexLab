# Analysis, Mach-O Unwind, and ARM64 Debugger Wave

> **For agentic workers:** Implement one subsystem task; use source-only compilation. Do not add or run tests.

**Goal:** Advance major function-analysis, Mach-O unwind, and native ARM64 debugging capabilities in HexLab.

**Architecture:** Keep changes within separate library boundaries, preserve bounded/cancelable parsing and fail-closed behavior, and document exact support. Root reviews the integration and capability ledger.

**Tech Stack:** C++20, current HexLab libraries, wxWidgets only for existing desktop integration.

**Spec:** `docs/capabilities.csv` rows `analysis.functions`, `loader.macho`, and `debug.platforms`.

## Global Constraints

- Do not add or run tests; source-only compilation is allowed.
- Do not touch active `libs/decompiler/src/decompiler.cpp` edits.
- Do not clean or remove anything under `out/`.
- Preserve current native APIs and unsupported states unless the implementation can prove support.

## Review Focus

- ARM/Thumb predication and mode transitions must not invent fallthrough or function ownership.
- Unwind pointer encodings, personality identity, and RTTI bounds must be validated before interpretation.
- ARM64 debug context/breakpoint operations must preserve unrelated registers and restore original instruction bytes on detach/failure.

### Task 1: Function recovery

Own `libs/analysis` function recovery and directly related docs. Expand generalized incremental/mode-aware recovery and ARM control-flow/predication coverage as a cohesive architecture capability.

### Task 2: Mach-O unwind and personality metadata

Own Mach-O unwind parsing/model/docs in `libs/loaders` and its bounded supporting metadata. Advance remaining CFI and supported personality/type-table interpretation without executing personality code.

### Task 3: Windows ARM64 debugger

Own the Windows native debugger backend/model/docs. Advance ARM64 live context, register edits, breakpoints, and lifecycle behavior using the supported Windows API surface; preserve other architectures.

### Integration

Root reviews changes, checks file boundaries and docs/ledger consistency, and performs source-only compilation for headers or targets not covered by agents. No tests or link targets.
