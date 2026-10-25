# Large Subsystem Wave

## Goal

Continue the approved C++/wxWidgets reverse-engineering suite toward full IDA Pro scope by advancing independent foundational subsystems in one integration wave.

## Constraints

- Preserve the C++20 monorepo and wxWidgets desktop scope.
- Do not open, focus, or interact with the desktop application; it remains on the user's second monitor while they play.
- Do not add or run tests in this wave. Compile changed translation units or targets where possible.
- Keep analysis bounded, cancellation-aware, and fail closed when evidence is insufficient.
- Each workstream owns its source and focused documentation. Do not edit the shared capability ledger, CMake/build lists, common plan, or tests; the integrator owns those files.
- Do not clean `out/`.

## Workstreams

1. **Incremental analysis** — inspect the current invalidation and reuse pipeline, then implement a substantial improvement to precise dependency closure for changed source/mapping or analysis decisions. Preserve current source-byte reuse validation and avoid unsafe cache reuse.
2. **Type model and ABI layout** — inspect the shared type model, layout engine, and persistence/import boundaries; implement a coherent missing type-layout capability end to end (prefer bitfields or per-type packing if the existing model supports it), preserving old serialized/imported types and rejecting ambiguous layouts.
3. **Remote debugging** — inspect the GDB Remote Serial Protocol backend and implement a coherent substantial capability from its documented gaps, spanning protocol handling and backend behavior (prefer hardware breakpoints and thread-aware resume if supported cleanly). Preserve bounded packet parsing and explicit unsupported errors.

## Integration

- Review each implementation against current APIs and documented behavior.
- Compile affected components without replacing DLLs loaded by the open desktop process.
- Update capability evidence only after source review and successful compilation.
- The full product objective remains active after this wave.

## Wave Progress

- **Incremental analysis:** indexed dependency fact read ranges by start offset and prefix maximum end, then retained the existing prerequisite-closure walk. `hexlab_analysis` Debug `ClCompile` passed. The worst case can still scan many candidate ranges when long intervals overlap; large-project timing remains unmeasured.
- **Type model and importer:** retained base and per-pointer `const`/`volatile`, plus pointer-only `restrict`, through C header import. Qualified forward references and flexible-array tails remain supported. The type codec writes version 8 while decoding versions 1–7. `hexlab_types` Debug `ClCompile` passed after correcting a stale identifier found during integration review.
- **Remote debugging:** the server handles RSP `Z1`–`Z4` through `DebugSession`, advertises `hwbreak+` only for supported Windows x86/x64 and Linux x86-64 host/target combinations, and makes identical insert/remove requests idempotent. Windows `hexlab_debug_server` Debug `ClCompile` passed. Thread-specific continue remains unsupported because the shared session API resumes process-wide.
- No tests were added or run. No link was performed, and the desktop application was not opened or focused.
