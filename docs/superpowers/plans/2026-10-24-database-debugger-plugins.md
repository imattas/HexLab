# Database, Debugger, and Plugin Work Plan

## Goal

Advance three large, independent HexLab subsystems toward the approved full IDA-scale scope: transactional project storage, live debugger interoperability, and native plugin lifecycle/API.

## Constraints

- Keep the full C++20 monorepo and wxWidgets architecture; do not reduce the product to a demo.
- Leave the open HexLab window on DISPLAY2 and do not interact with it or bring it to the foreground.
- Preserve the active decompiler work in `libs/decompiler/src/decompiler.cpp`, `docs/decompiler-structuring.md`, and active decompiler tests.
- Each agent owns one complete subsystem workstream and its subsystem documentation; do not touch shared build lists or `docs/capabilities.csv`.
- Do not add or run tests in this wave. Do not clean `out/` or other existing artifact directories.
- Keep changes bounded, documented, cancellation-aware, and compatible with current schema/protocol/ABI versioning.

## Independent Workstreams

1. **Transactional project storage** — inspect `libs/database` end to end and improve one substantial durability/recovery/migration path without changing schema compatibility silently.
2. **GDB Remote Serial Protocol** — inspect `libs/debugger` RSP client/server and implement a coherent interoperability improvement across protocol handling and session behavior, preserving bounded packet parsing and cancellation.
3. **Native plugin system** — inspect `libs/plugins` SDK, ABI, runtime and lifecycle; improve one substantial end-to-end extension capability with explicit ABI/lifetime/error contracts.
4. **ELF static linking** — extend the existing x86-64/AArch64 ELF linker to preserve zero-filled `.bss` sections in relocatable and executable outputs, including symbol/relocation resolution and PT_LOAD memory extents.
5. **Project recovery workflow** — expose validated recovery candidates from the desktop project-open flow with explicit user choice and revalidation on open.
6. **Plugin discovery workflow** — connect bounded candidate scanning to the plugin panel and require explicit selection before loading code.
7. **Debugger termination workflow** — expose `DebugSession::terminate()` in the debugger panel with clear distinction from detach and a target-termination confirmation.

## Integration

- Review every changed file and the documented support limits.
- Compile affected sources without linking over DLLs loaded by the open desktop process; record any file-lock limitation.
- Update capability evidence only after review and record the integrated result here.
- Full IDA-scale parity remains an ongoing objective.


## Integration update ? 2026-10-24

- Project storage adds bounded, read-only discovery of interrupted Save As and retained prior-version artifacts; candidates are exposed only after normal project validation. Discovery does not change the artifacts.
- RSP debugger sessions now support target termination: `k` for single-process sessions and `vKill;pid` for advertised multiprocess mode with a known process ID. Native termination and restart remain unsupported.
- Native plugin manager adds deterministic bounded directory scanning for direct module candidates. Discovery does not load or execute modules; callers explicitly choose paths.
- ELF static link output now preserves writable SHT_NOBITS `.bss`, rebases its symbols, applies text/data references to BSS, and models zero-fill in the executable's writable PT_LOAD memory extent. BSS relocations, common symbols, COMDAT, and GOT/PLT/TLS remain unsupported.
- Source compilation passed for `hexlab_loaders`, `hexlab_database`, `hexlab_debugger`, and `hexlab_plugins` using MSBuild `ClCompile` in Debug configuration. No tests were added or run. Library linking was omitted because the open HexLab process has the component DLLs loaded.


## Desktop workflow update ? 2026-10-24

- Project open failures now trigger bounded recovery discovery off the UI thread. A wxWidgets choice dialog identifies each validated candidate and requires explicit selection; the selected path goes through normal project-open validation. No artifact is changed automatically.
- The Plugins view now offers directory scanning and a separate list labeled as unloaded modules. Users must select a candidate and explicitly load it; scanning does not execute module code.
- The debugger view now has a separate confirmed **Terminate target** command. It runs off the UI thread, leaves displayed state unchanged on failure, and is distinct from detach.
- Debug MSVC compilation succeeded for loader, database, debugger, plugin, and desktop-component sources. `hexlab_desktop_components.lib` linked successfully. No tests were run. The running HexLab executable remains open and was not relinked or interacted with.
