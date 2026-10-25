# HexLab foundation validation

Validated on the Windows x64 development host on 2026-10-19 using CMake 4.4.4, MSVC 19.44, Windows SDK 10.0.26100.0 and pinned wxWidgets 3.2.12. This evidence applies to the foundation; the [capability inventory](capabilities.csv) identifies the remaining application work.

## Automated checks

| Configuration | Checks | Result |
| --- | --- | --- |
| Debug desktop | `core`, `cli`, `desktop_smoke`, `desktop_floating_smoke` | 4/4 passed |
| Release headless | `core`, `cli` | 2/2 passed |
| Offline headless with GUI disabled | `core`, `cli`, no `_deps` directory | 2/2 passed without GUI dependency acquisition |
| Installed developer distribution | CLI output, engine and wx DLLs, headers, import library, notices, desktop launch | Passed |

The core test binary executes 39 checks, including integer overflow, address-space identity, half-open ranges, invalid result access, endian-specific integer reads, unaligned input, maximum-size requests and unchanged cursors on failure. The CLI test invokes the actual executable with valid and invalid argument combinations.

The floating-pane regression test first failed with a real wxWidgets assertion: resetting a recently closed floating pane attempted to attach its window to another sizer before deferred destruction released the old membership. The application now detaches that membership on pane close. Main frame destruction also destroys owned floating windows while the manager still exists. The regression and full desktop suite pass after the fix.

## Runtime and visual checks

`dumpbin /dependents` confirms that the installed CLI imports `hexlab_core.dll`. The desktop imports that engine DLL plus wxWidgets base, core and AUI DLLs. The install tree has separate executables, DLLs, import libraries, development headers, documentation and dependency notices.

Actual installed-app captures verified the main window, Functions/Symbols/Output labels, About version information and a smaller window layout. The About command and normal close were exercised through native window commands. Keyboard focus automation could not independently prove the shortcut interaction; a complete accessibility and high DPI audit remains required later. No visual result is inferred from compilation alone.

## Review and remaining work

An independent read-only code review found no critical or important defects in the foundation. Its coverage comment led to the extra floating-pane regression check; dependency naming and capability evidence were corrected during final validation.

This is a developer distribution, with the Visual C++ Debug runtime available on this machine. Fresh-machine installers, Release desktop packaging and Linux/macOS delivery remain unverified. Binary loaders, instruction decoders, persistent projects, types, the decompiler, debugger and extension SDK remain required future stages.

Git commits could not be created because author identity is unset. Source files are preserved on the new `feat/foundation` branch without an invented identity.
