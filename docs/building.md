# Building HexLab

HexLab uses C++20 and CMake 3.24 or later. The current development host has Visual Studio Build Tools 2022 with MSVC 19.44 and Windows SDK 10.0.26100.0. Install the Desktop development with C++ workload on a new Windows host. The Visual Studio CMake generator locates the compiler without a developer-shell PATH.

## Headless build

Run from the repository root:

```powershell
cmake --preset windows-headless
cmake --build --preset windows-headless
ctest --preset windows-headless
cmake --build --preset windows-headless-release
ctest --preset windows-headless-release
./out/build/windows-headless/bin/Debug/hexlab_cli.exe --help
```

The headless build uses the C++ standard library, operating system runtime and vendored SQLite DLL. It does not fetch wxWidgets. Tests remain active in Release.

ELF differential tests require Python 3 and the observed LLVM tools bound by `tests/fixtures/elf_oracle/tools.json`. `HEXLAB_ELF_CLANG`, `HEXLAB_ELF_LLD` and `HEXLAB_ELF_READOBJ` select their locations. A missing or different tool fails validation rather than skipping it. These are test-only dependencies; `BUILD_TESTING=OFF` excludes their discovery and all test targets. The currently recorded binary hashes describe the validated Windows development host.

## Desktop build

```powershell
cmake --preset windows-desktop -DHEXLAB_ENABLE_GUI_TESTS=ON
cmake --build --preset windows-desktop --parallel 4
ctest --preset windows-desktop
./out/build/windows-desktop/bin/Debug/hexlab.exe
```

The initial configure fetches the pinned wxWidgets source and its submodules. It requires Git and network access. Subsequent builds reuse the dependency checkout. Desktop smoke tests require an interactive Windows desktop. `desktop_smoke` exercises floating, hiding and reset; `desktop_floating_smoke` closes a floating pane, resets its layout immediately and shuts down with a pane still floating.

HexLab is a monorepo: `apps/` contains separate desktop, CLI, and debugger-server tools; `libs/` contains core, image, loaders, processors, the type model, analysis, database, workspace, debugger, and plugin DLL targets. The database links a separate vendored SQLite runtime. `hexlab.exe`, `hexlab_cli.exe`, and `hexlab_debug_server.exe` use shared engines; the desktop additionally uses wxWidgets DLLs. Engine DLLs have no wx dependency. See [the GDB Remote Serial Protocol server guide](debug-server.md) for local target-control and connection details.

Install the complete suite rather than copying one executable:

```powershell
cmake --install out/build/windows-desktop --config Debug --prefix out/install/ProjectAnalysisDebug
./out/install/ProjectAnalysisDebug/bin/hexlab_cli.exe --version
./out/install/ProjectAnalysisDebug/bin/hexlab.exe --smoke-test
```

The install tree contains `bin/` tools and Windows runtime DLLs, `lib/` engine and wxWidgets runtime/link libraries on Linux/macOS, `include/` development headers and `share/hexlab/` documentation and notices. The desktop executable uses a relative runtime search path to resolve the bundled wxWidgets libraries. Debug builds require the installed Visual C++ Debug runtime and are developer packages. Release archives include the application-owned runtime files; host-provided runtime installation and fresh-machine validation remain separate requirements.

The install tree also contains `share/hexlab/package-manifest.json`. It lists
the packaged tools, engine runtime targets, relative install directories,
desktop inclusion, target architecture, and the native plugin ABI version.
See [package manifest](package-manifest.md) for its schema and platform limits.

Create a relocatable multi-file release archive from a Release build with CPack:

```powershell
cmake --build out/build/windows-desktop --config Release --target package
```

The ZIP is written to `out/build/windows-desktop/packages/` and contains the
complete install tree, including `hexlab.exe`, `hexlab_cli.exe`, engine and
wxWidgets DLLs, headers, documentation and third-party notices. The archive
test extracts the generated ZIP, checks the GUI and runtime inventory and
required notices, then runs the packaged CLI from the extracted `bin/` with
that directory as its only non-system runtime search path. This verifies the
CLI without depending on the source or build tree; the test does not launch
the GUI. Windows systems need
the matching Microsoft Visual C++ 2022 Redistributable; the package does not
bundle Microsoft's runtime. Linux/macOS headless builds produce a TGZ with
their CLI and shared engine libraries. Native GUI packaging and fresh-machine
validation remain host-specific work.

An optional Windows installer can be generated alongside the ZIP when NSIS is
installed. Configure the existing build with
`-DHEXLAB_BUILD_NSIS_INSTALLER=ON`, then build the `package` target. CMake
requires `makensis` on `PATH`; CPack creates an installable multi-file tree,
Start Menu shortcuts for the GUI and CLI, a link to the build guide, and a
Windows uninstall entry. The installer does not bundle the application into a
single executable and does not launch HexLab automatically at the finish page.
The ZIP remains the default when this option is disabled.

The `Windows release package` workflow builds the Release ZIP on Windows Server
2022 for pushes, pull requests, and manual runs. It uploads the multi-file ZIP
and a SHA-256 checksum as a 14-day workflow artifact. This makes the same
relocatable install tree available for review without publishing a release or
changing the local build's package directory.

Linux desktop builds produce both a relocatable TGZ and an installable Debian
package; macOS desktop builds produce a TGZ. Linux packages include the GUI,
CLI and debugger server, HexLab engine shared libraries, wxWidgets runtime
libraries, headers, documentation, third-party notices, and an XDG application
launcher with a scalable icon. The DEB installs under `/usr` and uses
`dpkg-shlibdeps` to declare host runtime-library dependencies. To install it on
Debian or Ubuntu, run `sudo apt install ./HexLab-*-Linux-*.deb`. The TGZ can be
extracted to a chosen prefix and run from its `bin/` directory; its executables
use relative runtime paths to find the bundled libraries.

When `HEXLAB_ENABLE_PYTHON_AUTOMATION=ON`, the desktop embeds the system CPython
runtime instead of bundling a Python distribution. On Linux the DEB dependency
scanner records the needed host Python shared-library dependency. Python
automation remains disabled by default.

The cross-platform desktop workflow extracts each native Linux and macOS
Release TGZ under a fresh runner directory and runs the packaged CLI version
command from that relocated tree with `LD_LIBRARY_PATH` and
`DYLD_LIBRARY_PATH` unset. This checks that the CLI resolves its bundled engine
libraries using the installed runtime paths. The workflow also verifies the
desktop executable and bundled wxWidgets libraries are present; it does not
launch the GUI. It uploads each TGZ with a SHA-256 sidecar, plus the Linux DEB
and its checksum, as 14-day artifacts. Artifact names include runner platform
and commit SHA. These artifacts are for review and download; the workflow does
not publish a GitHub release.

Validate the installed files and both tools with:

```powershell
cmake -DPREFIX=G:/HexLab/out/install/X86ModeDebug -DGENERATOR=G:/HexLab/out/build/windows-desktop/bin/Debug/hexlab_fixture_generator.exe -DDESKTOP=ON -P tests/install_tests.cmake
cmake -DAPP=G:/HexLab/out/install/X86ModeDebug/bin/hexlab.exe -DMODE=--smoke-test-floating -P tests/desktop_smoke.cmake
```

Replace the absolute workspace path when using another checkout. The install test checks engine and wx runtime DLLs, development files, notices, CLI output and a real desktop launch.

For a GUI-free offline configuration from a fresh build directory:

```powershell
cmake -S . -B out/build/headless-offline -G "Visual Studio 17 2022" -A x64 -DHEXLAB_BUILD_DESKTOP=OFF -DBUILD_TESTING=ON -DFETCHCONTENT_FULLY_DISCONNECTED=ON
cmake --build out/build/headless-offline --config Debug
ctest --test-dir out/build/headless-offline -C Debug --output-on-failure
```

For an offline desktop build, obtain a complete wxWidgets checkout at the commit listed in [third-party dependencies](third-party.md), including its submodules. Pass `-DFETCHCONTENT_SOURCE_DIR_WXWIDGETS=C:/path/to/wxWidgets` at configure time. Do not use a GitHub auto-generated source archive without required submodule content. After provisioning, application startup uses no network service.

Linux and macOS headless presets and CI jobs exercise three compiler/configuration pairs: Clang Debug on Ubuntu 24.04 (`linux-headless`), GCC Release on Ubuntu 24.04 (`linux-gcc-headless-release`), and Apple Clang Debug on macOS 14 (`macos-headless`). Each configures without wxWidgets, builds the CLI and test targets, and runs every CTest registered by that preset; tests that require the pinned LLVM oracle executables remain disabled on these hosts. The CLI uses native entry points and strict UTF-8 argument decoding; paths are converted to each host's filesystem representation. Separate `linux-desktop` and `macos-desktop` presets build the complete Release distribution, including wxWidgets and CPack TGZ packaging, on their native CI runners. Linux CI installs the GTK/X11/Wayland development dependencies required by wxWidgets. These targets have not been run in this Windows development environment, so successful CI runs are the platform verification gate. Desktop runtime launch and interactive behavior remain unverified on Linux and macOS.

For a native GCC Debug build without the test-only LLVM tools or GUI dependencies:

```sh
cmake -S . -B out/build/linux-gcc-debug \
  -DCMAKE_BUILD_TYPE=Debug \
  -DCMAKE_C_COMPILER=gcc -DCMAKE_CXX_COMPILER=g++ \
  -DHEXLAB_BUILD_DESKTOP=OFF -DBUILD_TESTING=OFF \
  -DHEXLAB_ENABLE_PINNED_LLVM_ORACLES=OFF
cmake --build out/build/linux-gcc-debug --target hexlab_cli --parallel 3
```

The Linux engine libraries are shared objects; vendored static Zydis, Zycore,
and Capstone are compiled as position-independent code so they can be linked
into those libraries. The desktop target additionally needs wxWidgets and its
GTK/X11/Wayland development dependencies, which headless builds do not require.

## Current functionality

The application loads explicit raw mappings, PE32/PE32+ and ELF32/ELF64, parses bounded metadata, traces original x86 scalar subsets and finds ASCII/UTF-16 candidates. Use `hexlab_cli processors` to inspect the enabled decoder contexts and their bounded subset labels. Use `hexlab_cli inspect <path>`, `hexlab_cli disassemble <path>`, or `hexlab_cli decompile <path>`; `--help` documents format selection, raw options and budgets. `decompile` recovers functions through the shared analysis engine, lifts them to typed IR, applies conservative SSA simplification and prints structured pseudocode where supported, retaining explicit CFG output for unsupported shapes. Desktop File > Open detects PE and ELF; File > Open Raw requests a flat mapping or segmented profile. Both frontends preserve unsupported and incomplete states. CLI exit codes are 0 for a successful command, 1 for loading/unsupported analysis errors, 2 for argument errors and 3 for incomplete analysis. Metadata-only inspect can succeed with explicit metadata warnings.

See [binary analysis validation](binary-analysis-validation.md). Project databases, persistent edits, search and graph/reference views are described in [project analysis validation](project-analysis-validation.md). Pseudocode, debugging and broader processor/format support remain later work. [The capability inventory](capabilities.csv) tracks the full destination.

The project backend has schema/input/history tests plus process-kill tests for transaction recovery, first-save/Save As publication and editable-process ownership. Test callbacks compile only with `BUILD_TESTING=ON`. Project commands are exposed through the [project CLI](project-cli.md); The wx desktop uses the same commands through per-document actors. Save As currently requires a local destination with no live reader/writer or nonempty unrecovered WAL; closed read-only connections' empty WAL/index scratch is handled during publication. Failure to restore after a native filesystem error retains an explicitly named recovery copy beside the destination. Tests cover synchronized process death at the recorded checkpoints, not physical power loss or every internal filesystem failure.

Shared project-command tests cover annotations, decisions, grouped patches, failed transactions, stale facts and file-only recovery after header edits. Graph tests independently parse JSON and render a fixture from deterministic SCC layout coordinates. Patch-export tests compare complete files against literal edits and verify receipt hashes with Windows `Get-FileHash`; exports protect input/project/backing identities and reject destinations with journal companions. The project CLI uses these services; the wx desktop uses these same services.

Incremental tests verify actual skipped decoding and shared unchanged function/block records; ownership and reference indexes are rebuilt conservatively, and changed bytes rescan the full string domain when narrower boundaries are not proven. Optional complete-derived caches are bounded to 64 MiB. Loading validates effective bytes and typed instruction records, rewalks rooted ownership, rebuilds references and scans strings before adopting cached models. Encoding also validates instruction records. Recovery and cache-load validation have separate counters; these checks do not claim a cache hit avoids all analysis work. Invalid caches recompute without changing user history or repairing read-only projects.

Actor tests synchronize late completions, close/reopen, Save As, cancellation and input-lease retirement with explicit barriers. Each writer owns its SQL connection; the shared pool has exactly two workers. Search tests compare masked streaming pages against an independent literal matcher and cover effective patches, Unicode, unique contiguous mappings, split instruction file ranges, immediate widths and stale cursors. Search patterns are limited to 4096 encoded bytes, pages to 4096 hits, and retained per-document history to 100000 hits. Each page has separate candidate/comparison budgets; reaching a budget returns a continuation. Immediate results explicitly report partial decoded-source coverage. Both the project CLI and native Find dialogs expose search with per-document result history.



The schema/storage guide is [project format](project-format.md). To run installed project and native desktop component workflows after the ordinary install check:

```powershell
cmake -DPREFIX=G:/HexLab/out/install/X86ModeDebug -DTEST_BIN=G:/HexLab/out/build/windows-desktop/bin/Debug -DDESKTOP=ON -P tests/project_install_tests.cmake
```

This copies validation executables without DLLs into the package validation directory and resolves the installed runtimes through the child PATH. The ordinary install check also launches the actual packaged application. See the validation document for the distinction between application smoke checks and native workflow harnesses.

The Windows x64 test build also configures `tests/fixtures/x86_32_oracle` with the MSVC Win32 toolchain. Install both x86 and x64 C++ build tools. This separate executable executes authored probes and is checked by the x64 original decoder; an unavailable oracle is a test failure. Production `BUILD_TESTING=OFF` builds do not configure it. See [x86-32 validation](x86-32-validation.md).

The segmented-analysis development tests also require pinned test-only QEMU,
Bochs, NASM and firmware. Provision them once with
`powershell -NoProfile -File tests/provision_x86_16_tools.ps1 -Download`;
`-Offline` verifies or reconstructs them from cached archives. They stay under
`out/tools`, with no installer execution or global installation. CMake tests
never download a tool or silently skip a missing oracle. See the
[authored16 fixture](../tests/fixtures/x86_16_oracle/README.md) for exact pins,
execution scope and the separate boundary oracle. Production builds require none
of these tools. Scoped segmented loading/navigation is available through
[raw profiles](x86-profiles.md); see [segmented validation](segmented-analysis-validation.md)
for delivery evidence and explicit limits.

The current segmented developer bundle uses `out/install/SegmentedDebug`.
After installation, run the ordinary install check above with that prefix,
then `tests/project_install_tests.cmake` and `tests/segmented_install_tests.cmake`
with `-DPREFIX=G:/HexLab/out/install/SegmentedDebug` and
`-DTEST_BIN=G:/HexLab/out/build/windows-desktop/bin/Debug` (`-DDESKTOP=ON`
for the project/native check). Those validation tools exercise installed engines.

To build the separate SDK consumer:

```powershell
cmake -S tests/sdk/segmented -B out/build/segmented-sdk -G 'Visual Studio 17 2022' -A x64 -DHEXLAB_PREFIX=G:/HexLab/out/install/SegmentedDebug
cmake --build out/build/segmented-sdk --config Debug
$env:PATH = 'G:/HexLab/out/install/SegmentedDebug/bin;' + $env:PATH
./out/build/segmented-sdk/Debug/segmented_consumer.exe G:/HexLab/out/install/SegmentedDebug G:/HexLab/out/install/SegmentedDebug/test-fixtures/raw.bin
```

The authorized output cleanup removed older installation prefixes and auxiliary
build trees used in historical examples above. The active desktop/headless builds
are `out/build/windows-headless` and `out/build/windows-desktop`; current delivery
checks also use `out/build/macho-{sdk,production,offline}`. The accepted ElfDebug
bundle remains preserved. MachODebug has passed installed SDK validation and is
accepted for the scoped Mach-O stage after final review correction and revalidation.
Recreate a removed destination with the install step before running its example.

Both CLI parsers now support Mach-O with an optional zero-based universal slice:

```powershell
./out/build/windows-headless/bin/Debug/hexlab_cli.exe inspect sample.macho --format macho --slice 1
./out/build/windows-headless/bin/Debug/hexlab_cli.exe project create sample.hxproj --input sample.macho --format macho --slice 1
```

Automatic detection also accepts `--slice`. Project inspection/editing retains
the saved selection and rejects a selection override. The native Mach-O page
provides indexed source records and readable selected-record details. Select a
Slice row and use **Open original slice in new tab** to import that slice from
the original source independently of the current project's recipe and edits.
Saved projects can reopen from embedded bytes after the external source is
removed; opening a different original slice requires the original source file.

The accepted Mach-O developer bundle at `out/install/MachODebug` is an immutable
Windows x64 Debug baseline with eight import libraries. The current worktree adds
type-model, debugger, plugin, decompiler, and symbol-ingestion DLLs, so a fresh
SDK/install verification is still required before that baseline can be used for
these new APIs. Its existing SDK example is copied
to `validation/sdk-source/macho`; build it in Debug against the accepted prefix's
public headers and eight import libraries:

```powershell
cmake -S tests/sdk/macho -B out/build/macho-sdk -G 'Visual Studio 17 2022' -A x64 -DHEXLAB_PREFIX=G:/HexLab/out/install/MachODebug
cmake --build out/build/macho-sdk --config Debug
$env:PATH = 'G:/HexLab/out/install/MachODebug/bin;' + $env:PATH
./out/build/macho-sdk/Debug/macho_consumer.exe G:/HexLab/out/install/MachODebug/validation/macho/sdk-inputs G:/HexLab/out/install/MachODebug/validation/sdk-artifacts G:/HexLab/out/install/MachODebug
```

Generate/verify the installed Mach-O validation fixtures and workflows with:

```powershell
cmake -DPREFIX=G:/HexLab/out/install/MachODebug -DTEST_BIN=G:/HexLab/out/build/windows-desktop/bin/Debug -DDESKTOP=ON -P tests/macho_install_tests.cmake
```

The SDK build has no source-engine include or library fallback. Its consumer
checks durable slices, source-bound references, public resolver APIs, editing,
whole-container export, Save As, embedded read-only reopen and actual DLL paths.
See [Mach-O validation](macho-analysis-validation.md) for tool identities,
runtime/production boundaries, observed limits and final bundle-review status.

A64 scalar inputs are supported in the current developer build through compatible
PE/ELF/Mach-O loading and explicit raw mode. For example:

```powershell
./out/build/windows-headless/bin/Debug/hexlab_cli.exe disassemble sample.bin --format raw --arch a64 --base 0x1000
./out/build/windows-headless/bin/Debug/hexlab_cli.exe project create sample.a64.hxproj --input sample.bin --format raw --arch a64 --base 0x1000
```

The desktop raw dialog has an AArch64 choice using the same mapping validation.
The scalar A64 decoder covers control flow, move-wide and immediate arithmetic, ADR/ADRP, unsigned-offset integer loads/stores, and shifted-register ADD/SUB plus AND/ORR/EOR/ANDS. Shifted-register operands retain width, shift amount and flags/register effects; reserved shifts and inverted logical variants outside this subset are rejected.

Unsupported instructions and unresolved branches/imports remain partial results;
see arm-validation.md for the tested scope. The preserved installed MachODebug
bundle predates this A64 work; a new ARM delivery is still a later stage.

The public processor SDK also exposes `decode_a32` for the original A32 scalar
subset: control transfers, the sixteen basic data-processing operations,
single loads/stores and register-list transfers. Typed operands preserve barrel
shifts, pre/post indexing, writeback and partial flag effects. A32 image analysis
and raw CLI choices await the mixed-state analysis stage. Derived cache schema11
and reference payload9 retain these operand shapes; engine27 recomputes earlier
cached analysis while preserving project annotations/history. Standalone
reference payload7/8 remains readable under its original source identity.

`decode_thumb` adds the original Thumb scalar subset and accepts an explicit
`ThumbITState`. Its default is unknown; `{true, 0}` means the caller established
a boundary outside IT. The decoder retains incoming/outgoing IT state and
avoids inventing predicates or implicit flag writes at an unknown boundary.
The shared mode dispatcher uses unknown state. Pure decoding supports narrow
scalar/control/memory/list forms and wide B/BL/BLX branches under the Armv7
contract. Automatic Thumb analysis still awaits source-bound mode/IT validation.
Current engine27 uses derived schema11 and reference payload9/cache10 for the
distinct Thumb relative operand; standalone payload7/8 remains readable with
its original identities. Accepted installations predate this developer work.

The image SDK now accepts an optional `ArmImageProfile` of source-attributed A32,
Thumb, data, unknown and conflict ranges plus declared roots. `context_at` uses
the range at the requested physical address; `arm_code_at` exposes its origins.
`code_window` stops at every declaration boundary and excludes non-code states.
An explicit profile makes gaps unknown. The image validates bounded declaration
shapes and file extents; loaders must verify the meaning of source records.
This API does not yet enable automatic mixed-state flow or durable mode edits.

Raw ARM/Thumb declarations use `--format raw --arm-profile mapping.profile` in
both standalone inspection and project creation. The bounded `ArmRawProfile`
parser/formatter/file reader are public loader APIs. The opening worker embeds
canonical profile text in recipe version3/kind6; reopening retains the mapping
after the external profile or original input disappears. See arm-validation.md
for grammar and evidence. ARM projects currently expose valid mappings/manual
decoding with incomplete automatic analysis; mode edits and IT-aware recovery
remain subsequent work. The desktop profile picker remains part of Task6.
