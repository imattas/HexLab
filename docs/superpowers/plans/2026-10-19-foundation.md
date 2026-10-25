# HexLab Foundation Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [x]`) syntax for tracking.

**Goal:** Deliver the buildable C++ foundation, checked binary-access primitives, headless executable and a real wxWidgets desktop shell required by stage 1 of the full HexLab application.

**Architecture:** The GUI and CLI link the same wx-free C++20 core. Checked address and byte APIs establish the contracts that later loaders and decoders consume. The first desktop shell has working docking, layout reset, output and orderly shutdown; it does not claim to analyze binaries.

**Tech Stack:** C++20, CMake 3.24 or later, Visual Studio 2022 x64 on the current host, wxWidgets 3.2.12, CTest, standard-library-only core tests.

**Spec:** [Approved application architecture](../specs/2026-10-19-hexlab-design.md), stage 1 of Implementation sequence and the applicable Component boundaries, Address and image model, Desktop interaction, and Validation sections.

## Global Constraints

- â€œUse C++20 and CMake.â€
- â€œKeep wxWidgets types out of the analysis engine.â€
- â€œNative analysis is local and usable offline.â€
- â€œEvery dependency needs a pinned version and recorded license before introduction.â€
- â€œHalf-open ranges define ownership; file offsets and virtual addresses are different types.â€
- â€œValidate all additions, multiplications, indexing and conversions before accessing bytes.â€
- â€œFile loading never executes the input.â€
- Windows is the first verified host; Linux and macOS remain required delivery targets in the application scope.
- This plan implements stage 1 only. The full goal remains open through all subsequent stages.

## Review Focus

- Address arithmetic at the maximum 64-bit offset must report overflow rather than wrap; task 1 covers this boundary.
- A truncated, empty or oversized byte request must fail without reading memory outside its span or advancing its cursor; task 2 covers this boundary.
- A user building only the CLI must not need a GUI dependency download; task 3 covers a fresh headless build.
- An unknown command-line argument must produce an error and a nonzero exit status; task 3 covers this behavior.
- Closing a docked or floating pane must not corrupt frame destruction; task 4 covers pane teardown and reset in its smoke procedure.

## File Map

| File | Responsibility |
| --- | --- |
| `.gitignore` | Exclude build outputs and dependency caches |
| `CMakeLists.txt` | Project, core and executable targets, testing and install rules |
| `CMakePresets.json` | Windows desktop and GUI-free Debug configure/build/test presets |
| `cmake/WxWidgets.cmake` | Reproducible dependency acquisition, external-source override and GUI linkage |
| `include/hexlab/core/result.hpp` | Explicit result and diagnostic types |
| `include/hexlab/core/address.hpp`, `src/core/address.cpp` | Typed addresses, ranges and checked arithmetic |
| `include/hexlab/core/byte_reader.hpp`, `src/core/byte_reader.cpp` | Bounded endian-aware reads |
| `include/hexlab/core/version.hpp.in` | Generated application version constant |
| `src/cli/main.cpp` | Help/version command handling and exit status |
| `src/desktop/app.cpp` | wx application lifetime and launch smoke mode |
| `src/desktop/main_frame.hpp`, `src/desktop/main_frame.cpp` | Native frame, dockable panes, menus and cleanup |
| `tests/core_tests.cpp` | Known-answer and failure-path tests for core primitives |
| `tests/cli_tests.cmake` | End-to-end CLI argument checks |
| `docs/building.md` | Exact build and smoke commands, dependency override and offline workflow |
| `docs/third-party.md` | wxWidgets pin, upstream URL, license and bundled dependency notices |
| `docs/capabilities.csv` | Honest feature states and evidence paths across the full application goal |

## Task 1 Checked addresses and project build

**Files:** Create `.gitignore`, `CMakeLists.txt`, `CMakePresets.json`, `include/hexlab/core/result.hpp`, `include/hexlab/core/address.hpp`, `src/core/address.cpp`, `tests/core_tests.cpp`.

**Consumes:** C++20 standard library only.

**Produces:**

- `enum class ErrorCode { overflow, out_of_bounds, invalid_argument };`
- `struct Error { ErrorCode code; std::string message; };`
- `template<class T> class Result` with constructors accepting `T` or `Error`, `bool has_value() const noexcept`, explicit `operator bool() const noexcept`, `const T& value() const`, `T& value()`, `const Error& error() const`. Invalid accessor use throws `std::logic_error`; no default success value.
- `struct AddressSpaceId { std::uint32_t value; };`, `struct Address { AddressSpaceId space; std::uint64_t offset; };` and `struct FileOffset { std::uint64_t value; };`, each equality comparable.
- `Result<std::uint64_t> checked_add(std::uint64_t, std::uint64_t);` and `checked_multiply` with the same parameter and return types.
- `Result<Address> advance(Address, std::uint64_t);` preserves address space.
- `class AddressRange` with `static Result<AddressRange> create(Address begin, std::uint64_t size)`, `bool contains(Address) const noexcept`, `Address begin() const noexcept`, `std::uint64_t size() const noexcept`. A range whose exclusive endpoint overflows is rejected, including a one-unit range starting at UINT64_MAX. Empty ranges are valid and contain no addresses.
- CMake targets `hexlab_core` and `hexlab_core_tests`; CTest name `core`.

- [x] Create build files with `HEXLAB_BUILD_DESKTOP` defaulting to `ON`, `BUILD_TESTING` integration, out-of-source build enforcement, C++20 target requirements and project version `0.1.0`. Until task 4, use the GUI-free preset to avoid referencing absent desktop code. Set MSVC `/W4 /permissive- /utf-8` and GCC/Clang `-Wall -Wextra -Wpedantic` on project targets only.
- [x] Add a small test runner with named checks that return a failing exit status, independent of `assert` and therefore active in Release. Write tests before the core implementation: `checked_add(2,3)==5`; max+1 reports `overflow`; multiply max*2 reports `overflow`; max*0==0; advancing address `{7,0x1000}` by 4 yields `{7,0x1004}`; range `[0x1000,0x1004)` includes first/last bytes and excludes endpoint and other address spaces; empty ranges contain nothing; overflowing ranges fail.
- [x] Add tests asserting `Result<int>(Error{...}).value()` and `Result<int>(7).error()` throw `std::logic_error`, and `static_assert(!std::is_convertible_v<FileOffset, Address>)`.
- [x] Run `cmake --preset windows-headless`, then `cmake --build --preset windows-headless`. Confirm failure due to missing primitive implementations before supplying them; do not treat a generator or SDK failure as the expected test failure.
- [x] Implement the declared types and functions; check arithmetic before performing it. Use subtraction-based bounds checks rather than unchecked endpoint addition in `contains`.
- [x] Run `cmake --build --preset windows-headless`, then `ctest --preset windows-headless -R core --output-on-failure`. Require a successful build and `100% tests passed`.
- [ ] Initialize Git if the workspace is still not a repository, add the approved spec and plan along with task 1 files, and commit `feat: establish checked address core and CMake build`. Never invent Git author identity; if identity is unavailable, preserve the changes and report that commit limitation.

## Task 2 Bounded binary reading

**Files:** Create `include/hexlab/core/byte_reader.hpp`, `src/core/byte_reader.cpp`; modify `CMakeLists.txt`, `tests/core_tests.cpp`.

**Consumes:** `Result<T>`, `Error`, `ErrorCode` from task 1.

**Produces:**

- `enum class ByteOrder { little, big };`
- `class ByteReader` borrowing `std::span<const std::byte>` through `explicit ByteReader(std::span<const std::byte>) noexcept`.
- `std::size_t position() const noexcept`, `std::size_t remaining() const noexcept`.
- `Result<std::span<const std::byte>> read_bytes(std::size_t count)`.
- `Result<std::uint8_t> read_u8()`, `Result<std::uint16_t> read_u16(ByteOrder)`, `Result<std::uint32_t> read_u32(ByteOrder)`, `Result<std::uint64_t> read_u64(ByteOrder)`.
- `Result<std::size_t> seek(std::size_t position)` returning the new position; permits the end cursor, rejects positions beyond input size. All failed operations leave the cursor unchanged. Successful `read_bytes(0)` is permitted, including on empty input.

- [x] Write tests using bytes `01 23 45 67 89 AB CD EF`: little-endian u32 is `0x67452301`, big-endian u32 is `0x01234567`, little-endian u64 is `0xEFCDAB8967452301`, big-endian u64 is `0x0123456789ABCDEF`; verify u8/u16 and exact cursor movement.
- [x] Add boundary tests for empty input, zero-length read, reading one byte beyond the end, `read_bytes(SIZE_MAX)` after a nonzero cursor, `seek(SIZE_MAX)`, and a truncated u64. Assert failure codes and unchanged position after every rejected read or seek.
- [x] Build the headless preset and confirm the new tests cannot compile or link until the byte-reader implementation exists.
- [x] Implement bounded reads using `count <= remaining()` before slicing. Assemble unsigned values bytewise without alignment assumptions or host-endian casts. Document the borrowed-span lifetime.
- [x] Run the headless build and core CTest command from task 1. Require all named assertions to pass.
- [ ] Commit `feat: add bounded endian-aware binary reader` with task 2 files only.

## Task 3 Shared CLI and reproducible dependency path

**Files:** Create `include/hexlab/core/version.hpp.in`, `src/cli/main.cpp`, `tests/cli_tests.cmake`, `cmake/WxWidgets.cmake`, `docs/building.md`, `docs/third-party.md`; modify `CMakeLists.txt`, `CMakePresets.json`.

**Consumes:** `hexlab_core`, project version from task 1.

**Produces:** `hexlab_cli` executable, generated `hexlab::version` string constant, CTest name `cli`, and dependency target wrapper `hexlab_wx` for task 4. CLI accepts no arguments or `--help` with exit status 0 and usage text; `--version` prints `HexLab 0.1.0` with status 0; all other combinations print a diagnostic to stderr and return 2.

- [x] Write a CMake-script integration test invoking the actual executable for no arguments, `--help`, `--version`, `--unknown`, and `--version extra`. Assert status and output independently for each case. Register it using `$<TARGET_FILE:hexlab_cli>` so Debug/Release paths remain correct.
- [x] Run headless configure/build and `ctest --preset windows-headless -R cli --output-on-failure`; establish an expected failure because CLI behavior is absent.
- [x] Implement CLI parsing and generated version header. Link `hexlab_cli` to `hexlab_core` without wxWidgets or any GUI entry point. Do not add fake analysis commands.
- [x] Implement `cmake/WxWidgets.cmake`, included only when `HEXLAB_BUILD_DESKTOP=ON`. Pin upstream `https://github.com/wxWidgets/wxWidgets.git` to commit `3b7c7fc839093ad28146bd17555af2565c792c96` (release v3.2.12, verified with `git ls-remote`). Fetch required submodules at their pinned commits; do not shallow-clone an arbitrary hash. Respect `FETCHCONTENT_SOURCE_DIR_WXWIDGETS` for a complete local source checkout. Use upstream CMake targets and static wx libraries, samples/tests/demos/install disabled, and AUI enabled. Do not expose upstream warning policies to project core targets.
- [x] Add `windows-desktop` and `windows-headless` configure/build/test presets using `Visual Studio 17 2022`, architecture `x64`, Debug configuration and separate output paths under `out/build/`. Add a headless Release build/test preset for runtime checks that do not depend on Debug assertions.
- [x] Configure a fresh headless tree with `cmake -S . -B out/build/headless-offline -G "Visual Studio 17 2022" -A x64 -DHEXLAB_BUILD_DESKTOP=OFF -DBUILD_TESTING=ON -DFETCHCONTENT_FULLY_DISCONNECTED=ON`; build and run CTest there. Require success and no wx dependency tree or network fetch. This test is independent of the configured desktop tree.
- [x] Document the dependency pin, wxWindows Library Licence source path and upstream URL in `docs/third-party.md`. Document bundled libraries enabled by the actual wx configuration and include their notices when distributing. The library pin is not evidence that application license terms have been selected.
- [x] Run Debug and Release core and CLI CTests. Document working build commands and the complete-source offline override; distinguish offline runtime from the first dependency acquisition.
- [ ] Commit `feat: add headless CLI and pinned wxWidgets build integration`.

## Task 4 Dockable wxWidgets desktop

**Files:** Create `src/desktop/app.cpp`, `src/desktop/main_frame.hpp`, `src/desktop/main_frame.cpp`; modify `CMakeLists.txt`, `docs/building.md`.

**Consumes:** `hexlab_core`, generated `hexlab::version`, `hexlab_wx` wrapper target from task 3.

**Produces:** `hexlab` GUI executable and a launch test mode `hexlab --smoke-test`. `class MainFrame final : public wxFrame` owns `wxAuiManager`, creates its pane content and calls `UnInit()` before destruction. A public `void ResetLayout()` restores a known arrangement. The application uses the normal wx event loop.

- [x] Add a failing CTest named `desktop_smoke` that launches `hexlab --smoke-test` with a 30-second timeout. The executable must build, initialize wxWidgets, show its frame, dispatch events, reset layout and close cleanly with exit status 0. Register this test only in desktop builds with `HEXLAB_ENABLE_GUI_TESTS=ON`; document that it requires an interactive desktop. Establish failure before implementing the application.
- [x] Implement the native frame with title `HexLab`, initial client size 1280x800 in device-independent units, status text `Ready`, and a welcome center panel explaining that no binary is open. Add empty Functions and Symbols panes on the left and read-only Output at the bottom. Empty lists have meaningful headings; do not fabricate rows or claim available decompilation/debugging.
- [x] Add working File > Exit, View > Reset Layout, and Help > About commands. About shows application version and wxWidgets version. Preserve native keyboard traversal and use a system fixed-width font for the output panel. File opening arrives with the loader stage; do not put an inert Open command in this shell.
- [x] Implement smoke mode with an event-loop callback that exercises hide/show and reset for panes, verifies expected pane visibility, and closes through normal frame shutdown. Keep this mode self-contained and avoid background processes. A missing or invalid pane must produce a nonzero result rather than a false smoke pass.
- [x] Configure/build `windows-desktop`, run core/CLI tests and explicitly enable/run `desktop_smoke` on this interactive host. Record whether GUI launch is supported; a headless environment cannot count as a passed GUI test.
- [x] Launch the desktop for visual inspection, capture an actual screenshot, and inspect it. Verify readable labels, pane docking/floating/closing, reset layout, resize, keyboard access, About and normal Exit. Close any test-launched window after inspection. If a visible inspection window is needed, explain its purpose; background helpers remain hidden.
- [ ] Commit `feat: add dockable wxWidgets desktop shell`.

## Task 5 Install verification and full-scope tracking

**Files:** Modify `CMakeLists.txt`, `docs/building.md`, `docs/third-party.md`; create `docs/capabilities.csv`.

**Consumes:** Buildable/tested GUI and CLI from tasks 1â€“4.

**Produces:** Installable executables with necessary notices; capability inventory columns `id,area,capability,variant,state,evidence,next_stage`, with states `absent`, `partial`, `implemented`, `verified` only.

- [x] Add install rules for both enabled executables and the relevant notices. Install into a workspace-local directory with `cmake --install out/build/windows-desktop --config Debug --prefix out/install/Debug`; verify installed `hexlab_cli --version` and launch the installed desktop smoke mode. Missing runtime libraries are a failed install check, even when the build-tree executable works.
- [x] Populate the capability inventory from every row of the approved full-scope table. Split the foundation capabilities into precise entries and cite their actual commands/results. Mark loader/processor/database/type/IR/decompiler/debugger/automation/collaboration functionality absent until implemented; do not mark a whole category verified because a shell or helper exists. Processor variant enumeration and reference parity auditing remain required later work.
- [x] Add the actual verified toolchain, exact dependency provisioning and Debug/Release test commands to `docs/building.md`. Record unsupported or untested host platforms accurately.
- [x] Run the final Debug desktop CTests, Release headless CTests and installed executable checks once after any task 5 changes. Check tracked changes for unexpected outputs or fetched dependency sources.
- [ ] Commit `build: verify foundation installation and track full capability scope`.

## Plan Review

Stage 1 requirements map to tasks as follows: CMake and address primitives to task 1; bounded access to task 2; headless entry point and reproducible dependency provisioning to task 3; the real desktop window to task 4; test evidence, installation and durable scope tracking to task 5. Tasks 2â€“5 preserve the approved future architecture without implementing those later subsystems.

The user approved this plan on 2026-10-19. Proceed with recommended Native execution: the primary agent implements the tasks in this session, followed by a fresh review.

## User amendment during implementation

The user explicitly requires a monorepo with shared libraries, multiple tools and supporting distribution files. This supersedes the static linkage and single-root source layout above. Move `src/desktop/` to `apps/desktop/`, `src/cli/` to `apps/cli/`, `src/core/` to `libs/core/src/`, and `include/hexlab/core/` to `libs/core/include/hexlab/core/`. Add per-component CMake files. Build `hexlab_core` and wxWidgets as shared libraries. Generate explicit public export declarations for the core DLL. The CLI version command calls an exported core function so it actually uses the shared engine.

Build executables and runtime DLLs under `out/build/<preset>/bin/<config>/`. Install tools and required DLLs to `bin/`, link libraries to `lib/`, headers to `include/`, and notices/docs to `share/hexlab/`. Copy wx DLLs beside the GUI for development launches and verify installed launches as well. Future libraries and plugin directories are added with working code rather than empty scaffolding. Test contracts and full-scope completion requirements are preserved.
