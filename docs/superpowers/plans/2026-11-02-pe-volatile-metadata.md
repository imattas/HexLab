# PE Volatile Metadata Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Decode bounded legacy PE volatile-access and covered-code tables.

**Architecture:** Append an inspection object to `PeLoadConfiguration` and call
a focused optional-metadata parser from the existing load-config path. Retain
all existing pointer fields and preserve unrelated metadata on payload failure.

**Tech Stack:** C++20, CMake, Windows MSVC, WSL Ubuntu Clang/Make.

**Spec:** `docs/superpowers/specs/2026-11-02-pe-volatile-metadata-design.md`

## Global Constraints

- Support exactly raw Version == 1; header is 24 bytes, capped at 1 MiB.
- 16 MiB aggregate table bytes; 1,000,000 aggregate rows.
- 1,000,000 aggregate target mapping steps.
- Header and tables must be mapped initialized bytes; targets must be executable initialized bytes.
- Preserve order, duplicates and overlaps; publish both row vectors atomically.
- No tests added or run; both builds use `BUILD_TESTING=OFF`.
- No push, CI, target execution, CLI or UI changes.

## Review Focus

- Short or absent pointer fields: no speculative reads or metadata objects.
- Invalid pointer/payload: unrelated load-config fields remain available.
- Unknown versions and extended headers: preserve raw fields without decoding unknown rows.
- Integer overflow, unmapped gaps and zero-filled tails: reject safely before publication.
- Malformed second table or cancellation: no partial decoded vectors; cancellation propagates.

### Task 1: Metadata model, bounded parser and integration

**Files:** Modify `libs/image/include/hexlab/image/pe_metadata.hpp`,
`libs/loaders/src/pe_internal.hpp`, `libs/loaders/src/pe_load_config.cpp`,
`libs/loaders/CMakeLists.txt`; create `libs/loaders/src/pe_volatile.cpp`.

**Interfaces:** Produce `PeVolatileMetadata read_volatile_metadata(const Image&,
const ImageMetadata&, std::uint64_t, std::stop_token)` plus the additive public
metadata types named in the spec. Consume existing `ImageReader` and `Failure`.

- [x] Add status enum, indexed access/range rows, raw fields, optional source spans and a trailing optional object.
- [x] Implement header/version/byte/record budgets, exact table framing and executable initialized target validation.
- [x] Integrate the pointer-normalization diagnostic boundary, preserving zero/absent-pointer behavior.
- [x] Register the parser and review all five Review Focus cases by source inspection (tests prohibited).

### Task 2: Documentation and cross-platform build verification

**Files:** Create `libs/loaders/docs/pe-volatile-metadata.md`; update
`docs/pe-load-configuration.md` and this plan's completion record.

**Interfaces:** Document `PeLoadConfiguration::volatile_metadata`, status values,
raw version handling, exact limits, provenance and atomic-publication contract.

- [x] Record format references and explicit runtime/version proof boundaries.
- [x] Configure Windows using `cmake --preset windows-headless -DBUILD_TESTING=OFF`; build `hexlab_loaders` with `--config Release --parallel 2`.
- [x] Configure WSL Ubuntu using `cmake --preset linux-headless -G "Unix Makefiles" -B /tmp/hexlab-pe-volatile-nov02 -DBUILD_TESTING=OFF`; build `hexlab_loaders` with `--parallel 2`.
- [x] Confirm both exits are zero, inspect `git diff --check` and the full patch, update actual build outcomes, then commit locally.

## Execution record

Pre-code audit and spec completed. Managed worktree setup stalled; authorized
git fallback created `G:/HexLab/.worktrees/pe-volatile-metadata-nov02` on
`codex/pe-volatile-metadata-nov02` from `b60394af`. No tests run.

Ruling: the actual PE model is in `pe_metadata.hpp`, included by `metadata.hpp`;
the parent authorized the minimal additive model change there.

Ruling: Ubuntu lacks Ninja; the first Linux configure failed before compilation.
Use the available Unix Makefiles generator in a separate build directory:
`cmake --preset linux-headless -G "Unix Makefiles" -B out/build/linux-make-headless -DBUILD_TESTING=OFF`,
then `cmake --build out/build/linux-make-headless --target hexlab_loaders --parallel 2`.

Ruling: generation in the Windows-mounted output directory remained very slow
after more than eight minutes; stopped only the verified PE configure process
and moved the same configuration to WSL-native `/tmp/hexlab-pe-volatile-nov02`.
The original Make configure was interrupted before compilation. Final build:
`cmake --build /tmp/hexlab-pe-volatile-nov02 --target hexlab_loaders --parallel 2`.

Windows configure and Release `hexlab_loaders` build both exited 0 with MSVC
19.44.35229.0. The DLL linked successfully; `BUILD_TESTING:BOOL=OFF` and
`HEXLAB_BUILD_DESKTOP:BOOL=OFF` were confirmed in the generated cache.

WSL Ubuntu Clang 18.1.3 configure and Debug `hexlab_loaders` build both exited
0; `libhexlab_loaders.so` linked successfully. The cache confirmed Debug,
`BUILD_TESTING:BOOL=OFF`, and `HEXLAB_BUILD_DESKTOP:BOOL=OFF`. No tests added or
run. Final source review covered all five Review Focus cases; no implementation
changes were required after either build. The parent owns integration review.
