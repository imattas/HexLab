# PE Volatile Metadata Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Decode bounded legacy PE volatile-access and covered-code tables.

**Architecture:** Append an inspection object to `PeLoadConfiguration` and call
a focused optional-metadata parser from the existing load-config path. Retain
all existing pointer fields and preserve unrelated metadata on payload failure.

**Tech Stack:** C++20, CMake, Windows MSVC, WSL Ubuntu Clang/Ninja.

**Spec:** `docs/superpowers/specs/2026-11-02-pe-volatile-metadata-design.md`

## Global Constraints

- Support exactly raw Version == 1; header is 24 bytes, capped at 1 MiB.
- 16 MiB aggregate table bytes; 1,000,000 aggregate rows.
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

- [ ] Add status enum, indexed access/range rows, raw fields, optional source spans and a trailing optional object.
- [ ] Implement header/version/byte/record budgets, exact table framing and executable initialized target validation.
- [ ] Integrate the pointer-normalization diagnostic boundary, preserving zero/absent-pointer behavior.
- [ ] Register the parser and review all five Review Focus cases by source inspection (tests prohibited).

### Task 2: Documentation and cross-platform build verification

**Files:** Create `libs/loaders/docs/pe-volatile-metadata.md`; update
`docs/pe-load-configuration.md` and this plan's completion record.

**Interfaces:** Document `PeLoadConfiguration::volatile_metadata`, status values,
raw version handling, exact limits, provenance and atomic-publication contract.

- [ ] Record format references and explicit runtime/version proof boundaries.
- [ ] Configure Windows using `cmake --preset windows-headless -DBUILD_TESTING=OFF`; build `hexlab_loaders` with `--config Release --parallel 2`.
- [ ] Configure WSL Ubuntu using `cmake --preset linux-headless -DBUILD_TESTING=OFF`; build `hexlab_loaders` with `--parallel 2`.
- [ ] Confirm both exits are zero, inspect `git diff --check` and the full patch, update actual build outcomes, then commit locally.

## Execution record

Pre-code audit and spec completed. Managed worktree setup stalled; authorized
git fallback created `G:/HexLab/.worktrees/pe-volatile-metadata-nov02` on
`codex/pe-volatile-metadata-nov02` from `b60394af`. No tests run.
