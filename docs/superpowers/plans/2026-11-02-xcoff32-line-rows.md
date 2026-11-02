# XCOFF32 Line Rows Implementation Plan

> **For agentic workers:** Use superpowers:executing-plans to implement task-by-task. No delegation or tests per user instruction.

**Goal:** Expose bounded XCOFF32 function markers and address/line rows.
**Architecture:** Retain decoded rows in Xcoff32Section, decode after symbols, display through structural CLI inspection.
**Tech Stack:** C++20, CMake, MSVC, Clang on WSL.
**Spec:** ../specs/2026-11-02-xcoff32-line-rows.md

## Global Constraints

XCOFF32 only. Preserve raw fields and source offsets. Existing metadata/line budgets and cancellation apply. Do not add/run tests, CI or push. Do not edit capabilities.csv or archive indexing.

## Review Focus

Auxiliary/out-of-range symbol slots; wrong storage class/section; orphan address rows; section boundary addresses; huge ordinary/overflow counts and canceled reads.

### Task 1: Decode and present line rows

- [x] Add Xcoff32LineNumber with raw word, line number, function slot and file offset; add section vector.
- [x] Decode after symbols; reject invalid markers and orphan/address-outside-section rows; charge retained storage and reads.
- [x] Display function markers separately from raw line/address rows with source offsets.
- [x] Update inventory documentation and review diff for all five failure classes.
- [x] Build hexlab_loaders on Windows and WSL with BUILD_TESTING=OFF; record exact results. No tests.
- [x] Commit source and workflow docs locally.

## Execution ledger

Ruling: n_type function bit is optional in IBM documentation, so marker storage class and same-section definition establish the association without rejecting an unset bit.
Ruling: Native worktree creation did not finish promptly; use git fallback at G:/HexLab/.worktrees/xcoff32-line-rows-nov02, branch codex/xcoff32-line-rows-nov02, base b8833575.

### Build commands and results

- Windows configure: `cmake --preset windows-headless -DBUILD_TESTING=OFF` — exit 0, MSVC 19.44.35229.0, Debug x64.
- Windows build: `cmake --build --preset windows-headless --target hexlab_loaders -j 4` — exit 0; linked Debug/hexlab_loaders.dll.
- WSL first attempt: `cmake --preset linux-headless -DBUILD_TESTING=OFF` — exit 1 because Ninja is absent; no build ran.
- WSL Make configure on `/mnt/g` stalled during compiler detection; stopped that process and retained its output directory.
- WSL source snapshot: `git archive -o out/xcoff32-line-rows-source.tar HEAD`, then `tar -rf out/xcoff32-line-rows-source.tar libs/loaders/src/xcoff32.cpp libs/loaders/include/hexlab/loaders/xcoff32.hpp apps/cli/commands.cpp`, extracted into `/tmp/hexlab-xcoff32-line-rows-nov02`. SHA-256 hashes matched all three changed C++ files.
- WSL configure in snapshot: `cmake -S . -B out/build/linux-line-rows-make -G "Unix Makefiles" -DCMAKE_C_COMPILER=clang -DCMAKE_CXX_COMPILER=clang++ -DCMAKE_BUILD_TYPE=Debug -DHEXLAB_BUILD_DESKTOP=OFF -DBUILD_TESTING=OFF -DHEXLAB_ENABLE_PINNED_LLVM_ORACLES=OFF` — exit 0, Clang 18.1.3.
- WSL build: `cmake --build out/build/linux-line-rows-make --target hexlab_loaders -j 4` — exit 0; linked libhexlab_loaders.so.
- WSL CLI translation unit from build directory: `make -f apps/cli/CMakeFiles/hexlab_cli.dir/build.make apps/cli/CMakeFiles/hexlab_cli.dir/commands.cpp.o` — exit 0, 10 warnings in existing surrounding code; this checks the changed CLI without claiming a complete CLI link.
- Both CMake caches report `BUILD_TESTING:BOOL=OFF`. No tests added/run, no CI, no push. All out/untracked artifacts retained.

Self-review: aggregate counts checked before decoding; both raw bytes and retained vector charged; canceled before/after reads and per row; primary symbol lookup rejects auxiliary slots; class/section/function value and line address validated. Address arithmetic widens before subtracting. Optional function bit, include contexts, function bounds and payload overlap remain deliberately uninterpreted. No XCOFF64/archive/capabilities changes.
