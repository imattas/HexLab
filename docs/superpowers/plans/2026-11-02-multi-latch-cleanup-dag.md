# Multi-latch Cleanup DAG Implementation Plan

> **For agentic workers:** Use superpowers:executing-plans to implement this plan task-by-task. The explicit no-tests instruction overrides test-driven steps.

**Goal:** Structure shared and phi-bearing acyclic cleanup after proven multi-latch loops.

**Architecture:** Discover and validate a unique-node cleanup DAG, validate each incoming SSA edge, preflight guarded expansion, then emit the selected edge copies and original statements. Keep the existing latch-tree proof and fallback.

**Tech Stack:** C++20, CMake, Windows MSVC, WSL Ubuntu 24.04 clang/Make.

**Spec:** `docs/superpowers/specs/2026-11-02-multi-latch-cleanup-dag.md`

## Global Constraints

- Own only decompiler source and docs; do not edit `docs/capabilities.csv`.
- No tests added or run; `BUILD_TESTING=OFF` for both required builds.
- At most 128 function blocks, 4,096 edges, 64 unique cleanup nodes, 64 path blocks, 4,096 emitted cleanup occurrences, and 64 copies per node.
- At most 4,096 register/partition phis per block and 65,536 combined phi inputs.
- Preserve lossless fallback; no push or GitHub CI.

## Review Focus

- Shared cleanup joins must select the original edge's phi values before statements.
- Cycles, side entries from loop bodies, and malformed predecessors must reject.
- Memory phis must match exact predecessors and partition names must be unique.
- Shared-tail expansion must reject before writing any partial output.
- Loop predicates must execute before latch/header/exit copies can change values.

## Task 1: Prove and emit cleanup DAGs

**Files:** Modify `libs/decompiler/src/decompiler.cpp`, specifically the internal `try_explicit_preheader_multi_latch_loop` lambda; no public interface changes.

- [x] Replace tree-only cleanup classification with bounded acyclic discovery.
- [x] Retain the current loop proof and reject memory phis outside cleanup.
- [x] Validate unique cleanup ownership, exact predecessor sets, register copies, and memory token inputs.
- [x] Preflight expansion and emit edge-specific copies under the original predicates.
- [x] Review source diff against every proof boundary; run `git diff --check`.

## Task 2: Document and build

**Files:** Modify `libs/decompiler/docs/multi-latch-loops.md` and `docs/decompiler-structuring.md`; record evidence here.

- [x] Document accepted DAG shapes, limits, and residual fallback.
- [x] Configure/build Windows `hexlab_decompiler` with `BUILD_TESTING=OFF`.
- [x] Configure/build WSL `hexlab_decompiler` with `BUILD_TESTING=OFF`.
- [x] Record exact results, make a local commit, and report residuals.

## Execution ledger

- Ruling: No test cycle is performed because the explicit task instruction prohibits tests. Static review and platform builds are the available evidence; semantic behavior remains unverified by execution.
- Managed worktree creation stalled; use isolated git fallback `G:/HexLab/.worktrees/decompiler-cleanup-dag-nov02`, branch `codex/decompiler-cleanup-dag-nov02`, base `b60394af`.
- Static review: active-node tracking rejects cycles before completed-node reuse; exact cleanup predecessor reconstruction rejects loop-body side entries; per-edge copies use original block IDs, and cleanup-head copies remain before `break`. Expansion runs before any source output. No semantic execution was performed.
- Final review: separate self-review of the source diff found no issues; all agent slots were occupied, so no additional reviewer was spawned. Parent integration review is still required before integration. Compilation/linking and static inspection are not a semantic equivalence proof.
- WSL first direct `wsl -d Ubuntu-24.04 -- cmake ...` configure failed because CMake was absent from non-login `PATH`. Login shell locates `/home/imattas/.local/bin/cmake`; Ninja is absent, so the configured generator is Unix Makefiles. No dependency installation was required.

## Exact verification commands

Working directory: `G:/HexLab/.worktrees/decompiler-cleanup-dag-nov02`.

```powershell
cmake -S . -B out/build/windows-headless -G "Visual Studio 17 2022" -A x64 -DHEXLAB_BUILD_DESKTOP=OFF -DBUILD_TESTING=OFF -DHEXLAB_ENABLE_PINNED_LLVM_ORACLES=OFF
cmake --build out/build/windows-headless --config Debug --target hexlab_decompiler --parallel 2
wsl -d Ubuntu-24.04 -- bash -lc 'cmake -S /mnt/g/HexLab/.worktrees/decompiler-cleanup-dag-nov02 -B /mnt/g/HexLab/.worktrees/decompiler-cleanup-dag-nov02/out/build/linux-headless -G "Unix Makefiles" -DCMAKE_C_COMPILER=clang -DCMAKE_CXX_COMPILER=clang++ -DCMAKE_BUILD_TYPE=Debug -DHEXLAB_BUILD_DESKTOP=OFF -DBUILD_TESTING=OFF -DHEXLAB_ENABLE_PINNED_LLVM_ORACLES=OFF'
wsl -d Ubuntu-24.04 -- bash -lc 'cmake --build /mnt/g/HexLab/.worktrees/decompiler-cleanup-dag-nov02/out/build/linux-headless --target hexlab_decompiler --parallel 2'
wsl -d Ubuntu-24.04 -- bash -lc 'cmake -S /mnt/g/HexLab/.worktrees/decompiler-cleanup-dag-nov02 -B /home/imattas/hexlab-builds/decompiler-cleanup-dag-nov02 -G "Unix Makefiles" -DCMAKE_C_COMPILER=clang -DCMAKE_CXX_COMPILER=clang++ -DCMAKE_BUILD_TYPE=Debug -DHEXLAB_BUILD_DESKTOP=OFF -DBUILD_TESTING=OFF -DHEXLAB_ENABLE_PINNED_LLVM_ORACLES=OFF'
wsl -d Ubuntu-24.04 -- bash -lc 'cmake --build /home/imattas/hexlab-builds/decompiler-cleanup-dag-nov02 --target hexlab_decompiler --parallel 2'
git diff --check
```

Both configure commands exited 0. Both cache files record
`BUILD_TESTING:BOOL=OFF`. Build logs are captured at the worktree root as
`windows-decompiler-build.log` and `wsl-decompiler-build.log` (ignored, not
committed). Build completion results follow below.

The first WSL build was interrupted with SIGINT to its own process group after
GNU ld spent over eight minutes blocked on mounted-Windows-drive I/O while
linking a dependency. It had reported no compiler errors. The native-output
retry uses the same source worktree with build output under
`/home/imattas/hexlab-builds/decompiler-cleanup-dag-nov02`; its separate log is
`wsl-native-decompiler-build.log` at the worktree root. This is an infrastructure
retry, not a semantic verification result.

- Windows configure and Debug `hexlab_decompiler` build: exit 0. Output:
  `out/build/windows-headless/bin/Debug/hexlab_decompiler.dll`. Existing compiler
  warnings were emitted; no errors. The mounted-output WSL interruption exited 2.
- Native-output WSL configure and Debug `hexlab_decompiler` build: exit 0,
  ending `[100%] Built target hexlab_decompiler`. Output:
  `/home/imattas/hexlab-builds/decompiler-cleanup-dag-nov02/lib/libhexlab_decompiler.so`.
  Native retry cache also confirms `BUILD_TESTING:BOOL=OFF`. Existing warnings
  were emitted, with no compiler errors. No tests were added or run.
- `git diff --check`: exit 0. Production change remains inside the one internal
  multi-latch recognizer. No public interfaces changed, no GitHub CI, no push.
- Residuals: external side entries, nonreturn cleanup leaves, switches, cyclic
  cleanup, shared in-loop subtrees, memory phis outside cleanup, malformed phi
  inputs and shapes beyond the fixed proof/expansion budgets retain fallback.
