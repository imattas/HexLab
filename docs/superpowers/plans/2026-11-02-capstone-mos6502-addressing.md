# MOS6502 Fallback Addressing Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Preserve documented NMOS accumulator/indexed addressing facts and accurate target/pointer widths in the opaque fallback.

**Architecture:** Keep Capstone detail as the input. Add only instruction-ID/encoding-proven accumulator access and pointer width; retain typed memory indexes in register summaries after generic register handling.

**Tech Stack:** C++20, bundled Capstone, CMake/MSVC, CMake/WSL Clang.

**Spec:** docs/superpowers/specs/2026-11-02-capstone-mos6502-addressing.md

## Global Constraints

No tests added or run. No push, CI, capabilities.csv edits, native 6502 semantics changes, or artifact cleanup. BUILD_TESTING=OFF for both platform builds.

## Review Focus

- Exact accumulator encoding/ID/mode/register agreement required; unknown registers stay omitted.
- X and Y index reads survive generic register-summary replacement.
- Indirect JMP stays unresolved even when pointer slot is resolved.
- Branch/call/jump address operands do not claim byte data transfers.
- Indirect stores retain both pointer-read and data-write summaries.

### Task 1: Complete bounded addressing facts and record validation

**Files:** Modify libs/processors/src/capstone_fallback.cpp and docs/capstone-semantic-fallback.md; create this plan and its spec.

**Interfaces:** Consumes cs_insn and cs_detail::mos65xx; produces existing typed operands and Instruction register/memory summaries. No new public interface.

- [x] Add exact accumulator shift operand handling independent of cs_regs_access.
- [x] Set proven memory data widths, including exact NMOS indirect JMP pointer width and address-only zero width.
- [x] Supplement index-register read sets after generic register handling.
- [x] Update fallback documentation and inspect diff for all review-focus conditions.
- [x] Configure and build hexlab_processors and hexlab_cli on Windows and WSL with tests disabled; record exact commands/results.
- [x] Commit the bounded source/doc change locally.

## Execution ledger

Ruling: parent explicitly authorized inline implementation without further approvals and forbids tests/subagents; use build and source review verification instead of skill test/reviewer steps.
Ruling: managed create_worktree remained pending for several minutes; parent instructed manual fallback. Worktree G:/HexLab-capstone-mos6502 on codex/capstone-mos6502-details, base b88335752eeae14722880f18f00127829bb99d16; root artifacts untouched.

### Validation commands

Windows, from G:/HexLab-capstone-mos6502:

```powershell
cmake --preset windows-headless -DBUILD_TESTING=OFF
cmake --build --preset windows-headless --target hexlab_processors hexlab_cli --parallel 3
```

WSL Ubuntu-24.04 initially attempted `cmake --preset linux-headless -DBUILD_TESTING=OFF`; configure failed because Ninja is not installed. Retried Unix Makefiles on the mounted source; stopped that configure to avoid slow mounted-drive file operations. The final build uses a source mirror at /tmp/hexlab-capstone-mos6502-nov02 populated by `git archive HEAD` from the isolated base checkout plus the exact changed libs/processors/src/capstone_fallback.cpp copied from the worktree. No generated code or native decoder changes are introduced by the mirror.

```sh
cmake -S . -B out/build/wsl-make-headless -G "Unix Makefiles" -DCMAKE_C_COMPILER=clang -DCMAKE_CXX_COMPILER=clang++ -DCMAKE_BUILD_TYPE=Debug -DHEXLAB_BUILD_DESKTOP=OFF -DBUILD_TESTING=OFF -DHEXLAB_ENABLE_PINNED_LLVM_ORACLES=OFF
cmake --build out/build/wsl-make-headless --target hexlab_processors hexlab_cli --parallel 3
```

Logs are preserved as out-mos6502-{windows,wsl,wsl-local}-{configure,build}.log in the worktree; the ignored out/ source archive and build trees are preserved. No tests, GitHub CI, or push commands were run.

Source mirror verification: Windows Get-FileHash and WSL sha256sum both report SHA-256 `35f9c2c090ae05110c02c8ab1bcb3ce38e9ecc6f63c4a74ee3e4d0ecaeae165a` for the patched fallback.cpp. Both configured CMake caches report BUILD_TESTING:BOOL=OFF. The stalled managed-worktree orchestration call was terminated after the manual fallback was in use; no managed-worktree path was returned or used.

Windows result: configure exit 0; combined hexlab_processors and hexlab_cli Debug build exit 0. Both target artifacts linked. Existing C4251 DLL-interface/C4996 deprecation and unrelated source warnings remain; no compile/link errors. No tests run. Final `git diff --check` passed.

Review result: exact accumulator ID/byte/mode/register gate checked against bundled m6502.inc; indexed reads appended after generic summary replacement; address-only operands remain address access with zero width; indirect JMP retains pointer-slot address and no direct target; indirect stores retain existing pointer-read boolean. Unknown register/memory roles remain conservative.

WSL result: Ubuntu-24.04, Clang 18.1.3, Unix Makefiles, Debug configure exit 0; combined hexlab_processors and hexlab_cli build exit 0. Log ends `[100%] Built target hexlab_cli`; processor target also built. Existing missing-field-initializer, switch, and unrelated source warnings remain. No tests run.

Residuals: exact bus cycles, indirect effective addresses, NMOS JMP page wrapping, zero-page wrap behavior, broader MOS65XX variants and unknown register/access roles remain outside the fallback model. No executable instruction semantics or native-decoder coverage changed. Local commit contains only the fallback source, existing installed fallback documentation, spec, and plan; all logs, source archives, and build trees remain local artifacts.
