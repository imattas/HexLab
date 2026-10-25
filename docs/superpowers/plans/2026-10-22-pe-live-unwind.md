# PE Live-Context Unwinding Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Evaluate PE AMD64/ARM64 unwind metadata against caller-provided register and memory snapshots.

**Architecture:** Add a debugger-independent public API to the image library. Resolve one PE runtime function, evaluate supported unwind operations into a temporary copied register context, and publish a caller context only after validation and exact bounded reads succeed.

**Tech Stack:** C++20, HexLab `Result<T>`, PE metadata, CMake, CTest.

**Spec:** `docs/superpowers/specs/2026-10-22-pe-live-unwind-design.md`

## Global Constraints

- Do not change shared CMake files, README, capability manifests, or reference matrix in this task.
- Do not depend on the debugger library; use a memory callback and named register byte arrays.
- Keep memory requests exact and bounded; check address arithmetic and context widths.
- Unsupported metadata must return an explicit error without modifying input state.

## Review Focus

- PC outside all PE function ranges and module-base/RVA overflow return precise errors.
- Missing, wrongly sized, or short register/memory values fail without partial caller context.
- Chained AMD64 metadata cannot recurse beyond the fixed bound or loop.
- ARM64 xdata unsupported operations fail explicitly; packed forms use exact documented frame/register counts.
- Caller SP/PC arithmetic cannot wrap and source context remains unchanged on every failure.

---

### Task 1: Define PE unwind API and AMD64 evaluation

**Files:**
- Create: `libs/image/include/hexlab/image/pe_unwind.hpp`
- Create: `libs/image/src/pe_unwind.cpp`
- Test: `tests/pe_live_unwind_tests.cpp`

**Interfaces:**
- Produces `PeRegisterContext`, `PeMemoryReader`, `unwind_pe_frame(const PeMetadata &, Architecture, uint64_t module_base, uint64_t instruction_pointer, const PeRegisterContext &, const PeMemoryReader &) -> Result<PeRegisterContext>`.

- [x] Add tests for AMD64 stack allocation, saved nonvolatile GPR/XMM values, return address, machine frame, chained records, missing registers, and short memory.
- [x] Implement AMD64 metadata selection, checked reads/arithmetic, operation evaluation, partial-prolog behavior, and atomic output.
- [x] Build and run the isolated focused test executable.

### Task 2: Add ARM64 packed and xdata evaluation

**Files:**
- Modify: `libs/image/src/pe_unwind.cpp`
- Test: `tests/pe_live_unwind_tests.cpp`

- [x] Add tests for packed layouts, GPR/FP/LR restore, xdata save families, SVE/save-any, parent links, and missing context.
- [x] Implement packed/unpacked unwind execution, bounded parent resolution, partial prolog/epilog behavior, and checked address handling.
- [x] Run the focused standalone test executable and existing PE exception CTest.

### Task 3: Document runtime contract and integration requirements

**Files:**
- Create: `docs/pe-live-unwind.md`
- Modify: `libs/image/include/hexlab/image/pe_unwind.hpp` comments as needed.

- [x] Document caller snapshots, register conventions, supported operations, errors, and adapter boundary.
- [x] Report exact root integration additions required: `src/pe_unwind.cpp` in `libs/image/CMakeLists.txt`; `hexlab_pe_live_unwind_tests` plus CTest registration in `tests/CMakeLists.txt`.
- [x] Verify focused standalone suite plus existing PE metadata suite.
