# Mach-O Runtime Unwind Implementation Plan

> **For agentic workers:** This plan is being executed by the dispatched subagent in the current workspace; steps use checkbox syntax for tracking.

**Goal:** Evaluate validated Mach-O compact-unwind frame recipes against a supplied register context and stack reader to recover caller state.

**Architecture:** Keep compact-unwind lookup and recipe application in a Mach-O-specific loader API. Consume existing `MachOCompactUnwindFunction` rows, prove a containing interval from the next indexed entry in the same section, and use callback-based 8-byte stack reads. Reject every architecture/mode/encoding permutation outside the explicitly implemented subset.

**Tech Stack:** C++20, HexLab `Result`/ErrorCode, existing Mach-O metadata and loader library.

**Spec:** `docs/superpowers/specs/2026-10-22-macho-runtime-unwind-design.md`

## Global Constraints

- Do not alter shared CMake, README, capability, or reference-matrix files.
- Do not weaken unsupported behavior or silently synthesize missing register or memory values.
- Do not copy implementation from LLVM/libunwind or ELF unwind code.
- Preserve compact-unwind source provenance in every successful result.

## Review Focus

- Interior-PC lookup must require a next boundary in the same section: test containing interval and unbounded tail.
- Missing architectural registers must fail without defaulting to zero: test required register absence.
- Failed callback reads must fail without partial result publication: test read failure.
- Integer overflow/underflow in CFA/slot arithmetic must fail: test extreme pointers/stack values.
- Encodings with malformed permutations and unimplemented DWARF FDEs must return precise errors: test both.

---

### Task 1: Public API and evaluator

**Files:**
- Create: `libs/loaders/include/hexlab/loaders/macho_unwind.hpp`
- Create: `libs/loaders/src/macho_unwind.cpp`

**Interfaces:**
- Consumes: `MachOMetadata::container.slices[selected_slice]`, `compact_unwind_functions`, `Address`.
- Produces: `evaluate_macho_unwind(const MachOMetadata&, Address, const MachOUnwindContext&, const MachOUnwindMemoryReader&) -> Result<MachOUnwindResult>`.

- [x] Write tests for containing-interval lookup plus x86_64 RBP frame with saves, x86_64 immediate-stack with a Lehmer permutation, arm64 frame and frameless recipes with X19/X20 and D8/D9 saves; assert CFA, caller SP/PC, restored registers, and provenance.
- [x] Run tests to confirm missing API/behavior.
- [x] Implement bounded interval lookup; support x86_64 cpu type `0x01000007` and arm64 `0x0100000c`; validate mode and reserved fields; use checked arithmetic and callback reads.
- [x] Add malformed/negative tests for missing register, failed memory, unbounded PC, precise x86_64/arm64 DWARF FDE unsupported results, x86 indirect-stack, invalid permutation, reserved fields, pointer-authenticated arm64e LR, stack/CFA overflow, and invalid selected slice.
- [x] Build and run the isolated evaluator test.

### Task 2: Documentation and integration handoff

**Files:**
- Modify: `docs/macho-compact-unwind.md`
- Create: `docs/superpowers/specs/2026-10-22-macho-runtime-unwind-design.md`
- Create: `docs/superpowers/plans/2026-10-22-macho-runtime-unwind.md`

- [x] Document exact supported recipe subset and limits.
- [x] Verify spec/plan consistency and that all review-focus conditions have tests.
- [x] Report exact required integration lines for `libs/loaders/CMakeLists.txt` and `tests/CMakeLists.txt`, leaving those shared files untouched.

## Integration lines for root

- Loader sources: append `src/macho_unwind.cpp` to the `hexlab_add_library(loaders SOURCES ...)` list in `libs/loaders/CMakeLists.txt`.
- Test registration: add `add_executable(hexlab_macho_unwind_tests macho_unwind_tests.cpp)`, link `hexlab::loaders`, then `add_test(NAME macho_unwind COMMAND hexlab_macho_unwind_tests)` in `tests/CMakeLists.txt`.
