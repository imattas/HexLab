# Switch Dispatches Inside Loops Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Structure complete switch dispatches nested in pre-tested loop bodies while preserving the loop's common continuation.

**Architecture:** Extend the current loop-body recognizer and emitter in `decompiler.cpp`; do not rewrite the function-entry switch formatter. Keep recognized case paths phi-free and linear, validate every CFG edge, and route unsupported shapes to the existing explicit goto output.

**Tech Stack:** C++20, typed lifted CFG, decompiler formatter, focused C++ fixture executable.

**Spec:** `docs/superpowers/specs/2026-10-23-loop-switch-structuring.md`

## Global Constraints

- Preserve original block addresses and recovered switch case values.
- Reject malformed or incomplete switch metadata conservatively.
- Keep the loop continuation outside the emitted switch and emit it once.
- Preserve existing loop and entry-switch output.

## Review Focus

- Case aliases targeting the same block must not duplicate the arm body.
- Case arms that enter the loop header or exit must not be mistaken for a switch join.
- Case paths with a conditional edge, phi, cycle, or hidden extra block must fallback.
- A malformed default or duplicate case value must fallback.
- Shuffled block storage order must not change case semantics or output.

---

### Task 1: Loop switch fixture

**Files:**
- Modify: `tests/decompiler/structuring_loop_tests.cpp`

- [x] Add a complete switch fixture with two cases and a default whose straight-line arms converge on one shared loop-body continuation.
- [x] Add malformed/incomplete metadata assertions that require explicit goto fallback.

### Task 2: Recognize the loop switch region

**Files:**
- Modify: `libs/decompiler/src/decompiler.cpp`

- [x] Validate metadata against exact CFG successor destinations and unique values.
- [x] Resolve each target through a bounded linear path and find the nearest common continuation.
- [x] Track all dispatch and case-path blocks in loop-region coverage.

### Task 3: Emit switch and shared continuation

**Files:**
- Modify: `libs/decompiler/src/decompiler.cpp`
- Modify: `docs/decompiler-structuring.md`

- [x] Emit case labels from recovered values, each distinct arm once, and one switch `break` per converging arm.
- [x] Emit the common continuation in the parent loop chain exactly once.
- [x] Document supported forms and conservative fallback conditions.

### Task 4: Verify

**Files:**
- Build: `hexlab_decompiler_loop_structuring_tests`
- Run: `decompiler_loop_structuring`

- [x] Confirm the focused target builds and the focused CTest passes.
