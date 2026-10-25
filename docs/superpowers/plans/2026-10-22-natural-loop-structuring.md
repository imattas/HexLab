# Natural Loop Structuring Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Extend structured pseudocode for verified reducible natural loops with conditional `break`/`continue` paths and nested loop regions while preserving SSA edge assignments and lossless goto fallback elsewhere.

**Architecture:** Keep the public `format_structured_pseudocode(const LiftedFunction&)` API. Add a bounded loop-region analysis and recursive emitter in the existing decompiler formatter, using CFG edges and dominator/back-edge relations rather than block storage order. The recognizer must validate complete predecessor/phi correspondence and support only loop shapes whose conditional paths can be represented without changing execution; every unrecognized shape continues through `format_pseudocode` fallback.

**Tech Stack:** C++20, existing `LiftedFunction`/`LiftedBlock` IR, CMake, CTest.

**Spec:** `docs/decompiler-structuring.md` and the root-approved overarching HexLab architecture spec.

## Global Constraints

- Modify only `libs/decompiler` structuring code, `tests/decompiler` loop tests/CMake, this plan, and decompiler structuring documentation.
- Do not touch processor code, DWARF/project schemas, `docs/capabilities.csv`, or `out/`.
- Keep `format_pseudocode` as the lossless fallback for irreducible, malformed, ambiguous, or unsupported CFGs.
- Do not drop, duplicate, or reorder SSA edge assignments; validate phi predecessor identities against actual CFG edges.
- Use a unique isolated Debug build directory outside `out/`.

## Review Focus

- Conditional branch to the loop's unique exit must produce a conditional `break` and retain the non-exit path.
- Conditional branch to the loop header/latch must produce a `continue` at the correct loop nesting depth.
- Nested loops must bind `break` and `continue` to the innermost matching region and resume the enclosing body after inner-loop exit.
- Loop-carried and internal join phis must lower to assignments on their actual incoming edges, including shuffled block storage.
- Unclassified latches, irreducible cycles, missing edges, duplicate/foreign phi inputs, and side exits outside the recognized loop-control forms must preserve goto fallback with a reason. Explicit conditional continue edges may be multiple, but each must be identified and have a valid phi input/copy.

---

### Task 1: Dedicated loop CFG fixtures and expected structured output

**Files:**
- Create: `tests/decompiler/structuring_loop_tests.cpp`
- Modify: `tests/decompiler/CMakeLists.txt`

**Interfaces:**
- Consumes: existing public `LiftedFunction`, `to_ssa`, `format_structured_pseudocode` APIs.
- Produces: a dedicated `hexlab_decompiler_loop_structuring_tests` executable and `decompiler_loop_structuring` CTest case.

- [ ] **Step 1: Add a fixture for a pre-tested loop with a conditional early exit.** Assert structured output contains `while`, a conditional `break`, the surviving body statement, and no goto.
- [ ] **Step 2: Build the focused target and run CTest to verify RED.** Run `cmake --build agent-decompiler-structuring-build --config Debug --target hexlab_decompiler_loop_structuring_tests -- /m:1 /p:CL_MPCount=1`, then `ctest --test-dir agent-decompiler-structuring-build -C Debug -R '^decompiler_loop_structuring$' --output-on-failure`. Expected: the explicit CFG currently takes the goto fallback.
- [ ] **Step 3: Add continue and nesting fixtures.** Assert a conditional header/back-edge transfer renders `continue`; add an inner pre-tested loop with an early exit and assert its exit resumes the outer body. Shuffle block-array order in at least one fixture.
- [ ] **Step 4: Add SSA edge-copy fixture.** Run `to_ssa` over a loop with one loop-carried header phi and one branch merge inside the loop. Assert the initial and recurrent assignments remain on their preheader/back-edge paths and merge copies remain on the correct predecessor arms.
- [ ] **Step 5: Add malformed and unsupported CFG fixtures.** Require goto fallback and a nonempty reason for an unclassified latch, an irreducible cycle, and a loop phi whose inputs do not match CFG predecessors.
- [ ] **Step 6: Run the focused test to confirm all new structural expectations are still RED before implementation.** Record each expected fallback/missing structured construct in the work log.

### Task 2: Natural-loop region analysis and conservative validation

**Files:**
- Modify: `libs/decompiler/src/decompiler.cpp` at the structured pseudocode loop recognizer.
- Test: `tests/decompiler/structuring_loop_tests.cpp`

**Interfaces:**
- Consumes: the internal block/address lookup and formatter helpers; validated loop fixtures from Task 1.
- Produces: internal loop-region data with header, latch/back edges, member blocks, exits, and parent/child nesting; no public API changes.

- [ ] **Step 1: Add a focused assertion that shuffled CFG block order does not change loop membership or rendered output.** Run the dedicated test and observe failure before changing production code.
- [ ] **Step 2: Implement bounded dominator/back-edge analysis and natural-loop membership.** Recognize a back edge only when its target dominates its source; collect loop members by reverse predecessor traversal, and reject overlapping non-nested regions, unclassified latches, external side exits, unresolved targets, unreachable blocks, and malformed edge/phi data. Preserve any validated number of explicit conditional continues to the current header.
- [ ] **Step 3: Validate loop/header and internal join phi inputs against exact predecessor edges.** On invalid data, return to the existing lossless formatter with a specific fallback reason.
- [ ] **Step 4: Run the dedicated test and full existing decompiler CTests.** The analysis-only step may still fall back for valid new shapes; existing output must remain unchanged.

### Task 3: Recursive emission for early exits, continues, and nested loops

**Files:**
- Modify: `libs/decompiler/src/decompiler.cpp` loop region emitter.
- Test: `tests/decompiler/structuring_loop_tests.cpp`

**Interfaces:**
- Consumes: validated nested loop regions and exact edge-copy metadata from Task 2.
- Produces: structured C-like loop output with scoped `break` and `continue`; fallback remains the result for unsupported regions.

- [ ] **Step 1: Add a focused test for a conditional loop-exit edge that must render as `if (condition) break;`.** Run to verify failure before implementation.
- [ ] **Step 2: Implement recursive emission for the supported natural-loop body graph.** Emit each block once, structure only loop-control conditionals whose targets are the current loop header/latch or its unique exit, and recurse into a child loop before continuing the parent body.
- [ ] **Step 3: Lower SSA copies at the originating preheader, each validated back edge (normal latch or continue), and conditional/join predecessor.** Each loop-header phi must have exactly one preheader input and one input for every actual back-edge predecessor. Emit copies in the predecessor path immediately before its control transfer; do not hoist or merge copies unless the paths are proven equivalent.
- [ ] **Step 4: Run all dedicated fixtures.** Require `break`/`continue` binding to the innermost region and correct emitted order across nested loops and shuffled block storage.

### Task 4: Fallback boundaries, documentation, and final verification

**Files:**
- Modify: `docs/decompiler-structuring.md`
- Test: `tests/decompiler/structuring_loop_tests.cpp`
- Build: unique isolated directory `agent-decompiler-structuring-build/`

**Interfaces:**
- Consumes: final supported shape set from Tasks 1–3.
- Produces: documented guarantees/limits and verified focused Debug build.

- [ ] **Step 1: Add or tighten fallback tests for irreducible, malformed, unclassified-latch, and unsupported side-exit shapes.** Verify goto output and nonempty fallback reasons.
- [ ] **Step 2: Document the supported natural-loop shapes, phi-copy placement, and retained goto boundaries in `docs/decompiler-structuring.md`.** Name the specific recognized loop-control conditions and avoid promising arbitrary loop structuring.
- [ ] **Step 3: Build all decompiler test targets in `agent-decompiler-structuring-build` and run `ctest --test-dir agent-decompiler-structuring-build -C Debug -R '^decompiler(_.*)?$' --output-on-failure`.** Expected: all decompiler tests pass, including the new dedicated loop test.
- [ ] **Step 4: Run `git diff --check` and inspect the scoped file list.** Confirm no changes to `out/`, processor/DWARF/project schema files, or `docs/capabilities.csv`.
