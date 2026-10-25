# CLI Call Summary Integration Plan

> **For agentic workers:** Implement the bounded CLI integration described here; do not add or run tests.

**Goal:** Make proven local direct-call return constants and compatible interprocedural type facts available to CLI pseudocode without assuming unknown ABI register or memory effects.

**Architecture:** In the CLI decompile path, lift and SSA-convert recovered functions once, pass stable references to `optimize_with_call_summaries`, and use `recover_interprocedural_types` only for a fully complete, locally bound function set. Feed optimized bodies and inferred prototypes through local simplification and typed formatting. On resource or eligibility failure, retain per-function formatting.

**Tech Stack:** C++20, existing HexLab decompiler API and CLI.

**Spec:** `docs/superpowers/specs/2026-10-25-cli-call-summary-design.md`

## Global Constraints

- Do not add or run tests.
- Do not launch or focus the desktop GUI.
- Do not modify `out/`.
- Keep unknown boundary effects conservative and preserve fallback CLI behavior.

## Review Focus

- Duplicate recovered entries or body failures must not associate a summary with the wrong function.
- Incomplete and exported functions must not contribute summary facts.
- Resource-limit failures must not discard ordinary per-function output.
- Return constants must retain exact integer width and be propagated only by existing optimizer validation.

---

### Task 1: Prepare the stable lifted function set

**Files:**
- Modify: `apps/cli/commands.cpp`

**Interfaces:**
- Consumes: `recover_functions`, `decompiler::lift_function`, `decompiler::to_ssa`.
- Produces: ordered lifted bodies and `CallSummaryInput` records referring to them.

- [ ] Lift and SSA-convert each recovered body once; preserve a mapping from recovered-function order to optional lifted-body index, and record body completeness and exported-address binding.
- [ ] Keep boundary register effects unknown and boundary memory effect unknown for every input.

### Task 2: Run optional interprocedural summaries and retain fallback

**Files:**
- Modify: `apps/cli/commands.cpp`
- Modify: `libs/decompiler/README.md`

**Interfaces:**
- Consumes: ordered inputs from Task 1 and `decompiler::optimize_with_call_summaries`.
- Produces: per-function optimized bodies when available; otherwise the original SSA bodies.

- [ ] Invoke the bounded summary API once and associate result bodies by stable input index.
- [ ] On API failure, emit one diagnostic and continue the prior simplification path for all available bodies.
- [ ] Apply the existing constant, identity, dead-code, and structured formatting stages to the selected body without changing output behavior for functions with no proven facts.
- [ ] Select PE x64, ELF/Mach-O x64, or AArch64 ABI maps; run interprocedural type recovery only when all recovered bodies are complete and locally bound, and use its inferred prototypes in typed pseudocode formatting.
- [ ] Keep typed per-function formatting available when whole-set type recovery is ineligible or over budget.
- [ ] Document CLI-only integration and the unknown boundary-effect limits.

### Task 3: Compile and inspect the integration

**Files:**
- Inspect: `apps/cli/commands.cpp`, `libs/decompiler/README.md`

- [ ] Compile the changed CLI source/target using the existing Debug build directory, without running tests or the executable.
- [ ] Review `git diff --check` for the changed files and confirm no `out/` paths were modified.
