# Next IDA-Class Parity Wave

> **For agentic workers:** Implement one independent subsystem task per isolated worktree. Compile affected Windows Debug targets; do not add or run tests in this wave.

**Goal:** Advance three distinct HexLab capabilities that remain explicitly incomplete in `docs/capabilities.csv`: C++ partial-specialization matching, native hardware breakpoints, and WebAssembly MVP global/indirect-call lifting.

**Architecture:** Extend existing bounded C++ type-import, debugger, and WebAssembly loader/decompiler paths. Preserve exact metadata and operand semantics, fail closed on unsupported forms, and keep all project state/version changes explicit.

**Tech Stack:** Existing C++20 libraries, CMake/MSVC Debug builds, wxWidgets desktop where UI is needed.

**Spec:** Current capability gaps in `docs/capabilities.csv`; subsystem constraints in `docs/header-import.md`, `docs/debugger-platforms.md`, and `docs/wasm-analysis.md` / `docs/wasm-decompilation.md`.

## Global Constraints

- Confirm each feature is absent from current root source before implementation.
- Preserve checked bounds, cancellation, provenance, exact identities, and conservative unsupported behavior.
- Keep task source ownership separate; root owns integration, capability-ledger updates, and push.
- Do not add or run tests; compile the affected Debug targets and review the source changes.
- Leave `out/` untouched and do not launch the desktop.

## Review Focus

- Template patterns with signed, unsigned, boundary-width, dependent, or unsupported expressions must not bind to a wrong specialization.
- Hardware breakpoints must keep thread debug registers synchronized across thread creation/exit, resume, and session teardown; unsupported slot counts and ranges must fail cleanly.
- Wasm globals and indirect calls must preserve index spaces, mutability, function-type identity, stack types, and zero/one result shape; malformed or ambiguous metadata must not reach the lifter as valid facts.

## Workstreams

### Task 1: C++ partial-specialization matching

Own `libs/types/src/header_import.cpp` and focused header-import documentation. Extend bounded matching for partial specializations with already-supported integral non-type and template-template arguments. Do not add general dependent-expression evaluation, pack expansion, or implicit instantiation. Keep ambiguity explicit and fail closed.

### Task 2: Windows native hardware breakpoints

First audit the existing Windows native backend and public API. If x86/x64 support is already present, document its actual four-slot, alignment, watchpoint-kind, thread-lifecycle, hit-attribution, and cleanup limits rather than reimplementing it. Fix backend code only for a concrete lifecycle defect. Other backends must retain their current behavior.

### Task 3: WebAssembly MVP globals and indirect calls

Own Wasm metadata/loader and `libs/decompiler/src/wasm_lifting.cpp`, plus focused docs. Preserve imported/defined global and table/function-type index spaces, mutability, and bounded MVP element/function mappings. Lift `global.get`, `global.set`, and `call_indirect` only when the target table slot and signature are statically and uniquely proven; dynamic/ambiguous targets remain explicit unsupported operations. Calls are limited to existing supported numeric stack types and zero/one result.

## Integration

Root reviews workstream scope, failure behavior, and source/API compatibility before cherry-picking. Update only capability entries supported by integrated source and build evidence; build the combined Debug targets and push to `origin/feat/foundation`.

## Progress

- [ ] Task 1 implementation, review, and `hexlab_types` Debug build.
- [x] Task 2 audit: x86/x64 four-slot execution and write/access watchpoints were already implemented; platform docs and ledger now describe lifecycle behavior and read-only watchpoint limits. Debug `hexlab_debugger` and desktop-components builds passed; no tests/runtime validation.
- [ ] Task 3 implementation, review, and loader/decompiler/CLI Debug builds.
- [ ] Integrated source review, capability-ledger update, final builds, and push.
