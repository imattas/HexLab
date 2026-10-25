# Analysis Core Expansion Plan

> Implement independent analysis capabilities using `superpowers:subagent-driven-development`; compile changed Windows-supported targets without adding or running tests.

**Goal:** Advance cross-reference recovery, stack-frame modeling, and ABI classification toward the full HexLab/IDA-scale analysis workflow.

**Architecture:** Keep each feature in its existing analysis service and preserve the shared immutable image, typed instruction, and type graph contracts. Each workstream owns separate implementation and documentation files; root integration owns the capability ledger and combined source compilation.

**Tech Stack:** C++20, existing HexLab analysis/types APIs, CMake/MSVC source compilation.

**Spec:** `docs/superpowers/specs/2026-10-19-hexlab-design.md` (analysis and type/ABI sections).

## Constraints and review focus

- Keep wxWidgets out of engine code and use existing public service boundaries.
- Retain bounded work, cancellation, checked address/size arithmetic, and conservative joins.
- Unsupported or ambiguous semantics must remain explicit; never publish guessed targets or stack offsets.
- Do not edit tests or shared CMake files; do not launch the desktop or clean `out/`.
- Review branch joins, unknown writes/calls, unsupported vector/aggregate shapes, and persisted enum/version compatibility.

## Independent workstreams

1. **Cross-reference value propagation** — `libs/analysis/src/references.cpp` and focused reference documentation. Improve a broad missing dataflow capability (including memory spills if sound) while preserving the current CFG predecessor intersection, relocation guards, executable-target checks, cancellation, and unresolved-reference behavior.
2. **Stack-frame model** — `libs/analysis/src/stack.cpp`, `libs/analysis/include/hexlab/analysis/stack.hpp`, and focused stack documentation. Extend the returned frame summary with useful, evidence-backed frame/slot information across the already supported architectures; keep entry-SP offsets canonical and ambiguity explicit.
3. **Microsoft vectorcall ABI** — `libs/analysis/src/abi.cpp`, `libs/analysis/include/hexlab/analysis/abi.hpp`, and ABI docs. Add a defined x86/x64 `__vectorcall` classification path for supported scalar/vector/HVA forms; preserve unsupported results for varargs, unsupported shapes, and convention/platform mismatches. Use Microsoft’s published `__vectorcall` specification as the primary semantic reference.

## Progress

- Cross-references: bounded x86-32/x86-64 pointer spill/reload facts now flow through CFG joins; implicit/repeated/unknown stores and calls invalidate them. Source compilation passed; source review is underway.
- Stack frames: `StackFrameAnalysis` now reports an optional proven maximum stack-allocation extent. Zero means proven frameless; missing means incomplete or ambiguous. Source compilation passed.
- Microsoft vectorcall: implementation is in progress.

## Integration

- Review each implementation against its public API and documented limits.
- Update `docs/capabilities.csv` only after integration review.
- Compile changed Windows-supported libraries with `ClCompile` only; no linking into the open desktop process.
- Perform source and whitespace review. No tests are added or run under the active developer instruction.
- This wave is an increment and does not complete the full product objective.
- Cross-references and stack-frame model passed source review; their Windows analysis library compilation passed.
- Microsoft x86/x64 vectorcall passed a targeted source review against Microsoft documentation after fixing HVA spill, array, partial-width return, and unknown-parameter cases; source compilation passed.
- No tests added or run.
