# Analysis, Symbols, and Recovery Expansion

## Objective

Advance three independent engine areas toward a complete native reverse-engineering workbench: cross-unit DWARF resolution, stronger guarded switch recovery, and live PDB subfield locals.

## Workstreams

1. **DWARF references:** ordinary compile-unit/type-unit imports already build a bounded dependency DAG and resolve supported forward references. The remaining concrete gap is cross-reference resolution between split type-unit package contributions. Extend bounded indexing/resolution for uniquely identified TU-index signatures; ambiguous identities, cycles, and out-of-contribution offsets must fail explicitly without publishing partial import state.
2. **Switch bounds:** switch recovery proves selected unsigned bounds, but does not prove signed or normalized range checks. Extend range proof only for instruction/CFG patterns with exact typed semantics and complete known incoming-edge coverage; retain the unbounded verified-prefix behavior whenever proof is incomplete.
3. **PDB live locals:** CodeView subfield and indirect register-relative defranges are decoded and retained by the PDB model, but a PE metadata transfer layer drops their recipe fields before the debugger. Preserve those fields through the bounded image metadata path and evaluate only type-sized fragments with validated parent offsets, spill/indirect metadata, and checked memory ranges; keep unsupported or unavailable values explicit.

## Shared constraints

- Keep all parsing, proof, reads, result counts, and allocations bounded and cancellation-aware where APIs already support cancellation.
- Reject malformed or ambiguous evidence; never guess a type target, switch bound, register mapping, or parent value.
- Preserve the existing C++/wxWidgets monorepo architecture and public persistence compatibility.
- Do not read, write, clean, or build `out/`.
- Do not add or run tests in this wave. Compile affected Debug targets and review source paths instead.
- Keep ownership separate: DWARF agent owns `libs/symbols/src/dwarf.cpp` and DWARF docs; switch agent owns `libs/analysis/src/switches.cpp` and switch docs; PDB agent owns debugger-local evaluation code and PDB-local docs. Root owns shared planning and `docs/capabilities.csv`.
