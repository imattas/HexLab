# Analysis Core Expansion

## Objective

Advance three independent core capabilities toward a complete native reverse-engineering workbench: SIMD semantics, PE/PDB type information, and decompiler aggregate typing.

## Workstreams

1. **x86 SIMD:** extend the current SSE2/selected AVX subset with a coherent, useful operation family across decode, typed operands/effects, and lifting. Preserve lane widths, upper-register semantics, and memory widths. Owner: processor agent; avoid loaders and decompiler type recovery.
2. **PE/PDB type import:** extend a substantial C++ type-information gap in PE/PDB ingestion through bounded parsing, source provenance, and workspace-visible type records. Owner: loader agent; avoid processor and decompiler files.
3. **Decompiler aggregate types:** improve how recovered struct/array types flow into pseudocode and accesses, retaining conservative behavior for ambiguous layouts. Owner: decompiler agent; avoid processor and loader files.

## Constraints

- Work headlessly; do not launch/focus any GUI or browser.
- Leave `out/` untouched.
- Do not add or run tests. Focused Debug compilation is allowed.
- Each owner edits only its subsystem and its documentation; root owns `docs/capabilities.csv` and integration.
- Keep parsing and analysis bounded and reject malformed/ambiguous inputs conservatively.
