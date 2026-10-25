# Engine Subsystems Wave — 2026-10-26

## Goal

Advance HexLab toward an IDA-class reverse-engineering workbench by improving three independent core areas: control-flow analysis for switches, semantics-preserving C-like decompilation, and durable import of C declarations.

## Design

### Switch and indirect-target analysis

Generalize bounded switch recovery beyond same-block compare/branch patterns. The analyzer must only claim case counts/default edges when a path proof establishes the selector bound and that the selector value reaches dispatch unchanged. Preserve valid table prefixes and incomplete status when table bytes or targets fail validation. Bound graph, instruction, and table work; cancel promptly.

### Structured pseudocode

Improve CFG-to-source structuring for nested loops and multiway control flow. Render a structured region only when CFG edges and SSA values support it; otherwise keep the lossless existing fallback. Do not duplicate side effects, drop terminal edges, or invent source-level semantics.

### C declaration persistence

Extend the current bounded C-header workflow so parsed declarations remain useful after the import call. Preserve global object types, function prototypes, and enumerator values with project persistence, undo/redo, type queries, and portable exchange. Keep the operation atomic, target-ABI-aware, bounded, and backward-compatible with older plugin table prefixes.

## Constraints

- Continue using the existing C++/wxWidgets monorepo architecture.
- Keep all work headless; do not open or activate application windows.
- Do not add or run tests in this wave. Compile affected targets where practical and report gaps honestly.
- Leave `out/` untouched.
- Preserve explicit unsupported/incomplete states rather than guessing.

## Integration evidence

Each workstream reports changed files, semantic limits, and focused Debug build results. Root reviews ownership boundaries, updates `docs/capabilities.csv`, and appends outcomes to the wave plan.
