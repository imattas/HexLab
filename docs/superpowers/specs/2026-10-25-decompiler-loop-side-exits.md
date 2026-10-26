# Decompiler Loop Side Exits

## Intent

Improve pseudocode readability for reducible loops whose body exits through more than the currently recognized `break` shapes, while preserving exact CFG and SSA behavior.

## Goals

- Add one bounded, documented reducible loop-side-exit shape that is common in compiler output.
- Validate every consumed block, edge, loop exit, and phi predecessor before structured emission.
- Lower multiple SSA assignments in parallel on their original edges.
- Keep the existing state-machine or label/goto output for ambiguous, irreducible, or unsupported shapes.

## Non-goals

- Reconstructing arbitrary irreducible control flow or inventing source semantics.
- Removing the lossless CFG fallback or changing the lifted IR.
- Expanding into unrelated switch or exception structuring.

## Approaches

1. Relax existing structural checks. This is short but can misplace blocks or phi updates.
2. Add a separate bounded recognizer for one explicit side-exit shape with exact predecessor validation. **Selected** because successful output remains proof-backed and unsupported graphs retain fallback.
3. Rewrite the formatter around a general region graph. This is a larger architectural change than this focused gap requires.

## Constraints

- Keep existing C++20 formatter interfaces and output semantics.
- Do not add or run tests in this wave; compile the affected Debug target and inspect the graph-to-source path.
- Leave `out/` untouched and do not launch the desktop.
