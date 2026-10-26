# JVM Exception Edge Completeness

## Intent

Keep Java exception-flow metadata complete and make decompilation fail closed when analysis cannot represent every applicable handler. Users should never see pseudocode that silently omits possible catch paths.

## Goals

- Keep the analysis and JVM lifter's throw-site classification synchronized, including constant-pool loads whose resolution or bootstrap can throw.
- Preserve the existing bounded exception-table scan, but never expose its partial edge list as a complete graph to decompilation.
- Keep method-local address spaces, handler ordering, and existing explicit exceptional-edge presentation.
- Record any incomplete analysis in an explicit diagnostic or unsupported result.

## Non-goals

- Full bytecode verification or instruction-specific exceptional local/memory snapshots.
- Reconstructing source `try`/`catch` blocks or class hierarchy joins.
- Increasing existing parser/analysis limits without evidence.

## Approaches

1. Raise all table limits and retain partial results. This risks unbounded growth and still cannot make a capped result complete.
2. Share/synchronize the throw predicate and reject incomplete exceptional CFGs at the lifter boundary. **Selected** because it preserves current bounds and makes loss explicit.
3. Remove exception edges from decompilation. This would discard useful supported information.

## Constraints

- Keep all work in the existing C++20 engine and preserve bounded resource use.
- Do not add or run tests in this wave; compile affected Debug targets and inspect the dataflow.
- Leave `out/` untouched and do not launch the desktop.
- Unsupported or over-budget input must remain explicit; no partial handler graph may be labeled complete.
