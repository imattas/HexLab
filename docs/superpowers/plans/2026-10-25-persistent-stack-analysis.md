# Persistent Stack Analysis Design

## Intent

Retain the existing per-function stack-frame and local-slot results as source-bound analysis data. The CLI and desktop should read one immutable project snapshot rather than independently rerunning stack analysis for each presentation request. This supports stable function-level inspection and reuses the project's existing cache identity and invalidation rules.

## Current state

`analyze_stack_frame` consumes a `FunctionRecord` and `FunctionSnapshot` and returns slots, access sites, completeness, and maximum stack allocation. It currently runs directly from the CLI stack command and desktop pseudocode view. `DerivedProposal` already groups source-keyed functions, references, and strings and is serialized to a versioned derived cache. `ProjectSnapshot` publishes those derived layers to readers.

## Approaches

1. Recompute when each view asks. This keeps storage simple but repeats work and provides no retained per-function model.
2. Add a new database table keyed per function. This allows narrower reads but introduces independent cache identities, invalidation, and transactions alongside the existing whole-analysis cache.
3. Add stack results to `DerivedProposal` and the existing source-keyed cache. This preserves atomic publication and reuse of the existing `AnalysisKey`, at the cost of a derived-cache format version change. **Chosen:** the current analysis already serializes and validates a complete immutable snapshot; keeping stack facts in that envelope is the clearest ownership model.

## Design

- Add a canonical per-function stack record to `DerivedProposal`, keyed by `FunctionId`, containing `StackFrameAnalysis`.
- Generate a record for every recovered function during full analysis. During reference-only updates, reuse all stack records. During other incremental updates, reuse records only when their owning `FunctionRecord` is unchanged and recompute changed/new records.
- Extend the derived-cache envelope with a versioned stack section. Bump the derived-cache version so older payloads become normal cache misses and are rebuilt; do not reinterpret old bytes.
- Validate count and allocation budgets, unique function IDs, canonical slot order, slot widths/offsets, unique in-function access sites, and per-function source identity. On cache load, compare records against deterministic stack analysis over the validated reconstructed function facts before publishing.
- Add the immutable map to `ProjectSnapshot`. CLI and desktop stack presentation use that map and report missing analysis as unavailable rather than silently recomputing a different result.
- Keep the public on-demand `analyze_stack_frame` API for callers without a project snapshot.

## Constraints

C++20 shared engine; preserve bounded work, cancellation, source keys, and existing CLI/desktop behavior. Do not change project user-data schema or mutate user annotations. Do not add or run tests in this workstream; compile affected sources only. Do not launch the GUI or touch `out/`.

## Implementation steps

- [ ] Add stack result records to `DerivedProposal` and compute/reuse them across full and incremental analysis.
- [ ] Extend the derived-cache encoding/decoding and bump its version; validate cached records against reconstructed functions and bounded source facts.
- [ ] Publish stack results in `ProjectSnapshot`; adapt CLI and desktop consumers to use the snapshot model.
- [ ] Update stack-analysis documentation and capability evidence; compile changed analysis, workspace, CLI, and desktop sources where practical.
