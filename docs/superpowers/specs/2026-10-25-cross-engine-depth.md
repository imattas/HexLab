# Cross-Engine Depth Expansion

## Intent

Continue moving HexLab toward a native reverse-engineering workbench with stronger pseudocode, cross-architecture references, and managed metadata resolution. The current code already has bounded structured control flow, RISC-V address propagation, and exact managed assembly binding; this wave extends those existing paths instead of replacing them.

## Approaches

1. Add unrelated desktop controls. This would not address the remaining engine gaps recorded in the capability ledger.
2. Extend three established engine paths independently: nested post-tested-loop SSA joins, RISC-V producer provenance, and managed `ExportedType` forwarding. **Selected** because each has an existing model, clear conservative behavior, and non-overlapping implementation ownership.
3. Replace the control-flow, reference, or managed metadata models first. This increases migration risk and delays useful capability without being required by these bounded extensions.

## Goals

- Render a bounded two-level conditional diamond inside a post-tested loop when its CFG and register-phi edges are complete.
- Preserve a bounded producer dependency graph for RISC-V references already resolved by the architecture-specific address propagation pass.
- Resolve managed `ExportedType` forwarders across caller-supplied catalogs by exact assembly identity, including nested forwarded names.
- Keep malformed, ambiguous, unresolved, cyclic, and out-of-budget inputs explicit or on the existing fallback path.

## Constraints and non-goals

- Keep the existing C++20, wxWidgets, and library boundaries.
- Do not add or run tests in this wave; compile affected Debug targets only.
- Do not access, clean, or build `out/`; keep work headless.
- Do not load assemblies from disk or infer a missing assembly identity.
- Do not flatten CFG paths, reorder effects, or choose a branch when SSA/ownership information is ambiguous.
- This wave does not complete HexLab or claim IDA Pro feature parity.

## Workstreams

1. **Decompiler control flow:** extend the existing post-tested loop body recognizer by one nested conditional level. Register phis at each consumed join must have exact incoming-edge coverage and be emitted as parallel edge copies. Keep the current 1,024-block/4,096-edge bounds and fallback on side entries, side exits, memory-phi ambiguity, overlap, or deeper nesting.
2. **RISC-V references:** extend the current RISC-V constant/address state with bounded producer ancestry compatible with the existing reference producer DAG. Preserve exact address facts and merge provenance only when all incoming CFG paths agree on the value; preserve ambiguity and existing relocation/segment checks.
3. **Managed type forwarding:** parse bounded `ExportedType` rows and resolve supported assembly-scoped forwarders through exact `AssemblyRef` identities in supplied catalogs. Support nested `ExportedType` chains and reject cycles, duplicate names/identities, invalid coded indexes, and unsupported File/Module implementations without guessed bindings.

## Completion evidence

Affected Debug targets compile; source documentation and the capability ledger describe supported forms and explicit limits. No GUI is launched and no tests are run.
