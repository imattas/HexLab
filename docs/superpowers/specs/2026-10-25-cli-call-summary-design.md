# CLI Interprocedural Call Summary Design

## Intent

Use the decompiler's existing bounded call-summary and interprocedural
type-recovery engines in the CLI `--decompile` pipeline. Locally proven
direct-call return constants can reach callers, and compatible local callers
can contribute unanimous ABI argument and return types before pseudocode
formatting. This improves executable analysis output without changing bytes,
recovered function ownership, or ordinary disassembly.

## Goals and constraints

- Lift and convert the recovered function set once, preserving input ordering.
- Mark incomplete or externally exported functions ineligible for summaries.
- Select supported PE x64, ELF/Mach-O x64, and AArch64 ABI maps for type recovery.
- Use interprocedural type exchange only when all supplied bodies are complete
  and locally bound; still emit per-function typed output otherwise.
- Keep ABI boundary register and memory effects unknown until a sound ABI model
  is available; do not infer preserved registers or memory purity from missing
  metadata.
- Apply the existing summary optimizer only within its configured resource
  bounds. If the optional pass cannot run, retain the previous per-function
  simplification path and report the reason.
- Preserve CLI output for functions that receive no proven summary facts.
- Keep changes in CLI code and focused documentation; do not add or run tests,
  launch the desktop application, or modify `out/`.

## Approaches

1. Integrate summaries into the CLI only. This makes the existing engine useful
   in a deterministic headless workflow without imposing whole-project lifting
   costs on every interactive desktop refresh. **Selected.**
2. Integrate both CLI and desktop. This gives interactive parity but requires a
   snapshot-keyed cache and invalidation strategy to avoid relifting every body
   on each selection change.
3. Leave the engine as a library API. This avoids integration work but keeps
   the feature inaccessible to current product workflows.

## Architecture

The CLI decompile command will lift and SSA-convert recovered functions into a
stable vector, build `CallSummaryInput` records over those bodies, and invoke
`optimize_with_call_summaries` once. Boundary register and memory effects stay
unknown, so only facts established by complete bodies and proven return values
are used. For a fully complete, locally bound function set, it also invokes
`recover_interprocedural_types` with format-derived ABI maps. The inferred
prototypes then feed the existing typed pseudocode formatter. Summary/type
limits fall back to local optimization and per-function type recovery instead
of failing an otherwise usable CLI result.

## Non-goals

- Inferring ABI caller-saved/preserved registers or function memory purity.
- Summarizing exported/interposable functions, indirect calls, recursive calls,
  incomplete bodies, or architecture-specific delayed calls.
- Cross-function type propagation through incomplete or externally bound bodies.
- Interactive desktop integration or persistent summary/type caching.
- New decompiler semantics, tests, or changes to function recovery.

## Implementation calls

- Existing decompiler API and conservative rejection behavior are authoritative.
- Generic exports and any defined ELF/Mach-O symbol at a function entry make
  that address externally bound for this CLI invocation; the latter is
  deliberately conservative for local and static definitions.
- Summary failure is diagnostic and falls back to local simplification.
- Documentation will state the conservative limits and command scope.
