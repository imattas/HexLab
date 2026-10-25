# Analysis depth wave

## Objective

Expand three independent user-facing analysis domains toward the full IDA-scale
workbench: richer native pseudocode for nested CFG regions, real-world DWARF
location expression evaluation in live locals, and AMD64 C++ EH4 metadata.

## Workstreams

1. **Native decompiler structuring** — extend bounded structuring for nested
   conditional/loop regions and their SSA joins. Preserve each instruction and
   side effect exactly once, attach phi copies to proven CFG edges, and retain
   the existing state-machine or goto fallback for ambiguous graphs.
2. **DWARF live locations** — extend the expression decoder, canonical imported
   variable model, evaluator, and debugger presentation as one vertical slice.
   Prioritize common arithmetic/stack/branch operations and entry-value or
   register-relative expressions only when the runtime inputs can be supplied
   explicitly. Keep operation, stack, branch, memory-read, and recursion limits.
3. **PE C++ EH4** — parse a bounded, source-tracked subset of `__CxxFrameHandler4`
   function metadata into the existing PE exception model. Do not execute
   handlers or infer runtime catch selection; retain explicit unsupported
   diagnostics for unknown flags, encodings, or incomplete payloads.

## Constraints

- Use current subsystem APIs and persistence versions unless the feature cannot
  be represented; retain prior decoders when a versioned extension is required.
- Keep parsing and evaluation bounded and fail closed on malformed/ambiguous
  metadata.
- Do not add or run tests. Compile-only verification and focused source review
  are required.
- Do not read, write, clean, or build `out/`.
- Root owns shared plan, capability ledger, and integrated Debug build.

## Acceptance

- Each workstream adds behavior users can observe in the pseudocode, debugger
  locals, or PE metadata views.
- Documentation accurately states supported encodings and remaining gaps.
- The integrated Windows Debug desktop-components target compiles; no tests are
  run and the full remake remains active.
