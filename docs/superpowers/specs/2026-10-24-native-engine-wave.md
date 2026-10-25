# Native engine expansion wave

## Goal

Expand three independent HexLab subsystems: structured pseudocode for more
reducible CFGs, C type/header modeling for incomplete and flexible layouts, and
a Darwin debugger backend enhancement. Keep unsupported or ambiguous input explicit
and bounded. Retain the existing multi-file desktop and tool architecture.

## Workstreams

1. **Decompiler structure** — extend loop and nested-region recognition beyond
   the current one-level conditional diamond, preserving SSA edge copies,
   source block order constraints, and lossless goto/state-machine fallback.
2. **Type model and headers** — carry incomplete object/aggregate and flexible
   array member information through the immutable model, canonical persistence,
   layout, and bounded C header import where the existing interfaces support it.
3. **Darwin debugging** — extend the existing macOS native backend with Apple-Silicon NEON register
   read/write support, including safe mixed general and vector-register updates. Keep the backend platform-gated and avoid
   claiming runtime validation on Windows.

## Constraints

- Do not run or add tests in this wave; compile-only validation is permitted.
- Do not modify or clean `out/`.
- Avoid replacing or copying whole external projects. Use primary platform
  documentation and existing project abstractions.
- Update docs and capability evidence alongside delivered behavior.
- Root integrates shared documentation/ledger changes and runs one serial
  Debug build after independent work is complete.

## Acceptance

- Each workstream has a coherent implementation that compiles in the available
  Windows Debug configuration where platform boundaries permit.
- Unsupported CFGs continue to use explicit lossless fallback; invalid or
  unbounded type/debugger input is rejected cleanly.
- Documentation accurately distinguishes source implementation from runtime
  verification. No tests are run.
