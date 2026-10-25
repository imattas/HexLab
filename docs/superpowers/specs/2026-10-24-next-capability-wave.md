# Next capability wave

## Objective

Move three user-facing subsystems closer to the full HexLab reverse-engineering
workbench objective: preserve more real-world C compiler type declarations,
evaluate the already-decoded x86 vector operations with explicit lane semantics,
and recover managed exception flow without guessing CLR runtime behavior.

## Workstreams

1. **C type declarations** — map supported GNU/Clang calling-convention
   attributes into the existing function type model and support bounded vector
   typedef attributes using the existing vector type node. Reject conflicting,
   misplaced, and unrepresentable attributes.
2. **x86 SIMD semantics** — add pure, bounded lane operations for the currently
   decoded AVX/AVX2 subset, with exact 128/256-bit result shapes and VEX.128
   upper-lane clearing. Lift only operations whose operand and memory effects
   are represented exactly by the current IR.
3. **Managed exception flow** — inspect the current EH clause parser and CIL
   lifter, then add a bounded, explicitly represented subset of exception
   control flow (including real catch selection inputs where metadata allows).
   Retain lossless or incomplete output for filters, runtime-dependent dispatch,
   and ambiguous unwind behavior that cannot be justified from the method body.

## Constraints

- Keep parser, execution, and control-flow work bounded and fail closed.
- Preserve existing public enum/schema compatibility; append versioned data only
  when required and retain prior decoders.
- Do not add or run tests. Debug compilation and source review are the available
  verification for this wave.
- Do not modify or clean `out/`.
- Root owns the plan, shared capability ledger, and final integrated build.

## Acceptance

- Each workstream improves actual product behavior, has focused documentation,
  and does not overstate unimplemented runtime behavior.
- The integrated Windows Debug desktop-component target compiles.
- The overall full-remake objective remains active.
