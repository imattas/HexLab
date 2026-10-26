# Nested child-loop conditional join plan

## Scope

Files: `libs/decompiler/src/decompiler.cpp`, `docs/decompiler-structuring.md`,
and this task's SDD artifacts. The design is
`docs/superpowers/specs/2026-10-27-nested-loop-conditional-join-design.md`.

## Constraints

- One optional conditional diamond in a canonical pre-tested child loop.
- Each arm is one nonempty straight-line block and ends at the same join.
- The join has exactly those two predecessors; every register phi has one
  value from each.
- Emit edge-specific parallel copies before the join executes.
- Keep all unsupported, ambiguous, malformed, or side-exiting shapes on the
  existing state-machine/goto path.
- No tests may be added or run; compile-only verification is owned by root.
- Do not edit `out/`, the shared capability ledger, or root's active plan.

## Steps

- [x] Extend the nested-loop internal model with one conditional region and
   explicit arm/join phi-copy metadata.
- [x] Parse and validate a single conditional child-body diamond, proving arm
   disjointness, exact join predecessors, full phi inputs, and continuation to
   the existing single latch.
- [x] Emit the conditional and per-edge parallel copies exactly once while
   preserving the linear child-body order and join execution.
- [x] Document the supported shape and fallback limits; record source review and
   compile requirement in the task report.
- [ ] Root compiles `hexlab_decompiler` Debug and performs integration review.

## Review focus

Check duplicate block emission/omission, arm-to-join predecessor validation,
phi-copy simultaneity, join execution exactly once, latch reachability, loop
header and child-exit phi behavior, and conservative fallback for a second
conditional or any side exit.

## Follow-up implementation note

The formatter now also recognizes a conditional continue directly to the
child header when the other edge advances the traced straight-line child-body
chain. Child-header register phis must map exactly to the preheader, the
ordinary latch, and every recognized conditional-continue predecessor. Each
back-edge's copies are emitted immediately before its own transfer. Continue
edges nested inside a child diamond or routed through side blocks remain
unsupported and use the lossless fallback; this does not expand the one-diamond
scope above.
