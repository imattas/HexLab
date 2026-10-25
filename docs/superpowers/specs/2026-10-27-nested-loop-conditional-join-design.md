# Nested loop conditional join design

## Intent

Extend native C-like output for one common nested-loop shape: a canonical
pre-tested child loop whose body has one conditional diamond before its single
latch. The feature should keep the existing lossless goto fallback for shapes
the recognizer cannot prove safe.

## Goals and limits

- Accept one internal conditional in the child loop body.
- Require two disjoint, nonempty, single-block arms that each flow directly to
  the same join block.
- Require the join to have exactly the two arm blocks as predecessors.
- Lower join register phis into parallel copies at the ends of the matching
  `if`/`else` arm.
- Continue the child loop body at the join and preserve the existing unique
  latch, preheader, loop-header phi, and child-exit rules.
- Keep multiple child conditionals, nested child conditionals, conditional
  arm paths, side exits, and ambiguous joins on the existing fallback path.
- Add no tests or run tests under the repository compile-only instruction.

## Approaches considered

1. **General recursive child-loop structurer.** Reuses the broader region
   approach but would require arbitrary joins, nested control, and more complex
   termination checks.
2. **One bounded child-loop diamond.** Adds a single explicit region record
   with exact predecessor validation and phi copies; this matches the existing
   parent-loop diamond recognizer and keeps the fallback conservative.
3. **Expand all child-body phis to arbitrary blocks.** This risks accepting
   shared or side-exiting regions that the current formatter cannot represent.

Use approach 2. It adds the missing common case while keeping the current
structurer's bounded proof obligations.

## Implementation notes

The child-loop recognizer currently walks only unconditional single-successor
body blocks. Add one optional conditional region to `NestedLoopBody`; collect
the branch block, its two arm blocks, and the join in the child body order.
Validate both arm edges, exact incoming predecessors, complete phi inputs,
unique block ownership, and continuation to the existing child latch. During
emission, print the branch and arm statements once, emit parallel copies on
their respective edges, skip the stored arm blocks in the linear body walk,
and then emit the join in normal order. This preserves source addresses and
keeps simultaneous phi assignments correct.

## Verification constraints

Do not add or run tests. Root performs the compile-only verification. Review
must inspect rejected CFG shapes and ensure the existing fallback remains
lossless.
