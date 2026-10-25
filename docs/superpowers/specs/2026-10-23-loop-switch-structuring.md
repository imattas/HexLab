# Switch Dispatches Inside Loops

## Goal

Format a recovered complete switch dispatch inside a pre-tested loop as a C-like
`switch`, while preserving the loop's shared continuation and fallback behavior.

## Current behavior

The structurer accepts a complete switch only at function entry. The pre-tested
loop recognizer accepts straight-line blocks, conditional break/continue,
nested loops, and one-level if/else diamonds; a switch block currently takes the
explicit label/goto fallback.

## Design

Extend the existing pre-tested loop recognizer. A loop-body switch is eligible
only when its selector, case values, default destination, and CFG successors
agree; every case/default follows a bounded, acyclic, phi-free straight-line
path; and all paths converge on one shared continuation inside the loop.
Case-path blocks belong to the switch region and are consumed exactly once.
Each case path ends with a `break` from the C switch; the shared continuation
is emitted once after the switch and remains inside the loop. The loop latch,
header, and exit cannot be the switch join. No case may transfer directly to a
loop break/continue edge or return in this first form.

Incomplete metadata, duplicate values, mismatched CFG edges, cycles, phis,
conditional case paths, shared regions before the recognized join, or blocks
outside the recognized loop continue through the existing explicit goto
fallback. No case numbering is inferred from CFG successor order.

## Acceptance

- A complete two-case-plus-default dispatch in a pre-tested loop emits one
  `while`, one `switch`, each case's statements once, one shared continuation,
  and no goto fallback.
- Incomplete or mismatched switch metadata continues to report a fallback.
- Existing switch-at-entry and loop output remain unchanged.
