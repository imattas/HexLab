# Sequential conditional joins in nested loops

## Intent

Extend structured output for a canonical pre-tested child loop containing more
than one sequential if/else diamond. Each branch remains bounded and each
shared continuation is emitted once, with register phi assignments attached
to the correct incoming arm edges.

## Acceptance boundary

- Each recognized conditional has two distinct, direct single-block arms.
- Both arms are phi-free, non-terminating, and flow unconditionally to one
  shared join.
- The join has exactly those two arm blocks as predecessors and either one
  unconditional successor or is the branch block for the next sequential
  diamond.
- Multiple diamonds may occur sequentially in the child body; regions may not
  overlap or nest.
- Join phis must have one input from each arm predecessor. Parallel copies run
  at the end of the corresponding arm.
- The child loop still requires one latch, a unique preheader, and valid
  initial/recurrent header phi inputs. Unsupported shapes retain the existing
  state-machine or explicit-goto fallback.

## Chosen approach

Store each proven conditional join in child-body order and emit it when its
branch block is visited. The existing unique-block walk, exact predecessor
checks, parallel-copy helper, and latch validation remain the proof boundary.
Recursive regions and multi-block arms stay on the fallback path.
