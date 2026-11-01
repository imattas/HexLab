# Bounded multi-latch post-tested loops

The formatter recognizes a bounded post-tested loop with an explicit
preheader, where the conditional header is also the repeat destination. The
header dispatches into a binary tree of conditional dispatches and latch arms.
Each distinct latch either jumps unconditionally to the header or branches
between the header and a shared exit cleanup head. At least two latches and
one conditional exit latch are required. A dispatch tree can contain up to
127 dispatch/latch nodes and 64 latch leaves; each traced linear path contains
at most 64 blocks, and tree depth is below 64. The whole function is limited
to 128 blocks and 4,096 edges.

Before emitting structured output, the recognizer validates the complete CFG:
dispatch branches match their true/false CFG edges; each path block has only
its expected predecessor; every unconditional path edge is a resolved jump or
fallthrough; and every latch is distinct. The header predecessor set must
equal the preheader plus **all** proven latches. The cleanup head predecessor
set must equal only the **conditional exit** latches. Unconditional latches
cannot supply cleanup phi inputs because they never reach cleanup.

Header register phis must exactly cover the preheader and every proven latch;
cleanup-head register phis must exactly cover the conditional exit latches.
Duplicate predecessor inputs, missing or extra inputs, and duplicate phi
destinations reject this form. Each block may have at most 4,096 register phis,
with at most 65,536 combined inputs. Initial copies execute after the
preheader. Each latch emits simultaneous header copies before its `continue`;
only an actual exit edge emits cleanup copies before `break`. A conditional
latch evaluates its predicate before either edge's copies can change values
read by that predicate.

For example, a header dispatching to `retry` or `finish` can have `retry`
unconditionally repeat and `finish` conditionally repeat or exit. Header phi
inputs must then be exactly `{preheader, retry, finish}`, while cleanup phi
inputs must be exactly `{finish}`. Neither the `retry` branch nor its phi
copies execute on the `finish` path.

The cleanup consists of at most 64 blocks ending in an explicit return or
recognized `throw`, `rethrow_current_exception`, or `exception_unhandled`
transfer. Only the cleanup head may carry register phis. Every later block
has exactly its preceding block as predecessor; nonterminal cleanup links
are unconditional jumps or fallthroughs. All function blocks must be uniquely
claimed by the preheader, header, tree, or cleanup. The formatter emits the
cleanup once after the loop, follows explicit branch polarity in deterministic
tree order, and retains address-bearing statements in their owning arm. New
unconditional `continue` transfers also retain their source instruction
address (block begin for an empty block) and block ID.

Whole-memory or partition phis, side entries, extra exits, switch dispatch,
shared or overlapping arms, irreducible flow, malformed edge metadata, and
exhausted bounds are not accepted by this recognizer. All-unconditional trees
without a proven exit, conditional continue edges whose other arm starts
another dispatch subtree, branched cleanup, and register phis after the
cleanup head also remain unsupported. Those shapes continue through the
existing region/state-machine/explicit-goto formatters; no partial rendering
from this recognizer is retained.
