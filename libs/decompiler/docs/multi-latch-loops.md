# Bounded multi-latch post-tested loops

The formatter recognizes a bounded post-tested loop with an explicit
preheader, where the conditional header is also the repeat destination. The
header dispatches into a tree of conditional dispatches and latch arms.
Each distinct latch either jumps unconditionally to the header, branches
between the header and a shared exit cleanup head, or branches between the
header and a further in-loop subtree. The last form represents a guarded
`continue`: the sibling edge may follow a linear path to another conditional
dispatcher, conditional repeat guard, or unconditional latch. At least two
distinct backedge sources and one conditional exit latch are required. A
dispatch tree can contain up to 127 dispatch/latch nodes and 64 backedge
sources, including interior repeat guards; each traced linear path contains
at most 64 blocks, and tree depth is below 64. The whole function is limited
to 128 blocks and 4,096 edges.

Before emitting structured output, the recognizer validates the complete CFG:
dispatch branches match their true/false CFG edges; each path block has only
its expected predecessor; every unconditional path edge is a resolved jump or
fallthrough; and every latch is distinct. The header predecessor set must
equal the preheader plus **all** proven latches. The cleanup head predecessor
set must equal only the **conditional exit** latches. Unconditional latches
and interior repeat guards cannot supply cleanup phi inputs because those
edges never reach cleanup. Each repeat guard's sibling is classified by a
bounded lookahead: a resolved unconditional chain ending in an explicit return
is an exit candidate; a chain ending in another conditional or backedge must
pass the full in-loop subtree proof. Cycles, unresolved transfers, and an
exhausted lookahead reject the entire candidate.

Header register phis must exactly cover the preheader and every proven latch;
cleanup-head register phis must exactly cover the conditional exit latches.
Duplicate predecessor inputs, missing or extra inputs, and duplicate phi
destinations reject this form. Each block may have at most 4,096 register phis,
with at most 65,536 combined inputs. Initial copies execute after the
preheader. Each latch emits simultaneous header copies before its `continue`;
only an actual exit edge emits cleanup copies before `break`. A conditional
latch evaluates its predicate before either edge's copies can change values
read by that predicate. An interior repeat guard emits header copies only
inside its `continue` arm; its sibling emits the next subtree without those
copies, so later predicates and side effects keep their original values.

For example, a header dispatching to `retry` or `finish` can have `retry`
unconditionally repeat and `finish` conditionally repeat or exit. Header phi
inputs must then be exactly `{preheader, retry, finish}`, while cleanup phi
inputs must be exactly `{finish}`. Neither the `retry` branch nor its phi
copies execute on the `finish` path.

For example, `retry_now` may branch either to the header or to a second
dispatcher that chooses `retry_later` or `finish`. All three sources supply
header phi inputs alongside the preheader. If only `finish` can leave the
loop, it alone supplies the cleanup phi input. The `retry_now` predicate is
evaluated once, and only its repeat edge receives its header copies.

The cleanup contains at most 64 blocks and every path ends in an explicit
return. It may be a disjoint conditional decision tree: each conditional has
two distinct arms, each arm has one exact predecessor, and no blocks are shared
between arms. Only the cleanup head may carry register phis, and those inputs
must exactly cover the conditional exit latches. Other cleanup blocks are
phi-free; linear links are unconditional jumps or fallthroughs. All function
blocks must be uniquely claimed by the preheader, header, loop tree, or cleanup.
The formatter emits the cleanup once after the loop and emits conditional arms
in deterministic true/false order. New `continue` and `break` transfers retain
their source instruction address (block begin for an empty block) and block ID.

Whole-memory or partition phis, side entries, extra exits, switch dispatch,
shared or overlapping loop arms, irreducible flow, malformed edge metadata,
and exhausted bounds are not accepted by this recognizer. All-unconditional
trees without a proven exit and nonreturn exits (including `throw`,
`rethrow_current_exception`, and `exception_unhandled`) remain unsupported.
Cleanup joins, shared terminal returns, side entries, and register phis after
the cleanup head also remain unsupported. Shared in-loop subtrees, including
merges between repeat-guard siblings, remain unsupported even when their header
inputs are complete. Those shapes continue through the existing
region/state-machine/explicit-goto formatters; no partial rendering from this
recognizer is retained.
