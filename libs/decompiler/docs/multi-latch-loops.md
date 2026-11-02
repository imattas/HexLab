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
bounded lookahead: a resolved unconditional chain or acyclic conditional graph
whose leaves all return is an exit candidate; other conditional or backedge
paths must pass the full in-loop subtree proof. Cycles, unresolved transfers,
and an exhausted lookahead reject the entire candidate.

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

The cleanup contains at most 64 unique blocks and every path ends in an explicit
return. It may be an acyclic graph with nested conditionals, shared terminal
returns, shared nonterminal cleanup tails, and overlapping joins. Each
conditional has two distinct, exact true/false targets; linear links are
unconditional jumps or fallthroughs. Only conditional exit latches may enter
the cleanup head. Every other cleanup block's predecessor set must equal the
incoming edges discovered inside the cleanup graph. All function blocks must
be uniquely owned by the preheader, header, loop tree, or cleanup.

Every cleanup block may carry register phis when the inputs exactly cover its
original CFG predecessors and destinations are unique. Copies at the cleanup
head execute on the selected loop-exit edge. Copies at an interior cleanup
block execute before its statements, using the actual incoming predecessor ID.
Whole-memory and partition-memory phis are accepted throughout cleanup with
the same exact predecessor proof, nonempty unique partition names, at most
4,096 partition phis per block, and a combined 65,536 input budget including
register phis. Memory tokens are analysis-only; original memory statements
remain in their guarded blocks.

For example, cleanup block `E` may branch directly to shared block `J` or to
`K`, which in turn selects `J` or a separate return. A register phi at `J` must
have exactly the original predecessors `{E, K}`. The direct arm copies the
`E` input before its copy of `J`; the arm through `K` copies the `K` input.
If `J` contains another conditional or cleanup tail, it remains inside those
same guards. Its outgoing edges still use `J` as their original predecessor,
even though the formatter emits two copies of its source text.

The formatter emits cleanup after the loop, duplicating shared tails beneath
their incoming predicates. A selected invocation executes exactly one original
path, so copied side effects are neither hoisted nor repeated on that path.
Before output begins, expansion is checked against 4,096 block occurrences,
64 occurrences of any one block, and 64 blocks on a path. Conditional arms emit
in deterministic true/false order. New `continue` and `break` transfers retain
their source instruction address (block begin for an empty block) and block ID.

Whole-memory or partition phis outside cleanup, external side entries, extra
exits, switch dispatch, shared or overlapping loop arms, irreducible flow, malformed edge metadata,
and exhausted bounds are not accepted by this recognizer. All-unconditional
trees without a proven exit and nonreturn exits (including `throw`,
`rethrow_current_exception`, and `exception_unhandled`) remain unsupported.
Cleanup cycles, malformed phis, and expansion beyond the stated budgets remain
unsupported. Shared in-loop subtrees, including merges between repeat-guard
siblings, remain unsupported even when their header
inputs are complete. Those shapes continue through the existing
region/state-machine/explicit-goto formatters; no partial rendering from this
recognizer is retained.

The November 2 cleanup-DAG extension is verified by Windows and WSL library
builds and static review only; no tests were added or run in that session.
