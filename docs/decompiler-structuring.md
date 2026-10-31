# Decompiler control-flow structuring

The desktop pseudocode view first lifts supported instructions into typed IR,
converts register assignments to SSA, applies conservative constant folding,
then formats the resulting control flow. The structured formatter handles
nested acyclic two-way conditionals using their nearest common post-dominator
as each region's join. It lowers SSA phi values into edge-specific assignments
and follows multi-block straight-line arms. A simple conditional early return
is also structured, including the case where the return is on the branch's
false edge.
Single-exit functions and direct entry early-return guards try this local-join
structuring before return-tree expansion. This keeps a nested diamond's shared
continuation and its effects together instead of duplicating them into each
arm. If the bounded region recognizer cannot handle the graph, the larger
return-tree recognizer remains available.
Decision trees whose leaves return are structured without requiring a common
post-dominator. The same recognizer accepts explicit CIL `throw`, `rethrow`, and
unhandled-exception terminal transfers as non-returning leaves. It does not
infer non-return behavior from calls, unknown intrinsics, or empty exits. Their
nodes may be nested two-way conditionals, complete multiway switches, or
single-successor cleanup blocks. Shared terminal leaves and nonterminal return
subtrees may be duplicated under their incoming guarded paths when every CFG
predecessor is represented in the tree, fan-in is at most 64, and each register
or memory phi has exactly one input for every actual predecessor. Phi copies
are lowered for the incoming edge at each expansion. Unresolved edges,
incomplete switch metadata, cycles, external side entries, and other mixed
return/non-return leaves retain the fallback unless another existing
recognizer handles them. These decision trees use iterative validation and
emission, so nesting depth does not consume recursive C++ stack frames. The
recognizer accepts up to 4,096 blocks, 4,096 edges, and switch cases, 65,536
expanded block occurrences and phi copies, and 262,144 emitted instruction
copies. A path may be as deep as the block bound; indentation stops increasing
after 256 spaces. Larger or malformed trees retain the fallback.

Ghidra's native C++ decompiler is a useful architectural reference for this
stage. Its `blockaction.cc` tracks loop heads, tails, and loop containment, then
uses branch-path tracing and explicit goto edges when a graph cannot be
collapsed into structured regions. HexLab follows the same decomposition
principle while validating the exact CFG predecessors and SSA phi inputs needed
by each emitted region. The implementation is independent; this is a behavioral
reference, not copied source. See
[Ghidra's native block structuring implementation](https://github.com/NationalSecurityAgency/ghidra/blob/master/Ghidra/Features/Decompiler/src/decompile/cpp/blockaction.cc).

Whenever a structured edge carries more than one register-phi value, the
formatter captures every incoming source in a temporary before assigning any
destination. This preserves simultaneous SSA updates, including swaps, in
switch arms, nested early-return joins, acyclic conditional regions and the
simple two-arm fallback. The state-machine formatter uses the same parallel
copy rule on every block transition.

Reducible loop output includes canonical pre-tested `while` and post-tested
`do ... while` forms. A pre-tested loop has one conditional header and a
straight-line body chain. The chain can contain a conditional `break`, a
conditional edge back to the header rendered as `continue`, and a nested
canonical pre-tested loop whose exit rejoins the parent body. These conditional
transfers must be unambiguous. The nested loop body can contain the conditional
diamonds described below, joined by straight-line chains. The parent continuation is emitted after the loop,
preserving common cleanup and result code that precedes the return. The
post-tested form supports the loop edge on either condition arm and inverts the
displayed condition when needed. Its body may also contain a bounded switch whose
phi-free, straight-line arms reconverge at one shared continuation. Register
phis at that continuation are accepted when each input exactly matches one
case-tail predecessor; simultaneous copies execute in the corresponding case
before `break`. The formatter resumes the loop body at the continuation,
including when it is the latch. Switch edges and arm predecessors must match the
CFG exactly; side entries, side exits, memory phis, and ambiguous joins retain
the conservative fallback.

A post-tested loop's exit cleanup may end in one terminal conditional whose two
arms are bounded straight-line paths ending in explicit returns. Direct return
arms remain supported. Each arm path is capped at 64 blocks, phi-free (including
memory-partition phis), and every block must have exactly its preceding cleanup
block as its CFG predecessor. The loop exit must enter the cleanup chain
uniquely; the conditional must have exactly the two validated arm edges, and the
arm paths cannot share blocks, except that they may converge on one terminal
return block. That shared block must have exactly the two arm tails as
predecessors and no register or memory phis; it is duplicated into each guarded
arm. The formatter emits the cleanup chain once after the `do ... while`, then
emits the conditional and each return path. Additional cleanup branches, other
shared blocks, cleanup joins, side entries, and non-return leaves retain the
existing fallback.

Pre-tested loop-header SSA phis are lowered from the unique preheader and every
recognized backedge. Initial copies execute before the loop; recurrent copies
execute on the corresponding continue edge or at the normal latch. This keeps
multiple recognized backedges distinct. When an edge supplies multiple phi
values, temporary values capture every source before any destination is
assigned, preserving simultaneous SSA updates such as loop-carried swaps.
The nested-loop recognizer requires a single child latch and a unique
preheader edge into the child header. Child-header phis are lowered as
parallel initial copies on that preheader and parallel recurrent copies at the
latch. Child-exit phis are supported when the only incoming edges are the
child header's condition-failure edge and recognized conditional-break edges.
Each phi must have exactly one input for every such predecessor. The formatter
emits those copies on the corresponding `break` edge, using parallel copies
when several values are merged; it does not assign exit values on paths that
remain inside the child loop. A child body may contain sequential conditional
diamonds with two disjoint, nonempty,
multi-block straight-line arms and a shared join. Every arm block must have
exactly its preceding arm block (or the branch for an arm's first block) as
its sole predecessor. Each join must have exactly those two arm tails as
predecessors; its register phis are lowered into simultaneous edge copies at
the ends of the corresponding `if`/`else` arms. The branch's conditional-true
and conditional-false/fallthrough successor edges must resolve to its explicit
true and false target addresses, including any recorded target block IDs.
After the arms are emitted,
the join is visited once and can continue the child-body chain or begin the
next sequential diamond. Joins without register phis are accepted as well;
tracing cuts both arms at their first shared block rather than requiring a phi
or another branch to mark the continuation. A child region has one entry from
its header and cannot absorb blocks already owned by its parent. Nested or
overlapping child conditionals, side entries, empty arms, extra latches, or
ambiguous join shapes use the state-machine/goto fallback. A conditional child
`break` is accepted when exactly one explicit branch edge targets that child's
exit and the other edge continues the traced child-body chain. The break block
must have no register phi, and the child
exit must have no register phi because values from the header and break edges
are not yet merged. Resolved-edge and memory-phi completeness checks still
apply. Breaks to other blocks, multiple or ambiguous continuations, and
unrecognized side exits retain the fallback. A child-body conditional
`continue` is also accepted when exactly one explicit branch edge targets the
child header and the other edge advances the traced straight-line body chain.
The header's register phis must contain exactly one preheader input and one
input for every recognized continue edge and the ordinary latch edge; each
back-edge copy is emitted immediately before its corresponding `continue` or
the latch transfer. Conditional continues nested inside child diamonds,
continue paths through side blocks, and other unrecognized back edges retain
the fallback. A guarded return path from a pre-tested parent loop may end in a
terminal return block with register phis when that return has exactly one CFG
predecessor: the previous cleanup block or the guarded branch for a direct
return. Every phi must have exactly one input from that predecessor, and the
formatter emits parallel copies immediately before the return inside the
guard. Intermediate cleanup blocks remain phi-free; malformed or multiply
entered return blocks retain the fallback. A
pre-tested parent loop can also
contain a one-level conditional diamond when each arm is a disjoint, phi-free
straight-line chain ending at the same continuation; one arm may be empty when
its branch edge targets the continuation directly. The continuation must have
exactly those two arm tails as predecessors (the conditional branch itself is
the tail for an empty arm), and every nonempty arm block must have exactly its
expected incoming edge. It may contain SSA phis when each phi has exactly one
input from each tail; the formatter emits those edge copies at the end of the
corresponding `if`/`else` arm, including on a direct branch-to-continuation
edge, then emits the continuation once. A parent-loop arm may also contain up
to eight recursively nested conditionals whose arm joins converge at the same
outer continuation. At each level the continuation has exactly three incoming
edges: the two inner arm tails and the current outer sibling tail. Its phis
must contain one input for each edge; inner-edge copies are emitted in the
nested `if` arms and the sibling-edge copy is emitted in the enclosing arm.
Each nested branch must have a single predecessor, and the full region must
have disjoint arms with validated edges and memory phis. Deeper nesting, shared
arm blocks, and ambiguous joins retain the state-machine or goto fallback.

A pre-tested parent loop accepts a bounded conditional decision tree whose
leaves follow disjoint, phi-free unconditional chains back to the loop header.
At most 64 distinct latch tails are accepted. Every tail must be an exact
predecessor of the header, and the header predecessor set must equal the
preheader plus all of those tails. Every header phi must contain exactly one
input for each predecessor. Each leaf emits its own simultaneous edge copies
and `continue`, so the header condition is reevaluated after every latch.
Branches and chains must have exact recorded edges and unique predecessors;
shared latches, overlapping paths, extra header predecessors, and malformed
phis use the state-machine or explicit label/goto path. Parent and child
diamonds use the same bounded validation: at most 1,024 blocks and 4,096
edges, unique block IDs and addresses, resolved edges matching recorded block
IDs, a 64-level nested-child depth budget, and complete
whole-memory and partition-memory phi predecessor inputs on the consumed
region. The prepass rejects loop-diamond structuring for functions with more
than 65,536 combined whole-memory and partition-memory phi inputs, and each
block is limited to 4,096 partition phis. Multiple register-phi values use
parallel copies, preserving simultaneous updates.
General nested SSA joins, overlapping latch paths, and side exits that are not
a recognized child `break` retain the conservative fallback.
It can also contain a complete switch dispatch when every distinct target
follows a bounded, phi-free straight-line path to one shared continuation.
Each case path stays inside the loop, emits once, and ends with a switch
`break`; the common continuation remains in the parent loop chain and emits
once after the switch. Incomplete metadata, unresolved or extra CFG edges,
conditional/cyclic case paths, and paths that leave the loop use the explicit
label/goto path.
One or more case arms may instead end in a terminal return while the remaining
arms converge on that shared loop-body continuation. The returning arm may
start at its case target and contain a phi-free straight-line chain followed
by one terminal return. Every block on that arm, including the return block,
must have exactly its preceding arm block as its only predecessor (the switch
dispatch is the predecessor of the first block). Return arms are emitted
inside their case without a switch `break`; continuing cases retain the normal
switch break. A switch with only returning arms, shared return blocks, phis in
the return path, or a return path with another predecessor keeps the existing
state-machine or label/goto fallback.
Post-tested loops can also contain a sequence of one-level conditional diamonds
before the latch. Each branch arm must be a disjoint phi-free straight-line
chain, both arms must reach the same block, and the join must have exactly the
two arm tails as predecessors. The formatter emits each arm inside `if`/`else`
and emits the join once. One arm may contain a single nested conditional
diamond. Its two disjoint arms may reconverge at an inner join before the outer
join, or reach the outer join directly alongside the sibling arm. A distinct
inner join may continue through a straight-line chain to the outer join. Each
consumed join requires exactly its actual CFG predecessors, and each register
phi requires exactly one input from every such predecessor. The formatter
emits parallel register-phi copies on those predecessor edges before emitting
the join once. Side entries, side exits, overlapping arms, deeper nesting,
unresolved or extra edges, and memory-phi ambiguity retain the state-machine
or explicit label/goto fallback. The recognizer is bounded to 1,024 blocks
and 4,096 edges.

Post-tested loops with an explicit preheader also accept loop-carried register
and memory SSA phis in a bounded form. A straight-line setup chain
enters the loop header, a mostly straight-line body ends at one conditional latch,
and the latch branches back to the header or into a straight-line cleanup
chain ending in a return. The header and latch may be the same block. Setup,
body, latch, and cleanup blocks may carry register phis when each phi has
exactly one input for every actual CFG predecessor; function-entry phis are
rejected. Header predecessors must be exactly the preheader and latch, and
each other non-entry chain block must have exactly its preceding chain block as its
sole predecessor, except for validated diamond joins. After the loop header,
the body may contain a sequence of `if`/`else` diamonds: each arm follows at
most 64 disjoint straight-line blocks and both
arms converge at one join, which may be the latch. Arm blocks have exactly
their preceding edge as predecessor, and the join has exactly the two arm
tails as predecessors. Register phi copies execute on each actual branch,
arm, and join edge before the shared join is emitted once. Initial header
copies execute after setup, recurrent copies only
on the backedge, and cleanup copies only on the exit edge. Multiple values
use simultaneous copies, including loop-carried swaps. Whole-memory and
per-partition memory phis require the same exact predecessor coverage and
remain analysis-only; partition names must be nonempty and unique per block.

A body conditional may also leave through a return-only decision tree of at
most 64 blocks while its other edge continues toward the latch. Multiple such
regions may occur in sequence and may mix with the body diamonds.
The tree may contain straight-line blocks and nested two-way conditionals;
every leaf ends in a terminal return. A nonterminal block may be reached by
multiple branches inside the same tree when all of its actual CFG predecessors
are represented in that tree. The formatter expands that shared block at each
guarded path and lowers its register phis using the path's exact incoming edge;
each expansion counts toward the 64-block budget. Edges back to an ancestor,
external predecessors, and blocks already claimed by another region remain
unsupported. Every nested branch has two resolved, distinct successors
matching the true and false edges. Terminal returns may be shared by multiple
guarded side arms or by a side arm and the
ordinary loop-exit cleanup. Every actual predecessor of a shared terminal
return must be one of those recognized edges, with an exact SSA phi input.
The formatter emits
the tree only under the original side-return predicate, preserves each nested
branch polarity, and lowers register phi copies on each actual incoming edge.
It lowers the continuing edge before the remaining loop body. Each shared
terminal return is emitted on its selected path after that edge's phi copies;
only one such path executes. Shared blocks across separate side-return trees,
other joins, cycles, and unrecognized side entries retain explicit flow.

Each accepted conditional region records its branch and unique continuing
block on the body spine. All arms and nonterminal return-tree blocks must be
disjoint from previously claimed blocks. Every region must lie inside the loop, and its join
or continuing block must be the next spine block. Exact diamond-join
predecessors replace the ordinary single-spine-predecessor rule only at that
join. The formatter emits each body branch once, copies each arm's phi inputs
on its own edge, and emits the continuing join once before handling the next
region. A join may itself begin the next diamond or guarded return, and the
last join may be the latch. This avoids losing updates when multiple regions
carry different register or memory SSA versions. Region count shares the
existing whole-function block/edge/phi budgets; the 64-block limits apply to
each arm and each return tree.

The latch predicate is evaluated into `__hexlab_do_repeat` before recurrent
copies can overwrite header values used by that predicate. The emitted
`do ... while (__hexlab_do_repeat)` preserves either polarity of the original
backedge condition. No header update executes on loop exit. The recognizer
accepts at most 1,024 blocks, 4,096 edges, 4,096 register phis and 4,096 memory
partition phis per block, 65,536 combined register/memory phi inputs, and 64
cleanup blocks. It requires unique block IDs and addresses, exact resolved
edge kinds and target block
identities, complete function coverage, and a terminal return. Nested or overlapping
body branches, switches, nonterminal side entries or ambiguous exits, other multi-latch shapes,
extra or duplicated edges,
and malformed phis proceed to the existing region/state-machine/goto paths.

Explicit-preheader post-tested loops also accept bounded nested body-decision
trees when every nested conditional reconverges at the same validated body
join. Each nested arm may contain a disjoint linear chain or another
conditional tree; all leaf predecessor edges into the common join are checked
against the exact register and memory phi inputs. The formatter emits nested
`if` regions in place and lowers each leaf's copies on its own edge before
emitting the shared join once. Decision trees are limited to depth 32 and 64
blocks per outer arm. Trees with an intermediate join followed by more body
instructions, shared/side-entered leaves, return leaves, cycles, switches,
overlaps, or non-exact phi inputs retain the existing fallback output.

The function-entry post-tested recognizer accepts a bounded, phi-free straight-
line cleanup chain on the repeat edge. It emits this form as `while (true)` with
the latch predicate guarding the cleanup and an explicit `continue`; the other
edge still follows the validated exit path. The chain is limited to 64 blocks,
requires exact single-predecessor links through to the body entry, and cannot
contain memory/register phis, branches, switches, returns, or side entries.
Unsupported or ambiguous loop shapes retain lossless explicit gotos.

A bounded function-entry post-tested form accepts disjoint body arms ending in
their own conditional latches. Two-arm and three-arm dispatches retain their
specific recognizers; a general conditional decision tree now handles four to
64 latch leaves. Each latch must branch directly to the function-entry loop
header or to one shared phi-free exit chain ending in a terminal return. The
exit chain may contain at most 64 single-predecessor straight-line blocks; its
first block's predecessor set and the header predecessor set must exactly equal
the distinct latch blocks. Every function block must belong to the dispatch
tree, one latch path, or that exit chain.
Every tree and arm edge is checked against its recorded CFG predecessor and
successor, each non-latch block must have one predecessor, and paths cannot
share blocks. Each arm path is limited to 64 blocks including its latch, tree
depth is below 64, and the whole function is limited to 128 blocks and 4,096
edges. The formatter emits the decision tree inside `do { ... } while (true)`
and lowers each latch condition to `continue` or `break`. Register and memory
phis in the exit chain, side entries, additional exits, non-return exits,
overlapping arms, malformed edges, incomplete block coverage, and larger
graphs retain the existing fallback.

An explicit-preheader post-tested loop may also use a bounded nested body-
dispatch tree whose leaves end in distinct conditional latches. Each latch must
target the dispatcher header on one edge and the same terminal-return block on
the other. Internal dispatches and linear arm paths must have exact single-
predecessor links; the complete function must be covered by the preheader,
header, dispatch tree, latches, and one return block. The tree is limited to 64
latch leaves, 127 branch nodes, and at most 64 nodes along any dispatch path
(including its latch leaf); each linear path is capped at 64 blocks, and the
complete function at 128 blocks and 4,096 edges. Header
register phis must have exactly one initial input from the preheader and one
recurrent input from every latch. Return-block register phis must match exactly
the latch edges. The formatter emits the preheader once, applies initial phi
copies, then emits each latch's repeat or exit copies before `continue` or
`break`. Memory phis, shared paths, extra exits, side entries, non-return exits,
and malformed edge/phi sets retain the existing lossless fallback.

The acyclic structurer also handles nested regions with multiple explicit
terminal returns. An analysis-only virtual exit supplies post-dominators for
terminating arms; it does not add a source return or move instructions between
paths. This allows a shared SSA diamond followed by a return choice, an early
return before a nested diamond, and straight-line setup before those regions.
Shared instructions appear once, and register phi copies execute on their
incoming edges, including single-predecessor terminal arms. Every terminal arm
in a multi-exit function must end in an explicit return. A nested early-return
arm may share a terminal return continuation with its outer sibling; the
formatter emits that continuation once and lowers its phi copies on both actual
edges. Side effects in the nested arm stay before its condition, and effects in
the shared block stay after both paths converge. Other cross-region sharing
that would require duplicating a nonterminal conditional remains on the goto path.
One important shared-region shape is factored when a nested conditional has an
early-return arm and its sibling reaches the same later conditional: the early
return is emitted as a guarded exit, and the common conditional and its return
arms are emitted once afterward. This bounded recognizer requires a
straight-line outer sibling and terminal returns from the shared conditional;
more complex shared nonterminal regions still use explicit gotos.

The acyclic structurer requires every block to be reachable,
valid in-function edges, and complete register, whole-memory, and
partition-memory SSA phi inputs for every predecessor. Partition names must
be nonempty and unique within a block. Across the function, at most 65,536
register and memory-phi inputs are accepted; each block is limited to 4,096
register phis and 4,096 partition-memory phis. Malformed or over-budget phi
data uses the state-machine or explicit label/goto fallback. It
also accepts complete switch dispatches within conditional regions or other
switch arms. It finds the nearest common post-dominator of all distinct case
and default destinations, groups labels that share one destination, emits each
region once, and lowers phi values on the actual incoming edges. Case arms can
contain nested conditionals and switches and can converge on a nonterminal
continuation. Sharing that cannot be represented by nested regions moves to
the state-machine formatter rather than duplicating an original block.
It limits post-dominator analysis to 1,024 blocks and 4,096 edges to bound memory use. Blocks are
resolved by address, so block-array order does not affect the output. Cycles,
cross-region sharing that would require duplicating code, and irreducible flow
leave this region formatter for the state-machine formatter. Unterminated
multi-exit arms and malformed edge/phi data retain the explicit label/goto
output and report a fallback reason.

When nested regions cannot represent a valid direct CFG without duplicating
blocks, the formatter emits a bounded state-machine form: one `while` loop
dispatches on a block ID, and each case emits exactly one original block. A
direct edge assigns the target block ID and continues; a conditional edge
keeps the original condition and chooses between the two targets. Complete
multiway metadata emits a nested selector switch whose cases perform those
same transitions. This supports switches inside nested or irreducible loops,
cyclic case paths, and overlapping case continuations while each original
block's instructions remain in exactly one dispatch state. Register
phi copies are emitted simultaneously on the corresponding transition, so side effects and
edge values remain attached to their original blocks and edges. This covers
irreducible cycles and cross-region sharing without duplicating a shared
block. The formatter accepts at most 1,024 reachable blocks and 4,096 edges,
requires valid terminal direct branches and complete register/memory phi
inputs, rejects entry phis because the initial dispatch has no predecessor
edge, and requires every exit block to return without a successor edge.
Indirect branches without complete switch metadata, malformed or unresolved edges, unreachable blocks, and
unsupported terminal behavior still use the explicit label/goto fallback.

The desktop pseudocode path attaches recovered switch-table selector and case
index metadata to the corresponding lifted dispatch block. A default is only
accepted when the table analysis is complete and the CFG exposes exactly one
additional destination. The first switch formatter handles a complete dispatch
at function entry, after a proven straight-line setup chain, or after a direct
conditional guard with one terminal-return arm. Guarded dispatch requires a
phi-free return block and a phi-free single-successor setup chain into the
switch; it keeps setup and guard effects in their original order and nests the
switch only on the non-returning path. Prefix blocks must have no phis and one
unambiguous successor each. Distinct case/default arms must each follow a
disjoint straight-line path to a return, or converge on one shared linear
suffix ending in a terminal return.
An entry switch also accepts case-target chains where a case falls through
directly into another case target. Chains may terminate separately or merge
into a common linear suffix ending at a terminal return. Every shared block
must occur at the same suffix position on every path. The recognizer requires
exact predecessor/phi coverage and no unrecognized blocks; cycles, branched
suffixes, guarded/setup dispatches, and non-return continuations use the
existing region or state-machine formatter.
Shared-join arms receive edge-specific SSA phi assignments and explicit
`break` statements. Conditional or nested arms proceed to the general region
or state-machine formatter. The fast path also accepts a common linear suffix
after the switch join, provided each path shares exactly the same suffix and
it ends in a terminal return. It validates register-phi inputs for every
path-edge and emits the corresponding parallel copies inside each case or
once along the common suffix. Whole-memory and partition-memory phis must
also have exactly the derived predecessor inputs; these internal tokens need
no extra C statement because the original memory operations remain in place.
Branched or side-entered suffixes, malformed phi inputs, and unrecognized
blocks retain the region/state-machine fallback. Incomplete tables and
dispatches without an authoritative default continue through the label/goto
fallback. This keeps numbered cases tied to recovered table indexes instead
of guessing from successor order.

All switch metadata is validated before any structuring path consumes it.
Every case value must be unique, the selector and default must be present,
and the distinct case/default destinations must exactly match the resolved CFG
edges and block identities. The entire function is limited to 4,096 case labels
and 4,096 edges when it carries switch metadata; register and memory phis must
have exactly one value for every CFG predecessor, with at most 65,536 phi
inputs overall. A terminal unconditional
indirect branch is removed only when that validated metadata supplies its
dispatch; unrelated indirect transfers retain explicit gotos. Complex entry
switches are allowed to proceed from the straight-line fast path into the
general region or state-machine formatter.

The pseudocode view also lists uniquely defined SSA values with their saved
name, assigned type when available, and defining instruction address. Selecting
a variable navigates the synchronized disassembly to that definition, which
provides a direct route from a rendered name back to its machine-code origin.
Values with ambiguous or phi-only definitions are omitted from this definition
list, matching the read-only policy of the variable edit actions.

The focused `decompiler` test covers a canonical diamond, SSA edge copies,
multi-block arms and nested diamonds with shuffled storage order, inner and
outer SSA phi copies, true- and false-edge early returns, pre-tested while
loops with single- and multi-block bodies, loop-header SSA copies from the
actual latch, post-tested do-while loops with single- and multi-block
straight-line bodies, and conservative side-exit,
multi-exit, and malformed-phi fallbacks.
In the bounded nested-early-return shape that reconverges on a shared
nonterminal join, the direct early-return block may carry register phis when
its sole actual predecessor is the inner conditional. Their values are copied
in parallel inside the selected arm before the return. Memory phis, duplicate
phi destinations, missing predecessor inputs, and additional return-block
predecessors retain the fallback.
Return-only decision trees, including nested branches with distinct return
leaves, are covered as structured output. They may converge on shared terminal
return blocks when each shared block has at most 64 incoming edges. Register
phis at a shared terminal return are accepted only when every actual
predecessor supplies exactly one input. The formatter duplicates the return
block into each guarded arm and emits that predecessor's parallel phi copies
before the return, preserving path-specific values without creating a shared
merge statement. It also duplicates a shared conditional block when both of
its distinct successors are terminal returns. The block may have up to 64
incoming edges; any register phis must have exactly one input for each actual
predecessor with the same source version on every edge, so phi copies cannot
change the condition's value across copies. Those parallel copies execute
before the duplicated condition.
Whole-memory and partition-memory phis are accepted when
their inputs exactly cover the block's CFG predecessors; these analysis-only
tokens need no source assignment because the original memory operations remain
in their guarded blocks. Partition names must be nonempty and unique, with at
most 65,536 combined memory-phi inputs and 4,096 partition phis per block.
Other shared interior blocks, malformed edges or phis, and higher fan-in
continue to use the explicit fallback.

Canonical pre-tested loops also accept a conditional side edge from a loop-body
branch to a unique return path. The formatter emits the path under the branch
predicate and continues along the other edge inside the loop. A return path may
contain a bounded chain of phi-free blocks with one unconditional jump or
fallthrough each, and must end at a terminal return block. Each path block must
have exactly its preceding branch or path block as its CFG predecessor; blocks
cannot be shared by separate return paths or overlap the loop body. Shared
return blocks, nested loop-side returns, and paths with branches or extra
predecessors remain on the explicit fallback.

The dedicated `decompiler_loop_structuring` test covers a conditional early
break, a conditional continue with distinct header-phi values on the continue
and normal latch edges, nested pre-tested loops with shuffled block order, and
a one-level conditional diamond and complete switch dispatch inside a
pre-tested loop, each with one shared continuation. Incomplete switch
metadata retains the explicit goto fallback.

A pre-tested loop-body diamond may contain nested conditional child bodies up
to 64 levels deep. Discovery, phi validation, ownership checks, and emission
remain recursive, but that explicit depth budget bounds native call-stack use;
the CFG is separately limited to 1,024 blocks and each nested child must claim
distinct blocks. Deeper trees retain the explicit fallback. A diamond may also
contain one bounded side exit: the
final conditional in one outer diamond arm may branch directly to the loop's
already validated exit block while its other edge follows a straight-line path
to the outer in-loop join. The exit block must be phi-free (including memory
phis). The continue path and the outer sibling arm must be disjoint, and the
join must have exactly their two tail predecessors; register phis at the join
must cover those exact edges and are copied in parallel on each edge. The exit
branch itself must have exactly its two resolved conditional edges, and its
break arm must have no side-path blocks or edge assignments. The formatter emits
the break under its original predicate and emits the shared in-loop join once.
Other nested exit targets, side-path assignments, exit phis, extra join
predecessors, or ambiguous ownership retain the existing fallback.

The final nested conditional may also send its break edge through up to 64
phi-free straight-line cleanup blocks before reaching that same validated parent
loop exit. Each cleanup block must have exactly the preceding branch or cleanup
block as its CFG predecessor, one resolved unconditional jump or fallthrough,
and no return, switch, or memory phi. Cleanup statements are emitted only under
the break predicate, followed by `break`; the in-loop arm still reaches the
shared diamond join and keeps its exact edge-specific parallel phi copies.
Cleanup paths cannot overlap the in-loop continuation or sibling arm. Exit
phis, branched or cyclic cleanup paths, side entries, and paths longer than 64
blocks retain the existing fallback.

The dedicated `decompiler_multiexit_structuring` test runs fixtures through SSA,
constant and identity simplification, dead-code elimination, and formatting.
An independent interpreter for the emitted fixture subset checks every branch
combination against literal expected return values and side-effect counts.
Coverage includes shared joins before return choices, early returns around
local joins, a nested early return converging on a shared nonterminal
conditional, shuffled storage, straight-line setup, terminal phi copies, and
lossless fallback for malformed phis, missing returns, cycles, and sharing
across terminating regions. This is a bounded semantic check of those fixtures,
not a general C interpreter or an equivalence proof for arbitrary functions.

Canonical pre-tested loops also accept a conditional break edge that reaches the
loop's validated exit through a straight-line chain of at most 64 phi-free,
side-effect-preserving blocks. A cleanup chain may be shared by multiple
conditional break edges when every edge enters the same head block. That head's
predecessors must be exactly those recognized break branches, and every later
path block must have exactly the preceding path block as its predecessor. All
path blocks have one unconditional jump or fallthrough and no return, nested
branch, switch, or memory phi. The shared exit may contain register phis when
its predecessor set is exactly the loop-header condition failure edge plus one
distinct final edge for each cleanup-chain tail. Multiple source break branches
that share one chain contribute one CFG predecessor at that tail, even though
the chain is emitted under each branch predicate. Every phi has exactly one
input for each actual predecessor. A phi input from a shared tail is copied
after the chain inside each corresponding source break condition; the same SSA
input is valid because the cleanup chain itself has no merge phi. Copies for
the loop-header failure edge execute after the loop condition fails. The formatter emits the shared
exit block once. Different overlapping paths, side entries to later cleanup
blocks, exit memory phis, incomplete or duplicate phi inputs, and other
ambiguous shapes retain the existing fallback. The head-and-tail treatment
follows the region bookkeeping in Ghidra's native
[`LoopBody::mergeIdenticalHeads`](https://github.com/NationalSecurityAgency/ghidra/blob/master/Ghidra/Features/Decompiler/src/decompile/cpp/blockaction.cc#L2975-L3019);
HexLab adds an explicit predecessor and SSA-phi proof before emitting C-like
breaks, and does not copy Ghidra source.

Nested pre-tested child loops accept a cleanup chain of up to 1,024 blocks on a
conditional break edge, matching the enclosing CFG block budget. Cleanup
blocks are phi-free and each ends in one unconditional edge. A chain head may
have only the recognized break branches that use that exact chain as
predecessors; later blocks must have only the preceding cleanup block as their
predecessor. Paths cannot overlap the child body or another claimed region,
except that multiple child break predicates may use the exact same complete
cleanup chain. That chain is emitted under each predicate, while its
shared tail contributes one CFG predecessor and one exit-phi input. Child-exit
register phis are copied in parallel at the final cleanup edge while still
inside the original break condition. The child exit predecessor proof uses the
cleanup tail, so the header's condition-failure edge and every distinct break
tail must exactly account for the exit's phi inputs. Partially overlapping,
branched, or side-entered paths retain the existing fallback. This extends
HexLab's bounded region walk using the
same region-first structuring principle visible in Ghidra's native
[`blockaction.cc`](https://github.com/NationalSecurityAgency/ghidra/blob/master/Ghidra/Features/Decompiler/src/decompile/cpp/blockaction.cc); no Ghidra source is copied.

Nested pre-tested child loops also accept conditional continue edges that pass
through up to 1,024 phi-free cleanup blocks before returning to the child header,
matching the enclosing CFG block budget.
The cleanup chain must be single-entry, unconditional, and free of side entries,
returns, switches, and memory phis. Its final block must be an actual CFG
predecessor of the header. The child header's register phis are validated
against the cleanup tail and ordinary latch edges, and their parallel copies
are emitted after the guarded cleanup statements immediately before `continue`.
Direct conditional continues remain the zero-block case; ambiguous or
side-entered cleanup paths retain the existing fallback.

A nested pre-tested child loop may contain a guarded return-only side path while
its other conditional edge continues along the child body. The return side may
contain up to 64 single-entry, phi-free straight-line blocks and must end in a
terminal return. Its blocks are emitted only under the original branch
predicate; the sibling continuation remains in the child loop's ordinary body
spine. Return paths cannot be shared, re-enter either loop, contain nested
branches or switches, or carry register, whole-memory, or partition-memory
phis. Malformed edges and unrecognized return paths retain the existing
state-machine or label/goto fallback.

Structured acyclic two-arm conditionals also accept a direct edge from either
arm to the common join. The other arm may contain the existing bounded linear
region. Join phis must still have exactly one input for each actual predecessor;
copies for a direct arm are emitted inside that conditional arm. This covers
guarded straight-line work without inventing an SSA predecessor or hoisting
edge-specific copies across the branch.

The general acyclic-region formatter also handles overlapping joins and
side-entered cleanup/return regions by bounded tail duplication. For example,
one outer arm may enter a shared cleanup chain directly while the sibling
branches either into that same chain or into a separate return. The cleanup
may itself contain further conditionals, joins, complete switches, and multiple
return leaves. It need not be a terminal return or a single terminal-decision
block. Each incoming guarded path gets a copy of the shared region until its
nearest common post-dominator; ordinary local joins still emit once after their
own conditional or switch. Duplication never hoists effects out of a predicate,
and only one of the duplicated paths executes on a given invocation.

Every copy receives the actual original CFG predecessor's register-phi values
before its statements execute. Multiple values use simultaneous parallel
copies, including when different side entries select different values. Complete
whole-memory and partition-memory phis remain analysis-only; all original
memory statements stay in their guarded path. Recorded addresses, block IDs,
branch targets, predecessor coverage, and unique register-phi destinations must
validate before this formatter runs. Branch traversal uses explicit true/false
targets and grouped switch metadata rather than block storage order.

This path requires a reachable acyclic graph of at most 1,024 blocks and 4,096
edges, with explicit returns on every leaf of a multi-exit graph. Expansion is
limited to 4,096 emitted block occurrences, at most 64 copies of any one block,
and 64 nested conditional/switch regions. These bounds prevent exponential
source growth and bound the recursive emitter's native stack use. Exceeding a
bound discards the entire partial rendering and uses the existing state-machine
or label/goto fallback. Cycles, unresolved edges, incomplete switch metadata,
and malformed phi inputs retain that fallback as well.
