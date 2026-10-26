# Decompiler control-flow structuring

The desktop pseudocode view first lifts supported instructions into typed IR,
converts register assignments to SSA, applies conservative constant folding,
then formats the resulting control flow. The structured formatter handles
nested acyclic two-way conditionals using their nearest common post-dominator
as each region's join. It lowers SSA phi values into edge-specific assignments
and follows multi-block straight-line arms. A simple conditional early return
is also structured, including the case where the return is on the branch's
false edge.
Decision trees whose leaves all return are also structured when each block is
reachable exactly once from the entry, every non-entry block has one incoming
edge, and the leaves are terminal returns. This covers two-return conditionals
and nested return-only branches without requiring a common post-dominator.
Shared return blocks, SSA phis, unresolved edges, and mixed return/non-return
leaves remain on the label/goto path unless another existing recognizer handles
them.

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
phi-free, straight-line arms reconverge at one shared continuation. The formatter
emits each arm as a `case`/`default` body and resumes the loop body at that
continuation, including when it is the latch. Switch edges and arm predecessors
must match the CFG exactly; side entries, side exits, and ambiguous joins retain
the conservative fallback.

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
overlapping child conditionals, side entries, empty arms, extra latches,
conditional continues, or ambiguous join shapes use the state-machine/goto
fallback. A conditional child `break` is accepted when exactly one explicit
branch edge targets that child's exit and the other edge continues the traced
child-body chain. The break block must have no register phi, and the child
exit must have no register phi because values from the header and break edges
are not yet merged. Resolved-edge and memory-phi completeness checks still
apply. Breaks to other blocks, multiple or ambiguous continuations, and
unrecognized side exits retain the fallback. A
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
The tree may contain up to eight latch tails and four nested branch levels.
The header must have exactly the preheader and every latch tail as CFG
predecessors, and every header phi must contain exactly one input for each
predecessor. Each leaf emits its own simultaneous edge copies and `continue`,
so the header condition is reevaluated after every latch. Branches and chains
must have exact recorded edges and unique predecessors; shared latches,
overlapping paths, extra header predecessors, or larger/deeper trees use the
state-machine or explicit label/goto path. Parent and child diamonds use the
same bounded validation: at most 1,024 blocks and 4,096 edges, unique block IDs
and addresses, resolved edges matching recorded block IDs, and complete
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
and memory SSA phis in a bounded linear form. A straight-line setup chain
enters the loop header, a straight-line body ends at one conditional latch,
and the latch branches back to the header or into a straight-line cleanup
chain ending in a return. The header and latch may be the same block. Setup,
body, latch, and cleanup blocks may carry register phis when each phi has
exactly one input for every actual CFG predecessor; function-entry phis are
rejected. Header predecessors must be exactly the preheader and latch, and
each other non-entry block must have exactly its preceding chain block as its
sole predecessor. Initial copies execute after setup, recurrent copies only
on the backedge, and cleanup copies only on the exit edge. Multiple values
use simultaneous copies, including loop-carried swaps. Whole-memory and
per-partition memory phis require the same exact predecessor coverage and
remain analysis-only; partition names must be nonempty and unique per block.

The latch predicate is evaluated into `__hexlab_do_repeat` before recurrent
copies can overwrite header values used by that predicate. The emitted
`do ... while (__hexlab_do_repeat)` preserves either polarity of the original
backedge condition. No header update executes on loop exit. The recognizer
accepts at most 1,024 blocks, 4,096 edges, 4,096 register phis and 4,096 memory
partition phis per block, 65,536 combined register/memory phi inputs, and 64
cleanup blocks. It requires unique block IDs and addresses, exact resolved
edge kinds and target block
identities, complete function coverage, and a terminal return. Body branches,
switches, side entries or exits, multiple latches, extra or duplicated edges,
and malformed phis proceed to the existing region/state-machine/goto paths.

The earlier function-entry post-tested recognizer still requires a phi-free
latch and branches directly to the body entry or a straight-line return path.
Unsupported or ambiguous loop shapes retain lossless explicit gotos.

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
disjoint straight-line path to a return, or converge on one terminal return
join.
An entry switch also accepts phi-free case-target chains where a case falls
through directly into another case target and every chain ends at the same
terminal return. Each target's labels are emitted immediately before that
target's statements, so both direct dispatch and sequential fallthrough enter
the correct block. The recognizer requires disjoint linear chains, exact
predecessors, and no extra blocks; cycles, multiple fallthrough predecessors,
phis, guarded/setup dispatches, and non-return continuations use the existing
region or state-machine formatter.
Shared-join arms receive edge-specific SSA phi assignments and explicit
`break` statements. Conditional or nested arms proceed to the general region
or state-machine formatter. Incomplete tables and dispatches without an
authoritative default continue through the label/goto fallback. This keeps
numbered cases tied to recovered table indexes instead of guessing from
successor order.

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
Return-only decision trees, including nested branches with distinct return
leaves, are covered as structured output; shared or malformed trees continue
to use the explicit fallback.

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

A pre-tested loop-body diamond may contain one further bounded side exit: the
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
