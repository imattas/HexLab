# Bounded multi-latch post-tested loops

The formatter recognizes a small phi-free post-tested loop whose header is
also the repeat destination. It accepts either two conditional latch arms
selected by one conditional dispatch, or exactly three latch arms in a
conditional tree: one entry edge reaches a direct latch arm and the other
reaches a second conditional dispatch with two latch arms. Each arm is a
single-successor straight-line chain ending in a conditional latch.

Before emitting structured output, the recognizer validates the complete CFG:
the dispatch branches must match their CFG edges; each path block must have
only its expected predecessor; all three latches must be distinct and must
branch to the loop header and the same terminal return block; the header and
return predecessor sets must equal the proven latch set; and all function
blocks must be uniquely claimed by the loop or its return. The region is
bounded to 128 function blocks and at most 64 blocks on each traced arm.
Emission follows the original dispatch tree and preserves each block's
address-bearing statements in deterministic traversal order.

Register phis, whole-memory or partition phis, side entries, side exits,
nonreturn exits, internal arm branches, switch dispatch, shared or overlapping
arm blocks, irreducible flow, and exhausted bounds are not accepted by this
recognizer. Those shapes continue through the explicit CFG fallback. This
three-latch form does not generalize to wider dispatch trees or arbitrary
three-latch topologies.
