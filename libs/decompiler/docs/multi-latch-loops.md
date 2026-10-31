# Bounded multi-latch post-tested loops

The formatter recognizes a bounded post-tested loop with an explicit
preheader, where the conditional header is also the repeat destination. The
header dispatches into a binary tree of conditional dispatches and latch arms.
Each latch has one edge back to the loop header and one edge to the same
terminal return block. A dispatch tree can contain up to 127 dispatch/latch
nodes and 64 latch leaves; each traced path contains at most 64 blocks. The
whole function is limited to 128 blocks.

Before emitting structured output, the recognizer validates the complete CFG:
dispatch branches must match their CFG edges; each path block must have only
its expected predecessor; every latch must be distinct and branch to the loop
header and the same terminal return block; the header and return predecessor
sets must equal the proven latch set; and all function blocks must be uniquely
claimed by the loop or its return. Emission follows the original dispatch
tree and preserves each block's address-bearing statements in deterministic
traversal order.

Header register phis are supported only when their predecessor inputs exactly
cover the preheader and every proven latch; terminal-return register phis must
likewise cover precisely the latch set. Whole-memory or partition phis, side
entries, side exits, nonreturn exits, switch dispatch, shared or overlapping
arms, irreducible flow, malformed edge metadata, and exhausted bounds are not
accepted by this recognizer. Those shapes continue through the explicit CFG
fallback. The recognizer accepts only latch leaves in a binary conditional
dispatch tree; arbitrary latch topologies are not inferred.
