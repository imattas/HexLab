# Multi-latch loop cleanup DAG

The explicit-preheader multi-latch formatter currently accepts only disjoint
returning cleanup trees. Extend that same recognizer to acyclic cleanup graphs
with shared tails, nested joins, and edge-specific register and memory SSA phis.
This closes a coherent part of `decompiler.structure`; the public interface stays
`format_structured_pseudocode` and its existing lossless fallback.

## Approach and proof boundary

Use a unique-node DAG proof followed by bounded guarded tail duplication. A
postdominator rewrite could reduce output size but would introduce a second
general region structurer inside the loop recognizer. Merely allowing a shared
terminal return would leave nested cleanup joins unsupported. The selected
approach preserves each predicate, statement order, and original incoming edge.

Modify only `libs/decompiler/src/decompiler.cpp`,
`libs/decompiler/docs/multi-latch-loops.md`, and decompiler structuring docs.
The loop proof remains unchanged: one explicit preheader, conditional dispatcher,
2..64 proven latches, one shared cleanup head, disjoint in-loop paths, full
function coverage, at most 128 function blocks and 4,096 edges.

Cleanup has at most 64 unique blocks, all reachable from its head, no cycles,
switches or nonreturn transfers, and an explicit return at every leaf. Only exit
latches enter the head; every other predecessor must belong to the cleanup DAG.
Register phis at every cleanup node cover exactly its CFG predecessors with
unique destinations. Whole-memory and partition phis obey the same predecessor
proof; partition names are nonempty and unique. Retain per-block 4,096 phi bounds
and a combined 65,536 phi-input budget. Memory tokens need no source assignments.
Memory phis elsewhere in this loop shape remain unsupported.

Each copied block receives parallel register copies for its actual incoming
edge before its statements. Head copies remain on loop-exit edges. Cleanup
expansion allows at most 4,096 block occurrences, 64 occurrences per node, and
64 blocks on a path; reject before output if expansion exceeds these bounds.
Shared tails execute only under the selected original predicate. No partial
structured rendering escapes a failed proof.

## Verification and authorization

The ongoing task authorizes implementation without a new approval round and
explicitly prohibits adding or running tests. Verify by static review,
`git diff --check`, and Windows/WSL `hexlab_decompiler` builds configured with
`BUILD_TESTING=OFF`. Record exact commands and outcomes in the plan. Builds prove
compilation/linking only; semantic fixture coverage remains unverified here.
