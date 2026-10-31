# Post-tested loop exit paths

The native control-flow formatter now recognizes a bounded straight-line path
after the exit edge of a canonical post-tested loop. The path may contain up to
64 blocks and must end in one explicit terminal return. Intermediate blocks
must be phi-free, memory-phi-free, and contain only simple statements followed
by at most one unconditional jump or fallthrough to the next block.

Each exit-path block must have exactly one predecessor: the loop latch for the
first block and the preceding exit block for each later block. The path cannot
re-enter the loop body, share blocks with it, or leave any function block
unaccounted for. A path that fails these checks keeps the existing conservative
state-machine or label/goto output.

When accepted, the formatter emits the loop first, then emits each exit-path
block once in sequence. It omits only the terminal unconditional transfers
between those adjacent blocks; the return remains attached to its original
terminal block. Register phis, memory phis, conditional exits, and shared exit
continuations remain unsupported by this recognizer.

The exit cleanup may instead end in one conditional whose true and false arms
each follow a bounded phi-free straight-line path to a terminal return. The
paths may share only that final return block. Its complete predecessor set must
be exactly the two arm tails (or the conditional itself for a direct arm), and
the return block must have no register or memory phis. The formatter duplicates
the shared terminal return into both guarded arms, keeping each path's
statements and return under its original predicate. Other shared blocks, side
entries, and incomplete predecessor sets retain the existing fallback.
