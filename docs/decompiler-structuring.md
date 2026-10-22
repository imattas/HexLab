# Decompiler control-flow structuring

The desktop pseudocode view first lifts supported instructions into typed IR,
converts register assignments to SSA, applies conservative constant folding,
then formats the resulting control flow. The structured formatter handles a
two-way conditional whose arms are straight-line chains ending at one shared
join. It also handles a simple conditional early return, including the case
where the return is on the branch's false edge.

Two reducible loop forms are structured: a pre-tested `while` with one
conditional header, a single-successor chain of straight-line body blocks, and
a terminal exit; and a post-tested `do ... while` with a single body block and
conditional latch.
The post-tested form supports the loop edge on either condition arm and inverts
the displayed condition when needed. A `while` header phi with exactly one
preheader input and one back-edge input is lowered to assignments before and
at the end of the loop body. For multi-block bodies, the recurrent value comes
from the final latch block even when the CFG block array is shuffled. Side
exits, internal body branches, multiple latches, and unsupported loop-carried
phis retain explicit gotos.

Join-block SSA phi nodes are lowered into register-version assignments at the
end of each corresponding arm. Blocks are resolved by address, so the block
array order does not affect the output. More complex loops, nested conditionals,
switches, multiple joins, irreducible flow, or phis outside a supported join
retain the explicit label/goto output and report a fallback reason. It does
not present these cases as reconstructed C source.

The focused `decompiler` test covers a canonical diamond, SSA edge copies,
multi-block arms with shuffled storage order, true- and false-edge early
returns, pre-tested while loops with single- and multi-block bodies,
loop-header SSA copies from the actual latch, post-tested do-while loops, and
conservative side-exit and malformed-phi fallbacks.
