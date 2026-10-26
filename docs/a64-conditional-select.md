# AArch64 conditional selects

The A64 decoder supports the integer `CSEL`, `CSINC`, `CSINV`, and `CSNEG`
instructions in both 32-bit `W` and 64-bit `X` forms. Each instruction keeps
its condition code and three register operands. The disassembly formatter emits
the condition mnemonic (`eq`, `ne`, `cs`, `cc`, `mi`, `pl`, `vs`, `vc`, `hi`,
`ls`, `ge`, `lt`, `gt`, `le`, `al`, or `nv`). Register 31 is formatted as the
appropriate zero register.

The selected result is `Rn` when the NZCV condition holds. Otherwise it is
`Rm` for `CSEL`, `Rm + 1` for `CSINC`, bitwise `NOT Rm` for `CSINV`, or
two's-complement `-Rm` for `CSNEG`. Arithmetic and bitwise transformations use
the instruction's width, so the 32-bit forms wrap at 32 bits. These
instructions do not change NZCV. `AL` and `NV` are treated as always true and
do not read NZCV; all other conditions read the current NZCV value.

The lifter represents the operation as a typed conditional expression. When a
preceding comparison can be propagated safely, the condition may be rendered
from that comparison; otherwise the expression refers to the current NZCV
state. The existing bounded comparison propagation also carries conditional
compare results through compatible control-flow predecessors. This feature
covers the integer conditional-select family; floating-point conditional
select instructions are outside its scope.
