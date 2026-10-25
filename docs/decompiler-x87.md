# x87 lifting and compare branches

The common non-popping real arithmetic forms `FADD`, `FMUL`, `FSUB`,
`FSUBR`, `FDIV`, and `FDIVR` lift to 80-bit typed SSA expressions for the
register and supported memory-source encodings. `FCHS` and `FABS` lift as
unary updates to `ST(0)`. These expressions describe the numerical operation;
the current IR does not model x87 precision-control rounding or arithmetic
exception flags. Other transcendental, rounding, integer-conversion, and
stack-changing forms remain named intrinsics with their decoded register,
memory, status, and tag effects. The lifted intrinsic also preserves the
decoder's logical x87 stack depth delta. Pseudocode marks pushes and pops
explicitly. Because ST(i) is relative to TOP, a push or pop reads and
invalidates all eight logical stack registers in SSA; this prevents values
from being incorrectly carried across a stack rotation. The concrete
ST(i)-to-physical-register permutation and TOP/tag values remain opaque.

The decoder reports `FCOMI`, `FUCOMI`, `FCOMIP`, and `FUCOMIP` as reads of two
80-bit stack registers, writes to x87 status, and writes to EFLAGS. The
decompiler preserves each instruction as an `x87_<mnemonic>` intrinsic, so the
numeric comparison and its floating exception behavior remain explicit effects.

When a later x86 conditional branch uses those flags, the lifted predicate
reads the SSA version of EFLAGS written by the compare. The predicate uses
the architectural x87 compare result mapping: CF represents less or unordered,
ZF represents equal or unordered, PF represents unordered, and SF/OF are
cleared. This preserves cases such as `JE` accepting equal or unordered
results, `JP` accepting only unordered results, `JB` accepting less or
unordered, and `JA` accepting only greater.

Legacy `FCOM`, `FUCOM`, and their popping forms also flow through `FNSTSW AX`
and `SAHF`. The branch pass carries that proven sequence through acyclic CFG
edges and identical joins, tracks the `AX` copy, and derives `JB`, `JAE`, `JE`,
`JNE`, `JBE`, `JA`, `JP`, and `JNP` from the copied C0/C2/C3 bits in CF/PF/ZF.
Conditions involving SF or OF are left without a reconstructed predicate:
SAHF writes SF from FSW.B and preserves the previous OF value. Unrelated AX,
FSW, or EFLAGS writes and calls invalidate the propagated state.

Compare values and floating exception behavior remain opaque; branch recovery
only interprets the architecturally defined condition bits. The pass does not
distinguish `FCOM` from `FUCOM` exception signaling, model x87 TOP or concrete
logical stack rotation (although push/pop depth is retained), or make
rounding/exception state precise for arithmetic.
