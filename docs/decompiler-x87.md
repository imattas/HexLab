# x87 lifting and compare branches

The common non-popping real arithmetic forms `FADD`, `FMUL`, `FSUB`,
`FSUBR`, `FDIV`, and `FDIVR` lift to 80-bit typed SSA result expressions for
the register and supported memory-source encodings. Their intrinsic also
retains the FCW input and FSW output dependency, so the numeric expression
does not erase those architectural effects. The output expression currently
does not apply PC/RC rounding or calculate the resulting exception flags;
those values remain explicitly unknown. `FCHS` and `FABS` lift as unary
updates to `ST(0)`. Other transcendental, rounding, integer-conversion, and
stack-changing forms remain named intrinsics with their decoded register,
memory, status, and tag effects. The lifted intrinsic also preserves the
decoder's logical x87 stack depth delta. Pseudocode marks pushes and pops
explicitly. Because ST(i) is relative to TOP, a push or pop reads and
invalidates all eight logical stack registers in SSA; this prevents values
from being incorrectly carried across a stack rotation. The concrete
ST(i)-to-physical-register permutation and TOP/tag values remain opaque.

The processor semantic API has a separate finite-operand FDIV/FDIVR evaluator.
It generates quotient guard/round/sticky bits directly, honors x87 precision
and rounding control, and reuses the arithmetic exception path for gradual
underflow, overflow, and unmasked precision/underflow retirement. It accepts
only finite, nonzero operands; division by zero and infinity/NaN cases remain
outside this evaluator. The decompiler does not yet fold symbolic FDIV
expressions through this concrete helper, so lifted arithmetic still leaves
rounding and exception outputs unknown.

The IR includes exact binary80 literals for `FLD1` and `FLDZ` when their
logical stack output is known. A same-block `FCHS` or `FABS` over one of these
proven literals is folded through the exact processor semantic helper; inputs
that remain register values stay symbolic. `FSQRT` has a typed 80-bit result
with explicit FCW/FSW dependencies. Constant folding accepts a positive normal
literal only when the processor evaluator returns the same result under every
valid precision and rounding setting. FIST/FISTP/FISTTP remain named
memory-writing intrinsics with decoded stack deltas. The lifter has no proven
FCW/FSW values or concrete memory input for these instructions, so it does not
invent a converted store value or claim exception retirement.

`FRNDINT` carries a typed 80-bit rounded-value edge alongside its unknown FSW
output, retaining control/status dependencies and exception effects in the
intrinsic. A literal result folds only when the processor evaluator completes
under all four FCW rounding modes and all produce identical binary80 payloads.
Rounding-sensitive values, unsupported encodings, and unmasked precision
exceptions remain symbolic; folding does not claim a concrete precision flag
or exception retirement.

The decoder reports `FCOMI`, `FUCOMI`, `FCOMIP`, and `FUCOMIP` as reads of two
80-bit stack registers, writes to x87 status, and writes to EFLAGS. The
decompiler preserves each instruction as an `x87_<mnemonic>` intrinsic, so the
numeric comparison and its floating exception behavior remain explicit effects.

For non-popping `FCOMI` and `FUCOMI`, function lifting also exposes an
EFLAGS value formula when incoming TOP and both physical tags prove that the
operands are nonempty. Its condition result distinguishes ordered FCOMI from
FUCOMI's quiet-NaN behavior, consults FCW.IM/DM, and preserves incoming
CF/PF/ZF when an unmasked numeric exception prevents comparison completion.
The formula clears AF/SF/OF and preserves every other incoming flag bit.
FSW remains an unknown parallel output of the effectful intrinsic, and the
existing pending-exception trap edge remains attached to the instruction.

The optimizer can substitute exact same-block binary80 SSA literals into this
formula and evaluate CF/PF/ZF using `evaluate_x87_compare`. With unknown FCW,
it checks all four IM/DM combinations and folds only an identical result;
it never assumes the reset exception masks. An incomplete evaluation also
requires known incoming flags. Quiet NaNs therefore produce unordered for
FUCOMI without assuming invalid masking; FCOMI with NaNs and comparisons
with denormals stay symbolic when mask-dependent. Unknown or empty tags
retain the original opaque flags output. Popping FCOMIP/FUCOMIP remain
opaque because their TOP/tag retirement also depends on completion.

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

Legacy compare values and floating exception behavior remain opaque; their
branch recovery only interprets the architecturally defined condition bits.
General arithmetic rounding/exception state and exception-dependent stack
retirement remain incomplete.

## FLD ST(i) value copies

`FLD ST(i)` retains the source payload as an explicit x87 register-output value while separately preserving the push depth and unknown FSW/FTW outputs. When TOP is proven, the decompiler's existing stack remapper reads the source against pre-instruction TOP and writes the copy to the newly exposed physical slot. Unknown TOP remains represented by the logical stack boundary and does not fabricate a physical placement. This models the copy itself; stack overflow and pending exception delivery remain outside the lifter.

## Constant integer stores

The optimizer can replace the memory value of `FIST`, `FISTP`, or
`FISTTP` with an integer constant when its ST(0) input is an exact,
same-block binary80 SSA constant. It evaluates the conversion across every
FCW invalid/precision mask and rounding-control setting and folds only when all
settings complete and produce identical destination bits. This lets proven
exact conversions reach the stored value without assuming the reset control
word or exception masks.

Only the memory-output value is folded. The memory address, FSW updates, and
FISTP/FISTTP stack retirement remain explicit opaque effects. Fractional,
out-of-range, exceptional, nonconstant, or otherwise mask-dependent inputs
stay symbolic.
