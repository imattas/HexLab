# MIPS32 decompiler lifting slice

The typed decompiler IR currently lifts a bounded set of the native little-endian
MIPS32 decoder's integer instructions: `ADDU`, `SUBU`, `AND`, `OR`, `XOR`,
`NOR`, signed and unsigned `SLT`, fixed and variable shifts, `ADDIU`, `SLTI`,
`SLTIU`, `ANDI`, `ORI`, `XORI`, and `LUI`. Writes to architectural `$zero`
are discarded and reads from it become the 32-bit constant zero.

`BEQ`, `BNE`, `BLEZ`, `BGTZ`, `BLTZ`, and `BGEZ` carry typed predicates into
the IR. `LB`, `LBU`, `LH`, `LHU`, and `LW` lift as typed memory reads; signed
byte/halfword reads explicitly sign-extend to the 32-bit destination, and
unsigned reads zero-extend. `SB`, `SH`, and `SW` lift as typed memory writes.
`$zero` destinations are discarded. The existing memory SSA pass tracks these
reads and writes along the recovered CFG.

Analysis retains MIPS branch delay slots as a distinct CFG edge and block. The
decompiler preserves that CFG while ordering the statements so the slot's
effects run before the branch, call, or return. `JAL` and `JALR` write their
decoded link register with the instruction address plus eight before the slot;
the call itself follows the slot. `JR $ra` becomes a return after its slot.
Branch destinations are taken from the post-slot CFG successors. This relies on
the analysis delay-slot edge; incomplete or hand-authored CFGs without that edge
do not receive guessed slot semantics. MIPS `ERET` remains an intrinsic even
though its decoder marks the transfer as return-like; it restores exception
state and is not a function return.

Instructions with effects not represented by the current IR remain explicit
intrinsics. In particular, signed trapping `ADD`, `SUB`, and `ADDI` are not
lowered to wrapping arithmetic. Unaligned merge operations (`LWL`, `LWR`,
`SWL`, `SWR`) are not modeled because they combine byte lanes with the old
register/memory value and depend on endianness. `MULT`, `MULTU`, `DIV`, and
`DIVU` remain explicit typed effects: their two 32-bit inputs retain signed or
unsigned interpretation, and each effect defines fresh HI and LO SSA versions.
No concrete quotient, remainder, or product halves are fabricated. This keeps
division by zero and signed minimum divided by negative one conservative, since
those cases do not provide a portable HI/LO result. `MFHI`/`MFLO` copy the
current special-register value into a GPR, and `MTHI`/`MTLO` copy a GPR value
into HI/LO; these reads and writes participate in SSA versioning. The IR does
not model MIPS pipeline interlocks or hazards around HI/LO, and delay-slot
execution remains represented by the separate analysis CFG edge rather than
by instruction-local semantics. CP0 transfer state and system traps also
remain explicit intrinsics. The current slice therefore does not claim
architectural completion for whole functions containing unsupported effects.
# COP1 lifting

The bounded COP1 S/D/W scalar subset lifts to floating-typed FPR values.
`LWC1`/`SWC1` and `LDC1`/`SDC1` retain 32-/64-bit floating memory types; S and
D arithmetic, comparisons, conversions, and W rounding forms remain named
`mips.*` intrinsics with decoded FPR/FCSR effects and conversion result types.
`BC1T` and `BC1F` produce branches over the selected `mips.fccN` predicate.
The decoder records one delay slot; MIPS analysis owns and orders the slot
through its explicit CFG edge. Intrinsic FCSR condition/flag behavior, IEEE
arithmetic/conversion results, and runtime rounding remain abstract.
