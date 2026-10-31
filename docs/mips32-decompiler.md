# MIPS32 decompiler lifting slice

The typed decompiler IR currently lifts a bounded set of the native little-endian
MIPS32 decoder's integer instructions: `ADDU`, `SUBU`, `AND`, `OR`, `XOR`,
`NOR`, signed and unsigned `SLT`, fixed and variable shifts, `ADDIU`, `SLTI`,
`SLTIU`, `ANDI`, `ORI`, `XORI`, and `LUI`. Writes to architectural `$zero`
are discarded and reads from it become the 32-bit constant zero.

`BEQ`, `BNE`, `BLEZ`, `BGTZ`, `BLTZ`, `BGEZ`, and their conditional-link
`BLTZAL`/`BGEZAL` and likely-link `BLTZALL`/`BGEZALL` forms carry typed
predicates into the IR. The link forms assign `$ra = PC + 8`; likely-link
branches annul the delay-slot edge when their predicate is false. `LB`, `LBU`,
`LH`, `LHU`, and `LW` lift as typed memory reads; signed
byte/halfword reads explicitly sign-extend to the 32-bit destination, and
unsigned reads zero-extend. `SB`, `SH`, and `SW` lift as typed memory writes.
`$zero` destinations are discarded. The existing memory SSA pass tracks these
reads and writes along the recovered CFG.

Analysis retains MIPS branch delay slots as a distinct CFG edge and block. The
decompiler preserves that CFG while ordering the statements so the slot's
effects run before the branch, call, or return. `JAL` and `JALR` write their
decoded link register with the instruction address plus eight before the slot;
the call itself follows the slot. Conditional-link `BLTZAL`/`BGEZAL` and
`BLTZALL`/`BGEZALL` also write `$ra = PC + 8` before their conditional branch;
the likely-link forms execute their delay slot only on the taken path. `JR $ra`
becomes a return after its slot.
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
`LWC1`/`SWC1` and `LDC1`/`SDC1` retain 32-/64-bit floating memory types. S/D
add, subtract, multiply, divide, and square root define typed FPR and FCSR SSA
outputs; the FPR result and post-operation FCSR remain explicit unknown values
because IEEE exception and rounding execution is not modeled in the decompiler.
Their intrinsic operands include the decoded FPR values and incoming FCSR, so
rounding-mode and status dependencies remain visible. S/D/W conversions and W
rounding forms likewise define the correct typed FPR result and an explicit
unknown FCSR result. The sign/move family has exact bit-preserving lowering as
described below.
For all 16 classic S/D `C.<cond>` predicates, the intrinsic retains the
predicate and incoming aggregate FCSR dependency. The selected FCC output is
expressed as symbolic SSA from ordered equal/less/less-equal and unordered
terms, and the post-compare aggregate FCSR is an explicit unknown output for
Cause/Flag behavior. This
allows `BC1T`/`BC1F`/`BC1TL`/`BC1FL` and downstream condition flow to consume the predicate
without relying on host floating-point evaluation. Signaling-NaN exception
details and FCSR Cause/Flag updates remain unevaluated.
These branches produce edges over the selected `mips.fccN` predicate; the branch-likely variants execute the delay slot only on the taken edge.
`MFC1` and `MTC1` are typed 32-bit bitcasts between GPR and FPR values;
`CFC1` and `CTC1` on aggregate FCSR31 are exact 32-bit copies, and a write
projects its condition-code bits into FCC0-FCC7 SSA. FCCR25 writes conservatively
clobber all FCC state because its bit-level mapping is not modeled; FEXR26 and
FENR28 remain named effects with an aggregate FCSR dependency. MIPS64-only
doubleword transfer forms are not decoded in this MIPS32 mode.
The decoder records one delay slot; MIPS analysis owns and orders the slot
through its explicit CFG edge. COP1 operations remain symbolic in decompiled
functions; standalone processor semantic helpers evaluate binary32 `DIV.S`
and S/D-to-word rounding operations with their supported FCSR effects. They
are not yet connected to per-function execution. Other IEEE arithmetic and
conversion results and exact FCSR outputs remain abstract. See the evaluator
limits in
[`mips32.md`](mips32.md).


## Exact signed word to double conversion

`CVT.D.W` now lowers its destination to a typed `mips.s32_to_f64_exact`
expression from the source FPR's low 32-bit signed word. Every signed 32-bit
integer is exactly representable in binary64, so this conversion cannot be
inexact and its value is independent of FCSR rounding mode. The lift preserves
the decoder's incoming FCSR dependency and emits the incoming FCSR unchanged
as the status output. This covers only `CVT.D.W`; `CVT.S.W`, floating-format
conversions, floating-to-word conversions, and arithmetic retain explicit
unknown result/status outputs where rounding or IEEE exception behavior may
matter. Runtime FPR pairing and format validity remain outside this lift.

## Exact COP1 sign and move operations

The six existing native `ABS.S`, `MOV.S`, `NEG.S`, `ABS.D`, `MOV.D`, and
`NEG.D` instructions now lower to exact typed assignments in the MIPS32
pipeline. MOV copies the complete 32-/64-bit FPR value. ABS bitcasts the source
to an integer of the same width, clears only bit 31 or 63, and bitcasts back.
NEG uses the same integer bitcast and toggles only that sign bit with XOR.
D forms retain all 64 bits; they are not truncated to the MIPS32 GPR width.
Source/destination aliasing reads the pre-instruction source value.

These expressions match the existing native decoder and standalone sign
helper contract. They preserve every exponent/fraction bit, including NaN
payloads and signaling encodings, while preserving or changing the sign as
specified. No host floating arithmetic, numeric negation, NaN quieting,
rounding, or IEEE exception flag is introduced. The native forms read their
source FPR and write their destination FPR only; aggregate FCSR and FCC0-FCC7
remain unchanged.

The lift requires matching FPR banks and S/D widths, the decoded two-operand
write/read shape, and the exact source/destination register effects. Wrong
banks/types, memory/control effects, unexpected outputs, or extra FCSR/FCC
state dependencies retain an explicit intrinsic and all decoded implicit
reads/writes. Other COP1 arithmetic/conversions and alias views keep their
existing intrinsic behavior. Runtime FPR pairing/FR selection, CP1 unusable
exceptions, and full IEEE arithmetic/conversion exception execution remain
outside this bounded integration. FS-aware processor helpers remain standalone
and are not connected to function execution. The raw helper remains documented in
[MIPS32 processor coverage](mips32.md).

## Exact COP1 conditional moves

The native MIPS32 path decodes and lifts `MOVF.S/D`, `MOVT.S/D`, `MOVZ.S/D`,
and `MOVN.S/D`. The first pair reads the selected FCC0-FCC7 alias; the second
pair tests all 32 bits of its GPR condition, including architectural `$zero`.
The destination is a read/write operand: the typed result selects the complete
source bit pattern when the condition matches, otherwise its pre-instruction
value. Selection operates on same-width integer bitcasts and returns a 32- or
64-bit floating value, preserving NaN payloads, signaling encodings and signed
zeros without host floating arithmetic. FCSR and every FCC remain unchanged.

The decoder rejects the reserved MOVF/MOVT bit 17. Lifting requires exact FPR,
condition-bank/width, access, and implicit register effects; contradictory
facts remain explicit intrinsics retaining all supplied reads and writes.
Both native byte orders use the same fields. These classic pre-Release-6 S/D
forms use the existing logical scalar FPR model: runtime FR pairing, valid
format contents, coprocessor availability and exception delivery are not
inferred. Paired-single forms, Release 6 alternatives and general COP1
arithmetic/exception execution remain outside this slice. Encodings and
non-arithmetic move behavior follow the MIPS Technologies [MIPS32 Volume II-A,
Revision 3.00, MOVF/MOVT/MOVZ/MOVN.fmt](https://pages.hmc.edu/harris/class/e155/11/MIPS32InstructionSet.pdf).

## Exact GPR conditional moves

The SPECIAL `MOVZ rd, rs, rt` (function `0x0a`) and `MOVN` (function `0x0b`)
forms now decode with a zero `shamt` requirement. They retain the conditional
destination as read/write, read `rs` and the complete 32-bit `rt` condition,
and write `rd` unless it is `$zero`. Lifting selects the pre-instruction
`rd` when the condition does not match and selects `rs` when `rt` is zero
(`MOVZ`) or nonzero (`MOVN`). The choice is a 32-bit integer value operation;
no flags, memory effects, or delayed control transfer are introduced. A
malformed or contradictory effect record remains an explicit intrinsic.

The encoding and condition rule follow the MIPS32 Volume II-A instruction
reference linked above.

Conditional-link branches currently lift with their predicate, unconditional PC+8 `$ra` effect, and correct likely-slot annulment. Their CFG edges remain branch edges, so automatic call-graph discovery does not yet classify the taken target as a call. The ISA marks `rs = 31` encodings UNPREDICTABLE; HexLab currently decodes them conservatively without rejecting them.
