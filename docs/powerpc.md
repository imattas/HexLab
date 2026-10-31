# PowerPC/POWER decoder slice

The X-form `tw` and PPC64-only `td` conditional trap instructions are decoded
with the five TO enable bits and their signed/unsigned word or doubleword
comparands. Their lifter represents the trap predicate as the OR of selected
less-than, greater-than, and equality comparisons; TO=0 is an always-false
predicate. They have no register or memory outputs. Trap delivery and exception
state changes are not simulated.

The decompiler now gives scalar word/doubleword logical and arithmetic shifts
typed formulas for count masking, overshift handling, PPC64 word extension,
CA, and parallel Rc outputs. CA32 remains explicitly profile-dependent. See
[PowerPC scalar shift lifting](decompiler-powerpc-shifts.md) for exact scope
and validation limits.

Encoding review follows the [OpenPOWER Power ISA v3.1C specification](https://openpower.foundation/specifications/isa/) (reference source `P02`). The current implementation is a deliberately bounded subset.

HexLab includes an original fixed-width PowerPC decoder for PPC32 and PPC64 in either ELF byte order. The current integer slice covers immediate add/shifted-add and carry-add, multiply/subtract-immediate, signed/unsigned immediate compares, logical immediate operations, word rotate-and-mask (`rlwimi`, `rlwinm`, and `rlwnm`, including record forms), PPC64 doubleword rotate-and-mask (`rldicl`, `rldicr`, `rldic`, `rldimi`, `rldcl`, and `rldcr`, including record forms), selected X-form add/subtract/carry arithmetic, multiply/divide, logical operations, word/doubleword shifts, and register compares. It decodes D/DS-form and indexed integer loads/stores, including update forms, plus LR/CTR/XER transfers, `mfcr`/`mtcrf`, direct/conditional/LR-indirect/CTR-indirect branches, and system-call traps. Register operands and effects use explicit GPR, CR-field, LR, CTR, and XER banks. ELF e_machine 20/21 plus matching class select PPC32/PPC64; matching big- and little-endian files are supported. Raw CLI profiles are `ppc32le`, `ppc32be`, `ppc64le`, and `ppc64be`.

The instruction decoder preserves the difference between truncated input, reserved encodings, and valid instructions outside this subset. Immediate compare records the selected CR field and 32-/64-bit compare width; `rlw*` operands describe the 32-bit rotate/mask fields while destination register effects follow the selected GPR width. PPC64 `rld*` forms use six-bit shifts and mask indices, including the implicit `ME=63-SH` mask for `rldic` and `rldimi`. `subfic` records its XER carry effect, and `sc` is accepted only with its reserved bits clear and fixed suffix intact. The X-form integer subset also includes complementing logical operations (`andc`, `nand`, `nor`, `orc`, `eqv`), count-leading-zero (`cntlzw` and PPC64 `cntlzd`), and sign-extension (`extsb`, `extsh`, and PPC64 `extsw`), with Rc forms recording their CR0 write. `addze` and `addme`, including Rc forms, consume XER.CA, update only that XER bit while preserving the other modeled XER bits, and in record forms produce CR0 from the result and prior XER.SO. Overflow-enabled variants remain unsupported. PPC64 `lwa` (opcode 58 DS-form selector 10) is recognized as valid but remains outside the decoded subset; selector 11 is reserved.

The scalar floating-point slice decodes `lfs`, `lfd`, `stfs`, and `stfd` D-form memory operations; `fadds`, `fsubs`, `fmuls`, `fdivs`, `fadd`, `fsub`, `fmul`, and `fdiv`, including Rc forms; `fmadd`, `fmsub`, `fnmadd`, and `fnmsub` in single and double precision, including Rc forms; `fcmpu`/`fcmpo`; and `fmr`, `fneg`, `fabs`, and `frsp`, including Rc forms. FPR operands are named `f0` through `f31`, and FPSCR is represented as an explicit 32-bit register. Floating comparisons write the selected four-bit CR field as LT/GT/EQ/unordered and retain a conservative unknown FPSCR result; named floating predicates preserve ordered versus NaN behavior. Arithmetic, fused arithmetic, and `frsp` expose conservative post-operation FPSCR values, with the selected CR1 output derived from that post-operation value for Rc forms. Fused multiply-add/subtract forms retain a single-rounding named intrinsic and three explicit FPR sources rather than being decomposed into separate multiply and add operations. Non-rounding unary Rc forms copy the current FPSCR summary into CR1 without claiming an FPSCR update. `frsp` retains a single-precision rounding operation represented in the FPR value. Invalid reserved arithmetic fields fail as malformed instructions. `mffs`, `mtfsb0`, `mtfsb1`, `mtfsfi`, and `mtfsf` decode their register/immediate operands and FPSCR/CR1 dependencies; `mcrfs BF,BFA` copies the selected FPSCR nibble into CR field BF and clears only the exception bits copied. It also clears FX when field 0 is selected and recomputes the derived FEX/VX summary bits, preserving unrelated FPSCR status and control bits. `mtfsb0` and `mtfsb1` now produce an exact post-instruction FPSCR expression: the selected bit is addressed with architectural MSB-first numbering, FX is directly clearable/settable, and FEX/VX are recomputed from their source status/enable bits because the instruction cannot write those derived summary bits directly. Rc forms derive CR1 from this updated FPSCR. The lift validates the decoded immediate and register effects before claiming this result. `mtfsfi` and `mtfsf` still retain opaque post-update FPSCR values; detailed exception semantics remain incomplete. Reserved-field violations and Rc=1 on `mcrfs` are rejected. The `mcrfs` lift computes the copied nibble and post-instruction FPSCR value as explicit bit-vector expressions. The FPSCR bit definitions and derived FEX/VX rules follow the [PowerPC Microprocessor Family Programming Environments Manual](https://www.nxp.com/docs/en/user-guide/MPCFPE.pdf). Update-form floating memory operations remain unsupported.

`mcrfs` uses the architectural most-significant-first numbering of FPSCR fields. Its copied nibble is taken from the original FPSCR value. Exception status copied from fields 0, 1, 2, 3, or 5 is cleared; result-class, rounding, enable, and reserved bits in those fields are preserved. FPSCR[FX] is cleared when field 0 is selected, while derived FPSCR[FEX] and FPSCR[VX] are recomputed from the remaining exception and enable bits. The operation writes exactly the selected CR field and FPSCR, with no CR1 record side effect. The encoding and clearing rules follow [Power ISA Book I, section 4.6.11](https://fileadmin.cs.lth.se/cs/education/EDAN25/PowerISA_V2.07_PUBLIC.pdf).

The conversion family follows Book I section 4.6.7.2 of the [official OpenPOWER ISA download](https://files.openpowerfoundation.org/s/AKX2KtLkwCXxEaC). Opcode 63 uses exact ten-bit X-form XO values 14 (`fctiw`), 15 (`fctiwz`), 142 (`fctiwu`), 143 (`fctiwuz`), 814 (`fctid`), 815 (`fctidz`), 846 (`fcfid`), 942 (`fctidu`), 943 (`fctiduz`), and 974 (`fcfidu`). `fcfids` uses primary opcode 59 and XO 846. The unused FRA field must be zero in each conversion. Word-result conversions are enabled in PPC32/PPC64; doubleword conversions, `fcfidu`, and `fcfids` are enabled only in the repository's PPC64 profile, which has no separate processor-capability selector for a 64-bit implementation running 32-bit code. All forms accept Rc and format its trailing dot.

The conversion lifter reads floating binary64 sources for `fcti*` and a signed or unsigned integer64 FPR payload for `fcfid`, `fcfidu`, and `fcfids`. Named typed operations retain FPSCR RN rounding for non-z `fcti*`, fixed toward-zero rounding for z forms, signed or unsigned saturation after rounding, and the ISA-defined NaN result (signed minimum for signed conversions, zero for unsigned conversions). `fcfids` rounds the integer-to-float result to single precision; `fcfid`/`fcfidu` produce double precision. Word results occupy the low 32 FPR bits with an explicit undefined high half. Enabled invalid-operation write suppression retains the previous destination bits through a symbolic source/FPSCR predicate; the destination is therefore also a decoded read for `fcti*`. FPSCR exception and result fields remain unknown, and Rc derives CR1 from that post-operation FPSCR. These operations remain symbolic; detailed exception delivery and concrete FP evaluation are not implemented.

The bounded VMX integer slice decodes the exact opcode-4 VX forms `vaddubm`, `vadduhm`, `vadduwm`, `vsububm`, `vsubuhm`, `vsubuwm`, `vand`, `vandc`, `vor`, `vxor`, `vnor`, and signed/unsigned lane-wise `vmax*`/`vmin*` for byte, halfword, and word lanes in PPC32 and PPC64. Add/subtract wrap modulo their 8-, 16-, or 32-bit lane width; min/max compare each lane as signed or unsigned and copy one original lane unchanged. The logical forms act on all 128 bits and have no lane arrangement. Each instruction names `v0` through `v31`, reads VA and VB, and writes VD; source/destination aliasing is allowed. The decoder reads the instruction word in the selected ELF byte order, matches all 11 extended-opcode bits, and leaves other opcode-4 forms unsupported. There are no record, VSCR, or memory effects in this slice.

The PPC lifter retains each VMX operation as a typed, memory-free common-IR intrinsic with two vector source expressions, one vector register write, and a result type. The intrinsic name identifies the operation and `i8x16`, `i16x8`, `i32x4`, or opaque `bits128` shape; the vector type carries the same width and lane metadata. The lifter validates the decoder's operand, access, effect, and shape metadata before emitting that intrinsic. It does not evaluate lanes or claim concrete vector execution. Saturating arithmetic, comparisons, permutes, vector memory operations, VSX, and other VMX forms remain outside this slice.

The opcode-19 `mcrf BF,BFA` form copies one complete four-bit CR field into another. The decoder retains destination and source CR fields as typed operands and rejects nonzero reserved fields, including Rc. The lifter emits a direct CR-field assignment, preserving the source value and writing only BF. The same opcode group supports `crand`, `crandc`, `creqv`, `crnand`, `crnor`, `cror`, `crorc`, and `crxor`. These decode BT, BA, and BB as individual condition-register bits, format them as `crN.lt`, `crN.gt`, `crN.eq`, or `crN.so`, and lift the Boolean operation as a one-bit assignment that writes only BT. `evaluate_ppc_cr_logical_instruction` validates the decoded CR-bit read/write facts and computes the result from caller-supplied BA/BB values. Rc is rejected because the field is reserved. This follows [Power ISA v3.1C Book I §2.5.2](https://openpower.foundation/specifications/isa/); `mcrxr` remains unsupported. Caller-side CR sampling and commit remain external to the helper.

Legacy opcode-31 `mcrxr BF` is decoded with the BF destination and XER read/write effects; its other register fields and Rc must be zero. `evaluate_ppc_mcrxr_instruction` copies XER.SO/OV/CA into CR[BF].LT/GT/EQ, sets CR[BF].SO to zero, and clears only XER.SO/OV/CA. Other CR fields and XER bits are preserved. The helper returns the changed state for the caller to commit; it does not claim execution of concurrent or privileged state.

The VMX integer evaluator accepts two 16-byte register bit patterns in architectural register order (byte 0 is the most significant byte), independent of ELF byte order. It evaluates wrapping add/subtract and signed/unsigned min/max lane by lane, and the five logical forms bytewise across all 128 bits. Unsupported opcodes return no result. This evaluator is a pure operation helper; it does not model vector-register state, VSCR, exceptions, or instruction dispatch.

The decompiler also lifts `mullw`, `mulld`, `divw`, `divwu`, `divd`, and `divdu`. Word forms consume 32-bit operands in PPC64 mode and extend their result to the GPR width: signed multiply/divide sign-extend, while unsigned word division zero-extends. Doubleword forms are PPC64-only. Divide expressions use explicit `ppc_sdivw`, `ppc_udivw`, `ppc_sdivd`, and `ppc_udivd` IR operation names so their architectural exceptional cases are not treated as ordinary host division. Rc forms produce the GPR result and CR0 from the same pre-instruction inputs; the CR0 summary includes the symbolic XER.SO bit. Division by zero, signed minimum divided by negative one, and implementation-specific result details are not concretely evaluated.

Indexed byte-reversed memory coverage includes `lhbrx`, `lwbrx`, `sthbrx`, and `stwbrx`, plus PPC64 `ldbrx` and `stdbrx` (X-form XO 532 and 660). These use `(RA|0) + RB`, record their memory and register effects, and reject doubleword forms in PPC32.

Analysis recovers reachable functions through direct, conditional, LR, and CTR control flow, with PPC32/PPC64 address widths. The decompiler now lowers ordinary `addi`/`addis`, logical immediates and selected X-form logical/arithmetic operations, count-leading-zero and sign-extension operations, non-record `rlwimi`/`rlwinm`/`rlwnm` and PPC64 `rldicl`/`rldicr`/`rldic`/`rldimi`/`rldcl`/`rldcr`, `mulli`, `addze`/`addme`, non-update integer loads and stores, direct branches/calls, conditional branches, indirect LR/CTR transfers, and canonical LR returns into typed expressions, memory effects, or control-flow statements. Word and doubleword rotates use symbolic rotate-left operations with the exact wrapped PPC mask; insert forms preserve bits outside the mask, including PPC64's high word for `rlwimi`, while clear forms zero bits outside their selected mask. For branches that test a CR bit while ignoring CTR, the branch predicate identifies the exact BI bit in its CR field and whether the branch expects that bit to be set. CR compare forms (`cmp`, `cmpl`, `cmpi`, and `cmpli`) now produce the selected four-bit CR field from signed or unsigned less-than, greater-than, equality, and the symbolic XER.SO bit. Record-form add/subtract, logical, rotate/mask, count-leading-zero, sign-extension, and logical-immediate instructions produce their GPR and CR0 outputs in parallel from the pre-instruction state. `addze`/`addme` calculate the carry-in result and CA bit with parallel XER/CR0 outputs. BO/BI branch predicates now include exact CR polarity and post-decrement CTR tests. Counted non-link branches preserve their unconditional CTR update before the transfer; linked forms retain LR updates through a statement prefix or an explicit parallel-effect intrinsic. Update-form memory operations and other carry-producing arithmetic remain explicit effects. Branch predicates test CR bits directly; no comparison-operand recovery is inferred.

Immediate carry arithmetic is now lifted for `addic`, `addic.`, and `subfic`. The result is a typed width-specific add/subtract expression; XER is updated in parallel by replacing only its CA bit (architectural bit 29 in the retained 32-bit XER value) and preserving the remaining bits. `addic` carry-out is represented by unsigned wrap comparison; `subfic` CA is represented as unsigned `SIMM >= RA`, matching its no-borrow rule. `addic.` additionally produces CR0 from the result and the pre-instruction XER.SO bit. Decoder effects include XER reads so the untouched XER state is not lost. The decompiler retains these as symbolic expressions; the processor helper below can evaluate concrete inputs.

`evaluate_ppc_immediate_carry_instruction` evaluates decoded `addic`, `addic.`
and `subfic` from caller-supplied source and XER values. It returns the
width-limited result, XER with only CA replaced, and CR0 for `addic.` using the
incoming SO bit. The helper validates immediate/register shape and effects;
sampling and state commit remain caller-owned.

Byte-reversed indexed loads and stores lift through explicit `bswap16`, `bswap32`, or `bswap64` integer operations. Narrow PPC64 loads are zero-extended after byte reversal, and narrow stores are truncated before reversal. The typed operation represents native scalar byte-order reversal without expanding it into byte-wise accesses. Remaining scalar floating-point forms, vector forms beyond the VMX integer slice above, privileged/system instructions beyond the system-call trap, SPRs other than XER/LR/CTR/FPSCR, uncommon integer forms, ABI-specific function calling conventions, relocation-based target resolution, and complete POWER/PowerPC semantics are not implemented. Counted branches use typed CTR decrement/test expressions, and condition-register branches use explicit bit masks and polarity. Complete CR/CTR emulation and cross-instruction relational recovery are not claimed. PPC32 arithmetic target behavior is modeled at 32-bit addresses; exception and reservation effects are not modeled. Debugger register support and architecture-specific ABI recovery are not included.


## BO/BI control-flow lifting

The PPC32/PPC64 lifter interprets every BO bit combination accepted by the
original decoder for `bc`, `bclr` and `bcctr`. In the encoded five-bit value,
mask 16 ignores CR, mask 8 selects CR-set versus CR-clear, mask 4 ignores CTR,
and mask 2 selects zero versus nonzero after decrement. Bit zero is retained
as a prediction hint and does not alter the execution predicate. BI 0?31 selects
CR field `BI/4` and the field mask `1 << (3 - BI%4)`. Ignored inputs do not
create false CR/CTR dependencies.

`evaluate_ppc_branch_predicate` provides a concrete counterpart for callers
that already sampled the selected four-bit CR field and CTR. It returns the
taken decision and the post-decrement counter when BO tests CTR. Counter
decrement wraps at the requested PPC32/PPC64 width, and the CR polarity,
selected BI bit, and CTR zero/nonzero selector follow BO/BI encoding. Target
selection, LR writes, branch execution, and register-state commit remain
caller-owned.

`evaluate_ppc_sign_extend_instruction` evaluates decoded `extsb`, `extsh`,
and PPC64 `extsw`, including Rc forms. It sign-extends the selected low 8, 16,
or 32 source bits to the mode's GPR width. Rc forms also return the CR0 nibble
from the result relation and caller-supplied XER.SO. The decoder reports that
XER read for Rc forms. Source sampling and GPR/CR0 state commits remain
caller-owned.

`evaluate_ppc_addze_addme_instruction` evaluates `addze`/`addme` in PPC32 and
PPC64, including Rc forms. It consumes XER.CA, returns the width-truncated GPR
result, replaces only XER.CA with the operation's carry-out, and returns CR0
for record forms using the prior XER.SO. Register/XER sampling and committing
the GPR/XER/CR0 outputs remain caller-owned.

`evaluate_ppc_fp_unary_bits_instruction` evaluates `fmr`, `fneg`, and `fabs`
from a caller-supplied 64-bit FPR payload. These operations copy, toggle, or
clear only the IEEE-754 sign bit, preserving all exponent, significand, and NaN
payload bits. For Rc forms, the helper also returns CR1 from FPSCR bits 0:3
(the high nibble of its 32-bit representation). It validates the decoded FPR,
FPSCR, and CR1 effects. Sampling and committing those register values remain
caller-owned. `frsp`, arithmetic, exception flags, and FPSCR changes are outside
this bitwise helper.

When CTR is tested, it is decremented modulo the decoded register width before
testing; that update occurs even if the CR test fails. The final predicate is
the conjunction of the active CR and CTR tests. When LK is present, LR becomes
the next instruction address even when a conditional transfer is not taken.
PPC32 link addresses wrap at 32 bits. Indirect destinations clear the low two
address bits.

| Decoded transfer | Lifted representation |
| --- | --- |
| Non-link direct `b`/`bc`, without CTR update | Generic branch with an unconditional or explicit CR predicate |
| Non-link counted `bc`/`bclr` | Unconditional CTR assignment followed by a branch that reads the updated CTR; `bclr` targets the unchanged masked LR |
| Non-link CR-tested `bclr`/`bcctr` | Generic indirect branch with the masked LR/CTR target and explicit CR polarity |
| Canonical unconditional non-link `bclr` return | Existing generic void return |
| Unconditional linked direct `b`/`bc` or CTR-target `bcctr` | Unconditional LR assignment followed by a generic call |
| Conditional LK forms and every linked LR-target `bclr` | Explicit linked-branch intrinsic containing the full predicate and pre-update target, with parallel CTR/LR output formulas |

Generic branch nodes cannot themselves define CTR, so function lifting emits
bounded update statements before the transfer, under the same source instruction
origin. SSA consequently tests the post-decrement counter while retaining the
pre-instruction state for provenance. Internal callers that do not accept a
statement prefix receive an explicit effect instead of silently losing a write.
A generic conditional Call has no predicate, and an LR assignment before an
LR-target call would overwrite its target; those shapes deliberately remain one
intrinsic. Its output formulas read all inputs before defining any output.

Explicit effects retain BO, BI, both ignore flags, CR polarity, the CTR zero
selector, the prediction hint, the taken predicate, target and address domain.
Linked effects conservatively have unknown memory effects. Unsupported or
inconsistent operand/flow/register-effect metadata remains an explicit intrinsic
with the decoded writes and input registers intact. A `bcctr` requesting CTR
decrement/testing remains invalid/unmodeled, as in the decoder. Prediction
behavior, indirect-target resolution, conditional-call ABI recovery, exception
behavior and full POWER instruction semantics remain outside this slice.

This expansion was reviewed in source only. No builds or tests were run; serial
decompiler compilation and PPC branch/SSA checks remain follow-up work.


## PPC64 algebraic word loads

The PPC64 decoder supports `lwa RT,DS(RA)` (primary opcode 58, DS selector
`10`), `lwax RT,RA,RB` (opcode 31, XO 341), and
`lwaux RT,RA,RB` (opcode 31, XO 373). Every form reads a 32-bit memory
word and sign-extends it to the 64-bit destination GPR. It does not read a
64-bit memory value or zero-extend the word.

LWA's signed displacement is the 14-bit DS field followed by two zero bits,
with the complete signed 16-bit byte offset retained in its memory operand.
Its encoded range is -32768 through 32764, in multiples of four. LWAX uses
`(RA|0) + RB`; RA=0 means the zero base and creates no read of GPR0, while
RB=0 still reads the value of GPR0. Non-update forms permit RT to alias
address registers. LWAUX requires RA != 0 and RA != RT, reads the old RA and
RB, and writes the effective address back to RA. RB may alias RT or RA.
Reserved record bits on indexed forms, reserved DS selectors, and these
indexed algebraic loads in PPC32 mode are rejected. No CR or XER write is
introduced. New opcode IDs are appended after existing IDs.

The decompiler lowers LWA and LWAX to a 32-bit typed memory read followed by
`sext` to 64 bits. LWAUX stays one memory-reading intrinsic with parallel
output formulas for the signed load result and `old_RA + old_RB`. SSA reads
all source values before defining either output, preserving aliases without
accidentally loading through an updated base. Malformed widths, operand
shapes, update constraints, and unexpected register writes remain explicit
opaque effects. Instruction and data byte order follow the existing PPC
context and memory IR; neither indexed load reverses bytes.

This slice follows IBM's primary [Assembler Language Reference](https://www.ibm.com/docs/ssw_aix_71/assembler/assembler_pdf.pdf)
entries for LWA/LWAX/LWAUX and LLVM's
[PPC64 instruction definitions](https://github.com/llvm/llvm-project/blob/main/llvm/lib/Target/PowerPC/PPCInstr64Bit.td).
Memory faults, alignment enforcement, access permissions, and fault-suppressed
writeback are not executed by the decompiler. Other update-form memory
families retain their existing lifting behavior; broader Power ISA integer,
FP/vector/system instructions and ABI/debugger coverage remain incomplete.

## High-word multiply

The X-form `mulhw` (XO 75) and `mulhwu` (XO 11) decode in both PPC32 and PPC64, including Rc record forms. Both read the low 32 bits of RA and RB and write the high 32 bits of the signed or unsigned product to RT. In PPC32 the typed lifter represents the high-word operation and the record form computes CR0 from the result and XER.SO. In PPC64 the ISA leaves the destination's upper 32 bits and CR0 LT/GT/EQ undefined; the lifter retains source operands but marks those outputs unknown rather than inventing an extension. OE/reserved variants are not accepted.

Scalar population-count coverage includes X-form `popcntw` (XO 378) in PPC32/PPC64 and `popcntd` (XO 506) in PPC64. Both require RB and Rc to be zero, read the word/doubleword source from RS, write RA, and do not update CR or XER. The lifter emits a width-specific `popcount` unary expression; `popcntw` consumes the low 32 source bits and writes the count to the mode-width GPR. `evaluate_ppc_popcnt_word_instruction` validates the decoded width and effects before computing the concrete count. The decoder does not model CPU-generation feature availability. `popcntb`, which counts independently in byte lanes, remains unsupported by the word/doubleword helper.

The X-form `isel` (XO 15) selects RA when the encoded CR bit BC is one and RB when it is zero. It decodes in PPC32 and PPC64, requires the reserved Rc bit to be zero, and records both GPR reads plus the specific typed CR-bit read. The scalar lifter emits a width-correct conditional select, including when source and destination registers alias. `evaluate_ppc_isel_instruction` validates those decoded facts and returns the selected mode-width GPR value from caller-supplied RA/RB and CR-bit values. RA and RB are ordinary GPR numbers, so register zero is read as GPR0; it is not treated as an implicit zero source. Other conditional-select and CR-to-GPR forms are not included, and the caller remains responsible for sampling and committing register state.

The X-form `addo`/`addo.` and `subfo`/`subfo.` enable signed overflow reporting on the ordinary add/subtract result. The decoder records the XER dependency and write, plus CR0 for record forms. The lifter keeps the exact GPR result and record comparison while representing the post-operation XER as unknown: OV/SO details depend on overflow and prior sticky SO state, which this slice does not resolve bit by bit. Encodings with overflow enable clear continue to decode as `add`/`add.` and `subf`/`subf.`.

Encoding references: [Linux PowerPC raw opcode definitions](https://github.com/torvalds/linux/blob/master/arch/powerpc/include/asm/ppc-opcode.h) and [LLVM PowerPC instruction definitions](https://github.com/llvm/llvm-project/blob/main/llvm/lib/Target/PowerPC/PPCInstr64Bit.td).

## Per-byte population count

The X-form `popcntb` (XO 122) decodes in PPC32 and PPC64. It reads `RS`,
counts set bits independently in each byte, and writes the corresponding
0-through-8 count into the same byte position of `RA`. It does not update CR
or XER. Encoded `RB` and `Rc` must be zero. The typed lift uses the
`popcount_bytes` operation at the active GPR width; `evaluate_ppc_popcntb`
provides the same operation for a caller-supplied 32- or 64-bit value. Byte
positions are preserved and do not depend on instruction/data endianness.

The encoding follows IBM's [Power ISA documentation](https://openpower.foundation/specifications/).

## Count leading zeros

`evaluate_ppc_count_leading_zeros` evaluates decoded `cntlzw`/`cntlzw.` and
`cntlzd`/`cntlzd.` result operations from a mode-width GPR value. Word forms
count only the low 32 bits and return 32 for zero; doubleword forms count all
64 bits and are rejected for PPC32. The helper returns only the GPR result;
record-form CR0 updates, XER.SO, register sampling, and instruction dispatch
remain outside this evaluator.
