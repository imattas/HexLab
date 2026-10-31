# MIPS32 decoder slice

HexLab recognizes ELF `e_machine=EM_MIPS` (`8`) for ELF32 inputs in both byte orders. ELF32 selects the matching MIPS32 context; ELF64 little-endian MIPS is handled by the separate [MIPS64 integer decoder slice](mips64.md).

The fixed-width decoder covers selected SPECIAL shifts and register jumps, integer add/subtract/logic/compare, immediate forms, J/JAL, BEQ/BNE/BLEZ/BGTZ/BLTZ/BGEZ and their BEQL/BNEL/BLEZL/BGTZL/BLTZL/BGEZL likely forms, the REGIMM `BLTZAL`/`BGEZAL` conditional-link forms and `BLTZALL`/`BGEZALL` conditional-link-likely forms, and common byte/halfword/word loads and stores including LWL/LWR/SWL/SWR. Instruction-word and encoded low-halfword fields follow the ELF byte order. It also decodes the integer HI/LO path: MULT/MULTU and DIV/DIVU read two GPRs and write the special HI and LO registers; MFHI/MFLO transfer one special register to a GPR; MTHI/MTLO transfer a GPR to a special register. These operands have explicit access directions and format as `hi` and `lo`. A pure helper evaluates the 32-bit multiply/divide result pair; divide-by-zero and signed quotient overflow have no concrete helper result. The bounded native COP1 subset includes `MFC1`/`MTC1` and `CFC1`/`CTC1` for FCCR25/FEXR26/FENR28/FCSR31, as described below; unsupported encodings may still be decoded opaquely through the generic Capstone fallback. Reserved encodings, bad fixed fields, and unaligned addresses report `invalid`; fewer than four bytes report `truncated`.

MIPS32 Release 2 SPECIAL3 `EXT` and `INS` decode as `ext rt, rs, pos, size` and
`ins rt, rs, pos, size`. `EXT` accepts positions 0–31 and sizes 1–32 only when
`pos + size <= 32`; its `rd` field encodes `size - 1`. `INS` requires the
encoded inclusive MSB (`rd`) to be at least `pos`; the displayed size is
`msb - pos + 1`. Reserved ranges are invalid, while other SPECIAL3 functions
remain unsupported. Both expose exact GPR effects: `EXT` writes the extracted
zero-extended field, and `INS` reads/writes `rt`, reads `rs`, preserves all bits
outside the selected destination range, and inserts the low `size` bits of
`rs`. The MIPS32 decompiler expresses these as logical shifts, masks, and
merge operations. `evaluate_mips32_bitfield_instruction` evaluates the exact
decoded EXT/INS operands from a supplied source value and, for INS, the prior
destination. It validates position/size bounds and register effects, and
forces `$zero` source/destination values to zero. The caller still commits the
result; writes to `$zero` have no architectural effect.

Every decoded control transfer records `delay_slots = 1`. Automatic reachable analysis and function recovery decode and own the instruction at PC+4 before following a transfer's target or post-slot continuation. Calls and classic conditional branches continue at PC+8; likely branches send the not-taken edge directly to PC+8 and route the taken edge through the delay slot. Jumps have no invented fallthrough; returns terminate after their slot. A control transfer in a delay slot is explicitly unsupported, and missing, excluded, malformed, or truncated slots stop recovery without fabricating an edge. Instruction and membership budgets and cancellation continue to bound traversal. JAL, JALR, BLTZAL, BGEZAL, BLTZALL, and BGEZALL expose link-register writes; the REGIMM link forms use the PC+8 return address even when the branch predicate is false. Their taken edges are represented as conditional calls and contribute direct-call candidates to reachable and function recovery, while the not-taken continuation remains conditional; likely-link forms retain delay-slot annulment on that continuation. `jr $ra` is identified as return. Compressed/MIPS16/microMIPS, unsupported COP1 formats/functions, exception instructions, other REGIMM forms, and complete ISA semantics remain unsupported. COP1 `BC1TL`/`BC1FL` select FCC0-FCC7 like `BC1T`/`BC1F`; their not-taken edges annul the delay slot. The link and likely-link operations follow the MIPS32 Instruction Set Manual, Volume II, Revision 0.95: [official-format manual copy](https://www.ece.lsu.edu/ee4720/mips32v2.pdf).

The HI/LO encoding and result behavior follows the MIPS32 Instruction Set Manual, Volume II, Revision 0.95: [MIPS32 Architecture for Programmers](https://www.ece.lsu.edu/ee4720/mips32v2.pdf). Division by zero is architecturally unpredictable/undefined, so the semantic helper returns no result rather than choosing a quotient or remainder.
# COP1 scalar floating-point subset

The scalar decoder recognizes `LWC1`/`SWC1` and `LDC1`/`SDC1`, COP1 S-format arithmetic
operations `ADD.S`, `SUB.S`, `MUL.S`, `DIV.S`, `SQRT.S`, `ABS.S`, `MOV.S`,
`NEG.S`, all 16 classic `C.<cond>.S` comparisons, and `BC1T`/`BC1F`/`BC1TL`/
`BC1FL` branches selecting FCC0 through FCC7. It also recognizes D-format
arithmetic/unary operations and all 16 classic `C.<cond>.D` comparisons,
conversions between S/D/W for the common
`CVT` forms, and `ROUND.W`, `TRUNC.W`, `CEIL.W`, and `FLOOR.W` from S/D.
Decoded instructions expose logical 32- or 64-bit FPR operands, including the
correct destination width for S/D/W conversions, and explicit FCSR effects for
arithmetic, square root, and conversions; comparisons write the selected FCC
register, and branches read only their selected FCC register.
Sign/move operations `ABS`, `MOV`, and `NEG` do not claim FCSR effects.
All classic compare predicate bits and branch condition-code fields are
preserved in the formatter and MIPS32 lifting. FPR pairing mode is not inferred
from runtime CP0 state. `MFC1`/`MTC1` transfer the low 32-bit FPR/GPR bit pattern;
`CFC1`/`CTC1` support FCCR25, FEXR26, FENR28, and aggregate FCSR31. Other
control-register selectors are rejected as unsupported because their identity
and alias behavior are not modeled. FCSR31 transfers are represented as exact
32-bit SSA copies, and CTC1 writes also project FCC0-FCC7 from the FCSR condition
bits. FCCR25 writes conservatively invalidate all FCC SSA values; separate
FCCR/FEXR/FENR views remain named effects without fabricated bit-level aliases.
Long-word conversion forms and other formats/functions remain unsupported.
Classic S/D `MOVF`, `MOVT`, `MOVZ`, and `MOVN` now decode with a read/write
FPR destination and an exact selected-FCC or 32-bit GPR condition dependency.
They lift as full-width bit-preserving conditional copies without FCSR writes;
see [conditional move lifting](mips32-decompiler.md#exact-cop1-conditional-moves).
COP1 branch-likely forms retain their separately modeled delay-slot behavior.

This slice does not evaluate IEEE arithmetic or conversions, runtime rounding
modes, exception flags, or compare-result truth at runtime. The standalone
semantic helper evaluates `ABS.S/D`, `MOV.S/D`, and `NEG.S/D` exactly as
sign-bit operations, preserving all payload bits and leaving FCSR unchanged.
These six decoded operations now also lower to typed full-width bitcast and
mask/XOR/copy assignments in the MIPS32 decompiler; see
[sign/move lifting](mips32-decompiler.md#exact-cop1-sign-and-move-operations).
The decompiler retains floating operations and conversions as typed `mips.*`
intrinsics with their decoded FPR/FCSR effects. Conversion intrinsics carry
the proper scalar result type but do not produce a computed value. The
standalone helper now evaluates all eight S/D `ROUND.W`, `TRUNC.W`, `CEIL.W`,
and `FLOOR.W` forms from exact IEEE source bits, using their named rounding
rules independently of FCSR.RM. It returns the low-word result, Cause/Flag
updates, and destination suppression when an enabled Invalid or Inexact
exception occurs. Invalid conversions use the architecture's default
`INT32_MAX` result when the exception is disabled. With FCSR.FS set, the
standalone word-conversion evaluator follows Release 5+ behavior: a subnormal
source becomes same-sign zero and raises Inexact, which can suppress the
destination write when enabled. Other conversions and general arithmetic
still have no standalone evaluator.
These conversion rules follow the `ROUND.W`, `TRUNC.W`, `CEIL.W`, and
`FLOOR.W` entries in the [MIPS32 Instruction Set Manual, Volume II, Revision 0.95](https://www.ece.lsu.edu/ee4720/mips32v2.pdf).
Malformed fixed fields
(including nonzero unused unary `ft` and reserved compare bits) are invalid;
recognized but unmodeled formats/functions report unsupported.

The standalone MIPS32 semantic helper now evaluates binary32 `DIV.S` from
operand bit patterns with integer rational arithmetic. It implements all four
FCSR rounding modes, normal/subnormal rounding, signed zero/infinity, overflow,
underflow, divide-by-zero, invalid, and inexact conditions. It replaces the
FCSR Cause field on each operation, accumulates Flag bits only when no enabled
exception is taken, and reports whether the destination write is suppressed.
When FCSR.FS is set, this helper follows Release 5+ alternate flush behavior:
subnormal inputs become same-sign zero and raise Inexact; exact nonzero results
below the normal range are detected before rounding, flushed to same-sign zero,
and raise Underflow plus Inexact. Enabled exceptions suppress the FPR write,
and the unimplemented-operation exception is not modeled. With FS clear, the
helper retains gradual underflow and detects tininess after rounding. NaN
propagation quietens the first NaN payload; invalid `0/0` and `inf/inf` produce
the canonical quiet NaN. `evaluate_mips32_div_s_instruction` now connects the
decoded `DIV.S` operands and FCSR read/write effects to this evaluator while
keeping FPR/FCSR sampling and state commit caller-owned. The decompiler still
emits `DIV.S` as an intrinsic and does not execute the helper. The rounding,
flag, and Cause behavior follows the MIPS32
[Instruction Set Manual, `DIV.fmt`](https://courses.cs.washington.edu/courses/cse378/documentation/MIPS32_Architecture_For_Programmers_Volume_II.pdf)
and [Volume I FCSR field definitions](https://courses.grainger.illinois.edu/cs426/fa2022/Resources/MIPS32INT-AFP-03.02.pdf).
The Release 5+ flush behavior follows [MIPS32 Architecture Volume I-A, Revision 6.01, §6.7.2.4](https://www.ece.lsu.edu/ee4720/doc/mips32-r6-1a.pdf).

## SPECIAL2 multiply and count-leading operations

MIPS32 Release 2 `MUL rd, rs, rt` decodes SPECIAL2 function `0x02` when `shamt` is zero. It writes the low 32 bits of the signed word product to `rd`; the standalone helper computes those low bits with modulo-2^32 semantics (the low bits match for signed and unsigned multiplication). The architecture leaves HI/LO unpredictable after this instruction, so decoding reports both writes and lifting preserves the exact GPR result while assigning unknown values to HI and LO. Writes to `$zero` remain suppressed. `CLZ rd, rs` and `CLO rd, rs` decode from functions `0x20` and `0x21`; their `rt` field must duplicate `rd` and `shamt` must be zero. Other SPECIAL2 functions remain unsupported. The encoding and behavior are specified in the [MIPS32 Instruction Set Manual, Volume II](https://pages.hmc.edu/jspjut/class/f2013/e155/docs/MIPS32InstructionSet.pdf).

`evaluate_mips32_fcc_branch_instruction` evaluates decoded `BC1T`, `BC1F`,
`BC1TL`, and `BC1FL` from the selected caller-supplied FCC value. It validates
the FCC index/read effect, relative target, and one-delay-slot branch facts.
The result is only the taken predicate; branch-target transfer and likely-form
delay-slot annulment remain caller-owned.

`evaluate_mips32_integer_branch_instruction` evaluates decoded `BEQ`/`BNE`,
`BLEZ`/`BGTZ`, and `BLTZ`/`BGEZ`, including their supported likely variants,
from caller-supplied GPR values. It validates the GPR operands and read facts,
relative target, and classic one-delay-slot metadata, and treats `$zero` as
zero. It returns only the predicate; target transfer and likely-form delay-slot
annulment remain caller-owned.

`evaluate_mips32_add_immediate_instruction` evaluates `ADDI` and `ADDIU` from
the decoded signed 16-bit immediate and caller-supplied source GPR. `ADDI`
reports signed overflow and suppresses the destination write on that exception;
`ADDIU` wraps modulo 2^32. Writes to `$zero` are suppressed for both forms.
Exception delivery and committing a successful result remain caller-owned.

`evaluate_mips32_set_less_than_immediate_instruction` evaluates `SLTI` and
`SLTIU`. Both compare against the sign-extended 16-bit immediate; `SLTI`
interprets both operands as signed words, while `SLTIU` compares their 32-bit
patterns as unsigned values. It returns the architectural 0/1 result and
validates destination/source GPR and immediate metadata. `$zero` writes are
suppressed in the decoded effects; state commit remains caller-owned.

`evaluate_mips32_set_less_than_instruction` evaluates R-type `SLT` and
`SLTU` using caller-supplied source GPR values. `SLT` compares signed 32-bit
values; `SLTU` compares unsigned bit patterns. The helper validates decoded
GPR effects and treats `$zero` sources as zero. It returns the 0/1 result;
destination commit remains caller-owned.

`evaluate_mips32_logical_immediate_instruction` evaluates `ANDI`, `ORI`, and
`XORI` using the decoded zero-extended 16-bit immediate. It validates the
source/destination effects and suppresses writes to `$zero`; the caller
supplies the source register and commits the returned value.

`evaluate_mips32_logical_instruction` evaluates R-type `AND`, `OR`, `XOR`,
and `NOR` on caller-supplied GPR values. It checks the decoded register
operands/effects, treats `$zero` sources as zero, and returns the 32-bit
result. The caller commits the destination; writes to `$zero` are discarded
by the decoded register effects.

`evaluate_mips32_count_leading` computes SPECIAL2 `CLZ` and `CLO` over all 32
source bits, returning values from 0 through 32. Its instruction adapter checks
the decoded GPR shape/effects and forces `$zero` source reads to zero. The
caller supplies other source values and commits the destination; HI/LO and
other SPECIAL2 operations are not part of this helper.
