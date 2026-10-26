# MIPS32 decoder slice

HexLab recognizes ELF `e_machine=EM_MIPS` (`8`) for ELF32 inputs in both byte orders. ELF32 selects the matching MIPS32 context; ELF64 little-endian MIPS is handled by the separate [MIPS64 integer decoder slice](mips64.md).

The fixed-width decoder covers selected SPECIAL shifts and register jumps, integer add/subtract/logic/compare, immediate forms, J/JAL, BEQ/BNE/BLEZ/BGTZ/BLTZ/BGEZ and their BEQL/BNEL/BLEZL/BGTZL/BLTZL/BGEZL likely forms, and common byte/halfword/word loads and stores including LWL/LWR/SWL/SWR. Instruction-word and encoded low-halfword fields follow the ELF byte order. It also decodes the integer HI/LO path: MULT/MULTU and DIV/DIVU read two GPRs and write the special HI and LO registers; MFHI/MFLO transfer one special register to a GPR; MTHI/MTLO transfer a GPR to a special register. These operands have explicit access directions and format as `hi` and `lo`. A pure helper evaluates the 32-bit multiply/divide result pair; divide-by-zero and signed quotient overflow have no concrete helper result. The bounded native COP1 subset is described below; unsupported encodings may still be decoded opaquely through the generic Capstone fallback. Reserved encodings, bad fixed fields, and unaligned addresses report `invalid`; fewer than four bytes report `truncated`.

Every decoded control transfer records `delay_slots = 1`. Automatic reachable analysis and function recovery decode and own the instruction at PC+4 before following a transfer's target or post-slot continuation. Calls and classic conditional branches continue at PC+8; likely branches send the not-taken edge directly to PC+8 and route the taken edge through the delay slot. Jumps have no invented fallthrough; returns terminate after their slot. A control transfer in a delay slot is explicitly unsupported, and missing, excluded, malformed, or truncated slots stop recovery without fabricating an edge. Instruction and membership budgets and cancellation continue to bound traversal. JAL and JALR expose link-register writes, and `jr $ra` is identified as return. Compressed/MIPS16/microMIPS, unsupported COP1 formats/functions (including COP1 likely branches), exception instructions, REGIMM link-likely forms, and complete ISA semantics remain unsupported.

The HI/LO encoding and result behavior follows the MIPS32 Instruction Set Manual, Volume II, Revision 0.95: [MIPS32 Architecture for Programmers](https://www.ece.lsu.edu/ee4720/mips32v2.pdf). Division by zero is architecturally unpredictable/undefined, so the semantic helper returns no result rather than choosing a quotient or remainder.
# COP1 scalar floating-point subset

The scalar decoder recognizes `LWC1`/`SWC1` and `LDC1`/`SDC1`, COP1 S-format arithmetic
operations `ADD.S`, `SUB.S`, `MUL.S`, `DIV.S`, `SQRT.S`, `ABS.S`, `MOV.S`,
`NEG.S`, all 16 classic `C.<cond>.S` comparisons, and non-likely `BC1T`/`BC1F`
branches selecting FCC0 through FCC7. It also recognizes D-format
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
from runtime CP0 state. COP1 likely branches, long-word conversion forms,
MFC1/MTC1/CFC1/CTC1 transfers, other formats, and functions remain unsupported.

This slice does not evaluate IEEE arithmetic or conversions, runtime rounding
modes, exception flags, or compare-result truth at runtime. The decompiler
retains floating operations and conversions as typed `mips.*` intrinsics with
their decoded FPR/FCSR effects. Conversion intrinsics carry the proper scalar
result type but do not produce a computed value. Exact rounding and exception
behavior remain unsupported by the semantic evaluator. Malformed fixed fields
(including nonzero unused unary `ft` and reserved compare bits) are invalid;
recognized but unmodeled formats/functions report unsupported.
