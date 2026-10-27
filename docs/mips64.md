# MIPS64 decoder and analysis slice

HexLab assigns `EM_MIPS` (`e_machine=8`) with ELF64 class to the MIPS64 context for both little- and big-endian ELF data. MIPS64 instruction words are fixed at four bytes and use 64-bit GPR and effective-address operands. The selected byte order is preserved in the decoder context and used to assemble instruction words.

Linux debugger process identification uses the ELF class and byte order when reading `e_machine`, so it recognizes both little- and big-endian ELF64 MIPS processes as MIPS64. The loader follows the ELF64 `EM_MIPS` N64-class convention; it does not claim to validate individual ABI flags or select N32/O32 calling conventions.

The pre-Release 6 SPECIAL2 count-leading group covers CLZ/CLO on words and
DCLZ/DCLO on doublewords. The decoder requires the legacy `rt == rd` encoding
and a zero shift field; these instructions do not raise arithmetic exceptions.
The word forms inspect the low 32 bits and the architecture requires that
their source be a sign-extended word for predictable results. That runtime
source constraint is not checked. Release 6's recoded SPECIAL forms are not
decoded because this processor context does not select an ISA revision.

The MIPS64 Release 2 SPECIAL3 decoder recognizes DEXT/DEXTM/DEXTU and
DINS/DINSM/DINSU. It validates each instruction's position and field-size
constraints, reports the architectural position and size as explicit operands,
and preserves destination/source register effects. The lifter expresses
extract as a logical shift and mask, and insert as a preserved-field mask plus
the shifted source bits. Both formulas are 64-bit bitvector expressions and
are exact for every decoded field range. Since the decode context does not
select an ISA revision, Release 2 encodings are not gated for older MIPS64
cores.

The decoder covers selected integer SPECIAL operations, including trapping ADD/SUB and DADD/DSUB, nontrapping ADDU/SUBU and DADDU/DSUBU, signed/unsigned SLT, word and doubleword fixed/variable shifts, MOVZ/MOVN, and SYNC. MIPS64 Release 2 DROTR, DROTR32, and DROTRV decode with their distinct shift encodings and lift as 64-bit rotate-right bitvector formulas; a zero variable count avoids a width-sized shift. Since ISA revision selection is not modeled, Release 2 rotate encodings are accepted in the generic MIPS64 context. Immediate forms include ADDI/U, SLTI/U, logical immediates, LUI, and DADDI/U. The word ADD/ADDU/SUB/SUBU, ADDI/ADDIU, and fixed/variable shift forms operate on 32-bit values and sign-extend results to the 64-bit GPR; SLT/SLTU and SLTI/SLTIU produce a 64-bit 0/1 result. It also covers word MULT/MULTU/DIV/DIVU and doubleword DMULT/DMULTU/DDIV/DDIVU, 64-bit HI/LO moves, J/JAL, register jumps, BEQ/BNE/BLEZ/BGTZ/BLTZ/BGEZ and their likely forms, BLTZAL/BGEZAL and likely link variants, which write PC+8 to r31 regardless of branch outcome, byte/halfword/word and unaligned merge loads/stores, including LDL/LDR/SDL/SDR, plus LD/SD/LWU and LL/SC/LLD/SCD. LL and LL.D sign-extend their loaded values to 64 bits; SC and SCD conditionally write memory and return the success result in the target GPR. Word and doubleword multiply/divide remain named HI/LO intrinsics; their exceptional cases and exact result extension behavior are not evaluated. Its scalar COP1 subset includes LWC1/LDC1/SWC1/SDC1, S/D-format ADD/SUB/MUL/DIV/SQRT/ABS/MOV/NEG and conditional MOVF/MOVT/MOVZ/MOVN, all 16 compare predicates selecting FCC0-FCC7, BC1F/BC1T and branch-likely BC1FL/BC1TL selecting FCC0-FCC7, MFC1/DMFC1/CFC1/MTC1/DMTC1/CTC1, and selected S/D/W/L conversions (including fixed-rounding W/L conversions). COP1 transfers support FCCR25, FEXR26, FENR28, and FCSR31; the separate control-register views are tracked alongside aggregate FCSR state. COP1 decode carries FPR width, GPR/FPR/FCSR read/write, memory, and delay-slot effects. The decompiler keeps conversions and transfers as named typed intrinsics, including MFC1's 32-bit sign extension, and models FCSR state as an architectural effect. Likely conditional branches bypass their delay slot on the not-taken path. Control transfers retain their classic delay-slot count, and MIPS64 continuation arithmetic uses the 64-bit address domain. Reserved encodings and unsupported instructions are kept distinct from truncated input. The stack analyzer understands DADDIU stack/frame adjustments and common DADDU register-copy idioms.

This is an instruction and analysis subset, not full MIPS64 ISA or ABI support. Unaligned merge operations are decoded with merge/read-modify-write effects and retained as byte-order-tagged typed intrinsics. The processor library also exposes a pure byte-lane evaluator for LWL/LWR/LDL/LDR/SWL/SWR/SDL/SDR, including exact merged values, GPR byte masks, memory byte masks, and sign extension for word loads. The shared decompiler IR does not yet represent dynamic byte-granular memory effects, so lifted merge operations remain typed intrinsics instead of being lowered to ordinary full-width loads or stores. COP1 now decodes all 16 classic (pre-Release 6) S/D compare predicates across FCC0-FCC7 and retains each predicate, operands, and FCSR write as a named intrinsic; host floating-point evaluation remains intentionally absent. COP1 rounding modes and exception/NaN behavior are retained as named intrinsic effects rather than evaluated. BC1TL/BC1FL branch-likely forms select FCC0-FCC7, annul the delay slot on the not-taken path, and execute it on the taken path. REGIMM link-likely forms now annul their delay slot on the not-taken path; their r31 link value is modeled as a pre-slot write. The LL/SC reservation monitor is not modeled. Unsupported REGIMM suboperations, unsupported control-register selectors, other coprocessors, compressed modes, ISA revision selection, and MIPS-specific relocation evaluation remain outside this slice. Static address propagation is described below. FCSR alias effects are modeled in lifted SSA as described below. ELF64 identification alone does not establish a particular psABI.

## Static address propagation

Function-reference analysis propagates exact MIPS64 GPR address values through
supported `LUI`, immediate add/OR, `DADDU`/word add-subtract, and `DSLL`/
`DSLL32` sequences. It also follows `LD` pointer loads only from readable,
initialized bytes whose full 64-bit slot is not relocation-covered, using the
image byte order. Link writes from `JAL`, `JALR`, and `BLTZAL`/`BGEZAL`
(including likely forms) seed the decoded GPR destination with PC+8 only when
that address is representable and points to initialized executable bytes after
the classic delay slot. JALR with rd=zero creates no link value. Subsequent
arithmetic and indirect jumps can then resolve code references. CFG joins keep
a value only when every incoming path agrees, and propagation stops at fixed
graph and iteration budgets. Indirect control targets must be aligned and lie
in executable segments.

MIPS HI16/LO16 and any other unsupported, incomplete, or ambiguous instruction
relocations remain opaque. A relocation-covered instruction is never used as
an immediate source for static address reconstruction, so the encoded halfword
is not mistaken for an unrelocated address. Static pointer reads likewise
reject any relocation-covered byte range. HI16/LO16 records are not paired or
resolved; in particular, their symbol and addend identities are never inferred
from nearby raw immediates. N32 propagation and other ABI details remain
outside this 64-bit address-state slice.

The decompiler lifts the currently decoded integer subset into shared SSA. It preserves 64-bit arithmetic, sign-extending word operations and loads, zero-extending LWU, doubleword fixed and variable shifts (variable counts explicitly mask to six bits), effective-address loads/stores, typed unaligned merge intrinsics, common equality and signed conditional branches, JR-to-ra returns, and HI/LO dataflow. Word and doubleword multiply/divide are typed named intrinsics with HI/LO writes; multiplication width and division exceptional behavior are not evaluated. COP1 comparisons and branch predicates identify the selected FCC number. MFC1/DMFC1/MTC1/DMTC1 lower as typed bitcast/truncate/sign-extension SSA transfers, and CFC1/CTC1 on aggregate FCSR31 lower as 32-bit control-word transfers. CFC1 FCCR/FEXR/FENR now extracts their architectural fields from aggregate FCSR; CTC1 to those views updates only their corresponding FCSR fields and preserves the rest. FCCR[7:1] maps to FCSR[31:25], FCCR[0] to FCSR[23], FEXR maps Cause[17:12] and Flags[6:2], and FENR maps Enables[11:7], FS[24], and RM[1:0]. Runtime reserved-bit validation and CTC1 exceptions are not evaluated. COP1 arithmetic and numeric conversions retain typed intrinsic operands/results and FCSR effects. S/D conditional moves retain their old destination, source, exact FCC or GPR condition, and a conservative typed output; MOVF/MOVT read the selected FCC from FCSR without changing flags. Host floating-point evaluation, runtime rounding, NaN behavior, and exception flags remain unevaluated. Trapping DADD/DADDI and DMULT/DDIV families remain named intrinsics because overflow, exact wide-product, and exceptional division results are not modeled. SCD retains its conditional-store and success-result effects. Ordinary delay-slot statements execute before the delayed transfer in the lifted block, while JAL/JALR link writes remain before the slot; branch predicates, indirect call targets, and return values use their pre-slot SSA snapshot. Branch-likely predicates select the taken edge before the slot: the taken path executes the slot and then transfers, while the not-taken path annuls the slot and continues at PC+8. Delay-slot execution remains explicit in the CFG.

CLZ/CLO lift as a 32-bit count over the low word (with the source word
constraint described above), and DCLZ/DCLO lift as 64-bit counts. Pseudocode
keeps these as explicit `zext(clz(...))`, `zext(clo(...))` expressions instead
of opaque instruction intrinsics. Since each count is in the range 0–64, the
zero extension retains the exact result in the 64-bit GPR. DEXT variants lift
to a logical right shift followed by a field mask; DINS variants preserve bits
outside the selected field and combine the shifted source field. Invalid
operand shapes or ranges fail closed rather than rendering an approximate
bitfield operation.


The shared ABI classifier exposes an explicit mips_n64 convention for Linux N64 signatures. It models integer/pointer scalars in A0-A7, floating scalars in the matching F12-F19 argument slot, integer-only structure/union arguments up to 32 bytes as 8-byte chunks across A0-A7 and the stack, array parameters as indirect pointers, scalar returns in V0/F0, and integer-only aggregate returns up to 16 bytes in V0/V1. Larger aggregate returns use a hidden A0 result pointer. Stack overflow arguments use aligned 8-byte slots with 16-byte stack alignment. Floating-field/vector/recursive/unresolved aggregates, unsupported scalar widths, vectors, variadic signatures, and aggregates over 32 bytes are rejected; floating-field aggregate returns require the additional F0/F2 PCS rules and stay unsupported. This models the Linux N64 hard-float source ABI for declared prototypes; the API has no endian or soft-float selector, so it neither selects nor claims the soft-float variant. N64 classification is never inferred from ELF class alone. The MIPS N32 scalar profile is described below; N32 and O32 aggregate and variadic details remain outside this N64 classifier description.


Integer encoding and operation details follow the [MIPS64 Instruction Set Reference, Revision 5.04](https://repo.oss.cipunited.com/archives/mips_pdf/MD00087-2B-MIPS64BIS-AFP-05.04.pdf), including the REGIMM branch-and-link operation and LL/SC result effects.

The FPU control-register aliases are based on the CFC1/CTC1 field mappings in
the [MIPS32 Instruction Set, Revision 5.01](https://s3-eu-west-1.amazonaws.com/downloads-mips/documents/MD00086-2B-MIPS32BIS-AFP-05.04.pdf)
and cross-checked against Ghidra's [MIPS register declarations](https://github.com/NationalSecurityAgency/ghidra/blob/master/Ghidra/Processors/MIPS/data/languages/mips.sinc).
HexLab translates those field relationships into aggregate-FCSR SSA updates;
no Ghidra source was copied.
# Linux MIPS N32 ELF

ELF32 `EM_MIPS` inputs with `EF_MIPS_ABI2` (`e_flags & 0x20`) are routed to
the MIPS64 instruction decoder while their image address space remains 32-bit.
This recognizes the N32 ELF ABI marker; ELF32 MIPS files without that marker
continue to use the MIPS32 decoder. ELF64 MIPS continues to use MIPS64.

The loader does not infer N32 from ELF class alone. The N32 decoder route
currently provides the shared MIPS64 instruction subset and a 32-bit address
space. CLI and pseudocode decompilation select the N32 ABI profile from that
address-space width; it uses 32-bit pointers and 64-bit argument registers and
slots. The type system also accepts an explicit `mips_n32` function
convention. N32-specific relocation, unwind, and core-register integration
remain incomplete. Variadic N32 classification remains unsupported.

Register-register conditional traps TGE/TGEU/TLT/TLTU/TEQ/TNE are decoded with both 64-bit GPR inputs and the encoded 10-bit software trap code. The REGIMM immediate forms TGEI/TGEIU/TLTI/TLTIU/TEQI/TNEI are also decoded with a 64-bit source register and a sign-extended 16-bit immediate; the `u` suffix controls unsigned comparison and does not change immediate extension. The lifter records the exact signed or unsigned comparison predicate as the condition of a possible trap edge, while preserving the register-form software trap code as a separate operand. These exceptional edges remain separate from normal CFG successors. MIPS exception-vector selection, trap-code delivery, and handler dispatch are not modeled.
