# MIPS64 multiply semantics helper

`evaluate_mips64_multiply` evaluates the classic HI/LO product operations
`MULT`, `MULTU`, `DMULT`, and `DMULTU` without mutating architectural state.
The caller supplies both GPR values; the result contains the post-instruction
64-bit `HI` and `LO` values.

The word forms consume the low 32-bit words and require each input GPR to be a
sign-extended word, as required for predictable results on MIPS64. The helper
returns no value when either supplied word operand violates that constraint.
It returns each 32-bit half of the 64-bit product sign-extended to 64 bits,
including for `MULTU`, matching the MIPS64 word-operation result rule.

The doubleword forms produce the complete 128-bit product. `DMULT` interprets
both inputs as signed two's-complement integers; `DMULTU` uses unsigned
integers. A portable 32-bit-limb implementation computes the exact high and
low halves without compiler-specific 128-bit integer types. These operations
do not raise arithmetic exceptions.

This helper does not model multiply latency, interlocks, HI/LO architectural
state, or instruction scheduling. The shared decompiler continues to represent
the operations as typed HI/LO intrinsics rather than evaluating runtime
operands. Division and multiply/divide corner behavior remain outside this
slice. The word and doubleword result rules follow the [MIPS64 instruction set
reference](https://s3-eu-west-1.amazonaws.com/downloads-mips/documents/MIPS_Architecture_MIPS64_InstructionSet_%20AFP_P_MD00087_06.05.pdf).

`evaluate_mips64_multiply_instruction` connects decoded `MULT`, `MULTU`,
`DMULT`, and `DMULTU` instructions to this evaluator. It accepts only a
MIPS64 instruction with two typed GPR reads and decoded HI/LO writes;
`evaluate_mips64_multiply_accumulate_instruction` applies the same checks and
also requires decoded HI/LO reads for `MADD`, `MADDU`, `MSUB`, and `MSUBU`.
Both reject nonzero caller values for a source encoded as GPR zero. They still
take caller-sampled register values and do not own or commit machine state.
