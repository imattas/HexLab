# x86 BMI2 integer instructions

The native x86-64 decoder recognizes the scalar BMI2 `MULX`, `PDEP`, `PEXT`,
`BZHI`, `RORX`, `SHLX`, `SHRX`, and `SARX` encodings. The supported forms use
32-bit or 64-bit operands, require `VEX.L=0`, and retain the explicit operand
order in `Instruction::operands`. `MULX` also records its implicit EDX/RDX
input; none of the shift/rotate/multiply/deposit/extract forms alter flags.
`BZHI` records its flag write effect.

The decompiler keeps these as `x86_<mnemonic>` intrinsics with typed result
widths when a single destination is present, and retains all recorded register
outputs for `MULX`. This preserves semantics without pretending the C-like
expression model represents all BMI2 behavior.

VEX-encoded forms are not currently enabled in the 16-bit or 32-bit execution
modes. EVEX/APX variants and other BMI1/BMI2 instructions are not covered.
