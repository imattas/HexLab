# x86 BMI2 integer instructions

The native x86-64 decoder recognizes the scalar BMI2 `MULX`, `PDEP`, `PEXT`,
`BZHI`, `RORX`, `SHLX`, `SHRX`, and `SARX` encodings. The supported forms use
32-bit or 64-bit operands, require `VEX.L=0`, and retain the explicit operand
order in `Instruction::operands`. `MULX` also records its implicit EDX/RDX
input; none of the shift/rotate/multiply/deposit/extract forms alter flags.
`BZHI` records its flag write effect.

`evaluate_x86_bmi2_shift_instruction` concretely evaluates register or
caller-fetched memory sources for `SHLX`, `SHRX`, `SARX`, and immediate-count
`RORX`. SHLX/SHRX/SARX take the runtime count-register value; all counts use
the low five or six bits for 32- or 64-bit operands. The helper does not change
flags, matching these BMI2 forms. Memory reads, count-register sampling,
CPUID checks, and destination commit remain caller-owned.

`evaluate_x86_bzhi_instruction` evaluates the masked source value and the
defined status flags for decoded 32- and 64-bit `BZHI`. The index is taken
from the low byte of its register value. Indices below the operand width keep
the corresponding low source bits; larger indices preserve the full source
and set CF. OF is cleared, while SF, ZF, and PF reflect the result; AF is
reported undefined. The caller supplies register or fetched-memory source and
index values and remains responsible for memory access and committing outputs.

The decompiler keeps these as `x86_<mnemonic>` intrinsics with typed result
widths when a single destination is present, and retains all recorded register
outputs for `MULX`. This preserves semantics without pretending the C-like
expression model represents all BMI2 behavior.

VEX-encoded forms are not currently enabled in the 16-bit or 32-bit execution
modes. EVEX/APX variants remain unsupported. The native VEX BMI1 family is
documented in [x86 BMI1 integer instructions](x86-bmi1.md).
