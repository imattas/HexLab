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

`PDEP` and `PEXT` use the VEX `0F38 F5 /r` form: ModRM.reg is the destination,
VEX.vvvv is the data source, and ModRM.r/m is the mask source. The mask source
may be a GPR or memory; the data source and destination are GPRs. `VEX.W=1`
selects 64-bit operands in long mode and is ignored in 32-bit mode. `VEX.L`
must be zero. `evaluate_x86_bmi2` deposits source bits into ascending set-mask
positions for `PDEP` and gathers selected bits into contiguous low positions
for `PEXT`. Inputs and output are width-masked; 32-bit results are zero
extended. `evaluate_x86_bmi2_instruction` validates the decoded operand order,
access/register effects, address form, and absence of flag or memory writes
before using caller-supplied source/mask values. Neither instruction reads or
writes FLAGS. Callers still own memory access, CPUID availability, and result
commit.
Encoding-width rules follow Intel's [BMI2 instruction reference](
https://www.intel.com/content/dam/www/public/us/en/documents/manuals/64-ia-32-architectures-software-developer-vol-2b-manual.pdf).

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

VEX-encoded forms are enabled in 32-bit and 64-bit execution modes; 16-bit
execution mode remains unsupported. SHLX/SHRX/SARX use 32-bit operands in
32-bit mode even with VEX.W=1. Their exact decode and flag-preserving evaluator
contract is documented in [BMI2 shifts](x86-bmi2-shifts.md).
EVEX/APX variants remain unsupported. The native VEX BMI1 family is
documented in [x86 BMI1 integer instructions](x86-bmi1.md).
