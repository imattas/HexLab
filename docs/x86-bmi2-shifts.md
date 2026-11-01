# x86 BMI2 shifts

The native decoder recognizes three-byte VEX map `0F38`, opcode `F7`:

| VEX.pp | Instruction | Operand order |
| --- | --- | --- |
| 66 (1) | SHLX | ModRM.reg destination, ModRM.r/m source, VEX.vvvv count |
| F3 (2) | SARX | ModRM.reg destination, ModRM.r/m source, VEX.vvvv count |
| F2 (3) | SHRX | ModRM.reg destination, ModRM.r/m source, VEX.vvvv count |

VEX.L must be zero. Long mode uses 32-bit operands for W=0 and 64-bit for
W=1. In 32-bit mode W is ignored and all operands are 32 bits. Extended
registers require long mode. Register sources and memory sources share the
same width. ModRM/SIB/displacements determine the remaining instruction length;
there is no immediate count. Truncation and the 15-byte limit use the existing
decoder checks. Legacy mandatory prefixes, REX before VEX, and LOCK are invalid.
VEX.pp=0 selects BMI1 BEXTR and does not select a BMI2 shift.

`evaluate_x86_bmi2_shift` returns the width-truncated value and unchanged input
FLAGS. Counts are masked to five or six bits; zero effective count copies the
source. SARX fills from the sign bit using unsigned operations. SHLX/SHRX/SARX
have distinct opcodes from SHL/SHR/SAR and have no FLAGS register dependency;
their decoded flag masks are explicitly zero. A 32-bit result is zero-extended.

`evaluate_x86_bmi2_shift_flags_instruction` validates typed operands, access,
register effects, memory dependencies, and absent flag writes before delegating.
The existing value-only adapter shares this validation. RORX also shares the
pure evaluator and uses its decoded imm8. Callers supply source/count values
and incoming FLAGS; memory access and destination commit remain caller-owned.

Rules follow [Intel SDM Volume 2B, SARX/SHLX/SHRX](https://www.intel.com/content/dam/www/public/us/en/documents/manuals/64-ia-32-architectures-software-developer-vol-2b-manual.pdf).
CPUID enforcement, runtime exceptions, execution in real/v8086/16-bit modes,
and EVEX/APX forms are outside this slice. Validation is compile-only; no tests ran.
