# Zfa immediate floating-point loads

The scalar decoder accepts `FLI.H`, `FLI.S`, and `FLI.D` on RV32 and RV64,
including compressed-enabled modes when the next instruction is 32 bits.
Each uses OP-FP `0x53`, funct7 `0x7a`, `0x78`, or `0x79`, respectively,
`rs2=1`, and `funct3=0`. The five-bit `rs1` field is an unsigned constant
table selector. It never becomes a GPR read. Other half-precision FMV forms,
nonzero funct3 values, and Q-format instructions remain outside this slice.

Generic dispatch and formatting retain the distinct opcode, the physical
64-bit FPR destination, and the five-bit selector immediate. FLI writes only
that destination. It does not read `frm` or `fflags`, accrue exception flags,
access memory, or select a rounding mode. New opcode IDs are appended so
previous decoded and generic instruction IDs remain stable.

`evaluate_riscv_fli_operation` is the shared raw-bit semantic API for all
three formats. It returns logical IEEE-754 value bits and width without
using host floating-point arithmetic. Unsupported opcodes and selectors
above 31 return no result. Typed lifting uses the same helper to assign an
exact binary16, binary32, or binary64 constant. Malformed generic operand,
access, rounding, or register-effect records retain an opaque malformed
instruction instead of producing a constant assignment.

The half-precision table has these format-specific entries:

| Selector | Value | Binary16 bits |
| --- | --- | --- |
| 1 | Minimum positive normal, 2^-14 | `0x0400` |
| 2 | Subnormal 2^-16 | `0x0100` |
| 3 | Subnormal 2^-15 | `0x0200` |
| 28 | 2^15 | `0x7800` |
| 29, 30 | Positive infinity | `0x7c00` |
| 31 | Canonical quiet NaN | `0x7e00` |

Selectors 0 and 4 through 27 have the same numerical values as their S/D
counterparts. Selector 1 has a different minimum-normal value in each
format. Selector 29 produces 2^16 in S/D, but infinity in H without raising
an overflow flag. All 32 selectors are valid.

FLI.H requires Zfa and either Zfh or Zvfh; FLI.D requires D in addition to
Zfa. The current decoder does not gate instructions by extension profile.
The helper and lift represent logical values; physical FPR NaN-boxing and
128-bit FPR support for FLI.Q remain unimplemented. This change does not
add general half-precision arithmetic or conversions.

The encoding, constants, and absence of exception flags follow the ratified
[RISC-V Zfa 1.0 load-immediate specification](https://docs.riscv.org/reference/isa/v20260120/unpriv/zfa.html#_load_immediate_instructions).
