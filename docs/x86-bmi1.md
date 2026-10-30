# x86 BMI1 integer instructions

The original x86-64 decoder supports the VEX BMI1 family `ANDN`, `BEXTR`,
`BLSI`, `BLSMSK`, and `BLSR`, with 32-bit or 64-bit integer operands selected
by VEX.W. Existing legacy `TZCNT` support is unchanged. These are fallthrough
instructions with a register destination, register or memory input, and a
FLAGS write; they neither write memory nor read prior destination/FLAGS values.
For 32-bit destinations, the usual x86-64 zero-extension rule applies.

`ANDN` retains destination, inverted register source, then register/memory
source. `BEXTR` retains destination, register/memory data source, then register
control source. The lowest-set-bit family has two operands: VEX.vvvv is the
destination, and ModRM.reg selects `/1` BLSR, `/2` BLSMSK, or `/3` BLSI. The
group field never creates an extra register dependency. Effective addresses,
segments, RIP-relative resolution, and memory read effects use the shared
ModRM/SIB machinery. Canonical formatting and typed decompiler
`x86_<mnemonic>` intrinsics retain this order and all register/FLAGS outputs.

`evaluate_x86_bmi1` computes bounded 32-/64-bit results and individual defined
status flags. `evaluate_x86_bmi1_instruction` validates the decoded operand
shape and binds caller-provided source values in printed order, excluding the
destination. Neither helper accesses memory or mutates machine state. BEXTR
uses the low two control bytes for start and length, returns zero for an
out-of-range start or zero length, and clips extraction at the operand edge.
The lowest-set-bit operations handle zero without host signed overflow:
BLSI returns zero with CF clear; BLSR returns zero with CF set; BLSMSK returns
all ones with CF set and ZF clear. OF is cleared. SF and ZF follow the result,
except BEXTR leaves SF undefined. PF and AF remain explicitly undefined.

VEX.L must be zero. Reserved BLS group selectors are rejected; legacy
mandatory prefixes, REX, or LOCK before VEX are rejected by the shared prefix
validator. Unsupported prefix/map combinations do not receive BMI1 effects.
Truncated ModRM, SIB, or displacement bytes follow the shared truncated status.
Native VEX decoding remains limited to x86-64 execution contexts. VEX forms
in 16-/32-bit contexts, EVEX/APX forms, CPU-feature checks, runtime machine
execution, and ordinary decompiler expression/constant folding remain outside
this slice. The overall x86 capability remains partial.

Encoding and flag references: [Intel XED BMI definitions](https://github.com/intelxed/xed/blob/main/datafiles/hswbmi/hsw-bmi-vex-isa.xed.txt)
and [Ghidra BMI1 SLEIGH definitions](https://github.com/NationalSecurityAgency/ghidra/blob/master/Ghidra/Processors/x86/data/languages/bmi1.sinc).
Undefined flags stay undefined even where a reference implementation computes
extra flags as an implementation convenience.
