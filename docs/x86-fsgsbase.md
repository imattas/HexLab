# x86 FS/GS base transfers

The native x86-64 decoder recognizes the four FSGSBASE register forms:
`RDFSBASE`, `RDGSBASE`, `WRFSBASE`, and `WRGSBASE` (`F3 0F AE /0`–`/3`
with a register ModRM operand). REX.B extends the GPR index. The default
operand width is 32 bits and REX.W selects 64 bits. These instructions are
invalid outside 64-bit mode; other `0F AE` forms and combinations with an
operand-size override remain outside this coverage.

FS and GS base values are distinct 64-bit register facts, separate from the
16-bit segment selectors. Reads record the selected base as an input and the
GPR as an output. A 32-bit read takes the low half of the base and zeroes the
upper half of the destination GPR. Writes record the GPR as an input and the
selected base as an output; 32-bit writes zero the upper half of the base.
None of these forms changes arithmetic flags or accesses memory.

The decompiler lifts each form as a named intrinsic with explicit base and GPR
inputs/outputs. `evaluate_x86_fsgsbase_instruction` validates the decoded
facts and computes the transfer value supplied by the caller. The decoder,
lifter and evaluator model a successful instruction: CPUID availability,
CR4.FSGSBASE enablement, and the canonical-address fault on a 64-bit write
remain the caller's responsibility. Segment-relative memory address lifting
is not connected to these base facts yet, so this does not claim complete TLS
address recovery.

Instruction encodings, widths and architectural conditions follow the
[Intel 64 and IA-32 instruction reference](https://www.intel.com/content/dam/www/public/us/en/documents/manuals/64-ia-32-architectures-software-developer-vol-2b-manual.pdf).
