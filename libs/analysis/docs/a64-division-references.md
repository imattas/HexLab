# AArch64 division reference propagation

The register reference analysis propagates exact `UDIV` and `SDIV` results for
32-bit W and 64-bit X operands. It matches the operand, register-effect, width,
and zero-register record against the native four-byte encoding before using the
operation. Relocation-covered instructions remain unresolved.

Unsigned division uses the encoded width. Signed division truncates toward
zero, returns zero for a zero divisor, and returns the minimum signed value
for the minimum-value divided by minus-one overflow case. These rules follow
Arm's [A64 ISA overview](https://developer.arm.com/-/media/Files/pdf/graphics-and-multimedia/ARMv8_InstructionSetOverview.pdf).
A known zero numerator or divisor proves a zero result even when the other
input is unknown. Other unknown inputs discard the destination's previous
value. W results zero-extend into the corresponding X register.

An exact result remains available to later supported arithmetic, memory, and
indirect-control analysis. Only a result mapped to addressable image bytes
emits a reference at the division instruction. Exact definitions retain the
bounded producer chain, including its W/X register views; a later unknown
division invalidates both views. The existing CFG agreement, cancellation,
and 32-producer limits apply. This is static integer dataflow and does not
infer a source-level pointer type or execute target code.
