# AArch64 integer division evaluation

`evaluate_a64_divide_instruction` evaluates decoded W/X `UDIV` and `SDIV`
using caller-supplied raw GPR values. It masks operands to the instruction
width, treats WZR/XZR operands as zero, and returns W results zero-extended.
Both signed and unsigned division return zero for a zero divisor. Signed
minimum divided by negative one returns the minimum value, as required by A64.

The adapter validates decoded GPR widths, register effects, and the
three-operand form. Division does not update NZCV. The caller samples other
registers and commits the destination; the helper does not execute surrounding
control flow or model instruction timing.
