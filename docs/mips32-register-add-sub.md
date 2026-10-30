# MIPS32 register ADD/SUB

`evaluate_mips32_add_sub_instruction` evaluates decoded `ADD`, `ADDU`,
`SUB`, and `SUBU` from caller-supplied GPR values. `ADD` and `SUB` report a
signed-overflow exception and suppress the destination write when it occurs;
`ADDU` and `SUBU` wrap modulo 2^32. Writes to `$zero` are suppressed.

The adapter validates decoded operands and register effects and treats
`$zero` sources as zero. It returns the low 32-bit result and exception/write
status; exception delivery and destination commit remain caller-owned.
