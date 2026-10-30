# AArch64 CLZ and CLS semantics

The scalar one-source decoder recognizes W/X `CLZ` and `CLS` alongside the
existing RBIT/REV family. `evaluate_a64_bit_operation_instruction` computes
the result from a caller-supplied source value after validating the decoded
register operands and effects.

`CLZ` returns the number of leading zero bits in the selected 32- or 64-bit
source. `CLS` returns the number of leading bits equal to the sign bit, not
counting the sign bit itself; the result ranges from zero through 31 for W
forms and zero through 63 for X forms. An XZR/WZR source is treated as zero.
These instructions do not read or update NZCV. The evaluator returns a
zero-extended count and does not sample or commit register state.
