# MIPS64 doubleword add/sub semantics

`evaluate_mips64_add_sub_instruction` handles decoded `DADD`, `DADDU`, `DSUB`, `DSUBU`, `DADDI`, and `DADDIU`. `DADD`, `DSUB`, and `DADDI` return the modulo-2^64 bit result and report whether signed overflow raises an arithmetic exception. The `U` forms wrap without an overflow exception; `DADDIU` still uses its sign-extended 16-bit immediate.

The evaluator validates the MIPS64 operand and access shape, checks caller-supplied zero-register values, and reports whether the destination write occurs. Writes to `$zero` are suppressed, while overflow is still reported for trapping forms. The caller handles the exception and commits the returned value. No memory or HI/LO state is involved.
