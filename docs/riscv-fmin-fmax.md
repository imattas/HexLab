# RISC-V scalar FMIN/FMAX

`evaluate_riscv_float_min_max_instruction` evaluates decoded `FMIN.S`,
`FMAX.S`, `FMIN.D`, and `FMAX.D` using raw IEEE bit patterns. It returns the
selected value and accrued `fflags` bits. One NaN selects the numeric operand;
two NaNs return the canonical NaN. Signaling NaNs set NV. When both operands
are zero, minimum selects negative zero if present and maximum selects
positive zero if present.

The helper validates the decoded FPR and `fflags` effects. It does not merge
the returned exception bit into FCSR, resolve an architectural trap, or commit
the destination. The caller supplies both source bit patterns.
