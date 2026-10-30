# RISC-V scalar floating comparisons

`evaluate_riscv_float_compare_instruction` handles decoded `FEQ.S`, `FLT.S`, `FLE.S`, `FEQ.D`, `FLT.D`, and `FLE.D` using raw IEEE-754 operand bits. The integer destination result is 0 or 1. No host floating-point operations are used, so signaling NaNs and exception behavior are classified explicitly.

Comparisons with either operand NaN return false. `FEQ` sets accrued NV only when an operand is signaling NaN; ordered `FLT` and `FLE` set NV for either quiet or signaling NaNs. Positive and negative zero compare equal. All other numeric comparisons use their IEEE sign/magnitude ordering. For single-precision forms, inputs are low-32-bit binary32 encodings with no high bits set; double-precision forms consume the full 64-bit encoding.

The decoded-instruction adapter checks the integer destination, two floating-point sources, and FFLAGS effects. It returns the new boolean value and exception bit for the caller to commit; it does not update FCSR itself. The helper does not cover Zfa quiet comparison variants or other floating-point arithmetic.
