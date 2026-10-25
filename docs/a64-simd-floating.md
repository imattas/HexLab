# AArch64 AdvSIMD floating-point arithmetic

The A64 decoder recognizes vector three-register FADD, FSUB, FMUL, FDIV,
FMAX, and FMIN for IEEE single- and double-precision lanes. Supported
arrangements are 2S/4S in D/Q registers and 2D in Q registers. Reserved
arrangements, including D-form 64-bit lanes, are rejected. The decoder records
the operation, vector/lane widths, all three SIMD register operands, and
read/write effects. As with the existing integer AdvSIMD subset, a D-form
destination also records the architectural zeroing of the upper 64 bits.

Disassembly prints lane arrangements (for example `fadd v0.4s, v1.4s, v2.4s`).
Decompiler output retains each operation as a typed named intrinsic with
floating vector lane types; it does not lower a packed operation to scalar
arithmetic or pretend that a 64-bit D result preserves the old upper half.
Analysis consumes the decoder's normal register read/write metadata.

The lifting is descriptive, not an IEEE evaluator. It does not model FPCR
rounding modes, exception flags/traps, NaN payload/quieting rules, or exact
FMAX/FMIN NaN semantics. Scalar FP, half precision, fused operations,
comparisons, conversions, pairwise/reduction operations, and FP/SIMD loads and
stores remain unsupported by this feature slice.
