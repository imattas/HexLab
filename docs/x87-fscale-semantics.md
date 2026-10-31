# x87 FSCALE Semantics

`evaluate_x87_scale` evaluates the caller-supplied binary80 values for
`ST(0)` and `ST(1)`. It truncates `ST(1)` toward zero and adds that integer to
the `ST(0)` exponent. An in-range normal result preserves all 64 significand
bits, independent of FCW precision control. When scaling crosses the binary80
normal range, the helper normalizes subnormal inputs and rounds only as needed
for gradual underflow or overflow, using FCW rounding control.

The result records the updated FSW, normal completion, and whether a valid
`ST(0)` output exists. Unmasked invalid, denormal, overflow, or underflow
exceptions suppress the output. A masked overflow produces infinity or the
largest finite value according to FCW.RC; a masked massive underflow produces
signed zero or the least subnormal for directed rounding. Inexact scaling sets
PE, and unmasked PE reports `completed=false` while retaining the rounded
result, matching x87 precision exception retirement. OE/UE also imply PE. The
C1 output is computed for rounding; C0/C2/C3 are marked undefined by
`status_word_defined_mask`.

Normal zero/infinity cases and NaN propagation follow Intel's FSCALE class
table. A signaling NaN or unsupported binary80 encoding raises IE; quiet NaNs
propagate. A denormal operand sets DE when masked and prevents completion when
DE is unmasked. Pseudo-denormals use their equivalent exponent-one value and
do not set DE. Stack tags/TOP, stack-fault generation, pending exception
delivery, and committing the returned value remain caller-owned.

The exponent in `ST(1)` is truncated without converting out-of-range values to
a host integer. Finite scales whose integral magnitude necessarily exceeds
the binary80 exponent range use the exact overflow/underflow path. Unsupported
unnormal encodings are treated as invalid operands, consistent with the
instruction's #IA definition.

These rules follow Intel's [64 and IA-32 Architectures Software Developer's
Manual, Volume 2, FSCALE](https://cdrdv2-public.intel.com/774492/325383-sdm-vol-2abcd.pdf)
and its [instruction reference](https://intel.github.io/SDM/instruction/FSCALE.html).
