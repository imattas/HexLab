# x87 FXAM Semantics

`evaluate_x87_examine` computes the numeric class and status-word outputs of
`FXAM` from a caller-supplied binary80 value, current FSW, and physical
register empty-tag state. It reports unsupported encodings, NaNs, normal
finite values, infinities, signed zero, empty registers, and denormals. A
pseudo-denormal encoding (exponent zero with the explicit integer bit set) is
classified as normal because it has the value of the corresponding minimum
normal encoding.

The evaluator replaces C0, C1, C2, and C3 while preserving all other FSW bits.
C3:C2:C0 encode unsupported=`000`, NaN=`001`, normal=`010`, infinity=`011`,
zero=`100`, empty=`101`, and denormal=`110`; C1 receives the raw ST(0) sign
even when the register tag is empty. `FXAM` raises no floating-point
exceptions. The caller resolves logical ST(0) through its current TOP and
passes the selected physical tag; the evaluator does not mutate stack state,
TOP, or tags.

This is a caller-driven semantic helper. The x87 decoder already reports
FXAM's FSW effects, but the decompiler does not yet fold FXAM from concrete
stack-value and tag facts. Classification and condition-bit behavior follow
the Intel [64 and IA-32 Software Developer's Manual](https://cdrdv2-public.intel.com/825743/325462-sdm-vol-1-2abcd-3abcd-4.pdf),
FXAM instruction entry.
