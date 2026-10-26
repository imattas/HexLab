# x87 Rounding Semantics

`evaluate_x87_round_to_integral` evaluates the numeric and status effects of
FRNDINT for finite normal/subnormal values, pseudo-denormals, and infinities.
It selects
nearest with ties to even, toward negative infinity, toward positive infinity,
or toward zero from the control word's RC field. Values already integral and
infinities retain their original bit pattern; a nonintegral finite value is
rounded to an exactly representable binary80 integer, preserving the sign when
the rounded result is zero.

The precision flag is sticky when fractional bits are discarded. If that
exception is unmasked, the returned result has no value and `completed` is
false, representing that ST(0) was not written. C1 is set when the rounded
numeric result is greater than the source, and cleared otherwise. C0/C2/C3 are
architecturally undefined for FRNDINT, so `status_word_defined_mask` clears
their bits and identifies only the status bits this evaluator promises. Other
status bits are preserved; unmasked precision also sets ES and B.

NaNs and unsupported binary80 encodings return no result. This API does not
model stack underflow, memory access, pending-exception delivery, or decompiler
SSA integration. The behavior follows Intel's [FRNDINT instruction
reference](https://cdrdv2-public.intel.com/812383/253666-sdm-vol-2a.pdf).
