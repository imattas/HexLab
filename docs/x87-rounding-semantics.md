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

The caller-driven API also evaluates `FMUL` for zero and finite operands,
including normalization of subnormal and pseudo-denormal inputs when the
result is normal. Zero products preserve the XORed sign and clear C1 while
preserving other status bits. Finite products form the significand product
with integer limbs, apply FCW
precision-control and rounding-control fields, and reports PE, OE, C1, and
unmasked-exception retirement. It does not use host floating point.
NaN/infinity operands and gradual-underflow result rounding are not
implemented; those cases return no result. Reserved precision-control encoding
01 also fails closed. This scope follows Intel's [x87
floating-point operation and exception definitions](https://cdrdv2-public.intel.com/835781/325462-sdm-vol-1-2abcd-3abcd-4.pdf).
Ghidra's SLEIGH language documents floating-point operations as explicit
p-code operators, a reference for symbolic arithmetic coverage rather than
x87 exception behavior ([SLEIGH reference](https://ghidra.re/ghidra_docs/languages/html/sleigh)).
Its native decompiler `FloatFormat::roundToNearestEven` uses a halfway bit,
lower sticky bits, and the retained low bit for ties; this evaluator uses the
same general guard/sticky decision shape over integer limbs while honoring x87
RC/PC state ([Ghidra native float.cc](https://github.com/NationalSecurityAgency/ghidra/blob/master/Ghidra/Features/Decompiler/src/decompile/cpp/float.cc)).
