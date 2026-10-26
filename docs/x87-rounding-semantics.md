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

The caller-driven API evaluates `FMUL` for zero and finite operands, including
normalization of subnormal and pseudo-denormal inputs when the result is
normal. Zero products preserve the XORed sign and clear C1 while preserving
other status bits. Finite products form the significand product with integer
limbs and apply FCW precision-control and rounding-control fields.

The caller-driven `FADD`/`FSUB` API handles finite binary80 operands and signed
zeros. It aligns significands with an integer shift-right-jam path, normalizes
cancellation results, rounds to the selected PC/RC, and reports DE, PE, OE,
C1, and exception-delivery state. Opposite-sign exact cancellation produces
negative zero only under round-toward-negative-infinity; same-sign zero inputs
retain their sign. True subnormal inputs set DE and stop before arithmetic when
DM is clear. Gradual-underflow result rounding remains unsupported.

For x87 register arithmetic, an unmasked PE still commits the rounded value
while marking exception delivery incomplete. Unmasked overflow remains
fail-closed because the biased x87 register result is not modeled. Masked
overflow returns the RC-selected infinity or largest finite value. These
operations do not use host floating point. NaN/infinity operands, reserved
precision-control encoding 01, and unsupported encodings fail closed. The
operation and exception rules follow Intel's [x87 floating-point operation
and exception definitions](https://cdrdv2-public.intel.com/835781/325462-sdm-vol-1-2abcd-3abcd-4.pdf).
Ghidra's SLEIGH language documents floating-point operations as explicit
p-code operators, a reference for symbolic arithmetic coverage rather than
x87 exception behavior ([SLEIGH reference](https://ghidra.re/ghidra_docs/languages/html/sleigh)).
Its native decompiler `FloatFormat::roundToNearestEven` uses a halfway bit,
lower sticky bits, and the retained low bit for ties; this evaluator uses the
same general guard/sticky decision shape over integer limbs while honoring x87
RC/PC state ([Ghidra native float.cc](https://github.com/NationalSecurityAgency/ghidra/blob/master/Ghidra/Features/Decompiler/src/decompile/cpp/float.cc)).
