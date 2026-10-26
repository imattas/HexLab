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

The caller-driven API evaluates `FMUL` for zero, finite, infinity, and NaN
operands, including normalization of subnormal and pseudo-denormal inputs.
Finite products form the exact significand product with integer limbs, then
apply FCW precision-control and rounding-control fields. Gradual underflow
rounds directly into the binary80 subnormal lattice, retaining fewer
significant bits as the exponent approaches the least subnormal. A rounded
result that reaches the least normal value is encoded as normal. With UE
masked, the underflow flag is raised only when the tiny result is inexact; with
UE unmasked, a tiny result raises UE even when exact. PE records discarded
bits, and C1 follows whether rounding moved the numeric result upward. An
unmasked UE reports UE/ES/B and withholds a value; masked UE returns the
rounded value. Denormal inputs set DE when masked, and stop before arithmetic
when DM is clear.

The caller-driven `FADD`/`FSUB` API handles finite, zero, infinity, and NaN
binary80 operands. It aligns finite significands with an integer
shift-right-jam path, normalizes cancellation results, rounds to the selected
PC/RC, and reports DE, PE, OE, C1, and exception-delivery state. Opposite-sign
exact cancellation produces negative zero only under round-toward-negative-
infinity; same-sign zero inputs retain their sign. Masked denormal operands
set DE and continue; an unmasked DE stops before arithmetic.

QNaNs propagate without IE. Masked SNaNs are quieted and raise IE; x87 NaN
source selection uses the SDM's QNaN preference and larger-significand rule.
Masked unsupported encodings and invalid arithmetic combinations return the
x87 floating-point indefinite QNaN. The modeled invalid arithmetic cases are
opposite-signed infinities for addition, like-signed infinities for
subtraction, and zero multiplied by infinity. Unmasked IE sets IE/ES/B and
returns no destination value. Ordinary infinities and finite-plus-infinity
results retain their architectural signs.

For x87 register arithmetic, an unmasked PE still commits the rounded value
while marking exception delivery incomplete. Unmasked overflow remains
fail-closed because the biased x87 register result is not modeled. Masked
overflow returns the RC-selected infinity or largest finite value. These
operations do not use host floating point. Reserved precision-control encoding
01 and unmasked UE withhold the result value. The operation and
exception behavior follows Intel's [x87 floating-point operation and exception
definitions](https://cdrdv2-public.intel.com/874240/325462-090-sdm-vol-1-2abcd-3abcd-4.pdf).
Intel specifies x87 NaN source priority. Ghidra's native decompiler
`FloatFormat::roundToNearestEven` uses halfway, lower sticky, and retained-low
bits for ties; this evaluator applies the same general guard/sticky decision
shape over integer limbs while honoring x87 RC/PC state
([Ghidra native float.cc](https://github.com/NationalSecurityAgency/ghidra/blob/master/Ghidra/Features/Decompiler/src/decompile/cpp/float.cc)).
