# x87 FXTRACT semantics

`evaluate_x87_extract` computes the two binary80 values produced by FXTRACT.
For finite nonzero inputs, the significand keeps the input sign and is
normalized to the `[1, 2)` magnitude range. The exponent result is the exact
unbiased exponent encoded as a binary80 integer. In the returned result,
`significand` names the new ST(0), and `exponent` names ST(1), matching the
architectural push order.

Signed zero reports the divide-by-zero sticky bit. If ZE is masked, the
significand preserves the signed zero and ST(1) receives negative infinity; if
ZE is unmasked, the result is incomplete and the evaluator reports ZE/ES/B
without output values. Finite denormal operands report DE; a masked DE
continues with normalized exact outputs, while an unmasked DE prevents the
outputs. Pseudo-denormals are treated as their equivalent normalized value.
Infinities produce a signed unit significand and positive-infinity exponent.

Quiet NaNs propagate to both outputs, preserving the source sign and payload
without raising invalid-operation. Signaling NaNs report `invalid_operation`
and set sticky IE. If FCW.IM masks invalid-operation, the quiet bit is set in
both output NaNs while all remaining payload/sign bits are preserved. With
invalid-operation unmasked, IE/ES/B are set, `completed` is false, and both
optional outputs are absent; the caller must suppress the replacement and
push. Existing status bits are preserved. NaN propagation follows Intel SDM
Volume 1, section 4.8.3.4's [single-operand NaN rules](https://www.intel.com/content/dam/support/us/en/documents/processors/pentium4/sb/25366521.pdf)
and FXTRACT's invalid-operation definition.

The API fails closed for unsupported binary80 encodings, including pseudo-NaNs
with a clear explicit integer bit and unnormal encodings. It does not model
stack overflow/tag state, TOP updates, pending exception delivery, or
stack-fault condition codes; the caller handles the push. No transcendental or
host floating-point arithmetic is involved. Special cases and push behavior
follow Intel's [FXTRACT reference](https://www.intel.com/content/dam/www/public/us/en/documents/manuals/64-ia-32-architectures-software-developer-vol-2a-manual.pdf).
