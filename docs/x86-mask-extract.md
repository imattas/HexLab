# x86 vector sign-mask extraction

The original decoder supports legacy `MOVMSKPS`, `MOVMSKPD`, and `PMOVMSKB`
forms plus VEX.128/VEX.256 `VMOVMSKPS`, `VMOVMSKPD`, and `VPMOVMSKB`. VEX
forms are limited to long mode. All forms require an XMM or YMM register
source; memory-source and EVEX forms are outside this slice. The VEX encodings
require the reserved `vvvv` value and the instruction-specific mandatory
prefix. VEX.W is ignored. The destination is a 32-bit GPR in every enabled
form.

The decoded evaluator accepts a caller-supplied 16- or 32-byte source value in
architectural byte order and validates the decoded widths, register effects,
and vector shape. `MOVMSKPS` extracts each dword sign bit, `MOVMSKPD` each
qword sign bit, and `PMOVMSKB` each byte sign bit into corresponding low bits
of the result. The caller performs memory reads and applies the GPR result.
The decoder/evaluator do not gate instructions on AVX/AVX2 CPU features, and
the typed decompiler still does not lower the result to an explicit scalar
expression.
