# DEX scalar conversion and unary semantics

The Dalvik decoder and lifter now cover the complete unary/conversion opcode
range from `neg-int` through `int-to-short`. This includes signed integer and
long negation/complement, floating negation, all integer/long/float/double
conversions, and Java byte/char/short narrowing.

Integer conversions keep their bit widths explicit. `int-to-long` sign extends
the 32-bit source; `long-to-int` keeps its low 32 bits. Byte and short
conversions truncate to 8 or 16 bits and then sign extend, while char
conversion truncates to 16 bits and zero extends. Float and double conversion
operations remain typed and explicit in the common IR, preserving their Java
conversion behavior for the renderer and later semantic passes.

Each instruction uses the DEX 12x register encoding, with the low nibble as the
destination and high nibble as the source. Wide operands require an available
vN/vN+1 pair within the method's 16-bit register space. Malformed lengths and
wide register pairs that cross the 16-bit boundary are rejected instead of
being truncated.

This does not yet add remaining DEX arithmetic/literal families, verifier-wide
register joins, exception edges, or descriptor-resolved invoke results.

`dex_semantics.hpp` provides `evaluate_dex_integer_conversion` for decoded
`int-to-long`, `long-to-int`, `int-to-byte`, `int-to-char`, and
`int-to-short`. It validates the decoded vreg widths and component-slot read
and write effects, then returns the exact 32- or 64-bit result pattern. The
caller supplies the source bits and applies the destination.

`evaluate_dex_floating_conversion` covers `neg-float`, `neg-double`, and all
int/long/float/double conversions in this decoded range. It accepts and returns
raw IEEE-754 bit patterns, performs no host floating-point arithmetic, and
rounds integer-to-floating and double-to-float conversions to nearest-even.
Float/double-to-int/long conversions truncate toward zero, map NaN to zero,
and saturate out-of-range values to the signed destination limits, matching
Dalvik/Java conversion rules. Finite float-to-double conversion is exact;
NaN payload bits are carried across widths where possible. Both integer and
floating evaluators parse the mnemonic token from the full formatted decoded
text and validate the source/destination widths and wide component effects.

These are instruction-local value helpers. They do not infer DEX vreg types
across control-flow joins, validate reference assignability, or commit writes
to a method register file.
