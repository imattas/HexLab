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
vN/vN+1 pair within the common IR register-key limit. Malformed lengths and
wide register pairs that cross the supported boundary are rejected instead of
being truncated.

This does not yet add remaining DEX arithmetic/literal families, verifier-wide
register joins, exception edges, or descriptor-resolved invoke results.
