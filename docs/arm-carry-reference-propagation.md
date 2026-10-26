# ARM32 carry and predicate-aware reference propagation

The A32/Thumb reference pass carries proven NZCV bits alongside unanimous GPR
address values through an owned CFG. A flag-setting instruction updates each
written bit only when the shared decoded-instruction evaluator proves that bit
for every combination of unknown incoming flags consistent with known facts.
Calls discard register facts; unknown or unsupported flag effects discard the
affected flag facts.

The complete fourteen ARM condition codes are evaluated from proven NZCV. A
known-false predicated instruction preserves its incoming register and flag
state, while a known-true instruction permits ordinary dataflow and flag
transfer. An unknown predicate keeps the existing conservative behavior and
invalidates written register/flag facts. This applies to CS/CC, Z/N, V, unsigned
HI/LS, and signed GE/LT/GT/LE conditions, including Thumb IT predicates only
when the decoder identifies an exact condition.

Proven C feeds immediate RRX operand2 and memory offsets, plus ADC, SBC, and
RSC address calculations. Arithmetic remains 32-bit wrapping. A resulting
address is published only when the target is mapped. CFG edge facts are not
refined by branch outcomes; PC writes/interworking, unresolved registers,
relocation ambiguity, and unsupported operand forms remain conservative.
