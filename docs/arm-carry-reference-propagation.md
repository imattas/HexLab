# ARM32 carry-aware reference propagation

The A32/Thumb reference pass may carry a proven CPSR C bit alongside unanimous
GPR address values while propagating through an owned CFG. It derives C from
decoded instructions whose modeled flag write proves the result; when incoming
C is unknown, it keeps the result only if evaluating both possible inputs
produces the same C value. Calls discard register and carry facts.

A proven C value feeds immediate RRX operand2 and memory offsets, plus ADC,
SBC, and RSC address calculations. It also resolves A32/Thumb CS (C set) and
CC (C clear) predicates: a proven false condition preserves the incoming state,
while a proven true condition allows ordinary transfer and flag effects. Other
unknown predicates conservatively invalidate written facts. Arithmetic remains
32-bit wrapping. A resulting address is published only when the target is
mapped. PC writes, interworking, unresolved registers, relocation ambiguity,
and unsupported operand forms remain conservative.
