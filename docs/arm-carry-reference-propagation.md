# ARM32 carry-aware reference propagation

The A32/Thumb reference pass may now carry a proven CPSR C bit alongside unanimous
GPR address values while propagating through an owned CFG. It derives C only from
decoded, unconditional instructions whose modeled flag write proves the result;
when incoming C is unknown, it keeps the result only if evaluating both possible
inputs produces the same C value. Conditional or incomplete flag writes discard
the fact. Calls discard register and carry facts.

A proven C value feeds immediate RRX operand2 and memory offsets, plus ADC, SBC,
and RSC address calculations. Arithmetic remains 32-bit wrapping. A resulting
address is published only when the target is mapped and the instruction is
unconditional. PC writes, interworking, unresolved registers, relocation
ambiguity, and unsupported operand forms remain conservative.
