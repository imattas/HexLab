# x86 register `XCHG`

`evaluate_x86_exchange_instruction` evaluates register-register `XCHG` for
8-, 16-, 32-, and 64-bit operands. It validates the decoded opcode, two
read/write GPR operands, matching widths, and complete register read/write
effects, then returns both exchanged values as a parallel result. Width
masking preserves byte/word results and the architectural 32-bit zero-extended
value pattern in long mode.

The adapter rejects memory forms. The caller supplies register values and
commits both outputs; memory reads/writes, implicit locking, and atomicity are
not modeled.
