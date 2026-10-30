# x86 implicit MUL and IMUL lifting

In x86-64 mode, one-operand `MUL` and `IMUL` lower to typed intrinsic effects
for 8-, 16-, 32-, and 64-bit operands. The intrinsic consumes the explicit
source and the implicit accumulator input. Its full-product expression carries
the signed or unsigned interpretation, and parallel register outputs expose
the architectural result: an 8-bit operation writes the complete 16-bit `AX`,
while wider operations write the low product to `RAX`/`EAX`/`AX` and the high
product to `RDX`/`EDX`/`DX` at the operand width.

The FLAGS output marks `CF` and `OF` from the full product using the ISA's
overflow rule: unsigned `MUL` overflows when the high half is nonzero; signed
`IMUL` overflows when the high half is not the sign extension of the low half.
The other arithmetic flags are undefined by these instructions and remain
symbolic in the flags formula. A memory source is retained as a read effect.
Malformed operand or effect records fall back to an unknown intrinsic instead
of manufacturing accumulator results.

This is typed IR, not execution: the full-product, extraction, and partial
flags formulas remain named x86 operations for later consumers. The pure
decoded multiply evaluator remains the executable scalar helper and accepts
caller-supplied runtime operand values; lifting does not read target memory.
