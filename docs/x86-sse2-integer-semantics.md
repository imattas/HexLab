# SSE2 packed integer semantics

HexLab can evaluate the original 128-bit SSE2 integer operations `PADDD`,
`PADDQ`, `PSUBD`, `PSUBQ`, `PAND`, `POR`, `PXOR`, `PCMPEQB/W/D`, and
`PCMPGTB/W/D` from decoded instructions. The evaluator takes the two operand
values as 16-byte arrays in architectural byte order and returns the 16-byte
result. Arithmetic wraps independently in each 32-bit or 64-bit lane. Equality
and signed-greater-than comparisons return a lane filled with all ones when
true and zero when false. Logical operations work across the entire 128-bit
value.

When lifting a decoded instruction, the decompiler retains these operations as
named `x86_*` intrinsics. The intrinsic preserves both operand expressions,
the destination vector register writes, and a source-memory read effect when
the second operand is memory. This keeps vector behavior visible in pseudocode
until the IR has a native vector type and vector-expression operators.

The evaluator does not fetch memory, model XMM register state, update flags, or
implement floating-point SIMD. Those remain responsibilities of the caller or
future subsystems. This slice covers the currently decoded packed integer
arithmetic, logic, comparison, horizontal arithmetic, byte shuffle, min/max,
and multiply forms.

The evaluator also handles decoded `PAVGB`, `PAVGW`, `PMINUB`, `PMAXUB`, `PMINSW`, `PMAXSW`,
`PMULLW`, `PMULHW`, `PMULHUW`, `PMULUDQ`, and `PMADDWD`. The first four
operate independently on eight byte or word lanes; the word multiplies return
the low, signed high, or unsigned high half of each 16-by-16-bit product.
`PMULUDQ` multiplies source dwords 0 and 2 into two qword results, while
`PMADDWD` sums adjacent signed word products into four wrapping dword results.
`PAVGB` and `PAVGW` compute the unsigned rounded average `(a + b + 1) >> 1`
in each byte or word lane.
Immediate `PSLLDQ` and `PSRLDQ` shift the complete XMM byte sequence left or
right by the encoded count, fill vacated bytes with zero, and zero the full
result when the count is at least 16. Their legacy `66 0F 73 /7` and `/3`
encodings retain a destructive XMM destination and are lifted as typed 128-bit
intrinsics.
The evaluator still rejects any opcode outside its closed list and requires
the decoded 128-bit XMM/memory operand shape; it does not infer an operation
from a mnemonic or fetch memory itself.

`PSADBW` sums unsigned absolute differences of corresponding bytes separately
in each eight-byte group, returning each sum in the low 16 bits of its qword
and clearing the remaining bits in that qword. Its decoded XMM/m128 source and
destructive XMM destination are retained by the typed lift.
