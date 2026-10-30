# AArch64 AdvSIMD integer subset

The A64 decoder recognizes three-register AdvSIMD integer ADD and SUB for
8-, 16-, 32-, and 64-bit lanes in legal D/Q arrangements. It also recognizes
vector AND, ORR, and EOR in byte-oriented D/Q arrangements, plus signed and
unsigned elementwise maximum and minimum (`SMAX`, `SMIN`, `UMAX`, and `UMIN`)
for 8-, 16-, and 32-bit lanes in legal D/Q arrangements. Reserved 64-bit
arrangements with 64-bit lanes are rejected. Operand metadata records the
architectural V register, encoded 64- or 128-bit data width, lane width, and
register reads/writes. D-form destinations additionally publish the full V
register write because the upper 64 bits are cleared.

Disassembly prints arrangements such as `v0.8b`, `v2.4s`, and `v3.2d`.
Decompilation preserves these operations as typed named intrinsics rather than
using whole-vector addition or bitwise expressions that could misrepresent
lane semantics. Min/max intrinsic names retain signedness explicitly. D-form
intrinsic results carry the zero-upper effect.

Floating vector arithmetic coverage is documented separately in
[`a64-simd-floating.md`](a64-simd-floating.md). Other AdvSIMD arithmetic,
scalar FP/SIMD, per-lane execution, and AdvSIMD loads/stores remain unsupported.
