# Vector ABI classification

Header-imported vector types retain lane count, total width, alignment, and
their integer or floating lane type. The ABI classifier now handles standalone
vectors where the supported target convention has a shape rule it can apply
without guessing target CPU features.

For System V AMD64, naturally aligned 8- and 16-byte vectors with 32- or
64-bit lanes are assigned to one XMM argument register and returned in XMM0.
When the XMM argument bank is exhausted, vectors use aligned stack slots.
Standalone vectors inside aggregate layouts remain unsupported by the SysV
aggregate class merger. Vectors wider than 16 bytes are rejected because the
classifier has no target feature metadata to determine whether AVX vector
registers are available.

For Microsoft x64, a naturally aligned 16-byte vector with 32- or 64-bit lanes
returns in XMM0 and is passed indirectly in its positional integer register or
stack slot. Other vector widths and aggregate-contained vectors remain
unsupported for the default Microsoft x64 convention. With `__vectorcall`,
the existing classifier supports standalone 8-, 16-, and 32-byte vectors and
bounded homogeneous vector aggregates, using XMM/YMM registers where modeled.

For AAPCS64, naturally aligned 8- and 16-byte vectors with 32- or 64-bit lanes
use the SIMD/FP register bank and are returned in its first register; stack
placement applies when that bank is exhausted. Other lane widths, vector
shapes, and aggregate-contained vectors remain unsupported. RISC-V's current
integer ABI continues to reject vectors unless a future vector calling
convention and target vector-length model are added.

These rules apply to vector types represented in the current immutable type
graph. They do not infer CPU extensions, compiler-specific vector aliases,
vector-valued variadic promotions, or C++ copy-constructor properties.
