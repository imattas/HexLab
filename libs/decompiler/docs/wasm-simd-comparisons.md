# WebAssembly SIMD comparison lifting

Typed function lifting recognizes the integer comparisons at SIMD subopcodes
`0x23..0x40` and `0xd6..0xdb`, and the floating comparisons at `0x41..0x4c`.
Each consumes two `v128` values and produces a `v128` mask. The result type
records integer lanes at the comparison width: sixteen 8-bit, eight 16-bit,
four 32-bit, or two 64-bit lanes. Signedness remains explicit in the exact
operation name for signed integer predicates; unsigned predicates retain their
`_u` suffix.

The lifter derives accepted names and lane widths from the processor's explicit
comparison opcode table. It rejects mismatched mnemonics and decoded records
with unexpected operands or memory effects in both stack validation and
expression construction. Floating comparison results use the same integer
mask-lane representation as integer comparisons. Concrete evaluation of the
mask bits is provided separately by
`hexlab/processors/wasm_simd_comparison.hpp`.
