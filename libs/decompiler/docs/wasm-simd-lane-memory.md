# WebAssembly SIMD lane memory lifting

The typed WebAssembly lifter models `v128.load{8,16,32,64}_lane` and
`v128.store{8,16,32,64}_lane` when the module has exactly one validated
memory. It validates the two `memarg` immediates, the lane index, and the
operand stack types before emitting any lifted instructions.

Lane stores lower to a scalar lane extraction and a typed memory store. Lane
loads read the selected scalar from memory and emit a vector result operation
that preserves the untouched lanes from the input vector. Both forms carry an
out-of-bounds trap edge sized to the accessed lane and include the static
`memarg` offset in the checked effective address.

The decoder validates the encoded lane against the access width. The lifter
repeats that check at its boundary so malformed or externally constructed
instruction records cannot index a lane outside the vector. Multiple memories
and memory64 remain outside this lifter's current validated subset.
