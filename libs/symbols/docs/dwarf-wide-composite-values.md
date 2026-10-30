# Wide DWARF composite values

`evaluate_location_expression_sequence` can retain a wide `DW_OP_implicit_value`
when it forms a composite location with `DW_OP_piece` or `DW_OP_bit_piece`.
The corresponding `EvaluatedLocationPiece` is available, has kind `value`, and
contains the exact bytes in `bytes`; its `bit_size` and source/destination bit
offsets describe where the fragment belongs. This supports constants wider
than the scalar evaluator's 64-bit result without truncating them.

The fragment is preserved only when the piece expression consists of the
implicit-value block and optional `DW_OP_stack_value` operations. Other wide
expression calculations still return an unsupported error. The decoder's
existing 64 KiB implicit-value limit, a 64 KiB total copied-byte limit for
wide pieces, and the composite expression's shared operation budget continue
to apply. Non-composite calls to
`evaluate_location_expression` retain their scalar result contract.
