# A32 and Thumb-2 bitfield operations

The processor decoders recognize `SBFX`, `UBFX`, `BFI`, and the `BFC` alias
in A32 and Thumb-2 encodings. Decoded operands retain the destination, source
when present, least-significant bit, and field width. `BFI` and `BFC` mark the
old destination as read because bits outside the selected range are preserved;
all forms mark the destination as written. These instructions do not modify
NZCV. Thumb forms retain the surrounding IT predicate metadata.

`evaluate_arm32_bitfield_instruction` evaluates the four decoded operations
from caller-supplied source and prior-destination values. `UBFX` zero-extends
the selected field, `SBFX` sign-extends it, `BFI` inserts the low `width`
source bits at `lsb`, and `BFC` clears that destination range. The helper
checks the decoded operands/effects and rejects invalid ranges. It evaluates
the data operation only; callers remain responsible for resolving an A32
condition or Thumb IT predicate and committing the result.

PC operands are rejected. Thumb-2 SP operands are rejected; A32 SP is accepted
where the encoding permits it. No architecture profile, execution timing, or
exception behavior is inferred. Encodings and operation definitions follow
Arm's [A32/T32 Instruction Set reference](https://documentation-service.arm.com/static/668bf4af69e89f01e39c4cd2).
