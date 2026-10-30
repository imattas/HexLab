# Thumb-2 MOVW/MOVT semantics

`evaluate_thumb_move_wide_instruction` evaluates decoded Thumb-2 `MOVW` and
`MOVT`. MOVW replaces the destination with the zero-extended 16-bit immediate.
MOVT replaces the upper 16 bits and preserves the prior low half.

The adapter validates the four-byte Thumb form, immediate metadata, and the
distinct destination read/write effects of MOVT. The caller supplies the old
destination for MOVT and commits the returned register value. A32 move-wide
forms and PC/SP destinations are outside this helper.
