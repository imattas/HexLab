# PowerPC CR transfers

The PowerPC semantics helper evaluates decoded `MFCR` and `MTCRF` instructions from caller-supplied architectural state.

`MFCR` packs CR0 through CR7 into bits 31:28 down through 3:0 of the destination GPR. In PPC64 mode, the 32-bit result is zero-extended; GPR0 is still a writable destination for this instruction. `MTCRF` consumes the low 32 bits of its source GPR and uses the eight-bit FXM mask, where bit 7 selects CR0 and bit 0 selects CR7. Unselected fields are preserved. Each CR field is represented as a four-bit nibble.

The evaluator returns the packed GPR result or updated CR field array and the mask of fields written. It does not commit state or model XER/other side effects. It accepts only decoded PPC32/PPC64 forms whose operand shape and register effects match the decoder. CR logical operations, `MCRF`, and `MFOCRF` are outside this helper.
