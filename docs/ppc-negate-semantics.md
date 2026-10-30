# PowerPC NEG semantics

`evaluate_ppc_negate_instruction` evaluates decoded `NEG` in PPC32 and PPC64
modes as width-limited two's-complement negation. For the record form, it also
returns the CR0 LT/GT/EQ relation for the result and copies caller-supplied
XER.SO into CR0.SO. The decoder represents both ordinary and record forms as
`ppc_neg`; the presence of a CR0 write identifies the record form.

The helper validates the GPR operands and decoded CR0 effect. The caller
supplies the source and XER.SO values and commits the result. The decoder
rejects the overflow-enable encoding, so OV/SO update and exception delivery
are not part of this evaluator.
