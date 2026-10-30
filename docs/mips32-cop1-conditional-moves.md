# MIPS32 COP1 conditional moves

`evaluate_mips32_fp_conditional_move_instruction` evaluates decoded
`MOVF.S`, `MOVT.S`, `MOVF.D`, and `MOVT.D` from raw source and prior
destination bit patterns plus the selected FCC value. It validates the
instruction's FPR widths, destination read/write access, source read, FCC
register index, and matching decoded condition-code field.

`MOVT` selects the source when FCC is true; `MOVF` selects it when FCC is
false. Otherwise the helper returns the prior destination unchanged. Single
precision results use the low 32 bits; double precision results use all 64
bits. The instruction reads the selected FCC but does not modify FCSR. The
caller supplies FCC and register values and commits the returned result.

This helper does not evaluate floating-point arithmetic, validate runtime
FPR pairing or FS mode, or model FCSR exception flags and delivery.
