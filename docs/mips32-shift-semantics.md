# MIPS32 word shifts

`evaluate_mips32_shift_instruction` evaluates decoded fixed `SLL`, `SRL`, and
`SRA` plus variable `SLLV`, `SRLV`, and `SRAV`. It validates the three-operand
GPR form and access effects. Fixed shifts use the decoded five-bit immediate;
variable shifts use the low five bits of the caller-supplied amount-register
value. Arithmetic right shift explicitly fills from the source sign bit.

The helper returns the 32-bit GPR result. It handles `$zero` inputs and
suppressed `$zero` destinations according to the decoded register facts, but
does not sample registers, commit the result, or execute surrounding delay-slot
control flow.
