# PowerPC carry arithmetic evaluation

`evaluate_ppc_carry_binary_instruction` evaluates decoded `ADDC`, `ADDE`,
`SUBFC`, and `SUBFE` in PPC32 and PPC64 modes. It returns the width-limited GPR
result, the updated XER value, and an optional CR0 field for record forms.
`ADDE` and `SUBFE` consume pre-instruction XER.CA; the other two do not.

`SUBFC RT,RA,RB` computes `RB - RA`, setting CA when no borrow occurs.
`SUBFE` computes `RB - RA - (1 - CA)`. Addition carry is derived without
host-specific extended integer types, including PPC64 wraparound. Record forms
derive LT/GT/EQ from the result and copy the incoming XER.SO bit to CR0.SO.
All output formulas use the caller's old inputs, so destination/source aliasing
does not change the result.

The evaluator validates the decoded context, instruction shape, GPR banks and
widths, memory effects, source reads, and CA effects. It updates only XER.CA
and preserves other bits. The profile-dependent PPC64 XER.CA32 bit, overflow
enabled forms, exception delivery, and broader Power ISA carry operations are
not modeled by this API.
