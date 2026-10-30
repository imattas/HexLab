# BMI2 bit deposit and extract

The existing VEX decoder exposes 32-bit and 64-bit `PDEP` and `PEXT` forms
with destination, source, and mask operand effects. `PDEP` walks mask bits from
least to most significant, placing successive low source bits into set mask
positions. `PEXT` walks the same mask positions and packs selected source bits
into consecutive low destination bits. Both instructions leave FLAGS unchanged.

The pure `evaluate_x86_bmi2` helper computes both operations for 32- or 64-bit
register bit patterns. Its instruction adapter accepts only decoded PDEP/PEXT
shapes with matching operand widths and valid GPR or mask-memory operands; the
caller supplies runtime operand values, including any memory read. A 32-bit
result is returned in the low 32 bits, zero-extended. The helper does not test
whether the executing CPU advertises BMI2.

The decompiler preserves these operations as typed `x86_pdep` and `x86_pext`
intrinsics with their decoded result width and register effects. Concrete
execution of those intrinsics remains with the caller/evaluator.
