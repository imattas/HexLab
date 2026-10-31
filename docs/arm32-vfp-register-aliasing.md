# ARM32 VFP register identity

The typed register model represents VFP registers in `RegisterBank::arm32_vfp`.
An operand with width 32 is an S view (`S0` through `S63`); an operand with
width 64 is a D view (`D0` through `D31`). The views share a 32-bit lane file:
`D<n>` overlaps `S(2*n)` and `S(2*n+1)`. Two adjacent S views together overlap
one D view. `arm32_vfp_registers_overlap` provides this range-aware identity
check while leaving unrelated banks and malformed register numbers disjoint.

The formatter and Capstone fallback preserve the S/D spelling and width in
operands and register read/write effects. Effects retain the view named by the
instruction; clients that compare or invalidate VFP values must use the overlap
helper rather than `RegisterOperand` equality. The native A32/T32 decoder and
VFP floating-point instruction semantics are not implemented by this change.
This is register naming and alias identity coverage, not a claim of VFP ISA
decode coverage.
