# PowerPC exact single-precision arithmetic subset

`evaluate_ppc_fp_arithmetic_instruction` handles decoded `fadds`, `fsubs`, and
`fmuls` when both input FPRs contain finite, exactly representable normal or
zero binary32 values in the architecture's 64-bit FPR format. It evaluates
only cases whose exact result is also a normal or zero binary32 value, then
widens that result back to the 64-bit FPR representation. It updates FPRF and
clears FR/FI for an exact result; the other FPSCR sticky exception state is
preserved. Record forms return CR1 from the updated FPSCR.

For add/sub, operand top exponents may differ by at most 29 so the intermediate
is exact in binary64. Inputs or results that need rounding, subnormal handling,
overflow/underflow, NaN/Infinity propagation, or non-IEEE FPSCR mode return no
result. Unsupported decoded effects are rejected, including wrong FPR/FPSCR
register facts, memory effects, and non-fallthrough flow. Double arithmetic,
divide, fused operations, and exception delivery remain unmodeled.

The architectural distinction between 32-bit single values and the 64-bit FPR
representation, result rounding, FPSCR fields, and instruction effects follows
[Power ISA v2.07 Book I, Floating-Point Facility](https://fileadmin.cs.lth.se/cs/education/EDAN25/PowerISA_V2.07_PUBLIC.pdf),
sections 4.2–4.5 and the single-precision A-form instruction definitions.
