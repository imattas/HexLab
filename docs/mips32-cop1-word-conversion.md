# MIPS32 COP1 floating-to-word conversion semantics

`evaluate_mips32_word_conversion` converts raw IEEE binary32 or binary64 bit
patterns to a signed 32-bit integer without using host floating point. It
implements `CVT.W.S/D` with FCSR.RM and the opcode-fixed rounding of
`ROUND.W.S/D`, `TRUNC.W.S/D`, `CEIL.W.S/D`, and `FLOOR.W.S/D`. The exact
significand and binary exponent are used to handle subnormals, halfway cases,
directed rounding, and signed range limits deterministically.

NaNs, infinities, and rounded values outside the signed-word range raise
Invalid and use the MIPS32 default result `0x7fffffff` when Invalid is not
enabled. Finite discarded fractional bits raise Inexact. The result replaces
FCSR.Cause for Invalid and Inexact. If no enabled exception is taken, the
corresponding sticky FCSR.Flags are accrued; when an enabled exception is
taken, Flag bits are not updated. An enabled Invalid or Inexact exception
suppresses the destination write. With FCSR.FS set, subnormal inputs are
treated as same-sign zero and raise Inexact.

`evaluate_mips32_word_conversion_instruction` binds the evaluator to decoded
instructions and checks architecture/mode, opcode, operand count and access,
FPR widths and indexes, the precise FPR/FCSR read set, and FPR/FCSR write set.
Malformed instruction facts return no result so callers can retain a
conservative unmodeled effect.

This helper reports exception state and destination suppression; exception
delivery, committing architectural state, FPR pairing/runtime validity, and
other floating-point operations remain caller-owned or unsupported. The
decompiler continues to represent these conversions as typed intrinsics rather
than evaluate them during lifting.
