# Bounded MIPS64 COP1 numeric execution

The decoder covers ordinary S/D arithmetic and S/D/W/L conversions, but
MIPS64 lifting leaves arithmetic opaque and omits an explicit FCSR input.
The shared word-conversion folder is confined to call-summary propagation.

Implement a pure integer-bit evaluator for ADD/SUB/MUL/DIV/SQRT S/D,
S/D format conversions, W/L-to-floating conversions, and in-range floating
to W/L (including fixed rounding variants). Support all four rounding modes
only for finite normal/zero inputs and normal/zero floating results, FS=0,
and no enabled Inexact trap. Reject other cases without a guessed result.

Use one operation inventory across instruction validation, typed lifting,
and constant folding. Preserve FCSR Cause/Flag effects for evaluated cases.
Keep unevaluated operations as explicit intrinsics. Wire the execution pass
into ordinary SSA optimization, with SSA version/type checks and no cross-call
facts. Leave MIPS32 and unrelated floating-point operations unchanged.

Document the exact bounds and retain partial capability status. Run focused
MSVC compile checks for changed processor/decompiler translation units;
no tests are added or run. Review and commit locally without pushing.

Completed: 36-operation integer-only evaluator, decoded shape adapter,
explicit FCSR intrinsic inputs/outputs, local SSA execution and same-width
versioned FPR payload handling. Static review found no arithmetic defect and
identified the payload-kind integration gap, now addressed. Isolated Debug
ClCompile checks passed for the new evaluator, lifter, optimizer, and function
fingerprint unit. No tests or numeric execution probes were run.
