# AArch64 concrete NZCV evaluation

`a64_nzcv_semantics.hpp` exposes `evaluate_a64_nzcv_operation` for the
flag-setting `ADDS`, `SUBS`, and `ANDS` opcodes at W or X width. It takes raw
operand bit patterns and returns the width-limited result with concrete NZCV.
W results are zero-extended. `SUBS` sets C when no borrow occurs; `ANDS` sets
C and V to zero. Unsupported opcodes and widths return no result.

The helper evaluates operation-level behavior only. It does not inspect
decoded operand forms, resolve shifted-register operands, apply conditional
execution, sample registers, or commit the result and flags. Those remain
caller responsibilities; other A64 flag-setting operations are not covered.
