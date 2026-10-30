# A64 MOVN/MOVZ/MOVK semantics

`evaluate_a64_wide_move_instruction` evaluates decoded W/X `MOVN`, `MOVZ`,
and `MOVK`. MOVZ places the 16-bit immediate in the selected halfword and
zeros the rest; MOVN complements that width-limited value. MOVK replaces one
halfword in a caller-supplied prior destination. W results are zero-extended.

The helper validates destination and immediate/shift metadata, plus MOVK's
read/write effect. Writes to XZR/WZR are reported as suppressed. Register
sampling and commit remain caller-owned.
