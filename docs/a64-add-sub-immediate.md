# A64 add/subtract immediate evaluation

`evaluate_a64_add_sub_immediate_instruction` evaluates decoded W/X `ADD`,
`ADDS`, `SUB`, and `SUBS` immediate forms when both register operands use a
GPR or ZR. The decoded 12-bit immediate, including its optional 12-bit shift,
is used directly. W results are zero-extended. Flag-setting forms also return
the resulting NZCV values; other forms leave flags unreported.

The helper validates the register, immediate, and NZCV write facts. SP-based
forms are excluded because their register-31 interpretation needs separate
stack-pointer handling. Register and flag commits remain caller-owned.
