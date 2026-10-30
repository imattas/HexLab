# JVM `iinc` semantics

`evaluate_jvm_iinc_instruction` evaluates decoded `iinc` and `wide iinc` from
the current local's 32-bit int bit pattern. The signed 8-bit or 16-bit
increment is added modulo 2^32, matching JVM int overflow behavior. The return
value is the updated local's exact 32-bit representation.

The adapter validates JVM context, fallthrough flow, instruction length,
operand access and immediate widths/signedness. It also checks that the
decoded signed increment fits its encoded form. It does not read or update the
local-variable array; the caller supplies the old local value and commits the
returned value.
