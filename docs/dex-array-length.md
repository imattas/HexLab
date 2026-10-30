# DEX array length

`evaluate_dex_array_length_instruction` evaluates decoded `array-length`
from caller-supplied reference nullness and array length. A null reference is
reported as an explicit NullPointerException condition; a non-null array
returns its length as a 32-bit int result.

The helper validates the two-byte opcode, typed vreg operands, and decoded
memory/register effects. It does not read the array object, raise the
exception, update the register file, or perform verifier/type checks.
