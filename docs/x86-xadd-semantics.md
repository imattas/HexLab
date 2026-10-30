# x86 XADD semantics

`evaluate_x86_xadd_instruction` evaluates decoded register-register `XADD`
at 8-, 16-, 32-, or 64-bit width. The destination receives the width-limited
sum, the source receives the original destination value, and arithmetic
flags reflect the addition. If both operands name the same register, only
the sum is a final write.

Memory-destination forms are rejected because they require memory read/write
and locked atomic behavior. The helper validates decoded register and flags
effects; callers sample values and commit registers/flags.
