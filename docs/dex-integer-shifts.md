# DEX integer shifts

`evaluate_dex_integer_shift` evaluates decoded DEX `shl-int`, `shr-int`,
`ushr-int`, `shl-long`, `shr-long`, and `ushr-long` instructions, including
their `/2addr` forms. It accepts raw source value bits and the source
register's 32-bit shift amount, and returns a width-tagged result.

Shift amounts are masked to five bits for int operations and six bits for long
operations, as required by Dalvik. `shl` wraps at the result width; `shr`
sign-extends from the int or long sign bit; `ushr` shifts in zero bits. The
evaluator handles zero shifts explicitly and performs arithmetic right shift
without relying on implementation-defined signed shifts.

The helper checks DEX instruction context, opcode, fallthrough flow, decoded
operand count and access, encoding length, vreg banks and widths, and reported
register effects. For ordinary forms the operands are destination, value, and
amount; `/2addr` uses destination/value followed by amount. Wide values occupy
two adjacent 32-bit vregs, while shift amounts always occupy one.

The caller remains responsible for obtaining register values and committing
the returned value. This slice does not evaluate literal shifts, floating
operations, verifier state, or other DEX arithmetic.
