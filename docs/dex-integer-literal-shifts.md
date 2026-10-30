# DEX integer literal shifts

`evaluate_dex_integer_literal_shift` evaluates `shl-int/lit8`, `shr-int/lit8`,
and `ushr-int/lit8` from a decoded instruction and caller-supplied 32-bit
source value. The immediate is a signed encoded byte; its low five bits form
the shift count, including for negative literal values. Results wrap to 32
bits. `shr` sign-extends from bit 31, while `ushr` shifts in zeros.

The helper checks the DEX context and opcode, four-byte format, fallthrough
flow, exact mnemonic/opcode pairing, operand access and types, immediate
metadata, and the source/destination vreg effects. The caller supplies the
source value and commits the returned result. It does not cover literal
arithmetic, long shifts, register-count shifts, or verifier state.
