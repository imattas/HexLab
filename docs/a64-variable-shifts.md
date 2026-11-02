# AArch64 variable shifts

HexLab decodes and formats the AArch64 two-source variable shift instructions
`LSLV`, `LSRV`, `ASRV`, and `RORV` in both W and X forms. The decoded detail
contains the destination and both source registers, including zero-register
aliases, and records the architectural zero extension of W-form results into
the corresponding X register.

The decompiler models the count as the low five bits for W operations and low
six bits for X operations. It lowers left shift, logical right shift, arithmetic
right shift, and rotate right to typed integer expressions. Writes to `WZR` or
`XZR` are represented as discarded writes.

Reference propagation evaluates these operations only for a validated native
AArch64 instruction with known source values. It re-decodes the original bytes,
checks operand and register-effect agreement, rejects relocation-overlapped
instructions, applies modulo-width counts, and preserves W-form truncation.
Unknown inputs leave the destination unknown.
