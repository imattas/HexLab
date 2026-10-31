# MIPS64 set-less-than reference propagation

The bounded MIPS64 reference pass propagates `SLT`, `SLTU`, `SLTI`, and `SLTIU` when their inputs are known in the current basic-block state. Register zero is treated as the architectural constant zero. Signed forms compare the full 64-bit two's-complement values; unsigned forms compare their bit patterns. Immediate forms require a decoded, signed 16-bit immediate that has been sign-extended to 64 bits, matching the MIPS64 encoding.

The result is exactly zero or one. Unknown inputs invalidate the written destination instead of preserving stale values. This allows later register-indirect control-flow and effective-address evaluation to consume comparison results when they are used as address components. Relocation-aware address resolution remains governed by the common reference resolver.

The propagation is local to the existing recovered control-flow block state; it does not model exception behavior, delay-slot side effects, or infer values across unresolved joins.
