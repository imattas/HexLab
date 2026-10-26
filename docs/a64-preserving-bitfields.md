# AArch64 preserving bitfield moves

The native A64 processor and decompiler support the complete scalar `BFM`
immediate family for W and X registers. Disassembly uses the architectural
`BFI`, `BFXIL`, and `BFC` aliases, while all three retain one `a64_bfm` opcode
and the original `immr`/`imms` operands. The opcode is appended so existing
serialized opcode IDs do not change.
The function-engine fingerprint includes this semantic revision so existing
derived analysis is recomputed with the native BFM decoder.

## Decode and register effects

Accepted encodings have `opc=01`, the fixed bit 21 clear, and `N=sf`.
Both immediate fields must be smaller than the selected register width.
Register 31 means WZR/XZR, never SP. The destination is a read/write operand
because bits outside the field survive. W destinations additionally define
the corresponding 64-bit X register with zero extension. No flags or memory
are modified.

Reserved `opc=11`, fixed-bit violations, mismatched N/sf, and out-of-range
W-form immediates are rejected by the native bitfield decoder. They may still
be represented by the existing conservative decoder fallback, without BFM
lifting semantics.

## Typed IR and pseudocode

For width `W`, `r=immr`, and `s=imms`, the lifter computes:

- If `s >= r`: `count = s-r+1`, `lsb = 0`, and `field = source >> r`.
- Otherwise: `count = s+1`, `lsb = W-r`, and `field = source`.

With `low_mask` containing `count` low set bits and
`mask = low_mask << lsb`, the assignment is:

```text
destination = (old_destination & ~mask) | ((field & low_mask) << lsb)
```

Every node has the selected unsigned 32- or 64-bit integer type. Full-width
fields avoid host shifts by 64. Source/destination overlap reads the old SSA
value, and a zero source clears the selected field. A zero destination
discards the write. A W assignment is followed by an explicit zero-extended X
definition so a subsequent X read sees the upper bits cleared.

For example, `bfi x0, x1, #8, #8` produces the equivalent of
`x0 = (x0 & ~0xff00) | ((x1 & 0xff) << 8)`. The IR uses ordinary bitwise and
shift expressions, so both IR and C-like output expose the preserved bits.

Malformed typed operands (including SP/SIMD banks, mixed widths, invalid
register identities, signed or incorrectly sized immediates, and extra or
missing operands) retain an explicit `a64_bfm` intrinsic. This work adds no
SIMD bitfield operations or additional instruction families.

The encoding and alias rules follow [Arm's BFM specification](https://support.arm.com/documentation/111108/2026-06/Base-Instructions/BFM--Bitfield-move-?lang=en).
Validation for this change is a passed Windows Debug `hexlab_decompiler` build;
tests were neither added nor run, as requested.
