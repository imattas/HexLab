# Thumb-2 immediate arithmetic

HexLab decodes the Thumb-2 immediate ADD and SUB families below. Decoded
instructions carry their expanded immediate, register read/write effects, and
APSR effects when applicable.

## Supported encodings

| Encoding | Form | Flags |
| --- | --- | --- |
| Thumb-2 modified-immediate arithmetic | `ADD{S}`, `ADC{S}`, `SBC{S}`, `SUB{S}`, and `RSB{S}` with `Rd, Rn, #imm32` | Updated when `S=1` |
| T4, ADDW/SUBW | `ADDW Rd, Rn, #imm12` / `SUBW Rd, Rn, #imm12` | Not updated |

For these forms, the decoder currently accepts only `r0`–`r12` for `Rn` and
`Rd`. It rejects encodings with `SP` or `PC` in either field. The modified
immediate is expanded according to ThumbExpandImm: the four low-byte
replication forms are handled (with the three zero-byte replicated encodings
rejected), as are the rotated `1:xxxxxxx` forms. T4 reconstructs the plain
12-bit immediate from `i:imm3:imm8`.

Flag-setting modified-immediate forms record an APSR write with all four arithmetic flags
marked as written. ADC and SBC also read the incoming carry flag. Non-flag-
setting forms and ADDW/SUBW leave APSR untouched. The normal Thumb IT-state
machinery supplies predication and condition formatting.

The T3 arithmetic path currently accepts only `r0`–`r12` for `Rn` and `Rd`.
It rejects `SP` and `PC` in either field. Other T32 data-processing immediate
operations, including logical operations, are outside this arithmetic slice.
MOVW/MOVT lifting behavior is described below.

## MOVW and MOVT decompiler behavior

The Thumb-2 `MOVW`/`MOVT` forms lower to 32-bit assignments. `MOVW` replaces
the full destination with the decoded 16-bit immediate. `MOVT` reads the old
destination and replaces only bits 31:16, preserving bits 15:0. When an
instruction is governed by a known IT condition, the lifted assignment selects
the new value on the true path and preserves the incoming destination on the
false path. Both forms preserve APSR. The bounded decoder rejects SP and PC
destinations; the lifting path checks the decoded operand/effect shape and
retains malformed facts as an opaque intrinsic.

## References

- [Arm Architecture Reference Manual, Armv7-A and Armv7-R edition](https://documentation-service.arm.com/static/5f8ff0a1f86e16515cdbf82c)
- [LLVM ARM Thumb-2 instruction definitions](https://github.com/llvm/llvm-project/blob/main/llvm/lib/Target/ARM/ARMInstrThumb2.td)
