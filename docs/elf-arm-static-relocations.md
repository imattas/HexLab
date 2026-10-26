# ARM32 static ELF relocations

The ELF loader records the scalar ARM32 static data relocations below for both
REL and RELA tables. These rows retain their original relocation type, field
place, symbol-table provenance, and addend, and the analysis resolver can
associate the exact data field with a resolved symbol address when the symbol
is locally resolvable.

| Relocation | Type | Field | Expression | Notes |
| --- | ---: | ---: | --- | --- |
| `R_ARM_ABS32` | 2 | 4 bytes | `(S + A) | T` | Existing support; Thumb state bit is part of the ABI expression. |
| `R_ARM_REL32` | 3 | 4 bytes | `((S + A) | T) - P` | Existing support. |
| `R_ARM_ABS16` | 5 | 2 bytes | `S + A` | Overflow range permits signed or unsigned values. |
| `R_ARM_ABS8` | 8 | 1 byte | `S + A` | Overflow range permits signed or unsigned values. |
| `R_ARM_PREL31` | 42 | low 31 bits of a 4-byte word | `((S + A) | T) - P` | REL addend is sign-extended from bits 30:0; bit 31 is preserved by runtime application; the result must fit signed 31 bits. |
| `R_ARM_ABS32_NOI` | 55 | 4 bytes | `S + A` | Does not apply the Thumb function-state bit. |
| `R_ARM_REL32_NOI` | 56 | 4 bytes | `S + A - P` | Does not apply the Thumb function-state bit. |

The type numbers, expressions, field widths, and overflow ranges follow
[AAELF32, relocation codes and static data
relocations](https://github.com/ARM-software/abi-aa/blob/main/aaelf32/aaelf32.rst#relocation-codes).
RELA addends remain explicit. A narrowed relocation is useful as provenance
even when its resolved numeric value does
not denote a representable address. In that case the resolver reports
`overflow` instead of inventing a pointer.

Instruction-field relocations, grouped MOVW/MOVT or Thumb pairs, branch
relocations, and platform-specific `TARGET1`/`TARGET2` are not part of this
subset. Their field extraction, place bias, state bit handling, or
instruction-pair semantics require additional shape checks; they remain
unsupported and preserved as raw relocation records. `PREL31` is a data-field
relocation: its top bit is unrelated metadata and is not part of its signed
relocation expression.
