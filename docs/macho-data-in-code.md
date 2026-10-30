# Mach-O data-in-code kinds

`LC_DATA_IN_CODE` records preserve their raw 16-bit kind and now expose a
decoded `MachODataInCodeKind` when the value is recognized:

| Value | Kind | Meaning |
| --- | --- | --- |
| 1 | `data` | Data bytes embedded in a code section |
| 2 | `jump-table8` | Jump table with 8-bit entries |
| 3 | `jump-table16` | Jump table with 16-bit entries |
| 4 | `jump-table32` | Jump table with 32-bit entries |
| 5 | `absolute-jump-table32` | Absolute-address jump table with 32-bit entries |

The CLI prints the name and raw value. Unknown values remain available as raw
metadata, are labeled `unknown`, and keep the existing incomplete-protection
status. Record offsets, lengths, and object-section backing resolution retain
their existing validation rules. These labels classify declared data ranges;
they do not decode instructions or verify the contents against the declared
kind.
