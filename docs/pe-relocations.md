# PE base relocation support

`load_pe` maps an image at its preferred image base and reports relocation records
with source provenance. Call `load_pe_at_base(storage, load_base, stop)` to map it
at another base. Rebased bytes live in an immutable overlay: the input file remains
unchanged, `ImageMetadata::preferred_base` retains the on-disk base, mapped segment
and entry addresses move, and `LoadedImage::load_base` records the selected runtime
base. Import, export, and relocation addresses are adjusted with the mapping.

The loader applies these machine/type pairs:

| PE machine | Types | Operation |
| --- | --- | --- |
| x86 (`0x014c`) | `HIGH` (1), `LOW` (2), `HIGHLOW` (3) | Add the corresponding 16-bit half or 32-bit delta modulo field width. |
| x86 (`0x014c`) | `HIGHADJ` (4) | Combine the 16-bit high word with its following signed 16-bit addend, add the image delta and rounding bias, then store the resulting high word. |
| x64 (`0x8664`) | `HIGHLOW` (3), `DIR64` (10) | Add the base delta modulo 32 or 64 bits. |
| ARM / ARMNT (`0x01c0`, `0x01c4`) | `HIGHLOW` (3), `ARM_MOV32` (5); ARMNT only: `THUMB_MOV32` (7) | Adjust a 32-bit field or the immediate value in a validated matching MOVW/MOVT pair. |
| ARM64 (`0xaa64`) | `DIR64` (10) | Add the base delta modulo 64 bits. |

Block headers must fit the declared base-relocation directory and begin at a
32-bit-aligned position. Blocks are at least eight bytes, have an even-sized entry
payload, and name a page-aligned RVA inside the image. Relocation fields may not
cross a 4-KiB page or the mapped image extent.
Block, entry, and non-absolute-record counts are bounded. Duplicate/overlapping
fields, source-byte aliases, uninitialized targets, invalid ARM instruction pairs,
and unsupported types prevent rebasing. A malformed optional relocation directory
still leaves the ordinary preferred-base image available with incomplete metadata;
the loader refuses a requested rebase when that directory could not be parsed fully.

`HIGHADJ` consumes the next 16-bit relocation-table word as a signed addend; that
word is not interpreted as a relocation of its own. Missing pairs make the
directory incomplete, and the machine/type is accepted only for x86 PE32. The
parsed metadata retains the addend and its source span next to the fixup. An
explicit base change requires at least one supported relocation. The loader does
not synthesize fixups for images without a relocation directory. MIPS, RISC-V,
IA-64, ARM64 instruction relocations, and other machine/type combinations remain
unsupported. The API does not perform import binding, TLS
initialization, or runtime loader actions; it only applies the declared base
relocations.

The `loaders` test covers each supported type family, including a signed HIGHADJ
addend with source provenance and a missing-pair rejection, negative/overflow boundaries
for 32-bit fields, A32/Thumb packed immediates, preferred versus runtime bases,
source-file preservation, malformed blocks, missing relocation tables, and invalid
ARM instruction pairs. Type definitions and block structure follow the
[Microsoft PE format reference](https://learn.microsoft.com/en-us/windows/win32/debug/pe-format#base-relocation-types).
