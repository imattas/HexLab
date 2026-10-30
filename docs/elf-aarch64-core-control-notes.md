# AArch64 Linux core control notes

ELF core inspection recognizes three Linux AArch64 notes in `CORE` or
`LINUX` note namespaces:

| Note | Retained values |
| --- | --- |
| `NT_ARM_PAC_MASK` (`0x406`) | Data and instruction pointer-authentication masks |
| `NT_ARM_TAGGED_ADDR_CTRL` (`0x409`) | Tagged-address control word |
| `NT_ARM_PAC_ENABLED_KEYS` (`0x40a`) | Enabled pointer-authentication key mask |

The parser accepts only ELF64 AArch64 core files and exact descriptor sizes
(16 bytes for the PAC masks, 8 bytes for each control word). Values use the
ELF byte order and retain note/payload file offsets. Unsupported architecture
or size variants produce a core diagnostic while leaving the original generic
note available in the ELF note inventory. The CLI displays bounded retained
rows with their source locations.

These values describe captured control metadata; HexLab does not apply pointer
stripping, infer authenticated pointers, or interpret tagged-address/MTE policy
bits. Note identifiers and layouts follow the Linux UAPI `linux/elf.h` and
AArch64 `asm/ptrace.h` definitions.
