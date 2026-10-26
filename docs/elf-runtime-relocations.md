# ELF runtime relocation view

`apply_elf_runtime_relocations` creates a separate rebased `Image` view from a
loaded ELF shared object. Its `load_bias` parameter is the ELF load bias `B`,
not the resulting address of the lowest mapped segment. Mapped addresses and
entry points are shifted by `B`; original file offsets and relocation metadata
remain attached to the source image. A copy-on-write overlay holds changes, so
neither the input file nor the original loaded image is modified.

For ordinary dynamic REL/RELA records, the supported profiles include
little-endian ELF32 i386, ARM, and RISC-V `ET_DYN` records, plus little-endian
ELF64 x86-64, AArch64, PPC64, and RISC-V `ET_DYN` records, with these types:

| Architecture | Relocation | Type | Formula |
| --- | --- | ---: | --- |
| i386 | `R_386_RELATIVE` | 8 | `B + A` |
| i386 | `R_386_32` | 1 | `S + A` (low 32 bits) |
| i386 | `R_386_PC32` | 2 | `S + A - P` (low 32 bits) |
| i386 | `R_386_GLOB_DAT` | 6 | `S` |
| i386 | `R_386_JMP_SLOT` | 7 | `S` |
| ARM | `R_ARM_ABS32` | 2 | `(S + A) | T` (low 32 bits) |
| ARM | `R_ARM_REL32` | 3 | `((S + A) | T) - P` (low 32 bits) |
| ARM | `R_ARM_GLOB_DAT` | 21 | `(S + A) | T` (low 32 bits) |
| ARM | `R_ARM_JUMP_SLOT` | 22 | `S` for REL; `S + A` for RELA |
| ARM | `R_ARM_RELATIVE` | 23 | `B + A` |
| RISC-V ILP32 | `R_RISCV_32` | 1 | `S + A` (unsigned 32-bit field) |
| RISC-V ILP32 | `R_RISCV_RELATIVE` | 3 | `B + A` (32-bit field) |
| RISC-V ILP32 | `R_RISCV_JUMP_SLOT` | 5 | `S` |
| x86-64 | `R_X86_64_64` | 1 | `S + A` (64-bit field) |
| x86-64 | `R_X86_64_PC32` | 2 | `S + A - P` (signed 32-bit field) |
| x86-64 | `R_X86_64_32` | 10 | `S + A` (unsigned 32-bit field) |
| x86-64 | `R_X86_64_32S` | 11 | `S + A` (signed 32-bit field) |
| x86-64 | `R_X86_64_RELATIVE` | 8 | `B + A` |
| x86-64 | `R_X86_64_GLOB_DAT` | 6 | `S` |
| x86-64 | `R_X86_64_JUMP_SLOT` | 7 | `S` |
| AArch64 | `R_AARCH64_ABS64` | 257 | `S + A` (low 64 bits) |
| AArch64 | `R_AARCH64_RELATIVE` | 1027 | `B + A` |
| AArch64 | `R_AARCH64_GLOB_DAT` | 1025 | `S` |
| AArch64 | `R_AARCH64_JUMP_SLOT` | 1026 | `S` |
| PPC64 | `R_PPC64_ADDR64` | 38 | `S + A` (low 64 bits) |
| PPC64 | `R_PPC64_GLOB_DAT` | 20 | `S + A` (low 64 bits) |
| PPC64 | `R_PPC64_RELATIVE` | 22 | `B + A` |
| RISC-V LP64 | `R_RISCV_32` | 1 | `S + A` (unsigned 32-bit field) |
| RISC-V LP64 | `R_RISCV_64` | 2 | `S + A` (low 64 bits) |
| RISC-V LP64 | `R_RISCV_RELATIVE` | 3 | `B + A` |
| RISC-V LP64 | `R_RISCV_JUMP_SLOT` | 5 | `S` |

The RISC-V profile applies the same pointer-sized relative and jump-slot
operations for ILP32 and LP64, and supports the ABI's 32-bit absolute dynamic
relocation for either class. `R_RISCV_32` must fit its unsigned 32-bit field;
ELF32 runtime bases, symbol addresses, relative results, and rebased extents
must also fit in 32 bits. ELF32 `R_RISCV_64`, big-endian RISC-V, `GLOB_DAT`,
TLS, COPY, IFUNC, and instruction-field relocations remain unapplied. External
symbol relocations require an exact caller-supplied dependency and symbol
binding; the loader does not discover or load libraries. ELF32 RELATIVE REL
addends are read as unsigned 32-bit pointer words; RELA records use their
signed explicit addend before the 32-bit result check.

The ARM profile is little-endian ELF32 `ET_DYN` and supports dynamic REL and
RELA records for `R_ARM_ABS32`, `R_ARM_REL32`, `R_ARM_GLOB_DAT`,
`R_ARM_JUMP_SLOT`, and `R_ARM_RELATIVE`. REL addends are sampled from the
original four-byte target, except REL `JUMP_SLOT`, whose ABI addend is zero.
For symbol relocations, `T` is the Thumb bit from the resolved symbol address;
it is preserved after `S + A`. REL32 uses runtime place `P`. All ARM targets
must be complete four-byte fields in writable initialized load memory and
four-byte aligned. ELF32 addresses and rebased extents must fit in 32 bits.
Big-endian ARM, TLS, IFUNC, COPY, instruction relocations, and other ARM types
remain unapplied.

The AArch64 profile also supports the dynamic `R_AARCH64_ABS64` relocation. It
applies `S + A` and writes the low 64 bits without an overflow check, as
specified by AAELF64. All supported ordinary AArch64 ELF64 dynamic
relocations require an eight-byte aligned 64-bit target field. The ELF64
`ABS32`, `ABS16`, and `PREL*` data relocations remain static-only and are not
applied by this runtime overlay; the separate AArch64 P32/ELF32 profile is not
implemented.

The little-endian PPC64 ELF64 profile applies `R_PPC64_RELATIVE`,
`R_PPC64_ADDR64`, and `R_PPC64_GLOB_DAT` from dynamic RELA tables. Relative
records use `B + A` and require symbol index zero. `ADDR64` and `GLOB_DAT` use
`S + A` and write the low 64 bits; `GLOB_DAT` addends are retained and applied
as specified by the PowerPC64 ABI. Targets must be complete, writable,
initialized eight-byte fields aligned to eight bytes. External symbols use the
same exact caller-supplied dependency and GNU-version binding rules as other
supported symbol relocations. `R_PPC64_JMP_SLOT` remains unapplied because its
ABI-defined PLT entry initialization is not modeled as a scalar pointer patch;
big-endian PPC64 and other PPC64 dynamic relocation types remain skipped.

ELF64 pointer relocations and `R_X86_64_64` targets must be complete
eight-byte fields in writable, initialized load memory. The x86-64 `PC32`,
`32`, and `32S` records patch complete four-byte fields under the same target
checks. Their explicit RELA addends are preserved as signed 64-bit values;
runtime `P` for `PC32` is the relocation place plus load bias. `R_X86_64_64`
stores the low 64 bits of `S + A`; `R_X86_64_32` applies only when the
mathematical result is in `[0, UINT32_MAX]`; `R_X86_64_32S` and
`R_X86_64_PC32` apply only when their mathematical results fit signed 32 bits.
Out-of-range values and unavailable addends or places are skipped with a row
diagnostic. ELF32 i386 targets must be complete four-byte fields
in writable, initialized load memory. Its RELATIVE addend is the unsigned
32-bit word sampled from the original target bytes, and `B + A` must fit in
32 bits. ELF32 runtime addresses, symbol values, and rebased segment extents
are checked against the 32-bit address space. i386 `R_386_32` and `R_386_PC32`
use the original four-byte REL field as the exact unsigned 32-bit implicit
addend; their ABI `word32` results retain the low 32 bits. `R_386_PC32` uses
the rebased runtime place `P`. The i386 psABI specifies REL records for its
dynamic linker; i386 RELA rows remain skipped. RELATIVE requires symbol index
zero. ELF64 RELA uses its
explicit signed addend; ELF64 REL uses the signed 64-bit value sampled from
the original target bytes. Symbol-slot relocations require a validated nonzero
symbol index tied to the relocation table's symbol table. They apply only
when the referenced symbol is defined in the same image (or `SHN_ABS`), is not
TLS or GNU IFUNC, and yields a checked 64-bit value. For regular definitions,
`S` is the ELF symbol value plus `B`; absolute symbols retain their absolute
value. External undefined symbols can be supplied through the
`apply_elf_runtime_relocations` binding overload. Each binding contains an
exact dependency filename, base symbol name, optional GNU version name, and
already-relocated runtime address. A versioned import must match
`DT_VERNEED`'s dependency and version exactly. An unversioned import matches
only an unversioned export or an explicitly marked default version from a
library named by `DT_NEEDED`. Duplicate exact matches are ambiguous and remain
skipped. The caller selects and validates dependency images; the loader does
not open dependency paths or infer addresses from filenames. Applied external
rows retain the relocation index, caller binding index, and supplied runtime
address in `ElfRuntimeImage::resolved_symbols`. The binding table is capped at
65,536 rows and individual library, symbol, and version names at 4,096 bytes.
For x86-64 and AArch64 GLOB_DAT/JUMP_SLOT, RELA addends are ignored as required
by their formulas; i386 GLOB_DAT and JMP_SLOT likewise use `S` without an
addend. PPC64 GLOB_DAT is an explicit `S + A` relocation. Applied rows
retain their original relocation row index in `applied_indices`; external
symbol rows additionally identify the exact caller binding in
`resolved_symbols`.
Results are encoded in file byte order. The original bytes are retained as
each patch's expected value. Overlapping relocation fields are all left
unapplied. Duplicate table aliases are deduplicated by their original
relocation row identity.

Packed RELR entries use the universal `B + A` formula at the ELF pointer width.
Runtime application accepts ELF32/ELF64 in either byte order when the dynamic
RELR tag triple is present. It expands direct addresses and bitmap entries,
samples the pointer-sized implicit addend, checks ELF32 result overflow, and
encodes the result in file byte order. The ordinary REL/RELA architecture
subset above remains unchanged. RELR targets must be complete writable,
initialized pointer fields. Section-only `SHT_RELR` metadata is imported, but
runtime application follows the dynamic tag references.

Every unsupported or unsafe dynamic relocation is returned in `skipped` with
its original row index and a reason. `complete` is false when any record is
skipped or source relocation metadata is incomplete. Unsupported records do
not prevent supported, non-overlapping records from being applied. The stage
GNU symbol-version metadata is retained by the loader, and relocation lookup
uses the exact dynamic symbol-table index. Caller-supplied bindings add exact
version-aware external symbol matching without runtime library loading. TLS,
IFUNC, copy, instruction, and retained non-dynamic section relocations remain
unapplied; automatic dependency discovery and loading are not modeled. The
i386 runtime profile is little-endian `ET_DYN` with dynamic-table-owned REL
rows only. Other i386 relocation types, RELA rows, and big-endian i386 images
remain explicit skips. TLS, copy, and `R_386_IRELATIVE` relocations are not
applied; the latter would call a resolver and is deliberately never executed.

`ElfLoadOptions::runtime_load_bias` requests this stage from `load_elf`.
`LoadedImage::image` and its link-time metadata remain unchanged; optional
`LoadedImage::runtime_image` carries the rebased overlay, with applied row
indices, a completeness flag, and per-row skip diagnostics alongside it.

The implementation limits the number of considered relocation rows and checks
address rebasing, initialized backing, writable permissions, file provenance,
and overlap before producing the overlay. Address overflow rejects the
operation. The image must be `ET_DYN`; unsupported ordinary REL/RELA types are
reported in `skipped`, while RELR uses its class- and endian-neutral formula.
See
`tests/elf_dynamic_relocation_tests.cpp` for positive, unsupported-type,
symbol-index, field-boundary, overlap, metadata-preservation, and load-bias
overflow coverage.

The formulas follow the [i386 System V ABI relocation table](https://refspecs.linuxfoundation.org/elf/abi386-4.pdf),
the [x86-64 System V ABI relocation table](https://refspecs.linuxfoundation.org/elf/x86_64-SysV-psABI.pdf),
the [AAELF64 relocation table](https://github.com/ARM-software/abi-aa/blob/main/aaelf64/aaelf64.rst),
and the [64-bit PowerPC ELF ABI relocation table](https://refspecs.linuxfoundation.org/ELF/ppc64/PPC-elf64abi.pdf).
