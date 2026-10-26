# ELF runtime relocation view

`apply_elf_runtime_relocations` creates a separate rebased `Image` view from a
loaded ELF shared object. Its `load_bias` parameter is the ELF load bias `B`,
not the resulting address of the lowest mapped segment. Mapped addresses and
entry points are shifted by `B`; original file offsets and relocation metadata
remain attached to the source image. A copy-on-write overlay holds changes, so
neither the input file nor the original loaded image is modified.

For ordinary dynamic REL/RELA records, the supported profile is little-endian
ELF32 i386 `ET_DYN` REL records and little-endian ELF64 x86-64 or AArch64
`ET_DYN` records, with these types:

| Architecture | Relocation | Type | Formula |
| --- | --- | ---: | --- |
| i386 | `R_386_RELATIVE` | 8 | `B + A` |
| i386 | `R_386_GLOB_DAT` | 6 | `S` |
| i386 | `R_386_JMP_SLOT` | 7 | `S` |
| x86-64 | `R_X86_64_RELATIVE` | 8 | `B + A` |
| x86-64 | `R_X86_64_GLOB_DAT` | 6 | `S` |
| x86-64 | `R_X86_64_JUMP_SLOT` | 7 | `S` |
| AArch64 | `R_AARCH64_RELATIVE` | 1027 | `B + A` |
| AArch64 | `R_AARCH64_GLOB_DAT` | 1025 | `S` |
| AArch64 | `R_AARCH64_JUMP_SLOT` | 1026 | `S` |

ELF64 patch targets must be complete eight-byte fields in writable,
initialized load memory. ELF32 i386 targets must be complete four-byte fields
in writable, initialized load memory. Its RELATIVE addend is the unsigned
32-bit word sampled from the original target bytes, and `B + A` must fit in
32 bits. ELF32 runtime addresses, symbol values, and rebased segment extents
are checked against the 32-bit address space. i386 RELA runtime records are
left skipped. RELATIVE requires symbol index zero. ELF64 RELA uses its
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
RELA symbol-slot addends are ignored as required by these relocation formulas;
i386 GLOB_DAT and JMP_SLOT likewise use `S` without an addend. Applied rows
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
remain explicit skips.

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
the [x86-64 System V ABI relocation table](https://refspecs.linuxfoundation.org/elf/x86_64-SysV-psABI.pdf)
and the [AAELF64 relocation table](https://github.com/ARM-software/abi-aa/blob/main/aaelf64/aaelf64.rst).
