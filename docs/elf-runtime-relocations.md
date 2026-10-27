# ELF runtime relocation view

`apply_elf_runtime_relocations` creates a separate rebased `Image` view from a
loaded ELF shared object. Its `load_bias` parameter is the ELF load bias `B`,
not the resulting address of the lowest mapped segment. Mapped addresses and
entry points are shifted by `B`; original file offsets and relocation metadata
remain attached to the source image. A copy-on-write overlay holds changes, so
neither the input file nor the original loaded image is modified.

For ordinary dynamic REL/RELA records, the supported profiles include
little-endian ELF32 i386, ARM, RISC-V, and the bounded x32 relative subset,
plus little-endian ELF64 x86-64, AArch64, PPC64, and RISC-V `ET_DYN` records,
with these types:

| Architecture | Relocation | Type | Formula |
| --- | --- | ---: | --- |
| i386 | `R_386_RELATIVE` | 8 | `B + A` |
| i386 | `R_386_32` | 1 | `S + A` (low 32 bits) |
| i386 | `R_386_PC32` | 2 | `S + A - P` (low 32 bits) |
| i386 | `R_386_GLOB_DAT` | 6 | `S` |
| i386 | `R_386_JMP_SLOT` | 7 | `S` |
| ARM | `R_ARM_ABS32` | 2 | `(S + A) | T` (low 32 bits) |
| ARM | `R_ARM_REL32` | 3 | `((S + A) | T) - P` (low 32 bits) |
| ARM | `R_ARM_PREL31` | 42 | `((S + A) | T) - P` (signed 31-bit result; preserve place bit 31) |
| ARM | `R_ARM_ABS32_NOI` | 55 | `S + A` (low 32 bits, no Thumb bit) |
| ARM | `R_ARM_REL32_NOI` | 56 | `S + A - P` (low 32 bits, no Thumb bit) |
| ARM | `R_ARM_GLOB_DAT` | 21 | `(S + A) | T` (low 32 bits) |
| ARM | `R_ARM_JUMP_SLOT` | 22 | `S` for REL; `S + A` for RELA |
| ARM | `R_ARM_RELATIVE` | 23 | `B + A` |
| RISC-V ILP32 | `R_RISCV_32` | 1 | `S + A` (unsigned 32-bit field) |
| RISC-V ILP32 | `R_RISCV_RELATIVE` | 3 | `B + A` (32-bit field) |
| RISC-V ILP32 | `R_RISCV_JUMP_SLOT` | 5 | `S` |
| x86-64 ILP32 (x32) | `R_X86_64_RELATIVE` | 8 | `B + A` (32-bit class field) |
| x86-64 ILP32 (x32) | `R_X86_64_RELATIVE64` | 38 | `B + A` (64-bit field) |
| x86-64 | `R_X86_64_64` | 1 | `S + A` (64-bit field) |
| x86-64 | `R_X86_64_PC32` | 2 | `S + A - P` (signed 32-bit field) |
| x86-64 | `R_X86_64_32` | 10 | `S + A` (unsigned 32-bit field) |
| x86-64 | `R_X86_64_32S` | 11 | `S + A` (signed 32-bit field) |
| x86-64 | `R_X86_64_RELATIVE` | 8 | `B + A` |
| x86-64 | `R_X86_64_GLOB_DAT` | 6 | `S` |
| x86-64 | `R_X86_64_JUMP_SLOT` | 7 | `S` |
| AArch64 | `R_AARCH64_ABS64` | 257 | `S + A` (low 64 bits) |
| AArch64 | `R_AARCH64_ABS32` | 258 | `S + A` (check `[-2^31, 2^32-1]`) |
| AArch64 | `R_AARCH64_ABS16` | 259 | `S + A` (check `[-2^15, 2^16-1]`) |
| AArch64 | `R_AARCH64_PREL64` | 260 | `S + A - P` (low 64 bits) |
| AArch64 | `R_AARCH64_PREL32` | 261 | `S + A - P` (signed 32-bit field) |
| AArch64 | `R_AARCH64_PREL16` | 262 | `S + A - P` (signed 16-bit field) |
| AArch64 | `R_AARCH64_RELATIVE` | 1027 | `B + A` |
| AArch64 | `R_AARCH64_GLOB_DAT` | 1025 | `S` |
| AArch64 | `R_AARCH64_JUMP_SLOT` | 1026 | `S` |
| PPC64 | `R_PPC64_ADDR32` | 1 | `S + A` (signed-or-unsigned 32-bit field) |
| PPC64 | `R_PPC64_ADDR64` | 38 | `S + A` (low 64 bits) |
| PPC64 | `R_PPC64_GLOB_DAT` | 20 | `S + A` (low 64 bits) |
| PPC64 | `R_PPC64_JMP_SLOT` | 21 | `S` |
| PPC64 | `R_PPC64_RELATIVE` | 22 | `B + A` |
| s390x | `R_390_64` | 22 | `S + A` (low 64 bits) |
| s390x | `R_390_PC32` | 5 | `S + A - P` (low 32 bits) |
| s390x | `R_390_GLOB_DAT` | 10 | `S + A` (low 64 bits) |
| s390x | `R_390_JMP_SLOT` | 11 | `S` |
| s390x | `R_390_RELATIVE` | 12 | `B + A` |
| RISC-V LP64 | `R_RISCV_32` | 1 | `S + A` (unsigned 32-bit field) |
| RISC-V LP64 | `R_RISCV_64` | 2 | `S + A` (low 64 bits) |
| RISC-V LP64 | `R_RISCV_RELATIVE` | 3 | `B + A` |
| RISC-V LP64 | `R_RISCV_JUMP_SLOT` | 5 | `S` |

The x32 profile is deliberately limited to the two relative relocations above:
`R_X86_64_RELATIVE` applies at the ELF32 class width, while
`R_X86_64_RELATIVE64` always patches a 64-bit field. Both use the checked
`B + A` calculation, and only little-endian `ET_DYN` images are accepted. The
ILP32 ABI assigns `RELATIVE64` type 38 specifically to 64-bit fields; its
reference table is the [x86-64 psABI](https://github.com/hjl-tools/x86-psABI/wiki/x86-64-psABI-1.0.pdf).
Ghidra independently names type 38 `R_X86_64_RELATIVE64` in its
[`X86_64_ElfRelocationType`](https://github.com/NationalSecurityAgency/ghidra/blob/master/Ghidra/Processors/x86/src/main/java/ghidra/app/util/bin/format/elf/relocation/X86_64_ElfRelocationType.java)
enum. Other x32 relocation types remain unapplied until their class-specific
field widths and formulas are modeled.

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
RELA records for `R_ARM_ABS32`, `R_ARM_REL32`, `R_ARM_PREL31`,
`R_ARM_ABS32_NOI`, `R_ARM_REL32_NOI`, `R_ARM_GLOB_DAT`, `R_ARM_JUMP_SLOT`,
and `R_ARM_RELATIVE`. REL addends are sampled from the original four-byte
target, except REL `JUMP_SLOT`, whose ABI addend is zero. For ordinary ARM
symbol relocations, `T` is the Thumb bit from the resolved symbol address;
the NOI forms omit it. `REL32` and `PREL31` use runtime place `P`. PREL31
sign-extends the implicit addend from bits 30:0, checks the final signed
31-bit range, and preserves bit 31 in the destination word. All ARM targets
must be complete four-byte fields in writable initialized load memory and
four-byte aligned. ELF32 addresses and rebased extents must fit in 32 bits.
Big-endian ARM, TLS, IFUNC, COPY, instruction relocations, and other ARM types
remain unapplied.

The AArch64 profile supports dynamic `ABS64`, `ABS32`, `ABS16`, `PREL64`,
`PREL32`, and `PREL16` data relocations. `ABS64` and `PREL64` write low 64-bit
results without overflow checks; `ABS32` and `ABS16` accept the AAELF64 ranges
`[-2^31, 2^32-1]` and `[-2^15, 2^16-1]`; `PREL32` and `PREL16` require signed
32-bit and 16-bit results. AAELF64 defines these data fields as byte-aligned,
so the runtime view validates their exact field extent and backing without
imposing pointer alignment. Instruction-field relocations, including CALL26
and JUMP26, remain unapplied, as do other AArch64 dynamic relocation types and
the separate AArch64 P32/ELF32 profile. These formulas and overflow ranges
follow the [AAELF64 data relocation table](https://github.com/ARM-software/abi-aa/blob/main/aaelf64/aaelf64.rst#static-data-relocations).

The little-endian PPC64 ELF64 profile applies `R_PPC64_RELATIVE`,
`R_PPC64_ADDR32`, `R_PPC64_ADDR64`, `R_PPC64_GLOB_DAT`, and `R_PPC64_JMP_SLOT` from dynamic RELA tables. Relative
records use `B + A` and require symbol index zero. `ADDR32` and `ADDR64` use
`S + A`; `ADDR32` must fit `[-2^31, 2^32-1]` and writes the low 32 bits; `ADDR64` writes the
low 64 bits. `GLOB_DAT` also uses `S + A` and writes the low 64 bits; its
addend is retained and applied as specified by the PowerPC64 ABI. Targets must
be complete, writable, initialized fields aligned to their width. `JMP_SLOT` writes the
resolved symbol address as a scalar pointer; PLT instruction sequences are not
interpreted. External symbols use the
same exact caller-supplied dependency and GNU-version binding rules as other
supported symbol relocations; big-endian PPC64 and other PPC64 dynamic
relocation types remain skipped.

The s390x profile applies big-endian ELF64 `ET_DYN` dynamic RELA records for
`R_390_PC32`, `R_390_RELATIVE`, `R_390_64`, `R_390_GLOB_DAT`, and
`R_390_JMP_SLOT`.
`RELATIVE` requires symbol index zero and uses checked `B + A`; `64` and
`GLOB_DAT` use `S + A` with the ABI's low-64-bit result, while `JMP_SLOT`
writes `S` and ignores its RELA addend. `PC32` computes `S + A - P`, requires
signed-32-bit representability and an even result, then stores the ABI word32
value in a complete four-byte field, as specified by the
[zSeries ELF ABI](https://refspecs.linuxfoundation.org/ELF/zSeries/lzsabi0_zSeries/x1633.html); it requires a valid
runtime place and exact symbol resolution but no eight-byte alignment. The
other four types require aligned, complete eight-byte fields in writable
initialized load memory, and their
file-backed provenance must agree with the original image. Defined symbols
must resolve inside the image or be absolute; undefined symbols require the
same exact caller-supplied dependency and version binding used by other
supported symbol relocations. s390x REL records, little-endian s390x, TLS,
COPY, IFUNC, instruction relocations, and other relocation types remain
unapplied.

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
