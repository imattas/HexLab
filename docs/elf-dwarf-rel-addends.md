# ELF DWARF implicit addends

The shared ET_REL debug-data relocation path accepts these additional
little-endian `SHT_REL` absolute fields:

| Machine | Relocation | In-place addend | Result |
| --- | --- | --- | --- |
| x86-64 | `R_X86_64_64` | exact signed 64-bit bit pattern | low 64 bits of S+A |
| x86-64 | `R_X86_64_32` | signed 32-bit value | checked unsigned 32-bit S+A |
| AArch64 | `R_AARCH64_ABS64` | exact signed 64-bit bit pattern | low 64 bits of S+A |
| AArch64 | `R_AARCH64_ABS32` | signed 32-bit value | checked -2^31 through 2^32-1 |
| RISC-V | `R_RISCV_32` | signed 32-bit value | checked unsigned 32-bit S+A |
| RISC-V ELF64 | `R_RISCV_64` | exact signed 64-bit bit pattern | low 64 bits of S+A |

The existing signed `R_X86_64_32S` and unsigned i386 `R_386_32` and ARM32
`R_ARM_ABS32` implicit-addend forms also remain supported. RISC-V word
addends follow the sign extension used by LLVM LLD; the 64-bit absolute form
preserves the complete field bit pattern.
The x86-64 extraction convention matches LLVM LLD's `getImplicitAddend`;
the ordinary x86-64 psABI primarily specifies RELA records. This is bounded
data-field interpretation, without an instruction decoder or relaxation.

These forms apply to consumed ordinary debug sections, standalone DWO debug
sections and selected DWP package sections. DWP relocations apply to full
section buffers before CU/TU contribution slicing. The input's original ELF
storage and relocation rows remain unchanged. Each relocation must retain a
validated symbol-table/index identity, proven field width, bounded target field
and one defined section-relative symbol in a valid section. Compressed target
sections remain unsupported.

The loader computes at most 1,000,000 patches from the original decoded section
buffers, validates their arithmetic and sorts their section/offset extents
before applying any write. Duplicate, overlapping and composed relocation
fields fail the import. A REL addend can therefore never be read from a field
already modified by an earlier patch. Cancellation is checked while decoding,
validating and applying patches. Callers receive no partial import after an
unsupported field, overflow or overlap failure.

The AArch64 result rules apply to both REL and RELA: ABS64 writes the low
64 bits without an overflow rejection, and ABS32 accepts either the signed
or unsigned 32-bit range. Other narrow absolute results are checked after
negative-addend subtraction as well as positive addition, preventing silent
truncation of an oversized result.

Other relocation families, instruction and PC-relative patches, compressed
relocation targets and big-endian debug-data relocation remain unsupported.
Automatic DWO/DWP discovery and runtime/static linker relocation support are
separate capabilities.

The addend and AArch64 result rules follow
[AAELF64](https://github.com/ARM-software/abi-aa/blob/main/aaelf64/aaelf64.rst#addends-and-pc-bias).
The x86-64 extraction reference is
[LLVM LLD X86_64.cpp](https://github.com/llvm/llvm-project/blob/main/lld/ELF/Arch/X86_64.cpp).
RISC-V implicit addend extraction follows
[LLVM LLD RISCV.cpp](https://llvm.googlesource.com/llvm-project/+/refs/heads/main/lld/ELF/Arch/RISCV.cpp).
