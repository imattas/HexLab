# RISC-V ELF64 runtime relocation subset

The ELF loader records the RISC-V ELF64 `R_RISCV_64`, `R_RISCV_RELATIVE`,
and `R_RISCV_JUMP_SLOT` relocation fields. For little-endian `ET_DYN` images,
`apply_elf_runtime_relocations` can apply those records to a copy-on-write
runtime image.

`R_RISCV_RELATIVE` computes `B + A`. `R_RISCV_JUMP_SLOT` uses the exact
caller-supplied dependency and symbol binding, including version matching when
present. `R_RISCV_64` computes `S + A`; the addend comes from the RELA record or
the initialized field for REL. Defined in-image symbols and caller-supplied
external symbols are supported. External bindings remain caller-owned; the
loader does not locate or load shared libraries.

Each candidate field must be fully file-backed, writable, non-overlapping, and
consistent with the source image's file mapping. Unsupported records are
reported in `ElfRuntimeImage::skipped`, and leave the returned image marked
incomplete. The source image and storage are not modified.

This does not apply RV32 relocations, TLS or IFUNC relocations, COPY
relocations, or RISC-V instruction relocations. Big-endian RISC-V runtime
relocation application remains unsupported.

The relocation numbers and calculations follow the
[RISC-V ELF psABI relocation table](https://riscv-non-isa.github.io/riscv-elf-psabi-doc/#relocations).
