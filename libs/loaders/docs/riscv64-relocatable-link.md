# RISC-V ELF64 relocatable linking

`link_elf64_riscv_text` and `link_elf64_riscv_executable` provide bounded static linking for homogeneous little-endian ELF64 `EM_RISCV` `ET_REL` inputs. They use the existing archive/link layout: allocated `.text`, `.rodata`, `.data`, and `.bss` sections, local and global symbol rebasing, strong/weak/common symbol resolution, cancellation, and object/symbol/relocation/output limits. The executable API requires the requested entry symbol in merged `.text`, a 4 KiB aligned base address, and uses 4 KiB aligned load segments.

The linker applies these `SHT_RELA` relocations:

- `R_RISCV_32` and `R_RISCV_64` absolute values, with unsigned 32-bit overflow checking for the 32-bit form.
- `R_RISCV_BRANCH` and `R_RISCV_JAL`, after checking the instruction opcode, even displacement, and signed immediate range.
- `R_RISCV_CALL` and `R_RISCV_CALL_PLT`, for a checked AUIPC/JALR pair whose base registers agree and whose target displacement fits signed 32 bits.
- `R_RISCV_HI20`, `R_RISCV_LO12_I`, and `R_RISCV_LO12_S` for absolute signed-32-bit values. The instruction forms are checked before patching immediate fields.
- `R_RISCV_RELAX` is accepted as a marker only; it does not cause instruction relaxation or code-size changes.

All other relocation kinds fail with `unsupported`. In particular, PC-relative HI20/LO12 pairs, GOT/TLS, `R_RISCV_ALIGN`, compressed-instruction relocations, relaxation, and veneers are not implemented. Inputs using non-default allocated section names such as `.text.*` are not accepted by this shared linker layout. Output and input limits and cancellation are checked before publishing a result.

This is a static-link subset, not a dynamic linker or a complete RISC-V psABI implementation. Callers that need unsupported records must preserve the original objects or use a full system linker.
