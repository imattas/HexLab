# Mach-O paired SUBTRACTOR relocations

The bounded Mach-O static linker accepts `X86_64_RELOC_SUBTRACTOR` and
`ARM64_RELOC_SUBTRACTOR` records when they are followed by a matching
`UNSIGNED` record in the same relocation table. The pair must describe the same
file-backed field with the same width, and the subtractor record must name an
external symbol. Both symbols must resolve to supported merged object sections.

The linker computes the paired expression as **minuend − subtrahend + the
original field addend**. Four-byte results must fit a signed 32-bit value;
eight-byte results are retained as their two's-complement 64-bit representation.
The pair is validated during object parsing and checked again before application.

This adds static object-link support only. It does not apply dynamic Mach-O
rebases or binds, accept scattered relocations, resolve undefined external
symbols, link relocations stored in `__DATA,__bss`, or broaden the set of
supported source and target sections. Any unsupported or mismatched pair fails
the link rather than producing a partial executable.

Relocation type and pairing definitions: [LLVM Mach-O format definitions](https://github.com/llvm/llvm-project/blob/main/llvm/include/llvm/BinaryFormat/MachO.h).
