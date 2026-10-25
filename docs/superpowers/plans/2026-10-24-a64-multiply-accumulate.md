# AArch64 multiply-accumulate implementation plan

## Task 1: decode and formatting

Files: `instruction.hpp`, `a64_integer.cpp`, `a64_format.cpp`.

- Append MADD and MSUB opcodes after existing opcode values to preserve existing numeric IDs.
- Match the integer MADD/MSUB encoding class, extract sf/opc/Rm/Ra/Rn/Rd, and reject unsupported/reserved width encodings before publishing effects.
- Emit operands in `Rd, Rn, Rm, Ra` order, with correct 32/64-bit GPR/zero-register views and read/write effects.
- Format standard `madd`/`msub`, plus `mul`/`mneg` aliases for zero accumulator.
- Verification: source review only; root will compile the processor target. Do not add or run tests.

## Task 2: typed decompiler lifting and documentation

Files: `decompiler.cpp`, `docs/a64-multiply-accumulate.md`.

- Recognize the appended A64 opcodes only in arm64/A64 context and only with four expected W/X register operands.
- Build a width-typed product expression and an outer width-typed add/sub expression; discard zero-register destinations using the existing A64 rule.
- Document accepted formulas, alias formatting, result width, and explicit unsupported families.
- Verification: source review only; root will compile processor/decompiler targets serially. Do not add or run tests.

## Review focus

- Width and zero-register mapping for W and X forms.
- MADD/MSUB opcode-bit selection and alias formatting from the encoded accumulator.
- No mutation of existing opcode numeric values or changes outside the five owned files.
