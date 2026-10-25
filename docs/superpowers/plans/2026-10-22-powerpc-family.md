# PowerPC/POWER decoder and image support

**Date:** 2026-10-22
**Status:** Approved implementation plan
**Scope:** Original end-to-end PowerPC family slice in HexLab

## Goal

Add usable, original PowerPC support to the existing analysis toolchain. Distinguish PPC32 and PPC64 instruction/address widths, decode fixed-width instructions in either byte order, expose typed operands and register effects, load matching ELF executables, open raw PPC samples in CLI and wxWidgets, and verify behavior with known-encoding tests.

## Design decisions

- Preserve serialized enum identities by appending all new architecture, mode, register-bank, and opcode values.
- PPC instruction bytes are always four bytes; byte order comes from DecodeContext. PPC32 addresses/register effects are 32-bit; PPC64 effects are 64-bit.
- Add dedicated PPC GPR, condition-register field, LR, and CTR banks. Capture reads/writes explicitly, including record-form CR0 writes and branch condition/counter reads.
- Implement an auditable integer subset: immediate arithmetic/logical forms; common integer X-form arithmetic/logical and SPR move forms; integer byte/half/word loads/stores and PPC64 doubleword loads/stores; direct, conditional, LR-indirect, and CTR-indirect branches. Unsupported floating-point, vector, privileged, and unimplemented encodings stay unsupported; reserved encodings are invalid and short input is truncated.
- Map ELF e_machine 20 to PPC32 and 21 to PPC64 only where class and data encoding are compatible; preserve architecture identity for known but unsupported combinations.
- Raw selection has four explicit profiles: ppc32le, ppc32be, ppc64le, ppc64be; no host-endian defaults.
- Use no third-party decoder engine for product behavior.

## Implementation steps

1. Append architecture/mode and processor register/opcode identities without changing existing numeric values.
2. Implement ppc.cpp, decode dispatch/capability validation, register/mnemonic formatting, and precise PPC endian decoding.
3. Add ELF machine/class/endian selection and raw loader validation for PPC contexts.
4. Expose all four raw profiles in CLI and desktop; document usage and scope.
5. Add decoder known-answer tests for both widths and endiannesses, effects, flow/link/return, invalid/reserved and truncated cases; add ELF machine-context tests and CLI integration checks.
6. Have the root agent add source/test targets and the processor.powerpc capability evidence row, since those shared CMake and inventory files are reserved for integration.

## Acceptance evidence

- Fresh isolated build compiles processor, loader, CLI, and desktop targets with the new sources.
- Focused decoder, ELF, raw-CLI and existing processor/ELF tests pass.
- Tests confirm byte-order-correct decoding, widths/effects, branch targets and link semantics, and the distinction among unsupported/invalid/truncated results.
- Documentation lists the exact supported slice and limitations; no full POWER/PowerPC compatibility claim is made.
