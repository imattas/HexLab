# MIPS64 Little-Endian Decoder Implementation Plan

> **For agentic workers:** Implement a cohesive MIPS64 decoder milestone test-first. Root owns integrated verification and capability-ledger updates.

**Goal:** Extend the existing MIPS32 support into a real ELF64 little-endian MIPS64 decoding path with correct 64-bit register, immediate, memory, and control-flow effects.

**Architecture:** Append stable architecture/mode/opcode values without renumbering stored values. Reuse fixed-width MIPS instruction field extraction and existing control-flow/delay-slot behavior, but keep MIPS64 semantics distinct where sign extension, address domains, register width, or instruction forms differ. Enable only validated ELF64 little-endian N64 inputs; unknown ABI/endian combinations remain inspectable and undecoded.

**Tech Stack:** C++20, existing processor/decode model, ELF image loader, generated fixtures, CMake/CTest.

**Spec:** `docs/superpowers/specs/2026-10-19-hexlab-design.md`

## Global Constraints

- Preserve serialized enum ordinals by appending architecture, execution-mode, and opcode values.
- Do not reinterpret MIPS32 encodings as MIPS64 where width or semantics differ.
- Delay-slot ownership remains explicit through decode, analysis, function recovery, and existing conservative unsupported cases.
- Invalid, unsupported, and truncated instruction results remain distinct.

## Review Focus

- ELF32 and ELF64 class/ABI/endian combinations must select only a supported mode.
- Sign-extended 32-bit results in MIPS64 must not be confused with 64-bit arithmetic results.
- 64-bit load/store and immediate widths must retain signed displacement and address overflow checks.
- Branch/jump target formation must respect the 64-bit PC region and delay-slot model.
- Reserved fixed fields and unsupported coprocessor/privileged forms must not be guessed as valid instructions.

## Tasks

- [ ] Add ELF64 MIPS fixture and mode-selection tests for supported N64 little-endian and unsupported ABI/endian variants.
- [ ] Add typed MIPS64 instruction opcodes/effects for common SPECIAL, immediate, branch/jump, and LD/SD/word-load forms; verify W/X register width and sign extension.
- [ ] Dispatch MIPS64 mode and add function/reachable-analysis delay-slot regressions on 64-bit addresses.
- [ ] Add boundary, reserved-field, and unsupported-form cases plus focused documentation.
- [ ] Run MIPS64, MIPS32, ELF, architecture-dispatch, and integrated analysis tests; update capability evidence and state remaining ABI/extension gaps.

## Follow-up implementation

- MIPS64 COP1 control transfers now lift FCCR25, FEXR26, and FENR28 as exact
  bitfield views/updates of aggregate FCSR31. CFC1 extracts the aliased bits;
  CTC1 preserves unrelated FCSR bits while replacing only the selected view.
  The field equations were checked against MIPS32 Instruction Set Revision
  5.04 CFC1/CTC1 semantics and Ghidra's MIPS register declarations. The
  implementation translates behavior into HexLab SSA expressions; it does
  not copy Ghidra source. `hexlab_decompiler` Debug build passed. Runtime
  reserved-field validation and CTC1 exception behavior remain unmodeled.
