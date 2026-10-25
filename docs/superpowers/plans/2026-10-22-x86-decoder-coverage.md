# x86 Decoder Coverage Expansion Plan

> **For agentic workers:** Own a cohesive decoder expansion across 16/32/64-bit modes. Use test-first changes and the existing project decoder model; root owns integrated verification and capability-ledger updates.

**Goal:** Expand the original x86 decoder so common compiler-generated instructions decode consistently across real/protected 16-bit, 32-bit, and 64-bit execution modes.

**Architecture:** Extend the existing custom decoder and operand/effect representation. Keep mode and prefix interpretation explicit and share instruction families only where their encodings and semantics agree. Do not replace the decoder with Capstone/Zydis fallback or fabricate typed effects for unsupported encodings.

**Tech Stack:** C++20, CMake, CTest, `libs/processors`, existing independent assembler/decoder oracles when available.

**Spec:** `docs/superpowers/specs/2026-10-19-hexlab-design.md`

## Global Constraints

- Preserve current public decode APIs and persisted opcode values.
- Invalid and truncated encodings must remain distinguishable and bounded to the 15-byte instruction limit.
- Keep decode-only fallback explicitly separate from typed decode results.
- Verify legacy address-size, operand-size, segment, and REX interactions by mode.

## Review Focus

- Prefix order and duplicate/conflicting legacy prefixes must not alter instruction length silently.
- 16/32-bit ModRM/SIB and displacement rules differ from long mode and require mode-specific fixtures.
- Immediate sign extension and relative targets must be checked at the architectural width.
- Invalid group extensions and truncated multi-byte opcodes must not be accepted as nearby valid forms.
- The same byte sequence may have different valid meanings by mode; tests must assert both decode and rendered operands.

## Deliverable

Identify the highest-impact holes in the shared decoder, add representative common instruction families and mode-accurate operand/control-flow effects across x86-16/32/64, and validate with generated fixtures plus an independent oracle where practical. Update processor documentation and capability evidence with the actual coverage boundary.

