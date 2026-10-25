# A32 and Thumb Decompiler Coverage Plan

> **For agentic workers:** Own the architecture slice end to end. Use regression-first implementation and focused verification; root owns cross-track integration and capability-ledger updates.

**Goal:** Turn currently decoded A32 and Thumb instructions into useful typed IR and pseudocode across arithmetic, memory, condition codes, and control flow.

**Architecture:** Consume the existing decoded `Instruction` representation in the decompiler; do not duplicate instruction decoding. Preserve ARM condition predicates and Thumb ITSTATE semantics in the lifted control flow and effects. Unsupported or unpredictable forms remain explicit intrinsics/diagnostics.

**Tech Stack:** C++20, CMake, CTest, `libs/processors`, `libs/decompiler`, existing IR and test fixtures.

**Spec:** `docs/superpowers/specs/2026-10-19-hexlab-design.md`

## Global Constraints

- Do not change persisted opcode ordinals; append values only when unavoidable.
- Preserve instruction-origin mapping and existing conservative SSA behavior.
- Never treat conditional instructions as unconditional effects.
- Keep A64 behavior and processor decode ownership unchanged.

## Review Focus

- A32 conditional execution must preserve the false-path state.
- Thumb IT predicates must advance exactly once per governed instruction.
- PC-relative loads and literal pools must use decoded targets and remain address-width checked.
- Writeback, register-list, and flag-setting variants must not lose memory/register effects.
- Calls, returns, and interworking branches must preserve ARM/Thumb target mode.

## Deliverable

Add substantial A32/Thumb typed lifting for the instruction families already represented by the decoders, prioritize common compiler output, and test predicates, IT blocks, arithmetic flags, loads/stores, calls/returns, and mode transitions. Document exact decoded-versus-lifted coverage and unsupported forms.

## Status

- [x] Inspected existing decoder coverage and added typed lifting for common decoded A32/Thumb arithmetic, memory, predicates/ITSTATE, and control flow.
- [x] Added actual-byte decode-to-lift regression tests and documented supported semantics and limitations in `docs/arm32-decompiler.md`.
- [x] Focused verification passed: `decompiler` and `decompiler_arm32_lifting` (2/2).
- [x] The separate AArch64 UBFM/LSL regression issue was resolved in the independent AArch64 bitfield workstream; ARM32 and AArch64 focused checks pass independently.
