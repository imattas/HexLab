# x64 Shift and Rotate Evaluation Design

## Intent

Add a pure, decoded-instruction-connected evaluator for the scalar x86/x64 SHL, SHR, SAR, ROL, ROR, RCL, and RCR family. The decoder already represents these operations and the decompiler deliberately preserves their edge cases as intrinsics; analysis clients currently lack a precise execution helper.

## Approaches

1. Add only raw operation helpers. Small API, but callers must repeat opcode/operand validation and can misapply x86 counts.
2. Add operation helpers plus a decoded-instruction adapter (selected). Keeps the core arithmetic reusable and centralizes architecture, operand, width, and immediate-versus-runtime-count checks.
3. Build a stateful executor and memory interface. Broader scope than the processor semantic helpers and would duplicate the project's still-unified-executor work.

## Design

Return the destination value, value-defined status, whether flags are unchanged, and per-flag value/definedness for CF/PF/ZF/SF/OF/AF. Count normalization follows x86 masking, then the operation-specific rotation modulus. A zero effective count preserves destination and every incoming flag. Rotates preserve non-CF/OF flags. Shifts define PF/ZF/SF, define CF when the shifted-out bit is architecturally available, define OF only for count one, and report AF/other unsupported cases as undefined. Counts greater than operand width are conservative: mark the value and affected flags undefined. The adapter accepts only x86/x86-64 decoded scalar forms, derives destination width from the typed operand, uses encoded immediate counts directly, and requires a supplied runtime count for CL/register forms.

No memory reads/writes are performed. A memory destination is accepted only as a typed width description; the caller supplies its value. No tests may be added or run under the active repository constraint; compile-only verification is used if the shared build is free.

## Scope

- Add semantic result and helper API to `x64_semantics.hpp` and decoded adapter to `x64_instruction_semantics.hpp`.
- Document exact behavior and limits in `docs/x64-condition-semantics.md`.
- Do not change decoder, decompiler, opcode serialization, tests, capability ledger, or the active native-analysis-depth wave.
