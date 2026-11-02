# MIPS32 constant-count variable shift in O32 switch setups

## Goal

Recognize an O32 table setup that uses `SLLV` when its shift-count register is proven constant, without treating an unknown runtime shift as a fixed scale.

## Behavior

- Use architectural `SLLV` semantics: shift count is the low five bits of a proven 32-bit GPR value and the result wraps to 32 bits.
- For a dynamic selector, derive the scale from the proven low-five-bit count. The existing table-width check accepts only scales equal to the entry width (1, 2, or 4 bytes). This applies in the existing same-block recognizer and bounded unanimous predecessor proof.
- For a proven constant source, allow exact same-block or bounded predecessor constant propagation through `SLLV` with any proven low-five-bit count.
- Require the shift instruction to be a relocation-free four-byte MIPS32 instruction with exact GPR operands. Preserve the existing CFG budgets, guard proof, relocation checks, 4096-entry cap, executable-target decode, and case provenance. Selector-scale recovery has a separate cap of 128 shift-count constant proofs per recognizer.
- Do not propagate unknown counts or shift a previously symbolic selector/table-base value into another symbolic base.

## Scope

Changes are limited to `libs/analysis/src/switches.cpp` and `docs/switch-analysis-validation.md`, with a fingerprint token added for the switch analysis behavior. No decoder changes are needed because the native MIPS32 decoder already exposes `SLLV` source/count operands and register effects.

## Reference

The MIPS32 instruction manual defines `SLLV` as shifting by the low five bits of `GPR[rs]`, truncating to the 32-bit destination.
