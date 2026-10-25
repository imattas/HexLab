# AArch64 multiply-accumulate decode and lifting

## Intent

Extend the native AArch64 analysis path with common scalar W/X multiply-accumulate operations so decoded instructions retain correct modulo-width arithmetic in typed pseudocode. The parent task explicitly selected a broad end-to-end AArch64 lifting expansion. This work is separate from the current ABI-aware SSA pass and managed-code lifting.

## Approaches considered

1. Reuse the existing x86 `imul` opcode. This avoids an enum addition but obscures AArch64 instruction identity and cannot represent the accumulator operand cleanly.
2. Add distinct append-only `a64_madd` and `a64_msub` opcodes, preserve all four register operands, and lift to width-typed multiply followed by add/sub. This keeps decode metadata architecture-specific while reusing ordinary integer IR. **Chosen** because it is explicit, bounded, and makes the machine formula inspectable.
3. Add generic multiply-accumulate IR nodes and optimizer rules. This could preserve fused instruction identity longer, but it expands the public IR and all downstream consumers for no semantic benefit in the supported integer subset.

## Behavior

- Decode legal 32-bit and 64-bit MADD/MSUB integer data-processing encodings.
- Preserve destination, multiplicands, accumulator, register effects, and operation width; W-form writes use existing W/X register semantics.
- Format the aliases `MUL` and `MNEG` when the accumulator is the architectural zero register.
- Lift `Ra + Rn * Rm` and `Ra - Rn * Rm` into typed fixed-width expressions, with the zero register treated through the existing register-expression model.
- Treat WZR/XZR destinations as discarded writes.

## Limits

No signed/unsigned high-half multiply, long multiply, division, conditional select, or saturating arithmetic is added. Only legal base MADD/MSUB encodings are accepted. Existing tests must not be added or run under the parent task's compile-only constraint; root will perform serialized compilation.

## Source ownership

`libs/processors/include/hexlab/processors/instruction.hpp`, `libs/processors/src/a64_integer.cpp`, `libs/processors/src/a64_format.cpp`, `libs/decompiler/src/decompiler.cpp`, and a focused documentation page. No schema or persistence changes.
