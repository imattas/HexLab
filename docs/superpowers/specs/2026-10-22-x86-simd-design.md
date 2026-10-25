# Typed x86 SIMD Decoder Slice

## Goal

Add an original typed decoder path for a useful initial SSE2 integer subset and scalar single/double floating-point subset. Users opening raw x86 images or x86 binaries should see readable assembly and inspectable XMM, memory, and register effects. The work extends the existing x86 decoder and does not add a third-party decoder dependency.

## Scope

The initial set is:

- `movdqa`, `movdqu`
- `paddd`, `paddq`, `psubd`, `psubq`, `pand`, `por`, `pxor`
- `movss`, `movsd`
- `addss`, `addsd`, `subss`, `subsd`, `mulss`, `mulsd`, `divss`, `divsd`

The decoder accepts architectural XMM0–XMM7 encodings in 16-/32-bit modes and XMM0–XMM15 in 64-bit mode. It preserves existing x86 address-size, REX register extension, and memory addressing behavior. Mandatory legacy prefixes select an exact opcode form: `66` for the packed SSE2 operations and `movdqa`, `F3` for `movdqu` and single precision, and `F2` for double precision. Unsupported opcode families remain unsupported; malformed mandatory-prefix combinations are invalid; truncated supported forms remain truncated.

Decoded operands use a dedicated XMM register bank with 128-bit register width. Packed memory operands carry 128-bit data width; scalar memory operands carry 32- or 64-bit width. Move destinations are writes; packed and scalar arithmetic destinations are read/write; source operands are reads. Existing instruction finalization derives explicit address-register reads and memory read/write facts from these typed operands.

## Design

Implement the opcode-family decoder in a new `x64_simd.cpp`. It consumes the existing x86 parser state so ModRM, SIB, address-size, prefix, bounds, and truncation behavior stay consistent. A small local adapter maps ModRM register results to XMM while retaining the existing memory operand's GPR addressing fields. The x86 scalar decoder invokes this family for two-byte opcodes before generic F2/F3 rejection, allowing only the exact mandatory prefixes listed above.

Append `RegisterBank::xmm` and the SIMD opcodes to the ends of their enums so existing persisted values remain stable. Formatting names XMM registers and adds exact lowercase mnemonics. No general vector operand variant is needed for this slice: opcode identity and the width/access on the existing register and memory operand types express the supported forms. The instruction model remains coarse-grained for scalar lane preservation; consumers can identify scalar operation width from the opcode and memory width. No floating-point flags, MXCSR details, or lane-level SSA semantics are inferred.

The existing raw x86-64 workflow is sufficient for product integration; no new architecture or mode is introduced. A CLI regression disassembles a raw fixture containing representative packed and scalar operations. Focused decoder tests directly verify modes, prefixes, XMM indices, operands, access vectors, register effects, memory effects, formatting, invalid forms, and truncation at each encoded field boundary.

## Out of Scope

MMX, AVX/VEX/EVEX, packed floating-point operations, integer operations beyond the listed forms, scalar compare/test and flag production, MXCSR state, exact upper-lane merge/zero behavior, decompiler lifting, debugger register access, and performance/cycle modeling are deferred. Unsupported encodings must not be represented as successfully decoded SIMD instructions.

## Acceptance Criteria

- Every listed opcode decodes with correct XMM register identities and 128-bit architectural register width.
- Memory forms preserve 16-/32-/64-bit address semantics and report the exact access width and direction.
- Mandatory-prefix mismatches never silently select a different SIMD operation.
- REX.R and REX.B select XMM8–XMM15 only in 64-bit mode; legacy modes reject those extensions.
- Supported prefixes/opcodes with missing bytes report `truncated`; malformed prefix combinations report `invalid`; unimplemented families report `unsupported`.
- Generic assembly formatting names the operation and XMM registers and retains memory width qualifiers.
- Focused decoder, CLI, and existing x86 regression tests pass after shared-header/build-system integration.
