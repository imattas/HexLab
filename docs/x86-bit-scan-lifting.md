# x86 Bit-Scan Lifting

The original decoder recognizes BSF, BSR, TZCNT, and LZCNT with 16-, 32-, or
64-bit register destinations and register or memory sources. The typed
decompiler now emits width-specific scan intrinsics and explicit FLAGS output
expressions for those forms. The destination expression preserves each
operation's distinct bit order and count behavior; a memory source remains a
classified read.

For BSF/BSR, ZF is set exactly when the source is zero. The destination is
architecturally undefined for a zero source, so the lifted operation retains
that boundary rather than claiming a numeric result. For TZCNT/LZCNT, the
result is the trailing/leading zero count (the operand width for zero input),
CF reports zero input, and ZF reports a zero result. The affected but
architecturally undefined status bits are represented by an explicit unknown
term; unaffected FLAGS bits are carried from the incoming FLAGS value.

The existing caller-driven `evaluate_x86_bit_operation_instruction` computes
concrete results and defined/undefined flag facts for supported decoded scan
instructions. The typed IR is symbolic and does not execute host bit-scan
instructions. CPUID feature gating (notably whether F3 0F BC/BD executes as
TZCNT/LZCNT on a particular processor) remains outside the model, as do
runtime execution and independent hardware-oracle validation.
