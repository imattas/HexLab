# x86 wide compare-exchange

The native scalar decoder recognizes `CMPXCHG8B m64` in x86 16/32/64-bit
modes and `CMPXCHG16B m128` in long mode when `REX.W` is present. Both forms
require a memory operand, record the implicit accumulator/data register reads
and conditional EAX/RAX plus EDX/RDX writes, and record the flags dependency.
The instruction accepts `LOCK`; other `/r` group extensions remain outside
this implementation.

The decompiler preserves the memory operation and implicit input/output
register effects as `x86_cmpxchg8b` or `x86_cmpxchg16b` intrinsics. It does not
model a conditional atomic memory update.

The pure `evaluate_x86_cmpxchg_wide` helper and decoded adapter
`evaluate_x86_cmpxchg_wide_instruction` model the comparison, conditional
memory replacement, accumulator-pair reload on mismatch, and exact ZF update.
The input and result represent the remaining tracked FLAGS bits unchanged.
They accept caller-supplied memory/register values and do not perform memory
access, report memory faults, or provide atomicity for LOCK-prefixed forms.
See [wide compare-exchange semantics](x86-cmpxchg-wide-semantics.md).

The decoder does not perform CPUID feature gating. It records a FLAGS read as
well as a write so consumers preserve the non-ZF bits.
