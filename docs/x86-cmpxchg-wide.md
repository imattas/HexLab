# x86 wide compare-exchange

The native scalar decoder recognizes `CMPXCHG8B m64` in x86 16/32/64-bit
modes and `CMPXCHG16B m128` in long mode when `REX.W` is present. Both forms
require a memory operand, record the implicit accumulator/data register reads
and conditional EAX/RAX plus EDX/RDX writes, and record the flags dependency.
The instruction accepts `LOCK`; other `/r` group extensions remain outside
this implementation.

The decompiler preserves the memory operation and implicit input/output
register effects as `x86_cmpxchg8b` or `x86_cmpxchg16b` intrinsics. Compare,
conditional memory replacement, and ZF behavior remain opaque because the
current IR does not model a conditional atomic memory update. The decoder does
not perform CPUID feature gating, and detailed flag definedness is not
represented by the current flags effect metadata.
