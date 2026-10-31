# CMPXCHG8B and CMPXCHG16B evaluation

`evaluate_x86_cmpxchg_wide` is a pure state transition for the 64-bit
`CMPXCHG8B` and 128-bit `CMPXCHG16B` compare-exchange families. The
`*_instruction` adapter validates the decoded memory operand, implicit
register pairs, and FLAGS dependencies before applying the same transition.

For `CMPXCHG8B`, the low/high accumulator inputs are EAX/EDX and the low/high
source inputs are EBX/ECX. `CMPXCHG16B` uses RAX/RDX and RBX/RCX. On a match,
the source pair replaces memory; on a mismatch, memory is retained and loaded
into the accumulator pair. The helper sets ZF to the match result and preserves
CF, PF, SF, and OF in its `X86Flags` value. The decoder now records incoming
FLAGS because those bits survive the instruction.

The helper masks each pair half to 32 or 64 bits and returns the compare width,
conditional write indicators, new memory halves, accumulator halves, and
flags. Callers own memory reads/writes, fault handling, and synchronization;
the helper does not make a `LOCK` operation atomic. It does not apply CPUID
feature checks. The architectural flag behavior follows the Intel
[Software Developer's Manual, Volume 2A](https://www.intel.com/content/dam/www/public/us/en/documents/manuals/64-ia-32-architectures-software-developer-vol-2a-manual.pdf).
