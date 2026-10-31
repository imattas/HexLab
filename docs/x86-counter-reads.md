# x86 timestamp and counter reads

The native x86 decoder recognizes `RDTSC` (`0F 31`), `RDPMC` (`0F 33`), and
the fixed `RDTSCP` form (`0F 01 F9`) in 16-, 32-, and 64-bit execution
contexts. These instructions have no explicit operands. `RDTSC` and `RDTSCP`
write EDX:EAX; `RDPMC` reads ECX to select a performance counter and writes
EDX:EAX; `RDTSCP` also writes ECX with IA32_TSC_AUX. In 64-bit mode these
32-bit writes clear the upper halves of RAX, RDX, and, for RDTSCP, RCX.

The decode records implicit GPR effects but does not model the timestamp,
performance-counter, or TSC_AUX values. It does not enforce CPUID feature
availability, privilege checks for RDPMC, serialization/order constraints,
virtualization behavior, or operating-system counter policy. RDTSCP is
accepted only without legacy or REX prefixes in this subset. Runtime execution
and deterministic emulation remain unsupported.

Instruction forms and architectural effects follow the Intel 64 and IA-32
Architectures Software Developer's Manual, Volume 2.
