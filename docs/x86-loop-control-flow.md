# x86 LOOP-family control flow

The native x86 decoder represents `LOOP`, `LOOPE`/`LOOPZ`, `LOOPNE`/`LOOPNZ`, and `JCXZ`/`JECXZ`/`JRCXZ` as conditional branches. Each decoded instruction carries a typed `X86LoopCondition` and the effective counter width. The counter width follows address size (16, 32, or 64 bits), including the address-size override; the encoded branch displacement remains rel8.

`register_reads` names CX/ECX/RCX for all forms. The decrementing forms also list that register in `register_writes`; the zero-test form does not. `LOOPE` and `LOOPNE` read ZF. No form writes flags. `evaluate_x86_loop_instruction` accepts the pre-instruction counter and ZF and returns the updated counter, whether the branch is taken, and whether the counter was decremented. It does not resolve the branch target or modify caller-owned machine state.

The implementation covers legacy 16-bit and 32-bit modes and long mode. It models the architectural counter/condition behavior but does not emulate execution or memory. Broader x86 instruction coverage remains incomplete.
