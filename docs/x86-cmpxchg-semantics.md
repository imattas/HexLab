# x86 CMPXCHG semantics

`evaluate_x86_cmpxchg_instruction` evaluates byte, word, dword, and qword `CMPXCHG` forms with a register destination. It compares the width-sized accumulator value with the old destination using subtraction flags. If equal, the destination receives the source and the accumulator is not written. If unequal, the destination is preserved and the accumulator receives the old destination. The result reports both values, the comparison flags, and which registers are written.

The helper validates the decoder's explicit destination/source operands and implicit accumulator effects. In long mode, a dword accumulator writeback is returned as a 32-bit value; callers apply the architectural zero-extension when committing EAX. Values for byte and word register operands are width-sized, so callers preserve unaffected portions of their containing registers.

Memory destinations, locked atomic execution, `CMPXCHG8B`/`CMPXCHG16B`, and the destination-equals-accumulator alias are outside this evaluator. It returns state changes without committing registers or flags.
