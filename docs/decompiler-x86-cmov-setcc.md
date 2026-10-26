# x86 CMOVcc and SETcc decompilation

The native x86/x86-64 lifter now emits typed effects for `CMOVcc` and `SETcc` when the existing acyclic flag-producer analysis can prove the condition. It derives predicates from the supported preceding compare, test, arithmetic, shift/rotate, or x87 flag state and requires each requested status flag to be defined. Conditional register moves become a select between the source and the pre-instruction destination value. `SETcc` becomes an eight-bit zero-extended predicate written to its byte register or memory destination.

A memory-source `CMOVcc` remains an explicit intrinsic with a memory-read effect and an SSA register output. x86 reads the source memory operand even when the condition is false, so representing it as a lazy source-level ternary would lose a possible access fault. The intrinsic carries the selected value formula while retaining the unconditional read.

When flag provenance is missing, a join is ambiguous, flags are undefined for the requested condition, or the operand shape is not exact, the instruction keeps the existing explicit fallback effect. The lifter does not infer conditions from unknown flag bits, model memory faults, or execute the instruction.
