# x86 repeated string operations in pseudocode

`MOVS`, `CMPS`, `STOS`, `LODS`, and `SCAS` lift to named x86 string-operation
intrinsics rather than disappearing into a generic unsupported-instruction
placeholder. The intrinsic name records the element width, address width, and
repeat rule, for example `x86_string_cmps_i32_a64_repe`. Decoded implicit
memory operands preserve source/destination segment and index information;
the inputs include the direction/condition flags and, for repeated forms, the
count register. Decoded register writes preserve index updates, count
decrement, accumulator results, and comparison FLAGS effects. The IR marks
memory as read, write, or unknown when the operation both reads and writes.

`rep` on `MOVS`, `STOS`, and `LODS` is represented as count-controlled
repetition; on `CMPS` and `SCAS`, `rep` is `repe` and `repne` stops when ZF
becomes set. In all cases the count is the address-size-selected count
register, the source/destination indices wrap at their address width, and DF
selects increment or decrement by the element size. The decoder selects the
address width from the current mode and address-size prefix, and the element
width from opcode form, operand-size prefix, and (in long mode) REX.W.
The count-zero case performs no iteration or memory access; otherwise each
completed iteration updates indices and decrements the selected count before
the next count/ZF termination check.

The decompiler keeps the repeated operation as one effectful intrinsic. It
does not expand it into a CFG loop or claim the value/memory state after a
particular number of iterations. The processor semantics helper can evaluate
one iteration when the caller supplies sampled memory values; callers that
need full execution must loop with an explicit work/fault budget. Segment-base
resolution, page faults and partial progress at a fault boundary, and
interrupt/debug exceptions are not represented by the decompiler IR. Incomplete
synthetic instruction records lacking a decoded string memory operand use the
ordinary conservative lifting fallback.
