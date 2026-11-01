# AArch64 acquire/release single-register memory operations

The A64 decoder recognizes `LDARB`, `LDARH`, `LDAR` and the matching
`STLRB`, `STLRH`, `STLR` forms for byte, halfword, W-register, and X-register
transfers. It records the exact access width, base-register read, and memory
read or write effect. The rendered mnemonic preserves the acquire/release
operation while the existing sized-load/store opcodes keep these accesses
available to the decompiler's ordinary memory SSA and value propagation.

`Instruction::atomic_aq` marks an acquire load and `atomic_rl` marks a release
store. These flags retain the ordering class for analysis consumers; this does
not model inter-thread execution, barriers, or a complete AArch64 memory model.
The decoder does not claim exclusive-monitor behavior for these instructions.
Derived-cache version 101 invalidates instruction records created before these
memory forms were decoded.
