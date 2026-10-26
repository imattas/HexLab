# MIPS32 system and CP0 instruction slice

The native little-endian MIPS32 decoder recognizes `syscall` and `break` as
typed trap-flow instructions and retains their encoded 20-bit exception code
when it is nonzero. `sync` retains its five-bit `stype` operand. The decoder
also models `mfc0` and `mtc0` for select-zero CP0 registers, including read and
write effects, and recognizes `eret` as a non-delayed exception return. Common
CP0 register names (`status`, `cause`, `epc`, `count`, and others) are shown in
formatted output; unnamed slots use `c0rN`.

Nonzero CP0 register selects, unimplemented COP1 formats/functions, and COP2
operations remain explicit unsupported instructions. This slice does not
implement privileged-system semantics, TLB/cache effects, exception state
transitions, or MIPS32 big-endian and compressed modes. The typed decompiler
lifts the supported integer and COP1 transfer subset described in
`mips32-decompiler.md`; CP0/system effects remain conservative.

`tests/processor_tests.cpp` checks traps, exception codes, synchronization,
CP0 register effects and aliases, `eret` flow, and explicit handling of
unimplemented CP0 selects.
