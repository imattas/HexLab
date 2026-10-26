# Exact indexed memory partitions

HexLab supplements whole-memory SSA with a byte-range partition when it can
prove the effective address. For a constant register index, the AArch64
`UXTW`, `SXTW`, `UXTX`/`LSL`, and `SXTX` forms are reduced to a checked signed
offset from the same proven pointer root. Scaling and displacement are applied
with overflow checks; indexes that cannot be represented without wrapping
remain on whole-memory SSA.

The decoder currently represents the UXTX/LSL addressing form with an empty
`index_extend` and a 64-bit index. The memory partitioner also accepts an
explicit `uxtx` spelling, which has the same unsigned 64-bit semantics for
values in its supported nonnegative offset range. This keeps IR produced by
other lifters consistent without changing the decoder's display form.

This follows Arm's A64 register-offset load/store address calculation and
index extension rules in the [Arm Architecture Reference Manual](https://developer.arm.com/documentation/ddi0487/latest).
The algorithmic reference is Ghidra's native C++ [`Heritage::analyzeNewLoadGuards`](https://github.com/NationalSecurityAgency/ghidra/blob/master/Ghidra/Features/Decompiler/src/decompile/cpp/heritage.cc),
which refines memory-load/store alias information from address value sets.
HexLab keeps this slice narrower: it uses exact SSA constants and proven
pointer origins rather than a value-set solver. No Ghidra source code is copied.

Variable indices, unsupported extension spellings, wraparound address
arithmetic, and aliases through unrelated pointer roots stay on the
conservative whole-memory chain.
