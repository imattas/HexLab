# Decompiler stack variables

`recover_stack_variables` is a source-recovery pass over a lifted function. It
recognizes negative, constant-offset accesses through the conventional x86
frame registers (`rbp`/`ebp`) and stack pointer (`rsp`/`esp`), AArch64 frame
register (`x29`) and stack pointer (`sp`), AArch32 frame/stack registers
(`r11`/`sp`), RISC-V frame pointer (`s0`/`x8`) and stack pointer (`sp`/`x2`),
MIPS frame pointer (`$fp`/`$s8`/`$30`) and stack pointer (`$sp`/`$29`), and
PowerPC stack pointer (`r1`) and conventional frame register (`r31`). It follows constant register copies and add/sub adjustments,
including across blocks, back to one canonical frame-register SSA value. A
phi is accepted only if all paths resolve to the same canonical register and
offset. The analysis groups accesses by that canonical identity, checks that
observed byte ranges do not overlap, and assigns a stable name such as
`local_8` to an unambiguous slot. The pseudocode formatter then renders the
same name on loads and stores, for example:

```c
local_8 = 0x2a;
r0_1 = local_8;
```

Width conflicts are scoped to the exact frame-relative offset. Recovery keeps
that offset as raw memory while still naming independent, non-overlapping
locals in the same frame. The conflicting access widths are both considered
when checking overlap, so an ambiguous range cannot make a neighboring slot
look safe by being measured only at its narrower width.

The pass returns a copy and does not change the modeled address, width, or
memory-SSA version. It clears stale recovered names before recomputing them.
It records canonical frame location metadata alongside each recovered name;
`recover_types` uses that metadata to publish a typed `RecoveredStackVariable`
for the Variables view. Positive offsets, indexed addressing, unsupported
access widths, overlapping slots, ambiguous alias paths, conflicting phi
inputs, and escaped stack addresses remain raw memory expressions. Escape
evidence includes returning a stack-derived pointer, storing it to another
address, or passing it through an opaque intrinsic. This allows common
adjusted-SP locals to be recognized while keeping aliases outside the
function's frame model conservative.

## MIPS N32 incoming stack arguments

For MIPS64-mode functions with an explicitly selected `mips_n32` convention,
an exact-width stack slot read at or above entry SP is marked as a possible
incoming argument. N32 places the first eight scalar argument positions in
registers and starts overflow arguments at entry SP, in successive eight-byte
slots; the classifier uses this same zero-based stack offset. Writes alone do
not establish incoming-argument evidence. Automatic convention selection is
limited to ELF32 MIPS files with `EF_MIPS_ABI2`, no conflicting MIPS ABI
selector, and generic Linux/SysV OSABI. Other MIPS ELF variants remain
unselected. This is slot evidence only: the analysis does not infer which
parameter ordinal owns a slot, reconstruct split values, or claim N32
aggregate/variadic placements. The ELF marker follows the Linux N32 loader's
[ABI identification](https://code.googlesource.com/linux/torvalds/linux/%2B/56bf6fc266ca14d2b9276c8a62e4ff6783bfe68b/arch/mips/kernel/binfmt_elfn32.c);
the supported scalar placements are documented in [ABI classification](abi-classification.md#mips-n32-scalar-subset).
