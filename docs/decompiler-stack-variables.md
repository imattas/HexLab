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
