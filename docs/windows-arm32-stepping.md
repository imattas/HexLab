# Windows ARM32 software stepping

The native Windows ARM32 backend can single-step verified sequential Thumb and
A32 instructions by placing a temporary software breakpoint at the computed
successor. The branch decoder models the supported branch forms and selected
control-flow loads; instructions outside that set fail closed instead of
guessing a successor.

Thumb-2 `LDMIA.W` loads that include PC are supported, including the `POP.W`
alias based on SP. The backend reads the PC word from the ascending transfer
list, uses bit zero to select Thumb versus ARM state, and validates the loaded
target alignment. A conditional execution governed by ITSTATE is honored only
in the final IT slot. Writeback with the base register in the list, invalid or
unaligned extents, and overflowing target ranges are rejected. The temporary
successor trap is also rejected if it overlaps either the multi-register
transfer range or the stepped instruction, since either overlap could alter
the instruction's behavior before it executes.

This does not add support for Thumb-2 decrementing multi-register loads, A32
exception-return loads, or arbitrary PC-writing instructions. Windows ARM32
native runtime behavior still requires validation on an ARM32 Windows target.
