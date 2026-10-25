# ARM literal pointer reference propagation

A32 and Thumb reference analysis now follows a bounded, exact pointer value loaded
from a statically resolved 32-bit memory operand. This includes PC-relative
literal loads and loads through a base register whose value was already proven
by supported address-building instructions or earlier pointer loads.

A load creates a register value only when the instruction is an ordinary
32-bit `LDR`, its destination is a written ARM general-purpose register, the
pointer slot is readable and file-backed, no relocation overlaps the 4-byte
slot, and the value points into a mapped image address. The existing CFG data
flow merge retains only values that agree across incoming paths. Calls and
writes to the destination invalidate prior facts. A32 and Thumb execution
states remain separate.

The loaded pointer can then resolve a later register-based memory access into
a concrete data reference. This does not infer dynamic relocations, writable
runtime pointer contents, signed/byte/halfword loads, arbitrary register
arithmetic, or control-flow targets from `BX`/`BLX`.
