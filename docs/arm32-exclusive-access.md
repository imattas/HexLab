# A32 and Thumb-2 exclusive accesses

The decoder recognizes word, byte, and halfword `LDREX`/`STREX` forms in A32
and Thumb-2. Loads write the target register and mark an exclusive memory
read; stores read the value and base registers, write the status register, and
mark a possible conditional memory write. The address operand carries the
access width. PC operands are rejected. A load may use the same register for
its base and transfer value. A store's status register must be distinct from
its base and transfer value. Thumb forms also reject SP; LR remains available.

A32 forms are decoded for zero-offset addresses. Thumb word forms retain the
encoded scaled immediate offset; Thumb byte/halfword forms use the architectural
zero offset. The decoder does not emulate the local exclusive monitor, decide
whether a store succeeds, or model barriers, acquire/release variants,
doubleword accesses, or cache-coherency behavior. `STREX` status is represented
as a normal destination register write, with the success value determined by
the caller's runtime monitor model.

The field layouts follow the Arm A32/T32 instruction definitions and the QEMU
decoder's `a32.decode` / `t32.decode` tables.
