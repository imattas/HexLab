# 6502 stack pointer restore tracking

The stack analysis recognizes the `TSX` / `TXS` pair as a symbolic stack
pointer save and restore. `TSX` records the current entry-relative stack depth
as the value represented by X. `TAX`, `TAY`, `TXA`, and `TYA` preserve copies
of that sampled value in A, X, and Y independently. `INX`/`DEX` and `INY`/`DEY`
update only the corresponding copy while its signed delta stays within the
unambiguous range of -127 through 127. If X still has a proven copy,
`TXS` restores the sampled depth minus its tracked register delta, including after
intervening pushes or pulls. Overwriting one alias invalidates only that
register's copy. A `JSR` invalidates all aliases because no callee
register-preservation convention is assumed; the caller's entry-relative S
depth remains known across the balanced call. A `TXS` with no proven live
`TSX`-derived X value remains an unknown stack-pointer write and makes
subsequent stack-relative results incomplete.

A later `TSX` replaces X's alias and resets the frame base. It preserves tracked
A/Y copies only when the current S depth equals the previous TSX sample, which
proves those byte values still describe the newly sampled S. If S moved or its
depth is unknown, the old A/Y copies are discarded because their deltas use a
different frame base. At CFG joins, an alias is retained only when every
incoming path has the same known delta; otherwise it is discarded.

Page-one indexed stack slots using `$0100,X` or `$0100,Y` can use either
register's independently tracked copy. The source alias remains available
after a transfer instruction copies it to another register.

The accumulator copy can also pass through immediate `ADC` or `SBC` when the
carry input is known from `CLC` or `SEC`. The analysis applies the exact
8-bit offset change, including the carry/no-borrow input, and keeps the copy
only while its signed displacement remains in the same -127 through 127
window. This supports sequences such as `TSX; TXA; CLC; ADC #n; TAX; TXS`.
Arithmetic result carry is not inferred, and any other instruction that
writes the status register makes the carry input unknown. Non-immediate
arithmetic and arithmetic with unknown carry discard the accumulator copy.
These rules preserve the relative slot identity without claiming to know the
incoming hardware S value.

This recovers balanced save/restore sequences without guessing the incoming
hardware S value. It does not model cycle timing, interrupt interleavings, or
stack-page wrapping across an unknown entry S value.

Register values and deltas are byte-wide. Relative deltas use the unique signed
modulo-256 range -127 through 127. A displacement outside it, including either
ambiguous half-page case, is discarded so wrap cannot merge distinct linear
slot identities.
