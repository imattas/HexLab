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

Page-one indexed stack slots using `$0100,X` or `$0100,Y` can use either
register's independently tracked copy. The source alias remains available
after a transfer instruction copies it to another register.

This recovers balanced save/restore sequences without guessing the incoming
hardware S value. It does not model cycle timing, interrupt interleavings, or
stack-page wrapping across an unknown entry S value.
