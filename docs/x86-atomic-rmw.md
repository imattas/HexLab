# x86 exchange and compare-exchange lifting

The x86 lifter preserves decoded `XCHG`, `XADD`, and `CMPXCHG` operations as typed
intrinsics for 8-, 16-, 32-, and 64-bit operands. `XCHG` and `XADD` carry the old
destination and source values, the destination result type, and all decoded
register writes so both outputs of the exchange/add remain visible. `CMPXCHG`
also carries the implicit accumulator value and retains the
decoded accumulator/register writes and flag effects.

Memory destinations use an unknown memory effect because the generic IR does
not yet represent atomic memory operations or conditional writes. Register
destinations have no memory effect. The intrinsic preserves the operation and
its dependencies for analysis without claiming instruction execution, LOCK
atomicity (including XCHG's implicit memory locking), or detailed EFLAGS
computation.
