# x86 exchange and compare-exchange lifting

The x86 lifter preserves decoded `XADD` and `CMPXCHG` operations as typed
intrinsics for 8-, 16-, 32-, and 64-bit operands. `XADD` carries the old
destination and source values, the destination result type, and all decoded
register writes so both the sum and the source-register exchange remain
visible. `CMPXCHG` also carries the implicit accumulator value and retains the
decoded accumulator/register writes and flag effects.

Memory destinations use an unknown memory effect because the operation may
read or write memory depending on the compare result, and the generic IR does
not yet represent conditional atomic writes. Register destinations have no
memory effect. The intrinsic preserves the operation and its dependencies for
analysis without claiming instruction execution, LOCK atomicity, or detailed
EFLAGS computation.
