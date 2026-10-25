# Cross-ABI stack argument recovery

Interprocedural type recovery can now use stack arguments at a direct call when
the caller and callee use different calling conventions over the same machine
register file. This extends the existing cross-ABI register argument path.

The argument slot comes from the callee's ABI description or explicit
prototype. The analysis maps that slot from the caller's current stack pointer
back to its incoming stack base, including the caller's call-stack adjustment,
then scans backward for a store to that exact outgoing offset. The store must
be a register value with a byte-aligned width matching the recovered value's
type and the callee slot's integer, floating, or vector class.

The proof stops at an intervening call, an unknown or writing intrinsic, a
partial or overlapping store, a non-register value, or an address that cannot
be reduced to the incoming stack base plus a constant. It does not assume that
the caller's own incoming stack-argument slot map describes arguments that the
caller sends to another function. This matters when, for example, a Windows
x64 caller invokes a System V AMD64 callee whose stack arguments use a
different entry-relative location.

Recovered types enter the same bounded fixed point as register arguments.
Conflicting caller evidence prevents propagation; an unknown argument at a
non-recursive call also blocks consensus. Explicit prototypes remain
authoritative. Aggregate values split across stack locations, dynamic indexed
stores, and calls between different register files remain unsupported. The
result is analysis evidence, not a confirmed source declaration.
