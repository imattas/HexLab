# AArch64 statically resolved indirect calls

Function discovery can recover a local target for `blr Xn` when the incoming
register value is proven by the existing AArch64 constant-flow analysis. The
constant transfer now recognizes `adr` and `adrp` as address producers; supported
register arithmetic and copies can carry the address to the call. A candidate
is accepted only when the result maps to initialized executable bytes in the
same AArch64 execution context and is not rejected by function-recovery region
permissions.

Relocated operands do not produce constants. The analysis does not dereference
GOT entries, infer values loaded from memory, evaluate pointer-authentication
instructions, or resolve values that disagree across control-flow paths. It
also keeps the existing AArch64 CFG bounds and limits iterative indirect-call
discovery to eight rounds. Reaching a round limit marks the snapshot incomplete.
