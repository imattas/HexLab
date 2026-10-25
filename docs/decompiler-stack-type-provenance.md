# Stack Local Type Provenance

The decompiler carries exact type evidence from a register value into a recovered stack local when that value is stored to the local. This preserves ABI or prototype types across spill/reload sequences, including sequences whose store and reload occur in different basic blocks. For example, when a known `Node *` is spilled and reloaded before a field access, the local declaration can retain `Node *` instead of falling back to a generic byte pointer.

Exact type evidence is merged across all stores observed for the recovered slot. Repeated stores of the same type keep the type. If stores provide different exact types, the slot's exact type is marked ambiguous and is not used to override the ordinary inferred local type. Existing pointer-layout, width, and mixed integer/pointer checks remain in force.

This is a conservative provenance transfer, not full memory SSA. It applies to stack slots that the existing stack-variable recovery recognizes as unescaped, non-overlapping fixed frame-relative locations. It does not infer a source type from a cast, recover arbitrary heap/global memory types, or force an exact type onto a slot whose observed width conflicts with the type. Conflicts are suppressed rather than resolved by control-flow order.
