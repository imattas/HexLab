# AArch64 paired integer memory operations

The A64 scalar decoder recognizes integer W/X `LDP` and `STP` in signed-offset, pre-index, and post-index addressing modes. The typed instruction records both transfer registers, transfer width, signed byte displacement, the effective address, and whether the base register is updated. SIMD/FP pairs, non-temporal pair encodings, and reserved width/mode combinations remain unsupported.

The decompiler preserves a pair as one explicit memory intrinsic. It lists both effective element addresses (the second is one transfer-width after the first), keeps store values in transfer order, marks the correct memory read/write effect, and records all output registers. Pre/post-index forms also include the computed base update and mark the base register as written. For example, `stp x29, x30, [sp, #-16]!` retains the pre-decremented pair address and the updated SP; `ldp x29, x30, [sp], #16` reads from the old SP and records the post-increment.

This provides faithful IR and deterministic pseudocode for common AArch64 function prologues and epilogues. It does not yet perform stack-frame inference from these operations or recover pair loads as two ordinary SSA assignments; the intrinsic explicitly retains their grouped memory semantics.
