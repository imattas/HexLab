# Legacy JVM `jsr`/`ret` expansion

For classfile versions through 50, HexLab can lift legacy `jsr`, `jsr_w`,
`ret`, and `wide ret` control flow when the method has a recovered CFG and
matching classfile metadata. The classfile verifier tracks a return-address
value as a distinct verifier category. Each call site carries its exact
post-instruction bytecode address; `ret` branches only to the address set
proven for its local.

The lifter expands calls context-sensitively. It clones basic-block identities
for each nested call chain while retaining each cloned instruction's original
address, encoded bytes, and instruction ID. A subroutine may be called from
multiple sites, and a subroutine may call another subroutine. The output adds
symbolic `jvm_return_address` and `jvm_subroutine_return` intrinsics so the
return-address value and the expanded `ret` remain visible with source
provenance.

Expansion is bounded to 64 nested calls and 65,536 expanded blocks. A
recursive subroutine call, orphan `ret`, missing call continuation or target,
invalid `ret` local, path that bypasses `ret`, unresolved CFG edge, or normal
method return from inside a subroutine fails closed. Classfile versions 51
and later cannot use these opcodes. Methods with exception-table CFG edges or
StackMapTable frames are currently rejected by the subroutine expander because
their handler/frame identities need context-specific remapping. The loader's
classfile verifier still validates the stack and local categories for the
supported legacy forms and marks recursive or unsupported subroutine evidence
as partial.

This pass only expands control flow and verifies return-address transport. It
does not reconstruct source-level `finally` blocks or infer exception
semantics for old compiler patterns.
