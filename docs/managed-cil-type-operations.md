# Managed CIL type operations

The managed CIL lifter preserves the operand and TypeDef, TypeRef, or TypeSpec metadata token for `box`, `unbox`, `unbox.any`, `castclass`, and `isinst`. Each operation consumes one evaluation-stack value and produces one result. `box`, `unbox`, `castclass`, and `isinst` produce a managed-reference category; `unbox.any` keeps an unknown value type until the referenced metadata type can be resolved precisely. The token is retained in `referenced_tokens`, and the common IR emits an explicit `cil_box`, `cil_unbox`, `cil_unbox_any`, `cil_castclass`, or `cil_isinst` intrinsic rather than dropping the operation.

The token must use one of the three CLR type-token tables and have a nonzero row index. Invalid tokens and evaluation-stack underflow fail as malformed input. The stack-shape pass and emission pass use the same stack effect, so these operations participate in bounded CFG stack propagation and SSA joins.

This is not CLR verification or execution. Runtime type compatibility, exact boxed value layout, cast failure behavior, null behavior, and exception edges are opaque. The lifter therefore marks the result incomplete and records a diagnostic. `unbox.any` keeps an unknown result type; the implementation does not infer value types from unresolved or generic metadata.
