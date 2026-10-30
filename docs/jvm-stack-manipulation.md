# JVM operand stack manipulation

The JVM lifter models the category forms of `dup`, `dup_x1`, `dup_x2`,
`dup2`, `dup2_x1`, `dup2_x2`, and `swap`. These instructions reorder the
existing typed expression pointers on the evaluation stack, so duplicated
values keep their original expression and type. Category 1 values are at most
32 bits in this IR; category 2 values are 64 bits.

Every opcode accepts only the verifier-defined category shapes. Invalid shapes
and stack underflow return an unsupported-lift error instead of emitting a
mis-typed stack. `pop` is restricted to category 1. `pop2` accepts one
category-2 value or two category-1 values.

The same transfer rules run during shape inference and final emission across
basic blocks. Nonempty primitive stacks use versioned definitions and phis;
reference-bearing joins and backedges additionally need exact incoming
identities and matching explicit StackMapTable frames. Category-2 values remain
one logical expression and count as two physical slots. See
[JVM stack transport](../libs/decompiler/docs/jvm-stack-transport.md) for exact
frame requirements and the remaining verifier limitations.

The processor API exposes `evaluate_jvm_stack_manipulation_instruction` for
decoded `pop`, `pop2`, `dup*`, and `swap` bytecodes. Supply the category widths
of exactly the consumed stack suffix, bottom-to-top, using 1 for category 1
and 2 for category 2. The result reports the consumed value count and a
bottom-to-top list of source indices describing the remaining/reordered
suffix. Illegal category shapes, invalid widths, underflow, and mismatched
decoded opcode metadata return no result. This is a local stack permutation;
it does not verify operand types, method frames, or surrounding bytecode.
