# DEX conditional branch predicates

`evaluate_dex_branch_predicate_instruction` evaluates the decoded `if-eq`,
`if-ne`, `if-lt`, `if-ge`, `if-gt`, and `if-le` forms, including their `*z`
variants. Equality compares raw 32-bit values; relational branches interpret
them as signed Java `int` bit patterns. The adapter checks the DEX branch
encoding, typed vreg operands, read effects, and relative-target operand.

The caller supplies values for the decoded source registers and remains
responsible for choosing the branch target, updating the instruction pointer,
and maintaining verifier/type state. Reference equality is represented by
the same raw 32-bit equality operation; heap identity is not modeled.
