# JVM reference conditional branches

`evaluate_jvm_null_branch` evaluates decoded `ifnull` and `ifnonnull` from a
caller-supplied nullness fact. It verifies the JVM conditional-branch shape
and requires the decoder's relative target, then returns whether the branch
condition is true. The helper needs no object identity or runtime metadata.

It does not pop the operand stack, resolve the target to a function edge, or
update the program counter. Reference nullness and branch-state changes remain
caller-owned.

`evaluate_jvm_reference_branch` evaluates decoded `if_acmpeq` and
`if_acmpne` by comparing caller-supplied reference identity tokens. The same
token represents the same reference, and token zero may represent null. It
validates the conditional relative-target form but does not inspect objects,
pop the stack, resolve control flow, or update the program counter.
