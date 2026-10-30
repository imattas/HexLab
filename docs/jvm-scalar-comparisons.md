# JVM scalar compare instructions

The typed JVM lifter represents `lcmp`, `fcmpl`, `fcmpg`, `dcmpl`, and
`dcmpg` as explicit three-way comparison operations with an `int` result.
`lcmp` returns `-1`, `0`, or `1` according to signed long ordering. The float
and double forms return `-1` for `fcmpl`/`dcmpl` when either operand is NaN,
and `1` for `fcmpg`/`dcmpg` in that case; for ordered operands they return
`-1`, `0`, or `1` by numeric ordering. Equal signed zeros compare as zero.

Pseudocode uses `jvm_lcmp(a, b)`, `jvm_fcmpl_nan_minus_one(a, b)`,
`jvm_fcmpg_nan_plus_one(a, b)`, `jvm_dcmpl_nan_minus_one(a, b)`, or
`jvm_dcmpg_nan_plus_one(a, b)`. These are typed IR operations that preserve
the bytecode's exact result convention; later integer branches consume the
result as an ordinary signed `int`. This does not claim full classfile
verification or floating-point exception modeling.

`jvm_semantics.hpp` exposes `evaluate_jvm_integer_branch` for decoded `ifeq`,
`ifne`, `iflt`, `ifge`, `ifgt`, `ifle`, and the six `if_icmp*` operations. It
uses signed 32-bit stack values and validates the decoded JVM conditional
branch and relative target before returning the taken decision. Operand-stack
pops, target selection, PC updates, reference comparisons, and null tests
remain outside this evaluator.
