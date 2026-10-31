# JVM object and constant operations

The typed JVM lifter now materializes common `ldc`, `ldc_w`, and `ldc2_w`
constants, including integer/float/long/double values, String constants, Class
constants, and `CONSTANT_Dynamic` values. Symbolic values retain the constant
pool index. String values include an escaped preview of at most 96 encoded
bytes; the full modified UTF-8 value remains in class metadata. Dynamic values
validate the name-and-type descriptor and the encoded category, then retain the
bootstrap table index and constant-pool index as an opaque intrinsic. Bootstrap
methods are not decoded or executed.

`checkcast` and `instanceof` validate and retain the referenced Class constant.
They consume a reference and produce an opaque typed result (a reference for
`checkcast`, JVM int for `instanceof`). The class hierarchy is not linked, so
cast success and exact `ClassCastException` behavior are not inferred.

`monitorenter` and `monitorexit` preserve their reference operand as
synchronization intrinsics with unknown effects. This does not model monitor
ownership, reentrancy, or exceptional exits. `multianewarray` validates an
array Class descriptor and its requested rank, consumes each dimension size in
JVM stack order, and emits an allocation intrinsic. `new`, `newarray`,
`anewarray`, and `multianewarray` retain a may-trap edge for
`OutOfMemoryError` with an opaque runtime predicate; primitive/reference array
allocations also retain the exact negative-size predicate. Heap contents,
allocator thresholds, class-initialization failures, and other linkage errors
remain unresolved.

All operands use the existing typed stack checks. Values cross basic blocks
through versioned stack definitions and phis. Reference-bearing joins and
backedges require exact incoming reference identities and an explicit matching
StackMapTable frame; see [JVM stack transport](../libs/decompiler/docs/jvm-stack-transport.md).
These operations do not execute class code.
