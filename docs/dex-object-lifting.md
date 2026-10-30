# Dalvik object-operation lifting

The DEX lifter preserves common object-reference operations in the shared IR.
`move-object` forms and `return-object` use 32-bit pointer values. `const-string`,
`const-string/jumbo`, and `const-class` retain their string/type table indexes in
an explicitly unknown reference value until metadata resolution is available.
`move-exception` likewise records an unknown object reference because the
analysis snapshot does not link handler entries to declared exception types.

`instance-of` keeps its validated type index, reads the object reference, and
defines a boolean result whose runtime value remains unknown. `check-cast`
retains the type index and object operand as an opaque operation, since the
runtime type check may throw. With retained DEX metadata, both instructions and
`const-class` reject out-of-range type indexes; primitive descriptors remain
valid indexes and preserve the DEX runtime behavior. `new-instance` requires a
class descriptor, while `new-array` requires an array descriptor. Without
metadata, the lifter retains the prior opaque type-index form. Monitor
enter/exit and `throw` are preserved as opaque operations with unknown effects
so they are not silently discarded.

The processor validates each instruction's encoded size and register form before
lifting. Reference values remain 32-bit because this implementation targets the
DEX format's 32-bit virtual-register model. String/type indexes are not resolved
to names yet. Exception-handler edges, verifier type propagation, precise monitor
behavior, and runtime cast/throw semantics remain unsupported; the lifter does
not claim those effects are fully modeled.
