# JVM invokedynamic call-site lifting

The JVM lifter accepts `invokedynamic` instructions when classfile metadata is
available. It validates the instruction's two reserved zero bytes, resolves the
`CONSTANT_InvokeDynamic` entry and its name-and-type descriptor, consumes the
descriptor's ordered arguments from the operand stack, and emits a typed opaque
call-site intrinsic. Non-void results are retained as opaque values of the
descriptor's return type. The intrinsic records the call-site name and
descriptor, bootstrap-method table index, and constant-pool index.

This represents the data flow of modern Java call sites such as string
concatenation, lambdas, and method references without executing bootstrap code
or pretending that the bootstrap target has been resolved. Call sites have no
implicit receiver: their parameters come only from the call-site descriptor.
The effect is conservatively marked as unknown because bootstrap linkage may
perform arbitrary work.

BootstrapMethods contents and their method handles/arguments are not yet
retained by the classfile loader. The lifter therefore does not validate the
bootstrap index against that attribute, resolve LambdaMetafactory targets,
reconstruct lambda bodies, or fold StringConcatFactory recipes. Malformed
constant-pool entries, descriptors, operand-stack types, or nonzero reserved
bytes fail closed with a diagnostic.
