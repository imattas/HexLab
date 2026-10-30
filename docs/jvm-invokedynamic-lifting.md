# JVM invokedynamic call-site lifting

The JVM lifter accepts `invokedynamic` instructions when classfile metadata is
available. It validates the instruction's two reserved zero bytes, resolves the
`CONSTANT_InvokeDynamic` entry and its name-and-type descriptor, consumes the
descriptor's ordered arguments from the operand stack, and emits a typed opaque
call-site intrinsic. Non-void results are retained as opaque values of the
descriptor's return type. The intrinsic records the call-site name and
descriptor, bootstrap-method table index, and constant-pool index. The loader
retains the class-level `BootstrapMethods` attribute, including each method
handle index and ordered argument indices, and validates all entries and
bootstrap references.

The loader also gates modern constant-pool forms by classfile version:
`MethodHandle`, `MethodType`, and `InvokeDynamic` require version 51 or newer,
`Module` and `Package` require 53 or newer, and `Dynamic` requires 55 or newer.
Method-handle reference kinds are checked against special method names:
`REF_newInvokeSpecial` must target `<init>`, while other invocation kinds may
not target `<init>` or `<clinit>`. This is static classfile validation only;
bootstrap methods and dynamic constants are not resolved or executed. These
version and name constraints follow the [JVM Specification, Chapter 4](https://docs.oracle.com/javase/specs/jvms/se25/html/jvms-4.html).

This represents the data flow of modern Java call sites such as string
concatenation, lambdas, and method references without executing bootstrap code
or pretending that the bootstrap target has been resolved. Call sites have no
implicit receiver: their parameters come only from the call-site descriptor.
The effect is conservatively marked as unknown because bootstrap linkage may
perform arbitrary work.

For `StringConcatFactory.makeConcatWithConstants`, the lifter includes the
escaped recipe in the symbolic intrinsic when its `\u0001` dynamic-argument
and `\u0002` bootstrap-constant marker counts match the call-site descriptor
and retained bootstrap arguments. This annotates the recipe only; it does not
substitute arguments, fold a result, or execute linkage. The lifter does not
resolve LambdaMetafactory targets or reconstruct lambda bodies. Malformed
constant-pool entries, descriptors, operand-stack types, or nonzero reserved
bytes fail closed with a diagnostic.
