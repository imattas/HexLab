# JVM class-file loader

The built-in JVM loader reads one bounded class file. It retains the constant
pool, class declarations, members, method code bounds, exception tables, and
supported class-file attributes. It does not index JAR or ZIP containers.

## Bootstrap method metadata

`BootstrapMethods` entries must refer to a `CONSTANT_MethodHandle` using
`REF_invokeStatic` or `REF_newInvokeSpecial`, as required by the class-file
format. The loader also checks that each bootstrap argument is a supported
loadable constant kind and that every `CONSTANT_Dynamic` or
`CONSTANT_InvokeDynamic` entry refers to an existing bootstrap entry.

These checks validate local class-file structure only. The loader does not
resolve or execute bootstrap methods, check their runtime linkage behavior,
validate bootstrap method signatures against each call site, or evaluate
dynamic constants. Bootstrap entry and aggregate argument retention are each
capped at 8,192; oversized tables are rejected rather than partially retained.
