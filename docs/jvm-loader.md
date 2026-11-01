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

## Module descriptor references

The class-level `Module`, `ModulePackages`, and `ModuleMainClass` attributes
are decoded only on a Java 9-or-newer `module-info` class. Their constant-pool
operands are checked against the required `CONSTANT_Module`,
`CONSTANT_Package`, or `CONSTANT_Class` tags (and the referenced UTF-8 entry),
and duplicate entries, reserved flag bits, invalid counts, and attribute
length mismatches reject the class. The decoded module name, package list and
optional main class remain available as project metadata.

This is local descriptor metadata, not module resolution. It does not establish
that the listed packages or main class exist, or that requirements can be
satisfied. Unknown attributes remain file-backed opaque extents, and known
attributes must consume their declared extent exactly.

## Generic type-annotation targets

Declaration type annotations now bind to the owning declaration's parsed
`Signature` tree after all classfile attributes have been read. Binding covers
class/method type parameter declarations and their bounds, class supertypes,
field/Record-component types, and ordinary method result types. Both visibility
variants receive the same handling. The original `target_info`, `type_path`,
and annotation value remain intact.

`target_signature_node` identifies the declaration/type root;
`annotated_signature_node` identifies the selected type, class segment or
wildcard after following the encoded type path. Both indexes address the
immediate owner's `generic_signature.parsed.nodes`. Existing node text spans
and signature constant-pool/source offsets locate the selected source bytes.
Array elements, nested class segments, wildcard bounds and indexed type
arguments are navigated without expanding or copying signature text. Bound
index zero remains reserved for the class-bound slot even when that slot is
empty; such an empty slot cannot supply an annotated type.

A missing, malformed, over-budget or semantically unresolved signature, an
out-of-range type parameter/bound, or an incompatible path leaves the original
annotation available with `target_diagnostic` and marks metadata incomplete.
Binding failure does not reject otherwise readable classfile bytes. Non-generic
field/result/supertype declarations without a Signature are retained without a
binding attempt. A valid root can remain available when path navigation fails.
The CLI prints root/terminal node indexes or the diagnostic and caps output at
128 type annotations per visibility and owner.

Formal parameter, throws, receiver, constructor-result and Code targets remain
in their existing raw representation. Formal parameter indexes can differ from
method descriptor positions because of synthetic parameters. Generic throws
clauses can omit ordinary exceptions, and a constructor's Signature result is
`V` although its return-type annotation denotes the constructed class. The
loader does not guess those mappings, infer nested class segments from `$` in
binary names, resolve external types, or navigate paths against descriptors
when generic syntax is unavailable. These rules follow the
[JVMS target_info and type_path definitions](https://docs.oracle.com/javase/specs/jvms/se25/html/jvms-4.html#jvms-4.7.20.1).

Binding performs one bounded traversal of each retained signature root and at
most 255 steps for each retained annotation path. Existing class budgets cap
signature retention at 100,000 nodes and combined annotation metadata at 65,536
items; the binder introduces no recursive traversal or signature-text copies.
Cancellation is checked for every annotation.

Type-variable references are checked against the owning class and method
formal declarations. Erasure checks compare resolvable field, component,
superclass, interface and method signature types with their JVM descriptors.
When a formal has a cyclic or otherwise unresolved bound, the signature stays
available with a diagnostic and metadata is marked incomplete; the loader
does not guess an erasure or claim descriptor consistency for that signature.

Validation on Windows x64 Debug: configured with `BUILD_TESTING=OFF`, built and
linked `hexlab_loaders`, and compiled all CLI translation units with MSBuild
`/t:ClCompile /p:BuildProjectReferences=false`. Both commands exited zero. The
full CLI executable link was not run. No tests were added or run.
