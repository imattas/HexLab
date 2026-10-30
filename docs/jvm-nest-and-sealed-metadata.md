# JVM nest and sealed class metadata validation

The class-file loader retains `NestHost`, `NestMembers`, and
`PermittedSubclasses` references with their constant-pool indexes and file
provenance. For `PermittedSubclasses`, it enforces the class-file rule that a
final class or interface cannot also carry the attribute.

`link_jvm_metadata_workspace` cross-checks `PermittedSubclasses` references
against the class metadata supplied to the workspace. It retains one link row
per attribute reference with source and target metadata indexes, source-file
offset, and status: `resolved`, `missing`, `ambiguous`, or
`not_direct_subtype`. A unique target resolves only when its superclass or
one of its directly implemented interfaces names the declaring class. The
workspace does not search for absent class files or choose among duplicate
definitions. Sealed-link rows are capped by the workspace edge limit and name
byte limit; reference and interface checks share the readability work budget
and poll cancellation.

Nest cross-checking is exposed by `link_jvm_path_workspace`: among supplied
classes it checks reciprocal `NestHost`/`NestMembers` declarations and package
identity. Neither pass proves defining-loader identity or validates runtime
access control. The sealed pass does not verify named-module membership,
same-module requirements, or whether the class-file version permits the
declaring class to use a given sealed form beyond the loader's local attribute
validation.
