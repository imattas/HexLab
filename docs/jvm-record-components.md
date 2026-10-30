# JVM Record component metadata

The classfile loader retains finalized Java 16+ `Record` attributes (classfile
major version 60 or later). Minor versions must be zero or the classfile
preview marker 65535. Earlier Java 14/15 preview Record layouts are explicitly
unsupported. This describes classfile metadata, without requiring that the
class can be loaded or verified by a particular JVM.

`JvmMetadata::record` retains the Record attribute header's original file
offset and declared payload length. Its presence distinguishes an explicitly
empty Record from an absent attribute. The existing `record_components` vector
preserves declaration order. Every component retains its original name and
descriptor pool indexes, resolved text, complete source file extent, optional
raw generic Signature, runtime-visible/invisible declaration annotations and
runtime-visible/invisible type annotations.

`RuntimeVisibleAnnotations` and `RuntimeInvisibleAnnotations` are accepted in
component attribute lists, using the existing recursive annotation parser and
constant-pool tag checks. Each visibility may occur at most once per component,
including an empty annotation table. Annotation element values retain the same
validated textual encoding as class/field/method annotations. They are not
copied to a backing field, accessor or constructor parameter; attributes on
those declarations remain independent metadata.

Component names must be nonempty JVM unqualified names, and descriptors must
be valid non-void field descriptors. Attribute readers remain confined to the
component's enclosing Record payload and must consume their exact declared
extent. Components have stable ownership during parsing, so declaration and
type-annotation duplicate tracking distinguishes different components rather
than reusing a temporary object's address.

Existing limits apply: at most 8192 components, 8192 attributes per owner,
64 MiB per attribute and 256 MiB aggregate attribute payload. Component
declaration annotations share the class-wide 65,536 annotation-item budget and
64-level nesting bound with other annotations. Cancellation is checked between
attributes and annotation records. CLI inspection/project metadata output
prints Record/component source extents and at most 128 declaration-annotation
rows across all components, with bounded descriptor previews and an omission
count.

Unknown component attributes remain opaque under the existing incomplete-
metadata behavior. Generic-signature grammar, annotation class linkage,
reflection retention effects, generated record members, record inheritance and
full verifier semantics are not inferred.

The supported structures and allowed component annotation attributes follow
[JVMS 4.7.30](https://docs.oracle.com/javase/specs/jvms/se25/html/jvms-4.html#jvms-4.7.30)
and the attribute location/version tables in
[JVMS 4.7](https://docs.oracle.com/javase/specs/jvms/se25/html/jvms-4.html#jvms-4.7).
