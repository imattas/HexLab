# JVM annotation value metadata

The classfile loader retains typed `element_value` trees alongside the existing
text summaries. This covers RuntimeVisible/InvisibleAnnotations on declarations
and Record components, parameter annotations, type annotations, and
AnnotationDefault. The rules follow the [JVMS annotation structures](https://docs.oracle.com/javase/specs/jvms/se25/html/jvms-4.html#jvms-4.7.16.1)
and [AnnotationDefault](https://docs.oracle.com/javase/specs/jvms/se25/html/jvms-4.html#jvms-4.7.22).

`JvmAnnotationElement::encoded_value` and
`JvmMember::annotation_default_value` expose `JvmAnnotationValue`. Each node
retains its original tag, constant-pool indices, byte offset, and complete
encoded byte length, including the tag. Primitive and string nodes retain their
constant-pool reference; enum nodes retain both type and name indices; class
nodes retain the class-literal descriptor index. Arrays retain ordered children.
Nested annotation nodes retain their type index, ordered children, and a parallel
element-name-index vector. `JvmAnnotation` additionally retains its type index
and full annotation extent; top-level elements retain their name index.

Constant-pool indices address the owning `JvmMetadata::constant_pool`. Numeric
raw bits remain in the constant pool, preserving signed values, NaNs, and signed
zero without decimal conversion. String values retain the classfile's modified
UTF-8 through their original constant-pool entry. Consumers should inspect the
typed nodes rather than parsing human-readable `value` or `annotation_default`
strings; those existing summaries remain available in their previous format.

The parser now checks annotation and enum object descriptors, class-literal
return descriptors (including primitive and `void.class` literals), annotation
element names, enum constant names, and duplicate element names inside each
annotation. Declaration/parameter annotations and defaults require classfile
version 49 or later; type annotations retain their existing version-52 floor.
Constant-pool kind, attribute ownership, duplicate-attribute, and exact-extent
checks remain in effect.

AnnotationDefault compatibility uses the typed values. Scalar primitive tags
must match exactly; String and Class use their specified tags. Enum and nested
annotation values must carry the exact result descriptor. Every array element
is checked against the declared component type, including enum/annotation type
identity. A one-dimensional empty array is valid; multidimensional return types
and nested array defaults are rejected. Class resolution is unavailable, so an
object descriptor alone does not prove that an external type is an enum or an
annotation interface, that a named enum constant exists, or that an annotation
element is declared by that interface.

Bounds are shared across the entire classfile: at most 65,536 value-tree nodes,
the existing 65,536 aggregate annotation-item budget, and nesting depth 64
(the root value has depth zero). A separate 16 MiB text-work budget covers
resolved annotation descriptors, top-level element names, and all generated
summary fragments. Nested fragments are charged again when copied into parent
summaries, bounding temporary rendering work as well as retained strings.
Constant-pool storage and source bytes keep their existing independent bounds.
Cancellation is checked for every annotation declaration and value node and
during default-array compatibility checks. Malformed or over-budget annotation
metadata fails loading; it is never returned as a partially validated tree.

These structures describe classfile evidence. They do not instantiate
annotations, resolve classes, execute defaults, or provide reflection semantics.
