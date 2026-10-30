# JVM generic Signature metadata

`parse_jvm_generic_signature(text, kind, stop)` parses the class, method or field
generic-signature grammar from JVMS §4.7.9.1. Its flat, ordered syntax tree has
root index zero and explicit child indexes. Nodes retain their grammatical role,
identifier/base-type name where applicable, and byte offset/length within the
original signature text. Type parameters retain separate class-bound and
interface-bound nodes; an omitted class bound is an empty class-bound node
covering its colon. Class types retain package-qualified first segments and
separate nested-class suffixes with their own arguments. Exact, extends, super
and unbounded arguments stay distinct. Arrays, type variables, method parameters,
void/non-void results and class/type-variable throws types retain their shape.

The class loader attaches `JvmGenericSignatureAnalysis` to class, field, method
and Record-component `Signature` owners. Original signature strings remain
unchanged. Analysis retains the signature constant-pool index, the exact
two-byte attribute index field's file offset and the referenced CONSTANT_Utf8
payload's file offset. A parsed node's original source range starts at
`text_file_offset + text_offset` and has `text_size` bytes. Identifier bytes
preserve the classfile's validated modified UTF-8 encoding; offsets count bytes,
not Unicode characters. The standalone grammar API expects that encoding and
does not independently validate modified UTF-8.

`LocalVariableTypeTable` entries now use the bounded field-signature parser as
well. Each local retains raw text, an optional parsed tree or diagnostic, its
constant-pool index, attribute-field offset and referenced text offset. The CLI
shows a bounded tree for locals alongside their slot and bytecode range. These
generic locals are still metadata only: they are not bound to stack-map frames,
verified against bytecode types or used to infer runtime locals.

Signatures require classfile version 49 or newer for grammar analysis; the
ordinary loader's existing supported classfile-version range still applies.
The grammar requires nonempty identifiers/argument/formal-parameter lists,
correct delimiters, reference-only field types and generic arguments,
class-only supertype signatures, class/type-variable throws types, and exact
consumption. `void` is accepted only as a method result. Identifier characters
follow the generic grammar's forbidden ASCII delimiters, without imposing Java
source-language identifier rules.

Invalid or over-budget grammar leaves the raw string and an explicit unparsed
diagnostic, marks metadata incomplete, and preserves normal class loading.
Cancellation propagates as cancellation. Attribute framing, constant-pool tags
and duplicate attributes continue to use the ordinary hard validation rules.
This follows the distinction in the JVMS: generic Signature well-formedness is
not checked by Oracle's VM during class loading/linking. Standalone API callers
receive malformed/resource-limit errors directly.

Each signature is limited to 65,535 bytes, 1,024 nodes and 32 nested type levels.
Class loading additionally caps grammar analysis at 4,096 attempts, 8 MiB of
cumulative text examined and 100,000 retained nodes. Repeated references to the
same string count as separate work. Once those budgets are exhausted later
owners remain raw with diagnostics. Names are copied from bounded text;
the tree does not load classes, follow recursive type-variable bounds or expand
generic instantiations.

CLI class inspection and saved-project inspection print bounded structural
rows: up to 128 owners, 16 nodes per shown owner and 128 nodes overall. Rows show
grammar role, identifier, text/source range and child indexes; long identifiers
and child lists have bounded previews, with owner/node omission counts. The
original signature display remains available.

The class loader now binds each `Tname;` reference against the generic formal
parameters declared by its owner. Class formals scope class signatures, fields,
record components, methods and generic locals. Method formals are added for the
method signature and that method's `LocalVariableTypeTable`. An undeclared
variable leaves the grammar tree and raw signature intact, adds an owner
diagnostic and marks metadata incomplete; it does not reject the classfile.
This is name binding only: formal bounds are not recursively expanded and
shadowing is resolved by the method scope taking precedence over the class
scope.

These trees do not establish class-loader identities, validate declared bounds,
infer subtype/assignability, compare erased signatures with descriptors or
validate code. In particular, method signature parameter counts are not
required to equal descriptor counts because compiler generated constructor
parameters may be omitted from generic signatures.
Actual module linking, split/encrypted archives and compression beyond
stored/DEFLATE remain unsupported.

The grammar and loading distinction follow Oracle's
[JVMS Signature attribute and grammar](https://docs.oracle.com/javase/specs/jvms/se25/html/jvms-4.html#jvms-4.7.9).
