# JVM classfile analysis

The built-in JVM loader reads one bounded classfile (not a JAR). It retains the constant pool, class/super/interface names, fields, methods, and each method's `Code` bounds, max-stack/max-locals values, and exception table. Every nonempty `Code` array maps into its own 32-bit, byte-addressed address space so branch offsets are method-relative.

`Code` metadata also retains bounded, expanded `StackMapTable` verifier frames, including object constant-pool identities and uninitialized-object offsets. See [JVM StackMapTable metadata](jvm-stack-map-tables.md) for the public model, instruction-boundary checks, resource bounds, and distinction between parsed frames and full verification.

The classfile loader retains `RuntimeVisibleAnnotations` and
`RuntimeInvisibleAnnotations` on classes, fields, and methods. Annotation
descriptors and element names are resolved from the constant pool. Element
values are validated recursively and kept in a stable textual form; constant
and string entries identify their original constant-pool indices. Nesting is
limited to 64 levels and aggregate annotation items to 65,536. Method
`RuntimeVisibleParameterAnnotations` and
`RuntimeInvisibleParameterAnnotations` are also retained as ordered per-
parameter vectors, including empty parameter entries. `AnnotationDefault` is
retained in the same stable textual value form as annotation elements. These
attributes are accepted only on method declarations, duplicate occurrences
are rejected, and their payloads must be consumed exactly within the declared
attribute extent. CLI summaries show declaration and parameter annotation
visibility, owner, descriptor, and element count, and print annotation default
values. Runtime-visible and runtime-invisible type annotations are retained on
classes, fields, methods, and Code attributes. Their target_info bytes are
preserved in class-file order, type paths are decoded and validated, and Code
targets are checked against code length, local slots, and exception-table size.
The CLI shows visibility, owner, target type, path length, descriptor, and
element count. Type annotations nested in record-component attribute lists are
not yet retained.

For class-file version 52 and later, method `MethodParameters` attributes retain
each parameter's optional UTF-8 name index and access flags in descriptor
order. The parser enforces method ownership, one occurrence, exact attribute
length, descriptor parameter count, valid UTF-8 indexes, and only `final`,
`synthetic`, and `mandated` flags. A zero name index is retained as an unnamed
parameter. CLI summaries list parameter names (or `<unnamed>`) and flags.

Static-field `ConstantValue` attributes are retained after strict field-owner,
uniqueness, payload-length, constant-pool-tag, and descriptor checks. Numeric
values preserve their raw constant-pool bits; string values expose the resolved
modified-UTF-8 text. CLI field summaries show the value, with numeric values in
hexadecimal to preserve NaN payloads and signed zero. The metadata remains
partial only for other unsupported attributes.

Source and Code debug metadata includes the class-level `SourceFile`, each
method's optional `LineNumberTable`, `LocalVariableTable`, and
`LocalVariableTypeTable`. The loader retains line start offsets and source
line numbers, and local names, descriptors or generic signatures, slots, and
live ranges. Generic local signatures are retained as text without parsing
their grammar. Tables preserve absence versus an
explicitly empty table, aggregate legal repeated attributes, and require exact
payload lengths. Aggregate rows are capped at 65,535 per table kind and Code
attribute; duplicate local-variable entries are rejected across all tables
for that Code attribute. Line/local offsets and local slots are checked against the owning Code array
and `max_locals` (including the second slot of long/double locals). These
checks bound the referenced bytecode region, but do not prove that an offset
lands on an instruction boundary. `SourceDebugExtension` remains unsupported.

Class, field, and method metadata also retain their optional generic `Signature` string. The loader checks the exact two-byte payload, resolves its index as `CONSTANT_Utf8`, rejects duplicate signatures and signatures in Code attribute lists, and preserves absence separately from an empty signature. It retains the signature text without parsing or validating the generic-signature grammar. Class metadata also retains `Record` component names and descriptors (including a component's optional generic `Signature`), `NestHost`/`NestMembers`, and `PermittedSubclasses`. These attributes validate their declared extents and every referenced constant-pool entry. Each supported class attribute may appear at most once; list counts are bounded at 8192. Unknown nested Record component attributes are extent-checked and mark metadata incomplete. This metadata is descriptive: it does not yet synthesize Java record methods, prove nestmate access, or link permitted classes across classfiles.
The loader also retains the class-level `InnerClasses` table in its declared order. Each entry resolves the required inner `CONSTANT_Class`, optional outer class and optional inner simple-name `CONSTANT_Utf8`; entries have unique inner-class indexes, only defined access bits, an exact `2 + 8 * number_of_classes` payload, and a limit of 8192 entries. Duplicate attributes and uses outside class attributes are rejected. For classfile version 51 and later, an entry without an inner name cannot specify an outer class. The CLI prints each retained inner/outer/name tuple and access flags. This is descriptive metadata and does not link referenced classes or infer lexical relationships beyond the table.

The CLI's class summary prints these retained attributes and record component signatures.

For Java 9+ `module-info` classes, the loader retains the `Module`, `ModulePackages`, and `ModuleMainClass` attributes. The module record includes its name, flags and optional version; required modules and versions; exported/opened packages and qualified target modules; service uses and provider implementations; the declared package list; and optional main class. Every entry is checked against the required `CONSTANT_Module`, `CONSTANT_Package`, `CONSTANT_Class`, or `CONSTANT_Utf8` pool tag, flags are checked against the classfile masks, and the attribute extents must match exactly. Each module list is bounded, with no more than 8192 total entries in a `Module` attribute; module-package lists are capped at 8192. Module attributes are restricted to valid `ACC_MODULE` `module-info` classes, and package/main-class attributes require a `Module` attribute. This is descriptive metadata only: the loader does not resolve required modules, check package ownership across a module path, or enforce service-provider/linkage semantics.

Method-level `Exceptions` attributes are retained as an optional ordered list of declared exception class names (an explicitly empty attribute is distinct from an absent one). The parser requires the attribute payload to be exactly `2 + 2 * number_of_exceptions` bytes and validates every index as a `CONSTANT_Class` with a valid UTF-8 name. Duplicate attributes and uses outside method attributes are rejected by the attribute-context checks. Up to the classfile's `u2` count (65,535) is representable, subject to the 64 MiB per-attribute and 256 MiB aggregate attribute limits. The CLI prints retained declarations after the method descriptor. This is declaration metadata only; it does not establish that bytecode throws only those types or resolve external class hierarchies.

The parser accepts classfile major versions 45 through 70, a 512 MiB input, at most 8192 fields/methods and attributes per owner, 8192 exception handlers per Code attribute, 64 MiB per attribute, and 256 MiB total attribute payloads. It parses standard constant-pool tags 1, 3–12, 15–20, including two-slot long/double entries. Unknown constant-pool tags, malformed indices, invalid modified UTF-8, out-of-range code/handler extents, and oversized metadata fail closed. Unknown attributes are skipped within their validated extent and mark metadata partial.

The decoder covers standard JVM opcodes through `jsr_w`, including `wide`, `tableswitch`, and `lookupswitch`. Switch tables may use the full bounded JVM `Code` extent (65,535 bytes per instruction encoding), rather than a smaller arbitrary case cap. The byte extent therefore bounds dense tables to roughly 16K entries and lookup tables to roughly 8K pairs. Full encoded lengths and bytes are retained through function IDs, derived caches, incremental validation, graph fingerprints, and CLI byte display. Switch parsing validates alignment padding, table bounds, sorted lookup keys, and that targets lie outside the switch encoding. Reserved/implementation-dependent bytecodes and malformed or overflowing branch targets are unsupported/invalid. Method code is ordinary classfile bytecode and is never executed.

The typed common-IR lifter supports null and integer/long/float/double constants, primitive and reference local loads/stores through local index 255, `iinc`, category-1 `pop`/`dup`/`swap`, bounded object and one-dimensional array allocation, typed primitive/reference array loads and stores, `arraylength`, common scalar arithmetic, numeric conversions, conditional primitive/reference comparisons including `if_acmpeq`/`if_acmpne` and `ifnull`/`ifnonnull`, `goto`/`goto_w`, `athrow`, and typed/void returns. `athrow` consumes one typed reference, rejects a known uninitialized verifier value or residual operand-stack values, and must terminate its basic block; validated exception-table handler dispatch remains attached to its exceptional CFG edges. Integer `idiv`, `ldiv`, `irem`, and `lrem` use signed typed division/remainder expressions and add a may-trap edge whose exact i32 condition is divisor equal to zero; the JVM's minimum-integer divided by minus-one case wraps and does not trap. If protected by an exception-table range, these opcodes also retain their ordinary handler dispatch edge. Array operations validate stack operand types and preserve array/index/value ordering as JVM intrinsics with conservative heap read/write effects; loads and `arraylength` return opaque values of the bytecode's JVM stack type. `newarray` validates primitive type codes, while `anewarray` resolves its element class name from the constant pool. When classfile metadata is supplied, field access and `invokevirtual`, `invokespecial`, `invokestatic`, and `invokeinterface` decode their validated constant-pool descriptors to consume correctly typed stack values. Field operations remain typed and symbolic with unknown memory effects because resolution and static initialization can run code; method operations retain the symbolic owner/name/descriptor, ordered operands, unknown memory effects, and a typed opaque result when non-void. They do not claim virtual dispatch resolution or execute class code. Reference local values use an opaque 32-bit pointer type. Reference comparisons consume typed references, reject known uninitialized verifier values, and retain both validated CFG branch outcomes. The CLI, desktop pseudocode, and project automation paths pass loaded JVM metadata to the lifter.

The lifter transports nonempty operand stacks through versioned definitions and phis. Primitive joins/backedges require exact stack heights and value categories. Reference-bearing joins/backedges additionally require an explicit matching StackMapTable frame and exact incoming reference/local identities, including distinct uninitialized allocation offsets; missing or incomplete evidence fails closed. See [JVM stack transport](../libs/decompiler/docs/jvm-stack-transport.md) for the supported proof and remaining verifier limitations. Category-checked `pop2`, `dup*`, `dup2*`, and `swap` preserve logical category-2 values. The lifter lowers `tableswitch` and `lookupswitch` into switch dispatches after checking decoded CFG targets; exception edges retain ordered handler-dispatch metadata. Analysis and lifting conservatively classify `ldc`, `ldc_w`, and `ldc2_w` as throw-capable because reference and dynamic constants can trigger resolution or bootstrap behavior, and unknown constant kinds must retain exceptional coverage. A method whose exception-table scan exceeds the bounded CFG handler budget carries an explicit unsupported stop and is rejected by the JVM lifter; its partial handler edges are never presented as complete decompilation. Unsupported `ldc` kinds, legacy `jsr`/`ret` and unknown effects remain unsupported. `invokedynamic` call sites and dynamic constants retain their names, descriptors, bootstrap indices and constant-pool identity, but bootstrap behavior is not resolved or executed.

For `StringConcatFactory.makeConcatWithConstants`, when the bootstrap handle and recipe are validated and recipe marker counts match the call-site descriptor and static-argument list, pseudocode also records the escaped recipe and primitive/String bootstrap constants in order. Marker counts are computed from the original recipe's U+0001/U+0002 control bytes before display escaping, so literal text such as `\x01` cannot impersonate a dynamic-argument marker. String quotes are escaped explicitly; integer and long constants use `int32_raw` and `long64_raw`, while float and double constants use `float32_bits` and `double64_bits`, preserving all 32 or 64 bits so NaNs and signed zeros remain unambiguous. This is provenance for the concat recipe; it does not execute bootstrap code or claim full JVM string-conversion semantics. Unsupported bootstrap constant kinds leave the call as a generic `invokedynamic` operation.

Constructor reference tracking initializes aliases of a verifier-proven `new` object after its exact-class `<init>` call. In a method named `<init>`, it also initializes aliases of `uninitializedThis` after a void `invokespecial <init>` to the current class or its direct superclass. The resulting normal-path identity is the current class; a failed constructor call clears its uninitialized receiver aliases in exceptional locals. Exception dispatch retains every protected throwing instruction in the source block, preserves distinct ordered catch clauses to one handler, and formats each handler edge with its throwing sites. A handler's caught-object identity is retained when all clauses agree exactly or when the optional `JvmMetadata::known_hierarchy` graph proves a unique common ancestor. Reference stack/local frame constraints accept a narrower incoming class only when that graph proves assignability. Graph nodes and edges include defining-loader identity; duplicate identities, cycles, missing external nodes, incomplete edge lists, and ambiguous joins fail closed. The single-class loader leaves defining-loader identity unset and does not resolve external classes, so hierarchy-based joins require a caller-populated project/classpath graph. Each exceptional edge contributes only its throwing instruction's local reference snapshot to the handler entry. Handler stacks contain exactly the caught reference; source operand stacks are discarded. StackMapTable frames constrain these facts without creating missing identities.

Memory SSA uses the instruction's input version for array loads/stores, `arraylength`, `athrow`, primitive `ldc` forms, and integer division/remainder, whose exceptional exits do not publish a successful write. Other supported throw-capable operations use an unknown memory effect, including resolution, allocation, invocation, type checks, monitor operations, and fields; the handler receives that unknown version rather than a claimed precise pre-throw or successful post-write state. A handler gets an explicit memory phi even for one exceptional predecessor. Independent memory partitions are disabled for functions with these edges until their renamer can select instruction-specific inputs. Exception edges still remain explicit metadata, and structured output falls back rather than claiming reconstructed try/catch source.

The CLI `--format jvm` and automatic classfile detection are wired through durable project loading. `CAFEBABE` also identifies Mach-O FAT32; detection chooses JVM only when the big-endian major-version field is 45–70, otherwise it remains a Mach-O candidate.

The lifter's supported object and constant operations are detailed in [JVM object and constant operations](jvm-object-and-constant-operations.md).

