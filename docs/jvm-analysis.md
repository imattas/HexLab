# JVM classfile analysis

Generic `Signature` attributes now also retain bounded class/method/field syntax
trees for class, member and Record-component owners, with formal bounds,
arguments/wildcards, nested class segments and exact constant-pool text source
ranges. Invalid or over-budget generic grammar remains raw with diagnostics;
it does not prevent class loading. See [generic signatures](jvm-generic-signatures.md)
for the API, grammar subset, budgets and bounded CLI structural output.

Record components now retain both declaration and type annotations, complete
source extents and validated names/descriptors for finalized version-60+
Record attributes. See [Record component metadata](jvm-record-components.md)
for version rules, shared bounds, CLI output and limitations.

The built-in JVM loader reads one bounded classfile (not a JAR). It retains the constant pool, class/super/interface names, fields, methods, and each method's `Code` bounds, max-stack/max-locals values, and exception table. Every nonempty `Code` array maps into its own 32-bit, byte-addressed address space so branch offsets are method-relative.

`Code` metadata also retains bounded, expanded verifier frames from `StackMapTable` and pre-version-50 `StackMap`, including object constant-pool identities and uninitialized-object offsets. See [JVM stack-map metadata](jvm-stack-map-tables.md) for the public model, instruction-boundary checks, resource bounds, and distinction between parsed frames and full verification.

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
attributes are accepted only on methods in annotation interfaces; the method
must have no parameters, return an annotation element type, and the encoded
default kind must match its return descriptor. Duplicate occurrences are
rejected, and payloads must be consumed exactly within the declared attribute
extent. Scalar primitive, String, Class, enum, nested-annotation, and array
category matches are checked. CLI summaries show declaration and parameter annotation
visibility, owner, descriptor, and element count, and print annotation default
values. Runtime-visible and runtime-invisible type annotations are retained on
classes, fields, methods, and Code attributes. Their target_info bytes are
preserved in class-file order, type paths are decoded and validated, and Code
targets are checked against code length, local slots, and exception-table size.
The CLI shows visibility, owner, target type, path length, descriptor, and
element count. Type annotations nested in record-component attribute lists are
retained. The parser accepts the field-type target (target_type 0x13), validates each nested extent and duplicate visibility attribute, and preserves the type path and annotation payload. These remain descriptive metadata and do not synthesize record accessors.

For class-file version 52 and later, method `MethodParameters` attributes retain
each parameter's optional UTF-8 name index and access flags in descriptor
order. The parser enforces method ownership, one occurrence, exact attribute
length, descriptor parameter count, valid UTF-8 indexes, and only `final`,
`synthetic`, and `mandated` flags. A zero name index is retained as an unnamed
parameter. CLI summaries list parameter names (or `<unnamed>`) and flags.

Class, field, and method `Synthetic` and `Deprecated` attributes are retained
as explicit owner metadata. Both attributes must have zero-length payloads,
may appear only in class/member attribute lists, and reject duplicates on the
same owner. `Synthetic` is recorded separately from the access-flags word so
older classfiles using the attribute remain distinguishable; `Deprecated` has
no access-flag equivalent.

Static-field `ConstantValue` attributes are retained after strict field-owner,
uniqueness, payload-length, constant-pool-tag, and descriptor checks. Numeric
values preserve their raw constant-pool bits; string values expose the resolved
modified-UTF-8 text. CLI field summaries show the value, with numeric values in
hexadecimal to preserve NaN payloads and signed zero. The metadata remains
partial only for other unsupported attributes.

Source and Code debug metadata includes the class-level `SourceFile` and
`SourceDebugExtension`, plus each method's optional `LineNumberTable`,
`LocalVariableTable`, and `LocalVariableTypeTable`. `SourceDebugExtension`
retains its bounded raw UTF-8 payload (commonly a [JSR-45 SMAP](https://jcp.org/en/jsr/detail?id=45)
source map), rejecting malformed UTF-8, duplicate attributes, and member/Code
placement. Resolved SMAP strata are additionally decoded into generated-file,
default-stratum, source-file/path, and compact line-rule records. The loader
checks unique file IDs, line references, repeat counts, 32-bit line-range
arithmetic, and caps the interpretation at 64 strata, 8,192 files, one million
rules, and 16 MiB of copied names and paths. The CLI shows up to 256 file and
rule rows. Embedded maps are preserved in the raw attribute with an explicit
interpretation diagnostic; unknown future sections are skipped. The source
map records do not synthesize per-line rows or claim source-file access. The
CLI also prints a safe, bounded raw preview and the full payload size. The loader
retains line start offsets and source
line numbers, and local names, descriptors or generic signatures, slots, and
live ranges. Generic local signatures are retained as text without parsing
their grammar. Tables preserve absence versus an
explicitly empty table, aggregate legal repeated attributes, and require exact
payload lengths. Aggregate rows are capped at 65,535 per table kind and Code
attribute; duplicate local-variable entries are rejected across all tables
for that Code attribute. Line/local offsets and local slots are checked against the owning Code array
and `max_locals` (including the second slot of long/double locals). These
checks bound the referenced bytecode region, but do not prove that an offset
lands on an instruction boundary. The `Code` exception table is checked
separately: each protected-range start and handler must be an instruction
start, and each protected-range end must be an instruction start or exactly
`code_length`. This rejects ranges that split an encoded instruction while
preserving legal half-open ranges ending at the bytecode array boundary.

The JDK-specific class-level `CompilationID` and `SourceID` attributes are
retained as provenance values. Each may occur once and must contain exactly
one valid `CONSTANT_Utf8` index; member and Code placement is rejected. The
model keeps the original pool index and the file offset of its two-byte
reference, and the CLI prints a bounded escaped preview and full byte length.
Values are preserved as supplied: the loader does not infer timestamps,
resolve the source file, or treat these identifiers as class identity. See
[JVM build provenance](jvm-build-provenance.md).

Class, field, and method metadata also retain their optional generic `Signature` string. The loader checks the exact two-byte payload, resolves its index as `CONSTANT_Utf8`, rejects duplicate signatures and signatures in Code attribute lists, and preserves absence separately from an empty signature. It preserves the signature text and attaches bounded generic-grammar analysis; invalid or over-budget grammar receives an explicit diagnostic without preventing class loading. Class metadata also retains `Record` component names and descriptors (including a component's optional generic `Signature`), `NestHost`/`NestMembers`, and `PermittedSubclasses`. Nest and permitted-class entries preserve the exact constant-pool index and its class-file byte offset for provenance. Nest attributes require class-file version 55+, and `PermittedSubclasses` requires version 61+ or a supported Java 15/16 preview version. These attributes validate their declared extents and every referenced constant-pool entry. Each supported class attribute may appear at most once; list counts are bounded at 8192. Unknown nested Record component attributes are extent-checked and mark metadata incomplete. `link_jvm_metadata_workspace` cross-checks supplied permitted subclasses against direct superclass/interface metadata; `link_jvm_path_workspace` also checks supplied nest membership and package consistency. Neither pass searches for absent classes or establishes defining-loader identity. The loader does not synthesize Java record methods.
The class-level Valhalla preview `Preload` attribute is decoded only for classfile
version 67.65535. Its count and exact payload length are checked, up to 8192
class indexes are accepted, and each must resolve to `CONSTANT_Class`. The CLI
prints the class names with their constant-pool indexes and byte offsets. These
are advisory symbolic references: the loader does not load or link the named
classes. Other versions and attribute placements are rejected. See the
[Valhalla value-objects classfile draft](https://cr.openjdk.org/~dlsmith/jep401/jep401-20240222/specs/value-objects-jvms.html#jvms-4.7.32)
for the preview layout.
The loader also retains the class-level `InnerClasses` table in its declared order. Each entry resolves the required inner `CONSTANT_Class`, optional outer class and optional inner simple-name `CONSTANT_Utf8`; entries have unique inner-class indexes, only defined access bits, an exact `2 + 8 * number_of_classes` payload, and a limit of 8192 entries. Duplicate attributes and uses outside class attributes are rejected. For classfile version 51 and later, an entry without an inner name cannot specify an outer class. The CLI prints each retained inner/outer/name tuple and access flags. This is descriptive metadata and does not link referenced classes or infer lexical relationships beyond the table.

The class-level `EnclosingMethod` attribute is also retained for local and anonymous classes. Its four-byte payload must identify a valid enclosing class and either no method or a valid `CONSTANT_NameAndType` method name and descriptor; the attribute is limited to one occurrence and classfile version 49 or newer. The CLI prints the enclosing class and optional method descriptor. These names describe lexical ownership only and do not resolve the enclosing class or prove that the referenced method exists.

The CLI's class summary prints these retained attributes and record component signatures.

Attributes without a dedicated decoder are retained as opaque, file-backed
payload extents on their class, field, method, `Code`, or Record-component
owner. Each row includes the attribute name, absolute payload file offset, and
declared byte length; consumers can read the original bytes from the image
without copying them into the metadata model. Attribute payloads are still
bounded by their enclosing classfile and the loader's aggregate attribute-byte
limit, and the inventory itself is capped at 65,536 rows and 4 MiB of names.
The CLI lists up to 128 such rows and reports any omitted count. Opaque rows
are not semantic decoding: unknown attributes continue to make metadata
incomplete, so consumers must not infer that the loader understands them.

For Java 9+ `module-info` classes, the loader retains the `Module`, `ModulePackages`, `ModuleMainClass`, `ModuleTarget`, and `ModuleResolution` attributes. The module record includes its name, flags and optional version; required modules and versions; exported/opened packages and qualified target modules; service uses and provider implementations; the declared package list; and optional main class. `ModuleTarget` retains the optional platform name (a zero index means unspecified), while `ModuleResolution` retains its validated resolution flag bits. Both companion attributes require exactly two payload bytes, reject duplicates, require class-file version 53 or newer, and are restricted to `ACC_MODULE` `module-info` classes with a `Module` attribute; resolution flags outside the defined low four bits are rejected. Every entry is checked against the required `CONSTANT_Module`, `CONSTANT_Package`, `CONSTANT_Class`, or `CONSTANT_Utf8` pool tag, flags are checked against the classfile masks, and the attribute extents must match exactly. Each module list is bounded, with no more than 8192 total entries in a `Module` attribute; module-package lists are capped at 8192. The loader itself retains descriptive metadata; it does not implicitly resolve required modules or check package ownership across a module path.

CLI class inspection prints the module name, flags, version, counts, and bounded detail rows for requires, exports, opens, uses, and provides, along with non-empty `ModulePackages` and `ModuleMainClass` metadata. At most 128 module detail rows and 128 declared packages are printed; qualified target-module and provider lists show at most eight names per row and report their omitted count. Additional omitted module rows are counted. This is descriptive output and does not resolve modules or verify class ownership.

Callers with an explicit set of module descriptors can use `link_jvm_modules` to build a bounded descriptor graph. It records unique, missing, optional-missing (`requires static`), and duplicate-definition targets for `requires` entries and qualified `exports`/`opens`, and reports detected `requires` cycles. Default limits are 4096 module definitions, 65,536 edges, 4096 cycle reports, 65,536 total cycle members, 4 MiB of cycle-name bytes, and 4 MiB of copied module/target names. Duplicate definitions remain ambiguous instead of selecting a winner.

`link_jvm_workspace` adds caller-supplied `(module name, internal class name)` facts. It records each class-to-module assignment as resolved, missing, or ambiguous due to duplicate module definitions; reports package ownership and split packages across uniquely defined modules; and resolves module `uses`, `provides`, and provider implementation class names as missing, unique, or duplicate class definitions. The module graph also emits descriptor-derived readability: direct `requires` targets plus closure through `requires transitive` edges, with direct and transitive rows distinguished. Missing or duplicate definitions do not create readability edges, and a module's implicit self-readability is omitted. The closure is bounded by edge and work limits and observes cancellation. These APIs perform exact-name lookup only over supplied descriptors and class facts; they do not construct a runtime configuration, apply resolution roots or service binding, enforce exports/access rules, or prove that service/provider classes are assignable or instantiable. Both graph APIs are bounded and cancellation-aware.

`link_jvm_metadata_workspace` extracts `JvmModule` descriptors and `ModulePackages` package rows from loaded `JvmMetadata`, then infers class ownership only when exactly one uniquely named module declares the class's package. Classes whose package is absent from `ModulePackages` remain `unresolved_ownership`; packages declared by multiple modules remain `ambiguous_ownership`. Callers can use this with an explicitly assembled class/module inventory without copying descriptor fields by hand. The helper still needs callers to supply the metadata set; it does not read archives or search module paths.

`ModuleHashes` is also retained for Java 9+ `module-info` classes. The loader validates its UTF-8 algorithm reference and `CONSTANT_Module` indexes, rejects duplicate module entries, enforces exact attribute bounds and a 65535-byte aggregate hash retention limit, and requires a companion `Module` attribute. CLI inspection shows the algorithm, module names, hash lengths, and at most the first 16 bytes of each hash. Hash verification and module-path checks are not performed.

Method-level `Exceptions` attributes are retained as an optional ordered list of declared exception class names (an explicitly empty attribute is distinct from an absent one). The parser requires the attribute payload to be exactly `2 + 2 * number_of_exceptions` bytes and validates every index as a `CONSTANT_Class` with a valid UTF-8 name. Duplicate attributes and uses outside method attributes are rejected by the attribute-context checks. Up to the classfile's `u2` count (65,535) is representable, subject to the 64 MiB per-attribute and 256 MiB aggregate attribute limits. The CLI prints retained declarations after the method descriptor. This is declaration metadata only; it does not establish that bytecode throws only those types or resolve external class hierarchies.

The parser accepts classfile major versions 45 through 70, a 512 MiB input, at most 8192 fields/methods and attributes per owner, 8192 exception handlers per Code attribute, 64 MiB per attribute, and 256 MiB total attribute payloads. It parses standard constant-pool tags 1, 3–12, 15–20, including two-slot long/double entries. Unknown constant-pool tags, malformed indices, invalid modified UTF-8, out-of-range code/handler extents, and oversized metadata fail closed. Unknown attributes are skipped within their validated extent and mark metadata partial.

Every field and method declaration validates its unqualified name and descriptor, even when no parsed attribute would otherwise consume the descriptor. Field descriptors must describe exactly one non-void field type. Method descriptors must parse completely, stay within the JVMS 255 parameter-slot limit (including the receiver for instance methods), and have a valid return type. Constructors must return void; class initializers must be static with descriptor `()V`; other method names cannot contain angle brackets. Duplicate declarations with the same name and descriptor are rejected within their field or method table. This validates local classfile shape only and does not enforce cross-member language rules such as override compatibility or class hierarchy constraints.

For successfully parsed generic signatures, the loader checks erasure against the class header, field and Record component descriptors, method descriptors, and matching local-variable descriptors. Method and class formal type variables erase through their leftmost class or interface bound, defaulting to `java/lang/Object`; raw nested class segments erase to `$` binary names. Class signatures must also have the same superclass and superinterface counts as the class header. Erasure checks that depend on an unresolved cyclic formal bound are skipped; the loader does not compare generic signatures to every Java source-level type rule.

Constant-pool `Fieldref`, `Methodref`, `InterfaceMethodref`, `Dynamic`, and `InvokeDynamic` entries also validate their referenced name and descriptor regardless of whether the bytecode uses them. Method references reject `<clinit>`, allow `<init>` only for `Methodref`, and require constructor descriptors to return void. Field and dynamic-constant descriptors must be valid field types; method and invokedynamic descriptors must parse as complete method descriptors. This is syntax and entry-kind validation; it does not resolve referenced classes or prove that referenced members exist.

Class declarations reject reserved access-flag bits and incompatible combinations: final plus abstract, interfaces lacking `abstract` or marked `final`, annotations not marked as interfaces, and `ACC_MODULE` combined with any other class access flag. Module-info shape and required module attributes are checked separately. These checks validate class-header flags only; they do not establish whether a class is instantiable or linked correctly.

Field and method declaration flags reject reserved bits, conflicting visibility, and the incompatible final/volatile and abstract-method combinations. Interface fields must be public, static, and final. Methods marked abstract or native must omit `Code`; every other method must have exactly one `Code` attribute. This checks the declaration-level attribute contract without performing full version-specific access checks for every interface method form.

The decoder covers standard JVM opcodes through `jsr_w`, including `wide`, `tableswitch`, and `lookupswitch`. Switch tables may use the full bounded JVM `Code` extent (65,535 bytes per instruction encoding), rather than a smaller arbitrary case cap. Function recovery re-reads the complete encoded extent when its initial decode window ends inside a valid switch, using overflow-safe counts bounded by the same classfile limit. Processor capability metadata reports this 65,535-byte maximum, matching the decoder's extended-byte representation. The byte extent therefore bounds dense tables to roughly 16K entries and lookup tables to roughly 8K pairs. Full encoded lengths and bytes are retained through function IDs, derived caches, incremental validation, graph fingerprints, and CLI byte display. Switch parsing validates alignment padding, table bounds, sorted lookup keys, and that targets lie outside the switch encoding. Constant-pool-index instructions reject index zero; `invokeinterface` also requires a nonzero argument-word count and zero reserved byte, `invokedynamic` requires both reserved bytes to be zero, and `multianewarray` requires a nonzero dimension count. A `wide` local index that cannot fit any legal 16-bit `Code.max_locals` extent is rejected, including category-2 accesses starting at index 65534; per-method local bounds still require classfile context. When loading a classfile, every method `Code` array is scanned with this decoder: branch and switch destinations must land on decoded instruction starts in that same method, `ldc`/`ldc_w`/`ldc2_w` operands must name loadable constant-pool kinds with the required category (including the descriptor category of `CONSTANT_Dynamic`), field opcodes must name `CONSTANT_Fieldref` entries, and invoke opcodes must name the required method-reference kinds. `jsr`, `ret`, `jsr_w`, and `wide ret` are rejected from classfile version 51 onward. The standalone decoder has no class-version input and therefore still decodes those legacy opcodes; version enforcement belongs to the classfile loader. Reserved/implementation-dependent bytecodes and malformed or overflowing branch targets are unsupported/invalid. Method code is ordinary classfile bytecode and is never executed.

Classfile-aware bytecode scanning also checks invocation operands against the
constant pool: `invokevirtual`, `invokespecial`, `invokestatic`,
`invokeinterface`, and `invokedynamic` must reference the corresponding method
reference kind (with interface method references for `invokespecial` and
`invokestatic` accepted starting in classfile version 52). Each used descriptor
is checked against the 255 parameter-slot limit, including a receiver for
instance calls and excluding it for static or dynamic calls. For
`invokeinterface`, the encoded count must equal the receiver slot plus the
descriptor's parameter slots, counting `long` and `double` as two. The
standalone decoder can validate the nonzero index/count and reserved byte, but
cannot perform these checks without classfile constant-pool context.

The `bipush` and `sipush` lifter reads signed 8-bit and 16-bit immediate metadata and sign-extends each value into the JVM int stack type; it fails closed if the decoder metadata has an unexpected width or signedness. The typed common-IR lifter supports null and integer/long/float/double constants, class constants, and `CONSTANT_MethodType`/`CONSTANT_MethodHandle` loads as opaque typed references with validated descriptors/targets retained in deterministic intrinsic metadata, primitive and reference local loads/stores across the method `Code.max_locals` range, including `wide` indices through 65534 (category-2 values still require two in-range slots), `iinc`, category-1 `pop`/`dup`/`swap`, bounded object and one-dimensional array allocation, typed primitive/reference array loads and stores, `arraylength`, common scalar arithmetic, numeric conversions, conditional primitive/reference comparisons including `if_acmpeq`/`if_acmpne` and `ifnull`/`ifnonnull`, `goto`/`goto_w`, `athrow`, and typed/void returns. `athrow` consumes one typed reference, rejects a known uninitialized verifier value or residual operand-stack values, and must terminate its basic block; validated exception-table handler dispatch remains attached to its exceptional CFG edges. Integer `idiv`, `ldiv`, `irem`, and `lrem` use signed typed division/remainder expressions and add a may-trap edge whose exact i32 condition is divisor equal to zero; the JVM's minimum-integer divided by minus-one case wraps and does not trap. If protected by an exception-table range, these opcodes also retain their ordinary handler dispatch edge. Array operations validate stack operand types and preserve array/index/value ordering as JVM intrinsics with conservative heap read/write effects; loads and `arraylength` return opaque values of the bytecode's JVM stack type. `newarray` validates primitive type codes, while `anewarray` resolves its element class name from the constant pool. When classfile metadata is supplied, field access and `invokevirtual`, `invokespecial`, `invokestatic`, and `invokeinterface` decode their validated constant-pool descriptors to consume correctly typed stack values. Field operations remain typed and symbolic with unknown memory effects because resolution and static initialization can run code; method operations retain the symbolic owner/name/descriptor, ordered operands, unknown memory effects, and a typed opaque result when non-void. They do not claim virtual dispatch resolution or execute class code. Reference local values use an opaque 32-bit pointer type. Reference comparisons consume typed references, reject known uninitialized verifier values, and retain both validated CFG branch outcomes. The CLI, desktop pseudocode, and project automation paths pass loaded JVM metadata to the lifter. The common IR now carries 16-bit register indices, allowing lifted `wide` local accesses to retain their actual slot identity; reference-flow tracking is sized from `Code.max_locals` rather than capped at 256 locals. When code metadata is unavailable, the lifter only has the ordinary 256-slot fallback and rejects indexes outside that range. Pseudocode names these registers `jvm_local_<index>`, preserving high slots in CLI and desktop output.

The lifter transports nonempty operand stacks through versioned definitions and phis. Primitive joins/backedges require exact stack heights and value categories. Reference-bearing joins/backedges additionally require an explicit matching StackMapTable frame and exact incoming reference/local identities, including distinct uninitialized allocation offsets; missing or incomplete evidence fails closed. See [JVM stack transport](../libs/decompiler/docs/jvm-stack-transport.md) for the supported proof and remaining verifier limitations. Category-checked `pop2`, `dup*`, `dup2*`, and `swap` preserve logical category-2 values. The lifter lowers `tableswitch` and `lookupswitch` into switch dispatches after checking decoded CFG targets; exception edges retain ordered handler-dispatch metadata. Analysis and lifting conservatively classify `ldc`, `ldc_w`, and `ldc2_w` as throw-capable because reference and dynamic constants can trigger resolution or bootstrap behavior, and unknown constant kinds must retain exceptional coverage. A method whose exception-table scan exceeds the bounded CFG handler budget carries an explicit unsupported stop and is rejected by the JVM lifter; its partial handler edges are never presented as complete decompilation. Unsupported `ldc` kinds, legacy `jsr`/`ret` and unknown effects remain unsupported. Method-type and method-handle constants preserve their classfile identity and are not resolved or executed. `invokedynamic` call sites and dynamic constants retain their names, descriptors, bootstrap indices and constant-pool identity, but bootstrap behavior is not resolved or executed.

`lcmp`, `fcmpl`, `fcmpg`, `dcmpl`, and `dcmpg` lift as explicit typed three-way operations. Floating variants preserve their opcode-specific NaN result; see [JVM scalar compare instructions](jvm-scalar-comparisons.md).

For `ifnull` and `ifnonnull`, an exact null constant or verifier null identity
produces a constant branch predicate. Other reference operands keep a symbolic
comparison, since an ordinary object verifier type does not prove non-nullness.
`if_acmpeq` and `if_acmpne` similarly fold only when both operands are the
same versioned SSA register value or both are proven null; class-type identity
alone does not imply object identity.

For the exact `StringConcatFactory.makeConcat` bootstrap, pseudocode records the validated factory name and dynamic argument count when the static bootstrap argument list is empty. For `StringConcatFactory.makeConcatWithConstants`, when the bootstrap handle, exact factory descriptor, and recipe are validated and recipe marker counts match the call-site descriptor and static-argument list, pseudocode also records the escaped recipe and primitive/String bootstrap constants in order. Marker counts are computed from the original recipe's U+0001/U+0002 control bytes before display escaping, so literal text such as `\x01` cannot impersonate a dynamic-argument marker. String quotes are escaped explicitly; integer and long constants use `int32_raw` and `long64_raw`, while float and double constants use `float32_bits` and `double64_bits`, preserving all 32 or 64 bits so NaNs and signed zeros remain unambiguous. This is provenance for the concat recipe; it does not execute bootstrap code or claim full JVM string-conversion semantics. Unsupported bootstrap constant kinds leave the call as a generic `invokedynamic` operation.

The exact static `LambdaMetafactory.metafactory` form is recognized only when its bootstrap handle and signature match and its three static arguments are valid method-type, implementation-handle, and instantiated-method-type constants. Pseudocode records those validated symbolic identities with `linkage=unresolved`; it still emits an opaque `invokedynamic` operation because target-interface binding, adaptation checks, access/linkage, and lambda-body execution require runtime class resolution. `altMetafactory`, malformed or unsupported handle forms, and other bootstraps remain generic symbolic calls.

The exact static `LambdaMetafactory.altMetafactory` bootstrap is also summarized when its handle kind, owner, name and descriptor match. Its SAM and instantiated method types, implementation handle, serializable flag, marker interfaces, and bridge method types are checked against constant-pool tags and bounded counts (64 entries per optional list); flags outside the three specified bits, malformed counts, and trailing or missing static arguments leave the operation opaque. The summary is symbolic metadata only: captured arguments remain the ordinary `invokedynamic` operands, and marker-interface resolution, adaptation, runtime linkage, serialization behavior, bridge execution, and lambda-body recovery are not claimed.

Constructor reference tracking initializes aliases of a verifier-proven `new` object after its exact-class `<init>` call. In a method named `<init>`, it also initializes aliases of `uninitializedThis` after a void `invokespecial <init>` to the current class or its direct superclass. The resulting normal-path identity is the current class; a failed constructor call clears its uninitialized receiver aliases in exceptional locals. Exception dispatch retains every protected throwing instruction in the source block, preserves distinct ordered catch clauses to one handler, and formats each handler edge with its throwing sites. A handler's caught-object identity is retained when all clauses agree exactly or when the optional `JvmMetadata::known_hierarchy` graph proves a unique common ancestor. Reference stack/local frame constraints accept a narrower incoming class only when that graph proves assignability. Graph nodes and edges include defining-loader identity; duplicate identities, cycles, missing external nodes, incomplete edge lists, and ambiguous joins fail closed. The single-class loader leaves defining-loader identity unset and does not resolve external classes, so hierarchy-based joins require a caller-populated project/classpath graph. Each exceptional edge contributes only its throwing instruction's local reference snapshot to the handler entry. Handler stacks contain exactly the caught reference; source operand stacks are discarded. StackMapTable frames constrain these facts without creating missing identities.

Memory SSA uses the instruction's input version for array loads/stores, `arraylength`, `athrow`, primitive `ldc` forms, and integer division/remainder, whose exceptional exits do not publish a successful write. Other supported throw-capable operations use an unknown memory effect, including resolution, allocation, invocation, type checks, monitor operations, and fields; the handler receives that unknown version rather than a claimed precise pre-throw or successful post-write state. A handler gets an explicit memory phi even for one exceptional predecessor. Independent memory partitions are disabled for functions with these edges until their renamer can select instruction-specific inputs. Exception edges still remain explicit metadata, and structured output falls back rather than claiming reconstructed try/catch source.

Array loads and stores record null and signed index-range predicates for `NullPointerException` and `ArrayIndexOutOfBoundsException`. `aastore` also retains a typed symbolic component-type mismatch predicate. `arraylength` continues to record its exact null predicate. `newarray`/`anewarray` and every requested `multianewarray` dimension expose negative-size predicates. `checkcast` records a symbolic type mismatch, monitor operations record null checks and `monitorexit` also records symbolic ownership failure, and `athrow` exposes null-to-NPE and exception propagation. Symbolic predicates remain opaque where runtime class or monitor state is unavailable; these checks accompany the existing conservative memory and handler behavior.

The CLI `--format jvm` and automatic classfile detection are wired through durable project loading. `CAFEBABE` also identifies Mach-O FAT32; detection chooses JVM only when the big-endian major-version field is 45–70, otherwise it remains a Mach-O candidate.

The lifter's supported object and constant operations are detailed in [JVM object and constant operations](jvm-object-and-constant-operations.md).



Method `Code` attributes may also contain the optional `CharacterRangeTable`
compiler-debug attribute. Each entry retains its half-open bytecode interval,
half-open source character interval, and raw flags. The parser checks the
declared table extent, requires each range's start not to exceed its end, bounds
bytecode offsets to the owning Code array, and caps aggregate entries at 65,535
per method. Flag interpretation and source-file resolution are left to
consumers; this table does not establish instruction boundaries or recover
source text.
