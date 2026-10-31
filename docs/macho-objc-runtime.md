# Mach-O Objective-C class metadata

The Mach-O inspection CLI reports a bounded Objective-C class-list view for
little-endian 32-bit ObjC2 and 64-bit images. It scans regular, file-backed `__objc_classlist`
and `__objc_nlclslist` sections and retains each class-list section ordinal,
slot address, and index. These lists may refer to the same class object; rows are
deduplicated by the resolved class address while preserving every list origin.
The non-lazy list therefore adds provenance and covers classes represented only
there without creating duplicate class records.

Pointer fields are resolved with the existing Mach-O relocation and dyld
resolver. A resolved rebase or relocation is preferred. Raw slot bytes are
used only when no relocation or dyld record claims the field, and only when
they point into a mapped image segment. Runtime binds, authenticated pointers,
ambiguous fixups, and unsupported encodings remain explicitly unresolved.

For a validated class object, the scanner reads pointer-width-specific `class_t` data,
superclass, and `isa` fields, masks low fast-data flag bits before following
the data pointers, then reads the fixed 40-byte (32-bit) or 72-byte (64-bit)
`class_ro_t` prefix. It reports
the bounded class name, flags, instance start and size, and superclass index
and name only when the superclass address maps to a scanned class-list entry.
The strong and weak `class_ro_t` ivar-layout pointers are also resolved with
the same fixup policy. Their NUL-terminated encoded bytes are retained up to a
separate 4,096-byte limit for classes and directly referenced metaclasses;
the bytes are shown as hex and are not interpreted as instance-layout runs.
Null pointers remain absent, while unresolved pointers and unterminated or
over-limit byte strings mark the row and scan partial.
The directly referenced metaclass is decoded as a class object; its `class_ro_t`
name and class-method list are reported with separate pointer statuses. Names
must terminate within initialized mapped bytes and the configured name limit.
The CLI and desktop view also name recognized compiler-emitted
`class_ro_t.flags` bits (`metaclass`, `root-class`, C++ structors, hidden,
Objective-C exception, Swift initializer, ARC, and associated-object/weak-layout
attributes). The raw word remains available; unknown bits are not assigned a
meaning, and runtime `class_rw_t` state flags are not decoded as `class_ro_t`
flags.

Class and category list headers are accepted only when their full extents fit
inside initialized readable bytes. Their entries are decoded within the same
metadata byte and entry-count budgets:

- Big and relative method lists report selector, type encoding, and IMP fields.
  Both 32-bit and 64-bit ObjC2 images accept the bounded 12-byte small-method
  entry format with signed 32-bit offsets based at each name, type, and IMP
  field. Relative selector references are followed through their selector-reference
  slots unless the direct-selector flag is set. IMPs are retained only when
  they map to file-backed executable image bytes outside code exclusions.
  ARM32 IMPs preserve the encoded Thumb tag and mode separately from the
  canonical validated implementation address.
  The scanner attaches a detached parsed function signature when the complete
  method type encoding is recognized. This applies to class, metaclass,
  category, and protocol method lists. The raw encoding remains alongside it;
  an unsupported or malformed encoding has a signature status and no inferred
  type. Positional names (`arg0`, `arg1`, ...) are used because the runtime
  encoding does not contain source parameter names. The selector and IMP are
  reported separately and are not embedded in the type object.
- Ivar entries report name, type encoding, offset storage/value, size, and
  alignment when available. Properties retain their complete raw attribute
  string and decode its `T` type attribute into a detached type when the full
  encoding is supported. Unknown attributes are preserved; malformed type
  attributes receive a status rather than an inferred type.
- Protocol lists report each protocol reference address and its mangled name
  when the protocol object and name pointer resolve. When a matching
  `__objc_protolist` definition was scanned, each reference also carries its
  protocol-record index.
- `__objc_protolist` definitions decode the stable 32-byte or 64-byte `protocol_t`
  prefix: name, adopted protocols, required and optional instance/class
  method lists, and instance properties. Adoption references link back to
  scanned protocol records by exact metadata address. The runtime `size` field
  bounds optional tail inspection; when it covers `_classProperties`, that
  property list is resolved and decoded with the same extent, pointer, and
  entry validation as protocol instance properties. Records too short to carry
  the field are labeled `not-present-by-runtime-size`; invalid/unreadable sizes
  leave class properties unavailable instead of reading beyond the validated
  protocol object.
- Class conformance evidence follows each directly adopted scanned protocol's
  required instance and class methods through its exact adopted-protocol links.
  Each requirement retains the `__objc_protolist` definition index that
  declared it, so inherited requirements remain attributable. Method evidence
  combines the class's validated methods with methods from its linked scanned
  categories; it does not infer superclass methods or category registrations
  outside the image. Cycles, unresolved adoption links, incomplete protocol
  declarations, inheritance deeper than 32, or exhausted requirement-work
  budgets downgrade the result to partial evidence. Protocol declarations need
  validated selector names; their implementation pointers are not required to
  be non-null. The flattened requirement and emitted-result work are each
  bounded by `max_protocol_requirement_work` (200,000 by default).
- Metaclass `class_ro_t` records retain their raw compiler-emitted flags and
  report the recognized ObjC2 flag names through the same decoder used for
  ordinary classes. Runtime realization/future bits remain unsupported and
  are not reinterpreted as compiler flags.
- `__objc_catlist` and `__objc_nlcatlist` produce category nodes with their
  name, target class link, instance/class methods, protocols, and instance
  properties. The category instance-property list uses the standard sixth
  `category_t` pointer, and is decoded only when its pointer resolves under the
  shared relocation/dyld/raw-pointer policy and its complete list extent and
  entries are mapped and initialized. Each list retains its pointer slot and
  resolution status; each property retains its list address, entry index, and
  entry address along with the property name and complete raw attributes.
  Null property-list pointers remain empty; unresolved/authenticated/runtime-
  bound pointers and malformed or unmapped list tails are reported as
  incomplete and are never interpreted as raw addresses. When a category's
  target address matches a scanned class, category and class records link in
  both directions by exact metadata
  address; unresolved or unscanned targets remain explicit. Category and class
  rows are deduplicated by stable metadata address while preserving every
  section/index/slot origin.
- Newer category records may have a trailing `classProperties` pointer after
  the six standard fields. The scanner probes that seventh slot only when the
  full pointer is backed by initialized bytes, and accepts it only if the
  resolved target has a complete readable property-list header and extent with
  a valid stride. An absent, unresolved, or implausible tail is retained as a
  status but does not make an older six-field category incomplete; malformed
  property entries in a validated list use the ordinary incomplete-record
  handling. Because old and malformed optional tails cannot always be
  distinguished, this is conservative candidate recognition rather than an
  ABI-version determination.
- CLI output lists protocol definitions, their required and optional instance
  and class method signatures, instance properties with parsed type metadata,
  category class properties, and adopted protocol links with exact
  scanned-definition indices when available. The desktop metadata view also
  lists validated category class properties.

Each decoded field carries a status so unresolved, authenticated, runtime-bound,
ambiguous, and unsupported fixups remain distinguishable from null or raw
pointers. A partial field marks its owning class/category/protocol and scan incomplete;
decoded records remain available. The scanner bounds every list extent, string,
pointer slot, and scalar read. Protocol definitions use the same validated direct and relative method-list formats described above. The scanner does not infer category targets from runtime registration or decode optional protocol tail fields.

Default work limits are 100,000 classes, categories, and protocols, 64 MiB of metadata reads and validated list extents, 4,096 bytes per name and ivar-layout encoding, and 1,000,000 entries per list. A limit or unresolved class field
marks the scan partial while preserving the rows already decoded. Cancellation
is honored during scanning. Little-endian arm64_32 uses four-byte Objective-C
metadata pointers in a validated 64-bit address space. Big-endian images,
other ABI64_32 variants, ObjC1 `__OBJC`
records and runtime class data remain unsupported.
See the [32-bit layout and validation contract](../libs/analysis/docs/macho-objc-32bit.md)
for exact supported offsets, pointer checks and remaining runtime forms.
The Objective-C type import plan also persists complete categories whose name
and target link resolve to a scanned class. Parsed instance and class method
signatures are stored together in a separate incomplete aggregate named
`ObjC2.Category.<class>.<category>`. Parsed instance and class property
declarations contribute getter and, unless readonly, setter method signatures
to that category aggregate. Class-property accessors are added to its static
class-method list and use a pointer to the target's `ObjC2.Meta.<class>` type as
their receiver. Custom accessor selectors are retained. These signatures
include a typed `self` pointer, a selector pointer, and the property value for
setters. A category property does not establish object storage: the target
class layout is unchanged, and a `V` backing-ivar annotation is not treated as
proof that the named ivar exists or is safe to add. If an accessor selector is
already present in the category method list, its directly encoded signature
takes precedence over the synthesized property signature. Duplicate
target/category names, partial records, unlinked targets, and categories with
no representable method or property accessor signatures are skipped. The
source origin records the category-list section ordinal, list index, and
category record address, so the imported type can be traced to the metadata
that supplied it.
The same conservative accessor projection applies to validated class property
records: their getter/setter signatures are attached to `ObjC2.Class.<name>`
when that class type is imported, with explicit class method encodings taking
precedence. Property declarations do not rename ivars or establish storage.
Class-property metadata is scanned, displayed, and projected into synthesized
category class accessor methods when its type and attributes are validated.
Those methods describe declarations only; no metaclass layout or runtime
implementation is inferred.

The desktop type import also preserves scanned superclass storage. A derived
class embeds a concrete storage-only superclass aggregate as `__objc_super`
at offset zero, using the exact scanned address link rather than a name-based
project lookup. Each ancestor needs a unique resolved identity, a consistent
instance extent, and fully representable non-overlapping ivars. The base size
must fit before the derived class's `instanceStart`; local ivars cannot precede
that boundary. Remaining bytes stay opaque. An iterative 32-class walk rejects
cycles, unresolved or unscanned bases, deeper chains, and invalid ancestor
layouts with diagnostics. Eligible methods still import into an incomplete
aggregate when storage cannot be proven. The importer does not infer base
alignment, runtime layout sliding, or inherited method overrides. See
[desktop import behavior](desktop-macho-objective-c.md) for persistence details.

Method type parsing is separately bounded to 4,096 input bytes, 32 nested
types, and 256 encoded type nodes by default. It accepts the primitive codes
`v c C s S i I l L q Q B f d`, object (`@`, including quoted class annotations
and block `@?`), class (`#`), selector (`:`), C string (`*`), pointers (`^T`),
fixed arrays (`[nT]`), and named structs/unions (`{Name...}` / `(Name...)`).
The qualifiers `r` and `V` are retained as const and volatile; the direction
qualifiers `n N o O R` are consumed without changing the detached type.
Method frame sizes and per-argument offsets are accepted and discarded. Named
struct/union encodings are recursively validated but represented as incomplete
aggregates because the encoding alone does not provide reliable field layout.
Bitfields, long double, vectors, unknown codes, malformed strings, and any
encoding exceeding a budget remain raw and do not produce a partial signature.

Property records retain their complete raw attribute string and also decode
the standard single-letter flags `R`, `C`, `&`, `W`, `N`, and `D` as read-only,
copy, strong, weak, nonatomic, and dynamic metadata. Explicit `G`/`S` accessor
selectors and `V` backing-ivar names are retained or recognized; unrecognized
attributes remain available in the raw string and produce a
`parsed-with-unknown-attributes` status. Duplicate flags/accessors, empty
custom selectors, and conflicting ownership flags are reported as malformed.
The scanner derives the standard default getter and setter selector names for
ASCII property identifiers when attributes parse successfully, then links each
selector only to a unique method in the property's own scanned class or
category method list after checking its parsed signature. A getter must have
exactly the two encoded implicit parameters (`self` and `_cmd`) and return the
property's canonical parsed type. A setter must return `void`, have those two
implicit parameters plus one value parameter, and use the property's canonical
parsed type for that value. The comparison preserves qualifiers and named
reference identity; it does not attempt covariance, ABI coercion, or
compatibility between distinct object annotations. If the property or method
type is unavailable, or the signature shape/type disagrees, the method address
is withheld and the link status reports the reason. Selector comparisons are
capped at 200,000 per property list against its corresponding method list;
exhausting this budget marks the scan incomplete and labels remaining accessor
links `accessor-signature-budget`.
Explicit `G`/`S` selectors
override those defaults. Missing/ambiguous selectors, incomplete method lists,
unavailable attributes, and unsupported non-ASCII or non-identifier default
setter capitalization remain explicitly unresolved. This linkage does not
synthesize method declarations. The scanner
does not infer backing storage from these attributes. When an explicit `V` name is
present, it links that name to exactly one scanned class ivar by exact name for
class properties and category instance properties. The link reports a resolved
ivar row index, missing/ambiguous name, incomplete ivar list, or unscanned
category owner; it does not change object layout or claim that the ivar is
actually used at runtime. CLI and desktop property rows show the link status and
row index alongside getter/setter link statuses and method addresses, recognized
semantics, and raw attributes.

The class, method, ivar, property, protocol, and category record layouts follow
Apple's open-source Objective-C runtime definitions:
[Apple objc4](https://github.com/apple-oss-distributions/objc4).
