# Mach-O Objective-C class metadata

The Mach-O inspection CLI reports a bounded Objective-C class-list view for
little-endian 32-bit ObjC2 and 64-bit images. It scans regular, file-backed `__objc_classlist`
sections and retains each class-list section ordinal, slot address, and index.

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
The directly referenced metaclass is decoded as a class object; its `class_ro_t`
name and class-method list are reported with separate pointer statuses. Names
must terminate within initialized mapped bytes and the configured name limit.

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
  scanned protocol records by exact metadata address. Unvalidated optional
  protocol tail fields such as extended type arrays and class properties are
  not guessed.
- `__objc_catlist` and `__objc_nlcatlist` produce category nodes with their
  name, target class link, instance/class methods, protocols, and instance
  properties. When a category's target address matches a scanned class,
  category and class records link in both directions by exact metadata
  address; unresolved or unscanned targets remain explicit. Category and class
  rows are deduplicated by stable metadata address while preserving every
  section/index/slot origin.
- CLI output lists protocol definitions, their required and optional instance
  and class method signatures, instance properties with parsed type metadata,
  and adopted protocol links with exact scanned-definition indices when
  available.

Each decoded field carries a status so unresolved, authenticated, runtime-bound,
ambiguous, and unsupported fixups remain distinguishable from null or raw
pointers. A partial field marks its owning class/category/protocol and scan incomplete;
decoded records remain available. The scanner bounds every list extent, string,
pointer slot, and scalar read. Protocol definitions use the same validated direct and relative method-list formats described above. The scanner does not infer category targets from runtime registration or decode optional protocol/category tail fields.

Default work limits are 100,000 classes, categories, and protocols, 64 MiB of metadata reads and validated list extents, 4,096 bytes per name, and 1,000,000 entries per list. A limit or unresolved class field
marks the scan partial while preserving the rows already decoded. Cancellation
is honored during scanning. Big-endian images, arm64_32, ObjC1 `__OBJC`
records and runtime class data remain unsupported.
See the [32-bit layout and validation contract](../libs/analysis/docs/macho-objc-32bit.md)
for exact supported offsets, pointer checks and remaining runtime forms.
This hardening slice has source-review evidence only; no builds or tests were run.

The Objective-C type import plan also persists complete categories whose name
and target link resolve to a scanned class. Parsed instance and class method
signatures are stored together in a separate incomplete aggregate named
`ObjC2.Category.<class>.<category>`. This keeps category declarations and
their metadata provenance separate from the target class's instance layout.
Duplicate target/category names, partial records, unlinked targets, and
categories without parsed method signatures are skipped. The source origin
records the category-list section ordinal, list index, and category record
address, so the imported type can be traced to the metadata that supplied it.

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
The scanner does not infer default accessor names, synthesize declarations, or
infer backing storage from these attributes. CLI and desktop property rows show
the recognized semantics together with raw attributes for review.

The class, method, ivar, property, protocol, and category record layouts follow
Apple's open-source Objective-C runtime definitions:
[Apple objc4](https://github.com/apple-oss-distributions/objc4).
