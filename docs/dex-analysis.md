# Android DEX analysis

HexLab parses standard little-endian DEX versions 035 through 040 and single-
member DEX 041 containers whose logical file occupies the whole physical
container and whose header starts at offset zero. The loader validates the
041 extended header and derives the data bounds from the fixed header and ID
tables because the v41 `data_size` and `data_off` fields are unused. Multi-
member containers are recognized but unsupported; their members may share
later physical data and need per-member boundary handling. The bounded loader
verifies the SHA-1 signature over bytes `[0x20, file_size)` and the Adler-32
checksum over `[0x0c, file_size)` before interpreting tables.
Integrity mismatches are rejected with the DEX header field offset (`0x0c` for
the signature or `0x08` for the checksum) in the diagnostic. Both passes check
cancellation in bounded chunks. `DexMetadata::map_items` retains each validated map-list entry in source order as its section type, item count, and file offset; the map list itself is capped at 4,096 entries. Map offsets are strictly ordered for nonempty sections; the header and map-list entries must describe their actual locations, and fixed-width identifier sections must agree with header counts/offsets and end before the next mapped section. All mapped data sections must start inside the declared data extent, and map-defined four-byte-aligned item families (type lists, annotation sets/reference lists, code items, annotation directories, and hidden-API data) must have aligned starts even when the section is not otherwise decoded. This exposes the file directory without interpreting all section contents or synthesizing entries. The loader validates the header and map-list bounds, string/type/prototype/
field/method/class identifier tables, modified UTF-8 string lengths, encoded
class-data field/method lists, and each defined method's `code_item` instruction and
try/catch extents. Ordered typed and catch-all handlers are retained against
half-open method-relative protected ranges, with checked non-overlap/order and
aggregate row budgets. Function recovery adds explicit exception successors
from Dalvik opcodes with observable exception behavior; it preserves every
handler for the active range without guessing runtime type matches. Bounded
`debug_info_item` programs are also decoded into
method-relative source rows, parameter names, and local-variable live ranges.
For APK inputs, see [Android APK multidex loading](dex-apk-multidex.md) for the
bounded `classes.dex`, `classes2.dex`, … archive loader and per-entry provenance.
The standard `DBG_SET_PROLOGUE_END` and `DBG_SET_EPILOGUE_BEGIN` opcodes are
retained as flags on the next emitted source row, matching their position-state
semantics; they do not synthesize a line row or alter the address/line counters.
The CLI annotates those rows with `prologue-end` and `epilogue-begin`.
Each retained recursive `encoded_value` now includes its exact source byte
extent as well as its starting file offset. For array and nested-annotation
values, the parent extent covers its header and all encoded children; individual
children retain their own extents. The annotation CLI displays both offset and
byte length, allowing bounded source navigation without reparsing the value.

When retained DEX metadata is available, `const-string` and `const-string/jumbo`
resolve their string-pool index during lifting. The pseudocode records an escaped,
96-byte preview of the actual string and models resolution as an unknown-memory
effect with a typed reference result. Missing optional metadata keeps the prior
opaque-index representation; an index that contradicts the retained string
table is rejected as malformed.

The header's `link_size` and `link_off` must be both zero or both nonzero, and
any nonempty link range must fit the physical file. The validated `link_data`
extent is retained as `DexMetadata::link_data_offset` and
`DexMetadata::link_data_size`, and CLI metadata output reports its file offset
and byte count. Its payload remains opaque because the DEX format leaves its
contents unspecified; offsets are physical-file-relative in DEX 041 as well.

Type IDs are checked against the DEX `TypeDescriptor` grammar, including
255-dimension array limits and version-specific `SimpleName` characters.
Prototype shorty descriptors must match the return type, parameter count, and
each parameter's primitive/reference category; `void` is rejected in field and
parameter positions. Field and method owners, class definitions, superclasses,
interfaces, and annotation types are checked for their required class types;
method owners may be class or array types as allowed by DEX. Field, method, and
annotation element names are checked as `MemberName`s. Identifier tables now
also enforce unique specification ordering: UTF-16 string contents, descriptor
string indexes, prototype return/parameter tuples, field and method tuple
ordering, call-site offsets, and class-definition parent/interface precedence.
This is structural metadata validation; it does not perform class-hierarchy
resolution or Dalvik register-type verification. Rules follow the
[AOSP DEX format](https://source.android.com/docs/core/runtime/dex-format).

The public `DexMetadata::classes` vocabulary retains each validated class
definition's type ID, raw access flags, optional superclass and source-file
string IDs, class-data file offset, and ordered interface type IDs. Encoded
class-data members are grouped into static/instance fields and direct/virtual
methods, preserving each field or method ID and raw access flags. Method rows
also retain the `code_off` file offset, with zero indicating no code item.
Declared field and method rows additionally retain their validated name text
resolved from the string identifier table, so consumers can present member
names without reparsing source bytes or depending on DEX table indexes alone.
CLI inspection prints these names alongside each bounded declared-member row.
Class rows also print the source-file string ID and a bounded escaped preview
of its validated string when the optional `source_file_idx` is present;
`NO_INDEX` is displayed as absent. These are index-based records: the loader
does not resolve names into shared symbols/types or perform register type-flow
verification. It validates the class, field, and method access-flag masks and
visibility combinations; checks interface/annotation class relationships,
static-versus-instance field grouping, and direct-versus-virtual method
classification; and requires abstract/native methods to have no code while
concrete methods have code. It also checks the incompatible flag combinations
for abstract methods and rejects `ACC_DECLARED_SYNCHRONIZED` on a
`class_def_item`, where the format forbids it. These consistency checks follow
the [AOSP DEX access-flag definitions](https://android.googlesource.com/platform/dalvik/%2B/1c3da6197c677339cfdd41a948a5f79f804d6e4e/docs/dex-format.html).
Class rows are
capped at 250,000; member and interface rows share a one-million-row cap, and
the retained class records are capped at 64 MiB. Each interface index and
member owner is validated before retention. For every method with code, the
loader also checks `code_item.ins_size` against its prototype's incoming word
count, adding one receiver word for instance methods and two words for each
`J`/`D` parameter. A mismatch is rejected as malformed input. This validates
the method entry shape without claiming full Dalvik register-type verification.
For each instruction the shared decoder recognizes, the loader also checks
every decoded virtual-register read and write against that method's
`registers_size`; an out-of-range register rejects the file. Unknown opcode
families still stop this bounded register pass without claiming verifier
coverage for those instructions. The same scan validates inline string, type,
field, method, prototype, call-site, and method-handle references against the
corresponding DEX table. Optimized inline-cache and vtable operands are not
identifier-table indexes and remain uninterpreted by these checks. For
recognized wide move/result/return/constant, compare, array, field, unary,
conversion, long/double arithmetic, and two-address arithmetic opcodes, every
wide source and destination pair must fit completely inside `registers_size`;
a first word at the final register is rejected even though that individual
index is in range. Shift-long forms correctly treat the shift-count register
as a single word. This is a pair-boundary check only, not full register
type-flow or proof that a value actually has the instruction's declared type.
For recognized invoke forms the loader also checks that argument words fit
`outs_size` and match the referenced prototype, accounting for instance
receivers and two-word `J`/`D` parameters. Each wide argument must name
consecutive register slots in order; the loader rejects a split or reversed
pair. Inline-cache and quick-call forms
without a resolvable prototype are bounded by `outs_size` only. When the whole
method decodes, branch targets, try boundaries, catch handlers, and switch or
array-data payload references must land on the appropriate decoded instruction
or payload boundaries; branch and handler targets cannot enter data payloads.
Decoded return opcodes must match the enclosing method's return descriptor.
`move-result*` must immediately follow an invoke or filled-array producer and
match its known return shape, and `move-exception` may appear only at a decoded
catch-handler entry. Quick/inline calls with unknown return descriptors permit
any result variant after their immediate call instruction. Direct branches,
switch cases, and handler entries cannot target a `move-result` instruction,
so a path cannot bypass its matching producer.
For fully decoded methods, control-flow reachability starts at the method entry
and validated exception-handler entries. Reachable paths may not enter payload
data or fall off the end of the instruction array; unresolved opcode streams do
not receive this whole-method reachability certificate.

For DEX 038 and later, method-handle entries are validated for kind, reserved
fields, and referenced field/method indexes. Call-site entries are decoded as
bounded encoded arrays; the required bootstrap handle, name string, and method
type values are checked in order, the bootstrap handle must be an
`invoke-static` handle, and every encoded value's table references are
validated. `DexMetadata::method_handles` retains kind, member index, and item
file offset. `DexMetadata::call_sites` retains each item's file offset and all
ordered encoded values, including the bootstrap tuple and trailing arguments.
After class data is decoded, method-handle targets that are defined in this
DEX are checked against their declared static/instance access flags. Constructor
handles must name `<init>` methods with a void return, and locally defined
`invoke-interface` targets must belong to interface classes. External member
targets remain unresolved, so these cross-checks do not claim whole-program
verifier coverage.
The tables are capped at one million rows; encoded values share the loader's
250,000-node and 64 MiB limits. Bootstrap execution, linking semantics, and
dynamic call-site resolution are not performed. These records are available
through the public loaded-image metadata model; there is no separate database
serializer for DEX metadata, so project reopen reparses the source through its
loader recipe rather than restoring these records from a metadata blob.
The CLI's DEX inspection output also previews dynamic linkage: up to 128
method-handle rows and 128 call-site rows show handle kinds, local target/name
indices, and bounded trailing bootstrap arguments. At most 512 encoded argument
nodes are printed across the whole call-site preview; omitted table rows and
argument values are reported. This preview does not resolve external targets
or execute bootstrap methods.
The interpreter validates register, string, type, and code-address references,
requires an `end_sequence`, and caps each program at two million opcodes and
the aggregate retained debug metadata at two million rows/64 MiB. Multi-member
DEX 041 parsing, reverse-endian files, annotation visibility
interpretation, and verifier semantics beyond the `ins_size` invariant documented\nbelow are not implemented. Class
static initializers are retained as class/field-linked `encoded_value` trees.
Scalar payloads retain their DEX tag, encoded width, normalized payload bits, and exact
file offset; index-valued tags are checked against their identifier table.
Nested arrays and encoded annotations retain child order, with annotation
element names represented by string-table indices. Static-value decoding is
bounded to 250,000 nodes, 64 MiB of accounted metadata, and 64 nesting levels;
values may not outnumber a class's encoded static fields. Omitted trailing
entries remain omitted, as in the DEX format; the loader does not synthesize
language defaults or resolve referenced indices to names.
CLI inspection prints up to 256 explicit class/field values and resolves
validated string, type, field, method, and method-handle references for review.
Nested values retain their order and source file offsets. Display is capped at
512 value nodes and depth eight; truncation is reported, and the loader's full
validated model is unaffected by those presentation limits.
Each explicit static value is also checked against the owning FieldId's type
descriptor: primitive tags must match exactly, booleans remain 0/1, null is
accepted only for reference/array fields, and string/class/method-type/
method-handle constants require their corresponding built-in descriptors.
Enum values must reference a FieldId whose owner and field type both match the
declared enum field type. This validates encoded static initialization shape;
it does not resolve external classes or evaluate initializer code.

DEX annotation directories, annotation sets, and parameter annotation-set
reference lists retain their physical graph and exact extents, including
present-empty sets and absent parameter positions. Bounded CLI inspection shows
the graph, item values and flattened links. See [DEX annotation graph](dex-annotation-graph.md)
for retained records, resource accounting and display limits.
Known `dalvik.annotation.MethodParameters` annotations also expose validated
parameter names and flags in a provenance-preserving derived view; see
[DEX MethodParameters](dex-method-parameters.md).
Annotation items are deduplicated by their
file offset and linked to class definitions, declared fields, declared methods,
or individual prototype parameters. Each annotation keeps its visibility byte,
type index, ordered named values, item offset, and value offsets. Directory
member indexes must be ordered and identify members actually declared by that
class; annotation-set types and element names must be strictly ordered, and
parameter reference-list lengths must match the method prototype. The loader
caps annotation items at 250,000, annotation sets, set entries, directory
entries, parameter slots, and links at one million each, and annotation model
accounting at 64 MiB. These counts share the encoded-value 250,000-node,
64-MiB-accounted, 64-level limits with static initializers. It does not
interpret build/runtime/system visibility, resolve annotation names, apply
retention policy, or validate annotation declarations against class semantics.

For DEX 039 and later, the optional `hiddenapi_class_data_item` is parsed as a
single bounded map section. Its per-class offset table must fit the declared
section size, and nonzero flag streams must follow class-definition order and
match the fields and methods in each class's encoded class-data order. Each
ULEB128 value is retained with its class definition, field or method ID, and
source offset; the raw flag value is preserved without assigning a policy or
interpreting Android-release-specific bit meanings. Missing per-class streams
remain implicit zero flags. Parsing is bounded to two million retained flags
and 64 MiB of model records. The loader does not apply hidden-API access policy
or verify boot-class-path applicability. This structure was added to DEX in
Android 10; see the [AOSP DEX format reference](https://source.android.com/docs/core/runtime/dex-format#hiddenapi_class_data_item).

DEX catch edges are conservative metadata: the analysis does not resolve class
hierarchies to prune handlers or prove which typed catch receives a thrown
object. Handler targets are still validated against the method code extent, and
try ranges must be sorted and non-overlapping. A handler list above the
per-instruction CFG edge budget marks recovery incomplete instead of dropping
the excess edges silently.

Every defined method's Dalvik instruction stream is mapped to its own 32-bit
address space beginning at offset zero. Its image segment is named with the
class descriptor, method name, and prototype. This preserves code-unit-relative
branch offsets and prevents instructions in different methods from sharing
addresses. Packed/sparse switch payloads are validated from the referring
instruction and their targets remain in that method's address space. The
validator requires the complete payload and every case target to stay in the
same initialized executable method mapping; a case must have a complete code
unit and cannot point inside its own payload. Validated tables retain the
payload's original file offset and byte extent. Each case retains the source
file offsets of its key and target words (packed keys derive from the shared
`first_key` word). These offsets are reconstructed from the source image when
an instruction is loaded from the derived cache.

The decoder recognizes aligned packed-switch, sparse-switch, and
fill-array-data payloads as non-executable data directives. It validates their
headers and complete byte extents, keeps the payload's method-relative address
and exact encoded bytes, and formats up to 64 switch entries or 32 array values
per line (with an explicit ellipsis for larger valid payloads). Payloads above
32,000 bytes remain unsupported to keep instruction and derived-cache records
bounded. A control-flow path that reaches a payload stops as invalid data;
payload bytes never fall through into executable instructions. Switch dispatch
analysis continues to validate a referenced payload against method bounds and
case targets independently.

Function recovery treats every defined `code_item` as a method entry.
`invoke-direct` and `invoke-static` (including `/range`) references resolve to
that entry only when the referenced method ID has a validated code item,
producing cross-method call graph edges and call references. Virtual,
interface, and super invokes remain unresolved because their exact callee
requires dispatch evidence. Abstract, native, and otherwise code-less methods
also remain unresolved rather than being assigned invented code addresses.
Conditional branch references identify the relative target operand after the
source registers. Targets outside the method address space retain an unresolved
relative expression rather than treating a source register as a target.

The loader exposes parsed debug metadata to `inspect` and project inspection; it
does not import DEX classes, methods, or strings into the shared symbol/type
model. Source rows use byte offsets in the method address space; local scopes
are half-open byte ranges. Parameter names are retained in prototype order,
while source line rows do not include columns.

The desktop Source pane indexes DEX line rows in each method address space, so
source navigation stays method-relative. The pseudocode Variables pane applies
a debug local name only to a uniquely named SSA value for the matching virtual
register while that local's half-open live range contains the instruction.
It also lists decoded local types/ranges and named parameters as read-only DEX
metadata; parameter-to-register bindings are not inferred.

The decoder supports the common scalar move, result, return, constant, string
reference, monitor, throw, goto, conditional branch, packed/sparse switch,
invoke, `filled-new-array`/`filled-new-array/range`, and integer/floating arithmetic encodings listed in the supported-subset
source. It retains method call flow and direct intra-method branch targets.
Reference operands are shown
as table indices because string/type/field/method names are not yet attached to
the decoded instruction. Many core opcodes remain unsupported. Bounded packed/sparse switch tables are lifted to method CFG
dispatches with at most 64 cases; malformed payloads or targets outside the
recovered method remain incomplete. No Dalvik verifier-wide type model is
claimed. `inspect` and `disassemble` accept automatic detection or `--format
dex`; CLI decompilation supports the bounded method lifting subset described in
`dex-lifting.md`.

Every supported instruction exposes typed operands in Dalvik syntax order,
with one access entry per operand and explicit virtual-register read/write
sets. Wide values use 64-bit register operands; their effects name both 32-bit
virtual-register slots so high-half accesses retain dependencies. Long shifts
read a single-word shift count, conversions preserve distinct source and result
widths, and `/2addr` destinations are read/write. `check-cast` reads its reference
without defining a new register value. Array and field stores read their value
and address registers; loads write their destination. Invoke argument lists
retain encoded argument words as 32-bit reads, followed by the 16-bit method
index. No implicit result register is invented: `move-result*` defines the
explicit destination. Constants and table indices remain typed immediates;
branches and switches retain byte-relative target/payload operands.

Register ranges that exceed the 16-bit encoding and wide pairs whose second
slot would exceed that encoding are rejected before narrowing. Method-specific
register bounds are checked when retained code-item metadata is available.
Register indices are retained as 16-bit values through instruction facts and
reference provenance; older reference payload versions remain readable, and
the function engine identity was advanced so cached analyses are rebuilt.
Range instructions with more than 15 register words are unsupported because
their trailing table index would exceed the shared 16-operand instruction/cache
budget. Full verifier semantics remain unsupported.

Filled-array instructions decode their 35c register list (up to five entries)
or 3rc contiguous range, retain each source register and the 16-bit type index
as typed operands, and expose source-register reads plus allocation memory
effects. The range form rejects 16-bit arithmetic overflow. These instructions
fall through; they are not reported as direct method
calls or branches. The type index remains unresolved text such as `type@N`.
The decoder does not resolve whether the type is an array of single-word
elements or pair the produced object with the required following
`move-result-object`; those are verifier/lifter responsibilities and remain
unsupported.

Format and instruction details follow the Android Open Source Project's
[DEX file format](https://source.android.com/docs/core/runtime/dex-format),
[Dalvik bytecode reference](https://source.android.com/docs/core/runtime/dalvik-bytecode),
and [instruction formats](https://source.android.com/docs/core/runtime/instruction-formats).

The decoder also recognizes legacy optimized Dalvik code units listed in the
[AOSP optimized bytecode table](https://android.googlesource.com/platform/dalvik2/+/refs/heads/main/opcode-gen/bytecode.txt)
for volatile field access (`0xe3`–`0xeb`), inline invokes (`0xee`–`0xef`),
debugger `breakpoint` (`0xec`), `return-void-barrier` (`0xf1`), quick field access (`0xf2`–`0xf7`), and quick
virtual invokes (`0xf8`–`0xf9`). These forms retain their register effects,
field/vtable/inline indexes, and memory or call classification. Range invokes
accept their full encoded 8-bit word count and validate the 16-bit register
range. Quick indexes
remain unresolved; no dequickening, inline-method expansion, runtime-version
selection, or optimized-container validation is performed. Standard DEX
`invoke-polymorphic` and `invoke-custom` opcodes at `0xfa`–`0xfd` keep their
standard interpretation.

The optimized `throw-verification-error` form (`0xed`, 20bc) decodes its
error-kind byte and 16-bit table reference as separate typed immediates, and
ends control flow with `FlowKind::trap`. The reference remains an index because
the error kind selects among different DEX tables; HexLab does not resolve the
runtime-specific verification-error taxonomy or prove which handler catches
the resulting exception. The opcode is only meaningful in optimized Dalvik
code and is not validated against an optimized-container/runtime version.

# Optimized object initializer invoke

Optimized opcode `0xf0` has runtime-version-dependent encodings. Android API
14+ names it `invoke-object-init/range` and uses 3rc with exactly one receiver
word and a 16-bit starting register. Older API levels name it
`invoke-direct-empty` and use 35c with one packed receiver register. When the
runtime version is unavailable, HexLab distinguishes these legal forms by
the encoded count byte and rejects encodings that do not describe exactly one
receiver. Both forms retain the method index and receiver read, use three
code units, and are classified as calls with conservative memory read/write
effects. As with other optimized opcodes, ordinary DEX files should not
contain them; optimized-container and runtime-version validation are not
performed. The versioned forms follow the [AOSP Dalvik opcode history](https://android.googlesource.com/platform/external/smali/%2B/edc88aff44ff80f969df61725a992680cd0c464c/).
# DEX identifier catalogs

The reader retains bounded shared string, field-ID and method-ID catalogs,
including external member references, exact source offsets and encoded string
extents. CLI/project metadata output shows bounded identifier rows and escaped
name previews. See [DEX identifier catalogs](dex-identifier-catalogs.md) for
the API fields, memory budget and remaining limits. This is structural metadata
inventory and does not establish verifier or runtime member-resolution semantics.
# Bounded register type-flow

For completely decoded methods, the loader now propagates a small register
type state over the validated branch/switch control-flow graph. It seeds
incoming parameter words from the method prototype, follows normal edges and
propagates the pre-invoke state to handlers covering standard, range,
polymorphic, and custom invoke instructions. Normal and exceptional states
merge at joins under per-method and aggregate state-cell budgets. Invoke
exception edges do not receive the normal-path move-result write.

The current transfer subset recognizes scalar/wide constants,
string/class/new-instance/new-array results, scalar/wide/object moves,
move-exception, move-result-object/wide, check-cast, instance-of,
array-length, monitor operations, throw, fill-array-data, zero comparisons,
typed returns, long/float/double compare opcodes and two-register conditional
branches, integer/long/float/double arithmetic and conversions, and
descriptor-driven field, array, and resolvable invoke argument checks. It rejects known incompatible types at these uses; a
conflicting join remains unknown until a typed use consumes that register.
Nonzero 32-bit literals retain a shared int/float scalar category, and zero
valued scalar constants remain unknown because DEX also permits zero to be
used as a null reference. Wide literals remain long/double agnostic.
Unsupported instruction writes invalidate their
destination facts. Unknown facts are accepted conservatively and do not prove
definite initialization or class assignability.
Equality branches accept compatible integer or reference categories. The
ambiguous scalar category may pair with an integer category, but not with a
known reference; unknown values remain conservative. Ordered comparisons
require integer operands. `cmp-long`, `cmpl/cmpg-float`, and `cmpl/cmpg-double`
validate their source categories and establish an integer result register.

Arithmetic and conversion checks cover the standard register forms and
integer literal arithmetic; they validate register categories and wide pairs,
not numeric overflow or runtime value constraints. Array opcodes validate
reference/index and broad element categories, while `aget-wide`/`aput-wide`
remain long/double agnostic. Field descriptor checks apply to standard field
identifier opcodes; optimized quick/volatile forms are not linked to field
descriptors. Invoke checks validate argument categories when a method
prototype is available, including standard polymorphic/custom call-site
prototypes when retained metadata resolves them. For ordinary method-ID
invokes, tracked receiver types are checked against the method owner through
locally defined superclass and interface edges. Array receivers follow
reference-array covariance and the standard `Object`, `Cloneable`, and
`Serializable` supertypes. Each hierarchy walk is capped at 4096 visited
types. Known incompatible receivers are rejected. If local metadata cannot
prove a tracked receiver's relation, its exact type fact is dropped after the
call and only its broad reference category remains; the receiver is therefore
unverified at that call. Unknown register types remain conservative; reference
joins retain an exact type only when both incoming facts agree or one fact is
null. External hierarchy gaps are kept unresolved instead of being treated as
either a proven match or a malformed DEX. The pass does not resolve
external class definitions, infer common supertypes at joins, validate
field-owner receivers, or prove access, dispatch target identity, constructor
uninitialized-object rules, or quick/inline call signatures. Exceptional
state propagation covers standard array and field access, invokes, object and
array allocation, type/string resolution, monitors, throw, and integer/long
division and remainder. It sends each covered instruction's pre-state to
matching handlers, so a destination written only on the normal path is not
treated as initialized in a catch block. Other potentially throwing optimized
or unmodeled instruction families are outside this slice. The complete Dalvik
verifier lattice remains unsupported.
Methods with unsupported instruction decoding do not receive this CFG type
pass. It is a bounded partial verifier, not Android ART verification.
