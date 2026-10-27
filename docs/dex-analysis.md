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
cancellation in bounded chunks. `DexMetadata::map_items` retains each validated map-list entry in source order as its section type, item count, and file offset; the map list itself is capped at 4,096 entries. This exposes the file directory without interpreting all section contents or synthesizing entries. The loader validates the header and map-list bounds, string/type/prototype/
field/method/class identifier tables, modified UTF-8 string lengths, encoded
class-data field/method lists, and each defined method's `code_item` instruction and
try/catch extents. Ordered typed and catch-all handlers are retained against
half-open method-relative protected ranges, with checked non-overlap/order and
aggregate row budgets. Function recovery adds explicit exception successors
from Dalvik opcodes with observable exception behavior; it preserves every
handler for the active range without guessing runtime type matches. Bounded
`debug_info_item` programs are also decoded into
method-relative source rows, parameter names, and local-variable live ranges.

The public `DexMetadata::classes` vocabulary retains each validated class
definition's type ID, raw access flags, optional superclass and source-file
string IDs, class-data file offset, and ordered interface type IDs. Encoded
class-data members are grouped into static/instance fields and direct/virtual
methods, preserving each field or method ID and raw access flags. Method rows
also retain the `code_off` file offset, with zero indicating no code item.
These are index-based records: the loader does not resolve names into shared
symbols/types or infer verifier properties from access flags. Class rows are
capped at 250,000; member and interface rows share a one-million-row cap, and
the retained class records are capped at 64 MiB. Each interface index and
member owner is validated before retention.

For DEX 038 and later, method-handle entries are validated for kind, reserved
fields, and referenced field/method indexes. Call-site entries are decoded as
bounded encoded arrays; the required bootstrap handle, name string, and method
type values are checked in order, along with every encoded value's table
references. `DexMetadata::method_handles` retains kind, member index, and item
file offset. `DexMetadata::call_sites` retains each item's file offset and all
ordered encoded values, including the bootstrap tuple and trailing arguments.
The tables are capped at one million rows; encoded values share the loader's
250,000-node and 64 MiB limits. Bootstrap execution, linking semantics, and
dynamic call-site resolution are not performed. These records are available
through the public loaded-image metadata model; there is no separate database
serializer for DEX metadata, so project reopen reparses the source through its
loader recipe rather than restoring these records from a metadata blob.
The interpreter validates register, string, type, and code-address references,
requires an `end_sequence`, and caps each program at two million opcodes and
the aggregate retained debug metadata at two million rows/64 MiB. Multi-member
DEX 041 parsing, reverse-endian files, annotation visibility
interpretation, and verifier semantics are not implemented. Class
static initializers are retained as class/field-linked `encoded_value` trees.
Scalar payloads retain their DEX tag, encoded width, normalized payload bits, and exact
file offset; index-valued tags are checked against their identifier table.
Nested arrays and encoded annotations retain child order, with annotation
element names represented by string-table indices. Static-value decoding is
bounded to 250,000 nodes, 64 MiB of accounted metadata, and 64 nesting levels;
values may not outnumber a class's encoded static fields. Omitted trailing
entries remain omitted, as in the DEX format; the loader does not synthesize
language defaults or resolve referenced indices to names.

DEX annotation directories, annotation sets, and parameter annotation-set
reference lists are also retained. Annotation items are deduplicated by their
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

Registers above 255, wide pairs ending above 255, and register ranges that
exceed the 16-bit encoding are rejected before narrowing. Range instructions
with more than 15 register words are unsupported because their trailing table
index would exceed the shared 16-operand instruction/cache budget. Method
register-count and invoke prototype validation remain verifier responsibilities.

Filled-array instructions decode their 35c register list (up to five entries)
or 3rc contiguous range, retain each source register and the 16-bit type index
as typed operands, and expose source-register reads plus allocation memory
effects. The range form rejects 16-bit arithmetic overflow and reports register
indexes above 255 as unsupported because the shared register operand model is
8-bit. These instructions fall through; they are not reported as direct method
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
`return-void-barrier` (`0xf1`), quick field access (`0xf2`–`0xf7`), and quick
virtual invokes (`0xf8`–`0xf9`). These forms retain their register effects,
field/vtable/inline indexes, and memory or call classification. Range invokes
accept their full encoded 8-bit word count and validate the 16-bit register
range; typed register operands remain limited to v0..v255. Quick indexes
remain unresolved; no dequickening, inline-method expansion, runtime-version
selection, or optimized-container validation is performed. Standard DEX
`invoke-polymorphic` and `invoke-custom` opcodes at `0xfa`–`0xfd` keep their
standard interpretation.

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
