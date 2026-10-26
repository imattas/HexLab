# Android DEX analysis

HexLab recognizes standard little-endian DEX versions 035 through 040. The
bounded loader verifies the SHA-1 signature over bytes `[0x20, file_size)` and
the Adler-32 checksum over `[0x0c, file_size)` before interpreting tables.
Integrity mismatches are rejected with the DEX header field offset (`0x0c` for
the signature or `0x08` for the checksum) in the diagnostic. Both passes check
cancellation in bounded chunks. The loader validates the header and map-list bounds, string/type/prototype/
field/method/class identifier tables, modified UTF-8 string lengths, encoded
class-data field/method lists, and each defined method's `code_item` instruction and
try/catch extents. Ordered typed and catch-all handlers are retained against
half-open method-relative protected ranges, with checked non-overlap/order and
aggregate row budgets. Function recovery adds explicit exception successors
from Dalvik opcodes with observable exception behavior; it preserves every
handler for the active range without guessing runtime type matches. Bounded
`debug_info_item` programs are also decoded into
method-relative source rows, parameter names, and local-variable live ranges.
The interpreter validates register, string, type, and code-address references,
requires an `end_sequence`, and caps each program at two million opcodes and
the aggregate retained debug metadata at two million rows/64 MiB. DEX 041
containers, reverse-endian files, checksum/signature verification, annotation
visibility interpretation, and verifier semantics are not implemented. Class
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
the decoded instruction. Array payloads and many core opcodes remain
unsupported. Bounded packed/sparse switch tables are lifted to method CFG
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
