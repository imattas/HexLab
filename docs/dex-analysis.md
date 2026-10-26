# Android DEX analysis

HexLab recognizes standard little-endian DEX versions 035 through 040. The
bounded loader validates the header and map-list bounds, string/type/prototype/
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

The loader exposes parsed debug metadata to `inspect` and project inspection; it
does not import DEX classes, methods, or strings into the shared symbol/type
model. Source rows use byte offsets in the method address space; local scopes
are half-open byte ranges. Parameter names are retained in prototype order,
while source line rows do not include columns.

The decoder supports the common scalar move, result, return, constant, string
reference, monitor, throw, goto, conditional branch, packed/sparse switch,
invoke, and integer/floating arithmetic encodings listed in the supported-subset
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

Format and instruction details follow the Android Open Source Project's
[DEX file format](https://source.android.com/docs/core/runtime/dex-format),
[Dalvik bytecode reference](https://source.android.com/docs/core/runtime/dalvik-bytecode),
and [instruction formats](https://source.android.com/docs/core/runtime/instruction-formats).
