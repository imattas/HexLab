# Android DEX analysis

HexLab recognizes standard little-endian DEX versions 035 through 040. The
bounded loader validates the header and map-list bounds, string/type/prototype/
field/method/class identifier tables, modified UTF-8 string lengths, encoded
class-data method lists, and each defined method's `code_item` instruction and
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
containers, reverse-endian files, checksum/signature verification, annotations,
encoded static values, and verifier semantics are not implemented.

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
loader exposes parsed debug metadata to `inspect` and project inspection; it
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
