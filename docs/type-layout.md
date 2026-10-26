# ABI-aware type layout

`hexlab/types/layout.hpp` provides `layout(type, abi)` for calculating object
layout from the immutable type graph. Supported data models are x86-32,
x86-64, AArch64, and AArch32. The AArch32 profile uses four-byte pointers and
an eight-byte maximum natural alignment for aggregate members. The result
includes total size, alignment, ABI pointer width, aggregate member offsets,
and explicit byte ranges for internal and tail padding. Existing stored member
offsets and aggregate sizes are left
untouched; they are metadata to compare against, not inputs to the calculation.
The desktop Types & Symbols page uses the same API to inspect a selected type;
its ABI selector follows the loaded image when available and can be changed
independently for cross-target comparison.

Symbolic `named_reference` nodes can be resolved during layout through
`LayoutOptions::resolve_named_type`. The resolver returns a retained immutable
definition by project name. The Types & Symbols page supplies this resolver
from the active project's named type table, so forward references embedded in
compound definitions are laid out with the referenced definition. Missing or
ambiguous names report an error. Pointer layout remains independent of the
pointee's object layout, so recursive pointer graphs such as `Node *next` are
valid. A cycle that requires embedding an object by value is rejected.

Aggregate construction accepts a named-reference member without an immediate
size or guessed alignment; its extent and natural alignment are deferred until
layout resolves the definition. The stored aggregate size and offsets remain
source metadata and are compared with the freshly calculated result in the
desktop view. The editor requires an explicit stored aggregate size when a
by-value forward member has unknown extent.

The calculator uses each scalar's recorded size and natural alignment, capped
at 4 bytes for x86-32 and 16 bytes for x86-64/AArch64. Homogeneous integer and
floating vectors multiply their lane size by the lane count and use their
recorded alignment capped by the selected ABI. Pointers take the target ABI's
width and alignment (4 bytes for x86-32, 8 bytes for the other models),
regardless of the size recorded on the `Type`. Arrays multiply the derived
element size; enums inherit their integer underlying type's layout. Structures containing a CodeView virtual base return `unsupported` from layout: their model retains the validated 32/64-bit vbptr type, vbptr byte offset, vbtable entry index (signed 32-bit entries), and direct/indirect flag, but the base subobject offset depends on the runtime object and vbtable. Layout does not treat the zero serialization placeholder as a real offset. Structures align each member and round the final size to the maximum member alignment.
Unions place every member at offset zero and round their maximum member size
to the union alignment.

Integral bitfields retain their storage type, storage-unit byte offset, width,
and LSB-relative bit offset. Multiple fields that reference the same source
storage-unit offset and have the same storage size share one allocated unit in
the calculated layout. Bit ranges must be nonzero, fit the storage type, and
not overlap. Packing caps affect the alignment used to place each storage unit;
each member layout still reports its bit width and position. This simple unit
grouping follows the imported CodeView allocation boundaries and does not claim
to emulate every compiler's bitfield allocation ABI.

The type codec persists each member's optional bit width and bit offset beside
its ordinary type and byte offset, so project save/load retains the bitfield
graph without a new codec record form. Named references are serialized as
symbolic leaves; workspace layout resolves them against the immutable snapshot's
named type table and reports missing or ambiguous definitions rather than
guessing.

Callers can pass `LayoutOptions{maximum_member_alignment}` to model common
packing caps, such as `#pragma pack(1)` or `#pragma pack(4)`. A zero value keeps
the ABI default; accepted non-zero caps are powers of two from 1 through 16.
The cap applies to member placement and recursively to nested aggregates, so
both member offsets and aggregate tail padding are recalculated. It does not
change a scalar's alignment when that scalar is laid out on its own. The
option is a calculation override and leaves the immutable `Type` graph
unchanged.

An aggregate may retain its source packing cap in the immutable type graph.
That cap applies to the aggregate's own member placement; nested aggregates
use their own retained cap. A nonzero `LayoutOptions` cap remains an additional
calculation override. The C header importer preserves active `#pragma pack`,
packed aggregate attributes, and explicit aggregate alignment attributes on
completed structs and unions. Explicit over-alignment raises aggregate tail
padding and reported alignment while leaving packed member offsets intact.

Types can also carry C/C++ `const`, `volatile`, and pointer-only `restrict`
qualifiers through `Type::qualified`. Repeated qualifiers on a scalar are
flattened; nested pointer qualifiers remain attached to their own pointer
level. Qualifier bits are retained as part of the type identity. Qualifiers do not alter
object size or ABI alignment; layout delegates to the qualified base type.
Formatting displays pointee qualifiers before the base type and pointer
qualifiers after the pointer. This is type display syntax, not a complete C
declarator printer.

The C header importer retains base and pointer `const`/`volatile` qualifiers
and `restrict` on pointers. Qualified forward references and flexible array
members retain their incomplete status through aggregate construction/layout.
Invalid qualifier placements fail import rather than being silently discarded.
PDB qualifier metadata is not currently translated into these nodes.

This API covers data object layout only. Function types, `void`, empty
aggregates, incomplete aggregate definitions, unresolved names, and recursive
by-value graphs return an `unsupported` error. A final flexible array member
contributes zero size and the element alignment; the containing structure keeps
its normal tail padding. Its `MemberLayout::flexible_array` flag is true, so
callers can distinguish that zero-sized tail from an ordinary extent without
inspecting the source type graph. The flag is derived from the retained
incomplete-array member and is not serialized separately; type records preserve
the array's zero count and final-member placement across project save/load.
Checked arithmetic returns `overflow` instead of wrapping. Type records use
codec version 10 to retain incomplete aggregate definitions; versions 1 through
9 continue to decode in their original format. Version 10 appends an aggregate
completeness flag, leaving earlier kind numbers and record layouts intact.
Target-specific aggregate exceptions are not inferred.
