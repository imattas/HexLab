# Project type authoring

The Types & Symbols view stores immutable type graphs in the project. **New
integer type**, **New structure**, and **New compound type** open the dedicated
project type editor. Its kind selector covers integers, booleans, floating
types, pointers, fixed arrays, enumerations, function prototypes, structures,
and unions. The same editor opens through **Edit selected type** and preloads
the selected definition. Editing preserves its stable project type identity,
so address assignments continue to refer to the updated definition. Save
submits one validated project command; edits participate in undo/redo and are
stored with the project.

Compound definitions reference types already present in the project or use
symbolic forward names. The editor
uses a shared name, kind-specific fields, and a contextual error message.
Pointer creation chooses a pointee and 4- or 8-byte storage width/alignment.
Array creation requires an element and positive fixed count. Enum creation
requires an integer underlying type and comma-separated unique
enumerators. Each entry can be `NAME` or `NAME = VALUE`; values accept decimal
or `0x`-prefixed hexadecimal notation, including negative values for signed
underlying types. Unassigned values start at zero and then continue from the
previous value. For example, `None, Ready = 3, Error, Failed = -1` stores
values 0, 3, 4, and -1. Values are checked against the underlying integer
width, and duplicate names, empty entries, and overflowing implicit values are
rejected before the project command is submitted. Function prototypes select a
return type (including `void`), parameter names and existing parameter types,
variadic status, and a retained calling-convention qualifier, including the
explicit `aapcs32_vfp` option. Parameter lines
use `name type_name`; empty input creates a no-argument prototype. Structures use
`member_name type_name byte_offset`; offsets accept decimal or `0x` hexadecimal
values. Append `bit_width bit_offset` to author an integral bitfield, for
example `flags unsigned 0 3 0`; the bit offset is LSB-relative within the
storage unit. Unions use `member_name type_name` and place every member at
offset zero (with optional bit width and bit offset). Add `*` to a member type
token to create an inline pointer, for example
`next Node* 0` or `parent Node** 8`. The editor uses the selected member pointer
width, initialized from the loaded image when possible. A token matching an
existing project definition uses that type; an unknown name becomes a symbolic
`named_reference`. This supports self and mutual pointer graphs without
constructing owning pointer cycles. Unknown by-value members need an explicit
stored aggregate size in **Stored size for forward members**. That size is
metadata until the referenced definition exists; the layout inspector then
resolves the member and calculates its actual size and alignment. Direct
by-value cycles remain unlayoutable and are reported rather than guessed.

The immutable aggregate model validates declaration-name collisions across
instance data members, static data members, and methods. Multiple methods may
share a name to represent overloads; a method and a data declaration cannot
share one. Unnamed bitfields remain exempt because they have no declaration
name.

A final structure member can be written with a `[]` suffix to author a C-style
flexible array, for example `payload byte[] 4`. The element type must have a
complete size; inline pointer elements such as `items Node*[] 8` are supported.
The flexible member must be the final physical member and follow another
structure member; it cannot appear in a union. A bitfield cannot follow it.
It contributes no fixed tail size and uses its element type's alignment.
The type editor preserves this form when reopening the aggregate. Fixed arrays
remain independently authorable as named project types with a positive count.
For imported flexible-array types with nested qualifiers, the editor uses a
compact generated expression to preserve the exact type-graph nesting. The
expression starts with `$`; `N<bytes>:<name>` is a named type, `P<size>,<align>(T)`
is a pointer, `A<count>(T)` is an array (count zero is flexible), and
`Q<mask>(T)` qualifies the wrapped type (`const=1`, `volatile=2`, `restrict=4`).
For example, `$A0,1(Q1(N4:byte))` means a flexible array of const `byte`, while
`$Q1(A0,1(N4:byte))` preserves a const-qualified flexible-array node. Array records
carry their effective alignment so explicitly over-aligned array nodes round-trip.

Member names must be unique. The model validates known sizes, offsets,
alignment, overlaps, overflow, duplicate project type names, and descriptions
larger than 1 MiB before submitting a project command. Deferred members retain
their symbolic names and are checked by the layout resolver against the active
project definition table. Invalid entries remain in the editor with an
explanation so they can be corrected.

The type graph validates storage sizes, parameter/enumerator uniqueness and
enum value ranges,
nesting, and encoded-size limits before a project command commits. Invalid or
conflicting definitions leave project state unchanged. The editor does not yet
provide explicit per-field pointer alignment or type qualifiers. C header import can preserve supported
Microsoft calling-convention keywords on function types; see `header-import.md`.
PDB import represents self and mutually recursive
pointers as symbolic named references; layout requires resolving each
reference through the project's named-definition table. Header import remains
available for supported C declarations, with its own documented limitations
in `header-import.md`.

**Import PDB Types** reads a local MSF 7.0 PDB, decodes its bounded TPI graph,
and queues named project definitions while keeping CodeView type names intact.
It currently imports supported integer primitives, typedef aliases, fixed
arrays, ordinary near pointers with supported target sizes, structures and
unions with supported data members including CodeView integral bitfields and fixed-offset non-virtual base subobjects, and enums with numeric
values. Static data declarations and methods are retained in their owning
aggregate type as declaration metadata, separate from instance layout. Static
data type, access, source attributes, and declaration order survive type-record
version 13; prior versions remain readable. Pointer attributes retain
the CodeView pointer size; references, pointer-to-member modes, and
const/volatile/restrict modifiers that the project type model cannot retain
are skipped. The CodeView flat-pointer flag is accepted.
Existing project names, unnamed records, duplicate definitions, conflicting
ambiguous names, and unsupported type forms are skipped; malformed references
still fail the import. An unambiguous forward declaration with no available
definition is imported as a symbolic named reference, so pointers to opaque
external types retain their identity. A named reference has no size until a
project definition resolves it, so it cannot provide a guessed by-value
layout. Complete definitions are imported before opaque forwards, and a full
definition with the same name takes precedence. Direct by-value recursion,
zero-length arrays, and unsupported CodeView leaves remain unavailable for
project import. References to forwards with an unambiguous canonical definition
are resolved. Imported self and mutual pointer graphs are submitted as one
atomic project command. Imported enum values survive project-type encoding and
decoding. PDB GUID and age identify the source in the completion message; they
are not stored as project metadata.

The immutable type model can also retain explicit symbolic references to
separately named project definitions. The type layout inspector resolves these
references against the active project's definition table, including forward
references used as aggregate members. Pointer recursion remains representable;
by-value cycles, missing names, and ambiguous names do not produce a guessed
layout. The editor uses a trailing `*` to author pointer references and accepts
an unknown type token as a deferred by-value member.

Non-virtual PDB base subobjects are persisted as `$base$TypeName` aggregate members
at their CodeView byte offsets and participate in layout. Virtual bases remain
unsupported because their locations depend on runtime vbtable data.

Bitfield members keep the underlying integral storage type and CodeView's
storage-unit byte offset, declared bit width, and LSB-relative bit position.
The project model rejects zero-width fields, fields extending beyond their
storage unit, non-integral storage, overlapping bit ranges, and storage extents
outside the containing aggregate. Multiple disjoint fields can share a storage
unit. Persisted type encoding version 3 stores the optional width/position pair;
versions 1 and 2 remain readable and represent ordinary members without bit
metadata. Layout returns the storage-unit size and the bit range for each member.

## Assignment navigation

The **Assignments** table is an interactive index into the active project.
Use **Find assignment** to filter by displayed address or assigned type name;
the filter is case-insensitive and affects only the visible rows. A matching
row remains selectable and activating it navigates the main listing and bytes
view to its assigned address. Active-address synchronization selects the row
when it is visible under the current filter. From there, use **Assign to
selection** to change the type or **Clear assignment** to remove it. These
actions use the shared project command path, so edits participate in undo/redo
and persist through save and reopen. Activating a row in another document
cannot redirect the assignment because the table is rebuilt from the active
document snapshot. The filter is a view-only aid and is not saved with the
project.

The **Importable symbols** page can be filtered by symbol name or address.
Selecting or activating a result navigates the current document to that symbol, while
**Import symbols** remains a project-wide import action. The filter only changes
the visible list and does not change which symbols the import command considers.

The **Types** page has a separate **Find type** filter. It matches type names,
the formatted type shape, and stored byte size without changing the project
definition list. A selected type remains selected by its stable project ID as
the filter changes; Edit, ABI layout inspection, and **Assign selected type**
continue to use that definition even when other rows are filtered out. Hiding
the selected type disables its row-specific Edit/layout actions until the
filter reveals it again; assigning from the address selection can still open
the full type chooser.
