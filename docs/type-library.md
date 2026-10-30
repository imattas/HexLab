# Portable type libraries

The CLI exchanges editable project types, their DWARF declaration origins, and type assignments without project IDs:

```text
hexlab_cli project types export sample.hxproj --output sample.hxtl
hexlab_cli project types export-header sample.hxproj --output sample_types.h
hexlab_cli project types import other.hxproj --input sample.hxtl
hexlab_cli project types verify sample.hxtl
```

The binary `HXTL` format is versioned, little-endian, and length-prefixed. Version 6 is written by export; versions 2 through 5 and version 1 remain readable. A bundle contains up to 4096 unique named definitions, canonical type records, declaration kind, and optional DWARF origin offsets. Versions 2 through 6 also record the input size and SHA-256 plus a SHA-256 of the encoded load recipe. Version 6 adds a separate binary identity (input size and SHA-256) that binds file-offset assignments directly to the original image, independently of the loader recipe. Versions 3 onward support file-offset assignments alongside address assignments. Versions 4 onward append SHA-256 over the complete preceding bundle bytes; decoding verifies it before parsing records. Versions 5 and 6 can add an original-byte SHA-256 and byte count to each file-offset assignment whose type has a known size. Export hashes at most 64 MiB of assignment ranges per bundle; assignments beyond the remaining byte budget omit the witness. This detects accidental corruption but is not a signature or publisher-authentication mechanism. Type assignments refer to definitions by name. Address assignments require the complete source and recipe identity; file-offset assignments require the v6 binary identity to match exactly. Older bundles have no separately bound binary identity, so their file-offset assignments are skipped. On absent or mismatched identity, definitions remain importable and assignment rows are reported as skipped. Conflicting assignments fail by default; pass `--replace-assignments` to replace them.

The complete file is limited to 16 MiB, names to 512 bytes, definitions to 4096, and assignments to 262144. Every record is decoded and validated before the workspace import command runs. A graph-aware resolver validates named references across every nested type edge, including member, parameter, method, virtual-base, static-data, result, and element types. It accepts only exact names present in the bundle or destination and stops after one million unique type nodes or four million reference edges. Imports are one atomic, undoable project command. Matching names update in place; new names receive destination-local IDs. References remain symbolic by name, so nested types and forward references work when their targets are included in the bundle or already exist in the destination. Unknown references are rejected before workspace commit. Version 1 bundles contain definitions only.

File-offset assignments must start strictly inside the identified input. When
the assigned type is included in the bundle and has a known size, its complete
range must also fit inside the input. The encoder, decoder, and in-memory
assignment preflight enforce the same extent rule, including for legacy
versions that lack byte witnesses. This prevents a matching identity from
making an EOF or out-of-range location eligible for application.

Bundle-level definition names, assignment names, and source-origin strings must
be valid UTF-8 without embedded NUL bytes. Both encoding and decoding enforce
the same rule, including for legacy version-1 bundles; binary type records and
SHA-256 identity fields remain byte-oriented.

If the recipe differs but the exact binary identity matches, v6 file-offset assignments remain eligible while virtual-address assignments are skipped. A matching typed byte-range witness does not authorize applying an offset to a different image. Assignment-name validation and conflict policy apply only to selected rows. This keeps named type definitions portable even when location assignments cannot safely be reused.

This workflow handles the project type model, including aggregate layout, function types, enum values, qualifiers, methods and static data attached to declarations. It is not a compiler header/library importer and does not transfer project-local IDs or debug-variable records. Use native PDB/DWARF import for debug variables.

Library consumers can use `select_library_assignments` to apply the same
identity policy without duplicating it. Address assignments are selected only
when input size, input SHA-256, and recipe SHA-256 all match. File-offset
assignments require the separate binary identity and remain independent of the
recipe. A file-offset assignment with a byte witness is selected only when a
caller-supplied verifier confirms the destination bytes; without a verifier or
on a byte mismatch it is returned in the skipped list with a reason. Errors
from the verifier abort selection, so an I/O failure cannot silently turn into
a successful import. This API selects location assignments only; callers must
still resolve their symbolic type names and apply selected rows transactionally.

Consumers that need one preflight operation can call `prepare_library_import`.
It validates the bounded reference graph against bundled plus destination type
names, selects assignments using the source/binary identity and byte-witness
policy, and confirms every selected assignment names a bundled or
destination-provided type. Duplicate selected locations are rejected. Skipped
assignments are not required to resolve because they will not be applied. The
returned plan is validation output only; callers still apply it inside their
own project transaction.

Library consumers can call `merge_library_definitions` to combine definitions
from multiple bundles before encoding or importing them. It returns a
definition-only list sorted by exact name, so equivalent inputs produce the
same definition order. Repeated names are coalesced only when their canonical
type record, declaration kind, and origin metadata all match; conflicting
same-name definitions fail instead of silently choosing one. The merged graph
is checked against both the merged definitions and caller-supplied
destination names with the same node and edge limits as import preflight.
Assignments are not merged: bundles carrying source-specific assignments are
rejected so callers must select and apply assignments through the identity
policy separately. Source and binary identities likewise do not carry into
the returned definition list.

`project types verify <file>` validates a portable bundle without opening a
project. It checks the size bound, version, record extents, unique names,
assignment locations, every embedded type record, and the v4/v5 checksum when
present, then prints definition and assignment counts. It validates bundle
integrity; importing still performs destination-aware symbolic-reference and
source-identity checks.

Pass `--self-contained` to additionally require every symbolic type reference
to resolve to a definition carried in that bundle. This stricter mode is useful
for checking whether definitions can be moved without relying on names already
present in the destination project. Bundles that intentionally refer to
destination-provided types still pass ordinary verification but fail this
optional check. `--json` emits a schema-versioned report with verification,
definition and assignment counts, source-identity presence, and whether the
self-contained check was requested and passed.


Portable bundles validate UTF-8 and reject embedded NUL across all serialized type metadata as well as top-level names and source origins. This includes nested member, parameter, method, vtable-slot, enumerator, and symbolic type names. Validation is graph-aware and bounded to one million unique type nodes and four million reference edges, so malformed or adversarial metadata is rejected consistently on both encode and decode.

## C11 header consumer API

Library consumers can render the bundled definitions as a C11 header with
`types::render_library_c_header(bundle, include_guard)`. It first requires a
self-contained named-reference graph, then emits deterministic declarations
for typedefs, enums, structures, unions, object declarations and functions.
Aggregate output includes compile-time size, alignment and fixed-member-offset
checks, so a consumer compiling for a different layout fails visibly instead
of silently accepting a mismatched definition. The returned text can be
written by the caller; source identities, DWARF origins and location
assignments do not belong in the generated header.

The renderer is deliberately conservative. Definition and member names must be
C identifiers; integer widths are 8/16/32/64 bits; floating widths are
32/64/binary80; default-convention C function signatures and explicit
`cdecl`, `stdcall`, `fastcall`, `thiscall`, and `vectorcall` signatures are
supported, along with explicit `sysv_abi`, `ms_abi`, AAPCS32 base PCS, and
AAPCS32 VFP PCS function types. Microsoft
conventions use the `__cdecl`, `__stdcall`, `__fastcall`, `__thiscall`, and
`__vectorcall` spellings. SysV and Microsoft x86 ABI conventions use guarded
GNU-compatible attributes in direct function and function-pointer declarators.
AAPCS32 conventions use guarded `pcs("aapcs")` or `pcs("aapcs-vfp")` GNU
attributes. The generated header checks compiler and target macros and emits
`#error` if it cannot honor a required ABI attribute; it never silently drops
the recorded convention. A Microsoft x64 compiler uses its native default for
`ms_abi`. AAPCS64, MIPS conventions, and other non-default conventions are
still rejected with an unsupported result.
Named function parameters whose portable type is an array or function are
rendered with the standard C parameter adjustment: arrays become pointers to
their element type (including pointers to nested arrays), and function types
become pointers to functions. Qualified array/function parameter wrappers are
still rejected because the portable model does not record enough target C
parameter-adjustment detail to render those forms safely. Named references must resolve
inside the bundle. C++
methods, static data members, virtual bases, bitfields, and compiler-specific
vectors remain unsupported. Incomplete named structures and unions with no
members or C++ declarations are emitted as opaque forward typedefs, so pointer
aliases, pointer fields, and pointer-safe function signatures can refer to them.
The renderer rejects any object, parameter, result, array element, or aggregate
member that uses an incomplete aggregate by value; incomplete typedef aliases
are allowed, but using such an alias by value remains rejected. Enums are emitted
as fixed-width typedefs plus namespaced typed integer constant macros, whose
names take the form `Type_Enumerator`. Signed and unsigned values through
64-bit storage are supported, including the full `int64_t` and `uint64_t`
ranges; values are cast to the enum typedef so their declared storage width is
preserved in C expressions. Underlying enum storage wider than 64 bits remains
unsupported.
Binary80 relies on the target compiler's `long double` representation; the
generated assertions diagnose a mismatch when compiled. This creates a
source-level C consumer view; it does not preserve project-only behavior or
guarantee ABI portability across compilers and targets.

The project command `project types export-header <project> --output <header.h>`
renders supported project definitions and atomically publishes a self-contained
C11 header. Existing output paths are rejected by default; pass `--replace` to
atomically replace one. Unsupported type or ABI layouts fail before publication
with the renderer's specific diagnostic. Output is limited to 16 MiB, and graph
work is bounded. The project's protected paths prevent writing over project
inputs.
