# DWARF v4 symbol and type import

`hexlab/symbols/dwarf.hpp` imports a deliberately selected DWARF v4 subset from
`.debug_info`, `.debug_abbrev`, and `.debug_str`. It emits source-attributed DIE
records for base/derived types, fixed arrays, structs/unions and members, enums
and enumerators, function types, subprogram signatures, formal parameters, and
variables. Unit-relative references resolve only within the current compilation
unit. `DW_FORM_ref_addr` type references and subprogram
`DW_AT_specification`/`DW_AT_abstract_origin` references may target any ordinary
compile unit in the same `.debug_info` section, including a later unit. All
units are decoded and indexed before resolution, then resolved in a bounded
dependency order so target types and function signatures are available first.
Named enumeration types retain each enumerator's numeric value in the project
type graph, including unsigned constants through `UINT64_MAX`. Values use the
existing 64-bit two's-complement representation, so negative signed constants
remain exact; the importer checks each value against its declared integer base
type before constructing the enum. `ImportedEnumerator` preserves its original
signed `value` member for source compatibility and appends `exact_value`, which
contains the raw 64-bit value bits and an `is_signed` flag. New consumers should
use `exact_value` when present; the legacy `value` remains a signed projection
and may appear negative for unsigned constants above `INT64_MAX`.
Integral bitfield members with a positive `DW_AT_bit_size` may omit
`DW_AT_name`; these remain unnamed fields with their storage position and bit
range intact in the imported aggregate. Unnamed non-bitfield members remain
unsupported.
Const, volatile, restrict, and atomic wrapper DIEs retain their qualification
in the persisted type graph; restrict requires an unqualified pointer target.
Atomic wrappers preserve the referenced type's layout unless an explicit
supported alignment is present. Atomic byte sizes that differ from the
referenced type remain unsupported.
Ranged subprogram DIEs inherit missing names, return types, and parameter lists
from same-unit or cross-unit targets; cycles and non-subprogram targets are
malformed. Cross-unit function inheritance is limited to complete named
declarations whose return and parameter types resolve in the same import.
When a ranged subprogram DIE has a direct standard `DW_AT_linkage_name`, the
imported symbol retains that raw string in `ImportedSymbol::linkage_name`;
`ImportedSymbol::name` remains the source name. The linkage-name field is not
inherited from specification/origin DIEs and is not demangled.
Direct `DW_AT_decl_file`, `DW_AT_decl_line`, and `DW_AT_decl_column` values on
imported ranged functions and variable/parameter records are retained in the
optional `declaration_location` metadata. For v2-v4, `file_index` preserves the
one-based file number from the owning unit's line table; zero or missing values
are not rewritten. The importer does not resolve this index to a path or line
row. Values must be nonnegative integer forms; unsupported or negative values
are rejected.
Function ranges handle address-form `DW_AT_high_pc` and
constant-form offsets. Subprogram `DW_AT_ranges` with `DW_FORM_sec_offset`
reads the optional legacy `.debug_ranges` section and retains every half-open
interval in `ImportedSymbol::ranges`; the imported function root remains its
first interval. Each address-sized offset pair uses the compile unit's
`DW_AT_low_pc` as its initial base, or the most recent all-ones base-selection
entry. Lists require a zero/zero terminator and are limited to 4,096 ranges
and 8,192 nonterminal entries. Out-of-section offsets, truncated pairs,
missing bases or terminators, reversed or empty ranges, and address-width
overflow fail explicitly. Direct variable addresses and raw location-expression bytes are kept
separate in the result. Embedded DWARF v4 expressions receive a bounded
operation decode for register/base-register locations, frame-base
and CFA references, constants, dereferences, arithmetic plus, pieces, and
stack-value markers. The caller-driven evaluation API accepts register and
memory readers rather than accessing a process itself. Arithmetic, signed
comparison, and branch operations are evaluated by the same bounded engine;
`DW_OP_bra` and `DW_OP_skip` targets must be operation boundaries or the
expression end. Evaluation permits at most 4,096 decoded operations, 65,536
executed operations, 64 stack entries, and 4,096 memory reads. DWARF 5 section
2.5.1.5 defines these operations: [DWARF v5 standard](https://dwarfstd.org/doc/DWARF5.pdf).
Its composite-location
entry point retains ordered `DW_OP_piece`/`DW_OP_bit_piece` fragments, including
unavailable fragments; ordinary scalar evaluation still rejects composite
expressions. Unknown opcodes fail explicitly. The ELF importer and desktop
variable view retain decoded expressions, and live locals evaluates them using
the selected thread's explicitly supplied registers and memory reader.

The public importer can also consume optional `.debug_loc` and `.debug_ranges`
sections through `DwarfV4Sections::locations`/`ranges` or
`DwarfSections::locations`/`ranges`. It decodes the
legacy address-pair format, including base-selection entries, into half-open
PC ranges and retains each expression and decoded operation sequence. Offset
pairs use the compile unit's `DW_AT_low_pc` until a base-selection entry
replaces it. These ranges use the same PC-selecting evaluation API as v5
location lists. Lists are bounded to 4096 ranges, 64 KiB of expression bytes,
and 4096 total operations; missing terminators, empty/reversed ranges,
overflow, and truncated expressions are rejected. This section-level API does
not itself discover or load ELF sections. The range-pair encoding dates from
DWARF v2-v4; this DIE importer currently accepts v4 and v5 compilation units,
so v2/v3 DIE streams remain unsupported.

The importer keeps DWARF alignment uncertainty explicit. Base-type alignment
uses a conservative value; aggregate alignment is inferred from member types.
The current type graph cannot represent typedef/qualifier wrappers or enum
numeric values directly, so `ImportedType` carries typedef/const/volatile and
source-name metadata while enumerator values are returned as separate records.

It rejects unsupported forms and malformed references. Supplementary, split,
signature-based, unsupported non-type, unresolved cross-unit references, and
cross-unit dependency cycles,
recursive aggregate graphs, incomplete aggregate layouts, dynamic or
unknown-bound arrays, nonconstant member locations, DWARF v5 default-location
entries, and unrecognized type DIEs referenced as types are not guessed. It is not a
complete DWARF reader: other range/location-list forms, call-site information,
inheritance, templates, and DWARF versions other than 4 remain outside the
type/symbol subset.

ELF loading locates `.debug_info`, `.debug_abbrev`, and optional `.debug_str`,
`.debug_loc`, `.debug_loclists`, `.debug_ranges`, and `.debug_rnglists` sections and retains parsed records as
`ElfMetadata::dwarf_info`. Legacy v2-v4 `.debug_loc` ranges and v5
`.debug_loclists` ranges use the same durable project-variable and PC-selection
workflow. An explicitly supplied standalone DWO can also provide
`.debug_ranges.dwo` for a v4 split compile unit. The initial
project workflow supports little-endian ELF DWARF v4 and a bounded v5 subset.
Section reads and
retained records share the ELF metadata budget; duplicate, compressed, or
file-less debug sections produce a metadata diagnostic while leaving the image
loadable. Unsupported endianness and forms are reported explicitly. The Types
& Symbols page can import supported subprogram names and prototypes together
with named type graphs. The workspace command persists named types,
function-type definitions, address assignments, and names in one reversible
project transaction. Type name collisions are skipped, and function locations
are imported only when they map into the loaded image. Parsed variable scopes
and non-executable location expressions are stored as project rows and shown
in the variable view. Named type definitions and function-prototype definitions
retain the source identity, debug section, unit offset, DIE offset, and DIE size
through project reopen, undo/redo, and project exchange. Older project schemas
migrate with an absent origin; importing a new project record uses user-state
codec version 6 and SQLite schema version 7. Mach-O
`.debug_info` and DWARF relocations remain unsupported. The DIE importer supports
the bounded cross-unit reference subset described above.
The supported v5 DIE forms are summarized in `dwarf-v5-import.md`.

The same header exposes `import_dwarf_line_v2_v5()` for `.debug_line` line
programs from versions 2 through 5; `import_dwarf_line_v2_v4()` remains a
compatibility entry point. It returns per-unit directory/file tables
and address/file/line/column rows, including end-sequence markers. ELF loading
now applies that v2-v5 importer to ordinary `.debug_line` sections and supplies
the companion `.debug_str` and `.debug_line_str` tables, so v5 `DW_FORM_strp`
and `DW_FORM_line_strp` directory/file paths resolve during image loading.
Those companion sections are subject to the same duplicate-section, compressed
section, file-extent, cancellation, and aggregate metadata-budget checks. ELF
loading copies the parsed rows into `LoadedImage.metadata.elf->source_lines`,
where project snapshots retain them through their loaded-image metadata. The parser accepts
32- and 64-bit target addresses, either byte order, caps sections at 256 MiB,
caps directory/file tables at 65,536 each and rows at four million by default,
and checks cancellation when called by the ELF loader. DWARF v5 directory and
file tables use declared content/form descriptors, with inline strings and
fixed-width or ULEB numeric fields supported. Direct callers can pass optional
`.debug_str` and `.debug_line_str` byte spans through `DwarfLineSections`;
without a required table, the corresponding string-offset form is unsupported.
Malformed extents and arithmetic are rejected. Split DWARF, relocations for
`.debug_line` in relocatable object files, compressed line sections, and
compilation-directory path resolution are not implemented; source addresses
are emitted as recorded by the line program.

Mach-O loading also imports `__debug_line` from the selected slice into
`LoadedImage.metadata.macho->source_lines`. Rows retain the selected slice,
debug-section ordinal and file offset, unit and row indexes, and the raw
line-program address. For linked Mach-O images, the loader publishes a mapped
address only if exactly one declared section contains the row and that address
is present in the loaded image. For `MH_OBJECT`, addresses stay raw because
`__debug_line` relocations are not yet resolved. Compressed `__zdebug_line`
sections are reported as unavailable rather than parsed as ordinary bytes.

For address navigation over an imported line unit, `dwarf_line_row_at(unit,
address)` returns the row whose half-open address interval covers the query.
It chooses the last emitted row at duplicate addresses, treats each
`end_sequence` address as an exclusive bound, and does not invent coverage for
an unterminated sequence. Rows in a sequence must be address-ordered for the
lookup to use that sequence; malformed ordering is skipped safely.
