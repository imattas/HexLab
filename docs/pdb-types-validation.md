# PDB TPI type parsing

`parse_pdb_types` reads stream 2 (TPI) from an already validated MSF/PDB database. It bounds the type-index count at two million, validates the TPI header and exact record extent, checks each length-delimited record, caps names at 4096 bytes, and checks cancellation between records. Parsed records retain their TPI index and original leaf ID.

The decoded subset includes `LF_METHODLIST` in addition to `LF_POINTER` (flat pointers with encoded const/volatile/restrict flags), `LF_MODIFIER` (const and volatile), `LF_BITFIELD`, `LF_ARRAY`, `LF_CLASS`, `LF_STRUCTURE`, `LF_INTERFACE`, `LF_UNION`, `LF_ENUM`, `LF_ALIAS`, and `LF_FIELDLIST` data members/enumerators plus `LF_INDEX` field-list continuations. `LF_VFUNCTAB` field-list entries retain their pointer type as a typed aggregate declaration and an explicit graph edge. This leaf provides no byte offset, so the preview preserves the type without adding a guessed member to persisted object layout. Aggregate records retain the optional CodeView unique name when the unique-name property is set. Forward declarations with unique names canonicalize only to the same kind and exact unique name; the parser does not guess from a matching display name when the record supplies a stronger identity. When several valid full aggregates share a displayed name but have distinct unique names, import assigns each a deterministic storage key formed from a UTF-8-safe display-name prefix and a SHA-256 suffix over the display name, leaf kind, and unique name. Key generation is bounded to 100,000 colliding definitions and 16 MiB of identity/display-name bytes per import; over-budget groups are skipped as ambiguous. The project `Type` keeps the original display name, while recursive named references use the storage key so persisted layouts resolve to the matching definition. If unique identities are missing, invalid, or collide, that displayed-name group is skipped as ambiguous. It also decodes non-virtual `LF_BCLASS` entries, including access attributes, target type, and numeric subobject offset. Imported bases become `$base$TypeName` members in the project aggregate, so they participate in persistence, validation, and layout at the CodeView-reported offset. `LF_VBCLASS` and `LF_IVBCLASS` retain the base type, vbptr type, vbptr offset, vbtable index, and direct/indirect distinction. Imported virtual bases become `$vbase$TypeName` members (numbered when repeated) with an explicit recipe and no fixed base offset; the type codec persists that recipe, while layout returns unsupported because resolution requires a runtime object. `LF_BITFIELD` retains its underlying type index, declared width, and LSB-relative bit position; truncated records fail parsing, while zero widths, non-integral storage, and bit extents outside the underlying type make only dependent imports unsupported. Integer numeric leaves include immediate values and signed/unsigned 1-, 2-, 4-, and 8-byte encodings; signed encodings are sign-extended while preserving their 64-bit two's-complement value. Enum import retains both names and numeric values in the project type graph. Class and structure records are distinguished, and forward-declaration properties are retained. Every other well-formed top-level leaf is retained with its leaf ID and `unsupported` kind; unsupported field-list member leaf IDs are retained as explicit entries except for the explicitly imported `LF_VFUNCTAB` type edge. Primitive type indices remain encoded directly in references below `0x1000` and do not appear as TPI records. Qualifiers are represented explicitly and preserved by import. Restrict is accepted only on pointer records; unaligned and unknown modifier bits remain unsupported.

`LF_VECTOR` now retains its scalar element index, lane count, byte size, name, and TPI record provenance in the parsed graph. The graph emits an exact element-type edge, including when the element is supplied by a flattened type-server namespace. Project import accepts complete integer/floating lanes when `element_size * lane_count` exactly matches the record size and the vector width is a power of two from 2 through 64 bytes; the type model uses that width as the conventional SIMD alignment. Non-scalar/qualified lanes, count/size mismatches, non-power-of-two or wider vectors remain unsupported instead of being converted to arrays. Ghidra's Java `VectorMsType` independently decodes the same element index, count, integral byte size, and name but emits a textual representation rather than a native data type; its source also explicitly cautions that the size interpretation is not fully understood. HexLab therefore preserves the decoded record fields and only maps the well-formed conventional SIMD subset into its existing vector type ([Ghidra `VectorMsType.java`](https://github.com/NationalSecurityAgency/ghidra/blob/master/Ghidra/Features/PDB/src/main/java/ghidra/app/util/bin/format/pdb2/pdbreader/type/VectorMsType.java), [Microsoft `cvinfo.h`](https://github.com/microsoft/microsoft-pdb/blob/master/include/cvinfo.h)).

CodeView Boolean8/16/32/64/128 primitive indices import as boolean types with their encoded 1/2/4/8/16-byte storage widths. The direct CodeView `T_REAL80` and `T_REAL128` primitive indices import as floating types with their encoded 10-byte and 16-byte storage widths. These primitive type records do not encode target ABI alignment, so the bounded importer uses the matching power-of-two width for Boolean values and 8-byte/16-byte alignment for the 80-bit/128-bit floating forms; these conventional alignments cannot replace compiler/target ABI provenance when laying out aggregates containing the types. Other unmodeled scalar encodings remain unsupported.

Before conversion, import compares full aggregate definitions from the root TPI and type-server namespaces when they repeat a CodeView unique name. Equivalent definitions share the deterministic storage key; distinct unique names sharing a displayed name continue to use separate hashed storage keys. The comparison includes aggregate kind/name, layout and declaration metadata, flattened fields, and referenced type structure, while ignoring source TPI indices and record offsets. Distinct unsupported or type-server nodes cannot establish structural equality because their payload or namespace identity is not fully represented. Comparison is coinductive for recursive graphs and bounded to depth 128 and two million compared node pairs per import. Missing targets, differing structure, or exhausted bounds quarantine the affected displayed-name groups, so pointers and other dependent types cannot select one conflicting layout through an exact TPI index. Identity key generation remains bounded to 100,000 colliding definitions and 16 MiB of identity/display-name bytes per import.

`resolve_pdb_type_graph` builds a non-recursively expanded graph: pointers, arrays, aliases, enum underlying types, members, aggregate field lists, and continuation edges are recorded with explicit primitive/resolved flags. A missing TPI target remains an unresolved edge rather than aborting the whole graph. Forward declarations are matched to a same-kind, same-name full definition when one is present. Struct/class/union/enum field-list continuations are flattened iteratively, with visited-index cycle detection and a two-million expanded-field bound; edge count is capped at four million. Pointer/member recursion is represented as graph edges and never recursively expanded.

Function signatures are imported from `LF_PROCEDURE` plus `LF_ARGLIST`. The type importer preserves return type, ordered argument types, variadic tails, fixed-width simple pointer types, and supported CodeView calling-convention values (near C, fastcall, stdcall, thiscall, and vectorcall). A trailing `T_NOTYPE` marks a variadic list; a lone sentinel is treated as an unprototyped declaration and skipped. `S_LPROC32`/`S_GPROC32` retain their TPI procedure type index, while `S_LPROC32_ID`/`S_GPROC32_ID` retain and mark their IPI index. The desktop joins ID-based procedure symbols to the exact resolved `LF_FUNC_ID`/`LF_MFUNC_ID` entry, imports the source-named prototype, and assigns it only when the selected PDB uniquely matches the loaded PE GUID+age, the procedure name and section-relative address agree, and no user type assignment already exists at the entry. Target-dependent simple pointers, other CodeView conventions, and malformed parameter-count pairs remain unsupported. This procedure-signature path does not yet have a dedicated regression fixture.

`LF_MFUNCTION` records are decoded with return, class, `this` pointer, calling convention, argument-list, and signed `this` adjustment, and function option metadata. When a method declaration refers to a supported member-function type whose owning class matches the declaration, import produces a typed function signature for the explicit parameters and retains the implicit `this` type and adjustment separately. The `this` value must be a pointer (possibly cv-qualified) whose possibly qualified pointee is the canonical owning class; incompatible or unresolved forms cause that method declaration to be skipped. Accepted function option bits are retained on the method declaration. Unsupported conventions, option bits, owner/pointee mismatches, and malformed parameter counts cause that method declaration to be skipped; method thunks are not resolved. This remains a bounded subset, not a complete CodeView implementation. Bitfields are represented only for integral storage and preserve the compiler-reported storage-unit byte offset and bit range; static virtual-base offsets, unique-name matching, virtual table construction and dispatch, many other field-list member kinds, and floating/decimal/string numeric leaves remain unsupported. DBI Type Server Maps can be followed recursively and flattened into a single graph while preserving every PDB's local selector mapping. Nested `LF_TYPESERVER2` chains are also discovered by GUID+age. Both paths use caller-provided resolvers, exact identity checks, cancellation, a 32-level nesting bound, namespace-count limits, cycle detection, and a 512 MiB aggregate bound on retained server-stream data; a missing nested selector is retained as an unresolved reference and cannot alias another flattened namespace. Forward matching uses only kind and displayed name, so ambiguous same-name definitions are not canonicalized. Unknown field-list members stop decoding the remainder of that length-delimited field list because its size is not known; the encountered leaf remains explicit. Unsupported top-level records retain their leaf IDs.

Project import supports named aggregate self- and mutually-recursive pointer edges by materializing their pointees as symbolic `named_reference` nodes. A standalone forward declaration with no available canonical definition is also retained as a named reference, allowing ordinary pointers to opaque external types to survive import. Complete definitions are imported before opaque forwards, so a forward record does not shadow a same-name definition. The desktop submits imported definitions as one atomic project command, so the complete named graph is persisted together. These references preserve the displayed type name without owning the aggregate, so the immutable project graph stays acyclic in memory and in its versioned encoding. The layout inspector resolves names against the named definition table. A named reference has no storage size on its own; standalone layout is unavailable until resolution. Direct by-value recursion, unnamed cycles, unresolved required references, and unsupported CodeView pointer modes remain rejected or skipped.

Field lists retain `LF_STMEMBER` static data members, `LF_NESTTYPE` nested type declarations, `LF_ONEMETHOD`, and `LF_METHOD` overload sets. `LF_METHODLIST` entries are length-bounded, retain method attributes, resolve referenced function types, and preserve introducing-virtual slot offsets. The import result exposes static members, nested types, and methods as source declarations keyed by owning TPI namespace, aggregate type index, and flattened declaration ordinal. Supported static data members and methods are retained on their imported aggregate type; neither participates in instance layout. Static-member type, access, source attributes, and declaration order survive project type-record version 13. Method metadata records virtual-dispatch category explicitly. Missing or unsupported signatures and overload-count mismatches are skipped and counted.

`LF_VTSHAPE` records retain their packed four-bit slot kinds, and class/structure records preserve their shape and derivation-list indices. `LF_VFTABLE` records retain the complete-class and overridden-table references, the vfptr byte offset, and the ordered raw names (table symbol first, then method names), along with source TPI record offset and size. Import exposes every bounded table slot with its TPI namespace, type index, record offset, vfptr offset, slot index, and raw names. Where a raw method name exactly matches a virtual declaration in the same aggregate, the slot metadata is attached to that declaration and persisted by type-record version 12; versions 1 through 11 remain readable, and types without slots preserve their prior canonical IDs. `analyze_virtual_call` can use this evidence when the caller supplies an already-proven vfptr offset and slot byte offset, but it still requires a proven receiver aggregate and exact function signature. This is declaration/slot evidence only: it does not infer runtime receiver types, resolve concrete vftable addresses, follow overridden-table inheritance, or select a unique target. Unmatched table names and inherited/adjustor thunk names remain available in the import result without being assigned to declarations.

### Typed data-symbol associations

`parse_pdb_symbols` retains the CodeView type index on supported `S_LDATA32` and `S_GDATA32` rows. After importing the TPI graph, `import_pdb_data_symbols` joins data rows to successfully converted types using the exact TPI index and type-server namespace. Simple CodeView primitive types are resolved directly. Procedure rows are excluded, while duplicate module/global data rows and their section-relative address, source kind, module, and record provenance remain available in each returned symbol. A missing index or unavailable/unsupported TPI type remains an unresolved row with a diagnostic; the importer never falls back to symbol or type display names. The 2,000,000-row input cap matches the symbol parser's bound. This API exposes typed data-symbol evidence to callers but does not itself assign globals to project annotations or convert section-relative addresses to RVAs.

The local-symbol parser associates each `S_LOCAL`, `S_BPREL32`, and `S_REGREL32` row nested within an `S_BLOCK32` record with its nearest lexical block extent (section, start offset, and size). Procedure-level locals have no lexical extent. These coordinates remain section-relative. The field gives downstream consumers enough information to omit a block-local outside its declaring block; current desktop local rendering does not yet apply this lexical filter. Block ranges are decoded from their bounded symbol records, and malformed/truncated block records fail parsing.

The desktop **PDB declarations** page displays source declaration rows with owner TPI identity, signature, access, dispatch category, introducing-virtual slot, and implicit `this` type. The page remains a bounded preview capped at 50,000 rows, with longer type strings clipped. Imported aggregates also persist supported static data and method metadata in the project's type graph; static data is shown in the formatted aggregate type and remains separate from instance members and layout. Function prototypes that match PE procedure symbols continue through the separate, validated project type-assignment workflow.

The desktop **PDB data symbols** page shows up to 50,000 typed `S_LDATA32`/`S_GDATA32` rows with the imported type or unresolved diagnostic, section/offset, raw TPI index, module/global source, module/object identity, and CodeView record kind/offset. Activating a row navigates only when the selected PDB uniquely matches the loaded PE GUID+age and its one-based section/offset maps inside the loaded image. Otherwise the row remains inspectable and the details pane says why no mapped address is available. The view is read-only: it does not rename symbols, create globals, or assign types to addresses.

Validation: `pdb_types` exercises synthetic records, signed enum values, alias and continuation decoding, cyclic pointer/member and field-list graphs, unresolved references, forward declarations, unsupported leaves, truncated enum numeric payloads and cancellation. `pdb_import` verifies enum values survive project-type encoding and decoding, including unsigned 64-bit payloads. `pdb_msvc_artifact` parses the MSVC-generated PDB for the PDB test executable and verifies a signed enum through TPI decoding and project import.

Format references: [LLVM TPI stream](https://llvm.org/docs/PDB/TpiStream.html) and [LLVM CodeView type records](https://llvm.org/docs/PDB/CodeViewTypes.html), including the `LF_PROCEDURE`, `LF_MFUNCTION`, and `LF_ARGLIST` layouts.

## Virtual inheritance recipes

`LF_VBCLASS` and `LF_IVBCLASS` field-list entries are decoded within the enclosing
record extent: attributes, base type index, vbptr type index, and two numeric
leaves. Both the vbptr byte offset and vbtable entry index must be nonnegative;
truncated headers/numeric leaves reject parsing. The table index counts entries,
not bytes. The existing bounded field-list continuation and type-server namespace
resolution paths preserve both references and the direct/indirect leaf kind.

Import requires a named class/structure base identity and an ordinary supported
32- or 64-bit pointer to signed 32-bit displacement entries. Qualified pointer
and pointee types remain supported. The vbptr field must fit inside the recorded
aggregate extent and its pointer address width. The vbtable entry's byte range
(`index * 4` through `index * 4 + 3`) must also fit that width; no allocation or
target-memory access is driven by the index. Unions or non-class base records,
unknown/unsupported pointer forms, incomplete/non-integral/unsigned displacement
types, negative indexes, and overflowing relative extents fail closed. The same
recipe validation runs when constructing or decoding persisted project types.
Previously accepted malformed or unsupported recipes may therefore fail decoding.

A supported base becomes a `$vbase$TypeName` member with `offset == 0` only as a
serialization placeholder; `has_fixed_offset()` is false. `VirtualBaseLocation`
retains the vbptr type and byte offset, entry index, and indirect flag through
canonical identity, formatting, and the existing version-9-and-later type codec.
The runtime relation is `base = object + vbptr_offset + signed_entry`, where the
entry is read from the runtime vbtable selected by the vbptr. This importer does
not read that table or claim a static subobject offset. Named unresolved bases
may retain their recipe when their class identity is known, while layout remains
unsupported until a caller supplies a separate runtime evaluation mechanism.
No vbtable/vtordisp construction, dynamic dispatch, access-control enforcement,
legacy 16-bit virtual-base records, or automatic runtime evaluation is added.

Format evidence: [Microsoft CodeView virtual-base fields](https://github.com/microsoft/microsoft-pdb/blob/master/include/cvinfo.h)
and [LLVM virtual-base record mapping](https://github.com/llvm/llvm-project/blob/main/llvm/lib/DebugInfo/CodeView/TypeRecordMapping.cpp).
Source review covered numeric sign handling, record boundaries, qualified types,
base kind/namespace selection, pointer-width arithmetic, persistence validation,
and fixed-layout rejection. No tests were added or run for this hardening slice.

## Non-virtual interface bases

`LF_BINTERFACE` (`0x151a`) is decoded as a fixed-offset base entry in an
`LF_FIELDLIST`, using the same attributes/type-index/numeric-offset layout as
`LF_BCLASS`. This supports interface inheritance in PDBs that use
`LF_INTERFACE` aggregate records: the base and supported declarations following
it are retained instead of ending field-list decoding at that leaf. For example,
an `IDerived` record with an `IBase` entry at offset zero imports a
`$base$IBase` member at zero, followed by its ordinary supported fields.
That member uses the existing aggregate type representation and type-library
codec, so it participates in persisted size validation and layout without a
new storage version.

The parsed field retains its original `LF_BINTERFACE` leaf, attributes, type
index, and base byte offset; the enclosing TPI field-list record's byte offset
and size remain available on the graph node. Graph construction emits a
`base_class` reference; continuation expansion and root/nested type-server
selector remapping preserve it through the same bounded paths as `LF_BCLASS`.
Selector zero resolves inside the owning PDB's TPI namespace. Import resolves
the exact namespaced target and its canonical definition rather than looking up
a base by displayed name; existing unique-name collision handling still applies.

Truncated attributes, type indices, and numeric leaves fail parsing. Negative
signed interface-base offsets are malformed (`CodeView offset/index must be
nonnegative`); unsupported numeric encodings retain the existing unsupported
numeric-leaf diagnostic. Import skips a dependent aggregate and increments
`skipped_unsupported` for missing or unnamed bases, non-class/structure targets,
unions containing bases, incomplete base storage, duplicate generated member
names, or base extents outside the aggregate. No placeholder zero-sized base is
invented. The source attributes and interface-specific leaf remain inspection
provenance in the PDB graph; the persisted member records fixed layout, not an
interface-specific access-control or dispatch model. Virtual interface dispatch,
runtime vftable resolution, and other unknown field-list leaves are unchanged.

Format evidence: [Microsoft CodeView definitions](https://github.com/microsoft/microsoft-pdb/blob/master/include/cvinfo.h)
alias `lfBInterface` to `lfBClass`; [LLVM BaseClassRecord](https://llvm.org/docs/doxygen/TypeRecord_8h_source.html)
handles both leaves with the same base record. Validation for this slice is a
Debug `hexlab_types` compile and source review; no tests were added or run.

## PDB pointer records

The TPI reader decodes `LF_POINTER`'s referent index and packed attributes,
including pointer kind, pointer mode, and the explicit pointer-size field.
Project import materializes ordinary near pointers with a supported flat
pointer kind and power-of-two size. Reference modes, pointer-to-member modes,
based pointers, unaligned or unknown pointer flags, and recursive pointer
graphs are skipped rather than flattened into incorrect object types. The
flat-pointer flag is preserved and accepted. Const, volatile, and restrict
flags become explicit pointer qualifiers. Synthetic
records cover attribute extraction and import behavior; the generated MSVC PDB
regression verifies real ordinary pointer attributes in the decoded TPI graph.

## Modern nested and friend declarations

The TPI field-list reader decodes `LF_NESTTYPEEX`, `LF_FRIENDCLS`, and
`LF_FRIENDFCN` in addition to the existing `LF_NESTTYPE` form. Nested-type
access attributes are retained on the imported declaration. Friend class and
friend function records retain their referenced TPI type and declaration name;
friend class rows use the target type's display name when CodeView omits a name.
All three forms create explicit graph references and remain separate from object
layout. The parser requires zero reserved padding on friend records and bounds
type indices, names, and record reads to the containing length-delimited field
list. Missing or unsupported friend targets remain skipped declaration rows
rather than becoming guessed members. Other unknown field-list leaves stay
explicitly unsupported.

Format evidence: Microsoft's [`cvinfo.h`](https://github.com/microsoft/microsoft-pdb/blob/master/include/cvinfo.h)
defines the `LF_NESTTYPEEX`, `LF_FRIENDCLS`, and `LF_FRIENDFCN` payloads.
