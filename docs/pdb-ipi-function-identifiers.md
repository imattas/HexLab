# PDB CodeView IPI function identifiers

`parse_pdb_ids` reads the separate CodeView IPI stream (MSF stream 4) and
retains the stream's type-index range. It decodes `LF_FUNC_ID` (0x1601) and
`LF_MFUNC_ID` (0x1602) records as named references to TPI function types.
Each result carries its IPI index, leaf, parent scope or owner class, TPI
function-type index, name, and exact byte offset/length in stream 4. Unknown
well-framed ID leaves remain as `unsupported` records with their original
leaf and byte extent.

The parser validates the 56-byte minimum TPI/IPI header, declared header and
record extents, sequential record count, per-record length, required fixed
fields, and NUL-terminated names. Names are capped at 4096 bytes, ID indices
at two million records, and cancellation is checked between records. Malformed
fixed fields and unterminated names return errors that include the stream
offset; unknown leaves do not make the rest of the IPI stream unreadable.

`import_pdb_function_ids` joins supported IDs to an already parsed TPI stream
and `PdbTypeImportResult`. Global function IDs must refer to `LF_PROCEDURE`;
member function IDs must refer to `LF_MFUNCTION` whose owner agrees with the
ID's aggregate. For this owner check, an `LF_MFUNC_ID` forward aggregate is
resolved to a completed local TPI aggregate only by an exact, unique CodeView
unique name. Duplicate definitions with that identity, missing unique names,
and external namespace selectors stay unresolved; display names are never used
to guess owner identity. Parent scopes must name a supported IPI function ID. Missing,
mismatched, cyclic, or unrepresentable references remain visible with
per-record diagnostics instead of producing a partial signature. Signatures
are keyed by exact TPI indices and never by display names. Procedure and member
function signatures remain in the same root-TPI index map.

Module `S_LPROC32_ID` and `S_GPROC32_ID` symbols can carry one of these IPI
indices directly. The PDB symbol reader preserves the index as IPI-domain data
instead of treating it as a TPI index. During desktop import, an exact resolved
index supplies its source-named function signature; the prototype is assigned
to the module procedure's address only when the selected PDB uniquely matches
the loaded PE GUID+age and the name and section-relative address match the
PE-bound symbol. Existing address assignments are preserved. The PE symbol
view and CLI inspection output identify each available procedure type reference
as TPI or IPI.

The same stream parser also decodes `LF_BUILDINFO` (0x1603),
`LF_SUBSTR_LIST` (0x1604), `LF_STRING_ID` (0x1605), `LF_UDT_SRC_LINE`
(0x1606), and `LF_UDT_MOD_SRC_LINE` (0x1607). Their IPI references, TPI UDT
index, line number, module index, string, and original record extent are
retained in `CodeViewIdRecord` and `PdbImportedFunctionId`. The importer checks
that build-info and substring-list entries refer to string IDs, string IDs
refer only to substring lists, and UDT source records refer to both a source
string and a supported TPI UDT. Failed joins stay visible with diagnostics.
Build-info lists are limited to the five defined fields, record counts are
bounded by stream extents and the parser's two-million-record cap, and all
fixed fields and strings are read within each record boundary.

The desktop IPI page labels all seven supported record kinds instead of
presenting non-function metadata as an unsupported leaf. Selecting
`LF_BUILDINFO` resolves its string-ID references into the ordered fields
current directory, build tool, source file, program database, and command line.
Selecting a string ID shows its parent substring-list reference; a substring
list previews at most eight referenced strings; UDT source records show the
referenced source string, line, TPI type index, and optional module index.
Reference IDs and exact byte extents remain visible. This is a bounded
inspection view: it does not persist build metadata or rewrite paths from the
recorded working directory. The field order follows LLVM's
[`BuildInfoRecord`](https://www.llvm.org/doxygen/TypeRecord_8h_source.html)
definition.

This still does not decode ID records in object-file sections or linker-
generated ID forms. Unresolved records are reported to callers, and unresolved
or ambiguous procedure references are left unassigned.

The record IDs and field layouts were cross-checked against Microsoft's
[`cvinfo.h`](https://github.com/microsoft/microsoft-pdb/blob/master/include/cvinfo.h)
and LLVM's [CodeView type-record reference](https://www.llvm.org/docs/PDB/CodeViewTypes.html).
