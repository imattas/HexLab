# Importing PDB function identifiers

The desktop **Import PDB Types** workflow also reads the selected PDB's IPI
stream and joins `LF_FUNC_ID` and `LF_MFUNC_ID` records to their exact TPI
function records. Resolved signatures are stored in the project's shared type
table as named, source-scoped function types. Their names include the PDB GUID,
age, IPI index, and a readable form of the CodeView name, so importing another
PDB or a different IPI record does not replace a user type.

The **PDB function IDs** page lists supported and unsupported records from the
selected PDB. Each row retains the IPI index, CodeView name and kind, referenced
TPI function index, source record offset, and resolution/import status. Selecting
a row shows its source byte extent, parent IPI scope or class TPI index, full
function signature when resolved, and any unresolved-reference diagnostic.
Unsupported leaves remain visible with their leaf number and source extent.

When the selected PDB uniquely matches the loaded PE GUID and age, import also
uses module `S_LPROC32_ID` and `S_GPROC32_ID` records to connect an exact IPI
index to its procedure address. The source-named prototype is assigned only
when the PDB procedure's name and section-relative address match the PE-bound
symbol and no type assignment already exists at the entry. Existing function
assignments are preserved. TPI procedure symbols continue to use their exact
TPI function type index. Function prototypes are capped at 4096 newly imported
definitions per operation; the IPI inspection page still lists all bounded
parser records. The PDB identity remains visible so records from a manually
selected PDB are not mistaken for metadata bound to the active image.

The PDB parser caps the IPI stream by its existing record and input limits.
Unsupported CodeView ID leaves, unresolved parent/type references, unsupported
TPI signatures, and malformed streams are reported rather than guessed. The
page describes the selected PDB file; raw IPI records are not persisted as a
separate project artifact. Imported named types and type assignments are
persisted through the project's ordinary type tables.
