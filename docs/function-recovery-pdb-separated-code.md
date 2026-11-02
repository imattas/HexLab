# PDB function extents and separated code

HexLab uses matched PE PDB procedure symbols as function boundary evidence. A
procedure's declared CodeView size constrains instruction recovery to the
initialized executable bytes for that range. CodeView `S_SEPCODE` records
attached directly to that procedure can add discontiguous hot/cold fragments.
Recovered `FunctionChunk` rows retain the module, section, procedure record,
fragment record, section offset, and declared size as provenance; derived-cache
entries serialize that provenance as part of function results.

The PDB must match the PE image. Primary and separated ranges must map through
valid PE section coordinates, fit in one executable section, have initialized
file-backed bytes, and have no conflicting roots or metadata extents. A
separated row's parent address must fall inside its owner's primary range. All
separated rows for an owner are accepted together only when every row has
unambiguous disjoint ownership; conflicting rows are rejected and mark
recovery incomplete.

The current subset recognizes `S_SEPCODE` records whose `pParent` identifies
the owning procedure record directly. Rows nested under another scope or with
an unsupported parent relationship are omitted. It does not infer chunk bounds
from disassembly, synthesize missing PDB extents, or attach a fragment when the
matching procedure extent was rejected or superseded by other metadata.
