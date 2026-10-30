# CLR FieldRVA metadata

`parse_managed_field_rvas` exposes bounded `FieldRVA` table rows as a
FieldDef token, a nonzero RVA, and the row's offset within the metadata root.
FieldDef catalogs also carry the RVA and row provenance on the matching `ManagedField`;
the parser requires the FieldDef `HasFieldRVA` flag and table row to agree.
Duplicate FieldDef rows, invalid Field indexes, zero RVAs, inconsistent row
layouts, and truncated tables are rejected. The table is capped at 250,000
rows and the metadata root at 64 MiB.

The RVA identifies the start of initialized static data. This metadata parser
does not infer the data extent from the field signature, validate the RVA
against a PE section, or read/interpret the bytes. Struct layout, element
count, native alignment, and runtime mutation remain outside this record view.
CLI field output displays the RVA and FieldRVA-row provenance when available.
