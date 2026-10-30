# CLR MethodImpl metadata

The managed metadata reader exposes the ECMA-335 `MethodImpl` table through
`parse_managed_method_implementations`. Each result preserves the `MethodImpl`
token and metadata byte offset, the owning `TypeDef` token, and the body and
declaration tokens. Both method references are validated as non-null
`MethodDefOrRef` coded indexes and resolve to an in-range `MethodDef` or
`MemberRef` row.

This table records class-local method body/declaration associations, including
explicit interface implementations and method overrides. The parser retains
the metadata relationship without inferring virtual dispatch, checking method
signature compatibility, decoding IL bodies, or resolving external
`MemberRef` declarations. It bounds the metadata root at 64 MiB and the catalog
at 250,000 rows, and rejects inconsistent row layouts, truncated tables, and
invalid coded indexes.
