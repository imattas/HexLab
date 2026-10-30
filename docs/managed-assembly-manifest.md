# CLR Assembly manifest identity

`parse_managed_type_catalog` retains the module's single `Assembly` row as
`ManagedTypeCatalog::assembly_identity`. The identity includes the raw
`HashAlgId`, version, flags, culture, and public-key bytes, plus the Assembly
row offset in the metadata root and the #Blob index/payload offset. These
manifest-only source fields remain unset on `AssemblyRef` identities.

The Assembly table is limited to its one permitted row. The public-key blob is
validated against #Blob bounds and capped at 1 MiB before copying. The parser
retains `HashAlgId` as metadata; it does not hash referenced files, verify the
key/token relationship, authenticate the assembly, or make a publisher-trust
decision. A metadata root without an Assembly row remains a valid netmodule
and has no manifest identity.
