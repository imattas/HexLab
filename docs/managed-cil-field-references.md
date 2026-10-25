# Managed CIL field references

The managed loader now resolves field-shaped `MemberRef` rows alongside
`FieldDef` declarations. CIL `ldfld`, `stfld`, `ldsfld`, and `stsfld` can use
either token form when the owner and signature are present in the metadata.
Resolved owner names, field names, signature types, and the original metadata
token flow into the lifted field access and referenced-token list.

For a `MemberRef` whose parent is a closed generic `TypeSpec`, the loader
retains the parent's generic type arguments. The lifter substitutes those
arguments into `VAR` nodes in the field signature, so accesses such as
`Container<int>.Value` retain the concrete integer type. Open generic
variables without a closed owner remain unknown.

`MemberRef` metadata does not encode whether a field is static. For those
tokens, the opcode determines whether an object receiver is consumed. The
loader still validates staticness exactly for local `FieldDef` tokens, where
the flags are available. It does not guess staticness from field names or
external assemblies.

The parser is bounded to 250,000 `MemberRef` rows, 4,096-byte names, the
existing metadata heap and signature budgets, and the existing recursive
signature depth limit. Method-shaped `MemberRef` rows are skipped here and
continue through call-signature resolution. Invalid metadata indices,
truncated signatures, and unresolved owner identities fail with diagnostics.
This does not implement CLR field layout, reflection, or runtime field
resolution.
