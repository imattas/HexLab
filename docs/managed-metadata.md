# Managed PE metadata inspection

`parse_cli_metadata` validates the CLR metadata root and ECMA-335 table extents.
The loader exposes type and method definitions and now also exposes FieldDef
rows through `parse_managed_fields`. Each returned `ManagedField` retains its
metadata token, flags, name, signature-blob index, and owning type name.

Field ownership follows each TypeDef's `FieldList`. Optimized `#~` metadata
uses FieldDef row order directly. Unoptimized `#-` metadata may include a
FieldPtr table; its indexes are validated for bounds and uniqueness and its
order is used when assigning fields to types. Invalid list boundaries, orphan
fields, duplicate pointers, inconsistent row layouts, truncated tables, and
unterminated or oversized names are reported as errors.

`parse_managed_generic_parameters` exposes each GenericParam row with its
metadata token, TypeDef or MethodDef owner token, ordinal, flags, optional name,
and TypeDef/TypeRef/TypeSpec constraint tokens. It validates coded-index tags,
owner and constraint row bounds, duplicate ordinals per owner, reserved flag
bits, and the GenericParamConstraint table layout. Generic parameter ordinals
above 1023 are rejected as a resource limit. Constraints remain metadata tokens;
they are not resolved to display names or evaluated as C++ types.

`parse_managed_types` attaches TypeDef-owned generic rows to each
`ManagedTypeDefinition`. `parse_managed_methods` attaches MethodDef-owned rows
to each method and copies its declaring type's generic rows alongside them.
The CLI exposes these catalogs through `project managed-types` and includes
generic parameter flags and constraint tokens in `project methods` output.
The method signature decoder also retains generic arity. Workspace persistence
does not yet materialize these metadata records as editable project types.

`parse_managed_types` also reads the [ECMA-335 `NestedClass` table](https://www.ecma-international.org/wp-content/uploads/ECMA-335_6th_edition_june_2012.pdf).
Each type
retains its enclosing TypeDef token, and `full_name` uses `Outer+Inner` nesting
notation (including chains of nested types). Invalid TypeDef indexes, duplicate
nested ownership, self-nesting, and cycles are rejected. Top-level names keep
their namespace qualification. `parse_managed_type_catalog` adds TypeRef and
TypeSpec rows while preserving their original tokens. TypeRef retains its
ResolutionScope token and coded value; nested TypeRefs form `Outer+Inner` names
with cycle checks. AssemblyRef and ModuleRef scopes retain their row identity
and display name as explicitly unresolved external identities. TypeSpec blobs
are parsed with the bounded signature grammar and TypeDefOrRef tags resolve to
full TypeDef, TypeRef, or TypeSpec tokens. Recursive TypeSpec graphs and invalid
tags or row indexes are rejected; this metadata catalog does not create
editable project types or resolve external assemblies. A null TypeRef scope is
also retained as unresolved.

`parse_managed_type_catalog` retains up to 250,000 ECMA-335 `ExportedType`
rows, including flags, `TypeDefId`, full names, and the original Implementation
coded index and token. Nested ExportedType rows form `Outer+Inner` names and
inherit the enclosing row's AssemblyRef identity. Invalid coded indexes,
out-of-range rows, empty names, duplicate exported full names, and nested
implementation cycles are errors. File implementations retain their metadata
token and remain unresolved; the loader does not open linked modules. An
AssemblyRef implementation binds only when its root row has the `Forwarder`
flag (`0x00200000`). Assembled full names are capped at 4,096 bytes.

The parser preserves field signature indexes but does not yet decode field
signature blobs into editable C++ project types or resolve custom attributes.
`parse_managed_fields` now decodes the supported ECMA-335 `FIELD` signature
subset into bounded `ManagedTypeSignature` trees and resolves local TypeDef,
TypeRef, and TypeSpec tokens against the same metadata catalog used for method
signatures. The `project fields` query prints the owner, flags, raw signature
index, and a readable type shape. Unsupported signature elements are reported
per field and make the query return partial status, so one custom-modifier or
otherwise unsupported field does not hide the rest of the catalog. Truncated,
malformed, or out-of-range blobs remain hard errors. This is inspection data;
it is not converted into editable workspace types, and external assembly or
module TypeRefs remain unresolved. Field catalogs are capped at 250,000 rows,
with 100,000 resolved signature nodes per catalog. Generic constraint records
retain their tokens; they are not attached to resolved catalog names or
semantically checked.

`ManagedTypeCatalog` now retains each catalog's Assembly identity and full
AssemblyRef identity, including version, culture, flags, and public-key bytes.
After parsing the set of assemblies in a workspace, callers can run
`bind_managed_type_references` across the catalogs. It binds a TypeRef only
when exactly one loaded catalog has an exact AssemblyRef identity match and
exactly one TypeDef has the requested full name. It can also follow an
ExportedType row with an AssemblyRef implementation through further supplied
catalogs, including nested names. Nested TypeRefs inherit the outer TypeRef's
assembly scope. Missing assemblies, duplicate loaded identities, duplicate
TypeDef/ExportedType names, File implementations, and forwarding cycles stay
unresolved with a reason in `unresolved_scope`. Binding is bounded by the
4,096-catalog limit and never searches disk or loads code. ModuleRef and null
TypeRef scopes remain unresolved. Public-key-to-token conversion and missing
assembly identities are not inferred.

`managed_type_is_assignable_across_catalogs` follows local TypeDef base and
interface edges plus uniquely bound external TypeRefs. It returns false when a
chain contains an unresolved reference or the bounded traversal cannot prove
the relation. Generic TypeSpec substitution and strong-name public-key-to-token
conversion are not inferred by this resolver.

Method-shaped `MemberRef` signatures now carry recursively substituted
`ManagedTypeSignature` trees when their TypeSpec owner resolves to an
arity-validated local TypeDef. Substitution walks
pointer/byref, array, generic-instantiation, and nested TypeSpec nodes, and
applies both owner `VAR` and MethodSpec `MVAR` argument vectors. An open
argument that has no corresponding supplied value remains a VAR/MVAR node.
External or unbound constructor identity, invalid arity, cyclic TypeSpec trees,
and exhausted traversal budgets never produce guessed substitutions.
