# Managed PE metadata inspection

`parse_cli_metadata` validates the CLR metadata root and ECMA-335 table extents.
The loader exposes type and method definitions and now also exposes FieldDef
rows through `parse_managed_fields`. Each returned `ManagedField` retains its
metadata token, flags, name, signature-blob index, and owning type name.

Property declarations, ownership, signatures, defaults and accessor roles are
also exposed through `parse_managed_properties`, `inspect_managed_properties`
and the project `properties` CLI action. See [managed property metadata](managed-properties.md)
for exact supported tables, source offsets, limits and signature diagnostics.

Event declarations, EventMap/EventPtr ownership, TypeDefOrRef event type tokens,
and AddOn/RemoveOn/Fire/Other accessor associations are available through
`parse_managed_events`, `inspect_managed_events`, and the project `events`
action. See [managed event metadata](managed-events.md) for limits and
validation behavior.

ManifestResource names, visibility, implementation tokens, and bounded
embedded payloads are exposed by `parse_managed_resources` and
`inspect_managed_resources`; see [CLR resource metadata](managed-resources.md).

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
above 1023 are rejected as a resource limit. These records retain their
constraint tokens. `parse_managed_type_catalog` also adds resolved identities
to TypeDef-owned generic parameters: TypeDef and TypeRef constraints carry a
display name and scope, while TypeSpec constraints retain their resolved
signature tree. External TypeRefs remain explicitly unresolved until catalog
binding, which refreshes the associated identity. These identities preserve
metadata shape and scope; they are not evaluated as C++ types or checked for
constraint satisfaction. The catalog also retains MethodDef-owned generic
parameters with resolved constraint identities, and `parse_managed_methods`
attaches those records to methods. The standalone
`parse_managed_generic_parameters` API returns raw constraint tokens.

`parse_managed_methods` also attaches Param rows to each MethodDef. The
result preserves each Param token, sequence number, flags, and optional name;
sequence zero is the return parameter and positive sequences are one-based
signature parameters. Both optimized `#~` ordering and `#-` ParamPtr ordering
are honored. ParamList boundaries, pointer indexes, duplicate sequence
numbers, reserved flag bits, row layouts, and heap names are validated. This
exposes declaration metadata only. Param constants and FieldMarshal rows are
validated and attached to their owning parameter; parameter types still come
from the method signature.

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

The managed type and field catalogs retain ECMA-335 `ClassLayout` and
`FieldLayout` rows. Type definitions expose explicit packing size, declared
class size, and the metadata-root offset of the ClassLayout row; fields expose
their explicit field offset and FieldLayout row provenance. The
`project managed-types` and `project fields` summaries print these values when
present. Parent/index bounds, duplicate layout rows, sorted FieldLayout order,
row widths, and table extents are validated. This reports declarations only:
it does not compute runtime object sizes, infer implicit field offsets, or
validate architecture-specific layout behavior. A zero ClassLayout packing
value is retained as the CLR default marker.

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
with 100,000 resolved signature nodes per catalog. TypeDef- and
MethodDef-owned generic constraint records retain their tokens and expose
resolved identities, including full TypeSpec signature shape. Constraint
satisfaction is not evaluated.

`ManagedTypeCatalog` now retains each catalog's Assembly identity and full
AssemblyRef identity, including version, culture, flags, and public-key bytes.
After parsing the set of assemblies in a workspace, callers can run
`bind_managed_type_references` across the catalogs. It binds a TypeRef only
when exactly one loaded catalog has an exact AssemblyRef identity match and
exactly one TypeDef has the requested full name. It can also follow an
ExportedType row with an AssemblyRef implementation through further supplied
catalogs, including nested names. Nested TypeRefs inherit the outer TypeRef's
assembly scope. Identity matching accepts exact full-key or token bytes, and
compares a full key with its derived eight-byte SHA-1 public-key token when the
two catalogs store different representations, subject to 1 MiB per-key and
64 MiB aggregate key-processing caps plus a 16,000,000 identity-comparison cap;
other Assembly identity fields must still match.
Missing assemblies, duplicate loaded identities, duplicate
TypeDef/ExportedType names, File implementations, and forwarding cycles stay
unresolved with a reason in `unresolved_scope`. Binding is bounded by the
4,096-catalog limit and never searches disk or loads code. ModuleRef and null
TypeRef scopes remain unresolved. Missing assembly identities and oversized
public keys are not inferred or hashed.

When catalog binding succeeds, a TypeRef node inside a retained TypeSpec also
records the exact destination catalog index and TypeDef token, in addition to
its original source TypeRef token and display scope. This lets callers
distinguish identical names from different loaded assemblies without replacing
the original metadata identity. Binding revisits TypeSpec trees and validates
each `GENERICINST` arity against the uniquely resolved destination TypeDef;
known mismatches remain visible in metadata and are marked invalid, so a
consumer passing the signature to the CIL lifter keeps the resulting value
type unknown. An unresolved or ambiguous TypeRef does not
gain a guessed destination or arity proof. `VAR` and `MVAR` remain separate
ordinal spaces; substitution still requires an explicit declaring-type or
method argument context and leaves unbound variables open.

`managed_type_is_assignable_across_catalogs` follows local TypeDef base and
interface edges plus uniquely bound external TypeRefs. For closed generic
TypeSpec instances, it now substitutes the current constructed type arguments
for `VAR` nodes in TypeSpec base and interface edges, then compares the
resulting catalog-qualified TypeDef identity and argument shape. Closed generic
arguments are compared invariantly; generic variance and constraint satisfaction
are not inferred. Open `VAR`/`MVAR` values, unresolved or ambiguous references,
invalid arity, TypeSpec cycles, and array signatures with explicit bounds that
the current signature model does not retain cannot prove assignability and
return false, including when both arguments name the same open TypeSpec token.
Exact TypeSpec-token identity is accepted only after its signature resolves to a
closed constructed type; matching token values do not make open arguments
closed. The graph/signature work has fixed node and edge budgets.
Strong-name public-key-to-token conversion is not inferred by this resolver.

Method-shaped `MemberRef` signatures now carry recursively substituted
`ManagedTypeSignature` trees when their TypeSpec owner resolves to an
arity-validated local TypeDef. Substitution walks
pointer/byref, array, generic-instantiation, and nested TypeSpec nodes, and
applies both owner `VAR` and MethodSpec `MVAR` argument vectors. An open
argument that has no corresponding supplied value remains a VAR/MVAR node.
External or unbound constructor identity, invalid arity, cyclic TypeSpec trees,
and exhausted traversal budgets never produce guessed substitutions.

`parse_managed_user_strings` parses `#US` heap entries as UTF-16 code units,
keyed by the complete `0x70xxxxxx` metadata token. It validates the compressed
byte count, even UTF-16 payload length, and trailing kind byte; each string is
capped at 4 MiB. The CIL inspector resolves `ldstr` tokens against this catalog
for decompilation. The `project user-strings` query exposes the full catalog
from a loaded managed PE and prints each value as comma-separated four-digit
hexadecimal UTF-16 code units. This preserves embedded NULs and unpaired
surrogates exactly, without normalization or terminal decoding. A missing `#US`
stream is a valid empty catalog.

`parse_managed_constants` exposes bounded ECMA-335 Constant rows for Field,
Param and Property owners. Each result retains its Constant token, owner token,
blob index and element type. Integer, character, Boolean and IEEE floating-point
values retain their exact little-endian bits in `scalar_bits`; signed values
retain two's-complement bits without host conversions. String values retain
UTF-16 code units, including embedded NULs and unpaired surrogates, in
`string_value`. An ELEMENT_TYPE_CLASS value denotes null and must contain four
zero bytes. Both `#~` and `#-` tables and wide coded/blob indexes are supported.

The parser validates owner tags and row bounds, the owner's HasDefault flag,
unique ownership, zero padding, compressed blob extents, scalar widths, Boolean
values and even string byte counts. It caps the catalog at 250,000 rows, each
payload at 4 MiB and cumulative decoded payloads at 64 MiB, including repeated
references to the same blob. `parse_managed_fields` attaches Field constants as
`ManagedField::default_value`; `parse_managed_methods` attaches Param constants
as `ManagedParameter::default_value`, preserving return-parameter sequence zero
and ParamPtr ownership. Property constants are available through the standalone
catalog; property declarations attach them through `parse_managed_properties`.
Execution of default values is not inferred.
Constant payload types are retained as metadata and are not asserted compatible
with the owner's signature.

Field and parameter `FieldMarshal` rows are retained by
`parse_managed_marshal_descriptors` as raw `NativeType` bytes with parent token,
table offset, blob index and blob payload offset. The owner-aware field and
method catalogs also attach each row to its `ManagedField` or `ManagedParameter`
record, and the `project fields` and `project methods` queries show a compact
summary. The `project marshaling` query prints the full bounded catalog. Parser
validation and the deliberate opaque descriptor boundary are documented in
[CLR marshal metadata](managed-field-marshal.md).
