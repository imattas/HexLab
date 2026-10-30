# CLR generic parameter metadata

`parse_managed_generic_parameters` returns `GenericParam` rows with their
owner token, ordinal, validated variance/special-constraint flags, name, and
metadata-root row offset. Each `GenericParamConstraint` contributes its
validated TypeDef/TypeRef/TypeSpec token and a parallel metadata-root row
offset. The CLI reports both row locations with the existing variance,
reference-type, value-type, default-constructor, and constraint-token summary.

The parser caps the metadata root at the existing 64 MiB limit, GenericParam
rows at 250,000, GenericParamConstraint rows at 1,000,000, generic parameter
ordinals at 1,023, and aggregate parameter-name bytes at 8 MiB. It rejects
duplicate owner/ordinal pairs, reserved flag bits, invalid owner/type indexes,
and malformed row layouts.

Constraint tokens preserve metadata identity; they do not prove a runtime type
satisfies the constraint or imply a method implementation/dispatch relation.
External TypeRefs remain scoped or unresolved according to the type catalog,
and constraint satisfaction is not evaluated by this row parser.
