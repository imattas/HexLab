# Managed custom-attribute fixed values

## Goal

Decode common CLR custom-attribute constructor arguments into inert typed
records so static inspection can show attribute metadata without constructing
attribute objects or executing user code.

## Scope

- Retain the existing raw serialized blob as authoritative provenance.
- Decode bounded fixed arguments whose constructor signature uses primitive,
  string, or one-dimensional arrays of those types.
- Validate exact widths, Boolean encodings, SerString extents/UTF-8, array
  counts and the trailing named-argument count.
- Keep named arguments, enum/custom types, boxed/object values and unsupported
  signatures opaque with a status and diagnostic.
- Expose records through `project custom-attributes` in text output.

No attribute constructor is invoked and no custom type is instantiated.
Property named-argument values and enum-underlying-type resolution remain
unimplemented.

## Bounds

- At most 250,000 attribute rows and 4 MiB per existing serialized blob.
- At most 1,000,000 decoded values total, array count 65,536 per value, array
  nesting depth 16, and 1 MiB per decoded string.
