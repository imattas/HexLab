# First-class vector types

## Goal

Represent typed homogeneous integer and floating vectors in the immutable type
model, preserve them through serialization and ABI type recovery, and calculate
their size and alignment without degrading them to integers or arrays.

## Design

Add `Kind::vector` at the end of the enum so existing serialized kind numbers
stay stable. A vector owns one scalar lane type and a lane count; its total size
is derived with overflow checks. The factory accepts only complete integer or
floating lane types and a power-of-two alignment. The existing IR's
`ValueType` vector shape (`element_kind`, `element_bits`, `lanes`) is the source
for recovery. Opaque vectors without lane metadata remain unknown.

The type codec advances to version 5 while continuing to decode versions 1–4.
Formatting uses `vector<lane-type, lane-count>`. ABI slots explicitly marked
vector can infer arguments, and a configured vector return register can infer a
return type. Prototype constraints can carry vectors through incoming register
facts. Unsupported shapes retain diagnostics rather than inventing lane types.

## Boundaries

This increment does not add vector arithmetic semantics, vector ABI aggregate
classification, compiler header vector syntax, named vector aliases, or source
declarations. Vector memory and processor operations continue to be represented
by the existing IR semantics.

## Acceptance

- The type model validates lane types/count/alignment and checks size overflow.
- Encoding round-trips vectors with codec v5; v1–v4 records continue decoding.
- ABI recovery infers a concrete vector argument and return only when IR lane
  metadata or an explicit prototype supplies a supported shape.
- Focused type, layout, and decompiler type-recovery tests pass.
