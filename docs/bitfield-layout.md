# Aggregate bitfield layout

HexLab stores bitfield facts as immutable member metadata. `Member::offset` is
the storage-unit byte offset, `bit_width` is the declared width, and
`bit_offset` is the least-significant-bit-relative position within that unit.
The layout engine may coalesce adjacent fields only when their source metadata
identifies the same storage unit. It does not infer a compiler from the machine
architecture: `Abi::x86_64`, for example, does not distinguish Microsoft x64
from the System V AMD64 ABI.

## Zero-width barriers

An unnamed bitfield with width zero is represented explicitly by an empty name,
`bit_width == 0`, and `bit_offset == 0`. It occupies no bits or bytes in the
resulting member layout. It ends the preceding bitfield allocation group and
aligns the following member to the barrier type's effective member alignment,
subject to the active packing cap. This keeps a useful barrier in the type graph
without pretending that the field has a storage extent.

This behavior is a generic recorded-layout rule, not a claim that all compiler
ABIs agree on the barrier's effect on aggregate alignment. Microsoft documents
that an unnamed zero-width field forces the next bitfield to a boundary of the
field's type. GCC documents allocation and alignment details as ABI-dependent;
the Itanium C++ ABI delegates ordinary bitfield allocation to the underlying C
psABI. A target ABI must therefore be known before synthesizing omitted offsets.

## Policy and limits

The current layout policy is **recorded metadata**. It honors field widths,
bit positions, offsets, and compiler-derived effective alignments that are
already present. It does not silently reinterpret those facts as Microsoft,
GCC, or Itanium layout. For unnamed nonzero-width fields, retain an empty name
and a positive width; their width still contributes to the recorded storage
unit. For a union, each member begins at byte zero and the aggregate extent is
the maximum member extent; zero-width barriers add no extent.

When the producer did not preserve enough metadata to establish a compiler's
allocation unit, bit order, zero-width-field effects, or union storage extent,
the caller should treat the computed layout as unknown instead of selecting a
compiler policy by architecture name. Future compiler-specific policies need
an explicit target/compiler selection and must reject unsupported or ambiguous
inputs rather than manufacture offsets.
