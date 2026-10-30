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

In recorded-metadata mode the barrier uses its source-described byte offset
exactly. If that boundary precedes already occupied structure data, layout is
reported unsupported. In Microsoft mode an unnamed zero-width field ends the
active unit and aligns the next placement to the field type boundary. These
rules do not claim all compiler ABIs agree on aggregate alignment effects.
GCC documents allocation and alignment details as ABI-dependent; the Itanium
C++ ABI delegates ordinary bitfield allocation to the underlying C psABI. A
target ABI must therefore be known before synthesizing omitted offsets.

## Policy and limits

The current default layout policy is **recorded metadata**. It places each
bitfield at its recorded storage-unit byte offset and preserves its recorded
LSB-relative bit range and effective alignment. Fields with the same recorded
offset and storage-unit size share that unit. It does not silently reinterpret
those facts as Microsoft, GCC, or Itanium allocation. A recorded unit that
overlaps earlier occupied structure data is rejected as unsupported. For
unnamed nonzero-width fields, retain an empty name and a positive width; their
width still contributes to the recorded storage unit. For a union, each member
begins at byte zero and the aggregate extent is the maximum member extent;
zero-width barriers add no extent.

When the producer did not preserve enough metadata to establish a compiler's
allocation unit, bit order, zero-width-field effects, or union storage extent,
the caller should treat the computed layout as unknown instead of selecting a
compiler policy by architecture name. Future compiler-specific policies need
an explicit target/compiler selection and must reject unsupported or ambiguous
inputs rather than manufacture offsets.

## Explicit Microsoft allocation policy

Callers with Microsoft C/C++ provenance can opt into synthesized allocation
units with `LayoutOptions::bitfield_policy = BitfieldLayoutPolicy::microsoft`.
This policy uses the declared integer storage size, the active member alignment
and packing caps, and declaration order. Adjacent fields share an allocation
unit only when their storage sizes and effective alignments match and the next
field fits. Otherwise, the next field starts a new aligned unit. Bit positions
are assigned from least significant to most significant. A zero-width unnamed
field ends the active unit and aligns the following placement to its declared
type boundary. An ordinary member also ends the active unit. Union fields
remain at byte offset zero.

The selected `Abi` still controls pointer width and general aggregate alignment;
it does not imply Microsoft bitfield behavior. This opt-in implementation
supports 1-, 2-, and 4-byte allocation units and returns `unsupported` for
larger units rather than guessing their compiler layout. It does not model
Microsoft C++ non-trivial class rules or compiler versions. The allocation
rules follow Microsoft's published [C bitfield storage and alignment](https://learn.microsoft.com/en-us/cpp/c-language/padding-and-alignment-of-structure-members?view=msvc-170)
and [C++ bitfield](https://learn.microsoft.com/en-us/cpp/cpp/cpp-bit-fields?view=msvc-170)
documentation.

## Explicit Itanium-family allocation policy

Callers with Itanium C++ ABI provenance can select
`LayoutOptions::bitfield_policy = BitfieldLayoutPolicy::itanium`. The policy
uses each declared integral type's storage size and effective member
alignment, places fields in declaration order, shares a unit only for matching
size/alignment when the next field fits, and numbers bits from least
significant to most significant. A zero-width unnamed field closes the unit
and aligns the next placement; an ordinary member also closes it. Union fields
start at byte zero. This gives callers synthesized coordinates for the common
fixed-width integral cases while retaining width, offset and alignment in each
`MemberLayout`.

The implementation supports 1-, 2-, 4- and 8-byte units. It does not infer the
underlying psABI's target-specific exceptions, mixed-base allocation behavior,
or endian-specific bit numbering. The Itanium C++ ABI delegates ordinary
allocation to the platform C ABI, so this policy is deliberately a bounded
common subset and must be selected only when the caller has compiler/target
provenance. Recorded importer coordinates remain the default and preserve the
producer's exact bit positions.
