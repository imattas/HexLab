# Relocation-aware byte comparison

The comparison engine accepts caller-supplied ignored ranges on each
`RegionView`. A range uses a byte offset and size relative to the region, and
the spans must be sorted, non-overlapping, nonempty, and inside the bytes.
This lets a loader or analysis frontend suppress known relocation fields when
comparing rebased or relinked images.

For an aligned old/new byte pair, either side's ignored range suppresses the
pair from equal and changed counts and increments `Summary::ignored_bytes`.
Ignored bytes are not emitted as change runs. The total ignored-range count is
limited to one million per input image. A masked byte cannot participate in a
resynchronization anchor or its continuation evidence, which prevents a
relocation field from acting as a false byte-match anchor.

The comparison engine does not discover relocations; callers provide the
ranges. The desktop adapter and headless CLI build masks from recognized file-backed ELF
and Mach-O relocation fields, Mach-O dyld/chained and firmware-chained fixups, and x86/x64 PE base
relocations (HIGH, LOW, HIGHADJ, HIGHLOW, and DIR64). It uses validated field
sizes where the format supplies them, skips unsupported or incomplete field
records, maps only fully contained fields into a compared segment, merges
overlapping ranges, and cap collected fields at one million per input. Both
frontends apply the same relocation-kind exclusions and cancellation checks.
For i386 ELF, they also mask `R_386_SIZE32` only when the loader has validated
its four-byte field, decoded its implicit addend, and mapped it to an exact file
offset. Other symbol-size relocations remain visible, so the comparison does
not guess extents from unsupported or incomplete rows.
Matched region offsets pair by the comparison engine's existing bounded anchor algorithm; if
an insertion/deletion shifts a masked field before synchronization recovers,
callers should provide masks for both region sides according to their intended
byte alignment. Unsupported, runtime-only, or incomplete relocation metadata
may therefore leave some relocated bytes visible as ordinary changes. The
desktop summary/CSV and CLI text/JSON expose the ignored-byte count for review.

The ignored-byte total is stored in comparison session format version 11
(`HXCMPR11`). Versions 1 through 10 remain readable and default the new
counter to zero when that version predates the field.
