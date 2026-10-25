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

The API does not discover relocations. Callers must translate relocation
records to region-relative byte ranges and decide which relocation kinds are
safe to omit. Matched region offsets still pair by the comparison engine's
existing bounded anchor algorithm; if an insertion/deletion shifts a masked
field before synchronization recovers, callers should provide masks for both
region sides according to their intended byte alignment.

The ignored-byte total is stored in comparison session format version 6
(`HXCMPR6`). Versions 1 through 5 remain readable and default the new counter
to zero.
