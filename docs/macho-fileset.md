# Mach-O fileset entry inventory

The loader recognizes `LC_FILESET_ENTRY` (`0x35`) in a 64-bit `MH_FILESET`
parent and records its command index, entry identifier, VM address, and
slice-relative file offset. For each entry it validates the embedded 64-bit
Mach-O header and walks the declared child load-command envelopes. This
provides a bounded inventory of the images declared in a kernel collection or
other fileset without treating child offsets as offsets in the outer file.

The CLI reports bounded child `LC_UUID` values and `LC_SEGMENT_64` declarations
for each entry. Segment rows retain VM and raw file extents, section counts,
protection bits, and the absolute source command offset. A file offset is
reported as mapped only when the declared initialized extent fits inside the
selected containing slice; an invalid extent marks the child command inventory
incomplete. These records help distinguish kernel-collection components and
inspect their declared memory layout without treating them as loaded parent
segments.

Validation checks the entry string is terminated inside its load command,
reserved bits are zero, child header and command extents remain within the
selected slice, and the exact command count consumes `sizeofcmds`. The child
must have the same CPU type and subtype as its parent for the inventory row to
be marked valid. Duplicate entry identifiers, file offsets, or VM addresses
make command metadata incomplete while preserving the bounded rows for
inspection. Parsing remains subject to the loader's 64 MiB metadata budget and
checks cancellation while walking child commands.

This is declaration inventory and structural validation only. The loader does
not map child segments, parse child sections or symbols, dependencies, exports, fixups,
unwind data, or recursively nested filesets, and it does not resolve addresses
between entries. Those child images are not yet independently navigable as
loaded images. Universal-container selection continues to apply to the outer
slice; fileset offsets are interpreted relative to that selected slice.
