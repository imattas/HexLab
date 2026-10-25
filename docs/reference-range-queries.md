# Reference range queries

`ReferenceIndex` supports paged incoming and outgoing queries for a nonempty
virtual-address range. Incoming range queries return references whose numeric
target or resolved association falls inside the range. Outgoing range queries
return references whose source falls inside the range. Both include code,
data, relocation, import, user, and unresolved reference rows when their
address is in scope.

The public query uses a half-open interval `[begin, begin + size)`, rejects
zero-sized or overflowing ranges, and caps pages at 4096 rows. Outgoing rows
are returned in the index's deterministic source/operand/kind/identity order;
the range query iterates the existing source index and stores only the current
page. Numeric `Address` sources participate; file-offset-only relocation
sources are not included by a VA query.

For projects, `references --at va:<address> --direction outgoing --size N`
queries outgoing sources in the selected range. The existing `incoming`
direction with `--size` continues to query targets/associations. File-offset
locations cannot be used with `--size` because the CLI's range syntax is a VA
range. Exact-address queries remain available without `--size`.

The query operates on the same immutable reference index as exact incoming and
outgoing queries. It does not derive new references or change provenance; each
returned row retains its canonical identity, source, target, kind, access, and
provenance.

The immutable `ReferenceIndex` also exposes `incoming_file_range` and
`outgoing_file_range` for callers that work directly with file-backed
locations. They use the same half-open, nonempty, non-overflowing range rules
and 4096-row page cap. Incoming queries include file-offset targets and
associations; outgoing queries include file-offset sources. These direct
file-location queries do not translate between file offsets and virtual
addresses. Callers that need mapped bytes can use the image-aware variants
below.

# File-backed ranges across virtual mappings

`ReferenceIndex::incoming_mapped_file_range` and
`ReferenceIndex::outgoing_mapped_file_range` accept a file-offset interval and
also match virtual-address references backed by that interval in the supplied
image. Every matching segment is considered, including aliased mappings; a
reference that appears through multiple aliases is returned once in stable
reference-index order. File-only references continue to match directly. These
queries do not treat uninitialized segment tails as file-backed bytes.
The CLI exposes these queries with `--at file:<offset> --size N --mapped`;
without `--mapped`, a sized query remains a VA-range query.
The desktop References pane exposes the same mode with its `Address range`
and `Map file range` controls when the current location is a file offset in a
loaded image.
