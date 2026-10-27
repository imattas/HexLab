# PE POGO function roots

Recognized PE POGO LTCG/PGU rows provide function-start and extent evidence to
function recovery. Each profile row is considered only when its nonzero range
maps entirely to initialized executable bytes and passes the ordinary code
exclusion and relocation checks. The root retains the profile index, source
row index, and bounded source file span in its function-seed provenance.

Repeated rows with the same start and extent retain one root. Conflicting
extents for a start and overlapping distinct POGO extents mark analysis
incomplete; their roots remain available, but the ambiguous sizes do not become
ownership boundaries. User-defined chunks and stronger unwind extents continue
to take precedence. POGO names are not imported as symbols by this path.

The loader's POGO parser bounds profile entries and validates their image
ranges. Function recovery rechecks the current mapped base and initialized
executable backing, so a stale or non-code profile row cannot claim code. See
[PE POGO debug records](pe-pogo.md) for the source format and retained fields.
