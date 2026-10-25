# Live process memory search

`hexlab::debugger::search_memory` searches readable regions in the active
debug session. It accepts exact bytes and nibble masks, for example `48 8B ??
A? ?F`. A mask bit set to one must match the corresponding pattern bit. An
all-wildcard pattern is allowed.

Callers can restrict the scan to half-open address ranges and to mappings with
specific writable or executable permissions. Overlapping and adjacent ranges
are coalesced. Reads are clipped to eligible mappings, and matches crossing a
read chunk boundary are retained. Match alignment is measured from the target
address space, not from each selected range.

The operation is synchronous and read-only. It requires an active process and
memory-map support, and callers must serialize access to the session. A stop
token can cancel between backend reads; it cannot interrupt a backend call
already in progress. The report retains partial matches, byte/comparison
counters, and read-failure details when canceled or when a configured budget
is reached.

Input, range, result, read-failure, and total work limits are explicit in
`memory_search.hpp`. Invalid patterns/options fail before scanning. Read
failures can be accumulated up to a caller limit or made immediately fatal.
Protocol errors remain distinguishable from ordinary unmapped or unreadable
regions.
