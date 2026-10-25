# Bounded live memory search

`hexlab/debugger/memory_search.hpp` exposes the portable `search_memory`
function and its pattern, options, report, and hex parser. `DebugSession` also
offers `search_memory(pattern, options, stop_token)`. Existing backend virtual
methods and inspection APIs are unchanged. The implementation uses only
`DebugSession::memory_regions()` and `read_memory()`, so native and remote
backends share the same matching and limits.

HexLab's debug server exports native maps and permission flags through RSP;
see [Remote memory maps](remote-memory-map.md) for negotiation, snapshots,
and transfer bounds. Remote servers that provide only standard `ram`/`rom`
types retain type-derived permissions and do not imply executable memory.

```cpp
#include <hexlab/debugger/debugger.hpp>

auto pattern = hexlab::debugger::parse_memory_search_pattern("48 8B ?? A? ?F");
if (!pattern) { /* report pattern.error() */ }
else {
    hexlab::debugger::MemorySearchOptions options;
    options.executable = true;
    options.ranges.push_back({0x140000000, 0x100000});
    options.alignment = 1;
    auto result = session.search_memory(pattern.value(), options);
    if (!result) { /* setup failed: report result.error() */ }
    else {
        const auto& report = result.value();
        // Consume report.matches; inspect report.complete(), completion,
        // failures, bytes_requested, bytes_read, and comparisons.
    }
}
```

## Patterns and address selection

Patterns contain 1–4096 bytes. An empty mask requests exact matching; an
equal-length mask compares `(actual & mask) == (expected & mask)` per byte.
Arbitrary bit masks and all-wildcard patterns are supported. The parser accepts
hex byte pairs with ASCII whitespace separators, case-insensitive digits, and
`?` in either nibble. It rejects empty text, partial pairs, missing separators,
invalid digits, more than 4096 bytes, and more than 16384 input characters.
Programmatic patterns are validated when searching.

Only readable mapped regions qualify. Optional `writable` and `executable`
filters each accept `true`, `false`, or either value. An empty range list selects
all qualifying maps; otherwise ranges intersect the maps. Ranges are half-open,
must be nonempty, and must not wrap. Invalid backend map ranges produce a setup
error. Empty backend regions are ignored. The exclusive-end representation,
consistent with session inspection, cannot include address `UINT64_MAX`.

Ranges and qualifying maps are sorted and coalesced before their intersection,
so results ascend without duplicate addresses even when inputs overlap.
Adjacent qualifying maps can contain a cross-boundary match. Matches cannot
cross a gap, excluded region, excluded caller range, or unread byte span.
Alignment applies to the absolute match address: `address % alignment == 0`.
Any nonzero alignment is accepted; it need not be a power of two.

## Chunking and budgets

Reads use bounded chunks with up to `pattern_length - 1` retained bytes.
Patterns can exceed the chunk size, and matches can overlap or span multiple
chunks. The scanner trims each interval to its first possible aligned match
and the end of its last possible match. Intervals too small for an aligned
match require no reads. It never retries a failed or short read.

| Option | Default | Accepted range |
| --- | --- | --- |
| `chunk_size` | 64 KiB | 1 byte–1 MiB |
| `max_bytes` | 64 MiB | 1 byte–1 GiB |
| `max_comparisons` | 64 Mi comparisons | 1–1 Gi comparisons |
| `max_results` | 4096 | 1–65536 |
| `max_read_failures` | 64 | 1–4096 |
| range count | 0 | 0–4096 |

The byte budget counts **requested** bytes, including failed reads and unread
suffixes of short reads. `bytes_read` counts successfully returned bytes.
`comparisons` counts masked byte comparisons, including wildcard bytes; its
independent budget bounds long-pattern work even on repeated/wildcard data.
`candidates_checked` counts fully decided candidate addresses; a mismatch is a
decided candidate, while interruption midway through a candidate is not.
`eligible_bytes` counts the normalized selected map union before alignment,
pattern-length trimming, or budgets. None of these counters implies complete
coverage on its own. Working buffers are bounded by two read chunks plus
pattern overlap; stored matches, failures, input ranges, and maps have separate caps.
The existing session map cap remains 65536 regions.

The result cap stops immediately when the configured number of matches is
recorded. `result_limit_reached` conservatively reports a partial result even
if that match would have been the final candidate. Byte and comparison caps
report exhaustion only if more work is required. A scan can finish completely
using exactly its configured budget.

## Completion, failures, and cancellation

Validation, inactive-session errors, map enumeration errors, and unsupported
map inspection return a `Result` error before scanning. A backend that supports
reads but cannot enumerate memory maps is explicitly unsupported; caller ranges
do not bypass permission checks or map enumeration.

After scanning begins, budget exhaustion, cancellation, read failures, and
oversized backend read responses return a report retaining the matches and
counters obtained so far. `complete()` is true only for `completed`.
`completed_with_read_failures` means all selected intervals were visited but
unread spans prevent complete coverage. Other completion values identify the
specific stop condition.

By default, a failed chunk records its requested range and original backend
error, clears overlap, and proceeds. A short successful read records an I/O
failure for the missing suffix; the returned prefix is searched and overlap is
then cleared. Reaching `max_read_failures` stops. With `stop_on_read_failure`,
the first failed or short read stops immediately, before searching that read's
returned prefix. An oversized read is a fatal backend protocol error and its
bytes are not searched or counted as successfully read. Failures already known
are retained even if a subsequent match/comparison limit interrupts scanning.

A `std::stop_token` is checked before map enumeration, after enumeration,
before each read, at least every 1024 byte comparisons, and at final completion.
It cannot interrupt a backend operation already in progress. This API is
synchronous, performs no writes or execution control, and requires callers to
serialize access to the session. Running-target searches observe live reads,
not an atomic snapshot: mappings or bytes may change between chunks. Stop the
target first when stable inspection is required. Software breakpoint bytes are
searched exactly as exposed by the backend's existing memory-read API.

## Verification scope

The feature is intended to be checked by compiling the debugger library. No
runtime tests were run for this change, as requested for this work batch.
