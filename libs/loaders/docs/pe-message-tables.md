# PE message-table resources

`hexlab/loaders/pe_messages.hpp` exposes `inspect_pe_message_table(loaded,
resource_index, stop, limits)` and `find_pe_message(table, message_id)` for
numeric RT_MESSAGETABLE (11) resources inventoried by `load_pe`.

```cpp
#include <hexlab/loaders/pe_messages.hpp>

// image is a successful LoadedImage from load_pe; choose an explicit resource.
auto table = hexlab::inspect_pe_message_table(image, resource_index);
if (table) {
    if (const auto *message = hexlab::find_pe_message(table.value(), 0xc0000001u)) {
        // message->text contains UTF-8 for a Unicode entry.
        // message->ansi_bytes contains original bytes for an ANSI entry.
    }
}
```

The selected resource's name, language, and code page are retained. Selection
is explicit: callers choose the resource index from `metadata.pe->resources`;
the reader does not emulate Windows language fallback. Name and language
identifier values are copied; their name provenance remains on the original
resource. Blocks retain their original order, inclusive message ID range, and
payload-relative entry offset. Message rows retain the ID, block index,
payload-relative offset, raw flags, and declared entry length. Each block and
entry has file source spans, including entries that cross mapped sections.
Entry source spans include the header, terminator, and producer padding.

Flag 1 entries are strictly decoded from UTF-16LE to UTF-8, including paired
surrogates. Flag 0 entries retain bytes up to the first NUL; the API does not
assume the host locale or convert unspecified legacy code pages. Unicode text
also stops at its first NUL. Bytes following the terminator inside the declared
entry length are treated as opaque padding. Empty terminated messages are
valid. Formatting inserts such as `%1`, message escapes, and line endings are
preserved; no `FormatMessage` execution or argument expansion takes place.

Default bounds are 4096 blocks, 100,000 messages, 16 MiB payload, and 64 MiB
metadata. The metadata budget conservatively charges the input buffer, decoded
row storage, names, source spans, temporary range arrays, and maximum UTF-8
string capacity. The reader checks payload extent before allocation and uses
the existing initialized PE image reader: zero-fill bytes cannot satisfy a
message-table read. Cancellation is checked before reading and during every
block and message. Allocation failures become resource-limit errors.

Truncated headers, reversed or overlapping ID ranges, entries overlapping the
block directory, overlapping entry blocks, invalid entry lengths, missing
terminators, and malformed UTF-16 return a malformed error. Unknown flags
return unsupported. Limits return resource-limit errors. No partial table is
returned on failure. Unsorted nonoverlapping blocks and gaps between entry
blocks are accepted. Lookup returns a table-owned pointer or `nullptr` for an
absent ID; it does not mutate or reload the PE image.

This is an explicit supplementary loader API; normal `load_pe` does not eagerly
decode message payloads. It works on supported Windows and Linux hosts without
Windows SDK parsing services. No desktop or CLI presentation is added.

Format references: Microsoft's
[MESSAGE_RESOURCE_DATA](https://learn.microsoft.com/en-us/windows/win32/api/winnt/ns-winnt-message_resource_data),
[MESSAGE_RESOURCE_BLOCK](https://learn.microsoft.com/en-us/windows/win32/api/winnt/ns-winnt-message_resource_block), and
[MESSAGE_RESOURCE_ENTRY](https://learn.microsoft.com/en-us/windows/win32/api/winnt/ns-winnt-message_resource_entry).

Validation: Windows Debug MSVC 19.44 `hexlab_loaders` build passed with
`BUILD_TESTING=OFF`. A WSL Ubuntu 24.04 Clang 18.1.3 full loader build was
started with tests disabled; its result remains pending/unverified.
No tests were added or run.
