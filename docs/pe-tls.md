# PE TLS metadata

The PE loader parses the TLS data directory for PE32 and PE32+ using its
architecture-specific 24-byte or 40-byte layout and 4-byte or 8-byte preferred
base VA fields. It retains the template start and end as a normalized RVA and
length, TLS index RVA, callback-array RVA, zero-fill count, characteristics,
callback targets, and original file spans for the directory and each callback
slot. The zero pointer terminating the callback array is retained as its own
source record.

The directory stores preferred-base virtual addresses. HexLab normalizes these
addresses to image RVAs in `PeTlsDirectory`, so the metadata remains stable when
loading an image at another base. Every nonzero VA is checked against the
preferred-base image range before subtraction; template end may equal the image
end, while start/index/callback-array locations must remain inside it. The raw
template extent and index must map to initialized image bytes. Callback targets
must resolve to initialized executable bytes, and malformed or unterminated
callback arrays make PE metadata partial with a diagnostic. HexLab describes
TLS data and does not execute callbacks or materialize per-thread TLS blocks.

CLI inspection prints the normalized template start/end, index and callback
array RVAs, zero-fill/characteristics, callback target RVA/VA rows, source file
offsets, and the terminator provenance. Callback display is capped at 4,096
rows; parsing retains its separate one-million-entry bound.

Regression coverage includes PE32 and PE32+, RVA normalization, callback order,
source provenance, truncated directories, unmapped arrays, and invalid callback
targets in `tests/loader_tests.cpp`.
