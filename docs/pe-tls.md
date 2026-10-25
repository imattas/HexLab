# PE TLS metadata

The PE loader parses the TLS data directory for PE32 and PE32+. It retains the
template extent, TLS index location, zero-fill count, characteristics, callback
array location, callback targets, and original file spans for the directory and
each callback slot. The zero pointer terminating the callback array is retained
as its own source record.

The directory stores preferred-base virtual addresses. HexLab normalizes these
addresses to image RVAs in `PeTlsDirectory`, so the metadata remains stable when
loading an image at another base. Callback targets must resolve to initialized
executable bytes. The template and index must resolve to initialized image
bytes, and malformed or unterminated callback arrays make PE metadata partial
with a diagnostic. HexLab describes TLS data and does not execute callbacks or
materialize per-thread TLS blocks.

Regression coverage includes PE32 and PE32+, RVA normalization, callback order,
source provenance, truncated directories, unmapped arrays, and invalid callback
targets in `tests/loader_tests.cpp`.
