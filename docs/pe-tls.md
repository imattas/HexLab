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
callback arrays make PE metadata partial with a diagnostic. HexLab does not
execute callbacks or write a thread's TLS index slot.

`materialize_pe_tls_template` builds a caller-owned per-thread data block from
the initialized template bytes and the declared zero-fill tail. Its default
64 MiB limit can be overridden by the caller. It uses the selected image load
base while TLS RVAs stay normalized in metadata. The helper does not allocate
a thread environment block or execute TLS callbacks.

CLI inspection prints the normalized template start/end, index and callback
array RVAs, zero-fill/characteristics, callback target RVA/VA rows, source file
offsets, and the terminator provenance. Callback display is capped at 4,096
rows; parsing retains its separate one-million-entry bound.

Regression coverage includes PE32 and PE32+, RVA normalization, callback order,
source provenance, truncated directories, unmapped arrays, and invalid callback
targets in `tests/loader_tests.cpp`.

The TLS `Characteristics` field is retained, but the loader rejects bits outside the defined four-bit alignment field and rejects reserved alignment code 15. This prevents malformed directory flags from being presented as valid TLS metadata.
