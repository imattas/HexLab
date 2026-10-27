# PE POGO debug records

The PE debug-directory parser decodes `IMAGE_DEBUG_TYPE_POGO` records with the
recognized `LTCG` and `PGU\0` signatures. Each 4-byte-aligned row retains its
RVA, byte size, NUL-terminated name, and source file spans. The loader checks
record framing, name termination and alignment, aggregate count/name limits,
RVA arithmetic, and mapped image memory coverage for nonempty ranges. POGO rows
may describe code or data blocks, so they are not required to be executable.

CLI `inspect` prints the signature, row count, RVA, size, name, and source
offset, with separate 4,096-row caps for payload summaries and entries.
Unknown POGO signatures remain in the generic debug-directory metadata as
opaque payloads. This feature exposes compiler-supplied profile layout
metadata; it does not interpret profile
counters, reconstruct training data, rename symbols, or change analysis
priorities.

The signature and record layout follow the [Microsoft POGO overview](https://devblogs.microsoft.com/cppblog/pogo/)
and the [`IMAGE_DEBUG_TYPE_POGO` debug-directory entry](https://learn.microsoft.com/en-us/windows/win32/debug/pe-format#image-debug-directory).
