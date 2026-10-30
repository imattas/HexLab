# Intel Firmware Interface Table inventory

Use the firmware inspection command with an explicit file offset:

```text
hexlab_cli firmware inspect firmware.bin --fit-offset 0x100000 --format fit
```

The offset points to the `_FIT_   ` header within the complete input file.
The parser inventories bounded 16-byte records, retaining type, address, size
in 16-byte units, version, per-entry checksum flag/value, and file provenance.
It reports entry-type ordering and validates the table checksum only when the
header requests one.

The FIT pointer is not discovered automatically. Component addresses are not
mapped to file extents and entry payload checksums are not evaluated. The
inventory does not load or execute components. Input is capped at 512 MiB,
tables at 16 MiB and one million entries. See [firmware format inspection](firmware-formats.md).
