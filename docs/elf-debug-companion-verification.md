# ELF GNU debug companion verification

`verify_elf_gnu_debuglink_crc` compares an explicitly supplied companion file
with the CRC retained from a parsed `.gnu_debuglink` section. It streams the
entire companion through the GNU debuglink CRC-32 algorithm in bounded 1 MiB
reads and defaults to a 512 MiB input cap. The result is `true` for a match and
`false` for a checksum mismatch; I/O, cancellation, and limit failures remain
errors.

The helper consumes the caller's `ByteStorage`. It does not use the section's
filename to access the filesystem, discover sidecars, or establish trust in
the companion. `.gnu_debugaltlink` build-ID comparison and importing external
DWARF sections remain separate work. The checksum follows the documented
[GDB separate-debug-file format](https://sourceware.org/gdb/current/onlinedocs/gdb.html/Separate-Debug-Files.html).
