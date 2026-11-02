# ELF GNU debug companion verification

`verify_elf_gnu_debuglink_crc` compares an explicitly supplied companion file
with the CRC retained from a parsed `.gnu_debuglink` section. It streams the
entire companion through the GNU debuglink CRC-32 algorithm in bounded 1 MiB
reads and defaults to a 512 MiB input cap. The result is `true` for a match and
`false` for a checksum mismatch; I/O, cancellation, and limit failures remain
errors.

The helper consumes the caller's `ByteStorage`. It does not use the section's
filename to access the filesystem or establish trust in the companion.
The checksum follows the documented
[GDB separate-debug-file format](https://sourceware.org/gdb/current/onlinedocs/gdb.html/Separate-Debug-Files.html).

## Local companion catalog

`discover_elf_debug_companions` in `hexlab/loaders/elf_debug_companions.hpp`
provides bounded, offline discovery and identity selection for ELF executable
and shared-object GNU separate-debug files. The caller supplies the primary's
parsed `ElfMetadata`, its corresponding filesystem path, and optional explicit
candidate files and debug directories. The API never imports or merges DWARF.

```text
hexlab_cli elf debug-companions ./sdk/usr/bin/app --sysroot ./sdk \
  --debug-dir ./sdk/usr/lib/debug --json
hexlab_cli elf debug-companions ./app --candidate ./symbols/app.debug
```

For a valid basename in `.gnu_debuglink`, the search checks the primary's
directory and its `.debug` subdirectory. Each supplied debug directory also
contributes the primary's mirrored directory followed by that basename. With
`--sysroot`, the mirrored path is relative to the canonical sysroot; the
primary must be inside it. Without a sysroot it is the physical absolute
parent with its filesystem root removed. Windows drive letters become a
one-letter directory as in GDB's documented layout; mirroring UNC inputs into
global debug roots requires a sysroot. For a primary GNU build ID of at least
two bytes, each supplied debug directory contributes `.build-id/xx/rest.debug`,
using lowercase hex bytes.
No ambient `/usr/lib/debug`, host environment, directory enumeration,
`debuginfod`, network, or recursive search is used. Explicit candidates may
have any filename; matching is based on retained identity metadata.

Every discovered candidate must canonicalize to a regular file within its
declared search directory. An explicit candidate is allowed outside those
directories. A primary file, including its hard-link aliases, cannot satisfy
its own companion query. Multiple
spelled paths to the same canonical file are inspected once; separate
canonical paths, including separate hard-link names, remain distinct.

The candidate ELF must match the primary's machine, class, byte order,
object type, `e_flags`, OSABI and ABI version. It must declare a nonempty,
file-backed ordinary DWARF info/type/line section or static symbol table.
These declarations are reported separately; their payloads are not imported
or validated as debug records by this catalog. All retained GNU build-ID notes
must agree, and IDs are bounded to 64 bytes. At most 4,096 build-ID notes or
primary debuglinks are accepted. Conflicting primary debuglink
identities reject the query. Whenever the primary declares a build ID, the
candidate must carry the exact ID. Whenever it declares a debuglink, the
candidate's entire content must have that CRC, even if discovered through a
build-ID directory. This intentionally requires all supplied identities to
agree. SHA-256 hashes before and after verification must also agree; a changing
file makes the search incomplete. Matching a CRC/build ID associates files
with the same declared build; it is not publisher or code-signature validation.

The report retains source kind, original and canonical paths, status, observed
size, build ID, and the SHA-256 of matched content. Missing paths, nonregular
files, incompatible/malformed ELF, missing/mismatched build IDs and CRC
mismatches are distinct outcomes. Filesystem errors, per-file size failures,
directory escapes and changing content mark the report incomplete. Exactly
one matching canonical file is selected only when the search is complete;
multiple matches remain ambiguous. The API returns the selected open storage
and digest for caller use, but they describe discovery-time content: a later
consumer must revalidate a mutable file before importing it.

Defaults allow 128 exact candidate paths, 16 supplied roots, 32 KiB per path,
1 MiB of aggregate path text, 512 MiB per inspected file, and 1 GiB of aggregate
distinct inspected file sizes. Each candidate's parsed ELF tables/notes use
the existing 64 MiB metadata allocation budget. Hashing/CRC perform a bounded
number of full-file passes. Limits are caller-configurable; candidates and
roots have hard ceilings of 4,096 and 128. Aggregate budget exhaustion is an
error rather than a truncated selection. Cancellation is checked throughout
the query, file hashing and CRC work.

CLI text and JSON output expose the same report. Exit 0 means one selected
identity match; exit 3 means no selection, including missing/ambiguous or
incomplete searches; argument, input and budget errors use exit 2. JSON paths
must be representable as UTF-8. `.gnu_debugaltlink` supplementary association,
external DWARF import, package-manager lookup and runtime debugger symbol
binding remain separate work.
