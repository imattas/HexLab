# Mach-O two-level namespace hints

The loader decodes `LC_TWOLEVEL_HINTS` (0x16) in supported 32-bit and 64-bit
Mach-O slices, including big-endian images. The command must be exactly 16
bytes. Its table is a sequence of four-byte records wholly contained in the
selected slice, aligned to four bytes, and outside the Mach-O header and load
commands. Nonempty tables overlapping an active encryption declaration are
unsupported; ciphertext is never decoded as hints.

`MachOMetadata::two_level_hint_tables` retains each declaration's command index,
absolute command offset, slice-relative table offset, absolute table offset,
count, and first row in `two_level_hints`. Each hint retains its command/index
identity, absolute source offset, raw word, eight-bit sub-image index and
24-bit table-of-contents index. Bitfield placement follows the selected slice's
byte order, rather than the host compiler's C bitfield layout. Thin and
universal images use the same selected-slice bounds and absolute provenance.

Hints are associated with nlist entries only when the image has `MH_TWOLEVEL`,
there is exactly one hint command, one `LC_DYSYMTAB` and one `LC_SYMTAB`, the
dynamic undefined-symbol count matches the hint count, and every corresponding
nlist row is an external undefined or prebound-undefined symbol in that exact
table/index namespace. Association runs after all command payloads have been
read, so command order does not affect it. A table reports `symbols_associated`
and its dynamic-symbol command identity; associated rows retain their symbol
table command and symbol index. Missing, duplicated or inconsistent namespaces
retain the decoded hints without symbol associations and mark command metadata
incomplete. No partial prefix of associations is published.

The sub-image index is advisory: zero identifies the primary library, while
nonzero values refer to an ordered library sub-image. `LC_SUB_UMBRELLA` (0x13)
and `LC_SUB_LIBRARY` (0x15) are decoded into `MachOMetadata::sub_images` in
load-command order with command and file-offset provenance.

`LC_DYSYMTAB` contents (TOC) and module rows are decoded into the dynamic
symbol-table metadata. TOC rows retain symbol and module indices. Module rows
retain the nlist/reference/relocation/init-term ranges and ObjC module-info
size/address. The 32-bit module record stores the ObjC module-info address at
offset 44 and size at offset 48; the 64-bit record stores size at offset 44
and its 64-bit address at offset 48, matching Apple's [`dylib_module` and
`dylib_module_64` layouts](https://github.com/apple-oss-distributions/xnu/blob/main/EXTERNAL_HEADERS/mach-o/loader.h#L988-L1034).
Reads are bounded by the existing count, storage, file-extent, cancellation and
cumulative loader budgets. TOC symbol indices and module indices and module
ranges are validated against their declared tables.

`resolve_macho_two_level_hints` resolves an associated hint only against an
explicit caller-supplied provider keyed by the import library ordinal and
sub-image index. The provider must include a nonempty source string and parsed
metadata; results carry that provenance, TOC symbol and module indices, or a
conservative status such as missing/ambiguous provider, malformed provider
tables, invalid index, or name mismatch. Special ordinals, absent hint-symbol
associations and non-two-level images remain unresolved. This function does
not discover files, interpret runtime search paths, perform dyld rebinding,
prebind, or patch bytes. The caller is responsible for selecting the provider
file/sub-image matching the import library declaration.

Source bytes are never patched. Metadata is reparsed on image reopen and
participates in the existing tracked metadata-read set.

The aggregate hint count is capped at 1,000,000 across all declarations. Table
and row storage and a transient read window charge the loader's existing
cumulative 64 MiB budget. Reads are limited to 4,096 rows (16 KiB) at a time;
cancellation is checked while validating associations and decoding records.
Malformed extents/alignment/header overlap fail loading; excessive counts or
metadata use return a resource-limit error. The CLI's ordinary Mach-O
description prints declarations and at most 4,096 hint rows, with an omitted
row count.

The wire definition and advisory semantics follow Apple's
[`loader.h`](https://github.com/apple-oss-distributions/xnu/blob/main/EXTERNAL_HEADERS/mach-o/loader.h).
Endian-sensitive bitfield placement was cross-checked against Apple's
[`swap_twolevel_hint`](https://github.com/apple-oss-distributions/cctools/blob/main/libmacho/swap.c).

Validation for this increment is limited to fresh Windows MSVC Debug and
Ubuntu 24.04 WSL Clang Debug `hexlab_cli` builds with `BUILD_TESTING=OFF`, plus
source review and `git diff --check`. No tests, fixture execution, GUI session,
GitHub CI, or macOS runtime validation were performed.
