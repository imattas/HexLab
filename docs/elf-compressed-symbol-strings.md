# Compressed ELF symbol string tables

Section-backed ELF `SHT_SYMTAB` and `SHT_DYNSYM` records can use a linked
`SHT_STRTAB` marked with `SHF_COMPRESSED`. The loader expands that string table
with its existing bounded ELF zlib section reader, then validates the
expanded table's leading and trailing NUL bytes and each referenced name
offset while decoding symbols. Symbol names retain their normal decoded text;
the symbol row continues to identify its original symbol table and record.

The compressed input and declared expanded string table both count against
the shared 64 MiB ELF metadata budget. The decompressed buffer remains owned
for as long as symbol rows are decoded, and cancellation is checked during
the read and inflate process. Invalid compression headers, unsupported
algorithms, malformed or trailing DEFLATE data, incorrect expanded sizes,
out-of-range name offsets, and unterminated names fail closed.

This support is limited to `SHF_COMPRESSED` string tables linked from
section-backed symbol tables. Compressed symbol record tables are still
skipped, and dynamic-tag-only symbol/string tables are not covered by this
path. GNU `.zdebug_*` section naming is intended for DWARF sections and is not
treated as an alternate symbol string table naming scheme. No compressed
byte-to-expanded-string offset mapping is exposed.
