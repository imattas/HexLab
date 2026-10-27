# PE string-table resources

The PE resource parser decodes numeric `RT_STRING` (`type ID 6`) resources as
bounded blocks of sixteen UTF-16LE entries. For resource block ID `n`, entry
index `i` receives string ID `(n - 1) * 16 + i`. Empty entries are retained;
each row carries source spans for its length word and encoded characters. CLI
inspection prints the block, language, string ID, UTF-8 value, and source file
offset. The desktop Resources table summarizes decoded `RT_STRING` and
version-resource text together.

Parsing is capped at 1 MiB per block, 16 MiB of `RT_STRING` bytes per image,
and 65,536 retained entries per image. UTF-16 surrogate pairs are validated.
Truncated strings, invalid surrogate sequences, excess table bytes, or limits
leave the resource inventory usable and mark that string table incomplete;
valid earlier entries are retained. CLI output is limited to 256 tables and
4,096 strings. This decoder does not interpret accelerator, menu, dialog, or
other resource formats, and does not treat string text as trusted content.
