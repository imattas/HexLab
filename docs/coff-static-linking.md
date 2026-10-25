# COFF archive linking to static PE32+

`hexlab_cli archive link-pe` and the generic `link_coff_executable` API now
select AMD64 or ARM64 from the root/input machine. Selected inputs must be
homogeneous. The CLI considers only archive members with the root's machine,
so a same-named definition from another architecture cannot satisfy an external.
The existing `link_coff_amd64_executable` API remains AMD64-only. The ARM64
subset and pending validation are detailed in
[ARM64 COFF static linking](coff-arm64-static-linking.md).

## AMD64 input and runtime metadata

`hexlab_cli archive link-pe <archive.lib> --root-object <root.obj> --entry <symbol> --output <image.exe>` performs fixed-point archive-member selection from COFF external definitions and unresolved externals, then emits an AMD64 PE32+ console image. The archive may be an ordinary `ar` container with regular COFF, BigObj, or Microsoft import-object members; selection is deterministic in archive order and does not require a symbol index. BigObj members use the 32-bit section-number and 20-byte symbol layouts. AMD64 import/short-import members expose their public code symbol and `__imp_` symbol (or only the `__imp_` symbol for imported data) to selection and link into the image.

The linker accepts regular AMD64 COFF objects with initialized `.text`, `.rdata`, `.data`, `.pdata`, and `.xdata` sections plus uninitialized `.bss`. Long section names from the COFF string table are bounded to 4096 bytes; `$` subsections merge into their corresponding output section in deterministic object/section order, honoring encoded COFF section alignment. `.rdata`, `.pdata`, and `.xdata` are emitted as separate read-only PE sections. Initialized sections can carry `IMAGE_REL_AMD64_ADDR64`, `ADDR32`, `ADDR32NB`, and `REL32` through `REL32_5` relocations to symbols in any supported output section.

AMD64 `.pdata` contributions must contain whole 12-byte `RUNTIME_FUNCTION` records and use DWORD alignment. The linker applies `ADDR32NB` relocations, verifies that function ranges lie inside linked `.text`, that unwind RVAs lie inside DWORD-aligned `.xdata`, and that each referenced version-1 `UNWIND_INFO` header and its code/handler or chained tail fit. Chained records are checked against the complete merged `.pdata` table and must copy an existing `RUNTIME_FUNCTION` tuple. It sorts the merged runtime-function table by begin RVA, rejects overlapping functions, and writes the PE32+ exception-directory RVA and size. Because sorting can move records, references to symbols inside `.pdata` are rejected. Language-specific handler payloads remain opaque; the linker does not interpret C++ or SEH scope tables.

The emitted table follows Microsoft's AMD64 PE exception-table layout: each entry has begin/end/unwind RVAs, entries are sorted by function address, and the PE exception data-directory entry identifies `.pdata`. The linked image is still fixed-base; the supported `ADDR32NB` references are image-relative and need no load-time base relocation.

COMDAT section definitions are read from bounded 18-byte COFF auxiliary rows. The linker requires a matching section symbol and the following external symbol as the COMDAT key. It supports `NODUPLICATES` (reject a repeated key), `ANY` (first input/section wins), `SAME_SIZE` (require equal sizes, then first wins), `EXACT_MATCH` (require equal bytes and relocation records resolving to the same named external or same local section/name/offset, then first wins), and `LARGEST` (greatest size wins, first wins ties). `ASSOCIATIVE` sections are retained only when their parent chain reaches a selected non-associative COMDAT; invalid parents and cycles fail. Losing section contents and relocations are omitted. Relocations to external definitions in discarded sections bind through the selected definition of the same name; a kept relocation to a discarded local symbol fails. Unsupported selection values, including `NEWEST`, inconsistent selection modes, ambiguous duplicate definitions, and unresolved references fail explicitly.

It emits a PE32+ image at fixed base `0x140000000`, with import tables only for selected supported AMD64 short-import members. CRT startup, base relocations, and TLS metadata are not emitted. The root entry must resolve to an external symbol definition. Output section sizes, PE32+ RVAs, alignment arithmetic, input objects, symbols, relocations, and names are bounded. This is useful for freestanding entry points and inspection of static links, but it is not a replacement for `link.exe` or `lld-link` for ordinary Windows applications.

External common symbols (section zero with a nonzero size) coalesce by name into zero-filled `.bss`, taking the maximum requested size and natural alignment capped at 32 bytes. Selected strong section definitions take precedence. A common colliding with an absolute definition fails explicitly because absolute-symbol linking is unsupported. Archive summaries treat commons as definitions for member selection and accept inline symbol names occupying all eight bytes.

The writer emits a grouped import descriptor table, lookup tables, writable `.idata` IAT slots, and the PE import and IAT data directories. Import-by-name entries preserve hints and support `NAME`, `NOPREFIX`, `UNDECORATE`, and `EXPORTAS`; ordinal entries use the PE64 ordinal flag. Imported code symbols receive an AMD64 `jmp [rip+disp32]` thunk, while imported data/const references resolve through `__imp_` IAT symbols. Only version-0 AMD64 short-import records are accepted. Other import architectures and import variants, including delay imports, are unsupported. Absolute symbols, debug data, TLS, base relocations, `NEWEST` COMDAT selection, ARM64 unwind metadata, unwind versions other than version 1, and other relocation kinds remain unsupported. Unsupported allocated input sections and unresolved strong externals fail the link. Output and parser work are bounded by `CoffLinkLimits` and the existing archive limits.

Format references: [Microsoft's x64 exception handling documentation](https://learn.microsoft.com/en-us/cpp/build/exception-handling-x64) and [PE format documentation](https://learn.microsoft.com/en-us/windows/win32/debug/pe-format).

The shared PE header writer now places `SizeOfImage` at PE32+ optional-header
offset 56 and leaves the checksum field at offset 64 zero. Previously the image
size was placed in the checksum field. This correction applies to both machines;
AMD64 relocation, COMDAT, import and unwind behavior remains on its existing path.
