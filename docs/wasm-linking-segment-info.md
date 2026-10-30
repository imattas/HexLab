# WebAssembly object linking segment metadata

The Wasm loader parses version-2 `linking` custom sections' subsection 5
(`WASM_SEGMENT_INFO`) and subsection 8 (`WASM_SYMBOL_TABLE`). Segment rows retain their data-segment index from row order,
UTF-8 name, alignment exponent, flags, and source entry offset. Known flag bits
are shown as strings, TLS, and retain. The CLI displays at most 128 rows and
reports omissions.

The symbol-table inventory retains function, data, global, section, event, and
table symbol kinds, raw flags, object index, optional explicit name, inherited
import names, and entry provenance. Defined data symbols retain their segment
index, offset and size (or common size/alignment); regular extents are checked
against the selected data segment. Function/global/table indices are checked
against module index spaces and their undefined flags against import status.
The CLI displays at most 128 symbols and reports omissions.

The parser accepts up to 65,536 rows; names use the loader's existing per-name
and aggregate byte limits. Unknown subsections are skipped using their declared
extents. Unsupported versions, duplicate subsections, and malformed linking
payloads are ignored with informational diagnostics so optional custom metadata
does not invalidate the core Wasm module. A valid segment-info row count must
match the parsed data-segment count; a mismatch drops the segment metadata and
adds a diagnostic.

This is descriptive object metadata. HexLab does not apply relocations, resolve
symbols across modules, merge object files or data segments, or interpret
TLS/COMDAT behavior. Event indices and section-symbol targets are retained but
not validated against extension sections unsupported by the core Wasm loader.
The subsection layout follows the [WebAssembly tool-conventions linking
metadata](https://github.com/WebAssembly/tool-conventions/blob/main/Linking.md).
