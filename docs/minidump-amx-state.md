# Minidump classic AMX state

AMD64 contexts with `CONTEXT_XSTATE` can retain named AMX metadata from the
validated MiscInfo5 feature map. Standard XSAVE component 17 must be exactly
64 bytes and component 18 exactly 8,192 bytes. Each interpreted component must
start after the legacy XSAVE area and full header (XSAVE-relative offset 576),
fit the mapped XSTATE size and captured context, and not overlap another mapped
extended component. Compacted XSAVE payloads remain unsupported.

TILECFG recognizes only palette 0 (all 64 bytes zero) and the classic palette 1.
Palette 1 checks reserved bytes, eight tile dimensions with at most 16 rows and
64 column bytes, and matching zero/nonzero row and column counts. The complete
configuration is retained as four 128-bit `amx_tilecfg_partN` rows. Named aliases
retain `amx_palette_id`, `amx_start_row`, and palette 1 `tmmN_colsb` / `tmmN_rows`.
`start_row` is preserved as an eight-bit storage value; restart correctness and
instruction progress are not validated. Future palettes, enlarged components,
invalid reserved/dimension fields and overlapping mappings retain opaque chunks
and a diagnostic instead of receiving named interpretations.

TILEDATA is interpreted only when a fully captured, structurally valid palette 1
TILECFG is also present and in use, independently of feature table ordering.
Its eight 1,024-byte tile storage images become 16 rows of four 128-bit parts
per tile, named `tmmN_rowR_partP`. All 8,192 bytes are retained, including storage
outside the configured active dimensions. No element type, matrix arithmetic,
inactive-byte zeroing or synthesized initial state is inferred. A missing,
initial, unknown or invalid configuration leaves TILEDATA opaque.

Each named row carries its exact original dump-file offset, bytes and bit width.
The CLI's existing context formatter prints the rows; the desktop's existing
128-register display cap can omit later tile rows. The loader's existing
64 KiB aggregate XSTATE retention cap, fixed-prefix-plus-64-KiB capture bound
and 4,096-context decode limit still apply. Source ranges outside those bounds
are omitted with diagnostics. No host CPUID query, execution, register restore,
ARM64EC overlay decoding or compacted-layout interpretation is performed.

The layout follows Intel's [AMX configuration example](https://www.intel.com/content/www/us/en/developer/articles/code-sample/advanced-matrix-extensions-intrinsics-functions.html),
the [Intel AMX palette enumeration](https://github.com/intel/Intel-AMX-Detection/blob/main/amx_detection.c),
and the architectural XSAVE component definitions in the
[Intel Software Developer's Manual](https://cdrdv2-public.intel.com/868137/325462-089-sdm-vol-1-2abcd-3abcd-4.pdf).
