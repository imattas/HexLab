# PE dynamic value relocation metadata

The PE32 and PE32+ load-configuration parser now follows the
`DynamicValueRelocTable` preferred-base VA when that complete field is present.
For PE32+, the field is at load-config offset 192; the adjacent
`CHPEMetadataPointer` is at offset 200. PE32 keeps the corresponding fields at
offsets 120 and 124. Keeping these separate is required for hybrid images,
where both pointers may be present.
The loader normalizes it to an RVA, validates that the table and every record
are backed by initialized image bytes, and retains file provenance for the
table, record headers, optional version-2 header extensions, and fixup payloads.

Table versions 1 and 2 are structurally decoded. Version 1 records contain a
pointer-width symbol and a byte count for the following fixup payload. Version
2 records contain `HeaderSize`, `FixupInfoSize`, a pointer-width symbol, a
symbol group, flags, optional header extension bytes, and the bounded fixup
payload. The ARM64X symbol kind (6) is decoded into page blocks and individual
fixups. Each fixup retains its kind, argument bits, target RVA, affected width,
encoded source spans, and either replacement bytes or a scaled signed delta.
Zero-fill, value, and delta fixups are supported. Blocks require 4 KiB aligned
page RVAs and bounded 4-byte-multiple sizes; zero words are accepted only as
trailing block padding. Target extents are checked against the image size.
Other dynamic relocation symbol kinds remain opaque with a diagnostic.

Unknown table versions are retained with an `unsupported` status and a
diagnostic. Truncated headers, invalid record sizes, out-of-image references,
and incomplete record framing retain a `malformed` table model and diagnostic
without discarding the rest of load-configuration metadata. Table payloads are
capped at 16 MiB and record count at the shared one-million-record limit.

For a fully decoded table, HexLab applies the complete supported ARM64X fixup
set to `LoadedImage::pe_arm64x_image`, a separate effective-byte image view.
The canonical image remains unchanged. The view is built after any requested
PE base relocation, so DELTA reads the currently selected base view. Fixup
targets must be mapped and fully initialized in one file-backed segment;
overlapping virtual or file ranges, opaque dynamic-relocation records, and
unsupported ARM64X entries reject the whole view. ZERO_FILL writes zero bytes,
VALUE writes its decoded bytes, and DELTA adds its signed adjustment to an
initialized little-endian 32-bit value only when the result remains in range.
The table records application status, record/fixup indexes, and a diagnostic;
the fixup rows retain source-file provenance. The CLI reports that status and
the count applied.

Guard RF or function override records and section/offset fallback references
remain unsupported. Reserved ARM64X fixup types remain opaque and prevent view
creation.

## Selecting the process view

The loader now exposes `select_pe_runtime_view` and persists the requested
target in the PE load recipe. `--pe-runtime arm64` selects the classic ARM64
process view; `--pe-runtime x64-compatible` selects the x64/ARM64EC-compatible
process view. The latter retains the validated CHPE execution profile so AMD64
ranges decode as x64 and ARM64EC ranges decode as A64. The selected `Image`
shares the same address map and file provenance as the loader result while
reading bytes from the selected base or transformed overlay. The file's
`ImageMetadata` continues to describe the original PE headers and source rows.

The PE machine field identifies the default on-disk view: `AA64` is the classic
ARM64 view and `8664` is the x64-compatible view. Selecting the other view
requires the completely applied ARM64X fixup set and a validated nonempty CHPE
code map; otherwise selection returns an unsupported error rather than guessing
the instruction context. This selection models the two Windows-on-Arm process
families; it does not emulate the Windows loader's full conditional fixup,
Guard RF, or hybrid function override behavior. See Microsoft's
[`Arm64X PE files`](https://learn.microsoft.com/en-ca/windows/arm/arm64x-pe)
overview for the two process views and its [PE format documentation](https://learn.microsoft.com/en-us/windows/win32/debug/pe-format)
for load-configuration structures.

The field layout follows Microsoft's
[`IMAGE_LOAD_CONFIG_DIRECTORY32/64` and `IMAGE_DYNAMIC_RELOCATION` declarations](https://learn.microsoft.com/en-us/windows/win32/debug/pe-format#load-configuration-structure-image-only)
and the Windows SDK `winnt.h` declarations. Version framing was cross-checked
against LLVM's [`COFF.h` ARM64X relocation model](https://github.com/llvm/llvm-project/blob/main/llvm/include/llvm/Object/COFF.h)
and [`COFFObjectFile.cpp` dynamic-relocation reader](https://llvm.org/doxygen/COFFObjectFile_8cpp_source.html).
