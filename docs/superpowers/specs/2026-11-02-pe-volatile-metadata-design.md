# PE volatile metadata inspection

The `loader.pe` residual explicitly leaves volatile metadata payloads opaque.
`pe_load_config.cpp` currently normalizes `VolatileMetadataPointer` at PE32
offset 160 / PE32+ offset 256, but exposes neither volatile instructions nor
the code ranges covered by the compiler's metadata. Complete this existing
load-config feature as source-backed inspection metadata.

## Approach and scope

Keep the existing pointer/source fields and append an optional decoded object
to `PeLoadConfiguration`. A focused `pe_volatile.cpp` parser follows the enclave
parser's optional-metadata diagnostic boundary. This keeps the large load-config
parser manageable and preserves unrelated load-config metadata on failure.
Alternatives were extending the monolithic parser, or adding runtime memory
ordering/emulator behavior; the former obscures bounds and the latter exceeds
the loader's inspection responsibility. Ongoing authorization selects this
bounded parser approach without another approval pause.

## Interfaces and files

- `libs/image/include/hexlab/image/pe_metadata.hpp`: additive
  `PeVolatileMetadataStatus`, `PeVolatileAccess`, `PeVolatileRange`,
  `PeVolatileMetadata`, and trailing `PeLoadConfiguration::volatile_metadata`.
  Existing aggregate members retain their order.
- `libs/loaders/src/pe_volatile.cpp`: internal
  `PeVolatileMetadata read_volatile_metadata(const Image&, const ImageMetadata&,
  std::uint64_t rva, std::stop_token)`.
- `libs/loaders/src/pe_internal.hpp`: declaration of that function.
- `libs/loaders/src/pe_load_config.cpp`: call the parser only for a complete,
  nonzero pointer field; include normalization in its diagnostic boundary.
- `libs/loaders/CMakeLists.txt`: compile the new source.
- `libs/loaders/docs/pe-volatile-metadata.md`: proof bounds and build record.
- `docs/pe-load-configuration.md`: link the detailed parser documentation.

## Contract and bounds

Read the 24-byte legacy header: DWORD Size, Version, access-table RVA and byte
size, range-table RVA and byte size. Support exactly raw Version == 1; preserve
other raw versions as unsupported, including newer min/max-version encodings.
Size must be at least 24 and at most 1 MiB; validate the full declared source
extent, but interpret only the known prefix. Header/table bytes must be mapped
and initialized. Tables contain DWORD instruction RVAs or pairs of DWORD code
RVA/size. Sizes must be exact multiples of 4 or 8. Enforce 16 MiB aggregate
table bytes and 1,000,000 aggregate rows before allocation. Empty tables do not
dereference their retained RVA; nonempty tables require a nonzero RVA.

Access RVAs must address initialized executable bytes. Nonempty code ranges
must fit the image and span only initialized executable mappings. Widen all
range arithmetic to 64 bits. Preserve input order, duplicates and overlaps:
these are an inventory, not an inferred ordering/uniqueness contract. Do not
require access rows to occur inside the range table.

Retain raw header fields, header/table source spans and each row's indexed
source. Publish both row vectors atomically after all validation succeeds.
Failures retain header/provenance already read, an explicit malformed,
unsupported or resource-limit status, and a diagnostic; cancellation propagates.
Invalid preferred-base pointers also become optional-object diagnostics instead
of discarding other load-config fields. Zero/absent pointers create no object.
No target code, memory-order enforcement, trust decision, hot-patch decoding,
UI, CLI or language-specific handler execution is added.

## Verification

Per session instruction, do not add or run tests. Build `hexlab_loaders` on
Windows MSVC and WSL Ubuntu with `BUILD_TESTING=OFF` and desktop disabled;
record exact commands, exit results and limitations. Review the complete diff
for bounds, cancellation, atomic publication and additive API compatibility.
