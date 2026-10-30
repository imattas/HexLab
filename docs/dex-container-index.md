# DEX 041 container index

`inspect_dex041_container` walks the logical-header chain in a physical DEX
041 container. It validates the fixed 0x78-byte header, magic, endianness,
container size, header offset, and each logical member extent, then returns the
header offset, logical size, checksum, and stored signature for every member.
The walk is cancellation-aware and bounded to 512 MiB and one million members.

Structural inventory is exposed as `hexlab_cli dex container <path>`;
`--json` emits the member rows as machine-readable JSON. Output includes the
physical header offset, declared logical size, checksum, and signature for
each member. Malformed input exits with a nonzero status and a diagnostic.

`load_dex041_container` parses every member into its own `LoadedImage`, while
each image keeps the original container as its byte source so code ranges and
shared later data retain physical offsets. It checks the aggregate identifier
row count across the container against the existing one-million-row parser
budget and limits full loading to 256 members. Container-wide loading limits
are exact: physical input and the sum of logical member extents are each at
most 512 MiB (the member extents must cover the input exactly); aggregate
fixed identifier rows are at most 1,000,000; summed map section counts and
retained metadata rows, including nested encoded values, are each at most
2,000,000; decoded DEX string capacities are at most 64 MiB; the summed
`DexMetadata` vector capacities plus decoded string capacities are at most
256 MiB; and class definitions,
interfaces, and declared fields/methods together are at most 1,000,000 rows.
All members share the single physical container source rather than copying a
member-sized backing buffer. The CLI command
`hexlab_cli dex load-container <path>` reports classes,
method identifiers and code items parsed per logical member; `--json` emits
the same summary as JSON. The generic one-image `load_dex` interface continues
to reject multi-member containers and directs callers to the container API.

The member parser validates the DEX 041 header offset against the requested
member and accepts physical offset ranges through the container end, allowing
references to later shared data. It still only models metadata represented by
the current loader, and does not resolve external types or run the Android
verifier. The container fields and offset rules follow the [Android DEX format
documentation](https://source.android.com/docs/core/runtime/dex-format).

## VDEX 027 inventory

`hexlab_cli dex vdex <path> [--json]` inventories the sectioned Android VDEX
027 layout. It validates section-table extents and alignment, lists section
kinds, and walks concatenated DEX 035–040 members from the DEX section. Each
member retains its source offset, file size, header checksum and matching
VDEX checksum word. Verifier-dependency and type-lookup sections remain opaque;
the command does not run verification, optimize DEX, or execute code. Other
VDEX versions are rejected instead of being interpreted as this layout.
