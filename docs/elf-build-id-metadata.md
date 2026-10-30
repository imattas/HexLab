# GNU ELF Build ID metadata

ELF note parsing preserves every note in `ElfMetadata::notes` and additionally
exposes notes whose owner is `GNU` and whose type is `NT_GNU_BUILD_ID` (3) as
typed `ElfMetadata::gnu_build_ids` records. Each record retains the identifier
descriptor bytes, the note and descriptor file offsets, and optional
`PT_NOTE`/`SHT_NOTE` source indices. A note visible through both a program
header and a section header produces one typed record with both provenance
fields populated. Separate notes remain separate records, including records
with different identifier bytes.

Build ID descriptors must be nonempty and are retained as opaque bytes; the
loader does not assume a digest algorithm or length. The descriptor is charged
to the shared ELF metadata allocation budget, and note parsing keeps its
existing cancellation and extent checks. The loader does not choose a
preferred ID, compare it with another file, establish trust, or discover
external debug or symbol files from it.
