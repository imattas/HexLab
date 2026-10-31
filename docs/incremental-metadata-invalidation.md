# Incremental source and loader metadata invalidation

Incremental reuse depends on two separate proofs: decoded facts remain valid
for the current effective bytes, and loader-derived metadata still describes
the current source. Instruction-byte validation covers the first proof. The
loader supplies `metadata_reads` for file ranges whose contents contributed to
the parsed mapping and metadata; an edit intersecting those ranges reparses the
input and forces a complete derived rebuild.

Some loaders can return useful partial metadata while reporting
`metadata_complete == false`. Those ranges cannot prove that every
metadata-derived reference, symbol, or root was tracked. Project editing now
reparses such inputs after any effective-byte change, and the resulting
analysis basis records the incomplete state. `plan_invalidation` then refuses
to reuse prior function, reference, or string facts for byte edits, even when
the supplied patch ranges avoid the known metadata reads. The refreshed parse
feeds a full analysis, so a formerly missing root or relocation cannot remain
silently attached to the old metadata snapshot.

Metadata enumeration and byte-read tracking are separate guarantees. A loader
sets `metadata_reads_complete` only when its `metadata_reads` set covers every
dependency on the primary input; the default is uncertified. If that proof is
absent, any effective-byte edit reparses the loader and forces a full derived
rebuild, even when the known ranges do not intersect the changed bytes. This
prevents an omitted read from being missed when the omitted byte change happens
to leave the old mapping and metadata values unchanged. Loaders that track all
reads at `ByteStorage` or conservatively record the whole input can certify the
set. `metadata_complete` continues to describe semantic coverage of returned
metadata and does not imply that read tracking is complete.

When metadata is complete and the recipe and mapping are unchanged, the
project worker compares effective bytes within the union of old and new patch
extents. Those extents cover the complete diff between immutable project input
and its patch overlays. Verified changed ranges retain the incremental code
reuse and affected string-domain refresh paths. Unverified ranges keep the
conservative byte validation and full string scan fallback. Source identity,
recipe, engine, mapping, or metadata uncertainty continues to force a full
rebuild.

After reparsing, the incremental engine also compares the actual mapping and
`ImageMetadata` objects with the previous basis. If either changed even though
the old metadata read ranges did not report an intersection, it promotes the
operation to a complete analysis instead of rejecting the request or reusing
facts against stale loader output. This is a defensive fallback for observable
loader dependency omissions. It cannot detect a loader omission that produces
identical mapping and metadata objects; loaders must still report all
metadata-derived dependencies truthfully.

For a loader-metadata edit with an exact, certified effective-byte diff, the
engine can now retain decoded instruction facts whose recorded byte reads do
not intersect the changed ranges, provided the input identity, recipe,
external-input identity, engine, and instruction mapping remain compatible.
Recovery still revisits roots and reconstructs function ownership, blocks,
calls, references, and stack frames from the freshly parsed metadata. Changed
instruction dependencies are decoded again. This is useful when a header or
symbol-table edit changes roots or metadata while leaving executable bytes
untouched. If byte ranges are unverified or incomplete, or the mapping or
analysis identity changes, the engine keeps the full-fact rebuild path. The
invalidation plan and proposal must carry the same source key; cancellation
during dependency checks or recovery returns no proposal, and adoption still
rejects a proposal whose key no longer matches the current project revision.

The complete derived-fact rebuild is scoped by derived-data dependencies.
When loader metadata changes but the file-backed string mapping remains
identical, function and reference facts are rebuilt against the new metadata, while strings reuse
the prior scan if the effective bytes are proven unchanged. If the workspace
verified the changed byte ranges, only mapped string domains intersecting those
ranges are rescanned. The snapshot's string-rescan reason reports whether the
old scan was retained, refreshed by domain, or rescanned because its prior scan
was incomplete. A changed source identity, recipe, mapping, or unverified byte
diff does not qualify for this reuse.

Tracked loader reads use the `ByteStorage` boundary, so the range set is the
merged set of exact file extents consumed while building a mapping or metadata.
The minidump loader uses this boundary too; its scattered stream and captured
memory records invalidate the mapping when an overlapping effective byte
changes. A tracking set records which bytes were read, while
`metadata_reads_complete` states whether that list is exhaustive and
`metadata_complete` states whether the supported metadata was fully interpreted.
Each guarantee is independent and requires loader-specific validation.

The ELF loader keeps its constructed image on the same tracked storage used
by its table and metadata readers. This matters for optional runtime
relocations: implicit addends are read through the image's storage, and those
target bytes contribute to the returned relocated view just as parser reads
contribute to ordinary ELF metadata. Those accesses are therefore included in
`metadata_reads` before the loader certifies the dependency set as complete.

The PE loader also preserves its tracked storage through requested-base
relocation overlays and ARM64X effective-view construction. ARM64X fixups read
their target bytes to compute DELTA payloads; those reads are included in the
dependency snapshot before `metadata_reads_complete` is certified. The
preferred-base native view can then be rebound to the original immutable input
without losing the already collected dependency ranges.

The top-level `load_image` path also tracks recipe resolution and dispatch.
Automatic format detection and plugin probes read through the same source
boundary as the selected loader, so those input ranges are included in the
returned `metadata_reads`. Durable project reparses use the already-resolved
recipe and do not need to repeat format selection. Plugin image callbacks are
wrapped in `TrackingStorage`; their observed source reads replace plugin-supplied
ranges, and the callback's completeness claim is retained only when its image
uses the tracked source. A provider that depends on external files or state
must leave `metadata_reads_complete` false.

Auxiliary inputs have a separate dependency boundary. A PE loaded with an
explicit PDB path and an ELF loaded with caller supplied DWO/DWP or
supplementary DWARF sources cannot include those other storages in the primary
source's `ReadSet`. Selected ELF packages are content-fingerprinted, and ELF
resolver callbacks are fingerprinted when the caller supplies complete byte
manifests. In those cases, `metadata_reads_complete` certifies the tracked
primary-input dependencies while the external fingerprint independently
forces a full rebuild if an auxiliary artifact changes. An ELF callback without
a complete manifest keeps the primary read set uncertified, so byte edits
conservatively require a full rebuild.

Analysis semantic-decoder callbacks can attach primary-image file ranges to
each external input in their `SemanticDecoderReadSet` manifest. These ranges
must describe every image byte range the callback consults while using that
external input; they are normalized and included in the function engine
fingerprint. Each host-decoded instruction fact records the union of those
declared image ranges as dependencies. A verified byte edit intersecting a
declared range therefore invalidates host-decoded instruction facts and their
downstream CFG/references while retaining unrelated built-in decodes. The
current manifest is conservatively attributed to every host-decoded fact,
rather than tracking which individual external input each callback invocation
consulted. Unverified byte edits with declared callback reads, or a missing,
malformed, out-of-image, or incomplete manifest, keep the full-rebuild path.

Explicit local PDB bindings and caller-selected DWP packages now contribute a
content fingerprint to the loaded-image analysis identity. This includes both
the recipe-selected supplementary DWP package and the split-debug package
passed through `ElfLoadOptions::dwarf_split_debug_package`. When a saved
project is reopened or its shared state is refreshed, the loader rereads those
artifacts and a changed fingerprint changes the external-input component of
the analysis key. The normal invalidation planner therefore forces a full derived
rebuild against the refreshed metadata and rejects a matching derived-cache
entry. This fingerprints the full PDB bytes, including when its CodeView
identity stays the same, and the full selected DWP package. If a split-debug
package and recipe-selected supplementary package are both present, their
digests are combined with a domain tag rather than one replacing the other.
Those bytes remain outside the primary `metadata_reads` range set, but their
content identity independently detects changes to selected packages. ELF DWO
and supplementary resolver callbacks can provide stable caller-assigned
identities through `ElfLoadOptions`. Those digests identify callback code and
captured configuration, and participate in the loaded image's analysis key. A
callback without an identity marks its auxiliary inputs uncertified: analysis
bypasses cached and incremental derived results and does not encode a derived
cache entry. Resolver identities do not fingerprint external bytes. Without a
complete input manifest, callers must ensure their identity changes when
selected external content changes, and the ELF primary read set remains
uncertified for incremental byte edits. With a complete manifest for every
configured resolver, the primary read set can be used for precise byte-range
invalidation while changes to manifest contents still force a full rebuild.

The project analysis key stores the project load-recipe fingerprint and the
optional external-input fingerprint separately. Database cache validation can
continue to check the persisted project recipe, while derived and reference
cache namespaces include the external digest when one exists. A digest change
selects a different cache key and makes incremental planning choose a full
rebuild. Keys without an external digest retain their legacy encoding and
cache entries. Derived payload version 54 reads version 53 entries when no
external input is declared; reference payload version 17 reads older entries
under the same condition. Older entries are treated as stale for requests that
carry an external digest.

Workspace byte revisions are monotonic project revisions, not content hashes.
For patch edits, the workspace compares the old and new effective bytes inside
the union of old and new patch extents and supplies the resulting exact changed
ranges with both range-verification flags set. These extents cover every byte
that the patch set can alter. An empty result therefore certifies equivalent
effective bytes for that transition, even if the logical byte revision advanced
because the patch representation changed. Direct callers of the incremental
API must provide equivalent proof themselves; without it, missing ranges on an
advanced byte revision force a complete rebuild. Revisions may not move
backwards, and a nonempty byte diff must advance the byte revision.

The per-basis dependency index cache checks its immutable fact-owner identity
under a short mutex, then builds a missing index outside the lock. Concurrent
requests may duplicate index construction, but an unrelated or canceled
invalidation request is not blocked behind another request's full table walk.
Before publishing a completed build, the cache rechecks for an index installed
by a concurrent request and reuses that instance when it belongs to the same
fact owner. Cancellation is checked before publication. This changes contention
and cancellation behavior only; invalidation closure and fact-selection rules
are unchanged.

Stack-frame derivation checks cancellation while it builds the prior/current
function and block lookup maps, as well as while it evaluates functions. Large
snapshots therefore do not have to finish the entire map-preparation pass after
a request is canceled. This changes cancellation latency only; frame reuse
still requires the function and all its blocks to match their prior records.
The per-function block comparison polls cancellation for every owned block,
and reusing a cached stack frame copies slots and each slot's access evidence
with stop checks rather than performing one unchecked deep vector copy.

Dependency-index construction now also checks its stop token inside the
comparison steps used to sort per-fact prerequisite and decision lists and the
global read-interval table. This closes a cancellation gap where the edge
population loops were interruptible but a large sort could continue to run to
completion after cancellation. Both byte-range and decision invalidation
closures check cancellation while traversing fan-out edges and while copying
the ordered result set into its return vector. A canceled build or closure
returns `ErrorCode::canceled`; a partially built index is never published to
the per-basis cache.

Cancellation remains cooperative at the granularity of one comparison or one
fact/edge operation. Standard-library map/set insertion, `unique` compaction,
allocation, and destruction of a large temporary index or closure are not
interruptible; cancellation is observed at the next explicit check after
those operations. Workspace actors may still receive a completion containing
a canceled result, which their ticket/session checks must discard when stale.

Invalidation planning and reanalysis compare region, function, chunk, and
reference decisions element by element with stop-token checks. A cancellation
during a large decision comparison therefore returns `ErrorCode::canceled`
without waiting for the complete vector comparison. Equality keeps the
existing order-sensitive semantics; this changes cancellation latency only.

## Content-backed ELF callback dependency manifests

`ElfLoadOptions::dwarf_split_resolver_inputs` and
`dwarf_supplementary_resolver_inputs` let a caller declare the complete set of
immutable byte storages consumed by each resolver. Each entry has a stable,
nonempty identity and a `ByteStorage`. An explicitly empty manifest declares
that the resolver has no external byte inputs. A declaration requires the
matching callback and its existing stable code/configuration identity; byte
content does not identify callback implementation or captured non-byte state.

The shared image-layer `fingerprint_external_inputs` API hashes the full
contents of every declared storage in 64-KiB chunks. It sorts unique names,
then hashes a versioned domain, entry count, length-coded identities, sizes and
SHA-256 content digests. Reordering entries therefore preserves identity;
changing a name, length or byte changes it. Duplicate names, missing storages,
short reads and over-budget manifests fail explicitly. Defaults permit at
most 4,096 inputs, one MiB of identity bytes and 64 MiB of content across both
ELF resolver families; each namespaced identity is limited to 4,096 bytes.
Cancellation is checked between entries and chunks and after source reads.
Hashing uses a fixed initial extent and rejects an input whose size changes.

The ELF loader fingerprints these manifests before parsing and verifies the
same aggregate again after metadata parsing. A different second fingerprint
returns a conflict rather than publishing metadata with a mismatched input
identity. Split and supplementary names occupy distinct namespaces, and their
manifest-presence tags are part of the resolver fingerprint. The loaded image
retains the named sizes and digests in `external_input_dependencies`; these
cover entire artifacts, not only the parser's observed subranges.

Manifest content is folded into `LoadedImage::external_input_fingerprint`
alongside callback identities and selected split/supplementary DWP contents.
The selected split package can no longer overwrite resolver identity, and
direct `load_elf` callers now receive a content identity for their selected
supplementary package too. The existing workspace analysis-key path consumes
this fingerprint: on a fresh load, changing a declared external artifact changes
the external-input identity and forces derived-cache rejection/full reanalysis even when the
primary ELF and callback configuration identity are unchanged. The external
fingerprint is stored as a separate optional analysis-key component and also
selects a distinct persistent cache key.

A complete manifest is a caller contract. HexLab cannot observe hidden files,
network reads, mutable captured objects or undeclared storages inside an
arbitrary callback, and the supplied storages must remain immutable for the
load. The before/after checks detect changed observed content but do not make
a mutable source into an atomic snapshot. Callbacks without manifests retain
the earlier identity-only contract and must update that identity when external
contents change; callbacks without a stable identity remain uncertified and
bypass cached/incremental derived reuse. Exact callback read ranges and
automatic external-file discovery remain unsupported. With complete external
fingerprints, primary byte edits can use the loader's tracked ranges; a change
to any manifested or selected package input changes the external identity and
forces a full rebuild.

## Semantic decoder external read sets

`AnalysisOptions::semantic_decoder_read_set` declares the complete external inputs consulted by a semantic decoder. Each entry has a caller-selected, nonempty stable identity and a SHA-256 digest of the input content. An empty manifest explicitly declares that the decoder has no external inputs. The manifest is sorted by identity and included in the function-engine fingerprint, so changing an identity or digest invalidates the analysis key and forces full derived reanalysis. The callback code/configuration identity remains a separate `semantic_decoder_identity` responsibility; both identities are required for certified reuse.

The host accepts at most 4,096 entries, 1 MiB of identity bytes in total, and 4,096 bytes per identity. Duplicate, empty, NUL-containing, all-zero-digest, throwing, missing, or oversized declarations are treated as incomplete. (An empty external input still has its ordinary SHA-256 digest; all-zero is reserved as an omitted-digest sentinel.) Incomplete declarations disable derived-cache reads and writes and prevent incremental fact reuse; analysis runs from current inputs. For each engine fingerprint, HexLab captures the decoder identity and manifest once, sorts and validates that snapshot, and hashes that same snapshot; it does not call the providers again while constructing that fingerprint. Keyed full function recovery and full derived analysis recheck the engine fingerprint after decoding and fail with a conflict if the decoder identity or manifest changed during the operation. Incremental reanalysis already performs the same end check. The callback contract must keep the read set stable for the full analysis operation and update each digest when input content changes. Any changed manifest digest invalidates the whole derived analysis because the current API does not associate individual external inputs with particular decoded instructions. HexLab cannot discover files or state hidden inside arbitrary decoder callbacks or verify that a caller's digest describes the bytes actually read.
