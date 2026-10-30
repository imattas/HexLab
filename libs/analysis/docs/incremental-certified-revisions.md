# Certified no-change revision reuse

Incremental analysis can reuse the existing function snapshot, stack frames,
and string scan when a caller advances a source revision but supplies no dirty
byte ranges and certifies that the complete effective image was compared.
Function recovery is skipped in this case. Reference rows are re-indexed under
the new `AnalysisKey`, so the published reference index still belongs to the
current revision.

When the byte revision is unchanged, incremental analysis independently
compares effective image bytes before taking the same no-op path. This catches
an image change whose source revision was not advanced. If the byte revision
advances, `byte_ranges_verified` is the caller's proof that every effective
byte difference was reported; with an empty dirty set, that proof establishes
that the bytes did not change.

The optimization applies only when user decisions, image mapping, and loader
metadata are unchanged and the invalidation plan does not require a full
rebuild. A nonempty dirty set, changed decisions, changed mapping/metadata, or
an unverified byte revision follows the existing reanalysis path. Re-indexing
reference rows still costs time and memory proportional to the reference count.

When only user reference decisions change, the engine also retains the prior
stack-frame records directly. Function roots, ownership boundaries, instruction
bytes, mapping, and metadata are unchanged in this branch, so stack transfer
cannot change; rebuilding whole-snapshot lookup maps to rediscover that fact is
unnecessary. Function recovery and string recognition are skipped, while the
reference index is rebuilt under the new decision revision.

Dependency-index construction and invalidation closure expansion check the
stop token while traversing each prerequisite or dependent edge. This keeps
cancellation responsive even when a single fact has unusually high fan-out.
Index construction consumes the immutable dependency snapshot directly rather
than copying every fact and its read ranges into a temporary retained vector.
Prerequisite and decision IDs are copied into short-lived vectors with
cancellation checks before sorting and deduplication. Invalidation planning
also checks cancellation while merging affected facts, building changed
decision lists, and materializing function and reference-source outputs. This
closes several long uninterruptible collection-copy loops after dependency
closure calculation; host allocator calls and an individual ordered-container
operation still cannot be interrupted mid-call.

Region and function decision identities are indexed alongside byte reads.
Changing or removing an identity invalidates facts that recorded that decision
and their prerequisite dependents. Added identities are queried as well, while
new roots and ownership boundaries still use the normal recovery policy.
Function/block/seed facts are conservatively invalidated when the region or
function decision set changes, because these changes can affect recovery
outside the old dependency closure. Instruction decoding remains reusable when
its bytes and execution context are still valid.

Incremental reanalysis checks cancellation while cloning a function snapshot
for a new source key and while preparing the prior block/function lookup maps
used to retain identical records. This applies to no-change reuse,
reference-decision-only reuse, and the general recovery path. Cloning checks
between snapshot entries; copying one entry and individual allocator or
ordered-map operations remain cooperative cancellation boundaries. This changes
only cancellation latency and leaves fact selection, `AnalysisKey` identity,
and the derived-cache payload unchanged. The derived-cache format remains at
version 60 because no serialized fields or cache validation rules changed.

Reuse decisions that compare file-to-address mappings now check cancellation
between segment entries instead of comparing the full segment vector in one
uninterruptible operation. The check still compares every segment field and
returns the same reuse decision when not canceled; storage allocation and an
individual segment name comparison remain ordinary allocator/library calls.

Persistent derived-cache validation re-encodes the current rooted analysis and
compares that canonical payload with the stored payload in 64 KiB chunks,
checking cancellation between chunks. A size/content mismatch remains a cache
validation failure; a requested stop returns `ErrorCode::canceled` and prevents
the cache proposal from being returned. This bounds the final byte-comparison
phase for payloads up to the existing 64 MiB cache limit.

Semantic-decoder image-read manifests are checked again when reanalysis reaches
the reuse decision, in addition to the earlier invalidation-planning check. A
host may refresh its manifest between planning and execution; if the refreshed
manifest is missing, invalid, or intersects the planned byte changes, function
facts are fully rebuilt instead of reusing callback-derived instructions. The
manifest remains a caller certification, and stable external-input identity is
still required in the analysis key when callback behavior depends on external
content.
