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

Dependency-index construction and invalidation closure expansion check the
stop token while traversing each prerequisite or dependent edge. This keeps
cancellation responsive even when a single fact has unusually high fan-out.

Region and function decision identities are indexed alongside byte reads.
Changing or removing an identity invalidates facts that recorded that decision
and their prerequisite dependents. Added identities are queried as well, while
new roots and ownership boundaries still use the normal recovery policy.
Function/block/seed facts are conservatively invalidated when the region or
function decision set changes, because these changes can affect recovery
outside the old dependency closure. Instruction decoding remains reusable when
its bytes and execution context are still valid.
