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
