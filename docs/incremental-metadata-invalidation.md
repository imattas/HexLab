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

The complete rebuild is scoped by derived-data dependencies. When loader
metadata changes but the file-backed string mapping remains identical, function
and reference facts are rebuilt against the new metadata, while strings reuse
the prior scan if the effective bytes are proven unchanged. If the workspace
verified the changed byte ranges, only mapped string domains intersecting those
ranges are rescanned. The snapshot's string-rescan reason reports whether the
old scan was retained, refreshed by domain, or rescanned because its prior scan
was incomplete. A changed source identity, recipe, mapping, or unverified byte
diff does not qualify for this reuse.

This contract assumes loaders set `metadata_complete` truthfully and include
all metadata reads in their tracking set whenever they claim completeness.
Loader-specific proof that every optional table and stream is covered remains
part of the loader validation work.

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
