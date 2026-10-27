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

The complete rebuild is scoped by derived-data dependencies. When loader
metadata changes but the file-backed string mapping remains identical, function
and reference facts are rebuilt against the new metadata, while strings reuse
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
