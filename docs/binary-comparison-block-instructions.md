# Block-local function comparison

Function comparison can align normalized instruction fingerprints inside
confidently corresponding CFG blocks. This complements the whole-function
instruction sequence: if the compiler changes block order, a moved block's
instructions remain comparable as a unit rather than appearing as one long
delete/add span.

The desktop compare view shows per-block equal, changed, removed, and added
instruction counts beside the existing block correspondence rows. The
`hexlab_cli compare --functions` output prints summaries only for blocks with
instruction changes. Function and block correspondence still preserve
ambiguity; ambiguous blocks are never assigned an instruction diff.

The frontend includes block-local sequences only when every instruction has a
normalized fingerprint. Total retained block fingerprints are capped at four
million per desktop image and two million per CLI image. Block-local alignment
uses a four-million aggregate dynamic-programming cell budget per function
match operation. If that budget runs out, affected summaries are explicitly
marked as omitted. Comparison sessions store the derived block diffs in format
version 7; readers continue to accept versions 1 through 6. Version 5 introduced
block-local diffs; version 7 additionally preserves block instruction-similarity
evidence.

The fingerprints omit address-dependent branch targets and immediates where
the shared instruction normalizer supports it. They do not prove semantic
equivalence, recover split/merged blocks, or infer effects for opaque
instructions. The output is structural evidence for review, not a semantic
patch proof.

Block-local sequences also contribute to correspondence before alignment. For
each complete, nonempty block sequence, the matcher compares the normalized
instruction multiset and the multiset of ordered adjacent-instruction pairs.
Both use integer Dice overlap, retaining duplicate occurrences. Their combined
content score is 70% instruction overlap and 30% adjacency overlap; blocks with
fewer than two instructions on either side use instruction overlap alone.
This distinguishes changed blocks that have identical incoming/outgoing degrees
and edge kinds but different instruction content. Small insertions or deletions
preserve most local adjacency evidence, and block addresses and indexes are
never part of this signal.

`FunctionBlockMatchOptions::instruction_similarity_weight` defaults to 40% of
the candidate confidence; the remaining 60% uses the existing block-hash,
degree, edge-kind and anchored-neighbor score. Set the weight to zero to retain
graph/hash-only scoring. Missing or empty sequences add no content evidence.
An unavailable sequence must be empty; inconsistent availability flags are
rejected. A unique block hash anchors directly only when available instruction
and adjacency evidence do not disagree with equality. Hashes and overlap remain
heuristics: different sequences can have the same token and adjacency multisets.

Accepted pairs report `BlockCorrespondence::instruction_evidence` with
`available`, `fingerprint_similarity`, `adjacency_available`, and
`adjacency_similarity`. Percentages range from zero to 100. Zero is meaningful
when available; absent evidence has zero fields. Confidence and neighbor support
record the wave that accepted the match, rather than being inflated by matches
accepted later. Existing CLI and desktop adapters automatically use the revised
correspondence/confidence; the separate evidence percentages are available
through the compare API and saved sessions.

Reciprocal best-candidate and ambiguity-margin checks still apply. Similar
duplicates stay ambiguous, and instruction overlap alone does not force a
pairing. A candidate wave that exhausts its work budget publishes no matches
from that incomplete wave, since unseen candidates could change reciprocal
uniqueness. Previously completed waves and validated exact anchors are retained;
all remaining blocks are ambiguous and `budget_exhausted` is true.

Preparation is bounded by `max_instruction_fingerprint_items`, default four
million aggregate supplied instruction IDs plus retained adjacency hashes across
both sides. Input instructions count even when the score is disabled; adjacency
hashes do not. Exceeding this cap fails with `resource_limit` before feature
copies are allocated. `max_instruction_comparison_items`, default 64 million,
counts token and adjacency items conservatively for every candidate comparison
and anchor check, across all waves. Exhausting it stops correspondence with the
ambiguity behavior above. These budgets are separate from the existing
instruction-alignment matrix budget. Cancellation is checked during preparation,
comparison, and result construction; sorting checks it at block boundaries.
The weight must be 0..100, both instruction budgets must be nonzero, and the
feature budget must not exceed `UINT64_MAX / 200`, keeping overlap arithmetic
bounded without floating-point rounding.

Rebase and relocation tolerance depends on the frontend's instruction IDs
already omitting addresses and normalizing relocatable operands consistently.
This signal does not decode instructions, repair incomplete CFGs, infer
cross-architecture semantics or register effects, match split/merged blocks, or
establish semantic equivalence. The block API has no architecture tag: callers
must supply blocks from compatible instruction-normalization domains.
