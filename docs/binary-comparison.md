# Binary comparison engine

`hexlab::compare` compares bounded byte regions without loading files or depending on a loader, database, or UI. A caller supplies `ImageView` values whose `RegionView` entries each contain a stable identity key, starting address, and borrowed byte span. The spans need to remain valid only for the duration of `compare`.

## Alignment and result

Regions pair by unique key within each image; offsets pair within each matched region even when its base address moved. Different keys are additions/removals. Within a matched region, equal bytes pair directly. At a mismatch, the engine searches for an equal anchor of `resync_anchor_bytes` (default four) up to `resync_window_bytes` positions ahead on each side (capped at 256). Anchor lengths from 1 through 64 are accepted; longer anchors reduce accidental matches in repeated byte patterns while remaining bounded. It first chooses the smallest total number of skipped bytes, including when both images have a short insertion/deletion before the shared anchor. If several anchors tie at that distance, it checks up to 64 following bytes for each and uses a uniquely longest exact continuation. If the best continuation is still tied, it declines to resynchronize at that mismatch and reports the current bytes as changed. Skipped spans are paired as changes where possible, with any excess reported as additions or removals, then comparison resumes. Set the window to zero for strict offset pairing. This remains a bounded byte-level heuristic rather than semantic matching. Any remaining tail is removed or added. The engine does not infer region identity from names, addresses, contents, or executable metadata: callers choose keys that represent their intended correspondence.

The report contains ordered, coalesced `ChangeRun` records. Each run has its kind, region key, length, and optional old/new starting addresses. Changed runs carry both addresses; additions and removals carry only the address present on that side. `Summary` reports compared/equal/changed bytes, added/removed bytes, and matched/added/removed region counts. `CompareOptions::max_change_runs` defaults to one million retained runs. Comparison continues after that cap: `Report::total_runs` gives the complete coalesced run count and `runs_truncated` says whether records were omitted. This caps run storage independently of file size while preserving full byte totals. Arithmetic and address extents are checked before comparison; empty or duplicate keys and address overflow are rejected.

`Report::regions` adds one bounded summary row per aligned region: matched, added,
or removed status; old/new start addresses and sizes; paired, equal, changed,
ignored, added, and removed byte totals. Region order follows old-image input
order, followed by new-only regions. For matched regions the paired byte counts
plus removals/additions reconcile to each side's size; ignored bytes are paired
but excluded from equal and changed. The engine caps the combined region count
at two million and retains cancellation during byte processing. CLI text and
versioned JSON include the summaries under the existing `--limit`; the desktop
Regions page and CSV expose bounded/complete table projections. Comparison
sessions use format v12 to persist these rows and continue to load v1-v11.

The desktop Regions page can filter the displayed projection by status, region
key, old/new address, or any byte-count column. Press Enter or choose **Filter**
to apply the query; **Clear** restores the current displayed set. Filtering scans
only the first 100,000 rows shown by the page, and the status reports additional
omitted summaries separately.

Each `RegionView` can also provide sorted, disjoint `ignored_ranges` using offsets relative to that region. The comparison ignores a paired byte when either side marks its offset, and counts it in `Summary::ignored_bytes`; it is excluded from both equal and changed totals. Ignored ranges do not create equality anchors during insertion/deletion resynchronization, so relocation fields cannot falsely align otherwise different code. The input is capped at one million ignored ranges per image, and ranges must be nonempty and fully inside their region. The desktop now supplies file-backed field extents from recognized ELF/Mach-O relocations, Mach-O dyld/chained and firmware-chained fixups, and standard x86/x64 PE base relocations; duplicate or overlapping extents are merged before comparison. The result window and CSV report expose the ignored-byte count. The engine still treats masking as explicit caller policy and does not infer relocation locations itself. Unsupported, incomplete, or runtime-only relocation metadata can leave relocated bytes visible as ordinary changes; ignored bytes are excluded from both equal and changed counters, so inspect the ignored total when reviewing results.

## Cancellation and progress

Pass a `std::stop_token` to request cancellation from another thread. The progress callback receives `(visited, estimated_total)` periodically and can cancel by returning `false`. The estimated total is the exact number of byte positions processed: matched region pairs visit the larger region length, while unmatched regions visit their full length. A final callback reports completion, including for empty images. Set `progress_interval` to control callback frequency; zero is treated as one byte. Cancellation returns `ErrorCode::canceled` and does not return a partial report.

## Example

```cpp
using namespace hexlab::compare;
ImageView before{{RegionView{"text", 0x1000, before_bytes}}};
ImageView after{{RegionView{"text", 0x4000, after_bytes}}};
auto report = compare(before, after);
if (report) {
    for (const auto &run : report.value().runs) {
        // A changed run maps corresponding offsets between 0x1000 and 0x4000.
    }
}
```

Input ordering is preserved: old-image regions appear first, followed by new-only regions. This makes output deterministic for a deterministic input order.

## Function shape matching

`FunctionFeature` includes an architecture identifier, names, graph/count shape, opcode histogram, and optional normalized instruction fingerprints. A frontend can create each fingerprint from an instruction identity after replacing address-dependent operands (such as branch destinations and absolute addresses) with stable operand classes. Fingerprint values should be stable across load bases and renaming; they are compared as a multiset, so instruction order changes do not destroy all correspondence evidence. The comparison engine does not decode instructions or invent fingerprints itself.

`match_functions_detailed` scores only functions with the same architecture. Fingerprint similarity is the primary signal when fingerprints are present; otherwise the matcher uses opcode-histogram and graph/count shape. Names raise confidence when they agree but do not bypass architecture checks. Candidate assignments are accepted only when the best candidate is also the unique best candidate from the other image. Close candidates and many-to-one conflicts are emitted as `ambiguous`; candidates below `minimum_confidence` are emitted as `removed` or `added`. A function can never be forced into an arbitrary pair to make the counts line up. Entry addresses are not used as similarity evidence, so relocation has no effect.

`FunctionMatchOptions::weights` lets callers calibrate the base score for
different build families without changing graph refinement or ambiguity rules.
Without CFG colors, defaults give fingerprints 75% when present and opcode
histograms 60% when used without fingerprints. The remaining score comes from
instruction, block, and call-count shape at weights 25:15:10. When CFG colors
are present, their default 20% topology weight scales the prior score to 80%.
Shape-only evidence is capped at
59% when fingerprints, histograms, and CFG colors are all absent, and an exact nonempty name raises the score floor to 95%. Callers may
adjust those weights and caps from 0 to 100; at least one shape weight must
remain nonzero. Invalid weights are rejected before candidate scoring. These
values affect confidence only; reciprocal uniqueness and bounded call-graph
evidence still control whether a correspondence is accepted. Saved sessions
persist the resulting confidence and evidence, not the feature vectors or
input binaries.

`FunctionFeature::cfg_fingerprints` is an optional multiset of bounded,
address-independent CFG colors. The desktop frontend builds each initial
block color from the block's opcode multiset and outgoing edge kinds, then
performs three directed neighborhood-refinement rounds over internal
predecessor and successor edges. Each round contributes one color per block
and one color per directed edge, with edge colors incorporating the refined
source color, edge kind, and target color. The edge multiset preserves direct
connectivity evidence that a block-color multiset can blur. This provides
topology evidence even when instruction order or block layout changes. The
weight is configurable with `FunctionSimilarityWeights::cfg_weight`; when
either image lacks CFG colors, the available score remains unchanged. Color
hashes are comparison hints rather than semantic proofs, and unsupported or
incomplete CFG edges use a zero target color and their known edge kind. The desktop
frontend caps CFG collection at one million blocks and four million edges per
image; functions past the remaining budget simply omit this optional signal.
Because each captured edge contributes a color in each of three rounds, CFG
fingerprint item budgets can be reached before the extraction node/edge caps.

When instruction fingerprints are available, the engine also derives an
ordered local-sequence signal from adjacent fingerprint pairs. It retains a
deterministic bottom-k sketch of at most 128 distinct pairs per function, so
small insertions or deletions leave most local pairs available while functions
with the same instruction multiset in a different order can score differently.
The default `sequence_weight` is 30% of the fingerprint-family score; set it to
zero to disable this signal. `max_sequence_items` bounds all retained pairs
across both images and defaults to four million. The sketch is address
independent when the supplied instruction fingerprints are, but remains a
heuristic and is not a semantic-equivalence proof.

Frontends that retain CFG nodes and edges can provide `FunctionFeature::cfg_blocks`
instead of flattening topology into `cfg_fingerprints`. Each block carries an
address-independent instruction fingerprint and typed successor edges by
zero-based block index. The matcher validates every target, builds incoming
edges, and performs four rounds of directed neighborhood color refinement.
The resulting color multiset is invariant to block ordering and load address,
and the edge kinds distinguish conditional, fallthrough, switch, or frontend-
defined transitions. When both candidate functions have explicit CFGs, these
colors take precedence over their legacy flat CFG fingerprints; if either side
lacks explicit blocks, the legacy fingerprints are used. Explicit block and
edge records count against `max_fingerprint_items`, and their pairwise
refinement work counts against `max_cfg_comparison_items`.

Color refinement is a bounded structural heuristic, not graph isomorphism:
distinct CFGs can still produce the same color multiset, and matching topology
does not prove instruction semantics. Frontends should keep block fingerprints
independent of addresses and encode only instruction facts appropriate for
their comparison policy.

### Anchored call-graph refinement

Callers can optionally supply `FunctionFeature::direct_calls`, a vector of `FunctionAddress{entry, address_space}` destinations. The engine resolves these against the functions from the same image and builds incoming and outgoing neighborhoods. Unknown destinations contribute no evidence; repeated call sites to the same destination count once. When refinement is enabled, function addresses must be unique within each image and address space. Address-space identifiers may differ between images: only already established function correspondence connects the two namespaces.

The initial reciprocal unique matches become anchors. For each remaining candidate, refinement compares only its relationships to those anchors. Both the incoming and outgoing anchored neighborhoods must agree exactly, and at least one anchored relationship must support the pair. The pair must also meet the base confidence threshold and remain within `ambiguity_margin` of both sides' original best scores. A pair is accepted only when it is the sole eligible contextual candidate on each side. Each entire wave is evaluated before its matches become anchors for the next wave, so input order cannot create supporting evidence. This resolves relocated, reordered, stripped duplicate helpers through their known callers or callees while leaving unanchored cycles, shared-neighborhood duplicates, conflicting neighborhoods, and many-to-one claims ambiguous. Relationships to functions that are still unmatched do not establish evidence.

Each `FunctionMatch` carries `evidence.base_confidence`, `evidence.supporting_call_neighbors`, `evidence.call_graph_round`, and an optional `evidence.score_breakdown`. The breakdown reports the 0–100 shape similarity and whichever instruction fingerprint, opcode histogram, and CFG similarities were available, plus exact-name and name-floor flags. Missing component scores are unavailable rather than zero. Round zero denotes a match accepted by the original scoring pass; positive rounds record the wave in which graph evidence established correspondence. Supporting neighbors count distinct incoming and outgoing anchored relationships separately. Confidence remains the original instruction/shape/name score; the engine does not inflate it because a contextual match was found. These values explain the matching heuristic and do not assert semantic equivalence. Entries with no accepted correspondence have no supporting graph evidence.

For an unambiguous matched caller, `call_targets` summarizes its outgoing known in-image direct-call relationships when both frontends explicitly mark those sets complete. Targets are compared through the final function correspondence, so moved or renamed callees can remain unchanged. Added and removed counts include edges to functions confidently added or removed; edges touching an ambiguous or unrepresented target are counted as ambiguous. External, indirect, unresolved, and otherwise unknown calls are outside this summary. Frontends that cannot provide a complete target set leave the summary unavailable instead of presenting missing facts as an empty call graph. The desktop Functions table shows unchanged/added/removed/ambiguous counts, CSV export writes four `function_call_targets` summary rows per available caller, and the CLI prints the same counts. This is call-graph change evidence, not call-site alignment or proof of behavioral equivalence.

`max_call_edges` bounds the supplied call destinations across both images, including duplicate and unknown targets. `max_context_edge_visits` bounds adjacency items examined across refinement candidates. Exceeding either budget returns `ErrorCode::invalid_argument` without partial matches. `max_call_graph_rounds` defaults to 16; reaching that limit leaves unresolved candidates ambiguous. Set it to zero to disable refinement. Function matching progress is monotonic against a conservative estimate that includes the configured maximum refinement waves; completion can advance past unused waves. Callbacks run at wave boundaries as well as periodically during scoring/refinement, and either the callback or stop token can cancel the operation.

Matching is bounded by `max_candidate_pairs`, `max_fingerprint_items`, `max_opcode_histogram_items`, `max_cfg_comparison_items`, and `max_semantic_items` in `FunctionMatchOptions`; histogram buckets and semantic records across both images default to 16 million. Fingerprint and CFG-color items share `max_fingerprint_items`, while CFG comparisons across candidate pairs default to 64 million items. Histogram buckets and semantic records are counted before pair scoring, even when fingerprints would otherwise be the primary signal. When both are provided, semantic records must align one-to-one with their function or block instruction fingerprints; malformed lengths are rejected instead of silently losing semantic evidence. Histogram similarity uses an exact two-limb integer ratio, so the 0–100 score is deterministic across toolchains and cannot overflow while summing buckets. Over-budget work returns an error. The detailed API also accepts a stop token and progress callback and returns `ErrorCode::canceled` when either cancels. `match_functions` remains as a convenience wrapper for callers that do not need to observe errors; on cancellation or budget failure it conservatively reports old functions as ambiguous and new functions as added. Callers that need to distinguish those cases should use the detailed API.

Function matchers may provide `instruction_semantics` without a duplicate top-level `instruction_fingerprints` vector. In that form, each semantic record's normalized `fingerprint` supplies the function multiset and ordered sequence evidence; the same semantic and fingerprint item budgets apply. This can reduce adapter storage when semantic facts are already retained. It does not create instruction-body or block-local diffs, which still require explicit complete fingerprint sequences. If both vectors are present, their lengths must agree.

The API does not recover functions itself: callers provide features from their analysis snapshots. The desktop supplies normalized fingerprints for every fully typed instruction in a recovered function, along with architecture, names, opcode histograms, and graph/count shape. Fingerprints omit instruction addresses, encoded bytes, physical register numbers, and relative branch displacements, while retaining opcodes, operand classes and widths, conditions, memory addressing shape, and literal constants. A function containing an opaque instruction omits the fingerprint sequence and falls back to shape matching. This lets stripped or renamed functions match across load bases and register allocation changes without claiming that opaque code is equivalent. The function tab lists matched, added, removed, and ambiguous results with confidence, names, base confidence, and call-graph support evidence. Selecting a matched row displays its bounded instruction alignment when complete fingerprints are available. The alignment uses zero-based half-open instruction-index ranges for each side; it is not a source-line or byte-address map.

Function-body alignment is computed only for unambiguous matches with complete normalized fingerprint sequences. Each function is limited to 4 million LCS matrix cells and the whole comparison to 16 million cells. Over-budget, opaque, or unavailable bodies remain matched by the existing matcher, but no body diff is stored for them. These correspondences are exact normalized-fingerprint evidence, not proof of semantic equivalence.

Matched functions with bounded explicit CFG features also receive a block-correspondence result from `correspond_function_blocks`. Unique address-independent block fingerprints anchor the mapping first when available instruction evidence does not contradict them. Remaining candidates use incoming/outgoing degree, typed edge-kind shape, edges to blocks already mapped, and complete normalized instruction/adjacency overlap; only reciprocal, non-tied best candidates are accepted. The result reports matched, added, removed, and ambiguous block rows using zero-based indexes into each side's `cfg_blocks`, with per-match instruction similarity evidence. Candidate, edge, and instruction-comparison budgets bound refinement. An incomplete budget-limited wave publishes no new matches; unresolved blocks are ambiguous and `budget_exhausted` is set. Input feature or edge data above its cap returns `ErrorCode::resource_limit` before feature preparation. Cancellation returns an error without a partial correspondence. See [block-local comparison](binary-comparison-block-instructions.md) for score calibration, budgets and limitations. This is a conservative structural heuristic, and a match does not prove semantic equivalence. The desktop shows block mappings alongside instruction alignment.

Detailed instruction alignment can retain changed-pair evidence by opcode, control-flow class, normalized operand signature, and instruction effects (operand access, memory behavior, and architecture-specific effects). These counters are independent dimensions and can overlap. They explain which recorded facts differ; they do not establish semantic equivalence. New sessions use the v9 schema to persist per-run and aggregate evidence together with call-target summaries. Readers continue to accept v1–v8 sessions; semantic evidence remains unavailable in versions before v8.

The desktop adapter populates `direct_calls` from recovered analysis call facts on both images. It includes only direct targets that resolve to a function feature in the same image and preserves each endpoint's address space; repeated sites are collapsed, while indirect, unresolved, and external calls add no edge. Thus missing analysis facts simply leave some functions without optional graph evidence, and the matcher retains its shape/fingerprint behavior for them. Desktop and CLI features retain bounded, address-independent CFG block summaries where available. The Functions table shows the resulting per-match evidence and body-diff availability; the instruction-detail pane shows coalesced equality/change/add/remove spans and zero-based block correspondence rows for the selected matched function. When a complete fingerprint sequence also has a complete address map, whole-function instruction runs retain the address of each side's first instruction for navigation; each frontend stores at most one million instruction addresses per side, and later functions simply have no address map. Addresses are presentation metadata and never contribute to match or alignment evidence.

### Function instruction alignment

For a matched pair, `diff_function_instructions(old_fingerprints, new_fingerprints)` aligns the ordered normalized instruction fingerprints and returns coalesced runs with zero-based old/new instruction indexes. Equal fingerprints stay aligned across insertions and deletions; each unmatched span becomes a changed run when both sides contain instructions, with any longer-side remainder counted as an addition or removal. The result totals count paired substitutions once in `changed_instructions` and any unpaired old/new instructions in `removed_instructions` or `added_instructions`. This provides a reusable body-level diff without requiring the comparison library to load binaries or decode instructions. The caller supplies fingerprint sequences and remains responsible for normalizing addresses and operands consistently.

The implementation uses a longest-common-subsequence matrix when the whole body fits its default 4 million cell budget (about 16 MiB); callers can lower or raise `max_dynamic_cells`. For larger bodies, it builds exact anchors from fingerprints that occur once on each side, chooses a non-crossing subsequence with a longest-increasing-subsequence pass, then aligns each gap independently. The total old-plus-new fingerprints indexed by this fallback is capped by `max_anchor_index_items` (default 1 million). Exact gap matrices share the same total cell budget. If a gap does not fit the remaining budget, that gap is reported conservatively as changed/added/removed; it does not invent equal instruction matches. If the anchor index cap is exceeded, the body diff is unavailable with a budget error. This makes large body diffs useful when they contain distinctive instructions without allowing unbounded quadratic allocation.

The operation supports a stop token and progress callback. The full-matrix path reports periodically during matrix construction and reconstruction; the anchor path checks cancellation while indexing and selecting anchors, during exact gap matrices, and while emitting runs. Returning false at any callback cancels without a partial result. Fingerprints are compared exactly, so collisions or inconsistent frontend normalization can produce misleading alignments; equal runs are correspondence evidence, not semantic equivalence. Conservative gaps can overstate changed instructions when no unambiguous anchors or exact gap budget remain.

`diff_function_instructions_detailed` also receives per-instruction opcode, flow, operand, and effect signatures. If a fingerprint-aligned pair has conflicting semantic signatures, the detailed result splits that pair out of an equal run and reports it as changed, with the differing categories counted. Fingerprint-only comparison remains unchanged. This protects detailed output from treating an inconsistent or colliding fingerprint as sufficient evidence of equality; the semantic signatures still cover only the facts supplied by the frontend.

## Desktop workflow

In the desktop app, choose **File > Compare Current Project**, then select a binary. HexLab loads and compares it on a worker thread, reports progress, and supports cancellation. To compare projects already open in tabs, select the old side and choose **File > Compare Open Projects...**, then select the new side. Both workflows reuse the same byte alignment, function matching, and instruction-body diff. The results window has Bytes and Functions tabs. Use **Go to old side** or **Go to new side** to navigate a selected byte run or matched function. In the selected function's instruction alignment, select a run to see its zero-based range and mapped start addresses, then use **Go to old instruction** or **Go to new instruction** to navigate to that side. Navigation is enabled only when the run has an address and the captured side remains open; a raw-file comparison has no open new-side document, and a saved session does not bind its addresses to projects. Filter byte runs by kind or by text matching the displayed kind, region, or address, then use **Previous** and **Next** to step through visible runs that have an old-side address. The result count shows visible versus total runs. Regions align by segment name and occurrence, so renamed or structurally changed segments may appear as removals and additions.

The headless CLI compares two automatically detected images with `hexlab_cli compare old-image new-image`. It prints byte and region totals followed by up to 1000 change runs and per-region summaries. `--window` and `--anchor` tune bounded insertion/deletion resynchronization; `--limit` bounds emitted runs and region summaries. Add `--json` for a single machine-readable JSON object containing summary counters, per-region metrics, total counts, change runs, and omitted counts. Byte-only JSON uses `hexlab.compare.v2`; addresses are hexadecimal strings and absent old/new addresses are JSON `null`. Combining `--json --functions` uses `hexlab.compare.v7` and adds a bounded `functions` object with match totals, up to `--function-limit` ambiguity-preserving rows, address-space-qualified addresses, names, confidence, call-graph evidence, score breakdown, and outgoing call-target change summaries. Matched rows also include CFG block totals and changed-block instruction summaries, plus whole-function instruction-diff totals, semantic-change categories, and bounded non-equal runs. Each whole-function change run includes optional address objects (`address`, `space`) for the first old/new instruction when a complete fingerprint-to-address map is available. `omitted_matches`, `omitted_changed_blocks`, `omitted_changes`, and `omitted_regions` make truncation explicit; changed-block summaries have a shared 2,000-row cap and instruction runs use the shared `--instruction-limit`. Block or body details are `null` when correspondence/alignment is unavailable. This command compares file-backed image regions; region identity uses segment name and occurrence. Add `--functions` to recover functions in both images and print ambiguity-preserving function matches, call-target deltas, block correspondence totals, instruction-alignment summaries, and non-equal runs. `--function-limit` bounds the number of function rows printed, and `--instruction-limit` bounds the total emitted non-equal instruction runs. `--min-confidence` and `--ambiguity-margin` configure the same reciprocal matcher thresholds used by the desktop. The CLI uses the shared normalized instruction fingerprint schema, architecture-aware feature matching, and bounded matcher/body-diff budgets. Opaque instructions suppress that function's instruction alignment rather than becoming guessed matches; CFG block alignment may still be available. Function analysis can be slower than byte-only comparison; leave `--functions` off for a quick byte report.

## Persisted sessions

`save_session(path, session)` and `load_session(path)` persist completed result data independently of the input binaries. A `Session` contains the old/new display names, byte summary and change runs, and function matches. It deliberately does not store or embed binary bytes. The format is versioned and little-endian; the loader checks the signature, enum values, string and record limits, file-size ceiling (256 MiB), truncation, and trailing data before returning a session. Version 11 adds a CRC-32 checksum over the serialized header and payload so accidental damage is reported before a session is returned. The checksum detects corruption; it does not authenticate a session. Saving writes a temporary sibling and renames it into place.

New saves use version 14 (`HXCMPR14`) and include per-region byte summaries, ignored-byte totals, function correspondence evidence and score breakdowns, call-target summaries, bounded function instruction-diff runs, optional old/new instruction addresses, block correspondence, block-local instruction diffs, instruction coverage/similarity evidence, and the payload checksum. The reader also accepts versions 1 through 13; older sessions have instruction navigation addresses unavailable, and sessions before v12 also lack per-region summaries. Version 14 adds per-side block instruction coverage; prior similarity evidence is interpreted as complete. The loader checks region arithmetic, instruction-run kinds, half-open extents and counters, address-side consistency, confidence, and evidence ranges/availability. Older applications cannot read version 14 saves.

The desktop comparison window provides **File > Save Comparison Session As...**. From the main window, choose **File > Open Comparison Session...** to load a saved result without either original binary. The comparison window also provides an Open command. Saved windows retain byte and function results and filtering/navigation behavior; old-side navigation is unavailable when the source project is not open. Session saves use a new path; choose another path if the selected destination already exists.

Use **File > Export Comparison CSV...** to export a completed result for spreadsheet review. The UTF-8 CSV contains a fixed 60-column schema, summary rows, byte change runs, function results, stored function instruction-diff runs, and one `function_block` row per CFG block correspondence. Function rows include confidence, base confidence, supporting call-neighbor count, refinement round, and available score components. Instruction rows include old/new function entries, zero-based start/count fields, and optional mapped start addresses for both bodies. Block rows include old/new block indexes, match confidence and neighbor support, instruction evidence coverage and similarity, local diff counts and semantic changes, semantic-evidence availability, and budget-exhaustion flags. Fields that do not apply to a record type are blank so every row aligns with the header. Input names and region/function names are CSV-escaped; the export contains addresses and derived comparison results, not binary contents.

```cpp
compare::Session session{"old.exe", "new.exe", report, function_matches};
auto saved = compare::save_session("review.hxcmp", session);
auto restored = compare::load_session("review.hxc");
```

## Headless validation

The comparison library has a standalone CMake entry point, independent of the desktop and other HexLab subsystems:

```powershell
cmake -S libs/compare -B .agent-compare-neighborhood-20261022 -G "Visual Studio 17 2022" -A x64 -DBUILD_TESTING=ON
cmake --build .agent-compare-neighborhood-20261022 --config Debug --parallel 2
ctest --test-dir .agent-compare-neighborhood-20261022 -C Debug --output-on-failure
```

On 2026-10-22 the `binary_compare` suite passed in this isolated MSVC x64 Debug build. Test-first runtime failures were observed for two-wave duplicate-helper correspondence, session evidence persistence, cancellation before graph completion, and the architecture guard at a zero confidence threshold; each passed after its corresponding implementation change. Additional fixtures cover incoming/outgoing context, old/new ordering, duplicate and unresolved calls, address-space-qualified targets, contradictory context, unanchored cycles, many-to-one conflicts, insufficient instruction evidence, round/edge/work limits, a literal version 1 wire record, malformed version 2 evidence, and the existing byte-comparison/session behavior. This is focused engine validation; it does not claim desktop call-graph integration or a corpus-wide false-match rate.

