#pragma once
#include "hexlab/compare/compare_export.hpp"
#include <cstddef>
#include <cstdint>
#include <functional>
#include <optional>
#include <span>
#include <stop_token>
#include <string>
#include <utility>
#include <vector>

namespace hexlab::compare {
enum class ErrorCode { invalid_argument, overflow, canceled, resource_limit };
struct Error { ErrorCode code; std::string message; };
template<class T> class Result {
public:
    Result(T value) : value_(std::move(value)) {}
    Result(Error error) : error_(std::move(error)) {}
    bool has_value() const noexcept { return value_.has_value(); }
    explicit operator bool() const noexcept { return value_.has_value(); }
    T &value() { return value_.value(); }
    const T &value() const { return value_.value(); }
    const Error &error() const { return error_.value(); }
private:
    std::optional<T> value_;
    std::optional<Error> error_;
};
struct RegionView {
    std::string key; // stable identity used to align a region across images
    std::uint64_t address = 0;
    std::span<const std::byte> bytes;
    struct IgnoredRange {
        std::uint64_t offset = 0; // byte offset within this region
        std::uint64_t size = 0;
    };
    // Sorted, non-overlapping byte ranges whose contents should not affect a
    // matched-region comparison (for example, relocation fields).
    std::span<const IgnoredRange> ignored_ranges;
};
struct ImageView { std::vector<RegionView> regions; };
enum class ChangeKind { added, removed, changed };
struct ChangeRun {
    ChangeKind kind;
    std::string region_key;
    std::optional<std::uint64_t> old_address;
    std::optional<std::uint64_t> new_address;
    std::uint64_t size = 0;
};
struct Summary {
    std::uint64_t compared_bytes = 0, equal_bytes = 0, changed_bytes = 0;
    std::uint64_t added_bytes = 0, removed_bytes = 0;
    std::uint64_t matched_regions = 0, added_regions = 0, removed_regions = 0;
    std::uint64_t ignored_bytes = 0;
};
struct Report { Summary summary; std::vector<ChangeRun> runs; };
struct FunctionAddress {
    std::uint64_t entry = 0;
    std::uint32_t address_space = 0;
    bool operator==(const FunctionAddress &) const = default;
};
struct CfgEdgeFeature {
    // Index into the containing FunctionFeature::cfg_blocks vector.
    std::uint32_t target = 0;
    // Frontend-defined stable edge class, for example conditional-true,
    // conditional-false, fallthrough, switch, or indirect.
    std::uint32_t kind = 0;
};
// Compact instruction facts retained by comparison frontends. Signatures are
// normalized and address independent; they classify a changed fingerprint.
struct InstructionSemanticFeature {
    std::uint64_t fingerprint = 0;
    std::uint32_t opcode = 0, flow = 0;
    std::uint64_t operand_signature = 0, effect_signature = 0;
};
struct InstructionChangeEvidence {
    bool available = false;
    std::uint64_t opcode_changes = 0, flow_changes = 0;
    std::uint64_t operand_changes = 0, effect_changes = 0, unclassified_changes = 0;
};
struct CfgBlockFeature {
    // Address-independent summary of the block's normalized instructions.
    std::uint64_t fingerprint = 0;
    std::vector<CfgEdgeFeature> successors;
    // Optional complete instruction fingerprint sequence for block-local diff.
    // Empty or unavailable sequences never get treated as evidence of equality.
    std::vector<std::uint64_t> instruction_fingerprints;
    bool instruction_fingerprints_available = false;
    std::vector<InstructionSemanticFeature> instruction_semantics;
};
// Architecture-neutral function shape used for relocation-tolerant matching.
struct FunctionFeature {
    std::uint64_t entry = 0;
    std::string name;
    std::uint32_t architecture = 0;
    std::uint64_t instruction_count = 0, block_count = 0, call_count = 0;
    std::vector<std::uint32_t> opcode_histogram;
    std::uint32_t address_space = 0;
    // Stable, address-independent instruction IDs. The analysis frontend should
    // normalize operands (registers, immediates, and branch targets) before hashing.
    std::vector<std::uint64_t> instruction_fingerprints;
    std::vector<InstructionSemanticFeature> instruction_semantics;
    // Optional known direct-call destinations in this image. Unknown targets
    // are ignored, and duplicate call sites to one function count once.
    std::vector<FunctionAddress> direct_calls;
    // Address-independent CFG color multiset. Frontends may include refined
    // block colors and directed edge colors from bounded neighborhood rounds,
    // allowing function matching to distinguish similar opcode bags with
    // different control-flow topology. Empty when CFG facts are unavailable.
    std::vector<std::uint64_t> cfg_fingerprints;
    // Optional explicit CFG. When both sides provide it, the matcher refines
    // block colors over typed incoming/outgoing edges and compares the
    // resulting address-independent color multisets. Appended to preserve
    // existing aggregate initialization.
    std::vector<CfgBlockFeature> cfg_blocks;
};
enum class FunctionMatchKind { matched, added, removed, ambiguous };
struct FunctionMatchEvidence {
    std::uint32_t base_confidence = 0;
    // Distinct anchored caller/callee relations supporting this decision.
    // A neighbor appearing in both directions contributes two relations.
    std::uint64_t supporting_call_neighbors = 0;
    std::uint32_t call_graph_round = 0; // zero means accepted without graph refinement
};
struct FunctionMatch {
    FunctionMatchKind kind = FunctionMatchKind::ambiguous;
    std::optional<std::uint64_t> old_entry, new_entry;
    std::uint32_t confidence = 0; // 0..100
    std::uint32_t old_space = 0, new_space = 0;
    std::string old_name, new_name;
    FunctionMatchEvidence evidence;
};
// Relative weights used only for the base function score. Fingerprint and
// histogram weights are their percentage of the final score when that feature
// family is present; the remainder comes from the instruction/block/call
// shape score. Shape weights are normalized against their sum.
struct FunctionSimilarityWeights {
    std::uint32_t fingerprint_weight = 75;
    std::uint32_t histogram_weight = 60;
    std::uint32_t instruction_count_weight = 25;
    std::uint32_t block_count_weight = 15;
    std::uint32_t call_count_weight = 10;
    std::uint32_t same_name_floor = 95;
    std::uint32_t shape_only_ceiling = 59;
    std::uint32_t cfg_weight = 20;
    // Weight of ordered adjacent-instruction shingles within the fingerprint
    // score. Zero disables this extra sequence-order signal.
    std::uint32_t sequence_weight = 30;
};
struct FunctionMatchOptions {
    std::uint32_t minimum_confidence = 65, ambiguity_margin = 8;
    std::uint64_t max_candidate_pairs = 4'000'000;
    std::uint64_t max_fingerprint_items = 16'000'000;
    std::stop_token stop_token;
    std::function<bool(std::uint64_t, std::uint64_t)> progress;
    std::uint64_t max_call_edges = 16'000'000;
    // Total adjacency items examined during refinement across all candidates.
    std::uint64_t max_context_edge_visits = 64'000'000;
    std::uint32_t max_call_graph_rounds = 16; // zero disables graph refinement
    // Total opcode-histogram buckets across both images.
    std::uint64_t max_opcode_histogram_items = 16'000'000;
    // Appended to preserve existing aggregate initializers. Defaults retain
    // the original matching score calibration.
    FunctionSimilarityWeights weights;
    // Aggregate CFG-color comparisons across candidate pairs are bounded
    // separately from the amount of feature data supplied by callers.
    std::uint64_t max_cfg_comparison_items = 64'000'000;
    // Total retained bottom-k instruction-adjacency hashes across both images.
    std::uint64_t max_sequence_items = 4'000'000;
    // Aggregate instruction semantic records retained on functions and CFG
    // blocks. Appended to preserve positional aggregate initialization.
    std::uint64_t max_semantic_items = 16'000'000;
};
HEXLAB_COMPARE_EXPORT Result<std::vector<FunctionMatch>> match_functions_detailed(
    std::span<const FunctionFeature> old_functions, std::span<const FunctionFeature> new_functions,
    const FunctionMatchOptions &options = {});
// Convenience interface. Use match_functions_detailed when cancellation or
// budget errors must be surfaced to the caller.
HEXLAB_COMPARE_EXPORT std::vector<FunctionMatch> match_functions(
    std::span<const FunctionFeature> old_functions, std::span<const FunctionFeature> new_functions,
    const FunctionMatchOptions &options = {});
enum class InstructionDiffKind { equal, changed, removed, added };
struct InstructionDiffRun {
    InstructionDiffKind kind = InstructionDiffKind::equal;
    std::uint64_t old_start = 0, new_start = 0;
    std::uint64_t old_count = 0, new_count = 0;
    InstructionChangeEvidence semantic;
};
struct FunctionInstructionDiff {
    std::vector<InstructionDiffRun> runs;
    std::uint64_t equal_instructions = 0, changed_instructions = 0;
    std::uint64_t removed_instructions = 0, added_instructions = 0;
    InstructionChangeEvidence semantic;
};
struct FunctionInstructionDiffOptions {
    // Total LCS matrix cells across exact-alignment gaps are bounded before
    // allocation; defaults to 4 million cells (about 16 MiB using 32-bit lengths).
    std::uint64_t max_dynamic_cells = 4'000'000;
    std::stop_token stop_token;
    // Called every 256 matrix rows and every 64 reconstructed instructions.
    // Work progress uses the conservative bound old_count*new_count + 2*old_count + new_count; the
    // final completion callback runs only after all runs have been coalesced.
    // Return false to cancel.
    std::function<bool(std::uint64_t, std::uint64_t)> progress;
    // Patience-style fallback indexing is used when the whole-body matrix is
    // too large. This caps the total old+new fingerprints indexed by that path.
    // Kept last to preserve positional aggregate initialization.
    std::uint64_t max_anchor_index_items = 1'000'000;
};
enum class BlockMatchKind { matched, added, removed, ambiguous };
struct BlockInstructionEvidence {
    bool available = false, adjacency_available = false;
    std::uint32_t fingerprint_similarity = 0, adjacency_similarity = 0; // 0..100 Dice overlap
};
struct BlockCorrespondence {
    BlockMatchKind kind = BlockMatchKind::ambiguous;
    std::optional<std::uint32_t> old_block, new_block;
    std::uint32_t confidence = 0;
    // Count of compatible incoming/outgoing neighbors in the accepting wave.
    std::uint32_t supporting_neighbors = 0;
    bool instruction_diff_available = false;
    bool instruction_diff_budget_exhausted = false;
    FunctionInstructionDiff instruction_diff;
    // Present only for a matched pair whose complete, nonempty normalized
    // instruction sequences were compared. Does not assert semantic equality.
    BlockInstructionEvidence instruction_evidence;
};
struct FunctionBlockCorrespondence {
    std::vector<BlockCorrespondence> blocks;
    std::uint64_t matched = 0, added = 0, removed = 0, ambiguous = 0;
    // True means the work budget stopped refinement; unresolved nodes are
    // reported as ambiguous rather than being mislabeled added/removed.
    bool budget_exhausted = false;
    bool instruction_diff_budget_exhausted = false;
};
struct FunctionBlockMatchOptions {
    std::uint32_t minimum_confidence = 45;
    std::uint32_t ambiguity_margin = 8;
    std::uint64_t max_candidate_pairs = 4'000'000;
    std::uint64_t max_edge_visits = 16'000'000;
    std::stop_token stop_token;
    std::function<bool(std::uint64_t, std::uint64_t)> progress;
    // Aggregate cells used for block-local instruction alignment.
    std::uint64_t max_instruction_diff_cells = 4'000'000;
    // Blend complete normalized token/adjacency overlap into candidate scores.
    // Zero retains graph/fingerprint-only scoring and skips derived summaries.
    std::uint32_t instruction_similarity_weight = 40;
    // Aggregate supplied instructions plus retained adjacency hashes across
    // both sides, and aggregate items scanned across all candidate comparisons.
    std::uint64_t max_instruction_fingerprint_items = 4'000'000;
    std::uint64_t max_instruction_comparison_items = 64'000'000;
};
// Correspond CFG blocks by exact address-independent fingerprints first, then
// by normalized instruction overlap, block shape and already-matched typed
// neighbors. Result indexes refer to each feature's cfg_blocks array;
// ambiguous candidates are never forced.
HEXLAB_COMPARE_EXPORT Result<FunctionBlockCorrespondence> correspond_function_blocks(
    std::span<const CfgBlockFeature> old_blocks,
    std::span<const CfgBlockFeature> new_blocks,
    const FunctionBlockMatchOptions &options = {});
struct FunctionBodyDiff {
    std::uint64_t old_entry = 0, new_entry = 0;
    std::uint32_t old_space = 0, new_space = 0;
    FunctionInstructionDiff diff;
    FunctionBlockCorrespondence block_correspondence;
};
// Align already-normalized instruction fingerprint sequences. Run indexes are
// zero-based within the supplied old and new sequences; no binary bytes needed.
HEXLAB_COMPARE_EXPORT Result<FunctionInstructionDiff> diff_function_instructions(
    std::span<const std::uint64_t> old_fingerprints,
    std::span<const std::uint64_t> new_fingerprints,
    const FunctionInstructionDiffOptions &options = {});
HEXLAB_COMPARE_EXPORT Result<FunctionInstructionDiff> diff_function_instructions_detailed(
    std::span<const std::uint64_t> old_fingerprints, std::span<const std::uint64_t> new_fingerprints,
    std::span<const InstructionSemanticFeature> old_features,
    std::span<const InstructionSemanticFeature> new_features,
    const FunctionInstructionDiffOptions &options = {});
struct CompareOptions {
    std::stop_token stop_token;
    // Called periodically with bytes visited against total estimated visits.
    // Return false to cancel; stop_token provides thread-safe external cancel.
    std::function<bool(std::uint64_t, std::uint64_t)> progress;
    std::uint64_t progress_interval = 64 * 1024;
    // At a mismatch, search up to 256 positions for an equal anchor.
    // Zero preserves strict offset-by-offset comparison.
    std::uint64_t resync_window_bytes = 16;
    // Longer anchors reduce false resynchronization on repeated byte patterns.
    // Values from 1 through 64 are accepted; the default preserves prior behavior.
    std::uint64_t resync_anchor_bytes = 4;
};
// Regions align by unique key; bytes within a matched region align by offset,
// with bounded anchor-based insertion/deletion resynchronization.
// Unequal tails are additions/removals. Every emitted address is image-relative.
HEXLAB_COMPARE_EXPORT Result<Report> compare(const ImageView &old_image, const ImageView &new_image,
                                            const CompareOptions &options = {});
} // namespace hexlab::compare
