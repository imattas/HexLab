#include "hexlab/compare/compare.hpp"

#include <algorithm>
#include <map>
#include <tuple>

namespace hexlab::compare {
namespace {
struct Edge { std::uint32_t kind = 0, target = 0; };
struct Node {
    std::uint64_t fingerprint = 0;
    std::vector<Edge> outgoing, incoming;
    std::vector<std::uint32_t> outgoing_kinds, incoming_kinds;
    std::vector<std::uint64_t> instructions, adjacency;
};
struct Candidate {
    std::uint32_t old_index, new_index, score, support;
    BlockInstructionEvidence evidence;
};

std::uint64_t instruction_pair(std::uint64_t first, std::uint64_t second) {
    auto value = first ^ (second + UINT64_C(0x9e3779b97f4a7c15) + (first << 6) + (first >> 2));
    value = (value ^ (value >> 30)) * UINT64_C(0xbf58476d1ce4e5b9);
    value = (value ^ (value >> 27)) * UINT64_C(0x94d049bb133111eb);
    return value ^ (value >> 31);
}

std::uint32_t overlap(const std::vector<std::uint64_t>& left, const std::vector<std::uint64_t>& right,
                      std::stop_token stop) {
    std::size_t i = 0, j = 0;
    std::uint64_t common = 0;
    while (i < left.size() && j < right.size()) {
        if (((i + j) & 0x3ffu) == 0 && stop.stop_requested()) return 0;
        if (left[i] < right[j]) ++i;
        else if (right[j] < left[i]) ++j;
        else { ++common; ++i; ++j; }
    }
    const auto denominator = static_cast<std::uint64_t>(left.size()) + right.size();
    // Prepared items are bounded before this deterministic integer ratio.
    return denominator ? static_cast<std::uint32_t>(200 * common / denominator) : 0;
}

BlockInstructionEvidence instruction_evidence(const Node& left, const Node& right, std::stop_token stop) {
    BlockInstructionEvidence result;
    if (left.instructions.empty() || right.instructions.empty()) return result;
    result.available = true;
    result.fingerprint_similarity = overlap(left.instructions, right.instructions, stop);
    if (!left.adjacency.empty() && !right.adjacency.empty()) {
        result.adjacency_available = true;
        result.adjacency_similarity = overlap(left.adjacency, right.adjacency, stop);
    }
    return result;
}

std::uint32_t score_pair(const Node &old_node, const Node &new_node,
                         std::span<const std::int64_t> old_to_new,
                         std::uint32_t &support, const BlockInstructionEvidence& evidence,
                         std::uint32_t instruction_weight) {
    std::uint32_t score = old_node.fingerprint == new_node.fingerprint ? 40 : 0;
    if (old_node.outgoing.size() == new_node.outgoing.size() &&
        old_node.incoming.size() == new_node.incoming.size()) score += 25;
    if (old_node.outgoing_kinds == new_node.outgoing_kinds &&
        old_node.incoming_kinds == new_node.incoming_kinds) score += 20;
    support = 0;
    std::vector<std::pair<std::uint32_t, std::uint32_t>> new_outgoing, new_incoming;
    new_outgoing.reserve(new_node.outgoing.size());
    new_incoming.reserve(new_node.incoming.size());
    for (const auto &edge : new_node.outgoing) new_outgoing.emplace_back(edge.kind, edge.target);
    for (const auto &edge : new_node.incoming) new_incoming.emplace_back(edge.kind, edge.target);
    std::sort(new_outgoing.begin(), new_outgoing.end());
    std::sort(new_incoming.begin(), new_incoming.end());
    for (const auto &edge : old_node.outgoing)
        if (old_to_new[edge.target] >= 0 &&
            std::binary_search(new_outgoing.begin(), new_outgoing.end(),
                std::pair{edge.kind, static_cast<std::uint32_t>(old_to_new[edge.target])})) ++support;
    for (const auto &edge : old_node.incoming)
        if (old_to_new[edge.target] >= 0 &&
            std::binary_search(new_incoming.begin(), new_incoming.end(),
                std::pair{edge.kind, static_cast<std::uint32_t>(old_to_new[edge.target])})) ++support;
    score += std::min<std::uint32_t>(support, 3) * 5;
    if (evidence.available) {
        const auto content = evidence.adjacency_available
            ? (70u * evidence.fingerprint_similarity + 30u * evidence.adjacency_similarity) / 100u
            : evidence.fingerprint_similarity;
        score = (score * (100u - instruction_weight) + content * instruction_weight) / 100u;
    }
    return std::min(score, 100u);
}

bool prepare(std::span<const CfgBlockFeature> source, std::vector<Node> &nodes,
             bool use_instructions, std::stop_token stop) {
    if (source.size() > UINT32_MAX) return false;
    nodes.resize(source.size());
    for (std::size_t i = 0; i < source.size(); ++i) {
        if (stop.stop_requested()) return false;
        nodes[i].fingerprint = source[i].fingerprint;
        if (use_instructions && source[i].instruction_fingerprints_available) {
            const auto& sequence = source[i].instruction_fingerprints;
            nodes[i].instructions = sequence;
            std::sort(nodes[i].instructions.begin(), nodes[i].instructions.end());
            if (sequence.size() > 1) nodes[i].adjacency.reserve(sequence.size() - 1);
            for (std::size_t instruction = 1; instruction < sequence.size(); ++instruction) {
                if ((instruction & 0x3ffu) == 0 && stop.stop_requested()) return false;
                nodes[i].adjacency.push_back(instruction_pair(sequence[instruction - 1], sequence[instruction]));
            }
            std::sort(nodes[i].adjacency.begin(), nodes[i].adjacency.end());
        }
        for (const auto &edge : source[i].successors) {
            nodes[i].outgoing.push_back({edge.kind, edge.target});
            nodes[edge.target].incoming.push_back({edge.kind, static_cast<std::uint32_t>(i)});
            nodes[i].outgoing_kinds.push_back(edge.kind);
        }
    }
    for (auto &node : nodes) {
        if (stop.stop_requested()) return false;
        for (const auto &edge : node.incoming) node.incoming_kinds.push_back(edge.kind);
        std::sort(node.outgoing_kinds.begin(), node.outgoing_kinds.end());
        std::sort(node.incoming_kinds.begin(), node.incoming_kinds.end());
    }
    return true;
}
}

Result<FunctionBlockCorrespondence> correspond_function_blocks(
    std::span<const CfgBlockFeature> old_blocks,
    std::span<const CfgBlockFeature> new_blocks,
    const FunctionBlockMatchOptions &options) {
    if (options.minimum_confidence > 100 || options.ambiguity_margin > 100 ||
        !options.max_candidate_pairs || !options.max_edge_visits ||
        options.max_instruction_diff_cells > 16'000'000 || options.instruction_similarity_weight > 100 ||
        !options.max_instruction_fingerprint_items || !options.max_instruction_comparison_items ||
        options.max_instruction_fingerprint_items > UINT64_MAX / 200)
        return Error{ErrorCode::invalid_argument, "invalid block correspondence options"};
    if (options.stop_token.stop_requested()) return Error{ErrorCode::canceled, "block correspondence canceled"};
    if (old_blocks.size() > UINT32_MAX || new_blocks.size() > UINT32_MAX)
        return Error{ErrorCode::overflow, "CFG block index exceeds 32 bits"};
    if (!old_blocks.empty() && new_blocks.size() > UINT64_MAX / old_blocks.size())
        return Error{ErrorCode::overflow, "CFG candidate count overflows"};

    std::vector<Node> old_nodes, new_nodes;
    std::uint64_t edge_count = 0, instruction_items = 0;
    for (const auto blocks : {old_blocks, new_blocks}) for (const auto& block : blocks) {
        if (options.stop_token.stop_requested()) return Error{ErrorCode::canceled, "block correspondence canceled"};
        if (!block.instruction_fingerprints_available && !block.instruction_fingerprints.empty())
            return Error{ErrorCode::invalid_argument, "unavailable block instruction fingerprints must be empty"};
        const auto items = static_cast<std::uint64_t>(block.instruction_fingerprints.size());
        const auto adjacency = options.instruction_similarity_weight && items ? items - 1 : 0;
        if (items > options.max_instruction_fingerprint_items - instruction_items)
            return Error{ErrorCode::resource_limit, "block instruction feature budget exceeded"};
        instruction_items += items;
        if (adjacency > options.max_instruction_fingerprint_items - instruction_items)
            return Error{ErrorCode::resource_limit, "block instruction feature budget exceeded"};
        instruction_items += adjacency;
        if (block.successors.size() > options.max_edge_visits - edge_count)
            return Error{ErrorCode::resource_limit, "CFG edge budget exceeded before block correspondence"};
        edge_count += block.successors.size();
        for (const auto& edge : block.successors) {
            if (options.stop_token.stop_requested()) return Error{ErrorCode::canceled, "block correspondence canceled"};
            if (edge.target >= blocks.size()) return Error{ErrorCode::invalid_argument, "CFG edge target is outside the block list"};
        }
    }
    if (!prepare(old_blocks, old_nodes, options.instruction_similarity_weight != 0, options.stop_token) ||
        !prepare(new_blocks, new_nodes, options.instruction_similarity_weight != 0, options.stop_token))
        return Error{ErrorCode::canceled, "block correspondence canceled"};

    const auto unmatched = std::int64_t{-1};
    std::vector<std::int64_t> old_to_new(old_nodes.size(), unmatched), new_to_old(new_nodes.size(), unmatched);
    std::vector<Candidate> accepted(old_nodes.size());
    std::uint64_t instruction_visits = 0;
    const auto compare_instructions = [&](std::uint32_t oi, std::uint32_t ni, BlockInstructionEvidence& evidence) {
        const auto& left = old_nodes[oi]; const auto& right = new_nodes[ni];
        if (left.instructions.empty() || right.instructions.empty()) return true;
        const auto items = static_cast<std::uint64_t>(left.instructions.size()) + right.instructions.size() +
            left.adjacency.size() + right.adjacency.size();
        if (items > options.max_instruction_comparison_items - instruction_visits) return false;
        instruction_visits += items;
        evidence = instruction_evidence(left, right, options.stop_token);
        return true;
    };
    std::map<std::uint64_t, std::vector<std::uint32_t>> old_by_fingerprint, new_by_fingerprint;
    for (std::uint32_t i = 0; i < old_nodes.size(); ++i) {
        if (options.stop_token.stop_requested()) return Error{ErrorCode::canceled, "block correspondence canceled"};
        old_by_fingerprint[old_nodes[i].fingerprint].push_back(i);
    }
    for (std::uint32_t i = 0; i < new_nodes.size(); ++i) {
        if (options.stop_token.stop_requested()) return Error{ErrorCode::canceled, "block correspondence canceled"};
        new_by_fingerprint[new_nodes[i].fingerprint].push_back(i);
    }
    bool budget_exhausted = false;
    for (const auto &[fingerprint, old_group] : old_by_fingerprint) {
        if (options.stop_token.stop_requested()) return Error{ErrorCode::canceled, "block correspondence canceled"};
        const auto found = new_by_fingerprint.find(fingerprint);
        if (old_group.size() == 1 && found != new_by_fingerprint.end() && found->second.size() == 1) {
            const auto oi = old_group.front(), ni = found->second.front();
            BlockInstructionEvidence evidence;
            if (!compare_instructions(oi, ni, evidence)) { budget_exhausted = true; break; }
            // A coarse block hash must not force an anchor when complete
            // normalized instruction evidence visibly disagrees.
            if (evidence.available && (evidence.fingerprint_similarity != 100 ||
                (evidence.adjacency_available && evidence.adjacency_similarity != 100))) continue;
            old_to_new[oi] = ni;
            new_to_old[ni] = oi;
            accepted[oi] = {oi, ni, 100, 0, evidence};
        }
    }

    std::uint64_t candidate_visits = 0, edge_visits = edge_count;
    std::vector<bool> old_had_candidate(old_nodes.size()), new_had_candidate(new_nodes.size());
    for (;;) {
        if (options.stop_token.stop_requested()) return Error{ErrorCode::canceled, "block correspondence canceled"};
        if (budget_exhausted) break;
        std::fill(old_had_candidate.begin(), old_had_candidate.end(), false);
        std::fill(new_had_candidate.begin(), new_had_candidate.end(), false);
        std::vector<Candidate> candidates;
        std::vector<std::uint32_t> old_best(old_nodes.size()), old_second(old_nodes.size());
        std::vector<std::uint32_t> new_best(new_nodes.size()), new_second(new_nodes.size());
        std::vector<std::int64_t> old_pick(old_nodes.size(), unmatched), new_pick(new_nodes.size(), unmatched);
        std::vector<bool> old_tie(old_nodes.size()), new_tie(new_nodes.size());
        for (std::uint32_t oi = 0; oi < old_nodes.size() && !budget_exhausted; ++oi) {
            if (old_to_new[oi] >= 0) continue;
            for (std::uint32_t ni = 0; ni < new_nodes.size(); ++ni) {
                if (options.stop_token.stop_requested()) return Error{ErrorCode::canceled, "block correspondence canceled"};
                if (new_to_old[ni] >= 0) continue;
                if (candidate_visits >= options.max_candidate_pairs) { budget_exhausted = true; break; }
                const auto visits = old_nodes[oi].outgoing.size() + old_nodes[oi].incoming.size() +
                                    new_nodes[ni].outgoing.size() + new_nodes[ni].incoming.size();
                if (visits > options.max_edge_visits - std::min(options.max_edge_visits, edge_visits)) {
                    budget_exhausted = true; break;
                }
                edge_visits += visits;
                ++candidate_visits;
                BlockInstructionEvidence evidence;
                if (!compare_instructions(oi, ni, evidence)) { budget_exhausted = true; break; }
                if (options.stop_token.stop_requested()) return Error{ErrorCode::canceled, "block correspondence canceled"};
                std::uint32_t support = 0;
                const auto score = score_pair(old_nodes[oi], new_nodes[ni], old_to_new, support,
                                               evidence, options.instruction_similarity_weight);
                if ((candidate_visits & 0x3ffu) == 0 && options.progress &&
                    !options.progress(candidate_visits, options.max_candidate_pairs))
                    return Error{ErrorCode::canceled, "block correspondence canceled"};
                if (score < options.minimum_confidence) continue;
                candidates.push_back({oi, ni, score, support, evidence});
                old_had_candidate[oi] = true;
                new_had_candidate[ni] = true;
                if (score > old_best[oi]) { old_second[oi] = old_best[oi]; old_best[oi] = score; old_pick[oi] = ni; old_tie[oi] = false; }
                else if (score == old_best[oi]) { old_tie[oi] = true; }
                else if (score > old_second[oi]) old_second[oi] = score;
                if (score > new_best[ni]) { new_second[ni] = new_best[ni]; new_best[ni] = score; new_pick[ni] = oi; new_tie[ni] = false; }
                else if (score == new_best[ni]) { new_tie[ni] = true; }
                else if (score > new_second[ni]) new_second[ni] = score;
            }
        }
        // Reciprocal uniqueness needs the complete candidate set. Publishing
        // part of a budget-limited wave makes matches depend on input order.
        if (budget_exhausted) break;
        bool changed = false;
        for (const auto &candidate : candidates) {
            const auto oi = candidate.old_index, ni = candidate.new_index;
            if (old_to_new[oi] >= 0 || new_to_old[ni] >= 0 || old_pick[oi] != ni || new_pick[ni] != oi ||
                old_tie[oi] || new_tie[ni] || old_best[oi] - old_second[oi] < options.ambiguity_margin ||
                new_best[ni] - new_second[ni] < options.ambiguity_margin) continue;
            old_to_new[oi] = ni; new_to_old[ni] = oi; changed = true;
            accepted[oi] = candidate;
        }
        if (!changed || budget_exhausted) break;
    }
    if (options.progress && !options.progress(options.max_candidate_pairs, options.max_candidate_pairs))
        return Error{ErrorCode::canceled, "block correspondence canceled"};

    FunctionBlockCorrespondence result;
    result.budget_exhausted = budget_exhausted;
    for (std::uint32_t oi = 0; oi < old_nodes.size(); ++oi) {
        if (options.stop_token.stop_requested()) return Error{ErrorCode::canceled, "block correspondence canceled"};
        if (old_to_new[oi] >= 0) {
            const auto ni = static_cast<std::uint32_t>(old_to_new[oi]);
            const auto& evidence = accepted[oi];
            BlockCorrespondence row{BlockMatchKind::matched, oi, ni, evidence.score, evidence.support};
            row.instruction_evidence = evidence.evidence;
            result.blocks.push_back(std::move(row));
            ++result.matched;
            continue;
        }
        const auto kind = budget_exhausted || old_had_candidate[oi] ? BlockMatchKind::ambiguous : BlockMatchKind::removed;
        result.blocks.push_back({kind, oi, {}, 0, 0});
        if (kind == BlockMatchKind::ambiguous) ++result.ambiguous; else ++result.removed;
    }
    for (std::uint32_t ni = 0; ni < new_nodes.size(); ++ni) if (new_to_old[ni] < 0) {
        if (options.stop_token.stop_requested()) return Error{ErrorCode::canceled, "block correspondence canceled"};
        const auto kind = budget_exhausted || new_had_candidate[ni] ? BlockMatchKind::ambiguous : BlockMatchKind::added;
        result.blocks.push_back({kind, {}, ni, 0, 0});
        if (kind == BlockMatchKind::ambiguous) ++result.ambiguous; else ++result.added;
    }

    // Align each confidently paired or one-sided block independently. This
    // keeps block-local edits visible when a compiler reorders basic blocks,
    // while the aggregate matrix budget prevents many small blocks from
    // multiplying into unbounded work.
    std::uint64_t remaining_instruction_cells = options.max_instruction_diff_cells;
    const std::span<const std::uint64_t> empty_instructions;
    for (auto &row : result.blocks) {
        if (options.stop_token.stop_requested()) return Error{ErrorCode::canceled, "block correspondence canceled"};
        if (row.kind == BlockMatchKind::ambiguous) continue;
        const auto old_available = !row.old_block ||
            old_blocks[*row.old_block].instruction_fingerprints_available;
        const auto new_available = !row.new_block ||
            new_blocks[*row.new_block].instruction_fingerprints_available;
        if (!old_available || !new_available) continue;
        const auto old_sequence = row.old_block
            ? std::span<const std::uint64_t>(old_blocks[*row.old_block].instruction_fingerprints)
            : empty_instructions;
        const auto new_sequence = row.new_block
            ? std::span<const std::uint64_t>(new_blocks[*row.new_block].instruction_fingerprints)
            : empty_instructions;
        if (old_sequence.size() == UINT64_MAX || new_sequence.size() == UINT64_MAX) {
            row.instruction_diff_budget_exhausted = true;
            result.instruction_diff_budget_exhausted = true;
            continue;
        }
        const auto rows = static_cast<std::uint64_t>(old_sequence.size()) + 1;
        const auto columns = static_cast<std::uint64_t>(new_sequence.size()) + 1;
        if (rows > UINT64_MAX / columns || rows * columns > remaining_instruction_cells) {
            row.instruction_diff_budget_exhausted = true;
            result.instruction_diff_budget_exhausted = true;
            continue;
        }
        const auto cells = rows * columns;
        FunctionInstructionDiffOptions diff_options;
        diff_options.max_dynamic_cells = cells;
        diff_options.stop_token = options.stop_token;
        auto diff = old_blocks[*row.old_block].instruction_semantics.size() == old_sequence.size() &&
                    new_blocks[*row.new_block].instruction_semantics.size() == new_sequence.size()
            ? diff_function_instructions_detailed(old_sequence, new_sequence,
                old_blocks[*row.old_block].instruction_semantics,
                new_blocks[*row.new_block].instruction_semantics, diff_options)
            : diff_function_instructions(old_sequence, new_sequence, diff_options);
        if (!diff) {
            if (diff.error().code == ErrorCode::canceled) return diff.error();
            row.instruction_diff_budget_exhausted = true;
            result.instruction_diff_budget_exhausted = true;
            continue;
        }
        row.instruction_diff = std::move(diff.value());
        row.instruction_diff_available = true;
        remaining_instruction_cells -= cells;
    }
    if (options.stop_token.stop_requested()) return Error{ErrorCode::canceled, "block correspondence canceled"};
    return result;
}
} // namespace hexlab::compare
