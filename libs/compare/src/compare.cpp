#include "hexlab/compare/compare.hpp"
#include <algorithm>
#include <limits>
#include <map>
#include <queue>
#include <set>
#include <unordered_map>
#include <unordered_set>

namespace hexlab::compare {
namespace {
struct WideCount {
    std::uint64_t high = 0, low = 0;
    void add(std::uint64_t value) noexcept {
        const auto previous = low;
        low += value;
        high += low < previous;
    }
};
WideCount multiply_small(WideCount value, std::uint32_t factor) noexcept {
    const auto low_product = (value.low & UINT64_C(0xffffffff)) * factor;
    const auto high_product = (value.low >> 32) * factor;
    const auto low = low_product + (high_product << 32);
    const auto carry = (high_product >> 32) + (low < low_product);
    return {value.high * factor + carry, low};
}
bool less_equal(WideCount left, WideCount right) noexcept {
    return left.high < right.high || (left.high == right.high && left.low <= right.low);
}
std::uint32_t histogram_similarity(const std::vector<std::uint32_t> &left,
                                   const std::vector<std::uint32_t> &right) noexcept {
    WideCount numerator, denominator;
    const auto count = std::max(left.size(), right.size());
    for (std::size_t i = 0; i < count; ++i) {
        const auto a = i < left.size() ? left[i] : 0;
        const auto b = i < right.size() ? right[i] : 0;
        numerator.add(std::min(a, b));
        denominator.add(std::max(a, b));
    }
    if (!denominator.high && !denominator.low) return 100;
    const auto scaled_numerator = multiply_small(numerator, 100);
    std::uint32_t low = 0, high = 101;
    while (high - low > 1) {
        const auto middle = low + (high - low) / 2;
        if (less_equal(multiply_small(denominator, middle), scaled_numerator)) low = middle;
        else high = middle;
    }
    return low;
}
bool valid(const RegionView &r, std::stop_token stop) {
    if (r.key.empty() || (!r.bytes.empty() && r.bytes.size() - 1 > UINT64_MAX - r.address)) return false;
    std::uint64_t previous_end = 0;
    bool first = true;
    std::size_t range_index = 0;
    for (const auto &range : r.ignored_ranges) {
        if ((range_index++ & 0xffu) == 0 && stop.stop_requested()) return false;
        if (!range.size || range.offset > r.bytes.size() || range.size > r.bytes.size() - range.offset ||
            (!first && range.offset < previous_end)) return false;
        previous_end = range.offset + range.size;
        first = false;
    }
    return true;
}
std::optional<Error> validate(const ImageView &image, std::stop_token stop) {
    std::unordered_set<std::string> keys;
    std::uint64_t ignored_ranges = 0;
    std::size_t region_index = 0;
    for (const auto &r : image.regions) {
        if ((region_index++ & 0xffu) == 0 && stop.stop_requested())
            return Error{ErrorCode::canceled, "comparison canceled"};
        if (r.key.empty()) return Error{ErrorCode::invalid_argument, "region key must not be empty"};
        if (!r.bytes.empty() && r.bytes.size() - 1 > UINT64_MAX - r.address)
            return Error{ErrorCode::overflow, "region address extent overflows"};
        if (!valid(r, stop)) return stop.stop_requested()
            ? std::optional<Error>{Error{ErrorCode::canceled, "comparison canceled"}}
            : std::optional<Error>{Error{ErrorCode::invalid_argument, "ignored byte ranges must be nonempty, ordered, disjoint, and inside the region"}};
        if (r.ignored_ranges.size() > 1'000'000 - ignored_ranges)
            return Error{ErrorCode::resource_limit, "ignored byte range count exceeds budget"};
        ignored_ranges += r.ignored_ranges.size();
        if (!keys.insert(r.key).second) return Error{ErrorCode::invalid_argument, "region keys must be unique per image"};
    }
    return {};
}
bool ignored_at(const RegionView &region, std::size_t offset) {
    const auto ranges = region.ignored_ranges;
    auto it = std::upper_bound(ranges.begin(), ranges.end(), static_cast<std::uint64_t>(offset),
        [](std::uint64_t value, const RegionView::IgnoredRange &range) { return value < range.offset; });
    if (it == ranges.begin()) return false;
    --it;
    return offset - static_cast<std::size_t>(it->offset) < it->size;
}
bool increment(std::uint64_t &value, std::uint64_t n = 1) {
    if (n > UINT64_MAX - value) return false;
    value += n;
    return true;
}
struct FunctionAddressHash {
    std::size_t operator()(const FunctionAddress &address) const noexcept {
        return std::hash<std::uint64_t>{}(address.entry) ^
               (std::hash<std::uint32_t>{}(address.address_space) << 1);
    }
};
struct CallGraph {
    std::vector<std::vector<std::size_t>> outgoing, incoming;
};

std::uint64_t mix_sequence_pair(std::uint64_t first, std::uint64_t second) noexcept {
    auto value = first ^ (second + UINT64_C(0x9e3779b97f4a7c15) + (first << 6) + (first >> 2));
    value += UINT64_C(0x9e3779b97f4a7c15);
    value = (value ^ (value >> 30)) * UINT64_C(0xbf58476d1ce4e5b9);
    value = (value ^ (value >> 27)) * UINT64_C(0x94d049bb133111eb);
    return value ^ (value >> 31);
}

bool sequence_sketch(std::span<const std::uint64_t> sequence, std::stop_token stop,
                     std::vector<std::uint64_t> &out) {
    constexpr std::size_t sample_limit = 128;
    std::priority_queue<std::uint64_t> smallest;
    std::unordered_set<std::uint64_t> present;
    present.reserve(sample_limit * 2);
    for (std::size_t i = 1; i < sequence.size(); ++i) {
        if ((i & 0x3ffu) == 0 && stop.stop_requested()) return false;
        const auto hash = mix_sequence_pair(sequence[i - 1], sequence[i]);
        if (present.contains(hash)) continue;
        if (smallest.size() < sample_limit) {
            smallest.push(hash);
            present.insert(hash);
        } else if (hash < smallest.top()) {
            present.erase(smallest.top());
            smallest.pop();
            smallest.push(hash);
            present.insert(hash);
        }
    }
    if (stop.stop_requested()) return false;
    out.assign(present.begin(), present.end());
    std::sort(out.begin(), out.end());
    return true;
}

bool cfg_refinement(const FunctionFeature &function, std::stop_token stop,
                    std::vector<std::uint64_t> &out) {
    constexpr std::size_t rounds = 4;
    const auto &blocks = function.cfg_blocks;
    if (blocks.empty()) return true;
    if (blocks.size() > UINT32_MAX) return false;
    std::vector<std::vector<CfgEdgeFeature>> incoming(blocks.size());
    std::vector<std::uint64_t> colors;
    colors.reserve(blocks.size());
    for (std::size_t source = 0; source < blocks.size(); ++source) {
        if (stop.stop_requested()) return false;
        const auto &block = blocks[source];
        colors.push_back(mix_sequence_pair(block.fingerprint,
            static_cast<std::uint64_t>(block.successors.size())));
        for (const auto &edge : block.successors) {
            if (edge.target >= blocks.size()) return false;
            incoming[edge.target].push_back({static_cast<std::uint32_t>(source), edge.kind});
        }
    }
    for (std::size_t round = 0; round < rounds; ++round) {
        if (stop.stop_requested()) return false;
        std::vector<std::uint64_t> next(blocks.size());
        for (std::size_t node = 0; node < blocks.size(); ++node) {
            if ((node & 0x3ffu) == 0 && stop.stop_requested()) return false;
            std::vector<std::pair<std::uint64_t, std::uint64_t>> neighbors;
            neighbors.reserve(blocks[node].successors.size() + incoming[node].size());
            for (const auto &edge : blocks[node].successors)
                neighbors.emplace_back((UINT64_C(1) << 32) | edge.kind, colors[edge.target]);
            for (const auto &edge : incoming[node])
                neighbors.emplace_back(edge.kind, colors[edge.target]);
            std::sort(neighbors.begin(), neighbors.end());
            auto color = mix_sequence_pair(colors[node], round + 1);
            color = mix_sequence_pair(color, neighbors.size());
            for (const auto &[edge, neighbor] : neighbors) {
                color = mix_sequence_pair(color, edge);
                color = mix_sequence_pair(color, neighbor);
            }
            next[node] = color;
        }
        colors = std::move(next);
    }
    std::sort(colors.begin(), colors.end());
    out = std::move(colors);
    return true;
}
}

Result<std::vector<FunctionMatch>> match_functions_detailed(
    std::span<const FunctionFeature> old_functions, std::span<const FunctionFeature> new_functions,
    const FunctionMatchOptions &options) {
    const auto &weights = options.weights;
    if (options.minimum_confidence > 100 || options.ambiguity_margin > 100 || options.max_candidate_pairs == 0 ||
        options.max_fingerprint_items == 0 || options.max_call_edges == 0 || options.max_context_edge_visits == 0 ||
        options.max_semantic_items == 0 ||
        weights.fingerprint_weight > 100 || weights.histogram_weight > 100 ||
        weights.instruction_count_weight > 100 || weights.block_count_weight > 100 ||
        weights.call_count_weight > 100 || weights.same_name_floor > 100 || weights.shape_only_ceiling > 100 ||
        weights.cfg_weight > 100 || weights.sequence_weight > 100 || options.max_sequence_items == 0 ||
        (weights.instruction_count_weight == 0 && weights.block_count_weight == 0 &&
         weights.call_count_weight == 0))
        return Error{ErrorCode::invalid_argument, "invalid function matching options"};
    if (!old_functions.empty() && new_functions.size() > UINT64_MAX / old_functions.size())
        return Error{ErrorCode::overflow, "function candidate count overflows"};
    const auto pair_count = static_cast<std::uint64_t>(old_functions.size()) * new_functions.size();
    if (pair_count > options.max_candidate_pairs)
        return Error{ErrorCode::invalid_argument, "function candidate budget exceeded"};
    const auto valid_cfgs = [](auto functions) {
        for (const auto &function : functions) {
            if (function.cfg_blocks.size() > UINT32_MAX) return false;
            for (const auto &block : function.cfg_blocks)
                for (const auto &edge : block.successors)
                    if (edge.target >= function.cfg_blocks.size()) return false;
        }
        return true;
    };
    if (!valid_cfgs(old_functions) || !valid_cfgs(new_functions))
        return Error{ErrorCode::invalid_argument, "function CFG edge target is outside its block list"};
    std::uint64_t fingerprint_items = 0, histogram_items = 0, call_edges = 0, semantic_items = 0;
    const auto count_semantics = [&](const auto &items, std::size_t expected) -> bool {
        // Semantic-only frontends may omit the duplicate top-level fingerprint
        // vector; every semantic record still carries its normalized identity.
        if ((!items.empty() && expected != 0 && items.size() != expected) ||
            items.size() > options.max_semantic_items - semantic_items) return false;
        semantic_items += items.size();
        return true;
    };
    const auto count_fingerprints = [&](auto functions) -> bool {
        for (const auto &fn : functions) {
            if (!count_semantics(fn.instruction_semantics, fn.instruction_fingerprints.size())) return false;
            const auto instruction_items = fn.instruction_fingerprints.empty()
                ? fn.instruction_semantics.size() : fn.instruction_fingerprints.size();
            if (instruction_items > options.max_fingerprint_items - fingerprint_items) return false;
            fingerprint_items += instruction_items;
            if (fn.cfg_fingerprints.size() > options.max_fingerprint_items - fingerprint_items) return false;
            fingerprint_items += fn.cfg_fingerprints.size();
            if (fn.cfg_blocks.size() > options.max_fingerprint_items - fingerprint_items) return false;
            fingerprint_items += fn.cfg_blocks.size();
            for (std::size_t source = 0; source < fn.cfg_blocks.size(); ++source) {
                const auto &block = fn.cfg_blocks[source];
                if ((!block.instruction_semantics.empty() &&
                     (!block.instruction_fingerprints_available ||
                      block.instruction_semantics.size() != block.instruction_fingerprints.size())) ||
                    block.instruction_semantics.size() > options.max_semantic_items - semantic_items)
                    return false;
                semantic_items += block.instruction_semantics.size();
                const auto total_instructions = block.instruction_count ? block.instruction_count
                                                                         : block.instruction_fingerprints.size();
                if ((!block.instruction_fingerprints_available &&
                     (!block.instruction_fingerprints.empty() || !block.instruction_fingerprint_positions.empty())) ||
                    block.instruction_fingerprint_positions.size() &&
                        block.instruction_fingerprint_positions.size() != block.instruction_fingerprints.size() ||
                    block.instruction_fingerprints.size() > total_instructions ||
                    (block.instruction_fingerprints_complete &&
                     block.instruction_fingerprints.size() != total_instructions) ||
                    (!block.instruction_fingerprints_available && block.instruction_fingerprints_complete && total_instructions))
                    return false;
                std::uint64_t previous_position = 0;
                for (std::size_t i = 0; i < block.instruction_fingerprint_positions.size(); ++i) {
                    const auto position = block.instruction_fingerprint_positions[i];
                    if (position >= total_instructions || (i && position <= previous_position)) return false;
                    previous_position = position;
                }
                if (block.successors.size() > options.max_fingerprint_items - fingerprint_items) return false;
                fingerprint_items += block.successors.size();
                if (block.instruction_fingerprints.size() > options.max_fingerprint_items - fingerprint_items)
                    return false;
                fingerprint_items += block.instruction_fingerprints.size();
                if (block.instruction_fingerprint_positions.size() > options.max_fingerprint_items - fingerprint_items)
                    return false;
                fingerprint_items += block.instruction_fingerprint_positions.size();
                for (const auto &edge : block.successors)
                    if (edge.target >= fn.cfg_blocks.size()) return false;
            }
            if (fn.opcode_histogram.size() > options.max_opcode_histogram_items - histogram_items) return false;
            histogram_items += fn.opcode_histogram.size();
            if (fn.direct_calls.size() > options.max_call_edges - call_edges) return false;
            call_edges += fn.direct_calls.size();
        }
        return true;
    };
    if (!count_fingerprints(old_functions) || !count_fingerprints(new_functions))
        return Error{ErrorCode::invalid_argument, "function feature or semantic-record budget exceeded"};
    const bool refine = call_edges != 0 && options.max_call_graph_rounds != 0;
    const auto phases = 1ull + (refine ? options.max_call_graph_rounds : 0);
    if (pair_count > UINT64_MAX / phases)
        return Error{ErrorCode::overflow, "function progress estimate overflows"};
    const auto matching_work = pair_count * phases;
    if (call_edges > UINT64_MAX - matching_work)
        return Error{ErrorCode::overflow, "function progress estimate overflows"};
    const auto total_work = matching_work + call_edges;
    std::uint64_t visited = 0;
    const auto progress = [&](bool force = false) {
        return !options.stop_token.stop_requested() &&
            (!options.progress || (!force && (visited & 0x3ffu) != 0) || options.progress(visited, total_work));
    };
    std::vector<std::vector<std::uint64_t>> old_fingerprints, new_fingerprints;
    std::vector<std::vector<std::uint64_t>> old_cfg, new_cfg;
    std::vector<std::vector<std::uint64_t>> old_cfg_graph, new_cfg_graph;
    std::vector<std::uint64_t> old_cfg_work, new_cfg_work;
    std::vector<std::vector<std::uint64_t>> old_sequence, new_sequence;
    old_fingerprints.reserve(old_functions.size());
    new_fingerprints.reserve(new_functions.size());
    old_cfg.reserve(old_functions.size());
    new_cfg.reserve(new_functions.size());
    const auto prepare_fingerprints = [&](auto functions, auto &prepared, auto &prepared_cfg) -> bool {
        for (const auto &fn : functions) {
            if (options.stop_token.stop_requested()) return false;
            prepared.push_back(fn.instruction_fingerprints);
            if (prepared.back().empty() && !fn.instruction_semantics.empty()) {
                prepared.back().reserve(fn.instruction_semantics.size());
                for (const auto &instruction : fn.instruction_semantics)
                    prepared.back().push_back(instruction.fingerprint);
            }
            std::sort(prepared.back().begin(), prepared.back().end());
            prepared_cfg.push_back(fn.cfg_fingerprints);
            std::sort(prepared_cfg.back().begin(), prepared_cfg.back().end());
        }
        return true;
    };
    if (!prepare_fingerprints(old_functions, old_fingerprints, old_cfg) ||
        !prepare_fingerprints(new_functions, new_fingerprints, new_cfg))
        return Error{ErrorCode::canceled, "function matching canceled"};
    const auto prepare_cfg_graph = [&](auto functions, auto &prepared, auto &work_items) -> bool {
        prepared.reserve(functions.size());
        work_items.reserve(functions.size());
        for (const auto &function : functions) {
            std::vector<std::uint64_t> colors;
            if (!cfg_refinement(function, options.stop_token, colors)) return false;
            std::uint64_t items = static_cast<std::uint64_t>(function.cfg_blocks.size());
            for (const auto &block : function.cfg_blocks) {
                if (block.successors.size() > UINT64_MAX - items) return false;
                items += static_cast<std::uint64_t>(block.successors.size());
            }
            prepared.push_back(std::move(colors));
            work_items.push_back(items);
        }
        return true;
    };
    if (!prepare_cfg_graph(old_functions, old_cfg_graph, old_cfg_work) ||
        !prepare_cfg_graph(new_functions, new_cfg_graph, new_cfg_work)) {
        if (options.stop_token.stop_requested()) return Error{ErrorCode::canceled, "function matching canceled"};
        return Error{ErrorCode::invalid_argument, "invalid function CFG edge or refinement budget"};
    }
    std::uint64_t sequence_items = 0;
    const auto prepare_sequence = [&](auto functions, auto &prepared) -> bool {
        prepared.reserve(functions.size());
        for (const auto &function : functions) {
            if (options.stop_token.stop_requested()) return false;
            std::vector<std::uint64_t> sketch;
            auto instructions = function.instruction_fingerprints;
            if (instructions.empty() && !function.instruction_semantics.empty()) {
                instructions.reserve(function.instruction_semantics.size());
                for (const auto &instruction : function.instruction_semantics)
                    instructions.push_back(instruction.fingerprint);
            }
            if (!sequence_sketch(instructions, options.stop_token, sketch)) return false;
            if (sketch.size() > options.max_sequence_items - sequence_items) return false;
            sequence_items += sketch.size();
            prepared.push_back(std::move(sketch));
        }
        return true;
    };
    if (weights.sequence_weight == 0) {
        old_sequence.resize(old_functions.size());
        new_sequence.resize(new_functions.size());
    } else if (!prepare_sequence(old_functions, old_sequence) || !prepare_sequence(new_functions, new_sequence)) {
        if (options.stop_token.stop_requested())
            return Error{ErrorCode::canceled, "function matching canceled"};
        return Error{ErrorCode::invalid_argument, "function sequence-feature budget exceeded"};
    }
    const auto ratio = [](std::uint64_t x, std::uint64_t y) -> std::uint32_t {
        const auto hi = std::max(x, y), lo = std::min(x, y);
        return hi ? static_cast<std::uint32_t>((100.0L * static_cast<long double>(lo)) /
                                               static_cast<long double>(hi)) : 100;
    };
    const auto multiset_similarity = [](const auto &left, const auto &right) -> std::uint32_t {
        std::size_t i = 0, j = 0;
        std::uint64_t common = 0;
        while (i < left.size() && j < right.size()) {
            if (left[i] < right[j]) ++i;
            else if (right[j] < left[i]) ++j;
            else { ++common; ++i; ++j; }
        }
        const auto denom = static_cast<std::uint64_t>(left.size()) + right.size();
        return denom ? static_cast<std::uint32_t>((200 * common) / denom) : 100u;
    };
    struct ScoredCandidate { std::uint32_t total = 0; FunctionScoreBreakdown detail{}; };
    const auto similarity = [&](const FunctionFeature &a, const FunctionFeature &b,
                                const auto &left, const auto &right,
                                const auto &left_cfg, const auto &right_cfg,
                                const auto &left_sequence, const auto &right_sequence) -> ScoredCandidate {
        ScoredCandidate result;
        if (a.architecture != b.architecture) return result;
        const bool named = !a.name.empty() && a.name == b.name;
        result.detail.available = true;
        result.detail.exact_name = named;
        const auto shape_weight = weights.instruction_count_weight + weights.block_count_weight +
                                  weights.call_count_weight;
        const auto shape = static_cast<std::uint32_t>(
            (static_cast<std::uint64_t>(ratio(a.instruction_count, b.instruction_count)) *
                 weights.instruction_count_weight +
             static_cast<std::uint64_t>(ratio(a.block_count, b.block_count)) * weights.block_count_weight +
             static_cast<std::uint64_t>(ratio(a.call_count, b.call_count)) * weights.call_count_weight) /
            shape_weight);
        result.detail.shape_available = true;
        result.detail.shape_similarity = shape;
        std::uint32_t score = shape;
        if (!left.empty() || !right.empty()) {
            // Multiset Dice similarity is independent of instruction order and load address.
            auto fingerprint_score = multiset_similarity(left, right);
            if (weights.sequence_weight != 0 && (!left_sequence.empty() || !right_sequence.empty())) {
                const auto ordered_score = multiset_similarity(left_sequence, right_sequence);
                fingerprint_score = static_cast<std::uint32_t>(
                    (static_cast<std::uint64_t>(ordered_score) * weights.sequence_weight +
                     static_cast<std::uint64_t>(fingerprint_score) * (100u - weights.sequence_weight)) / 100u);
            }
            result.detail.instruction_available = true;
            result.detail.instruction_similarity = fingerprint_score;
            score = (fingerprint_score * weights.fingerprint_weight +
                     shape * (100u - weights.fingerprint_weight)) / 100u;
        } else if (!a.opcode_histogram.empty() || !b.opcode_histogram.empty()) {
            const auto hist = histogram_similarity(a.opcode_histogram, b.opcode_histogram);
            result.detail.histogram_available = true;
            result.detail.histogram_similarity = hist;
            score = (hist * weights.histogram_weight + shape * (100u - weights.histogram_weight)) / 100u;
        } else {
            // Coarse counts alone are not enough to assert a correspondence.
            score = std::min(score, weights.shape_only_ceiling);
        }
        if (!left_cfg.empty() || !right_cfg.empty()) {
            const auto cfg_score = multiset_similarity(left_cfg, right_cfg);
            result.detail.cfg_available = true;
            result.detail.cfg_similarity = cfg_score;
            score = (cfg_score * weights.cfg_weight + score * (100u - weights.cfg_weight)) / 100u;
        }
        if (named && score < weights.same_name_floor) {
            score = weights.same_name_floor;
            result.detail.name_floor_applied = true;
        }
        result.total = score;
        return result;
    };

    std::vector<ScoredCandidate> scores(static_cast<std::size_t>(pair_count));
    std::vector<std::uint32_t> old_best(old_functions.size()), new_best(new_functions.size());
    std::uint64_t cfg_comparison_items = 0;
    for (std::size_t oi = 0; oi < old_functions.size(); ++oi) {
        for (std::size_t ni = 0; ni < new_functions.size(); ++ni) {
            if (options.stop_token.stop_requested()) return Error{ErrorCode::canceled, "function matching canceled"};
            const auto cfg_items = static_cast<std::uint64_t>(old_cfg[oi].size()) +
                                   static_cast<std::uint64_t>(new_cfg[ni].size()) +
                                   ((!old_cfg_graph[oi].empty() && !new_cfg_graph[ni].empty())
                                        ? old_cfg_work[oi] + new_cfg_work[ni] : 0);
            if (cfg_items > options.max_cfg_comparison_items -
                                std::min(options.max_cfg_comparison_items, cfg_comparison_items))
                return Error{ErrorCode::invalid_argument, "function CFG comparison budget exceeded"};
            cfg_comparison_items += cfg_items;
            const auto scored = similarity(old_functions[oi], new_functions[ni], old_fingerprints[oi],
                                          new_fingerprints[ni],
                                          (!old_cfg_graph[oi].empty() && !new_cfg_graph[ni].empty())
                                              ? old_cfg_graph[oi] : old_cfg[oi],
                                          (!old_cfg_graph[oi].empty() && !new_cfg_graph[ni].empty())
                                              ? new_cfg_graph[ni] : new_cfg[ni],
                                          old_sequence[oi], new_sequence[ni]);
            scores[oi * new_functions.size() + ni] = scored;
            const auto score = scored.total;
            old_best[oi] = std::max(old_best[oi], score);
            new_best[ni] = std::max(new_best[ni], score);
            ++visited;
            if (!progress(visited == pair_count))
                return Error{ErrorCode::canceled, "function matching canceled"};
        }
    }
    const auto tied_old = [&](std::size_t oi) {
        if (old_best[oi] < options.minimum_confidence) return false;
        std::size_t count = 0;
        for (std::size_t ni = 0; ni < new_functions.size(); ++ni)
            if (old_best[oi] - scores[oi * new_functions.size() + ni].total <= options.ambiguity_margin) ++count;
        return count > 1;
    };
    const auto tied_new = [&](std::size_t ni) {
        if (new_best[ni] < options.minimum_confidence) return false;
        std::size_t count = 0;
        for (std::size_t oi = 0; oi < old_functions.size(); ++oi)
            if (new_best[ni] - scores[oi * new_functions.size() + ni].total <= options.ambiguity_margin) ++count;
        return count > 1;
    };
    const auto unmatched = std::numeric_limits<std::size_t>::max();
    std::vector<std::size_t> old_to_new(old_functions.size(), unmatched), new_to_old(new_functions.size(), unmatched);
    std::vector<FunctionMatchEvidence> evidence(old_functions.size());
    for (std::size_t oi = 0; oi < old_functions.size(); ++oi) {
        if (options.stop_token.stop_requested()) return Error{ErrorCode::canceled, "function matching canceled"};
        if (old_best[oi] == 0 || old_best[oi] < options.minimum_confidence) continue;
        std::size_t best_ni = 0;
        while (best_ni < new_functions.size() && scores[oi * new_functions.size() + best_ni].total != old_best[oi]) ++best_ni;
        const bool ambiguous = tied_old(oi) || best_ni == new_functions.size() || tied_new(best_ni) ||
                               new_best[best_ni] != old_best[oi];
        if (ambiguous) continue;
        old_to_new[oi] = best_ni;
        new_to_old[best_ni] = oi;
        evidence[oi].base_confidence = old_best[oi];
        evidence[oi].score_breakdown = scores[oi * new_functions.size() + best_ni].detail;
    }

    const auto build_graph = [&](auto functions) -> Result<CallGraph> {
        CallGraph graph;
        graph.outgoing.resize(functions.size()); graph.incoming.resize(functions.size());
        std::unordered_map<FunctionAddress, std::size_t, FunctionAddressHash> by_address;
        for (std::size_t i = 0; i < functions.size(); ++i) {
            if (options.stop_token.stop_requested()) return Error{ErrorCode::canceled, "function matching canceled"};
            if (!by_address.emplace(FunctionAddress{functions[i].entry, functions[i].address_space}, i).second)
                return Error{ErrorCode::invalid_argument, "function addresses must be unique per image and address space"};
        }
        for (std::size_t i = 0; i < functions.size(); ++i) {
            auto &targets = graph.outgoing[i];
            for (const auto &call : functions[i].direct_calls) {
                if (options.stop_token.stop_requested()) return Error{ErrorCode::canceled, "function matching canceled"};
                if (const auto found = by_address.find(call); found != by_address.end()) targets.push_back(found->second);
            }
            std::sort(targets.begin(), targets.end());
            targets.erase(std::unique(targets.begin(), targets.end()), targets.end());
            for (const auto target : targets) graph.incoming[target].push_back(i);
        }
        return graph;
    };
    if (refine) {
        auto old_graph = build_graph(old_functions);
        if (!old_graph) return old_graph.error();
        auto new_graph = build_graph(new_functions);
        if (!new_graph) return new_graph.error();
        std::uint64_t edge_visits = 0;
        bool budget_exceeded = false;
        const auto same_neighborhood = [&](const auto &left, const auto &right, std::uint64_t &support) {
            std::uint64_t old_count = 0, new_count = 0;
            for (const auto index : left) {
                if (!increment(edge_visits) || edge_visits > options.max_context_edge_visits) { budget_exceeded = true; return false; }
                if (options.stop_token.stop_requested()) return false;
                if (old_to_new[index] == unmatched) continue;
                ++old_count;
                if (!std::binary_search(right.begin(), right.end(), old_to_new[index])) return false;
            }
            for (const auto index : right) {
                if (!increment(edge_visits) || edge_visits > options.max_context_edge_visits) { budget_exceeded = true; return false; }
                if (options.stop_token.stop_requested()) return false;
                if (new_to_old[index] != unmatched) ++new_count;
            }
            support += old_count;
            return old_count == new_count;
        };
        for (std::uint64_t round = 1; round <= options.max_call_graph_rounds; ++round) {
            std::vector<std::size_t> candidates(old_functions.size(), unmatched);
            std::vector<std::size_t> old_counts(old_functions.size()), new_counts(new_functions.size());
            std::vector<std::uint64_t> supports(old_functions.size());
            for (std::size_t oi = 0; oi < old_functions.size(); ++oi) {
                for (std::size_t ni = 0; ni < new_functions.size(); ++ni) {
                    ++visited;
                    if (!progress()) return Error{ErrorCode::canceled, "function matching canceled"};
                    const auto score = scores[oi * new_functions.size() + ni].total;
                    if (old_to_new[oi] != unmatched || new_to_old[ni] != unmatched ||
                        old_functions[oi].architecture != new_functions[ni].architecture ||
                        score == 0 || score < options.minimum_confidence || old_best[oi] - score > options.ambiguity_margin ||
                        new_best[ni] - score > options.ambiguity_margin) continue;
                    std::uint64_t support = 0;
                    const bool same_out = same_neighborhood(old_graph.value().outgoing[oi],
                                                           new_graph.value().outgoing[ni], support);
                    const bool same_in = same_out && same_neighborhood(old_graph.value().incoming[oi],
                                                                      new_graph.value().incoming[ni], support);
                    if (budget_exceeded) return Error{ErrorCode::invalid_argument, "function call-context budget exceeded"};
                    if (options.stop_token.stop_requested()) return Error{ErrorCode::canceled, "function matching canceled"};
                    if (!same_in || support == 0) continue;
                    ++old_counts[oi]; ++new_counts[ni]; candidates[oi] = ni; supports[oi] = support;
                }
            }
            if (!progress(true)) return Error{ErrorCode::canceled, "function matching canceled"};
            bool changed = false;
            // Publish the entire wave together: iteration order cannot create evidence.
            for (std::size_t oi = 0; oi < old_functions.size(); ++oi) {
                const auto ni = candidates[oi];
                if (old_counts[oi] != 1 || new_counts[ni] != 1) continue;
                old_to_new[oi] = ni; new_to_old[ni] = oi;
                evidence[oi].base_confidence = scores[oi * new_functions.size() + ni].total;
                evidence[oi].supporting_call_neighbors = supports[oi];
                evidence[oi].call_graph_round = static_cast<std::uint32_t>(round);
                evidence[oi].score_breakdown = scores[oi * new_functions.size() + ni].detail;
                changed = true;
            }
            if (!changed) break;
        }
    }
    visited = matching_work;
    if (!progress(true)) return Error{ErrorCode::canceled, "function matching canceled"};
    std::vector<FunctionMatch> result;
    result.reserve(old_functions.size() + new_functions.size());
    for (std::size_t oi = 0; oi < old_functions.size(); ++oi) {
        const auto &fn = old_functions[oi];
        const auto ni = old_to_new[oi];
        if (ni != unmatched) {
            const auto &other = new_functions[ni];
            result.push_back({FunctionMatchKind::matched, fn.entry, other.entry, evidence[oi].base_confidence,
                              fn.address_space, other.address_space, fn.name, other.name, evidence[oi]});
        } else {
            const auto kind = old_best[oi] == 0 || old_best[oi] < options.minimum_confidence ? FunctionMatchKind::removed : FunctionMatchKind::ambiguous;
            result.push_back({kind, fn.entry, {}, kind == FunctionMatchKind::removed ? 0 : old_best[oi],
                              fn.address_space, 0, fn.name, {}, {old_best[oi], 0, 0}});
        }
    }
    for (std::size_t ni = 0; ni < new_functions.size(); ++ni)
        if (new_to_old[ni] == unmatched) result.push_back({FunctionMatchKind::added, {}, new_functions[ni].entry, 0, 0,
                                            new_functions[ni].address_space, {}, new_functions[ni].name});

    // Summarize outgoing in-image direct-call target changes only when both
    // frontends explicitly provide complete call-target sets for the matched
    // caller. Target pairs are compared through the final ambiguity-preserving
    // function mapping, never by their raw addresses.
    using QualifiedEntry = std::pair<std::uint32_t, std::uint64_t>;
    std::map<QualifiedEntry, std::size_t> match_by_old, match_by_new;
    std::map<QualifiedEntry, const FunctionFeature *> feature_by_old, feature_by_new;
    for (std::size_t i = 0; i < old_functions.size(); ++i) {
        if (options.stop_token.stop_requested()) return Error{ErrorCode::canceled, "function matching canceled"};
        feature_by_old.emplace(QualifiedEntry{old_functions[i].address_space, old_functions[i].entry}, &old_functions[i]);
    }
    for (std::size_t i = 0; i < new_functions.size(); ++i) {
        if (options.stop_token.stop_requested()) return Error{ErrorCode::canceled, "function matching canceled"};
        feature_by_new.emplace(QualifiedEntry{new_functions[i].address_space, new_functions[i].entry}, &new_functions[i]);
    }
    for (std::size_t i = 0; i < result.size(); ++i) {
        if (options.stop_token.stop_requested()) return Error{ErrorCode::canceled, "function matching canceled"};
        const auto &match = result[i];
        if (match.old_entry) match_by_old.emplace(QualifiedEntry{match.old_space, *match.old_entry}, i);
        if (match.new_entry) match_by_new.emplace(QualifiedEntry{match.new_space, *match.new_entry}, i);
    }
    for (auto &caller : result) {
        if (options.stop_token.stop_requested()) return Error{ErrorCode::canceled, "function matching canceled"};
        if (caller.kind != FunctionMatchKind::matched || !caller.old_entry || !caller.new_entry) continue;
        const auto old_source = feature_by_old.find({caller.old_space, *caller.old_entry});
        const auto new_source = feature_by_new.find({caller.new_space, *caller.new_entry});
        if (old_source == feature_by_old.end() || new_source == feature_by_new.end() ||
            !old_source->second->direct_calls_complete || !new_source->second->direct_calls_complete) continue;
        auto &summary = caller.call_targets;
        summary.available = true;
        std::set<QualifiedEntry> old_calls, new_calls;
        for (const auto &target : old_source->second->direct_calls) {
            if (options.stop_token.stop_requested()) return Error{ErrorCode::canceled, "function matching canceled"};
            old_calls.emplace(target.address_space, target.entry);
            ++visited;
            if (!progress()) return Error{ErrorCode::canceled, "function matching canceled"};
        }
        for (const auto &target : new_source->second->direct_calls) {
            if (options.stop_token.stop_requested()) return Error{ErrorCode::canceled, "function matching canceled"};
            new_calls.emplace(target.address_space, target.entry);
            ++visited;
            if (!progress()) return Error{ErrorCode::canceled, "function matching canceled"};
        }
        for (const auto &target : old_calls) {
            if (options.stop_token.stop_requested()) return Error{ErrorCode::canceled, "function matching canceled"};
            const auto mapped = match_by_old.find(target);
            if (mapped == match_by_old.end()) { ++summary.ambiguous; continue; }
            const auto &callee = result[mapped->second];
            if (callee.kind == FunctionMatchKind::matched && callee.new_entry) {
                if (new_calls.contains({callee.new_space, *callee.new_entry})) ++summary.unchanged;
                else ++summary.removed;
            } else if (callee.kind == FunctionMatchKind::removed) {
                ++summary.removed;
            } else {
                ++summary.ambiguous;
            }
        }
        for (const auto &target : new_calls) {
            if (options.stop_token.stop_requested()) return Error{ErrorCode::canceled, "function matching canceled"};
            const auto mapped = match_by_new.find(target);
            if (mapped == match_by_new.end()) { ++summary.ambiguous; continue; }
            const auto &callee = result[mapped->second];
            if (callee.kind == FunctionMatchKind::matched && callee.old_entry) {
                if (!old_calls.contains({callee.old_space, *callee.old_entry})) ++summary.added;
            } else if (callee.kind == FunctionMatchKind::added) {
                ++summary.added;
            } else if (callee.kind == FunctionMatchKind::ambiguous) {
                ++summary.ambiguous;
            } else {
                ++summary.ambiguous;
            }
        }
    }
    visited = total_work;
    if (!progress(true)) return Error{ErrorCode::canceled, "function matching canceled"};
    return result;
}

std::vector<FunctionMatch> match_functions(std::span<const FunctionFeature> old_functions,
                                           std::span<const FunctionFeature> new_functions,
                                           const FunctionMatchOptions &options) {
    auto result = match_functions_detailed(old_functions, new_functions, options);
    if (result) return std::move(result.value());
    std::vector<FunctionMatch> fallback;
    fallback.reserve(old_functions.size() + new_functions.size());
    for (const auto &fn : old_functions)
        fallback.push_back({FunctionMatchKind::ambiguous, fn.entry, {}, 0, fn.address_space, 0, fn.name, {}});
    for (const auto &fn : new_functions)
        fallback.push_back({FunctionMatchKind::added, {}, fn.entry, 0, 0, fn.address_space, {}, fn.name});
    return fallback;
}

Result<Report> compare(const ImageView &old_image, const ImageView &new_image,
                       const CompareOptions &options) {
    if (options.resync_anchor_bytes == 0 || options.resync_anchor_bytes > 64)
        return Error{ErrorCode::invalid_argument, "resynchronization anchor length must be between 1 and 64 bytes"};
    if (options.stop_token.stop_requested()) return Error{ErrorCode::canceled, "comparison canceled"};
    if (auto e = validate(old_image, options.stop_token)) return *e;
    if (auto e = validate(new_image, options.stop_token)) return *e;
    if (old_image.regions.size() > 2'000'000 || new_image.regions.size() > 2'000'000 ||
        old_image.regions.size() > 2'000'000 - std::min<std::size_t>(new_image.regions.size(), 2'000'000))
        return Error{ErrorCode::resource_limit, "comparison region count exceeds 2 million"};
    std::unordered_map<std::string, const RegionView *> newer;
    std::size_t setup_index = 0;
    for (const auto &r : new_image.regions) {
        if ((setup_index++ & 0xffu) == 0 && options.stop_token.stop_requested())
            return Error{ErrorCode::canceled, "comparison canceled"};
        newer.emplace(r.key, &r);
    }
    std::unordered_map<std::string, const RegionView *> older;
    setup_index = 0;
    for (const auto &r : old_image.regions) {
        if ((setup_index++ & 0xffu) == 0 && options.stop_token.stop_requested())
            return Error{ErrorCode::canceled, "comparison canceled"};
        older.emplace(r.key, &r);
    }
    std::unordered_set<std::string> visited;
    std::uint64_t total = 0;
    setup_index = 0;
    for (const auto &r : old_image.regions) {
        if ((setup_index++ & 0xffu) == 0 && options.stop_token.stop_requested())
            return Error{ErrorCode::canceled, "comparison canceled"};
        if (!increment(total, r.bytes.size())) return Error{ErrorCode::overflow, "comparison size overflows"};
    }
    setup_index = 0;
    for (const auto &r : new_image.regions) {
        if ((setup_index++ & 0xffu) == 0 && options.stop_token.stop_requested())
            return Error{ErrorCode::canceled, "comparison canceled"};
        const auto found = older.find(r.key);
        const auto old_size = found == older.end() ? 0 : found->second->bytes.size();
        if (r.bytes.size() > old_size && !increment(total, r.bytes.size() - old_size))
            return Error{ErrorCode::overflow, "comparison size overflows"};
    }
    Report report;
    report.region_summaries_available = true;
    std::uint64_t progressed = 0, since_callback = 0;
    std::optional<ChangeRun> last_logical_run;
    bool last_logical_run_retained = false;
    const auto canceled = [&]() { return options.stop_token.stop_requested(); };
    const auto emit = [&](ChangeKind kind, const std::string &key, std::optional<std::uint64_t> old_addr,
                          std::optional<std::uint64_t> new_addr) {
        const auto follows = [](const auto &address, const auto &previous, std::uint64_t size) {
            return (!address && !previous) || (address && previous && size <= UINT64_MAX - *previous &&
                                                *address == *previous + size);
        };
        if (last_logical_run && last_logical_run->kind == kind && last_logical_run->region_key == key &&
            last_logical_run->size != UINT64_MAX && follows(old_addr, last_logical_run->old_address, last_logical_run->size) &&
            follows(new_addr, last_logical_run->new_address, last_logical_run->size)) {
            ++last_logical_run->size;
            if (last_logical_run_retained) ++report.runs.back().size;
            return;
        }
        if (report.total_runs != UINT64_MAX) ++report.total_runs;
        last_logical_run = ChangeRun{kind, key, old_addr, new_addr, 1};
        last_logical_run_retained = report.runs.size() < options.max_change_runs;
        if (last_logical_run_retained) report.runs.push_back(*last_logical_run);
        else report.runs_truncated = true;
    };
    const auto account_progress = [&](bool force = false) -> bool {
        if (canceled()) return false;
        if (options.progress && (force || since_callback >= std::max<std::uint64_t>(1, options.progress_interval))) {
            if (!options.progress(progressed, total)) return false;
            since_callback = 0;
        }
        return true;
    };
    const auto account_byte = [&]() -> bool {
        if (!increment(progressed) || !increment(since_callback)) return false;
        return account_progress();
    };
    for (const auto &old_region : old_image.regions) {
        if (canceled()) return Error{ErrorCode::canceled, "comparison canceled"};
        const auto found = newer.find(old_region.key);
        if (found == newer.end()) {
            ++report.summary.removed_regions;
            RegionSummary region;
            region.region_key = old_region.key;
            region.kind = RegionChangeKind::removed;
            region.old_address = old_region.address;
            region.old_size = old_region.bytes.size();
            region.removed_bytes = old_region.bytes.size();
            report.regions.push_back(std::move(region));
            for (std::size_t i = 0; i < old_region.bytes.size(); ++i) {
                emit(ChangeKind::removed, old_region.key, old_region.address + i, {});
                if (!increment(report.summary.removed_bytes) || !account_byte()) return Error{ErrorCode::canceled, "comparison canceled"};
            }
            continue;
        }
        visited.insert(old_region.key);
        ++report.summary.matched_regions;
        const auto &new_region = *found->second;
        RegionSummary region;
        region.region_key = old_region.key;
        region.kind = RegionChangeKind::matched;
        region.old_address = old_region.address;
        region.new_address = new_region.address;
        region.old_size = old_region.bytes.size();
        region.new_size = new_region.bytes.size();
        std::size_t old_i = 0, new_i = 0;
        const auto old_size = old_region.bytes.size();
        const auto new_size = new_region.bytes.size();
        const auto compare_pair = [&](std::size_t oi, std::size_t ni) -> bool {
            if (!increment(report.summary.compared_bytes) || !increment(region.compared_bytes)) return false;
            if (ignored_at(old_region, oi) || ignored_at(new_region, ni)) {
                if (!increment(report.summary.ignored_bytes) || !increment(region.ignored_bytes)) return false;
            } else if (old_region.bytes[oi] == new_region.bytes[ni]) {
                if (!increment(report.summary.equal_bytes) || !increment(region.equal_bytes)) return false;
            } else {
                emit(ChangeKind::changed, old_region.key, old_region.address + oi, new_region.address + ni);
                if (!increment(report.summary.changed_bytes) || !increment(region.changed_bytes)) return false;
            }
            return account_byte();
        };
        while (old_i < old_size && new_i < new_size) {
            if (old_region.bytes[old_i] == new_region.bytes[new_i] ||
                ignored_at(old_region, old_i) || ignored_at(new_region, new_i)) {
                if (!compare_pair(old_i++, new_i++))
                    return Error{ErrorCode::canceled, "comparison canceled or counter overflow"};
                continue;
            }
            std::optional<std::pair<std::size_t, std::size_t>> anchor;
            const auto max_skip = static_cast<std::size_t>(std::min<std::uint64_t>(
                options.resync_window_bytes, 256));
            // Search by total skipped bytes so the nearest anchor wins. When
            // repeated bytes produce several anchors at that same distance,
            // use a short exact continuation to distinguish them instead of
            // selecting whichever happened to appear first in scan order.
            constexpr std::size_t lookahead_limit = 64;
            bool ambiguous_anchor = false;
            for (std::size_t distance = 1; distance <= 2 * max_skip && !anchor; ++distance) {
                const auto first_old_skip = distance > max_skip ? distance - max_skip : 0;
                const auto last_old_skip = std::min(distance, max_skip);
                std::size_t best_continuation = 0;
                for (std::size_t old_skip = first_old_skip; old_skip <= last_old_skip; ++old_skip) {
                    if (canceled()) return Error{ErrorCode::canceled, "comparison canceled"};
                    const auto new_skip = distance - old_skip;
                    if (old_skip > old_size - old_i || new_skip > new_size - new_i) continue;
                    const auto old_anchor = old_i + old_skip;
                    const auto new_anchor = new_i + new_skip;
                    const auto anchor_size = static_cast<std::size_t>(options.resync_anchor_bytes);
                    if (anchor_size > old_size - old_anchor || anchor_size > new_size - new_anchor) continue;
                    bool exact_anchor = true;
                    for (std::size_t byte = 0; byte < anchor_size; ++byte) {
                        if (ignored_at(old_region, old_anchor + byte) || ignored_at(new_region, new_anchor + byte) ||
                            old_region.bytes[old_anchor + byte] != new_region.bytes[new_anchor + byte]) {
                            exact_anchor = false;
                            break;
                        }
                    }
                    if (exact_anchor) {
                        const auto continuation_limit = std::min(
                            {lookahead_limit, old_size - old_anchor - anchor_size,
                             new_size - new_anchor - anchor_size});
                        std::size_t continuation = 0;
                        while (continuation < continuation_limit &&
                               !ignored_at(old_region, old_anchor + anchor_size + continuation) &&
                               !ignored_at(new_region, new_anchor + anchor_size + continuation) &&
                               old_region.bytes[old_anchor + anchor_size + continuation] ==
                                   new_region.bytes[new_anchor + anchor_size + continuation]) {
                            ++continuation;
                        }
                        if (!anchor || continuation > best_continuation) {
                            anchor = std::pair{old_skip, new_skip};
                            best_continuation = continuation;
                            ambiguous_anchor = false;
                        } else if (continuation == best_continuation &&
                                   *anchor != std::pair{old_skip, new_skip}) {
                            ambiguous_anchor = true;
                        }
                    }
                }
                if (anchor && ambiguous_anchor) {
                    anchor.reset();
                    break;
                }
            }
            if (!anchor || (anchor->first == 0 && anchor->second == 0)) {
                if (!compare_pair(old_i++, new_i++))
                    return Error{ErrorCode::canceled, "comparison canceled or counter overflow"};
                continue;
            }
            const auto paired = std::min(anchor->first, anchor->second);
            for (std::size_t n = 0; n < paired; ++n) {
                if (!compare_pair(old_i++, new_i++))
                    return Error{ErrorCode::canceled, "comparison canceled or counter overflow"};
            }
            while (anchor->first > paired) {
                emit(ChangeKind::removed, old_region.key, old_region.address + old_i, {});
                if (!increment(report.summary.removed_bytes) || !increment(region.removed_bytes) || !account_byte())
                    return Error{ErrorCode::canceled, "comparison canceled or counter overflow"};
                ++old_i;
                --anchor->first;
            }
            while (anchor->second > paired) {
                emit(ChangeKind::added, new_region.key, {}, new_region.address + new_i);
                if (!increment(report.summary.added_bytes) || !increment(region.added_bytes) || !account_byte())
                    return Error{ErrorCode::canceled, "comparison canceled or counter overflow"};
                ++new_i;
                --anchor->second;
            }
        }
        for (std::size_t i = old_i; i < old_size; ++i) {
            emit(ChangeKind::removed, old_region.key, old_region.address + i, {});
            if (!increment(report.summary.removed_bytes) || !increment(region.removed_bytes) || !account_byte()) return Error{ErrorCode::canceled, "comparison canceled"};
        }
        for (std::size_t i = new_i; i < new_size; ++i) {
            emit(ChangeKind::added, new_region.key, {}, new_region.address + i);
            if (!increment(report.summary.added_bytes) || !increment(region.added_bytes) || !account_byte()) return Error{ErrorCode::canceled, "comparison canceled"};
        }
        report.regions.push_back(std::move(region));
    }
    for (const auto &region : new_image.regions) if (!visited.contains(region.key)) {
        ++report.summary.added_regions;
        RegionSummary summary;
        summary.region_key = region.key;
        summary.kind = RegionChangeKind::added;
        summary.new_address = region.address;
        summary.new_size = region.bytes.size();
        summary.added_bytes = region.bytes.size();
        report.regions.push_back(std::move(summary));
        for (std::size_t i = 0; i < region.bytes.size(); ++i) {
            emit(ChangeKind::added, region.key, {}, region.address + i);
            if (!increment(report.summary.added_bytes) || !account_byte()) return Error{ErrorCode::canceled, "comparison canceled"};
        }
    }
    if (options.progress && !account_progress(true)) return Error{ErrorCode::canceled, "comparison canceled"};
    return report;
}
} // namespace hexlab::compare

