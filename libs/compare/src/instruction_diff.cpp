#include "hexlab/compare/compare.hpp"

#include <algorithm>
#include <limits>
#include <unordered_map>

namespace hexlab::compare {
namespace {
struct AnchorOccurrence {
    std::uint64_t old_index = 0;
    std::uint64_t new_index = 0;
    bool old_duplicate = false;
    bool new_seen = false;
    bool new_duplicate = false;
};
struct AnchorPair { std::uint64_t old_index = 0, new_index = 0; };

std::uint64_t saturating_add(std::uint64_t a, std::uint64_t b) noexcept {
    return b > UINT64_MAX - a ? UINT64_MAX : a + b;
}
std::uint64_t saturating_multiply(std::uint64_t a, std::uint64_t b) noexcept {
    return a && b > UINT64_MAX / a ? UINT64_MAX : a * b;
}

Result<FunctionInstructionDiff> diff_with_unique_anchors(
    std::span<const std::uint64_t> old_fingerprints,
    std::span<const std::uint64_t> new_fingerprints,
    const FunctionInstructionDiffOptions &options) {
    const auto old_size = static_cast<std::uint64_t>(old_fingerprints.size());
    const auto new_size = static_cast<std::uint64_t>(new_fingerprints.size());
    const auto item_count = old_size + new_size;
    if (!options.max_anchor_index_items || item_count > options.max_anchor_index_items)
        return Error{ErrorCode::invalid_argument, "instruction diff anchor-index budget exceeded"};
    if (options.stop_token.stop_requested())
        return Error{ErrorCode::canceled, "instruction diff canceled"};

    const auto total_work = saturating_add(options.max_dynamic_cells, saturating_multiply(item_count, 8));
    std::uint64_t visited = 0, last_reported = 0;
    auto advance = [&](std::uint64_t amount = 1, bool force = false) {
        visited = std::min(total_work, saturating_add(visited, amount));
        if (options.stop_token.stop_requested()) return false;
        if (!options.progress) return true;
        if (!force && visited - last_reported < 4096) return true;
        last_reported = visited;
        return options.progress(visited, total_work);
    };

    std::unordered_map<std::uint64_t, AnchorOccurrence> occurrences;
    occurrences.reserve(old_fingerprints.size());
    for (std::uint64_t i = 0; i < old_size; ++i) {
        const auto [found, inserted] = occurrences.try_emplace(old_fingerprints[static_cast<std::size_t>(i)],
                                                               AnchorOccurrence{i});
        if (!inserted) found->second.old_duplicate = true;
        if (!advance()) return Error{ErrorCode::canceled, "instruction diff canceled"};
    }
    for (std::uint64_t i = 0; i < new_size; ++i) {
        const auto found = occurrences.find(new_fingerprints[static_cast<std::size_t>(i)]);
        if (found != occurrences.end() && !found->second.old_duplicate) {
            auto &entry = found->second;
            if (entry.new_seen) entry.new_duplicate = true;
            else { entry.new_seen = true; entry.new_index = i; }
        }
        if (!advance()) return Error{ErrorCode::canceled, "instruction diff canceled"};
    }

    std::vector<AnchorPair> anchors;
    anchors.reserve(std::min(old_fingerprints.size(), new_fingerprints.size()));
    for (std::uint64_t i = 0; i < old_size; ++i) {
        const auto found = occurrences.find(old_fingerprints[static_cast<std::size_t>(i)]);
        if (found != occurrences.end()) {
            const auto &entry = found->second;
            if (!entry.old_duplicate && entry.old_index == i && entry.new_seen && !entry.new_duplicate)
                anchors.push_back({i, entry.new_index});
        }
        if (!advance()) return Error{ErrorCode::canceled, "instruction diff canceled"};
    }

    // Select a longest increasing subsequence of unique matches. These are
    // exact, non-crossing anchors; all non-anchor gaps are diffed separately.
    const auto none = std::numeric_limits<std::size_t>::max();
    std::vector<std::size_t> predecessor(anchors.size(), none), tails;
    tails.reserve(anchors.size());
    for (std::size_t i = 0; i < anchors.size(); ++i) {
        const auto target = anchors[i].new_index;
        const auto found = std::lower_bound(tails.begin(), tails.end(), target,
            [&](std::size_t anchor_index, std::uint64_t value) {
                return anchors[anchor_index].new_index < value;
            });
        const auto position = static_cast<std::size_t>(found - tails.begin());
        if (position) predecessor[i] = tails[position - 1];
        if (found == tails.end()) tails.push_back(i);
        else *found = i;
        if (!advance()) return Error{ErrorCode::canceled, "instruction diff canceled"};
    }
    std::vector<AnchorPair> ordered_anchors;
    ordered_anchors.reserve(tails.size());
    if (!tails.empty()) {
        auto index = tails.back();
        while (index != none) {
            ordered_anchors.push_back(anchors[index]);
            index = predecessor[index];
            if (!advance()) return Error{ErrorCode::canceled, "instruction diff canceled"};
        }
        std::reverse(ordered_anchors.begin(), ordered_anchors.end());
    }

    FunctionInstructionDiff result;
    const auto append_equal = [&](std::uint64_t old_start, std::uint64_t new_start,
                                  std::uint64_t count) {
        if (!count) return;
        if (!result.runs.empty() && result.runs.back().kind == InstructionDiffKind::equal &&
            result.runs.back().old_start + result.runs.back().old_count == old_start &&
            result.runs.back().new_start + result.runs.back().new_count == new_start) {
            result.runs.back().old_count += count;
            result.runs.back().new_count += count;
        } else result.runs.push_back({InstructionDiffKind::equal, old_start, new_start, count, count});
        result.equal_instructions += count;
    };
    const auto append_unmatched = [&](std::uint64_t old_start, std::uint64_t new_start,
                                      std::uint64_t old_count, std::uint64_t new_count) {
        if (!old_count && !new_count) return;
        if (old_count && new_count) {
            const auto paired = std::min(old_count, new_count);
            result.runs.push_back({InstructionDiffKind::changed, old_start, new_start, old_count, new_count});
            result.changed_instructions += paired;
            result.removed_instructions += old_count - paired;
            result.added_instructions += new_count - paired;
        } else if (old_count) {
            result.runs.push_back({InstructionDiffKind::removed, old_start, new_start, old_count, 0});
            result.removed_instructions += old_count;
        } else {
            result.runs.push_back({InstructionDiffKind::added, old_start, new_start, 0, new_count});
            result.added_instructions += new_count;
        }
    };

    std::uint64_t used_matrix_cells = 0;
    const auto append_gap = [&](std::uint64_t old_begin, std::uint64_t old_end,
                                std::uint64_t new_begin, std::uint64_t new_end) -> bool {
        const auto gap_old = old_end - old_begin, gap_new = new_end - new_begin;
        if (!gap_old && !gap_new) return true;
        const auto rows = gap_old + 1, columns = gap_new + 1;
        const bool dimensions_fit = rows <= UINT64_MAX / columns;
        const auto cells = dimensions_fit ? rows * columns : UINT64_MAX;
        const auto remaining_cells = options.max_dynamic_cells - used_matrix_cells;
        if (!dimensions_fit || cells > remaining_cells || cells > std::numeric_limits<std::size_t>::max()) {
            append_unmatched(old_begin, new_begin, gap_old, gap_new);
            return advance(gap_old + gap_new);
        }
        used_matrix_cells += cells;
        std::vector<std::uint32_t> lcs(static_cast<std::size_t>(cells), 0);
        const auto at = [columns](std::uint64_t i, std::uint64_t j) {
            return static_cast<std::size_t>(i * columns + j);
        };
        for (std::uint64_t i = gap_old; i > 0; --i) {
            if (options.stop_token.stop_requested()) return false;
            for (std::uint64_t j = gap_new; j > 0; --j) {
                const auto old_index = old_begin + i - 1;
                const auto new_index = new_begin + j - 1;
                if (old_fingerprints[static_cast<std::size_t>(old_index)] ==
                    new_fingerprints[static_cast<std::size_t>(new_index)])
                    lcs[at(i - 1, j - 1)] = lcs[at(i, j)] + 1;
                else lcs[at(i - 1, j - 1)] = std::max(lcs[at(i, j - 1)], lcs[at(i - 1, j)]);
            }
            if (!advance(gap_new, (i & 0xffu) == 1)) return false;
        }
        std::uint64_t old_index = 0, new_index = 0;
        std::uint64_t unmatched_old_start = old_begin, unmatched_new_start = new_begin;
        std::uint64_t unmatched_old = 0, unmatched_new = 0;
        const auto flush = [&] {
            append_unmatched(unmatched_old_start, unmatched_new_start, unmatched_old, unmatched_new);
            unmatched_old = 0; unmatched_new = 0;
        };
        while (old_index < gap_old || new_index < gap_new) {
            if (options.stop_token.stop_requested()) return false;
            if (old_index < gap_old && new_index < gap_new &&
                old_fingerprints[static_cast<std::size_t>(old_begin + old_index)] ==
                new_fingerprints[static_cast<std::size_t>(new_begin + new_index)]) {
                flush();
                append_equal(old_begin + old_index, new_begin + new_index, 1);
                ++old_index; ++new_index;
            } else if (old_index < gap_old && (new_index == gap_new ||
                       lcs[at(old_index + 1, new_index)] > lcs[at(old_index, new_index + 1)])) {
                if (!unmatched_old && !unmatched_new) {
                    unmatched_old_start = old_begin + old_index;
                    unmatched_new_start = new_begin + new_index;
                }
                ++unmatched_old; ++old_index;
            } else {
                if (!unmatched_old && !unmatched_new) {
                    unmatched_old_start = old_begin + old_index;
                    unmatched_new_start = new_begin + new_index;
                }
                ++unmatched_new; ++new_index;
            }
            if (!advance()) return false;
        }
        flush();
        return true;
    };

    std::uint64_t old_begin = 0, new_begin = 0;
    for (const auto &anchor : ordered_anchors) {
        if (!append_gap(old_begin, anchor.old_index, new_begin, anchor.new_index))
            return Error{ErrorCode::canceled, "instruction diff canceled"};
        append_equal(anchor.old_index, anchor.new_index, 1);
        old_begin = anchor.old_index + 1;
        new_begin = anchor.new_index + 1;
        if (!advance()) return Error{ErrorCode::canceled, "instruction diff canceled"};
    }
    if (!append_gap(old_begin, old_size, new_begin, new_size))
        return Error{ErrorCode::canceled, "instruction diff canceled"};
    if (options.progress && !options.progress(total_work, total_work))
        return Error{ErrorCode::canceled, "instruction diff canceled"};
    return result;
}
} // namespace

Result<FunctionInstructionDiff> diff_function_instructions(
    std::span<const std::uint64_t> old_fingerprints,
    std::span<const std::uint64_t> new_fingerprints,
    const FunctionInstructionDiffOptions &options) {
    if (!options.max_dynamic_cells)
        return Error{ErrorCode::invalid_argument, "instruction diff matrix budget must be nonzero"};
    if (options.stop_token.stop_requested())
        return Error{ErrorCode::canceled, "instruction diff canceled"};

    const auto old_size = static_cast<std::uint64_t>(old_fingerprints.size());
    const auto new_size = static_cast<std::uint64_t>(new_fingerprints.size());
    if (old_size == UINT64_MAX || new_size == UINT64_MAX)
        return Error{ErrorCode::overflow, "instruction diff dimensions overflow"};
    if (std::min(old_size, new_size) > UINT32_MAX)
        return Error{ErrorCode::overflow, "instruction diff LCS length exceeds the matrix cell type"};
    if (old_size > UINT64_MAX - new_size || old_size + new_size > std::numeric_limits<std::size_t>::max())
        return Error{ErrorCode::overflow, "instruction diff output length overflows"};
    const auto rows = old_size + 1;
    const auto columns = new_size + 1;
    const bool full_matrix_fits_u64 = rows <= UINT64_MAX / columns;
    const auto cells = full_matrix_fits_u64 ? rows * columns : UINT64_MAX;
    if (!full_matrix_fits_u64 || cells > options.max_dynamic_cells ||
        cells > std::numeric_limits<std::size_t>::max())
        return diff_with_unique_anchors(old_fingerprints, new_fingerprints, options);
    const auto matrix_work = old_size * new_size;
    if (old_size > (UINT64_MAX - new_size) / 2)
        return Error{ErrorCode::overflow, "instruction diff progress estimate overflows"};
    const auto row_and_sequence_work = 2 * old_size + new_size;
    if (matrix_work > UINT64_MAX - row_and_sequence_work)
        return Error{ErrorCode::overflow, "instruction diff progress estimate overflows"};
    const auto total_work = matrix_work + row_and_sequence_work;

    // Bottom-up longest-common-subsequence lengths make the reconstruction
    // deterministic. The full matrix is small by contract and checked before
    // allocation, so no input can trigger unbounded quadratic memory use.
    std::vector<std::uint32_t> lcs(static_cast<std::size_t>(cells), 0);
    const auto at = [columns](std::uint64_t i, std::uint64_t j) {
        return static_cast<std::size_t>(i * columns + j);
    };
    std::uint64_t completed_rows = 0;
    for (std::uint64_t i = old_size; i > 0; --i) {
        if (options.stop_token.stop_requested())
            return Error{ErrorCode::canceled, "instruction diff canceled"};
        const auto old_index = i - 1;
        for (std::uint64_t j = new_size; j > 0; --j) {
            if (((new_size - j) & 0xfffu) == 0 && options.stop_token.stop_requested())
                return Error{ErrorCode::canceled, "instruction diff canceled"};
            const auto new_index = j - 1;
            if (old_fingerprints[static_cast<std::size_t>(old_index)] ==
                new_fingerprints[static_cast<std::size_t>(new_index)]) {
                lcs[at(old_index, new_index)] = lcs[at(i, j)] + 1;
            } else {
                lcs[at(old_index, new_index)] =
                    std::max(lcs[at(i, new_index)], lcs[at(old_index, j)]);
            }
        }
        ++completed_rows;
        if (options.progress && ((completed_rows & 0xffu) == 0 || completed_rows == old_size) &&
            !options.progress(completed_rows * columns, total_work))
            return Error{ErrorCode::canceled, "instruction diff canceled"};
    }

    enum class Operation : std::uint8_t { equal, removed, added };
    std::uint64_t old_index = 0, new_index = 0;
    std::uint64_t processed_operations = 0;
    std::uint64_t unmatched_old_start = 0, unmatched_new_start = 0;
    std::uint64_t unmatched_old_count = 0, unmatched_new_count = 0;
    FunctionInstructionDiff result;
    const auto flush_unmatched = [&]() {
        if (!unmatched_old_count && !unmatched_new_count) return;
        if (unmatched_old_count && unmatched_new_count) {
            const auto paired = std::min(unmatched_old_count, unmatched_new_count);
            result.runs.push_back({InstructionDiffKind::changed, unmatched_old_start, unmatched_new_start,
                                   unmatched_old_count, unmatched_new_count});
            result.changed_instructions += paired;
            result.removed_instructions += unmatched_old_count - paired;
            result.added_instructions += unmatched_new_count - paired;
        } else if (unmatched_old_count) {
            result.runs.push_back({InstructionDiffKind::removed, unmatched_old_start, unmatched_new_start,
                                   unmatched_old_count, 0});
            result.removed_instructions += unmatched_old_count;
        } else {
            result.runs.push_back({InstructionDiffKind::added, unmatched_old_start, unmatched_new_start,
                                   0, unmatched_new_count});
            result.added_instructions += unmatched_new_count;
        }
        unmatched_old_count = 0;
        unmatched_new_count = 0;
    };
    while (old_index < old_size || new_index < new_size) {
        if (options.stop_token.stop_requested())
            return Error{ErrorCode::canceled, "instruction diff canceled"};
        Operation operation;
        if (old_index < old_size && new_index < new_size &&
            old_fingerprints[static_cast<std::size_t>(old_index)] ==
                new_fingerprints[static_cast<std::size_t>(new_index)]) {
            operation = Operation::equal;
        } else if (old_index < old_size &&
                   (new_index == new_size ||
                    lcs[at(old_index + 1, new_index)] > lcs[at(old_index, new_index + 1)])) {
            operation = Operation::removed;
        } else {
            operation = Operation::added;
        }

        if (operation == Operation::equal) {
            flush_unmatched();
            if (!result.runs.empty() && result.runs.back().kind == InstructionDiffKind::equal &&
                result.runs.back().old_start + result.runs.back().old_count == old_index &&
                result.runs.back().new_start + result.runs.back().new_count == new_index) {
                ++result.runs.back().old_count;
                ++result.runs.back().new_count;
            } else {
                result.runs.push_back({InstructionDiffKind::equal, old_index, new_index, 1, 1});
            }
            ++result.equal_instructions;
            ++old_index;
            ++new_index;
        } else {
            if (!unmatched_old_count && !unmatched_new_count) {
                unmatched_old_start = old_index;
                unmatched_new_start = new_index;
            }
            if (operation == Operation::removed) {
                ++unmatched_old_count;
                ++old_index;
            } else {
                ++unmatched_new_count;
                ++new_index;
            }
        }

        ++processed_operations;
        const auto maximum_operations = old_size + new_size;
        if (options.progress && (processed_operations & 0x3fu) == 0 &&
            processed_operations < maximum_operations &&
            !options.progress(matrix_work + old_size + processed_operations, total_work))
            return Error{ErrorCode::canceled, "instruction diff canceled"};
    }
    flush_unmatched();
    if (options.progress && !options.progress(total_work, total_work))
        return Error{ErrorCode::canceled, "instruction diff canceled"};
    return result;
}
} // namespace hexlab::compare
