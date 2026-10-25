#include "hexlab/analysis/references.hpp"
#include "hexlab/image/image.hpp"
#include <algorithm>
#include <bit>
#include <limits>

namespace hexlab {
namespace {
void add_range_matches(const std::map<std::tuple<unsigned, std::uint32_t, std::uint64_t>, std::vector<std::size_t>> &index,
                       unsigned kind, std::uint32_t space, std::uint64_t begin, std::uint64_t end,
                       std::vector<std::uint64_t> &matches) {
    for (auto it = index.lower_bound({kind, space, begin}); it != index.end(); ++it) {
        const auto &[key_kind, key_space, offset] = it->first;
        if (key_kind != kind || key_space != space || offset >= end)
            break;
        for (const auto row : it->second)
            matches[row / 64] |= UINT64_C(1) << (row % 64);
    }
}

Result<ReferencePage> make_matched_page(std::span<const Reference> references,
                                        const std::vector<std::uint64_t> &matches, PageRequest request) {
    ReferencePage page;
    for (const auto word : matches)
        page.total += static_cast<std::uint64_t>(std::popcount(word));
    if (request.offset >= page.total)
        return page;

    const auto count = std::min<std::uint64_t>(request.limit, page.total - request.offset);
    page.rows.reserve(static_cast<std::size_t>(count));
    std::uint64_t ordinal = 0;
    for (std::size_t word_index = 0; word_index < matches.size() && page.rows.size() < count; ++word_index) {
        auto word = matches[word_index];
        while (word && page.rows.size() < count) {
            const auto bit = static_cast<std::size_t>(std::countr_zero(word));
            const auto index = word_index * 64 + bit;
            if (ordinal >= request.offset)
                page.rows.push_back(references[index]);
            ++ordinal;
            word &= word - 1;
        }
    }
    if (request.offset + count < page.total)
        page.next_offset = request.offset + count;
    return page;
}

Result<std::pair<std::uint64_t, std::uint64_t>> checked_file_range(FileOffset begin, std::uint64_t size,
                                                                   PageRequest request, const char *message) {
    if (!size || size > std::numeric_limits<std::uint64_t>::max() - begin.value)
        return Error{ErrorCode::invalid_argument, message};
    if (request.limit == 0 || request.limit > 4096)
        return Error{ErrorCode::invalid_argument, "Reference page size must be between 1 and 4096"};
    return std::pair{begin.value, begin.value + size};
}
} // namespace

Result<ReferencePage> ReferenceIndex::incoming_range(Address begin, std::uint64_t size, PageRequest request) const {
    if (!size || size > std::numeric_limits<std::uint64_t>::max() - begin.offset)
        return Error{ErrorCode::invalid_argument, "Reference target range must be nonempty and not overflow"};
    if (request.limit == 0 || request.limit > 4096)
        return Error{ErrorCode::invalid_argument, "Reference page size must be between 1 and 4096"};

    const auto end = begin.offset + size;
    const auto first = incoming_.lower_bound({0, begin.space.value, begin.offset});
    // Each reference has at most one numeric target and one association. A
    // bitmap de-duplicates rows when both addresses overlap the queried range
    // without allocating memory proportional to the number of matches.
    std::vector<std::uint64_t> matches((references_.size() + 63) / 64);
    for (auto it = first; it != incoming_.end(); ++it) {
        const auto &[kind, space, offset] = it->first;
        if (kind != 0 || space != begin.space.value || offset >= end)
            break;
        for (const auto index : it->second)
            matches[index / 64] |= UINT64_C(1) << (index % 64);
    }

    ReferencePage page;
    for (const auto word : matches)
        page.total += static_cast<std::uint64_t>(std::popcount(word));
    if (request.offset >= page.total)
        return page;

    const auto count = std::min<std::uint64_t>(request.limit, page.total - request.offset);
    page.rows.reserve(static_cast<std::size_t>(count));
    std::uint64_t ordinal = 0;
    for (std::size_t word_index = 0; word_index < matches.size() && page.rows.size() < count; ++word_index) {
        auto word = matches[word_index];
        while (word && page.rows.size() < count) {
            const auto bit = static_cast<std::size_t>(std::countr_zero(word));
            const auto index = word_index * 64 + bit;
            if (ordinal >= request.offset)
                page.rows.push_back(references_[index]);
            ++ordinal;
            word &= word - 1;
        }
    }
    if (request.offset + count < page.total)
        page.next_offset = request.offset + count;
    return page;
}

Result<ReferencePage> ReferenceIndex::outgoing_range(Address begin, std::uint64_t size, PageRequest request) const {
    if (!size || size > std::numeric_limits<std::uint64_t>::max() - begin.offset)
        return Error{ErrorCode::invalid_argument, "Reference source range must be nonempty and not overflow"};
    if (request.limit == 0 || request.limit > 4096)
        return Error{ErrorCode::invalid_argument, "Reference page size must be between 1 and 4096"};

    const auto end = begin.offset + size;
    ReferencePage page;
    for (auto it = outgoing_.lower_bound({0, begin.space.value, begin.offset}); it != outgoing_.end(); ++it) {
        const auto &[kind, space, offset] = it->first;
        if (kind != 0 || space != begin.space.value || offset >= end)
            break;
        page.total += it->second.size();
    }
    if (request.offset >= page.total)
        return page;

    const auto count = std::min<std::uint64_t>(request.limit, page.total - request.offset);
    page.rows.reserve(static_cast<std::size_t>(count));
    std::uint64_t ordinal = 0;
    for (auto it = outgoing_.lower_bound({0, begin.space.value, begin.offset}); it != outgoing_.end(); ++it) {
        const auto &[kind, space, offset] = it->first;
        if (kind != 0 || space != begin.space.value || offset >= end)
            break;
        for (const auto index : it->second) {
            if (ordinal >= request.offset && page.rows.size() < count)
                page.rows.push_back(references_[index]);
            ++ordinal;
        }
        if (page.rows.size() == count)
            break;
    }
    if (request.offset + count < page.total)
        page.next_offset = request.offset + count;
    return page;
}

Result<ReferencePage> ReferenceIndex::incoming_file_range(FileOffset begin, std::uint64_t size,
                                                           PageRequest request) const {
    if (!size || size > std::numeric_limits<std::uint64_t>::max() - begin.value)
        return Error{ErrorCode::invalid_argument, "Reference file target range must be nonempty and not overflow"};
    if (request.limit == 0 || request.limit > 4096)
        return Error{ErrorCode::invalid_argument, "Reference page size must be between 1 and 4096"};
    const auto end = begin.value + size;
    const auto first = incoming_.lower_bound({1, 0, begin.value});
    std::vector<std::uint64_t> matches((references_.size() + 63) / 64);
    for (auto it = first; it != incoming_.end(); ++it) {
        const auto &[kind, space, offset] = it->first;
        if (kind != 1 || offset >= end) break;
        for (const auto index : it->second) matches[index / 64] |= UINT64_C(1) << (index % 64);
    }
    ReferencePage page;
    for (const auto word : matches) page.total += static_cast<std::uint64_t>(std::popcount(word));
    if (request.offset >= page.total) return page;
    const auto count = std::min<std::uint64_t>(request.limit, page.total - request.offset);
    page.rows.reserve(static_cast<std::size_t>(count));
    std::uint64_t ordinal = 0;
    for (std::size_t word_index = 0; word_index < matches.size() && page.rows.size() < count; ++word_index) {
        auto word = matches[word_index];
        while (word && page.rows.size() < count) {
            const auto bit = static_cast<std::size_t>(std::countr_zero(word));
            const auto index = word_index * 64 + bit;
            if (ordinal >= request.offset) page.rows.push_back(references_[index]);
            ++ordinal;
            word &= word - 1;
        }
    }
    if (request.offset + count < page.total) page.next_offset = request.offset + count;
    return page;
}

Result<ReferencePage> ReferenceIndex::outgoing_file_range(FileOffset begin, std::uint64_t size,
                                                           PageRequest request) const {
    if (!size || size > std::numeric_limits<std::uint64_t>::max() - begin.value)
        return Error{ErrorCode::invalid_argument, "Reference file source range must be nonempty and not overflow"};
    if (request.limit == 0 || request.limit > 4096)
        return Error{ErrorCode::invalid_argument, "Reference page size must be between 1 and 4096"};
    const auto end = begin.value + size;
    ReferencePage page;
    for (auto it = outgoing_.lower_bound({1, 0, begin.value}); it != outgoing_.end(); ++it) {
        const auto &[kind, space, offset] = it->first;
        if (kind != 1 || offset >= end) break;
        page.total += it->second.size();
    }
    if (request.offset >= page.total) return page;
    const auto count = std::min<std::uint64_t>(request.limit, page.total - request.offset);
    page.rows.reserve(static_cast<std::size_t>(count));
    std::uint64_t ordinal = 0;
    for (auto it = outgoing_.lower_bound({1, 0, begin.value}); it != outgoing_.end() && page.rows.size() < count; ++it) {
        const auto &[kind, space, offset] = it->first;
        if (kind != 1 || offset >= end) break;
        for (const auto index : it->second) {
            if (ordinal >= request.offset && page.rows.size() < count) page.rows.push_back(references_[index]);
            ++ordinal;
        }
    }
    if (request.offset + count < page.total) page.next_offset = request.offset + count;
    return page;
}

Result<ReferencePage> ReferenceIndex::incoming_mapped_file_range(const Image &image, FileOffset begin,
                                                                  std::uint64_t size, PageRequest request) const {
    auto range = checked_file_range(begin, size, request,
                                    "Reference mapped-file target range must be nonempty and not overflow");
    if (!range)
        return range.error();
    const auto [file_begin, file_end] = range.value();
    std::vector<std::uint64_t> matches((references_.size() + 63) / 64);
    add_range_matches(incoming_, 1, 0, file_begin, file_end, matches);
    for (const auto &segment : image.layout().segments) {
        if (!segment.file_size)
            continue;
        const auto segment_begin = segment.file_begin.value;
        const auto segment_end = segment_begin + segment.file_size;
        const auto overlap_begin = std::max(file_begin, segment_begin);
        const auto overlap_end = std::min(file_end, segment_end);
        if (overlap_begin >= overlap_end)
            continue;
        const auto virtual_begin = segment.begin.offset + (overlap_begin - segment_begin);
        const auto virtual_end = virtual_begin + (overlap_end - overlap_begin);
        add_range_matches(incoming_, 0, segment.begin.space.value, virtual_begin, virtual_end, matches);
    }
    return make_matched_page(references_, matches, request);
}

Result<ReferencePage> ReferenceIndex::outgoing_mapped_file_range(const Image &image, FileOffset begin,
                                                                  std::uint64_t size, PageRequest request) const {
    auto range = checked_file_range(begin, size, request,
                                    "Reference mapped-file source range must be nonempty and not overflow");
    if (!range)
        return range.error();
    const auto [file_begin, file_end] = range.value();
    std::vector<std::uint64_t> matches((references_.size() + 63) / 64);
    add_range_matches(outgoing_, 1, 0, file_begin, file_end, matches);
    for (const auto &segment : image.layout().segments) {
        if (!segment.file_size)
            continue;
        const auto segment_begin = segment.file_begin.value;
        const auto segment_end = segment_begin + segment.file_size;
        const auto overlap_begin = std::max(file_begin, segment_begin);
        const auto overlap_end = std::min(file_end, segment_end);
        if (overlap_begin >= overlap_end)
            continue;
        const auto virtual_begin = segment.begin.offset + (overlap_begin - segment_begin);
        const auto virtual_end = virtual_begin + (overlap_end - overlap_begin);
        add_range_matches(outgoing_, 0, segment.begin.space.value, virtual_begin, virtual_end, matches);
    }
    return make_matched_page(references_, matches, request);
}
} // namespace hexlab
