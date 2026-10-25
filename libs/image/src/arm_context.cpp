#include "hexlab/image/image.hpp"
#include <algorithm>
#include <tuple>

namespace hexlab {
namespace {
bool before(Address a, Address b) noexcept {
    return std::tie(a.space.value, a.offset) < std::tie(b.space.value, b.offset);
}
bool arm_domain(const AddressSpace &space, DecodeContext context) noexcept {
    return space.width_bits == 32 && space.unit_bytes == 1 && space.order == ByteOrder::little &&
           context.architecture == Architecture::arm && context.order == ByteOrder::little &&
           (context.mode == ExecutionMode::unknown || context.mode == ExecutionMode::a32 ||
            context.mode == ExecutionMode::thumb) &&
           !context.stack_address_width && !context.segmented_memory;
}
auto source_key(const ArmContextSource &source) noexcept {
    return std::tuple{source.kind,
                      source.namespace_id,
                      source.record_index,
                      source.evidence.has_value(),
                      source.evidence ? source.evidence->begin.value : 0,
                      source.evidence ? source.evidence->size : 0};
}
} // namespace
const ArmCodeRange *Image::arm_code_at(Address at) const noexcept {
    if (!layout_.arm_profile)
        return nullptr;
    const auto &ranges = layout_.arm_profile->ranges;
    const auto next = std::upper_bound(ranges.begin(), ranges.end(), at,
                                       [](Address value, const auto &range) { return before(value, range.begin); });
    if (next == ranges.begin())
        return nullptr;
    const auto &range = *std::prev(next);
    return range.begin.space == at.space && at.offset - range.begin.offset < range.size ? &range : nullptr;
}
Result<bool> Image::normalize_arm_profile() {
    if (!layout_.arm_profile)
        return true;
    if (layout_.x86_profile || !arm_domain(layout_.space, decode_context()))
        return Error{ErrorCode::invalid_argument, "ARM context profile requires flat little-endian ARM32 domains"};
    for (const auto &domain : layout_.domains)
        if (!arm_domain(domain.space, domain.context))
            return Error{ErrorCode::invalid_argument, "ARM profile contains an incompatible additional domain"};
    auto &profile = *layout_.arm_profile;
    constexpr std::uint64_t record_limit = 1000000, byte_limit = 64 * 1024 * 1024;
    if (profile.ranges.size() > record_limit || profile.roots.size() > record_limit)
        return Error{ErrorCode::resource_limit, "ARM profile exceeds range/root count budget"};
    std::uint64_t source_count = 0;
    std::uint64_t metadata_bytes =
        profile.ranges.size() * sizeof(ArmCodeRange) + profile.roots.size() * sizeof(ArmCodeRoot);
    const auto sources = [&](std::vector<ArmContextSource> &rows) -> Result<bool> {
        if (rows.size() > record_limit - source_count)
            return Error{ErrorCode::resource_limit, "ARM profile exceeds source declaration count budget"};
        source_count += rows.size();
        metadata_bytes += rows.size() * sizeof(ArmContextSource);
        if (metadata_bytes > byte_limit)
            return Error{ErrorCode::resource_limit, "ARM profile exceeds metadata byte budget"};
        if (rows.empty())
            return Error{ErrorCode::malformed, "ARM context declaration has no source"};
        for (const auto &row : rows) {
            if (row.kind < ArmContextSourceKind::raw_declaration || row.kind > ArmContextSourceKind::user_override)
                return Error{ErrorCode::malformed, "Invalid ARM context source kind"};
            if (!row.evidence && (row.kind == ArmContextSourceKind::elf_mapping_symbol ||
                                  row.kind == ArmContextSourceKind::elf_function_symbol ||
                                  row.kind == ArmContextSourceKind::platform_entry))
                return Error{ErrorCode::malformed, "Source record requires original file evidence"};
            if (row.evidence && (!row.evidence->size || row.evidence->begin.value > storage_->size() ||
                                 row.evidence->size > storage_->size() - row.evidence->begin.value))
                return Error{ErrorCode::malformed, "ARM context source evidence exceeds original file"};
        }
        std::sort(rows.begin(), rows.end(), [](const auto &a, const auto &b) { return source_key(a) < source_key(b); });
        rows.erase(std::unique(rows.begin(), rows.end()), rows.end());
        return true;
    };
    if (metadata_bytes > byte_limit)
        return Error{ErrorCode::resource_limit, "ARM profile exceeds metadata byte budget"};
    std::sort(profile.ranges.begin(), profile.ranges.end(),
              [](const auto &a, const auto &b) { return before(a.begin, b.begin); });
    const ArmCodeRange *previous = nullptr;
    for (auto &range : profile.ranges) {
        if (range.kind < ArmCodeKind::a32 || range.kind > ArmCodeKind::conflict)
            return Error{ErrorCode::malformed, "Invalid ARM context range kind"};
        const auto *domain = space(range.begin.space);
        if (!domain || !range.size || range.begin.offset >= UINT64_C(0x100000000) ||
            range.size > UINT64_C(0x100000000) - range.begin.offset)
            return Error{ErrorCode::malformed, "ARM context range exceeds its declared domain"};
        if (previous && previous->begin.space == range.begin.space &&
            range.begin.offset - previous->begin.offset < previous->size)
            return Error{ErrorCode::malformed, "Overlapping ARM context declarations must be resolved explicitly"};
        previous = &range;
        const auto *segment = segment_at(range.begin);
        if (!segment || range.size > segment->file_size ||
            range.begin.offset - segment->begin.offset > segment->file_size - range.size)
            return Error{ErrorCode::malformed, "ARM context range exceeds initialized segment backing"};
        const bool code = range.kind == ArmCodeKind::a32 || range.kind == ArmCodeKind::thumb;
        const auto alignment = range.kind == ArmCodeKind::a32 ? 4u : 2u;
        if (code && (!segment->executable || range.begin.offset % alignment || range.size % alignment))
            return Error{ErrorCode::malformed, "ARM code range needs executable backing and aligned complete units"};
        auto valid = sources(range.sources);
        if (!valid)
            return valid.error();
        if (range.kind == ArmCodeKind::conflict && range.sources.size() < 2)
            return Error{ErrorCode::malformed, "ARM context conflict requires distinct source declarations"};
    }
    std::sort(profile.roots.begin(), profile.roots.end(),
              [](const auto &a, const auto &b) { return before(a.at, b.at); });
    const ArmCodeRoot *previous_root = nullptr;
    for (auto &root : profile.roots) {
        if (previous_root && previous_root->at == root.at)
            return Error{ErrorCode::malformed, "Duplicate ARM code roots must be resolved explicitly"};
        previous_root = &root;
        auto valid = sources(root.sources);
        if (!valid)
            return valid.error();
        const auto *range = arm_code_at(root.at);
        const auto expected = !range                              ? ExecutionMode::unknown
                              : range->kind == ArmCodeKind::a32   ? ExecutionMode::a32
                              : range->kind == ArmCodeKind::thumb ? ExecutionMode::thumb
                                                                  : ExecutionMode::unknown;
        const auto alignment = root.mode == ExecutionMode::a32 ? 4u : 2u;
        if ((root.mode != ExecutionMode::a32 && root.mode != ExecutionMode::thumb) || root.mode != expected ||
            root.at.offset % alignment || code_window(root.at, alignment) != alignment)
            return Error{ErrorCode::malformed, "ARM root conflicts with source code context or exclusion boundary"};
        if (root.known_thumb_it_clear &&
            (root.mode != ExecutionMode::thumb ||
             std::none_of(root.sources.begin(), root.sources.end(),
                          [](const auto &source) { return source.kind != ArmContextSourceKind::elf_mapping_symbol; })))
            return Error{ErrorCode::malformed, "Known-clear Thumb IT root needs an explicit entry declaration"};
    }
    return true;
}
} // namespace hexlab
