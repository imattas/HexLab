#include "hexlab/image/image.hpp"
#include <algorithm>
#include <limits>
#include <new>
#include <stdexcept>

namespace hexlab {
namespace {
bool valid_space(const AddressSpace &space) noexcept {
    return space.width_bits != 0 && space.width_bits <= 64 && space.unit_bytes == 1 &&
           (space.order == ByteOrder::little || space.order == ByteOrder::big);
}
bool less(Address a, Address b) noexcept {
    return a.space.value < b.space.value || (a.space == b.space && a.offset < b.offset);
}
} // namespace
Result<std::shared_ptr<const Image>> Image::create(std::shared_ptr<const ByteStorage> storage, ImageLayout layout) {
    try {
        if (!storage || !valid_space(layout.space))
            return Error{ErrorCode::invalid_argument, "Image requires storage and a valid byte-addressed space"};
        std::sort(layout.domains.begin(), layout.domains.end(),
                  [](const auto &a, const auto &b) { return a.space.id.value < b.space.id.value; });
        for (std::size_t i = 0; i < layout.domains.size(); ++i) {
            const auto &domain = layout.domains[i];
            if (!valid_space(domain.space) || domain.context.order != domain.space.order ||
                domain.space.id == layout.space.id || (i && domain.space.id == layout.domains[i - 1].space.id))
                return Error{ErrorCode::invalid_argument, "Invalid or duplicate additional image domain"};
        }
        const auto find_space = [&](AddressSpaceId id) -> const AddressSpace * {
            if (id == layout.space.id)
                return &layout.space;
            auto found = std::lower_bound(layout.domains.begin(), layout.domains.end(), id.value,
                                          [](const auto &domain, auto value) { return domain.space.id.value < value; });
            return found != layout.domains.end() && found->space.id == id ? &found->space : nullptr;
        };
        std::sort(layout.segments.begin(), layout.segments.end(),
                  [](const Segment &a, const Segment &b) { return less(a.begin, b.begin); });
        std::uint64_t previous_end = 0;
        std::optional<AddressSpaceId> previous_space;
        for (const auto &s : layout.segments) {
            const auto *domain = find_space(s.begin.space);
            const auto end = checked_add(s.begin.offset, s.size);
            const auto file_end = checked_add(s.file_begin.value, s.file_size);
            if (!end || !file_end)
                return Error{ErrorCode::overflow, "Image segment extent overflow: " + s.name};
            if (!domain || s.file_size > s.size || file_end.value() > storage->size())
                return Error{ErrorCode::malformed, "Invalid segment backing or address space: " + s.name};
            if (domain->width_bits < 64 && (s.begin.offset >= (std::uint64_t{1} << domain->width_bits) ||
                                            end.value() > (std::uint64_t{1} << domain->width_bits)))
                return Error{ErrorCode::overflow, "Segment exceeds declared address width: " + s.name};
            if (s.size != 0) {
                if (previous_space == s.begin.space && s.begin.offset < previous_end)
                    return Error{ErrorCode::malformed, "Overlapping virtual segments: " + s.name};
                previous_space = s.begin.space;
                previous_end = end.value();
            }
        }
        constexpr std::size_t range_limit = 1000000;
        if (layout.encrypted_ranges.size() > range_limit || layout.code_exclusions.size() > range_limit ||
            (layout.execution_profile && layout.execution_profile->ranges.size() > range_limit))
            return Error{ErrorCode::resource_limit, "Image code policy exceeds range budget"};
        if (layout.arm_profile && layout.execution_profile)
            return Error{ErrorCode::invalid_argument,
                         "ARM context profiles and multi-ISA execution profiles cannot be combined"};
        if (layout.execution_profile)
            std::sort(layout.execution_profile->ranges.begin(), layout.execution_profile->ranges.end(),
                      [](const auto &a, const auto &b) { return less(a.begin, b.begin); });
        layout.code_exclusions.insert(layout.code_exclusions.end(), layout.encrypted_ranges.begin(),
                                      layout.encrypted_ranges.end());
        const auto normalize = [&](std::vector<ImageCodeRange> &rows) -> Result<bool> {
            for (const auto &row : rows) {
                const auto *domain = find_space(row.begin.space);
                const auto end = checked_add(row.begin.offset, row.size);
                if (!end)
                    return end.error();
                if (!domain || (domain->width_bits < 64 && (row.begin.offset >= (UINT64_C(1) << domain->width_bits) ||
                                                            end.value() > (UINT64_C(1) << domain->width_bits))))
                    return Error{ErrorCode::malformed, "Code policy range exceeds image address space"};
            }
            std::sort(rows.begin(), rows.end(), [](const auto &a, const auto &b) { return less(a.begin, b.begin); });
            std::size_t used = 0;
            for (const auto row : rows) {
                if (!row.size)
                    continue;
                if (used && rows[used - 1].begin.space == row.begin.space &&
                    row.begin.offset <= rows[used - 1].begin.offset + rows[used - 1].size) {
                    auto &last = rows[used - 1];
                    last.size =
                        std::max(last.begin.offset + last.size, row.begin.offset + row.size) - last.begin.offset;
                } else
                    rows[used++] = row;
            }
            rows.resize(used);
            return true;
        };
        auto normalized = normalize(layout.code_exclusions);
        if (!normalized)
            return normalized.error();
        if (layout.code_exclusions.size() > range_limit)
            return Error{ErrorCode::resource_limit, "Canonical code policy exceeds range budget"};
        normalized = normalize(layout.encrypted_ranges);
        if (!normalized)
            return normalized.error();
        auto image = std::shared_ptr<Image>(new Image(std::move(storage), std::move(layout)));
        auto arm_valid = image->normalize_arm_profile();
        if (!arm_valid)
            return arm_valid.error();
        auto execution_valid = image->validate_execution_profile();
        if (!execution_valid)
            return execution_valid.error();
        auto profile_valid = image->validate_profile();
        if (!profile_valid)
            return profile_valid.error();
        for (auto entry : image->layout().entries)
            if (!image->segment_at(entry))
                return Error{ErrorCode::malformed, "Entry is not mapped"};
        return std::shared_ptr<const Image>(std::move(image));
    } catch (const std::bad_alloc &) {
        return Error{ErrorCode::resource_limit, "Cannot allocate image mappings/code policy"};
    } catch (const std::length_error &) {
        return Error{ErrorCode::resource_limit, "Image mappings/code policy exceed container bounds"};
    }
}
namespace {
std::uint64_t policy_window(const std::vector<ImageCodeRange> &rows, Address at, std::uint64_t maximum) noexcept {
    const auto next = std::upper_bound(rows.begin(), rows.end(), at,
                                       [](Address value, const auto &row) { return less(value, row.begin); });
    if (next != rows.begin()) {
        const auto &previous = *std::prev(next);
        if (previous.begin.space == at.space && at.offset - previous.begin.offset < previous.size)
            return 0;
    }
    return next != rows.end() && next->begin.space == at.space ? std::min(maximum, next->begin.offset - at.offset)
                                                               : maximum;
}
} // namespace
std::uint64_t Image::code_window(Address at, std::uint64_t maximum) const noexcept {
    if (layout_.execution_profile) {
        const auto *range = execution_range_at(at);
        if (!range)
            return 0;
        maximum = std::min(maximum, range->size - (at.offset - range->begin.offset));
    }
    if (layout_.arm_profile) {
        const auto *range = arm_code_at(at);
        if (!range || (range->kind != ArmCodeKind::a32 && range->kind != ArmCodeKind::thumb))
            return 0;
        maximum = std::min(maximum, range->size - (at.offset - range->begin.offset));
    }
    return policy_window(layout_.code_exclusions, at, maximum);
}
std::uint64_t Image::plaintext_window(Address at, std::uint64_t maximum) const noexcept {
    return policy_window(layout_.encrypted_ranges, at, maximum);
}
const AddressSpace *Image::space(AddressSpaceId id) const noexcept {
    if (id == layout_.space.id)
        return &layout_.space;
    auto found = std::lower_bound(layout_.domains.begin(), layout_.domains.end(), id.value,
                                  [](const auto &domain, auto value) { return domain.space.id.value < value; });
    return found != layout_.domains.end() && found->space.id == id ? &found->space : nullptr;
}
Result<DecodeContext> Image::context_at(Address address) const {
    const auto *domain = space(address.space);
    if (!domain || (domain->width_bits < 64 && address.offset >= (UINT64_C(1) << domain->width_bits)))
        return Error{ErrorCode::out_of_bounds, "Address is outside its declared domain"};
    if (layout_.arm_profile) {
        const auto *range = arm_code_at(address);
        if (range && range->kind == ArmCodeKind::conflict)
            return Error{ErrorCode::conflict, "Conflicting ARM code-context declarations at address"};
        const auto mode = !range                              ? ExecutionMode::unknown
                          : range->kind == ArmCodeKind::a32   ? ExecutionMode::a32
                          : range->kind == ArmCodeKind::thumb ? ExecutionMode::thumb
                                                              : ExecutionMode::unknown;
        return DecodeContext{Architecture::arm, mode, domain->order};
    }
    if (layout_.execution_profile) {
        if (const auto *range = execution_range_at(address))
            return range->context;
        return DecodeContext{Architecture::unknown, ExecutionMode::unknown, domain->order};
    }
    if (address.space == layout_.space.id)
        return decode_context();
    auto found = std::lower_bound(layout_.domains.begin(), layout_.domains.end(), address.space.value,
                                  [](const auto &row, auto value) { return row.space.id.value < value; });
    return found->context;
}
const ImageExecutionRange *Image::execution_range_at(Address address) const noexcept {
    if (!layout_.execution_profile)
        return nullptr;
    const auto &ranges = layout_.execution_profile->ranges;
    const auto next = std::upper_bound(ranges.begin(), ranges.end(), address,
                                       [](Address value, const auto &range) { return less(value, range.begin); });
    if (next == ranges.begin())
        return nullptr;
    const auto &range = *std::prev(next);
    return range.begin.space == address.space && address.offset >= range.begin.offset &&
                   address.offset - range.begin.offset < range.size
               ? &range
               : nullptr;
}
Result<bool> Image::validate_execution_profile() const {
    if (!layout_.execution_profile)
        return true;
    std::optional<Address> previous_end;
    for (const auto &range : layout_.execution_profile->ranges) {
        const auto *domain = space(range.begin.space);
        const auto end = checked_add(range.begin.offset, range.size);
        if (!domain || !range.size || !end || range.context.order != domain->order ||
            range.context.architecture == Architecture::unknown || range.context.mode == ExecutionMode::unknown)
            return Error{ErrorCode::malformed, "Invalid multi-ISA image execution range"};
        if (domain->width_bits < 64 && end.value() > (UINT64_C(1) << domain->width_bits))
            return Error{ErrorCode::overflow, "Execution range exceeds its address space"};
        if (previous_end && previous_end->space == range.begin.space && range.begin.offset < previous_end->offset)
            return Error{ErrorCode::malformed, "Overlapping multi-ISA image execution ranges"};
        std::uint64_t cursor = range.begin.offset;
        while (cursor < end.value()) {
            const auto *segment = segment_at({range.begin.space, cursor});
            if (!segment || !segment->executable || cursor < segment->begin.offset)
                return Error{ErrorCode::malformed,
                             "Execution range leaves executable image segments"};
            const auto relative = cursor - segment->begin.offset;
            if (relative >= segment->file_size)
                return Error{ErrorCode::malformed,
                             "Execution range includes uninitialized image bytes"};
            const auto amount = std::min(end.value() - cursor, segment->file_size - relative);
            if (!amount)
                return Error{ErrorCode::malformed,
                             "Execution range includes uninitialized image bytes"};
            cursor += amount;
        }
        previous_end = Address{range.begin.space, end.value()};
    }
    if (layout_.execution_profile->ranges.empty())
        return Error{ErrorCode::malformed, "An authoritative execution profile cannot be empty"};
    return true;
}
const Segment *Image::segment_at(Address address) const noexcept {
    if (!space(address.space))
        return nullptr;
    const auto &segments = layout_.segments;
    auto it = std::upper_bound(segments.begin(), segments.end(), address,
                               [](Address value, const Segment &s) { return less(value, s.begin); });
    while (it != segments.begin()) {
        --it;
        if (it->begin.space != address.space)
            return nullptr;
        if (it->size != 0)
            return address.offset - it->begin.offset < it->size ? &*it : nullptr;
    }
    return nullptr;
}
Result<std::vector<std::byte>> Image::read(Address address, std::size_t count) const {
    const auto *domain = space(address.space);
    if (!domain)
        return Error{ErrorCode::out_of_bounds, "Read uses an undeclared address space"};
    const auto end = checked_add(address.offset, count);
    if (!end)
        return end.error();
    if (domain->width_bits < 64 &&
        (address.offset >= (UINT64_C(1) << domain->width_bits) || end.value() > (UINT64_C(1) << domain->width_bits)))
        return Error{ErrorCode::out_of_bounds, "Read exceeds declared address width"};
    // Validate the entire range before allocating or exposing partial bytes.
    std::uint64_t cursor = address.offset;
    while (cursor < end.value()) {
        const auto *s = segment_at({address.space, cursor});
        if (!s)
            return Error{ErrorCode::out_of_bounds, "Read crosses an unmapped address: " + std::to_string(cursor)};
        cursor += std::min(end.value() - cursor, s->size - (cursor - s->begin.offset));
    }
    try {
        std::vector<std::byte> output(count, std::byte{0});
        std::size_t done = 0;
        while (done < count) {
            const auto *s = segment_at({address.space, address.offset + done});
            const auto relative = address.offset + done - s->begin.offset;
            const auto chunk = static_cast<std::size_t>(std::min<std::uint64_t>(count - done, s->size - relative));
            if (relative < s->file_size) {
                const auto backed = static_cast<std::size_t>(std::min<std::uint64_t>(chunk, s->file_size - relative));
                auto input = storage_->read_at({s->file_begin.value + relative}, backed);
                if (!input)
                    return input.error();
                if (input.value().bytes.size() != backed)
                    return Error{ErrorCode::io, "Initialized image backing returned a short read"};
                std::copy(input.value().bytes.begin(), input.value().bytes.end(),
                          output.begin() + static_cast<std::ptrdiff_t>(done));
            }
            done += chunk;
        }
        return output;
    } catch (const std::bad_alloc &) {
        return Error{ErrorCode::resource_limit, "Cannot allocate requested image read"};
    } catch (const std::length_error &) {
        return Error{ErrorCode::resource_limit, "Requested image read is too large"};
    }
}
Result<FileOffset> Image::to_file_offset(Address address) const {
    const auto *s = segment_at(address);
    if (!s || address.offset - s->begin.offset >= s->file_size)
        return Error{ErrorCode::out_of_bounds, "Address has no initialized file backing"};
    return FileOffset{s->file_begin.value + (address.offset - s->begin.offset)};
}
Result<Address> Image::to_address(FileOffset offset) const {
    const Segment *found = nullptr;
    for (const auto &s : layout_.segments) {
        if (offset.value >= s.file_begin.value && offset.value - s.file_begin.value < s.file_size) {
            if (found)
                return Error{ErrorCode::invalid_argument, "File offset maps to multiple virtual addresses"};
            found = &s;
        }
    }
    if (!found)
        return Error{ErrorCode::out_of_bounds, "File offset is not virtually mapped"};
    return Address{found->begin.space, found->begin.offset + (offset.value - found->file_begin.value)};
}
} // namespace hexlab
