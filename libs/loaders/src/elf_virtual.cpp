#include "elf_internal.hpp"
#include <algorithm>
namespace hexlab::elf_detail {
void validate_virtual_initialized(const Image &image, Address begin, std::uint64_t size, std::stop_token stop) {
    canceled(stop);
    const auto *space = image.space(begin.space);
    require(space != nullptr, "ELF metadata uses an unknown address space");
    const auto end = add(begin.offset, size);
    require(space->width_bits == 64 ||
                (begin.offset < (UINT64_C(1) << space->width_bits) && end <= (UINT64_C(1) << space->width_bits)),
            "ELF metadata exceeds address domain");
    for (auto cursor = begin.offset; cursor < end;) {
        canceled(stop);
        const auto *segment = image.segment_at({begin.space, cursor});
        require(segment != nullptr, "ELF declared metadata extent crosses unmapped memory");
        const auto relative = cursor - segment->begin.offset;
        require(relative < segment->file_size, "ELF declared metadata extent crosses zero-filled memory");
        cursor = add(cursor, std::min(end - cursor, segment->file_size - relative));
    }
}
void validate_virtual_file(const Image &image, Address begin, std::uint64_t size, FileOffset file,
                           std::stop_token stop) {
    const auto end = add(begin.offset, size);
    for (auto cursor = begin.offset; cursor < end;) {
        canceled(stop);
        const auto *segment = image.segment_at({begin.space, cursor});
        require(segment != nullptr, "ELF metadata array crosses unmapped memory");
        const auto relative = cursor - segment->begin.offset;
        require(relative < segment->file_size, "ELF metadata array crosses zero-filled memory");
        require(add(segment->file_begin.value, relative) == add(file.value, cursor - begin.offset),
                "ELF metadata array disagrees with canonical file backing");
        cursor = add(cursor, std::min(end - cursor, segment->file_size - relative));
    }
}
ByteView read_virtual(const Reader &reader, const Image &image, Address begin, std::size_t size, Budget &budget,
                      std::stop_token stop) {
    canceled(stop);
    budget.include(size);
    const auto *space = image.space(begin.space);
    require(space != nullptr, "ELF metadata uses an unknown address space");
    const auto end = add(begin.offset, size);
    require(space->width_bits == 64 ||
                (begin.offset < (UINT64_C(1) << space->width_bits) && end <= (UINT64_C(1) << space->width_bits)),
            "ELF metadata exceeds address domain");
    if (!size)
        return {};
    std::optional<std::uint64_t> first;
    bool contiguous = true;
    for (auto cursor = begin.offset; cursor < end;) {
        canceled(stop);
        const auto *segment = image.segment_at({begin.space, cursor});
        require(segment != nullptr, "ELF metadata crosses unmapped memory");
        const auto relative = cursor - segment->begin.offset;
        require(relative < segment->file_size, "ELF metadata points into zero-filled memory");
        const auto count = std::min(end - cursor, segment->file_size - relative);
        const auto file = add(segment->file_begin.value, relative);
        if (!first)
            first = file;
        else if (file != add(*first, cursor - begin.offset))
            contiguous = false;
        cursor = add(cursor, count);
    }
    if (contiguous)
        return reader.bytes(*first, size);
    auto bytes = std::make_shared<std::vector<std::byte>>(size);
    for (auto cursor = begin.offset; cursor < end;) {
        canceled(stop);
        const auto *segment = image.segment_at({begin.space, cursor});
        const auto relative = cursor - segment->begin.offset;
        const auto count = std::min(end - cursor, segment->file_size - relative);
        const auto input = reader.bytes(add(segment->file_begin.value, relative), static_cast<std::size_t>(count));
        std::copy(input.bytes.begin(), input.bytes.end(),
                  bytes->begin() + static_cast<std::ptrdiff_t>(cursor - begin.offset));
        cursor += count;
    }
    return {bytes, std::span<const std::byte>(*bytes)};
}
} // namespace hexlab::elf_detail
