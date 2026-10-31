#include "hexlab/loaders/macho_shared_cache.hpp"
#include <algorithm>
#include <array>
#include <iterator>
#include <limits>

namespace hexlab {
namespace {
std::uint32_t little_u32(std::span<const std::byte> bytes, std::size_t offset) {
    return std::to_integer<std::uint32_t>(bytes[offset]) |
        (std::to_integer<std::uint32_t>(bytes[offset + 1]) << 8) |
        (std::to_integer<std::uint32_t>(bytes[offset + 2]) << 16) |
        (std::to_integer<std::uint32_t>(bytes[offset + 3]) << 24);
}

std::uint64_t little_u64(std::span<const std::byte> bytes, std::size_t offset) {
    return std::uint64_t{little_u32(bytes, offset)} |
        (std::uint64_t{little_u32(bytes, offset + 4)} << 32);
}
}

Result<MachOSharedCacheInfo> inspect_macho_shared_cache_mappings(
    const ByteStorage &storage, std::stop_token stop, MachOSharedCacheLimits limits) {
    constexpr std::size_t header_prefix_size = 32;
    constexpr std::size_t mapping_record_size = 32;
    constexpr std::uint32_t max_vm_protection = 0x7;
    if (!limits.max_mappings || limits.max_mappings > 65'536 ||
        limits.max_metadata_bytes < header_prefix_size || limits.max_metadata_bytes > 4 * 1024 * 1024)
        return Error{ErrorCode::invalid_argument, "Invalid dyld shared-cache inspection limits"};
    if (storage.size() < header_prefix_size)
        return Error{ErrorCode::malformed, "dyld shared-cache header is shorter than its mapping-table prefix"};
    if (stop.stop_requested()) return Error{ErrorCode::canceled, "dyld shared-cache inspection canceled"};

    auto header_view = storage.read_at(FileOffset{0}, header_prefix_size);
    if (!header_view) return header_view.error();
    const auto header = header_view.value().bytes;
    if (header.size() != header_prefix_size)
        return Error{ErrorCode::malformed, "dyld shared-cache header prefix is truncated"};
    constexpr std::array<char, 7> magic_prefix{'d', 'y', 'l', 'd', '_', 'v', '1'};
    for (std::size_t i = 0; i < magic_prefix.size(); ++i)
        if (std::to_integer<unsigned char>(header[i]) != static_cast<unsigned char>(magic_prefix[i]))
            return Error{ErrorCode::unsupported, "Input does not have a dyld_v1 shared-cache magic"};
    if (std::to_integer<unsigned char>(header[7]) != ' ')
        return Error{ErrorCode::malformed, "dyld shared-cache architecture field is not space separated"};

    MachOSharedCacheInfo result;
    for (std::size_t i = 0; i < 16; ++i) {
        const auto character = std::to_integer<unsigned char>(header[i]);
        if (character < 0x20 || character > 0x7e)
            return Error{ErrorCode::malformed, "dyld shared-cache magic contains a non-printable byte"};
        result.magic.push_back(static_cast<char>(character));
    }
    while (!result.magic.empty() && result.magic.back() == ' ') result.magic.pop_back();

    const auto mapping_offset = little_u32(header, 16);
    const auto mapping_count = little_u32(header, 20);
    if (!mapping_count || mapping_count > limits.max_mappings)
        return Error{ErrorCode::resource_limit, "dyld shared-cache mapping count is empty or exceeds its cap"};
    const auto table_size = std::uint64_t{mapping_count} * mapping_record_size;
    if (table_size > limits.max_metadata_bytes || mapping_offset < header_prefix_size ||
        mapping_offset > storage.size() || table_size > storage.size() - mapping_offset)
        return Error{ErrorCode::malformed, "dyld shared-cache mapping table is outside the file or over budget"};
    if (stop.stop_requested()) return Error{ErrorCode::canceled, "dyld shared-cache inspection canceled"};
    auto table_view = storage.read_at(FileOffset{mapping_offset}, static_cast<std::size_t>(table_size));
    if (!table_view) return table_view.error();
    const auto table = table_view.value().bytes;
    if (table.size() != table_size)
        return Error{ErrorCode::malformed, "dyld shared-cache mapping table read was truncated"};

    try {
        result.mappings.reserve(mapping_count);
        for (std::uint32_t i = 0; i < mapping_count; ++i) {
            if (stop.stop_requested()) return Error{ErrorCode::canceled, "dyld shared-cache inspection canceled"};
            const auto offset = static_cast<std::size_t>(i) * mapping_record_size;
            MachOSharedCacheMapping mapping;
            mapping.address = little_u64(table, offset);
            mapping.size = little_u64(table, offset + 8);
            mapping.file_offset = little_u64(table, offset + 16);
            mapping.max_protection = little_u32(table, offset + 24);
            mapping.initial_protection = little_u32(table, offset + 28);
            if (!mapping.size || mapping.address > UINT64_MAX - mapping.size ||
                mapping.file_offset > storage.size() || mapping.size > storage.size() - mapping.file_offset)
                return Error{ErrorCode::malformed, "dyld shared-cache mapping has an invalid VM or file extent"};
            if ((mapping.max_protection & ~max_vm_protection) ||
                (mapping.initial_protection & ~mapping.max_protection))
                return Error{ErrorCode::malformed, "dyld shared-cache mapping protection bits are inconsistent"};
            result.mappings.push_back(mapping);
        }
        std::sort(result.mappings.begin(), result.mappings.end(), [](const auto &a, const auto &b) {
            return a.address < b.address;
        });
        for (std::size_t i = 1; i < result.mappings.size(); ++i) {
            const auto &previous = result.mappings[i - 1];
            if (previous.address + previous.size > result.mappings[i].address)
                return Error{ErrorCode::malformed, "dyld shared-cache VM mappings overlap"};
        }
        return result;
    } catch (const std::bad_alloc &) {
        return Error{ErrorCode::resource_limit, "Cannot allocate dyld shared-cache mapping inventory"};
    }
}

Result<FileOffset> macho_shared_cache_file_offset(
    const MachOSharedCacheInfo &cache, std::uint64_t address, std::uint64_t size) {
    if (!size || address > UINT64_MAX - size)
        return Error{ErrorCode::invalid_argument, "dyld shared-cache translation requires a non-empty non-overflowing range"};
    const auto found = std::upper_bound(cache.mappings.begin(), cache.mappings.end(), address,
        [](std::uint64_t value, const MachOSharedCacheMapping &mapping) { return value < mapping.address; });
    if (found == cache.mappings.begin())
        return Error{ErrorCode::out_of_bounds, "Address is outside dyld shared-cache mappings"};
    const auto &mapping = *std::prev(found);
    if (address < mapping.address)
        return Error{ErrorCode::out_of_bounds, "Range crosses or falls outside a dyld shared-cache mapping"};
    const auto displacement = address - mapping.address;
    if (displacement > mapping.size || size > mapping.size - displacement)
        return Error{ErrorCode::out_of_bounds, "Range crosses or falls outside a dyld shared-cache mapping"};
    if (mapping.file_offset > UINT64_MAX - displacement)
        return Error{ErrorCode::overflow, "dyld shared-cache file offset overflows"};
    return FileOffset{mapping.file_offset + displacement};
}

} // namespace hexlab
