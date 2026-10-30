#include "hexlab/loaders/dex_container.hpp"
#include <algorithm>
#include <cstring>
#include <new>

namespace hexlab {
namespace {
constexpr std::uint64_t maximum_container_bytes = 512ull * 1024 * 1024;
constexpr std::uint32_t header_bytes = 0x78;
constexpr std::size_t maximum_members = 1'000'000;

std::uint32_t little_u32(std::span<const std::byte> bytes, std::size_t offset) {
    return std::to_integer<std::uint32_t>(bytes[offset]) |
        (std::to_integer<std::uint32_t>(bytes[offset + 1]) << 8) |
        (std::to_integer<std::uint32_t>(bytes[offset + 2]) << 16) |
        (std::to_integer<std::uint32_t>(bytes[offset + 3]) << 24);
}
}

Result<std::vector<DexContainerMember>> inspect_dex041_container(
    const ByteStorage &storage, std::stop_token stop) {
    const auto container_size = storage.size();
    if (container_size < header_bytes)
        return Error{ErrorCode::malformed, "Truncated DEX 041 container header"};
    if (container_size > maximum_container_bytes || container_size > UINT32_MAX)
        return Error{ErrorCode::resource_limit, "DEX 041 container exceeds the 512 MiB inventory limit"};

    std::vector<DexContainerMember> members;
    std::uint64_t offset = 0;
    try {
        while (offset < container_size) {
            if (stop.stop_requested()) return Error{ErrorCode::canceled, "DEX 041 container inventory canceled"};
            if (members.size() >= maximum_members)
                return Error{ErrorCode::resource_limit, "DEX 041 container exceeds one million logical members"};
            if ((offset & 3) || container_size - offset < header_bytes)
                return Error{ErrorCode::malformed, "DEX 041 next-header offset is unaligned or truncated"};
            auto read = storage.read_at({offset}, header_bytes);
            if (!read) return read.error();
            const auto bytes = read.value().bytes;
            if (bytes.size() != header_bytes)
                return Error{ErrorCode::io, "DEX 041 source returned an incomplete header"};
            if (std::memcmp(bytes.data(), "dex\n041\0", 8) != 0)
                return Error{ErrorCode::malformed, "DEX 041 member magic is invalid"};

            const auto logical_size = little_u32(bytes, 32);
            const auto declared_header_size = little_u32(bytes, 36);
            const auto endian = little_u32(bytes, 40);
            const auto declared_container_size = little_u32(bytes, 112);
            const auto declared_header_offset = little_u32(bytes, 116);
            if (logical_size < header_bytes || declared_header_size != header_bytes || endian != 0x12345678 ||
                declared_container_size != container_size || declared_header_offset != offset ||
                logical_size > container_size - offset)
                return Error{ErrorCode::malformed, "DEX 041 member bounds or container identity are inconsistent"};

            DexContainerMember member;
            member.header_offset = static_cast<std::uint32_t>(offset);
            member.logical_file_size = logical_size;
            member.checksum = little_u32(bytes, 8);
            std::copy_n(bytes.begin() + 12, member.signature.size(), member.signature.begin());
            members.push_back(member);
            offset += logical_size;
        }
    } catch (const std::bad_alloc &) {
        return Error{ErrorCode::resource_limit, "Cannot allocate DEX 041 container inventory"};
    }
    return members;
}

} // namespace hexlab
