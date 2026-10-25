#pragma once

#include "hexlab/debugger/debugger.hpp"

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <optional>
#include <span>
#include <string>
#include <utility>
#include <vector>

namespace hexlab::debugger::darwin {

// Decode the remote ABI explicitly: dyld pointers belong to the target, never
// to this process. Only native little-endian 64-bit Mach-O targets are exposed.
inline std::uint32_t image_u32(std::span<const std::byte> bytes, std::size_t offset) {
    std::uint32_t value = 0;
    for (unsigned i = 0; i < 4; ++i)
        value |= std::to_integer<std::uint32_t>(bytes[offset + i]) << (8 * i);
    return value;
}
inline std::uint64_t image_u64(std::span<const std::byte> bytes, std::size_t offset) {
    return image_u32(bytes, offset) | (static_cast<std::uint64_t>(image_u32(bytes, offset + 4)) << 32);
}

template<class Read>
Result<std::string> image_path(std::uint64_t address, Read& read) {
    if (address == 0) return Error{ErrorCode::malformed, "dyld image path is null"};
    std::string path;
    constexpr std::size_t max_path = 4096;
    while (path.size() < max_path) {
        // Do not cross a possible 4 KiB page boundary merely to find a NUL.
        const auto size = std::min({std::size_t{64}, max_path - path.size(),
            std::size_t{4096} - static_cast<std::size_t>(address & 4095)});
        if (address > UINT64_MAX - size)
            return Error{ErrorCode::malformed, "dyld image path address overflows"};
        auto bytes = read(address, size);
        if (!bytes) return bytes.error();
        if (bytes.value().size() != size) return Error{ErrorCode::io, "short dyld image path read"};
        for (const auto byte : bytes.value()) {
            if (byte == std::byte{}) return path;
            path.push_back(static_cast<char>(std::to_integer<unsigned char>(byte)));
        }
        address += size;
    }
    return Error{ErrorCode::resource_limit, "dyld image path exceeds 4096 bytes"};
}

template<class Read>
Result<std::pair<std::uint64_t, std::uint64_t>> image_extent(std::uint64_t address, Read& read) {
    constexpr std::size_t header_size = 32;
    if (address == 0 || address > UINT64_MAX - header_size)
        return Error{ErrorCode::malformed, "invalid dyld image load address"};
    auto header = read(address, header_size);
    if (!header) return header.error();
    if (header.value().size() != header_size) return Error{ErrorCode::io, "short Mach-O header read"};
    if (image_u32(header.value(), 0) != 0xfeedfacfu)
        return Error{ErrorCode::unsupported, "dyld image is not a little-endian 64-bit Mach-O image"};
    const auto cpu = image_u32(header.value(), 4);
    if (cpu != 0x01000007u && cpu != 0x0100000cu)
        return Error{ErrorCode::unsupported, "Darwin module inspection supports only x86-64 and AArch64 Mach-O images"};
    const auto count = image_u32(header.value(), 16);
    const auto command_bytes = image_u32(header.value(), 20);
    if (command_bytes > max_inspection_read)
        return Error{ErrorCode::resource_limit, "Mach-O load commands exceed the inspection read limit"};
    if (count == 0 || count > command_bytes / 8 || address + header_size > UINT64_MAX - command_bytes)
        return Error{ErrorCode::malformed, "invalid Mach-O load command count or extent"};
    auto commands = read(address + header_size, command_bytes);
    if (!commands) return commands.error();
    if (commands.value().size() != command_bytes) return Error{ErrorCode::io, "short Mach-O load command read"};
    struct Segment { std::uint64_t address; std::uint64_t size; };
    std::vector<Segment> segments;
    std::optional<std::uint64_t> header_vmaddr;
    std::size_t offset = 0;
    for (std::uint32_t i = 0; i < count; ++i) {
        if (offset > command_bytes || command_bytes - offset < 8)
            return Error{ErrorCode::malformed, "truncated Mach-O load command"};
        const auto kind = image_u32(commands.value(), offset);
        const auto size = image_u32(commands.value(), offset + 4);
        if (size < 8 || size % 8 != 0 || size > command_bytes - offset)
            return Error{ErrorCode::malformed, "invalid Mach-O load command size"};
        if (kind == 0x19) { // LC_SEGMENT_64
            if (size < 72) return Error{ErrorCode::malformed, "truncated Mach-O segment command"};
            const auto vmaddr = image_u64(commands.value(), offset + 24);
            const auto vmsize = image_u64(commands.value(), offset + 32);
            const auto fileoff = image_u64(commands.value(), offset + 40);
            const auto filesize = image_u64(commands.value(), offset + 48);
            const auto sections = image_u32(commands.value(), offset + 64);
            if (sections > (size - 72) / 80 || vmaddr > UINT64_MAX - vmsize ||
                fileoff > UINT64_MAX - filesize || filesize > vmsize)
                return Error{ErrorCode::malformed, "invalid Mach-O segment extent or section count"};
            constexpr char pagezero_name[16] = "__PAGEZERO";
            const bool pagezero = std::memcmp(commands.value().data() + offset + 8,
                pagezero_name, sizeof(pagezero_name)) == 0;
            if (vmsize != 0 && !pagezero) segments.push_back({vmaddr, vmsize});
            if (fileoff == 0 && filesize >= header_size && vmsize >= header_size && !pagezero) {
                if (header_vmaddr) return Error{ErrorCode::malformed, "ambiguous Mach-O header segment"};
                header_vmaddr = vmaddr;
            }
        }
        offset += size;
    }
    if (offset != command_bytes || !header_vmaddr || segments.empty())
        return Error{ErrorCode::malformed, "Mach-O image lacks a valid header segment or command extent"};
    std::uint64_t begin = UINT64_MAX;
    std::uint64_t end = 0;
    for (const auto& segment : segments) {
        std::uint64_t runtime;
        if (segment.address >= *header_vmaddr) {
            const auto delta = segment.address - *header_vmaddr;
            if (address > UINT64_MAX - delta)
                return Error{ErrorCode::malformed, "slid Mach-O segment address overflows"};
            runtime = address + delta;
        } else {
            const auto delta = *header_vmaddr - segment.address;
            if (address < delta) return Error{ErrorCode::malformed, "slid Mach-O segment address underflows"};
            runtime = address - delta;
        }
        if (runtime > UINT64_MAX - segment.size)
            return Error{ErrorCode::malformed, "slid Mach-O segment extent overflows"};
        begin = std::min(begin, runtime);
        end = std::max(end, runtime + segment.size);
    }
    return std::pair{begin, end - begin};
}

template<class Read>
Result<std::vector<ModuleInfo>> image_modules(std::uint64_t infos_address, Read&& read) {
    constexpr std::size_t prefix_size = 16;
    constexpr std::size_t image_size = 24;
    if (infos_address == 0 || infos_address > UINT64_MAX - prefix_size)
        return Error{ErrorCode::busy, "Darwin dyld image information is not initialized"};
    auto prefix = read(infos_address, prefix_size);
    if (!prefix) return prefix.error();
    if (prefix.value().size() != prefix_size) return Error{ErrorCode::io, "short dyld image information read"};
    if (image_u32(prefix.value(), 0) == 0)
        return Error{ErrorCode::unsupported, "unsupported dyld image information version"};
    const auto count = image_u32(prefix.value(), 4);
    const auto array = image_u64(prefix.value(), 8);
    if (count > max_inspection_modules)
        return Error{ErrorCode::resource_limit, "Darwin image count exceeds the inspection module limit"};
    if (array == 0) return Error{ErrorCode::busy, "dyld is updating its image list; resume to a later stop"};
    const auto table_size = static_cast<std::size_t>(count) * image_size;
    if (array > UINT64_MAX - table_size) return Error{ErrorCode::malformed, "dyld image array extent overflows"};
    auto table = read(array, table_size);
    if (!table) return table.error();
    if (table.value().size() != table_size) return Error{ErrorCode::io, "short dyld image array read"};
    std::vector<ModuleInfo> modules;
    modules.reserve(count);
    for (std::uint32_t i = 0; i < count; ++i) {
        const auto offset = static_cast<std::size_t>(i) * image_size;
        auto path = image_path(image_u64(table.value(), offset + 8), read);
        if (!path) return path.error();
        auto extent = image_extent(image_u64(table.value(), offset), read);
        if (!extent) return extent.error();
        const auto slash = path.value().find_last_of('/');
        auto name = path.value().substr(slash == std::string::npos ? 0 : slash + 1);
        modules.push_back({std::move(name), std::move(path.value()), extent.value().first, extent.value().second});
    }
    auto after = read(infos_address, prefix_size);
    if (!after) return after.error();
    if (after.value() != prefix.value())
        return Error{ErrorCode::busy, "dyld image list changed during inspection"};
    std::sort(modules.begin(), modules.end(), [](const auto& left, const auto& right) { return left.base < right.base; });
    return modules;
}

} // namespace hexlab::debugger::darwin
