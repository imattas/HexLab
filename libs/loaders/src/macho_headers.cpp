#include "hexlab/loaders/macho.hpp"
#include <algorithm>
#include <new>
#include <stdexcept>
namespace hexlab {
namespace {
struct Failure {
    Error error;
};
void require(bool value, const char *message, ErrorCode code = ErrorCode::malformed) {
    if (!value)
        throw Failure{{code, message}};
}
void canceled(std::stop_token stop) {
    require(!stop.stop_requested(), "Mach-O container inspection canceled", ErrorCode::canceled);
}
constexpr std::uint64_t metadata_limit = 64 * 1024 * 1024;
struct Budget {
    std::uint64_t bytes = 0, commands = 0;
    void include(std::uint64_t count) {
        require(count <= metadata_limit - bytes, "Mach-O metadata exceeds64MiB budget", ErrorCode::resource_limit);
        bytes += count;
    }
};
std::uint64_t integer(std::span<const std::byte> bytes, std::size_t offset, std::size_t width, ByteOrder order) {
    require(offset <= bytes.size() && width <= bytes.size() - offset && width <= 8, "Truncated Mach-O scalar");
    std::uint64_t value = 0;
    for (std::size_t i = 0; i < width; ++i)
        value |= std::to_integer<std::uint64_t>(bytes[offset + i])
                 << (8 * (order == ByteOrder::little ? i : width - i - 1));
    return value;
}
ByteView read(const ByteStorage &storage, std::uint64_t offset, std::size_t count, std::stop_token stop) {
    canceled(stop);
    require(offset <= storage.size() && count <= storage.size() - offset, "Mach-O record exceeds input extent");
    auto result = storage.read_at({offset}, count);
    if (!result)
        throw Failure{result.error()};
    require(result.value().bytes.size() == count, "Mach-O storage returned an incomplete view");
    canceled(stop);
    return std::move(result.value());
}
struct Magic {
    bool universal, wide;
    ByteOrder order;
};
Magic magic(std::span<const std::byte> bytes) {
    switch (integer(bytes, 0, 4, ByteOrder::big)) {
    case 0xfeedface:
        return {false, false, ByteOrder::big};
    case 0xcefaedfe:
        return {false, false, ByteOrder::little};
    case 0xfeedfacf:
        return {false, true, ByteOrder::big};
    case 0xcffaedfe:
        return {false, true, ByteOrder::little};
    case 0xcafebabe:
        return {true, false, ByteOrder::big};
    case 0xbebafeca:
        return {true, false, ByteOrder::little};
    case 0xcafebabf:
        return {true, true, ByteOrder::big};
    case 0xbfbafeca:
        return {true, true, ByteOrder::little};
    default:
        throw Failure{{ErrorCode::malformed, "Invalid Mach-O magic"}};
    }
}
MachOHeader header(const ByteStorage &storage, const MachOSlice &slice, Budget &budget, std::stop_token stop) {
    require(slice.size >= 28, "Truncated Mach-O fixed header in slice");
    const auto first = read(storage, slice.offset, 4, stop);
    const auto kind = magic(first.bytes);
    require(!kind.universal, "Nested universal Mach-O slice is invalid");
    const auto size = kind.wide ? 32u : 28u;
    require(slice.size >= size, "Truncated Mach-O64 header in slice");
    const auto fixed = read(storage, slice.offset, size, stop);
    const auto value = [&](std::size_t at) {
        return static_cast<std::uint32_t>(integer(fixed.bytes, at, 4, kind.order));
    };
    MachOHeader out;
    out.is_64 = kind.wide;
    out.order = kind.order;
    out.cpu_type = value(4);
    out.cpu_subtype = value(8);
    out.file_type = value(12);
    out.command_count = value(16);
    out.command_bytes = value(20);
    out.flags = value(24);
    out.reserved = kind.wide ? value(28) : 0;
    // Keep the reserved word as source metadata, but do not reject older
    // binaries that left it populated. It does not affect address mapping.
    require(out.command_count <= 65536 && out.command_count <= 1048576 - budget.commands,
            "Mach-O command count exceeds budget", ErrorCode::resource_limit);
    require(out.command_bytes <= slice.size - size, "Mach-O command extent crosses slice boundary");
    require(out.command_count <= out.command_bytes / 8, "Mach-O commands cannot fit declared extent");
    budget.include(out.command_bytes);
    budget.include(std::uint64_t(out.command_count) * sizeof(MachOLoadCommand));
    budget.commands += out.command_count;
    out.commands.reserve(out.command_count);
    std::uint64_t position = size;
    const auto end = position + out.command_bytes; // Bounded by the already-checked slice size.
    for (std::uint32_t index = 0; index < out.command_count; ++index) {
        canceled(stop);
        require(position <= end && 8 <= end - position, "Truncated Mach-O command envelope");
        const auto at = slice.offset + position; // Slice end has been checked against storage size.
        const auto bytes = read(storage, at, 8, stop);
        const auto command = static_cast<std::uint32_t>(integer(bytes.bytes, 0, 4, kind.order));
        const auto extent = static_cast<std::uint32_t>(integer(bytes.bytes, 4, 4, kind.order));
        require(extent >= 8 && extent % (kind.wide ? 8 : 4) == 0, "Invalid Mach-O command size/alignment");
        require(extent <= end - position, "Mach-O command crosses declared extent");
        out.commands.push_back({index, command, extent, at});
        position += extent;
    }
    require(position == end, "Mach-O command count does not consume sizeofcmds");
    canceled(stop);
    return out;
}
} // namespace
Result<MachOContainer> read_macho_container(const ByteStorage &storage, std::stop_token stop) {
    try {
        const auto first = read(storage, 0, 4, stop);
        const auto kind = magic(first.bytes);
        MachOContainer out;
        out.universal = kind.universal;
        out.fat_64 = kind.universal && kind.wide;
        out.order = kind.order;
        Budget budget;
        if (!kind.universal) {
            MachOSlice slice;
            slice.size = storage.size();
            budget.include(sizeof(MachOSlice));
            slice.header = header(storage, slice, budget, stop);
            slice.cpu_type = slice.header.cpu_type;
            slice.cpu_subtype = slice.header.cpu_subtype;
            out.slices.push_back(std::move(slice));
            return out;
        }
        const auto fixed = read(storage, 0, 8, stop);
        const auto count = integer(fixed.bytes, 4, 4, kind.order);
        require(count && count <= 4096, "Mach-O universal slice count exceeds budget", ErrorCode::resource_limit);
        const auto stride = kind.wide ? 32u : 20u;
        const auto table_end = 8 + count * stride;
        require(table_end <= storage.size(), "Truncated Mach-O universal descriptor table");
        budget.include(table_end + count * (sizeof(MachOSlice) + sizeof(std::pair<std::uint64_t, std::uint64_t>)));
        out.slices.reserve(static_cast<std::size_t>(count));
        std::vector<std::pair<std::uint64_t, std::uint64_t>> intervals;
        intervals.reserve(static_cast<std::size_t>(count));
        for (std::uint32_t index = 0; index < count; ++index) {
            const auto bytes = read(storage, 8 + std::uint64_t(index) * stride, stride, stop);
            const auto value = [&](std::size_t at, std::size_t width) {
                return integer(bytes.bytes, at, width, kind.order);
            };
            MachOSlice slice;
            slice.index = index;
            slice.cpu_type = static_cast<std::uint32_t>(value(0, 4));
            slice.cpu_subtype = static_cast<std::uint32_t>(value(4, 4));
            slice.offset = value(8, kind.wide ? 8 : 4);
            slice.size = value(kind.wide ? 16 : 12, kind.wide ? 8 : 4);
            slice.alignment = static_cast<std::uint32_t>(value(kind.wide ? 24 : 16, 4));
            slice.reserved = kind.wide ? static_cast<std::uint32_t>(value(28, 4)) : 0;
            require(!kind.wide || slice.reserved == 0,
                    "Mach-O FAT64 descriptor reserved field is nonzero");
            require(slice.alignment < 64, "Mach-O slice alignment exponent overflows");
            require(slice.offset % (UINT64_C(1) << slice.alignment) == 0, "Misaligned Mach-O universal slice");
            require(slice.offset >= table_end && slice.offset <= storage.size() && slice.size >= 28 &&
                        slice.size <= storage.size() - slice.offset,
                    "Mach-O universal slice exceeds source or overlaps descriptors");
            intervals.emplace_back(slice.offset, slice.offset + slice.size);
            out.slices.push_back(std::move(slice));
        }
        std::sort(intervals.begin(), intervals.end());
        for (std::size_t index = 1; index < intervals.size(); ++index)
            require(intervals[index - 1].second <= intervals[index].first, "Overlapping Mach-O universal slices");
        for (auto &slice : out.slices) {
            canceled(stop);
            slice.header = header(storage, slice, budget, stop);
            require(slice.header.cpu_type == slice.cpu_type && slice.header.cpu_subtype == slice.cpu_subtype,
                    "Mach-O universal CPU descriptor differs from inner header");
        }
        canceled(stop);
        return out;
    } catch (const Failure &failure) {
        return failure.error;
    } catch (const std::bad_alloc &) {
        return Error{ErrorCode::resource_limit, "Cannot allocate Mach-O container metadata"};
    } catch (const std::length_error &) {
        return Error{ErrorCode::resource_limit, "Mach-O container allocation exceeds limits"};
    }
}
} // namespace hexlab
