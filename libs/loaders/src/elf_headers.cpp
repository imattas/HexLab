#include "hexlab/loaders/elf.hpp"
#include <new>

namespace hexlab {
namespace {
struct Failure {
    Error error;
};
void require(bool condition, const char *message, ErrorCode code = ErrorCode::malformed) {
    if (!condition)
        throw Failure{{code, message}};
}
void canceled(std::stop_token stop) {
    require(!stop.stop_requested(), "ELF header reading canceled", ErrorCode::canceled);
}
ByteView read(const ByteStorage &storage, std::uint64_t offset, std::size_t size, std::stop_token stop) {
    canceled(stop);
    require(offset <= storage.size() && size <= storage.size() - offset, "Truncated ELF header or section0");
    auto result = storage.read_at({offset}, size);
    if (!result)
        throw Failure{result.error()};
    require(result.value().bytes.size() == size, "ELF storage returned an incomplete view");
    canceled(stop);
    return std::move(result.value());
}
std::uint64_t integer(std::span<const std::byte> data, std::size_t at, std::size_t size, ByteOrder order) {
    require(at <= data.size() && size <= data.size() - at, "Truncated ELF integer");
    std::uint64_t result = 0;
    for (std::size_t i = 0; i < size; ++i)
        result |= std::to_integer<std::uint64_t>(data[at + i]) << (8 * (order == ByteOrder::little ? i : size - i - 1));
    return result;
}
constexpr std::uint64_t metadata_limit = 64 * 1024 * 1024;
std::uint64_t table_extent(const ByteStorage &storage, const ElfTable &table, std::uint64_t minimum,
                           std::uint64_t count_limit) {
    require(table.count <= count_limit, "ELF table record limit exceeded", ErrorCode::resource_limit);
    if (!table.count) {
        require(table.offset == 0, "Empty ELF table has a nonzero offset");
        return 0;
    }
    require(table.offset != 0 && table.stride >= minimum, "Invalid ELF table offset or entry size");
    require(table.stride <= metadata_limit / table.count, "ELF metadata extent limit exceeded",
            ErrorCode::resource_limit);
    const auto size = table.stride * table.count;
    require(table.offset <= storage.size() && size <= storage.size() - table.offset, "ELF table exceeds source extent");
    return size;
}
} // namespace
Result<ElfHeader> read_elf_header(const ByteStorage &storage, std::stop_token stop) {
    try {
        const auto ident = read(storage, 0, 16, stop);
        const auto b = ident.bytes;
        require(b[0] == std::byte{0x7f} && b[1] == std::byte{'E'} && b[2] == std::byte{'L'} && b[3] == std::byte{'F'},
                "Invalid ELF magic");
        require(b[4] == std::byte{1} || b[4] == std::byte{2}, "Unsupported ELF class", ErrorCode::unsupported);
        require(b[5] == std::byte{1} || b[5] == std::byte{2}, "Unsupported ELF byte order", ErrorCode::unsupported);
        require(b[6] == std::byte{1}, "Unsupported ELF identification version", ErrorCode::unsupported);
        ElfHeader header;
        header.is_64 = b[4] == std::byte{2};
        header.order = b[5] == std::byte{1} ? ByteOrder::little : ByteOrder::big;
        header.os_abi = std::to_integer<std::uint8_t>(b[7]);
        header.abi_version = std::to_integer<std::uint8_t>(b[8]);
        const auto full = read(storage, 0, header.is_64 ? 64 : 52, stop);
        const auto get = [&](std::size_t at, std::size_t width) {
            return integer(full.bytes, at, width, header.order);
        };
        header.object_type = static_cast<std::uint16_t>(get(16, 2));
        header.machine = static_cast<std::uint16_t>(get(18, 2));
        header.version = static_cast<std::uint32_t>(get(20, 4));
        require(header.object_type >= 1 && header.object_type <= 4, "Unsupported ELF object type",
                ErrorCode::unsupported);
        require(header.version == 1, "Unsupported ELF header version", ErrorCode::unsupported);
        const auto width = header.is_64 ? 8u : 4u;
        header.entry = get(24, width);
        header.programs.offset = get(header.is_64 ? 32 : 28, width);
        header.sections.offset = get(header.is_64 ? 40 : 32, width);
        header.flags = static_cast<std::uint32_t>(get(header.is_64 ? 48 : 36, 4));
        const auto fields = header.is_64 ? 54u : 42u;
        require(get(fields - 2, 2) == (header.is_64 ? 64u : 52u), "Invalid ELF header size");
        header.programs.stride = get(fields, 2);
        header.programs.count = get(fields + 2, 2);
        header.sections.stride = get(fields + 4, 2);
        header.sections.count = get(fields + 6, 2);
        header.section_names = get(fields + 8, 2);
        require(header.sections.count < 0xff00, "Reserved ELF section count must use extended encoding");
        require(header.section_names < 0xff00 || header.section_names == 0xffff, "Reserved ELF section-name index");
        const bool extended_sections = header.sections.offset != 0 && header.sections.count == 0;
        const bool extended_programs = header.programs.count == 0xffff;
        const bool extended_names = header.section_names == 0xffff;
        if (extended_sections || extended_programs || extended_names) {
            require(header.sections.offset != 0 && header.sections.stride >= (header.is_64 ? 64u : 40u),
                    "Extended ELF header fields require a section0 record");
            const auto first = read(storage, header.sections.offset, header.is_64 ? 64 : 40, stop);
            const auto section = [&](std::size_t at, std::size_t n) {
                return integer(first.bytes, at, n, header.order);
            };
            require(section(4, 4) == 0, "ELF extended-count carrier must be SHT_NULL");
            if (extended_sections) {
                header.sections.count = section(header.is_64 ? 32 : 20, width);
                require(header.sections.count != 0, "ELF extended section count cannot be zero");
            }
            if (extended_programs)
                header.programs.count = section(header.is_64 ? 44 : 28, 4);
            if (extended_names)
                header.section_names = section(header.is_64 ? 40 : 24, 4);
        }
        const auto programs_size = table_extent(storage, header.programs, header.is_64 ? 56 : 32, 65536);
        const auto sections_size = table_extent(storage, header.sections, header.is_64 ? 64 : 40, 1048576);
        require(sections_size <= metadata_limit - programs_size, "Combined ELF metadata extent limit exceeded",
                ErrorCode::resource_limit);
        require(header.section_names == 0 || header.section_names < header.sections.count,
                "ELF section-name index is outside table");
        canceled(stop);
        return header;
    } catch (const Failure &error) {
        return error.error;
    } catch (const std::bad_alloc &) {
        return Error{ErrorCode::resource_limit, "Cannot allocate ELF header data"};
    }
}
} // namespace hexlab
