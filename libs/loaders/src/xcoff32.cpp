#include "hexlab/loaders/xcoff32.hpp"
#include <limits>
#include <new>
#include <stdexcept>

namespace hexlab {
namespace {
struct Failure { Error error; };
void require(bool ok, const char *message, ErrorCode code = ErrorCode::malformed) {
    if (!ok) throw Failure{{code, message}};
}
void canceled(std::stop_token stop) {
    require(!stop.stop_requested(), "XCOFF32 object inspection canceled", ErrorCode::canceled);
}
std::uint32_t be(std::span<const std::byte> bytes, std::size_t at, std::size_t width) {
    require(at <= bytes.size() && width <= bytes.size() - at, "Truncated XCOFF32 record");
    std::uint32_t value = 0;
    for (std::size_t i = 0; i < width; ++i)
        value = (value << 8) | std::to_integer<std::uint8_t>(bytes[at + i]);
    return value;
}
bool contains(std::uint64_t extent, std::uint64_t offset, std::uint64_t size) {
    return offset <= extent && size <= extent - offset;
}
void charge(std::uint64_t size, std::uint64_t &budget, const Xcoff32ObjectLimits &limits) {
    require(budget <= limits.max_metadata_bytes && size <= limits.max_metadata_bytes - budget,
            "XCOFF32 object metadata exceeds configured limit", ErrorCode::resource_limit);
    budget += size;
}
std::vector<std::byte> read(const ByteStorage &storage, std::uint64_t offset,
                          std::uint64_t size, std::uint64_t &budget,
                          const Xcoff32ObjectLimits &limits, std::stop_token stop) {
    canceled(stop);
    require(contains(storage.size(), offset, size), "XCOFF32 record exceeds file extent");
    require(size <= std::numeric_limits<std::size_t>::max(),
            "XCOFF32 record exceeds host address space", ErrorCode::resource_limit);
    charge(size, budget, limits);
    auto view = storage.read_at({offset}, static_cast<std::size_t>(size));
    if (!view) throw Failure{view.error()};
    require(view.value().bytes.size() == size, "Incomplete XCOFF32 record read", ErrorCode::io);
    canceled(stop);
    return {view.value().bytes.begin(), view.value().bytes.end()};
}
}

Result<Xcoff32Object> inspect_xcoff32_object(const ByteStorage &storage,
    std::stop_token stop, Xcoff32ObjectLimits limits) try {
    require(limits.max_sections && limits.max_symbols && limits.max_metadata_bytes && limits.max_name_bytes,
            "XCOFF32 object limits must be positive", ErrorCode::invalid_argument);
    std::uint64_t budget = 0;
    const auto header = read(storage, 0, 20, budget, limits, stop);
    require(be(header, 0, 2) == 0x01df, "Invalid XCOFF32 magic");
    const auto section_count = be(header, 2, 2);
    Xcoff32Object result;
    result.timestamp = be(header, 4, 4);
    result.symbol_table_file_offset = be(header, 8, 4);
    result.symbol_count = be(header, 12, 4);
    result.file_flags = static_cast<std::uint16_t>(be(header, 18, 2));
    require((result.file_flags & 0x0002u) == 0,
            "XCOFF32 inventory accepts relocatable objects, not F_EXEC images", ErrorCode::unsupported);
    require(be(header, 16, 2) == 0,
            "XCOFF32 inventory does not support optional headers", ErrorCode::unsupported);
    require(section_count <= limits.max_sections,
            "XCOFF32 section count exceeds configured limit", ErrorCode::resource_limit);
    require(result.symbol_count <= limits.max_symbols,
            "XCOFF32 symbol count exceeds configured limit", ErrorCode::resource_limit);
    const auto section_bytes = std::uint64_t{section_count} * 40;
    const auto header_end = 20 + section_bytes;
    const auto sections = read(storage, 20, section_bytes, budget, limits, stop);
    charge(std::uint64_t{section_count} * sizeof(Xcoff32Section), budget, limits);
    result.sections.reserve(section_count);
    for (std::uint32_t index = 0; index < section_count; ++index) {
        canceled(stop);
        const auto row = std::span<const std::byte>(sections).subspan(std::size_t{index} * 40, 40);
        Xcoff32Section section;
        section.index = index + 1;
        std::size_t name_size = 0;
        while (name_size < 8 && row[name_size] != std::byte{0}) ++name_size;
        require(name_size <= limits.max_name_bytes,
                "XCOFF32 section name exceeds limit", ErrorCode::resource_limit);
        charge(name_size, budget, limits);
        section.name.assign(reinterpret_cast<const char *>(row.data()), name_size);
        section.physical_address = be(row, 8, 4);
        section.virtual_address = be(row, 12, 4);
        section.size = be(row, 16, 4);
        section.data_file_offset = be(row, 20, 4);
        section.relocation_file_offset = be(row, 24, 4);
        section.line_number_file_offset = be(row, 28, 4);
        section.relocation_count = static_cast<std::uint16_t>(be(row, 32, 2));
        section.line_number_count = static_cast<std::uint16_t>(be(row, 34, 2));
        section.flags = be(row, 36, 4);
        const auto type = section.flags & 0xffffu;
        require(section.flags != 0xffffffffu && type != 0x8000 &&
                    section.relocation_count != 0xffff && section.line_number_count != 0xffff,
                "XCOFF32 deleted or overflow section headers are unsupported", ErrorCode::unsupported);
        // BSS/TBSS have no file-backed data; names do not determine section type.
        if (type != 0x80 && type != 0x800 && section.data_file_offset && section.size)
            require(section.data_file_offset >= header_end &&
                        contains(storage.size(), section.data_file_offset, section.size),
                    "XCOFF32 section data exceeds file extent or overlaps headers");
        if (section.relocation_count) {
            require(type != 0x1000, "XCOFF32 loader relocation rows are unsupported", ErrorCode::unsupported);
            require(section.relocation_file_offset >= header_end &&
                        contains(storage.size(), section.relocation_file_offset,
                                 std::uint64_t{section.relocation_count} * 10),
                    "XCOFF32 relocation table exceeds file extent or overlaps headers");
        }
        if (section.line_number_count)
            require(section.line_number_file_offset >= header_end &&
                        contains(storage.size(), section.line_number_file_offset,
                                 std::uint64_t{section.line_number_count} * 6),
                    "XCOFF32 line-number table exceeds file extent or overlaps headers");
        result.sections.push_back(std::move(section));
    }

    if (result.symbol_count) {
        const auto symbol_offset = std::uint64_t{result.symbol_table_file_offset};
        const auto symbol_bytes = std::uint64_t{result.symbol_count} * 18;
        require(symbol_offset >= header_end, "XCOFF32 symbol table overlaps headers");
        const auto symbols = read(storage, symbol_offset, symbol_bytes, budget, limits, stop);
        const auto string_offset = symbol_offset + symbol_bytes;
        std::vector<std::byte> strings;
        // A string table is optional when all retained names are inline. If
        // present, lengths <= 4 describe an empty table; larger lengths are
        // checked against the source extent before any name lookup.
        if (contains(storage.size(), string_offset, 4)) {
            const auto string_header = read(storage, string_offset, 4, budget, limits, stop);
            result.string_table_size = be(string_header, 0, 4);
            strings = result.string_table_size > 4
                ? read(storage, string_offset, result.string_table_size, budget, limits, stop)
                : string_header;
        }
        // A conservative charge for every slot bounds retained primary records
        // even when there are no auxiliary rows and every name is empty.
        charge(std::uint64_t{result.symbol_count} * sizeof(Xcoff32Object::Symbol), budget, limits);
        result.symbols.reserve(result.symbol_count);
        for (std::uint32_t i = 0; i < result.symbol_count;) {
            canceled(stop);
            const auto row = std::span<const std::byte>(symbols).subspan(std::size_t{i} * 18, 18);
            Xcoff32Object::Symbol symbol;
            symbol.index = i;
            symbol.value = be(row, 8, 4);
            const auto raw_section = static_cast<std::int32_t>(be(row, 12, 2));
            symbol.section_number = static_cast<std::int16_t>(raw_section >= 0x8000 ?
                static_cast<std::int32_t>(raw_section) - 0x10000 : raw_section);
            symbol.type = static_cast<std::uint16_t>(be(row, 14, 2));
            symbol.storage_class = static_cast<std::uint8_t>(be(row, 16, 1));
            symbol.auxiliary_count = static_cast<std::uint8_t>(be(row, 17, 1));
            require(symbol.auxiliary_count <= result.symbol_count - i - 1,
                    "XCOFF32 auxiliary symbol count exceeds table");
            if (symbol.storage_class == 2 || symbol.storage_class == 107 ||
                symbol.storage_class == 111 || symbol.storage_class == 3) {
                require(symbol.section_number >= -2 && (symbol.section_number <= 0 ||
                            static_cast<std::uint32_t>(symbol.section_number) <= section_count),
                        "XCOFF32 symbol section number is invalid");
                const bool inline_name = be(row, 0, 4) != 0;
                const auto offset = be(row, 4, 4);
                if (inline_name || offset != 0) {
                    const auto name_bytes = inline_name ? row.first(8) : std::span<const std::byte>(strings);
                    const std::size_t begin = inline_name ? 0 : offset;
                    require(inline_name || (offset >= 4 && offset < strings.size()),
                            "XCOFF32 symbol name offset is outside string table");
                    auto end = begin;
                    while (end < name_bytes.size() && name_bytes[end] != std::byte{0} &&
                           end - begin <= limits.max_name_bytes) ++end;
                    require(end - begin <= limits.max_name_bytes,
                            "XCOFF32 symbol name exceeds limit", ErrorCode::resource_limit);
                    require(inline_name || end < name_bytes.size(), "Unterminated XCOFF32 symbol name");
                    charge(end - begin, budget, limits);
                    symbol.name.assign(reinterpret_cast<const char *>(name_bytes.data() + begin), end - begin);
                }
            }
            result.symbols.push_back(std::move(symbol));
            i += 1 + result.symbols.back().auxiliary_count;
        }
    }
    canceled(stop);
    return result;
} catch (const Failure &failure) {
    return failure.error;
} catch (const std::bad_alloc &) {
    return Error{ErrorCode::resource_limit, "Cannot allocate bounded XCOFF32 object metadata"};
} catch (const std::length_error &) {
    return Error{ErrorCode::resource_limit, "XCOFF32 object metadata exceeds host container limits"};
}

} // namespace hexlab
