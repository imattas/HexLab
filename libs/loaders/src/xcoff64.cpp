#include "hexlab/loaders/xcoff64.hpp"
#include <algorithm>
#include <limits>
#include <new>
#include <optional>
#include <string_view>

namespace hexlab {
namespace {
struct Failure { Error error; };
void require(bool ok, const char *message, ErrorCode code = ErrorCode::malformed) {
    if (!ok) throw Failure{{code, message}};
}
std::uint64_t be(std::span<const std::byte> bytes, std::size_t at, std::size_t width) {
    require(at <= bytes.size() && width <= bytes.size() - at, "Truncated XCOFF64 record");
    std::uint64_t value = 0;
    for (std::size_t i = 0; i < width; ++i)
        value = (value << 8) | std::to_integer<std::uint8_t>(bytes[at + i]);
    return value;
}
std::vector<std::byte> read(const ByteStorage &storage, std::uint64_t offset,
                            std::uint64_t size, std::uint64_t &budget,
                            const Xcoff64ObjectLimits &limits, std::stop_token stop) {
    require(!stop.stop_requested(), "XCOFF64 object inspection canceled", ErrorCode::canceled);
    require(budget <= limits.max_metadata_bytes && size <= limits.max_metadata_bytes - budget,
            "XCOFF64 object metadata exceeds configured limit", ErrorCode::resource_limit);
    require(offset <= storage.size() && size <= storage.size() - offset,
            "XCOFF64 object record exceeds file extent");
    require(size <= std::numeric_limits<std::size_t>::max(),
            "XCOFF64 object record exceeds host address space", ErrorCode::resource_limit);
    budget += size;
    auto view = storage.read_at({offset}, static_cast<std::size_t>(size));
    if (!view) throw Failure{view.error()};
    require(view.value().bytes.size() == size, "XCOFF64 source returned an incomplete record", ErrorCode::io);
    return {view.value().bytes.begin(), view.value().bytes.end()};
}
bool bss_section(std::string_view name, std::uint32_t flags) {
    constexpr std::uint32_t styp_bss = 0x80;
    return name == ".bss" || name == ".tbss" || (flags & styp_bss) != 0;
}
bool contains(std::uint64_t extent, std::uint64_t offset, std::uint64_t length) {
    return offset <= extent && length <= extent - offset;
}
}

Result<Xcoff64Object> inspect_xcoff64_object(const ByteStorage &storage,
    std::stop_token stop, Xcoff64ObjectLimits limits) try {
    require(limits.max_sections != 0 && limits.max_symbols != 0 && limits.max_relocations != 0 &&
                limits.max_metadata_bytes != 0 && limits.max_name_bytes != 0,
            "XCOFF64 object limits must be positive", ErrorCode::invalid_argument);
    require(!stop.stop_requested(), "XCOFF64 object inspection canceled", ErrorCode::canceled);
    require(storage.size() >= 24, "Truncated XCOFF64 file header");
    std::uint64_t budget = 0;
    const auto header = read(storage, 0, 24, budget, limits, stop);
    require(be(header, 0, 2) == 0x01f7, "Invalid XCOFF64 magic");
    const auto section_count = static_cast<std::uint32_t>(be(header, 2, 2));
    const auto symbol_offset = be(header, 8, 8);
    const auto optional_size = be(header, 16, 2);
    const auto symbol_count = static_cast<std::uint32_t>(be(header, 20, 4));
    const auto file_flags = static_cast<std::uint16_t>(be(header, 18, 2));
    require((file_flags & 0x0002u) == 0,
            "XCOFF64 inventory accepts relocatable objects, not F_EXEC images",
            ErrorCode::unsupported);
    require(optional_size == 0,
            "XCOFF64 inventory currently accepts relocatable objects without an auxiliary header",
            ErrorCode::unsupported);
    require(section_count <= limits.max_sections,
            "XCOFF64 section count exceeds configured limit", ErrorCode::resource_limit);
    require(symbol_count <= limits.max_symbols,
            "XCOFF64 symbol count exceeds configured limit", ErrorCode::resource_limit);
    constexpr std::uint64_t file_header_size = 24;
    constexpr std::uint64_t section_header_size = 72;
    require(section_count <= (UINT64_MAX - file_header_size) / section_header_size,
            "XCOFF64 section-header extent overflows", ErrorCode::overflow);
    const auto section_table_offset = file_header_size;
    const auto section_table_size = std::uint64_t{section_count} * section_header_size;
    require(section_table_offset <= storage.size() && section_table_size <= storage.size() - section_table_offset,
            "XCOFF64 section-header table exceeds file extent");
    const auto section_headers = read(storage, section_table_offset, section_table_size, budget, limits, stop);

    Xcoff64Object result;
    result.file_flags = file_flags;
    result.symbol_count = symbol_count;
    result.symbol_table_file_offset = symbol_offset;
    if (symbol_count) {
        constexpr std::uint64_t symbol_size = 18;
        require(symbol_offset >= section_table_offset + section_table_size,
                "XCOFF64 symbol table overlaps file headers");
        require(symbol_count <= (UINT64_MAX - symbol_offset) / symbol_size,
                "XCOFF64 symbol table extent overflows", ErrorCode::overflow);
        const auto symbol_bytes = std::uint64_t{symbol_count} * symbol_size;
        const auto strings_offset = symbol_offset + symbol_bytes;
        require(contains(storage.size(), strings_offset, 4), "XCOFF64 string table header exceeds file extent");
        const auto string_header = read(storage, strings_offset, 4, budget, limits, stop);
        const auto string_size = be(string_header, 0, 4);
        require(string_size >= 4 && contains(storage.size(), strings_offset, string_size),
                "XCOFF64 string table extent is invalid");
        const auto symbols = read(storage, symbol_offset, symbol_bytes, budget, limits, stop);
        const auto strings = read(storage, strings_offset, string_size, budget, limits, stop);
        for (std::uint32_t i = 0; i < symbol_count;) {
            require(!stop.stop_requested(), "XCOFF64 symbol scan canceled", ErrorCode::canceled);
            const auto row = std::span<const std::byte>(symbols).subspan(std::size_t{i} * 18, 18);
            Xcoff64Object::Symbol symbol;
            symbol.index = i;
            symbol.value = be(row, 0, 8);
            symbol.section_number = static_cast<std::int16_t>(be(row, 12, 2));
            symbol.storage_class = static_cast<std::uint8_t>(be(row, 16, 1));
            const auto aux_count = be(row, 17, 1);
            require(aux_count <= symbol_count - i - 1, "XCOFF64 auxiliary symbol count exceeds table");
            if (aux_count && (symbol.storage_class == 2 || symbol.storage_class == 107 || symbol.storage_class == 111)) {
                const auto auxiliary = std::span<const std::byte>(symbols).subspan(
                    static_cast<std::size_t>((std::uint64_t{i} + aux_count) * 18), 18);
                if (be(auxiliary, 17, 1) == 251) { // AUX_CSECT, the last auxiliary row
                    symbol.csect_type = static_cast<std::uint8_t>(be(auxiliary, 10, 1) & 7u);
                    symbol.storage_mapping_class = static_cast<std::uint8_t>(be(auxiliary, 11, 1));
                }
            }
            // Only binder-relevant classes have their names interpreted here.
            // Debugging symbol names may instead refer to the .debug section.
            if (symbol.storage_class == 2 || symbol.storage_class == 107 || symbol.storage_class == 111 ||
                symbol.storage_class == 3) {
                require(symbol.section_number >= -2 && (symbol.section_number <= 0 ||
                            static_cast<std::uint32_t>(symbol.section_number) <= section_count),
                        "XCOFF64 symbol section number is invalid");
                const auto offset = be(row, 8, 4);
                require(offset >= 4 && offset < strings.size(), "XCOFF64 symbol name offset is outside string table");
                std::size_t end = static_cast<std::size_t>(offset);
                while (end < strings.size() && strings[end] != std::byte{0} && end - offset <= limits.max_name_bytes) ++end;
                require(end - offset <= limits.max_name_bytes, "XCOFF64 symbol name exceeds limit", ErrorCode::resource_limit);
                require(end < strings.size(), "Unterminated XCOFF64 symbol name");
                const auto length = end - static_cast<std::size_t>(offset);
                require(length <= limits.max_metadata_bytes - budget,
                        "XCOFF64 decoded symbol names exceed metadata budget", ErrorCode::resource_limit);
                budget += length;
                symbol.name.assign(reinterpret_cast<const char *>(strings.data() + offset), length);
            }
            result.symbols.push_back(std::move(symbol));
            i += 1 + static_cast<std::uint32_t>(aux_count);
        }
    }

    std::uint64_t relocation_total = 0;
    result.sections.reserve(section_count);
    for (std::uint32_t index = 0; index < section_count; ++index) {
        if (stop.stop_requested()) return Error{ErrorCode::canceled, "XCOFF64 section scan canceled"};
        const auto header_offset = static_cast<std::size_t>(std::uint64_t{index} * section_header_size);
        const auto row = std::span<const std::byte>(section_headers).subspan(header_offset, section_header_size);
        Xcoff64Section section;
        section.index = index + 1;
        const auto raw_name = row.first(8);
        std::size_t name_size = 0;
        while (name_size < raw_name.size() && raw_name[name_size] != std::byte{0}) ++name_size;
        section.name.assign(reinterpret_cast<const char *>(raw_name.data()), name_size);
        section.physical_address = be(row, 8, 8);
        section.virtual_address = be(row, 16, 8);
        section.size = be(row, 24, 8);
        section.data_file_offset = be(row, 32, 8);
        section.relocation_file_offset = be(row, 40, 8);
        const auto line_file_offset = be(row, 48, 8);
        section.relocation_count = static_cast<std::uint32_t>(be(row, 56, 4));
        section.line_number_count = static_cast<std::uint32_t>(be(row, 60, 4));
        section.flags = static_cast<std::uint32_t>(be(row, 64, 4));
        if (section.size && !bss_section(section.name, section.flags))
            require(section.data_file_offset && contains(storage.size(), section.data_file_offset, section.size),
                    "XCOFF64 initialized section data exceeds file extent");
        if (section.line_number_count)
            require(line_file_offset != 0, "XCOFF64 line-number count has no file offset");
        section.loader_relocation_encoding = section.name == ".loader" || (section.flags & 0xffffu) == 0x1000;
        if (section.relocation_count) {
            require(section.relocation_file_offset != 0, "XCOFF64 relocation count has no file offset");
            if (section.relocation_count > limits.max_relocations - relocation_total)
                return Error{ErrorCode::resource_limit, "XCOFF64 relocation count exceeds configured limit"};
            relocation_total += section.relocation_count;
            const std::uint64_t relocation_size = section.loader_relocation_encoding ? 16 : 14;
            require(section.relocation_count <= (UINT64_MAX - section.relocation_file_offset) / relocation_size,
                    "XCOFF64 relocation table extent overflows", ErrorCode::overflow);
            const auto byte_count = std::uint64_t{section.relocation_count} * relocation_size;
            require(contains(storage.size(), section.relocation_file_offset, byte_count),
                    "XCOFF64 relocation table exceeds file extent");
            if (!section.loader_relocation_encoding) {
                const auto relocation_bytes = read(storage, section.relocation_file_offset,
                                                   byte_count, budget, limits, stop);
                section.relocations.reserve(section.relocation_count);
                std::optional<std::uint64_t> previous_address;
                for (std::uint32_t relocation_index = 0; relocation_index < section.relocation_count;
                     ++relocation_index) {
                    require(!stop.stop_requested(), "XCOFF64 relocation scan canceled", ErrorCode::canceled);
                    const auto at = static_cast<std::size_t>(std::uint64_t{relocation_index} * relocation_size);
                    const auto relocation = std::span<const std::byte>(relocation_bytes).subspan(at, 14);
                    Xcoff64Relocation value;
                    value.virtual_address = be(relocation, 0, 8);
                    value.symbol_index = static_cast<std::uint32_t>(be(relocation, 8, 4));
                    value.size_info = static_cast<std::uint8_t>(be(relocation, 12, 1));
                    value.type = static_cast<std::uint8_t>(be(relocation, 13, 1));
                    value.file_offset = section.relocation_file_offset + at;
                    require(value.symbol_index < symbol_count,
                            "XCOFF64 relocation symbol index exceeds symbol table");
                    const auto symbol = std::lower_bound(result.symbols.begin(), result.symbols.end(), value.symbol_index,
                        [](const auto &candidate, auto slot) { return candidate.index < slot; });
                    require(symbol != result.symbols.end() && symbol->index == value.symbol_index,
                            "XCOFF64 relocation refers to an auxiliary symbol slot");
                    require(value.virtual_address >= section.physical_address &&
                                value.virtual_address - section.physical_address < section.size,
                            "XCOFF64 relocation address is outside its section");
                    require(!previous_address || value.virtual_address >= *previous_address,
                            "XCOFF64 section relocations are not in ascending address order");
                    previous_address = value.virtual_address;
                    section.relocations.push_back(value);
                }
            }
        }
        result.sections.push_back(std::move(section));
    }
    return result;
} catch (const Failure &failure) {
    return failure.error;
} catch (const std::bad_alloc &) {
    return Error{ErrorCode::resource_limit, "Cannot allocate bounded XCOFF64 object metadata"};
} catch (const std::length_error &) {
    return Error{ErrorCode::resource_limit, "XCOFF64 object metadata exceeds host container limits"};
}

std::string_view xcoff64_relocation_type_name(std::uint8_t type) {
    switch (type) {
    case 0x00: return "R_POS";
    case 0x01: return "R_NEG";
    case 0x02: return "R_REL";
    case 0x03: return "R_TOC";
    case 0x05: return "R_GL";
    case 0x06: return "R_TCL";
    case 0x08: return "R_BA";
    case 0x0a: return "R_BR";
    case 0x0c: return "R_RL";
    case 0x0d: return "R_RLA";
    case 0x0f: return "R_REF";
    case 0x12: return "R_TRL";
    case 0x13: return "R_TRLA";
    case 0x18: return "R_RBA";
    case 0x1a: return "R_RBR";
    case 0x20: return "R_TLS";
    case 0x21: return "R_TLS_IE";
    case 0x22: return "R_TLS_LD";
    case 0x23: return "R_TLS_LE";
    case 0x24: return "R_TLSM";
    case 0x25: return "R_TLSML";
    case 0x30: return "R_TOCU";
    case 0x31: return "R_TOCL";
    default: return "unknown";
    }
}

} // namespace hexlab
