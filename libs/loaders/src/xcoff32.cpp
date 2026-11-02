#include "hexlab/loaders/xcoff32.hpp"
#include <algorithm>
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
    require(limits.max_sections && limits.max_symbols && limits.max_relocations && limits.max_metadata_bytes && limits.max_name_bytes,
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
    std::uint64_t relocation_total = 0;
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
            require(section.relocation_file_offset != 0, "XCOFF32 relocation count has no file offset");
            require(section.relocation_count <= limits.max_relocations - relocation_total,
                    "XCOFF32 relocation count exceeds configured limit", ErrorCode::resource_limit);
            relocation_total += section.relocation_count;
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

    for (auto &section : result.sections) {
        if (!section.relocation_count) continue;
        canceled(stop);
        const auto bytes_count = std::uint64_t{section.relocation_count} * 10;
        const auto rows = read(storage, section.relocation_file_offset, bytes_count, budget, limits, stop);
        charge(std::uint64_t{section.relocation_count} * sizeof(Xcoff32Relocation), budget, limits);
        section.relocations.reserve(section.relocation_count);
        std::uint32_t previous_address = 0;
        bool have_previous = false;
        for (std::uint32_t i = 0; i < section.relocation_count; ++i) {
            canceled(stop);
            const auto at = std::size_t{i} * 10;
            const auto row = std::span<const std::byte>(rows).subspan(at, 10);
            Xcoff32Relocation relocation;
            relocation.virtual_address = be(row, 0, 4);
            relocation.symbol_index = be(row, 4, 4);
            relocation.size_info = static_cast<std::uint8_t>(be(row, 8, 1));
            relocation.type = static_cast<std::uint8_t>(be(row, 9, 1));
            relocation.file_offset = std::uint64_t{section.relocation_file_offset} + at;
            require(relocation.symbol_index < result.symbol_count,
                    "XCOFF32 relocation symbol index exceeds symbol table");
            const auto symbol = std::lower_bound(result.symbols.begin(), result.symbols.end(), relocation.symbol_index,
                [](const auto &candidate, auto slot) { return candidate.index < slot; });
            require(symbol != result.symbols.end() && symbol->index == relocation.symbol_index,
                    "XCOFF32 relocation refers to an auxiliary symbol slot");
            require(relocation.virtual_address >= section.physical_address &&
                        std::uint64_t{relocation.virtual_address} - section.physical_address < section.size,
                    "XCOFF32 relocation address is outside its section");
            require(!have_previous || relocation.virtual_address >= previous_address,
                    "XCOFF32 section relocations are not in ascending address order");
            previous_address = relocation.virtual_address;
            have_previous = true;
            section.relocations.push_back(relocation);
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

Result<LoadedImage> load_xcoff32_executable(std::shared_ptr<const ByteStorage> storage,
    std::stop_token stop, Xcoff32ObjectLimits limits) try {
    require(bool(storage), "XCOFF32 executable loading requires storage", ErrorCode::invalid_argument);
    require(limits.max_sections && limits.max_metadata_bytes && limits.max_name_bytes,
            "XCOFF32 executable limits must be positive", ErrorCode::invalid_argument);
    std::uint64_t budget = 0;
    const auto header = read(*storage, 0, 20, budget, limits, stop);
    require(be(header, 0, 2) == 0x01df, "Invalid XCOFF32 magic");
    const auto section_count = be(header, 2, 2);
    const auto optional_size = be(header, 16, 2);
    const auto flags = static_cast<std::uint16_t>(be(header, 18, 2));
    require((flags & 0x0002u) != 0,
            "XCOFF32 linked-image loader requires F_EXEC", ErrorCode::unsupported);
    // AIX defines the executable auxiliary header as 72 bytes. Read the
    // declared size, but reject nonstandard layouts before interpreting entry.
    require(optional_size == 72,
            "Unsupported XCOFF32 executable auxiliary-header size", ErrorCode::unsupported);
    const auto auxiliary = read(*storage, 20, optional_size, budget, limits, stop);
    const auto entry_value = be(auxiliary, 20, 4);
    require(section_count && section_count <= limits.max_sections,
            "XCOFF32 executable section count exceeds configured limit", ErrorCode::resource_limit);
    const std::uint64_t section_headers_offset = 20 + optional_size;
    const std::uint64_t section_bytes = std::uint64_t{section_count} * 40;
    require(contains(storage->size(), section_headers_offset, section_bytes),
            "XCOFF32 executable section headers exceed file extent");
    auto section_rows = read(*storage, section_headers_offset, section_bytes, budget, limits, stop);
    const auto section_end = section_headers_offset + section_bytes;
    ImageLayout layout{{{0}, 32, 1, ByteOrder::big}, Architecture::powerpc,
                       ExecutionMode::ppc32, {}, {}};
    LoadedImage loaded;
    loaded.metadata_complete = true;
    loaded.metadata.format = "XCOFF32 executable";
    loaded.metadata.machine = 1; // IBM POWER/PowerPC
    loaded.metadata.header_size = static_cast<std::uint32_t>(section_end);
    bool loader_section_seen = false;
    bool other_section_seen = false;
    bool has_text = false;
    std::uint64_t low = UINT64_MAX, high = 0;
    for (std::uint32_t i = 0; i < section_count; ++i) {
        canceled(stop);
        const auto row = std::span<const std::byte>(section_rows).subspan(std::size_t{i} * 40, 40);
        std::size_t name_size = 0;
        while (name_size < 8 && row[name_size] != std::byte{0}) ++name_size;
        require(name_size <= limits.max_name_bytes,
                "XCOFF32 executable section name exceeds limit", ErrorCode::resource_limit);
        const std::string name(reinterpret_cast<const char *>(row.data()), name_size);
        const auto address = be(row, 12, 4);
        const auto size = be(row, 16, 4);
        const auto raw_offset = be(row, 20, 4);
        const auto section_flags = be(row, 36, 4);
        const auto type = section_flags & 0xffffu;
        require(section_flags != 0xffffffffu && type != 0x8000,
                "Deleted or overflow XCOFF32 executable section is unsupported", ErrorCode::unsupported);
        const bool bss = type == 0x80 || type == 0x800;
        const bool mapped = type == 0x20 || type == 0x40 || bss || type == 0x400;
        if (size) {
            require(std::uint64_t{address} + size <= (UINT64_C(1) << 32),
                    "XCOFF32 section virtual extent wraps the 32-bit address space");
            if (!bss) {
                require(raw_offset != 0 && raw_offset >= section_end &&
                            contains(storage->size(), raw_offset, size),
                        "XCOFF32 initialized section data exceeds file extent or overlaps headers");
            }
        }
        if (type == 0x1000) loader_section_seen = true;
        else if (!mapped && size && type != 0x10 && type != 0x200)
            other_section_seen = true;
        if (!mapped || !size) continue;
        const bool executable = type == 0x20;
        const bool writable = type == 0x40 || bss || type == 0x400;
        layout.segments.push_back({name.empty() ? "section" + std::to_string(i + 1) : name,
            {{0}, address}, size, {bss ? 0 : raw_offset}, bss ? 0 : size,
            true, writable, executable});
        loaded.metadata.sections.push_back({name, {address}, size,
            {bss ? 0 : raw_offset}, bss ? 0 : size, section_flags});
        low = std::min<std::uint64_t>(low, address);
        high = std::max<std::uint64_t>(high, std::uint64_t{address} + size);
        has_text |= executable;
    }
    require(has_text, "XCOFF32 executable has no initialized text section", ErrorCode::unsupported);
    auto image = Image::create(storage, layout);
    if (!image) throw Failure{image.error()};
    const Address entry{{0}, entry_value};
    const auto *entry_segment = image.value()->segment_at(entry);
    require(entry_segment && entry_segment->executable && image.value()->to_file_offset(entry),
            "XCOFF32 executable entry is not in initialized text");
    layout.entries.push_back(entry);
    image = Image::create(storage, std::move(layout));
    if (!image) throw Failure{image.error()};
    loaded.image = std::move(image.value());
    loaded.metadata.preferred_base = low;
    loaded.metadata.image_size = high - low;
    if (loader_section_seen) {
        loaded.metadata_complete = false;
        loaded.diagnostics.push_back({DiagnosticSeverity::warning,
            "XCOFF32 loader section is not interpreted; imports and loader relocations remain unresolved", {}});
    }
    if (other_section_seen) {
        loaded.metadata_complete = false;
        loaded.diagnostics.push_back({DiagnosticSeverity::warning,
            "One or more XCOFF32 section types are not mapped by this loader", {}});
    }
    // The image contains file-backed data and zero-fill mappings only. Runtime
    // AIX loader relocation, import binding, and TOC setup remain out of scope.
    loaded.metadata_reads_complete = false;
    canceled(stop);
    return loaded;
} catch (const Failure &failure) {
    return failure.error;
} catch (const std::bad_alloc &) {
    return Error{ErrorCode::resource_limit, "Cannot allocate bounded XCOFF32 executable metadata"};
} catch (const std::length_error &) {
    return Error{ErrorCode::resource_limit, "XCOFF32 executable metadata exceeds host container limits"};
}

std::string_view xcoff32_relocation_type_name(std::uint8_t type) {
    switch (type) {
    case 0x00: return "R_POS"; case 0x01: return "R_NEG"; case 0x02: return "R_REL";
    case 0x03: return "R_TOC"; case 0x05: return "R_GL"; case 0x06: return "R_TCL";
    case 0x08: return "R_BA"; case 0x0a: return "R_BR"; case 0x0c: return "R_RL";
    case 0x0d: return "R_RLA"; case 0x0f: return "R_REF"; case 0x12: return "R_TRL";
    case 0x13: return "R_TRLA"; case 0x18: return "R_RBA"; case 0x1a: return "R_RBR";
    case 0x20: return "R_TLS"; case 0x21: return "R_TLS_IE"; case 0x22: return "R_TLS_LD";
    case 0x23: return "R_TLS_LE"; case 0x24: return "R_TLSM"; case 0x25: return "R_TLSML";
    case 0x30: return "R_TOCU"; case 0x31: return "R_TOCL";
    default: return "unknown";
    }
}

} // namespace hexlab
