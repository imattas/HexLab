#include "hexlab/loaders/xcoff32.hpp"
#include <algorithm>
#include <cstring>
#include <limits>
#include <new>
#include <stdexcept>

namespace hexlab {
namespace {
class OwnedBytes final : public ByteStorage, public std::enable_shared_from_this<OwnedBytes> {
public:
    explicit OwnedBytes(std::vector<std::byte> bytes) : bytes_(std::move(bytes)) {}
    std::uint64_t size() const noexcept override { return bytes_.size(); }
    Result<ByteView> read_at(FileOffset offset, std::size_t count) const override {
        if (offset.value > bytes_.size() || count > bytes_.size() - static_cast<std::size_t>(offset.value))
            return Error{ErrorCode::io, "Synthetic XCOFF32 read exceeds mapped bytes"};
        auto owner = std::static_pointer_cast<const void>(shared_from_this());
        return ByteView{std::move(owner), std::span<const std::byte>(bytes_).subspan(
            static_cast<std::size_t>(offset.value), count)};
    }
    static std::shared_ptr<OwnedBytes> create(std::vector<std::byte> bytes) {
        return std::shared_ptr<OwnedBytes>(new OwnedBytes(std::move(bytes)));
    }
private:
    std::vector<std::byte> bytes_;
};
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
    struct RelocationOverflow {
        std::uint32_t section = 0, target = 0, count = 0;
    };
    std::vector<RelocationOverflow> relocation_overflows;
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
        const auto encoded_relocation_count = be(row, 32, 2);
        section.relocation_count = encoded_relocation_count;
        section.line_number_count = static_cast<std::uint16_t>(be(row, 34, 2));
        section.flags = be(row, 36, 4);
        const auto type = section.flags & 0xffffu;
        require(section.flags != 0xffffffffu,
                "XCOFF32 deleted section headers are unsupported", ErrorCode::unsupported);
        if (type == 0x8000) {
            require(section.flags == 0x8000u,
                    "XCOFF32 overflow section has unsupported subtype flags", ErrorCode::unsupported);
            const auto target_section = encoded_relocation_count;
            const auto target_line_section = section.line_number_count;
            const auto relocation_count = section.physical_address;
            const auto line_count = section.virtual_address;
            require(section.size == 0 && section.data_file_offset == 0,
                    "XCOFF32 overflow section has nonzero size or data pointer");
            require(target_section != 0 && target_section == target_line_section &&
                        target_section <= section_count,
                    "XCOFF32 overflow section has inconsistent target section numbers");
            require(relocation_count > 0xfffeu && relocation_count <= limits.max_relocations,
                    "XCOFF32 overflow relocation count is invalid", ErrorCode::resource_limit);
            require(line_count == 0,
                    "XCOFF32 line-number overflow is unsupported", ErrorCode::unsupported);
            require(section.relocation_file_offset != 0,
                    "XCOFF32 overflow section has no relocation-table pointer");
            relocation_overflows.push_back({index + 1, target_section, relocation_count});
            section.relocation_count = 0;
            section.line_number_count = 0;
            result.sections.push_back(std::move(section));
            continue;
        }
        require((section.relocation_count == 0xffffu) == (section.line_number_count == 0xffffu),
                "XCOFF32 relocation and line-number overflow markers are not paired");
        // BSS/TBSS have no file-backed data; names do not determine section type.
        if (type != 0x80 && type != 0x800 && section.data_file_offset && section.size)
            require(section.data_file_offset >= header_end &&
                        contains(storage.size(), section.data_file_offset, section.size),
                    "XCOFF32 section data exceeds file extent or overlaps headers");
        if (section.relocation_count && section.relocation_count != 0xffffu) {
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
        if (section.line_number_count && section.line_number_count != 0xffffu)
            require(section.line_number_file_offset >= header_end &&
                        contains(storage.size(), section.line_number_file_offset,
                                 std::uint64_t{section.line_number_count} * 6),
                    "XCOFF32 line-number table exceeds file extent or overlaps headers");
        result.sections.push_back(std::move(section));
    }

    // XCOFF32 overflow headers identify the primary section by its one-based
    // section number; the primary header contains no backlink. Search all
    // headers before reading relocation arrays so ordering is irrelevant.
    for (const auto &overflow : relocation_overflows) {
        canceled(stop);
        auto &target = result.sections[overflow.target - 1];
        require((target.flags & 0xffffu) != 0x8000u && target.relocation_count == 0xffffu &&
                    target.line_number_count == 0xffffu,
                "XCOFF32 overflow header does not match a primary overflow marker");
        const auto &overflow_section = result.sections[overflow.section - 1];
        require(target.relocation_file_offset == overflow_section.relocation_file_offset,
                "XCOFF32 overflow and primary relocation offsets disagree");
        require(target.line_number_file_offset == overflow_section.line_number_file_offset,
                "XCOFF32 overflow and primary line-number offsets disagree");
        require(target.relocation_count == 0xffffu,
                "Duplicate XCOFF32 relocation overflow header");
        target.relocation_count = overflow.count;
        require(overflow.count <= limits.max_relocations - relocation_total,
                "XCOFF32 aggregate relocation count exceeds configured limit", ErrorCode::resource_limit);
        relocation_total += overflow.count;
        require(target.relocation_file_offset >= header_end &&
                    contains(storage.size(), target.relocation_file_offset,
                             std::uint64_t{overflow.count} * 10),
                "XCOFF32 overflow relocation table exceeds file extent or overlaps headers");
        target.line_number_count = 0;
    }
    for (const auto &section : result.sections) {
        if ((section.flags & 0xffffu) == 0x8000u) continue;
        require(section.relocation_count != 0xffffu && section.line_number_count != 0xffffu,
                "XCOFF32 overflow marker has no matching overflow section", ErrorCode::unsupported);
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

Result<LoadedImage> load_xcoff32_relocatable(std::shared_ptr<const ByteStorage> storage,
    std::stop_token stop, Xcoff32ObjectLimits limits) try {
    require(bool(storage), "XCOFF32 object loading requires storage", ErrorCode::invalid_argument);
    auto inspected = inspect_xcoff32_object(*storage, stop, limits);
    if (!inspected) throw Failure{inspected.error()};
    const auto &object = inspected.value();
    struct Mapping { std::uint32_t address = 0; bool mapped = false; };
    std::vector<Mapping> mappings(object.sections.size());
    std::uint64_t total = 0x10000;
    for (const auto &section : object.sections) {
        canceled(stop);
        const auto type = section.flags & 0xffffu;
        const bool mapped = type == 0x20 || type == 0x40 || type == 0x80 ||
                            type == 0x400 || type == 0x800;
        if (type == 0x8000u) continue; // Overflow headers describe another section's tables.
        if (!mapped || !section.size) continue;
        total = (total + 0xfff) & ~UINT64_C(0xfff);
        require(total <= UINT32_MAX && section.size <= (UINT64_C(1) << 32) - total,
                "XCOFF32 synthetic section layout exceeds 32-bit address space", ErrorCode::resource_limit);
        mappings[section.index - 1] = {static_cast<std::uint32_t>(total), true};
        total += section.size;
    }
    require(total <= limits.max_metadata_bytes && total <= std::numeric_limits<std::size_t>::max(),
            "XCOFF32 synthetic image exceeds configured byte limit", ErrorCode::resource_limit);
    std::vector<std::byte> bytes(static_cast<std::size_t>(total));
    ImageLayout layout{{{0}, 32, 1, ByteOrder::big}, Architecture::powerpc,
                        ExecutionMode::ppc32, {}, {}};
    LoadedImage loaded;
    loaded.metadata.format = "XCOFF32 relocatable object";
    loaded.metadata.machine = 1;
    loaded.metadata.preferred_base = 0x10000;
    loaded.metadata.image_size = total - 0x10000;
    loaded.metadata_complete = true;
    std::uint64_t budget = total;
    for (const auto &section : object.sections) {
        canceled(stop);
        const auto type = section.flags & 0xffffu;
        const auto mapping = mappings[section.index - 1];
        if (!mapping.mapped) {
            if (section.size || section.relocation_count) {
                loaded.metadata_complete = false;
                loaded.diagnostics.push_back({DiagnosticSeverity::warning,
                    "XCOFF32 section type " + std::to_string(type) + " is inventoried but not mapped", {}});
            }
            continue;
        }
        const bool bss = type == 0x80 || type == 0x800;
        if (!bss && section.size) {
            auto raw = read(*storage, section.data_file_offset, section.size, budget, limits, stop);
            std::copy(raw.begin(), raw.end(), bytes.begin() + mapping.address);
        }
        const bool executable = type == 0x20;
        const bool writable = type != 0x20;
        layout.segments.push_back({section.name.empty() ? "section" + std::to_string(section.index) : section.name,
            {{0}, mapping.address}, section.size, {mapping.address}, section.size,
            true, writable, executable});
        loaded.metadata.sections.push_back({section.name, {mapping.address}, section.size,
            {mapping.address}, section.size, section.flags});
    }
    auto symbol_for_slot = [&](std::uint32_t slot) -> const Xcoff32Object::Symbol * {
        auto it = std::lower_bound(object.symbols.begin(), object.symbols.end(), slot,
            [](const auto &candidate, auto index) { return candidate.index < index; });
        return it != object.symbols.end() && it->index == slot ? &*it : nullptr;
    };
    auto symbol_address = [&](const Xcoff32Object::Symbol &symbol) -> std::optional<std::uint64_t> {
        if (symbol.section_number == -1) return symbol.value;
        if (symbol.section_number <= 0 || static_cast<std::size_t>(symbol.section_number) > object.sections.size())
            return {};
        const auto &section = object.sections[static_cast<std::size_t>(symbol.section_number - 1)];
        const auto mapping = mappings[section.index - 1];
        if (!mapping.mapped || symbol.value < section.physical_address ||
            std::uint64_t{symbol.value} - section.physical_address > section.size) return {};
        return std::uint64_t{mapping.address} + symbol.value - section.physical_address;
    };
    for (const auto &symbol : object.symbols) {
        if (symbol.name.empty()) continue;
        const auto address = symbol_address(symbol);
        if (!address || symbol.storage_class == 3) continue;
        loaded.metadata.exports.push_back({symbol.index, symbol.name, Address{{0}, *address}, {}});
    }
    for (const auto &section : object.sections) {
        const auto mapping = mappings[section.index - 1];
        if (!mapping.mapped) continue;
        for (const auto &reloc : section.relocations) {
            canceled(stop);
            const auto type = reloc.type;
            if (type == 0x0f) continue; // R_REF records a reference without patching bytes.
            if (type != 0x00 && type != 0x01 && type != 0x02) {
                loaded.metadata_complete = false;
                loaded.diagnostics.push_back({DiagnosticSeverity::warning,
                    "XCOFF32 " + std::string(xcoff32_relocation_type_name(type)) +
                    " relocation is retained but not applied", Address{{0},
                    std::uint64_t{mapping.address} + reloc.virtual_address - section.physical_address}});
                continue;
            }
            const auto width_bits = (reloc.size_info & 0x3fu) + 1u;
            if ((width_bits != 8 && width_bits != 16 && width_bits != 32) ||
                (reloc.size_info & 0x40u) != 0) {
                loaded.metadata_complete = false;
                loaded.diagnostics.push_back({DiagnosticSeverity::warning,
                    "XCOFF32 relocation uses an unsupported bit-field or instruction encoding",
                    Address{{0}, std::uint64_t{mapping.address} + reloc.virtual_address - section.physical_address}});
                continue;
            }
            const auto *symbol = symbol_for_slot(reloc.symbol_index);
            const auto resolved = symbol ? symbol_address(*symbol) : std::optional<std::uint64_t>{};
            if (!resolved) {
                loaded.metadata_complete = false;
                loaded.diagnostics.push_back({DiagnosticSeverity::warning,
                    "XCOFF32 relocation target is undefined, common, or outside mapped sections",
                    Address{{0}, std::uint64_t{mapping.address} + reloc.virtual_address - section.physical_address}});
                continue;
            }
            const std::uint64_t place = std::uint64_t{mapping.address} + reloc.virtual_address - section.physical_address;
            const auto width = width_bits / 8;
            const auto within_section = std::uint64_t{reloc.virtual_address} - section.physical_address;
            if (width > section.size - within_section) {
                loaded.metadata_complete = false;
                loaded.diagnostics.push_back({DiagnosticSeverity::warning,
                    "XCOFF32 relocation field crosses the end of its section", Address{{0}, place}});
                continue;
            }
            const auto old = be(bytes, static_cast<std::size_t>(place), width);
            const std::int64_t addend = (reloc.size_info & 0x80u) &&
                (old & (UINT32_C(1) << (width_bits - 1)))
                ? static_cast<std::int64_t>(old) - (INT64_C(1) << width_bits) : old;
            const std::int64_t value = type == 0x00 ? addend + static_cast<std::int64_t>(*resolved) :
                type == 0x01 ? addend - static_cast<std::int64_t>(*resolved) :
                addend + static_cast<std::int64_t>(*resolved) - static_cast<std::int64_t>(place);
            const std::int64_t minimum = (reloc.size_info & 0x80u) ? -(INT64_C(1) << (width_bits - 1)) : 0;
            const std::int64_t maximum = (reloc.size_info & 0x80u)
                ? (INT64_C(1) << (width_bits - 1)) - 1 : (INT64_C(1) << width_bits) - 1;
            if (value < minimum || value > maximum) {
                loaded.metadata_complete = false;
                loaded.diagnostics.push_back({DiagnosticSeverity::warning,
                    "XCOFF32 relocation result overflows its encoded field",
                    Address{{0}, place}});
                continue;
            }
            for (std::size_t i = 0; i < width; ++i)
                bytes[static_cast<std::size_t>(place) + width - i - 1] =
                    static_cast<std::byte>((static_cast<std::uint64_t>(value) >> (i * 8)) & 0xff);
        }
    }
    auto backing = OwnedBytes::create(std::move(bytes));
    auto image = Image::create(backing, std::move(layout));
    if (!image) throw Failure{image.error()};
    loaded.image = std::move(image.value());
    loaded.metadata_reads_complete = false;
    return loaded;
} catch (const Failure &failure) {
    return failure.error;
} catch (const std::bad_alloc &) {
    return Error{ErrorCode::resource_limit, "Cannot allocate bounded synthetic XCOFF32 image"};
} catch (const std::length_error &) {
    return Error{ErrorCode::resource_limit, "Synthetic XCOFF32 image exceeds host container limits"};
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
    const auto entry_value = be(auxiliary, 16, 4);
    const auto toc_value = be(auxiliary, 28, 4);
    const auto toc_section_number = be(auxiliary, 38, 2);
    const auto entry_section_number = be(auxiliary, 32, 2);
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
    struct MappedSection { std::uint32_t address, size; std::uint32_t flags; };
    std::vector<MappedSection> section_map;
    charge(std::uint64_t{section_count} * sizeof(MappedSection), budget, limits);
    section_map.reserve(section_count);
    std::uint32_t loader_file_offset = 0, loader_size = 0;
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
        if (type == 0x1000) {
            require(!loader_section_seen, "Multiple XCOFF32 loader sections are unsupported", ErrorCode::unsupported);
            loader_section_seen = true;
            loader_file_offset = raw_offset;
            loader_size = size;
        }
        else if (!mapped && size && type != 0x10 && type != 0x200)
            other_section_seen = true;
        section_map.push_back({address, size, section_flags});
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
    if (entry_section_number) {
        require(entry_section_number <= section_count &&
                    (section_map[entry_section_number - 1].flags & 0xffffu) == 0x20 &&
                    section_map[entry_section_number - 1].address <= entry_value &&
                    std::uint64_t{entry_value} - section_map[entry_section_number - 1].address <
                        section_map[entry_section_number - 1].size,
                "XCOFF32 auxiliary-header entry section does not contain the entry point");
    }
    layout.entries.push_back(entry);
    image = Image::create(storage, std::move(layout));
    if (!image) throw Failure{image.error()};
    loaded.image = std::move(image.value());
    loaded.metadata.preferred_base = low;
    loaded.metadata.image_size = high - low;
    if (toc_value || toc_section_number) {
        const bool toc_valid = toc_section_number && toc_section_number <= section_count &&
            ((section_map[toc_section_number - 1].flags & 0xffffu) == 0x20 ||
             (section_map[toc_section_number - 1].flags & 0xffffu) == 0x40 ||
             (section_map[toc_section_number - 1].flags & 0xffffu) == 0x80 ||
             (section_map[toc_section_number - 1].flags & 0xffffu) == 0x400 ||
             (section_map[toc_section_number - 1].flags & 0xffffu) == 0x800) &&
            section_map[toc_section_number - 1].address <= toc_value &&
            std::uint64_t{toc_value} - section_map[toc_section_number - 1].address <
                section_map[toc_section_number - 1].size;
        const auto message = toc_valid
            ? "AIX TOC anchor at address " + std::to_string(toc_value) + " is in section " +
                std::to_string(toc_section_number) + "; runtime r2 setup is not performed"
            : "XCOFF32 auxiliary-header TOC anchor/section is inconsistent";
        charge(sizeof(Diagnostic) + message.size(), budget, limits);
        loaded.diagnostics.push_back({toc_valid ? DiagnosticSeverity::info : DiagnosticSeverity::warning,
                                      message, {}});
        if (!toc_valid) loaded.metadata_complete = false;
    }
    if (loader_section_seen) {
        // AIX loader.h defines a 32-byte header, 24-byte symbol rows, and
        // 12-byte relocation rows. LLVM's LoaderSectionHeader32 and related
        // structs use the same layout; see the references in the XCOFF32 doc.
        constexpr std::uint64_t loader_header_size = 32;
        constexpr std::uint64_t loader_symbol_size = 24;
        constexpr std::uint64_t loader_relocation_size = 12;
        require(loader_size >= loader_header_size, "Truncated XCOFF32 loader section");
        auto loader_data = read(*storage, loader_file_offset, loader_size, budget, limits, stop);
        const auto loader = std::span<const std::byte>(loader_data);
        const auto version = be(loader, 0, 4);
        const auto symbol_count = be(loader, 4, 4);
        const auto relocation_count = be(loader, 8, 4);
        const auto import_string_size = be(loader, 12, 4);
        const auto import_count = be(loader, 16, 4);
        const auto import_offset = be(loader, 20, 4);
        const auto string_size = be(loader, 24, 4);
        const auto string_offset = be(loader, 28, 4);
        require(version == 1, "Unsupported XCOFF32 loader-section version", ErrorCode::unsupported);
        require(symbol_count <= limits.max_symbols && import_count <= limits.max_symbols &&
                    relocation_count <= limits.max_relocations,
                "XCOFF32 loader table count exceeds configured limits", ErrorCode::resource_limit);
        const std::uint64_t symbols_offset = loader_header_size;
        const std::uint64_t symbols_size = std::uint64_t{symbol_count} * loader_symbol_size;
        const std::uint64_t relocations_offset = symbols_offset + symbols_size;
        const std::uint64_t relocations_size = std::uint64_t{relocation_count} * loader_relocation_size;
        require(contains(loader.size(), symbols_offset, symbols_size) &&
                    contains(loader.size(), relocations_offset, relocations_size),
                "XCOFF32 loader symbol or relocation table exceeds section extent");
        require((import_count == 0 && import_string_size == 0) ||
                    (import_count != 0 && import_string_size != 0 &&
                     contains(loader.size(), import_offset, import_string_size)),
                "XCOFF32 import-file ID table exceeds loader section");
        require((string_size == 0 && string_offset == 0) ||
                    (string_size != 0 && contains(loader.size(), string_offset, string_size)),
                "XCOFF32 loader string table exceeds section extent");
        const auto disjoint = [](std::uint64_t a, std::uint64_t as,
                                 std::uint64_t b, std::uint64_t bs) {
            return as == 0 || bs == 0 || a + as <= b || b + bs <= a;
        };
        require(disjoint(symbols_offset, symbols_size, import_offset, import_string_size) &&
                    disjoint(symbols_offset, symbols_size, string_offset, string_size) &&
                    disjoint(relocations_offset, relocations_size, import_offset, import_string_size) &&
                    disjoint(relocations_offset, relocations_size, string_offset, string_size) &&
                    disjoint(import_offset, import_string_size, string_offset, string_size),
                "XCOFF32 loader tables overlap");
        require(disjoint(0, loader_header_size, import_offset, import_string_size) &&
                    disjoint(0, loader_header_size, string_offset, string_size),
                "XCOFF32 loader string tables overlap the loader header");

        struct ImportFileId { std::string path, base, member; };
        std::vector<ImportFileId> import_ids;
        charge(std::uint64_t{import_count} * sizeof(ImportFileId), budget, limits);
        import_ids.reserve(import_count);
        std::uint64_t import_cursor = import_offset;
        const std::uint64_t import_end = import_cursor + import_string_size;
        const auto loader_string = [&](std::uint64_t &cursor, std::uint64_t end,
                                       const char *description) -> std::string {
            require(cursor < end, description);
            const auto begin = cursor;
            while (cursor < end && loader[static_cast<std::size_t>(cursor)] != std::byte{0} &&
                   cursor - begin <= limits.max_name_bytes) ++cursor;
            require(cursor < end && cursor - begin <= limits.max_name_bytes, description,
                    cursor - begin > limits.max_name_bytes ? ErrorCode::resource_limit : ErrorCode::malformed);
            const auto length = static_cast<std::size_t>(cursor - begin);
            charge(length, budget, limits);
            std::string value(reinterpret_cast<const char *>(loader.data() + begin), length);
            ++cursor;
            return value;
        };
        for (std::uint32_t i = 0; i < import_count; ++i) {
            canceled(stop);
            ImportFileId id;
            id.path = loader_string(import_cursor, import_end, "Truncated XCOFF32 import path");
            id.base = loader_string(import_cursor, import_end, "Truncated XCOFF32 import base name");
            id.member = loader_string(import_cursor, import_end, "Truncated XCOFF32 import member name");
            import_ids.push_back(std::move(id));
        }
        require(import_cursor == import_end, "XCOFF32 import-file ID count does not consume its declared table");

        const auto symbol_name = [&](std::span<const std::byte> row) -> std::string {
            const auto zeroes = be(row, 0, 4);
            std::uint64_t begin = 0, end = 8;
            std::span<const std::byte> names = row;
            if (zeroes == 0) {
                const auto offset = be(row, 4, 4);
                require(offset < string_size, "XCOFF32 loader symbol name offset is outside string table");
                begin = offset;
                end = string_size;
                names = loader.subspan(string_offset, string_size);
            }
            auto terminator = begin;
            while (terminator < end && names[static_cast<std::size_t>(terminator)] != std::byte{0} &&
                   terminator - begin <= limits.max_name_bytes) ++terminator;
            require(terminator - begin <= limits.max_name_bytes,
                    "XCOFF32 loader symbol name exceeds limit", ErrorCode::resource_limit);
            require(zeroes != 0 || terminator < end, "Unterminated XCOFF32 loader symbol name");
            const auto length = static_cast<std::size_t>(terminator - begin);
            charge(length, budget, limits);
            return {reinterpret_cast<const char *>(names.data() + begin), length};
        };
        constexpr std::uint8_t loader_import = 0x40, loader_export = 0x10;
        constexpr std::int32_t implicit_text = 0, implicit_data = 1, implicit_bss = 2,
                                implicit_tdata = -1, implicit_tbss = -2;
        std::uint64_t imports_seen = 0, exports_seen = 0;
        std::uint64_t import_diagnostics = 0, relocation_diagnostics = 0;
        std::vector<std::string> names;
        charge(std::uint64_t{symbol_count} * sizeof(std::string), budget, limits);
        names.reserve(symbol_count);
        for (std::uint32_t i = 0; i < symbol_count; ++i) {
            canceled(stop);
            const auto row = loader.subspan(static_cast<std::size_t>(symbols_offset +
                std::uint64_t{i} * loader_symbol_size), loader_symbol_size);
            auto name = symbol_name(row);
            const auto value = be(row, 8, 4);
            const auto raw_section = be(row, 12, 2);
            const auto section_number = static_cast<std::int32_t>(raw_section >= 0x8000 ?
                static_cast<std::int32_t>(raw_section) - 0x10000 : raw_section);
            const auto symbol_type = static_cast<std::uint8_t>(be(row, 14, 1));
            const auto import_id = be(row, 16, 4);
            const bool imported = (symbol_type & loader_import) != 0;
            require(!imported || (section_number == 0 && import_id < import_ids.size()),
                    "XCOFF32 imported loader symbol has invalid section or import-file ID");
            require(imported || (section_number >= -2 && section_number <= static_cast<std::int32_t>(section_count)),
                    "XCOFF32 loader symbol section number is invalid");
            if (imported) {
                ++imports_seen;
                const auto &id = import_ids[import_id];
                std::string library = id.path;
                if (!id.base.empty()) {
                    if (!library.empty()) library.push_back(':');
                    library += id.base;
                }
                if (!id.member.empty()) library += "(" + id.member + ")";
                if (import_diagnostics < 64) {
                    auto message = "Unresolved XCOFF32 import " + (name.empty() ? std::string("<unnamed>") : name) +
                        (library.empty() ? std::string{} : " from " + library);
                    charge(sizeof(Diagnostic) + message.size(), budget, limits);
                    loaded.diagnostics.push_back({DiagnosticSeverity::warning, std::move(message), {}});
                    ++import_diagnostics;
                }
                loaded.metadata_complete = false;
            }
            if ((symbol_type & loader_export) != 0 && !imported && section_number > 0) {
                const auto &section = section_map[static_cast<std::size_t>(section_number - 1)];
                require(value >= section.address && std::uint64_t{value} - section.address < section.size,
                        "XCOFF32 exported loader symbol lies outside its section");
                charge(sizeof(ExportSymbol) + name.size(), budget, limits);
                loaded.metadata.exports.push_back({i + 3,
                    name.empty() ? std::nullopt : std::optional<std::string>{name},
                    Address{{0}, value}, std::nullopt});
                ++exports_seen;
            }
            names.push_back(std::move(name));
        }
        if (imports_seen > import_diagnostics) {
            const auto message = std::to_string(imports_seen - import_diagnostics) +
                " additional XCOFF32 imports were not expanded in diagnostics";
            charge(sizeof(Diagnostic) + message.size(), budget, limits);
            loaded.diagnostics.push_back({DiagnosticSeverity::warning, message, {}});
        }
        for (std::uint32_t i = 0; i < relocation_count; ++i) {
            canceled(stop);
            const auto row = loader.subspan(static_cast<std::size_t>(relocations_offset +
                std::uint64_t{i} * loader_relocation_size), loader_relocation_size);
            const auto address = be(row, 0, 4);
            const auto symbol_raw = be(row, 4, 4);
            const auto symbol_index = static_cast<std::int32_t>(symbol_raw >= 0x80000000u ?
                static_cast<std::int64_t>(symbol_raw) - 0x100000000LL : symbol_raw);
            const auto relocation_type = be(row, 8, 2);
            const auto raw_target_section = be(row, 10, 2);
            const auto target_section = static_cast<std::int32_t>(raw_target_section >= 0x8000 ?
                static_cast<std::int32_t>(raw_target_section) - 0x10000 : raw_target_section);
            require(target_section > 0 && target_section <= static_cast<std::int32_t>(section_count),
                    "XCOFF32 loader relocation section number is invalid");
            const auto &target = section_map[static_cast<std::size_t>(target_section - 1)];
            const auto target_type = target.flags & 0xffffu;
            require(target_type == 0x20 || target_type == 0x40 || target_type == 0x80 ||
                        target_type == 0x400 || target_type == 0x800,
                    "XCOFF32 loader relocation targets a section this loader does not map",
                    ErrorCode::unsupported);
            require(address >= target.address && std::uint64_t{address} - target.address < target.size,
                    "XCOFF32 loader relocation address lies outside its target section");
            require(symbol_index < 0 ? symbol_index == implicit_tdata || symbol_index == implicit_tbss
                                     : symbol_index < 3 || static_cast<std::uint32_t>(symbol_index - 3) < symbol_count,
                    "XCOFF32 loader relocation symbol index is invalid");
            std::string symbol;
            if (symbol_index >= 3) symbol = names[static_cast<std::size_t>(symbol_index - 3)];
            else if (symbol_index == implicit_text) symbol = ".text";
            else if (symbol_index == implicit_data) symbol = ".data";
            else if (symbol_index == implicit_bss) symbol = ".bss";
            else if (symbol_index == implicit_tdata) symbol = ".tdata";
            else symbol = ".tbss";
            if (relocation_diagnostics < 128) {
                const auto message = "Unapplied XCOFF32 loader relocation " + std::to_string(i) +
                    " at address " + std::to_string(address) + " (type " + std::to_string(relocation_type) +
                    ", symbol " + (symbol.empty() ? std::string("<unnamed>") : symbol) + ")";
                charge(sizeof(Diagnostic) + message.size(), budget, limits);
                loaded.diagnostics.push_back({DiagnosticSeverity::warning, message, {}});
                ++relocation_diagnostics;
            }
            loaded.metadata_complete = false;
        }
        if (relocation_count > relocation_diagnostics) {
            const auto message = std::to_string(relocation_count - relocation_diagnostics) +
                " additional XCOFF32 loader relocations were not expanded in diagnostics";
            charge(sizeof(Diagnostic) + message.size(), budget, limits);
            loaded.diagnostics.push_back({DiagnosticSeverity::warning, message, {}});
        }
        if (imports_seen || relocation_count) loaded.metadata_complete = false;
        if (exports_seen) {
            const auto message = "Retained " + std::to_string(exports_seen) + " XCOFF32 exported loader symbols";
            charge(sizeof(Diagnostic) + message.size(), budget, limits);
            loaded.diagnostics.push_back({DiagnosticSeverity::info, message, {}});
        }
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

Result<LoadedImage> load_xcoff32_image(std::shared_ptr<const ByteStorage> storage,
    std::stop_token stop, Xcoff32ObjectLimits limits) {
    if (!storage) return Error{ErrorCode::invalid_argument, "XCOFF32 loading requires storage"};
    std::uint64_t budget = 0;
    try {
        const auto header = read(*storage, 0, 20, budget, limits, stop);
        require(be(header, 0, 2) == 0x01df, "Invalid XCOFF32 magic");
        return (be(header, 18, 2) & 0x0002u)
            ? load_xcoff32_executable(std::move(storage), stop, limits)
            : load_xcoff32_relocatable(std::move(storage), stop, limits);
    } catch (const Failure &failure) {
        return failure.error;
    }
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
