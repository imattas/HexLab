#include "references_internal.hpp"
#include <algorithm>
#include <bit>
#include <set>
#include <tuple>
namespace hexlab::reference_detail {
namespace {
struct Writer {
    std::vector<std::byte> bytes;
    void number(std::uint64_t value, std::size_t width) {
        require(width <= 8 && width <= reference_payload_limit - bytes.size(), "ELF provenance scalar exceeds payload");
        for (auto i = width; i; --i)
            bytes.push_back(std::byte(value >> (8 * (i - 1))));
    }
    void flag(bool value) { number(value, 1); }
    void address(Address value) {
        number(value.space.value, 4);
        number(value.offset, 8);
    }
    void optional_address(const std::optional<Address> &value) {
        flag(bool(value));
        if (value)
            address(*value);
    }
    void optional_index(const std::optional<std::uint32_t> &value) {
        flag(bool(value));
        if (value)
            number(*value, 4);
    }
    void source(const ElfTableSource &value) {
        optional_index(value.section);
        number(value.file_offset, 8);
        optional_address(value.address);
    }
    void text(const std::string &value) {
        require(value.size() <= 65536, "ELF reference name exceeds field budget");
        number(value.size(), 4);
        require(value.size() <= reference_payload_limit - bytes.size(), "ELF reference name exceeds payload budget");
        for (const auto c : value)
            bytes.push_back(std::byte(static_cast<unsigned char>(c)));
    }
    void relocation(const ElfRelocation &value) {
        source(value.source);
        number(value.index, 4);
        number(value.type, 4);
        number(value.symbol_index, 4);
        flag(value.symbol_index_validated);
        flag(bool(value.symbol_table));
        if (value.symbol_table)
            source(*value.symbol_table);
        optional_index(value.target_section);
        number(value.offset, 8);
        flag(value.explicit_addend);
        flag(bool(value.addend));
        if (value.addend)
            number(std::bit_cast<std::uint64_t>(*value.addend), 8);
        flag(bool(value.field_size));
        if (value.field_size)
            number(*value.field_size, 8);
        number(static_cast<unsigned>(value.kind), 1);
        optional_address(value.place);
        flag(bool(value.file_place));
        if (value.file_place)
            number(value.file_place->value, 8);
        number(value.record_file_offset, 8);
        number(value.record_stride, 8);
    }
    void symbol(const ElfSymbol &value) {
        optional_index(value.table);
        number(value.table_offset, 8);
        optional_address(value.table_address);
        number(value.index, 4);
        number(value.name_index, 4);
        number(value.section_index, 4);
        number(value.raw_section, 2);
        number(value.binding, 1);
        number(value.type, 1);
        number(value.other, 1);
        number(value.visibility, 1);
        number(value.value, 8);
        number(value.size, 8);
        text(value.name);
        number(static_cast<unsigned>(value.state), 1);
        optional_address(value.address);
    }
};
struct Reader {
    std::span<const std::byte> bytes;
    std::size_t cursor = 0;
    std::uint64_t number(std::size_t width) {
        require(width <= 8 && width <= bytes.size() - cursor, "Truncated ELF reference provenance");
        std::uint64_t value = 0;
        for (std::size_t i = 0; i < width; ++i)
            value = (value << 8) | std::to_integer<std::uint64_t>(bytes[cursor++]);
        return value;
    }
    bool flag() {
        const auto value = number(1);
        require(value <= 1, "Invalid ELF provenance flag");
        return value != 0;
    }
    Address address() {
        const auto space = static_cast<std::uint32_t>(number(4));
        return {{space}, number(8)};
    }
    std::optional<Address> optional_address() {
        if (!flag())
            return {};
        return address();
    }
    std::optional<std::uint32_t> optional_index() {
        if (!flag())
            return {};
        return static_cast<std::uint32_t>(number(4));
    }
    ElfTableSource source() {
        const auto section = optional_index();
        const auto file = number(8);
        return {section, file, optional_address()};
    }
    std::string text() {
        const auto size = number(4);
        require(size <= 65536 && size <= bytes.size() - cursor, "Invalid ELF provenance text extent");
        std::string value(reinterpret_cast<const char *>(bytes.data() + cursor), static_cast<std::size_t>(size));
        cursor += static_cast<std::size_t>(size);
        return value;
    }
    ElfRelocation relocation() {
        ElfRelocation value;
        value.source = source();
        value.index = static_cast<std::uint32_t>(number(4));
        value.type = static_cast<std::uint32_t>(number(4));
        value.symbol_index = static_cast<std::uint32_t>(number(4));
        value.symbol_index_validated = flag();
        if (flag())
            value.symbol_table = source();
        value.target_section = optional_index();
        value.offset = number(8);
        value.explicit_addend = flag();
        if (flag())
            value.addend = std::bit_cast<std::int64_t>(number(8));
        if (flag())
            value.field_size = number(8);
        value.kind = static_cast<ElfRelocationKind>(number(1));
        value.place = optional_address();
        if (flag())
            value.file_place = FileOffset{number(8)};
        value.record_file_offset = number(8);
        value.record_stride = number(8);
        return value;
    }
    ElfSymbol symbol() {
        ElfSymbol value;
        value.table = optional_index();
        value.table_offset = number(8);
        value.table_address = optional_address();
        value.index = static_cast<std::uint32_t>(number(4));
        value.name_index = static_cast<std::uint32_t>(number(4));
        value.section_index = static_cast<std::uint32_t>(number(4));
        value.raw_section = static_cast<std::uint16_t>(number(2));
        value.binding = static_cast<std::uint8_t>(number(1));
        value.type = static_cast<std::uint8_t>(number(1));
        value.other = static_cast<std::uint8_t>(number(1));
        value.visibility = static_cast<std::uint8_t>(number(1));
        value.value = number(8);
        value.size = number(8);
        value.name = text();
        value.state = static_cast<ElfSymbolState>(number(1));
        value.address = optional_address();
        return value;
    }
};
using TableKey = std::tuple<bool, std::optional<std::uint32_t>, std::uint64_t, bool, std::uint32_t, std::uint64_t>;
TableKey table_key(const std::optional<ElfTableSource> &source) {
    if (!source)
        return {false, {}, 0, false, 0, 0};
    return {true,
            source->section,
            source->file_offset,
            bool(source->address),
            source->address ? source->address->space.value : 0,
            source->address ? source->address->offset : 0};
}
using OriginKey =
    std::tuple<TableKey, std::uint32_t, std::uint64_t, bool, std::uint64_t, TableKey, std::optional<std::uint32_t>>;
OriginKey origin_key(const ElfRelocation &row) {
    const bool unused =
        row.symbol_index == 0 && (row.kind == ElfRelocationKind::base_relative || row.kind == ElfRelocationKind::ifunc);
    return {table_key(row.source), row.index,         row.record_file_offset,
            row.explicit_addend,   row.record_stride, table_key(unused ? std::nullopt : row.symbol_table),
            row.target_section};
}
void validate_source(const ElfTableSource &source) {
    require((source.section && *source.section != 0) || source.address,
            "ELF provenance lacks actual table source identity");
    require(!source.section || *source.section != 0, "ELF provenance cannot use null section as a table");
}
} // namespace
std::size_t elf_provenance_weight(const ElfReferenceProvenance &value) {
    std::size_t size = sizeof(value);
    const auto include = [&](std::size_t count) {
        if (count > reference_payload_limit - size)
            throw Failure{{ErrorCode::resource_limit, "ELF reference provenance exceeds allocation budget"}};
        size += count;
    };
    require(value.origins.size() <= 4096, "ELF reference origin count exceeds bound");
    include(value.origins.size() * sizeof(ElfReferenceOrigin));
    for (const auto &origin : value.origins)
        if (origin.symbol)
            include(origin.symbol->name.size());
    return size;
}
void validate_elf_provenance(const ElfReferenceProvenance &value) {
    (void)elf_provenance_weight(value);
    require(value.resolution != ElfResolutionReason::none &&
                static_cast<unsigned>(value.resolution) <= static_cast<unsigned>(ElfResolutionReason::overflow) &&
                !value.origins.empty(),
            "Invalid ELF reference resolution provenance");
    require(value.resolution != ElfResolutionReason::resolved || value.origins.size() == 1,
            "Resolved ELF reference has ambiguous origins");
    require(value.resolution != ElfResolutionReason::ambiguous || value.origins.size() > 1,
            "Ambiguous ELF reference lacks multiple origins");
    std::set<OriginKey> origins;
    for (const auto &origin : value.origins) {
        const auto &row = origin.relocation;
        validate_source(row.source);
        if (row.symbol_table)
            validate_source(*row.symbol_table);
        require(row.kind != ElfRelocationKind::none &&
                    static_cast<unsigned>(row.kind) <= static_cast<unsigned>(ElfRelocationKind::plt_absolute) &&
                    row.record_stride >= 8 && row.record_stride <= reference_payload_limit &&
                    row.record_stride <= UINT64_MAX - row.record_file_offset &&
                    (!row.explicit_addend || row.addend.has_value()),
                "Invalid original ELF relocation provenance");
        if (!row.source.address) {
            require(row.index <= (UINT64_MAX - row.source.file_offset) / row.record_stride &&
                        row.record_file_offset == row.source.file_offset + std::uint64_t{row.index} * row.record_stride,
                    "ELF section relocation record differs from source/index/stride");
        }
        if (row.place)
            require(row.place->offset == row.offset, "ELF reference place differs from original relocation offset");
        require(origins.insert(origin_key(row)).second, "Duplicate original ELF relocation provenance");
        if (row.field_size) {
            if (row.place)
                require(*row.field_size <= UINT64_MAX - row.place->offset, "ELF reference memory field overflows");
            if (row.file_place)
                require(*row.field_size <= UINT64_MAX - row.file_place->value, "ELF reference file field overflows");
        }
        if (!origin.symbol)
            continue;
        const auto &symbol = *origin.symbol;
        require(row.symbol_index_validated && row.symbol_table && symbol.index == row.symbol_index &&
                    symbol.table == row.symbol_table->section && symbol.table_offset == row.symbol_table->file_offset &&
                    symbol.table_address == row.symbol_table->address,
                "ELF reference symbol copy differs from relocation namespace/index");
        require(symbol.binding <= 15 && symbol.type <= 15 && symbol.visibility == (symbol.other & 7) &&
                    static_cast<unsigned>(symbol.state) <= static_cast<unsigned>(ElfSymbolState::reserved) &&
                    symbol.name.size() <= 65536 && symbol.name.find('\0') == std::string::npos &&
                    (symbol.name_index || symbol.name.empty()),
                "Invalid declared ELF reference symbol");
        if (symbol.state != ElfSymbolState::defined)
            require(!symbol.address, "Special ELF symbol cannot invent an address");
    }
}
std::vector<std::byte> elf_provenance_bytes(const ElfReferenceProvenance &value) {
    validate_elf_provenance(value);
    Writer out;
    out.number(1, 1);
    out.number(static_cast<unsigned>(value.resolution), 1);
    out.number(value.origins.size(), 4);
    for (const auto &origin : value.origins) {
        out.relocation(origin.relocation);
        out.flag(bool(origin.symbol));
        if (origin.symbol)
            out.symbol(*origin.symbol);
    }
    return std::move(out.bytes);
}
ElfReferenceProvenance read_elf_provenance(std::span<const std::byte> bytes) {
    require(bytes.size() <= reference_payload_limit, "ELF provenance payload exceeds bound");
    Reader in{bytes};
    require(in.number(1) == 1, "Unknown ELF provenance payload version");
    ElfReferenceProvenance value;
    value.resolution = static_cast<ElfResolutionReason>(in.number(1));
    const auto count = in.number(4);
    require(count && count <= 4096 && count <= bytes.size() / 32, "Invalid ELF reference origin count");
    value.origins.reserve(static_cast<std::size_t>(count));
    for (std::uint64_t i = 0; i < count; ++i) {
        ElfReferenceOrigin origin;
        origin.relocation = in.relocation();
        if (in.flag())
            origin.symbol = in.symbol();
        value.origins.push_back(std::move(origin));
    }
    require(in.cursor == bytes.size(), "Trailing ELF reference provenance bytes");
    validate_elf_provenance(value);
    return value;
}
std::string elf_symbol_key(const ElfSymbolIdentity &value) {
    Writer out;
    out.source(value.table);
    out.number(value.index, 4);
    return {reinterpret_cast<const char *>(out.bytes.data()), out.bytes.size()};
}
} // namespace hexlab::reference_detail
