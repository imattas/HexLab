#include "references_internal.hpp"
#include <algorithm>
#include <set>
#include <map>
#include <tuple>
namespace hexlab::reference_detail {
namespace {
struct Writer {
    std::vector<std::byte> bytes;
    template <class T> void scalar(const T &value, std::size_t width) {
        require(width <= 8 && width <= reference_payload_limit - bytes.size(), "Mach-O provenance scalar budget");
        for (auto i = width; i; --i)
            bytes.push_back(std::byte(std::uint64_t(value) >> ((i - 1) * 8)));
    }
    void flag(bool value) { scalar(value, 1); }
    void address(const Address &value) {
        scalar(value.space.value, 4);
        scalar(value.offset, 8);
    }
    template <class T> void optional(const std::optional<T> &value, std::size_t width) {
        flag(bool(value));
        if (value)
            scalar(*value, width);
    }
    template <class T, class F> void object(const std::optional<T> &value, F operation) {
        flag(bool(value));
        if (value)
            operation(*value);
    }
    void text(const std::string &value) {
        require(value.size() <= 65536, "Mach-O provenance text limit");
        scalar(value.size(), 4);
        require(value.size() <= reference_payload_limit - bytes.size(), "Mach-O provenance text budget");
        for (unsigned char byte : value)
            bytes.push_back(std::byte(byte));
    }
};
struct Reader {
    std::span<const std::byte> bytes;
    std::size_t cursor = 0;
    template <class T> void scalar(T &value, std::size_t width) {
        require(width <= 8 && cursor <= bytes.size() && width <= bytes.size() - cursor, "Truncated Mach-O provenance");
        std::uint64_t result = 0;
        for (std::size_t i = 0; i < width; ++i)
            result = (result << 8) | std::to_integer<unsigned>(bytes[cursor++]);
        value = static_cast<T>(result);
    }
    void flag(bool &value) {
        std::uint8_t raw;
        scalar(raw, 1);
        require(raw <= 1, "Noncanonical Mach-O provenance boolean");
        value = raw != 0;
    }
    void address(Address &value) {
        scalar(value.space.value, 4);
        scalar(value.offset, 8);
    }
    template <class T> void optional(std::optional<T> &value, std::size_t width) {
        bool present;
        flag(present);
        if (present) {
            T item{};
            scalar(item, width);
            value = item;
        }
    }
    template <class T, class F> void object(std::optional<T> &value, F operation) {
        bool present;
        flag(present);
        if (present) {
            value.emplace();
            operation(*value);
        }
    }
    void text(std::string &value) {
        std::uint32_t size;
        scalar(size, 4);
        require(size <= 65536 && size <= bytes.size() - cursor, "Mach-O provenance text extent");
        value.assign(reinterpret_cast<const char *>(bytes.data() + cursor), size);
        cursor += size;
    }
};
template <class A, class T> void context(A &a, T &v) {
    a.scalar(v.slice_index, 4);
    a.scalar(v.slice_offset, 8);
    a.scalar(v.slice_size, 8);
    a.scalar(v.cpu_type, 4);
    a.scalar(v.cpu_subtype, 4);
    a.scalar(v.file_type, 4);
    a.scalar(v.flags, 4);
    a.flag(v.is_64);
    a.scalar(v.order, 1);
}
template <class A, class T> void table(A &a, T &v) {
    a.scalar(v.kind, 1);
    a.scalar(v.owner, 4);
    a.scalar(v.count, 4);
    a.scalar(v.offset.value, 8);
    a.scalar(v.first_row, 8);
    a.optional(v.symbol_table, 4);
}
template <class A, class T> void relocation(A &a, T &v) {
    a.scalar(v.table, 4);
    a.scalar(v.index, 4);
    a.scalar(v.raw_address, 4);
    a.scalar(v.raw_info, 4);
    a.scalar(v.offset, 4);
    a.scalar(v.symbol_number, 4);
    a.scalar(v.type, 1);
    a.scalar(v.length, 1);
    a.scalar(v.field_size, 1);
    a.flag(v.pc_relative);
    a.flag(v.external);
    a.flag(v.scattered);
    a.flag(v.auxiliary);
    a.flag(v.retained);
    a.flag(v.symbol_index_validated);
    a.scalar(v.kind, 1);
    a.optional(v.symbol_table, 4);
    a.optional(v.value, 4);
    a.optional(v.pair, 8);
    a.scalar(v.record_file_offset, 8);
    a.object(v.place, [&](auto &at) { a.address(at); });
    a.object(v.file_place, [&](auto &at) { a.scalar(at.value, 8); });
    a.optional(v.encoded_value, 8);
}
template <class A, class T> void symbol_table(A &a, T &v) {
    a.scalar(v.command_index, 4);
    a.scalar(v.raw_symbol_offset, 4);
    a.scalar(v.raw_string_offset, 4);
    a.scalar(v.count, 4);
    a.scalar(v.stride, 4);
    a.scalar(v.string_size, 4);
    a.scalar(v.symbol_offset.value, 8);
    a.scalar(v.string_offset.value, 8);
    a.scalar(v.first_symbol, 8);
}
template <class A, class T> void symbol(A &a, T &v) {
    a.scalar(v.table_command, 4);
    a.scalar(v.index, 4);
    a.scalar(v.string_index, 4);
    a.scalar(v.type, 1);
    a.scalar(v.section, 1);
    a.scalar(v.descriptor, 2);
    a.scalar(v.value, 8);
    a.scalar(v.record_file_offset, 8);
    a.text(v.name);
    a.object(v.indirect_name, [&](auto &name) { a.text(name); });
    a.optional(v.library_ordinal, 1);
    a.scalar(v.state, 1);
    a.object(v.address, [&](auto &at) { a.address(at); });
    a.flag(v.code);
}
template <class A, class T> void origin(A &a, T &v) {
    relocation(a, v.relocation);
    table(a, v.table);
    a.object(v.symbol_table, [&](auto &item) { symbol_table(a, item); });
    a.object(v.symbol, [&](auto &item) { symbol(a, item); });
}
bool text_valid(const std::string &value) { return value.size() <= 65536 && value.find('\0') == std::string::npos; }
} // namespace
std::size_t macho_provenance_weight(const MachOReferenceProvenance &value) {
    require(!value.origins.empty() && value.origins.size() <= 4096, "Mach-O reference origin count limit");
    std::size_t size = sizeof(value) + value.origins.size() * sizeof(MachOReferenceOrigin);
    for (const auto &item : value.origins)
        if (item.symbol) {
            const auto add =
                item.symbol->name.size() + (item.symbol->indirect_name ? item.symbol->indirect_name->size() : 0);
            require(add <= reference_payload_limit - size, "Mach-O provenance allocation budget");
            size += add;
        }
    return size;
}
void validate_macho_provenance(const MachOReferenceProvenance &value) {
    (void)macho_provenance_weight(value);
    const auto &c = value.context;
    require(c.slice_index < 4096 && c.slice_size <= UINT64_MAX - c.slice_offset &&
                (c.order == ByteOrder::little || c.order == ByteOrder::big),
            "Invalid Mach-O reference context");
    require(value.resolution != MachOResolutionReason::none &&
                static_cast<unsigned>(value.resolution) <=
                    static_cast<unsigned>(MachOResolutionReason::runtime_binding),
            "Invalid Mach-O reference resolution");
    require(!value.constant || value.resolution == MachOResolutionReason::resolved, "Unresolved Mach-O scalar claim");
    const auto within = [&](std::uint64_t offset, std::uint64_t size) {
        return offset >= c.slice_offset && offset - c.slice_offset <= c.slice_size &&
               size <= c.slice_size - (offset - c.slice_offset);
    };
    std::map<std::pair<std::uint32_t, std::uint32_t>, const MachOReferenceOrigin *> sources;
    std::optional<std::uint64_t> previous;
    for (const auto &item : value.origins) {
        const auto &r = item.relocation;
        const auto &t = item.table;
        require(t.first_row <= 1000000 && r.index <= 1000000 - t.first_row, "Mach-O origin global index exceeds bound");
        const auto global = t.first_row + r.index;
        require(!previous || *previous < global, "Mach-O origins are not in canonical source order");
        previous = global;
        require(sources.emplace(std::pair{r.table, r.index}, &item).second, "Duplicate Mach-O origin identity");
    }
    for (const auto &item : value.origins) {
        const auto &r = item.relocation;
        const auto &t = item.table;
        require(static_cast<unsigned>(t.kind) <= static_cast<unsigned>(MachORelocationSource::local) &&
                    t.count <= 1000000 && r.index < t.count && t.first_row <= 1000000 &&
                    t.count <= 1000000 - t.first_row && within(t.offset.value, std::uint64_t(t.count) * 8) &&
                    r.record_file_offset == t.offset.value + std::uint64_t(r.index) * 8,
                "Mach-O relocation record differs from original bounded table/index");
        require(t.kind != MachORelocationSource::section || t.owner != 0, "Mach-O section origin has null ordinal");
        require(r.length <= 3 && r.field_size == (1u << r.length) && r.type <= 15 &&
                    static_cast<unsigned>(r.kind) <= static_cast<unsigned>(MachORelocationKind::unknown),
                "Invalid Mach-O relocation fields");
        require(r.scattered == (c.cpu_type != 0x01000007 && bool(r.raw_address & 0x80000000)),
                "Mach-O scattered flag differs from original word/context");
        if (r.scattered) {
            require(r.offset == (r.raw_address & 0xffffff) && r.type == ((r.raw_address >> 24) & 15) &&
                        r.length == ((r.raw_address >> 28) & 3) && r.pc_relative == bool(r.raw_address & 0x40000000) &&
                        r.value == r.raw_info && !r.external,
                    "Mach-O scattered values differ from original words");
        } else {
            const auto little = c.order == ByteOrder::little;
            require(r.offset == r.raw_address &&
                        r.symbol_number == (little ? r.raw_info & 0xffffff : r.raw_info >> 8) &&
                        r.type == (little ? r.raw_info >> 28 : r.raw_info & 15) &&
                        r.length == ((r.raw_info >> (little ? 25 : 5)) & 3) &&
                        r.pc_relative == bool((r.raw_info >> (little ? 24 : 7)) & 1) &&
                        r.external == bool((r.raw_info >> (little ? 27 : 4)) & 1) && !r.value,
                    "Mach-O normal fields differ from original words/order");
        }
        require(!r.file_place || within(r.file_place->value, r.field_size), "Mach-O field backing exceeds slice");
        require(!r.place || r.field_size <= UINT64_MAX - r.place->offset, "Mach-O field VM extent overflow");
        require(!r.retained || (c.file_type != 1 && t.kind == MachORelocationSource::section),
                "Mach-O retained record has incompatible source role");
        require(!r.retained || !r.encoded_value, "Retained Mach-O record cannot claim unapplied field bits");
        require(!r.symbol_index_validated || (r.external && !r.scattered && item.symbol_table && item.symbol),
                "Validated Mach-O nlist origin lacks its actual namespace and symbol copy");
        if (item.symbol_table) {
            const auto &s = *item.symbol_table;
            require(r.symbol_table == s.command_index && s.stride == (c.is_64 ? 16u : 12u) &&
                        s.symbol_offset.value == c.slice_offset + s.raw_symbol_offset &&
                        s.string_offset.value == c.slice_offset + s.raw_string_offset &&
                        within(s.symbol_offset.value, std::uint64_t(s.count) * s.stride) &&
                        within(s.string_offset.value, s.string_size),
                    "Mach-O symbol namespace exceeds source");
            if (r.symbol_index_validated)
                require(r.symbol_number < s.count, "Mach-O nlist index out of bounds");
        }
        if (item.symbol) {
            const auto &s = *item.symbol;
            require(item.symbol_table && r.symbol_index_validated && s.index == r.symbol_number &&
                        s.table_command == item.symbol_table->command_index &&
                        s.record_file_offset == item.symbol_table->symbol_offset.value +
                                                    std::uint64_t(s.index) * item.symbol_table->stride &&
                        ((!s.string_index && s.name.empty()) || s.string_index < item.symbol_table->string_size) &&
                        text_valid(s.name) && (!s.indirect_name || text_valid(*s.indirect_name)) &&
                        static_cast<unsigned>(s.state) <= static_cast<unsigned>(MachOSymbolState::unknown),
                    "Mach-O symbol copy differs from original namespace/index or bounds");
        }
        if (r.pair) {
            require(*r.pair >= t.first_row && *r.pair < t.first_row + t.count && *r.pair != t.first_row + r.index,
                    "Mach-O paired origin escapes table namespace");
            const auto found = sources.find({r.table, static_cast<std::uint32_t>(*r.pair - t.first_row)});
            require(found != sources.end() && found->second->table == t &&
                        found->second->relocation.pair == t.first_row + r.index,
                    "Mach-O compound provenance lacks paired source");
        }
    }
    if (value.constant) {
        const auto &first = value.origins[0];
        const auto &r = first.relocation;
        require(c.file_type == 1 && r.encoded_value, "Mach-O scalar lacks original object field bits");
        if (r.kind == MachORelocationKind::subtractor) {
            require(value.origins.size() == 2 && first.symbol && value.origins[1].symbol && first.symbol->address &&
                        value.origins[1].symbol->address &&
                        first.symbol->address->space == value.origins[1].symbol->address->space &&
                        (r.field_size == 4 || r.field_size == 8),
                    "Mach-O subtractor scalar lacks same-domain symbols");
            const auto mask = r.field_size == 8 ? UINT64_MAX : UINT64_C(0xffffffff);
            require(*value.constant ==
                        ((value.origins[1].symbol->address->offset - first.symbol->address->offset + *r.encoded_value) &
                         mask),
                    "Mach-O scalar differs from original subtractor equation");
        } else
            require(value.origins.size() == 1 && r.kind == MachORelocationKind::absolute && !r.external &&
                        !r.scattered && r.symbol_number == 0 && *value.constant == *r.encoded_value,
                    "Mach-O scalar differs from original absolute bit pattern");
    }
}
std::vector<std::byte> macho_provenance_bytes(const MachOReferenceProvenance &value) {
    validate_macho_provenance(value);
    Writer out;
    out.scalar(1, 1);
    out.scalar(value.resolution, 1);
    context(out, value.context);
    out.optional(value.constant, 8);
    out.scalar(value.origins.size(), 4);
    for (const auto &item : value.origins)
        origin(out, item);
    return std::move(out.bytes);
}
MachOReferenceProvenance read_macho_provenance(std::span<const std::byte> bytes) {
    require(bytes.size() <= reference_payload_limit, "Mach-O provenance payload budget");
    Reader in{bytes};
    unsigned version;
    in.scalar(version, 1);
    require(version == 1, "Unknown Mach-O provenance version");
    MachOReferenceProvenance value;
    in.scalar(value.resolution, 1);
    context(in, value.context);
    in.optional(value.constant, 8);
    std::uint32_t count;
    in.scalar(count, 4);
    require(count && count <= 4096 && count <= bytes.size() / 64, "Mach-O provenance origin count bound");
    value.origins.resize(count);
    for (auto &item : value.origins)
        origin(in, item);
    require(in.cursor == bytes.size(), "Trailing Mach-O provenance bytes");
    validate_macho_provenance(value);
    return value;
}
std::string macho_symbol_key(const MachOSymbolIdentity &value) {
    require(value.slice_index < 4096, "Mach-O symbol query slice exceeds bound");
    Writer out;
    out.scalar(value.slice_index, 4);
    out.scalar(value.slice_offset.value, 8);
    out.scalar(value.table_command, 4);
    out.scalar(value.table_offset.value, 8);
    out.scalar(value.index, 4);
    return {reinterpret_cast<const char *>(out.bytes.data()), out.bytes.size()};
}
} // namespace hexlab::reference_detail
