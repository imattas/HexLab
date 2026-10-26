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

template <class A, class T> void stream(A &a, T &v) {
    a.scalar(v.command_index, 4);
    a.scalar(v.kind, 1);
    a.scalar(v.raw_offset, 4);
    a.scalar(v.size, 4);
    a.scalar(v.offset.value, 8);
    a.flag(v.complete);
}
template <class A, class T> void operation(A &a, T &v) {
    a.scalar(v.stream, 4);
    a.scalar(v.index, 4);
    a.scalar(v.encoded_size, 4);
    a.scalar(v.record_file_offset, 8);
    a.scalar(v.byte, 1);
    a.optional(v.first, 8);
    a.optional(v.second, 8);
    a.optional(v.signed_value, 8);
    a.object(v.symbol, [&](auto &s) { a.text(s); });
}
template <class A, class T> void fixup(A &a, T &v) {
    a.scalar(v.stream, 4);
    a.scalar(v.operation, 4);
    a.scalar(v.repeat_index, 4);
    a.scalar(v.segment_index, 4);
    a.scalar(v.record_file_offset, 8);
    a.scalar(v.segment_offset, 8);
    a.scalar(v.type, 1);
    a.scalar(v.field_size, 1);
    a.scalar(v.symbol_flags, 1);
    a.optional(v.library_ordinal, 4);
    a.scalar(v.addend, 8);
    a.text(v.symbol);
    a.object(v.place, [&](auto &at) { a.address(at); });
    a.object(v.file_place, [&](auto &at) { a.scalar(at.value, 8); });
    a.optional(v.encoded_value, 8);
}
template <class A, class T> void header(A &a, T &v) {
    a.scalar(v.stream, 4);
    a.scalar(v.version, 4);
    a.scalar(v.starts_offset, 4);
    a.scalar(v.imports_offset, 4);
    a.scalar(v.symbols_offset, 4);
    a.scalar(v.imports_count, 4);
    a.scalar(v.imports_format, 4);
    a.scalar(v.symbols_format, 4);
    a.scalar(v.record_file_offset, 8);
    a.scalar(v.first_import_row, 8);
    a.flag(v.imports_available);
    a.flag(v.complete);
}
template <class A, class T> void pointer(A &a, T &v) {
    a.scalar(v.header, 4);
    a.scalar(v.starts, 4);
    a.scalar(v.page_index, 4);
    a.scalar(v.chain_start_index, 4);
    a.scalar(v.node_index, 4);
    a.scalar(v.segment_offset, 8);
    a.scalar(v.raw, 8);
    a.scalar(v.next, 2);
    a.scalar(v.diversity, 2);
    a.scalar(v.field_size, 1);
    a.scalar(v.stride, 1);
    a.scalar(v.high8, 1);
    a.scalar(v.key, 1);
    a.flag(v.bind);
    a.flag(v.authenticated);
    a.flag(v.address_diversity);
    a.flag(v.target_is_offset);
    a.flag(v.non_pointer);
    a.flag(v.complete);
    a.optional(v.target, 8);
    a.optional(v.import_row, 8);
    a.optional(v.import_index, 4);
    a.optional(v.scalar_value, 4);
    a.scalar(v.addend, 8);
    a.object(v.place, [&](auto &at) { a.address(at); });
    a.object(v.file_place, [&](auto &at) { a.scalar(at.value, 8); });
}
template <class A, class T> void import(A &a, T &v) {
    a.scalar(v.header, 4);
    a.scalar(v.index, 4);
    a.scalar(v.name_offset, 4);
    a.scalar(v.record_file_offset, 8);
    a.scalar(v.raw_info, 8);
    a.scalar(v.raw_addend, 8);
    a.scalar(v.library_ordinal, 4);
    a.scalar(v.addend, 8);
    a.flag(v.weak_import);
    a.flag(v.complete);
    a.object(v.name, [&](auto &s) { a.text(s); });
    a.object(v.name_file_offset, [&](auto &at) { a.scalar(at.value, 8); });
}
template <class A, class T> void binding(A &a, T &v) {
    a.optional(v.library_ordinal, 4);
    a.text(v.name);
    a.scalar(v.addend, 8);
    a.flag(v.weak_import);
    a.optional(v.import_row, 8);
}
void write_origin(Writer &a, const MachODyldReferenceOrigin &v) {
    a.scalar(v.identity.source, 1);
    a.scalar(v.identity.row, 8);
    a.scalar(v.stream_index, 4);
    stream(a, v.stream);
    a.scalar(v.record.index(), 1);
    if (const auto *classic = std::get_if<MachODyldClassicOrigin>(&v.record)) {
        operation(a, classic->operation);
        fixup(a, classic->fixup);
    } else {
        const auto &chain = std::get<MachODyldChainedOrigin>(v.record);
        header(a, chain.header);
        pointer(a, chain.pointer);
        a.object(chain.import, [&](auto &v) { import(a, v); });
        a.scalar(chain.starts_record_file_offset, 8);
        a.scalar(chain.segment_offset, 8);
        a.scalar(chain.segment_index, 4);
        a.scalar(chain.max_valid_pointer, 4);
        a.scalar(chain.pointer_format, 2);
        a.flag(chain.starts_complete);
    }
}
MachODyldReferenceOrigin read_origin(Reader &a) {
    MachODyldReferenceOrigin v;
    a.scalar(v.identity.source, 1);
    a.scalar(v.identity.row, 8);
    a.scalar(v.stream_index, 4);
    stream(a, v.stream);
    std::uint8_t tag{};
    a.scalar(tag, 1);
    require(tag <= 1, "Unknown owned dyld record kind");
    if (!tag) {
        auto &classic = v.record.emplace<MachODyldClassicOrigin>();
        operation(a, classic.operation);
        fixup(a, classic.fixup);
    } else {
        auto &chain = v.record.emplace<MachODyldChainedOrigin>();
        header(a, chain.header);
        pointer(a, chain.pointer);
        a.object(chain.import, [&](auto &v) { import(a, v); });
        a.scalar(chain.starts_record_file_offset, 8);
        a.scalar(chain.segment_offset, 8);
        a.scalar(chain.segment_index, 4);
        a.scalar(chain.max_valid_pointer, 4);
        a.scalar(chain.pointer_format, 2);
        a.flag(chain.starts_complete);
    }
    return v;
}
std::int64_t signed_bits(std::uint64_t bits, unsigned width) {
    if (width < 64 && (bits & (UINT64_C(1) << (width - 1))))
        bits |= UINT64_MAX << width;
    return static_cast<std::int64_t>(bits);
}
void validate_pointer_bits(const MachODyldChainedOrigin &v) {
    const auto &p = v.pointer;
    const auto raw = p.raw;
    const auto format = v.pointer_format;
    if (format == 2 || format == 6) {
        require(p.field_size == 8 && p.stride == 4 && !p.authenticated && p.bind == bool(raw >> 63) &&
                    p.next == ((raw >> 51) & 0xfff),
                "Owned generic64 flags differ from original word");
        if (p.bind) {
            require(p.import_index == (raw & 0xffffff) && p.addend == static_cast<std::int64_t>((raw >> 24) & 0xff) &&
                        !p.target && (!p.complete || !((raw >> 32) & 0x7ffff)),
                    "Owned generic64 bind differs from original word");
        } else
            require(p.target == (raw & UINT64_C(0xfffffffff)) && p.high8 == ((raw >> 36) & 0xff) &&
                        p.target_is_offset == (format == 6) && (!p.complete || !((raw >> 44) & 0x7f)),
                    "Owned generic64 target differs from original word");
    } else if (format == 3) {
        require(raw <= UINT32_MAX && p.field_size == 4 && p.stride == 4 && !p.authenticated &&
                    p.bind == bool(raw >> 31) && p.next == ((raw >> 26) & 31) && !p.high8 && !p.target_is_offset,
                "Owned generic32 flags differ from original word");
        if (p.bind)
            require(p.import_index == (raw & 0xfffff) && p.addend == static_cast<std::int64_t>((raw >> 20) & 63) &&
                        !p.target && !p.non_pointer,
                    "Owned generic32 bind differs from original word");
        else {
            const auto target = raw & 0x3ffffff;
            require(p.target == target && p.non_pointer == (target > v.max_valid_pointer),
                    "Owned generic32 target differs from original word");
            if (p.non_pointer)
                require(p.scalar_value ==
                            static_cast<std::uint32_t>(target - (UINT64_C(0x4000000) + v.max_valid_pointer) / 2),
                        "Owned generic32 scalar restoration differs from original word");
        }
    } else if (format == 8 || format == 11) {
        require(p.field_size == 8 && p.stride == (format == 8 ? 4 : 1) && !p.bind &&
                    p.authenticated == bool(raw >> 63) && p.next == ((raw >> 51) & 0xfff) &&
                    p.target == (raw & 0x3fffffff) && p.diversity == ((raw >> 32) & 0xffff) &&
                    p.address_diversity == bool((raw >> 48) & 1) && p.key == ((raw >> 49) & 3) &&
                    !p.target_is_offset && !p.complete,
                "Owned kernel-cache pointer differs from original word");
    } else if (format == 13) {
        require(p.field_size == 8 && p.stride == 8 && !p.bind &&
                    p.authenticated == bool(raw >> 63) && p.next == ((raw >> 52) & 0x7ff) &&
                    p.target == (raw & UINT64_C(0x3ffffffff)) && !p.target_is_offset && !p.complete,
                "Owned ARM64e shared-cache pointer differs from original word");
        if (p.authenticated)
            require(p.diversity == ((raw >> 34) & 0xffff) && p.address_diversity == bool((raw >> 50) & 1) &&
                        p.key == (((raw >> 51) & 1) ? 2 : 0) && !p.high8,
                    "Owned authenticated shared-cache pointer differs from original word");
        else
            require(p.high8 == ((raw >> 34) & 0xff) && !p.diversity && !p.address_diversity && !p.key,
                    "Owned unauthenticated shared-cache pointer differs from original word");
    } else {
        require(format == 1 || format == 7 || format == 9 || format == 12,
                "Unknown owned chained pointer layout");
        require(p.field_size == 8 && p.stride == (format == 7 ? 4 : 8) && p.bind == bool((raw >> 62) & 1) &&
                    p.authenticated == bool(raw >> 63) && p.next == ((raw >> 51) & 0x7ff),
                "Owned ARM64e flags differ from original word");
        if (p.authenticated)
            require(p.diversity == ((raw >> 32) & 0xffff) && p.key == ((raw >> 49) & 3) &&
                        p.address_diversity == bool((raw >> 48) & 1),
                    "Owned authentication fields differ from original word");
        if (p.bind) {
            const auto bits = format == 12 ? 24u : 16u;
            require(p.import_index == (raw & ((UINT64_C(1) << bits) - 1)) && !p.target &&
                        p.addend == (p.authenticated ? 0 : signed_bits((raw >> 32) & 0x7ffff, 19)) &&
                        (!p.complete || !((raw >> bits) & ((UINT64_C(1) << (32 - bits)) - 1))),
                    "Owned ARM64e bind differs from original word");
        } else if (p.authenticated)
            require(p.target == (raw & UINT32_MAX) && p.target_is_offset,
                    "Owned authenticated target differs from original word");
        else
            require(p.target == (raw & UINT64_C(0x7ffffffffff)) && p.high8 == ((raw >> 43) & 0xff) &&
                        p.target_is_offset == (format != 1),
                    "Owned ARM64e target differs from original word");
    }
    if (!p.bind)
        require(!p.import_index && !p.import_row && !v.import, "Owned rebase claims a bind namespace");
    if (v.import) {
        const auto &imp = *v.import;
        const auto form = v.header.imports_format;
        require(form >= 1 && form <= 3, "Unknown owned chained import layout");
        const auto bits = form == 3 ? 16u : 8u;
        const auto mask = (UINT64_C(1) << bits) - 1;
        const auto ordinal = imp.raw_info & mask;
        const auto value = ordinal > mask - 15
                               ? static_cast<std::int64_t>(ordinal) - static_cast<std::int64_t>(mask + 1)
                               : static_cast<std::int64_t>(ordinal);
        require(imp.library_ordinal == value && imp.weak_import == bool((imp.raw_info >> bits) & 1) &&
                    imp.name_offset == (imp.raw_info >> (form == 3 ? 32 : 9)) &&
                    (form == 3 || imp.raw_info <= UINT32_MAX),
                "Owned chained import differs from original word");
        require((form == 1 ? imp.raw_addend == 0 && imp.addend == 0
                           : imp.addend == signed_bits(imp.raw_addend, form == 3 ? 64 : 32)) &&
                    (form != 2 || imp.raw_addend <= UINT32_MAX),
                "Owned import addend differs from original word");
        require(form != 3 || !imp.complete || !((imp.raw_info >> 17) & 0x7fff),
                "Owned import reserved bits claim complete semantics");
    }
}
} // namespace
MachODyldReferenceProvenance own_dyld_provenance(const MachOMetadata &m, const MachODyldResolution &resolution,
                                                 std::optional<Address> anchor, std::stop_token stop) {
    require(m.selected_slice < m.container.slices.size(), "Missing owned dyld slice");
    const auto &slice = m.container.slices[m.selected_slice];
    const auto &h = slice.header;
    MachODyldReferenceProvenance out{
        {m.selected_slice, slice.offset, slice.size, h.cpu_type, h.cpu_subtype, h.file_type, h.flags, h.is_64, h.order},
        anchor,
        resolution,
        {}};
    require(resolution.origins.size() <= 4096, "Owned dyld origin budget");
    for (const auto id : resolution.origins) {
        canceled(stop);
        MachODyldReferenceOrigin origin;
        origin.identity = id;
        if (id.source == MachODyldSource::classic) {
            require(id.row < m.dyld_fixups.size(), "Owned classic dyld row outside namespace");
            const auto &row = m.dyld_fixups[static_cast<std::size_t>(id.row)];
            require(row.stream < m.dyld_streams.size() && row.operation < m.dyld_operations.size(),
                    "Owned classic dyld source absent");
            origin.stream_index = row.stream;
            origin.stream = m.dyld_streams[row.stream];
            origin.record = MachODyldClassicOrigin{m.dyld_operations[row.operation], row};
        } else {
            require(id.source == MachODyldSource::chained && id.row < m.chained_pointers.size(),
                    "Owned chained dyld row outside namespace");
            const auto &row = m.chained_pointers[static_cast<std::size_t>(id.row)];
            require(row.header < m.chained_headers.size() && row.starts < m.chained_starts.size(),
                    "Owned chained dyld source absent");
            const auto &head = m.chained_headers[row.header];
            const auto &starts = m.chained_starts[row.starts];
            require(head.stream < m.dyld_streams.size(), "Owned chained stream absent");
            origin.stream_index = head.stream;
            origin.stream = m.dyld_streams[head.stream];
            MachODyldChainedOrigin chain{head,
                                         row,
                                         {},
                                         starts.record_file_offset,
                                         starts.segment_offset,
                                         starts.segment_index,
                                         starts.max_valid_pointer,
                                         starts.pointer_format,
                                         starts.complete};
            if (row.import_row) {
                require(*row.import_row < m.chained_imports.size(), "Owned chained import absent");
                chain.import = m.chained_imports[static_cast<std::size_t>(*row.import_row)];
            }
            origin.record = std::move(chain);
        }
        out.origins.push_back(std::move(origin));
    }
    return out;
}
std::size_t dyld_provenance_weight(const MachODyldReferenceProvenance &v) {
    std::size_t size = sizeof(v) + v.origins.size() * sizeof(MachODyldReferenceOrigin);
    const auto add = [&](std::size_t n) {
        require(n <= reference_payload_limit - std::min(size, reference_payload_limit), "Owned dyld provenance budget");
        size += n;
    };
    add(v.queries.size() * sizeof(MachODyldQuery));
    if (v.resolution.binding)
        add(v.resolution.binding->name.size());
    for (const auto &origin : v.origins) {
        if (const auto *classic = std::get_if<MachODyldClassicOrigin>(&origin.record)) {
            add(classic->fixup.symbol.size());
            if (classic->operation.symbol)
                add(classic->operation.symbol->size());
        } else if (const auto &chain = std::get<MachODyldChainedOrigin>(origin.record);
                   chain.import && chain.import->name)
            add(chain.import->name->size());
    }
    require(size <= reference_payload_limit, "Owned dyld provenance budget");
    return size;
}
void validate_dyld_provenance(const MachODyldReferenceProvenance &v) {
    using R = MachODyldResolutionReason;
    const auto &c = v.context;
    const auto &r = v.resolution;
    require(static_cast<unsigned>(v.use) <= static_cast<unsigned>(MachODyldUse::instruction_bytes) &&
                v.queries.size() <= 2 && (v.use == MachODyldUse::raw_data ? v.queries.empty() : !v.queries.empty()),
            "Invalid dyld use/query model");
    for (const auto &query : v.queries) {
        require(query.at.space.value == 0 && query.width && query.width <= 8 &&
                    query.width <= UINT64_MAX - query.at.offset,
                "Invalid dyld query range");
        require((v.use == MachODyldUse::memory_slot) != query.field.has_value(), "Dyld query field/use mismatch");
        if (query.field)
            require(query.field->offset < 15 && query.field->size == query.width &&
                        query.width <= 15 - query.field->offset,
                    "Dyld query exceeds instruction model");
    }
    if (v.use == MachODyldUse::memory_slot)
        require(v.queries.size() == 1, "Memory slot query is not singular");
    require(c.slice_size >= (c.is_64 ? 32u : 28u) && c.slice_size <= UINT64_MAX - c.slice_offset &&
                (c.order == ByteOrder::little || c.order == ByteOrder::big),
            "Invalid owned dyld slice context");
    require(!v.origins.empty() && v.origins.size() <= 4096 && v.origins.size() == r.origins.size() &&
                static_cast<unsigned>(r.reason) <= static_cast<unsigned>(R::unmapped_target) && r.reason != R::none,
            "Invalid owned dyld resolution/origin count");
    const auto in_slice = [&](std::uint64_t offset, std::uint64_t size) {
        return offset >= c.slice_offset && offset - c.slice_offset <= c.slice_size &&
               size <= c.slice_size - (offset - c.slice_offset);
    };
    const auto text = [&](const std::string &s) {
        require(s.size() <= 65536 && s.find('\0') == std::string::npos, "Invalid owned dyld name");
    };
    if (v.header_anchor)
        require(v.header_anchor->space.value == 0, "Owned dyld anchor outside linked domain");
    if (r.binding)
        text(r.binding->name);
    require((r.reason == R::resolved) == r.address.has_value(), "Owned dyld address/resolution mismatch");
    require(!r.binding || r.reason == R::runtime_binding, "Nonbinding dyld result owns a binding");
    require(!r.constant || r.reason == R::non_pointer, "Dyld pointer result claims scalar constant");
    for (std::size_t i = 0; i < v.origins.size(); ++i) {
        const auto &o = v.origins[i];
        require(!o.record.valueless_by_exception(), "Missing owned dyld record");
        require(o.identity == r.origins[i] && (!i || v.origins[i - 1].identity < o.identity),
                "Noncanonical owned dyld origin order");
        require(static_cast<unsigned>(o.stream.kind) <= static_cast<unsigned>(MachODyldStreamKind::chained) &&
                    in_slice(o.stream.offset.value, o.stream.size) &&
                    o.stream.offset.value - c.slice_offset == o.stream.raw_offset,
                "Owned dyld stream outside slice");
        if (const auto *classic = std::get_if<MachODyldClassicOrigin>(&o.record)) {
            const auto &op = classic->operation;
            const auto &f = classic->fixup;
            require(o.identity.source == MachODyldSource::classic && f.stream == o.stream_index &&
                        op.stream == f.stream && f.record_file_offset == op.record_file_offset && op.encoded_size &&
                        op.record_file_offset >= o.stream.offset.value &&
                        op.record_file_offset - o.stream.offset.value <= o.stream.size &&
                        op.encoded_size <= o.stream.size - (op.record_file_offset - o.stream.offset.value) &&
                        o.stream.kind <= MachODyldStreamKind::lazy_bind,
                    "Owned classic source namespace mismatch");
            require(f.field_size == 0 || f.field_size == 4 || f.field_size == 8, "Invalid owned classic field width");
            require(!f.encoded_value || f.field_size != 4 || *f.encoded_value <= UINT32_MAX,
                    "Owned classic scalar exceeds its original field width");
            text(f.symbol);
            if (op.symbol)
                text(*op.symbol);
            if (f.file_place)
                require(in_slice(f.file_place->value, f.field_size), "Owned classic slot outside slice");
            if (f.place)
                require(f.place->space.value == 0, "Owned classic slot outside linked domain");
            if (r.reason == R::resolved) {
                require(o.stream.kind == MachODyldStreamKind::rebase && f.type == 1 &&
                            f.field_size == (c.is_64 ? 8 : 4) && f.encoded_value &&
                            *r.address == Address{{0}, *f.encoded_value},
                        "Resolved classic pointer differs from original word");
            }
            if (r.binding)
                require(o.stream.kind != MachODyldStreamKind::rebase &&
                            *r.binding ==
                                MachODyldBinding{f.library_ordinal, f.symbol, f.addend, bool(f.symbol_flags & 1), {}},
                        "Owned classic binding differs from original state");
        } else {
            const auto &chain = std::get<MachODyldChainedOrigin>(o.record);
            const auto &p = chain.pointer;
            const auto &h = chain.header;
            validate_pointer_bits(chain);
            require(o.identity.source == MachODyldSource::chained && o.stream.kind == MachODyldStreamKind::chained &&
                        h.stream == o.stream_index && h.record_file_offset == o.stream.offset.value &&
                        in_slice(h.record_file_offset, 28) && in_slice(chain.starts_record_file_offset, 22) &&
                        (p.field_size == 4 || p.field_size == 8),
                    "Owned chained namespace/record extent mismatch");
            if (p.file_place)
                require(in_slice(p.file_place->value, p.field_size), "Owned chained slot outside slice");
            if (p.place)
                require(p.place->space.value == 0, "Owned chained slot outside linked domain");
            if (chain.import) {
                const auto &imp = *chain.import;
                require(p.bind && p.import_row && p.import_index && imp.header == p.header &&
                            imp.index == *p.import_index && imp.index < h.imports_count &&
                            h.first_import_row <= *p.import_row && *p.import_row - h.first_import_row == imp.index &&
                            in_slice(imp.record_file_offset, 4),
                        "Owned import crosses chained header namespace");
                if (imp.name)
                    text(*imp.name);
                if (imp.name_file_offset)
                    require(in_slice(imp.name_file_offset->value, imp.name ? imp.name->size() + 1 : 1),
                            "Owned import name outside slice");
                if (r.binding) {
                    require(imp.name && !((p.addend > 0 && imp.addend > INT64_MAX - p.addend) ||
                                          (p.addend < 0 && imp.addend < INT64_MIN - p.addend)),
                            "Owned binding addend overflow");
                    require(*r.binding == MachODyldBinding{imp.library_ordinal, *imp.name, imp.addend + p.addend,
                                                           imp.weak_import, p.import_row},
                            "Owned chained binding differs from import");
                }
            } else
                require(!r.binding && !p.import_row, "Owned chained binding lacks import source");
            if (r.reason == R::resolved) {
                require(!p.bind && !p.authenticated && !p.non_pointer && p.complete && chain.starts_complete &&
                            p.field_size == (c.is_64 ? 8 : 4) && !h.version && c.order == ByteOrder::little && p.target,
                        "Unsupported chained pointer claims resolution");
                auto target = *p.target | (std::uint64_t(p.high8) << 56);
                if (p.target_is_offset) {
                    require(v.header_anchor && target <= UINT64_MAX - v.header_anchor->offset,
                            "Owned chained anchor missing/overflowing");
                    target += v.header_anchor->offset;
                }
                require(*r.address == Address{{0}, target}, "Resolved chained pointer differs from original payload");
            }
            if (r.reason == R::non_pointer)
                require(p.non_pointer && p.scalar_value && r.constant == p.scalar_value,
                        "Owned scalar differs from original chained word");
        }
    }
    if (r.reason == R::resolved || r.binding)
        require(v.origins.size() == 1, "Competing owned sources claim unique dyld resolution");
    (void)dyld_provenance_weight(v);
}
std::vector<std::byte> dyld_provenance_bytes(const MachODyldReferenceProvenance &v) {
    validate_dyld_provenance(v);
    Writer a;
    a.scalar(2, 1);
    context(a, v.context);
    a.object(v.header_anchor, [&](auto &at) { a.address(at); });
    a.scalar(v.resolution.reason, 1);
    a.object(v.resolution.address, [&](auto &at) { a.address(at); });
    a.optional(v.resolution.constant, 8);
    a.object(v.resolution.binding, [&](auto &v) { binding(a, v); });
    a.scalar(v.origins.size(), 4);
    for (const auto &origin : v.origins)
        write_origin(a, origin);
    a.scalar(v.use, 1);
    a.scalar(v.queries.size(), 1);
    for (const auto &query : v.queries) {
        a.address(query.at);
        a.scalar(query.width, 1);
        a.object(query.field, [&](auto &field) {
            a.scalar(field.offset, 1);
            a.scalar(field.size, 1);
        });
    }
    return std::move(a.bytes);
}
MachODyldReferenceProvenance read_dyld_provenance(std::span<const std::byte> bytes) {
    require(bytes.size() <= reference_payload_limit, "Owned dyld block budget");
    Reader a{bytes};
    std::uint8_t version{};
    a.scalar(version, 1);
    require(version == 2, "Unknown owned dyld block version");
    MachODyldReferenceProvenance v;
    context(a, v.context);
    a.object(v.header_anchor, [&](auto &at) { a.address(at); });
    a.scalar(v.resolution.reason, 1);
    a.object(v.resolution.address, [&](auto &at) { a.address(at); });
    a.optional(v.resolution.constant, 8);
    a.object(v.resolution.binding, [&](auto &v) { binding(a, v); });
    std::uint32_t count{};
    a.scalar(count, 4);
    require(count && count <= 4096 && count <= (bytes.size() - a.cursor) / 32, "Owned dyld origin count");
    for (std::uint32_t i = 0; i < count; ++i) {
        auto origin = read_origin(a);
        v.resolution.origins.push_back(origin.identity);
        v.origins.push_back(std::move(origin));
    }
    a.scalar(v.use, 1);
    std::uint8_t queries = 0;
    a.scalar(queries, 1);
    require(queries <= 2, "Owned dyld query count exceeds bound");
    for (std::uint8_t i = 0; i < queries; ++i) {
        MachODyldQuery query;
        a.address(query.at);
        a.scalar(query.width, 1);
        a.object(query.field, [&](auto &field) {
            a.scalar(field.offset, 1);
            a.scalar(field.size, 1);
        });
        v.queries.push_back(query);
    }
    require(a.cursor == bytes.size(), "Trailing owned dyld bytes");
    validate_dyld_provenance(v);
    return v;
}
} // namespace hexlab::reference_detail
