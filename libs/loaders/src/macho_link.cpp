#include "hexlab/loaders/macho_link.hpp"
#include "hexlab/loaders/macho.hpp"
#include <algorithm>
#include <bit>
#include <cstring>
#include <limits>
#include <map>
#include <set>
#include <tuple>

namespace hexlab {
namespace {
struct Failure { Error error; };
void require(bool value, std::string message, ErrorCode code = ErrorCode::malformed) {
    if (!value) throw Failure{{code, std::move(message)}};
}
void canceled(std::stop_token stop) { require(!stop.stop_requested(), "Mach-O link canceled", ErrorCode::canceled); }
std::uint64_t align_to(std::uint64_t value, std::uint64_t alignment) {
    require(alignment && !(alignment & (alignment - 1)) && value <= UINT64_MAX - (alignment - 1),
            "Mach-O output alignment is invalid or overflows", ErrorCode::resource_limit);
    return (value + alignment - 1) & ~(alignment - 1);
}
void put(std::vector<std::byte> &bytes, std::size_t at, std::uint64_t value, std::size_t width) {
    require(width && width <= 8 && (width == 8 || value < (UINT64_C(1) << (width * 8))),
            "Mach-O output scalar does not fit its field", ErrorCode::resource_limit);
    require(at <= bytes.size() && width <= bytes.size() - at, "Mach-O output field exceeds output extent",
            ErrorCode::resource_limit);
    for (std::size_t i = 0; i < width; ++i) bytes[at + i] = static_cast<std::byte>(value >> (8 * i));
}
std::int64_t sign_extend(std::uint64_t value, std::size_t width) {
    require(width && width <= 8, "Invalid Mach-O relocation width");
    const auto bits = width * 8;
    if (bits == 64) return std::bit_cast<std::int64_t>(value);
    const auto sign = UINT64_C(1) << (bits - 1);
    value &= (UINT64_C(1) << bits) - 1;
    return static_cast<std::int64_t>((value ^ sign) - sign);
}
std::int64_t sign_extend_bits(std::uint64_t value, unsigned bits) {
    require(bits && bits <= 64, "Invalid Mach-O relocation bit width");
    if (bits == 64) return std::bit_cast<std::int64_t>(value);
    const auto mask = (UINT64_C(1) << bits) - 1;
    const auto sign = UINT64_C(1) << (bits - 1);
    value &= mask;
    return static_cast<std::int64_t>((value ^ sign) - sign);
}
std::uint64_t add_signed(std::uint64_t value, std::int64_t addend) {
    if (addend >= 0) {
        const auto amount = static_cast<std::uint64_t>(addend);
        require(value <= UINT64_MAX - amount, "Mach-O relocation address overflows", ErrorCode::unsupported);
        return value + amount;
    }
    const auto amount = static_cast<std::uint64_t>(-(addend + 1)) + 1;
    require(value >= amount, "Mach-O relocation address underflows", ErrorCode::unsupported);
    return value - amount;
}
std::int64_t difference(std::uint64_t target, std::uint64_t place);
std::uint32_t apply_arm64_relocation(std::uint8_t type, std::uint32_t instruction,
                                     std::uint64_t target, std::uint64_t place,
                                     std::optional<std::int64_t> explicit_addend) {
    require((place & 3) == 0, "ARM64 Mach-O instruction relocation is not aligned", ErrorCode::malformed);
    if (type == 2) { // ARM64_RELOC_BRANCH26
        require((instruction & 0x7c000000u) == 0x14000000u,
                "ARM64 BRANCH26 relocation requires B or BL", ErrorCode::malformed);
        require((instruction & 0x03ffffffu) == 0 && !explicit_addend,
                "ARM64 BRANCH26 requires a zero immediate and does not accept ADDEND records", ErrorCode::unsupported);
        const auto adjusted = target;
        const auto delta = difference(adjusted, place);
        require((delta & 3) == 0 && delta >= -(INT64_C(1) << 27) && delta < (INT64_C(1) << 27),
                "ARM64 BRANCH26 target is unaligned or out of range (veneers are unsupported)", ErrorCode::unsupported);
        return (instruction & 0xfc000000u) |
               (static_cast<std::uint32_t>(static_cast<std::uint64_t>(delta >> 2)) & 0x03ffffffu);
    }
    if (type == 3) { // ARM64_RELOC_PAGE21
        require((instruction & 0x9f000000u) == 0x90000000u,
                "ARM64 PAGE21 relocation requires ADRP", ErrorCode::malformed);
        require((instruction & 0x60ffffe0u) == 0,
                "ARM64 PAGE21 relocation requires a zero immediate", ErrorCode::unsupported);
        const auto adjusted = add_signed(target, explicit_addend.value_or(0));
        const auto target_page = adjusted & ~UINT64_C(0xfff);
        const auto place_page = place & ~UINT64_C(0xfff);
        const auto delta = difference(target_page, place_page);
        require((delta & 0xfff) == 0 && delta >= -(INT64_C(1) << 32) && delta < (INT64_C(1) << 32),
                "ARM64 PAGE21 target is out of range", ErrorCode::unsupported);
        const auto pages = static_cast<std::uint64_t>(delta >> 12) & 0x1fffffu;
        return (instruction & 0x9f00001fu) | (static_cast<std::uint32_t>(pages & 3) << 29) |
               (static_cast<std::uint32_t>((pages >> 2) & 0x7ffff) << 5);
    }
    require(type == 4 || type == 6,
            "Unsupported ARM64 Mach-O relocation type " + std::to_string(type), ErrorCode::unsupported);
    unsigned scale = 0;
    if (type == 6) {
        require((instruction & 0xffc00000u) == 0xf9400000u &&
                    (instruction & 0x003ffc00u) == 0,
                "ARM64 GOT_LOAD_PAGEOFF12 requires LDR X with a zero immediate", ErrorCode::unsupported);
        scale = 3;
    } else if ((instruction & 0x7fc00000u) == 0x11000000u) {
        require((instruction & (1u << 22)) == 0 && (instruction & 0x003ffc00u) == 0,
                "ARM64 PAGEOFF12 ADD must have a zero, unshifted immediate", ErrorCode::unsupported);
        scale = 0;
    } else if ((instruction & 0x3b000000u) == 0x39000000u) {
        require((instruction & 0x003ffc00u) == 0,
                "ARM64 PAGEOFF12 load/store must have a zero immediate", ErrorCode::unsupported);
        scale = instruction >> 30;
        if (scale == 0 && (instruction & 0x04800000u) == 0x04800000u) scale = 4;
    } else {
        require(false, "ARM64 PAGEOFF12 requires ADD immediate or integer unsigned-immediate load/store", ErrorCode::unsupported);
    }
    const auto adjusted = add_signed(target, explicit_addend.value_or(0));
    const auto low = adjusted & 0xfffu;
    const auto alignment = UINT64_C(1) << scale;
    require((low & (alignment - 1)) == 0, "ARM64 PAGEOFF12 target violates access alignment", ErrorCode::unsupported);
    return (instruction & ~0x003ffc00u) | (static_cast<std::uint32_t>(low >> scale) << 10);
}
std::int64_t difference(std::uint64_t target, std::uint64_t place) {
    require(target <= INT64_MAX && place <= INT64_MAX, "Mach-O PC-relative address exceeds signed range",
            ErrorCode::unsupported);
    return static_cast<std::int64_t>(target) - static_cast<std::int64_t>(place);
}
struct Relocation {
    std::size_t object = 0;
    std::uint32_t source_section = 0;
    MachORelocation row;
    std::optional<std::size_t> got_entry;
};
struct GotEntry {
    std::size_t object = 0;
    std::uint32_t section = 0;
    std::uint64_t value = 0, output_offset = 0;
    std::int64_t addend = 0;
};
struct ReadOnlyContribution {
    std::uint32_t source_section = 0;
    std::uint64_t alignment = 1, output_offset = 0;
    std::vector<std::byte> bytes;
};
struct Object {
    std::shared_ptr<const ByteStorage> storage;
    MachOMetadata metadata;
    std::uint32_t text_section = 0, data_section = 0, bss_section = 0;
    std::uint32_t eh_frame_section = 0;
    std::uint64_t alignment = 1, output_offset = 0;
    std::uint64_t data_alignment = 1, data_output_offset = 0;
    std::uint64_t bss_alignment = 1, bss_output_offset = 0, bss_contribution_size = 0;
    std::uint64_t eh_frame_alignment = 1, eh_frame_output_offset = 0;
    std::vector<std::byte> text, data, eh_frame;
    std::vector<ReadOnlyContribution> read_only;
};
void validate_eh_frame(std::span<const std::byte> bytes) {
    require(bytes.size() <= 64u * 1024u * 1024u, "Mach-O __eh_frame exceeds 64 MiB link bound", ErrorCode::resource_limit);
    std::set<std::size_t> cies;
    std::vector<std::pair<std::size_t, std::uint32_t>> fdes;
    std::size_t at = 0;
    auto u32 = [&](std::size_t offset) {
        require(offset <= bytes.size() && 4 <= bytes.size() - offset, "Truncated Mach-O __eh_frame record");
        std::uint32_t value = 0;
        for (unsigned i = 0; i < 4; ++i) value |= std::to_integer<std::uint32_t>(bytes[offset + i]) << (8 * i);
        return value;
    };
    while (at < bytes.size()) {
        const auto length = u32(at);
        if (!length) {
            for (std::size_t i = at + 4; i < bytes.size(); ++i)
                require(bytes[i] == std::byte{0}, "Nonzero bytes follow Mach-O __eh_frame terminator");
            break;
        }
        require(length != UINT32_MAX && length >= 4 && length <= bytes.size() - at - 4,
                "Mach-O __eh_frame uses extended or out-of-bounds records", ErrorCode::unsupported);
        const auto id_at = at + 4;
        const auto id = u32(id_at);
        if (!id) cies.insert(at);
        else fdes.emplace_back(id_at, id);
        at += 4 + length;
    }
    for (const auto &[id_at, distance] : fdes) {
        require(distance <= id_at && cies.contains(id_at - distance),
                "Mach-O FDE does not reference a preceding CIE record", ErrorCode::unsupported);
    }
}
const ReadOnlyContribution *read_only_contribution(const Object &object, std::uint32_t section) {
    const auto found = std::find_if(object.read_only.begin(), object.read_only.end(),
        [&](const auto &contribution) { return contribution.source_section == section; });
    return found == object.read_only.end() ? nullptr : &*found;
}
struct Definition { std::size_t object = 0; const MachOSymbol *symbol = nullptr; bool weak = false; };
struct OutputSymbol { std::string name; std::uint64_t value = 0; std::uint16_t descriptor = 0; std::uint8_t section = 0; };

std::vector<std::byte> build(std::vector<Object> &objects, std::string_view entry,
                             std::uint64_t base, std::stop_token stop, const MachOLinkLimits &limits) {
    require(!objects.empty() && objects.size() <= limits.max_objects, "Mach-O object count is outside configured limits",
            ErrorCode::resource_limit);
    const auto &first_header = objects.front().metadata.container.slices[objects.front().metadata.selected_slice].header;
    const bool arm64 = first_header.cpu_type == 0x0100000c;
    require(first_header.cpu_type == 0x01000007 || arm64,
            "Mach-O static link supports x86-64 and ARM64 objects", ErrorCode::unsupported);
    const auto cpu_type = first_header.cpu_type;
    constexpr std::uint64_t x64_user_limit = UINT64_C(0x00007fffffffffff);
    constexpr std::uint64_t arm64_user_limit = UINT64_C(0x0000ffffffffffff);
    const auto max_user_address = arm64 ? arm64_user_limit : x64_user_limit;
    require(base <= max_user_address, "Mach-O base address exceeds supported architecture user range", ErrorCode::unsupported);
    std::map<std::string, Definition, std::less<>> definitions;
    std::size_t symbols_seen = 0, relocations_seen = 0;
    std::vector<Relocation> relocations;
    std::uint64_t code_size = 0, code_alignment = 1, eh_frame_size = 0, eh_frame_alignment = 8;
    std::uint64_t const_size = 0, const_alignment = 1;
    std::uint64_t data_size = 0, data_alignment = 1, bss_size = 0, bss_alignment = 1;
    for (std::size_t oi = 0; oi < objects.size(); ++oi) {
        canceled(stop);
        const auto &object = objects[oi];
        require(object.storage->size() <= limits.max_output_bytes,
                "Mach-O input object exceeds configured byte limit", ErrorCode::resource_limit);
        const auto &metadata = object.metadata;
        const auto &header = metadata.container.slices[metadata.selected_slice].header;
        require(header.file_type == 1 && header.is_64 && header.order == ByteOrder::little &&
                    header.cpu_type == cpu_type,
                "Mach-O static link requires one little-endian 64-bit CPU architecture", ErrorCode::unsupported);
        require(metadata.symbols_complete, "Mach-O object symbol metadata is incomplete", ErrorCode::unsupported);
        require(metadata.symbols.size() <= limits.max_symbols - symbols_seen,
                "Mach-O link symbol limit exceeded", ErrorCode::resource_limit);
        symbols_seen += metadata.symbols.size();
        const MachOSection *text = nullptr, *data = nullptr, *bss = nullptr, *eh_frame = nullptr;
        std::vector<const MachOSection *> read_only_sections;
        for (const auto &section : metadata.sections) {
            if (section.segment_name == "__TEXT" && section.name == "__text" && section.size) {
                require(!text, "Mach-O object has multiple __TEXT,__text sections", ErrorCode::unsupported);
                text = &section;
            } else if (section.segment_name == "__DATA" && section.name == "__data" && section.size) {
                require(!data, "Mach-O object has multiple __DATA,__data sections", ErrorCode::unsupported);
                data = &section;
            } else if (section.segment_name == "__TEXT" && section.name == "__const" && section.size) {
                require((section.flags & 0xff) == 0,
                        "Mach-O __TEXT,__const must be an S_REGULAR section", ErrorCode::unsupported);
                read_only_sections.push_back(&section);
            } else if (section.segment_name == "__DATA_CONST" && section.name == "__const" && section.size) {
                require((section.flags & 0xff) == 0,
                        "Mach-O __DATA_CONST,__const must be an S_REGULAR section", ErrorCode::unsupported);
                read_only_sections.push_back(&section);
            } else if (section.segment_name == "__TEXT" && section.name == "__cstring" && section.size) {
                require((section.flags & 0xff) == 2,
                        "Mach-O __TEXT,__cstring must be an S_CSTRING_LITERALS section", ErrorCode::unsupported);
                read_only_sections.push_back(&section);
            } else if (section.segment_name == "__TEXT" &&
                       (section.name == "__literal4" || section.name == "__literal8" ||
                        section.name == "__literal16") && section.size) {
                const auto expected_kind = section.name == "__literal4" ? 3u : section.name == "__literal8" ? 4u : 5u;
                require((section.flags & 0xff) == expected_kind,
                        "Mach-O literal section has a mismatched section type", ErrorCode::unsupported);
                const std::uint64_t element_size = section.name == "__literal4" ? 4 : section.name == "__literal8" ? 8 : 16;
                require(section.size % element_size == 0,
                        "Mach-O literal section size is not a whole number of elements", ErrorCode::malformed);
                read_only_sections.push_back(&section);
            } else if (section.segment_name == "__DATA" && section.name == "__bss" && section.size &&
                       (section.flags & 0xff) == 1) {
                require(!bss, "Mach-O object has multiple __DATA,__bss sections", ErrorCode::unsupported);
                bss = &section;
            } else if (section.segment_name == "__TEXT" && section.name == "__eh_frame" && section.size) {
                require(!eh_frame, "Mach-O object has multiple __TEXT,__eh_frame sections", ErrorCode::unsupported);
                require((section.flags & 0xff) == 0, "Mach-O __eh_frame must be an S_REGULAR section", ErrorCode::unsupported);
                eh_frame = &section;
            } else if (section.size && section.name != "__eh_frame" && section.name != "__compact_unwind" &&
                       section.name != "__debug_info" && section.name != "__debug_abbrev" &&
                       section.name != "__debug_line" && section.name != "__debug_str") {
                throw Failure{{ErrorCode::unsupported,
                    "Mach-O static link subset only maps __TEXT,__text/read-only literals, __DATA_CONST,__const, and __DATA,__data/__bss sections"}};
            }
        }
        require(text && text->file_offset && text->size <= limits.max_output_bytes && text->size <= SIZE_MAX &&
                    text->file_offset->value <= object.storage->size() &&
                    text->size <= object.storage->size() - text->file_offset->value,
                "Mach-O object has no bounded initialized __TEXT,__text section", ErrorCode::unsupported);
        require(text->alignment < 63, "Mach-O text alignment exponent exceeds the link limit", ErrorCode::resource_limit);
        const auto alignment = UINT64_C(1) << text->alignment;
        code_alignment = std::max(code_alignment, alignment);
        const auto aligned = align_to(code_size, alignment);
        require(aligned <= limits.max_output_bytes && text->size <= limits.max_output_bytes - aligned,
                "Mach-O merged text exceeds output limit",
                ErrorCode::resource_limit);
        auto &mutable_object = objects[oi];
        mutable_object.output_offset = aligned;
        mutable_object.text_section = text->ordinal;
        mutable_object.alignment = alignment;
        code_size = aligned + text->size;
        auto source = object.storage->read_at(*text->file_offset, static_cast<std::size_t>(text->size));
        if (!source) throw Failure{source.error()};
        mutable_object.text.assign(source.value().bytes.begin(), source.value().bytes.end());
        if (eh_frame) {
            require(eh_frame->file_offset && eh_frame->size <= limits.max_output_bytes && eh_frame->size <= SIZE_MAX &&
                        eh_frame->file_offset->value <= object.storage->size() &&
                        eh_frame->size <= object.storage->size() - eh_frame->file_offset->value,
                    "Mach-O object has an unbounded initialized __eh_frame section", ErrorCode::unsupported);
            require(eh_frame->alignment < 63, "Mach-O __eh_frame alignment exponent exceeds the link limit", ErrorCode::resource_limit);
            auto frame = object.storage->read_at(*eh_frame->file_offset, static_cast<std::size_t>(eh_frame->size));
            if (!frame) throw Failure{frame.error()};
            validate_eh_frame(frame.value().bytes);
            const auto alignment = std::max<std::uint64_t>(8, UINT64_C(1) << eh_frame->alignment);
            const auto offset = align_to(eh_frame_size, alignment);
            require(offset <= limits.max_output_bytes && eh_frame->size <= limits.max_output_bytes - offset,
                    "Merged Mach-O __eh_frame exceeds output limit", ErrorCode::resource_limit);
            mutable_object.eh_frame_section = eh_frame->ordinal;
            mutable_object.eh_frame_alignment = alignment;
            mutable_object.eh_frame_output_offset = offset;
            mutable_object.eh_frame.assign(frame.value().bytes.begin(), frame.value().bytes.end());
            eh_frame_alignment = std::max(eh_frame_alignment, alignment);
            eh_frame_size = offset + eh_frame->size;
        }
        for (const auto *section : read_only_sections) {
            require(section->file_offset && section->size <= limits.max_output_bytes && section->size <= SIZE_MAX &&
                        section->file_offset->value <= object.storage->size() &&
                        section->size <= object.storage->size() - section->file_offset->value,
                    "Mach-O object has an unbounded initialized read-only section", ErrorCode::unsupported);
            if (section->name == "__cstring") {
                auto last = object.storage->read_at({section->file_offset->value + section->size - 1}, 1);
                if (!last) throw Failure{last.error()};
                require(last.value().bytes.size() == 1 && last.value().bytes.front() == std::byte{0},
                        "Mach-O __cstring section is not NUL terminated", ErrorCode::malformed);
            }
            require(section->alignment < 63, "Mach-O read-only alignment exponent exceeds the link limit", ErrorCode::resource_limit);
            const auto alignment = UINT64_C(1) << section->alignment;
            const auto offset = align_to(const_size, alignment);
            require(offset <= limits.max_output_bytes && section->size <= limits.max_output_bytes - offset,
                    "Mach-O merged read-only sections exceed output limit", ErrorCode::resource_limit);
            auto bytes = object.storage->read_at(*section->file_offset, static_cast<std::size_t>(section->size));
            if (!bytes) throw Failure{bytes.error()};
            mutable_object.read_only.push_back({section->ordinal, alignment, offset,
                std::vector<std::byte>(bytes.value().bytes.begin(), bytes.value().bytes.end())});
            const_alignment = std::max(const_alignment, alignment);
            const_size = offset + section->size;
        }
        if (data) {
            require(data->file_offset && data->size <= limits.max_output_bytes && data->size <= SIZE_MAX &&
                        data->file_offset->value <= object.storage->size() &&
                        data->size <= object.storage->size() - data->file_offset->value,
                    "Mach-O object has an unbounded initialized __DATA,__data section", ErrorCode::unsupported);
            require(data->alignment < 63, "Mach-O data alignment exponent exceeds the link limit", ErrorCode::resource_limit);
            const auto data_section_alignment = UINT64_C(1) << data->alignment;
            const auto data_aligned = align_to(data_size, data_section_alignment);
            require(data_aligned <= limits.max_output_bytes && data->size <= limits.max_output_bytes - data_aligned,
                    "Mach-O merged data exceeds output limit", ErrorCode::resource_limit);
            mutable_object.data_section = data->ordinal;
            mutable_object.data_alignment = data_section_alignment;
            mutable_object.data_output_offset = data_aligned;
            data_alignment = std::max(data_alignment, data_section_alignment);
            data_size = data_aligned + data->size;
            auto data_source = object.storage->read_at(*data->file_offset, static_cast<std::size_t>(data->size));
            if (!data_source) throw Failure{data_source.error()};
            mutable_object.data.assign(data_source.value().bytes.begin(), data_source.value().bytes.end());
        }
        if (bss) {
            require(bss->alignment < 63, "Mach-O bss alignment exponent exceeds the link limit", ErrorCode::resource_limit);
            const auto a = UINT64_C(1) << bss->alignment, off = align_to(bss_size, a);
            require(off <= limits.max_output_bytes && bss->size <= limits.max_output_bytes - off,
                    "Mach-O merged bss exceeds output limit", ErrorCode::resource_limit);
            mutable_object.bss_section = bss->ordinal; mutable_object.bss_alignment = a;
            mutable_object.bss_output_offset = off; mutable_object.bss_contribution_size = bss->size;
            bss_alignment = std::max(bss_alignment, a); bss_size = off + bss->size;
        }
        for (const auto &symbol : metadata.symbols) {
            canceled(stop);
            if (!(symbol.type & 1) || symbol.name.empty() || symbol.state != MachOSymbolState::defined ||
                (symbol.section != text->ordinal && !read_only_contribution(mutable_object, symbol.section) &&
                 (!data || symbol.section != data->ordinal) && (!bss || symbol.section != bss->ordinal)))
                continue;
            const auto section_size = symbol.section == text->ordinal ? text->size :
                read_only_contribution(mutable_object, symbol.section) ?
                    read_only_contribution(mutable_object, symbol.section)->bytes.size() :
                data && symbol.section == data->ordinal ? data->size : bss->size;
            require(symbol.value <= section_size, "Mach-O defined symbol exceeds its source section");
            const bool weak = (symbol.descriptor & 0x0080) != 0;
            auto [at, inserted] = definitions.emplace(symbol.name, Definition{oi, &symbol, weak});
            if (!inserted) {
                require(at->second.weak && !weak, "Duplicate strong Mach-O symbol: " + symbol.name,
                        ErrorCode::conflict);
                if (at->second.weak && !weak) at->second = {oi, &symbol, false};
            }
        }
        for (const auto &row : metadata.relocations) {
            if (row.table >= metadata.relocation_tables.size())
                throw Failure{{ErrorCode::malformed, "Mach-O relocation has an invalid table identity"}};
            const auto &table = metadata.relocation_tables[row.table];
            if (table.kind == MachORelocationSource::section && bss && table.owner == bss->ordinal)
                throw Failure{{ErrorCode::unsupported, "Relocations stored in Mach-O __DATA,__bss are unsupported"}};
            if (table.kind != MachORelocationSource::section ||
                (table.owner != text->ordinal && table.owner != mutable_object.eh_frame_section && !read_only_contribution(mutable_object, table.owner) &&
                 (!data || table.owner != data->ordinal))) continue;
            if (row.auxiliary) continue;
            require(++relocations_seen <= limits.max_relocations, "Mach-O link relocation limit exceeded",
                    ErrorCode::resource_limit);
            require(row.file_place && !row.scattered && !row.auxiliary,
                    "Mach-O relocation lacks a validated primary field", ErrorCode::unsupported);
            const auto *read_only_source = read_only_contribution(mutable_object, table.owner);
            const auto source_size = table.owner == text->ordinal ? text->size : table.owner == mutable_object.eh_frame_section ? mutable_object.eh_frame.size() :
                read_only_source ? read_only_source->bytes.size() : data->size;
            if (table.owner == mutable_object.eh_frame_section) {
                require((arm64 && row.type == 0 && !row.pc_relative && (row.field_size == 4 || row.field_size == 8)) ||
                            (!arm64 && ((row.type == 0 && !row.pc_relative && (row.field_size == 4 || row.field_size == 8)) ||
                                        (row.type == 1 && row.pc_relative && row.field_size == 4))),
                        "Unsupported Mach-O __eh_frame relocation encoding", ErrorCode::unsupported);
            }
            require(row.offset <= source_size && row.field_size <= source_size - row.offset,
                    "Mach-O relocation field exceeds its source section");
            if (arm64) {
                if (row.type == 0) {
                    require(!row.pc_relative && (row.length == 2 || row.length == 3) &&
                                row.field_size == (row.length == 2 ? 4 : 8),
                            "ARM64 UNSIGNED relocation has incompatible width/flags", ErrorCode::unsupported);
                } else if (row.type == 1) {
                    require(!row.pc_relative && row.external && row.pair &&
                                (row.length == 2 || row.length == 3) &&
                                row.field_size == (row.length == 2 ? 4 : 8),
                            "ARM64 SUBTRACTOR relocation has incompatible pair or width/flags", ErrorCode::unsupported);
                } else {
                    require(row.length == 2 && row.field_size == 4,
                            "ARM64 instruction relocation must address a 32-bit instruction", ErrorCode::unsupported);
                    require((row.type == 2 || row.type == 3 || row.type == 5 || row.type == 7) == row.pc_relative,
                            "ARM64 relocation has incompatible PC-relative flag", ErrorCode::unsupported);
                    require(row.type == 2 || row.type == 3 || row.type == 4 ||
                                row.type == 5 || row.type == 6 || row.type == 7,
                            "Unsupported ARM64 Mach-O relocation type " + std::to_string(row.type), ErrorCode::unsupported);
                }
            } else {
                require(row.encoded_value && (row.field_size == 4 || row.field_size == 8),
                        "Mach-O x86-64 relocation lacks a supported field width", ErrorCode::unsupported);
                require(row.type == 0 || row.type == 1 || row.type == 2 || row.type == 5 || row.type == 6 || row.type == 7 || row.type == 8,
                        "Unsupported x86-64 Mach-O relocation type " + std::to_string(row.type), ErrorCode::unsupported);
                if (row.type == 0) require(!row.pc_relative, "UNSIGNED relocation is marked PC-relative");
                else if (row.type == 5)
                    require(!row.pc_relative && row.external && row.pair,
                            "x86-64 SUBTRACTOR relocation has incompatible pair or flags", ErrorCode::unsupported);
                else require(row.pc_relative && row.field_size == 4,
                             "PC-relative x86-64 relocation has incompatible width/flags", ErrorCode::unsupported);
            }
            relocations.push_back({oi, table.owner, row});
        }
        if (arm64) {
            for (const auto &row : metadata.relocations) {
                if (row.type != 10 || !row.auxiliary) continue;
                require(row.pair && *row.pair < metadata.relocations.size(),
                        "ARM64 ADDEND relocation has no paired primary record");
                const auto &primary = metadata.relocations[static_cast<std::size_t>(*row.pair)];
                require(primary.table == row.table && primary.type >= 3 && primary.type <= 6 &&
                            !primary.auxiliary && primary.offset == row.offset,
                        "ARM64 ADDEND must pair with PAGE21/PAGEOFF12 or GOT_LOAD_PAGE21/GOT_LOAD_PAGEOFF12 at the same offset",
                        ErrorCode::unsupported);
            }
        }
    }
    std::vector<GotEntry> got_entries;
    std::map<std::tuple<std::size_t, std::uint32_t, std::uint64_t, std::int64_t>, std::size_t> got_indices;
    const auto got_symbol_target = [&](std::size_t object_index, const MachORelocation &row) {
        require(object_index < objects.size() && row.table < objects[object_index].metadata.relocation_tables.size(),
                "Mach-O GOT relocation has an invalid table", ErrorCode::malformed);
        const auto &object = objects[object_index];
        const auto &table = object.metadata.relocation_tables[row.table];
        require(row.external && table.symbol_table.has_value(),
                "ARM64 GOT relocation must reference an external symbol", ErrorCode::unsupported);
        const auto symbol = std::find_if(object.metadata.symbols.begin(), object.metadata.symbols.end(), [&](const auto &s) {
            return s.table_command == *table.symbol_table && s.index == row.symbol_number;
        });
        require(symbol != object.metadata.symbols.end(), "ARM64 GOT relocation references an unknown symbol", ErrorCode::malformed);
        const auto supported = [&](const Object &target_object, const MachOSymbol &target_symbol) {
            return target_symbol.state == MachOSymbolState::defined &&
                (target_symbol.section == target_object.text_section || read_only_contribution(target_object, target_symbol.section) ||
                 (target_object.data_section && target_symbol.section == target_object.data_section) ||
                 (target_object.bss_section && target_symbol.section == target_object.bss_section));
        };
        const auto definition = definitions.find(symbol->name);
        require(definition != definitions.end() && supported(objects[definition->second.object], *definition->second.symbol),
                "ARM64 GOT symbol is unresolved or outside supported output sections: " + symbol->name,
                ErrorCode::unsupported);
        return std::tuple{definition->second.object, definition->second.symbol->section,
                          definition->second.symbol->value};
    };
    for (auto &relocation : relocations) {
        const auto type = relocation.row.type;
        if (!arm64 || (type != 5 && type != 6 && type != 7)) continue;
        std::int64_t addend = 0;
        if (type == 5 || type == 6) {
            if (relocation.row.pair) {
                require(*relocation.row.pair < objects[relocation.object].metadata.relocations.size(),
                        "ARM64 GOT relocation has an invalid ADDEND pair", ErrorCode::malformed);
                const auto &companion = objects[relocation.object].metadata.relocations[
                    static_cast<std::size_t>(*relocation.row.pair)];
                if (companion.type == 10 && companion.auxiliary)
                    addend = sign_extend_bits(companion.symbol_number, 24);
            }
        }
        const auto [target_object, target_section, target_value] = got_symbol_target(relocation.object, relocation.row);
        const auto key = std::tuple{target_object, target_section, target_value, addend};
        auto [found, inserted] = got_indices.emplace(key, got_entries.size());
        if (inserted) {
            require(got_entries.size() < limits.max_relocations,
                    "ARM64 synthesized GOT exceeds relocation limit", ErrorCode::resource_limit);
            got_entries.push_back({target_object, target_section, target_value, 0, addend});
        }
        relocation.got_entry = found->second;
    }
    if (arm64) {
        std::map<std::tuple<std::size_t, std::uint32_t, std::uint32_t>, const Relocation *> got_pages;
        for (const auto &relocation : relocations) {
            if (relocation.row.type != 5) continue;
            const auto key = std::tuple{relocation.object, relocation.source_section, relocation.row.offset};
            require(got_pages.emplace(key, &relocation).second,
                    "ARM64 GOT_LOAD_PAGE21 relocation is ambiguous at one instruction", ErrorCode::unsupported);
        }
        for (const auto &relocation : relocations) {
            if (relocation.row.type != 6) continue;
            const auto &object = objects[relocation.object];
            require(relocation.row.offset >= 4, "ARM64 GOT_LOAD_PAGEOFF12 has no preceding PAGE21",
                    ErrorCode::unsupported);
            const auto page_key = std::tuple{relocation.object, relocation.source_section,
                                             relocation.row.offset - 4};
            const auto page = got_pages.find(page_key);
            require(page != got_pages.end() && page->second->got_entry == relocation.got_entry,
                    "ARM64 GOT_LOAD_PAGEOFF12 must immediately follow a PAGE21 relocation to the same symbol/addend",
                    ErrorCode::unsupported);
            auto page_bytes = object.storage->read_at(*page->second->row.file_place, 4);
            auto load_bytes = object.storage->read_at(*relocation.row.file_place, 4);
            if (!page_bytes) throw Failure{page_bytes.error()};
            if (!load_bytes) throw Failure{load_bytes.error()};
            const auto instruction = [](std::span<const std::byte> bytes) {
                std::uint32_t value = 0;
                for (std::size_t i = 0; i < 4; ++i)
                    value |= std::to_integer<std::uint32_t>(bytes[i]) << (i * 8);
                return value;
            };
            require((instruction(page_bytes.value().bytes) & 31u) ==
                        ((instruction(load_bytes.value().bytes) >> 5) & 31u),
                    "ARM64 GOT_LOAD_PAGEOFF12 base register does not match adjacent PAGE21 destination",
                    ErrorCode::unsupported);
        }
    }
    for (auto &got : got_entries) {
        const auto offset = align_to(const_size, 8);
        require(offset <= limits.max_output_bytes && 8 <= limits.max_output_bytes - offset,
                "ARM64 synthesized GOT exceeds output limit", ErrorCode::resource_limit);
        got.output_offset = offset;
        const_size = offset + 8;
        const_alignment = std::max<std::uint64_t>(const_alignment, 8);
    }
    require(code_size <= limits.max_output_bytes, "Mach-O merged text exceeds output limit", ErrorCode::resource_limit);
    require(code_size <= SIZE_MAX, "Mach-O merged text exceeds addressable memory", ErrorCode::resource_limit);
    require(const_size <= limits.max_output_bytes && const_size <= SIZE_MAX && bss_size <= limits.max_output_bytes &&
                bss_size <= SIZE_MAX && data_size <= limits.max_output_bytes && data_size <= SIZE_MAX,
            "Mach-O merged data exceeds output limit", ErrorCode::resource_limit);
    auto entry_found = definitions.find(entry);
    require(entry_found != definitions.end(), "Mach-O executable entry symbol is undefined: " + std::string(entry),
            ErrorCode::invalid_argument);
    constexpr std::uint32_t lc_segment_64 = 0x19, lc_symtab = 0x2, lc_unixthread = 0x5;
    constexpr std::size_t header_size = 32, const_segment_command_size = 152, data_segment_command_size = 312;
    const std::size_t text_segment_command_size = eh_frame_size ? 232 : 152;
    constexpr std::size_t symtab_command_size = 24;
    const std::size_t thread_command_size = arm64 ? 288 : 184;
    constexpr std::size_t nlist_size = 16;
    const std::uint64_t page_size = arm64 ? 0x4000 : 0x1000;
    constexpr std::uint64_t stack_size = 0x10000;
    require((base & (page_size - 1)) == 0, "Mach-O image base must be page aligned", ErrorCode::invalid_argument);
    const auto commands_end = header_size + text_segment_command_size + const_segment_command_size + data_segment_command_size +
                              symtab_command_size + thread_command_size;
    const auto code_file_offset_u64 = align_to(commands_end, std::max(page_size, code_alignment));
    require(code_file_offset_u64 <= SIZE_MAX, "Mach-O header alignment exceeds addressable memory",
            ErrorCode::resource_limit);
    const auto code_file_offset = static_cast<std::size_t>(code_file_offset_u64);
    require(code_file_offset <= limits.max_output_bytes,
            "Mach-O text alignment pushes headers beyond configured output limit", ErrorCode::resource_limit);
    require(base <= max_user_address && code_file_offset <= max_user_address - base,
            "Mach-O code base exceeds the supported architecture user address range", ErrorCode::unsupported);
    const auto code_base = base + code_file_offset;
    require(code_base <= max_user_address && code_size <= max_user_address - code_base,
            "Mach-O code mapping exceeds the supported architecture user address range", ErrorCode::unsupported);
    require(code_size <= SIZE_MAX - code_file_offset,
            "Mach-O output offsets overflow addressable memory", ErrorCode::resource_limit);
    const auto eh_frame_file_offset_u64 = align_to(code_file_offset_u64 + code_size, eh_frame_alignment);
    const auto eh_frame_address = base + eh_frame_file_offset_u64;
    require(eh_frame_file_offset_u64 <= UINT32_MAX,
            "Mach-O __eh_frame file offset exceeds its section-header field", ErrorCode::resource_limit);
    const auto const_file_offset_u64 = align_to(eh_frame_file_offset_u64 + eh_frame_size, std::max(page_size, const_alignment));
    require(const_file_offset_u64 <= SIZE_MAX && const_file_offset_u64 <= max_user_address - base,
            "Mach-O const offset exceeds supported range", ErrorCode::resource_limit);
    const auto const_file_offset = static_cast<std::size_t>(const_file_offset_u64);
    const auto const_address = base + const_file_offset_u64;
    require(const_size <= SIZE_MAX - const_file_offset,
            "Mach-O output offsets overflow addressable memory", ErrorCode::resource_limit);
    const auto preliminary_symoff = const_file_offset + static_cast<std::size_t>(const_size);
    require(preliminary_symoff <= UINT32_MAX && definitions.size() <= UINT32_MAX &&
                definitions.size() <= (SIZE_MAX - preliminary_symoff) / nlist_size,
            "Mach-O symbol table exceeds output field limits", ErrorCode::resource_limit);
    const auto preliminary_strtab = preliminary_symoff + definitions.size() * nlist_size;
    std::size_t preliminary_string_bytes = 1;
    for (const auto &[name, unused] : definitions) {
        (void)unused;
        require(name.size() < SIZE_MAX - preliminary_string_bytes,
                "Mach-O string table exceeds addressable memory", ErrorCode::resource_limit);
        preliminary_string_bytes += name.size() + 1;
    }
    require(preliminary_strtab <= SIZE_MAX - preliminary_string_bytes,
            "Mach-O output offsets overflow addressable memory", ErrorCode::resource_limit);
    const auto preliminary_text_end = preliminary_strtab + preliminary_string_bytes;
    require(base <= max_user_address && preliminary_text_end <= max_user_address - base,
            "Mach-O text and symbol mapping exceeds the supported user address range", ErrorCode::unsupported);
    const auto data_address = align_to(base + preliminary_text_end, std::max({page_size, data_alignment, bss_alignment}));
    require(data_address >= base, "Mach-O initialized data address underflows the image base", ErrorCode::resource_limit);
    require(data_address <= max_user_address && data_size <= max_user_address - data_address,
            "Mach-O initialized data mapping exceeds the supported user address range", ErrorCode::unsupported);
    const auto data_file_offset_u64 = data_address - base;
    require(data_file_offset_u64 <= SIZE_MAX && data_file_offset_u64 <= limits.max_output_bytes,
            "Mach-O initialized data offset exceeds configured output limit", ErrorCode::resource_limit);
    const auto data_file_offset = static_cast<std::size_t>(data_file_offset_u64);
    require(data_address <= UINT64_MAX - data_size, "Mach-O initialized data address overflows", ErrorCode::resource_limit);
    const auto bss_address = align_to(data_address + data_size, bss_alignment);
    require(bss_address <= UINT64_MAX - bss_size, "Mach-O bss address overflows", ErrorCode::resource_limit);
    const auto stack_address = align_to(bss_address + bss_size, 16);
    const auto &entry_object = objects[entry_found->second.object];
    const auto entry_section = std::find_if(entry_object.metadata.sections.begin(), entry_object.metadata.sections.end(),
        [&](const auto &section) { return section.ordinal == entry_found->second.symbol->section; });
    require(entry_found->second.symbol->section == entry_object.text_section &&
                entry_section != entry_object.metadata.sections.end() &&
                entry_found->second.symbol->value < entry_section->size,
            "Mach-O entry symbol must lie inside a supported __text section", ErrorCode::malformed);
    const auto entry_address = code_base + entry_object.output_offset + entry_found->second.symbol->value;
    std::vector<std::byte> code(static_cast<std::size_t>(code_size));
    std::vector<std::byte> eh_frame_bytes(static_cast<std::size_t>(eh_frame_size));
    std::vector<std::byte> constants(static_cast<std::size_t>(const_size));
    std::vector<std::byte> data(static_cast<std::size_t>(data_size));
    for (const auto &object : objects) {
        std::copy(object.text.begin(), object.text.end(), code.begin() + static_cast<std::ptrdiff_t>(object.output_offset));
        if (!object.eh_frame.empty())
            std::copy(object.eh_frame.begin(), object.eh_frame.end(), eh_frame_bytes.begin() + static_cast<std::ptrdiff_t>(object.eh_frame_output_offset));
        for (const auto &contribution : object.read_only)
            std::copy(contribution.bytes.begin(), contribution.bytes.end(),
                      constants.begin() + static_cast<std::ptrdiff_t>(contribution.output_offset));
        if (!object.data.empty())
            std::copy(object.data.begin(), object.data.end(), data.begin() + static_cast<std::ptrdiff_t>(object.data_output_offset));
    }
    auto linked_address = [&](std::size_t object_index, std::uint32_t section_ordinal, std::uint64_t value) {
        require(object_index < objects.size(), "Mach-O relocation references an invalid object", ErrorCode::malformed);
        const auto &object = objects[object_index];
        if (section_ordinal == object.text_section) {
            require(value <= object.text.size(), "Mach-O text symbol exceeds its contribution", ErrorCode::malformed);
            return code_base + object.output_offset + value;
        }
        if (const auto *contribution = read_only_contribution(object, section_ordinal)) {
            require(value <= contribution->bytes.size(), "Mach-O read-only symbol exceeds its contribution", ErrorCode::malformed);
            return const_address + contribution->output_offset + value;
        }
        if (object.data_section && section_ordinal == object.data_section) {
            require(value <= object.data.size(), "Mach-O data symbol exceeds its contribution", ErrorCode::malformed);
            return data_address + object.data_output_offset + value;
        }
        if (object.bss_section && section_ordinal == object.bss_section) {
            require(value <= object.bss_contribution_size, "Mach-O bss symbol exceeds its contribution", ErrorCode::malformed);
            return bss_address + object.bss_output_offset + value;
        }
        if (object.eh_frame_section && section_ordinal == object.eh_frame_section) {
            require(value <= object.eh_frame.size(), "Mach-O eh_frame symbol exceeds its contribution", ErrorCode::malformed);
            return eh_frame_address + object.eh_frame_output_offset + value;
        }
        throw Failure{{ErrorCode::unsupported, "Mach-O symbol or relocation target is outside supported output sections"}};
    };
    for (const auto &got : got_entries) {
        const auto value = add_signed(linked_address(got.object, got.section, got.value), got.addend);
        require(value <= max_user_address, "ARM64 GOT symbol plus addend exceeds supported user address range",
                ErrorCode::unsupported);
        put(constants, static_cast<std::size_t>(got.output_offset), value, 8);
    }
    const auto relocation_target = [&](std::size_t object_index, const MachORelocation &symbol_row) {
        require(object_index < objects.size() && symbol_row.table < objects[object_index].metadata.relocation_tables.size(),
                "Mach-O relocation symbol has an invalid table", ErrorCode::malformed);
        const auto &object = objects[object_index];
        if (!symbol_row.external)
            return linked_address(object_index, symbol_row.symbol_number, 0);
        const auto &table = object.metadata.relocation_tables[symbol_row.table];
        require(table.symbol_table.has_value(), "External Mach-O relocation has no symbol-table command");
        const auto symbol = std::find_if(object.metadata.symbols.begin(), object.metadata.symbols.end(), [&](const auto &s) {
            return s.table_command == *table.symbol_table && s.index == symbol_row.symbol_number;
        });
        require(symbol != object.metadata.symbols.end(),
                "Mach-O relocation references an unknown symbol-table index", ErrorCode::malformed);
        if (symbol->state == MachOSymbolState::defined &&
            (symbol->section == object.text_section || read_only_contribution(object, symbol->section) ||
             (object.data_section && symbol->section == object.data_section) ||
             (object.bss_section && symbol->section == object.bss_section)))
            return linked_address(object_index, symbol->section, symbol->value);
        const auto definition = definitions.find(symbol->name);
        require(definition != definitions.end(), "Mach-O relocation symbol is unresolved or unsupported: " + symbol->name,
                ErrorCode::unsupported);
        return linked_address(definition->second.object, definition->second.symbol->section,
                              definition->second.symbol->value);
    };
    for (const auto &reloc : relocations) {
        canceled(stop);
        const auto &object = objects[reloc.object];
        const auto &row = reloc.row;
        const bool source_text = reloc.source_section == object.text_section;
        const bool source_eh_frame = object.eh_frame_section && reloc.source_section == object.eh_frame_section;
        const auto *read_only_source = read_only_contribution(object, reloc.source_section);
        const bool source_const = read_only_source != nullptr;
        const bool source_data = object.data_section && reloc.source_section == object.data_section;
        require(source_text || source_eh_frame || source_const || source_data,
                "Mach-O relocation source is outside file-backed merged sections", ErrorCode::unsupported);
        auto &source_bytes = source_text ? code : source_eh_frame ? eh_frame_bytes : source_const ? constants : data;
        const auto source_offset = source_text ? object.output_offset : source_eh_frame ? object.eh_frame_output_offset : source_const ? read_only_source->output_offset : object.data_output_offset;
        const auto source_base = source_text ? code_base + object.output_offset : source_eh_frame ? eh_frame_address + object.eh_frame_output_offset : source_const ? const_address + read_only_source->output_offset : data_address + object.data_output_offset;
        const auto place = source_base + row.offset;
        const auto field_at = static_cast<std::size_t>(source_offset + row.offset);
        std::uint64_t relocation_bits = 0;
        if (arm64) {
            auto field = object.storage->read_at(*row.file_place, row.field_size);
            if (!field) throw Failure{field.error()};
            require(field.value().bytes.size() == row.field_size, "ARM64 Mach-O relocation field is truncated");
            for (std::size_t byte = 0; byte < row.field_size; ++byte)
                relocation_bits |= std::to_integer<std::uint64_t>(field.value().bytes[byte]) << (byte * 8);
        } else {
            require(row.encoded_value.has_value(), "x86-64 Mach-O relocation lost its encoded addend", ErrorCode::malformed);
            relocation_bits = *row.encoded_value;
        }
        const auto addend = arm64 ? std::int64_t{0} : sign_extend(relocation_bits, row.field_size);
        const auto target = relocation_target(reloc.object, row);
        if (row.kind == MachORelocationKind::subtractor) {
            require(row.pair && *row.pair < object.metadata.relocations.size(),
                    "Mach-O SUBTRACTOR relocation has an invalid UNSIGNED pair", ErrorCode::malformed);
            const auto &unsigned_row = object.metadata.relocations[static_cast<std::size_t>(*row.pair)];
            require(unsigned_row.auxiliary && unsigned_row.kind == MachORelocationKind::absolute &&
                        unsigned_row.table == row.table && unsigned_row.offset == row.offset &&
                        unsigned_row.field_size == row.field_size && unsigned_row.file_place == row.file_place,
                    "Mach-O SUBTRACTOR relocation has a mismatched UNSIGNED pair", ErrorCode::malformed);
            const auto minuend = relocation_target(reloc.object, unsigned_row);
            const auto subtrahend = target;
            auto value = difference(minuend, subtrahend);
            const auto subtractor_addend = sign_extend(relocation_bits, row.field_size);
            require((subtractor_addend >= 0 && value <= INT64_MAX - subtractor_addend) ||
                        (subtractor_addend < 0 && value >= INT64_MIN - subtractor_addend),
                    "Mach-O SUBTRACTOR result overflows", ErrorCode::unsupported);
            value += subtractor_addend;
            if (row.field_size == 4) {
                require(value >= INT32_MIN && value <= INT32_MAX,
                        "Mach-O 32-bit SUBTRACTOR result overflows", ErrorCode::unsupported);
                put(source_bytes, field_at, static_cast<std::uint32_t>(static_cast<std::int32_t>(value)), 4);
            } else {
                put(source_bytes, field_at, std::bit_cast<std::uint64_t>(value), 8);
            }
            continue;
        }
        if (arm64 && (row.type == 5 || row.type == 6 || row.type == 7)) {
            require(reloc.got_entry && *reloc.got_entry < got_entries.size(),
                    "ARM64 GOT relocation has no synthesized slot", ErrorCode::malformed);
            const auto got_address = const_address + got_entries[*reloc.got_entry].output_offset;
            if (row.type == 5 || row.type == 6) {
                require(relocation_bits <= UINT32_MAX,
                        "ARM64 GOT instruction relocation field exceeds 32 bits", ErrorCode::malformed);
                const auto relocated = apply_arm64_relocation(row.type == 5 ? 3 : 6,
                    static_cast<std::uint32_t>(relocation_bits), got_address, place, std::nullopt);
                put(source_bytes, field_at, relocated, 4);
            } else {
                const auto implicit_addend = sign_extend(relocation_bits, 4);
                auto value = difference(got_address, place);
                require((implicit_addend >= 0 && value <= INT64_MAX - implicit_addend) ||
                            (implicit_addend < 0 && value >= INT64_MIN - implicit_addend),
                        "ARM64 POINTER_TO_GOT relocation overflows", ErrorCode::unsupported);
                value += implicit_addend;
                require(value >= INT32_MIN && value <= INT32_MAX,
                        "ARM64 POINTER_TO_GOT relocation is out of 32-bit PC-relative range", ErrorCode::unsupported);
                put(source_bytes, field_at, static_cast<std::uint32_t>(static_cast<std::int32_t>(value)), 4);
            }
            continue;
        }
        if (arm64 && row.type == 0) {
            std::uint64_t value = 0;
            if (row.length == 2) {
                value = add_signed(target, sign_extend(relocation_bits, 4));
            } else {
                require(target <= UINT64_MAX - relocation_bits, "ARM64 Mach-O UNSIGNED relocation overflows",
                        ErrorCode::unsupported);
                value = target + relocation_bits;
            }
            put(source_bytes, field_at, value, row.field_size);
        } else if (arm64) {
            std::optional<std::int64_t> explicit_addend;
            if (row.pair) {
                require(*row.pair < object.metadata.relocations.size(), "ARM64 Mach-O relocation pair is invalid");
                const auto &paired = object.metadata.relocations[static_cast<std::size_t>(*row.pair)];
                if (paired.type == 10 && paired.auxiliary)
                    explicit_addend = sign_extend_bits(paired.symbol_number, 24);
            }
            require(relocation_bits <= UINT32_MAX, "ARM64 instruction relocation field exceeds 32 bits", ErrorCode::malformed);
            const auto relocated = apply_arm64_relocation(row.type, static_cast<std::uint32_t>(relocation_bits),
                                                          target, place, explicit_addend);
            put(source_bytes, field_at, relocated, 4);
        } else if (row.type == 0) {
            require(target <= UINT64_MAX - relocation_bits, "Mach-O UNSIGNED relocation overflows",
                    ErrorCode::unsupported);
            const auto value = target + relocation_bits;
            if (row.field_size == 4)
                require(value <= UINT32_MAX, "Mach-O UNSIGNED 32-bit relocation overflows", ErrorCode::unsupported);
            put(source_bytes, field_at, value, row.field_size);
        } else {
            auto value = difference(target, place);
            const auto correction = row.type == 6 ? 1 : row.type == 7 ? 2 : row.type == 8 ? 4 : 0;
            require(addend >= INT64_MIN + correction, "Mach-O relocation addend underflows", ErrorCode::unsupported);
            const auto delta = addend - correction;
            if (delta >= 0)
                require(value <= INT64_MAX - delta, "Mach-O PC-relative relocation overflows", ErrorCode::unsupported);
            else
                require(value >= INT64_MIN - delta, "Mach-O PC-relative relocation underflows", ErrorCode::unsupported);
            value += delta;
            require(value >= INT32_MIN && value <= INT32_MAX, "Mach-O PC-relative relocation overflows",
                    ErrorCode::unsupported);
            put(source_bytes, field_at, static_cast<std::uint32_t>(value), 4);
        }
    }

    std::vector<OutputSymbol> output_symbols;
    for (const auto &[name, definition] : definitions) {
        if (definition.object >= objects.size()) continue;
        const auto &object = objects[definition.object];
        const auto section_index = definition.symbol->section == object.text_section ? 1 :
            read_only_contribution(object, definition.symbol->section) ? 2 :
            definition.symbol->section == object.data_section ? 3 : 4;
        output_symbols.push_back({name, linked_address(definition.object, definition.symbol->section,
                                                       definition.symbol->value),
                                  definition.symbol->descriptor, static_cast<std::uint8_t>(section_index)});
    }
    std::sort(output_symbols.begin(), output_symbols.end(), [](const auto &a, const auto &b) { return a.name < b.name; });
    require(constants.size() <= SIZE_MAX - const_file_offset, "Mach-O output offsets overflow addressable memory",
            ErrorCode::resource_limit);
    const auto symoff = const_file_offset + constants.size();
    require(symoff <= UINT32_MAX, "Mach-O symbol table offset exceeds LC_SYMTAB fields", ErrorCode::resource_limit);
    require(symoff <= limits.max_output_bytes &&
                output_symbols.size() <= (limits.max_output_bytes - symoff) / nlist_size,
            "Mach-O output symbol table exceeds output limit", ErrorCode::resource_limit);
    require(output_symbols.size() <= UINT32_MAX, "Mach-O symbol count exceeds LC_SYMTAB fields", ErrorCode::resource_limit);
    require(output_symbols.size() <= (SIZE_MAX - symoff) / nlist_size,
            "Mach-O symbol table exceeds addressable memory", ErrorCode::resource_limit);
    const auto strtab_offset = symoff + output_symbols.size() * nlist_size;
    std::vector<std::byte> strings{std::byte{0}};
    std::vector<std::uint32_t> string_offsets;
    for (const auto &symbol : output_symbols) {
        require(strings.size() <= UINT32_MAX && symbol.name.size() <= UINT32_MAX - strings.size(),
                "Mach-O output symbol name table overflows",
                ErrorCode::resource_limit);
        string_offsets.push_back(static_cast<std::uint32_t>(strings.size()));
        for (const auto ch : symbol.name) strings.push_back(static_cast<std::byte>(static_cast<unsigned char>(ch)));
        strings.push_back(std::byte{0});
    }
    require(strtab_offset <= limits.max_output_bytes && strings.size() <= limits.max_output_bytes - strtab_offset,
            "Mach-O linked output exceeds configured limit", ErrorCode::resource_limit);
    require(strtab_offset <= UINT32_MAX && strings.size() <= UINT32_MAX - strtab_offset,
            "Mach-O string table exceeds 32-bit LC_SYMTAB offsets", ErrorCode::resource_limit);
    require(strtab_offset <= SIZE_MAX && strings.size() <= SIZE_MAX - strtab_offset,
            "Mach-O string table offsets overflow addressable memory", ErrorCode::resource_limit);
    const auto text_file_size = strtab_offset + strings.size();
    require(base + text_file_size <= data_address && data_address == base + data_file_offset_u64,
            "Mach-O initialized-data address no longer matches its layout", ErrorCode::malformed);
    require(data_size <= SIZE_MAX - data_file_offset && data_file_offset <= limits.max_output_bytes &&
                data_size <= limits.max_output_bytes - data_file_offset,
            "Mach-O initialized data exceeds configured output limits", ErrorCode::resource_limit);
    std::vector<std::byte> output(data_file_offset + static_cast<std::size_t>(data_size));
    require(data_address <= max_user_address && data_size <= max_user_address - data_address,
            "Mach-O initialized data mapping exceeds the supported user address range", ErrorCode::unsupported);
    require(bss_address <= max_user_address && bss_size <= max_user_address - bss_address &&
                stack_address <= max_user_address && stack_size <= max_user_address - stack_address,
            "Mach-O output mapping exceeds the supported x86-64 user address range", ErrorCode::unsupported);
    std::copy(code.begin(), code.end(), output.begin() + static_cast<std::ptrdiff_t>(code_file_offset));
    if (!eh_frame_bytes.empty())
        std::copy(eh_frame_bytes.begin(), eh_frame_bytes.end(), output.begin() + static_cast<std::ptrdiff_t>(static_cast<std::size_t>(eh_frame_file_offset_u64)));
    if (!constants.empty()) std::copy(constants.begin(), constants.end(), output.begin() + static_cast<std::ptrdiff_t>(const_file_offset));
    if (!data.empty()) std::copy(data.begin(), data.end(), output.begin() + static_cast<std::ptrdiff_t>(data_file_offset));
    put(output, 0, 0xfeedfacf, 4); put(output, 4, cpu_type, 4); put(output, 8, arm64 ? 0 : 3, 4);
    put(output, 12, 2, 4); put(output, 16, 5, 4);
    put(output, 20, text_segment_command_size + const_segment_command_size + data_segment_command_size + symtab_command_size + thread_command_size, 4);
    put(output, 24, 1, 4); put(output, 28, 0, 4);
    std::size_t command = header_size;
    put(output, command, lc_segment_64, 4); put(output, command + 4, text_segment_command_size, 4);
    std::memcpy(output.data() + command + 8, "__TEXT", 6);
    put(output, command + 24, base, 8); put(output, command + 32, eh_frame_size ? const_file_offset - code_file_offset : code_file_offset + code_size, 8);
    put(output, command + 40, 0, 8); put(output, command + 48, eh_frame_size ? const_file_offset - code_file_offset : code_file_offset + code_size, 8);
    put(output, command + 56, 5, 4); put(output, command + 60, 5, 4); put(output, command + 64, eh_frame_size ? 2 : 1, 4);
    const auto section = command + 72;
    std::memcpy(output.data() + section, "__text", 6); std::memcpy(output.data() + section + 16, "__TEXT", 6);
    put(output, section + 32, base + code_file_offset, 8); put(output, section + 40, code_size, 8);
    put(output, section + 48, code_file_offset, 4); put(output, section + 52, std::countr_zero(code_alignment), 4);
    put(output, section + 64, 0x80000400, 4);
    if (eh_frame_size) {
        const auto eh_section = section + 80;
        std::memcpy(output.data() + eh_section, "__eh_frame", 10);
        std::memcpy(output.data() + eh_section + 16, "__TEXT", 6);
        put(output, eh_section + 32, eh_frame_address, 8); put(output, eh_section + 40, eh_frame_size, 8);
        put(output, eh_section + 48, eh_frame_file_offset_u64, 4);
        put(output, eh_section + 52, std::countr_zero(eh_frame_alignment), 4);
        put(output, eh_section + 64, 0, 4);
    }
    command += text_segment_command_size;
    put(output, command, lc_segment_64, 4); put(output, command + 4, const_segment_command_size, 4);
    std::memcpy(output.data() + command + 8, "__CONST", 7);
    put(output, command + 24, const_address, 8); put(output, command + 32, const_size, 8);
    put(output, command + 40, const_file_offset, 8); put(output, command + 48, const_size, 8);
    put(output, command + 56, 1, 4); put(output, command + 60, 1, 4); put(output, command + 64, 1, 4);
    const auto const_section_command = command + 72;
    std::memcpy(output.data() + const_section_command, "__const", 7); std::memcpy(output.data() + const_section_command + 16, "__CONST", 7);
    put(output, const_section_command + 32, const_address, 8); put(output, const_section_command + 40, const_size, 8);
    put(output, const_section_command + 48, const_file_offset, 4); put(output, const_section_command + 52, std::countr_zero(const_alignment), 4);
    command += const_segment_command_size;
    put(output, command, lc_segment_64, 4); put(output, command + 4, data_segment_command_size, 4);
    std::memcpy(output.data() + command + 8, "__DATA", 6);
    put(output, command + 24, data_address, 8);
    put(output, command + 32, stack_address + stack_size - data_address, 8);
    put(output, command + 40, data_file_offset, 8); put(output, command + 48, data.size(), 8);
    put(output, command + 56, 7, 4); put(output, command + 60, 3, 4); put(output, command + 64, 1, 4);
    put(output, command + 68, 3, 4);
    const auto data_section = command + 72;
    std::memcpy(output.data() + data_section, "__data", 6); std::memcpy(output.data() + data_section + 16, "__DATA", 6);
    put(output, data_section + 32, data_address, 8); put(output, data_section + 40, data.size(), 8);
    put(output, data_section + 48, data_file_offset, 4); put(output, data_section + 52, std::countr_zero(data_alignment), 4);
    put(output, data_section + 64, 0, 4);
    const auto bss_section = command + 152;
    std::memcpy(output.data() + bss_section, "__bss", 5); std::memcpy(output.data() + bss_section + 16, "__DATA", 6);
    put(output, bss_section + 32, bss_address, 8); put(output, bss_section + 40, bss_size, 8);
    put(output, bss_section + 48, 0, 4); put(output, bss_section + 52, std::countr_zero(bss_alignment), 4);
    put(output, bss_section + 64, 1, 4);
    const auto stack_section = command + 232;
    std::memcpy(output.data() + stack_section, "__stack", 7); std::memcpy(output.data() + stack_section + 16, "__DATA", 6);
    put(output, stack_section + 32, stack_address, 8); put(output, stack_section + 40, stack_size, 8);
    put(output, stack_section + 48, 0, 4); put(output, stack_section + 52, 4, 4); put(output, stack_section + 64, 1, 4);
    command += data_segment_command_size;
    put(output, command, lc_symtab, 4); put(output, command + 4, symtab_command_size, 4);
    put(output, command + 8, symoff, 4); put(output, command + 12, output_symbols.size(), 4);
    put(output, command + 16, strtab_offset, 4); put(output, command + 20, strings.size(), 4);
    command += symtab_command_size;
    put(output, command, lc_unixthread, 4); put(output, command + 4, thread_command_size, 4);
    put(output, command + 8, arm64 ? 6 : 4, 4);
    put(output, command + 12, arm64 ? 68 : 42, 4);
    if (arm64) {
        // ARM_THREAD_STATE64: x0-x28, fp, lr, sp, pc, cpsr, pad.
        put(output, command + 16 + 248, stack_address + stack_size - 16, 8);
        put(output, command + 16 + 256, entry_address, 8);
    } else {
        put(output, command + 16 + 56, stack_address + stack_size - 16, 8);
        put(output, command + 16 + 128, entry_address, 8);
        put(output, command + 16 + 136, 0x202, 8);
        put(output, command + 16 + 144, 0x2b, 8);
    }
    for (std::size_t i = 0; i < output_symbols.size(); ++i) {
        const auto at = symoff + i * nlist_size;
        put(output, at, string_offsets[i], 4); put(output, at + 4, 0x0f, 1); put(output, at + 5, output_symbols[i].section, 1);
        put(output, at + 6, output_symbols[i].descriptor & 0x0080 ? 0x0080 : 0, 2);
        put(output, at + 8, output_symbols[i].value, 8);
    }
    std::copy(strings.begin(), strings.end(), output.begin() + static_cast<std::ptrdiff_t>(strtab_offset));
    return output;
}
} // namespace

Result<std::vector<std::byte>> link_macho64_executable(
    std::span<const std::shared_ptr<const ByteStorage>> inputs, std::string_view entry_symbol,
    std::uint64_t base_address, std::stop_token stop, MachOLinkLimits limits) {
    try {
        require(!inputs.empty() && inputs.size() <= limits.max_objects, "Mach-O input object count is outside configured limits",
                ErrorCode::resource_limit);
        require(!entry_symbol.empty(), "Mach-O executable entry symbol cannot be empty", ErrorCode::invalid_argument);
        std::vector<Object> objects;
        objects.reserve(inputs.size());
        for (const auto &input : inputs) {
            canceled(stop);
            require(bool(input), "Mach-O link input is null");
            MachOOptions options;
            auto loaded = load_macho(input, options, stop);
            if (!loaded) throw Failure{loaded.error()};
            require(loaded.value().metadata.macho.has_value(), "Mach-O link input has no Mach-O metadata");
            require(loaded.value().metadata.macho->container.slices.size() == 1,
                    "Universal Mach-O inputs are outside the static link subset", ErrorCode::unsupported);
            objects.push_back({input, *loaded.value().metadata.macho});
        }
        return build(objects, entry_symbol, base_address, stop, limits);
    } catch (const Failure &failure) { return failure.error; }
      catch (const std::bad_alloc &) { return Error{ErrorCode::resource_limit, "Cannot allocate linked Mach-O output"}; }
      catch (const std::length_error &) { return Error{ErrorCode::resource_limit, "Mach-O linked output exceeds allocation limits"}; }
}

Result<std::vector<std::byte>> link_macho64_x86_64_executable(
    std::span<const std::shared_ptr<const ByteStorage>> inputs, std::string_view entry_symbol,
    std::uint64_t base_address, std::stop_token stop, MachOLinkLimits limits) {
    return link_macho64_executable(inputs, entry_symbol, base_address, stop, limits);
}

} // namespace hexlab
