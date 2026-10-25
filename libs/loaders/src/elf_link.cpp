#include "hexlab/loaders/elf_link.hpp"
#include "hexlab/loaders/elf.hpp"
#include "hexlab/image/elf_metadata.hpp"
#include <algorithm>
#include <cstring>
#include <limits>
#include <map>
#include <string_view>

namespace hexlab {
namespace {
struct Failure { Error error; };
void require(bool ok, std::string_view message, ErrorCode code = ErrorCode::malformed) {
    if (!ok) throw Failure{{code, std::string(message)}};
}
void canceled(std::stop_token stop) {
    require(!stop.stop_requested(), "ELF link canceled", ErrorCode::canceled);
}
std::uint64_t align_up(std::uint64_t value, std::uint64_t alignment) {
    require(alignment && (alignment & (alignment - 1)) == 0, "ELF section alignment must be a power of two");
    require(value <= UINT64_MAX - (alignment - 1), "ELF output alignment overflows", ErrorCode::resource_limit);
    return (value + alignment - 1) & ~(alignment - 1);
}
void put(std::vector<std::byte> &out, std::size_t at, std::uint64_t value, std::size_t width) {
    require(at <= out.size() && width <= out.size() - at, "ELF output field exceeds output extent", ErrorCode::resource_limit);
    for (std::size_t i = 0; i < width; ++i) out[at + i] = static_cast<std::byte>((value >> (8 * i)) & 0xff);
}
std::uint64_t read_le(std::span<const std::byte> bytes) {
    std::uint64_t value = 0;
    for (std::size_t i = 0; i < bytes.size(); ++i) value |= std::to_integer<std::uint64_t>(bytes[i]) << (8 * i);
    return value;
}
std::uint64_t add_signed(std::uint64_t base, std::int64_t addend) {
    if (addend >= 0) {
        const auto positive = static_cast<std::uint64_t>(addend);
        require(base <= UINT64_MAX - positive, "ELF relocation addition overflows", ErrorCode::unsupported);
        return base + positive;
    }
    const auto magnitude = static_cast<std::uint64_t>(-(addend + 1)) + 1;
    require(base >= magnitude, "ELF relocation result is negative", ErrorCode::unsupported);
    return base - magnitude;
}
std::int64_t pc_value(std::uint64_t symbol, std::int64_t addend, std::uint64_t place) {
    require(symbol <= INT64_MAX && place <= INT64_MAX, "ELF PC-relative address exceeds supported range", ErrorCode::unsupported);
    const auto base = static_cast<std::int64_t>(symbol) - static_cast<std::int64_t>(place);
    if (addend > 0) require(base <= INT64_MAX - addend, "ELF PC-relative relocation overflows", ErrorCode::unsupported);
    if (addend < 0) require(base >= INT64_MIN - addend, "ELF PC-relative relocation overflows", ErrorCode::unsupported);
    return base + addend;
}
struct Object {
    std::shared_ptr<const ByteStorage> storage;
    ElfMetadata elf;
    std::uint32_t text_section = 0;
    std::uint64_t output_offset = 0;
    std::vector<std::byte> text;
    std::optional<std::uint32_t> rodata_section;
    std::uint64_t rodata_output_offset = 0;
    std::vector<std::byte> rodata;
    std::optional<std::uint32_t> data_section;
    std::uint64_t data_output_offset = 0;
    std::vector<std::byte> data;
    std::optional<std::uint32_t> bss_section;
    std::uint64_t bss_output_offset = 0;
    std::uint64_t bss_size = 0;
};
struct OutputSymbol {
    std::string name;
    std::uint8_t info = 0, other = 0;
    std::uint16_t section = 0;
    std::uint64_t value = 0, size = 0;
    std::size_t object = 0;
    std::uint32_t source_section = 0;
    std::uint32_t source_index = 0;
};
struct Definition {
    std::size_t object = 0;
    std::uint32_t symbol = 0;
    bool strong = false;
    bool common = false;
    std::uint64_t common_alignment = 1;
    std::uint64_t common_size = 0;
    std::uint64_t common_offset = 0;
};

std::size_t aarch64_width(std::uint32_t type) {
    if (type == 0) return 0;
    if (type == 257 || type == 260) return 8;
    require(type == 258 || type == 261 || type == 275 || type == 277 || type == 282 || type == 283 || type == 286,
            "Unsupported AArch64 ELF relocation type " + std::to_string(type), ErrorCode::unsupported);
    return 4;
}

std::uint64_t aarch64_relocation(std::uint32_t type, std::uint64_t target, std::int64_t addend,
                                std::uint64_t place, std::uint32_t instruction) {
    // AAELF64 static relocations. Preserve every instruction bit outside the
    // relocated immediate; address calculations use final section VAs for EXEC.
    if (type == 257) return target + static_cast<std::uint64_t>(addend); // ABS64 has no overflow check.
    if (type == 258) {
        const auto value = pc_value(target, addend, 0);
        require(value >= INT32_MIN && value <= UINT32_MAX, "AArch64 ABS32 relocation overflows", ErrorCode::unsupported);
        return static_cast<std::uint32_t>(value);
    }
    if (type == 260) return target + static_cast<std::uint64_t>(addend) - place; // PREL64, no overflow check.
    if (type == 261) {
        const auto value = pc_value(target, addend, place);
        require(value >= INT32_MIN && value <= INT32_MAX, "AArch64 PREL32 relocation overflows", ErrorCode::unsupported);
        return static_cast<std::uint64_t>(value);
    }
    require((place & 3) == 0, "AArch64 relocation place is not instruction aligned", ErrorCode::malformed);
    if (type == 282 || type == 283) {
        require((instruction & 0xfc000000U) == (type == 283 ? 0x94000000U : 0x14000000U),
                "AArch64 branch relocation has incompatible instruction", ErrorCode::malformed);
        const auto value = pc_value(target, addend, place);
        require((value & 3) == 0, "AArch64 branch target is not instruction aligned", ErrorCode::unsupported);
        require(value >= -(INT64_C(1) << 27) && value < (INT64_C(1) << 27),
                "AArch64 branch relocation overflows (veneers are unsupported)", ErrorCode::unsupported);
        return (instruction & 0xfc000000U) | ((static_cast<std::uint64_t>(value) >> 2) & 0x03ffffffU);
    }
    if (type == 275) {
        require((instruction & 0x9f000000U) == 0x90000000U,
                "AArch64 page relocation requires ADRP instruction", ErrorCode::malformed);
        const auto displacement = pc_value(target, addend, place & ~UINT64_C(0xfff));
        const auto value = displacement - static_cast<std::int64_t>(static_cast<std::uint64_t>(displacement) & 0xfff);
        require(value >= -(INT64_C(1) << 32) && value < (INT64_C(1) << 32),
                "AArch64 page relocation overflows", ErrorCode::unsupported);
        const auto immediate = static_cast<std::uint64_t>(value) >> 12;
        return (instruction & 0x9f00001fU) | ((immediate & 3) << 29) | (((immediate >> 2) & 0x7ffff) << 5);
    }
    const auto low = (target + static_cast<std::uint64_t>(addend)) & 0xfff;
    if (type == 277) {
        require((instruction & 0x7fc00000U) == 0x11000000U,
                "AArch64 low12 relocation requires unshifted ADD immediate instruction", ErrorCode::malformed);
        return (instruction & ~UINT32_C(0x003ffc00)) | (low << 10);
    }
    require((instruction & 0x3b000000U) == 0x39000000U && (instruction >> 30) == 3,
            "AArch64 load/store relocation requires 64-bit unsigned immediate instruction", ErrorCode::malformed);
    require((low & 7) == 0, "AArch64 load/store target is not 8-byte aligned", ErrorCode::unsupported);
    return (instruction & ~UINT32_C(0x003ffc00)) | ((low >> 3) << 10);
}

std::vector<std::byte> build_output(const std::vector<Object> &objects, const std::vector<OutputSymbol> &symbols,
                                    std::uint64_t text_alignment, std::uint64_t rodata_alignment,
                                    std::uint64_t data_alignment,
                                    std::uint64_t bss_alignment, std::uint64_t bss_extent,
                                    std::uint64_t max_output,
                                    std::uint16_t machine, bool executable = false, std::uint64_t entry = 0, std::uint64_t base = 0) {
    std::vector<std::byte> text;
    for (const auto &object : objects) {
        require(object.output_offset <= max_output && object.text.size() <= max_output - object.output_offset,
                "ELF linked text exceeds output limit", ErrorCode::resource_limit);
        if (text.size() < object.output_offset) text.resize(static_cast<std::size_t>(object.output_offset));
        text.insert(text.end(), object.text.begin(), object.text.end());
    }
    std::vector<std::byte> rodata;
    for (const auto &object : objects) {
        if (!object.rodata_section) continue;
        require(object.rodata_output_offset <= max_output && object.rodata.size() <= max_output - object.rodata_output_offset,
                "ELF linked .rodata exceeds output limit", ErrorCode::resource_limit);
        if (rodata.size() < object.rodata_output_offset) rodata.resize(static_cast<std::size_t>(object.rodata_output_offset));
        rodata.insert(rodata.end(), object.rodata.begin(), object.rodata.end());
    }
    std::vector<std::byte> data;
    for (const auto &object : objects) {
        if (!object.data_section) continue;
        require(object.data_output_offset <= max_output && object.data.size() <= max_output - object.data_output_offset,
                "ELF linked data exceeds output limit", ErrorCode::resource_limit);
        if (data.size() < object.data_output_offset) data.resize(static_cast<std::size_t>(object.data_output_offset));
        data.insert(data.end(), object.data.begin(), object.data.end());
    }
    std::uint64_t bss_size = 0;
    for (const auto &object : objects) {
        if (!object.bss_section) continue;
        require(object.bss_output_offset <= max_output && object.bss_size <= max_output - object.bss_output_offset,
                "ELF linked .bss exceeds output limit", ErrorCode::resource_limit);
        bss_size = std::max(bss_size, object.bss_output_offset + object.bss_size);
    }
    bss_size = std::max(bss_size, bss_extent);
    std::vector<std::byte> strings{std::byte{0}};
    std::vector<std::uint32_t> name_offsets;
    name_offsets.reserve(symbols.size());
    for (const auto &symbol : symbols) {
        require(symbol.name.size() < max_output && strings.size() <= max_output - symbol.name.size() - 1,
                "ELF output symbol strings exceed output limit", ErrorCode::resource_limit);
        name_offsets.push_back(static_cast<std::uint32_t>(strings.size()));
        for (const char ch : symbol.name) strings.push_back(static_cast<std::byte>(ch));
        strings.push_back(std::byte{0});
    }
    std::vector<std::byte> symtab(24, std::byte{0});
    std::size_t local_count = 1;
    for (std::size_t i = 0; i < symbols.size(); ++i) {
        const auto &symbol = symbols[i];
        const auto at = symtab.size();
        symtab.resize(at + 24);
        put(symtab, at, name_offsets[i], 4);
        put(symtab, at + 4, symbol.info, 1);
        put(symtab, at + 5, symbol.other, 1);
        put(symtab, at + 6, symbol.section, 2);
        put(symtab, at + 8, symbol.value, 8);
        put(symtab, at + 16, symbol.size, 8);
        if ((symbol.info >> 4) == 0) ++local_count;
    }
    // ELF requires all local symbols to precede globals. Caller already orders them.
    std::vector<std::byte> shstrings{std::byte{0}};
    const auto add_name = [&](const char *name, std::vector<std::byte> &table) {
        const auto result = static_cast<std::uint32_t>(table.size());
        for (const char *at = name; *at; ++at) table.push_back(static_cast<std::byte>(*at));
        table.push_back(std::byte{0});
        return result;
    };
    const bool has_rodata = !rodata.empty();
    const auto text_name = add_name(".text", shstrings);
    const auto data_name = add_name(".data", shstrings);
    const auto bss_name = add_name(".bss", shstrings);
    const auto rodata_name = has_rodata ? add_name(".rodata", shstrings) : 0;
    const auto str_name = add_name(".strtab", shstrings);
    const auto sym_name = add_name(".symtab", shstrings);
    const auto shstr_name = add_name(".shstrtab", shstrings);
    const auto str_section_index = has_rodata ? 5U : 4U;
    const auto sym_section_index = has_rodata ? 6U : 5U;
    const auto shstr_section_index = has_rodata ? 7U : 6U;
    std::vector<std::byte> out(64 + (executable ? (rodata.empty() ? 2 : 3) * 56 : 0), std::byte{0});
    const auto text_offset = align_up(out.size(), text_alignment);
    require(text_offset <= max_output && text.size() <= max_output - text_offset,
            "ELF linked text and alignment padding exceed output limit", ErrorCode::resource_limit);
    out.resize(static_cast<std::size_t>(text_offset));
    out.insert(out.end(), text.begin(), text.end());
    const auto segment_alignment = executable && machine == 183 ? UINT64_C(65536) : UINT64_C(1);
    const auto rodata_offset = align_up(out.size(), std::max(rodata_alignment, segment_alignment));
    require(rodata_offset <= max_output && rodata.size() <= max_output - rodata_offset,
            "ELF linked .rodata and alignment padding exceed output limit", ErrorCode::resource_limit);
    out.resize(static_cast<std::size_t>(rodata_offset));
    out.insert(out.end(), rodata.begin(), rodata.end());
    const auto data_offset = align_up(out.size(), std::max(data_alignment, segment_alignment));
    require(data_offset <= max_output && data.size() <= max_output - data_offset,
            "ELF linked data and alignment padding exceed output limit", ErrorCode::resource_limit);
    out.resize(static_cast<std::size_t>(data_offset));
    out.insert(out.end(), data.begin(), data.end());
    const auto bss_offset = bss_size ? align_up(out.size(), bss_alignment) : out.size();
    require(bss_offset <= max_output && bss_size <= max_output - bss_offset,
            "ELF linked .bss extent exceeds output limit", ErrorCode::resource_limit);
    out.resize(static_cast<std::size_t>(bss_offset));
    const auto str_offset = out.size(); out.insert(out.end(), strings.begin(), strings.end());
    const auto sym_offset = align_up(out.size(), 8); out.resize(static_cast<std::size_t>(sym_offset));
    out.insert(out.end(), symtab.begin(), symtab.end());
    const auto shstr_offset = out.size(); out.insert(out.end(), shstrings.begin(), shstrings.end());
    const auto section_count = has_rodata ? 8U : 7U;
    const auto shoff = align_up(out.size(), 8); out.resize(static_cast<std::size_t>(shoff + section_count * 64));
    const auto section = [&](std::size_t index, std::uint32_t name, std::uint32_t type, std::uint64_t flags,
                             std::uint64_t address, std::uint64_t offset, std::uint64_t size, std::uint32_t link,
                             std::uint32_t info, std::uint64_t alignment, std::uint64_t entry_size) {
        const auto at = static_cast<std::size_t>(shoff) + index * 64;
        put(out, at, name, 4); put(out, at + 4, type, 4); put(out, at + 8, flags, 8);
        put(out, at + 16, address, 8); put(out, at + 24, offset, 8); put(out, at + 32, size, 8); put(out, at + 40, link, 4);
        put(out, at + 44, info, 4); put(out, at + 48, alignment, 8); put(out, at + 56, entry_size, 8);
    };
    const auto text_address = executable ? base + text_offset : 0;
    const auto rodata_address = executable ? base + rodata_offset : 0;
    const auto data_address = executable ? base + data_offset : 0;
    const auto bss_address = executable ? base + bss_offset : 0;
    section(1, text_name, 1, 6, text_address, text_offset, text.size(), 0, 0, text_alignment, 0);
    section(2, data_name, 1, 3, data_address, data_offset, data.size(), 0, 0, data_alignment, 0);
    section(3, bss_name, 8, 3, bss_address, bss_offset, bss_size, 0, 0, bss_alignment, 0);
    if (has_rodata)
        section(4, rodata_name, 1, 2, rodata_address, rodata_offset, rodata.size(), 0, 0, rodata_alignment, 0);
    section(str_section_index, str_name, 3, 0, 0, str_offset, strings.size(), 0, 0, 1, 0);
    section(sym_section_index, sym_name, 2, 0, 0, sym_offset, symtab.size(), str_section_index,
            static_cast<std::uint32_t>(local_count), 8, 24);
    section(shstr_section_index, shstr_name, 3, 0, 0, shstr_offset, shstrings.size(), 0, 0, 1, 0);
    if (executable) {
        const auto program_header = [&](std::size_t index, std::uint32_t flags, std::uint64_t offset,
                                        std::uint64_t address, std::uint64_t file_size, std::uint64_t memory_size) {
            const auto at = 64 + index * 56;
            put(out, at, 1, 4); put(out, at + 4, flags, 4); put(out, at + 8, offset, 8);
            put(out, at + 16, address, 8); put(out, at + 24, address, 8);
            put(out, at + 32, file_size, 8); put(out, at + 40, memory_size, 8); put(out, at + 48, segment_alignment, 8);
        };
        program_header(0, 5, 0, base, text_offset + text.size(), text_offset + text.size());
        if (!rodata.empty()) program_header(1, 4, rodata_offset, rodata_address, rodata.size(), rodata.size());
        const auto data_memory_size = bss_size ? bss_offset + bss_size - data_offset : data.size();
        program_header(rodata.empty() ? 1 : 2, 6, data_offset, data_address, data.size(), data_memory_size);
    }
    out[0]=std::byte{0x7f}; out[1]=std::byte{'E'}; out[2]=std::byte{'L'}; out[3]=std::byte{'F'};
    out[4]=std::byte{2}; out[5]=std::byte{1}; out[6]=std::byte{1};
    put(out, 16, executable ? 2 : 1, 2); put(out, 18, machine, 2); put(out, 20, 1, 4);
    put(out, 24, entry, 8); put(out, 32, executable ? 64 : 0, 8); put(out, 40, shoff, 8);
    put(out, 52, 64, 2); put(out, 54, executable ? 56 : 0, 2);
    put(out, 56, executable ? (rodata.empty() ? 2 : 3) : 0, 2); put(out, 58, 64, 2);
    put(out, 60, section_count, 2); put(out, 62, shstr_section_index, 2);
    require(out.size() <= max_output, "ELF linked output exceeds configured limit", ErrorCode::resource_limit);
    return out;
}
} // namespace

static Result<std::vector<std::byte>> link_elf64_impl(
    std::span<const std::shared_ptr<const ByteStorage>> inputs, std::uint16_t machine, bool executable, std::string_view entry_name,
    std::uint64_t base_address, std::stop_token stop, ElfLinkLimits limits) {
    try {
        require(!inputs.empty() && inputs.size() <= limits.max_objects, "ELF link object count is outside configured limits", ErrorCode::resource_limit);
        require(limits.max_symbols && limits.max_relocations && limits.max_output_bytes, "ELF link limits must be positive", ErrorCode::invalid_argument);
        std::vector<Object> objects;
        objects.reserve(inputs.size());
        std::size_t symbol_count = 0, relocation_count = 0;
        std::uint64_t text_end = 0;
        std::uint64_t text_alignment = 1;
        std::uint64_t rodata_end = 0;
        std::uint64_t rodata_alignment = 1;
        std::uint64_t data_end = 0;
        std::uint64_t data_alignment = 1;
        std::uint64_t bss_end = 0;
        std::uint64_t bss_alignment = 1;
        for (const auto &input : inputs) {
            canceled(stop);
            require(input != nullptr, "ELF link input storage is null", ErrorCode::invalid_argument);
            auto loaded = load_elf(input, stop);
            if (!loaded) throw Failure{loaded.error()};
            require(loaded.value().metadata.elf.has_value(), "ELF linker input has no ELF metadata", ErrorCode::unsupported);
            auto &elf = *loaded.value().metadata.elf;
            require(elf.header.object_type == 1 && elf.header.is_64 && elf.header.order == ByteOrder::little && elf.header.machine == machine,
                    machine == 183 ? "ELF link subset requires ELF64 little-endian AArch64 ET_REL objects"
                                   : "ELF link subset requires ELF64 little-endian x86-64 ET_REL objects", ErrorCode::unsupported);
            require(elf.symbols.size() <= limits.max_symbols - symbol_count, "ELF link symbol limit exceeded", ErrorCode::resource_limit);
            symbol_count += elf.symbols.size();
            std::optional<std::uint32_t> text_index;
            std::optional<std::uint32_t> rodata_index;
            std::optional<std::uint32_t> data_index;
            std::optional<std::uint32_t> bss_index;
            for (const auto &section : elf.sections) {
                canceled(stop);
                if ((section.flags & 2) && section.size) {
                    const bool is_text = section.name == ".text";
                    const bool is_rodata = section.name == ".rodata";
                    const bool is_data = section.name == ".data";
                    const bool is_bss = section.name == ".bss";
                    require((is_text || is_rodata || is_data || is_bss) &&
                                (is_bss ? section.type == 8 : section.type == 1) &&
                                (is_text ? !text_index : is_rodata ? !rodata_index : is_data ? !data_index : !bss_index),
                            std::string("ELF link subset supports only allocated .text, .rodata, .data, and .bss sections; found ") +
                                section.name + " at index " + std::to_string(section.index), ErrorCode::unsupported);
                    if (is_text) text_index = section.index;
                    else if (is_rodata) rodata_index = section.index;
                    else if (is_data) data_index = section.index;
                    else bss_index = section.index;
                }
            }
            require(text_index.has_value(), "ELF link input must define an allocated .text section", ErrorCode::unsupported);
            const auto &text_section = elf.sections[*text_index];
            require(text_section.flags & 4, "ELF .text section must be executable", ErrorCode::unsupported);
            require(text_section.size <= limits.max_output_bytes && text_section.size <= std::numeric_limits<std::size_t>::max(),
                    "ELF .text section exceeds output limit", ErrorCode::resource_limit);
            auto view = input->read_at({text_section.offset}, static_cast<std::size_t>(text_section.size));
            if (!view) throw Failure{view.error()};
            require(view.value().bytes.size() == text_section.size, "Incomplete ELF .text section read", ErrorCode::io);
            const auto alignment = std::max<std::uint64_t>(1, text_section.alignment);
            text_alignment = std::max(text_alignment, alignment);
            text_end = align_up(text_end, alignment);
            require(text_end <= limits.max_output_bytes && text_section.size <= limits.max_output_bytes - text_end,
                    "Combined ELF .text exceeds output limit", ErrorCode::resource_limit);
            Object object{input, std::move(elf), *text_index, text_end,
                          {view.value().bytes.begin(), view.value().bytes.end()}};
            text_end += text_section.size;
            Object &stored = object;
            if (rodata_index) {
                const auto &rodata_section = stored.elf.sections[*rodata_index];
                require((rodata_section.flags & 2) && !(rodata_section.flags & (1 | 4)),
                        "ELF .rodata section must be allocated, non-writable, and non-executable", ErrorCode::unsupported);
                require(rodata_section.size <= limits.max_output_bytes && rodata_section.size <= std::numeric_limits<std::size_t>::max(),
                        "ELF .rodata section exceeds output limit", ErrorCode::resource_limit);
                auto rodata_view = input->read_at({rodata_section.offset}, static_cast<std::size_t>(rodata_section.size));
                if (!rodata_view) throw Failure{rodata_view.error()};
                require(rodata_view.value().bytes.size() == rodata_section.size, "Incomplete ELF .rodata section read", ErrorCode::io);
                const auto rodata_section_alignment = std::max<std::uint64_t>(1, rodata_section.alignment);
                rodata_alignment = std::max(rodata_alignment, rodata_section_alignment);
                rodata_end = align_up(rodata_end, rodata_section_alignment);
                require(rodata_end <= limits.max_output_bytes && rodata_section.size <= limits.max_output_bytes - rodata_end,
                        "Combined ELF .rodata exceeds output limit", ErrorCode::resource_limit);
                stored.rodata_section = *rodata_index;
                stored.rodata_output_offset = rodata_end;
                stored.rodata.assign(rodata_view.value().bytes.begin(), rodata_view.value().bytes.end());
                rodata_end += rodata_section.size;
            }
            if (data_index) {
                const auto &data_section = stored.elf.sections[*data_index];
                require((data_section.flags & 1) && !(data_section.flags & 4),
                        "ELF .data section must be writable and non-executable", ErrorCode::unsupported);
                require(data_section.size <= limits.max_output_bytes && data_section.size <= std::numeric_limits<std::size_t>::max(),
                        "ELF .data section exceeds output limit", ErrorCode::resource_limit);
                auto data_view = input->read_at({data_section.offset}, static_cast<std::size_t>(data_section.size));
                if (!data_view) throw Failure{data_view.error()};
                require(data_view.value().bytes.size() == data_section.size, "Incomplete ELF .data section read", ErrorCode::io);
                const auto data_section_alignment = std::max<std::uint64_t>(1, data_section.alignment);
                data_alignment = std::max(data_alignment, data_section_alignment);
                data_end = align_up(data_end, data_section_alignment);
                require(data_end <= limits.max_output_bytes && data_section.size <= limits.max_output_bytes - data_end,
                        "Combined ELF .data exceeds output limit", ErrorCode::resource_limit);
                stored.data_section = *data_index;
                stored.data_output_offset = data_end;
                stored.data.assign(data_view.value().bytes.begin(), data_view.value().bytes.end());
                data_end += data_section.size;
            }
            if (bss_index) {
                const auto &bss_section = stored.elf.sections[*bss_index];
                require((bss_section.flags & 1) && !(bss_section.flags & 4),
                        "ELF .bss section must be writable and non-executable", ErrorCode::unsupported);
                require(bss_section.size <= limits.max_output_bytes,
                        "ELF .bss section exceeds output limit", ErrorCode::resource_limit);
                const auto section_alignment = std::max<std::uint64_t>(1, bss_section.alignment);
                bss_alignment = std::max(bss_alignment, section_alignment);
                bss_end = align_up(bss_end, section_alignment);
                require(bss_end <= limits.max_output_bytes && bss_section.size <= limits.max_output_bytes - bss_end,
                        "Combined ELF .bss exceeds output limit", ErrorCode::resource_limit);
                stored.bss_section = *bss_index;
                stored.bss_output_offset = bss_end;
                stored.bss_size = bss_section.size;
                bss_end += bss_section.size;
            }
            objects.push_back(std::move(object));
        }
        std::map<std::string, Definition> common_symbols;
        std::map<std::string, bool> strong_definitions;
        for (std::size_t oi = 0; oi < objects.size(); ++oi) {
            for (std::size_t si = 0; si < objects[oi].elf.symbols.size(); ++si) {
                canceled(stop);
                const auto &symbol = objects[oi].elf.symbols[si];
                if (symbol.binding != 1 && symbol.binding != 2 && symbol.binding != 10) continue;
                if (symbol.state == ElfSymbolState::defined || symbol.state == ElfSymbolState::absolute) {
                    if ((symbol.binding == 1 || symbol.binding == 10) && !symbol.name.empty())
                        strong_definitions.emplace(symbol.name, true);
                    continue;
                }
                if (symbol.state != ElfSymbolState::common) continue;
                require(!symbol.name.empty(), "ELF common symbol has no name", ErrorCode::unsupported);
                const auto alignment = std::max<std::uint64_t>(1, symbol.value);
                require((alignment & (alignment - 1)) == 0,
                        "ELF common symbol alignment is not a power of two", ErrorCode::malformed);
                require(alignment <= limits.max_output_bytes && symbol.size <= limits.max_output_bytes,
                        "ELF common symbol exceeds output limit", ErrorCode::resource_limit);
                auto [it, inserted] = common_symbols.emplace(symbol.name,
                    Definition{oi, static_cast<std::uint32_t>(si), false, true, alignment, symbol.size, 0});
                if (!inserted) {
                    it->second.common_alignment = std::max(it->second.common_alignment, alignment);
                    it->second.common_size = std::max(it->second.common_size, symbol.size);
                    const auto &selected = objects[it->second.object].elf.symbols[it->second.symbol];
                    if (selected.binding == 2 && symbol.binding != 2) {
                        it->second.object = oi;
                        it->second.symbol = static_cast<std::uint32_t>(si);
                    }
                }
            }
        }
        for (auto &[name, common] : common_symbols) {
            canceled(stop);
            if (strong_definitions.contains(name)) continue;
            bss_alignment = std::max(bss_alignment, common.common_alignment);
            bss_end = align_up(bss_end, common.common_alignment);
            require(bss_end <= limits.max_output_bytes && common.common_size <= limits.max_output_bytes - bss_end,
                    "Combined ELF common symbols exceed output limit", ErrorCode::resource_limit);
            common.common_offset = bss_end;
            bss_end += common.common_size;
        }
        const auto file_text_offset = align_up(64 + (executable ? (rodata_end ? 3 : 2) * 56 : 0), text_alignment);
        const auto segment_alignment = executable && machine == 183 ? UINT64_C(65536) : UINT64_C(1);
        if (executable && machine == 183)
            require(base_address % std::max({segment_alignment, text_alignment, rodata_alignment, data_alignment, bss_alignment}) == 0,
                    "AArch64 executable base must satisfy 64KiB and input section alignment", ErrorCode::invalid_argument);
        const auto file_rodata_offset = align_up(file_text_offset + text_end, std::max(rodata_alignment, segment_alignment));
        require(file_rodata_offset <= UINT64_MAX - rodata_end, "ELF executable .rodata extent overflows", ErrorCode::resource_limit);
        const auto file_data_offset = align_up(file_rodata_offset + rodata_end, std::max(data_alignment, segment_alignment));
        require(file_data_offset <= UINT64_MAX - data_end, "ELF executable section extent overflows", ErrorCode::resource_limit);
        const auto file_bss_offset = bss_end ? align_up(file_data_offset + data_end, bss_alignment)
                                             : file_data_offset + data_end;
        require(file_bss_offset <= UINT64_MAX - bss_end, "ELF executable .bss extent overflows", ErrorCode::resource_limit);
        const auto virtual_end_offset = file_bss_offset + bss_end;
        require(!executable || (base_address <= UINT64_MAX - virtual_end_offset &&
                                base_address + virtual_end_offset <= INT64_MAX),
                "ELF executable base and sections exceed supported address range", ErrorCode::unsupported);
        std::map<std::string, Definition> definitions;
        for (std::size_t oi = 0; oi < objects.size(); ++oi) {
            const auto &elf = objects[oi].elf;
            for (std::size_t si = 0; si < elf.symbols.size(); ++si) {
                const auto &symbol = elf.symbols[si];
                if (symbol.binding != 1 && symbol.binding != 2 && symbol.binding != 10) continue;
                if (symbol.state != ElfSymbolState::defined && symbol.state != ElfSymbolState::absolute) continue;
                const auto &obj = objects[oi];
                if (symbol.state == ElfSymbolState::defined && obj.bss_section &&
                    symbol.section_index == *obj.bss_section) {
                    require(symbol.value <= obj.bss_size && symbol.size <= obj.bss_size - symbol.value,
                            "ELF .bss symbol extent exceeds its input section", ErrorCode::malformed);
                }
                require(symbol.state == ElfSymbolState::absolute || symbol.section_index == obj.text_section ||
                            (obj.rodata_section && symbol.section_index == *obj.rodata_section) ||
                            (obj.data_section && symbol.section_index == *obj.data_section) ||
                            (obj.bss_section && symbol.section_index == *obj.bss_section),
                        "ELF link subset cannot export symbols outside .text/.rodata/.data/.bss", ErrorCode::unsupported);
                if (symbol.name.empty()) continue;
                const bool strong = symbol.binding == 1 || symbol.binding == 10;
                auto [it, inserted] = definitions.emplace(symbol.name, Definition{oi, static_cast<std::uint32_t>(si), strong});
                if (!inserted && strong && it->second.strong)
                    throw Failure{{ErrorCode::unsupported, "Multiple strong ELF definitions for symbol " + symbol.name}};
                if (!inserted && strong) it->second = {oi, static_cast<std::uint32_t>(si), true};
            }
        }
        for (const auto &[name, common] : common_symbols) {
            if (strong_definitions.contains(name)) continue;
            definitions.insert_or_assign(name, common);
        }
        for (const auto &object : objects) {
            for (const auto &symbol : object.elf.symbols) {
                if ((symbol.binding == 1 || symbol.binding == 10) && symbol.state == ElfSymbolState::undefined &&
                    !symbol.name.empty())
                    require(definitions.contains(symbol.name), "Unresolved strong ELF symbol " + symbol.name,
                            ErrorCode::unsupported);
            }
        }
        std::uint64_t entry_address = 0;
        if (executable) {
            const auto found = definitions.find(std::string(entry_name));
            require(found != definitions.end(), "ELF executable entry symbol is undefined: " + std::string(entry_name),
                    ErrorCode::unsupported);
            const auto &provider = objects[found->second.object];
            const auto &entry_symbol = provider.elf.symbols[found->second.symbol];
            require(entry_symbol.state == ElfSymbolState::defined && entry_symbol.section_index == provider.text_section &&
                        entry_symbol.value < provider.text.size(),
                    "ELF executable entry symbol must identify a byte in merged .text", ErrorCode::unsupported);
            entry_address = base_address + file_text_offset + provider.output_offset + entry_symbol.value;
        }
        std::vector<OutputSymbol> output_symbols;
        std::vector<std::vector<bool>> included(objects.size());
        for (std::size_t oi = 0; oi < objects.size(); ++oi) included[oi].resize(objects[oi].elf.symbols.size());
        for (std::size_t oi = 0; oi < objects.size(); ++oi) {
            const auto &elf = objects[oi].elf;
            for (const auto &table : elf.symbol_tables) {
                if (!table.source.section || !table.symbol_begin) continue;
                const auto &section = elf.sections[*table.source.section];
                if (section.type != 2) continue; // Output one canonical SYMTAB.
                const auto local_end = std::min<std::uint64_t>(*table.symbol_begin + section.info,
                                                               *table.symbol_begin + table.count.value_or(0));
                for (std::uint64_t ix = *table.symbol_begin + 1; ix < *table.symbol_begin + table.count.value_or(0); ++ix) {
                    const auto &symbol = elf.symbols[static_cast<std::size_t>(ix)];
                    if (symbol.state != ElfSymbolState::defined && symbol.state != ElfSymbolState::absolute) continue;
                    if (symbol.state == ElfSymbolState::defined && symbol.section_index != objects[oi].text_section &&
                        (!objects[oi].rodata_section || symbol.section_index != *objects[oi].rodata_section) &&
                        (!objects[oi].data_section || symbol.section_index != *objects[oi].data_section) &&
                        (!objects[oi].bss_section || symbol.section_index != *objects[oi].bss_section)) continue;
                    const auto binding = symbol.binding;
                    if (binding != 0 && binding != 1 && binding != 2 && binding != 10) continue;
                    if (binding != 0) {
                        const auto def = definitions.find(symbol.name);
                        if (def == definitions.end() || def->second.object != oi || def->second.symbol != ix) continue;
                    }
                    if (included[oi][static_cast<std::size_t>(ix)]) continue;
                    included[oi][static_cast<std::size_t>(ix)] = true;
                    const bool local = ix < local_end;
                    const bool in_rodata = symbol.state == ElfSymbolState::defined && objects[oi].rodata_section &&
                                           symbol.section_index == *objects[oi].rodata_section;
                    const bool in_data = symbol.state == ElfSymbolState::defined && objects[oi].data_section &&
                                         symbol.section_index == *objects[oi].data_section;
                    const bool in_bss = symbol.state == ElfSymbolState::defined && objects[oi].bss_section &&
                                        symbol.section_index == *objects[oi].bss_section;
                    const auto value = symbol.state == ElfSymbolState::absolute ? symbol.value :
                        executable ? base_address + (in_bss ? file_bss_offset + objects[oi].bss_output_offset
                                                    : in_data ? file_data_offset + objects[oi].data_output_offset
                                                    : in_rodata ? file_rodata_offset + objects[oi].rodata_output_offset
                                                                : file_text_offset + objects[oi].output_offset) + symbol.value
                                   : (in_bss ? objects[oi].bss_output_offset + symbol.value
                                      : in_data ? objects[oi].data_output_offset + symbol.value
                                      : in_rodata ? objects[oi].rodata_output_offset + symbol.value
                                                  : objects[oi].output_offset + symbol.value);
                    output_symbols.push_back({symbol.name, static_cast<std::uint8_t>((binding << 4) | symbol.type), symbol.other,
                        static_cast<std::uint16_t>(symbol.state == ElfSymbolState::absolute ? 0xfff1 : (in_bss ? 3 : in_data ? 2 : in_rodata ? 4 : 1)),
                        value,
                        symbol.size, oi, *table.source.section, symbol.index});
                    (void)local;
                }
            }
        }
        for (const auto &[name, definition] : definitions) {
            if (!definition.common) continue;
            const auto &symbol = objects[definition.object].elf.symbols[definition.symbol];
            const auto value = executable
                ? base_address + file_bss_offset + definition.common_offset
                : definition.common_offset;
            output_symbols.push_back({name,
                static_cast<std::uint8_t>((symbol.binding << 4) | symbol.type), symbol.other,
                3, value, definition.common_size, definition.object, 0, symbol.index});
        }
        std::stable_sort(output_symbols.begin(), output_symbols.end(), [](const auto &a, const auto &b) {
            return (a.info >> 4) == 0 && (b.info >> 4) != 0;
        });
        for (std::size_t oi = 0; oi < objects.size(); ++oi) {
            auto &object = objects[oi];
            auto &elf = object.elf;
            for (const auto &relocation : elf.relocations) {
                canceled(stop);
                require(++relocation_count <= limits.max_relocations, "ELF link relocation limit exceeded", ErrorCode::resource_limit);
                const bool target_text = relocation.target_section && *relocation.target_section == object.text_section;
                const bool target_rodata = relocation.target_section && object.rodata_section &&
                                           *relocation.target_section == *object.rodata_section;
                const bool target_data = relocation.target_section && object.data_section &&
                                         *relocation.target_section == *object.data_section;
                require(target_text || target_rodata || target_data,
                        "ELF link subset supports relocations targeting merged .text, .rodata, and .data only", ErrorCode::unsupported);
                auto &target_bytes = target_text ? object.text : target_rodata ? object.rodata : object.data;
                const auto target_output_offset = target_text ? object.output_offset : target_rodata ? object.rodata_output_offset : object.data_output_offset;
                const auto target_file_offset = target_text ? file_text_offset : target_rodata ? file_rodata_offset : file_data_offset;
                const auto target_name = target_text ? ".text" : target_rodata ? ".rodata" : ".data";
                require(relocation.explicit_addend && relocation.addend,
                        "ELF link subset supports RELA relocations only", ErrorCode::unsupported);
                const auto type = relocation.type;
                const std::size_t width = machine == 183 ? aarch64_width(type) : type == 0 ? 0 : (type == 1 || type == 24 ? 8 : 4);
                require(machine == 183 || type == 0 || type == 1 || type == 2 || type == 4 || type == 10 || type == 11 || type == 24,
                        "Unsupported x86-64 ELF relocation type " + std::to_string(type), ErrorCode::unsupported);
                require(relocation.offset <= target_bytes.size() && width <= target_bytes.size() - relocation.offset,
                        std::string("ELF relocation field exceeds ") + target_name, ErrorCode::malformed);
                if (type == 0) continue;
                require(relocation.symbol_table && relocation.symbol_index_validated,
                        "ELF relocation symbol table/index is unavailable", ErrorCode::unsupported);
                const auto table = std::find_if(elf.symbol_tables.begin(), elf.symbol_tables.end(), [&](const auto &candidate) {
                    return candidate.source == *relocation.symbol_table;
                });
                require(table != elf.symbol_tables.end() && table->symbol_begin && table->count && relocation.symbol_index < *table->count,
                        "ELF relocation symbol index is unavailable", ErrorCode::malformed);
                const auto si = static_cast<std::size_t>(*table->symbol_begin + relocation.symbol_index);
                require(si < elf.symbols.size(), "ELF relocation symbol index exceeds loaded table", ErrorCode::malformed);
                const auto &symbol = elf.symbols[si];
                std::uint64_t target = 0;
                std::uint64_t symbol_file_offset = 0;
                bool absolute_target = relocation.symbol_index == 0;
                if (relocation.symbol_index != 0) {
                    if (symbol.binding == 0) {
                        require(symbol.state == ElfSymbolState::defined || symbol.state == ElfSymbolState::absolute,
                                "Unresolved local ELF relocation symbol " + symbol.name, ErrorCode::unsupported);
                        if (symbol.state == ElfSymbolState::absolute) { target = symbol.value; absolute_target = true; }
                        else if (symbol.section_index == object.text_section) {
                            target = object.output_offset + symbol.value; symbol_file_offset = file_text_offset;
                        } else if (object.rodata_section && symbol.section_index == *object.rodata_section) {
                            target = object.rodata_output_offset + symbol.value; symbol_file_offset = file_rodata_offset;
                        } else if (object.data_section && symbol.section_index == *object.data_section) {
                            target = object.data_output_offset + symbol.value; symbol_file_offset = file_data_offset;
                        } else if (object.bss_section && symbol.section_index == *object.bss_section) {
                            target = object.bss_output_offset + symbol.value; symbol_file_offset = file_bss_offset;
                        }
                        else throw Failure{{ErrorCode::unsupported, "Local ELF relocation symbol is outside merged .text/.rodata/.data/.bss: " + symbol.name}};
                    } else {
                        const auto def = definitions.find(symbol.name);
                        if (def == definitions.end()) {
                            require(symbol.binding == 2, "Unresolved strong ELF relocation symbol " + symbol.name, ErrorCode::unsupported);
                            target = 0;
                            absolute_target = true;
                        } else {
                            const auto &defined = objects[def->second.object].elf.symbols[def->second.symbol];
                            if (def->second.common) {
                                target = def->second.common_offset;
                                symbol_file_offset = file_bss_offset;
                            } else if (defined.state == ElfSymbolState::absolute) { target = defined.value; absolute_target = true; }
                            else {
                                const auto &provider = objects[def->second.object];
                                if (defined.section_index == provider.text_section) {
                                    target = provider.output_offset + defined.value; symbol_file_offset = file_text_offset;
                                } else if (provider.rodata_section && defined.section_index == *provider.rodata_section) {
                                    target = provider.rodata_output_offset + defined.value; symbol_file_offset = file_rodata_offset;
                                } else if (provider.data_section && defined.section_index == *provider.data_section) {
                                    target = provider.data_output_offset + defined.value; symbol_file_offset = file_data_offset;
                                } else if (provider.bss_section && defined.section_index == *provider.bss_section) {
                                    target = provider.bss_output_offset + defined.value; symbol_file_offset = file_bss_offset;
                                }
                                else throw Failure{{ErrorCode::unsupported, "ELF relocation provider is outside merged .text/.rodata/.data/.bss: " + symbol.name}};
                            }
                        }
                    }
                }
                const auto place = (executable ? base_address + target_file_offset : 0) +
                                   target_output_offset + relocation.offset;
                if (executable && !absolute_target)
                    target += base_address + symbol_file_offset;
                std::uint64_t result = 0;
                if (machine == 183) {
                    const auto instruction = width == 4 ? static_cast<std::uint32_t>(read_le(
                        std::span<const std::byte>(target_bytes).subspan(static_cast<std::size_t>(relocation.offset), 4))) : 0;
                    result = aarch64_relocation(type, target, *relocation.addend, place, instruction);
                } else if (type == 1) result = add_signed(target, *relocation.addend);
                else if (type == 10) {
                    result = add_signed(target, *relocation.addend);
                    require(result <= UINT32_MAX, "R_X86_64_32 relocation overflows", ErrorCode::unsupported);
                } else if (type == 11) {
                    const auto signed_result = static_cast<std::int64_t>(target <= INT64_MAX ? target : 0);
                    require(target <= INT64_MAX, "R_X86_64_32S symbol exceeds signed range", ErrorCode::unsupported);
                    require((*relocation.addend >= 0 && signed_result <= INT64_MAX - *relocation.addend) ||
                            (*relocation.addend < 0 && signed_result >= INT64_MIN - *relocation.addend),
                            "R_X86_64_32S addition overflows", ErrorCode::unsupported);
                    const auto signed_value = signed_result + *relocation.addend;
                    require(signed_value >= INT32_MIN && signed_value <= INT32_MAX, "R_X86_64_32S relocation overflows", ErrorCode::unsupported);
                    result = static_cast<std::uint32_t>(static_cast<std::int32_t>(signed_value));
                } else {
                    const auto signed_result = pc_value(target, *relocation.addend, place);
                    if (type == 2 || type == 4)
                        require(signed_result >= INT32_MIN && signed_result <= INT32_MAX, "R_X86_64_PC32/PLT32 relocation overflows", ErrorCode::unsupported);
                    result = static_cast<std::uint64_t>(signed_result);
                }
                for (std::size_t b = 0; b < width; ++b)
                    target_bytes[static_cast<std::size_t>(relocation.offset) + b] = static_cast<std::byte>((result >> (8 * b)) & 0xff);
            }
        }
        canceled(stop);
        return build_output(objects, output_symbols, text_alignment, rodata_alignment, data_alignment, bss_alignment, bss_end,
                            limits.max_output_bytes,
                            machine, executable, entry_address, base_address);
    } catch (const Failure &failure) { return failure.error; }
      catch (const std::bad_alloc &) { return Error{ErrorCode::resource_limit, "Cannot allocate linked ELF output"}; }
}

Result<std::vector<std::byte>> link_elf64_x86_64_text(
    std::span<const std::shared_ptr<const ByteStorage>> inputs, std::stop_token stop, ElfLinkLimits limits) {
    return link_elf64_impl(inputs, 62, false, {}, 0, stop, limits);
}

Result<std::vector<std::byte>> link_elf64_x86_64_executable(
    std::span<const std::shared_ptr<const ByteStorage>> inputs, std::string_view entry_symbol,
    std::uint64_t base_address, std::stop_token stop, ElfLinkLimits limits) {
    if (entry_symbol.empty())
        return Error{ErrorCode::invalid_argument, "ELF executable entry symbol cannot be empty"};
    return link_elf64_impl(inputs, 62, true, entry_symbol, base_address, stop, limits);
}

Result<std::vector<std::byte>> link_elf64_aarch64_text(
    std::span<const std::shared_ptr<const ByteStorage>> inputs, std::stop_token stop, ElfLinkLimits limits) {
    return link_elf64_impl(inputs, 183, false, {}, 0, stop, limits);
}

Result<std::vector<std::byte>> link_elf64_aarch64_executable(
    std::span<const std::shared_ptr<const ByteStorage>> inputs, std::string_view entry_symbol,
    std::uint64_t base_address, std::stop_token stop, ElfLinkLimits limits) {
    if (entry_symbol.empty())
        return Error{ErrorCode::invalid_argument, "ELF executable entry symbol cannot be empty"};
    return link_elf64_impl(inputs, 183, true, entry_symbol, base_address, stop, limits);
}
} // namespace hexlab
