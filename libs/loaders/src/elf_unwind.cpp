#include "elf_internal.hpp"
#include <bit>
#include <string_view>

namespace hexlab::elf_detail {
namespace {
struct Cursor {
    const Reader &reader;
    std::span<const std::byte> data;
    std::size_t at = 0, end = 0;

    void need(std::size_t n) const { require(at <= end && n <= end - at, "Truncated ELF .eh_frame record"); }
    std::uint64_t fixed(std::size_t n) {
        need(n);
        const auto result = reader.value(data, at, n);
        at += n;
        return result;
    }
    std::uint64_t uleb() {
        std::uint64_t value = 0;
        unsigned shift = 0;
        for (unsigned i = 0; i < 10; ++i) {
            const auto byte = static_cast<std::uint8_t>(fixed(1));
            require(shift < 64 || (byte & 0x7f) == 0, "ELF .eh_frame ULEB128 overflows", ErrorCode::overflow);
            if (shift < 64) {
                require((byte & 0x7f) <= (UINT64_MAX >> shift), "ELF .eh_frame ULEB128 overflows", ErrorCode::overflow);
                value |= std::uint64_t(byte & 0x7f) << shift;
            }
            if (!(byte & 0x80)) return value;
            shift += 7;
        }
        require(false, "ELF .eh_frame ULEB128 exceeds ten bytes");
        return 0;
    }
    std::int64_t sleb() {
        std::uint64_t value = 0;
        unsigned shift = 0;
        std::uint8_t byte = 0;
        for (unsigned i = 0; i < 10; ++i) {
            byte = static_cast<std::uint8_t>(fixed(1));
            require(i != 9 || (byte & 0x7f) == 0 || (byte & 0x7f) == 0x7f,
                    "ELF .eh_frame SLEB128 overflows", ErrorCode::overflow);
            if (shift < 64) value |= std::uint64_t(byte & 0x7f) << shift;
            shift += 7;
            if (!(byte & 0x80)) {
                if (shift < 64 && (byte & 0x40)) value |= (~UINT64_C(0)) << shift;
                return std::bit_cast<std::int64_t>(value);
            }
        }
        require(false, "ELF .eh_frame SLEB128 exceeds ten bytes");
        return 0;
    }
    std::string cstring() {
        const auto start = at;
        while (at < end && data[at] != std::byte{0}) ++at;
        require(at < end, "Unterminated ELF .eh_frame augmentation string");
        std::string result(reinterpret_cast<const char *>(data.data() + start), at - start);
        ++at;
        return result;
    }
};

struct Cie {
    std::uint8_t fde_encoding = 0;
    bool has_z_augmentation = false;
    std::uint64_t code_alignment = 1, return_register = 0;
    std::int64_t data_alignment = 0;
    std::vector<std::byte> instructions;
    std::optional<ElfEhFramePointer> personality;
    std::optional<std::uint8_t> lsda_encoding;
    std::optional<std::uint64_t> lsda_encoding_file_offset;
    std::uint64_t file_offset = 0;
};

std::uint64_t add_signed(std::uint64_t base, std::int64_t delta) {
    if (delta >= 0) {
        require(static_cast<std::uint64_t>(delta) <= UINT64_MAX - base, "ELF .eh_frame address overflows", ErrorCode::overflow);
        return base + static_cast<std::uint64_t>(delta);
    }
    const auto magnitude = static_cast<std::uint64_t>(-(delta + 1)) + 1;
    require(magnitude <= base, "ELF .eh_frame address underflows", ErrorCode::overflow);
    return base - magnitude;
}

void validate_encoding(std::uint8_t encoding, bool allow_indirect, bool allow_omit = false) {
    if (encoding == 0xff && allow_omit) return;
    require(encoding != 0xff, "DW_EH_PE_omit cannot encode an ELF .eh_frame address", ErrorCode::unsupported);
    require(allow_indirect || !(encoding & 0x80), "Indirect FDE range encodings are unsupported", ErrorCode::unsupported);
    const auto application = encoding & 0x70;
    require(application == 0 || application == 0x10,
            "Unsupported DW_EH_PE application in ELF .eh_frame", ErrorCode::unsupported);
    const auto format = encoding & 0x0f;
    require(format == 0 || format == 1 || format == 2 || format == 3 || format == 4 ||
                format == 9 || format == 10 || format == 11 || format == 12,
            "Unsupported DW_EH_PE format in ELF .eh_frame", ErrorCode::unsupported);
}

std::uint64_t encoded(Cursor &cursor, std::uint8_t encoding, std::uint64_t field_address,
                      unsigned address_size, bool apply_relative, bool exception_pointer = false) {
    validate_encoding(encoding, exception_pointer);
    const auto application = encoding & 0x70;
    const auto format = encoding & 0x0f;
    std::uint64_t raw = 0;
    std::int64_t signed_value = 0;
    bool is_signed = false;
    switch (format) {
    case 0x00: raw = cursor.fixed(address_size); break;
    case 0x01: raw = cursor.uleb(); break;
    case 0x02: raw = cursor.fixed(2); break;
    case 0x03: raw = cursor.fixed(4); break;
    case 0x04: raw = cursor.fixed(8); break;
    case 0x09: signed_value = cursor.sleb(); is_signed = true; break;
    case 0x0a: signed_value = std::bit_cast<std::int16_t>(static_cast<std::uint16_t>(cursor.fixed(2))); is_signed = true; break;
    case 0x0b: signed_value = std::bit_cast<std::int32_t>(static_cast<std::uint32_t>(cursor.fixed(4))); is_signed = true; break;
    case 0x0c: signed_value = std::bit_cast<std::int64_t>(cursor.fixed(8)); is_signed = true; break;
    default: require(false, "Unsupported DW_EH_PE format in ELF .eh_frame", ErrorCode::unsupported);
    }
    if (exception_pointer && (is_signed ? signed_value == 0 : raw == 0)) return 0;
    if (!apply_relative || application == 0) {
        if (is_signed) {
            require(signed_value >= 0, "Negative ELF .eh_frame extent", ErrorCode::malformed);
            return static_cast<std::uint64_t>(signed_value);
        }
        return raw;
    }
    if (!is_signed) {
        require(raw <= static_cast<std::uint64_t>(INT64_MAX),
                "Relative DW_EH_PE value exceeds signed address range", ErrorCode::overflow);
        signed_value = static_cast<std::int64_t>(raw);
    }
    return add_signed(field_address, signed_value);
}

ElfEhFramePointer exception_pointer(Cursor &cursor, std::uint8_t encoding,
                                   std::uint64_t encoding_file_offset,
                                   const ElfSection &section, unsigned address_size) {
    const auto start = cursor.at;
    const auto value = encoded(cursor, encoding, add(section.address, start), address_size, true, true);
    ElfEhFramePointer result{encoding, encoding_file_offset, add(section.offset, start),
                             cursor.at - start, value, std::nullopt};
    if (!(encoding & 0x80) && value != 0) result.target = Address{{0}, value};
    return result;
}

void parse_section(const ByteStorage &storage, const Image &image, const ElfMetadata &metadata,
                   const ElfSection &section, Budget &budget, std::stop_token stop,
                   std::vector<ElfUnwindRange> &output,
                   std::vector<ElfEhFrameFunction> &cfi_output) {
    require(metadata.header.object_type != 1,
            "Relocatable ELF .eh_frame requires relocation application", ErrorCode::unsupported);
    require(section.flags & 2, "ELF .eh_frame section is not allocated", ErrorCode::unsupported);
    require(section.type != 8, "ELF .eh_frame is SHT_NOBITS", ErrorCode::unsupported);
    require(!(section.flags & 0x800), "Compressed ELF .eh_frame is unsupported", ErrorCode::unsupported);
    const auto machine = metadata.header.machine;
    const bool supported_machine = (machine == 3 && !metadata.header.is_64) ||
                                   (machine == 62 && metadata.header.is_64) ||
                                   (machine == 40 && !metadata.header.is_64) ||
                                   (machine == 183 && metadata.header.is_64) || machine == 243 ||
                                   (machine == 8 && !metadata.header.is_64);
    require(supported_machine, "ELF machine has no supported .eh_frame root semantics", ErrorCode::unsupported);
    require(section.size <= metadata_limit, "ELF .eh_frame exceeds metadata budget", ErrorCode::resource_limit);
    budget.include(section.size);
    Reader reader(storage, metadata.header.order, stop);
    const auto view = reader.bytes(section.offset, static_cast<std::size_t>(section.size));
    const auto data = view.bytes;
    std::vector<ElfUnwindRange> parsed;
    std::vector<ElfEhFrameFunction> parsed_cfi;
    std::map<std::size_t, Cie> cies;
    std::size_t cursor = 0;
    const unsigned address_size = metadata.header.is_64 ? 8 : 4;
    while (cursor < data.size()) {
        canceled(stop);
        require(data.size() - cursor >= 4, "Truncated ELF .eh_frame entry length");
        Cursor header{reader, data, cursor, data.size()};
        const auto length32 = header.fixed(4);
        if (length32 == 0) {
            require(std::all_of(data.begin() + static_cast<std::ptrdiff_t>(header.at), data.end(),
                                [](std::byte value) { return value == std::byte{0}; }),
                    "Nonzero bytes follow the ELF .eh_frame terminator");
            cursor = data.size();
            break;
        }
        const bool extended = length32 == UINT32_MAX;
        const auto id_width = extended ? 8u : 4u;
        const auto length = extended ? header.fixed(8) : length32;
        require(length >= id_width && length <= data.size() - header.at,
                "ELF .eh_frame entry exceeds section bounds");
        const auto entry_start = cursor;
        const auto body_start = header.at;
        const auto entry_end = body_start + static_cast<std::size_t>(length);
        Cursor entry{reader, data, body_start, entry_end};
        const auto id_field = entry.at;
        const auto id = entry.fixed(id_width);
        if (id == 0) {
            const auto version = entry.fixed(1);
            require(version == 1 || version == 3 || version == 4,
                    "Unsupported ELF .eh_frame CIE version", ErrorCode::unsupported);
            const auto augmentation = entry.cstring();
            if (version == 4) {
                require(entry.fixed(1) == address_size && entry.fixed(1) == 0,
                        "Unsupported ELF .eh_frame CIE address/segment size", ErrorCode::unsupported);
            }
            Cie cie;
            cie.file_offset = add(section.offset, entry_start);
            cie.code_alignment = entry.uleb();
            cie.data_alignment = entry.sleb();
            cie.return_register = version == 1 ? entry.fixed(1) : entry.uleb();
            if (augmentation.empty()) {
                cie.fde_encoding = 0;
            } else {
                require(augmentation.front() == 'z',
                        "Unsupported ELF .eh_frame CIE augmentation", ErrorCode::unsupported);
                cie.has_z_augmentation = true;
                const auto augmentation_size = entry.uleb();
                require(augmentation_size <= entry.end - entry.at,
                        "ELF .eh_frame CIE augmentation exceeds record bounds");
                Cursor payload{reader, data, entry.at, entry.at + static_cast<std::size_t>(augmentation_size)};
                bool seen_p = false, seen_l = false, seen_r = false;
                for (std::size_t i = 1; i < augmentation.size(); ++i) {
                    canceled(stop);
                    const auto encoding_offset = add(section.offset, payload.at);
                    switch (augmentation[i]) {
                    case 'P': {
                        require(!seen_p, "Duplicate ELF .eh_frame P augmentation");
                        seen_p = true;
                        const auto encoding = static_cast<std::uint8_t>(payload.fixed(1));
                        cie.personality = exception_pointer(payload, encoding, encoding_offset, section, address_size);
                        break;
                    }
                    case 'L':
                        require(!seen_l, "Duplicate ELF .eh_frame L augmentation");
                        seen_l = true;
                        cie.lsda_encoding = static_cast<std::uint8_t>(payload.fixed(1));
                        cie.lsda_encoding_file_offset = encoding_offset;
                        validate_encoding(*cie.lsda_encoding, true, true);
                        break;
                    case 'R':
                        require(!seen_r, "Duplicate ELF .eh_frame R augmentation");
                        seen_r = true;
                        cie.fde_encoding = static_cast<std::uint8_t>(payload.fixed(1));
                        validate_encoding(cie.fde_encoding, false);
                        break;
                    default:
                        require(false, "Unsupported ELF .eh_frame CIE augmentation", ErrorCode::unsupported);
                    }
                }
                entry.at = payload.end;
            }
            cie.instructions.assign(data.begin() + static_cast<std::ptrdiff_t>(entry.at),
                                    data.begin() + static_cast<std::ptrdiff_t>(entry.end));
            require(cie.code_alignment != 0, "ELF .eh_frame CIE has zero code alignment");
            budget.include(sizeof(std::pair<const std::size_t, Cie>) + 4 * sizeof(void *));
            require(cies.emplace(entry_start, std::move(cie)).second, "Duplicate ELF .eh_frame CIE location");
        } else {
            require(id <= id_field, "ELF .eh_frame FDE CIE pointer precedes section", ErrorCode::malformed);
            // Unlike .debug_frame, the .eh_frame CIE pointer is a backward
            // distance from this field to the CIE record's length field.
            const auto cie_at = id_field - static_cast<std::size_t>(id);
            const auto cie = cies.find(cie_at);
            require(cie != cies.end(), "ELF .eh_frame FDE references an unknown CIE", ErrorCode::unsupported);
            const auto location_field = entry.at;
            const auto field_address = add(section.address, location_field);
            const auto encoded_begin = encoded(entry, cie->second.fde_encoding, field_address, address_size, true);
            const auto begin_value = machine == 40 ? encoded_begin & ~UINT64_C(1) : encoded_begin;
            const auto range_encoding = static_cast<std::uint8_t>(cie->second.fde_encoding & 0x0f);
            const auto range_value = encoded(entry, range_encoding, 0, address_size, false);
            require(range_value > 0, "ELF .eh_frame FDE has an empty code range");
            std::optional<ElfEhFramePointer> lsda;
            if (cie->second.has_z_augmentation) {
                const auto augmentation_size = entry.uleb();
                require(augmentation_size <= entry.end - entry.at,
                        "ELF .eh_frame FDE augmentation exceeds record bounds");
                Cursor payload{reader, data, entry.at, entry.at + static_cast<std::size_t>(augmentation_size)};
                if (cie->second.lsda_encoding && *cie->second.lsda_encoding != 0xff)
                    lsda = exception_pointer(payload, *cie->second.lsda_encoding,
                        *cie->second.lsda_encoding_file_offset, section, address_size);
                entry.at = payload.end;
            }
            std::vector<std::byte> fde_instructions(
                data.begin() + static_cast<std::ptrdiff_t>(entry.at),
                data.begin() + static_cast<std::ptrdiff_t>(entry.end));
            require(begin_value <= UINT64_MAX - range_value,
                    "ELF .eh_frame FDE code range overflows", ErrorCode::overflow);
            require(metadata.header.is_64 || (begin_value <= UINT32_MAX && range_value - 1 <= UINT32_MAX - begin_value),
                    "ELF32 .eh_frame FDE range exceeds target address width", ErrorCode::overflow);
            const Address begin{{0}, begin_value};
            auto end = begin_value + range_value;
            for (auto address = begin_value; address < end;) {
                canceled(stop);
                const auto *segment = image.segment_at({{0}, address});
                require(segment && segment->executable && address - segment->begin.offset < segment->file_size,
                        "ELF .eh_frame FDE does not cover initialized executable code");
                address += std::min(end - address, segment->file_size - (address - segment->begin.offset));
            }
            budget.include(sizeof(ElfUnwindRange));
            parsed.push_back({section.index, add(section.offset, entry_start), entry_end - entry_start,
                              begin, range_value});
            if (((machine == 62 || machine == 183) && metadata.header.is_64) ||
                (machine == 40 && !metadata.header.is_64) || machine == 243) {
                budget.include(sizeof(ElfEhFrameFunction) + cie->second.instructions.size() + fde_instructions.size());
                parsed_cfi.push_back({section.index, add(section.offset, entry_start), entry_end - entry_start,
                    begin, range_value, cie->second.code_alignment, cie->second.data_alignment,
                    cie->second.return_register, cie->second.instructions, std::move(fde_instructions),
                    cie->second.personality, std::move(lsda), cie->second.lsda_encoding,
                    cie->second.lsda_encoding_file_offset, cie->second.file_offset});
            }
        }
        cursor = entry_end;
    }
    // Publish both collections only after the entire section has been accepted.
    output = std::move(parsed);
    cfi_output = std::move(parsed_cfi);
}
} // namespace

Result<bool> read_unwind_ranges(const ByteStorage &storage, const Image &image, ElfMetadata &metadata,
                                Budget &budget, std::stop_token stop) {
    try {
        bool found = false;
        metadata.unwind_ranges.clear();
        metadata.eh_frame_functions.clear();
        std::optional<Error> first_failure;
        // Parse the runtime source first, independently of ELF section order.
        // A malformed optional debug section cannot discard accepted EH CFI.
        for (const std::string_view section_name : {".eh_frame", ".debug_frame"}) {
            for (const auto &section : metadata.sections) {
                canceled(stop);
                if (section.name != section_name || section.size == 0) continue;
                found = true;
                std::vector<ElfUnwindRange> ranges;
                std::vector<ElfEhFrameFunction> functions;
                try {
                    if (section_name == ".debug_frame")
                        parse_debug_frame_section(storage, image, metadata, section, budget, stop, ranges, functions);
                    else parse_section(storage, image, metadata, section, budget, stop, ranges, functions);
                } catch (const Failure &failure) {
                    if (failure.error.code == ErrorCode::canceled || failure.error.code == ErrorCode::resource_limit) throw;
                    if (!first_failure) first_failure = failure.error;
                    continue;
                }
                // Reserve both destinations before publishing either accepted
                // collection, preserving the existing per-section transaction.
                metadata.unwind_ranges.reserve(metadata.unwind_ranges.size() + ranges.size());
                metadata.eh_frame_functions.reserve(metadata.eh_frame_functions.size() + functions.size());
                metadata.unwind_ranges.insert(metadata.unwind_ranges.end(),
                    std::make_move_iterator(ranges.begin()), std::make_move_iterator(ranges.end()));
                metadata.eh_frame_functions.insert(metadata.eh_frame_functions.end(),
                    std::make_move_iterator(functions.begin()), std::make_move_iterator(functions.end()));
            }
        }
        std::sort(metadata.unwind_ranges.begin(), metadata.unwind_ranges.end(), [](const auto &a, const auto &b) {
            return std::tie(a.begin.space.value, a.begin.offset, a.file_offset) <
                   std::tie(b.begin.space.value, b.begin.offset, b.file_offset);
        });
        if (first_failure) return *first_failure;
        return found;
    } catch (const Failure &failure) {
        return failure.error;
    } catch (const std::bad_alloc &) {
        return Error{ErrorCode::resource_limit, "Cannot allocate ELF unwind metadata"};
    }
}

Result<bool> read_arm_ehabi(const ByteStorage &storage, const Image &image, ElfMetadata &metadata,
                            Budget &budget, std::stop_token stop) {
    try {
        metadata.arm_ehabi_functions.clear();
        std::vector<const ElfSection *> tables, extabs;
        for (const auto &section : metadata.sections) {
            canceled(stop);
            if (section.name == ".ARM.exidx" || section.type == 0x70000001u)
                tables.push_back(&section);
            if (section.name == ".ARM.extab")
                extabs.push_back(&section);
        }
        if (tables.empty()) return false;
        require(metadata.header.object_type != 1,
                "Relocatable ELF .ARM.exidx requires relocation application", ErrorCode::unsupported);
        require((metadata.header.object_type == 2 || metadata.header.object_type == 3) &&
                    !metadata.header.is_64 && metadata.header.order == ByteOrder::little &&
                    metadata.header.machine == 40,
                "ELF .ARM.exidx roots require a linked little-endian ELF32 ARM image", ErrorCode::unsupported);
        Reader reader(storage, ByteOrder::little, stop);
        std::sort(tables.begin(), tables.end(), [](const auto *a, const auto *b) {
            return std::tie(a->address, a->offset, a->index) < std::tie(b->address, b->offset, b->index);
        });
        std::sort(extabs.begin(), extabs.end(), [](const auto *a, const auto *b) {
            return std::tie(a->address, a->offset, a->index) < std::tie(b->address, b->offset, b->index);
        });
        const auto prel31 = [&](std::uint32_t raw, std::uint64_t place) {
            std::int64_t delta = raw & 0x7fffffffu;
            if (delta & 0x40000000ll) delta |= ~0x7fffffffll;
            const auto target = add_signed(place, delta);
            require(target <= UINT32_MAX, "ELF .ARM.exidx PREL31 target exceeds ELF32", ErrorCode::overflow);
            return target;
        };
        std::vector<ElfArmEhabiFunction> parsed;
        std::uint64_t previous_table_end = 0;
        bool have_previous_table = false;
        std::optional<std::uint64_t> previous_start;
        std::uint64_t count = 0;
        for (const auto *section : tables) {
            canceled(stop);
            require((section->flags & 2) && !(section->flags & 0x800) && section->type != 8,
                    "ELF .ARM.exidx must be allocated initialized data", ErrorCode::unsupported);
            require(section->entry_size == 0 || section->entry_size == 8,
                    "ELF .ARM.exidx has an unsupported entry size", ErrorCode::unsupported);
            require(section->size % 8 == 0, "ELF .ARM.exidx size is not a whole number of rows");
            const auto section_end = add(section->address, section->size);
            require(section_end <= UINT32_MAX + UINT64_C(1), "ELF .ARM.exidx exceeds ELF32 address space", ErrorCode::overflow);
            require(!have_previous_table || previous_table_end <= section->address,
                    "ELF .ARM.exidx table sections overlap or are out of order");
            previous_table_end = section_end;
            have_previous_table = true;
            require(section->size <= metadata_limit, "ELF .ARM.exidx exceeds metadata budget", ErrorCode::resource_limit);
            budget.include(section->size);
            const auto bytes = reader.bytes(section->offset, static_cast<std::size_t>(section->size)).bytes;
            for (std::uint64_t offset = 0; offset < section->size; offset += 8) {
                canceled(stop);
                require(++count <= metadata_limit / sizeof(ElfArmEhabiFunction),
                        "ELF .ARM.exidx row count exceeds metadata budget", ErrorCode::resource_limit);
                const auto row = static_cast<std::size_t>(offset);
                const auto raw_start = static_cast<std::uint32_t>(reader.value(bytes, row, 4));
                const auto raw_recipe = static_cast<std::uint32_t>(reader.value(bytes, row + 4, 4));
                const auto decoded = prel31(raw_start, add(section->address, offset));
                const Address begin{{0}, decoded & ~UINT64_C(1)};
                require(!previous_start || begin.offset > *previous_start,
                        "ELF .ARM.exidx function starts are not strictly increasing");
                previous_start = begin.offset;
                const auto *segment = image.segment_at(begin);
                require(segment && segment->executable && begin.offset >= segment->begin.offset &&
                            begin.offset - segment->begin.offset < segment->file_size,
                        "ELF .ARM.exidx row does not start in initialized executable memory");
                ElfArmEhabiFunction function;
                function.section = section->index;
                function.file_offset = add(section->offset, offset);
                function.begin = begin;
                function.raw_start = raw_start;
                function.raw_recipe = raw_recipe;
                if (raw_recipe == 1) {
                    function.recipe_kind = ElfArmEhabiRecipeKind::cantunwind;
                } else if (raw_recipe & 0x80000000u) {
                    function.recipe_kind = ElfArmEhabiRecipeKind::compact_inline;
                } else {
                    function.recipe_kind = ElfArmEhabiRecipeKind::extab_reference;
                    const auto target = prel31(raw_recipe, add(add(section->address, offset), 4));
                    require((target & 3) == 0, "ELF .ARM.exidx extab reference is not word aligned");
                    const ElfSection *extab = nullptr;
                    for (const auto *candidate : extabs) {
                        if (target >= candidate->address && target - candidate->address <= candidate->size &&
                            candidate->size - (target - candidate->address) >= 4) {
                            require((candidate->flags & 2) && candidate->type == 1 && !(candidate->flags & 0x800),
                                    "ELF .ARM.extab is not allocated initialized data", ErrorCode::unsupported);
                            extab = candidate;
                            break;
                        }
                    }
                    require(extab != nullptr, "ELF .ARM.exidx extab reference leaves .ARM.extab", ErrorCode::unsupported);
                    const auto extab_offset = target - extab->address;
                    const auto extab_file = add(extab->offset, extab_offset);
                    const auto word = reader.bytes(extab_file, 4).bytes;
                    function.extab_address = Address{{0}, target};
                    function.extab_word = static_cast<std::uint32_t>(reader.value(word, 0, 4));
                    function.extab_section = extab->index;
                    function.extab_file_offset = extab_file;
                }
                budget.include(sizeof(ElfArmEhabiFunction));
                parsed.push_back(std::move(function));
            }
        }
        metadata.arm_ehabi_functions = std::move(parsed);
        return true;
    } catch (const Failure &failure) {
        return failure.error;
    } catch (const std::bad_alloc &) {
        return Error{ErrorCode::resource_limit, "Cannot allocate ELF ARM EHABI metadata"};
    }
}
} // namespace hexlab::elf_detail
