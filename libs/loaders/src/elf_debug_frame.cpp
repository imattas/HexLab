#include "elf_internal.hpp"
#include <bit>
#include <span>

namespace hexlab::elf_detail {
namespace {
struct FrameCursor {
    const Reader &reader;
    std::span<const std::byte> bytes;
    std::size_t at = 0, end = 0;
    std::uint64_t fixed(unsigned width) {
        require(at <= end && width <= end - at, "Truncated ELF .debug_frame operand");
        const auto value = reader.value(bytes, at, width); at += width; return value;
    }
    std::uint64_t uleb() {
        std::uint64_t value = 0;
        for (unsigned i = 0; i < 10; ++i) {
            const auto byte = fixed(1);
            require(i != 9 || (byte & 0xfe) == 0, ".debug_frame ULEB128 overflows", ErrorCode::overflow);
            value |= (byte & 0x7f) << (i * 7);
            if (!(byte & 0x80)) return value;
        }
        throw Failure{{ErrorCode::malformed, ".debug_frame ULEB128 exceeds ten bytes"}};
    }
    std::int64_t sleb() {
        std::uint64_t value = 0;
        for (unsigned i = 0; i < 10; ++i) {
            const auto byte = fixed(1);
            require(i != 9 || byte == 0 || byte == 0x7f, ".debug_frame SLEB128 overflows", ErrorCode::overflow);
            value |= (byte & 0x7f) << (i * 7);
            const auto bits = (i + 1) * 7;
            if (!(byte & 0x80)) {
                if (bits < 64 && (byte & 0x40)) value |= UINT64_MAX << bits;
                return std::bit_cast<std::int64_t>(value);
            }
        }
        throw Failure{{ErrorCode::malformed, ".debug_frame SLEB128 exceeds ten bytes"}};
    }
};
struct FrameRecord {
    std::size_t begin = 0, body = 0, end = 0;
    std::uint64_t id = 0;
    bool cie = false;
};
struct FrameCie {
    std::uint64_t file_offset = 0, code_alignment = 0, return_register = 0;
    std::int64_t data_alignment = 0;
    bool has_z_augmentation = false;
    std::vector<std::byte> instructions;
};
constexpr std::size_t max_frame_records = 65536;
constexpr std::size_t max_cfi_bytes = 1024 * 1024;

bool zero_tail(std::span<const std::byte> bytes, std::size_t at, std::stop_token stop) {
    for (; at < bytes.size(); ++at) {
        if ((at & 0xfffu) == 0) canceled(stop);
        if (bytes[at] != std::byte{0}) return false;
    }
    return true;
}
} // namespace

void parse_debug_frame_section(const ByteStorage &storage, const Image &image, const ElfMetadata &metadata,
    const ElfSection &section, Budget &budget, std::stop_token stop,
    std::vector<ElfUnwindRange> &ranges, std::vector<ElfEhFrameFunction> &functions) {
    require(metadata.header.object_type == 2 || metadata.header.object_type == 3,
        "ELF .debug_frame requires linked EXEC/DYN addresses; relocatable CFI is unsupported", ErrorCode::unsupported);
    require(section.type != 8 && !(section.flags & 0x800),
        "NOBITS or compressed ELF .debug_frame is unsupported", ErrorCode::unsupported);
    const auto machine = metadata.header.machine;
    const bool supported = (machine == 3 && !metadata.header.is_64) || (machine == 62 && metadata.header.is_64) ||
        (machine == 40 && !metadata.header.is_64) || (machine == 183 && metadata.header.is_64) || machine == 243 ||
        (machine == 8 && !metadata.header.is_64);
    require(supported, "ELF machine has no supported .debug_frame root semantics", ErrorCode::unsupported);
    require(section.size <= metadata_limit, "ELF .debug_frame exceeds metadata budget", ErrorCode::resource_limit);
    budget.include(section.size);
    const unsigned address_size = metadata.header.is_64 ? 8 : 4;
    Reader reader(storage, metadata.header.order, stop);
    const auto view = reader.bytes(section.offset, static_cast<std::size_t>(section.size));
    const auto bytes = view.bytes;
    std::vector<FrameRecord> records;
    for (std::size_t at = 0; at < bytes.size();) {
        canceled(stop);
        if (bytes.size() - at < 4) {
            require(zero_tail(bytes, at, stop), "Nonzero truncated .debug_frame length"); break;
        }
        require(at % address_size == 0, "ELF .debug_frame record is not address-size aligned");
        FrameCursor header{reader, bytes, at, bytes.size()};
        const auto length32 = header.fixed(4);
        if (!length32) {
            require(zero_tail(bytes, at, stop), "Nonzero bytes follow .debug_frame zero padding"); break;
        }
        require(length32 < 0xfffffff0u || length32 == UINT32_MAX,
            "Reserved .debug_frame initial length", ErrorCode::malformed);
        const bool dwarf64 = length32 == UINT32_MAX;
        const auto length = dwarf64 ? header.fixed(8) : length32;
        const auto id_size = dwarf64 ? 8u : 4u;
        require(length >= id_size && length <= bytes.size() - header.at, "ELF .debug_frame record exceeds section");
        const auto end = header.at + static_cast<std::size_t>(length);
        require((end - at) % address_size == 0, "ELF .debug_frame record size is not address-size aligned");
        FrameCursor entry{reader, bytes, header.at, end};
        const auto id = entry.fixed(id_size);
        require(records.size() < max_frame_records, "ELF .debug_frame exceeds 65536 records", ErrorCode::resource_limit);
        budget.include(sizeof(FrameRecord));
        records.push_back({at, entry.at, end, id, id == (dwarf64 ? UINT64_MAX : UINT32_MAX)});
        at = end;
    }
    // Index all CIEs before resolving FDEs: .debug_frame pointers are absolute
    // section offsets and may legally refer forward, unlike .eh_frame backrefs.
    std::map<std::size_t, FrameCie> cies;
    for (const auto &record : records) {
        canceled(stop);
        if (!record.cie) continue;
        FrameCursor cursor{reader, bytes, record.body, record.end};
        const auto version = cursor.fixed(1);
        require(version == 1 || version == 3 || version == 4, "Unsupported .debug_frame CIE version", ErrorCode::unsupported);
        std::string augmentation;
        while (true) {
            const auto character = cursor.fixed(1);
            if (!character) break;
            require(augmentation.size() < 16, ".debug_frame CIE augmentation string is too long",
                ErrorCode::resource_limit);
            augmentation.push_back(static_cast<char>(character));
        }
        const bool has_z_augmentation = augmentation == "zR";
        require(augmentation.empty() || has_z_augmentation,
            "Unsupported .debug_frame CIE augmentation", ErrorCode::unsupported);
        if (version == 4) {
            require(cursor.fixed(1) == address_size && cursor.fixed(1) == 0,
                "Unsupported .debug_frame address/segment size", ErrorCode::unsupported);
        }
        FrameCie cie;
        cie.file_offset = add(section.offset, record.begin);
        cie.code_alignment = cursor.uleb(); cie.data_alignment = cursor.sleb();
        cie.return_register = version == 1 ? cursor.fixed(1) : cursor.uleb();
        cie.has_z_augmentation = has_z_augmentation;
        if (has_z_augmentation) {
            const auto augmentation_size = cursor.uleb();
            require(augmentation_size == 1 && cursor.fixed(1) == 0,
                "Only native absolute-pointer .debug_frame zR encoding is supported", ErrorCode::unsupported);
        }
        require(cie.code_alignment != 0, "ELF .debug_frame CIE has zero code alignment");
        const auto size = cursor.end - cursor.at;
        require(size <= max_cfi_bytes, ".debug_frame CIE instructions exceed 1 MiB", ErrorCode::resource_limit);
        budget.include(sizeof(std::pair<const std::size_t, FrameCie>) + 4 * sizeof(void *) + size);
        cie.instructions.assign(bytes.begin() + static_cast<std::ptrdiff_t>(cursor.at), bytes.begin() + static_cast<std::ptrdiff_t>(cursor.end));
        require(cies.emplace(record.begin, std::move(cie)).second, "Duplicate .debug_frame CIE offset");
    }
    require(records.empty() || !cies.empty(), "Nonempty .debug_frame contains no CIE");
    std::vector<ElfUnwindRange> parsed_ranges;
    std::vector<ElfEhFrameFunction> parsed_functions;
    for (const auto &record : records) {
        canceled(stop);
        if (record.cie) continue;
        require(record.id < bytes.size(), ".debug_frame CIE pointer exceeds its section");
        const auto found = cies.find(static_cast<std::size_t>(record.id));
        require(found != cies.end(), ".debug_frame FDE does not reference a CIE record start");
        const auto &cie = found->second;
        FrameCursor cursor{reader, bytes, record.body, record.end};
        const auto raw_begin = cursor.fixed(address_size);
        const auto begin = machine == 40 ? raw_begin & ~UINT64_C(1) : raw_begin;
        const auto size = cursor.fixed(address_size);
        if (cie.has_z_augmentation) {
            const auto augmentation_size = cursor.uleb();
            require(augmentation_size == 0,
                "Unexpected .debug_frame FDE augmentation data", ErrorCode::unsupported);
        }
        const std::uint64_t limit = address_size == 4 ? UINT32_MAX : UINT64_MAX;
        require(size != 0 && begin <= limit && size - 1 <= limit - begin,
            "ELF .debug_frame range is empty or exceeds target address width", ErrorCode::overflow);
        require(size <= UINT64_MAX - begin, "ELF .debug_frame range overflows", ErrorCode::overflow);
        const auto end = begin + size;
        for (auto at = begin; at < end;) {
            canceled(stop);
            const auto *segment = image.segment_at({{0}, at});
            require(segment && segment->executable && at - segment->begin.offset < segment->file_size,
                "ELF .debug_frame FDE does not cover initialized executable bytes");
            at += std::min(end - at, segment->file_size - (at - segment->begin.offset));
        }
        budget.include(sizeof(ElfUnwindRange));
        parsed_ranges.push_back({section.index, add(section.offset, record.begin), record.end - record.begin,
            {{0}, begin}, size, ElfCfiSectionKind::debug_frame});
        const bool live = (machine == 62 && metadata.header.is_64) || (machine == 183 && metadata.header.is_64) ||
            (machine == 40 && !metadata.header.is_64) || machine == 243;
        if (!live) continue;
        const auto instruction_size = cursor.end - cursor.at;
        require(instruction_size <= max_cfi_bytes - cie.instructions.size(),
            "Combined .debug_frame CIE/FDE instructions exceed 1 MiB", ErrorCode::resource_limit);
        budget.include(sizeof(ElfEhFrameFunction) + cie.instructions.size() + instruction_size);
        ElfEhFrameFunction fde;
        fde.section = section.index; fde.file_offset = add(section.offset, record.begin);
        fde.record_size = record.end - record.begin; fde.begin = {{0}, begin}; fde.size = size;
        fde.code_alignment = cie.code_alignment; fde.data_alignment = cie.data_alignment;
        fde.return_register = cie.return_register; fde.cie_file_offset = cie.file_offset;
        fde.cie_instructions = cie.instructions;
        fde.instructions.assign(bytes.begin() + static_cast<std::ptrdiff_t>(cursor.at), bytes.begin() + static_cast<std::ptrdiff_t>(cursor.end));
        fde.source_kind = ElfCfiSectionKind::debug_frame;
        parsed_functions.push_back(std::move(fde));
    }
    // Publish neither roots nor recipes until every record in this section is
    // accepted. A malformed later FDE cannot leave earlier guessed roots.
    ranges = std::move(parsed_ranges); functions = std::move(parsed_functions);
}
} // namespace hexlab::elf_detail
