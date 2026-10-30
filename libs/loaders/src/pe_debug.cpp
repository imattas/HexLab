#include "pe_internal.hpp"
#include <algorithm>
#include <cctype>
#include <iterator>
#include <limits>
#include <new>

namespace hexlab::pe_detail {
Result<std::size_t> read_debug_directory(const Image &image, const Directory &directory,
                                        ImageMetadata &metadata, std::stop_token stop) {
    return guarded([&]() -> std::size_t {
        ImageReader r(image, metadata, stop);
        require(directory.size % 28 == 0, "PE debug directory has a partial entry");
        const auto count = directory.size / 28;
        require(count <= record_limit, "PE debug directory exceeds record budget");
        std::vector<PeCodeViewIdentity> codeview;
        std::vector<PePdbChecksum> pdb_checksums;
        std::vector<PeDebugDirectoryEntry> entries;
        std::vector<PeFpoRecord> fpo_records;
        std::vector<PePogoData> pogo_data;
        std::size_t pogo_entry_count = 0;
        std::size_t pogo_name_bytes = 0;
        for (std::uint32_t index = 0; index < count; ++index) {
            canceled(stop);
            const auto at = std::uint64_t{directory.location} + std::uint64_t{index} * 28;
            PeDebugDirectoryEntry entry;
            entry.timestamp = r.integer<std::uint32_t>(at + 4);
            entry.major_version = r.integer<std::uint16_t>(at + 8);
            entry.minor_version = r.integer<std::uint16_t>(at + 10);
            const auto type = r.integer<std::uint32_t>(at + 12);
            entry.type = type;
            entry.data_size = r.integer<std::uint32_t>(at + 16);
            entry.data_rva = r.integer<std::uint32_t>(at + 20);
            entry.raw_offset = r.integer<std::uint32_t>(at + 24);
            entry.entry = {index, r.sources(at, 28)};
            if (entry.data_size) {
                require(entry.raw_offset != 0 || entry.data_rva != 0,
                        "PE debug payload has no file location");
                if (entry.raw_offset) {
                    require(entry.raw_offset <= image.storage()->size() &&
                            entry.data_size <= image.storage()->size() - entry.raw_offset,
                            "PE debug raw payload exceeds input");
                    entry.raw_data = {{{entry.raw_offset}, entry.data_size}};
                } else {
                    entry.raw_data = r.sources(entry.data_rva, entry.data_size);
                }
            }
            if (type == 16) { // IMAGE_DEBUG_TYPE_REPRO.
                entry.reproducible_build = true;
                if (entry.data_size) {
                    constexpr std::uint32_t repro_payload_limit = 4096;
                    require(entry.data_size >= 5 && entry.data_size <= repro_payload_limit,
                            "PE reproducible-build hash payload has an invalid bounded size");
                    std::vector<std::byte> payload;
                    if (entry.raw_offset) {
                        FileReader file_reader(*image.storage());
                        const auto view = file_reader.bytes(entry.raw_offset, entry.data_size,
                                                            "reproducible-build debug payload");
                        payload.assign(view.bytes.begin(), view.bytes.end());
                    } else {
                        payload = r.bytes(entry.data_rva, entry.data_size);
                    }
                    const auto hash_size = std::to_integer<std::uint32_t>(payload[0]) |
                        (std::to_integer<std::uint32_t>(payload[1]) << 8) |
                        (std::to_integer<std::uint32_t>(payload[2]) << 16) |
                        (std::to_integer<std::uint32_t>(payload[3]) << 24);
                    require(hash_size != 0 && hash_size == entry.data_size - 4,
                            "PE reproducible-build hash length disagrees with its payload");
                    entry.reproducible_hash.assign(payload.begin() + 4, payload.end());
                    const auto hash_source = entry.raw_offset
                        ? std::vector<PeSourceSpan>{{FileOffset{std::uint64_t{entry.raw_offset} + 4}, hash_size}}
                        : r.sources(std::uint64_t{entry.data_rva} + 4, hash_size);
                    entry.reproducible_hash_source = PeRecordSource{index, hash_source};
                }
            }
            if (type == 20) { // IMAGE_DEBUG_TYPE_EX_DLLCHARACTERISTICS.
                require(entry.data_size == 4,
                        "PE extended DLL characteristics payload must be one DWORD");
                std::vector<std::byte> payload;
                if (entry.raw_offset) {
                    FileReader file_reader(*image.storage());
                    const auto view = file_reader.bytes(entry.raw_offset, 4,
                                                        "extended DLL characteristics payload");
                    payload.assign(view.bytes.begin(), view.bytes.end());
                } else {
                    payload = r.bytes(entry.data_rva, 4);
                }
                const auto flags = std::to_integer<std::uint32_t>(payload[0]) |
                    (std::to_integer<std::uint32_t>(payload[1]) << 8) |
                    (std::to_integer<std::uint32_t>(payload[2]) << 16) |
                    (std::to_integer<std::uint32_t>(payload[3]) << 24);
                entry.extended_dll_characteristics = flags;
                const auto source = entry.raw_offset
                    ? std::vector<PeSourceSpan>{{FileOffset{entry.raw_offset}, 4}}
                    : r.sources(entry.data_rva, 4);
                entry.extended_dll_characteristics_source = PeRecordSource{index, source};
            }
            entries.push_back(entry);
            if (type == 3) { // IMAGE_DEBUG_TYPE_FPO, legacy x86 frame metadata.
                require(metadata.machine == 0x14c,
                        "PE FPO debug records are only supported for x86 images", ErrorCode::unsupported);
                require(entry.data_size % 16 == 0, "PE FPO debug payload has a partial 16-byte record");
                const auto fpo_count = entry.data_size / 16;
                require(fpo_count <= record_limit - fpo_records.size(),
                        "PE FPO record count exceeds inspection budget", ErrorCode::resource_limit);
                std::vector<std::byte> payload;
                if (entry.raw_offset) {
                    FileReader file_reader(*image.storage());
                    const auto raw_payload = file_reader.bytes(entry.raw_offset, entry.data_size, "FPO debug payload");
                    payload.assign(raw_payload.bytes.begin(), raw_payload.bytes.end());
                } else if (entry.data_size) {
                    payload = r.bytes(entry.data_rva, entry.data_size);
                }
                std::uint64_t previous_end = fpo_records.empty() ? 0 :
                    std::uint64_t{fpo_records.back().begin_rva} + fpo_records.back().code_size;
                for (std::uint32_t row = 0; row < fpo_count; ++row) {
                    canceled(stop);
                    const auto offset = std::size_t{row} * 16;
                    const auto u16 = [&](std::size_t at) {
                        return static_cast<std::uint16_t>(std::to_integer<unsigned>(payload[at]) |
                            (std::to_integer<unsigned>(payload[at + 1]) << 8));
                    };
                    const auto u32 = [&](std::size_t at) {
                        return std::to_integer<std::uint32_t>(payload[at]) |
                            (std::to_integer<std::uint32_t>(payload[at + 1]) << 8) |
                            (std::to_integer<std::uint32_t>(payload[at + 2]) << 16) |
                            (std::to_integer<std::uint32_t>(payload[at + 3]) << 24);
                    };
                    PeFpoRecord record;
                    record.begin_rva = u32(offset);
                    record.code_size = u32(offset + 4);
                    record.local_dwords = u32(offset + 8);
                    record.parameter_dwords = u16(offset + 12);
                    const auto flags = u16(offset + 14);
                    record.prolog_size = static_cast<std::uint8_t>(flags & 0xffu);
                    record.saved_register_count = static_cast<std::uint8_t>((flags >> 8) & 7u);
                    record.has_seh = ((flags >> 11) & 1u) != 0;
                    record.uses_base_pointer = ((flags >> 12) & 1u) != 0;
                    require(((flags >> 13) & 1u) == 0,
                            "PE FPO record has a nonzero reserved bit");
                    record.frame_kind = static_cast<PeFpoFrameKind>((flags >> 14) & 3u);
                    require(record.code_size != 0 && record.prolog_size <= record.code_size,
                            "PE FPO record has an empty function or oversized prolog");
                    const auto end_rva = std::uint64_t{record.begin_rva} + record.code_size;
                    require(end_rva <= metadata.image_size &&
                                (fpo_records.empty() || record.begin_rva >= previous_end),
                            "PE FPO records overlap or exceed the image");
                    const auto address = r.address(record.begin_rva);
                    const auto *segment = image.segment_at(address);
                    require(segment && segment->executable && r.initialized_extent(record.begin_rva) >= record.code_size,
                            "PE FPO function range is not initialized executable code");
                    if (entry.raw_offset)
                        record.source = {row, {{FileOffset{std::uint64_t{entry.raw_offset} + offset}, 16}}};
                    else
                        record.source = {row, r.sources(std::uint64_t{entry.data_rva} + offset, 16)};
                    fpo_records.push_back(std::move(record));
                    previous_end = end_rva;
                }
            }
            if (type == 13) { // IMAGE_DEBUG_TYPE_POGO.
                constexpr std::uint32_t signature_ltcg = 0x4c544347u; // "LTCG"
                constexpr std::uint32_t signature_pgu = 0x50475500u; // "PGU\0"
                constexpr std::size_t payload_limit = 16u * 1024u * 1024u;
                require(entry.data_size <= payload_limit,
                        "PE POGO payload exceeds inspection budget", ErrorCode::resource_limit);
                require(entry.data_size >= 4, "PE POGO payload is shorter than its signature");
                std::vector<std::byte> payload;
                if (entry.raw_offset) {
                    FileReader file_reader(*image.storage());
                    const auto raw_payload = file_reader.bytes(entry.raw_offset, entry.data_size, "POGO debug payload");
                    payload.assign(raw_payload.bytes.begin(), raw_payload.bytes.end());
                } else {
                    payload = r.bytes(entry.data_rva, entry.data_size);
                }
                const auto u32 = [&](std::size_t at) {
                    return std::to_integer<std::uint32_t>(payload[at]) |
                        (std::to_integer<std::uint32_t>(payload[at + 1]) << 8) |
                        (std::to_integer<std::uint32_t>(payload[at + 2]) << 16) |
                        (std::to_integer<std::uint32_t>(payload[at + 3]) << 24);
                };
                PePogoData data;
                data.signature = u32(0);
                if (data.signature != signature_ltcg && data.signature != signature_pgu)
                    continue; // Preserve unrecognized POGO variants as generic debug payloads.
                if (entry.raw_offset)
                    data.signature_source = {0, {{FileOffset{entry.raw_offset}, 4}}};
                else
                    data.signature_source = {0, r.sources(entry.data_rva, 4)};
                std::size_t cursor = 4;
                while (cursor < payload.size()) {
                    canceled(stop);
                    const auto remaining = payload.size() - cursor;
                    if (remaining <= 3 && std::all_of(payload.begin() + static_cast<std::ptrdiff_t>(cursor), payload.end(),
                                                       [](std::byte value) { return value == std::byte{0}; }))
                        break;
                    require(remaining >= 10, "PE POGO entry has no complete RVA, size, and name");
                    const auto rva = u32(cursor);
                    const auto size = u32(cursor + 4);
                    const auto name_begin = cursor + 8;
                    const auto name_end = std::find(payload.begin() + static_cast<std::ptrdiff_t>(name_begin),
                                                    payload.end(), std::byte{0});
                    require(name_end != payload.end(), "PE POGO entry name is unterminated");
                    const auto name_size = static_cast<std::size_t>(name_end -
                        (payload.begin() + static_cast<std::ptrdiff_t>(name_begin)));
                    require(name_size != 0, "PE POGO entry name is empty");
                    require(name_size <= 65536 && name_size <= 16u * 1024u * 1024u - pogo_name_bytes,
                            "PE POGO aggregate name budget exceeded", ErrorCode::resource_limit);
                    require(pogo_entry_count < record_limit,
                            "PE POGO entry count exceeds inspection budget", ErrorCode::resource_limit);
                    require(rva <= metadata.image_size && size <= metadata.image_size - rva,
                            "PE POGO code/data range exceeds the image");
                    if (size) {
                        auto covered_rva = std::uint64_t{rva};
                        auto remaining = std::uint64_t{size};
                        while (remaining) {
                            const auto address = r.address(covered_rva);
                            const auto *segment = image.segment_at(address);
                            require(segment && address.offset >= segment->begin.offset,
                                    "PE POGO code/data range is not fully mapped");
                            const auto within = address.offset - segment->begin.offset;
                            require(within < segment->size,
                                    "PE POGO code/data range is not fully mapped");
                            const auto extent = std::min(remaining, segment->size - within);
                            require(extent != 0, "PE POGO code/data range mapping is empty");
                            covered_rva += extent;
                            remaining -= extent;
                        }
                    }
                    const auto raw_end = static_cast<std::size_t>(name_end - payload.begin()) + 1;
                    require(raw_end <= std::numeric_limits<std::size_t>::max() - 3,
                            "PE POGO entry alignment overflows", ErrorCode::overflow);
                    const auto next = (raw_end + 3) & ~std::size_t{3};
                    require(next <= payload.size(), "PE POGO entry padding exceeds payload");
                    PePogoEntry record;
                    record.rva = rva;
                    record.size = size;
                    record.name.assign(reinterpret_cast<const char *>(payload.data() + name_begin), name_size);
                    if (entry.raw_offset)
                        record.source = {static_cast<std::uint32_t>(pogo_entry_count),
                            {{FileOffset{std::uint64_t{entry.raw_offset} + cursor}, next - cursor}}};
                    else
                        record.source = {static_cast<std::uint32_t>(pogo_entry_count),
                            r.sources(std::uint64_t{entry.data_rva} + cursor, next - cursor)};
                    data.entries.push_back(std::move(record));
                    ++pogo_entry_count;
                    pogo_name_bytes += name_size;
                    cursor = next;
                }
                pogo_data.push_back(std::move(data));
            }
            if (type == 19) { // IMAGE_DEBUG_TYPE_PDB_CHECKSUM.
                constexpr std::size_t checksum_record_limit = 128;
                require(entry.data_size >= 3 && entry.data_size <= checksum_record_limit,
                        "PE PDB checksum record has an invalid bounded size");
                std::vector<std::byte> payload;
                if (entry.raw_offset) {
                    FileReader file_reader(*image.storage());
                    const auto view = file_reader.bytes(entry.raw_offset, entry.data_size, "PDB checksum payload");
                    payload.assign(view.bytes.begin(), view.bytes.end());
                } else {
                    payload = r.bytes(entry.data_rva, entry.data_size);
                }
                const auto terminator = std::find(payload.begin(), payload.end(), std::byte{0});
                require(terminator != payload.end() && terminator != payload.begin(),
                        "PE PDB checksum algorithm name is empty or unterminated");
                PePdbChecksum checksum;
                for (auto it = payload.begin(); it != terminator; ++it) {
                    const auto ch = std::to_integer<unsigned char>(*it);
                    require(ch >= 0x21 && ch <= 0x7e,
                            "PE PDB checksum algorithm name is not printable ASCII");
                    checksum.algorithm.push_back(static_cast<char>(ch));
                }
                const auto digest_begin = static_cast<std::size_t>(terminator - payload.begin()) + 1;
                require(digest_begin < payload.size(), "PE PDB checksum digest is empty");
                checksum.digest.assign(payload.begin() + static_cast<std::ptrdiff_t>(digest_begin), payload.end());
                std::string algorithm = checksum.algorithm;
                std::transform(algorithm.begin(), algorithm.end(), algorithm.begin(),
                               [](unsigned char ch) { return static_cast<char>(std::tolower(ch)); });
                if (algorithm == "sha256")
                    require(checksum.digest.size() == 32, "PE SHA256 PDB checksum has an invalid digest size");
                checksum.source = PeRecordSource{index, entry.raw_offset
                    ? std::vector<PeSourceSpan>{{FileOffset{entry.raw_offset}, entry.data_size}}
                    : r.sources(entry.data_rva, entry.data_size)};
                pdb_checksums.push_back(std::move(checksum));
                continue;
            }
            if (type != 2) continue; // IMAGE_DEBUG_TYPE_CODEVIEW
            const auto data_size = entry.data_size;
            const auto raw_offset = entry.raw_offset;
            require(data_size <= 1024 * 1024, "PE CodeView record exceeds inspection limit",
                    ErrorCode::resource_limit);
            require(data_size >= 5, "PE CodeView record is truncated");
            require(raw_offset <= image.storage()->size() && data_size <= image.storage()->size() - raw_offset,
                    "PE CodeView raw record exceeds input");
            const auto bytes = image.storage()->read_at({raw_offset}, data_size);
            if (!bytes) throw Failure{bytes.error()};
            require(bytes.value().bytes.size() == data_size, "Incomplete PE CodeView record", ErrorCode::io);
            const auto &record = bytes.value().bytes;
            PeCodeViewIdentity identity;
            const auto u32 = [&](std::size_t offset) {
                return std::to_integer<std::uint32_t>(record[offset]) |
                    (std::to_integer<std::uint32_t>(record[offset + 1]) << 8) |
                    (std::to_integer<std::uint32_t>(record[offset + 2]) << 16) |
                    (std::to_integer<std::uint32_t>(record[offset + 3]) << 24);
            };
            std::size_t path_offset = 0;
            if (record[0] == std::byte{'R'} && record[1] == std::byte{'S'} &&
                record[2] == std::byte{'D'} && record[3] == std::byte{'S'}) {
                require(data_size >= 25, "PE RSDS CodeView record is truncated");
                std::copy_n(record.begin() + 4, identity.guid.size(), identity.guid.begin());
                identity.age = u32(20);
                path_offset = 24;
            } else if (record[0] == std::byte{'N'} && record[1] == std::byte{'B'} &&
                       record[2] == std::byte{'1'} && record[3] == std::byte{'0'}) {
                require(data_size >= 17, "PE NB10 CodeView record is truncated");
                identity.rsds = false;
                identity.nb10_signature = u32(4);
                identity.nb10_timestamp = u32(8);
                identity.age = u32(12);
                path_offset = 16;
            } else {
                throw Failure{{ErrorCode::unsupported, "Unsupported PE CodeView signature"}};
            }
            const auto path_begin = record.begin() + static_cast<std::ptrdiff_t>(path_offset);
            const auto terminator = std::find(path_begin, record.end(), std::byte{0});
            require(terminator != record.end(), "PE CodeView path lacks a terminator");
            require(terminator != path_begin, "PE CodeView path is empty");
            identity.path.reserve(static_cast<std::size_t>(terminator - path_begin));
            for (auto it = path_begin; it != terminator; ++it)
                identity.path.push_back(static_cast<char>(std::to_integer<unsigned char>(*it)));
            identity.directory_entry = {index, r.sources(at, 28)};
            identity.record = {{{raw_offset}, data_size}};
            codeview.push_back(std::move(identity));
        }
        const auto count_read = entries.size() + codeview.size() + pdb_checksums.size() + fpo_records.size() + pogo_entry_count;
        if (metadata.pe) {
            metadata.pe->debug_directories.insert(metadata.pe->debug_directories.end(),
                                                   std::make_move_iterator(entries.begin()),
                                                   std::make_move_iterator(entries.end()));
            metadata.pe->codeview.insert(metadata.pe->codeview.end(),
                                         std::make_move_iterator(codeview.begin()),
                                         std::make_move_iterator(codeview.end()));
            metadata.pe->pdb_checksums.insert(metadata.pe->pdb_checksums.end(),
                                               std::make_move_iterator(pdb_checksums.begin()),
                                               std::make_move_iterator(pdb_checksums.end()));
            metadata.pe->fpo_records.insert(metadata.pe->fpo_records.end(),
                                            std::make_move_iterator(fpo_records.begin()),
                                            std::make_move_iterator(fpo_records.end()));
            metadata.pe->pogo_data.insert(metadata.pe->pogo_data.end(),
                                          std::make_move_iterator(pogo_data.begin()),
                                          std::make_move_iterator(pogo_data.end()));
        }
        return count_read;
    });
}

} // namespace hexlab::pe_detail

namespace hexlab {
Result<PeCoffSymbolTable> read_pe_coff_symbols(const LoadedImage &loaded, std::stop_token stop) {
    using namespace pe_detail;
    try {
        require(loaded.image != nullptr && loaded.metadata.pe.has_value(),
                "COFF symbols require a loaded PE image", ErrorCode::invalid_argument);
        const auto &storage = *loaded.image->storage();
        FileReader reader(storage);
        canceled(stop);
        const auto nt = reader.integer<std::uint32_t>(0x3c, "DOS e_lfanew");
        require(reader.integer<std::uint32_t>(nt, "signature") == 0x4550,
                "Missing PE signature");
        const auto coff = add(nt, 4, "COFF header position");
        const auto symbol_offset = reader.integer<std::uint32_t>(coff + 8, "COFF symbol-table pointer");
        const auto record_count = reader.integer<std::uint32_t>(coff + 12, "COFF symbol count");
        PeCoffSymbolTable result;
        result.symbol_table_file_offset = {symbol_offset};
        result.declared_record_count = record_count;
        require((symbol_offset == 0) == (record_count == 0),
                "PE COFF symbol-table pointer and record count disagree");
        if (!record_count)
            return result;

        constexpr std::uint32_t max_primary_symbols = 262144;
        constexpr std::uint32_t max_string_table_size = 16u * 1024u * 1024u;
        require(record_count <= record_limit,
                "PE COFF symbol record count exceeds parser budget", ErrorCode::resource_limit);
        const auto section_count = reader.integer<std::uint16_t>(coff + 2, "COFF section count");
        const auto optional_size = reader.integer<std::uint16_t>(coff + 16, "optional-header size");
        const auto section_table = add(add(coff, 20, "section-table position"), optional_size,
                                       "section-table position");
        const auto headers_end = add(section_table, std::uint64_t{section_count} * 40,
                                     "section-table extent");
        require(symbol_offset >= headers_end,
                "PE COFF symbol table overlaps PE headers or section declarations");
        const auto record_bytes = std::uint64_t{record_count} * 18;
        require(symbol_offset <= storage.size() && record_bytes <= storage.size() - symbol_offset,
                "PE COFF symbol records exceed input");
        const auto string_offset = add(symbol_offset, record_bytes, "COFF string-table position");
        require(string_offset <= storage.size() && 4 <= storage.size() - string_offset,
                "PE COFF string table is truncated");
        const auto string_size = reader.integer<std::uint32_t>(string_offset, "COFF string-table size");
        require(string_size >= 4 && string_size <= max_string_table_size,
                "PE COFF string-table size is invalid or exceeds its inspection budget",
                ErrorCode::resource_limit);
        require(string_size <= storage.size() - string_offset,
                "PE COFF string table exceeds input");
        result.string_table_file_offset = {string_offset};
        result.string_table_size = string_size;
        auto string_table = reader.bytes(string_offset, string_size, "COFF string table").bytes;

        const auto read_name = [&](std::uint64_t record_at) -> std::string {
            const auto name = reader.bytes(record_at, 8, "COFF symbol name").bytes;
            const auto first = std::to_integer<std::uint32_t>(name[0]) |
                               (std::to_integer<std::uint32_t>(name[1]) << 8) |
                               (std::to_integer<std::uint32_t>(name[2]) << 16) |
                               (std::to_integer<std::uint32_t>(name[3]) << 24);
            std::string value;
            if (first != 0) {
                for (const auto byte : name) {
                    if (byte == std::byte{0}) break;
                    require(value.size() < 8, "PE COFF short name exceeds its field");
                    value.push_back(static_cast<char>(std::to_integer<unsigned char>(byte)));
                }
                return value;
            }
            const auto offset = std::to_integer<std::uint32_t>(name[4]) |
                                (std::to_integer<std::uint32_t>(name[5]) << 8) |
                                (std::to_integer<std::uint32_t>(name[6]) << 16) |
                                (std::to_integer<std::uint32_t>(name[7]) << 24);
            require(offset >= 4 && offset < string_table.size(),
                    "PE COFF long-name offset is outside the string table");
            const auto begin = string_table.begin() + offset;
            const auto end = std::find(begin, string_table.end(), std::byte{0});
            require(end != string_table.end(), "PE COFF long name lacks a terminator");
            require(end - begin <= 65536, "PE COFF symbol name exceeds inspection limit",
                    ErrorCode::resource_limit);
            value.reserve(static_cast<std::size_t>(end - begin));
            for (auto it = begin; it != end; ++it)
                value.push_back(static_cast<char>(std::to_integer<unsigned char>(*it)));
            return value;
        };

        std::uint64_t index = 0;
        std::size_t name_bytes = 0;
        result.symbols.reserve(std::min<std::uint32_t>(record_count, 65536));
        constexpr std::uint32_t no_primary_symbol = UINT32_MAX;
        std::vector<std::uint32_t> primary_by_raw_index(record_count, no_primary_symbol);
        while (index < record_count) {
            canceled(stop);
            require(result.symbols.size() < max_primary_symbols,
                    "PE COFF primary symbol count exceeds inspection budget", ErrorCode::resource_limit);
            const auto at = add(symbol_offset, index * 18, "COFF symbol position");
            PeCoffSymbol symbol;
            symbol.name = read_name(at);
            require(symbol.name.size() <= max_string_table_size - name_bytes,
                    "PE COFF symbol names exceed aggregate inspection budget", ErrorCode::resource_limit);
            name_bytes += symbol.name.size();
            symbol.value = reader.integer<std::uint32_t>(at + 8, "COFF symbol value");
            symbol.section_number = reader.integer<std::int16_t>(at + 12, "COFF section number");
            symbol.type = reader.integer<std::uint16_t>(at + 14, "COFF symbol type");
            symbol.storage_class = reader.integer<std::uint8_t>(at + 16, "COFF storage class");
            const auto auxiliary_count = reader.integer<std::uint8_t>(at + 17, "COFF auxiliary count");
            symbol.raw_index = static_cast<std::uint32_t>(index);
            symbol.source_file_offset = {at};
            require(auxiliary_count <= record_count - index - 1,
                    "PE COFF auxiliary records exceed the declared symbol table");
            if (symbol.storage_class == 105) { // IMAGE_SYM_CLASS_WEAK_EXTERNAL
                require(auxiliary_count == 1,
                        "COFF weak external must have exactly one auxiliary record");
                const auto weak_auxiliary = add(at, 18, "COFF weak-external auxiliary position");
                const auto tag_index = reader.integer<std::uint32_t>(weak_auxiliary,
                                                                     "COFF weak-external tag index");
                const auto characteristics = reader.integer<std::uint32_t>(weak_auxiliary + 4,
                                                                            "COFF weak-external characteristics");
                require(characteristics >= static_cast<std::uint32_t>(PeWeakExternalSearch::no_library) &&
                            characteristics <= static_cast<std::uint32_t>(PeWeakExternalSearch::anti_dependency),
                        "COFF weak-external search characteristics are unsupported");
                symbol.weak_external_tag_index = tag_index;
                symbol.weak_external_search = static_cast<PeWeakExternalSearch>(characteristics);
            }
            if (auxiliary_count && (symbol.storage_class == 2 || symbol.storage_class == 3) &&
                (symbol.type & 0x30u) == 0x20u && symbol.section_number > 0 &&
                static_cast<std::size_t>(symbol.section_number) <= loaded.metadata.sections.size()) {
                const auto &section = loaded.metadata.sections[static_cast<std::size_t>(symbol.section_number - 1)];
                const auto auxiliary_at = add(at, 18, "COFF function auxiliary position");
                const auto function_size = reader.integer<std::uint32_t>(auxiliary_at + 4,
                                                                         "COFF function auxiliary size");
                const auto mapped_extent = std::max(section.virtual_size, section.raw_size);
                const auto backed_extent = std::min<std::uint64_t>(mapped_extent, section.raw_size);
                if ((section.characteristics & 0x20000000u) && function_size &&
                    symbol.value < backed_extent && function_size <= backed_extent - symbol.value) {
                    symbol.function_size = function_size;
                    symbol.function_aux_file_offset = {auxiliary_at};
                }
            }
            if (symbol.section_number > 0 &&
                static_cast<std::size_t>(symbol.section_number) <= loaded.metadata.sections.size()) {
                const auto &section = loaded.metadata.sections[static_cast<std::size_t>(symbol.section_number - 1)];
                const auto extent = std::max(section.virtual_size, section.raw_size);
                const auto rva = std::uint64_t{section.rva.value} + symbol.value;
                if (symbol.value < extent && rva < loaded.metadata.image_size && rva <= UINT32_MAX)
                    symbol.section_rva = static_cast<std::uint32_t>(rva);
            }
            symbol.auxiliary_records.reserve(auxiliary_count);
            for (std::uint32_t auxiliary = 0; auxiliary < auxiliary_count; ++auxiliary) {
                canceled(stop);
                const auto aux_at = add(at, std::uint64_t{auxiliary + 1} * 18, "COFF auxiliary position");
                const auto bytes = reader.bytes(aux_at, 18, "COFF auxiliary record").bytes;
                std::array<std::byte, 18> record{};
                std::copy(bytes.begin(), bytes.end(), record.begin());
                symbol.auxiliary_records.push_back(record);
            }
            if (symbol.storage_class == 3 && symbol.value == 0 && symbol.type == 0 &&
                symbol.section_number > 0 &&
                static_cast<std::size_t>(symbol.section_number) <= section_count && auxiliary_count == 1 &&
                symbol.name == loaded.metadata.sections[static_cast<std::size_t>(symbol.section_number - 1)].name) {
                const auto auxiliary_at = add(at, 18, "COFF section-definition auxiliary position");
                PeCoffSectionDefinition section_definition;
                section_definition.length = reader.integer<std::uint32_t>(auxiliary_at,
                    "COFF section-definition length");
                section_definition.relocation_count = reader.integer<std::uint16_t>(auxiliary_at + 4,
                    "COFF section-definition relocation count");
                section_definition.line_number_count = reader.integer<std::uint16_t>(auxiliary_at + 6,
                    "COFF section-definition line-number count");
                section_definition.checksum = reader.integer<std::uint32_t>(auxiliary_at + 8,
                    "COFF section-definition checksum");
                const auto section_low = reader.integer<std::uint16_t>(auxiliary_at + 12,
                    "COFF section-definition associated section");
                section_definition.selection = reader.integer<std::uint8_t>(auxiliary_at + 14,
                    "COFF section-definition selection");
                const auto section_high = reader.integer<std::uint16_t>(auxiliary_at + 16,
                    "COFF section-definition associated section high word");
                section_definition.associated_section = (std::uint32_t{section_high} << 16) | section_low;
                section_definition.source_file_offset = {auxiliary_at};
                symbol.section_definition = section_definition;
            }
            result.symbols.push_back(std::move(symbol));
            primary_by_raw_index[static_cast<std::size_t>(index)] =
                static_cast<std::uint32_t>(result.symbols.size() - 1);
            index += std::uint64_t{auxiliary_count} + 1;
        }
        for (std::size_t symbol_index = 0; symbol_index < result.symbols.size(); ++symbol_index) {
            canceled(stop);
            auto &symbol = result.symbols[symbol_index];
            if (!symbol.weak_external_tag_index) continue;
            const auto tag_index = *symbol.weak_external_tag_index;
            require(tag_index < primary_by_raw_index.size(),
                    "COFF weak-external tag index exceeds the symbol table");
            const auto target_index = primary_by_raw_index[tag_index];
            require(target_index != no_primary_symbol,
                    "COFF weak-external tag index refers to an auxiliary record");
            require(target_index != symbol_index,
                    "COFF weak external refers to itself as its fallback symbol");
            symbol.weak_external_target_name = result.symbols[target_index].name;
        }
        return result;
    } catch (const Failure &failure) {
        return failure.error;
    } catch (const std::bad_alloc &) {
        return Error{ErrorCode::resource_limit, "Cannot allocate PE COFF symbol table"};
    } catch (const std::length_error &) {
        return Error{ErrorCode::resource_limit, "PE COFF symbol table exceeds memory limits"};
    }
}
}
