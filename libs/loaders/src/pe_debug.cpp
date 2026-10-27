#include "pe_internal.hpp"
#include <algorithm>
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
        std::vector<PeDebugDirectoryEntry> entries;
        std::vector<PeFpoRecord> fpo_records;
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
            if (type != 2) continue; // IMAGE_DEBUG_TYPE_CODEVIEW
            const auto data_size = entry.data_size;
            const auto raw_offset = entry.raw_offset;
            require(data_size <= 1024 * 1024, "PE CodeView record exceeds inspection limit",
                    ErrorCode::resource_limit);
            require(data_size >= 25, "PE CodeView record is truncated");
            require(raw_offset <= image.storage()->size() && data_size <= image.storage()->size() - raw_offset,
                    "PE CodeView raw record exceeds input");
            const auto bytes = image.storage()->read_at({raw_offset}, data_size);
            if (!bytes) throw Failure{bytes.error()};
            require(bytes.value().bytes.size() == data_size, "Incomplete PE CodeView record", ErrorCode::io);
            const auto &record = bytes.value().bytes;
            require(record[0] == std::byte{'R'} && record[1] == std::byte{'S'} &&
                    record[2] == std::byte{'D'} && record[3] == std::byte{'S'},
                    "Unsupported PE CodeView signature", ErrorCode::unsupported);
            PeCodeViewIdentity identity;
            std::copy_n(record.begin() + 4, identity.guid.size(), identity.guid.begin());
            identity.age = std::to_integer<std::uint32_t>(record[20]) |
                (std::to_integer<std::uint32_t>(record[21]) << 8) |
                (std::to_integer<std::uint32_t>(record[22]) << 16) |
                (std::to_integer<std::uint32_t>(record[23]) << 24);
            const auto path_begin = record.begin() + 24;
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
        const auto count_read = codeview.size() + fpo_records.size();
        if (metadata.pe) {
            metadata.pe->debug_directories.insert(metadata.pe->debug_directories.end(),
                                                   std::make_move_iterator(entries.begin()),
                                                   std::make_move_iterator(entries.end()));
            metadata.pe->codeview.insert(metadata.pe->codeview.end(),
                                         std::make_move_iterator(codeview.begin()),
                                         std::make_move_iterator(codeview.end()));
            metadata.pe->fpo_records.insert(metadata.pe->fpo_records.end(),
                                            std::make_move_iterator(fpo_records.begin()),
                                            std::make_move_iterator(fpo_records.end()));
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
            result.symbols.push_back(std::move(symbol));
            index += std::uint64_t{auxiliary_count} + 1;
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
