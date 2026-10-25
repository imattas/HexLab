#include "pe_internal.hpp"
#include <string>

namespace hexlab::pe_detail {
namespace {
constexpr std::uint32_t dynamic_relocation_arm64x = 6;

void decode_arm64x_fixups(ImageReader &reader, PeDynamicRelocationRecord &record,
                          std::stop_token stop) {
    const auto begin = std::uint64_t{record.fixup_rva};
    const auto end = begin + record.fixup_size;
    std::uint64_t cursor = begin;
    std::uint32_t fixup_index = 0;
    while (cursor < end) {
        canceled(stop);
        if (end - cursor < 8) {
            const auto trailing = reader.bytes(cursor, static_cast<std::size_t>(end - cursor));
            require(std::all_of(trailing.begin(), trailing.end(), [](std::byte b) { return b == std::byte{0}; }),
                    "ARM64X relocation payload has nonzero trailing bytes after its last block");
            cursor = end;
            break;
        }
        const auto page_rva = reader.integer<std::uint32_t>(cursor);
        const auto block_size = reader.integer<std::uint32_t>(cursor + 4);
        if (page_rva == 0 && block_size == 0) {
            const auto trailing = reader.bytes(cursor, static_cast<std::size_t>(end - cursor));
            require(std::all_of(trailing.begin(), trailing.end(), [](std::byte b) { return b == std::byte{0}; }),
                    "ARM64X relocation payload has data after its zero terminator");
            cursor = end;
            break;
        }
        require((page_rva & 0xfffu) == 0, "ARM64X relocation page RVA is not 4 KiB aligned");
        require(block_size >= 12 && (block_size & 3u) == 0 && block_size <= end - cursor,
                "ARM64X relocation block has an invalid size");
        const auto block_end = cursor + block_size;
        auto entry = cursor + 8;
        bool padding_started = false;
        while (entry < block_end) {
            canceled(stop);
            require(block_end - entry >= 2, "ARM64X relocation block ends inside an entry");
            const auto word = reader.integer<std::uint16_t>(entry);
            if (!word) {
                padding_started = true;
                entry += 2;
                continue;
            }
            require(!padding_started, "ARM64X relocation block has a nonzero entry after padding");
            require(fixup_index < record_limit,
                    "ARM64X fixup count exceeds record budget", ErrorCode::resource_limit);
            const auto type = static_cast<std::uint8_t>((word >> 12) & 3u);
            const auto argument = static_cast<std::uint8_t>(word >> 14);
            const auto offset = static_cast<std::uint16_t>(word & 0x0fffu);
            const auto target_rva64 = std::uint64_t{page_rva} + offset;
            require(target_rva64 <= UINT32_MAX, "ARM64X relocation target RVA overflows 32 bits");

            PeDynamicRelocationFixup fixup;
            fixup.argument = argument;
            fixup.rva = static_cast<std::uint32_t>(target_rva64);
            std::uint64_t encoded_size = 2;
            if (type == 0 || type == 1) {
                fixup.kind = type == 0 ? PeDynamicRelocationFixupKind::zero_fill
                                       : PeDynamicRelocationFixupKind::value;
                fixup.size = static_cast<std::uint8_t>(1u << argument);
                if (type == 1) {
                    const auto stored_value_size = (std::uint64_t{fixup.size} + 1u) & ~std::uint64_t{1};
                    require(stored_value_size <= block_end - entry - 2,
                            "ARM64X VALUE payload exceeds its relocation block");
                    fixup.value = reader.bytes(entry + 2, fixup.size);
                    encoded_size += stored_value_size;
                }
            } else if (type == 2) {
                fixup.kind = PeDynamicRelocationFixupKind::delta;
                fixup.size = 4;
                require(block_end - entry >= 4,
                        "ARM64X DELTA payload exceeds its relocation block");
                const auto raw_delta = reader.integer<std::uint16_t>(entry + 2);
                const auto scale = (argument & 2u) ? 8 : 4;
                const auto magnitude = static_cast<std::int32_t>(raw_delta) * scale;
                fixup.delta = (argument & 1u) ? -magnitude : magnitude;
                encoded_size = 4;
            } else {
                throw Failure{{ErrorCode::unsupported, "ARM64X relocation uses a reserved fixup type"}};
            }
            require(fixup.rva <= reader.image_size() && fixup.size <= reader.image_size() - fixup.rva,
                    "ARM64X relocation target exceeds the PE image");
            fixup.source = PeRecordSource{fixup_index, reader.sources(entry, encoded_size)};
            record.fixups.push_back(std::move(fixup));
            ++fixup_index;
            entry += encoded_size;
        }
        cursor = block_end;
    }
    require(cursor == end, "ARM64X relocation payload does not end on a block boundary");
    record.fixups_decoded = true;
    record.diagnostic = "ARM64X fixups decoded; loader actions are not applied";
}
} // namespace

Result<std::size_t> read_load_configuration(const Image& image, const Directory& directory, bool pe64,
                                            ImageMetadata& metadata, std::stop_token stop) {
    return guarded([&]() -> std::size_t {
        ImageReader reader(image, metadata, stop);
        require(directory.size >= 4, "Truncated PE load-configuration size field");
        const auto declared = reader.integer<std::uint32_t>(directory.location);
        require(declared >= 4 && declared <= directory.size, "Invalid PE load-configuration declared size");
        // Materialize only the prefix whose layout is understood here. The
        // declared size remains available as metadata, but arbitrarily large
        // future tails do not cause allocation or interpretation.
        const auto known_prefix_size = pe64 ? std::size_t{320} : std::size_t{192};
        const auto structure = reader.bytes(directory.location,
            std::min<std::size_t>(declared, known_prefix_size));
        const auto u16 = [&](std::size_t at) {
            return static_cast<std::uint16_t>(std::to_integer<unsigned>(structure[at]) |
                                              (std::to_integer<unsigned>(structure[at + 1]) << 8));
        };
        const auto u32 = [&](std::size_t at) {
            std::uint32_t value = 0;
            for (unsigned i = 0; i < 4; ++i)
                value |= std::to_integer<std::uint32_t>(structure[at + i]) << (8 * i);
            return value;
        };
        const auto u64 = [&](std::size_t at) {
            std::uint64_t value = 0;
            for (unsigned i = 0; i < 8; ++i)
                value |= std::to_integer<std::uint64_t>(structure[at + i]) << (8 * i);
            return value;
        };
        const std::size_t width = pe64 ? 8 : 4;
        // IMAGE_LOAD_CONFIG_DIRECTORY32/64 have ABI-defined offsets. Ignore
        // newer trailing fields unless the declared structure includes them.
        const std::size_t cookie_at = pe64 ? 88 : 60;
        const std::size_t check_at = pe64 ? 112 : 72;
        const std::size_t dispatch_at = pe64 ? 120 : 76;
        const std::size_t table_at = pe64 ? 128 : 80;
        const std::size_t count_at = pe64 ? 136 : 84;
        const std::size_t flags_at = pe64 ? 144 : 88;
        const std::size_t address_taken_table_at = pe64 ? 160 : 104;
        const std::size_t address_taken_count_at = pe64 ? 168 : 108;
        const std::size_t long_jump_table_at = pe64 ? 176 : 112;
        const std::size_t long_jump_count_at = pe64 ? 184 : 116;
        // IMAGE_LOAD_CONFIG_DIRECTORY64 places DynamicValueRelocTable at
        // offset 192; CHPEMetadataPointer follows it at offset 200. The PE32
        // fields are 32-bit and remain at offsets 120 and 124 respectively.
        const std::size_t dynamic_reloc_table_at = pe64 ? 192 : 120;
        const std::size_t eh_continuation_table_at = pe64 ? 264 : 164;
        const std::size_t eh_continuation_count_at = pe64 ? 272 : 168;
        const std::size_t xfg_check_at = pe64 ? 280 : 172;
        const std::size_t xfg_dispatch_at = pe64 ? 288 : 176;
        const std::size_t xfg_table_dispatch_at = pe64 ? 296 : 180;
        const std::size_t cast_guard_failure_mode_at = pe64 ? 304 : 184;
        const std::size_t guard_memcpy_at = pe64 ? 312 : 188;
        const auto pointer = [&](std::size_t at) { return pe64 ? u64(at) : u32(at); };
        const auto normalize = [&](std::uint64_t va, const char* field) -> std::uint64_t {
            require(va >= metadata.preferred_base, std::string("PE load configuration ") + field + " precedes image base");
            const auto rva = va - metadata.preferred_base;
            require(rva < metadata.image_size, std::string("PE load configuration ") + field + " exceeds image");
            (void)reader.sources(rva, 1);
            return rva;
        };
        const auto read_target_table = [&](std::uint64_t table_va, std::uint64_t count,
                                           const char* field, bool executable) {
            std::vector<PeLoadConfigTarget> targets;
            require((table_va == 0) == (count == 0),
                    std::string("Inconsistent PE ") + field + " table and count");
            if (!table_va) return targets;
            const auto table_rva = normalize(table_va, field);
            require(count <= record_limit, std::string("PE ") + field + " table exceeds record budget",
                    ErrorCode::resource_limit);
            require(table_rva <= metadata.image_size && count <= (metadata.image_size - table_rva) / 4,
                    std::string("PE ") + field + " table exceeds image");
            targets.reserve(static_cast<std::size_t>(count));
            for (std::uint64_t i = 0; i < count; ++i) {
                canceled(stop);
                const auto row = add(table_rva, i * 4, field);
                const auto target_rva = reader.integer<std::uint32_t>(row);
                const auto target = reader.address(target_rva);
                const auto* segment = image.segment_at(target);
                require(segment && reader.initialized_extent(target_rva),
                        std::string("PE ") + field + " entry does not point to initialized image bytes");
                require(!executable || segment->executable,
                        std::string("PE ") + field + " entry does not point to executable bytes");
                if (!targets.empty())
                    require(targets.back().rva < target_rva,
                            std::string("PE ") + field + " table is not strictly ordered");
                targets.push_back({target_rva,
                    PeRecordSource{static_cast<std::uint32_t>(i), reader.sources(row, 4)}});
            }
            return targets;
        };
        PeLoadConfiguration result;
        result.declared_size = declared;
        result.directory_source = PeRecordSource{0, reader.sources(directory.location, declared)};
        if (declared >= 12) {
            result.timestamp = u32(4);
            result.major_version = u16(8);
            result.minor_version = u16(10);
        }
        if (declared >= cookie_at + width) {
            const auto value = pointer(cookie_at);
            if (value) {
                result.security_cookie_rva = normalize(value, "security cookie");
                result.security_cookie_source = PeRecordSource{0, reader.sources(directory.location + cookie_at, width)};
            }
        }
        if (!pe64 && declared >= 72) {
            constexpr std::size_t safe_seh_table_at = 64;
            constexpr std::size_t safe_seh_count_at = 68;
            const auto table = u32(safe_seh_table_at);
            const auto count = u32(safe_seh_count_at);
            require((table == 0) == (count == 0),
                    "Inconsistent PE SafeSEH handler table and count");
            if (table) {
                result.safe_seh_table_rva = normalize(table, "SafeSEH handler table");
                result.safe_seh_table_source = PeRecordSource{
                    0, reader.sources(directory.location + safe_seh_table_at, 8)};
                const auto table_rva = *result.safe_seh_table_rva;
                require(count <= record_limit, "PE SafeSEH handler table exceeds record budget",
                        ErrorCode::resource_limit);
                require(table_rva <= metadata.image_size &&
                        count <= (metadata.image_size - table_rva) / 4,
                        "PE SafeSEH handler table exceeds image");
                result.safe_seh_handlers.reserve(count);
                for (std::uint32_t i = 0; i < count; ++i) {
                    canceled(stop);
                    const auto row = add(table_rva, static_cast<std::uint64_t>(i) * 4,
                                         "SafeSEH handler table row");
                    const auto handler_rva = reader.integer<std::uint32_t>(row);
                    const auto handler = reader.address(handler_rva);
                    const auto *segment = image.segment_at(handler);
                    require(segment && segment->executable && reader.initialized_extent(handler_rva),
                            "PE SafeSEH handler does not point to initialized executable bytes");
                    if (!result.safe_seh_handlers.empty())
                        require(result.safe_seh_handlers.back().rva < handler_rva,
                                "PE SafeSEH handler table is not strictly ordered");
                    result.safe_seh_handlers.push_back({handler_rva,
                        PeRecordSource{i, reader.sources(row, 4)}});
                }
            }
        }
        if (declared >= flags_at + 4) {
            const auto check = pointer(check_at), dispatch = pointer(dispatch_at);
            const auto table = pointer(table_at);
            const auto count = pe64 ? u64(count_at) : u32(count_at);
            result.guard_flags = u32(flags_at);
            if (check) result.guard_check_rva = normalize(check, "Guard CF check pointer");
            if (dispatch) result.guard_dispatch_rva = normalize(dispatch, "Guard CF dispatch pointer");
            require((table == 0) == (count == 0), "Inconsistent PE Guard CF function table and count");
            if (table) {
                require((result.guard_flags & 0x100u) != 0, "PE Guard CF table is present without instrumentation flag");
                result.guard_function_table_rva = normalize(table, "Guard CF function table");
                const auto table_rva = *result.guard_function_table_rva;
                const auto extra = static_cast<std::uint64_t>(result.guard_flags >> 28);
                const auto stride = std::uint64_t{4} + extra;
                require(count <= record_limit, "PE Guard CF function table exceeds record budget", ErrorCode::resource_limit);
                require(table_rva <= metadata.image_size && count <= (metadata.image_size - table_rva) / stride,
                        "PE Guard CF function table exceeds image");
                result.guard_functions.reserve(static_cast<std::size_t>(count));
                for (std::uint64_t i = 0; i < count; ++i) {
                    canceled(stop);
                    const auto row = add(table_rva, i * stride, "Guard CF table row");
                    const auto entry = reader.bytes(row, static_cast<std::size_t>(stride));
                    std::uint32_t function_rva = 0;
                    for (unsigned b = 0; b < 4; ++b)
                        function_rva |= std::to_integer<std::uint32_t>(entry[b]) << (8 * b);
                    const auto target = reader.address(function_rva);
                    const auto* segment = image.segment_at(target);
                    require(segment && segment->executable && reader.initialized_extent(function_rva),
                            "PE Guard CF function does not point to initialized executable bytes");
                    PeGuardCfFunction function;
                    function.rva = function_rva;
                    function.metadata.assign(entry.begin() + 4, entry.end());
                    function.source = PeRecordSource{static_cast<std::uint32_t>(i), reader.sources(row, stride)};
                    if (!result.guard_functions.empty())
                        require(result.guard_functions.back().rva < function.rva, "PE Guard CF function table is not strictly ordered");
                    result.guard_functions.push_back(std::move(function));
                }
            }
        }
        if (declared >= address_taken_count_at + width) {
            const auto table = pointer(address_taken_table_at);
            const auto count = pe64 ? u64(address_taken_count_at) : u32(address_taken_count_at);
            if (table) result.guard_address_taken_iat_table_rva = normalize(table, "Guard address-taken IAT table");
            result.guard_address_taken_iat_entries = read_target_table(
                table, count, "Guard address-taken IAT", false);
        }
        if (declared >= long_jump_count_at + width) {
            const auto table = pointer(long_jump_table_at);
            const auto count = pe64 ? u64(long_jump_count_at) : u32(long_jump_count_at);
            if (table) result.guard_long_jump_table_rva = normalize(table, "Guard long-jump table");
            result.guard_long_jump_targets = read_target_table(table, count, "Guard long-jump", true);
        }
        if (declared >= eh_continuation_count_at + width) {
            const auto table = pointer(eh_continuation_table_at);
            const auto count = pe64 ? u64(eh_continuation_count_at) : u32(eh_continuation_count_at);
            if (table) result.guard_eh_continuation_table_rva = normalize(table, "Guard EH continuation table");
            result.guard_eh_continuation_targets = read_target_table(
                table, count, "Guard EH continuation", true);
        }
        // XFG and related helper pointers were appended after the EH
        // continuation fields. A short or older structure must not be read
        // past its declared version, even when the containing directory is
        // larger. normalize() also verifies each non-null VA maps to an
        // initialized byte in the image.
        const auto read_optional_pointer = [&](std::size_t at, const char* field)
            -> std::optional<std::uint64_t> {
            if (declared < at + width) return {};
            const auto value = pointer(at);
            if (!value) return {};
            return normalize(value, field);
        };
        result.guard_xfg_check_rva = read_optional_pointer(xfg_check_at, "Guard XFG check pointer");
        result.guard_xfg_dispatch_rva = read_optional_pointer(xfg_dispatch_at, "Guard XFG dispatch pointer");
        result.guard_xfg_table_dispatch_rva = read_optional_pointer(
            xfg_table_dispatch_at, "Guard XFG table-dispatch pointer");
        result.cast_guard_failure_mode_rva = read_optional_pointer(
            cast_guard_failure_mode_at, "CastGuard failure-mode pointer");
        result.guard_memcpy_rva = read_optional_pointer(guard_memcpy_at, "Guard memcpy pointer");
        if (declared >= dynamic_reloc_table_at + width) {
            const auto table_va = pointer(dynamic_reloc_table_at);
            if (table_va) {
                result.dynamic_value_relocation_table_rva = normalize(table_va, "dynamic value relocation table");
                result.dynamic_value_relocation_table_pointer_source = PeRecordSource{
                    0, reader.sources(directory.location + dynamic_reloc_table_at, width)};
                PeDynamicRelocationTable table;
                const auto table_rva = *result.dynamic_value_relocation_table_rva;
                try {
                    constexpr std::uint64_t table_payload_limit = 16 * 1024 * 1024;
                    require(table_rva <= metadata.image_size && metadata.image_size - table_rva >= 8,
                            "PE dynamic relocation table header exceeds image");
                    table.version = reader.integer<std::uint32_t>(table_rva);
                    table.size = reader.integer<std::uint32_t>(table_rva + 4);
                    require(table.size <= table_payload_limit,
                            "PE dynamic relocation table exceeds the 16 MiB payload budget",
                            ErrorCode::resource_limit);
                    require(table.size <= metadata.image_size - table_rva - 8,
                            "PE dynamic relocation table exceeds image");
                    const auto table_bytes = std::uint64_t{8} + table.size;
                    // Ensure the full table is file-backed before inspecting rows.
                    table.source = PeRecordSource{0, reader.sources(table_rva, table_bytes)};
                    if (table.version != 1 && table.version != 2) {
                        table.status = PeDynamicRelocationStatus::unsupported;
                        table.diagnostic = "Dynamic relocation table version is unsupported";
                    } else {
                        std::uint64_t cursor = table_rva + 8;
                        const auto table_end = cursor + table.size;
                        std::uint32_t record_index = 0;
                        while (cursor < table_end) {
                            canceled(stop);
                            require(record_index < record_limit,
                                    "PE dynamic relocation record count exceeds budget",
                                    ErrorCode::resource_limit);
                            const auto record_start = cursor;
                            PeDynamicRelocationRecord record;
                            const auto symbol_width = pe64 ? std::uint64_t{8} : std::uint64_t{4};
                            if (table.version == 1) {
                                const auto header_size = symbol_width + 4;
                                require(header_size <= table_end - cursor,
                                        "Truncated PE dynamic relocation v1 record header");
                                record.symbol = pe64 ? reader.integer<std::uint64_t>(cursor)
                                                     : reader.integer<std::uint32_t>(cursor);
                                record.header_size = static_cast<std::uint32_t>(header_size);
                                record.fixup_size = reader.integer<std::uint32_t>(cursor + symbol_width);
                                cursor += header_size;
                                require(record.fixup_size <= table_end - cursor,
                                        "PE dynamic relocation v1 fixup data exceeds table");
                            } else {
                                const auto minimum_header = symbol_width + 16;
                                require(minimum_header <= table_end - cursor,
                                        "Truncated PE dynamic relocation v2 record header");
                                record.header_size = reader.integer<std::uint32_t>(cursor);
                                record.fixup_size = reader.integer<std::uint32_t>(cursor + 4);
                                require(record.header_size >= minimum_header &&
                                            record.header_size <= table_end - cursor,
                                        "Invalid PE dynamic relocation v2 header size");
                                record.symbol = pe64 ? reader.integer<std::uint64_t>(cursor + 8)
                                                     : reader.integer<std::uint32_t>(cursor + 8);
                                record.symbol_group = reader.integer<std::uint32_t>(cursor + 8 + symbol_width);
                                record.flags = reader.integer<std::uint32_t>(cursor + 12 + symbol_width);
                                if (record.header_size > minimum_header)
                                    record.header_extension = reader.sources(cursor + minimum_header,
                                        record.header_size - minimum_header);
                                cursor += record.header_size;
                                require(record.fixup_size <= table_end - cursor,
                                        "PE dynamic relocation v2 fixup data exceeds table");
                            }
                            require(cursor <= UINT32_MAX,
                                    "PE dynamic relocation fixup RVA exceeds 32-bit range");
                            record.fixup_rva = static_cast<std::uint32_t>(cursor);
                            if (record.fixup_size)
                                record.fixup_source = PeRecordSource{record_index,
                                    reader.sources(cursor, record.fixup_size)};
                            if (record.symbol == dynamic_relocation_arm64x && pe64) {
                                try {
                                    decode_arm64x_fixups(reader, record, stop);
                                } catch (const Failure &failure) {
                                    if (failure.error.code != ErrorCode::unsupported) throw;
                                    record.fixups.clear();
                                    record.fixups_decoded = false;
                                    record.diagnostic = failure.error.message + "; fixup bytes remain opaque";
                                }
                            } else if (record.symbol == dynamic_relocation_arm64x) {
                                record.diagnostic = "ARM64X dynamic relocations require a PE32+ image; fixup bytes remain opaque";
                            } else {
                                record.diagnostic = "Fixup symbol is unsupported; payload remains opaque";
                            }
                            cursor += record.fixup_size;
                            record.source = PeRecordSource{record_index,
                                reader.sources(record_start, cursor - record_start)};
                            table.records.push_back(std::move(record));
                            ++record_index;
                        }
                        require(cursor == table_end,
                                "PE dynamic relocation table does not end on a record boundary");
                        table.status = PeDynamicRelocationStatus::decoded_layout;
                        table.diagnostic = "Record framing decoded; supported ARM64X records contain structured fixups";
                    }
                } catch (const Failure& failure) {
                    table.status = PeDynamicRelocationStatus::malformed;
                    table.diagnostic = failure.error.message;
                }
                result.dynamic_value_relocations = std::move(table);
            }
        }
        metadata.pe->load_configuration = std::move(result);
        return 1;
    });
}
} // namespace hexlab::pe_detail
