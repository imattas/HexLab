#include "pe_internal.hpp"

#include <functional>
#include <unordered_set>

namespace hexlab::pe_detail {
namespace {
std::optional<std::string> resolve_amd64_handler_name(const Image& image,
                                                      const ImageMetadata& metadata,
                                                      const ImageReader& reader,
                                                      std::uint32_t handler_rva) {
    const auto handler_address = reader.address(handler_rva);
    for (const auto& exported : metadata.exports) {
        if (exported.address && *exported.address == handler_address && exported.name)
            return *exported.name;
    }

    // Recognize only the canonical x64 import jump stub. Other thunk shapes
    // are deliberately left unresolved instead of guessing at identity.
    const auto available = reader.initialized_extent(handler_rva);
    std::uint64_t opcode_rva = handler_rva;
    std::uint64_t next_rva = 0;
    if (available >= 10) {
        const auto prefix = reader.bytes(handler_rva, 6);
        if (std::to_integer<std::uint8_t>(prefix[0]) == 0xf3 &&
            std::to_integer<std::uint8_t>(prefix[1]) == 0x0f &&
            std::to_integer<std::uint8_t>(prefix[2]) == 0x1e &&
            std::to_integer<std::uint8_t>(prefix[3]) == 0xfa &&
            std::to_integer<std::uint8_t>(prefix[4]) == 0xff &&
            std::to_integer<std::uint8_t>(prefix[5]) == 0x25) {
            opcode_rva += 4;
            next_rva = std::uint64_t{handler_rva} + 10;
        }
    }
    if (!next_rva && available >= 6) {
        const auto prefix = reader.bytes(handler_rva, 2);
        if (std::to_integer<std::uint8_t>(prefix[0]) == 0xff &&
            std::to_integer<std::uint8_t>(prefix[1]) == 0x25)
            next_rva = std::uint64_t{handler_rva} + 6;
    }
    if (!next_rva || next_rva > metadata.image_size) return {};
    const auto displacement = reader.integer<std::int32_t>(opcode_rva + 2);
    const auto target_signed = static_cast<std::int64_t>(next_rva) + displacement;
    if (target_signed < 0 || static_cast<std::uint64_t>(target_signed) >= metadata.image_size) return {};
    const auto target = reader.address(static_cast<std::uint64_t>(target_signed));
    for (const auto& imported : metadata.imports) {
        if (imported.iat == target && imported.name) return *imported.name;
    }
    (void)image;
    return {};
}

std::size_t read_arm64_exception_directory(const Image &image, const Directory &directory,
                                           ImageMetadata &metadata, std::stop_token stop) {
    require(directory.size % 8 == 0, "ARM64 exception-directory size is not a multiple of 8");
    const auto count = directory.size / 8;
    ImageReader reader(image, metadata, stop);
    reader.array(directory.location, count, 8);

    const auto validate_code_range = [&](std::uint32_t begin_rva, std::uint32_t end_rva) {
        require(begin_rva < end_rva && end_rva <= metadata.image_size,
                "ARM64 unwind code range is empty or exceeds the image");
        const auto begin = reader.address(begin_rva);
        const auto *segment = image.segment_at(begin);
        require(segment && segment->executable,
                "ARM64 unwind code range does not begin in executable code");
        const auto relative = begin.offset - segment->begin.offset;
        require(relative <= segment->file_size && end_rva - begin_rva <= segment->file_size - relative,
                "ARM64 unwind code range exceeds initialized executable bytes");
        require(image.segment_at(reader.address(end_rva - 1)) == segment,
                "ARM64 unwind code range crosses executable section boundaries");
    };
    const auto validate_code_start = [&](std::uint32_t begin_rva) {
        require(begin_rva < metadata.image_size, "ARM64 pdata code start exceeds the image");
        const auto begin = reader.address(begin_rva);
        const auto *segment = image.segment_at(begin);
        require(segment && segment->executable &&
                    begin.offset - segment->begin.offset < segment->file_size,
                "ARM64 pdata code start is not initialized executable code");
        require((begin_rva & 3u) == 0, "ARM64 pdata code start is not instruction aligned");
    };
    const auto nonzero_span = [&](std::uint64_t rva, std::uint64_t size, std::uint32_t index) {
        return PeRecordSource{index, reader.sources(rva, size)};
    };

    std::vector<PeArm64RuntimeFunction> parsed;
    parsed.reserve(static_cast<std::size_t>(count));
    std::uint32_t previous_begin = 0;
    for (std::uint32_t index = 0; index < count; ++index) {
        canceled(stop);
        const auto row = std::uint64_t{directory.location} + std::uint64_t{index} * 8;
        PeArm64RuntimeFunction function;
        function.begin_rva = reader.integer<std::uint32_t>(row);
        const auto unwind_word = reader.integer<std::uint32_t>(row + 4);
        require(index == 0 || function.begin_rva > previous_begin,
                "ARM64 pdata table is not strictly sorted by function start");
        validate_code_start(function.begin_rva);
        const auto tag = static_cast<std::uint8_t>(unwind_word & 3u);
        function.kind = static_cast<PeArm64UnwindKind>(tag);
        function.source = nonzero_span(row, 8, index);

        if (tag == 1 || tag == 2) {
            const auto packed = unwind_word >> 2;
            PeArm64PackedUnwind info;
            info.function_length = static_cast<std::uint16_t>(packed & 0x7ffu);
            info.reg_f = static_cast<std::uint8_t>((packed >> 11) & 7u);
            info.reg_i = static_cast<std::uint8_t>((packed >> 14) & 0xfu);
            info.homes_parameters = ((packed >> 18) & 1u) != 0;
            info.cr = static_cast<std::uint8_t>((packed >> 19) & 3u);
            info.frame_size = static_cast<std::uint16_t>((packed >> 21) & 0x1ffu);
            require(info.function_length != 0 && info.reg_i <= 10,
                    "ARM64 packed unwind has an invalid function length or integer-register count");
            require(info.reg_f <= 7 && info.frame_size <= 511,
                    "ARM64 packed unwind has an invalid floating-register count or frame size");
            function.function_length = std::uint32_t{info.function_length} * 4u;
            const auto end = std::uint64_t{function.begin_rva} + function.function_length;
            require(end <= std::numeric_limits<std::uint32_t>::max(),
                    "ARM64 packed unwind function extent overflows");
            validate_code_range(function.begin_rva, static_cast<std::uint32_t>(end));
            function.packed_unwind = info;
        } else if (tag == 0) {
            const auto xdata_rva = unwind_word & ~3u;
            require(xdata_rva != 0 && (xdata_rva & 3u) == 0,
                    "ARM64 xdata RVA is zero or misaligned");
            const auto header_word = reader.integer<std::uint32_t>(xdata_rva);
            PeArm64Xdata info;
            info.function_length = (header_word & 0x3ffffu) * 4u;
            info.version = static_cast<std::uint8_t>((header_word >> 18) & 3u);
            info.has_exception_data = ((header_word >> 20) & 1u) != 0;
            info.single_epilog = ((header_word >> 21) & 1u) != 0;
            info.epilog_count = static_cast<std::uint16_t>((header_word >> 22) & 0x1fu);
            info.code_words = static_cast<std::uint8_t>((header_word >> 27) & 0x1fu);
            require(info.function_length != 0, "ARM64 xdata function length is zero");
            require(info.version == 0, "ARM64 xdata version is unsupported", ErrorCode::unsupported);

            std::uint64_t cursor = std::uint64_t{xdata_rva} + 4;
            if (!info.epilog_count && !info.code_words) {
                const auto extension = reader.integer<std::uint32_t>(cursor);
                require((extension & 0xff000000u) == 0,
                        "ARM64 xdata extended header has nonzero reserved bits");
                info.epilog_count = static_cast<std::uint16_t>(extension & 0xffffu);
                info.code_words = static_cast<std::uint8_t>((extension >> 16) & 0xffu);
                info.extended_header = true;
                cursor += 4;
            }
            require(info.epilog_count != 0 || info.code_words != 0,
                    "ARM64 xdata extension has no epilogs or unwind codes");
            require(!info.single_epilog || info.epilog_count < std::uint32_t{info.code_words} * 4u,
                    "ARM64 xdata single-epilog code index exceeds the code array");
            if (!info.single_epilog) {
                require(info.epilog_count <= record_limit,
                        "ARM64 xdata epilog count exceeds the metadata record budget", ErrorCode::resource_limit);
                reader.array(cursor, info.epilog_count, 4);
                std::uint32_t previous_offset = 0;
                for (std::uint32_t scope_index = 0; scope_index < info.epilog_count; ++scope_index) {
                    const auto scope_rva = cursor + std::uint64_t{scope_index} * 4;
                    const auto scope_word = reader.integer<std::uint32_t>(scope_rva);
                    PeArm64EpilogScope scope;
                    scope.start_offset = (scope_word & 0x3ffffu) * 4u;
                    const auto reserved = (scope_word >> 18) & 0xfu;
                    scope.unwind_code_index = static_cast<std::uint16_t>((scope_word >> 22) & 0x3ffu);
                    require(reserved == 0 && scope.start_offset < info.function_length &&
                                (scope_index == 0 || scope.start_offset > previous_offset),
                            "ARM64 xdata epilog scopes have invalid reserved bits, bounds, or ordering");
                    require(scope.unwind_code_index < std::uint32_t{info.code_words} * 4u,
                            "ARM64 xdata epilog code index exceeds the code array");
                    scope.source = nonzero_span(scope_rva, 4, scope_index);
                    info.epilog_scopes.push_back(std::move(scope));
                    previous_offset = info.epilog_scopes.back().start_offset;
                }
                cursor += std::uint64_t{info.epilog_count} * 4;
            }

            const auto code_size = std::uint64_t{info.code_words} * 4;
            auto code_bytes = reader.bytes(cursor, static_cast<std::size_t>(code_size));
            std::vector<std::uint16_t> code_offsets;
            for (std::size_t position = 0; position < code_bytes.size();) {
                const auto opcode = std::to_integer<std::uint8_t>(code_bytes[position]);
                std::size_t size = 1;
                if (opcode >= 0xc0 && opcode <= 0xdf) size = 2;
                else if (opcode == 0xe0) size = 4;
                else if (opcode == 0xe2 || opcode == 0xe7 || opcode == 0xdf) size = opcode == 0xe7 ? 3 : 2;
                else if ((opcode >= 0xe8 && opcode <= 0xec) || opcode == 0xfc) size = 1;
                else if (opcode == 0xe1 || (opcode >= 0xe3 && opcode <= 0xe6)) size = 1;
                else if (opcode >= 0xed) {
                    require(false, "ARM64 xdata contains a reserved unwind opcode", ErrorCode::unsupported);
                }
                require(size <= code_bytes.size() - position,
                        "ARM64 xdata unwind opcode is truncated");
                if (opcode == 0xe7) {
                    const auto selector = std::to_integer<std::uint8_t>(code_bytes[position + 1]);
                    const auto extension = std::to_integer<std::uint8_t>(code_bytes[position + 2]);
                    require((selector & 0x80u) == 0,
                            "ARM64 xdata save_any opcode uses a reserved encoding");
                    if ((extension & 0xc0u) == 0xc0u && (selector & 0x10u) != 0) {
                        const auto preg = selector & 0x0fu;
                        require(preg == 0 || preg >= 4,
                                "ARM64 xdata save_preg selector is reserved");
                    }
                }
                const bool has_zero_padding = opcode == 0xe4 &&
                    std::all_of(code_bytes.begin() + static_cast<std::ptrdiff_t>(position + 1),
                                code_bytes.end(), [](std::byte value) { return value == std::byte{0}; });
                code_offsets.push_back(static_cast<std::uint16_t>(position));
                PeArm64UnwindCode code;
                code.opcode = opcode;
                code.source = nonzero_span(cursor + position, size, static_cast<std::uint32_t>(info.unwind_codes.size()));
                for (std::size_t byte = 0; byte < size; ++byte)
                    code.encoding.push_back(std::to_integer<std::uint8_t>(code_bytes[position + byte]));
                info.unwind_codes.push_back(std::move(code));
                position += size;
                if (has_zero_padding) break; // The remaining zero bytes are word-alignment padding.
            }
            if (info.single_epilog)
                require(std::find(code_offsets.begin(), code_offsets.end(), info.epilog_count) != code_offsets.end(),
                        "ARM64 xdata single-epilog index is not an unwind-code boundary");
            for (const auto &scope : info.epilog_scopes)
                require(std::find(code_offsets.begin(), code_offsets.end(), scope.unwind_code_index) != code_offsets.end(),
                        "ARM64 xdata epilog index is not an unwind-code boundary");
            cursor += code_size;
            if (info.has_exception_data) {
                const auto handler_rva = reader.integer<std::uint32_t>(cursor);
                require(handler_rva != 0, "ARM64 xdata handler RVA is zero");
                validate_code_start(handler_rva);
                info.handler_rva = handler_rva;
                info.handler_source = nonzero_span(cursor, 4, 0);
                cursor += 4;
            }
            const auto function_end = std::uint64_t{function.begin_rva} + info.function_length;
            require(function_end <= std::numeric_limits<std::uint32_t>::max(),
                    "ARM64 xdata function extent overflows");
            validate_code_range(function.begin_rva, static_cast<std::uint32_t>(function_end));
            function.function_length = info.function_length;
            info.source = nonzero_span(xdata_rva, cursor - xdata_rva, index);
            function.xdata = std::move(info);
        } else {
            const auto parent_rva = unwind_word & ~3u;
            require(parent_rva >= directory.location &&
                        (parent_rva - directory.location) % 8 == 0 &&
                        (parent_rva - directory.location) / 8 < count,
                    "ARM64 pdata link does not reference a row in the exception directory");
            function.linked_record_rva = parent_rva;
            function.linked_record_index = (parent_rva - directory.location) / 8;
        }
        parsed.push_back(std::move(function));
        previous_begin = parsed.back().begin_rva;
    }

    std::vector<std::uint8_t> link_state(parsed.size(), 0);
    std::function<void(std::size_t, std::uint32_t)> validate_link;
    validate_link = [&](std::size_t index, std::uint32_t depth) {
        canceled(stop);
        require(depth < 32, "ARM64 pdata link depth exceeds limit", ErrorCode::resource_limit);
        require(link_state[index] != 1, "ARM64 pdata links contain a cycle");
        if (link_state[index] == 2) return;
        link_state[index] = 1;
        const auto &function = parsed[index];
        if (function.kind == PeArm64UnwindKind::pdata_link) {
            require(function.linked_record_index && *function.linked_record_index < parsed.size(),
                    "ARM64 pdata link target is invalid");
            validate_link(*function.linked_record_index, depth + 1);
        }
        link_state[index] = 2;
    };
    for (std::size_t index = 0; index < parsed.size(); ++index) validate_link(index, 0);

    auto &functions = metadata.pe->arm64_exception_functions;
    functions.insert(functions.end(), parsed.begin(), parsed.end());
    return parsed.size();
}

} // namespace

Result<std::size_t> read_exception_directory(const Image &image, const Directory &directory,
                                             ImageMetadata &metadata, std::stop_token stop) {
    return guarded([&] {
        if (metadata.machine == 0xaa64)
            return read_arm64_exception_directory(image, directory, metadata, stop);
        require(metadata.machine == 0x8664, "PE exception-directory decoding currently supports AMD64 only",
                ErrorCode::unsupported);
        require(directory.size % 12 == 0, "AMD64 exception-directory size is not a multiple of 12");
        const auto count = directory.size / 12;
        ImageReader reader(image, metadata, stop);
        reader.array(directory.location, count, 12);

        const auto validate_code_range = [&](std::uint32_t begin_rva, std::uint32_t end_rva) {
            require(begin_rva < end_rva && end_rva <= metadata.image_size,
                    "AMD64 unwind code range is empty or exceeds the image");
            const auto begin = reader.address(begin_rva);
            const auto *segment = image.segment_at(begin);
            require(segment && segment->executable,
                    "AMD64 unwind code range does not begin in executable code");
            const auto relative = begin.offset - segment->begin.offset;
            require(relative <= segment->file_size && end_rva - begin_rva <= segment->file_size - relative,
                    "AMD64 unwind code range exceeds initialized executable bytes");
            require(image.segment_at(reader.address(end_rva - 1)) == segment,
                    "AMD64 unwind code range crosses executable section boundaries");
        };
        const auto nonvolatile_register = [](std::uint8_t reg) {
            return reg == 3 || reg == 5 || reg == 6 || reg == 7 || (reg >= 12 && reg <= 15);
        };
        std::unordered_set<std::uint32_t> active_unwind_records;
        std::function<PeUnwindInfo(std::uint32_t, std::uint32_t, std::uint32_t, std::uint32_t)> parse_unwind;
        parse_unwind = [&](std::uint32_t unwind_rva, std::uint32_t depth,
                           std::uint32_t function_begin, std::uint32_t function_end) -> PeUnwindInfo {
            canceled(stop);
            require(depth < 32, "AMD64 chained unwind depth exceeds limit", ErrorCode::resource_limit);
            require(unwind_rva != 0 && (unwind_rva & 3u) == 0,
                    "AMD64 UNWIND_INFO RVA is zero or misaligned");
            require(active_unwind_records.insert(unwind_rva).second,
                    "AMD64 chained UNWIND_INFO contains a cycle");
            struct ActiveGuard {
                std::unordered_set<std::uint32_t> &active;
                std::uint32_t rva;
                ~ActiveGuard() { active.erase(rva); }
            } active_guard{active_unwind_records, unwind_rva};

            const auto header = reader.bytes(unwind_rva, 4);
            const auto version_flags = std::to_integer<std::uint8_t>(header[0]);
            PeUnwindInfo info;
            info.version = static_cast<std::uint8_t>(version_flags & 7u);
            info.flags = static_cast<std::uint8_t>(version_flags >> 3);
            info.size_of_prolog = std::to_integer<std::uint8_t>(header[1]);
            const auto codes_rva = std::uint64_t{unwind_rva} + 4;
            std::uint64_t tail_rva = 0;
            if (info.version == 3) {
                require((info.flags & ~0x0fu) == 0,
                        "AMD64 UNWIND_INFO_V3 uses reserved flags",
                        ErrorCode::unsupported);
                require((info.flags & 4u) == 0 || (info.flags & 3u) == 0,
                        "AMD64 UNWIND_INFO_V3 flags combine chain and handler modes");
                const auto operation_count_and_epilogs = std::to_integer<std::uint8_t>(header[3]);
                const auto operation_count = static_cast<std::uint8_t>(operation_count_and_epilogs & 0x1fu);
                const auto epilog_count = static_cast<std::uint8_t>(operation_count_and_epilogs >> 5);
                require(epilog_count == 0,
                        "AMD64 UNWIND_INFO_V3 epilog descriptors are unsupported", ErrorCode::unsupported);
                const auto payload_words = std::to_integer<std::uint8_t>(header[2]);
                const auto payload_size = std::uint64_t{payload_words} * 2;
                const auto payload_end = codes_rva + payload_size;
                if (payload_size) reader.array(codes_rva, 1, payload_size);
                const bool large_prolog = (info.flags & 8u) != 0;
                const std::uint64_t ip_offset_width = large_prolog ? 2 : 1;
                std::uint64_t offsets_rva = codes_rva;
                if (large_prolog) {
                    require(payload_size >= 1,
                            "AMD64 UNWIND_INFO_V3 large-prolog extension is truncated");
                    const auto high_byte = reader.integer<std::uint8_t>(codes_rva);
                    info.size_of_prolog = static_cast<std::uint16_t>(
                        (static_cast<std::uint16_t>(high_byte) << 8) | info.size_of_prolog);
                    offsets_rva += 1;
                }
                require(function_begin < function_end &&
                            info.size_of_prolog <= function_end - function_begin,
                        "AMD64 UNWIND_INFO_V3 prolog exceeds its runtime-function extent");
                require(operation_count <= (payload_size - (large_prolog ? 1u : 0u)) / ip_offset_width,
                        "AMD64 UNWIND_INFO_V3 prolog IP-offset array exceeds its payload");
                const auto offset_bytes = std::uint64_t{operation_count} * ip_offset_width;
                std::vector<std::uint16_t> code_offsets;
                code_offsets.reserve(operation_count);
                std::uint16_t previous_offset = std::numeric_limits<std::uint16_t>::max();
                for (std::uint8_t i = 0; i < operation_count; ++i) {
                    const auto offset_rva = offsets_rva + std::uint64_t{i} * ip_offset_width;
                    const auto offset = large_prolog
                        ? reader.integer<std::uint16_t>(offset_rva)
                        : reader.integer<std::uint8_t>(offset_rva);
                    require(offset <= info.size_of_prolog && offset <= previous_offset,
                            "AMD64 UNWIND_INFO_V3 prolog IP offsets are invalid or out of order");
                    previous_offset = offset;
                    code_offsets.push_back(offset);
                }
                auto wod_cursor = offsets_rva + offset_bytes;
                const auto wod_end = payload_end;
                bool has_frame_pointer_operation = false;
                for (std::uint8_t i = 0; i < operation_count; ++i) {
                    canceled(stop);
                    require(wod_cursor < wod_end, "AMD64 UNWIND_INFO_V3 WOD pool is truncated");
                    const auto wod_start = wod_cursor;
                    const auto first = reader.integer<std::uint8_t>(wod_cursor);
                    PeUnwindOperation decoded;
                    decoded.code_offset = code_offsets[i];
                    std::size_t wod_size = 0;
                    if (first == 0x00) { // WOD_SET_FPREG
                        wod_size = 2;
                        decoded.kind = PeUnwindOperationKind::set_frame_pointer;
                    } else if (first == 0x01) { // WOD_ALLOC_HUGE
                        wod_size = 5;
                        decoded.kind = PeUnwindOperationKind::allocate_stack;
                    } else if (first == 0x02) { // WOD_ALLOC_LARGE
                        wod_size = 3;
                        decoded.kind = PeUnwindOperationKind::allocate_stack;
                    } else if (first == 0x03) {
                        require(false, "AMD64 UNWIND_INFO_V3 canonical-frame WOD is unsupported",
                                ErrorCode::unsupported);
                    } else if ((first & 0x07u) == 0x04u) { // WOD_PUSH
                        wod_size = 1;
                        decoded.kind = PeUnwindOperationKind::push_nonvolatile;
                        decoded.register_number = static_cast<std::uint8_t>(first >> 3);
                        decoded.stack_size = 8;
                        require(decoded.register_number < 16 && nonvolatile_register(decoded.register_number),
                                "AMD64 UNWIND_INFO_V3 push WOD names an unsupported register",
                                ErrorCode::unsupported);
                    } else if ((first & 0x07u) == 0x05u) { // WOD_SAVE_NONVOL_FAR
                        wod_size = 5;
                        decoded.kind = PeUnwindOperationKind::save_nonvolatile;
                        decoded.register_number = static_cast<std::uint8_t>(first >> 3);
                        require(decoded.register_number < 16 && nonvolatile_register(decoded.register_number),
                                "AMD64 UNWIND_INFO_V3 save WOD names an unsupported register",
                                ErrorCode::unsupported);
                    } else if ((first & 0x07u) == 0x06u) { // WOD_SAVE_NONVOL
                        wod_size = 3;
                        decoded.kind = PeUnwindOperationKind::save_nonvolatile;
                        decoded.register_number = static_cast<std::uint8_t>(first >> 3);
                        require(decoded.register_number < 16 && nonvolatile_register(decoded.register_number),
                                "AMD64 UNWIND_INFO_V3 save WOD names an unsupported register",
                                ErrorCode::unsupported);
                    } else if ((first & 0x0fu) == 0x08u) { // WOD_ALLOC_SMALL
                        wod_size = 1;
                        decoded.kind = PeUnwindOperationKind::allocate_stack;
                        decoded.stack_size = static_cast<std::uint32_t>(first >> 4) * 8u + 8u;
                    } else if ((first & 0x0fu) == 0x09u) { // WOD_SAVE_XMM128_FAR
                        wod_size = 5;
                        decoded.kind = PeUnwindOperationKind::save_xmm128;
                        decoded.register_number = static_cast<std::uint8_t>(first >> 4);
                    } else if ((first & 0x0fu) == 0x0au) { // WOD_SAVE_XMM128
                        wod_size = 3;
                        decoded.kind = PeUnwindOperationKind::save_xmm128;
                        decoded.register_number = static_cast<std::uint8_t>(first >> 4);
                    } else if ((first & 0x3fu) == 0x20u) {
                        require(false, "AMD64 UNWIND_INFO_V3 APX PUSH2 WOD is unsupported",
                                ErrorCode::unsupported);
                    } else {
                        require(false, "AMD64 UNWIND_INFO_V3 WOD opcode is unsupported",
                                ErrorCode::unsupported);
                    }
                    require(wod_size != 0, "AMD64 UNWIND_INFO_V3 WOD has no supported encoding",
                            ErrorCode::unsupported);
                    require(wod_size <= wod_end - wod_cursor,
                            "AMD64 UNWIND_INFO_V3 WOD is truncated");
                    if (decoded.kind == PeUnwindOperationKind::set_frame_pointer) {
                        require(wod_size == 2 && !has_frame_pointer_operation,
                                "AMD64 UNWIND_INFO_V3 has a duplicate or malformed frame-pointer WOD");
                        const auto operand = reader.integer<std::uint8_t>(wod_cursor + 1);
                        decoded.register_number = static_cast<std::uint8_t>(operand & 0x0fu);
                        info.frame_register = decoded.register_number;
                        info.frame_offset = static_cast<std::uint8_t>(operand >> 4);
                        require(nonvolatile_register(info.frame_register),
                                "AMD64 UNWIND_INFO_V3 frame-pointer WOD names a volatile register");
                        decoded.stack_offset = std::uint32_t{info.frame_offset} * 16u;
                        has_frame_pointer_operation = true;
                    } else if (decoded.kind == PeUnwindOperationKind::allocate_stack) {
                        if (first == 0x01) decoded.stack_size = reader.integer<std::uint32_t>(wod_cursor + 1);
                        else if (first == 0x02)
                            decoded.stack_size = std::uint32_t{reader.integer<std::uint16_t>(wod_cursor + 1)} * 8u;
                        require(decoded.stack_size != 0 && (decoded.stack_size & 7u) == 0,
                                "AMD64 UNWIND_INFO_V3 stack allocation is zero or unaligned");
                    } else if (decoded.kind == PeUnwindOperationKind::save_nonvolatile) {
                        if ((first & 0x07u) == 0x05u) {
                            decoded.stack_offset = reader.integer<std::uint32_t>(wod_cursor + 1);
                            require((decoded.stack_offset & 7u) == 0,
                                    "AMD64 UNWIND_INFO_V3 far register-save offset is unaligned");
                        } else {
                            decoded.stack_offset = std::uint32_t{reader.integer<std::uint16_t>(wod_cursor + 1)} * 8u;
                        }
                    } else if (decoded.kind == PeUnwindOperationKind::save_xmm128) {
                        require(decoded.register_number >= 6 && decoded.register_number <= 15,
                                "AMD64 UNWIND_INFO_V3 XMM WOD names a volatile or invalid register");
                        if ((first & 0x0fu) == 0x09u) {
                            decoded.stack_offset = reader.integer<std::uint32_t>(wod_cursor + 1);
                            require((decoded.stack_offset & 15u) == 0,
                                    "AMD64 UNWIND_INFO_V3 far XMM-save offset is unaligned");
                        } else {
                            decoded.stack_offset = std::uint32_t{reader.integer<std::uint16_t>(wod_cursor + 1)} * 16u;
                        }
                    }
                    auto sources = reader.sources(offsets_rva + std::uint64_t{i} * ip_offset_width,
                                                  static_cast<std::size_t>(ip_offset_width));
                    auto wod_sources = reader.sources(wod_start, wod_size);
                    sources.insert(sources.end(), wod_sources.begin(), wod_sources.end());
                    decoded.source = {i, std::move(sources)};
                    info.operations.push_back(std::move(decoded));
                    wod_cursor += wod_size;
                }
                if (wod_cursor < wod_end) {
                    const auto padding = reader.bytes(wod_cursor,
                        static_cast<std::size_t>(wod_end - wod_cursor));
                    require(std::all_of(padding.begin(), padding.end(),
                                [](std::byte value) { return value == std::byte{0}; }),
                            "AMD64 UNWIND_INFO_V3 payload has nonzero bytes after its declared WODs");
                }
                require((info.frame_register != 0) == has_frame_pointer_operation,
                        "AMD64 UNWIND_INFO_V3 frame-register and WOD presence disagree");
                if (!info.frame_register)
                    require(info.frame_offset == 0,
                            "AMD64 UNWIND_INFO_V3 has a frame offset without a frame register");
                tail_rva = (payload_end + 3u) & ~std::uint64_t{3};
            } else {
                const auto code_count = std::to_integer<std::uint8_t>(header[2]);
                const auto frame = std::to_integer<std::uint8_t>(header[3]);
                info.frame_register = static_cast<std::uint8_t>(frame & 0x0fu);
                info.frame_offset = static_cast<std::uint8_t>(frame >> 4);
                require(info.version == 1, "AMD64 UNWIND_INFO version is unsupported", ErrorCode::unsupported);
                require(function_begin < function_end &&
                            info.size_of_prolog <= function_end - function_begin,
                        "AMD64 UNWIND_INFO prolog exceeds its runtime-function extent");
                require((info.flags & ~7u) == 0,
                        "AMD64 UNWIND_INFO has reserved flags");
                require((info.flags & 4u) == 0 || (info.flags & 3u) == 0,
                        "AMD64 UNWIND_INFO flags combine chain and handler modes");
                require(!info.frame_register || nonvolatile_register(info.frame_register),
                        "AMD64 UNWIND_INFO frame register is not nonvolatile");
                require(info.frame_register || info.frame_offset == 0,
                        "AMD64 UNWIND_INFO has a frame offset without a frame register");
                reader.array(codes_rva, code_count, 2);
                std::uint8_t previous_code_offset = 0xff;
                bool has_frame_pointer_operation = false;
                for (std::uint16_t slot = 0; slot < code_count;) {
                    const auto slot_rva = codes_rva + std::uint64_t{slot} * 2;
                    const auto code = reader.bytes(slot_rva, 2);
                    const auto code_offset = std::to_integer<std::uint8_t>(code[0]);
                    const auto operation_info = std::to_integer<std::uint8_t>(code[1]);
                    const auto operation = operation_info & 0x0fu;
                    const auto operation_info_value = static_cast<std::uint8_t>(operation_info >> 4);
                    require(code_offset <= info.size_of_prolog && code_offset <= previous_code_offset,
                            "AMD64 UNWIND_CODE offsets are invalid or out of order");
                    previous_code_offset = code_offset;

                    PeUnwindOperation decoded;
                    decoded.code_offset = code_offset;
                    std::uint16_t consumed_slots = 1;
                    switch (operation) {
                    case 0: // UWOP_PUSH_NONVOL
                        require(nonvolatile_register(operation_info_value),
                                "UWOP_PUSH_NONVOL names a volatile or invalid register");
                        decoded.kind = PeUnwindOperationKind::push_nonvolatile;
                        decoded.register_number = operation_info_value;
                        decoded.stack_size = 8;
                        break;
                    case 1: // UWOP_ALLOC_LARGE
                        decoded.kind = PeUnwindOperationKind::allocate_stack;
                        if (operation_info_value == 0) {
                            consumed_slots = 2;
                            require(slot + consumed_slots <= code_count,
                                    "UWOP_ALLOC_LARGE is missing its scaled operand slot");
                            const auto operand = reader.bytes(slot_rva + 2, 2);
                            const auto units = static_cast<std::uint32_t>(std::to_integer<std::uint8_t>(operand[0]) |
                                                                          (std::to_integer<std::uint8_t>(operand[1]) << 8));
                            decoded.stack_size = units * 8u;
                        } else if (operation_info_value == 1) {
                            consumed_slots = 3;
                            require(slot + consumed_slots <= code_count,
                                    "UWOP_ALLOC_LARGE is missing its unscaled operand slots");
                            decoded.stack_size = reader.integer<std::uint32_t>(static_cast<std::uint64_t>(slot_rva + 2));
                        } else {
                            require(false, "UWOP_ALLOC_LARGE has an invalid OpInfo value");
                        }
                        require(decoded.stack_size != 0 && (decoded.stack_size & 7u) == 0,
                                "UWOP_ALLOC_LARGE stack size is zero or unaligned");
                        break;
                    case 2: // UWOP_ALLOC_SMALL
                        decoded.kind = PeUnwindOperationKind::allocate_stack;
                        decoded.stack_size = static_cast<std::uint32_t>(operation_info_value) * 8u + 8u;
                        break;
                    case 3: // UWOP_SET_FPREG
                        require(operation_info_value == 0 && info.frame_register != 0 &&
                                    !has_frame_pointer_operation,
                                "UWOP_SET_FPREG has invalid OpInfo, frame-register, or duplicate encoding");
                        has_frame_pointer_operation = true;
                        decoded.kind = PeUnwindOperationKind::set_frame_pointer;
                        decoded.register_number = info.frame_register;
                        decoded.stack_offset = std::uint32_t{info.frame_offset} * 16u;
                        break;
                    case 4: // UWOP_SAVE_NONVOL
                    case 5: // UWOP_SAVE_NONVOL_FAR
                        require(nonvolatile_register(operation_info_value),
                                "UWOP_SAVE_NONVOL names a volatile or invalid register");
                        decoded.kind = PeUnwindOperationKind::save_nonvolatile;
                        decoded.register_number = operation_info_value;
                        consumed_slots = operation == 4 ? 2 : 3;
                        require(slot + consumed_slots <= code_count,
                                "UWOP_SAVE_NONVOL is missing its offset operand slots");
                        if (operation == 4) {
                            const auto operand = reader.bytes(slot_rva + 2, 2);
                            const auto units = static_cast<std::uint32_t>(std::to_integer<std::uint8_t>(operand[0]) |
                                                                          (std::to_integer<std::uint8_t>(operand[1]) << 8));
                            decoded.stack_offset = units * 8u;
                        } else {
                            decoded.stack_offset = reader.integer<std::uint32_t>(slot_rva + 2);
                            require((decoded.stack_offset & 7u) == 0,
                                    "UWOP_SAVE_NONVOL_FAR offset is not eight-byte aligned");
                        }
                        break;
                    case 8: // UWOP_SAVE_XMM128
                    case 9: // UWOP_SAVE_XMM128_FAR
                        decoded.kind = PeUnwindOperationKind::save_xmm128;
                        decoded.register_number = operation_info_value;
                        require(decoded.register_number >= 6 && decoded.register_number <= 15,
                                "UWOP_SAVE_XMM128 names a volatile or invalid register");
                        consumed_slots = operation == 8 ? 2 : 3;
                        require(slot + consumed_slots <= code_count,
                                "UWOP_SAVE_XMM128 is missing its offset operand slots");
                        if (operation == 8) {
                            const auto operand = reader.bytes(slot_rva + 2, 2);
                            const auto units = static_cast<std::uint32_t>(std::to_integer<std::uint8_t>(operand[0]) |
                                                                          (std::to_integer<std::uint8_t>(operand[1]) << 8));
                            decoded.stack_offset = units * 16u;
                        } else {
                            decoded.stack_offset = reader.integer<std::uint32_t>(slot_rva + 2);
                            require((decoded.stack_offset & 15u) == 0,
                                    "UWOP_SAVE_XMM128_FAR offset is not sixteen-byte aligned");
                        }
                        break;
                    case 10: // UWOP_PUSH_MACHFRAME
                        require(operation_info_value <= 1,
                                "UWOP_PUSH_MACHFRAME has an invalid OpInfo value");
                        decoded.kind = PeUnwindOperationKind::push_machine_frame;
                        decoded.machine_frame_has_error_code = operation_info_value != 0;
                        decoded.stack_size = decoded.machine_frame_has_error_code ? 48u : 40u;
                        break;
                    default:
                        require(false, "AMD64 UNWIND_CODE operation is unsupported", ErrorCode::unsupported);
                    }
                    decoded.source = {slot, reader.sources(slot_rva, std::uint64_t{consumed_slots} * 2)};
                    info.operations.push_back(std::move(decoded));
                    slot = static_cast<std::uint16_t>(slot + consumed_slots);
                }
                require((info.frame_register != 0) == has_frame_pointer_operation,
                        "AMD64 UNWIND_INFO frame register and UWOP_SET_FPREG presence disagree");

                tail_rva = codes_rva + std::uint64_t{code_count + (code_count & 1u)} * 2;
            }
            const auto flags_source = [&](std::uint64_t rva, std::uint64_t size, std::uint32_t index) {
                return PeRecordSource{index, reader.sources(rva, size)};
            };
            if (info.flags & 4u) {
                const auto chain_bytes = reader.bytes(tail_rva, 12);
                (void)chain_bytes;
                auto chained = std::make_shared<PeChainedRuntimeFunction>();
                chained->begin_rva = reader.integer<std::uint32_t>(tail_rva);
                chained->end_rva = reader.integer<std::uint32_t>(tail_rva + 4);
                chained->unwind_info_rva = reader.integer<std::uint32_t>(tail_rva + 8);
                validate_code_range(chained->begin_rva, chained->end_rva);
                require(chained->unwind_info_rva && (chained->unwind_info_rva & 3u) == 0,
                        "AMD64 chained UNWIND_INFO RVA is zero or misaligned");
                chained->source = flags_source(tail_rva, 12, 0);
                chained->unwind_info = std::make_shared<PeUnwindInfo>(
                    parse_unwind(chained->unwind_info_rva, depth + 1,
                                 chained->begin_rva, chained->end_rva));
                info.chained_function = std::move(chained);
            } else if (info.flags & 3u) {
                const auto handler_rva = reader.integer<std::uint32_t>(tail_rva);
                require(handler_rva != 0, "AMD64 UNWIND_INFO handler RVA is zero");
                const auto handler = reader.address(handler_rva);
                const auto *handler_segment = image.segment_at(handler);
                require(handler_segment && handler_segment->executable &&
                            handler.offset - handler_segment->begin.offset < handler_segment->file_size,
                        "AMD64 UNWIND_INFO handler does not point to initialized executable code");
                info.handler_rva = handler_rva;
                info.handler_source = flags_source(tail_rva, 4, 0);
                PeHandlerPayload payload;
                const auto payload_rva = tail_rva + 4;
                require(payload_rva <= metadata.image_size && payload_rva <= UINT32_MAX,
                        "AMD64 handler payload RVA exceeds the image");
                payload.payload_rva = static_cast<std::uint32_t>(payload_rva);
                payload.handler_name = resolve_amd64_handler_name(image, metadata, reader, handler_rva);
                if (payload.handler_name && *payload.handler_name == "__C_specific_handler") {
                    require(payload_rva <= metadata.image_size && metadata.image_size - payload_rva >= 4,
                            "AMD64 C-specific payload count exceeds the image bounds");
                    const auto scope_count = reader.integer<std::uint32_t>(payload_rva);
                    require(scope_count <= record_limit,
                            "AMD64 C-specific scope table exceeds the metadata record budget", ErrorCode::resource_limit);
                    require(scope_count <= (metadata.image_size - payload_rva - 4) / 16,
                            "AMD64 C-specific scope table exceeds the image bounds");
                    const auto payload_size = std::uint64_t{4} + std::uint64_t{scope_count} * 16;
                    require(payload_size <= 1024 * 1024,
                            "AMD64 C-specific scope table exceeds the 1 MiB payload budget", ErrorCode::resource_limit);
                    reader.array(payload_rva, 1, payload_size);
                    payload.status = PeHandlerPayloadStatus::decoded_c_specific_scope_table;
                    payload.source = flags_source(payload_rva, payload_size, 0);
                    payload.c_specific_scopes.reserve(scope_count);
                    for (std::uint32_t scope_index = 0; scope_index < scope_count; ++scope_index) {
                        canceled(stop);
                        const auto row = payload_rva + 4 + std::uint64_t{scope_index} * 16;
                        PeScopeRecord scope;
                        scope.begin_rva = reader.integer<std::uint32_t>(row);
                        scope.end_rva = reader.integer<std::uint32_t>(row + 4);
                        scope.handler_rva = reader.integer<std::uint32_t>(row + 8);
                        scope.jump_target_rva = reader.integer<std::uint32_t>(row + 12);
                        require(scope.begin_rva >= function_begin && scope.begin_rva < scope.end_rva &&
                                    scope.end_rva <= function_end,
                                "AMD64 C-specific scope range is outside its runtime function");
                        if (scope.handler_rva) {
                            const auto scope_handler = reader.address(scope.handler_rva);
                            const auto* segment = image.segment_at(scope_handler);
                            require(segment && segment->executable &&
                                        scope_handler.offset - segment->begin.offset < segment->file_size,
                                    "AMD64 C-specific filter/finally handler is not initialized executable code");
                        }
                        if (scope.jump_target_rva) {
                            const auto target = reader.address(scope.jump_target_rva);
                            const auto* target_segment = image.segment_at(target);
                            require(target_segment && target_segment->executable &&
                                        target.offset - target_segment->begin.offset < target_segment->file_size,
                                    "AMD64 C-specific jump target is not initialized executable code");
                        }
                        scope.source = flags_source(row, 16, scope_index);
                        payload.c_specific_scopes.push_back(std::move(scope));
                    }
                } else if (payload.handler_name && *payload.handler_name == "__CxxFrameHandler4") {
                    PeCxxFuncInfo4 fh4;
                    fh4.status = PeCxxFuncInfo4Status::decoded_subset;
                    std::uint64_t cursor = payload_rva;
                    std::uint64_t header_end = cursor;
                    try {
                        const auto compressed = [&](std::uint64_t &at) -> std::uint32_t {
                            const auto first = reader.integer<std::uint8_t>(at);
                            std::uint32_t value = 0;
                            std::uint32_t width = 0;
                            if ((first & 1u) == 0) { width = 1; value = first >> 1; }
                            else if ((first & 3u) == 1) width = 2;
                            else if ((first & 7u) == 3) width = 3;
                            else if ((first & 15u) == 7) width = 4;
                            else if ((first & 15u) == 15) {
                                require(at <= metadata.image_size && metadata.image_size - at >= 5,
                                        "FH4 compressed integer is truncated");
                                value = reader.integer<std::uint32_t>(at + 1);
                                width = 5;
                            } else {
                                require(false, "FH4 compressed integer has an invalid prefix");
                            }
                            if (width > 1 && width < 5) {
                                require(at <= metadata.image_size && width <= metadata.image_size - at,
                                        "FH4 compressed integer is truncated");
                                const auto b1 = reader.integer<std::uint8_t>(at + 1);
                                if (width == 2) value = (first >> 2) | (std::uint32_t{b1} << 6);
                                if (width >= 3) {
                                    const auto b2 = reader.integer<std::uint8_t>(at + 2);
                                    value = (first >> 3) | (std::uint32_t{b1} << 5) | (std::uint32_t{b2} << 13);
                                    if (width == 4) {
                                        const auto b3 = reader.integer<std::uint8_t>(at + 3);
                                        value = (first >> 4) | (std::uint32_t{b1} << 4) |
                                                (std::uint32_t{b2} << 12) | (std::uint32_t{b3} << 20);
                                    }
                                }
                            }
                            at += width;
                            return value;
                        };
                        fh4.header = reader.integer<std::uint8_t>(cursor++);
                        fh4.is_catch_funclet = (fh4.header & 0x01u) != 0;
                        fh4.has_ehs_flag = (fh4.header & 0x20u) != 0;
                        fh4.is_noexcept = (fh4.header & 0x40u) != 0;
                        const auto header_flag_source = flags_source(cursor - 1, 1, 0);
                        fh4.catch_funclet_flag_source = header_flag_source;
                        fh4.ehs_flag_source = header_flag_source;
                        fh4.noexcept_flag_source = header_flag_source;
                        fh4.unknown_header_flags = static_cast<std::uint8_t>(fh4.header & 0x80u);
                        constexpr std::uint8_t separated_flag = 0x02;
                        constexpr std::uint8_t bbt_flag = 0x04;
                        constexpr std::uint8_t unwind_flag = 0x08;
                        constexpr std::uint8_t try_flag = 0x10;
                        constexpr std::uint8_t known_flags = 0x7f;
                        if (fh4.header & bbt_flag) fh4.bbt_flags = compressed(cursor);
                        if (fh4.header & unwind_flag) {
                            fh4.unwind_map_rva = reader.integer<std::uint32_t>(cursor);
                            cursor += 4;
                        }
                        if (fh4.header & try_flag) {
                            fh4.try_block_map_rva = reader.integer<std::uint32_t>(cursor);
                            cursor += 4;
                        }
                        fh4.ip_map_rva = reader.integer<std::uint32_t>(cursor);
                        cursor += 4;
                        if (fh4.header & 1u) fh4.catch_frame = compressed(cursor);
                        header_end = cursor;
                        if (fh4.header & ~known_flags) {
                            fh4.status = PeCxxFuncInfo4Status::unsupported;
                            fh4.diagnostic = "FH4 header has unknown flag bits";
                        } else {
                            constexpr std::uint64_t fh4_payload_budget = 1024 * 1024;
                            std::uint64_t fh4_bytes_used = header_end - payload_rva;
                            require(fh4_bytes_used <= fh4_payload_budget,
                                    "FH4 function metadata exceeds the 1 MiB payload budget",
                                    ErrorCode::resource_limit);
                            const auto charge_fh4_bytes = [&](std::uint64_t begin, std::uint64_t end) {
                                require(begin <= end && end - begin <= fh4_payload_budget - fh4_bytes_used,
                                        "FH4 function metadata exceeds the 1 MiB payload budget",
                                        ErrorCode::resource_limit);
                                fh4_bytes_used += end - begin;
                            };
                            const auto image_relative_rva = [&](std::int32_t displacement, const char *what) {
                                require(displacement > 0 && static_cast<std::uint64_t>(displacement) < metadata.image_size,
                                        std::string("FH4 ") + what + " has an invalid image-relative RVA");
                                return static_cast<std::uint32_t>(displacement);
                            };
                            const auto require_executable_rva = [&](std::uint32_t rva, const char *what) {
                                require(rva != 0 && rva < metadata.image_size,
                                        std::string("FH4 ") + what + " RVA is zero or exceeds the image");
                                const auto target = reader.address(rva);
                                const auto *segment = image.segment_at(target);
                                require(segment && segment->executable &&
                                            target.offset - segment->begin.offset < segment->file_size,
                                        std::string("FH4 ") + what + " is not initialized executable code");
                            };
                            const auto decode_state = [](std::uint32_t encoded, const char *what) {
                                require(encoded <= static_cast<std::uint32_t>(INT32_MAX) + 1u,
                                        std::string("FH4 ") + what + " state exceeds signed range");
                                return static_cast<std::int32_t>(encoded - 1u);
                            };
                            std::optional<std::uint32_t> unwind_state_count;
                            const auto validate_state = [&](std::int32_t state, const char *what) {
                                if (unwind_state_count && state >= 0)
                                    require(static_cast<std::uint32_t>(state) < *unwind_state_count,
                                            std::string("FH4 ") + what + " exceeds the unwind-state map");
                            };

                            if (fh4.header & unwind_flag) {
                                require(fh4.unwind_map_rva && *fh4.unwind_map_rva < metadata.image_size,
                                        "FH4 unwind-map RVA is zero or exceeds the image");
                                std::uint64_t unwind_cursor = *fh4.unwind_map_rva;
                                const auto count_start = unwind_cursor;
                                const auto unwind_count = compressed(unwind_cursor);
                                fh4.unwind_map_count_source = flags_source(
                                    count_start, unwind_cursor - count_start, 0);
                                require(unwind_count <= record_limit,
                                        "FH4 unwind-map count exceeds the metadata record budget",
                                        ErrorCode::resource_limit);
                                unwind_state_count = unwind_count;
                                fh4.unwind_map.reserve(unwind_count);
                                std::vector<std::uint64_t> unwind_entry_starts;
                                unwind_entry_starts.reserve(unwind_count);
                                for (std::uint32_t i = 0; i < unwind_count; ++i) {
                                    canceled(stop);
                                    const auto entry_start = unwind_cursor;
                                    const auto packed = compressed(unwind_cursor);
                                    PeCxxUnwindMap4Entry entry;
                                    entry.previous_entry_offset = packed >> 2;
                                    if (entry.previous_entry_offset != 0) {
                                        if (entry.previous_entry_offset <= entry_start - *fh4.unwind_map_rva) {
                                            const auto previous_start = entry_start - entry.previous_entry_offset;
                                            const auto previous = std::find(
                                                unwind_entry_starts.begin(), unwind_entry_starts.end(), previous_start);
                                            require(previous != unwind_entry_starts.end(),
                                                    "FH4 unwind-map backward link does not identify an earlier row");
                                            entry.previous_entry_index = static_cast<std::uint32_t>(
                                                std::distance(unwind_entry_starts.begin(), previous));
                                        }
                                    }
                                    entry.type = static_cast<PeCxxUnwindEntry4Type>(packed & 3u);
                                    if (entry.type == PeCxxUnwindEntry4Type::destructor_object ||
                                        entry.type == PeCxxUnwindEntry4Type::destructor_pointer ||
                                        entry.type == PeCxxUnwindEntry4Type::action_rva) {
                                        const auto action_start = unwind_cursor;
                                        const auto action = image_relative_rva(
                                            reader.integer<std::int32_t>(unwind_cursor), "unwind action");
                                        unwind_cursor += 4;
                                        require_executable_rva(action, "unwind action");
                                        entry.action_rva = action;
                                        entry.action_source = flags_source(action_start, 4, i);
                                    }
                                    if (entry.type == PeCxxUnwindEntry4Type::destructor_object ||
                                        entry.type == PeCxxUnwindEntry4Type::destructor_pointer) {
                                        const auto object_start = unwind_cursor;
                                        entry.object_offset = compressed(unwind_cursor);
                                        entry.object_source = flags_source(
                                            object_start, unwind_cursor - object_start, i);
                                    }
                                    entry.source = flags_source(entry_start, unwind_cursor - entry_start, i);
                                    unwind_entry_starts.push_back(entry_start);
                                    fh4.unwind_map.push_back(std::move(entry));
                                }
                                charge_fh4_bytes(count_start, unwind_cursor);
                            }

                            if (fh4.header & try_flag) {
                                require(fh4.try_block_map_rva && *fh4.try_block_map_rva < metadata.image_size,
                                        "FH4 try-block-map RVA is zero or exceeds the image");
                                std::uint64_t try_cursor = *fh4.try_block_map_rva;
                                const auto count_start = try_cursor;
                                const auto try_count = compressed(try_cursor);
                                fh4.try_block_count_source = flags_source(
                                    count_start, try_cursor - count_start, 0);
                                require(try_count <= record_limit,
                                        "FH4 try-block count exceeds the metadata record budget",
                                        ErrorCode::resource_limit);
                                fh4.try_blocks.reserve(try_count);
                                for (std::uint32_t try_index = 0; try_index < try_count; ++try_index) {
                                    canceled(stop);
                                    const auto row_start = try_cursor;
                                    PeCxxTryBlockMap4Entry try_block;
                                    try_block.try_low = decode_state(compressed(try_cursor), "try-low");
                                    try_block.try_high = decode_state(compressed(try_cursor), "try-high");
                                    try_block.catch_high = decode_state(compressed(try_cursor), "catch-high");
                                    const auto handler_array_displacement = reader.integer<std::int32_t>(try_cursor);
                                    try_cursor += 4;
                                    require(try_block.try_low <= try_block.try_high &&
                                                try_block.catch_high >= try_block.try_high,
                                            "FH4 try/catch state range is invalid");
                                    validate_state(try_block.try_low, "try-low");
                                    validate_state(try_block.try_high, "try-high");
                                    validate_state(try_block.catch_high, "catch-high");
                                    try_block.source = flags_source(row_start, try_cursor - row_start, try_index);
                                    if (handler_array_displacement) {
                                        const auto handler_array_rva = image_relative_rva(
                                            handler_array_displacement, "handler-array pointer");
                                        try_block.handler_array_rva = handler_array_rva;
                                        std::uint64_t handler_cursor = handler_array_rva;
                                        const auto handler_count_start = handler_cursor;
                                        const auto handler_count = compressed(handler_cursor);
                                        try_block.handler_array_count_source = flags_source(
                                            handler_count_start, handler_cursor - handler_count_start, 0);
                                        require(handler_count <= record_limit,
                                                "FH4 handler count exceeds the metadata record budget",
                                                ErrorCode::resource_limit);
                                        try_block.handlers.reserve(handler_count);
                                        for (std::uint32_t handler_index = 0; handler_index < handler_count; ++handler_index) {
                                            canceled(stop);
                                            const auto handler_start = handler_cursor;
                                            PeCxxHandlerType4 handler;
                                            handler.header = reader.integer<std::uint8_t>(handler_cursor++);
                                            constexpr std::uint8_t adjectives_flag = 0x01;
                                            constexpr std::uint8_t type_flag = 0x02;
                                            constexpr std::uint8_t catch_object_flag = 0x04;
                                            constexpr std::uint8_t continuation_rva_flag = 0x08;
                                            constexpr std::uint8_t continuation_count_mask = 0x30;
                                            require((handler.header & 0xc0u) == 0,
                                                    "FH4 handler header has nonzero reserved bits");
                                            const auto continuation_count =
                                                static_cast<std::uint8_t>((handler.header & continuation_count_mask) >> 4);
                                            require(continuation_count != 3,
                                                    "FH4 handler header uses the reserved continuation count");
                                            handler.continuation_addresses_are_rvas =
                                                (handler.header & continuation_rva_flag) != 0;
                                            if (handler.header & adjectives_flag) {
                                                const auto field_start = handler_cursor;
                                                handler.adjectives = compressed(handler_cursor);
                                                handler.adjectives_source = flags_source(
                                                    field_start, handler_cursor - field_start, handler_index);
                                            }
                                            if (handler.header & type_flag) {
                                                const auto field_start = handler_cursor;
                                                const auto type_displacement = reader.integer<std::int32_t>(handler_cursor);
                                                handler_cursor += 4;
                                                if (type_displacement == 0) {
                                                    handler.type_descriptor_rva = 0;
                                                    handler.type_descriptor_source = flags_source(
                                                        field_start, 4, handler_index);
                                                } else {
                                                    const auto type_rva = image_relative_rva(
                                                        type_displacement, "catch type pointer");
                                                    constexpr std::uint32_t type_name_offset = 16;
                                                    reader.array(type_rva, 1, type_name_offset);
                                                    const auto name_rva = std::uint64_t{type_rva} + type_name_offset;
                                                    const auto remaining_budget =
                                                        fh4_payload_budget - fh4_bytes_used;
                                                    require(remaining_budget > type_name_offset,
                                                            "FH4 type-descriptor metadata exceeds the 1 MiB payload budget",
                                                            ErrorCode::resource_limit);
                                                    require(name_rva <= metadata.image_size,
                                                            "FH4 type-descriptor name exceeds the image bounds");
                                                    const auto name_limit = name_rva + std::min<std::uint64_t>(
                                                        remaining_budget - type_name_offset,
                                                        metadata.image_size - name_rva);
                                                    auto decorated_name = reader.string(name_rva, name_limit);
                                                    const auto descriptor_size = type_name_offset +
                                                        decorated_name.size() + 1;
                                                    charge_fh4_bytes(type_rva, type_rva + descriptor_size);
                                                    handler.type_descriptor_rva = type_rva;
                                                    handler.decorated_type_name = std::move(decorated_name);
                                                    handler.type_descriptor_source = flags_source(
                                                        type_rva, descriptor_size, handler_index);
                                                }
                                                if (!handler.type_descriptor_source)
                                                    handler.type_descriptor_source = flags_source(
                                                        field_start, 4, handler_index);
                                            }
                                            if (handler.header & catch_object_flag) {
                                                const auto field_start = handler_cursor;
                                                handler.catch_object_offset = compressed(handler_cursor);
                                                handler.catch_object_source = flags_source(
                                                    field_start, handler_cursor - field_start, handler_index);
                                            }
                                            const auto handler_rva_start = handler_cursor;
                                            handler.handler_rva = image_relative_rva(
                                                reader.integer<std::int32_t>(handler_cursor), "catch handler");
                                            handler_cursor += 4;
                                            require_executable_rva(handler.handler_rva, "catch handler");
                                            handler.handler_source = flags_source(handler_rva_start, 4, handler_index);
                                            handler.continuation_addresses.reserve(continuation_count);
                                            handler.continuation_sources.reserve(continuation_count);
                                            for (std::uint8_t continuation_index = 0;
                                                 continuation_index < continuation_count; ++continuation_index) {
                                                const auto field_start = handler_cursor;
                                                std::uint32_t continuation = 0;
                                                if (handler.continuation_addresses_are_rvas) {
                                                    continuation = reader.integer<std::uint32_t>(handler_cursor);
                                                    handler_cursor += 4;
                                                } else {
                                                    continuation = compressed(handler_cursor);
                                                }
                                                std::uint32_t continuation_rva = 0;
                                                if (handler.continuation_addresses_are_rvas) {
                                                    require(continuation < metadata.image_size,
                                                            "FH4 continuation RVA exceeds the image");
                                                    continuation_rva = continuation;
                                                } else {
                                                    require(continuation < function_end - function_begin,
                                                            "FH4 function-relative continuation exceeds its runtime function");
                                                    continuation_rva = static_cast<std::uint32_t>(
                                                        std::uint64_t{function_begin} + continuation);
                                                }
                                                require_executable_rva(continuation_rva, "catch continuation");
                                                handler.continuation_addresses.push_back(continuation);
                                                handler.continuation_sources.push_back(flags_source(
                                                    field_start, handler_cursor - field_start, continuation_index));
                                            }
                                            handler.source = flags_source(
                                                handler_start, handler_cursor - handler_start, handler_index);
                                            try_block.handlers.push_back(std::move(handler));
                                        }
                                        charge_fh4_bytes(handler_count_start, handler_cursor);
                                    }
                                    fh4.try_blocks.push_back(std::move(try_block));
                                }
                                charge_fh4_bytes(count_start, try_cursor);
                            }

                            if (fh4.ip_map_rva) {
                            std::uint64_t effective_ip_map_rva = fh4.ip_map_rva;
                            if (fh4.header & separated_flag) {
                                fh4.separated_ip_map_rva = fh4.ip_map_rva;
                                std::uint64_t separated_cursor = fh4.ip_map_rva;
                                const auto count_start = separated_cursor;
                                const auto separated_count = compressed(separated_cursor);
                                fh4.separated_ip_map_count_source = flags_source(
                                    count_start, separated_cursor - count_start, 0);
                                require(separated_count <= record_limit,
                                        "FH4 separated IP-map count exceeds the metadata record budget",
                                        ErrorCode::resource_limit);
                                reader.array(separated_cursor, separated_count, 8);
                                charge_fh4_bytes(count_start,
                                    separated_cursor + std::uint64_t{separated_count} * 8);
                                fh4.separated_ip_maps.reserve(separated_count);
                                std::optional<std::uint32_t> selected_map;
                                std::unordered_set<std::uint32_t> mapped_functions;
                                for (std::uint32_t i = 0; i < separated_count; ++i) {
                                    canceled(stop);
                                    const auto row = separated_cursor + std::uint64_t{i} * 8;
                                    PeCxxSeparatedIpMap4Entry entry;
                                    entry.function_rva = reader.integer<std::uint32_t>(row);
                                    entry.ip_map_rva = reader.integer<std::uint32_t>(row + 4);
                                    require(mapped_functions.insert(entry.function_rva).second,
                                            "FH4 separated IP-map table repeats a function RVA");
                                    require(entry.function_rva < metadata.image_size,
                                            "FH4 separated IP-map function RVA exceeds the image");
                                    const auto function_address = reader.address(entry.function_rva);
                                    const auto *function_segment = image.segment_at(function_address);
                                    require(function_segment && function_segment->executable &&
                                                function_address.offset - function_segment->begin.offset < function_segment->file_size,
                                            "FH4 separated IP-map function RVA is not initialized executable code");
                                    require(entry.ip_map_rva && entry.ip_map_rva < metadata.image_size,
                                            "FH4 separated IP-map entry has an invalid map RVA");
                                    (void)reader.integer<std::uint8_t>(entry.ip_map_rva);
                                    entry.source = flags_source(row, 8, i);
                                    if (entry.function_rva == function_begin) selected_map = entry.ip_map_rva;
                                    fh4.separated_ip_maps.push_back(std::move(entry));
                                }
                                require(selected_map.has_value(),
                                        "FH4 separated IP-map table has no row for its runtime function");
                                effective_ip_map_rva = *selected_map;
                            }
                            fh4.ip_map_rva = static_cast<std::uint32_t>(effective_ip_map_rva);
                            std::uint64_t map_cursor = effective_ip_map_rva;
                            const auto count_start = map_cursor;
                            const auto map_count = compressed(map_cursor);
                            fh4.ip_map_count_source = flags_source(count_start, map_cursor - count_start, 0);
                            require(map_count <= record_limit, "FH4 IP map count exceeds the metadata record budget", ErrorCode::resource_limit);
                            std::uint64_t ip_offset = 0;
                            fh4.ip_to_state.reserve(map_count);
                            for (std::uint32_t i = 0; i < map_count; ++i) {
                                canceled(stop);
                                const auto entry_start = map_cursor;
                                const auto delta = compressed(map_cursor);
                                const auto encoded_state = compressed(map_cursor);
                                require(delta <= UINT32_MAX - ip_offset, "FH4 IP map offset overflows");
                                ip_offset += delta;
                                require(ip_offset <= function_end - function_begin,
                                        "FH4 IP map entry exceeds its runtime function");
                                PeCxxIpToState4Entry entry;
                                entry.ip_rva = static_cast<std::uint32_t>(std::uint64_t{function_begin} + ip_offset);
                                entry.state = decode_state(encoded_state, "IP map");
                                validate_state(entry.state, "IP-map");
                                entry.source = flags_source(entry_start, map_cursor - entry_start, i);
                                fh4.ip_to_state.push_back(std::move(entry));
                            }
                            charge_fh4_bytes(count_start, map_cursor);
                        } else {
                            fh4.status = PeCxxFuncInfo4Status::unsupported;
                            fh4.diagnostic = "FH4 IP map RVA is null";
                        }
                        }
                    } catch (const Failure &failure) {
                        fh4.status = PeCxxFuncInfo4Status::malformed;
                        fh4.diagnostic = failure.error.message;
                    }
                    fh4.source = flags_source(payload_rva, header_end - payload_rva, 0);
                    payload.status = PeHandlerPayloadStatus::decoded_cxx_func_info4;
                    payload.source = fh4.source;
                    payload.cxx_func_info4 = std::move(fh4);
                } else if (payload.handler_name && *payload.handler_name == "__CxxFrameHandler3") {
                    // The modern FuncInfo schema (magic 0x19930522) has a fixed
                    // 40-byte header. Relative pointers are RVAs from the image base.
                    require(payload_rva <= metadata.image_size && metadata.image_size - payload_rva >= 40,
                            "AMD64 C++ FuncInfo header exceeds the image bounds");
                    reader.array(payload_rva, 1, 40);
                    PeCxxFuncInfo cxx;
                    cxx.magic = reader.integer<std::uint32_t>(payload_rva);
                    cxx.max_state = reader.integer<std::int32_t>(payload_rva + 4);
                    cxx.unwind_map_rva = reader.integer<std::uint32_t>(payload_rva + 8);
                    cxx.try_block_count = reader.integer<std::uint32_t>(payload_rva + 12);
                    cxx.try_block_map_rva = reader.integer<std::uint32_t>(payload_rva + 16);
                    cxx.ip_map_count = reader.integer<std::uint32_t>(payload_rva + 20);
                    cxx.ip_map_rva = reader.integer<std::uint32_t>(payload_rva + 24);
                    cxx.unwind_help = reader.integer<std::int32_t>(payload_rva + 28);
                    cxx.es_type_list_rva = reader.integer<std::uint32_t>(payload_rva + 32);
                    cxx.eh_flags = reader.integer<std::int32_t>(payload_rva + 36);
                    cxx.has_ehs_flag = (static_cast<std::uint32_t>(cxx.eh_flags) & 0x1u) != 0;
                    cxx.has_dynamic_stack_alignment = (static_cast<std::uint32_t>(cxx.eh_flags) & 0x2u) != 0;
                    cxx.is_noexcept = (static_cast<std::uint32_t>(cxx.eh_flags) & 0x4u) != 0;
                    cxx.unknown_eh_flags = static_cast<std::uint32_t>(cxx.eh_flags) & ~0x7u;
                    require(cxx.magic == 0x19930522u,
                            "AMD64 C++ FuncInfo magic is unsupported", ErrorCode::unsupported);
                    require(cxx.max_state >= 0 && static_cast<std::uint32_t>(cxx.max_state) <= record_limit,
                            "AMD64 C++ unwind map count exceeds the metadata record budget", ErrorCode::resource_limit);
                    require(cxx.try_block_count <= record_limit && cxx.ip_map_count <= record_limit,
                            "AMD64 C++ FuncInfo table count exceeds the metadata record budget", ErrorCode::resource_limit);
                    const auto validate_counted_rva = [&](std::uint32_t count, std::uint32_t rva,
                                                          std::uint64_t record_size, const char *what) {
                        require((count == 0) == (rva == 0), std::string("AMD64 C++ ") + what +
                                    " count and RVA disagree");
                        if (!count) return;
                        require(rva < metadata.image_size &&
                                    std::uint64_t{count} <= (metadata.image_size - rva) / record_size,
                                std::string("AMD64 C++ ") + what + " exceeds image bounds");
                    };
                    validate_counted_rva(static_cast<std::uint32_t>(cxx.max_state), cxx.unwind_map_rva, 8, "unwind map");
                    validate_counted_rva(cxx.try_block_count, cxx.try_block_map_rva, 20, "try-block map");
                    validate_counted_rva(cxx.ip_map_count, cxx.ip_map_rva, 8, "IP-to-state map");
                    if (cxx.es_type_list_rva)
                        require(cxx.es_type_list_rva < metadata.image_size,
                                "AMD64 C++ ES type-list RVA exceeds the image");
                    const auto payload_size = std::uint64_t{40} +
                        std::uint64_t{static_cast<std::uint32_t>(cxx.max_state)} * 8 +
                        std::uint64_t{cxx.try_block_count} * 20 + std::uint64_t{cxx.ip_map_count} * 8;
                    require(payload_size <= 1024 * 1024,
                            "AMD64 C++ FuncInfo payload exceeds the 1 MiB budget", ErrorCode::resource_limit);
                    std::uint64_t total_handler_count = 0;
                    std::uint64_t total_type_descriptor_bytes = 0;
                    std::uint64_t cxx_metadata_bytes = payload_size;
                    payload.status = PeHandlerPayloadStatus::decoded_cxx_func_info;
                    cxx.source = flags_source(payload_rva, 40, 0);
                    cxx.eh_flags_source = flags_source(payload_rva + 36, 4, 0);
                    payload.source = cxx.source;
                    payload.cxx_func_info = cxx;
                    payload.cxx_func_info->unwind_map.reserve(static_cast<std::size_t>(cxx.max_state));
                    for (std::int32_t state = 0; state < cxx.max_state; ++state) {
                        canceled(stop);
                        const auto row = std::uint64_t{cxx.unwind_map_rva} +
                            std::uint64_t{static_cast<std::uint32_t>(state)} * 8;
                        PeCxxUnwindMapEntry entry;
                        entry.to_state = reader.integer<std::int32_t>(row);
                        entry.action_rva = reader.integer<std::uint32_t>(row + 4);
                        require(entry.to_state == -1 || (entry.to_state >= 0 && entry.to_state < state),
                                "AMD64 C++ unwind map has an invalid predecessor state");
                        if (entry.action_rva) {
                            const auto action = reader.address(entry.action_rva);
                            const auto *segment = image.segment_at(action);
                            require(segment && segment->executable &&
                                        action.offset - segment->begin.offset < segment->file_size,
                                    "AMD64 C++ unwind action is not initialized executable code");
                        }
                        entry.source = flags_source(row, 8, static_cast<std::uint32_t>(state));
                        payload.cxx_func_info->unwind_map.push_back(std::move(entry));
                    }
                    const auto relative_image_rva = [&](std::int32_t displacement, const char *what) {
                        require(displacement > 0 && static_cast<std::uint64_t>(displacement) < metadata.image_size,
                                std::string("AMD64 C++ ") + what + " has an invalid image-relative RVA");
                        return static_cast<std::uint32_t>(displacement);
                    };
                    auto &cxx_info = *payload.cxx_func_info;
                    cxx_info.try_blocks.reserve(cxx.try_block_count);
                    for (std::uint32_t try_index = 0; try_index < cxx.try_block_count; ++try_index) {
                        canceled(stop);
                        const auto row = std::uint64_t{cxx.try_block_map_rva} + std::uint64_t{try_index} * 20;
                        PeCxxTryBlockMapEntry try_block;
                        try_block.try_low = reader.integer<std::int32_t>(row);
                        try_block.try_high = reader.integer<std::int32_t>(row + 4);
                        try_block.catch_high = reader.integer<std::int32_t>(row + 8);
                        const auto handler_count = reader.integer<std::int32_t>(row + 12);
                        const auto handler_array_displacement = reader.integer<std::int32_t>(row + 16);
                        require(try_block.try_low >= 0 && try_block.try_low <= try_block.try_high &&
                                    try_block.try_high < cxx.max_state &&
                                    try_block.catch_high >= try_block.try_high &&
                                    try_block.catch_high < cxx.max_state,
                                "AMD64 C++ try-block state range is invalid");
                        require(handler_count > 0 && static_cast<std::uint64_t>(handler_count) <= record_limit - total_handler_count,
                                "AMD64 C++ handler array count exceeds the metadata record budget", ErrorCode::resource_limit);
                        total_handler_count += static_cast<std::uint32_t>(handler_count);
                        const auto handler_array_rva = relative_image_rva(handler_array_displacement, "handler-array pointer");
                        reader.array(handler_array_rva, static_cast<std::uint32_t>(handler_count), 20);
                        cxx_metadata_bytes = payload_size + total_handler_count * 20 + total_type_descriptor_bytes;
                        require(cxx_metadata_bytes <= 1024 * 1024,
                                "AMD64 C++ try/catch metadata exceeds the 1 MiB budget", ErrorCode::resource_limit);
                        try_block.source = flags_source(row, 20, try_index);
                        try_block.handlers.reserve(static_cast<std::size_t>(handler_count));
                        for (std::int32_t handler_index = 0; handler_index < handler_count; ++handler_index) {
                            canceled(stop);
                            const auto handler_row = std::uint64_t{handler_array_rva} +
                                std::uint64_t{static_cast<std::uint32_t>(handler_index)} * 20;
                            PeCxxHandlerType cxx_handler;
                            cxx_handler.adjectives = reader.integer<std::uint32_t>(handler_row);
                            const auto type_displacement = reader.integer<std::int32_t>(handler_row + 4);
                            cxx_handler.catch_object_offset = reader.integer<std::int32_t>(handler_row + 8);
                            const auto handler_displacement = reader.integer<std::int32_t>(handler_row + 12);
                            cxx_handler.frame_offset = reader.integer<std::int32_t>(handler_row + 16);
                            if (type_displacement) {
                                const auto type_rva = relative_image_rva(type_displacement, "catch type pointer");
                                constexpr std::uint32_t type_name_offset = 16; // 64-bit TypeDescriptor prefix.
                                reader.array(type_rva, 1, type_name_offset);
                                const auto name_rva = std::uint64_t{type_rva} + type_name_offset;
                                const auto remaining_budget = 1024 * 1024 - cxx_metadata_bytes;
                                require(remaining_budget > type_name_offset,
                                        "AMD64 C++ type-descriptor metadata exceeds the 1 MiB budget",
                                        ErrorCode::resource_limit);
                                const auto name_bytes = std::min<std::uint64_t>(
                                    reader.initialized_extent(name_rva), remaining_budget - type_name_offset);
                                const auto name_limit = name_rva + name_bytes;
                                auto decorated_name = reader.string(name_rva, name_limit);
                                const auto type_descriptor_size = type_name_offset + decorated_name.size() + 1;
                                require(type_descriptor_size <= remaining_budget,
                                        "AMD64 C++ type-descriptor metadata exceeds the 1 MiB budget",
                                        ErrorCode::resource_limit);
                                total_type_descriptor_bytes += type_descriptor_size;
                                cxx_metadata_bytes += type_descriptor_size;
                                cxx_handler.type_descriptor_rva = type_rva;
                                cxx_handler.decorated_type_name = std::move(decorated_name);
                                cxx_handler.type_descriptor_source = flags_source(
                                    type_rva, type_descriptor_size,
                                    static_cast<std::uint32_t>(handler_index));
                            }
                            cxx_handler.handler_rva = relative_image_rva(handler_displacement, "catch handler pointer");
                            const auto catch_handler_address = reader.address(cxx_handler.handler_rva);
                            const auto *catch_handler_segment = image.segment_at(catch_handler_address);
                            require(catch_handler_segment && catch_handler_segment->executable &&
                                        catch_handler_address.offset - catch_handler_segment->begin.offset < catch_handler_segment->file_size,
                                    "AMD64 C++ catch handler is not initialized executable code");
                            cxx_handler.source = flags_source(handler_row, 20, static_cast<std::uint32_t>(handler_index));
                            try_block.handlers.push_back(std::move(cxx_handler));
                        }
                        cxx_info.try_blocks.push_back(std::move(try_block));
                    }
                    if (cxx.es_type_list_rva) {
                        const auto list_rva = cxx.es_type_list_rva;
                        reader.array(list_rva, 1, 8);
                        const auto type_count = reader.integer<std::int32_t>(list_rva);
                        const auto type_array_displacement = reader.integer<std::int32_t>(list_rva + 4);
                        require(type_count >= 0 && static_cast<std::uint64_t>(type_count) <= record_limit,
                                "AMD64 C++ exception-specification type count exceeds the metadata record budget",
                                ErrorCode::resource_limit);

                        PeCxxExceptionSpecTypeList type_list;
                        type_list.count = static_cast<std::uint32_t>(type_count);
                        type_list.source = flags_source(list_rva, 8, 0);
                        cxx_metadata_bytes += 8;
                        require(cxx_metadata_bytes <= 1024 * 1024,
                                "AMD64 C++ exception-specification metadata exceeds the 1 MiB budget",
                                ErrorCode::resource_limit);
                        if (type_count > 0) {
                            type_list.type_array_rva = relative_image_rva(
                                type_array_displacement, "exception-specification type-array pointer");
                            reader.array(type_list.type_array_rva, static_cast<std::uint32_t>(type_count), 20);
                            const auto type_array_size = std::uint64_t{static_cast<std::uint32_t>(type_count)} * 20;
                            require(type_array_size <= 1024 * 1024 - cxx_metadata_bytes,
                                    "AMD64 C++ exception-specification type array exceeds the 1 MiB budget",
                                    ErrorCode::resource_limit);
                            cxx_metadata_bytes += type_array_size;
                            type_list.type_array_source = flags_source(type_list.type_array_rva,
                                                                       type_array_size, 0);
                            type_list.types.reserve(static_cast<std::size_t>(type_count));
                            for (std::int32_t type_index = 0; type_index < type_count; ++type_index) {
                                canceled(stop);
                                const auto row = std::uint64_t{type_list.type_array_rva} +
                                                 std::uint64_t{static_cast<std::uint32_t>(type_index)} * 20;
                                PeCxxExceptionSpecType type;
                                type.adjectives = reader.integer<std::uint32_t>(row);
                                const auto type_displacement = reader.integer<std::int32_t>(row + 4);
                                if (type_displacement) {
                                    const auto descriptor_rva = relative_image_rva(
                                        type_displacement, "exception-specification type pointer");
                                    constexpr std::uint32_t type_name_offset = 16;
                                    reader.array(descriptor_rva, 1, type_name_offset);
                                    const auto name_rva = std::uint64_t{descriptor_rva} + type_name_offset;
                                    const auto remaining_budget = 1024 * 1024 - cxx_metadata_bytes;
                                    require(remaining_budget > type_name_offset,
                                            "AMD64 C++ exception-specification names exceed the 1 MiB budget",
                                            ErrorCode::resource_limit);
                                    const auto name_bytes = std::min<std::uint64_t>(
                                        reader.initialized_extent(name_rva), remaining_budget - type_name_offset);
                                    const auto decorated_name = reader.string(name_rva, name_rva + name_bytes);
                                    const auto descriptor_size = type_name_offset + decorated_name.size() + 1;
                                    require(descriptor_size <= remaining_budget,
                                            "AMD64 C++ exception-specification names exceed the 1 MiB budget",
                                            ErrorCode::resource_limit);
                                    cxx_metadata_bytes += descriptor_size;
                                    type.type_descriptor_rva = descriptor_rva;
                                    type.decorated_type_name = decorated_name;
                                    type.type_descriptor_source = flags_source(
                                        descriptor_rva, descriptor_size, static_cast<std::uint32_t>(type_index));
                                }
                                type.source = flags_source(row, 20, static_cast<std::uint32_t>(type_index));
                                type_list.types.push_back(std::move(type));
                            }
                        }
                        cxx_info.exception_spec_types = std::move(type_list);
                    }
                    cxx_info.ip_to_state.reserve(cxx.ip_map_count);
                    std::uint32_t previous_ip = 0;
                    std::int32_t previous_state = -2;
                    for (std::uint32_t ip_index = 0; ip_index < cxx.ip_map_count; ++ip_index) {
                        canceled(stop);
                        const auto row = std::uint64_t{cxx.ip_map_rva} + std::uint64_t{ip_index} * 8;
                        const auto ip_displacement = reader.integer<std::int32_t>(row);
                        PeCxxIpToStateEntry entry;
                        entry.ip_rva = static_cast<std::uint32_t>(relative_image_rva(ip_displacement, "IP-to-state address"));
                        entry.state = reader.integer<std::int32_t>(row + 4);
                        require(entry.ip_rva >= function_begin && entry.ip_rva <= function_end,
                                "AMD64 C++ IP-to-state address is outside its runtime function");
                        require(entry.state == -1 || (entry.state >= 0 && entry.state < cxx.max_state),
                                "AMD64 C++ IP-to-state entry has an invalid state");
                        require(ip_index == 0 || entry.ip_rva > previous_ip ||
                                    (entry.ip_rva == previous_ip && entry.state == previous_state),
                                "AMD64 C++ IP-to-state entries are not ordered");
                        entry.source = flags_source(row, 8, ip_index);
                        cxx_info.ip_to_state.push_back(std::move(entry));
                        previous_ip = cxx_info.ip_to_state.back().ip_rva;
                        previous_state = cxx_info.ip_to_state.back().state;
                    }
                } else {
                    payload.status = payload.handler_name ? PeHandlerPayloadStatus::unsupported_handler
                                                         : PeHandlerPayloadStatus::unresolved_handler;
                    if (payload_rva < metadata.image_size) {
                        const auto address = reader.address(payload_rva);
                        const auto* segment = image.segment_at(address);
                        if (segment) {
                            const auto relative = address.offset - segment->begin.offset;
                            if (relative < segment->file_size) {
                                const auto preview_size = static_cast<std::size_t>(
                                    std::min<std::uint64_t>({256, segment->file_size - relative,
                                                             metadata.image_size - payload_rva}));
                                if (preview_size) {
                                    payload.opaque_preview = reader.bytes(payload_rva, preview_size);
                                    payload.source = flags_source(payload_rva, preview_size, 0);
                                }
                            }
                        }
                    }
                }
                info.handler_payload = std::move(payload);
            }
            info.source = flags_source(unwind_rva, tail_rva + ((info.flags & 7u) ? ((info.flags & 4u) ? 12u : 4u) : 0u) - unwind_rva, 0);
            return info;
        };

        std::vector<PeRuntimeFunction> parsed;
        parsed.reserve(count);
        std::uint32_t previous_begin = 0;
        std::uint32_t previous_end = 0;
        for (std::uint32_t index = 0; index < count; ++index) {
            canceled(stop);
            const auto row = std::uint64_t{directory.location} + std::uint64_t{index} * 12;
            PeRuntimeFunction function;
            function.begin_rva = reader.integer<std::uint32_t>(row);
            function.end_rva = reader.integer<std::uint32_t>(row + 4);
            function.unwind_info_rva = reader.integer<std::uint32_t>(row + 8);
            require(function.begin_rva < function.end_rva && function.end_rva <= metadata.image_size,
                    "AMD64 runtime-function code range is empty or exceeds the image");
            require(index == 0 || (function.begin_rva > previous_begin &&
                                   function.begin_rva >= previous_end),
                    "AMD64 runtime-function ranges are not strictly ordered and non-overlapping");

            require(function.unwind_info_rva != 0 && (function.unwind_info_rva & 3u) == 0,
                    "AMD64 runtime-function UNWIND_INFO RVA is zero or misaligned");
            validate_code_range(function.begin_rva, function.end_rva);
            function.unwind_info = parse_unwind(function.unwind_info_rva, 0,
                                                function.begin_rva, function.end_rva);
            function.source = {index, reader.sources(row, 12)};
            parsed.push_back(std::move(function));
            previous_begin = parsed.back().begin_rva;
            previous_end = parsed.back().end_rva;
        }
        auto &functions = metadata.pe->exception_functions;
        functions.insert(functions.end(), parsed.begin(), parsed.end());
        return parsed.size();
    });
}
} // namespace hexlab::pe_detail
