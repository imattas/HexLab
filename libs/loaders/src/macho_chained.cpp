#include "macho_dyld_internal.hpp"
#include "hexlab/image/macho_mapping.hpp"
#include "miniz_tinfl.h"
#include <queue>
#include <map>
#include <tuple>
#include <algorithm>
namespace hexlab::macho_detail {
namespace {
constexpr std::uint32_t max_chained_imports = 1'000'000;
constexpr std::uint32_t max_chained_pages = 65'535;
constexpr std::size_t max_chained_symbol_bytes = 64 * 1024;
constexpr std::size_t max_chained_symbol_pool_bytes = 16 * 1024 * 1024;
constexpr std::size_t chained_inflate_input_window = 64 * 1024;
constexpr std::size_t chained_inflate_output_window = 32 * 1024;
void extent(std::span<const std::byte> bytes, std::uint64_t offset, std::uint64_t size) {
    require(offset <= bytes.size() && size <= bytes.size() - offset, "Mach-O chained field crosses payload boundary");
}
std::int64_t signed_field(std::uint64_t value, unsigned bits) {
    if (bits < 64 && (value & (UINT64_C(1) << (bits - 1))))
        value |= UINT64_MAX << bits;
    return std::bit_cast<std::int64_t>(value);
}
std::vector<std::uint8_t> inflate_symbol_pool(std::span<const std::byte> input, Budget &budget,
                                              std::stop_token stop) {
    require(!input.empty(), "Mach-O chained zlib symbol pool is empty");
    budget.include(max_chained_symbol_pool_bytes);
    std::vector<std::uint8_t> output(max_chained_symbol_pool_bytes);
    std::uint8_t empty_output = 0;
    std::size_t input_offset = 0;
    std::size_t output_offset = 0;
    tinfl_decompressor decompressor;
    tinfl_init(&decompressor);
    constexpr auto base_flags = TINFL_FLAG_PARSE_ZLIB_HEADER | TINFL_FLAG_COMPUTE_ADLER32 |
                                TINFL_FLAG_USING_NON_WRAPPING_OUTPUT_BUF;
    for (;;) {
        canceled(stop);
        const auto input_remaining = input.size() - input_offset;
        const auto input_window = std::min(chained_inflate_input_window, input_remaining);
        const bool more_input = input_window < input_remaining;
        const auto output_remaining = output.size() - output_offset;
        const auto output_window = std::min(chained_inflate_output_window, output_remaining);
        auto *output_base = output.empty() ? &empty_output : output.data();
        auto *output_next = output_base + output_offset;
        std::size_t input_used = input_window;
        std::size_t output_written = output_window;
        const auto flags = base_flags | (more_input ? TINFL_FLAG_HAS_MORE_INPUT : 0);
        const auto status = tinfl_decompress(&decompressor,
            reinterpret_cast<const mz_uint8 *>(input.data()) + input_offset,
            &input_used, output_base, output_next, &output_written, flags);
        require(input_used <= input_window && output_written <= output_window,
                "Mach-O chained zlib decoder returned invalid window counts");
        input_offset += input_used;
        require(output_written <= output.size() - output_offset,
                "Mach-O chained symbol pool exceeds 16 MiB", ErrorCode::resource_limit);
        output_offset += output_written;
        if (status == TINFL_STATUS_DONE) {
            require(input_offset == input.size(), "Mach-O chained zlib symbol pool has trailing bytes");
            break;
        }
        if (status == TINFL_STATUS_HAS_MORE_OUTPUT) {
            require(output_offset < output.size(), "Mach-O chained symbol pool exceeds 16 MiB",
                    ErrorCode::resource_limit);
            require(output_written != 0 || input_used != 0, "Mach-O chained zlib decoder made no progress");
            continue;
        }
        if (status == TINFL_STATUS_NEEDS_MORE_INPUT) {
            require((input_used != 0 || output_written != 0) && input_offset < input.size(),
                    "Malformed or truncated Mach-O chained zlib symbol pool");
            continue;
        }
        require(false, "Malformed or truncated Mach-O chained zlib symbol pool");
    }
    output.resize(output_offset);
    return output;
}
std::pair<std::uint8_t, std::uint8_t> layout(std::uint16_t format) {
    switch (format) {
    case 2:
    case 6:
        return {std::uint8_t{8}, std::uint8_t{4}};
    case 8: // DYLD_CHAINED_PTR_64_KERNEL_CACHE
        return {std::uint8_t{8}, std::uint8_t{4}};
    case 11: // DYLD_CHAINED_PTR_X86_64_KERNEL_CACHE
        return {std::uint8_t{8}, std::uint8_t{1}};
    case 3:
    case 4: // DYLD_CHAINED_PTR_32_CACHE
    case 5: // DYLD_CHAINED_PTR_32_FIRMWARE
        return {std::uint8_t{4}, std::uint8_t{4}};
    case 1:
    case 9:
    case 12:
    case 13: // DYLD_CHAINED_PTR_ARM64E_SHARED_CACHE
        return {std::uint8_t{8}, std::uint8_t{8}};
    case 7: // DYLD_CHAINED_PTR_ARM64E_KERNEL
    case 10: // DYLD_CHAINED_PTR_ARM64E_FIRMWARE
        return {std::uint8_t{8}, std::uint8_t{4}};
    case 14: // DYLD_CHAINED_PTR_ARM64E_SEGMENTED: 8-byte word, 4-byte stride
        return {std::uint8_t{8}, std::uint8_t{4}};
    default:
        return {std::uint8_t{0}, std::uint8_t{0}};
    }
}
void pointer_bits(MachOChainedPointer &row, const MachOChainedStarts &starts) {
    const auto raw = row.raw;
    const auto format = starts.pointer_format;
    if (format == 2 || format == 6) {
        row.bind = bool(raw >> 63);
        row.next = static_cast<std::uint16_t>((raw >> 51) & 0xfff);
        if (row.bind) {
            row.import_index = static_cast<std::uint32_t>(raw & 0xffffff);
            row.addend = (raw >> 24) & 0xff; // Unsigned8-bit on-disk addend.
            if ((raw >> 32) & 0x7ffff)
                row.complete = false;
        } else {
            row.target = raw & UINT64_C(0xfffffffff);
            row.high8 = static_cast<std::uint8_t>((raw >> 36) & 0xff);
            row.target_is_offset = format == 6;
            if ((raw >> 44) & 0x7f)
                row.complete = false;
        }
    } else if (format == 3) {
        row.bind = bool(raw & (UINT64_C(1) << 31));
        row.next = static_cast<std::uint16_t>((raw >> 26) & 31);
        if (row.bind) {
            row.import_index = static_cast<std::uint32_t>(raw & 0xfffff);
            row.addend = (raw >> 20) & 63;
        } else {
            row.target = raw & 0x3ffffff;
            if (*row.target > starts.max_valid_pointer) {
                row.non_pointer = true;
                const auto bias = (UINT64_C(0x4000000) + starts.max_valid_pointer) / 2;
                row.scalar_value = static_cast<std::uint32_t>(*row.target - bias);
            }
        }
    } else if (format == 4) {
        // Cache-relative targets need the cache mapping context to resolve.
        // Preserve the exact 30-bit target and 2-bit next field only.
        row.next = static_cast<std::uint16_t>((raw >> 30) & 0x3);
        row.target = raw & UINT64_C(0x3fffffff);
        row.target_is_offset = true;
        row.target_base_kind = MachOChainedTargetBaseKind::shared_cache;
        row.complete = false;
    } else if (format == 5) {
        // Firmware pointers store the target VM address directly, with a
        // six-bit next field measured in four-byte units.
        row.next = static_cast<std::uint16_t>((raw >> 26) & 0x3f);
        row.target = raw & UINT64_C(0x03ffffff);
    } else if (format == 14) {
        // Preserve the packed 4-bit segment index and 28-bit segment offset
        // as a target payload. The caller maps it through the segment list
        // while retaining the original encoding in target/raw. For rebases,
        // bits 32..50 are reserved and must be zero. Authenticated variants
        // assign those bits to diversity/address-diversity/key instead.
        row.target = raw & UINT32_MAX;
        row.next = static_cast<std::uint16_t>((raw >> 51) & 0xfff);
        row.authenticated = bool(raw >> 63);
        if (row.authenticated) {
            row.diversity = static_cast<std::uint16_t>((raw >> 32) & 0xffff);
            row.address_diversity = bool((raw >> 48) & 1);
            row.key = static_cast<std::uint8_t>((raw >> 49) & 3);
        } else if ((raw >> 32) & 0x7ffff) {
            row.complete = false;
        }
    } else if (format == 8 || format == 11) {
        // Kernel-cache targets are relative to one of several cache images.
        // Retain their encoded target/authentication fields, but keep the row
        // incomplete until a dyld shared-cache base table is available.
        row.authenticated = bool(raw >> 63);
        row.next = static_cast<std::uint16_t>((raw >> 51) & 0xfff);
        row.target = raw & 0x3fffffff;
        row.cache_level = static_cast<std::uint8_t>((raw >> 30) & 0x3);
        row.target_is_offset = true;
        row.target_base_kind = MachOChainedTargetBaseKind::cache_level;
        row.diversity = static_cast<std::uint16_t>((raw >> 32) & 0xffff);
        row.address_diversity = bool((raw >> 48) & 1);
        row.key = static_cast<std::uint8_t>((raw >> 49) & 3);
        row.complete = false;
    } else if (format == 13) {
        // The target is relative to the dyld shared cache, whose base is not
        // available from a standalone Mach-O image. Retain the chain and its
        // exact payload without presenting an image-relative rebase.
        row.authenticated = bool(raw >> 63);
        row.next = static_cast<std::uint16_t>((raw >> 52) & 0x7ff);
        row.target = raw & UINT64_C(0x3ffffffff);
        row.target_is_offset = true;
        row.target_base_kind = MachOChainedTargetBaseKind::shared_cache;
        if (!row.authenticated && ((raw >> 42) & 0x3ff))
            row.complete = false;
        if (row.authenticated) {
            row.diversity = static_cast<std::uint16_t>((raw >> 34) & 0xffff);
            row.address_diversity = bool((raw >> 50) & 1);
            row.key = static_cast<std::uint8_t>(((raw >> 51) & 1) ? 2 : 0); // DA or IA.
        } else {
            row.high8 = static_cast<std::uint8_t>((raw >> 34) & 0xff);
        }
        row.complete = false;
    } else {
        row.bind = bool(raw & (UINT64_C(1) << 62));
        row.authenticated = bool(raw >> 63);
        row.next = static_cast<std::uint16_t>((raw >> 51) & 0x7ff);
        if (row.authenticated) {
            row.diversity = static_cast<std::uint16_t>(raw >> 32);
            row.address_diversity = bool((raw >> 48) & 1);
            row.key = static_cast<std::uint8_t>((raw >> 49) & 3);
        }
        if (row.bind) {
            const auto bits = format == 12 ? 24u : 16u;
            row.import_index = static_cast<std::uint32_t>(raw & ((UINT64_C(1) << bits) - 1));
            if ((raw >> bits) & ((UINT64_C(1) << (32 - bits)) - 1))
                row.complete = false;
            if (!row.authenticated)
                row.addend = signed_field((raw >> 32) & 0x7ffff, 19);
        } else if (row.authenticated) {
            row.target = raw & 0xffffffff;
            row.target_is_offset = true;
        } else {
            row.target = raw & UINT64_C(0x7ffffffffff);
            row.high8 = static_cast<std::uint8_t>((raw >> 43) & 0xff);
            row.target_is_offset = format != 1 && format != 10;
        }
    }
}
} // namespace
void read_chained(const Reader &reader, const Image &image, MachOMetadata &metadata, std::uint32_t stream_id,
                  std::uint32_t libraries, std::optional<Address> header_anchor, Budget &budget, std::stop_token stop) {
    auto &stream = metadata.dyld_streams[stream_id];
    budget.include(stream.size + sizeof(MachOChainedHeader));
    const auto view = reader.bytes(stream.raw_offset, stream.size);
    const auto bytes = view.bytes;
    extent(bytes, 0, 28);
    const auto number = [&](std::uint64_t at, std::size_t width) {
        extent(bytes, at, width);
        return reader.value(bytes, static_cast<std::size_t>(at), width);
    };
    const auto absolute = [&](std::uint64_t offset) { return add(stream.offset.value, offset); };
    MachOChainedHeader declaration;
    declaration.stream = stream_id;
    declaration.record_file_offset = stream.offset.value;
    declaration.version = static_cast<std::uint32_t>(number(0, 4));
    declaration.starts_offset = static_cast<std::uint32_t>(number(4, 4));
    declaration.imports_offset = static_cast<std::uint32_t>(number(8, 4));
    declaration.symbols_offset = static_cast<std::uint32_t>(number(12, 4));
    declaration.imports_count = static_cast<std::uint32_t>(number(16, 4));
    declaration.imports_format = static_cast<std::uint32_t>(number(20, 4));
    declaration.symbols_format = static_cast<std::uint32_t>(number(24, 4));
    declaration.first_import_row = metadata.chained_imports.size();
    const auto header_id = static_cast<std::uint32_t>(metadata.chained_headers.size());
    metadata.chained_headers.push_back(declaration);
    auto &header = metadata.chained_headers.back();
    const auto &slice = metadata.container.slices[metadata.selected_slice];
    std::vector<std::pair<std::uint64_t, std::uint64_t>> metadata_ranges{{0, 28}};
    if (header.version != 0 || slice.header.order != ByteOrder::little) {
        header.complete = stream.complete = metadata.dyld_complete = false;
        return;
    }
    require(metadata.chained_imports.size() <= max_chained_imports &&
                header.imports_count <= max_chained_imports - metadata.chained_imports.size(),
            "Mach-O chained import count exceeds budget", ErrorCode::resource_limit);
    extent(bytes, header.symbols_offset, 0);
    const auto stride = header.imports_format == 1   ? 4u
                        : header.imports_format == 2 ? 8u
                        : header.imports_format == 3 ? 16u
                                                     : 0u;
    if (!stride || header.symbols_format > 1)
        header.complete = false;
    extent(bytes, header.imports_offset, std::uint64_t(header.imports_count) * stride);
    if (header.imports_count && stride != 0) {
        require(header.imports_offset >= 28, "Mach-O chained imports overlap the fixed header");
        metadata_ranges.emplace_back(header.imports_offset,
                                     std::uint64_t(header.imports_offset) + std::uint64_t(header.imports_count) * stride);
    }
    header.imports_available = stride != 0;
    std::vector<std::uint8_t> decompressed_symbols;
    std::span<const std::uint8_t> symbols;
    if (header.symbols_format == 0) {
        extent(bytes, header.symbols_offset, 0);
        symbols = {reinterpret_cast<const std::uint8_t *>(bytes.data() + header.symbols_offset),
                   bytes.size() - header.symbols_offset};
    } else if (header.symbols_format == 1) {
        extent(bytes, header.symbols_offset, 0);
        const auto compressed = bytes.subspan(header.symbols_offset);
        decompressed_symbols = inflate_symbol_pool(compressed, budget, stop);
        symbols = decompressed_symbols;
    }
    require(header.imports_count == 0 || !symbols.empty(),
            "Mach-O chained imports reference an empty symbol pool");
    if (header.imports_count) {
        require(header.symbols_offset >= 28 && header.symbols_offset < bytes.size(),
                "Mach-O chained symbol pool overlaps the fixed header or is empty");
        metadata_ranges.emplace_back(header.symbols_offset, bytes.size());
    }
    std::size_t symbol_pool_bytes = 0;
    for (std::uint32_t i = 0; stride && i < header.imports_count; ++i) {
        canceled(stop);
        budget.include(sizeof(MachOChainedImport));
        const auto at = std::uint64_t(header.imports_offset) + std::uint64_t(i) * stride;
        MachOChainedImport row;
        row.header = header_id;
        row.index = i;
        row.record_file_offset = absolute(at);
        row.raw_info = number(at, stride == 16 ? 8 : 4);
        const auto ordinal_bits = stride == 16 ? 16u : 8u;
        const auto ordinal_mask = (UINT64_C(1) << ordinal_bits) - 1;
        const auto raw_ordinal = row.raw_info & ordinal_mask;
        row.library_ordinal =
            static_cast<std::int32_t>(raw_ordinal > ordinal_mask - 15 ? static_cast<std::int64_t>(raw_ordinal) -
                                                                            static_cast<std::int64_t>(ordinal_mask + 1)
                : static_cast<std::int64_t>(raw_ordinal));
        require(row.library_ordinal <= 0 || static_cast<std::uint32_t>(row.library_ordinal) <= libraries,
                "Mach-O chained import dependency ordinal exceeds library list");
        row.weak_import = bool((row.raw_info >> ordinal_bits) & 1);
        row.name_offset = static_cast<std::uint32_t>(row.raw_info >> (stride == 16 ? 32 : 9));
        if (stride > 4) {
            row.raw_addend = number(at + (stride == 16 ? 8 : 4), stride == 16 ? 8 : 4);
            row.addend = signed_field(row.raw_addend, stride == 16 ? 64 : 32);
        }
        if (row.library_ordinal < -3 || (stride == 16 && ((row.raw_info >> 17) & 0x7fff)))
            row.complete = false;
        if (header.symbols_format <= 1 && !symbols.empty()) {
            const auto name = std::uint64_t(row.name_offset);
            require(name < symbols.size(), "Mach-O chained symbol offset exceeds symbol pool");
            const auto available = std::min<std::uint64_t>(symbols.size() - name, max_chained_symbol_bytes + 1);
            std::uint64_t length = 0;
            while (length < available && symbols[static_cast<std::size_t>(name + length)] != 0) {
                canceled(stop);
                ++length;
            }
            require(length < available && length <= max_chained_symbol_bytes,
                    "Mach-O chained symbol exceeds 64 KiB or is unterminated");
            require(length <= max_chained_symbol_pool_bytes - symbol_pool_bytes,
                    "Mach-O chained symbol pool exceeds 16 MiB", ErrorCode::resource_limit);
            budget.include(length);
            symbol_pool_bytes += static_cast<std::size_t>(length);
            row.name = std::string(reinterpret_cast<const char *>(symbols.data() + name),
                                   static_cast<std::size_t>(length));
            if (header.symbols_format == 0)
                row.name_file_offset = FileOffset{absolute(header.symbols_offset + name)};
        } else
            row.complete = false;
        header.complete = header.complete && row.complete;
        metadata.chained_imports.push_back(std::move(row));
    }
    struct Task {
        std::uint64_t file, offset;
        std::uint32_t starts, page, source, node;
    };
    const auto later = [](const Task &a, const Task &b) {
        return std::tie(a.file, a.starts, a.offset) > std::tie(b.file, b.starts, b.offset);
    };
    std::priority_queue<Task, std::vector<Task>, decltype(later)> pending(later);
    const auto enqueue = [&](std::uint32_t starts_id, std::uint32_t page, std::uint32_t source, std::uint64_t offset,
                             std::uint32_t node) {
        const auto &starts = metadata.chained_starts[starts_id];
        const auto &segment = metadata.segments[starts.segment_index];
        const auto [width, step] = layout(starts.pointer_format);
        (void)step;
        const auto page_begin = std::uint64_t(page) * starts.page_size;
        require(offset >= page_begin && offset - page_begin < starts.page_size &&
                    width <= starts.page_size - (offset - page_begin),
                "Mach-O chained pointer crosses page boundary");
        require(offset <= segment.memory_size && width <= segment.memory_size - offset,
                "Mach-O chained pointer exceeds segment memory");
        const auto at = add(segment.address, offset);
        std::uint64_t file = UINT64_MAX;
        for (unsigned byte = 0; byte < width; ++byte) {
            const Address address{{0}, add(at, byte)};
            require(image.segment_at(address) != nullptr, "Mach-O chained pointer crosses unmapped memory");
            const auto source_file = image.to_file_offset(address);
            if (source_file)
                file = std::min(file, source_file.value().value);
        }
        budget.include(sizeof(Task));
        pending.push({file, offset, starts_id, page, source, node});
    };
    if (header.starts_offset) {
        require(header.starts_offset >= 28, "Mach-O chained starts overlaps fixed header");
        const auto count = number(header.starts_offset, 4);
        require(count <= metadata.segments.size(), "Mach-O chained segment count exceeds original commands");
        extent(bytes, std::uint64_t(header.starts_offset) + 4, count * 4);
        metadata_ranges.emplace_back(header.starts_offset,
                                     std::uint64_t(header.starts_offset) + 4 + count * 4);
        for (std::uint32_t segment_index = 0; segment_index < count; ++segment_index) {
            canceled(stop);
            const auto entry = std::uint64_t(header.starts_offset) + 4 + std::uint64_t(segment_index) * 4;
            const auto relative = number(entry, 4);
            if (!relative)
                continue;
            require(relative >= 4 + count * 4, "Mach-O segment starts overlaps segment-offset array");
            const auto at = add(header.starts_offset, relative);
            extent(bytes, at, 22);
            MachOChainedStarts row;
            row.header = header_id;
            row.segment_index = segment_index;
            row.source_entry_file_offset = absolute(entry);
            row.record_file_offset = absolute(at);
            row.size = static_cast<std::uint32_t>(number(at, 4));
            row.page_size = static_cast<std::uint16_t>(number(at + 4, 2));
            row.pointer_format = static_cast<std::uint16_t>(number(at + 6, 2));
            row.segment_offset = number(at + 8, 8);
            row.max_valid_pointer = static_cast<std::uint32_t>(number(at + 16, 4));
            row.page_count = static_cast<std::uint16_t>(number(at + 20, 2));
            require(row.page_count <= max_chained_pages, "Mach-O chained page count exceeds limit",
                    ErrorCode::resource_limit);
            require(row.size >= 22 && !(row.size & 1) && std::uint64_t(row.page_count) * 2 <= row.size - 22,
                    "Mach-O chained page array exceeds segment-start record");
            extent(bytes, at, row.size);
            metadata_ranges.emplace_back(at, at + row.size);
            const auto slots = (row.size - 22) / 2;
            budget.include(sizeof(row) + std::uint64_t(slots) * 2);
            for (std::uint32_t slot = 0; slot < slots; ++slot) {
                canceled(stop);
                row.page_starts.push_back(static_cast<std::uint16_t>(number(at + 22 + std::uint64_t(slot) * 2, 2)));
            }
            const auto [width, step] = layout(row.pointer_format);
            (void)step;
            if (!width || width != (slice.header.is_64 ? 8 : 4) || (row.page_size != 4096 && row.page_size != 16384) ||
                slice.header.file_type == 1)
                row.complete = false;
            if (header_anchor)
                require(row.segment_offset <= UINT64_MAX - header_anchor->offset &&
                            header_anchor->offset + row.segment_offset == metadata.segments[segment_index].address,
                        "Mach-O chained segment offset disagrees with canonical mapped header");
            else {
                row.complete = false;
            }
            const auto starts_id = static_cast<std::uint32_t>(metadata.chained_starts.size());
            metadata.chained_starts.push_back(std::move(row));
            const auto &starts = metadata.chained_starts.back();
            header.complete = header.complete && starts.complete;
            if (!width || width != (slice.header.is_64 ? 8 : 4) ||
                (starts.page_size != 4096 && starts.page_size != 16384) || slice.header.file_type == 1)
                continue;
            for (std::uint32_t page = 0; page < starts.page_count; ++page) {
                canceled(stop);
                const auto value = starts.page_starts[page];
                if (value == 0xffff)
                    continue;
                const auto start = [&](std::uint16_t value, std::uint32_t source) {
                    enqueue(starts_id, page, source, std::uint64_t(page) * starts.page_size + value, 0);
                };
                if (!(value & 0x8000))
                    start(value, page);
                else {
                    std::uint32_t overflow = value & 0x7fff;
                    require(overflow >= starts.page_count, "Mach-O multi-start index points into primary page entries");
                    for (;;) {
                        canceled(stop);
                        require(overflow < starts.page_starts.size(), "Unterminated Mach-O multi-start list");
                        const auto extra = starts.page_starts[overflow];
                        start(extra & 0x7fff, overflow++);
                        if (extra & 0x8000)
                            break;
                    }
                }
            }
        }
    }
    std::sort(metadata_ranges.begin(), metadata_ranges.end());
    for (std::size_t i = 1; i < metadata_ranges.size(); ++i)
        require(metadata_ranges[i].first >= metadata_ranges[i - 1].second,
                "Mach-O chained header, imports, symbols, or starts records overlap");
    std::map<std::pair<std::uint32_t, std::uint64_t>, std::size_t> visited;
    while (!pending.empty()) {
        canceled(stop);
        const auto task = pending.top();
        pending.pop();
        require(metadata.chained_pointers.size() < 1000000, "Mach-O chained pointer count exceeds budget",
                ErrorCode::resource_limit);
        const auto identity = std::pair{task.starts, task.offset};
        const auto after = visited.lower_bound(identity);
        require(after == visited.end() || after->first != identity, "Converging or duplicate Mach-O pointer chains");
        budget.include(sizeof(MachOChainedPointer) + 64);
        const auto &starts = metadata.chained_starts[task.starts];
        const auto &segment = metadata.segments[starts.segment_index];
        const auto [width, step] = layout(starts.pointer_format);
        MachOChainedPointer row;
        row.header = header_id;
        row.starts = task.starts;
        row.page_index = task.page;
        row.chain_start_index = task.source;
        row.node_index = task.node;
        row.segment_offset = task.offset;
        row.field_size = width;
        row.stride = step;
        row.place = Address{{0}, add(segment.address, task.offset)};
        std::optional<FileOffset> first;
        bool contiguous = true;
        for (unsigned byte = 0; byte < width; ++byte) {
            const auto file = image.to_file_offset({row.place->space, add(row.place->offset, byte)});
            if (!file) {
                contiguous = false;
                continue;
            }
            if (byte == 0)
                first = file.value();
            else if (!first || file.value().value != add(first->value, byte))
                contiguous = false;
            const auto source = reader.bytes(file.value().value - slice.offset, 1);
            row.raw |= std::to_integer<std::uint64_t>(source.bytes[0]) << (byte * 8);
        }
        if (contiguous)
            row.file_place = first;
        pointer_bits(row, starts);
        // The on-disk word may be ciphertext; never interpret its packed
        // destination as an address unless this source range is plaintext.
        const bool encrypted = image.plaintext_window(*row.place, width) != width;
        if (!encrypted && starts.pointer_format == 14 && row.target) {
            const auto target_segment_index = static_cast<std::uint32_t>((*row.target >> 28) & 0xf);
            const auto target_segment_offset = *row.target & UINT64_C(0x0fffffff);
            if (target_segment_index < metadata.segments.size()) {
                const auto &target_segment = metadata.segments[target_segment_index];
                if (target_segment_offset < target_segment.memory_size &&
                    target_segment.address <= UINT64_MAX - target_segment_offset) {
                    const Address target{row.place->space, target_segment.address + target_segment_offset};
                    if (image.segment_at(target)) row.target_address = target;
                }
            }
        }
        // The vmaddr-based formats carry enough context to identify an
        // in-image rebase without a slide or shared-cache mapping. Keep
        // offset-based/cache formats unresolved here; their bases differ.
        const auto pointer_format = starts.pointer_format;
        const bool vmaddr_target = pointer_format == 1 || pointer_format == 2 ||
            pointer_format == 3 || pointer_format == 5 || pointer_format == 10;
        if (!encrypted && row.complete && vmaddr_target && !row.bind && !row.authenticated &&
            row.target && !row.non_pointer) {
            const auto target = *row.target | (std::uint64_t(row.high8) << 56);
            const Address destination{row.place->space, target};
            if (image.segment_at(destination)) row.target_address = destination;
        }
        // Userland offset formats are relative to the preferred image base.
        // Resolve only complete, unauthenticated rebases whose preferred-base
        // target is mapped to plaintext file bytes. Authenticated pointers keep
        // their decoded target/PAC fields but need runtime signing context;
        // Shared-cache and kernel-cache formats need external base metadata.
        const bool in_image_offset_target = pointer_format == 6 || pointer_format == 7 ||
                                            pointer_format == 9 || pointer_format == 12;
        const auto &mapped_segments = image.layout().segments;
        if (!encrypted && row.complete && in_image_offset_target && !row.bind &&
            !row.authenticated && row.target && !row.non_pointer && !mapped_segments.empty() &&
            metadata.container.slices.at(metadata.selected_slice).header.file_type != 1) {
            const auto base = std::min_element(mapped_segments.begin(), mapped_segments.end(),
                [](const auto &left, const auto &right) {
                    return left.begin.offset < right.begin.offset;
                })->begin.offset;
            if (*row.target <= UINT64_MAX - base) {
                const auto target = (base + *row.target) | (std::uint64_t(row.high8) << 56);
                const Address destination{row.place->space, target};
                if (image.segment_at(destination) && image.to_file_offset(destination) &&
                    image.plaintext_window(destination, 1) == 1)
                    row.target_address = destination;
            }
        }
        // Preserve the literal bits for inspection, but ciphertext is not a
        // chain link or an import-index equation.
        if (encrypted) {
            row.complete = false;
            row.source_interpretation_valid = false;
        }
        const auto overlap = [&](auto entry) {
            auto &previous = metadata.chained_pointers[entry->second];
            previous.complete = false;
            previous.source_interpretation_valid = false;
            row.source_interpretation_valid = false;
            row.complete = false;
        };
        if (after != visited.begin()) {
            const auto before = std::prev(after);
            if (before->first.first == task.starts &&
                before->first.second + metadata.chained_pointers[before->second].field_size > task.offset)
                overlap(before);
        }
        for (auto entry = after;
             entry != visited.end() && entry->first.first == task.starts && entry->first.second < task.offset + width;
             ++entry)
            overlap(entry);
        visited.emplace_hint(after, identity, metadata.chained_pointers.size());
        if (row.import_index && !encrypted) {
            require(*row.import_index < header.imports_count, "Mach-O chain ordinal exceeds its import namespace");
            if (header.imports_available)
                row.import_row = header.first_import_row + *row.import_index;
            else
                row.complete = false;
        }
        header.complete = header.complete && row.complete;
        if (row.next && !encrypted)
            enqueue(task.starts, task.page, task.source, add(task.offset, std::uint64_t(row.next) * step),
                    task.node + 1);
        metadata.chained_pointers.push_back(std::move(row));
    }
    stream.complete = stream.complete && header.complete;
    metadata.dyld_complete = metadata.dyld_complete && stream.complete;
}
namespace {
void walk_firmware_chains(const Reader &reader, const Image &image, MachOMetadata &metadata,
                          Budget &budget, std::stop_token stop) {
    const auto &slice = metadata.container.slices.at(metadata.selected_slice);
    const auto anchor = take(macho_header_anchor(image, slice, stop));
    std::optional<Address> text_anchor;
    bool duplicate_text = false;
    for (const auto &segment : metadata.segments) if (segment.name == "__TEXT") {
        if (text_anchor) { duplicate_text = true; break; }
        text_anchor = Address{{0}, segment.address};
    }
    if (duplicate_text) text_anchor.reset();
    struct Task {
        std::uint32_t start, node;
        Address place;
        FileOffset file;
        const Segment *segment;
    };
    const auto later = [](const Task &a, const Task &b) {
        return std::tie(a.file.value, a.start, a.node) > std::tie(b.file.value, b.start, b.node);
    };
    std::priority_queue<Task, std::vector<Task>, decltype(later)> pending(later);
    std::map<std::uint64_t, std::size_t> visited;
    budget.include(metadata.chain_start_offsets.size());
    std::vector<bool> failed(metadata.chain_start_offsets.size(), false);
    const auto fail = [&](std::uint32_t start) {
        failed[start] = true;
        metadata.chain_start_offsets[start].chain_complete = false;
        metadata.dyld_complete = false;
    };
    const auto enqueue = [&](std::uint32_t start, std::uint32_t node, Address place, const Segment *segment) {
        const auto width = layout(static_cast<std::uint16_t>(metadata.chain_start_offsets[start].pointer_format)).first;
        if (!segment || place.space != segment->begin.space || place.offset < segment->begin.offset ||
            place.offset - segment->begin.offset > segment->size ||
            width > segment->size - (place.offset - segment->begin.offset)) { fail(start); return; }
        const auto file = image.to_file_offset(place);
        if (!file || file.value().value < slice.offset || file.value().value - slice.offset > slice.size ||
            width > slice.size - (file.value().value - slice.offset)) { fail(start); return; }
        for (unsigned byte = 0; byte < width; ++byte) {
            const Address at{place.space, add(place.offset, byte)};
            const auto mapped = image.to_file_offset(at);
            if (image.segment_at(at) != segment || !mapped || mapped.value().value != add(file.value().value, byte)) {
                fail(start); return;
            }
        }
        budget.include(sizeof(Task));
        pending.push({start, node, place, file.value(), segment});
    };
    for (std::uint32_t start = 0; start < metadata.chain_start_offsets.size(); ++start) {
        canceled(stop);
        const auto &row = metadata.chain_start_offsets[start];
        if (row.complete && row.pointer_address)
            enqueue(start, 0, *row.pointer_address, image.segment_at(*row.pointer_address));
    }
    while (!pending.empty()) {
        canceled(stop);
        const auto task = pending.top(); pending.pop();
        if (failed[task.start]) continue;
        auto &start = metadata.chain_start_offsets[task.start];
        const auto [width, stride] = layout(static_cast<std::uint16_t>(start.pointer_format));
        const auto after = visited.lower_bound(task.place.offset);
        const auto invalidate = [&](auto entry) {
            auto &previous = metadata.firmware_chained_pointers[entry->second];
            previous.complete = false; previous.target_address.reset();
            fail(previous.chain_start_row); fail(task.start);
        };
        if (after != visited.begin()) {
            const auto previous = std::prev(after);
            const auto &row = metadata.firmware_chained_pointers[previous->second];
            if (task.place.offset - previous->first < row.field_size) invalidate(previous);
        }
        for (auto entry = after; entry != visited.end() && entry->first - task.place.offset < width; ++entry)
            invalidate(entry);
        if (failed[task.start]) continue;
        require(metadata.chained_pointers.size() < 1'000'000 &&
                    metadata.firmware_chained_pointers.size() < 1'000'000 - metadata.chained_pointers.size(),
                "Mach-O chained pointer count exceeds budget", ErrorCode::resource_limit);
        budget.include(sizeof(MachOFirmwareChainedPointer) + 64);
        const auto bytes = reader.bytes(task.file.value - slice.offset, width);
        MachOFirmwareChainedPointer row;
        row.chain_start_row = task.start; row.node_index = task.node;
        row.place = task.place; row.file_place = task.file; row.field_size = width; row.stride = stride;
        row.raw = reader.value(bytes.bytes, 0, width);
        if (image.plaintext_window(task.place, width) != width) row.complete = false;
        else {
            MachOChainedPointer decoded; decoded.raw = row.raw;
            MachOChainedStarts starts; starts.pointer_format = static_cast<std::uint16_t>(start.pointer_format);
            pointer_bits(decoded, starts);
            row.next = decoded.next; row.target = decoded.target; row.high8 = decoded.high8;
            row.bind = decoded.bind; row.authenticated = decoded.authenticated;
            row.diversity = decoded.diversity; row.address_diversity = decoded.address_diversity; row.key = decoded.key;
            row.target_is_offset = decoded.target_is_offset || start.coordinate_flags == 2;
            row.import_index = decoded.import_index; row.addend = decoded.addend;
            row.complete = decoded.complete;
            if (row.complete && !row.bind && !row.authenticated && row.target) {
                auto target = *row.target | (std::uint64_t(row.high8) << 56);
                const auto base = start.coordinate_flags == 2 ? text_anchor : anchor;
                const bool overflow = row.target_is_offset && (!base || target > UINT64_MAX - base->offset);
                if (!overflow) {
                    if (row.target_is_offset) target += base->offset;
                    const Address address{task.place.space, target};
                    if (image.segment_at(address)) row.target_address = address;
                }
            }
        }
        if (!start.pointer_count) start.first_pointer_row = static_cast<std::uint32_t>(metadata.firmware_chained_pointers.size());
        ++start.pointer_count;
        visited.emplace_hint(after, task.place.offset, metadata.firmware_chained_pointers.size());
        const auto next = row.next;
        const auto complete = row.complete;
        metadata.firmware_chained_pointers.push_back(std::move(row));
        if (!complete) fail(task.start);
        else if (!next) start.chain_complete = true;
        else if (std::uint64_t(next) * stride > UINT64_MAX - task.place.offset) fail(task.start);
        else enqueue(task.start, task.node + 1, {task.place.space, task.place.offset + std::uint64_t(next) * stride}, task.segment);
    }
}
} // namespace
void read_chain_starts_section(const Reader &reader, const Image &image, MachOMetadata &metadata,
                               Budget &budget, std::stop_token stop) {
    const auto &slice = metadata.container.slices.at(metadata.selected_slice);
    for (const auto &section : metadata.sections) {
        if (section.name != "__chain_starts" || section.segment_name != "__TEXT") continue;
        canceled(stop);
        if (!section.file_offset || section.size < 8) {
            metadata.dyld_complete = false;
            continue;
        }
        const auto fixed = reader.bytes(section.raw_file_offset, 8);
        const auto pointer_format = static_cast<std::uint32_t>(reader.value(fixed.bytes, 0, 4));
        const auto count = reader.value(fixed.bytes, 4, 4);
        const std::uint64_t width = pointer_format == 5 ? 4 : pointer_format == 7 ? 8 : 0;
        const bool supported = width != 0 && width == (slice.header.is_64 ? 8u : 4u) &&
                               slice.header.order == ByteOrder::little && slice.header.file_type != 1;
        const bool coordinate_known = section.reserved1 == 1 || section.reserved1 == 2;
        const bool bounded = count <= 1'000'000 && count <= (section.size - 8) / 4;
        const auto entries = std::min<std::uint64_t>({count, (section.size - 8) / 4, 1'000'000});
        if (!bounded) metadata.dyld_complete = false;
        if (!supported || !coordinate_known) metadata.dyld_complete = false;
        for (std::uint32_t index = 0; index < entries; ++index) {
            canceled(stop);
            budget.include(sizeof(MachOChainStartOffset));
            const auto rel = std::uint64_t(section.raw_file_offset) + 8 + std::uint64_t(index) * 4;
            const auto bytes = reader.bytes(rel, 4);
            MachOChainStartOffset row;
            row.section_ordinal = section.ordinal;
            row.index = index;
            row.pointer_format = pointer_format;
            row.coordinate_flags = section.reserved1;
            row.raw_offset = reader.value(bytes.bytes, 0, 4);
            row.record_file_offset = reader.file(rel, 4).value;
            row.complete = bounded && supported && coordinate_known;
            if (row.complete && row.coordinate_flags == 1) {
                // Apple defines these values as file offsets within the image.
                if (row.raw_offset <= slice.size && width <= slice.size - row.raw_offset) {
                    const auto file = reader.file(row.raw_offset, width);
                    const auto address = image.to_address(file);
                    if (address) {
                        bool contiguous = true;
                        for (std::uint64_t byte = 0; byte < width; ++byte) {
                            const auto mapped = image.to_file_offset({address.value().space, add(address.value().offset, byte)});
                            if (!mapped || mapped.value().value != file.value + byte) { contiguous = false; break; }
                        }
                        if (contiguous) {
                            row.pointer_address = address.value();
                            row.pointer_file_offset = file;
                        } else row.complete = false;
                    } else row.complete = false;
                } else row.complete = false;
            } else if (row.complete && row.coordinate_flags == 2) {
                const MachOSegment *text = nullptr;
                for (const auto &segment : metadata.segments) if (segment.name == "__TEXT") {
                    if (text) { text = nullptr; break; }
                    text = &segment;
                }
                // VM offsets are relative to __TEXT's base, but may name
                // pointers in other mapped segments such as __DATA.
                if (text && row.raw_offset <= UINT64_MAX - text->address) {
                    const Address address{{0}, add(text->address, row.raw_offset)};
                    bool contiguous = true;
                    std::optional<FileOffset> first;
                    for (std::uint64_t byte = 0; byte < width; ++byte) {
                        const auto mapped = image.to_file_offset({address.space, add(address.offset, byte)});
                        if (!mapped) { contiguous = false; break; }
                        if (byte == 0) first = mapped.value();
                        else if (!first || mapped.value().value != add(first->value, byte)) { contiguous = false; break; }
                    }
                    if (contiguous) {
                        row.pointer_address = address;
                        row.pointer_file_offset = first;
                    } else row.complete = false;
                } else row.complete = false;
            }
            if (!row.complete) metadata.dyld_complete = false;
            metadata.chain_start_offsets.push_back(std::move(row));
        }
    }
    walk_firmware_chains(reader, image, metadata, budget, stop);
}
} // namespace hexlab::macho_detail

namespace hexlab {
Result<std::vector<MachOChainedExternalTarget>> resolve_macho_chained_external_targets(
    const MachOMetadata &metadata, const MachOChainedTargetBases &bases, std::stop_token stop,
    MachOChainedTargetResolutionLimits limits) {
    if (metadata.chained_pointers.size() > limits.max_pointer_rows || limits.max_pointer_rows > 1'000'000)
        return Error{ErrorCode::resource_limit, "Mach-O chained target resolution exceeds its pointer-row limit"};
    try {
        std::vector<MachOChainedExternalTarget> output;
        for (std::size_t index = 0; index < metadata.chained_pointers.size(); ++index) {
            if (stop.stop_requested())
                return Error{ErrorCode::canceled, "Mach-O chained target resolution canceled"};
            const auto &row = metadata.chained_pointers[index];
            if (row.bind || !row.target_base_kind) continue;
            MachOChainedExternalTarget resolved;
            resolved.pointer_index = index;
            resolved.authentication_required = row.authenticated;
            resolved.base_kind = *row.target_base_kind;
            resolved.cache_level = row.cache_level;
            if (!row.source_interpretation_valid || !row.place || !row.target || row.non_pointer || !row.field_size) {
                resolved.status = MachOChainedExternalTargetStatus::invalid_encoding;
                output.push_back(std::move(resolved));
                continue;
            }
            const auto pointer_format = row.starts < metadata.chained_starts.size()
                ? metadata.chained_starts[row.starts].pointer_format : 0;
            std::optional<std::uint64_t> base;
            if (*row.target_base_kind == MachOChainedTargetBaseKind::cache_level) {
                if ((pointer_format != 8 && pointer_format != 11) || !row.cache_level || *row.cache_level >= 4) {
                    resolved.status = MachOChainedExternalTargetStatus::invalid_encoding;
                    output.push_back(std::move(resolved));
                    continue;
                }
                const bool reserved = !row.authenticated && ((row.raw >> 32) & 0x7ffff) != 0;
                if (reserved) {
                    resolved.status = MachOChainedExternalTargetStatus::invalid_encoding;
                    output.push_back(std::move(resolved));
                    continue;
                }
                base = bases.cache_level_bases[*row.cache_level];
            } else {
                if (pointer_format != 4 && pointer_format != 13) {
                    resolved.status = MachOChainedExternalTargetStatus::invalid_encoding;
                    output.push_back(std::move(resolved));
                    continue;
                }
                const bool reserved = pointer_format == 13 && !row.authenticated &&
                    ((row.raw >> 42) & 0x3ff) != 0;
                if (reserved) {
                    resolved.status = MachOChainedExternalTargetStatus::invalid_encoding;
                    output.push_back(std::move(resolved));
                    continue;
                }
                base = bases.shared_cache_base;
            }
            if (!base) {
                resolved.status = MachOChainedExternalTargetStatus::missing_base;
                output.push_back(std::move(resolved));
                continue;
            }
            resolved.base_address = *base;
            if (*row.target > UINT64_MAX - *base) {
                resolved.status = MachOChainedExternalTargetStatus::overflow;
                output.push_back(std::move(resolved));
                continue;
            }
            auto target = *base + *row.target;
            if (pointer_format == 13 && !row.authenticated) {
                if (target > UINT64_C(0x00ffffffffffffff)) {
                    resolved.status = MachOChainedExternalTargetStatus::overflow;
                    output.push_back(std::move(resolved));
                    continue;
                }
                target |= std::uint64_t(row.high8) << 56;
            }
            resolved.status = MachOChainedExternalTargetStatus::resolved;
            resolved.target_address = target;
            output.push_back(std::move(resolved));
        }
        return output;
    } catch (const std::bad_alloc &) {
        return Error{ErrorCode::resource_limit, "Cannot allocate Mach-O chained target resolution rows"};
    }
}
} // namespace hexlab
