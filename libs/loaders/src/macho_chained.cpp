#include "macho_dyld_internal.hpp"
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
    case 7: // DYLD_CHAINED_PTR_ARM64E_KERNEL: 8-byte word, 4-byte chain stride
    case 10: // DYLD_CHAINED_PTR_ARM64E_FIRMWARE: 8-byte word, 4-byte stride
    case 9:
    case 12:
    case 13: // DYLD_CHAINED_PTR_ARM64E_SHARED_CACHE
        return {std::uint8_t{8}, std::uint8_t{8}};
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
        row.complete = false;
    } else if (format == 5) {
        // Unlike the cache-relative format 4, format 5 stores a VM address.
        // Retain it as a direct target; the chain is fully decoded even when
        // a later resolver cannot map that target in this image.
        row.next = static_cast<std::uint16_t>((raw >> 26) & 0x3f);
        row.target = raw & UINT64_C(0x03ffffff);
    } else if (format == 14) {
        // Preserve the packed 4-bit segment index and 28-bit segment offset
        // as an unassembled target payload. Resolution needs the segmented
        // format's address table, which this image model does not carry.
        row.target = raw & UINT32_MAX;
        row.next = static_cast<std::uint16_t>((raw >> 51) & 0xfff);
        row.authenticated = bool(raw >> 63);
        if (row.authenticated) {
            row.diversity = static_cast<std::uint16_t>((raw >> 32) & 0xffff);
            row.address_diversity = bool((raw >> 48) & 1);
            row.key = static_cast<std::uint8_t>((raw >> 49) & 3);
        }
        row.complete = false;
    } else if (format == 8 || format == 11) {
        // Kernel-cache targets are relative to one of several cache images.
        // Retain their encoded target/authentication fields, but keep the row
        // incomplete until a dyld shared-cache base table is available.
        row.authenticated = bool(raw >> 63);
        row.next = static_cast<std::uint16_t>((raw >> 51) & 0xfff);
        row.target = raw & 0x3fffffff;
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
        // Preserve the literal bits for inspection, but ciphertext is not a
        // chain link or an import-index equation.
        const bool encrypted = image.plaintext_window(*row.place, width) != width;
        if (encrypted) row.complete = false;
        const auto overlap = [&](auto entry) {
            auto &previous = metadata.chained_pointers[entry->second];
            previous.complete = false;
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
} // namespace hexlab::macho_detail
