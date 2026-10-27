#include "macho_internal.hpp"
#include "hexlab/image/macho_mapping.hpp"
#include <algorithm>
#include <limits>
#include <map>
#include <set>
#include <utility>
namespace hexlab::macho_detail {
namespace {
bool executable(const Image &image, Address at) {
    const auto *mapped = image.segment_at(at);
    return mapped && mapped->executable && at.offset - mapped->begin.offset < mapped->file_size;
}
bool readable_file_byte(const Image &image, Address at) {
    const auto *mapped = image.segment_at(at);
    return mapped && mapped->readable && at.offset >= mapped->begin.offset &&
           at.offset - mapped->begin.offset < mapped->file_size;
}
std::string command_string(const Reader &reader, const MachOLoadCommand &command, std::uint64_t slice,
                           std::uint32_t offset, std::uint32_t minimum, Budget &budget) {
    require(offset >= minimum && offset < command.size, "Mach-O command string offset is outside string payload");
    const auto count = std::min<std::uint32_t>(command.size - offset, 65537);
    const auto bytes = reader.bytes(command.file_offset - slice + offset, count);
    const auto end = std::find(bytes.bytes.begin(), bytes.bytes.end(), std::byte{0});
    require(end != bytes.bytes.end(), "Unterminated or oversized Mach-O command string");
    const auto size = static_cast<std::size_t>(end - bytes.bytes.begin());
    budget.include(count + size);
    return {reinterpret_cast<const char *>(bytes.bytes.data()), size};
}
bool dylib(std::uint32_t command) {
    return command == 0xc || command == 0xd || command == 0x80000018 || command == 0x8000001f || command == 0x20 ||
           command == 0x80000023;
}
void dynamic_symbols(const Reader &reader, const MachOLoadCommand &command, const MachOSlice &slice,
                     MachOMetadata &metadata, Budget &budget, std::stop_token stop) {
    require(command.size >= 80, "Truncated Mach-O dynamic symbol command");
    const auto bytes = reader.bytes(command.file_offset - slice.offset, 80);
    const auto field = [&](std::size_t offset) {
        return static_cast<std::uint32_t>(reader.value(bytes.bytes, offset, 4));
    };
    MachODynamicSymbolTable table;
    table.command_index = command.index;
    table.record_file_offset = command.file_offset;
    const MachOSymbolTable *symbols = metadata.symbol_tables.size() == 1 ? &metadata.symbol_tables[0] : nullptr;
    if (symbols)
        table.symbol_table = symbols->command_index;
    else
        metadata.commands_complete = false;
    std::vector<std::pair<std::uint64_t, std::uint64_t>> ranges;
    for (std::size_t i = 0; i < 3; ++i) {
        table.ranges[i] = {field(8 + i * 8), field(12 + i * 8)};
        const auto &range = table.ranges[i];
        if (symbols)
            require(range.begin <= symbols->count && range.count <= symbols->count - range.begin,
                    "Mach-O dynamic symbol range exceeds nlist table");
        if (range.count)
            ranges.emplace_back(range.begin, std::uint64_t(range.begin) + range.count);
    }
    std::sort(ranges.begin(), ranges.end());
    for (std::size_t i = 1; i < ranges.size(); ++i)
        require(ranges[i - 1].second <= ranges[i].first, "Overlapping Mach-O dynamic symbol groups");
    const std::array<std::uint32_t, 6> strides{8, slice.header.is_64 ? 56u : 52u, 4, 4, 8, 8};
    budget.include(sizeof(MachODynamicSymbolTable));
    for (std::size_t i = 0; i < table.tables.size(); ++i) {
        canceled(stop);
        auto &value = table.tables[i];
        value.raw_offset = field(32 + 8 * i);
        value.count = field(36 + 8 * i);
        value.stride = strides[i];
        require(value.count <= 1000000, "Mach-O dynamic table count exceeds budget", ErrorCode::resource_limit);
        const auto extent = std::uint64_t(value.count) * value.stride;
        value.offset = reader.file(value.raw_offset, extent);
        budget.include(extent);
        if (i != 3) {
            if (value.count)
                metadata.commands_complete = false; // Raw bounded declarations; payload semantics handled separately.
            continue;
        }
        budget.include(std::uint64_t(value.count) * sizeof(std::uint32_t));
        for (std::uint32_t row = 0; row < value.count; ++row) {
            const auto record = reader.bytes(std::uint64_t(value.raw_offset) + row * UINT64_C(4), 4);
            const auto index = static_cast<std::uint32_t>(reader.value(record.bytes, 0, 4));
            if (!(index & 0xc0000000) && symbols)
                require(index < symbols->count, "Mach-O indirect symbol index exceeds nlist table");
            if ((index & 0xc0000000) && (index & 0x3fffffff))
                metadata.commands_complete = false;
            table.indirect_symbols.push_back(index);
        }
    }
    metadata.dynamic_symbol_tables.push_back(std::move(table));
}
std::uint64_t uleb(std::span<const std::byte> bytes, std::size_t &cursor) {
    std::uint64_t result = 0;
    for (unsigned index = 0; index < 10; ++index) {
        require(cursor < bytes.size(), "Truncated Mach-O function-start ULEB");
        const auto value = std::to_integer<unsigned>(bytes[cursor++]);
        require(index != 9 || (value & 0x7f) <= 1, "Mach-O function-start ULEB overflows64 bits");
        result |= std::uint64_t(value & 0x7f) << (7 * index);
        if (!(value & 0x80))
            return result;
    }
    throw Failure{{ErrorCode::malformed, "Mach-O function-start ULEB exceeds10 bytes"}};
}
void function_starts(const Reader &reader, const MachOLoadCommand &command, const MachOSlice &slice, const Image &image,
                     MachOMetadata &metadata, std::optional<std::uint64_t> text_base, Budget &budget,
                     std::stop_token stop) {
    require(command.size >= 16, "Truncated Mach-O function-start command");
    const auto fixed = reader.bytes(command.file_offset - slice.offset, 16);
    const auto offset = reader.value(fixed.bytes, 8, 4), size = reader.value(fixed.bytes, 12, 4);
    budget.include(size);
    const auto bytes = reader.bytes(offset, static_cast<std::size_t>(size));
    std::uint64_t address = text_base.value_or(0);
    bool terminated = size == 0;
    std::size_t cursor = 0;
    while (cursor < bytes.bytes.size()) {
        canceled(stop);
        const auto record = cursor, delta = uleb(bytes.bytes, cursor);
        if (!delta) {
            terminated = true;
            break;
        }
        require(metadata.function_starts.size() < 1000000, "Mach-O function-start count exceeds budget",
                ErrorCode::resource_limit);
        budget.include(sizeof(MachOFunctionStart));
        MachOFunctionStart row{command.index, reader.file(offset + record, cursor - record).value, delta, {}};
        address = add(address, delta);
        if (text_base && executable(image, {{0}, address}))
            row.address = Address{{0}, address};
        else
            metadata.commands_complete = false;
        metadata.function_starts.push_back(std::move(row));
    }
    require(terminated, "Mach-O function-start stream has no terminator");
}
void build_version(const Reader &reader, const MachOLoadCommand &command, MachOMetadata &metadata,
                   Budget &budget, std::stop_token stop) {
    const bool modern = command.command == 0x32;
    const auto fixed_size = modern ? 24u : 16u;
    require(command.size >= fixed_size, "Truncated Mach-O build-version command");
    if (!modern && command.size != fixed_size)
        metadata.commands_complete = false;
    const auto fixed = reader.bytes(command.file_offset - metadata.container.slices[metadata.selected_slice].offset,
                                    fixed_size);
    const auto field = [&](std::size_t at) { return static_cast<std::uint32_t>(reader.value(fixed.bytes, at, 4)); };
    MachOBuildVersion row;
    row.command_index = command.index;
    row.command = command.command;
    row.record_file_offset = command.file_offset;
    if (modern) {
        row.platform = field(8);
        row.minimum_os = field(12);
        row.sdk = field(16);
        const auto count = field(20);
        require(count <= 4096, "Mach-O build-version tool count exceeds budget", ErrorCode::resource_limit);
        const auto tools_size = std::uint64_t(count) * 8;
        require(tools_size <= command.size - fixed_size, "Mach-O build-version tools cross command boundary");
        if (tools_size != command.size - fixed_size)
            metadata.commands_complete = false;
        budget.include(sizeof(MachOBuildVersion) + tools_size + std::uint64_t(count) * sizeof(MachOBuildToolVersion));
        row.tools.reserve(count);
        for (std::uint32_t index = 0; index < count; ++index) {
            canceled(stop);
            const auto tool = reader.bytes(command.file_offset - metadata.container.slices[metadata.selected_slice].offset +
                                               fixed_size + std::uint64_t(index) * 8,
                                           8);
            row.tools.push_back({static_cast<std::uint32_t>(reader.value(tool.bytes, 0, 4)),
                                 static_cast<std::uint32_t>(reader.value(tool.bytes, 4, 4))});
        }
    } else {
        switch (command.command) {
        case 0x24: row.platform = 1; break; // LC_VERSION_MIN_MACOSX
        case 0x25: row.platform = 2; break; // LC_VERSION_MIN_IPHONEOS
        case 0x2f: row.platform = 3; break; // LC_VERSION_MIN_TVOS
        case 0x30: row.platform = 4; break; // LC_VERSION_MIN_WATCHOS
        default: return;
        }
        row.minimum_os = field(8);
        row.sdk = field(12);
        budget.include(sizeof(MachOBuildVersion));
    }
    metadata.build_versions.push_back(std::move(row));
}
void fileset_entry(const Reader &reader, const MachOLoadCommand &command, const MachOSlice &slice,
                   MachOMetadata &metadata, Budget &budget, std::stop_token stop) {
    require(slice.header.is_64 && slice.header.file_type == 0xc,
            "LC_FILESET_ENTRY requires a 64-bit MH_FILESET parent");
    require(command.size >= 32, "Truncated Mach-O fileset entry command");
    const auto fixed = reader.bytes(command.file_offset - slice.offset, 32);
    const auto u32 = [&](std::size_t at) { return static_cast<std::uint32_t>(reader.value(fixed.bytes, at, 4)); };
    MachOFileSetEntry row;
    row.command_index = command.index;
    row.record_file_offset = command.file_offset;
    row.vm_address = reader.value(fixed.bytes, 8, 8);
    row.raw_file_offset = reader.value(fixed.bytes, 16, 8);
    row.entry_id_offset = u32(24);
    row.reserved = u32(28);
    require(row.reserved == 0, "Mach-O fileset entry reserved field is nonzero");
    row.entry_id = command_string(reader, command, slice.offset, row.entry_id_offset, 32, budget);
    require(!row.entry_id.empty(), "Mach-O fileset entry has an empty identifier");

    // fileset file offsets are relative to the containing Mach-O slice. Validate
    // each embedded image's fixed header and command envelope without mapping
    // its segments or recursively importing its metadata into the parent.
    require(row.raw_file_offset >= std::uint64_t{32} + slice.header.command_bytes &&
                row.raw_file_offset <= slice.size && 32 <= slice.size - row.raw_file_offset,
            "Mach-O fileset child header overlaps the parent commands or exceeds the slice");
    const auto child_header = reader.bytes(row.raw_file_offset, 32);
    require(reader.value(child_header.bytes, 0, 4) == 0xfeedfacf,
            "Mach-O fileset child is not a 64-bit image with the parent byte order");
    row.child_is_64 = true;
    row.child_cpu_type = static_cast<std::uint32_t>(reader.value(child_header.bytes, 4, 4));
    row.child_cpu_subtype = static_cast<std::uint32_t>(reader.value(child_header.bytes, 8, 4));
    row.child_file_type = static_cast<std::uint32_t>(reader.value(child_header.bytes, 12, 4));
    row.child_command_count = static_cast<std::uint32_t>(reader.value(child_header.bytes, 16, 4));
    row.child_command_bytes = static_cast<std::uint32_t>(reader.value(child_header.bytes, 20, 4));
    require(row.child_command_count <= 65536 &&
                row.child_command_bytes <= slice.size - row.raw_file_offset - 32 &&
                row.child_command_count <= row.child_command_bytes / 8,
            "Mach-O fileset child command extent exceeds the containing slice", ErrorCode::resource_limit);
    budget.include(row.child_command_bytes);
    std::uint64_t cursor = 0;
    for (std::uint32_t index = 0; index < row.child_command_count; ++index) {
        canceled(stop);
        require(cursor <= row.child_command_bytes && 8 <= row.child_command_bytes - cursor,
                "Truncated Mach-O fileset child load-command envelope");
        const auto envelope = reader.bytes(row.raw_file_offset + 32 + cursor, 8);
        const auto size = static_cast<std::uint32_t>(reader.value(envelope.bytes, 4, 4));
        require(size >= 8 && size % 8 == 0 && size <= row.child_command_bytes - cursor,
                "Invalid Mach-O fileset child load-command size or alignment");
        cursor += size;
    }
    require(cursor == row.child_command_bytes,
            "Mach-O fileset child command count does not consume sizeofcmds");
    row.child_commands_valid = row.child_cpu_type == slice.header.cpu_type &&
                               row.child_cpu_subtype == slice.header.cpu_subtype;
    if (!row.child_commands_valid)
        metadata.commands_complete = false;
    for (const auto &previous : metadata.fileset_entries)
        if (previous.entry_id == row.entry_id || previous.raw_file_offset == row.raw_file_offset ||
            previous.vm_address == row.vm_address) {
            metadata.commands_complete = false;
            break;
        }
    budget.include(sizeof(MachOFileSetEntry));
    metadata.fileset_entries.push_back(std::move(row));
}
void thread(const Reader &reader, const MachOLoadCommand &command, const MachOSlice &slice, const Image &image,
            MachOMetadata &metadata, Budget &budget, std::stop_token stop) {
    std::uint64_t cursor = 8;
    while (cursor < command.size) {
        canceled(stop);
        require(8 <= command.size - cursor, "Truncated Mach-O thread-state flavor/count");
        const auto record = command.file_offset - slice.offset + cursor;
        const auto fixed = reader.bytes(record, 8);
        MachOEntry entry;
        entry.command_index = command.index;
        entry.command = command.command;
        entry.record_file_offset = reader.file(record, 8).value;
        entry.flavor = static_cast<std::uint32_t>(reader.value(fixed.bytes, 0, 4));
        entry.count = static_cast<std::uint32_t>(reader.value(fixed.bytes, 4, 4));
        const auto size = std::uint64_t(entry.count) * 4;
        require(size <= command.size - cursor - 8, "Mach-O thread state crosses command boundary");
        const bool x32 = slice.header.cpu_type == 7 && !slice.header.is_64 && entry.flavor == 1;
        const bool x64 = slice.header.cpu_type == 0x01000007 && slice.header.is_64 && entry.flavor == 4;
        if (x32 || x64) {
            require(entry.count == (x64 ? 42u : 16u), "Mach-O x86 thread-state count differs from known layout");
            const auto pc = reader.bytes(record + 8 + (x64 ? 128 : 40), x64 ? 8 : 4);
            entry.value = reader.value(pc.bytes, 0, x64 ? 8 : 4);
            if (executable(image, {{0}, *entry.value}))
                entry.address = Address{{0}, *entry.value};
        }
        if (!entry.address)
            metadata.commands_complete = false;
        budget.include(sizeof(MachOEntry));
        metadata.entries.push_back(std::move(entry));
        cursor += 8 + size;
    }
}

void compact_unwind(const Reader &reader, const MachOSlice &slice, const Image &image,
                    MachOMetadata &metadata, std::optional<std::uint64_t> text_base,
                    Budget &budget, std::stop_token stop) {
    const auto arch = slice.header.cpu_type;
    std::vector<MachOCompactUnwindFunction> functions;
    std::vector<MachOFunctionStart> roots;
    for (const auto &section : metadata.sections) {
        canceled(stop);
        if (section.name != "__unwind_info" || section.segment_name != "__TEXT")
            continue;
        if (!slice.header.is_64 || slice.header.order != ByteOrder::little || !text_base ||
            (arch != 0x01000007u && arch != 0x0100000cu)) {
            metadata.commands_complete = false;
            return;
        }
        require(section.file_offset && section.size >= 28, "Mach-O __unwind_info section has no complete initialized header");
        const auto base = section.file_offset->value - slice.offset;
        const auto header = reader.bytes(base, 28);
        const auto field = [&](std::size_t at) { return static_cast<std::uint32_t>(reader.value(header.bytes, at, 4)); };
        const auto version = field(0), common_offset = field(4), common_count = field(8);
        const auto personality_offset = field(12), personality_count = field(16);
        const auto index_offset = field(20), index_count = field(24);
        require(version == 1, "Unsupported Mach-O compact-unwind version");
        require(index_count >= 2 && index_count <= 1000000, "Invalid Mach-O compact-unwind index count",
                index_count > 1000000 ? ErrorCode::resource_limit : ErrorCode::malformed);
        const auto in_section = [&](std::uint64_t offset, std::uint64_t size) {
            require(offset <= section.size && size <= section.size - offset,
                    "Mach-O compact-unwind table crosses __unwind_info section");
        };
        in_section(common_offset, std::uint64_t(common_count) * 4);
        in_section(personality_offset, std::uint64_t(personality_count) * 4);
        in_section(index_offset, std::uint64_t(index_count) * 12);
        const auto index_end = std::uint64_t(index_offset) + std::uint64_t(index_count) * 12;
        budget.include(sizeof(MachOCompactUnwindFunction) * std::uint64_t(index_count));
        const auto index = reader.bytes(base + index_offset, static_cast<std::size_t>(index_count) * 12);
        struct IndexRow { std::uint32_t function, page, lsda; std::uint64_t file; };
        std::vector<IndexRow> rows;
        rows.reserve(index_count);
        for (std::uint32_t i = 0; i < index_count; ++i) {
            canceled(stop);
            const auto at = std::size_t(i) * 12;
            const auto row = IndexRow{static_cast<std::uint32_t>(reader.value(index.bytes, at, 4)),
                                      static_cast<std::uint32_t>(reader.value(index.bytes, at + 4, 4)),
                                      static_cast<std::uint32_t>(reader.value(index.bytes, at + 8, 4)),
                                      reader.file(base + index_offset + at, 12).value};
            if (!rows.empty())
                require(row.function > rows.back().function, "Mach-O compact-unwind index is not strictly ordered");
            if (i + 1 < index_count) {
                require(row.page >= index_end && row.page < section.size,
                        "Mach-O compact-unwind second-level page overlaps its index or exceeds the section");
                if (!rows.empty())
                    require(row.page > rows.back().page, "Mach-O compact-unwind second-level pages are not ordered");
            }
            rows.push_back(row);
        }
        for (std::uint32_t page = 0; page + 1 < index_count; ++page) {
            canceled(stop);
            const auto &directory = rows[page];
            const auto kind = [&] {
                in_section(directory.page, 4);
                const auto scalar = reader.bytes(base + directory.page, 4);
                return static_cast<std::uint32_t>(reader.value(scalar.bytes, 0, 4));
            }();
            const auto header_size = kind == 2 ? 8u : kind == 3 ? 12u : 0u;
            require(header_size != 0, "Unsupported Mach-O compact-unwind second-level page kind");
            in_section(directory.page, header_size);
            const auto page_header = reader.bytes(base + directory.page, header_size);
            const auto entry_offset = static_cast<std::uint32_t>(reader.value(page_header.bytes, 4, 2));
            const auto entry_count = static_cast<std::uint32_t>(reader.value(page_header.bytes, 6, 2));
            const std::uint32_t stride = kind == 3 ? 4u : 8u;
            require(entry_offset >= header_size && entry_count > 0, "Invalid Mach-O compact-unwind page entry range");
            std::uint64_t page_end = std::uint64_t(directory.page) + entry_offset + std::uint64_t(entry_count) * stride;
            std::uint32_t local_encodings_offset = 0, local_encodings_count = 0;
            if (kind == 3) {
                local_encodings_offset = static_cast<std::uint32_t>(reader.value(page_header.bytes, 8, 2));
                local_encodings_count = static_cast<std::uint32_t>(reader.value(page_header.bytes, 10, 2));
                require(!local_encodings_count || local_encodings_offset >= entry_offset + entry_count * stride,
                        "Mach-O compact-unwind local encodings overlap page entries");
                page_end = std::max(page_end, std::uint64_t(directory.page) + local_encodings_offset +
                                               std::uint64_t(local_encodings_count) * 4);
            }
            in_section(directory.page, page_end - directory.page);
            const auto next_page = page + 2 < index_count ? rows[page + 1].page : section.size;
            require(page_end <= next_page, "Mach-O compact-unwind second-level pages overlap");
            const auto entries = reader.bytes(base + directory.page + entry_offset,
                                               static_cast<std::size_t>(entry_count) * stride);
            std::uint32_t previous = 0;
            for (std::uint32_t item = 0; item < entry_count; ++item) {
                canceled(stop);
                std::uint32_t function_offset = 0, encoding = 0;
                if (kind == 3) {
                    const auto packed = static_cast<std::uint32_t>(reader.value(entries.bytes, item * 4, 4));
                    const auto relative = packed & 0x00ffffffu;
                    require(relative <= UINT32_MAX - directory.function,
                            "Mach-O compressed compact-unwind function offset overflows", ErrorCode::overflow);
                    function_offset = directory.function + relative;
                    const auto encoding_index = packed >> 24;
                    if (encoding_index < common_count) {
                        const auto common = reader.bytes(base + common_offset + std::uint64_t(encoding_index) * 4, 4);
                        encoding = static_cast<std::uint32_t>(reader.value(common.bytes, 0, 4));
                    } else {
                        const auto local_index = encoding_index - common_count;
                        require(local_index < local_encodings_count,
                                "Mach-O compressed compact-unwind encoding index is invalid");
                        const auto local = reader.bytes(base + directory.page + local_encodings_offset +
                                                            std::uint64_t(local_index) * 4, 4);
                        encoding = static_cast<std::uint32_t>(reader.value(local.bytes, 0, 4));
                    }
                } else {
                    function_offset = static_cast<std::uint32_t>(reader.value(entries.bytes, item * 8, 4));
                    encoding = static_cast<std::uint32_t>(reader.value(entries.bytes, item * 8 + 4, 4));
                }
                if (arch == 0x01000007u && (encoding & 0xff000000u) == 0x03000000u) {
                    // x86_64 indirect-stack entries use the same saved-register
                    // permutation as immediate-stack entries, plus a code
                    // offset to the subq immediate and a push adjustment.
                    const auto count = (encoding >> 10) & 7u;
                    const auto rank = encoding & 0x3ffu;
                    const auto immediate_offset = (encoding >> 16) & 0xffu;
                    require(function_offset >= directory.function && function_offset < rows[page + 1].function,
                            "Mach-O x86_64 indirect-stack function interval is invalid");
                    require(count <= 6, "Mach-O x86_64 indirect-stack save count exceeds the register set");
                    std::uint32_t permutations = 1;
                    for (unsigned n = 0; n < count; ++n) permutations *= 6u - n;
                    require(rank < permutations, "Mach-O x86_64 indirect-stack register permutation is invalid");
                    require(immediate_offset >= 3 && immediate_offset <= rows[page + 1].function - function_offset &&
                                4 <= rows[page + 1].function - function_offset - immediate_offset,
                            "Mach-O x86_64 indirect-stack immediate is outside its function interval");
                }
                require(item == 0 || function_offset > previous,
                        "Mach-O compact-unwind function entries are not strictly ordered");
                if (!(function_offset >= directory.function && function_offset < rows[page + 1].function))
                    throw Failure{{ErrorCode::malformed,
                                   "Mach-O compact-unwind function entry is outside its index range: " +
                                       std::to_string(function_offset) + "/" + std::to_string(directory.function) +
                                       ".." + std::to_string(rows[page + 1].function)}};
                previous = function_offset;
                require(function_offset <= UINT64_MAX - *text_base, "Mach-O compact-unwind function address overflows", ErrorCode::overflow);
                const Address address{{0}, *text_base + function_offset};
                require(executable(image, address), "Mach-O compact-unwind function is outside initialized executable bytes");
                const auto source = reader.file(base + directory.page + entry_offset + std::uint64_t(item) * stride, stride);
                functions.push_back({section.ordinal, page, item, encoding, source.value, function_offset, address});
                roots.push_back({UINT32_MAX, source.value, function_offset, address});
                budget.include(sizeof(MachOFunctionStart));
            }
        }
    }
    for (auto &function : functions) metadata.compact_unwind_functions.push_back(std::move(function));
    for (auto &root : roots) metadata.function_starts.push_back(std::move(root));
}
std::uint64_t frame_uleb(std::span<const std::byte> bytes, std::size_t &cursor) {
    std::uint64_t result = 0;
    for (unsigned i = 0; i < 10; ++i) {
        require(cursor < bytes.size(), "Truncated Mach-O eh_frame ULEB");
        const auto byte = std::to_integer<unsigned>(bytes[cursor++]);
        require(i != 9 || (byte & 0x7f) <= 1, "Mach-O eh_frame ULEB overflows");
        result |= std::uint64_t(byte & 0x7f) << (i * 7);
        if (!(byte & 0x80)) return result;
    }
    throw Failure{{ErrorCode::malformed, "Mach-O eh_frame ULEB exceeds ten bytes"}};
}
std::int64_t frame_sleb(std::span<const std::byte> bytes, std::size_t &cursor) {
    std::uint64_t result = 0;
    unsigned shift = 0;
    unsigned byte = 0;
    for (unsigned i = 0; i < 10; ++i) {
        require(cursor < bytes.size(), "Truncated Mach-O eh_frame SLEB");
        byte = std::to_integer<unsigned>(bytes[cursor++]);
        require(i != 9 || (byte == 0 || byte == 0x7f), "Mach-O eh_frame SLEB overflows");
        result |= std::uint64_t(byte & 0x7f) << shift;
        shift += 7;
        if (!(byte & 0x80)) {
            if (shift < 64 && (byte & 0x40)) result |= (~UINT64_C(0)) << shift;
            return static_cast<std::int64_t>(result);
        }
    }
    throw Failure{{ErrorCode::malformed, "Mach-O eh_frame SLEB exceeds ten bytes"}};
}
struct FrameScalar {
    std::uint64_t value = 0;
    bool is_signed = false;
};

// Read just the encoded scalar. Keeping this separate from application/base
// handling lets FDE ranges use the CIE format nibble without applying its
// initial-location relocation mode.
FrameScalar frame_scalar(std::span<const std::byte> bytes, std::size_t &cursor,
                         std::size_t end, std::uint8_t format) {
    require(end <= bytes.size() && cursor <= end,
            "Mach-O EH scalar bounds exceed the containing record");
    require(format == 0 || format == 1 || format == 2 || format == 3 || format == 4 ||
                format == 8 || format == 9 || format == 0x0a || format == 0x0b || format == 0x0c,
            "Unsupported Mach-O EH pointer format", ErrorCode::unsupported);
    FrameScalar result;
    result.is_signed = format == 8 || format == 9 || format >= 0x0a;
    if (format == 1) {
        result.value = frame_uleb(bytes.first(end), cursor);
        return result;
    }
    if (format == 9) {
        result.value = static_cast<std::uint64_t>(frame_sleb(bytes.first(end), cursor));
        return result;
    }
    const auto width = format == 0 || format == 8 || format == 0x0c ? 8u :
                       format == 2 || format == 0x0a ? 2u :
                       format == 3 || format == 0x0b ? 4u : 8u;
    require(width <= end - cursor, "Truncated Mach-O encoded EH pointer");
    for (unsigned i = 0; i < width; ++i)
        result.value |= std::uint64_t(std::to_integer<unsigned>(bytes[cursor + i])) << (i * 8);
    cursor += width;
    if (result.is_signed && width < 8 &&
        (result.value & (UINT64_C(1) << (width * 8 - 1))))
        result.value |= (~UINT64_C(0)) << (width * 8);
    return result;
}

std::optional<std::size_t> fixed_eh_width(std::uint8_t format, bool is_64) {
    switch (format) {
    case 0: return is_64 ? 8u : 4u; // absptr
    case 2: case 0x0a: return 2u;
    case 3: case 0x0b: return 4u;
    case 4: case 8: case 0x0c: return 8u;
    default: return {};
    }
}

void classify_personality(const MachOMetadata &metadata, MachOEhFrameFunction &function) {
    if (!function.personality) return;
    std::optional<std::string> fallback;
    for (const auto &symbol : metadata.symbols) {
        if (!symbol.address || *symbol.address != *function.personality ||
            symbol.state != MachOSymbolState::defined)
            continue;
        if (!fallback) fallback = symbol.name;
        auto source_name = std::string_view(symbol.name);
        // Mach-O's external C symbol spelling adds one leading underscore.
        if (source_name.starts_with('_')) source_name.remove_prefix(1);
        if (source_name == "__gxx_personality_v0") {
            function.personality_symbol = symbol.name;
            function.personality_kind = MachOPersonalityKind::itanium_cxx;
            return;
        }
    }
    function.personality_symbol = std::move(fallback);
}

std::uint64_t frame_pointer(std::span<const std::byte> bytes, std::size_t &cursor, std::size_t end,
                            std::uint8_t encoding, std::uint64_t section_va) {
    require(!(encoding & 0x80), "Indirect Mach-O EH pointers are unsupported", ErrorCode::unsupported);
    const auto application = encoding & 0x70;
    require(application == 0 || application == 0x10 || application == 0x50,
            "Unsupported Mach-O EH pointer application", ErrorCode::unsupported);
    if (application == 0x50) {
        require((encoding & 0x0f) == 0, "Aligned Mach-O EH pointer must use absptr", ErrorCode::unsupported);
        require(section_va <= UINT64_MAX - cursor, "Mach-O aligned EH pointer address overflows", ErrorCode::overflow);
        const auto address = section_va + cursor;
        const auto padding = static_cast<std::size_t>((8 - (address & 7)) & 7);
        require(padding <= end - cursor, "Truncated Mach-O aligned EH pointer padding");
        cursor += padding;
    }
    const auto encoded_at = cursor;
    const auto scalar = frame_scalar(bytes, cursor, end, encoding & 0x0f);
    if (application != 0x10) return scalar.value;
    require(encoded_at <= UINT64_MAX - section_va, "Mach-O PC-relative EH base overflows", ErrorCode::overflow);
    const auto base = section_va + encoded_at;
    if (scalar.is_signed) {
        const auto delta = static_cast<std::int64_t>(scalar.value);
        if (delta < 0) {
            const auto magnitude = static_cast<std::uint64_t>(-(delta + 1)) + 1;
            require(magnitude <= base, "Mach-O PC-relative EH pointer underflows", ErrorCode::overflow);
            return base - magnitude;
        }
        require(static_cast<std::uint64_t>(delta) <= UINT64_MAX - base,
                "Mach-O PC-relative EH pointer overflows", ErrorCode::overflow);
        return base + static_cast<std::uint64_t>(delta);
    }
    require(scalar.value <= UINT64_MAX - base, "Mach-O PC-relative EH pointer overflows", ErrorCode::overflow);
    return base + scalar.value;
}
void parse_lsda(const Reader &reader, const Image &image, MachOMetadata &metadata, Budget &budget,
                const MachOSlice &slice, MachOEhFrameFunction &function,
                std::uint64_t lsda_va, std::uint8_t encoding,
                const std::map<std::uint64_t, std::pair<std::vector<std::string>, bool>> &rtti_symbols,
                std::stop_token stop) {
    const MachOSection *section = nullptr;
    for (const auto &candidate : metadata.sections) {
        if (!candidate.file_offset || lsda_va < candidate.address || lsda_va - candidate.address >= candidate.size) continue;
        require(section == nullptr, "Mach-O LSDA address maps to overlapping sections");
        section = &candidate;
    }
    if (!section) { function.lsda_complete = false; return; }
    const auto delta = lsda_va - section->address;
    const auto remaining = section->size - delta;
    if (remaining > 16 * 1024 * 1024) throw Failure{{ErrorCode::resource_limit, "Mach-O LSDA exceeds bounded parser budget"}};
    const auto section_file = section->file_offset->value - slice.offset;
    require(delta <= UINT64_MAX - section_file, "Mach-O LSDA file offset overflows", ErrorCode::overflow);
    function.lsda_section = section->ordinal;
    function.lsda_file_offset = section_file + delta;
    auto bytes_view = reader.bytes(section_file + delta, static_cast<std::size_t>(remaining));
    const auto bytes = std::span<const std::byte>(bytes_view.bytes);
    std::size_t cursor = 0;
    require(!bytes.empty(), "Empty Mach-O LSDA");
    std::uint64_t lp_start = function.address->offset;
    const auto lp_encoding = std::to_integer<std::uint8_t>(bytes[cursor++]);
    if (lp_encoding != 0xff) lp_start = frame_pointer(bytes, cursor, bytes.size(), lp_encoding, lsda_va);
    require(executable(image, {{0}, lp_start}), "Mach-O LSDA LPStart is outside initialized executable bytes");
    require(cursor < bytes.size(), "Truncated Mach-O LSDA type-table encoding");
    const auto type_encoding = std::to_integer<std::uint8_t>(bytes[cursor++]);
    function.type_table_encoding = type_encoding;
    if (type_encoding != 0xff) {
        const auto type_offset = frame_uleb(bytes, cursor);
        require(type_offset <= bytes.size() - cursor, "Mach-O LSDA type table exceeds section extent");
        const auto application = type_encoding & 0x70;
        const auto format = type_encoding & 0x0f;
        function.type_table_base_offset = static_cast<std::uint64_t>(cursor) + type_offset;
        // Positive type filters index a reverse table. Random access is safe
        // only for fixed-width entries and known Itanium C++ personality data.
        if ((type_encoding & 0x80) || (application != 0 && application != 0x10) ||
            !fixed_eh_width(format, slice.header.is_64) ||
            function.personality_kind != MachOPersonalityKind::itanium_cxx) {
            function.type_table_complete = false;
            function.lsda_complete = false;
        }
    }
    require(cursor < bytes.size(), "Truncated Mach-O LSDA call-site encoding");
    const auto call_encoding = std::to_integer<std::uint8_t>(bytes[cursor++]);
    function.call_site_encoding = call_encoding;
    require(!(call_encoding & 0x80) && (call_encoding & 0x70) == 0 &&
                (call_encoding == 0x00 || call_encoding == 0x01 || call_encoding == 0x02 || call_encoding == 0x03 || call_encoding == 0x04 ||
                 call_encoding == 0x08 || call_encoding == 0x09 || call_encoding == 0x0a || call_encoding == 0x0b || call_encoding == 0x0c),
            "Unsupported Mach-O LSDA call-site encoding", ErrorCode::unsupported);
    const auto table_size = frame_uleb(bytes, cursor);
    require(table_size <= bytes.size() - cursor, "Mach-O LSDA call-site table exceeds section extent");
    const auto table_end = cursor + static_cast<std::size_t>(table_size);
    function.action_table_offset = table_end;
    std::uint64_t prior_end = 0;
    while (cursor < table_end) {
        canceled(stop);
        require(function.call_sites.size() < 1000000, "Mach-O LSDA call-site count exceeds budget", ErrorCode::resource_limit);
        const auto row_start = cursor;
        MachOEhFrameCallSite row;
        row.start = frame_pointer(bytes, cursor, table_end, call_encoding, 0);
        row.length = frame_pointer(bytes, cursor, table_end, call_encoding, 0);
        row.landing_pad = frame_pointer(bytes, cursor, table_end, call_encoding, 0);
        row.action = frame_uleb(bytes.first(table_end), cursor);
        require(row.start >= prior_end && row.start <= function.size && row.length <= function.size - row.start,
                "Mach-O LSDA call-site range is outside its FDE");
        require(row.landing_pad == 0 || (row.landing_pad < function.size &&
                    row.landing_pad <= UINT64_MAX - lp_start && executable(image, {{0}, lp_start + row.landing_pad})),
                "Mach-O LSDA landing pad is outside initialized executable bytes");
        prior_end = row.start + row.length;
        row.record_offset = row_start;
        row.encoded_size = cursor - row_start;
        budget.include(sizeof(MachOEhFrameCallSite));
        function.call_sites.push_back(row);
    }
    require(cursor == table_end, "Mach-O LSDA call-site table is malformed");

    // Call-site action values are one-based byte offsets from the action table.
    // The signed displacement in each action record is relative to the byte
    // immediately after its own SLEB128 field, as emitted by DWARF EH producers.
    const auto action_end = function.type_table_base_offset
        ? static_cast<std::size_t>(*function.type_table_base_offset) : bytes.size();
    require(action_end >= table_end, "Mach-O LSDA type table overlaps its call-site/action data");
    std::map<std::uint64_t, std::size_t> action_indices;
    std::map<std::uint64_t, std::uint64_t> action_record_ends;
    for (auto &row : function.call_sites) {
        if (!row.action) continue;
        require(row.action - 1 <= std::numeric_limits<std::size_t>::max() - table_end,
                "Mach-O LSDA action offset overflows", ErrorCode::overflow);
        auto action_offset = static_cast<std::uint64_t>(table_end) + row.action - 1;
        std::set<std::uint64_t> chain_offsets;
        for (std::size_t count = 0; ; ++count) {
            canceled(stop);
            require(count < 4096, "Mach-O LSDA action chain exceeds record limit", ErrorCode::resource_limit);
            require(action_offset >= table_end && action_offset < action_end,
                    "Mach-O LSDA action record is outside its bounded action table");
            require(chain_offsets.insert(action_offset).second, "Mach-O LSDA action chain contains a cycle");
            row.action_chain.push_back(action_offset);
            budget.include(sizeof(std::uint64_t));

            auto found_action = action_indices.find(action_offset);
            if (found_action == action_indices.end()) {
                require(function.actions.size() < 65536,
                        "Mach-O LSDA action count exceeds budget", ErrorCode::resource_limit);
                std::size_t action_cursor = static_cast<std::size_t>(action_offset);
                const auto bounded = bytes.first(action_end);
                MachOEhFrameAction action;
                action.record_offset = action_offset;
                action.type_filter = frame_sleb(bounded, action_cursor);
                action.next_displacement = frame_sleb(bounded, action_cursor);
                action.encoded_size = action_cursor - action_offset;
                action_record_ends.emplace(action_offset, action_cursor);
                if (action.next_displacement != 0) {
                    std::uint64_t next_offset = action_cursor;
                    if (action.next_displacement < 0) {
                        const auto magnitude = static_cast<std::uint64_t>(-(action.next_displacement + 1)) + 1;
                        require(magnitude <= next_offset, "Mach-O LSDA action displacement underflows", ErrorCode::overflow);
                        next_offset -= magnitude;
                    } else {
                        const auto magnitude = static_cast<std::uint64_t>(action.next_displacement);
                        require(magnitude <= UINT64_MAX - next_offset,
                                "Mach-O LSDA action displacement overflows", ErrorCode::overflow);
                        next_offset += magnitude;
                    }
                    require(next_offset >= table_end && next_offset < action_end,
                            "Mach-O LSDA next-action record is outside its bounded action table");
                    action.next_record_offset = next_offset;
                }
                budget.include(sizeof(MachOEhFrameAction));
                const auto index = function.actions.size();
                function.actions.push_back(std::move(action));
                found_action = action_indices.emplace(action_offset, index).first;
            }
            const auto &action = function.actions[found_action->second];
            if (!action.next_record_offset) break;
            action_offset = *action.next_record_offset;
        }
        if (!function.type_table_complete)
            function.lsda_complete = false;
    }

    std::uint64_t largest_type_index = 0;
    for (const auto &action : function.actions) {
        // Negative filters identify exception-specification lists, whose
        // entries use a separate ABI representation that this parser retains
        // only as a raw filter value.
        if (action.type_filter < 0) function.type_table_complete = false;
        if (action.type_filter > 0)
            largest_type_index = std::max(largest_type_index,
                                           static_cast<std::uint64_t>(action.type_filter));
    }
    if (largest_type_index) {
        const auto width = fixed_eh_width(function.type_table_encoding & 0x0f, slice.header.is_64);
        if (!width || function.personality_kind != MachOPersonalityKind::itanium_cxx ||
            !function.type_table_base_offset || largest_type_index > 65536 ||
            largest_type_index > UINT64_MAX / *width) {
            function.type_table_complete = false;
        } else {
            const auto table_base = *function.type_table_base_offset;
            const auto lowest_entry = largest_type_index * *width <= table_base
                ? table_base - largest_type_index * *width : UINT64_MAX;
            if (lowest_entry == UINT64_MAX || lowest_entry < table_end) {
                function.type_table_complete = false;
            } else {
                for (const auto &[record_offset, record_end] : action_record_ends) {
                    (void)record_offset;
                    if (record_end > lowest_entry) function.type_table_complete = false;
                }
                std::map<std::uint32_t, MachOEhFrameTypeInfo> entries;
                for (auto &action : function.actions) {
                    if (action.type_filter <= 0) {
                        if (action.type_filter < 0) function.type_table_complete = false;
                        continue;
                    }
                    const auto index = static_cast<std::uint32_t>(action.type_filter);
                    if (entries.contains(index)) {
                        action.type_info_index = index;
                        continue;
                    }
                    const auto distance = std::uint64_t{index} * *width;
                    if (distance > table_base) {
                        function.type_table_complete = false;
                        continue;
                    }
                    const auto entry_offset = table_base - distance;
                    if (entry_offset < table_end || *width > table_base - entry_offset) {
                        function.type_table_complete = false;
                        continue;
                    }
                    std::size_t entry_cursor = static_cast<std::size_t>(entry_offset);
                    std::uint64_t value = 0;
                    try {
                        value = frame_pointer(bytes, entry_cursor,
                            static_cast<std::size_t>(entry_offset + *width),
                            function.type_table_encoding, lsda_va);
                    } catch (const Failure &error) {
                        if (error.error.code != ErrorCode::unsupported) throw;
                        function.type_table_complete = false;
                        continue;
                    }
                    require(entry_cursor == entry_offset + *width,
                            "Mach-O LSDA type entry did not consume its fixed-width encoding");
                    MachOEhFrameTypeInfo info;
                    info.index = index;
                    info.record_offset = entry_offset;
                    info.encoded_size = *width;
                    info.encoding = function.type_table_encoding;
                    info.value = value;
                    info.null_pointer = value == 0;
                    if (!value) {
                        info.target_state = MachOEhFrameRttiTargetState::null_catch_all;
                    } else if (readable_file_byte(image, {{0}, value})) {
                        info.address = Address{{0}, value};
                        info.target_state = MachOEhFrameRttiTargetState::readable_pointer;
                    } else {
                        function.type_table_complete = false;
                        info.target_state = MachOEhFrameRttiTargetState::invalid_pointer;
                    }
                    if (info.address) {
                        if (const auto symbols = rtti_symbols.find(value); symbols != rtti_symbols.end()) {
                            info.rtti_symbols = symbols->second.first;
                            info.target_state = symbols->second.second || info.rtti_symbols.size() > 1
                                ? MachOEhFrameRttiTargetState::ambiguous_defined_rtti_symbols
                                : MachOEhFrameRttiTargetState::exact_defined_rtti_symbol;
                            for (const auto &name : info.rtti_symbols) budget.include(name.size());
                        }
                    }
                    budget.include(sizeof(MachOEhFrameTypeInfo));
                    entries.emplace(index, std::move(info));
                    action.type_info_index = index;
                }
                for (auto &[index, info] : entries) {
                    (void)index;
                    function.type_infos.push_back(std::move(info));
                }
            }
        }
    }
    if (function.actions.size() > 65536) function.type_table_complete = false;
    if (!function.type_table_complete) function.lsda_complete = false;
    budget.include(bytes.size());
    (void)encoding;
}
void eh_frame(const Reader &reader, const MachOSlice &slice, const Image &image,
              MachOMetadata &metadata, Budget &budget, std::stop_token stop) {
    const auto arch = slice.header.cpu_type;
    std::map<std::uint64_t, std::pair<std::vector<std::string>, bool>> rtti_symbols;
    for (const auto &symbol : metadata.symbols) {
        canceled(stop);
        if (symbol.state != MachOSymbolState::defined) continue;
        auto name = std::string_view(symbol.name);
        // Mach-O adds one underscore to the Itanium ABI's _ZTI prefix.
        if (name.starts_with('_')) name.remove_prefix(1);
        if (!name.starts_with("_ZTI")) continue;
        const auto [entry, inserted] = rtti_symbols.try_emplace(symbol.value);
        if (inserted)
            budget.include(sizeof(std::uint64_t) + sizeof(std::pair<std::vector<std::string>, bool>));
        auto &matches = entry->second;
        if (matches.first.size() < 16) {
            budget.include(sizeof(std::string) + symbol.name.size());
            matches.first.push_back(symbol.name);
        }
        else matches.second = true;
    }
    for (const auto &section : metadata.sections) {
        canceled(stop);
        if (section.name != "__eh_frame") continue;
        if (!slice.header.is_64 || slice.header.order != ByteOrder::little ||
            (arch != 0x01000007u && arch != 0x0100000cu)) {
            metadata.commands_complete = false;
            continue;
        }
        require(section.file_offset.has_value(), "Mach-O __eh_frame section has no initialized backing");
        require(section.size <= 64 * 1024 * 1024, "Mach-O __eh_frame exceeds bounded parser budget",
                ErrorCode::resource_limit);
        const auto raw = reader.bytes(section.file_offset->value - slice.offset, static_cast<std::size_t>(section.size));
        budget.include(section.size);
        struct Cie {
            std::uint8_t pointer_encoding = 0, lsda_encoding = 0xff;
            std::optional<Address> personality;
            bool has_personality_field = false;
            std::uint8_t personality_encoding = 0xff;
            std::optional<FileOffset> personality_source;
            std::uint64_t personality_source_size = 0;
            bool supported = false, has_z_augmentation = false;
            std::uint64_t code_alignment = 1, return_register = 0;
            std::int64_t data_alignment = 0;
            std::vector<std::byte> instructions;
        };
        std::map<std::size_t, Cie> cies;
        std::size_t cursor = 0;
        while (cursor + 4 <= raw.bytes.size()) {
            canceled(stop);
            const auto record = cursor;
            const auto length = static_cast<std::uint32_t>(reader.value(raw.bytes, cursor, 4)); cursor += 4;
            if (!length) break;
            require(length != 0xffffffffu && length >= 4 && length <= raw.bytes.size() - cursor,
                    "Mach-O eh_frame record exceeds section extent");
            const auto end = cursor + length;
            const auto id_at = cursor;
            const auto id = static_cast<std::uint32_t>(reader.value(raw.bytes, cursor, 4)); cursor += 4;
            if (!id) {
                require(cursor < end, "Truncated Mach-O eh_frame CIE");
                const auto version = std::to_integer<unsigned>(raw.bytes[cursor++]);
                require(version == 1 || version == 3 || version == 4, "Unsupported Mach-O eh_frame CIE version");
                const auto aug_begin = cursor;
                while (cursor < end && raw.bytes[cursor] != std::byte{0}) ++cursor;
                require(cursor < end, "Unterminated Mach-O eh_frame augmentation string");
                const std::string augmentation(reinterpret_cast<const char *>(raw.bytes.data() + aug_begin), cursor - aug_begin);
                ++cursor;
                // CIE v4 makes the target address width explicit. This parser
                // only handles 64-bit Mach-O slices, and has no segmented
                // address-space model, so require the matching plain layout.
                if (version == 4) {
                    require(end - cursor >= 2, "Truncated Mach-O eh_frame CIE v4 address sizes");
                    const auto address_size = std::to_integer<std::uint8_t>(raw.bytes[cursor++]);
                    const auto segment_size = std::to_integer<std::uint8_t>(raw.bytes[cursor++]);
                    require(address_size == 8 && segment_size == 0,
                            "Unsupported Mach-O eh_frame CIE v4 address/segment size", ErrorCode::unsupported);
                }
                const auto code_alignment = frame_uleb(raw.bytes.first(end), cursor);
                const auto data_alignment = frame_sleb(raw.bytes.first(end), cursor);
                if (version == 1) { require(cursor < end, "Truncated Mach-O eh_frame return register"); ++cursor; }
                const auto return_register = version == 1
                    ? std::uint64_t(std::to_integer<unsigned>(raw.bytes[cursor - 1]))
                    : frame_uleb(raw.bytes.first(end), cursor);
                Cie cie;
                cie.code_alignment = code_alignment;
                cie.data_alignment = data_alignment;
                cie.return_register = return_register;
                // 'S' is a marker with no payload (signal-frame CIE). Accept
                // it alongside the common pointer/personality/LSDA fields.
                // Unknown augmentation characters remain fail-closed.
                cie.supported = !augmentation.empty() && augmentation[0] == 'z';
                if (cie.supported) {
                    for (std::size_t ai = 1; ai < augmentation.size(); ++ai)
                        if (augmentation[ai] != 'P' && augmentation[ai] != 'L' &&
                            augmentation[ai] != 'R' && augmentation[ai] != 'S')
                            cie.supported = false;
                }
                cie.has_z_augmentation = !augmentation.empty() && augmentation[0] == 'z';
                if (cie.has_z_augmentation) {
                    const auto aug_size = frame_uleb(raw.bytes.first(end), cursor);
                    require(aug_size <= end - cursor, "Mach-O eh_frame CIE augmentation exceeds record");
                    const auto aug_end = cursor + static_cast<std::size_t>(aug_size);
                    for (std::size_t ai = 1; ai < augmentation.size(); ++ai) {
                        const char tag = augmentation[ai];
                        if (tag == 'P') {
                            require(cursor < aug_end, "Truncated Mach-O CIE personality encoding");
                            const auto personality_field_start = cursor;
                            const auto enc = std::to_integer<std::uint8_t>(raw.bytes[cursor++]);
                            cie.has_personality_field = true;
                            cie.personality_encoding = enc;
                            // Keep the encoding byte and its provenance even if
                            // decoding the following pointer is unsupported.
                            cie.personality_source = reader.file(section.file_offset->value - slice.offset + personality_field_start, 1);
                            cie.personality_source_size = 1;
                            require(cursor <= UINT64_MAX - section.address, "Mach-O personality field address overflows", ErrorCode::overflow);
                            try {
                                const auto value = frame_pointer(raw.bytes, cursor, aug_end, enc, section.address);
                                cie.personality = Address{{0}, value};
                                cie.personality_source = reader.file(section.file_offset->value - slice.offset + personality_field_start,
                                                                     cursor - personality_field_start);
                                cie.personality_source_size = cursor - personality_field_start;
                            } catch (const Failure &error) {
                                if (error.error.code != ErrorCode::unsupported) throw;
                                cie.supported = false;
                                cursor = aug_end;
                                break;
                            }
                        } else if (tag == 'L') {
                            require(cursor < aug_end, "Truncated Mach-O CIE LSDA encoding");
                            cie.lsda_encoding = std::to_integer<std::uint8_t>(raw.bytes[cursor++]);
                        } else if (tag == 'R') {
                            require(cursor < aug_end, "Truncated Mach-O CIE FDE encoding");
                            cie.pointer_encoding = std::to_integer<std::uint8_t>(raw.bytes[cursor++]);
                        } else if (tag == 'S') {
                            // Marker only; no augmentation bytes.
                        } else cie.supported = false;
                    }
                    require(cursor <= aug_end, "Mach-O CIE augmentation overrun");
                    if (cursor != aug_end) cie.supported = false;
                    cursor = aug_end;
                } else cie.supported = false;
                require(cursor <= end && code_alignment != 0, "Malformed Mach-O eh_frame CIE");
                if (!cie.supported)
                    metadata.commands_complete = false;
                cie.instructions.assign(raw.bytes.begin() + static_cast<std::ptrdiff_t>(cursor),
                                        raw.bytes.begin() + static_cast<std::ptrdiff_t>(end));
                cies.emplace(record, cie);
            } else {
                require(id <= id_at, "Mach-O eh_frame FDE CIE pointer does not point backward");
                const auto cie_offset = id_at - id;
                const auto found = cies.find(cie_offset);
                if (found != cies.end() && found->second.supported) {
                    const auto encoding = found->second.pointer_encoding;
                    const auto application = encoding & 0x70;
                    const auto format = encoding & 0x0f;
                    // EH pointer encodings used by common 64-bit Mach-O toolchains.
                    // Unsupported application modes and indirect pointers are deliberately
                    // skipped: resolving them requires section/indirection semantics.
                    if (!(encoding & 0x80) && (application == 0 || application == 0x10 || application == 0x50) &&
                        format <= 0x0c && format != 0x05 && format != 0x06 && format != 0x07) {
                        const auto decode = [&](bool apply_pc) -> std::pair<std::uint64_t, bool> {
                            if (apply_pc && application == 0x50) {
                                require(format == 0, "Aligned Mach-O FDE pointer must use absptr", ErrorCode::unsupported);
                                require(section.address <= UINT64_MAX - cursor,
                                        "Mach-O aligned FDE field address overflows", ErrorCode::overflow);
                                const auto field_va = section.address + cursor;
                                cursor += static_cast<std::size_t>((8 - (field_va & 7)) & 7);
                                require(cursor <= end, "Truncated Mach-O aligned FDE pointer padding");
                            }
                            const auto encoded_at = cursor;
                            const auto scalar = frame_scalar(raw.bytes, cursor, end, format);
                            auto value = scalar.value;
                            bool is_signed = scalar.is_signed;
                            if (apply_pc && application == 0x10) {
                                require(encoded_at <= UINT64_MAX - section.address,
                                        "Mach-O eh_frame FDE field address overflows", ErrorCode::overflow);
                                const auto field_va = section.address + encoded_at;
                                if (is_signed) {
                                    const auto delta = static_cast<std::int64_t>(value);
                                    if (delta >= 0) {
                                        require(static_cast<std::uint64_t>(delta) <= UINT64_MAX - field_va,
                                                "Mach-O eh_frame FDE address overflows", ErrorCode::overflow);
                                        value = field_va + static_cast<std::uint64_t>(delta);
                                    } else {
                                        const auto magnitude = static_cast<std::uint64_t>(-(delta + 1)) + 1;
                                        require(magnitude <= field_va, "Mach-O eh_frame FDE address underflows", ErrorCode::overflow);
                                        value = field_va - magnitude;
                                    }
                                } else {
                                    require(value <= UINT64_MAX - field_va, "Mach-O eh_frame FDE address overflows", ErrorCode::overflow);
                                    value += field_va;
                                }
                                is_signed = false;
                            }
                            return {value, is_signed};
                        };
                        const auto initial_location = decode(true);
                        const auto start = initial_location.first;
                        // The FDE range uses only the format nibble; its application bits are ignored.
                        const auto size_value = decode(false).first;
                        require(size_value <= UINT32_MAX, "Mach-O eh_frame FDE range exceeds metadata width", ErrorCode::overflow);
                        const auto size = static_cast<std::uint32_t>(size_value);
                        const Address address{{0}, start};
                        require(size && executable(image, address) && size - 1 <= UINT64_MAX - start &&
                                    executable(image, {{0}, start + size - 1}),
                                "Mach-O eh_frame FDE range is outside initialized executable bytes");
                        std::optional<std::uint64_t> lsda_va;
                        bool lsda_pointer_supported = true;
                        if (found->second.has_z_augmentation) {
                            const auto aug_size = frame_uleb(raw.bytes.first(end), cursor);
                            require(aug_size <= end - cursor, "Mach-O eh_frame FDE augmentation exceeds record");
                            const auto aug_end = cursor + static_cast<std::size_t>(aug_size);
                            if (found->second.lsda_encoding != 0xff && aug_size) {
                                require(cursor <= UINT64_MAX - section.address, "Mach-O LSDA field address overflows", ErrorCode::overflow);
                                try {
                                    lsda_va = frame_pointer(raw.bytes, cursor, aug_end, found->second.lsda_encoding,
                                                            section.address);
                                } catch (const Failure &error) {
                                    if (error.error.code != ErrorCode::unsupported) throw;
                                    lsda_pointer_supported = false;
                                    metadata.commands_complete = false;
                                }
                            }
                            cursor = aug_end;
                            if (found->second.personality)
                                require(executable(image, *found->second.personality),
                                        "Mach-O exception personality is outside initialized executable bytes");
                        }
                        const auto source = reader.file(section.file_offset->value - slice.offset + record, length + 4);
                        MachOEhFrameFunction function;
                        function.section = section.ordinal;
                        function.record_file_offset = source.value;
                        function.size = size;
                        function.address = address;
                        function.pointer_encoding = encoding;
                        function.code_alignment = found->second.code_alignment;
                        function.data_alignment = found->second.data_alignment;
                        function.return_register = found->second.return_register;
                        function.personality = found->second.personality;
                        function.has_personality_field = found->second.has_personality_field;
                        function.personality_encoding = found->second.personality_encoding;
                        function.personality_source = found->second.personality_source;
                        function.personality_source_size = found->second.personality_source_size;
                        classify_personality(metadata, function);
                        if (function.personality_symbol)
                            budget.include(function.personality_symbol->size());
                        function.lsda_encoding = found->second.lsda_encoding;
                        if (!lsda_pointer_supported)
                            function.lsda_complete = false;
                        function.cie_instructions = found->second.instructions;
                        function.instructions.assign(raw.bytes.begin() + static_cast<std::ptrdiff_t>(cursor),
                                                     raw.bytes.begin() + static_cast<std::ptrdiff_t>(end));
                        if (lsda_va) {
                            function.lsda = Address{{0}, *lsda_va};
                            try { parse_lsda(reader, image, metadata, budget, slice, function, *lsda_va,
                                             found->second.lsda_encoding, rtti_symbols, stop); }
                            catch (const Failure &error) {
                                if (error.error.code == ErrorCode::unsupported) {
                                    // Do not expose a partially decoded exception table as usable
                                    // metadata when a later field requires an unsupported encoding.
                                    function.call_sites.clear();
                                    function.actions.clear();
                                    function.type_infos.clear();
                                    function.action_table_offset = 0;
                                    function.type_table_base_offset.reset();
                                    function.call_site_encoding = 0xff;
                                    function.type_table_encoding = 0xff;
                                    function.type_table_complete = false;
                                    function.lsda_complete = false;
                                }
                                else throw;
                            }
                        }
                        const auto cfi_bytes = found->second.instructions.size() + function.instructions.size();
                        budget.include(sizeof(MachOEhFrameFunction) + sizeof(MachOFunctionStart) + cfi_bytes);
                        metadata.eh_frame_functions.push_back(std::move(function));
                        metadata.function_starts.push_back({UINT32_MAX, source.value, start, address});
                    }
                }
            }
            cursor = end;
        }
    }
}
} // namespace
bool supported_command(std::uint32_t command) {
    return command == 1 || command == 0x19 || command == 2 || command == 0xb || dylib(command) || command == 0xe ||
           command == 0xf || command == 0x8000001c || command == 0x80000028 || command == 4 || command == 5 ||
           command == 0x11 || command == 0x1a || command == 0x26 || command == 0x22 || command == 0x80000022 || command == 0x80000033 ||
           command == 0x80000034 || command == 0x29 || command == 0x1d || command == 0x21 || command == 0x2c ||
           command == 0x32 || command == 0x24 || command == 0x25 || command == 0x2f || command == 0x30 ||
           command == 0x35;
}
void read_commands(const ByteStorage &storage, const Image &image, MachOMetadata &metadata, Budget &budget,
                   std::stop_token stop) {
    const auto &slice = metadata.container.slices[metadata.selected_slice];
    Reader reader(storage, slice, stop);
    std::optional<std::uint64_t> text_base;
    bool ambiguous_text = false;
    const auto header_anchor = take(macho_header_anchor(image, slice, stop));
    if (slice.header.file_type != 1) {
        for (const auto &segment : metadata.segments) {
            canceled(stop);
            if (segment.name == "__TEXT") {
                if (text_base && *text_base != segment.address)
                    ambiguous_text = true;
                else
                    text_base = segment.address;
            }
        }
        if (ambiguous_text)
            text_base.reset();
    }
    std::uint32_t ordinal = 0;
    for (const auto &command : slice.header.commands) {
        canceled(stop);
        if (dylib(command.command)) {
            require(command.size >= 24, "Truncated Mach-O dylib command");
            const auto fixed = reader.bytes(command.file_offset - slice.offset, 24);
            const auto field = [&](std::size_t at) {
                return static_cast<std::uint32_t>(reader.value(fixed.bytes, at, 4));
            };
            MachOLibrary row;
            row.command_index = command.index;
            row.command = command.command;
            row.record_file_offset = command.file_offset;
            row.name_offset = field(8);
            row.timestamp = field(12);
            row.current_version = field(16);
            row.compatibility_version = field(20);
            if (command.command != 0xd)
                row.ordinal = ++ordinal;
            row.name = command_string(reader, command, slice.offset, row.name_offset, 24, budget);
            budget.include(sizeof(MachOLibrary));
            metadata.libraries.push_back(std::move(row));
        } else if (command.command == 0xe || command.command == 0xf || command.command == 0x8000001c) {
            require(command.size >= 12, "Truncated Mach-O path command");
            const auto fixed = reader.bytes(command.file_offset - slice.offset, 12);
            MachOCommandString row{command.index,
                                   command.command,
                                   static_cast<std::uint32_t>(reader.value(fixed.bytes, 8, 4)),
                                   command.file_offset,
                                   {}};
            row.name = command_string(reader, command, slice.offset, row.name_offset, 12, budget);
            budget.include(sizeof(MachOCommandString));
            metadata.paths.push_back(std::move(row));
        } else if (command.command == 0xb) {
            dynamic_symbols(reader, command, slice, metadata, budget, stop);
        } else if (command.command == 0x80000028) {
            require(command.size >= 24, "Truncated Mach-O main entry command");
            const auto fixed = reader.bytes(command.file_offset - slice.offset, 24);
            MachOEntry entry;
            entry.command_index = command.index;
            entry.command = command.command;
            entry.record_file_offset = command.file_offset;
            entry.value = reader.value(fixed.bytes, 8, 8);
            entry.stack_size = reader.value(fixed.bytes, 16, 8);
            if (slice.header.file_type == 2) {
                if (header_anchor && *entry.value <= UINT64_MAX - header_anchor->offset) {
                    const Address at{header_anchor->space, header_anchor->offset + *entry.value};
                    if (executable(image, at))
                        entry.address = at;
                }
            }
            if (!entry.address)
                metadata.commands_complete = false;
            budget.include(sizeof(MachOEntry));
            metadata.entries.push_back(std::move(entry));
        } else if (command.command == 0x11 || command.command == 0x1a) {
            const bool is_64 = command.command == 0x1a;
            require(is_64 == slice.header.is_64, "Mach-O routines command width disagrees with header");
            const auto extent = is_64 ? 72u : 40u;
            require(command.size >= extent, "Truncated Mach-O routines command");
            const auto fixed = reader.bytes(command.file_offset - slice.offset, extent);
            MachOInitializer initializer;
            initializer.command_index = command.index;
            initializer.command = command.command;
            initializer.record_file_offset = command.file_offset;
            initializer.value = reader.value(fixed.bytes, 8, is_64 ? 8u : 4u);
            if (initializer.value) {
                const Address at{image.layout().space.id, initializer.value};
                if (executable(image, at))
                    initializer.address = at;
            }
            if (initializer.value && !initializer.address)
                metadata.commands_complete = false;
            budget.include(sizeof(MachOInitializer));
            metadata.initializers.push_back(std::move(initializer));
        } else if (command.command == 4 || command.command == 5) {
            thread(reader, command, slice, image, metadata, budget, stop);
        } else if (command.command == 0x32 || command.command == 0x24 || command.command == 0x25 ||
                   command.command == 0x2f || command.command == 0x30) {
            build_version(reader, command, metadata, budget, stop);
        } else if (command.command == 0x26) {
            function_starts(reader, command, slice, image, metadata, text_base, budget, stop);
        } else if (command.command == 0x35) {
            fileset_entry(reader, command, slice, metadata, budget, stop);
        }
    }
    compact_unwind(reader, slice, image, metadata, text_base, budget, stop);
    eh_frame(reader, slice, image, metadata, budget, stop);
    std::set<std::pair<std::uint32_t, std::uint64_t>> entries;
    for (const auto &entry : metadata.entries)
        if (entry.address)
            entries.emplace(entry.address->space.value, entry.address->offset);
    metadata.entries_conflict = entries.size() > 1;
    if (metadata.entries_conflict)
        metadata.commands_complete = false;
}
} // namespace hexlab::macho_detail
