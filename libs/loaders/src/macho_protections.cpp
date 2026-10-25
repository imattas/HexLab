#include "macho_internal.hpp"
#include <algorithm>
namespace hexlab::macho_detail {
void read_protections(const ByteStorage &storage, const Image &image, MachOMetadata &metadata, ImageLayout &layout,
                      Budget &budget, std::stop_token stop) {
    const auto &slice = metadata.container.slices[metadata.selected_slice];
    Reader reader(storage, slice, stop);
    std::uint64_t work = 64 * 1024 * 1024;
    const auto exclude = [&](FileOffset file, std::uint64_t size, bool encrypted) {
        if (!size)
            return;
        const auto end = add(file.value, size);
        // Map every initialized alias, including independent object domains and
        // SG_HIGHVM placement. File coordinates stay relative to the selected slice.
        for (const auto &segment : image.layout().segments) {
            canceled(stop);
            require(work != 0, "Mach-O protection mapping exceeds work budget", ErrorCode::resource_limit);
            --work;
            const auto begin = std::max(file.value, segment.file_begin.value);
            const auto last = std::min(end, add(segment.file_begin.value, segment.file_size));
            if (begin >= last)
                continue;
            const ImageCodeRange row{{segment.begin.space, add(segment.begin.offset, begin - segment.file_begin.value)},
                                     last - begin};
            budget.include(sizeof(ImageCodeRange) * (encrypted ? 2 : 1));
            (encrypted ? layout.encrypted_ranges : layout.code_exclusions).push_back(row);
        }
    };
    for (const auto &command : slice.header.commands) {
        canceled(stop);
        const auto type = command.command;
        if (type != 0x29 && type != 0x1d && type != 0x21 && type != 0x2c)
            continue;
        const bool encrypted = type == 0x21 || type == 0x2c;
        const auto minimum = encrypted ? type == 0x2c ? 24u : 20u : 16u;
        require(command.size >= minimum, "Truncated Mach-O protection command");
        const auto bytes = reader.bytes(command.file_offset - slice.offset, minimum);
        const auto field = [&](std::size_t at, std::size_t width = 4) { return reader.value(bytes.bytes, at, width); };
        const auto offset = static_cast<std::uint32_t>(field(8));
        const auto size = static_cast<std::uint32_t>(field(12));
        const auto file = reader.file(offset, size);
        if (encrypted) {
            budget.include(sizeof(MachOEncryption));
            MachOEncryption row{command.index,
                                type,
                                offset,
                                size,
                                static_cast<std::uint32_t>(field(16)),
                                type == 0x2c ? static_cast<std::uint32_t>(field(20)) : 0,
                                command.file_offset,
                                file};
            if (row.cryptid && row.size) {
                metadata.protections_complete = false;
                exclude(file, size, true);
            }
            metadata.encryption.push_back(row);
            continue;
        }
        budget.include(sizeof(MachOLinkeditDeclaration));
        MachOLinkeditDeclaration declaration{command.index, type, offset, size, file, metadata.data_in_code.size()};
        if (type == 0x1d) {
            if (size)
                metadata.protections_complete = false;
            declaration.first_row = 0;
            metadata.code_signatures.push_back(declaration);
            continue;
        }
        require(size % 8 == 0, "Mach-O data-in-code table has a partial record");
        budget.include(size + std::uint64_t(size / 8) * sizeof(MachODataInCode));
        const auto payload = reader.bytes(offset, size);
        const auto table = static_cast<std::uint32_t>(metadata.data_in_code_tables.size());
        metadata.data_in_code_tables.push_back(declaration);
        for (std::uint32_t index = 0; index < size / 8; ++index) {
            canceled(stop);
            const auto at = std::size_t(index) * 8;
            MachODataInCode row;
            row.table = table;
            row.index = index;
            row.record_file_offset = add(file.value, at);
            row.raw_offset = static_cast<std::uint32_t>(reader.value(payload.bytes, at, 4));
            row.length = static_cast<std::uint16_t>(reader.value(payload.bytes, at + 4, 2));
            row.kind = static_cast<std::uint16_t>(reader.value(payload.bytes, at + 6, 2));
            if (row.kind < 1 || row.kind > 5)
                metadata.protections_complete = false;
            if (slice.header.file_type == 1) {
                std::uint32_t matches = 0;
                const auto end = add(row.raw_offset, row.length);
                for (const auto &section : metadata.sections) {
                    canceled(stop);
                    require(work != 0, "Mach-O object protection mapping exceeds work budget",
                            ErrorCode::resource_limit);
                    --work;
                    const auto begin = std::max<std::uint64_t>(row.raw_offset, section.address);
                    const auto last = std::min(end, add(section.address, section.size));
                    if (!section.file_offset || begin >= last)
                        continue;
                    const Address at{{section.ordinal}, begin - section.address};
                    const auto *mapped = image.segment_at(at);
                    if (!mapped || at.offset - mapped->begin.offset > mapped->file_size ||
                        last - begin > mapped->file_size - (at.offset - mapped->begin.offset))
                        continue;
                    const auto file = take(image.to_file_offset(at));
                    if (!matches && begin == row.raw_offset && last == end)
                        row.offset = file;
                    else
                        row.offset.reset();
                    ++matches;
                    if (row.length) {
                        budget.include(sizeof(ImageCodeRange));
                        layout.code_exclusions.push_back({at, last - begin});
                    }
                }
                if ((matches != 1 || !row.offset) && row.length)
                    metadata.protections_complete = false;
            } else {
                row.offset = reader.file(row.raw_offset, row.length);
                exclude(*row.offset, row.length, false);
            }
            metadata.data_in_code.push_back(row);
        }
    }
}
} // namespace hexlab::macho_detail
