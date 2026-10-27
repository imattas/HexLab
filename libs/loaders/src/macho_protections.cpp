#include "macho_internal.hpp"
#include <algorithm>
#include <utility>
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
            declaration.first_row = 0;
            if (size) {
                // Signature parsing is deliberately bounded independently of
                // the file extent so a large CMS payload cannot consume the
                // loader's entire metadata budget.
                constexpr std::uint32_t signature_parse_limit = 16 * 1024 * 1024;
                if (size > signature_parse_limit) {
                    metadata.protections_complete = false;
                } else {
                    budget.include(size);
                    const auto payload = reader.bytes(offset, size);
                    const auto be32 = [&](std::size_t at) {
                        require(at <= payload.bytes.size() && 4 <= payload.bytes.size() - at,
                                "Truncated Mach-O code-signing blob scalar");
                        return (std::to_integer<std::uint32_t>(payload.bytes[at]) << 24) |
                               (std::to_integer<std::uint32_t>(payload.bytes[at + 1]) << 16) |
                               (std::to_integer<std::uint32_t>(payload.bytes[at + 2]) << 8) |
                               std::to_integer<std::uint32_t>(payload.bytes[at + 3]);
                    };
                    constexpr std::uint32_t superblob_magic = 0xfade0cc0;
                    constexpr std::uint32_t code_directory_magic = 0xfade0c02;
                    if (size < 12 || be32(0) != superblob_magic) {
                        metadata.protections_complete = false;
                    } else {
                        const auto declared_size = be32(4);
                        const auto count = be32(8);
                        require(declared_size >= 12 && declared_size <= size,
                                "Mach-O code-signing SuperBlob length exceeds its declaration");
                        require(count <= 4096 && count <= (declared_size - 12) / 8,
                                "Mach-O code-signing SuperBlob index count exceeds bounds", ErrorCode::resource_limit);
                        const auto index_end = std::uint64_t{12} + std::uint64_t(count) * 8;
                        if (declared_size != size)
                            metadata.protections_complete = false;
                        budget.include(std::uint64_t(count) * sizeof(MachOCodeSignatureBlob));
                        std::vector<std::pair<std::uint64_t, std::uint64_t>> blob_ranges;
                        blob_ranges.reserve(count);
                        for (std::uint32_t index = 0; index < count; ++index) {
                            canceled(stop);
                            const auto at = std::size_t{12} + std::size_t(index) * 8;
                            MachOCodeSignatureBlob blob;
                            blob.signature = static_cast<std::uint32_t>(metadata.code_signatures.size());
                            blob.index = index;
                            blob.slot_type = be32(at);
                            blob.raw_offset = be32(at + 4);
                            require(blob.raw_offset >= index_end && blob.raw_offset <= declared_size &&
                                        8 <= declared_size - blob.raw_offset,
                                    "Mach-O code-signing blob header overlaps index or exceeds SuperBlob");
                            blob.magic = be32(static_cast<std::size_t>(blob.raw_offset));
                            blob.size = be32(static_cast<std::size_t>(blob.raw_offset) + 4);
                            require(blob.size >= 8 && blob.size <= declared_size - blob.raw_offset,
                                    "Mach-O code-signing blob exceeds SuperBlob");
                            blob.record_file_offset = add(file.value, blob.raw_offset);
                            blob_ranges.emplace_back(blob.raw_offset, blob.raw_offset + blob.size);
                            if (blob.magic == code_directory_magic) {
                                require(blob.size >= 44, "Truncated Mach-O CodeDirectory header");
                                const auto base = static_cast<std::size_t>(blob.raw_offset);
                                blob.code_directory = true;
                                blob.code_directory_version = be32(base + 8);
                                blob.code_directory_flags = be32(base + 12);
                                blob.code_limit = be32(base + 32);
                                blob.code_slots = be32(base + 28);
                                blob.hash_size = std::to_integer<std::uint8_t>(payload.bytes[base + 36]);
                                blob.hash_type = std::to_integer<std::uint8_t>(payload.bytes[base + 37]);
                                blob.platform = std::to_integer<std::uint8_t>(payload.bytes[base + 38]);
                                blob.page_size_exponent = std::to_integer<std::uint8_t>(payload.bytes[base + 39]);
                            } else {
                                metadata.protections_complete = false;
                            }
                            metadata.code_signature_blobs.push_back(std::move(blob));
                        }
                        std::sort(blob_ranges.begin(), blob_ranges.end());
                        for (std::size_t index = 1; index < blob_ranges.size(); ++index)
                            if (blob_ranges[index - 1].second > blob_ranges[index].first)
                                metadata.protections_complete = false;
                    }
                }
            }
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
