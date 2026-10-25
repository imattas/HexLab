#include "pe_internal.hpp"

namespace hexlab::pe_detail {
Result<std::size_t> read_chpe_metadata(const Image &image, const Directory &directory, bool pe64,
                                       ImageMetadata &metadata, std::stop_token stop) {
    return guarded([&]() -> std::size_t {
        ImageReader reader(image, metadata, stop);
        require(directory.size >= 4, "Truncated PE load-configuration size field");
        const auto declared = reader.integer<std::uint32_t>(directory.location);
        require(declared >= 4 && declared <= directory.size,
                "Invalid PE load-configuration declared size");

        // IMAGE_LOAD_CONFIG_DIRECTORY32::CHPEMetadataPointer is at 124;
        // IMAGE_LOAD_CONFIG_DIRECTORY64::CHPEMetadataPointer is at 200.
        const std::uint64_t pointer_offset = pe64 ? 200 : 124;
        const std::uint64_t pointer_width = pe64 ? 8 : 4;
        if (declared < pointer_offset + pointer_width)
            return 0;
        const auto pointer_va = pe64 ? reader.integer<std::uint64_t>(directory.location + pointer_offset)
                                     : reader.integer<std::uint32_t>(directory.location + pointer_offset);
        if (!pointer_va)
            return 0;
        require(pe64, "PE CHPE metadata requires a PE32+ image", ErrorCode::unsupported);
        require(pointer_va >= metadata.preferred_base,
                "PE CHPE metadata pointer precedes the preferred image base");
        const auto metadata_rva64 = pointer_va - metadata.preferred_base;
        require(metadata_rva64 < metadata.image_size && metadata_rva64 <= UINT32_MAX,
                "PE CHPE metadata pointer exceeds the image");
        const auto metadata_rva = static_cast<std::uint32_t>(metadata_rva64);
        (void)reader.sources(metadata_rva, 12);
        const auto version = reader.integer<std::uint32_t>(metadata_rva);
        require(version == 1 || version == 2,
                "Unsupported PE CHPE metadata version", ErrorCode::unsupported);
        const std::uint32_t header_size = version == 1 ? 80u : 92u;
        (void)reader.sources(metadata_rva, header_size);

        PeChpeMetadata chpe;
        chpe.version = version;
        chpe.metadata_rva = metadata_rva;
        chpe.source = PeRecordSource{0, reader.sources(metadata_rva, header_size)};
        chpe.code_map_rva = reader.integer<std::uint32_t>(metadata_rva + 4);
        chpe.code_map_count = reader.integer<std::uint32_t>(metadata_rva + 8);
        require((chpe.code_map_rva == 0) == (chpe.code_map_count == 0),
                "Inconsistent PE CHPE code-map RVA and count");
        if (chpe.code_map_count) {
            constexpr std::uint64_t range_size = 8;
            reader.array(chpe.code_map_rva, chpe.code_map_count, range_size);
            const auto table_bytes = std::uint64_t{chpe.code_map_count} * range_size;
            chpe.code_map_source = PeRecordSource{0, reader.sources(chpe.code_map_rva, table_bytes)};
            chpe.code_ranges.reserve(chpe.code_map_count);
            std::uint64_t previous_end = 0;
            bool first = true;
            for (std::uint32_t index = 0; index < chpe.code_map_count; ++index) {
                canceled(stop);
                const auto row_rva = std::uint64_t{chpe.code_map_rva} + std::uint64_t{index} * range_size;
                const auto tagged_start = reader.integer<std::uint32_t>(row_rva);
                const auto length = reader.integer<std::uint32_t>(row_rva + 4);
                const auto start = tagged_start & ~std::uint32_t{3};
                const auto kind_tag = tagged_start & 3u;
                require(length != 0, "PE CHPE code map contains an empty range");
                const auto end = checked_add(start, length);
                require(end && end.value() <= metadata.image_size,
                        "PE CHPE code range exceeds the image");
                require(first || start >= previous_end,
                        "PE CHPE code map ranges are unsorted or overlapping");
                const auto target = reader.address(start);
                const auto *segment = image.segment_at(target);
                require(segment && segment->executable,
                        "PE CHPE code range does not map to executable bytes");
                std::uint64_t range_cursor = start;
                std::uint64_t range_remaining = length;
                while (range_remaining) {
                    const auto range_address = reader.address(range_cursor);
                    const auto *range_segment = image.segment_at(range_address);
                    require(range_segment && range_segment->executable,
                            "PE CHPE code range crosses non-executable or unmapped bytes");
                    const auto within_segment = range_address.offset - range_segment->begin.offset;
                    require(within_segment < range_segment->file_size,
                            "PE CHPE code range includes uninitialized bytes");
                    const auto backed = std::min<std::uint64_t>(range_remaining,
                        range_segment->file_size - within_segment);
                    require(backed != 0, "PE CHPE code range includes uninitialized bytes");
                    range_cursor += backed;
                    range_remaining -= backed;
                }
                PeChpeCodeRange range;
                range.start_rva = start;
                range.length = length;
                switch (kind_tag) {
                case 0: range.kind = PeChpeCodeRangeKind::arm64; break;
                case 1: range.kind = PeChpeCodeRangeKind::arm64ec; break;
                case 2: range.kind = PeChpeCodeRangeKind::amd64; break;
                default:
                    throw Failure{{ErrorCode::unsupported,
                                   "PE CHPE code map has a reserved range type"}};
                }
                range.source = PeRecordSource{index, reader.sources(row_rva, range_size)};
                chpe.code_ranges.push_back(std::move(range));
                previous_end = end.value();
                first = false;
            }
        }
        if (!metadata.pe || !metadata.pe->load_configuration)
            throw Failure{{ErrorCode::malformed,
                           "PE CHPE metadata was found without a parsed load configuration"}};
        metadata.pe->load_configuration->chpe_metadata = std::move(chpe);
        return 1;
    });
}
} // namespace hexlab::pe_detail
