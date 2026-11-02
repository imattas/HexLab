#include "pe_internal.hpp"

namespace hexlab::pe_detail {
PeVolatileMetadata read_volatile_metadata(const Image &image, const ImageMetadata &metadata,
                                         std::uint64_t rva, std::stop_token stop) {
    PeVolatileMetadata result;
    try {
        ImageReader reader(image, metadata, stop);
        require(rva <= UINT32_MAX, "PE volatile metadata RVA exceeds 32 bits");
        result.rva = static_cast<std::uint32_t>(rva);
        result.declared_size = reader.integer<std::uint32_t>(rva);
        require(result.declared_size >= 24, "PE volatile metadata lacks its 24-byte header");
        require(result.declared_size <= 1024 * 1024,
                "PE volatile metadata header exceeds 1 MiB inspection budget", ErrorCode::resource_limit);
        const auto header = reader.bytes(rva, 24);
        const auto u32 = [&](std::size_t at) {
            std::uint32_t value = 0;
            for (unsigned i = 0; i < 4; ++i)
                value |= std::to_integer<std::uint32_t>(header[at + i]) << (8 * i);
            return value;
        };
        result.source = PeRecordSource{0, reader.sources(rva, 24)};
        result.version = u32(4);
        result.access_table_rva = u32(8);
        result.access_table_size = u32(12);
        result.range_table_rva = u32(16);
        result.range_table_size = u32(20);
        result.source = PeRecordSource{0, reader.sources(rva, result.declared_size)};
        require(result.version == 1, "PE volatile metadata version is unsupported", ErrorCode::unsupported);

        require(result.access_table_size % 4 == 0,
                "PE volatile access table ends inside a 4-byte RVA row");
        require(result.range_table_size % 8 == 0,
                "PE volatile range table ends inside an 8-byte range row");
        const auto table_bytes = std::uint64_t{result.access_table_size} + result.range_table_size;
        require(table_bytes <= 16 * 1024 * 1024,
                "PE volatile tables exceed 16 MiB inspection budget", ErrorCode::resource_limit);
        const auto access_count = result.access_table_size / 4;
        const auto range_count = result.range_table_size / 8;
        require(std::uint64_t{access_count} + range_count <= record_limit,
                "PE volatile tables exceed aggregate record budget", ErrorCode::resource_limit);
        if (result.access_table_size) {
            require(result.access_table_rva != 0, "PE volatile access table has a null RVA");
            result.access_table_source = PeRecordSource{
                0, reader.sources(result.access_table_rva, result.access_table_size)};
        }
        if (result.range_table_size) {
            require(result.range_table_rva != 0, "PE volatile range table has a null RVA");
            result.range_table_source = PeRecordSource{
                0, reader.sources(result.range_table_rva, result.range_table_size)};
        }

        std::size_t mapping_steps = 0;
        const auto validate_code = [&](std::uint32_t target_rva, std::uint32_t size) {
            require(size != 0, "PE volatile code range is empty");
            require(target_rva < metadata.image_size && size <= metadata.image_size - target_rva,
                    "PE volatile code extent exceeds image");
            std::uint64_t done = 0;
            while (done < size) {
                canceled(stop);
                require(mapping_steps < record_limit,
                        "PE volatile target validation exceeds mapping-step budget", ErrorCode::resource_limit);
                ++mapping_steps;
                const auto at = std::uint64_t{target_rva} + done;
                const auto *segment = image.segment_at(reader.address(at));
                require(segment && segment->executable,
                        "PE volatile target references unmapped or non-executable bytes");
                done += std::min<std::uint64_t>(size - done, reader.initialized_extent(at));
            }
        };
        std::vector<PeVolatileAccess> accesses;
        std::vector<PeVolatileRange> ranges;
        accesses.reserve(access_count);
        ranges.reserve(range_count);
        for (std::uint32_t i = 0; i < access_count; ++i) {
            canceled(stop);
            const auto row = std::uint64_t{result.access_table_rva} + std::uint64_t{i} * 4;
            const auto target = reader.integer<std::uint32_t>(row);
            validate_code(target, 1);
            accesses.push_back({target, PeRecordSource{i, reader.sources(row, 4)}});
        }
        for (std::uint32_t i = 0; i < range_count; ++i) {
            canceled(stop);
            const auto row = std::uint64_t{result.range_table_rva} + std::uint64_t{i} * 8;
            const auto target = reader.integer<std::uint32_t>(row);
            const auto size = reader.integer<std::uint32_t>(row + 4);
            validate_code(target, size);
            ranges.push_back({target, size, PeRecordSource{i, reader.sources(row, 8)}});
        }
        result.accesses = std::move(accesses);
        result.ranges = std::move(ranges);
        result.status = PeVolatileMetadataStatus::decoded;
    } catch (const Failure &failure) {
        if (failure.error.code == ErrorCode::canceled) throw;
        result.status = failure.error.code == ErrorCode::unsupported ? PeVolatileMetadataStatus::unsupported :
            failure.error.code == ErrorCode::resource_limit ? PeVolatileMetadataStatus::resource_limit :
            PeVolatileMetadataStatus::malformed;
        result.diagnostic = failure.error.message;
    }
    return result;
}
} // namespace hexlab::pe_detail
