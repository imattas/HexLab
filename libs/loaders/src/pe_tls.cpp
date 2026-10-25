#include "pe_internal.hpp"

namespace hexlab::pe_detail {
Result<std::size_t> read_tls(const Image& image, const Directory& directory, bool pe64,
                             ImageMetadata& metadata, std::stop_token stop) {
    return guarded([&]() -> std::size_t {
        ImageReader reader(image, metadata, stop);
        const std::size_t width = pe64 ? 8 : 4;
        const std::size_t size = pe64 ? 40 : 24;
        require(directory.size >= size, "Truncated PE TLS directory");
        const auto data = reader.bytes(directory.location, size);
        const auto get = [&](std::size_t offset, std::size_t n) {
            std::uint64_t value = 0;
            for (std::size_t i = 0; i < n; ++i)
                value |= std::to_integer<std::uint64_t>(data[offset + i]) << (8 * i);
            return value;
        };
        const auto rva = [&](std::uint64_t va, bool allow_end, const char* field) {
            require(va >= metadata.preferred_base, std::string("PE TLS ") + field + " precedes image base");
            const auto offset = va - metadata.preferred_base;
            require(allow_end ? offset <= metadata.image_size : offset < metadata.image_size,
                    std::string("PE TLS ") + field + " exceeds image");
            return offset;
        };
        const auto start_va = get(0, width);
        const auto end_va = get(width, width);
        const auto index_va = get(width * 2, width);
        const auto callbacks_va = get(width * 3, width);
        const auto zero_fill = static_cast<std::uint32_t>(get(width * 4, 4));
        const auto characteristics = static_cast<std::uint32_t>(get(width * 4 + 4, 4));
        PeTlsDirectory tls;
        tls.zero_fill = zero_fill;
        tls.characteristics = characteristics;
        tls.directory = {0, reader.sources(directory.location, size)};

        require((start_va == 0) == (end_va == 0), "PE TLS template has only one endpoint");
        if (start_va) {
            tls.template_rva = rva(start_va, false, "template start");
            const auto end_rva = rva(end_va, true, "template end");
            require(end_rva >= tls.template_rva, "PE TLS template end precedes start");
            tls.template_size = end_rva - tls.template_rva;
            if (tls.template_size)
                (void)reader.sources(tls.template_rva, tls.template_size);
        }
        if (index_va) {
            tls.index_rva = rva(index_va, false, "index address");
            (void)reader.sources(tls.index_rva, 4);
        }
        if (callbacks_va) {
            tls.callbacks_rva = rva(callbacks_va, false, "callback array");
            for (std::size_t index = 0; index < record_limit; ++index) {
                canceled(stop);
                const auto slot = add(tls.callbacks_rva, std::uint64_t{index} * width, "TLS callback slot");
                const auto encoded = reader.bytes(slot, width);
                std::uint64_t bounded = 0;
                for (std::size_t byte = 0; byte < width; ++byte)
                    bounded |= std::to_integer<std::uint64_t>(encoded[byte]) << (8 * byte);
                const auto provenance = reader.sources(slot, width);
                if (!bounded) {
                    tls.callback_terminator = PeRecordSource{static_cast<std::uint32_t>(index), provenance};
                    break;
                }
                const auto callback_rva = rva(bounded, false, "callback target");
                const auto callback = reader.address(callback_rva);
                const auto* segment = image.segment_at(callback);
                require(segment && segment->executable && reader.initialized_extent(callback_rva),
                        "PE TLS callback does not point to initialized executable bytes");
                tls.callbacks.push_back({callback_rva, {static_cast<std::uint32_t>(index), provenance}});
            }
            require(tls.callback_terminator.has_value(), "PE TLS callback array has no bounded terminator",
                    ErrorCode::resource_limit);
        }
        metadata.pe->tls = std::move(tls);
        return 1;
    });
}
} // namespace hexlab::pe_detail
