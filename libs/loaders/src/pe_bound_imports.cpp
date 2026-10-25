#include "pe_internal.hpp"
#include <iterator>

namespace hexlab::pe_detail {
Result<std::size_t> read_bound_imports(const Image &image, const Directory &directory,
                                      ImageMetadata &metadata, std::stop_token stop) {
    return guarded([&]() -> std::size_t {
        ImageReader r(image, metadata, stop);
        constexpr std::uint64_t descriptor_size = 8;
        require(directory.size >= descriptor_size, "Bound import directory is shorter than a descriptor");
        const auto directory_end = add(directory.location, directory.size, "bound import directory end");
        std::uint64_t cursor = 0;
        std::uint32_t descriptor_index = 0;
        std::size_t records_used = 0;
        bool terminated = false;
        std::vector<PeBoundImport> imports;

        const auto read_name = [&](std::uint16_t relative_offset) {
            require(relative_offset != 0, "Bound import record lacks a module name offset");
            const auto name_rva = add(directory.location, relative_offset, "bound import module-name RVA");
            require(name_rva < directory_end, "Bound import module-name offset exceeds directory");
            auto name = r.string(name_rva, directory_end);
            require(!name.empty(), "Bound import module name is empty");
            auto source = r.sources(name_rva, name.size() + 1);
            return std::pair<std::string, std::vector<PeSourceSpan>>{std::move(name), std::move(source)};
        };

        while (cursor <= directory.size && descriptor_size <= directory.size - cursor) {
            canceled(stop);
            const auto descriptor_rva = add(directory.location, cursor, "bound import descriptor RVA");
            const auto timestamp = r.integer<std::uint32_t>(descriptor_rva);
            const auto name_offset = r.integer<std::uint16_t>(descriptor_rva + 4);
            const auto forwarder_count = r.integer<std::uint16_t>(descriptor_rva + 6);
            cursor += descriptor_size;
            if (timestamp == 0 && name_offset == 0 && forwarder_count == 0) {
                terminated = true;
                break;
            }
            require(descriptor_index < record_limit, "Bound import record budget reached", ErrorCode::resource_limit);
            auto [library, library_source] = read_name(name_offset);
            PeBoundImport bound;
            bound.timestamp = timestamp;
            bound.library = std::move(library);
            bound.descriptor = {descriptor_index, r.sources(descriptor_rva, descriptor_size)};
            bound.library_name = std::move(library_source);
            require(records_used < record_limit, "Bound import record budget reached", ErrorCode::resource_limit);
            require(forwarder_count <= record_limit - records_used - 1,
                    "Bound forwarder record budget reached", ErrorCode::resource_limit);
            records_used += static_cast<std::size_t>(forwarder_count) + 1;
            bound.forwarders.reserve(forwarder_count);
            for (std::uint32_t i = 0; i < forwarder_count; ++i) {
                canceled(stop);
                require(cursor <= directory.size && descriptor_size <= directory.size - cursor,
                        "Bound forwarder-reference array exceeds directory");
                const auto forwarder_rva = add(directory.location, cursor, "bound forwarder RVA");
                const auto forwarder_timestamp = r.integer<std::uint32_t>(forwarder_rva);
                const auto forwarder_name_offset = r.integer<std::uint16_t>(forwarder_rva + 4);
                const auto reserved = r.integer<std::uint16_t>(forwarder_rva + 6);
                require(reserved == 0, "Bound forwarder reserved field is nonzero");
                auto [forwarder_name, forwarder_source] = read_name(forwarder_name_offset);
                PeBoundImportForwarder forwarder;
                forwarder.timestamp = forwarder_timestamp;
                forwarder.library = std::move(forwarder_name);
                forwarder.descriptor = {i, r.sources(forwarder_rva, descriptor_size)};
                forwarder.library_name = std::move(forwarder_source);
                bound.forwarders.push_back(std::move(forwarder));
                cursor += descriptor_size;
            }
            imports.push_back(std::move(bound));
            ++descriptor_index;
        }
        require(terminated, "Bound import descriptor table lacks a directory-bounded terminator");
        const auto count = imports.size();
        if (!metadata.pe) metadata.pe.emplace();
        metadata.pe->bound_imports.insert(metadata.pe->bound_imports.end(),
                                          std::make_move_iterator(imports.begin()),
                                          std::make_move_iterator(imports.end()));
        return count;
    });
}
} // namespace hexlab::pe_detail
