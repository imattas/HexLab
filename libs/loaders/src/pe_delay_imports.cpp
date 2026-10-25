#include "pe_internal.hpp"
#include <iterator>

namespace hexlab::pe_detail {
namespace {
std::uint32_t address_rva(std::uint32_t raw, bool rva_mode, const ImageMetadata &metadata) {
    if (rva_mode) return raw;
    require(std::uint64_t{raw} >= metadata.preferred_base,
            "Delay import VA precedes the preferred image base");
    const auto rva = std::uint64_t{raw} - metadata.preferred_base;
    require(rva <= UINT32_MAX, "Delay import VA does not map to a 32-bit RVA");
    return static_cast<std::uint32_t>(rva);
}
}

Result<std::size_t> read_delay_imports(const Image &image, const Directory &directory, bool pe64,
                                      ImageMetadata &metadata, std::stop_token stop) {
    return guarded([&]() -> std::size_t {
        ImageReader r(image, metadata, stop);
        require(directory.size >= 32, "Delay import directory is shorter than a descriptor");
        std::vector<ImportSymbol> imports;
        std::vector<PeImportSource> provenance;
        const std::uint64_t width = pe64 ? 8 : 4;
        const std::uint64_t ordinal_bit = pe64 ? (std::uint64_t{1} << 63) : (std::uint64_t{1} << 31);
        bool terminated = false;

        for (std::uint64_t offset = 0; offset + 32 <= directory.size; offset += 32) {
            canceled(stop);
            const auto at = std::uint64_t{directory.location} + offset;
            const auto attributes = r.integer<std::uint32_t>(at);
            const auto name_field = r.integer<std::uint32_t>(at + 4);
            const auto module_handle = r.integer<std::uint32_t>(at + 8);
            const auto iat_field = r.integer<std::uint32_t>(at + 12);
            const auto int_field = r.integer<std::uint32_t>(at + 16);
            const auto bound_iat = r.integer<std::uint32_t>(at + 20);
            const auto unload_iat = r.integer<std::uint32_t>(at + 24);
            const auto timestamp = r.integer<std::uint32_t>(at + 28);
            if (!(attributes | name_field | module_handle | iat_field | int_field | bound_iat | unload_iat | timestamp)) {
                terminated = true;
                break;
            }

            // IMAGE_DELAYLOAD_DESCRIPTOR only defines bit zero (RVA mode).
            require((attributes & ~1u) == 0, "Delay import descriptor has reserved attribute bits set");
            const bool rva_mode = (attributes & 1u) != 0;
            require(name_field != 0 && iat_field != 0,
                    "Delay import descriptor lacks library name or IAT");
            const auto name = address_rva(name_field, rva_mode, metadata);
            const auto iat = address_rva(iat_field, rva_mode, metadata);
            const auto lookup = int_field ? address_rva(int_field, rva_mode, metadata) : iat;
            // Validate optional table pointers when present. Their contents are not needed
            // to enumerate imported symbols, but malformed descriptor pointers should not
            // be silently accepted.
            if (module_handle) (void)r.address(address_rva(module_handle, rva_mode, metadata));
            if (bound_iat) (void)r.address(address_rva(bound_iat, rva_mode, metadata));
            if (unload_iat) (void)r.address(address_rva(unload_iat, rva_mode, metadata));

            auto [library, library_source] = r.sourced_string(name);
            require(!library.empty(), "Empty delay import library name");
            (void)r.initialized_extent(lookup);
            const auto capacity = std::min<std::uint64_t>(record_limit, (metadata.image_size - lookup) / width);
            bool thunk_end = false;
            for (std::uint64_t index = 0; index < capacity; ++index) {
                canceled(stop);
                const auto thunk_at = lookup + index * width;
                const auto iat_at = iat + index * width;
                const auto value = pe64 ? r.integer<std::uint64_t>(thunk_at) : r.integer<std::uint32_t>(thunk_at);
                if (!value) { thunk_end = true; break; }
                (void)r.bytes(iat_at, static_cast<std::size_t>(width));
                ImportSymbol symbol{library, {}, {}, r.address(thunk_at), r.address(iat_at), true};
                PeImportSource source;
                source.descriptor = {static_cast<std::uint32_t>(offset / 32), r.sources(at, 32)};
                source.delay_load = true;
                source.lookup_thunk = r.sources(thunk_at, width);
                source.iat_thunk = r.sources(iat_at, width);
                source.library_name = library_source;
                if (value & ordinal_bit) {
                    require((value & ~(ordinal_bit | 0xffffULL)) == 0,
                            "Delay import ordinal thunk has reserved bits set");
                    symbol.ordinal = static_cast<std::uint16_t>(value & 0xffff);
                } else {
                    require(value <= UINT32_MAX, "Delay import name thunk is not a 32-bit address");
                    const auto hint_name = address_rva(static_cast<std::uint32_t>(value), rva_mode, metadata);
                    (void)r.integer<std::uint16_t>(hint_name);
                    auto [symbol_name, symbol_source] = r.sourced_string(std::uint64_t{hint_name} + 2);
                    require(!symbol_name.empty(), "Empty delay imported symbol name");
                    symbol.name = std::move(symbol_name);
                    source.symbol_name = std::move(symbol_source);
                }
                if (imports.size() >= record_limit)
                    throw Failure{{ErrorCode::resource_limit, "Delay import record budget reached"}};
                imports.push_back(std::move(symbol));
                provenance.push_back(std::move(source));
            }
            require(thunk_end, "Delay import thunk table lacks a bounded terminator");
        }
        require(terminated, "Delay import descriptor table lacks a directory-bounded terminator");
        const auto count = imports.size();
        metadata.imports.insert(metadata.imports.end(), std::make_move_iterator(imports.begin()),
                                std::make_move_iterator(imports.end()));
        if (!metadata.pe) metadata.pe.emplace();
        metadata.pe->imports.insert(metadata.pe->imports.end(), std::make_move_iterator(provenance.begin()),
                                    std::make_move_iterator(provenance.end()));
        return count;
    });
}
}
