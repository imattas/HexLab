#include "pe_internal.hpp"

namespace hexlab::pe_detail {
PeEnclaveConfiguration read_enclave_configuration(const Image &image, const ImageMetadata &metadata,
                                                  std::uint64_t rva, bool pe64, std::stop_token stop) {
    PeEnclaveConfiguration result;
    try {
        ImageReader reader(image, metadata, stop);
        require(rva <= UINT32_MAX, "PE enclave configuration RVA exceeds 32 bits");
        result.rva = static_cast<std::uint32_t>(rva);
        result.declared_size = reader.integer<std::uint32_t>(rva);
        require(result.declared_size >= 8, "PE enclave configuration lacks its size/version prefix");
        result.minimum_required_size = reader.integer<std::uint32_t>(rva + 4);
        const auto minimum = result.minimum_required_size ? result.minimum_required_size : 8u;
        require(minimum >= 8 && minimum <= result.declared_size,
                "PE enclave minimum required size is inconsistent with its declared size");
        constexpr std::uint32_t configuration_limit = 1024 * 1024;
        require(result.declared_size <= configuration_limit,
                "PE enclave configuration exceeds 1 MiB inspection budget", ErrorCode::resource_limit);
        result.source = PeRecordSource{0, reader.sources(rva, result.declared_size)};
        const std::uint32_t known_size = pe64 ? 80 : 76;
        require(minimum <= known_size,
                "PE enclave configuration requires an unsupported structure version", ErrorCode::unsupported);
        require(result.declared_size >= known_size,
                "PE enclave configuration has an unsupported short structure", ErrorCode::unsupported);
        // Read only the known prefix. Future optional tails and import-entry
        // extensions remain source-backed and are never allocated as payloads.
        const auto header = reader.bytes(rva, known_size);
        const auto u32 = [&](std::size_t at) {
            std::uint32_t value = 0;
            for (unsigned i = 0; i < 4; ++i)
                value |= std::to_integer<std::uint32_t>(header[at + i]) << (8 * i);
            return value;
        };
        result.policy_flags = u32(8);
        result.import_count = u32(12);
        result.import_list_rva = u32(16);
        result.import_entry_size = u32(20);
        std::copy_n(header.begin() + 24, 16, result.family_id.begin());
        std::copy_n(header.begin() + 40, 16, result.image_id.begin());
        result.image_version = u32(56);
        result.security_version = u32(60);
        result.enclave_size = u32(64);
        if (pe64) result.enclave_size |= std::uint64_t{u32(68)} << 32;
        result.thread_count = u32(pe64 ? 72 : 68);
        result.enclave_flags = u32(pe64 ? 76 : 72);
        constexpr std::uint32_t import_limit = 4096;
        constexpr std::uint64_t table_byte_limit = 16 * 1024 * 1024;
        constexpr std::uint64_t name_byte_limit = 1024 * 1024;
        constexpr std::uint64_t name_limit = 4096;
        require(result.import_count <= import_limit,
                "PE enclave imports exceed 4096-record inspection budget", ErrorCode::resource_limit);
        if (result.import_count) {
            require(result.import_list_rva != 0, "PE enclave import table has a null RVA");
            require(result.import_entry_size >= 80, "PE enclave import entry is shorter than its known layout");
            const auto table_size = std::uint64_t{result.import_count} * result.import_entry_size;
            require(table_size <= table_byte_limit,
                    "PE enclave import table exceeds 16 MiB inspection budget", ErrorCode::resource_limit);
            result.import_table_source = PeRecordSource{0, reader.sources(result.import_list_rva, table_size)};
            std::vector<PeEnclaveImport> imports;
            imports.reserve(result.import_count);
            std::uint64_t name_bytes = 0;
            for (std::uint32_t i = 0; i < result.import_count; ++i) {
                canceled(stop);
                const auto row = std::uint64_t{result.import_list_rva} + std::uint64_t{i} * result.import_entry_size;
                const auto bytes = reader.bytes(row, 80);
                const auto integer = [&](std::size_t at) {
                    std::uint32_t value = 0;
                    for (unsigned b = 0; b < 4; ++b)
                        value |= std::to_integer<std::uint32_t>(bytes[at + b]) << (8 * b);
                    return value;
                };
                PeEnclaveImport entry;
                entry.match_type = integer(0);
                entry.minimum_security_version = integer(4);
                std::copy_n(bytes.begin() + 8, 32, entry.unique_or_author_id.begin());
                std::copy_n(bytes.begin() + 40, 16, entry.family_id.begin());
                std::copy_n(bytes.begin() + 56, 16, entry.image_id.begin());
                entry.name_rva = integer(72);
                entry.reserved = integer(76);
                require(entry.name_rva != 0, "PE enclave import has a null name RVA");
                require(name_bytes < name_byte_limit,
                        "PE enclave import names exceed 1 MiB inspection budget", ErrorCode::resource_limit);
                const auto remaining = std::min(name_limit, name_byte_limit - name_bytes);
                entry.name = reader.string(entry.name_rva, std::uint64_t{entry.name_rva} + remaining);
                require(!entry.name.empty(), "PE enclave import name is empty");
                name_bytes += entry.name.size() + 1;
                entry.source = PeRecordSource{i, reader.sources(row, result.import_entry_size)};
                entry.name_source = PeRecordSource{i, reader.sources(entry.name_rva, entry.name.size() + 1)};
                imports.push_back(std::move(entry));
            }
            result.imports = std::move(imports);
        }
        result.status = PeEnclaveConfigurationStatus::decoded;
    } catch (const Failure &failure) {
        // Optional enclave metadata must not discard other load-config fields.
        // Cancellation still aborts the caller rather than becoming metadata.
        if (failure.error.code == ErrorCode::canceled) throw;
        result.status = failure.error.code == ErrorCode::unsupported ? PeEnclaveConfigurationStatus::unsupported :
            failure.error.code == ErrorCode::resource_limit ? PeEnclaveConfigurationStatus::resource_limit :
            PeEnclaveConfigurationStatus::malformed;
        result.diagnostic = failure.error.message;
    }
    return result;
}
} // namespace hexlab::pe_detail
