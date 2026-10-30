#include "pe_internal.hpp"

namespace hexlab::pe_detail {
namespace {
constexpr std::uint64_t max_certificate_table_size = 64ull * 1024 * 1024;
}
Result<std::size_t> read_certificates(const Image& image, const Directory& directory,
                                      ImageMetadata& metadata, std::stop_token stop) {
    return guarded([&]() -> std::size_t {
        PeCertificateTable table;
        table.file_offset = {directory.location};
        table.size = directory.size;
        table.source = PeRecordSource{0, {{{directory.location}, directory.size}}};
        metadata.pe->certificate_table = std::move(table);
        auto &inventory = *metadata.pe->certificate_table;
        try {
            require(directory.file_offset, "PE certificate directory is not file-backed");
            require((directory.location & 7u) == 0,
                    "PE certificate table file offset is not 8-byte aligned");
            require((directory.size & 7u) == 0,
                    "PE certificate table size is not 8-byte aligned");
            require(directory.size <= max_certificate_table_size,
                    "PE certificate table exceeds the 64 MiB inspection limit", ErrorCode::resource_limit);
            const auto table_end = add(directory.location, directory.size, "certificate table extent");
            require(directory.size == 0 || directory.location >= metadata.header_size,
                    "PE certificate table overlaps mapped headers");
            for (const auto &section : metadata.sections) {
                if (!section.raw_size) continue;
                const auto section_end = add(section.raw_position.value, section.raw_size,
                                             "section raw extent for certificate overlap check");
                require(directory.size == 0 || table_end <= section.raw_position.value || directory.location >= section_end,
                        "PE certificate table overlaps section raw bytes");
            }
            FileReader reader(*image.storage());
            (void)reader.bytes(directory.location, directory.size, "certificate table");
        std::uint64_t cursor = 0;
        while (cursor < directory.size) {
            canceled(stop);
            require(inventory.records.size() < record_limit,
                    "PE certificate record count exceeds inspection budget",
                    ErrorCode::resource_limit);
            require(directory.size - cursor >= 8,
                    "Truncated PE WIN_CERTIFICATE header");
            const auto record_offset = add(directory.location, cursor, "certificate record offset");
            const auto length = reader.integer<std::uint32_t>(record_offset, "WIN_CERTIFICATE length");
            const auto revision = reader.integer<std::uint16_t>(record_offset + 4, "WIN_CERTIFICATE revision");
            const auto type = reader.integer<std::uint16_t>(record_offset + 6, "WIN_CERTIFICATE type");
            require(length >= 8, "WIN_CERTIFICATE length is smaller than its header");
            require(revision == 0x0100 || revision == 0x0200,
                    "Unsupported WIN_CERTIFICATE revision");
            require(type != 0, "WIN_CERTIFICATE type is zero");
            require(length <= directory.size - cursor,
                    "WIN_CERTIFICATE record exceeds certificate table");
            const auto aligned_length = add(length, 7, "certificate record alignment") & ~std::uint64_t{7};
            require(aligned_length <= directory.size - cursor,
                    "WIN_CERTIFICATE aligned extent exceeds certificate table");

            PeCertificateRecord record;
            record.length = length;
            record.revision = revision;
            record.type = type;
            record.source = PeRecordSource{static_cast<std::uint32_t>(inventory.records.size()),
                {{{record_offset}, length}}};
            if (length > 8)
                record.payload.push_back({{record_offset + 8}, length - 8});
            const auto padding_size = aligned_length - length;
            if (padding_size != 0) {
                const auto padding_offset = add(record_offset, length, "certificate alignment padding offset");
                const auto padding = reader.bytes(padding_offset, static_cast<std::size_t>(padding_size),
                                                  "certificate alignment padding");
                record.alignment_padding.push_back({{padding_offset}, padding_size});
                record.alignment_padding_nonzero = std::any_of(
                    padding.bytes.begin(), padding.bytes.end(),
                    [](std::byte value) { return value != std::byte{0}; });
            }
            inventory.records.push_back(std::move(record));
            cursor += aligned_length;
        }
        require(cursor == directory.size, "PE certificate table has trailing bytes");
        return inventory.records.size();
        } catch (const Failure &failure) {
            inventory.complete = false;
            inventory.diagnostic = failure.error.message;
            throw;
        }
    });
}
} // namespace hexlab::pe_detail
