#include "hexlab/firmware/intel_microcode.hpp"
#include <new>

namespace hexlab::firmware {
namespace {
std::uint32_t u32(std::span<const std::byte> bytes, std::size_t at) {
    return std::uint32_t(std::to_integer<std::uint8_t>(bytes[at])) |
        (std::uint32_t(std::to_integer<std::uint8_t>(bytes[at + 1])) << 8) |
        (std::uint32_t(std::to_integer<std::uint8_t>(bytes[at + 2])) << 16) |
        (std::uint32_t(std::to_integer<std::uint8_t>(bytes[at + 3])) << 24);
}
std::uint32_t dword_sum(std::span<const std::byte> bytes) {
    std::uint32_t sum = 0;
    for (std::size_t at = 0; at < bytes.size(); at += 4) sum += u32(bytes, at);
    return sum;
}
}

Result<IntelMicrocodeUpdate> parse_intel_microcode_update(std::span<const std::byte> bytes,
        std::uint64_t file_offset, std::stop_token stop, IntelMicrocodeLimits limits) {
    constexpr std::uint32_t header_bytes = 48;
    constexpr std::uint32_t legacy_data_bytes = 2000;
    constexpr std::uint32_t legacy_total_bytes = 2048;
    constexpr std::uint32_t extension_header_bytes = 20;
    constexpr std::uint32_t extension_row_bytes = 12;
    if (!limits.max_input_bytes || limits.max_update_bytes < legacy_total_bytes ||
        !limits.max_extended_signatures)
        return Error{ErrorCode::invalid_argument, "Intel microcode limits are invalid"};
    if (bytes.size() > limits.max_input_bytes)
        return Error{ErrorCode::resource_limit, "Intel microcode input exceeds configured byte limit"};
    if (stop.stop_requested()) return Error{ErrorCode::canceled, "Intel microcode parsing canceled"};
    if (file_offset > bytes.size() || bytes.size() - static_cast<std::size_t>(file_offset) < header_bytes)
        return Error{ErrorCode::malformed, "Truncated Intel microcode header"};
    const auto input = bytes.subspan(static_cast<std::size_t>(file_offset));
    if (u32(input, 0) != 1)
        return Error{ErrorCode::malformed, "Unsupported Intel microcode header version"};
    const auto data_size = u32(input, 28);
    const auto total_size = u32(input, 32);
    const auto effective_data_size = data_size ? data_size : legacy_data_bytes;
    const auto effective_total_size = total_size ? total_size : legacy_total_bytes;
    if (effective_total_size < header_bytes || (effective_total_size & 1023u) ||
        (effective_data_size & 3u) ||
        effective_data_size > effective_total_size - header_bytes)
        return Error{ErrorCode::malformed, "Intel microcode data and total sizes are inconsistent or unaligned"};
    if (effective_total_size > limits.max_update_bytes)
        return Error{ErrorCode::resource_limit, "Intel microcode update exceeds configured byte limit"};
    if (effective_total_size > input.size())
        return Error{ErrorCode::malformed, "Intel microcode update exceeds supplied input"};
    const auto extension_at = header_bytes + effective_data_size;
    const auto extension_size = effective_total_size - extension_at;
    if (extension_size && (extension_size < extension_header_bytes ||
        (extension_size - extension_header_bytes) % extension_row_bytes))
        return Error{ErrorCode::malformed, "Intel microcode extension table has an invalid size"};
    const auto update = input.first(effective_total_size);
    try {
        IntelMicrocodeUpdate result;
        result.file_offset = file_offset;
        result.update_revision = u32(input, 4);
        result.date = u32(input, 8);
        result.processor_signature = u32(input, 12);
        result.checksum = u32(input, 16);
        result.loader_revision = u32(input, 20);
        result.processor_flags = u32(input, 24);
        result.data_size = data_size;
        result.total_size = total_size;
        result.effective_data_size = effective_data_size;
        result.effective_total_size = effective_total_size;
        result.reserved_fields_zero = u32(input, 36) == 0 && u32(input, 40) == 0 && u32(input, 44) == 0;
        result.base_checksum_valid = dword_sum(update.first(extension_at)) == 0;
        result.extension_table_present = extension_size != 0;
        if (extension_size) {
            const auto table = update.subspan(extension_at, extension_size);
            const auto count = u32(table, 0);
            const auto available = (extension_size - extension_header_bytes) / extension_row_bytes;
            if (count != available)
                return Error{ErrorCode::malformed, "Intel microcode extension count does not match table size"};
            if (count > limits.max_extended_signatures)
                return Error{ErrorCode::resource_limit, "Intel microcode extension count exceeds configured limit"};
            if (stop.stop_requested()) return Error{ErrorCode::canceled, "Intel microcode parsing canceled"};
            result.extension_reserved_fields_zero = u32(table, 8) == 0 &&
                u32(table, 12) == 0 && u32(table, 16) == 0;
            result.extension_table_checksum_valid = dword_sum(table) == 0;
            result.extended_signatures.reserve(count);
            for (std::uint32_t i = 0; i < count; ++i) {
                if ((i & 0xfffu) == 0 && stop.stop_requested())
                    return Error{ErrorCode::canceled, "Intel microcode parsing canceled"};
                const auto at = extension_header_bytes + std::size_t(i) * extension_row_bytes;
                IntelMicrocodeSignature signature;
                signature.file_offset = file_offset + extension_at + at;
                signature.processor_signature = u32(table, at);
                signature.processor_flags = u32(table, at + 4);
                signature.checksum = u32(table, at + 8);
                signature.checksum_valid = static_cast<std::uint32_t>(
                    (result.processor_signature + result.processor_flags + result.checksum) -
                    (signature.processor_signature + signature.processor_flags + signature.checksum)) == 0;
                result.extended_signatures.push_back(signature);
            }
        }
        return result;
    } catch (const std::bad_alloc &) {
        return Error{ErrorCode::resource_limit, "Cannot allocate Intel microcode signature inventory"};
    }
}
} // namespace hexlab::firmware
