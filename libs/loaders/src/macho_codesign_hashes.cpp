#include "hexlab/loaders/macho.hpp"
#include "hexlab/core/sha256.hpp"
#include <algorithm>
#include <limits>

namespace hexlab {
namespace {
std::uint32_t be32(std::span<const std::byte> bytes, std::size_t offset) {
    return (std::to_integer<std::uint32_t>(bytes[offset]) << 24) |
           (std::to_integer<std::uint32_t>(bytes[offset + 1]) << 16) |
           (std::to_integer<std::uint32_t>(bytes[offset + 2]) << 8) |
           std::to_integer<std::uint32_t>(bytes[offset + 3]);
}
}

Result<MachOCodeDirectoryHashVerification> verify_macho_code_directory_hashes(
        const Image &image, const ImageMetadata &metadata, std::uint32_t signature_index,
        std::uint32_t blob_index, std::stop_token stop, MachOCodeDirectoryHashLimits limits) {
    constexpr std::uint64_t max_page_bytes = 16ULL * 1024 * 1024;
    if (!limits.max_code_bytes || !limits.max_code_slots || limits.max_code_slots > 4'000'000 ||
        limits.max_retained_mismatches > 4096)
        return Error{ErrorCode::invalid_argument, "Mach-O CodeDirectory hash limits are invalid"};
    if (!metadata.macho || !image.storage())
        return Error{ErrorCode::invalid_argument, "Mach-O image metadata or original storage is unavailable"};
    const auto &macho = *metadata.macho;
    if (macho.selected_slice >= macho.container.slices.size())
        return Error{ErrorCode::malformed, "Mach-O selected slice index is invalid"};
    if (signature_index >= macho.code_signatures.size())
        return Error{ErrorCode::out_of_bounds, "Mach-O code-signature index is out of range"};
    const auto blob = std::find_if(macho.code_signature_blobs.begin(), macho.code_signature_blobs.end(),
        [&](const MachOCodeSignatureBlob &row) {
            return row.signature == signature_index && row.index == blob_index;
        });
    if (blob == macho.code_signature_blobs.end() || !blob->code_directory)
        return Error{ErrorCode::out_of_bounds, "Selected Mach-O blob is not an inventoried CodeDirectory"};
    if (blob->size < 44 || blob->record_file_offset > image.storage()->size() ||
        blob->size > image.storage()->size() - blob->record_file_offset)
        return Error{ErrorCode::malformed, "Mach-O CodeDirectory blob exceeds original storage"};
    if (stop.stop_requested()) return Error{ErrorCode::canceled, "Mach-O CodeDirectory verification canceled"};
    auto directory_read = image.storage()->read_at({blob->record_file_offset}, blob->size);
    if (!directory_read) return directory_read.error();
    const auto directory = std::span<const std::byte>(directory_read.value().bytes);
    if (directory.size() != blob->size || be32(directory, 0) != 0xfade0c02 || be32(directory, 4) != blob->size)
        return Error{ErrorCode::malformed, "Mach-O CodeDirectory header or length is inconsistent"};
    const auto version = be32(directory, 8);
    if (version < 0x20001 || version > 0x20100)
        return Error{ErrorCode::unsupported, "Mach-O CodeDirectory version uses unsupported extended fields"};
    if (version >= 0x20100 && blob->size < 52)
        return Error{ErrorCode::malformed, "Mach-O CodeDirectory is truncated before teamOffset"};
    const auto hash_offset = be32(directory, 16);
    const auto special_slots = be32(directory, 24);
    const auto code_slots = be32(directory, 28);
    const auto code_limit = be32(directory, 32);
    const auto hash_size = std::to_integer<std::uint8_t>(directory[36]);
    const auto hash_type = std::to_integer<std::uint8_t>(directory[37]);
    const auto page_exponent = std::to_integer<std::uint8_t>(directory[39]);
    if (!((hash_type == 2 && hash_size == 32) || (hash_type == 3 && hash_size == 20)))
        return Error{ErrorCode::unsupported, "Mach-O CodeDirectory hash type is not SHA-256 or truncated SHA-256"};
    if (page_exponent == 0 || page_exponent > 24)
        return Error{ErrorCode::unsupported, "Mach-O CodeDirectory page size is outside the supported bound"};
    const std::uint64_t page_size = UINT64_C(1) << page_exponent;
    if (page_size > max_page_bytes)
        return Error{ErrorCode::resource_limit, "Mach-O CodeDirectory page exceeds 16 MiB"};
    if (code_limit > limits.max_code_bytes)
        return Error{ErrorCode::resource_limit, "Mach-O CodeDirectory code range exceeds configured byte limit"};
    const auto expected_slots = code_limit == 0 ? 0 : (std::uint64_t(code_limit) + page_size - 1) / page_size;
    if (expected_slots != code_slots || code_slots > limits.max_code_slots)
        return Error{ErrorCode::malformed, "Mach-O CodeDirectory code-slot count does not match its page range"};
    const auto special_bytes = std::uint64_t(special_slots) * hash_size;
    const auto code_hash_bytes = std::uint64_t(code_slots) * hash_size;
    if (hash_offset < special_bytes || hash_offset - special_bytes < (version >= 0x20100 ? 52u : 44u) ||
        hash_offset > directory.size() || code_hash_bytes > directory.size() - hash_offset)
        return Error{ErrorCode::malformed, "Mach-O CodeDirectory hash arrays exceed the blob"};
    const auto &slice = macho.container.slices[macho.selected_slice];
    if (code_limit > slice.size || slice.offset > image.storage()->size() ||
        code_limit > image.storage()->size() - slice.offset)
        return Error{ErrorCode::malformed, "Mach-O CodeDirectory code range exceeds its selected slice"};
    MachOCodeDirectoryHashVerification result;
    result.signature_index = signature_index;
    result.blob_index = blob_index;
    result.code_limit = code_limit;
    result.page_size = static_cast<std::uint32_t>(page_size);
    result.code_slots = code_slots;
    result.hash_type = hash_type;
    result.hash_size = hash_size;
    result.mismatch_slots.reserve(std::min<std::uint32_t>(limits.max_retained_mismatches, code_slots));
    for (std::uint32_t slot = 0; slot < code_slots; ++slot) {
        if ((slot & 0xffu) == 0 && stop.stop_requested())
            return Error{ErrorCode::canceled, "Mach-O CodeDirectory verification canceled"};
        const auto relative = std::uint64_t(slot) * page_size;
        const auto bytes = static_cast<std::size_t>(std::min<std::uint64_t>(page_size, code_limit - relative));
        const auto file_offset = slice.offset + relative;
        auto page = image.storage()->read_at({file_offset}, bytes);
        if (!page) return page.error();
        if (page.value().bytes.size() != bytes)
            return Error{ErrorCode::malformed, "Short read while hashing Mach-O code page"};
        Sha256 hasher;
        auto updated = hasher.update(page.value().bytes);
        if (!updated) return updated.error();
        const auto actual = hasher.digest();
        const auto hash_at = std::size_t(hash_offset) + std::size_t(slot) * hash_size;
        const bool matches = std::equal(actual.begin(), actual.begin() + hash_size,
                                         directory.begin() + static_cast<std::ptrdiff_t>(hash_at));
        if (!matches) {
            ++result.mismatch_count;
            if (result.mismatch_slots.size() < limits.max_retained_mismatches)
                result.mismatch_slots.push_back(slot);
        }
        ++result.verified_slots;
    }
    result.matches = result.mismatch_count == 0;
    return result;
}
} // namespace hexlab
