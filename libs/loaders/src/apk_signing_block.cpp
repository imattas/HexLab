#include "hexlab/loaders/apk_signing_block.hpp"
#include <algorithm>
#include <array>
#include <limits>
#include <new>
#include <optional>
#include <set>
#include <stdexcept>
#include <string>
#include <string_view>

namespace hexlab {
namespace {
constexpr std::uint32_t eocd_signature = 0x06054b50;
constexpr std::uint32_t zip64_eocd_signature = 0x06064b50;
constexpr std::uint32_t zip64_locator_signature = 0x07064b50;
constexpr std::size_t eocd_size = 22;
constexpr std::size_t zip64_locator_size = 20;
constexpr std::uint64_t max_zip_comment = 65535;
constexpr std::array<std::byte, 16> signing_magic{
    std::byte{'A'}, std::byte{'P'}, std::byte{'K'}, std::byte{' '},
    std::byte{'S'}, std::byte{'i'}, std::byte{'g'}, std::byte{' '},
    std::byte{'B'}, std::byte{'l'}, std::byte{'o'}, std::byte{'c'},
    std::byte{'k'}, std::byte{' '}, std::byte{'4'}, std::byte{'2'}};

std::uint16_t u16(std::span<const std::byte> bytes, std::size_t at) {
    return static_cast<std::uint16_t>(std::to_integer<std::uint8_t>(bytes[at]) |
        (std::to_integer<std::uint8_t>(bytes[at + 1]) << 8));
}
std::uint32_t u32(std::span<const std::byte> bytes, std::size_t at) {
    return std::uint32_t(std::to_integer<std::uint8_t>(bytes[at])) |
        (std::uint32_t(std::to_integer<std::uint8_t>(bytes[at + 1])) << 8) |
        (std::uint32_t(std::to_integer<std::uint8_t>(bytes[at + 2])) << 16) |
        (std::uint32_t(std::to_integer<std::uint8_t>(bytes[at + 3])) << 24);
}
std::uint64_t u64(std::span<const std::byte> bytes, std::size_t at) {
    return std::uint64_t(u32(bytes, at)) | (std::uint64_t(u32(bytes, at + 4)) << 32);
}
bool contains(std::uint64_t size, std::uint64_t offset, std::uint64_t length) {
    return offset <= size && length <= size - offset;
}
Result<std::vector<std::byte>> read_exact(const ByteStorage &storage, std::uint64_t offset,
                                          std::size_t size, std::string_view what) {
    if (!contains(storage.size(), offset, size))
        return Error{ErrorCode::malformed, std::string(what) + " exceeds APK extent"};
    auto view = storage.read_at({offset}, size);
    if (!view) return view.error();
    if (view.value().bytes.size() != size)
        return Error{ErrorCode::io, std::string("APK source returned an incomplete ") + std::string(what)};
    return std::vector<std::byte>(view.value().bytes.begin(), view.value().bytes.end());
}

struct DirectoryInfo { std::uint64_t offset = 0, size = 0, end_record_offset = 0; };
Result<DirectoryInfo> central_directory(const ByteStorage &storage, std::stop_token stop) {
    if (storage.size() < eocd_size)
        return Error{ErrorCode::malformed, "APK ZIP end record is truncated"};
    const auto tail_size = static_cast<std::size_t>(std::min<std::uint64_t>(
        storage.size(), eocd_size + max_zip_comment));
    const auto tail_offset = storage.size() - tail_size;
    auto tail_result = read_exact(storage, tail_offset, tail_size, "ZIP end-record search window");
    if (!tail_result) return tail_result.error();
    const auto tail = std::span<const std::byte>(tail_result.value());
    std::optional<std::size_t> eocd;
    if (tail.size() >= eocd_size) {
        for (std::size_t at = tail.size() - eocd_size;; --at) {
            if (stop.stop_requested()) return Error{ErrorCode::canceled, "APK Signing Block scan canceled"};
            if (u32(tail, at) == eocd_signature && at + eocd_size + u16(tail, at + 20) == tail.size()) {
                eocd = at;
                break;
            }
            if (!at) break;
        }
    }
    if (!eocd) return Error{ErrorCode::malformed, "APK ZIP end record was not found"};
    const auto end = *eocd;
    if (u16(tail, end + 4) != 0 || u16(tail, end + 6) != 0 ||
        u16(tail, end + 8) != u16(tail, end + 10))
        return Error{ErrorCode::unsupported, "APK Signing Block inspection requires a single-disk ZIP archive"};
    DirectoryInfo directory{u32(tail, end + 16), u32(tail, end + 12), tail_offset + end};
    const bool zip64_locator = end >= zip64_locator_size &&
        u32(tail, end - zip64_locator_size) == zip64_locator_signature;
    const bool zip64_sentinel = u16(tail, end + 8) == UINT16_MAX ||
        u16(tail, end + 10) == UINT16_MAX || u32(tail, end + 12) == UINT32_MAX ||
        u32(tail, end + 16) == UINT32_MAX;
    if (zip64_locator || zip64_sentinel) {
        if (!zip64_locator)
            return Error{ErrorCode::malformed, "ZIP64 APK is missing its end-record locator"};
        const auto locator_offset = tail_offset + end - zip64_locator_size;
        auto locator_result = read_exact(storage, locator_offset, zip64_locator_size, "ZIP64 locator");
        if (!locator_result) return locator_result.error();
        const auto locator = std::span<const std::byte>(locator_result.value());
        const auto record_disk = u32(locator, 4);
        const auto record_offset = u64(locator, 8);
        if (record_disk != 0 || u32(locator, 16) != 1 ||
            !contains(storage.size(), record_offset, 56))
            return Error{ErrorCode::malformed, "APK ZIP64 locator is invalid"};
        auto record_result = read_exact(storage, record_offset, 56, "ZIP64 end record");
        if (!record_result) return record_result.error();
        const auto record = std::span<const std::byte>(record_result.value());
        const auto record_size = u64(record, 4);
        if (u32(record, 0) != zip64_eocd_signature || record_size < 44 ||
            record_size > UINT64_MAX - 12 ||
            !contains(storage.size(), record_offset, record_size + 12) ||
            u32(record, 16) != 0 || u32(record, 20) != 0 ||
            u64(record, 24) != u64(record, 32))
            return Error{ErrorCode::malformed, "APK ZIP64 end record is invalid or multi-disk"};
        directory.size = u64(record, 40);
        directory.offset = u64(record, 48);
    }
    if (!contains(storage.size(), directory.offset, directory.size) ||
        directory.offset + directory.size > directory.end_record_offset)
        return Error{ErrorCode::malformed, "APK central-directory extent exceeds the ZIP end record"};
    return directory;
}
}

Result<ApkSigningBlock> inspect_apk_signing_block(const ByteStorage &storage,
    std::stop_token stop, ApkSigningBlockLimits limits) try {
    if (!limits.max_block_bytes || limits.max_block_bytes > 256ULL * 1024 * 1024 ||
        !limits.max_pair_value_bytes || limits.max_pair_value_bytes > limits.max_block_bytes ||
        !limits.max_pairs || limits.max_pairs > 65536)
        return Error{ErrorCode::invalid_argument, "Invalid APK Signing Block limits"};
    auto directory_result = central_directory(storage, stop);
    if (!directory_result) return directory_result.error();
    ApkSigningBlock result;
    result.central_directory_offset = directory_result.value().offset;
    if (result.central_directory_offset < 24) return result;
    auto footer_result = read_exact(storage, result.central_directory_offset - 24, 24, "APK Signing Block footer");
    if (!footer_result) return footer_result.error();
    const auto footer = std::span<const std::byte>(footer_result.value());
    if (!std::equal(signing_magic.begin(), signing_magic.end(), footer.begin() + 8)) return result;
    const auto footer_size = u64(footer, 0);
    if (footer_size < 24 || footer_size > UINT64_MAX - 8)
        return Error{ErrorCode::malformed, "APK Signing Block footer size is invalid"};
    const auto block_size = footer_size + 8;
    if (block_size > limits.max_block_bytes)
        return Error{ErrorCode::resource_limit, "APK Signing Block exceeds its configured size limit"};
    if (block_size > result.central_directory_offset)
        return Error{ErrorCode::malformed, "APK Signing Block begins before the APK file"};
    const auto block_offset = result.central_directory_offset - block_size;
    auto leading_size_result = read_exact(storage, block_offset, 8, "APK Signing Block leading size");
    if (!leading_size_result) return leading_size_result.error();
    if (u64(leading_size_result.value(), 0) != footer_size)
        return Error{ErrorCode::malformed, "APK Signing Block leading and trailing sizes disagree"};
    const auto pairs_begin = block_offset + 8;
    const auto pairs_end = result.central_directory_offset - 24;
    if (pairs_end < pairs_begin)
        return Error{ErrorCode::malformed, "APK Signing Block pair extent is invalid"};
    result.present = true;
    result.block_offset = block_offset;
    result.block_size = block_size;
    std::set<std::uint32_t> ids;
    std::uint64_t aggregate_value_bytes = 0;
    for (auto offset = pairs_begin; offset < pairs_end;) {
        if (stop.stop_requested()) return Error{ErrorCode::canceled, "APK Signing Block pair scan canceled"};
        if (result.pairs.size() >= limits.max_pairs)
            return Error{ErrorCode::resource_limit, "APK Signing Block pair count exceeds its configured limit"};
        if (!contains(pairs_end, offset, 8))
            return Error{ErrorCode::malformed, "APK Signing Block pair length is truncated"};
        auto length_result = read_exact(storage, offset, 8, "APK Signing Block pair length");
        if (!length_result) return length_result.error();
        const auto pair_length = u64(length_result.value(), 0);
        if (pair_length < 4 || !contains(pairs_end, offset + 8, pair_length))
            return Error{ErrorCode::malformed, "APK Signing Block pair length is invalid"};
        auto id_result = read_exact(storage, offset + 8, 4, "APK Signing Block pair ID");
        if (!id_result) return id_result.error();
        const auto id = u32(id_result.value(), 0);
        if (!ids.insert(id).second)
            return Error{ErrorCode::malformed, "APK Signing Block contains a duplicate pair ID"};
        const auto value_size = pair_length - 4;
        if (value_size > limits.max_pair_value_bytes - aggregate_value_bytes)
            return Error{ErrorCode::resource_limit, "APK Signing Block pair values exceed their aggregate limit"};
        aggregate_value_bytes += value_size;
        if (value_size > std::numeric_limits<std::size_t>::max())
            return Error{ErrorCode::resource_limit, "APK Signing Block pair exceeds host address space"};
        auto value = read_exact(storage, offset + 12, static_cast<std::size_t>(value_size),
                                "APK Signing Block pair value");
        if (!value) return value.error();
        result.pairs.push_back({id, offset, std::move(value.value())});
        offset += 8 + pair_length;
    }
    if (result.pairs.empty())
        return Error{ErrorCode::malformed, "APK Signing Block contains no pair records"};
    return result;
} catch (const std::bad_alloc &) {
    return Error{ErrorCode::resource_limit, "Cannot allocate bounded APK Signing Block metadata"};
} catch (const std::length_error &) {
    return Error{ErrorCode::resource_limit, "APK Signing Block metadata exceeds host container limits"};
}

} // namespace hexlab
