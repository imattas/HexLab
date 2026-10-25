#include "hexlab/loaders/jar.hpp"
#include "hexlab/image/byte_storage.hpp"
#include "miniz.h"
#include "miniz_tinfl.h"
#include <algorithm>
#include <array>
#include <limits>
#include <new>
#include <optional>

namespace hexlab {
namespace {
constexpr std::uint32_t eocd_signature = 0x06054b50;
constexpr std::uint32_t zip64_eocd_signature = 0x06064b50;
constexpr std::uint32_t zip64_locator_signature = 0x07064b50;
constexpr std::uint32_t central_signature = 0x02014b50;
constexpr std::uint32_t local_signature = 0x04034b50;
constexpr std::size_t eocd_size = 22;
constexpr std::size_t central_header_size = 46;
constexpr std::size_t local_header_size = 30;
constexpr std::size_t zip64_locator_size = 20;
constexpr std::uint64_t max_zip_comment = 65535;

Error malformed(std::string message) { return {ErrorCode::malformed, std::move(message)}; }
bool contains(std::size_t size, std::uint64_t offset, std::uint64_t length) {
    return offset <= size && length <= size - static_cast<std::size_t>(offset);
}
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
struct Zip64Fields {
    std::optional<std::uint64_t> uncompressed_size;
    std::optional<std::uint64_t> compressed_size;
    std::optional<std::uint64_t> local_header_offset;
    std::optional<std::uint32_t> disk_start;
    bool present = false;
};
Result<Zip64Fields> zip64_extra(std::span<const std::byte> extra, bool need_uncompressed,
                                bool need_compressed, bool need_offset, bool need_disk) {
    Zip64Fields values;
    std::size_t at = 0;
    while (at < extra.size()) {
        if (extra.size() - at < 4) return malformed("truncated ZIP extra-field header");
        const auto id = u16(extra, at), size = u16(extra, at + 2);
        at += 4;
        if (size > extra.size() - at) return malformed("ZIP extra-field payload exceeds its declared extent");
        if (id == 1) {
            if (values.present) return malformed("duplicate ZIP64 extra field");
            values.present = true;
            const auto data = extra.subspan(at, size);
            std::size_t cursor = 0;
            if (need_uncompressed) {
                if (data.size() - cursor < 8) return malformed("ZIP64 extra field omits uncompressed size");
                values.uncompressed_size = u64(data, cursor); cursor += 8;
            }
            if (need_compressed) {
                if (data.size() - cursor < 8) return malformed("ZIP64 extra field omits compressed size");
                values.compressed_size = u64(data, cursor); cursor += 8;
            }
            if (need_offset) {
                if (data.size() - cursor < 8) return malformed("ZIP64 extra field omits local-header offset");
                values.local_header_offset = u64(data, cursor); cursor += 8;
            }
            if (need_disk) {
                if (data.size() - cursor < 4) return malformed("ZIP64 extra field omits disk number");
                values.disk_start = u32(data, cursor); cursor += 4;
            }
        }
        at += size;
    }
    if ((need_uncompressed || need_compressed || need_offset || need_disk) && !values.present)
        return malformed("ZIP64 sentinel is missing its ZIP64 extra field");
    return values;
}

Result<std::shared_ptr<const std::vector<std::byte>>> read_source(const ByteStorage &storage,
                                                                 std::stop_token stop,
                                                                 JarLimits limits) {
    if (stop.stop_requested()) return Error{ErrorCode::canceled, "JAR loading canceled"};
    if (limits.max_archive_bytes == 0 || storage.size() > limits.max_archive_bytes ||
        storage.size() > std::numeric_limits<std::size_t>::max())
        return Error{ErrorCode::resource_limit, "ZIP archive exceeds its bounded input size"};
    try {
        const auto count = static_cast<std::size_t>(storage.size());
        auto view = storage.read_at({0}, count);
        if (!view) return view.error();
        if (view.value().bytes.size() != count)
            return Error{ErrorCode::io, "ZIP source returned an incomplete archive read"};
        auto copy = std::make_shared<std::vector<std::byte>>(view.value().bytes.begin(), view.value().bytes.end());
        return std::shared_ptr<const std::vector<std::byte>>(std::move(copy));
    } catch (const std::bad_alloc &) {
        return Error{ErrorCode::resource_limit, "Cannot allocate bounded ZIP archive storage"};
    }
}

class OwnedStorage final : public ByteStorage, public std::enable_shared_from_this<OwnedStorage> {
  public:
    explicit OwnedStorage(std::vector<std::byte> bytes) : bytes_(std::move(bytes)) {}
    std::uint64_t size() const noexcept override { return bytes_.size(); }
    Result<ByteView> read_at(FileOffset offset, std::size_t count) const override {
        if (offset.value > bytes_.size() || count > bytes_.size() - static_cast<std::size_t>(offset.value))
            return Error{ErrorCode::out_of_bounds, "JAR class read exceeds its bounded member"};
        return ByteView{shared_from_this(), std::span<const std::byte>(bytes_).subspan(
                                               static_cast<std::size_t>(offset.value), count)};
    }
  private:
    std::vector<std::byte> bytes_;
};
} // namespace

Result<JarArchive> read_jar_archive(const ByteStorage &storage, std::stop_token stop, JarLimits limits) {
    if (limits.max_members == 0 || limits.max_name_bytes == 0 || limits.max_member_bytes == 0 ||
        limits.max_total_uncompressed_bytes == 0)
        return Error{ErrorCode::invalid_argument, "ZIP limits must be positive"};
    auto source = read_source(storage, stop, limits);
    if (!source) return source.error();
    const auto bytes = std::span<const std::byte>(*source.value());
    if (bytes.size() < eocd_size) return malformed("truncated ZIP end-of-central-directory record");
    const auto search_begin = bytes.size() > eocd_size + max_zip_comment
                                  ? bytes.size() - static_cast<std::size_t>(eocd_size + max_zip_comment)
                                  : 0;
    std::optional<std::size_t> eocd;
    for (std::size_t at = bytes.size() - eocd_size;; --at) {
        if (u32(bytes, at) == eocd_signature) {
            const auto comment_size = u16(bytes, at + 20);
            if (at + eocd_size + comment_size == bytes.size()) {
                eocd = at;
                break;
            }
        }
        if (at == search_begin) break;
    }
    if (!eocd) return malformed("ZIP end-of-central-directory record was not found");
    const auto end = *eocd;
    const auto disk = u16(bytes, end + 4), central_disk = u16(bytes, end + 6);
    const auto disk_count = u16(bytes, end + 8), entry_count = u16(bytes, end + 10);
    const auto central_size = u32(bytes, end + 12), central_offset = u32(bytes, end + 16);
    if (disk || central_disk)
        return Error{ErrorCode::unsupported, "Multi-disk ZIP archives are unsupported"};
    std::uint64_t total_entries = entry_count;
    std::uint64_t directory_size = central_size;
    std::uint64_t directory_offset = central_offset;
    std::uint64_t directory_limit = end;
    bool zip64 = false;
    const bool locator_present = end >= zip64_locator_size &&
                                 u32(bytes, end - zip64_locator_size) == zip64_locator_signature;
    if (locator_present) {
        const auto locator = end - zip64_locator_size;
        const auto locator_disk = u32(bytes, locator + 4);
        const auto zip64_offset = u64(bytes, locator + 8);
        const auto disk_total = u32(bytes, locator + 16);
        if (locator_disk != 0 || disk_total != 1)
            return Error{ErrorCode::unsupported, "Multi-disk ZIP64 archives are unsupported"};
        if (!contains(bytes.size(), zip64_offset, 12 + 44) ||
            u32(bytes, static_cast<std::size_t>(zip64_offset)) != zip64_eocd_signature)
            return malformed("ZIP64 end-of-central-directory record is missing or truncated");
        const auto record_size = u64(bytes, static_cast<std::size_t>(zip64_offset) + 4);
        if (record_size < 44 || record_size > std::numeric_limits<std::uint64_t>::max() - 12 ||
            !contains(bytes.size(), zip64_offset, 12 + record_size) ||
            zip64_offset + 12 + record_size != locator)
            return malformed("ZIP64 end-of-central-directory extent is invalid");
        const auto record = static_cast<std::size_t>(zip64_offset);
        const auto record_disk = u32(bytes, record + 16), record_directory_disk = u32(bytes, record + 20);
        const auto entries_on_disk = u64(bytes, record + 24);
        total_entries = u64(bytes, record + 32);
        directory_size = u64(bytes, record + 40);
        directory_offset = u64(bytes, record + 48);
        if (record_disk || record_directory_disk || entries_on_disk != total_entries)
            return Error{ErrorCode::unsupported, "Multi-disk ZIP64 archives are unsupported"};
        if ((disk_count != UINT16_MAX && disk_count != entries_on_disk) ||
            (entry_count != UINT16_MAX && entry_count != total_entries) ||
            (central_size != UINT32_MAX && central_size != directory_size) ||
            (central_offset != UINT32_MAX && central_offset != directory_offset))
            return malformed("ZIP32 and ZIP64 end records disagree");
        directory_limit = zip64_offset;
        zip64 = true;
    } else if (disk_count == UINT16_MAX || entry_count == UINT16_MAX ||
               central_size == UINT32_MAX || central_offset == UINT32_MAX) {
        return malformed("ZIP64 end-of-central-directory locator is missing");
    } else if (disk_count != entry_count) {
        return Error{ErrorCode::unsupported, "Multi-disk ZIP archives are unsupported"};
    }
    if (total_entries > limits.max_members || total_entries > std::numeric_limits<std::size_t>::max())
        return Error{ErrorCode::resource_limit, "ZIP member count exceeds its configured limit"};
    if (directory_size > std::numeric_limits<std::uint64_t>::max() - directory_offset ||
        !contains(bytes.size(), directory_offset, directory_size) ||
        directory_offset + directory_size > directory_limit ||
        (!zip64 && directory_offset + directory_size != end))
        return malformed("ZIP central directory extent is invalid");

    JarArchive archive;
    archive.source = std::move(source.value());
    archive.members.reserve(static_cast<std::size_t>(total_entries));
    std::size_t at = static_cast<std::size_t>(directory_offset);
    const auto directory_end = directory_offset + directory_size;
    std::uint64_t total_uncompressed = 0;
    for (std::uint64_t i = 0; i < total_entries; ++i) {
        if (stop.stop_requested()) return Error{ErrorCode::canceled, "JAR inventory canceled"};
        if (!contains(static_cast<std::size_t>(directory_end), at, central_header_size) ||
            u32(bytes, at) != central_signature)
            return malformed("Invalid ZIP central-directory entry");
        const auto flags = u16(bytes, at + 8), method = u16(bytes, at + 10);
        const auto crc = u32(bytes, at + 16);
        const auto compressed32 = u32(bytes, at + 20), uncompressed32 = u32(bytes, at + 24);
        const auto name_size = u16(bytes, at + 28), extra_size = u16(bytes, at + 30);
        const auto comment_size = u16(bytes, at + 32);
        const auto start_disk16 = u16(bytes, at + 34);
        const auto local_offset = u32(bytes, at + 42);
        const auto variable_size = std::uint64_t(name_size) + extra_size + comment_size;
        if (!contains(static_cast<std::size_t>(directory_end), at + central_header_size, variable_size))
            return malformed("ZIP central-directory variable fields exceed the archive");
        if (name_size == 0 || name_size > limits.max_name_bytes)
            return Error{ErrorCode::resource_limit, "ZIP member name is empty or exceeds its bound"};
        const auto extra = bytes.subspan(at + central_header_size + name_size, extra_size);
        const bool need_uncompressed = uncompressed32 == UINT32_MAX;
        const bool need_compressed = compressed32 == UINT32_MAX;
        const bool need_offset = local_offset == UINT32_MAX;
        const bool need_disk = start_disk16 == UINT16_MAX;
        auto extra_values = zip64_extra(extra, need_uncompressed, need_compressed, need_offset, need_disk);
        if (!extra_values) return extra_values.error();
        const std::uint64_t uncompressed = need_uncompressed ? *extra_values.value().uncompressed_size
                                                              : uncompressed32;
        const std::uint64_t compressed = need_compressed ? *extra_values.value().compressed_size
                                                          : compressed32;
        const std::uint64_t local_header_offset = need_offset ? *extra_values.value().local_header_offset
                                                               : local_offset;
        const std::uint32_t start_disk = need_disk ? *extra_values.value().disk_start : start_disk16;
        if (start_disk != 0) return Error{ErrorCode::unsupported, "Split ZIP members are unsupported"};
        const auto name_begin = at + central_header_size;
        const auto name_bytes = bytes.subspan(name_begin, name_size);
        if (std::find(name_bytes.begin(), name_bytes.end(), std::byte{0}) != name_bytes.end())
            return malformed("ZIP member name contains a null byte");
        std::string name(reinterpret_cast<const char *>(name_bytes.data()), name_bytes.size());

        if (!contains(bytes.size(), local_header_offset, local_header_size) ||
            u32(bytes, static_cast<std::size_t>(local_header_offset)) != local_signature)
            return malformed("ZIP member local header is out of bounds or malformed");
        const auto local_at = static_cast<std::size_t>(local_header_offset);
        const auto local_flags = u16(bytes, local_at + 6), local_method = u16(bytes, local_at + 8);
        const auto local_crc = u32(bytes, local_at + 14);
        const auto local_compressed32 = u32(bytes, local_at + 18), local_uncompressed32 = u32(bytes, local_at + 22);
        const auto local_name_size = u16(bytes, local_at + 26), local_extra_size = u16(bytes, local_at + 28);
        if (local_flags != flags || local_method != method || local_name_size != name_size)
            return malformed("ZIP local and central headers disagree");
        const auto local_variable = std::uint64_t(local_name_size) + local_extra_size;
        if (!contains(bytes.size(), local_header_offset + local_header_size, local_variable))
            return malformed("ZIP local header fields exceed the archive");
        const auto local_name = bytes.subspan(local_at + local_header_size, local_name_size);
        if (!std::equal(local_name.begin(), local_name.end(), name_bytes.begin()))
            return malformed("ZIP local and central member names disagree");
        const auto local_extra = bytes.subspan(local_at + local_header_size + local_name_size, local_extra_size);
        const bool local_need_uncompressed = local_uncompressed32 == UINT32_MAX;
        const bool local_need_compressed = local_compressed32 == UINT32_MAX;
        auto local_values = zip64_extra(local_extra, local_need_uncompressed, local_need_compressed, false, false);
        if (!local_values) return local_values.error();
        const std::uint64_t local_uncompressed = local_need_uncompressed
                                                    ? *local_values.value().uncompressed_size
                                                    : local_uncompressed32;
        const std::uint64_t local_compressed = local_need_compressed
                                                  ? *local_values.value().compressed_size
                                                  : local_compressed32;
        const bool descriptor = (flags & 0x0008) != 0;
        if ((!descriptor && (local_crc != crc || local_compressed != compressed || local_uncompressed != uncompressed)) ||
            (descriptor && ((local_crc && local_crc != crc) || (local_compressed && local_compressed != compressed) ||
                            (local_uncompressed && local_uncompressed != uncompressed))))
            return malformed("ZIP local sizes or CRC disagree with the central directory");
        const auto data_offset = local_header_offset + local_header_size + local_variable;
        if (!contains(static_cast<std::size_t>(directory_offset), data_offset, compressed))
            return malformed("ZIP member data overlaps or exceeds the central directory");
        if (uncompressed > limits.max_member_bytes || uncompressed > limits.max_total_uncompressed_bytes ||
            total_uncompressed > limits.max_total_uncompressed_bytes - uncompressed)
            return Error{ErrorCode::resource_limit, "ZIP uncompressed data exceeds configured limits"};
        total_uncompressed += uncompressed;
        const bool encrypted = (flags & (0x0001 | 0x0040 | 0x2000)) != 0;
        const bool supported = !encrypted && (method == 0 || method == 8);
        const bool directory = name.back() == '/';
        archive.members.push_back({std::move(name), compressed, uncompressed, crc, data_offset, method,
                                   directory, encrypted, supported});
        at += central_header_size + static_cast<std::size_t>(variable_size);
    }
    if (at != directory_end)
        return malformed("ZIP central directory size does not match its entry count");
    return archive;
}

Result<std::vector<std::byte>> extract_jar_member(const JarArchive &archive, std::size_t member_index,
                                                  std::stop_token stop, JarLimits limits) {
    if (!archive.source || member_index >= archive.members.size())
        return Error{ErrorCode::invalid_argument, "Invalid ZIP member selection"};
    const auto &member = archive.members[member_index];
    if (member.directory) return Error{ErrorCode::invalid_argument, "Cannot extract a ZIP directory entry"};
    if (member.encrypted) return Error{ErrorCode::unsupported, "Encrypted ZIP members are unsupported"};
    if (!member.supported) return Error{ErrorCode::unsupported, "ZIP compression method is unsupported"};
    if (member.uncompressed_size > limits.max_member_bytes ||
        member.uncompressed_size > std::numeric_limits<std::size_t>::max())
        return Error{ErrorCode::resource_limit, "ZIP member exceeds its extraction size limit"};
    if (!contains(archive.source->size(), member.data_offset, member.compressed_size) ||
        member.compressed_size > std::numeric_limits<std::size_t>::max())
        return malformed("ZIP member data is outside the retained source buffer");
    if (stop.stop_requested()) return Error{ErrorCode::canceled, "ZIP member extraction canceled"};
    try {
        std::vector<std::byte> output(static_cast<std::size_t>(member.uncompressed_size));
        const auto *input = archive.source->data() + static_cast<std::size_t>(member.data_offset);
        if (member.compression_method == 0) {
            if (member.compressed_size != member.uncompressed_size)
                return malformed("Stored ZIP member has different compressed and uncompressed sizes");
            std::copy_n(input, output.size(), output.data());
        } else {
            std::byte empty_output{};
            auto *destination = output.empty() ? &empty_output : output.data();
            const auto destination_size = output.empty() ? std::size_t{1} : output.size();
            const auto produced = tinfl_decompress_mem_to_mem(
                destination, destination_size, input, static_cast<std::size_t>(member.compressed_size),
                TINFL_FLAG_USING_NON_WRAPPING_OUTPUT_BUF);
            if (produced == TINFL_DECOMPRESS_MEM_TO_MEM_FAILED || produced != output.size())
                return malformed("Deflate ZIP member did not decompress to its declared size");
        }
        if (stop.stop_requested()) return Error{ErrorCode::canceled, "ZIP member extraction canceled"};
        const auto crc = static_cast<std::uint32_t>(mz_crc32(MZ_CRC32_INIT,
            reinterpret_cast<const unsigned char *>(output.data()), output.size()));
        if (crc != member.crc32) return malformed("ZIP member CRC-32 mismatch");
        return output;
    } catch (const std::bad_alloc &) {
        return Error{ErrorCode::resource_limit, "Cannot allocate ZIP member output"};
    }
}

Result<LoadedImage> load_jvm_jar_class(const JarArchive &archive, std::size_t member_index,
                                      std::stop_token stop, JarLimits limits) {
    if (member_index >= archive.members.size())
        return Error{ErrorCode::invalid_argument, "Invalid JAR class member selection"};
    const auto &member = archive.members[member_index];
    if (member.directory || !member.name.ends_with(".class"))
        return Error{ErrorCode::invalid_argument, "Selected JAR member is not a class file"};
    auto bytes = extract_jar_member(archive, member_index, stop, limits);
    if (!bytes) return bytes.error();
    try {
        auto storage = std::make_shared<OwnedStorage>(std::move(bytes.value()));
        return load_jvm_class(std::move(storage), stop);
    } catch (const std::bad_alloc &) {
        return Error{ErrorCode::resource_limit, "Cannot allocate JAR class storage"};
    }
}

} // namespace hexlab
