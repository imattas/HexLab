#include "hexlab/loaders/dex_archive.hpp"
#include <algorithm>
#include <charconv>
#include <cstring>
#include <memory>
#include <new>
#include <optional>
#include <stdexcept>
#include <string_view>

namespace hexlab {
namespace {
class DexEntryStorage final : public ByteStorage, public std::enable_shared_from_this<DexEntryStorage> {
  public:
    explicit DexEntryStorage(std::vector<std::byte> bytes) : bytes_(std::move(bytes)) {}
    std::uint64_t size() const noexcept override { return bytes_.size(); }
    Result<ByteView> read_at(FileOffset offset, std::size_t count) const override {
        if (offset.value > bytes_.size() || count > bytes_.size() - static_cast<std::size_t>(offset.value))
            return Error{ErrorCode::out_of_bounds, "DEX APK member read exceeds its bounded extent"};
        return ByteView{shared_from_this(), std::span<const std::byte>(bytes_).subspan(
            static_cast<std::size_t>(offset.value), count)};
    }
  private:
    std::vector<std::byte> bytes_;
};

struct Candidate { std::size_t archive_index = 0; std::uint32_t number = 0; };

std::optional<std::uint32_t> canonical_dex_number(std::string_view name) {
    if (name == "classes.dex") return 1;
    constexpr std::string_view prefix = "classes", suffix = ".dex";
    if (!name.starts_with(prefix) || !name.ends_with(suffix) || name.size() <= prefix.size() + suffix.size())
        return std::nullopt;
    const auto digits = name.substr(prefix.size(), name.size() - prefix.size() - suffix.size());
    if (digits.front() < '2' || digits.front() > '9') return std::nullopt;
    std::uint32_t value = 0;
    const auto parsed = std::from_chars(digits.data(), digits.data() + digits.size(), value);
    if (parsed.ec != std::errc{} || parsed.ptr != digits.data() + digits.size() || value < 2) return std::nullopt;
    return value;
}
}

Result<std::vector<DexArchiveImage>> load_android_dex_archive(
    const ByteStorage &storage, std::stop_token stop, DexArchiveLimits limits) {
    if (limits.max_dex_members == 0 || limits.max_dex_members > 4096 ||
        limits.max_total_dex_bytes == 0 || limits.max_total_dex_bytes > 4ULL * 1024 * 1024 * 1024)
        return Error{ErrorCode::invalid_argument, "Invalid APK DEX loading limits"};
    auto archive = read_jar_archive(storage, stop, limits.zip);
    if (!archive) return archive.error();
    try {
        std::vector<Candidate> candidates;
        for (std::size_t index = 0; index < archive.value().members.size(); ++index) {
            if (stop.stop_requested()) return Error{ErrorCode::canceled, "APK DEX inventory canceled"};
            const auto &member = archive.value().members[index];
            if (member.directory) continue;
            if (auto number = canonical_dex_number(member.name))
                candidates.push_back({index, *number});
        }
        if (candidates.empty())
            return Error{ErrorCode::malformed, "APK has no canonical classes.dex primary member"};
        std::sort(candidates.begin(), candidates.end(), [](const auto &a, const auto &b) { return a.number < b.number; });
        if (candidates.front().number != 1)
            return Error{ErrorCode::malformed, "APK has no canonical classes.dex primary member"};
        if (candidates.size() > limits.max_dex_members)
            return Error{ErrorCode::resource_limit, "APK DEX member count exceeds its configured limit"};
        std::uint64_t total_uncompressed = 0;
        for (std::size_t i = 0; i < candidates.size(); ++i) {
            if (candidates[i].number != i + 1)
                return Error{ErrorCode::malformed, "APK multidex entries must be contiguous from classes.dex"};
            const auto &member = archive.value().members[candidates[i].archive_index];
            if (member.uncompressed_size > 512ull * 1024 * 1024)
                return Error{ErrorCode::resource_limit, "APK DEX entry exceeds the 512 MiB parser limit"};
            if (member.uncompressed_size > limits.max_total_dex_bytes - total_uncompressed)
                return Error{ErrorCode::resource_limit, "APK DEX uncompressed size exceeds its aggregate limit"};
            total_uncompressed += member.uncompressed_size;
        }
        std::vector<DexArchiveImage> result;
        result.reserve(candidates.size());
        DexMetadataUsage aggregate_usage;
        auto extraction_limits = limits.zip;
        extraction_limits.max_member_bytes = std::min({extraction_limits.max_member_bytes,
            limits.max_total_dex_bytes, std::uint64_t{512} * 1024 * 1024});
        for (const auto &candidate : candidates) {
            if (stop.stop_requested()) return Error{ErrorCode::canceled, "APK DEX loading canceled"};
            const auto &member = archive.value().members[candidate.archive_index];
            auto extracted = extract_jar_member(archive.value(), candidate.archive_index, stop, extraction_limits);
            if (!extracted) return extracted.error();
            auto entry_storage = std::make_shared<DexEntryStorage>(std::move(extracted.value()));
            std::vector<LoadedImage> logical_members;
            if (entry_storage->size() < 8)
                return Error{ErrorCode::malformed, "APK DEX entry is shorter than its magic"};
            auto prefix = entry_storage->read_at({0}, 8);
            if (!prefix) return prefix.error();
            if (prefix.value().bytes.size() == 8 && std::memcmp(prefix.value().bytes.data(), "dex\n041\0", 8) == 0) {
                auto loaded = load_dex041_container(entry_storage, stop);
                if (!loaded) return loaded.error();
                logical_members = std::move(loaded.value());
            } else {
                auto loaded = load_dex(entry_storage, stop);
                if (!loaded) return loaded.error();
                logical_members.push_back(std::move(loaded.value()));
            }
            if (logical_members.size() > limits.max_dex_members - result.size())
                return Error{ErrorCode::resource_limit, "APK logical DEX member count exceeds its configured limit"};
            for (std::size_t logical_index = 0; logical_index < logical_members.size(); ++logical_index) {
                if (logical_index > UINT32_MAX) return Error{ErrorCode::resource_limit, "DEX 041 logical member index exceeds its field width"};
                DexArchiveImage row;
                row.entry_name = member.name;
                row.archive_entry_index = static_cast<std::uint32_t>(candidate.archive_index);
                row.logical_member_index = static_cast<std::uint32_t>(logical_index);
                row.data_offset = member.data_offset;
                row.compressed_size = member.compressed_size;
                row.uncompressed_size = member.uncompressed_size;
                row.crc32 = member.crc32;
                row.compression_method = member.compression_method;
                row.loaded = std::move(logical_members[logical_index]);
                if (!row.loaded.metadata.dex)
                    return Error{ErrorCode::malformed, "DEX parser returned an image without typed metadata"};
                const auto usage = measure_dex_metadata_usage(*row.loaded.metadata.dex, stop);
                if (stop.stop_requested()) return Error{ErrorCode::canceled, "APK DEX metadata accounting canceled"};
                const auto add = [](std::uint64_t &total, std::uint64_t value) {
                    total = value > UINT64_MAX - total ? UINT64_MAX : total + value;
                };
                add(aggregate_usage.rows, usage.rows);
                add(aggregate_usage.string_capacity, usage.string_capacity);
                add(aggregate_usage.retained_capacity_bytes, usage.retained_capacity_bytes);
                add(aggregate_usage.class_member_rows, usage.class_member_rows);
                if (aggregate_usage.rows > 2'000'000 || aggregate_usage.string_capacity > 64ull * 1024 * 1024 ||
                    aggregate_usage.retained_capacity_bytes > 256ull * 1024 * 1024 ||
                    aggregate_usage.class_member_rows > 1'000'000)
                    return Error{ErrorCode::resource_limit, "APK DEX aggregate retained metadata exceeds its row or byte limits"};
                result.push_back(std::move(row));
            }
        }
        return result;
    } catch (const std::bad_alloc &) {
        return Error{ErrorCode::resource_limit, "Cannot allocate bounded APK DEX metadata"};
    } catch (const std::length_error &) {
        return Error{ErrorCode::resource_limit, "APK DEX metadata exceeds host limits"};
    }
}

} // namespace hexlab
