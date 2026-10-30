#include "hexlab/loaders/jmod.hpp"
#include "hexlab/image/byte_storage.hpp"
#include <algorithm>
#include <array>
#include <limits>
#include <memory>
#include <new>
#include <optional>
#include <string_view>

namespace hexlab {
namespace {
class SnapshotStorage final : public ByteStorage,
                              public std::enable_shared_from_this<SnapshotStorage> {
  public:
    explicit SnapshotStorage(std::vector<std::byte> bytes) : bytes_(std::move(bytes)) {}
    std::uint64_t size() const noexcept override { return bytes_.size(); }
    Result<ByteView> read_at(FileOffset offset, std::size_t count) const override {
        if (offset.value > bytes_.size() || count > bytes_.size() - static_cast<std::size_t>(offset.value))
            return Error{ErrorCode::out_of_bounds, "JMOD embedded ZIP read exceeds its bounded extent"};
        return ByteView{shared_from_this(), std::span<const std::byte>(bytes_).subspan(
            static_cast<std::size_t>(offset.value), count)};
    }
  private:
    std::vector<std::byte> bytes_;
};

JmodSection section_from_name(std::string_view name) {
    if (name == "classes") return JmodSection::classes;
    if (name == "conf") return JmodSection::conf;
    if (name == "headers") return JmodSection::headers;
    if (name == "legal") return JmodSection::legal;
    if (name == "lib") return JmodSection::lib;
    if (name == "bin") return JmodSection::bin;
    if (name == "include") return JmodSection::include;
    if (name == "man") return JmodSection::man;
    return JmodSection::unknown;
}

bool safe_class_name(std::string_view name) {
    if (name.empty() || name.size() > 4096 || name.front() == '/' || name.back() == '/') return false;
    bool segment_start = true;
    for (const unsigned char c : name) {
        if (c == '/' || c == '.') {
            if (segment_start || c == '.') return false;
            segment_start = true;
            continue;
        }
        if (c == '\\' || c == ';' || c == '[' || c == '\0') return false;
        segment_start = false;
    }
    return !segment_start;
}
}

Result<JmodArchive> read_jmod_archive(const ByteStorage &storage, std::stop_token stop, JarLimits limits) {
    if (storage.size() < 4) return Error{ErrorCode::malformed, "JMOD header is truncated"};
    if (stop.stop_requested()) return Error{ErrorCode::canceled, "JMOD loading canceled"};
    auto prefix = storage.read_at({0}, 4);
    if (!prefix) return prefix.error();
    if (prefix.value().bytes.size() != 4) return Error{ErrorCode::io, "JMOD source returned an incomplete header"};
    constexpr std::array<std::byte, 4> magic{std::byte{'J'}, std::byte{'M'}, std::byte{1}, std::byte{0}};
    if (!std::equal(magic.begin(), magic.end(), prefix.value().bytes.begin()))
        return Error{ErrorCode::malformed, "JMOD magic or version is unsupported"};
    const auto zip_size = storage.size() - 4;
    if (zip_size > limits.max_archive_bytes)
        return Error{ErrorCode::resource_limit, "JMOD embedded ZIP exceeds its configured byte limit"};
    if (zip_size > std::numeric_limits<std::size_t>::max())
        return Error{ErrorCode::resource_limit, "JMOD embedded ZIP exceeds host address space"};
    try {
        std::vector<std::byte> zip_bytes;
        zip_bytes.reserve(static_cast<std::size_t>(zip_size));
        constexpr std::size_t chunk_size = 1024 * 1024;
        for (std::uint64_t offset = 0; offset < zip_size;) {
            if (stop.stop_requested()) return Error{ErrorCode::canceled, "JMOD ZIP snapshot canceled"};
            const auto count = static_cast<std::size_t>(std::min<std::uint64_t>(chunk_size, zip_size - offset));
            auto part = storage.read_at({offset + 4}, count);
            if (!part) return part.error();
            if (part.value().bytes.size() != count)
                return Error{ErrorCode::io, "JMOD source returned an incomplete ZIP read"};
            zip_bytes.insert(zip_bytes.end(), part.value().bytes.begin(), part.value().bytes.end());
            offset += count;
        }
        auto snapshot = std::make_shared<SnapshotStorage>(std::move(zip_bytes));
        auto archive = read_jar_archive(*snapshot, stop, limits);
        if (!archive) return archive.error();
        JmodArchive result;
        result.archive = std::move(archive.value());
        result.major_version = 1;
        result.minor_version = 0;
        result.members.reserve(result.archive.members.size());
        for (std::size_t index = 0; index < result.archive.members.size(); ++index) {
            if (stop.stop_requested()) return Error{ErrorCode::canceled, "JMOD section inventory canceled"};
            const auto &member = result.archive.members[index];
            const auto slash = member.name.find('/');
            if (slash == std::string::npos || slash == 0)
                return Error{ErrorCode::malformed, "JMOD member is not rooted in a section"};
            const auto section_name = std::string_view(member.name).substr(0, slash);
            const auto path = std::string_view(member.name).substr(slash + 1);
            if (!member.directory && path.empty())
                return Error{ErrorCode::malformed, "JMOD file member has an empty section-relative path"};
            result.members.push_back({index, section_from_name(section_name), std::string(path)});
        }
        return result;
    } catch (const std::bad_alloc &) {
        return Error{ErrorCode::resource_limit, "Cannot allocate bounded JMOD container state"};
    }
}

Result<LoadedImage> load_jmod_class(const JmodArchive &jmod, std::string_view internal_name,
                                   std::stop_token stop, JarLimits limits) {
    if (!safe_class_name(internal_name))
        return Error{ErrorCode::invalid_argument, "JMOD internal class name is invalid"};
    std::optional<std::size_t> found;
    for (const auto &member : jmod.members) {
        if (member.section != JmodSection::classes || member.path_in_section.empty()) continue;
        if (member.path_in_section == std::string(internal_name) + ".class") {
            if (found) return Error{ErrorCode::malformed, "JMOD contains duplicate class paths"};
            found = member.archive_member_index;
        }
    }
    if (!found) return Error{ErrorCode::out_of_bounds, "JMOD class was not found in the classes section"};
    return load_jvm_jar_class(jmod.archive, *found, stop, limits);
}

} // namespace hexlab
