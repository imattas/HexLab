#pragma once
#include "hexlab/loaders/macho.hpp"
#include <stdexcept>
namespace hexlab::macho_detail {
inline constexpr std::uint64_t metadata_limit = 64 * 1024 * 1024;
struct Failure {
    Error error;
};
inline void require(bool condition, const char *message, ErrorCode code = ErrorCode::malformed) {
    if (!condition)
        throw Failure{{code, message}};
}
template <class T> T take(Result<T> result) {
    if (!result)
        throw Failure{result.error()};
    return std::move(result.value());
}
inline void canceled(std::stop_token stop) {
    require(!stop.stop_requested(), "Mach-O loading canceled", ErrorCode::canceled);
}
inline std::uint64_t add(std::uint64_t a, std::uint64_t b) {
    require(b <= UINT64_MAX - a, "Mach-O extent overflow", ErrorCode::overflow);
    return a + b;
}
struct Budget {
    std::uint64_t used = 0;
    void include(std::uint64_t size) {
        require(size <= metadata_limit - used, "Mach-O parsed metadata exceeds64MiB budget", ErrorCode::resource_limit);
        used += size;
    }
};
class Reader {
    const ByteStorage &storage_;
    const MachOSlice &slice_;
    std::stop_token stop_;

  public:
    Reader(const ByteStorage &storage, const MachOSlice &slice, std::stop_token stop)
        : storage_(storage), slice_(slice), stop_(stop) {}
    FileOffset file(std::uint64_t offset, std::uint64_t size) const {
        require(offset <= slice_.size && size <= slice_.size - offset, "Mach-O field crosses selected slice boundary");
        return {add(slice_.offset, offset)};
    }
    ByteView bytes(std::uint64_t relative, std::size_t size) const {
        canceled(stop_);
        auto view = take(storage_.read_at(file(relative, size), size));
        require(view.bytes.size() == size, "Incomplete Mach-O storage view");
        canceled(stop_);
        return view;
    }
    std::uint64_t value(std::span<const std::byte> bytes, std::size_t at, std::size_t width) const {
        require(width <= 8 && at <= bytes.size() && width <= bytes.size() - at, "Truncated Mach-O command scalar");
        std::uint64_t result = 0;
        for (std::size_t i = 0; i < width; ++i)
            result |= std::to_integer<std::uint64_t>(bytes[at + i])
                      << (8 * (slice_.header.order == ByteOrder::little ? i : width - i - 1));
        return result;
    }
};
void read_segments(const ByteStorage &, MachOMetadata &, Budget &, std::stop_token);
void read_protections(const ByteStorage &, const Image &, MachOMetadata &, ImageLayout &, Budget &, std::stop_token);
void map_segments(const MachOMetadata &, ImageLayout &, Budget &, std::stop_token);
void read_symbols(const ByteStorage &, const Image &, MachOMetadata &, Budget &, std::stop_token);
void read_indirect_symbol_bindings(MachOMetadata &, Budget &, std::stop_token);
Result<bool> read_source_lines(const ByteStorage &, const Image &, MachOMetadata &, Budget &, std::stop_token);
void read_commands(const ByteStorage &, const Image &, MachOMetadata &, Budget &, std::stop_token);
bool supported_command(std::uint32_t);
Result<std::uint32_t> select_slice(const MachOContainer &, const MachOOptions &);
Result<LoadedImage> load_macho_bound(std::shared_ptr<const ByteStorage>, const MachOOptions &, std::optional<bool>, std::stop_token);
void read_relocations(const ByteStorage &, const Image &, MachOMetadata &, Budget &, std::stop_token);
void read_dyld(const ByteStorage &, const Image &, MachOMetadata &, Budget &, std::stop_token);
} // namespace hexlab::macho_detail
