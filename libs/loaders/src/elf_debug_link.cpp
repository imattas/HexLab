#include "hexlab/loaders/elf.hpp"
#include "miniz.h"
#include <algorithm>

namespace hexlab {
Result<bool> verify_elf_gnu_debuglink_crc(const ElfGnuDebugLink &link,
                                          const ByteStorage &companion,
                                          std::stop_token stop,
                                          std::uint64_t max_bytes) {
    if (!max_bytes)
        return Error{ErrorCode::invalid_argument, "ELF debuglink byte limit must be positive"};
    if (companion.size() > max_bytes)
        return Error{ErrorCode::resource_limit, "ELF debug companion exceeds verification byte limit"};
    if (link.filename.empty())
        return Error{ErrorCode::invalid_argument, "ELF debuglink filename metadata is empty"};
    constexpr std::size_t chunk_bytes = 1024 * 1024;
    mz_ulong crc = MZ_CRC32_INIT;
    std::uint64_t offset = 0;
    while (offset < companion.size()) {
        if (stop.stop_requested())
            return Error{ErrorCode::canceled, "ELF debug companion CRC verification canceled"};
        const auto count = static_cast<std::size_t>(
            std::min<std::uint64_t>(chunk_bytes, companion.size() - offset));
        auto view = companion.read_at({offset}, count);
        if (!view) return view.error();
        if (view.value().bytes.size() != count)
            return Error{ErrorCode::io, "ELF debug companion returned an incomplete CRC read"};
        crc = mz_crc32(crc,
            reinterpret_cast<const unsigned char *>(view.value().bytes.data()),
            count);
        offset += count;
    }
    if (stop.stop_requested())
        return Error{ErrorCode::canceled, "ELF debug companion CRC verification canceled"};
    return static_cast<std::uint32_t>(crc) == link.crc32;
}
} // namespace hexlab
