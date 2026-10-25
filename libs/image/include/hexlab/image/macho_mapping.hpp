#pragma once
#include "hexlab/image/image.hpp"
#include "hexlab/image/macho_metadata.hpp"
#include <stop_token>

namespace hexlab {
// A source extent is not a VM anchor. Every fixed-header byte must have
// exactly one mapping, contiguous in the same address domain.
inline Result<std::optional<Address>> macho_header_anchor(const Image &image, const MachOSlice &slice,
                                                          std::stop_token stop) {
    if (stop.stop_requested())
        return Error{ErrorCode::canceled, "Mach-O header mapping canceled"};
    const auto size = slice.header.is_64 ? 32u : 28u;
    if (slice.header.file_type == 1 || slice.size < size || slice.offset > image.storage()->size() ||
        size > image.storage()->size() - slice.offset)
        return std::optional<Address>{};
    const auto anchor = image.to_address({slice.offset});
    if (!anchor)
        return std::optional<Address>{};
    for (std::uint64_t i = 1; i < size; ++i) {
        if (stop.stop_requested())
            return Error{ErrorCode::canceled, "Mach-O header mapping canceled"};
        const auto byte = image.to_address({slice.offset + i});
        if (!byte || i > UINT64_MAX - anchor.value().offset ||
            byte.value() != Address{anchor.value().space, anchor.value().offset + i})
            return std::optional<Address>{};
    }
    return std::optional<Address>{anchor.value()};
}
} // namespace hexlab
