#pragma once
#include "hexlab/image/byte_storage.hpp"
#include "hexlab/loaders/loaded_image.hpp"
#include "hexlab/image/macho_metadata.hpp"
#include "hexlab/loaders/loaders_export.hpp"
#include <stop_token>
namespace hexlab {
// Container/header/load-command envelope inspection only. Command payloads,
// image mappings, architecture support and linking are separate contracts.
HEXLAB_LOADERS_EXPORT Result<MachOContainer> read_macho_container(const ByteStorage &, std::stop_token);
struct MachOOptions {
    std::optional<std::uint32_t> slice_index;
    bool operator==(const MachOOptions &) const = default;
};
HEXLAB_LOADERS_EXPORT Result<LoadedImage> load_macho(std::shared_ptr<const ByteStorage>, const MachOOptions &,
                                                     std::stop_token);
} // namespace hexlab
