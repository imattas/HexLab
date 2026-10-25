#pragma once
#include "hexlab/image/byte_storage.hpp"
#include "hexlab/loaders/loaders_export.hpp"
#include <span>
#include <string_view>
#include <vector>

namespace hexlab {
struct MachOLinkLimits {
    std::size_t max_objects = 100'000;
    std::size_t max_symbols = 2'000'000;
    std::size_t max_relocations = 4'000'000;
    std::uint64_t max_output_bytes = 512ULL * 1024 * 1024;
};

// Produces a static x86-64 or ARM64 Mach-O MH_EXECUTE. The bounded subset merges
// __TEXT,__text, __DATA,__data, optional zero-fill __DATA,__bss, and supported
// read-only __TEXT __const/__cstring/__literal4/__literal8/__literal16 plus
// __DATA_CONST,__const contributions into the output __const mapping. Supported x86-64 relocations may be
// stored in file-backed sections and target any merged section, including paired
// SUBTRACTOR/UNSIGNED records. ARM64 accepts UNSIGNED, SUBTRACTOR/UNSIGNED,
// BRANCH26, PAGE21, PAGEOFF12, and supported PAGE21/PAGEOFF12 ADDEND companions.
// Dynamic linking and unsupported relocation families are rejected.
HEXLAB_LOADERS_EXPORT Result<std::vector<std::byte>> link_macho64_executable(
    std::span<const std::shared_ptr<const ByteStorage>>, std::string_view entry_symbol = "_start",
    std::uint64_t base_address = 0x100000000ULL, std::stop_token = {}, MachOLinkLimits = {});

// Compatibility entry point retained for existing callers.
HEXLAB_LOADERS_EXPORT Result<std::vector<std::byte>> link_macho64_x86_64_executable(
    std::span<const std::shared_ptr<const ByteStorage>>, std::string_view entry_symbol = "_start",
    std::uint64_t base_address = 0x100000000ULL, std::stop_token = {}, MachOLinkLimits = {});
} // namespace hexlab
