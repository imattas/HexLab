#pragma once

#include "hexlab/core/result.hpp"
#include "hexlab/image/byte_storage.hpp"
#include "hexlab/loaders/loaded_image.hpp"
#include "hexlab/loaders/loaders_export.hpp"
#include <cstddef>
#include <cstdint>
#include <stop_token>
#include <string>
#include <string_view>
#include <vector>

namespace hexlab {

struct Xcoff32Relocation {
    std::uint32_t virtual_address = 0, symbol_index = 0;
    std::uint8_t size_info = 0, type = 0;
    std::uint64_t file_offset = 0;
};

struct Xcoff32Section {
    std::uint32_t index = 0, flags = 0;
    std::string name;
    std::uint32_t physical_address = 0, virtual_address = 0, size = 0;
    std::uint32_t data_file_offset = 0, relocation_file_offset = 0, line_number_file_offset = 0;
    // Expanded XCOFF32 relocation count, including STYP_OVRFLO counts.
    std::uint32_t relocation_count = 0;
    std::uint16_t line_number_count = 0;
    std::vector<Xcoff32Relocation> relocations;
};

struct Xcoff32Object {
    std::uint16_t file_flags = 0;
    std::uint32_t timestamp = 0, symbol_count = 0, symbol_table_file_offset = 0;
    std::uint32_t string_table_size = 0;
    std::vector<Xcoff32Section> sections;
    struct Symbol {
        std::uint32_t index = 0, value = 0;
        std::int16_t section_number = 0;
        std::uint16_t type = 0;
        std::uint8_t storage_class = 0, auxiliary_count = 0;
        std::string name;
    };
    // Primary rows only, in slot order. Names are interpreted only for
    // C_EXT, C_HIDEXT, C_WEAKEXT and C_STAT; debug names remain absent.
    std::vector<Symbol> symbols;
};

struct Xcoff32ObjectLimits {
    std::size_t max_sections = 4096;
    std::uint32_t max_symbols = 1'000'000;
    std::uint64_t max_relocations = 1'000'000;
    std::uint64_t max_metadata_bytes = 256ULL * 1024 * 1024;
    std::size_t max_name_bytes = 4096;
};

// Structural inventory of big-endian relocatable XCOFF32 without an optional
// header. Decodes ordinary relocation rows as metadata; it does not modify the
// source storage. Overflow sections and loader relocation rows are unsupported.
HEXLAB_LOADERS_EXPORT std::string_view xcoff32_relocation_type_name(std::uint8_t);
HEXLAB_LOADERS_EXPORT Result<Xcoff32Object> inspect_xcoff32_object(
    const ByteStorage &, std::stop_token = {}, Xcoff32ObjectLimits = {});

// Maps common initialized and zero-fill sections of a relocatable object into
// deterministic synthetic section bases. Applies bounded data-field R_POS,
// R_NEG, and R_REL relocations to locally defined symbols. Unsupported section
// kinds, relocation encodings, common symbols, and unresolved external symbols
// remain explicitly diagnosed; no AIX library binding or csect linker layout
// is inferred.
HEXLAB_LOADERS_EXPORT Result<LoadedImage> load_xcoff32_relocatable(
    std::shared_ptr<const ByteStorage>, std::stop_token = {}, Xcoff32ObjectLimits = {});

// Maps an already linked, big-endian XCOFF32 executable into its declared
// virtual addresses and inventories the bounded AIX loader tables. Imports
// and loader relocations are reported as unresolved: no runtime binding or
// relocation is performed.
HEXLAB_LOADERS_EXPORT Result<LoadedImage> load_xcoff32_executable(
    std::shared_ptr<const ByteStorage>, std::stop_token = {}, Xcoff32ObjectLimits = {});

// Detects the XCOFF32 F_EXEC bit and routes the input to the linked executable
// mapper or relocatable-object mapper above.
HEXLAB_LOADERS_EXPORT Result<LoadedImage> load_xcoff32_image(
    std::shared_ptr<const ByteStorage>, std::stop_token = {}, Xcoff32ObjectLimits = {});

} // namespace hexlab
