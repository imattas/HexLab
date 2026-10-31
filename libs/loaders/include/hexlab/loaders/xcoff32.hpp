#pragma once

#include "hexlab/core/result.hpp"
#include "hexlab/image/byte_storage.hpp"
#include "hexlab/loaders/loaders_export.hpp"
#include <cstddef>
#include <cstdint>
#include <stop_token>
#include <string>
#include <vector>

namespace hexlab {

struct Xcoff32Section {
    std::uint32_t index = 0, flags = 0;
    std::string name;
    std::uint32_t physical_address = 0, virtual_address = 0, size = 0;
    std::uint32_t data_file_offset = 0, relocation_file_offset = 0, line_number_file_offset = 0;
    std::uint16_t relocation_count = 0, line_number_count = 0;
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
    std::uint64_t max_metadata_bytes = 256ULL * 1024 * 1024;
    std::size_t max_name_bytes = 4096;
};

// Structural inventory of big-endian relocatable XCOFF32 without an optional
// header. Checks ordinary relocation/line table extents but does not decode
// or apply those rows. Overflow sections and loader relocation rows are
// explicitly unsupported. No csect interpretation or linking is performed.
HEXLAB_LOADERS_EXPORT Result<Xcoff32Object> inspect_xcoff32_object(
    const ByteStorage &, std::stop_token = {}, Xcoff32ObjectLimits = {});

} // namespace hexlab
