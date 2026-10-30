#pragma once

#include "hexlab/core/result.hpp"
#include "hexlab/image/byte_storage.hpp"
#include "hexlab/loaders/loaders_export.hpp"
#include <cstddef>
#include <cstdint>
#include <stop_token>
#include <string>
#include <string_view>
#include <vector>

namespace hexlab {

struct Xcoff64Relocation {
    std::uint64_t virtual_address = 0;
    std::uint32_t symbol_index = 0;
    std::uint8_t size_info = 0, type = 0;
    std::uint64_t file_offset = 0;
};

struct Xcoff64Section {
    std::uint32_t index = 0, flags = 0;
    std::string name;
    std::uint64_t physical_address = 0, virtual_address = 0, size = 0;
    std::uint64_t data_file_offset = 0, relocation_file_offset = 0;
    std::uint32_t relocation_count = 0, line_number_count = 0;
    bool loader_relocation_encoding = false;
    std::vector<Xcoff64Relocation> relocations;
};

struct Xcoff64Object {
    std::uint16_t file_flags = 0;
    std::uint32_t symbol_count = 0;
    std::uint64_t symbol_table_file_offset = 0;
    std::vector<Xcoff64Section> sections;
    struct Symbol {
        std::uint32_t index = 0;
        std::uint64_t value = 0;
        std::int16_t section_number = 0;
        std::uint8_t storage_class = 0;
        // 0xff means no recognized AUX_CSECT record was present.
        std::uint8_t csect_type = 0xff, storage_mapping_class = 0xff;
        std::string name;
    };
    // Primary rows only, in slot order; auxiliary slots are deliberately absent.
    std::vector<Symbol> symbols;
};

struct Xcoff64ObjectLimits {
    std::size_t max_sections = 4096;
    std::uint32_t max_symbols = 1'000'000;
    std::uint64_t max_relocations = 1'000'000;
    std::uint64_t max_metadata_bytes = 256ULL * 1024 * 1024;
    std::size_t max_name_bytes = 4096;
};

// Classification only: a recognized name does not imply relocation application.
HEXLAB_LOADERS_EXPORT std::string_view xcoff64_relocation_type_name(std::uint8_t);

// Inspects a big-endian XCOFF64 relocatable object, retaining bounded section
// metadata, binder-relevant primary symbol names and ordinary relocation rows.
// Auxiliary symbol slots are skipped and cannot be relocation targets.
// Relocations in `.loader` use their
// distinct 16-byte encoding and are extent-checked but not decoded.
HEXLAB_LOADERS_EXPORT Result<Xcoff64Object> inspect_xcoff64_object(
    const ByteStorage &, std::stop_token = {}, Xcoff64ObjectLimits = {});

} // namespace hexlab
