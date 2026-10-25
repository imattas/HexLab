#pragma once
#include "hexlab/loaders/loaded_image.hpp"
#include <array>
#include <cstddef>
#include <cstdint>
#include <optional>
#include <stop_token>
#include <string>
#include <vector>
namespace hexlab {
HEXLAB_LOADERS_EXPORT Result<LoadedImage> load_pe(std::shared_ptr<const ByteStorage>, std::stop_token);
// Maps at an explicit runtime base, applying supported PE base relocations
// through an immutable source overlay.
HEXLAB_LOADERS_EXPORT Result<LoadedImage> load_pe_at_base(std::shared_ptr<const ByteStorage>, std::uint64_t,
                                                          std::stop_token);
// Select the image bytes and decode context for a Windows-on-Arm process.
// Metadata remains tied to the original PE file and source locations.
HEXLAB_LOADERS_EXPORT Result<std::shared_ptr<const Image>> select_pe_runtime_view(
    const LoadedImage &, PeRuntimeArchitecture);

// COFF symbols are optional records embedded after the PE headers. They are
// not part of the PE image mapping, so this bounded reader exposes them
// separately from ImageMetadata.
struct PeCoffSymbol {
    std::string name;
    std::uint32_t raw_index = 0, value = 0;
    std::int16_t section_number = 0;
    std::uint16_t type = 0;
    std::uint8_t storage_class = 0;
    // Present for a valid positive section number when Value falls inside the
    // section's declared image extent.
    std::optional<std::uint32_t> section_rva;
    std::vector<std::array<std::byte, 18>> auxiliary_records;
    FileOffset source_file_offset{};
    bool operator==(const PeCoffSymbol &) const = default;
};
struct PeCoffSymbolTable {
    FileOffset symbol_table_file_offset{};
    FileOffset string_table_file_offset{};
    std::uint32_t declared_record_count = 0, string_table_size = 0;
    std::vector<PeCoffSymbol> symbols;
    bool operator==(const PeCoffSymbolTable &) const = default;
};
// Reads the optional COFF symbol table from a PE file, preserving auxiliary
// records and resolving section-relative values to RVAs when they are in range.
HEXLAB_LOADERS_EXPORT Result<PeCoffSymbolTable> read_pe_coff_symbols(const LoadedImage &, std::stop_token = {});
}
