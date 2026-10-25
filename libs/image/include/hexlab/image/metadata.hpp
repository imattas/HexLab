#pragma once
#include "hexlab/image/image.hpp"
#include "hexlab/image/elf_metadata.hpp"
#include "hexlab/image/macho_metadata.hpp"
#include "hexlab/image/pe_metadata.hpp"
#include "hexlab/image/jvm_metadata.hpp"
#include "hexlab/image/wasm_metadata.hpp"
#include "hexlab/image/dex_metadata.hpp"
#include "hexlab/image/minidump_metadata.hpp"
#include <optional>

namespace hexlab {
enum class DiagnosticSeverity { info, warning, error };
struct Diagnostic {
    DiagnosticSeverity severity;
    std::string message;
    std::optional<Address> location;
};
struct SectionDeclaration {
    std::string name;
    Rva rva;
    std::uint32_t virtual_size;
    FileOffset raw_position;
    std::uint32_t raw_size;
    std::uint32_t characteristics;
    bool operator==(const SectionDeclaration &) const = default;
};
struct Directory {
    std::uint32_t index, location, size;
    bool file_offset;
    bool operator==(const Directory &) const = default;
};
struct ImportSymbol {
    std::string library;
    std::optional<std::string> name;
    std::optional<std::uint16_t> ordinal;
    Address thunk, iat;
    // True when this row came from IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT.
    bool delay_load = false;
    bool operator==(const ImportSymbol &) const = default;
};
struct ExportSymbol {
    std::uint32_t ordinal;
    std::optional<std::string> name;
    std::optional<Address> address;
    std::optional<std::string> forwarder;
    bool operator==(const ExportSymbol &) const = default;
};
struct Relocation {
    std::uint16_t type;
    Address address;
    Rva page;
    std::uint16_t offset;
    bool operator==(const Relocation &) const = default;
};
struct FirmwareDataRecord {
    Address address;
    std::uint64_t size = 0;
    std::uint64_t source_line = 0, record_index = 0;
    FileOffset packed_file_offset;
    bool operator==(const FirmwareDataRecord &) const = default;
};
struct FirmwareMetadata {
    bool intel_hex = true;
    bool has_start_address = false;
    std::uint64_t start_address = 0;
    std::vector<FirmwareDataRecord> records;
    bool operator==(const FirmwareMetadata &) const = default;
};
struct ImageMetadata {
    std::string format;
    std::uint16_t machine = 0, subsystem = 0;
    std::uint64_t preferred_base = 0;
    std::uint64_t image_size = 0;
    std::uint32_t header_size = 0;
    std::vector<SectionDeclaration> sections;
    std::vector<Directory> directories;
    std::vector<ImportSymbol> imports;
    std::vector<ExportSymbol> exports;
    std::vector<Relocation> relocations;
    std::optional<ElfMetadata> elf;
    std::optional<MachOMetadata> macho;
    std::optional<PeMetadata> pe;
    std::optional<FirmwareMetadata> firmware;
    std::optional<JvmMetadata> jvm;
    std::optional<WasmMetadata> wasm;
    std::optional<DexMetadata> dex;
    std::optional<MinidumpMetadata> minidump;
    bool operator==(const ImageMetadata &) const = default;
};
} // namespace hexlab
