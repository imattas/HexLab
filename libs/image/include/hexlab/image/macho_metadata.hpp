#pragma once
#include "hexlab/core/address.hpp"
#include "hexlab/core/byte_reader.hpp"
#include <vector>
#include <optional>
#include <string>
#include <array>
namespace hexlab {
struct MachOLoadCommand {
    std::uint32_t index = 0, command = 0, size = 0;
    std::uint64_t file_offset = 0;
    bool operator==(const MachOLoadCommand &) const = default;
};
struct MachOHeader {
    bool is_64 = false;
    ByteOrder order = ByteOrder::little;
    std::uint32_t cpu_type = 0, cpu_subtype = 0, file_type = 0;
    std::uint32_t command_count = 0, command_bytes = 0, flags = 0, reserved = 0;
    std::vector<MachOLoadCommand> commands;
    bool operator==(const MachOHeader &) const = default;
};
struct MachOSlice {
    std::uint32_t index = 0, cpu_type = 0, cpu_subtype = 0;
    std::uint64_t offset = 0, size = 0;
    std::uint32_t alignment = 0, reserved = 0;
    MachOHeader header;
    bool operator==(const MachOSlice &) const = default;
};
struct MachOContainer {
    bool universal = false, fat_64 = false;
    ByteOrder order = ByteOrder::little;
    std::vector<MachOSlice> slices;
    bool operator==(const MachOContainer &) const = default;
};
struct MachOSegment {
    std::uint32_t command_index = 0;
    std::string name;
    std::uint64_t address = 0, memory_size = 0, raw_file_offset = 0, file_size = 0;
    FileOffset file_offset{};
    std::uint32_t maximum_protection = 0, initial_protection = 0, flags = 0;
    std::uint32_t first_section = 0, section_count = 0;
    bool operator==(const MachOSegment &) const = default;
};
struct MachOSection {
    std::uint32_t ordinal = 0, segment_index = 0;
    std::string name, segment_name;
    std::uint64_t address = 0, size = 0, record_file_offset = 0;
    std::uint32_t raw_file_offset = 0, alignment = 0, relocation_offset = 0, relocation_count = 0, flags = 0;
    std::uint32_t reserved1 = 0, reserved2 = 0, reserved3 = 0;
    std::optional<FileOffset> file_offset;
    bool operator==(const MachOSection &) const = default;
};
struct MachOSourceLine {
    std::uint32_t selected_slice = 0, source_section = 0, line_unit = 0, row = 0;
    FileOffset source_file_offset{};
    std::uint64_t raw_address = 0;
    std::optional<Address> address;
    std::optional<std::uint32_t> address_section;
    std::string file;
    std::int64_t line = 0;
    std::uint64_t column = 0;
    bool end_sequence = false;
    bool operator==(const MachOSourceLine &) const = default;
};
enum class MachOSymbolState { undefined, defined, absolute, common, indirect, prebound_undefined, debug, unknown };
struct MachOSymbol {
    std::uint32_t table_command = 0, index = 0, string_index = 0;
    std::uint8_t type = 0, section = 0;
    std::uint16_t descriptor = 0;
    std::uint64_t value = 0, record_file_offset = 0;
    std::string name;
    std::optional<std::string> indirect_name;
    std::optional<std::uint8_t> library_ordinal;
    MachOSymbolState state = MachOSymbolState::undefined;
    std::optional<Address> address;
    // An executable definition is an analysis seed, not a declared function type.
    bool code = false;
    bool operator==(const MachOSymbol &) const = default;
};
struct MachOSymbolTable {
    std::uint32_t command_index = 0, raw_symbol_offset = 0, raw_string_offset = 0;
    std::uint32_t count = 0, stride = 0, string_size = 0;
    FileOffset symbol_offset{}, string_offset{};
    std::uint64_t first_symbol = 0;
    bool operator==(const MachOSymbolTable &) const = default;
};
struct MachOLibrary {
    std::uint32_t command_index = 0, command = 0, name_offset = 0;
    std::uint32_t timestamp = 0, current_version = 0, compatibility_version = 0;
    std::uint64_t record_file_offset = 0;
    std::optional<std::uint32_t> ordinal;
    std::string name;
    bool operator==(const MachOLibrary &) const = default;
};
struct MachOCommandString {
    std::uint32_t command_index = 0, command = 0, name_offset = 0;
    std::uint64_t record_file_offset = 0;
    std::string name;
    bool operator==(const MachOCommandString &) const = default;
};
// One bounded, NUL-terminated option string from LC_LINKER_OPTION.
struct MachOLinkerOption {
    std::uint32_t command_index = 0, option_index = 0;
    std::uint64_t record_file_offset = 0, string_file_offset = 0;
    std::string option;
    bool operator==(const MachOLinkerOption &) const = default;
};
struct MachODyldEnvironment {
    std::uint32_t command_index = 0, name_offset = 0;
    std::uint64_t record_file_offset = 0;
    std::string value;
    bool operator==(const MachODyldEnvironment &) const = default;
};
struct MachOUuid {
    std::uint32_t command_index = 0;
    std::uint64_t record_file_offset = 0;
    std::uint64_t value_file_offset = 0;
    std::array<std::uint8_t, 16> bytes{};
    bool operator==(const MachOUuid &) const = default;
};
struct MachOBuildToolVersion {
    std::uint32_t tool = 0, version = 0;
    bool operator==(const MachOBuildToolVersion &) const = default;
};
struct MachOBuildVersion {
    std::uint32_t command_index = 0, command = 0, platform = 0, minimum_os = 0, sdk = 0;
    std::uint64_t record_file_offset = 0;
    std::vector<MachOBuildToolVersion> tools;
    bool operator==(const MachOBuildVersion &) const = default;
};
// LC_SOURCE_VERSION packs A.B.C.D.E into 24/10/10/10/10 bits.
struct MachOSourceVersion {
    std::uint32_t command_index = 0, command = 0;
    std::uint64_t record_file_offset = 0, packed = 0;
    std::uint32_t major = 0, minor = 0, patch = 0, build = 0, prerelease = 0;
    bool operator==(const MachOSourceVersion &) const = default;
};
// LC_NOTE records a bounded opaque data span owned by the fixed 16-byte name.
struct MachONote {
    std::uint32_t command_index = 0;
    std::uint64_t record_file_offset = 0, data_size = 0;
    std::string data_owner;
    FileOffset data_offset{};
    bool operator==(const MachONote &) const = default;
};
// A bounded LC_FILESET_ENTRY declaration. Child commands are range-checked,
// but child images are not mapped or recursively imported into this image.
struct MachOFileSetEntry {
    std::uint32_t command_index = 0, entry_id_offset = 0, reserved = 0;
    std::uint64_t record_file_offset = 0, vm_address = 0, raw_file_offset = 0;
    std::string entry_id;
    bool child_is_64 = false;
    std::uint32_t child_cpu_type = 0, child_cpu_subtype = 0, child_file_type = 0;
    std::uint32_t child_command_count = 0, child_command_bytes = 0;
    bool child_commands_valid = false;
    bool operator==(const MachOFileSetEntry &) const = default;
};
struct MachOEntry {
    std::uint32_t command_index = 0, command = 0, flavor = 0, count = 0;
    std::uint64_t record_file_offset = 0, stack_size = 0;
    std::optional<std::uint64_t> value;
    std::optional<Address> address;
    bool operator==(const MachOEntry &) const = default;
};
// Module initializer declared by LC_ROUTINES/LC_ROUTINES_64. The address is
// retained only when it maps to initialized executable image bytes.
struct MachOInitializer {
    std::uint32_t command_index = 0, command = 0;
    std::uint64_t record_file_offset = 0, value = 0;
    std::optional<Address> address;
    bool operator==(const MachOInitializer &) const = default;
};
struct MachOFunctionStart {
    std::uint32_t command_index = 0;
    std::uint64_t record_file_offset = 0, delta = 0;
    std::optional<Address> address;
    bool operator==(const MachOFunctionStart &) const = default;
};
// Function entries recovered from the __unwind_info compact-unwind index.
// Encoding words are preserved but deliberately not interpreted here.
struct MachOCompactUnwindFunction {
    std::uint32_t section = 0, page = 0, index = 0, encoding = 0;
    std::uint64_t record_file_offset = 0, function_offset = 0;
    std::optional<Address> address;
    // End of this indexed interval is the next compact-unwind entry, or the
    // next top-level index row for the final entry on a page.
    std::uint64_t size = 0;
    bool operator==(const MachOCompactUnwindFunction &) const = default;
};
struct MachOEhFrameCallSite {
    std::uint64_t start = 0, length = 0, landing_pad = 0, action = 0;
    // Byte extent of the encoded row relative to the start of its LSDA.
    std::uint64_t record_offset = 0, encoded_size = 0;
    // Byte offsets of the bounded action records reachable from this row,
    // relative to the beginning of the LSDA. The chain order is preserved.
    std::vector<std::uint64_t> action_chain;
    bool operator==(const MachOEhFrameCallSite &) const = default;
};
struct MachOEhFrameAction {
    std::uint64_t record_offset = 0;
    std::uint64_t encoded_size = 0;
    std::int64_t type_filter = 0;
    std::int64_t next_displacement = 0;
    std::optional<std::uint64_t> next_record_offset;
    // Positive Itanium C++ filters index the fixed-width reverse type table.
    // Negative exception-specification filters remain raw and unresolved.
    std::optional<std::uint32_t> type_info_index;
    bool operator==(const MachOEhFrameAction &) const = default;
};
enum class MachOEhFrameRttiTargetState : std::uint8_t {
    unresolved,
    null_catch_all,
    readable_pointer,
    exact_defined_rtti_symbol,
    ambiguous_defined_rtti_symbols,
    invalid_pointer
};
struct MachOEhFrameTypeInfo {
    std::uint32_t index = 0;
    std::uint64_t record_offset = 0, encoded_size = 0, value = 0;
    std::uint8_t encoding = 0xff;
    bool null_pointer = false;
    std::optional<Address> address;
    // Exact-address matches against defined Itanium RTTI symbols. Aliases are
    // retained and never resolved by choosing an arbitrary name.
    std::vector<std::string> rtti_symbols;
    MachOEhFrameRttiTargetState target_state = MachOEhFrameRttiTargetState::unresolved;
    bool operator==(const MachOEhFrameTypeInfo &) const = default;
};
enum class MachOPersonalityKind : std::uint8_t { unknown, itanium_cxx };
// Bounded function ranges decoded from a supported Mach-O __eh_frame FDE.
struct MachOEhFrameFunction {
    std::uint32_t section = 0;
    std::uint64_t record_file_offset = 0, size = 0;
    // The CIE's DW_EH_PE encoding for FDE initial locations; retained so the
    // address recipe is inspectable alongside the resolved function range.
    std::uint8_t pointer_encoding = 0;
    std::optional<Address> address;
    std::uint64_t code_alignment = 1;
    std::int64_t data_alignment = 0;
    std::uint64_t return_register = 0;
    std::vector<std::byte> cie_instructions, instructions;
    std::optional<Address> personality, lsda;
    std::optional<std::string> personality_symbol;
    MachOPersonalityKind personality_kind = MachOPersonalityKind::unknown;
    // True when the CIE has a P augmentation field, even if its pointer encoding
    // could not be decoded into an address.
    bool has_personality_field = false;
    std::uint8_t personality_encoding = 0xff;
    // Source span of the encoded personality field in its CIE (global file offset).
    std::optional<FileOffset> personality_source;
    std::uint64_t personality_source_size = 0;
    // Slice-relative file provenance for the containing initialized LSDA section.
    std::optional<std::uint32_t> lsda_section;
    std::optional<std::uint64_t> lsda_file_offset;
    std::uint8_t lsda_encoding = 0xff, call_site_encoding = 0xff;
    std::uint8_t type_table_encoding = 0xff;
    std::uint64_t action_table_offset = 0;
    std::optional<std::uint64_t> type_table_base_offset;
    std::vector<MachOEhFrameCallSite> call_sites;
    std::vector<MachOEhFrameAction> actions;
    std::vector<MachOEhFrameTypeInfo> type_infos;
    bool type_table_complete = true;
    bool lsda_complete = true;
    bool operator==(const MachOEhFrameFunction &) const = default;
};
struct MachOSymbolRange {
    std::uint32_t begin = 0, count = 0;
    bool operator==(const MachOSymbolRange &) const = default;
};
struct MachODataTable {
    std::uint32_t raw_offset = 0, count = 0, stride = 0;
    FileOffset offset{};
    bool operator==(const MachODataTable &) const = default;
};
struct MachODynamicSymbolTable {
    std::uint32_t command_index = 0;
    std::uint64_t record_file_offset = 0;
    std::optional<std::uint32_t> symbol_table;
    // local / external-defined / undefined groups.
    std::array<MachOSymbolRange, 3> ranges;
    // contents / modules / references / indirect / external-relocations / local-relocations.
    std::array<MachODataTable, 6> tables;
    std::vector<std::uint32_t> indirect_symbols;
    bool operator==(const MachODynamicSymbolTable &) const = default;
};
enum class MachOIndirectBindingKind : std::uint8_t { symbol, local, absolute, reserved_flags };
struct MachOIndirectSymbolBinding {
    std::uint32_t dynamic_symbol_table_command = 0, section_ordinal = 0;
    std::uint8_t section_type = 0;
    std::optional<std::uint32_t> symbol_table_command, symbol_index;
    std::uint64_t slot_index = 0, section_offset = 0;
    std::uint32_t indirect_table_index = 0, raw_symbol_index = 0;
    MachOIndirectBindingKind kind = MachOIndirectBindingKind::symbol;
    std::optional<FileOffset> slot_file_offset;
    bool operator==(const MachOIndirectSymbolBinding &) const = default;
};
enum class MachORelocationSource { section, external, local };
enum class MachORelocationKind {
    absolute,
    pc_relative,
    branch,
    got,
    subtractor,
    section_difference,
    pair,
    tlv,
    prebound,
    addend,
    unknown
};
struct MachORelocationTable {
    MachORelocationSource kind = MachORelocationSource::section;
    std::uint32_t owner = 0, count = 0;
    FileOffset offset{};
    std::uint64_t first_row = 0;
    std::optional<std::uint32_t> symbol_table;
    bool operator==(const MachORelocationTable &) const = default;
};
struct MachORelocation {
    std::uint32_t table = 0, index = 0, raw_address = 0, raw_info = 0;
    std::uint32_t offset = 0, symbol_number = 0;
    std::uint8_t type = 0, length = 0, field_size = 0;
    bool pc_relative = false, external = false, scattered = false, auxiliary = false, retained = false;
    bool symbol_index_validated = false;
    MachORelocationKind kind = MachORelocationKind::unknown;
    std::optional<std::uint32_t> symbol_table, value;
    std::optional<std::uint64_t> pair;
    std::uint64_t record_file_offset = 0;
    std::optional<Address> place;
    std::optional<FileOffset> file_place;
    // Literal original field bits, not an architecture-independent addend.
    std::optional<std::uint64_t> encoded_value;
    bool operator==(const MachORelocation &) const = default;
};
enum class MachODyldStreamKind { rebase, bind, weak_bind, lazy_bind, exports, chained };
struct MachODyldStream {
    std::uint32_t command_index = 0;
    MachODyldStreamKind kind = MachODyldStreamKind::rebase;
    std::uint32_t raw_offset = 0, size = 0;
    FileOffset offset{};
    bool complete = true;
    bool operator==(const MachODyldStream &) const = default;
};
struct MachODyldOperation {
    std::uint32_t stream = 0, index = 0, encoded_size = 0;
    std::uint64_t record_file_offset = 0;
    std::uint8_t byte = 0;
    std::optional<std::uint64_t> first, second;
    std::optional<std::int64_t> signed_value;
    std::optional<std::string> symbol;
    bool operator==(const MachODyldOperation &) const = default;
};
struct MachODyldFixup {
    std::uint32_t stream = 0, operation = 0, repeat_index = 0, segment_index = 0;
    std::uint64_t record_file_offset = 0, segment_offset = 0;
    std::uint8_t type = 0, field_size = 0, symbol_flags = 0;
    std::optional<std::int32_t> library_ordinal;
    std::int64_t addend = 0;
    std::string symbol;
    std::optional<Address> place;
    std::optional<FileOffset> file_place;
    std::optional<std::uint64_t> encoded_value;
    bool operator==(const MachODyldFixup &) const = default;
};
struct MachODyldExport {
    std::uint32_t stream = 0, index = 0, terminal_size = 0;
    std::uint64_t record_file_offset = 0, terminal_file_offset = 0, flags = 0;
    std::string name;
    std::optional<std::uint64_t> value, resolver, library_ordinal;
    std::optional<std::string> import_name;
    std::optional<Address> address, resolver_address;
    bool complete = true;
    bool is_definition() const noexcept {
        // Only regular definitions (optionally weak or stub/resolver) carry
        // preferred image addresses. Reexports, TLS and scalars do not.
        return complete && address.has_value() && (flags & ~UINT64_C(0x14)) == 0;
    }
    bool operator==(const MachODyldExport &) const = default;
};
struct MachOChainedHeader {
    std::uint32_t stream = 0, version = 0, starts_offset = 0, imports_offset = 0, symbols_offset = 0;
    std::uint32_t imports_count = 0, imports_format = 0, symbols_format = 0;
    std::uint64_t record_file_offset = 0, first_import_row = 0;
    bool imports_available = false, complete = true;
    bool operator==(const MachOChainedHeader &) const = default;
};
struct MachOChainedImport {
    std::uint32_t header = 0, index = 0, name_offset = 0;
    std::uint64_t record_file_offset = 0, raw_info = 0, raw_addend = 0;
    std::int32_t library_ordinal = 0;
    std::int64_t addend = 0;
    bool weak_import = false, complete = true;
    std::optional<std::string> name;
    std::optional<FileOffset> name_file_offset;
    bool operator==(const MachOChainedImport &) const = default;
};
struct MachOChainedStarts {
    std::uint32_t header = 0, segment_index = 0, size = 0, max_valid_pointer = 0;
    std::uint64_t record_file_offset = 0, source_entry_file_offset = 0, segment_offset = 0;
    std::uint16_t page_size = 0, pointer_format = 0, page_count = 0;
    // The complete array, including overflow entries addressed by START_MULTI.
    std::vector<std::uint16_t> page_starts;
    bool complete = true;
    bool operator==(const MachOChainedStarts &) const = default;
};
enum class MachOChainedTargetBaseKind : std::uint8_t {
    shared_cache,
    cache_level
};
struct MachOChainedPointer {
    std::uint32_t header = 0, starts = 0, page_index = 0, chain_start_index = 0, node_index = 0;
    std::uint64_t segment_offset = 0, raw = 0;
    std::uint16_t next = 0, diversity = 0;
    std::uint8_t field_size = 0, stride = 0, high8 = 0, key = 0;
    // Kernel-cache pointer formats select one of four cache-level bases.
    std::optional<std::uint8_t> cache_level;
    // The encoded target is an offset into a base not carried by a standalone
    // Mach-O image; expose which external mapping is needed to resolve it.
    std::optional<MachOChainedTargetBaseKind> target_base_kind;
    bool bind = false, authenticated = false, address_diversity = false, target_is_offset = false;
    bool non_pointer = false, complete = true;
    // False when the pointer bytes are encrypted or overlap another chain
    // field, so later context-based target resolution must not interpret them.
    bool source_interpretation_valid = true;
    // Target payload is unassembled; high8 and authentication are separate.
    std::optional<std::uint64_t> target, import_row;
    std::optional<std::uint32_t> import_index, scalar_value;
    std::int64_t addend = 0;
    std::optional<Address> place;
    std::optional<FileOffset> file_place;
    // Address-resolvable in-image rebases retain their mapped destination.
    // Format 14's segment index/offset and unauthenticated preferred-base
    // offsets can be mapped; PAC is retained as metadata and never applied.
    std::optional<Address> target_address;
    bool operator==(const MachOChainedPointer &) const = default;
};
// One source-backed offset from the firmware __TEXT,__chain_starts table.
// The row identifies a chain's first pointer location, not its rebased target.
struct MachOChainStartOffset {
    std::uint32_t section_ordinal = 0, index = 0, pointer_format = 0, coordinate_flags = 0;
    std::uint64_t raw_offset = 0, record_file_offset = 0;
    std::optional<Address> pointer_address;
    std::optional<FileOffset> pointer_file_offset;
    bool complete = true;
    // First node index and total count in firmware_chained_pointers. Nodes
    // from different chains can interleave; select them by chain_start_row.
    // chain_complete describes traversal only; authenticated/bind nodes still
    // have no resolved target.
    std::uint32_t first_pointer_row = 0, pointer_count = 0;
    bool chain_complete = false;
    bool operator==(const MachOChainStartOffset &) const = default;
};
// A node walked from __TEXT,__chain_starts, independent of LC_DYLD_CHAINED_FIXUPS
// header/import namespaces. Every published node retains its original word.
struct MachOFirmwareChainedPointer {
    std::uint32_t chain_start_row = 0, node_index = 0;
    std::uint64_t raw = 0;
    std::uint16_t next = 0, diversity = 0;
    std::uint8_t field_size = 0, stride = 4, high8 = 0, key = 0;
    bool bind = false, authenticated = false, address_diversity = false, target_is_offset = false;
    bool complete = true;
    std::optional<std::uint64_t> target;
    std::optional<std::uint32_t> import_index;
    std::int64_t addend = 0;
    Address place{};
    FileOffset file_place{};
    std::optional<Address> target_address;
    bool operator==(const MachOFirmwareChainedPointer &) const = default;
};
struct MachOLinkeditDeclaration {
    std::uint32_t command_index = 0, command = 0, raw_offset = 0, size = 0;
    FileOffset offset{};
    std::uint64_t first_row = 0;
    bool operator==(const MachOLinkeditDeclaration &) const = default;
};
// A bounded code-signing blob inventory row. CodeDirectory fields describe
// encoded values only; no hashes, CMS signatures, or trust are verified.
struct MachOCodeSignatureBlob {
    std::uint32_t signature = 0, index = 0, slot_type = 0, magic = 0, size = 0;
    std::uint64_t raw_offset = 0, record_file_offset = 0;
    std::optional<std::uint32_t> code_directory_version, code_directory_flags, code_limit, code_slots;
    std::optional<std::uint64_t> code_limit64;
    std::uint8_t hash_size = 0, hash_type = 0, platform = 0, page_size_exponent = 0;
    bool code_directory = false;
    bool operator==(const MachOCodeSignatureBlob &) const = default;
};
enum class MachODataInCodeKind : std::uint16_t {
    data = 1, jump_table8 = 2, jump_table16 = 3, jump_table32 = 4, absolute_jump_table32 = 5
};
struct MachODataInCode {
    std::uint32_t table = 0, index = 0, raw_offset = 0;
    std::uint16_t length = 0, kind = 0;
    std::optional<MachODataInCodeKind> decoded_kind;
    std::uint64_t record_file_offset = 0;
    // Object records use object VM coordinates. Backing remains absent when
    // those declarations cannot identify one unique initialized section.
    std::optional<FileOffset> offset;
    bool operator==(const MachODataInCode &) const = default;
};
struct MachOEncryption {
    std::uint32_t command_index = 0, command = 0, raw_offset = 0, size = 0, cryptid = 0, pad = 0;
    std::uint64_t record_file_offset = 0;
    FileOffset offset{};
    bool operator==(const MachOEncryption &) const = default;
};
struct MachOMetadata {
    MachOContainer container;
    std::uint32_t selected_slice = 0;
    std::vector<MachOSegment> segments;
    std::vector<MachOSection> sections;
    std::vector<MachOSourceLine> source_lines;
    std::vector<MachOSymbolTable> symbol_tables;
    std::vector<MachOSymbol> symbols;
    bool symbols_complete = true;
    std::vector<MachOLibrary> libraries;
    std::vector<MachOCommandString> paths;
    std::vector<MachOLinkerOption> linker_options;
    std::vector<MachODyldEnvironment> dyld_environments;
    std::vector<MachOUuid> uuids;
    std::vector<MachOBuildVersion> build_versions;
    std::vector<MachOSourceVersion> source_versions;
    std::vector<MachONote> notes;
    std::vector<MachOFileSetEntry> fileset_entries;
    std::vector<MachOEntry> entries;
    std::vector<MachOInitializer> initializers;
    std::vector<MachOFunctionStart> function_starts;
    std::vector<MachOCompactUnwindFunction> compact_unwind_functions;
    std::vector<MachOEhFrameFunction> eh_frame_functions;
    std::vector<MachODynamicSymbolTable> dynamic_symbol_tables;
    std::vector<MachOIndirectSymbolBinding> indirect_symbol_bindings;
    bool indirect_symbol_bindings_complete = true;
    bool commands_complete = true, entries_conflict = false;
    std::vector<MachORelocationTable> relocation_tables;
    std::vector<MachORelocation> relocations;
    bool relocations_complete = true;
    std::vector<MachODyldStream> dyld_streams;
    std::vector<MachODyldOperation> dyld_operations;
    std::vector<MachODyldFixup> dyld_fixups;
    std::vector<MachODyldExport> dyld_exports;
    std::vector<MachOChainedHeader> chained_headers;
    std::vector<MachOChainedImport> chained_imports;
    std::vector<MachOChainedStarts> chained_starts;
    std::vector<MachOChainedPointer> chained_pointers;
    std::vector<MachOChainStartOffset> chain_start_offsets;
    std::vector<MachOFirmwareChainedPointer> firmware_chained_pointers;
    bool dyld_complete = true;
    // Signature bytes are declared, never authenticated by this parser.
    std::vector<MachOLinkeditDeclaration> data_in_code_tables, code_signatures;
    std::vector<MachOCodeSignatureBlob> code_signature_blobs;
    std::vector<MachODataInCode> data_in_code;
    std::vector<MachOEncryption> encryption;
    bool protections_complete = true;
    bool operator==(const MachOMetadata &) const = default;
};
} // namespace hexlab
