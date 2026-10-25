#pragma once
#include "hexlab/core/byte_reader.hpp"
#include "hexlab/core/address.hpp"
#include "hexlab/symbols/dwarf.hpp"
#include <optional>
#include <string>
#include <vector>
namespace hexlab {
struct ElfTable {
    std::uint64_t offset = 0, stride = 0, count = 0;
    bool operator==(const ElfTable &) const = default;
};
struct ElfHeader {
    bool is_64 = false;
    ByteOrder order = ByteOrder::little;
    std::uint16_t object_type = 0, machine = 0;
    std::uint32_t version = 0, flags = 0;
    std::uint64_t entry = 0;
    std::uint8_t os_abi = 0, abi_version = 0;
    ElfTable programs, sections;
    std::uint64_t section_names = 0;
    bool operator==(const ElfHeader &) const = default;
};
struct ElfProgram {
    std::uint32_t index = 0, type = 0, flags = 0;
    std::uint64_t offset = 0, address = 0, physical_address = 0, file_size = 0, memory_size = 0, alignment = 0;
    bool operator==(const ElfProgram &) const = default;
};
struct ElfSection {
    std::uint32_t index = 0, name_index = 0, type = 0, link = 0, info = 0;
    std::uint64_t flags = 0, address = 0, offset = 0, size = 0, alignment = 0, entry_size = 0;
    std::string name;
    bool operator==(const ElfSection &) const = default;
};
enum class ElfSymbolState { undefined, defined, absolute, common, tls, reserved };
struct ElfTableSource {
    std::optional<std::uint32_t> section;
    std::uint64_t file_offset = 0;
    std::optional<Address> address;
    bool operator==(const ElfTableSource &) const = default;
};
enum class ElfSymbolCountSource { section, explicit_size, sysv_hash, gnu_hash, unavailable };
struct ElfSymbolTable {
    ElfTableSource source;
    std::uint64_t stride = 0;
    std::optional<std::uint64_t> count, symbol_begin;
    ElfSymbolCountSource count_source = ElfSymbolCountSource::section;
    bool operator==(const ElfSymbolTable &) const = default;
};
struct ElfSymbol {
    std::optional<std::uint32_t> table;
    std::uint64_t table_offset = 0;
    std::optional<Address> table_address;
    std::uint32_t index = 0, name_index = 0, section_index = 0;
    std::uint16_t raw_section = 0;
    std::uint8_t binding = 0, type = 0, other = 0, visibility = 0;
    std::uint64_t value = 0, size = 0;
    std::string name;
    ElfSymbolState state = ElfSymbolState::undefined;
    std::optional<Address> address;
    // GNU ELF symbol versions remain separate from the base symbol name.
    // Index 0/1 have their ABI-defined local/global meanings and no version name.
    std::uint16_t version_index = 0;
    bool version_hidden = false;
    std::optional<std::string> version_name, version_file;
    bool operator==(const ElfSymbol &) const = default;
};
enum class ElfRelocationKind {
    none,
    absolute,
    pc_relative,
    plt_relative,
    got,
    global_data,
    jump_slot,
    base_relative,
    copy,
    symbol_size,
    tls,
    ifunc,
    unknown,
    plt_absolute
};
struct ElfRelocation {
    ElfTableSource source;
    std::uint32_t index = 0, type = 0, symbol_index = 0;
    bool symbol_index_validated = false;
    std::optional<ElfTableSource> symbol_table;
    std::optional<std::uint32_t> target_section;
    std::uint64_t offset = 0;
    bool explicit_addend = false;
    std::optional<std::int64_t> addend;
    std::optional<std::uint64_t> field_size;
    ElfRelocationKind kind = ElfRelocationKind::unknown;
    std::optional<Address> place;
    std::optional<FileOffset> file_place;
    std::uint64_t record_file_offset = 0, record_stride = 0;
    bool operator==(const ElfRelocation &) const = default;
};
struct ElfRelocationTable {
    ElfTableSource source;
    std::uint64_t size = 0, stride = 0;
    bool explicit_addend = false;
    std::optional<ElfTableSource> symbol_table;
    std::optional<std::uint32_t> target_section;
    std::vector<std::uint64_t> rows;
    bool operator==(const ElfRelocationTable &) const = default;
};
struct ElfDynamicRelocationTable {
    std::int64_t tag = 0;
    std::uint64_t table_index = 0;
    bool operator==(const ElfDynamicRelocationTable &) const = default;
};
struct ElfInterpreter {
    std::uint32_t program = 0;
    std::uint64_t file_offset = 0, size = 0;
    std::string path;
    bool operator==(const ElfInterpreter &) const = default;
};
struct ElfNote {
    std::uint32_t program = 0;
    std::uint64_t file_offset = 0, description_file_offset = 0;
    std::uint32_t type = 0;
    std::string name;
    std::vector<std::byte> description;
    bool operator==(const ElfNote &) const = default;
};
enum class ElfCoreThreadStatus { decoded, unsupported, malformed };
struct ElfCoreRegister {
    std::string name;
    std::uint64_t value = 0;
    // Width of the stored gregset word, not the architectural selector width.
    std::uint16_t bits = 0, gregset_index = 0;
    std::uint64_t file_offset = 0;
    // Linux MIPS deliberately writes zero for the unsaved k0/k1 slots.
    bool kernel_placeholder = false;
    bool operator==(const ElfCoreRegister &) const = default;
};
struct ElfCoreThread {
    std::uint32_t process_id = 0, parent_process_id = 0, process_group_id = 0, session_id = 0;
    std::optional<std::int16_t> current_signal;
    std::uint64_t note_file_offset = 0;
    ElfCoreThreadStatus status = ElfCoreThreadStatus::unsupported;
    std::vector<ElfCoreRegister> registers;
    std::string diagnostic;
    std::uint64_t payload_file_offset = 0;
    std::optional<std::uint64_t> gregset_file_offset;
    std::uint16_t gregset_slots = 0, register_word_bits = 0;
    ByteOrder register_byte_order = ByteOrder::little;
    std::string register_layout;
    std::optional<std::uint32_t> floating_point_valid;
    bool operator==(const ElfCoreThread &) const = default;
};
struct ElfCoreAuxiliaryValue {
    std::uint64_t type = 0, value = 0;
    std::uint64_t note_file_offset = 0, entry_file_offset = 0;
    bool operator==(const ElfCoreAuxiliaryValue &) const = default;
};
struct ElfCoreFileMapping {
    std::uint64_t start = 0, end = 0, file_offset = 0;
    std::uint64_t note_file_offset = 0, entry_file_offset = 0;
    std::string path;
    bool operator==(const ElfCoreFileMapping &) const = default;
};
struct ElfCoreSignalInfo {
    std::int32_t signal = 0, error = 0, code = 0;
    std::optional<std::uint64_t> fault_address;
    std::uint64_t note_file_offset = 0, payload_file_offset = 0;
    bool operator==(const ElfCoreSignalInfo &) const = default;
};
struct ElfCoreInfo {
    std::optional<std::uint32_t> process_id, parent_process_id, process_group_id, session_id;
    std::optional<std::string> executable, arguments;
    std::vector<ElfCoreThread> threads;
    std::vector<ElfCoreAuxiliaryValue> auxiliary_values;
    std::vector<ElfCoreFileMapping> file_mappings;
    std::vector<ElfCoreSignalInfo> signal_info;
    // PT_LOAD records remain in ElfMetadata::programs and image segments retain
    // their original file offsets. This counts the memory segments surfaced.
    std::uint32_t load_segment_count = 0;
    std::vector<std::string> diagnostics;
    bool operator==(const ElfCoreInfo &) const = default;
};
struct ElfSourceLine {
    Address address;
    std::string file;
    std::int64_t line = 0;
    std::uint64_t column = 0;
    bool end_sequence = false;
    bool operator==(const ElfSourceLine &) const = default;
};
enum class ElfCfiSectionKind : std::uint8_t { eh_frame, debug_frame };
// A validated function range decoded from one ELF CFI FDE. The source fields
// identify the exact FDE bytes so downstream analysis can retain evidence.
struct ElfUnwindRange {
    std::uint32_t section = 0;
    std::uint64_t file_offset = 0, record_size = 0;
    Address begin;
    std::uint64_t size = 0;
    ElfCfiSectionKind source_kind = ElfCfiSectionKind::eh_frame;
    bool operator==(const ElfUnwindRange &) const = default;
};
// An encoded exception pointer. value is the decoded direct address or, for
// indirect encodings, the address of the unresolved pointer slot. No runtime
// relocation or memory dereference is performed. A zero value is a null pointer.
struct ElfEhFramePointer {
    std::uint8_t encoding = 0;
    std::uint64_t encoding_file_offset = 0, file_offset = 0, encoded_size = 0, value = 0;
    std::optional<Address> target;
    bool operator==(const ElfEhFramePointer &) const = default;
};
// Bounded x86-64/AArch64/ARM32/RV32/RV64 ELF CFI recipe for caller unwinding.
struct ElfEhFrameFunction {
    std::uint32_t section = 0;
    std::uint64_t file_offset = 0, record_size = 0;
    Address begin;
    std::uint64_t size = 0, code_alignment = 1;
    std::int64_t data_alignment = 0;
    std::uint64_t return_register = 0;
    std::vector<std::byte> cie_instructions, instructions;
    std::optional<ElfEhFramePointer> personality, lsda;
    std::optional<std::uint8_t> lsda_encoding;
    std::optional<std::uint64_t> lsda_encoding_file_offset;
    std::uint64_t cie_file_offset = 0;
    ElfCfiSectionKind source_kind = ElfCfiSectionKind::eh_frame;
    bool operator==(const ElfEhFrameFunction &) const = default;
};
// Structural Itanium C++ ABI metadata. Addresses are link-time image addresses;
// parsed slots are candidate executable targets and do not prove call-site dispatch.
enum class ElfRttiDescriptorKind : std::uint8_t { class_type, single_inheritance, multiple_inheritance };
struct ElfRttiBase {
    Address type_info;
    std::optional<std::string> mangled_name;
    std::int64_t offset_flags = 0;
    std::int64_t base_offset = 0;
    bool is_virtual = false, is_public = false;
    bool operator==(const ElfRttiBase &) const = default;
};
struct ElfRttiClass {
    Address type_info;
    Address descriptor_vtable;
    std::optional<std::string> mangled_name;
    ElfRttiDescriptorKind descriptor_kind = ElfRttiDescriptorKind::class_type;
    std::vector<ElfRttiBase> direct_bases;
    std::optional<std::string> diagnostic;
    bool operator==(const ElfRttiClass &) const = default;
};
enum class ElfVTableSlotState : std::uint8_t {
    resolved_executable,
    null_pointer,
    unresolved,
    ambiguous,
    non_executable_target
};
struct ElfVTableSlot {
    std::uint32_t index = 0;
    Address slot;
    std::optional<Address> target;
    ElfVTableSlotState state = ElfVTableSlotState::unresolved;
    bool operator==(const ElfVTableSlot &) const = default;
};
struct ElfVTableHeader {
    Address symbol_begin, address_point;
    std::int64_t offset_to_top = 0;
    std::optional<Address> type_info;
    std::optional<std::string> type_name;
    std::uint32_t symbol_index = 0;
    // Slots are populated only for a primary address point whose type_info is
    // validated. A symbol may contain secondary tables; parsing stops before
    // the next recognized two-word table header.
    std::vector<ElfVTableSlot> slots;
    bool slots_scanned = false;
    bool slots_complete = false;
    bool operator==(const ElfVTableHeader &) const = default;
};
struct ElfDynamicEntry {
    std::uint32_t index = 0;
    std::int64_t tag = 0;
    std::uint64_t value = 0;
    std::optional<std::string> string_value;
    bool operator==(const ElfDynamicEntry &) const = default;
};
struct ElfDynamicTable {
    ElfTableSource source;
    std::optional<std::uint32_t> program;
    std::uint64_t size = 0, stride = 0;
    std::vector<ElfDynamicEntry> entries;
    std::optional<ElfTableSource> symbol_table;
    std::vector<ElfDynamicRelocationTable> relocation_tables;
    bool operator==(const ElfDynamicTable &) const = default;
};
struct ElfMetadata {
    ElfHeader header;
    std::vector<ElfProgram> programs;
    std::vector<ElfSection> sections;
    std::vector<ElfSymbol> symbols;
    std::vector<ElfSymbolTable> symbol_tables;
    std::vector<ElfRelocation> relocations;
    std::vector<ElfRelocationTable> relocation_tables;
    bool relocations_complete = true;
    std::optional<ElfInterpreter> interpreter;
    std::vector<ElfNote> notes;
    std::optional<ElfCoreInfo> core;
    std::vector<ElfSourceLine> source_lines;
    // Parsed project-importable DWARF v4/v5 records. The parser retains its
    // source provenance and never evaluates variable locations.
    std::optional<symbols::ImportResult> dwarf_info;
    std::vector<ElfUnwindRange> unwind_ranges;
    // Legacy name: includes validated .eh_frame and .debug_frame recipes.
    // source_kind identifies the record's actual CFI section format.
    std::vector<ElfEhFrameFunction> eh_frame_functions;
    std::vector<ElfRttiClass> rtti_classes;
    std::vector<ElfVTableHeader> vtable_headers;
    bool rtti_complete = true;
    std::vector<ElfDynamicTable> dynamic_tables;
    bool dynamic_complete = true;
    bool operator==(const ElfMetadata &) const = default;
};
} // namespace hexlab
