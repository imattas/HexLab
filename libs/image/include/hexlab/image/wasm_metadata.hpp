#pragma once

#include "hexlab/core/address.hpp"
#include <cstddef>
#include <cstdint>
#include <optional>
#include <string>
#include <vector>

namespace hexlab {

enum class WasmExternalKind : std::uint8_t { function = 0, table = 1, memory = 2, global = 3 };

struct WasmLimits {
    std::uint32_t minimum = 0;
    std::optional<std::uint32_t> maximum;
    bool shared = false;
    bool operator==(const WasmLimits &) const = default;
};

struct WasmFunctionType {
    std::uint32_t parameter_count = 0;
    std::uint32_t result_count = 0;
    // Numeric MVP value-type codes, in declaration order. Retained so local
    // access lifting can recover typed function parameters without guessing.
    std::vector<std::uint8_t> parameter_types;
    std::vector<std::uint8_t> result_types;
    bool operator==(const WasmFunctionType &) const = default;
};

struct WasmImport {
    std::string module, name;
    WasmExternalKind kind = WasmExternalKind::function;
    // Index in the kind-specific module index space, including defined items.
    std::uint32_t index = 0;
    std::optional<std::uint32_t> function_type_index;
    std::optional<WasmLimits> limits;
    std::optional<std::uint8_t> global_value_type;
    bool global_mutable = false;
    // Caller-supplied symbolic host mapping. This identifies an external
    // binding for analysis only; the loader never resolves or invokes it.
    std::optional<std::string> host_binding;
    std::uint32_t entry_index = 0;
    FileOffset section_file_offset{};
    FileOffset entry_file_offset{};
    bool operator==(const WasmImport &) const = default;
};

struct WasmExport {
    std::string name;
    WasmExternalKind kind = WasmExternalKind::function;
    // Index in the kind-specific module index space.
    std::uint32_t index = 0;
    // Resolved from the function index space when kind == function.
    std::optional<std::uint32_t> function_type_index;
    // Resolved from the corresponding kind-specific index space. Table and
    // memory exports retain their limits; global exports retain their value
    // type and mutability.
    std::optional<WasmLimits> limits;
    std::optional<std::uint8_t> global_value_type;
    bool global_mutable = false;
    std::uint32_t entry_index = 0;
    FileOffset section_file_offset{};
    FileOffset entry_file_offset{};
    bool operator==(const WasmExport &) const = default;
};

struct WasmStartFunction {
    // Index in the combined imported-then-defined function index space.
    std::uint32_t function_index = 0;
    std::uint32_t function_type_index = 0;
    FileOffset section_file_offset{};
    FileOffset entry_file_offset{};
    bool operator==(const WasmStartFunction &) const = default;
};

// Producer custom-section metadata is descriptive only and never affects
// module validation or execution. Unknown field/tool names are preserved.
struct WasmProducer {
    std::string field, name, version;
    FileOffset entry_file_offset{};
    bool operator==(const WasmProducer &) const = default;
};

// Feature declarations from the tool-conventions target_features section.
// These describe the module's intended target and do not change MVP validation.
struct WasmTargetFeature {
    std::string name;
    bool enabled = false;
    FileOffset entry_file_offset{};
    bool operator==(const WasmTargetFeature &) const = default;
};

struct WasmDylinkNeeded {
    std::string name;
    FileOffset entry_file_offset{};
    bool operator==(const WasmDylinkNeeded &) const = default;
};

struct WasmDylinkPath {
    std::string path;
    FileOffset entry_file_offset{};
    bool operator==(const WasmDylinkPath &) const = default;
};

struct WasmDylinkExportInfo {
    std::string name;
    std::uint32_t flags = 0;
    FileOffset entry_file_offset{};
    bool operator==(const WasmDylinkExportInfo &) const = default;
};

struct WasmDylinkImportInfo {
    std::string module, name;
    std::uint32_t flags = 0;
    FileOffset entry_file_offset{};
    bool operator==(const WasmDylinkImportInfo &) const = default;
};

struct WasmDylinkOpaqueSubsection {
    std::uint8_t id = 0;
    FileOffset entry_file_offset{};
    std::vector<std::byte> payload;
    bool operator==(const WasmDylinkOpaqueSubsection &) const = default;
};

struct WasmDylinkInfo {
    std::uint32_t memory_size = 0, memory_alignment = 0;
    std::uint32_t table_size = 0, table_alignment = 0;
    bool memory_info_present = false;
    FileOffset section_file_offset{};
    std::vector<WasmDylinkNeeded> needed;
    std::vector<WasmDylinkPath> runtime_paths;
    std::vector<WasmDylinkExportInfo> exports;
    std::vector<WasmDylinkImportInfo> imports;
    std::vector<WasmDylinkOpaqueSubsection> unknown_subsections;
    bool operator==(const WasmDylinkInfo &) const = default;
};

// A bounded inventory row for any custom section. The section and payload
// ranges point into the original module; payload bytes remain opaque here.
struct WasmCustomSection {
    std::string name;
    FileOffset section_file_offset{};
    std::uint32_t section_size = 0;
    FileOffset payload_file_offset{};
    std::uint32_t payload_size = 0;
    bool operator==(const WasmCustomSection &) const = default;
};

enum class WasmDataMode : std::uint8_t { active, passive };
enum class WasmOffsetExpressionKind : std::uint8_t { i32_constant, global_get, extended_integer };
struct WasmConstantInstruction {
    std::uint8_t opcode = 0;
    // Integer literal bits or immutable-global index; zero for arithmetic.
    std::uint64_t immediate = 0;
    FileOffset file_offset{};
    bool operator==(const WasmConstantInstruction &) const = default;
};
struct WasmDataSegment {
    WasmDataMode mode = WasmDataMode::active;
    std::uint32_t memory_index = 0;
    WasmOffsetExpressionKind offset_kind = WasmOffsetExpressionKind::i32_constant;
    // i32.const offsets are retained as their unsigned wasm32 bit pattern;
    // global.get offsets use this value as a global index.
    std::uint32_t offset_value = 0;
    FileOffset offset_expression_file_offset{};
    std::vector<WasmConstantInstruction> offset_instructions;
    std::optional<std::uint32_t> evaluated_offset_value;
    std::uint32_t byte_count = 0;
    FileOffset section_file_offset{};
    FileOffset entry_file_offset{};
    FileOffset bytes_file_offset{};
    bool operator==(const WasmDataSegment &) const = default;
};

enum class WasmElementMode : std::uint8_t { active, passive, declarative };
struct WasmElementSegment {
    WasmElementMode mode = WasmElementMode::active;
    std::uint32_t table_index = 0;
    WasmOffsetExpressionKind offset_kind = WasmOffsetExpressionKind::i32_constant;
    std::uint32_t offset_value = 0;
    FileOffset offset_expression_file_offset{};
    std::vector<WasmConstantInstruction> offset_instructions;
    std::optional<std::uint32_t> evaluated_offset_value;
    // One entry per element expression; an empty optional represents ref.null.
    std::vector<std::optional<std::uint32_t>> function_indices;
    FileOffset section_file_offset{};
    FileOffset entry_file_offset{};
    bool operator==(const WasmElementSegment &) const = default;
};

struct WasmTableElement {
    std::uint32_t slot = 0;
    std::uint32_t function_index = 0;
    bool operator==(const WasmTableElement &) const = default;
};

enum class WasmGlobalInitializerKind : std::uint8_t { numeric_constant, global_get, ref_null, ref_func, extended_integer };
struct WasmGlobalInitializer {
    WasmGlobalInitializerKind kind = WasmGlobalInitializerKind::numeric_constant;
    // Numeric constants retain their exact unsigned bit pattern, including
    // floating-point NaN payloads and signed zero. global_get/ref_func retain
    // the referenced global/function index; ref_null has value zero.
    std::uint64_t value = 0;
    FileOffset expression_file_offset{};
    // Present only for extended integer expressions. Instructions retain
    // source order and exclude the final end opcode; value is unused.
    std::vector<WasmConstantInstruction> instructions;
    std::optional<std::uint64_t> evaluated_value_bits;
    bool operator==(const WasmGlobalInitializer &) const = default;
};

struct WasmGlobal {
    std::uint8_t value_type = 0;
    bool mutable_value = false;
    bool imported = false;
    // Imported values are supplied by the host and have no initializer.
    std::optional<WasmGlobalInitializer> initializer;
    // Optional raw host value supplied by a caller-side import resolver.
    // Numeric values preserve their exact bits; funcref values are unsupported.
    std::optional<std::uint64_t> host_value_bits;
    FileOffset section_file_offset{};
    FileOffset entry_file_offset{};
    bool operator==(const WasmGlobal &) const = default;
};

struct WasmFunctionName {
    std::uint32_t function_index = 0;
    std::string name;
    FileOffset entry_file_offset{};
    bool operator==(const WasmFunctionName &) const = default;
};

struct WasmModuleName {
    std::string name;
    FileOffset entry_file_offset{};
    bool operator==(const WasmModuleName &) const = default;
};

// Name-section index associations for subsection IDs 4..9 (type, table,
// memory, global, element-segment, and data-segment index spaces).
struct WasmIndexName {
    std::uint8_t subsection_id = 0;
    std::uint32_t index = 0;
    std::string name;
    FileOffset entry_file_offset{};
    bool operator==(const WasmIndexName &) const = default;
};

struct WasmLocalName {
    std::uint32_t function_index = 0, local_index = 0;
    std::string name;
    FileOffset entry_file_offset{};
    bool operator==(const WasmLocalName &) const = default;
};

struct WasmLabelName {
    std::uint32_t function_index = 0, label_index = 0;
    std::string name;
    FileOffset entry_file_offset{};
    bool operator==(const WasmLabelName &) const = default;
};

struct WasmLinkingSegmentInfo {
    std::uint32_t segment_index = 0, alignment_log2 = 0, flags = 0;
    std::string name;
    FileOffset entry_file_offset{};
    bool operator==(const WasmLinkingSegmentInfo &) const = default;
};

struct WasmLinkingSymbol {
    // Linking-convention symbol kind: function=0, data=1, global=2,
    // section=3, event=4, table=5.
    std::uint8_t kind = 0;
    std::uint32_t flags = 0, index = 0;
    // Present for explicit/defined symbol names. Import names are kept in the
    // separate fields when the linking table inherits them from the import.
    std::optional<std::string> name;
    std::optional<std::string> import_module, import_name;
    std::optional<std::uint32_t> data_segment_index, data_offset, data_size;
    std::optional<std::uint8_t> common_alignment_log2;
    FileOffset entry_file_offset{};
    bool operator==(const WasmLinkingSymbol &) const = default;
};

// Parsed metadata from tool-conventions `reloc.*` custom sections. The loader
// inventories references but does not apply relocations.
struct WasmRelocation {
    std::uint32_t offset = 0, index = 0;
    std::uint8_t type = 0;
    std::optional<std::int32_t> addend;
    FileOffset entry_file_offset{};
    bool operator==(const WasmRelocation &) const = default;
};
struct WasmRelocationSection {
    std::string name;
    std::uint32_t target_section_index = 0;
    FileOffset section_file_offset{};
    std::vector<WasmRelocation> entries;
    bool operator==(const WasmRelocationSection &) const = default;
};

struct WasmFunctionLocals {
    // Function index in the full imported-then-defined index space.
    std::uint32_t function_index = 0;
    // Declared local value types, excluding parameters, in local-index order.
    std::vector<std::uint8_t> value_types;
    bool operator==(const WasmFunctionLocals &) const = default;
};

struct WasmMetadata {
    std::uint32_t type_count = 0;
    std::uint32_t imported_functions = 0, imported_tables = 0, imported_memories = 0, imported_globals = 0;
    std::uint32_t defined_functions = 0, defined_tables = 0, defined_memories = 0, defined_globals = 0;
    // Full function index space: imported functions first, then defined functions.
    std::vector<std::uint32_t> function_type_indices;
    std::vector<WasmFunctionType> function_types;
    std::vector<WasmImport> imports;
    std::vector<WasmExport> exports;
    std::optional<WasmStartFunction> start_function;
    std::vector<WasmProducer> producers;
    std::vector<WasmTargetFeature> target_features;
    std::optional<WasmDylinkInfo> dylink;
    std::vector<WasmCustomSection> custom_sections;
    std::optional<std::uint32_t> declared_data_count;
    std::vector<WasmDataSegment> data_segments;
    std::vector<WasmLimits> defined_memory_limits;
    std::vector<WasmLimits> defined_table_limits;
    // Active constant-offset data segments are exposed in a separate wasm32
    // address space when their initial memory image can be reconstructed.
    // Imported memory leaves untouched bytes unmapped because their initial
    // contents are supplied by the host.
    std::optional<AddressSpaceId> linear_memory_space;
    std::uint64_t linear_memory_size = 0;
    bool linear_memory_complete = false;
    std::vector<WasmElementSegment> element_segments;
    std::uint32_t initial_table_element_count = 0;
    bool initial_table_complete = false;
    // Sparse non-null slots after applying active element segments in module
    // order. Defined-table holes are null; imported-table holes are unknown.
    std::vector<WasmTableElement> initial_table_elements;
    // Full imported-then-defined global index space.
    std::vector<WasmGlobal> globals;
    std::vector<WasmFunctionName> function_names;
    std::vector<WasmLocalName> local_names;
    std::vector<WasmLabelName> label_names;
    std::vector<WasmLinkingSegmentInfo> linking_segments;
    bool linking_segment_info_present = false;
    std::vector<WasmLinkingSymbol> linking_symbols;
    bool linking_symbol_table_present = false;
    std::vector<WasmRelocationSection> relocation_sections;
    std::optional<WasmModuleName> module_name;
    std::vector<WasmIndexName> index_names;
    // Expanded, bounded local declarations for defined functions only.
    std::vector<WasmFunctionLocals> function_locals;
    bool operator==(const WasmMetadata &) const = default;
};

} // namespace hexlab
