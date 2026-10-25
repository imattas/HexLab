#pragma once

#include "hexlab/core/address.hpp"
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

enum class WasmDataMode : std::uint8_t { active, passive };
enum class WasmOffsetExpressionKind : std::uint8_t { i32_constant, global_get };
struct WasmDataSegment {
    WasmDataMode mode = WasmDataMode::active;
    std::uint32_t memory_index = 0;
    WasmOffsetExpressionKind offset_kind = WasmOffsetExpressionKind::i32_constant;
    // i32.const offsets are retained as their unsigned wasm32 bit pattern;
    // global.get offsets use this value as a global index.
    std::uint32_t offset_value = 0;
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
    std::vector<std::uint32_t> function_indices;
    FileOffset section_file_offset{};
    FileOffset entry_file_offset{};
    bool operator==(const WasmElementSegment &) const = default;
};

struct WasmTableElement {
    std::uint32_t slot = 0;
    std::uint32_t function_index = 0;
    bool operator==(const WasmTableElement &) const = default;
};

struct WasmFunctionName {
    std::uint32_t function_index = 0;
    std::string name;
    FileOffset entry_file_offset{};
    bool operator==(const WasmFunctionName &) const = default;
};

struct WasmLocalName {
    std::uint32_t function_index = 0, local_index = 0;
    std::string name;
    FileOffset entry_file_offset{};
    bool operator==(const WasmLocalName &) const = default;
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
    std::vector<WasmFunctionName> function_names;
    std::vector<WasmLocalName> local_names;
    bool operator==(const WasmMetadata &) const = default;
};

} // namespace hexlab
