#pragma once
#include <cstdint>
#include <optional>
#include <string>
#include <vector>

namespace hexlab {
struct DexMapItem {
    std::uint16_t type = 0; // DEX map_item type code.
    std::uint32_t size = 0; // Number of items in the section.
    std::uint32_t offset = 0; // Section start in the DEX file.
    bool operator==(const DexMapItem &) const = default;
};
struct DexDebugLine {
    std::uint32_t address = 0; // Byte offset in the method-relative address space.
    std::uint32_t line = 0;
    std::string source_file;
    bool operator==(const DexDebugLine &) const = default;
};
struct DexDebugLocal {
    std::uint32_t register_index = 0;
    std::uint32_t begin = 0, end = 0; // Half-open byte offsets in the method.
    std::optional<std::string> name, type, signature;
    bool parameter = false;
    bool operator==(const DexDebugLocal &) const = default;
};
struct DexMethodDebug {
    std::uint32_t method_index = 0;
    std::uint32_t line_start = 0;
    std::vector<std::optional<std::string>> parameter_names;
    std::vector<DexDebugLine> lines;
    std::vector<DexDebugLocal> locals;
    bool operator==(const DexMethodDebug &) const = default;
};
struct DexExceptionHandler {
    std::uint32_t address = 0; // Byte offset in the method-relative address space.
    std::optional<std::uint32_t> type_index; // Empty for the encoded catch-all.
    bool operator==(const DexExceptionHandler &) const = default;
};
struct DexExceptionRegion {
    std::uint32_t begin = 0, end = 0; // Half-open byte offsets in the method.
    std::vector<DexExceptionHandler> handlers; // Encoded order, including catch-all last.
    bool operator==(const DexExceptionRegion &) const = default;
};
struct DexMethodCode {
    std::uint32_t method_index = 0;
    std::uint32_t register_count = 0;
    std::uint32_t incoming_register_count = 0;
    std::vector<DexExceptionRegion> exception_regions;
    bool operator==(const DexMethodCode &) const = default;
};
struct DexDeclaredField {
    std::uint32_t field_index = 0;
    std::uint32_t access_flags = 0;
    bool operator==(const DexDeclaredField &) const = default;
};
struct DexDeclaredMethod {
    std::uint32_t method_index = 0;
    std::uint32_t access_flags = 0;
    std::uint32_t code_offset = 0; // Zero for abstract, native, or otherwise code-less methods.
    bool operator==(const DexDeclaredMethod &) const = default;
};
struct DexClassDefinition {
    std::uint32_t class_index = 0; // Type ID.
    std::uint32_t access_flags = 0;
    std::optional<std::uint32_t> superclass_index;
    std::optional<std::uint32_t> source_file_index;
    std::uint32_t class_data_offset = 0;
    std::vector<std::uint32_t> interface_indices;
    std::vector<DexDeclaredField> static_fields, instance_fields;
    std::vector<DexDeclaredMethod> direct_methods, virtual_methods;
    bool operator==(const DexClassDefinition &) const = default;
};
// A lossless, bounded representation of DEX encoded_value. The raw payload
// preserves the encoded scalar bits (floating point encodings are normalized
// to their full 32/64-bit width); index-valued tags retain the referenced
// table index. Annotation children carry their element name index.
struct DexEncodedValue {
    std::uint8_t type = 0; // DEX VALUE_* tag.
    std::uint8_t value_arg = 0;
    std::uint64_t payload = 0;
    std::uint32_t name_index = UINT32_MAX; // Set only for annotation elements.
    std::uint64_t file_offset = 0;
    std::vector<DexEncodedValue> children; // Array elements or annotation elements.
    bool operator==(const DexEncodedValue &) const = default;
};
struct DexStaticValue {
    std::uint32_t class_index = 0;
    std::uint32_t field_index = 0;
    DexEncodedValue value;
    bool operator==(const DexStaticValue &) const = default;
};
struct DexMethodHandle {
    std::uint16_t kind = 0; // DEX method_handle_type (static/instance field or method operation).
    std::uint32_t member_index = 0; // Field ID for kinds 0..3; method ID for kinds 4..8.
    std::uint64_t file_offset = 0; // method_handle_item start in the DEX file.
    bool operator==(const DexMethodHandle &) const = default;
};
struct DexCallSite {
    std::uint64_t file_offset = 0; // call_site_item encoded_array start in the DEX file.
    // Bootstrap handle, method name, method type, then ordered bootstrap arguments.
    std::vector<DexEncodedValue> values;
    bool operator==(const DexCallSite &) const = default;
};
// Compact return-value shape retained from each DEX proto_id. It is enough to
// type invoke results without duplicating potentially large type descriptors.
enum class DexReturnKind : std::uint8_t { unknown, void_value, integer32, float32, integer64, float64, reference };
struct DexAnnotationItem {
    std::uint8_t visibility = 0; // DEX build, runtime, or system visibility.
    std::uint32_t type_index = 0;
    std::uint64_t file_offset = 0; // annotation_item start in the DEX file.
    std::vector<DexEncodedValue> elements; // name_index is set on each element value.
    bool operator==(const DexAnnotationItem &) const = default;
};
enum class DexAnnotationTargetKind : std::uint8_t { class_def, field, method, parameter };
struct DexAnnotationLink {
    DexAnnotationTargetKind kind = DexAnnotationTargetKind::class_def;
    std::uint32_t class_def_index = 0;
    std::uint32_t member_index = UINT32_MAX; // Field or method ID; unset for class targets.
    std::uint32_t parameter_index = UINT32_MAX; // Set only for parameter targets.
    std::uint32_t annotation_index = 0; // Index in DexMetadata::annotations.
    std::uint64_t file_offset = 0; // Exact file location of the annotation-set offset reference.
    bool operator==(const DexAnnotationLink &) const = default;
};
enum class DexHiddenApiMemberKind : std::uint8_t { field, method };
struct DexHiddenApiFlag {
    std::uint32_t class_def_index = 0;
    DexHiddenApiMemberKind kind = DexHiddenApiMemberKind::field;
    std::uint32_t member_index = 0;
    std::uint32_t flags = 0; // Retained raw ULEB128 value; interpretation varies by Android release.
    std::uint64_t file_offset = 0; // Exact source offset of the encoded flag.
    bool operator==(const DexHiddenApiFlag &) const = default;
};
struct DexMetadata {
    std::vector<DexMapItem> map_items;
    // proto_id and method_id order is the DEX table index order.
    std::vector<DexReturnKind> prototype_return_kinds;
    // Number of Dalvik register words occupied by each prototype's parameters.
    // Wide primitive parameters count as two; the implicit receiver is excluded.
    std::vector<std::uint32_t> prototype_parameter_word_counts;
    std::vector<std::uint32_t> method_prototype_indices;
    std::vector<DexClassDefinition> classes;
    std::vector<DexMethodDebug> methods;
    std::vector<DexMethodCode> code;
    std::vector<DexStaticValue> static_values;
    std::vector<DexMethodHandle> method_handles;
    std::vector<DexCallSite> call_sites;
    std::vector<DexAnnotationItem> annotations;
    std::vector<DexAnnotationLink> annotation_links;
    std::vector<DexHiddenApiFlag> hidden_api_flags;
    bool operator==(const DexMetadata &) const = default;
};
}
