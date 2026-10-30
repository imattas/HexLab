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
    bool prologue_end = false;
    bool epilogue_begin = false;
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
    std::string name; // Resolved from the validated DEX string_id table.
    bool operator==(const DexDeclaredField &) const = default;
};
struct DexDeclaredMethod {
    std::uint32_t method_index = 0;
    std::uint32_t access_flags = 0;
    std::uint32_t code_offset = 0; // Zero for abstract, native, or otherwise code-less methods.
    std::string name; // Resolved from the validated DEX string_id table.
    bool operator==(const DexDeclaredMethod &) const = default;
};
struct DexClassDefinition {
    std::uint32_t class_index = 0; // Type ID.
    std::uint32_t access_flags = 0;
    std::optional<std::uint32_t> superclass_index;
    std::optional<std::uint32_t> source_file_index;
    std::uint32_t class_data_offset = 0;
    std::uint32_t annotations_offset = 0; // Zero means no directory, not an empty directory.
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
    std::uint64_t byte_size = 0; // Exact encoded_value extent, including nested children for containers.
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
    std::uint64_t byte_size = 0; // Complete visibility + encoded_annotation extent.
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
struct DexAnnotationSet {
    std::uint64_t file_offset=0, byte_size=0;
    // Indexes into DexMetadata::annotations in the original set-entry order.
    // Empty vectors preserve an explicitly present empty annotation_set_item.
    std::vector<std::uint32_t> annotation_indices;
    bool operator==(const DexAnnotationSet &) const = default;
};
struct DexAnnotationSetRefList {
    std::uint64_t file_offset=0, byte_size=0;
    // Prototype parameter positions, excluding the implicit receiver. Zero
    // means absent annotations; a nonzero offset can name a present empty set.
    std::vector<std::uint32_t> set_offsets;
    bool operator==(const DexAnnotationSetRefList &) const = default;
};
struct DexAnnotationDirectoryEntry {
    std::uint32_t member_index=0, annotations_offset=0;
    std::uint64_t file_offset=0;
    bool operator==(const DexAnnotationDirectoryEntry &) const = default;
};
struct DexAnnotationDirectory {
    std::uint32_t class_def_index=0, class_annotations_offset=0;
    std::uint64_t file_offset=0, byte_size=0;
    std::vector<DexAnnotationDirectoryEntry> fields, methods, parameters;
    bool operator==(const DexAnnotationDirectory &) const = default;
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
struct DexMethodParameterMetadata {
    std::uint32_t method_index = 0, parameter_index = 0;
    std::optional<std::uint32_t> name_index;
    std::uint32_t access_flags = 0;
    std::uint64_t name_file_offset = 0, access_flags_file_offset = 0;
    bool operator==(const DexMethodParameterMetadata &) const = default;
};
struct DexMethodThrows {
    std::uint32_t method_index = 0;
    std::vector<std::uint32_t> type_indices;
    std::uint64_t value_file_offset = 0;
    std::uint64_t annotation_link_file_offset = 0;
    bool operator==(const DexMethodThrows &) const = default;
};
struct DexStringSource {
    std::uint32_t id_file_offset = 0, data_file_offset = 0;
    // Complete string_data_item, including ULEB128 length and NUL terminator.
    std::uint32_t data_size = 0, utf16_size = 0;
    bool operator==(const DexStringSource &) const = default;
};
struct DexFieldIdentifier {
    std::uint32_t declaring_type_index = 0, type_index = 0, name_index = 0;
    std::uint64_t file_offset = 0;
    bool operator==(const DexFieldIdentifier &) const = default;
};
struct DexMethodIdentifier {
    std::uint32_t declaring_type_index = 0, prototype_index = 0, name_index = 0;
    std::uint64_t file_offset = 0;
    bool operator==(const DexMethodIdentifier &) const = default;
};
struct DexMetadata {
    std::vector<DexMapItem> map_items;
    // Opaque header-declared link_data section. The format leaves its payload
    // unspecified; retain only its validated physical source extent.
    std::uint32_t link_data_offset = 0;
    std::uint32_t link_data_size = 0;
    // Complete identifier catalogs, in original table-index order. References
    // include members defined elsewhere; no external resolution is implied.
    std::vector<std::string> strings;
    std::vector<DexStringSource> string_sources;
    std::vector<DexFieldIdentifier> field_identifiers;
    std::vector<DexMethodIdentifier> method_identifiers;
    // Type IDs are retained once; prototype rows refer to this shared table.
    // This preserves complete descriptors without copying long class/array
    // descriptors into every prototype that uses them.
    std::vector<std::string> type_descriptors;
    // proto_id and method_id order is the DEX table index order.
    std::vector<DexReturnKind> prototype_return_kinds;
    std::vector<std::uint32_t> prototype_return_type_indices;
    // Half-open ranges into prototype_parameter_type_indices, one per proto
    // plus a terminal offset. Parameter entries remain in encoded order.
    std::vector<std::uint32_t> prototype_parameter_offsets;
    std::vector<std::uint32_t> prototype_parameter_type_indices;
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
    // Reachable containers retain the directory graph, including empty sets
    // and null parameter positions that produce no flattened annotation link.
    std::vector<DexAnnotationSet> annotation_sets;
    std::vector<DexAnnotationSetRefList> annotation_set_ref_lists;
    std::vector<DexAnnotationDirectory> annotation_directories;
    std::vector<DexHiddenApiFlag> hidden_api_flags;
    // Decoded dalvik.annotation.MethodParameters rows, linked by method ID.
    std::vector<DexMethodParameterMetadata> method_parameters;
    // Decoded dalvik.annotation.Throws value arrays, linked by method ID.
    // Type assignability and duplicate type entries are retained, not resolved.
    std::vector<DexMethodThrows> method_throws;
    bool operator==(const DexMetadata &) const = default;
};
}
