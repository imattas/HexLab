#pragma once
#include <cstdint>
#include <optional>
#include <string>
#include <vector>

namespace hexlab {
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
struct DexMetadata {
    std::vector<DexMethodDebug> methods;
    std::vector<DexMethodCode> code;
    std::vector<DexStaticValue> static_values;
    std::vector<DexMethodHandle> method_handles;
    std::vector<DexCallSite> call_sites;
    std::vector<DexAnnotationItem> annotations;
    std::vector<DexAnnotationLink> annotation_links;
    bool operator==(const DexMetadata &) const = default;
};
}
