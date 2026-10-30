#pragma once
#include "hexlab/core/address.hpp"
#include <cstdint>
#include <optional>
#include <string>
#include <utility>
#include <vector>

namespace hexlab {
struct JvmConstant {
    std::uint8_t tag = 0;
    std::uint64_t first = 0, second = 0;
    std::string text;
    bool operator==(const JvmConstant &) const = default;
};
enum class JvmGenericSignatureKind : std::uint8_t { class_signature, method_signature, field_signature };
enum class JvmGenericNodeKind : std::uint8_t {
    class_signature, method_signature, field_signature, type_parameter,
    class_bound, interface_bound, superclass, superinterface, parameters,
    result, throws_type, primitive, void_type, class_type, class_segment,
    type_variable, array_type, exact_argument, extends_argument, super_argument,
    unbounded_argument
};
// Flat, ordered syntax tree. Child indexes refer to this signature's nodes;
// spans address the original CONSTANT_Utf8 bytes, preserving modified UTF-8.
struct JvmGenericSignatureNode {
    JvmGenericNodeKind kind=JvmGenericNodeKind::field_signature;
    std::uint32_t text_offset=0, text_size=0;
    std::string name;
    std::vector<std::uint32_t> children;
    bool operator==(const JvmGenericSignatureNode &) const = default;
};
struct JvmGenericSignature {
    JvmGenericSignatureKind kind=JvmGenericSignatureKind::field_signature;
    // The root is always node zero. Names and syntax do not prove type identity.
    std::vector<JvmGenericSignatureNode> nodes;
    bool operator==(const JvmGenericSignature &) const = default;
};
struct JvmGenericSignatureAnalysis {
    std::uint16_t signature_index=0;
    FileOffset reference_file_offset{}, text_file_offset{};
    std::optional<JvmGenericSignature> parsed;
    std::string diagnostic;
    bool operator==(const JvmGenericSignatureAnalysis &) const = default;
};
// BootstrapMethods entries retain constant-pool indices after loader validation.
// The indices address JvmMetadata::constant_pool and preserve argument order.
struct JvmBootstrapMethod {
    std::uint16_t method_handle_index = 0;
    std::vector<std::uint16_t> argument_indices;
    bool operator==(const JvmBootstrapMethod &) const = default;
};
// An attribute whose payload is not decoded by this loader is retained as a
// bounded file-backed extent. Consumers can inspect the original bytes without
// forcing a second copy into metadata memory.
struct JvmOpaqueAttribute {
    std::string name;
    FileOffset payload_file_offset{};
    std::uint32_t payload_size = 0;
    bool operator==(const JvmOpaqueAttribute &) const = default;
};
struct JvmExceptionHandler {
    std::uint16_t start_pc = 0, end_pc = 0, handler_pc = 0, catch_type = 0;
    bool operator==(const JvmExceptionHandler &) const = default;
};
struct JvmLineNumber {
    std::uint16_t start_pc = 0, line_number = 0;
    bool operator==(const JvmLineNumber &) const = default;
};
// Optional compiler debug mapping from half-open bytecode and source character
// intervals (CharacterRangeTable).
struct JvmCharacterRange {
    std::uint16_t start_pc = 0, end_pc = 0, flags = 0;
    std::uint32_t character_start = 0, character_end = 0;
    bool operator==(const JvmCharacterRange &) const = default;
};
struct JvmLocalVariable {
    std::uint16_t start_pc = 0, length = 0, name_index = 0, descriptor_index = 0, slot = 0;
    std::string name, descriptor;
    bool operator==(const JvmLocalVariable &) const = default;
};
// LocalVariableTypeTable retains generic local signatures as class-file text
// and a bounded field-signature grammar tree when parsing succeeds.
struct JvmLocalVariableType {
    std::uint16_t start_pc = 0, length = 0, name_index = 0, signature_index = 0, slot = 0;
    std::string name, signature;
    std::optional<JvmGenericSignatureAnalysis> generic_signature;
    bool operator==(const JvmLocalVariableType &) const = default;
};
// Annotation element values use a lossless, validated JVM-style textual form
// (for example `enum(Lx;#NAME)` or `[const(I:3),... ]`).
struct JvmAnnotationElement { std::string name, value; bool operator==(const JvmAnnotationElement &) const = default; };
struct JvmAnnotation { std::string descriptor; std::vector<JvmAnnotationElement> elements; bool operator==(const JvmAnnotation &) const = default; };
// Type annotations preserve the target_info encoding and validated type path
// in class-file order, alongside the decoded annotation payload.
struct JvmTypeAnnotation {
    std::uint8_t target_type = 0;
    std::vector<std::uint8_t> target_info;
    std::vector<std::pair<std::uint8_t, std::uint8_t>> type_path;
    JvmAnnotation annotation;
    bool operator==(const JvmTypeAnnotation &) const = default;
};
struct JvmMethodParameter {
    std::uint16_t name_index = 0, access_flags = 0;
    std::optional<std::string> name;
    bool operator==(const JvmMethodParameter &) const = default;
};
// Values retain the class-file verification_type_info tag. Long/double are
// one logical entry occupying two JVM local/operand locations.
enum class JvmVerificationKind : std::uint8_t {
    top = 0, integer = 1, float_value = 2, double_value = 3,
    long_value = 4, null_value = 5, uninitialized_this = 6,
    object = 7, uninitialized = 8
};
struct JvmVerificationType {
    JvmVerificationKind kind = JvmVerificationKind::top;
    // Nonzero for encoded Object entries and the implicit initialized this.
    std::uint16_t class_index = 0;
    // Meaningful only for uninitialized; zero is a valid new instruction offset.
    std::uint16_t uninitialized_offset = 0;
    // Implicit reference parameters may have no CONSTANT_Class entry. These
    // fields select their exact type in the owning JvmMember::descriptor.
    std::uint16_t descriptor_offset = 0, descriptor_length = 0;
    bool operator==(const JvmVerificationType &) const = default;
};
struct JvmStackMapFrame {
    std::uint8_t frame_type = 0;
    std::uint16_t offset_delta = 0;
    std::uint32_t bytecode_offset = 0;
    // Expanded relative to the preceding frame; category-2 entries are not
    // followed by synthetic Top values. Stack order is bottom to top.
    std::vector<JvmVerificationType> locals, stack;
    std::uint16_t local_slots = 0, stack_slots = 0;
    bool operator==(const JvmStackMapFrame &) const = default;
};
struct JvmStackMapTable {
    // The implicit method-entry frame, separate from encoded entries (which
    // may themselves apply at bytecode offset zero). Legacy StackMap entries
    // are normalized into the same expanded full-frame representation.
    std::vector<JvmVerificationType> initial_locals;
    std::uint16_t initial_local_slots = 0;
    std::vector<JvmStackMapFrame> frames;
    bool operator==(const JvmStackMapTable &) const = default;
};
struct JvmCode {
    Address begin;
    FileOffset file_begin;
    std::uint16_t max_stack = 0, max_locals = 0;
    std::uint32_t code_size = 0;
    std::vector<JvmExceptionHandler> exception_table;
    std::optional<std::vector<JvmLineNumber>> line_numbers;
    std::optional<std::vector<JvmCharacterRange>> character_ranges;
    std::optional<std::vector<JvmLocalVariable>> local_variables;
    std::optional<std::vector<JvmLocalVariableType>> local_variable_types;
    // Distinguishes an absent attribute from an explicitly empty table.
    std::optional<JvmStackMapTable> stack_map_table;
    std::vector<JvmTypeAnnotation> visible_type_annotations, invisible_type_annotations;
    std::vector<JvmOpaqueAttribute> opaque_attributes;
    bool operator==(const JvmCode &) const = default;
};
struct JvmMember {
    std::uint16_t access_flags = 0, name_index = 0, descriptor_index = 0;
    std::string name, descriptor;
    // Explicit legacy attributes are retained separately from access flags:
    // Deprecated has no class-file access-flag equivalent.
    bool synthetic_attribute = false, deprecated_attribute = false;
    std::optional<std::string> signature;
    std::optional<JvmGenericSignatureAnalysis> generic_signature;
    std::optional<std::vector<JvmMethodParameter>> method_parameters;
    // ConstantValue payload: numeric entries preserve their class-file bits;
    // strings contain the resolved CONSTANT_Utf8 text.
    std::optional<JvmConstant> constant_value;
    // Exceptions attribute class names, in class-file declaration order.
    std::optional<std::vector<std::string>> declared_exceptions;
    std::vector<JvmAnnotation> visible_annotations, invisible_annotations;
    // Parameter annotation vectors preserve the classfile's parameter order;
    // empty inner vectors represent parameters with no annotations.
    std::optional<std::vector<std::vector<JvmAnnotation>>> visible_parameter_annotations, invisible_parameter_annotations;
    // AnnotationDefault uses the same validated textual encoding as element values.
    std::optional<std::string> annotation_default;
    std::vector<JvmTypeAnnotation> visible_type_annotations, invisible_type_annotations;
    std::vector<JvmOpaqueAttribute> opaque_attributes;
    std::optional<JvmCode> code;
    bool operator==(const JvmMember &) const = default;
};
struct JvmRecordComponent {
    std::uint16_t name_index = 0, descriptor_index = 0;
    std::string name, descriptor;
    std::optional<std::string> signature;
    std::optional<JvmGenericSignatureAnalysis> generic_signature;
    std::vector<JvmAnnotation> visible_annotations, invisible_annotations;
    std::vector<JvmTypeAnnotation> visible_type_annotations, invisible_type_annotations;
    std::vector<JvmOpaqueAttribute> opaque_attributes;
    FileOffset file_begin{};
    std::uint64_t byte_size = 0; // Complete record_component_info, including nested attributes.
    bool operator==(const JvmRecordComponent &) const = default;
};
struct JvmRecordDeclaration {
    FileOffset attribute_file_offset{}; // Six-byte attribute header, not just its payload.
    std::uint32_t attribute_length = 0;
    bool operator==(const JvmRecordDeclaration &) const = default;
};
struct JvmInnerClass {
    std::string inner_class;
    std::optional<std::string> outer_class;
    std::optional<std::string> inner_name;
    std::uint16_t access_flags = 0;
    bool operator==(const JvmInnerClass &) const = default;
};
// EnclosingMethod retains the lexical owner and, when present, its method.
struct JvmEnclosingMethod {
    std::string class_name;
    std::optional<std::string> method_name;
    std::optional<std::string> method_descriptor;
    bool operator==(const JvmEnclosingMethod &) const = default;
};
struct JvmModuleRequire {
    std::string module;
    std::uint16_t flags = 0;
    std::optional<std::string> version;
    bool operator==(const JvmModuleRequire &) const = default;
};
struct JvmModuleExport {
    std::string package_name;
    std::uint16_t flags = 0;
    std::vector<std::string> to_modules;
    bool operator==(const JvmModuleExport &) const = default;
};
struct JvmModuleProvide {
    std::string service;
    std::vector<std::string> implementations;
    bool operator==(const JvmModuleProvide &) const = default;
};
struct JvmModule {
    std::string name;
    std::uint16_t flags = 0;
    std::optional<std::string> version;
    std::vector<JvmModuleRequire> required_modules;
    std::vector<JvmModuleExport> exports, opens;
    std::vector<std::string> uses;
    std::vector<JvmModuleProvide> provides;
    bool operator==(const JvmModule &) const = default;
};
struct JvmModuleTarget {
    // Absent when the attribute's target_platform_index is zero.
    std::optional<std::string> platform;
    bool operator==(const JvmModuleTarget &) const = default;
};
struct JvmModuleHash {
    std::string module;
    std::vector<std::uint8_t> hash;
    bool operator==(const JvmModuleHash &) const = default;
};
// Optional class-path facts supplied by a linker or project loader. Names alone
// are not JVM type identities: defining loader identity is part of every node
// and edge. Missing nodes/edges remain unresolved rather than guessed.
struct JvmTypeIdentity {
    std::string class_name, defining_loader;
    bool operator==(const JvmTypeIdentity &) const = default;
};
struct JvmHierarchyClass {
    JvmTypeIdentity identity;
    std::optional<JvmTypeIdentity> superclass;
    std::vector<JvmTypeIdentity> interfaces;
    bool complete = false;
    bool operator==(const JvmHierarchyClass &) const = default;
};
// JDK-specific class-file provenance attributes. The index and reference
// offset preserve where the CONSTANT_Utf8 value came from in the classfile.
struct JvmProvenanceId {
    std::uint16_t constant_pool_index = 0;
    FileOffset reference_file_offset{};
    std::string value;
    bool operator==(const JvmProvenanceId &) const = default;
};
struct JvmSourceMapFile {
    std::uint32_t id = 0;
    std::string name;
    std::optional<std::string> path;
    bool operator==(const JvmSourceMapFile &) const = default;
};
// A compact JSR-45 LineInfo rule. For each input line in [input_start,
// input_start + repeat_count), it maps to output_start + n * output_increment
// through output_increment consecutive output lines.
struct JvmSourceMapLine {
    std::uint32_t input_start = 0, file_id = 0, repeat_count = 1;
    std::uint32_t output_start = 0, output_increment = 1;
    bool operator==(const JvmSourceMapLine &) const = default;
};
struct JvmSourceMapStratum {
    std::string name;
    std::vector<JvmSourceMapFile> files;
    std::vector<JvmSourceMapLine> lines;
    bool operator==(const JvmSourceMapStratum &) const = default;
};
struct JvmSourceDebugMap {
    std::string generated_file, default_stratum;
    std::vector<JvmSourceMapStratum> strata;
    bool operator==(const JvmSourceDebugMap &) const = default;
};
struct JvmClassReference {
    std::uint16_t constant_pool_index = 0;
    FileOffset reference_file_offset{};
    std::string class_name;
    bool operator==(const JvmClassReference &) const = default;
};
struct JvmMetadata {
    std::uint16_t minor_version = 0, major_version = 0, access_flags = 0, this_class = 0, super_class = 0;
    std::string class_name, super_name;
    bool synthetic_attribute = false, deprecated_attribute = false;
    std::optional<std::string> source_file;
    // Raw UTF-8 SourceDebugExtension payload (commonly a JSR-45 SMAP mapping).
    std::optional<std::string> source_debug_extension;
    std::optional<JvmSourceDebugMap> source_debug_map;
    std::optional<std::string> source_debug_map_diagnostic;
    std::optional<JvmProvenanceId> compilation_id, source_id;
    std::optional<std::string> signature;
    std::optional<JvmGenericSignatureAnalysis> generic_signature;
    // Empty identity means the defining loader is unknown. In that state only
    // same-class-name proofs are possible; hierarchy traversal is disabled.
    std::string defining_loader;
    std::vector<JvmHierarchyClass> known_hierarchy;
    std::vector<JvmConstant> constant_pool; // JVM's one-based indices; unusable slots are tag 0.
    std::optional<std::vector<JvmBootstrapMethod>> bootstrap_methods;
    std::vector<std::string> interfaces;
    // Presence distinguishes an empty Record attribute from no Record metadata.
    std::optional<JvmRecordDeclaration> record;
    std::vector<JvmRecordComponent> record_components;
    std::vector<JvmInnerClass> inner_classes;
    std::optional<JvmEnclosingMethod> enclosing_method;
    std::optional<std::string> nest_host;
    std::vector<std::string> nest_members, permitted_subclasses;
    std::optional<JvmClassReference> nest_host_reference;
    std::vector<JvmClassReference> nest_member_references, permitted_subclass_references;
    // Preview Valhalla Preload entries, retained in attribute order.
    std::optional<std::vector<JvmClassReference>> preload_classes;
    std::optional<JvmModule> module;
    std::optional<JvmModuleTarget> module_target;
    std::optional<std::uint16_t> module_resolution;
    std::optional<std::string> module_hash_algorithm;
    std::vector<JvmModuleHash> module_hashes;
    std::vector<std::string> module_packages;
    std::optional<std::string> module_main_class;
    std::vector<JvmMember> fields, methods;
    std::vector<JvmAnnotation> visible_annotations, invisible_annotations;
    std::vector<JvmTypeAnnotation> visible_type_annotations, invisible_type_annotations;
    std::vector<JvmOpaqueAttribute> opaque_attributes;
    bool operator==(const JvmMetadata &) const = default;
};
} // namespace hexlab
