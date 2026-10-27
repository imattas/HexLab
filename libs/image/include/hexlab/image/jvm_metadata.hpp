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
struct JvmExceptionHandler {
    std::uint16_t start_pc = 0, end_pc = 0, handler_pc = 0, catch_type = 0;
    bool operator==(const JvmExceptionHandler &) const = default;
};
struct JvmLineNumber {
    std::uint16_t start_pc = 0, line_number = 0;
    bool operator==(const JvmLineNumber &) const = default;
};
struct JvmLocalVariable {
    std::uint16_t start_pc = 0, length = 0, name_index = 0, descriptor_index = 0, slot = 0;
    std::string name, descriptor;
    bool operator==(const JvmLocalVariable &) const = default;
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
    // may themselves apply at bytecode offset zero).
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
    std::optional<std::vector<JvmLocalVariable>> local_variables;
    // Distinguishes an absent attribute from an explicitly empty table.
    std::optional<JvmStackMapTable> stack_map_table;
    std::vector<JvmTypeAnnotation> visible_type_annotations, invisible_type_annotations;
    bool operator==(const JvmCode &) const = default;
};
struct JvmMember {
    std::uint16_t access_flags = 0, name_index = 0, descriptor_index = 0;
    std::string name, descriptor;
    std::optional<std::string> signature;
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
    std::optional<JvmCode> code;
    bool operator==(const JvmMember &) const = default;
};
struct JvmRecordComponent {
    std::uint16_t name_index = 0, descriptor_index = 0;
    std::string name, descriptor;
    std::optional<std::string> signature;
    bool operator==(const JvmRecordComponent &) const = default;
};
struct JvmInnerClass {
    std::string inner_class;
    std::optional<std::string> outer_class;
    std::optional<std::string> inner_name;
    std::uint16_t access_flags = 0;
    bool operator==(const JvmInnerClass &) const = default;
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
struct JvmMetadata {
    std::uint16_t minor_version = 0, major_version = 0, access_flags = 0, this_class = 0, super_class = 0;
    std::string class_name, super_name;
    std::optional<std::string> source_file;
    std::optional<std::string> signature;
    // Empty identity means the defining loader is unknown. In that state only
    // same-class-name proofs are possible; hierarchy traversal is disabled.
    std::string defining_loader;
    std::vector<JvmHierarchyClass> known_hierarchy;
    std::vector<JvmConstant> constant_pool; // JVM's one-based indices; unusable slots are tag 0.
    std::vector<std::string> interfaces;
    std::vector<JvmRecordComponent> record_components;
    std::vector<JvmInnerClass> inner_classes;
    std::optional<std::string> nest_host;
    std::vector<std::string> nest_members, permitted_subclasses;
    std::optional<JvmModule> module;
    std::vector<std::string> module_packages;
    std::optional<std::string> module_main_class;
    std::vector<JvmMember> fields, methods;
    std::vector<JvmAnnotation> visible_annotations, invisible_annotations;
    std::vector<JvmTypeAnnotation> visible_type_annotations, invisible_type_annotations;
    bool operator==(const JvmMetadata &) const = default;
};
} // namespace hexlab
