#pragma once
#include "hexlab/core/address.hpp"
#include <cstdint>
#include <optional>
#include <string>
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
    // Distinguishes an absent attribute from an explicitly empty table.
    std::optional<JvmStackMapTable> stack_map_table;
    bool operator==(const JvmCode &) const = default;
};
struct JvmMember {
    std::uint16_t access_flags = 0, name_index = 0, descriptor_index = 0;
    std::string name, descriptor;
    std::optional<JvmCode> code;
    bool operator==(const JvmMember &) const = default;
};
struct JvmRecordComponent {
    std::uint16_t name_index = 0, descriptor_index = 0;
    std::string name, descriptor;
    std::optional<std::string> signature;
    bool operator==(const JvmRecordComponent &) const = default;
};
struct JvmMetadata {
    std::uint16_t minor_version = 0, major_version = 0, access_flags = 0, this_class = 0, super_class = 0;
    std::string class_name, super_name;
    std::vector<JvmConstant> constant_pool; // JVM's one-based indices; unusable slots are tag 0.
    std::vector<std::string> interfaces;
    std::vector<JvmRecordComponent> record_components;
    std::optional<std::string> nest_host;
    std::vector<std::string> nest_members, permitted_subclasses;
    std::vector<JvmMember> fields, methods;
    bool operator==(const JvmMetadata &) const = default;
};
} // namespace hexlab
