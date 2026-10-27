#pragma once
#include "hexlab/core/address.hpp"
#include "hexlab/core/byte_reader.hpp"
#include <array>
#include <cstdint>
#include <optional>
#include <string>
#include <vector>

namespace hexlab {
struct MinidumpStream {
    std::uint32_t type = 0, size = 0, rva = 0;
    bool operator==(const MinidumpStream &) const = default;
};
struct MinidumpMemoryRegion {
    Address begin{};
    std::uint64_t size = 0;
    FileOffset file_begin{};
    std::uint32_t protect = 0, state = 0, type = 0;
    bool readable = true, writable = false, executable = false;
    bool operator==(const MinidumpMemoryRegion &) const = default;
};
struct MinidumpModule {
    std::uint64_t image_base = 0;
    std::uint32_t image_size = 0, checksum = 0, timestamp = 0;
    std::string name;
    std::uint32_t cv_record_size = 0, cv_record_rva = 0;
    // RSDS and NB10 CodeView identities retain the exact PDB path bytes because
    // CodeView does not identify the path's character encoding.
    std::string codeview_kind, pdb_path;
    std::array<std::byte, 16> pdb_guid{};
    std::uint32_t pdb_age = 0, pdb_timestamp = 0;
    bool operator==(const MinidumpModule &) const = default;
};
struct MinidumpUnloadedModule {
    std::uint64_t image_base = 0;
    std::uint32_t image_size = 0, checksum = 0, timestamp = 0;
    std::string name;
    // File offsets of the descriptor and its MINIDUMP_STRING.
    FileOffset record_file_offset{}, name_file_offset{};
    bool operator==(const MinidumpUnloadedModule &) const = default;
};
struct MinidumpThreadName {
    std::uint32_t thread_id = 0;
    std::string name;
    // File offsets of the MINIDUMP_THREAD_NAME row and its MINIDUMP_STRING.
    FileOffset record_file_offset{}, string_file_offset{};
    bool operator==(const MinidumpThreadName &) const = default;
};
struct MinidumpThreadInfo {
    std::uint32_t thread_id = 0, dump_flags = 0, dump_error = 0, exit_status = 0;
    std::uint64_t create_time = 0, exit_time = 0, kernel_time = 0, user_time = 0;
    std::uint64_t start_address = 0, affinity = 0;
    // File offset of the extensible MINIDUMP_THREAD_INFO row.
    FileOffset record_file_offset{};
    bool operator==(const MinidumpThreadInfo &) const = default;
};
struct MinidumpRegister {
    std::string name;
    std::uint64_t value = 0;
    std::uint8_t width = 0;
    // Exact little-endian captured bytes, including registers wider than value.
    // value is meaningful only for registers of at most 64 bits.
    std::vector<std::byte> bytes;
    FileOffset file_offset{};
    bool operator==(const MinidumpRegister &) const = default;
};
enum class MinidumpContextStatus : std::uint8_t {
    decoded, partial, not_captured, unsupported_architecture, architecture_mismatch, malformed
};
struct MinidumpContext {
    std::uint16_t processor_architecture = 0xffff;
    std::uint64_t flags = 0;
    bool control_valid = false, integer_valid = false;
    std::vector<MinidumpRegister> registers;
    std::vector<std::string> diagnostics;
    MinidumpContextStatus status = MinidumpContextStatus::not_captured;
    bool architecture_valid = false, segments_valid = false, floating_valid = false, debug_valid = false;
    bool floating_low_valid = false, floating_high_valid = false;
    std::uint32_t requested_groups = 0, decoded_groups = 0;
    std::uint32_t source_rva = 0, source_size = 0;
    ByteOrder byte_order = ByteOrder::little;
    // Bounded fixed-layout prefix. Source size may also include unsupported
    // extended state, whose original file extent remains inspectable.
    std::vector<std::byte> captured_prefix;
    bool operator==(const MinidumpContext &) const = default;
};
struct MinidumpThread {
    std::uint32_t id = 0, suspend_count = 0, priority_class = 0, priority = 0;
    std::uint64_t teb = 0, stack_address = 0;
    std::uint32_t stack_size = 0, stack_rva = 0;
    std::uint32_t context_size = 0, context_rva = 0;
    std::optional<MinidumpContext> context;
    FileOffset record_file_offset{};
    bool operator==(const MinidumpThread &) const = default;
};
struct MinidumpException {
    std::uint32_t thread_id = 0, code = 0, flags = 0, parameter_count = 0;
    std::uint64_t address = 0, record = 0;
    std::vector<std::uint64_t> parameters;
    std::uint32_t context_size = 0, context_rva = 0;
    std::optional<MinidumpContext> context;
    FileOffset record_file_offset{};
    bool operator==(const MinidumpException &) const = default;
};
struct MinidumpProcessInfo {
    // MINIDUMP_MISC_INFO Flags1 bits gate which base process fields are valid.
    std::uint32_t flags = 0;
    std::optional<std::uint32_t> process_id;
    std::optional<std::uint32_t> process_create_time;
    std::optional<std::uint32_t> process_user_time;
    std::optional<std::uint32_t> process_kernel_time;
    bool operator==(const MinidumpProcessInfo &) const = default;
};
struct MinidumpMetadata {
    std::uint16_t processor_architecture = 0xffff;
    std::uint8_t processor_count = 0;
    std::uint32_t timestamp = 0, flags_low = 0;
    std::uint64_t flags = 0;
    std::vector<MinidumpStream> streams;
    std::vector<MinidumpMemoryRegion> memory;
    std::vector<MinidumpModule> modules;
    std::vector<MinidumpUnloadedModule> unloaded_modules;
    std::vector<MinidumpThread> threads;
    std::vector<MinidumpThreadName> thread_names;
    std::vector<MinidumpThreadInfo> thread_info;
    std::optional<MinidumpException> exception;
    std::optional<MinidumpProcessInfo> process_info;
    std::vector<std::string> diagnostics;
    bool operator==(const MinidumpMetadata &) const = default;
};
} // namespace hexlab
