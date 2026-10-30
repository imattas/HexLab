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
    std::optional<std::uint64_t> allocation_base;
    std::optional<std::uint32_t> allocation_protect;
    bool operator==(const MinidumpMemoryRegion &) const = default;
};
struct MinidumpMemoryInfo {
    std::uint64_t base = 0, allocation_base = 0, region_size = 0;
    std::uint32_t allocation_protect = 0, protect = 0, state = 0, type = 0;
    FileOffset record_file_offset{};
    bool operator==(const MinidumpMemoryInfo &) const = default;
};
enum class MinidumpPdbStatus : std::uint8_t { unavailable, missing, malformed, mismatch, ambiguous, matched, unsupported_identity };
struct MinidumpPdbSymbol {
    std::string name, module_name, object_name;
    std::uint16_t section = 0, module_index = 0, record_kind = 0;
    std::uint32_t section_offset = 0, size = 0, record_offset = 0;
    bool procedure = false, public_symbol = false;
    bool operator==(const MinidumpPdbSymbol &) const = default;
};
struct MinidumpModule {
    std::uint64_t image_base = 0;
    std::uint32_t image_size = 0, checksum = 0, timestamp = 0;
    std::string name;
    // The 13 DWORD VS_FIXEDFILEINFO payload is preserved verbatim in field
    // order. Its signature is checked before CLI version tuples are shown.
    std::array<std::uint32_t, 13> version_info{};
    bool version_info_signature_valid = false;
    FileOffset version_info_file_offset{};
    std::uint32_t cv_record_size = 0, cv_record_rva = 0;
    // RSDS and NB10 CodeView identities retain the exact PDB path bytes because
    // CodeView does not identify the path's character encoding.
    std::string codeview_kind, pdb_path;
    std::array<std::byte, 16> pdb_guid{};
    std::uint32_t pdb_age = 0, pdb_timestamp = 0;
    MinidumpPdbStatus pdb_status = MinidumpPdbStatus::unavailable;
    std::string bound_pdb_path, pdb_diagnostic;
    std::uint32_t pdb_symbol_count = 0;
    bool pdb_symbols_complete = false;
    std::vector<MinidumpPdbSymbol> pdb_symbols;
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
// The object-specific information payload is OS- and type-specific. Keep its
// bytes opaque while decoding the linked-list header and preserving provenance.
struct MinidumpHandleObjectInformation {
    std::uint32_t next_info_rva = 0, info_type = 0, size_of_info = 0;
    FileOffset record_file_offset{}, data_file_offset{};
    std::vector<std::byte> data;
    bool operator==(const MinidumpHandleObjectInformation &) const = default;
};
struct MinidumpHandle {
    std::uint64_t handle = 0;
    std::uint32_t attributes = 0, granted_access = 0, handle_count = 0, pointer_count = 0;
    std::uint32_t object_info_rva = 0, reserved = 0;
    std::string type_name, object_name;
    std::vector<MinidumpHandleObjectInformation> object_information;
    FileOffset record_file_offset{}, type_name_file_offset{}, object_name_file_offset{};
    bool operator==(const MinidumpHandle &) const = default;
};
// Fixed-width AVRF_HANDLE_OPERATION prefix. Captured traces are historical
// return-address storage, not a reconstructed or symbolized live call stack.
struct MinidumpHandleOperation {
    std::uint64_t handle = 0;
    std::uint32_t process_id = 0, thread_id = 0, operation_type = 0, spare = 0;
    std::uint32_t backtrace_depth = 0, backtrace_index = 0;
    std::array<std::uint64_t, 32> return_addresses{};
    FileOffset record_file_offset{}, return_addresses_file_offset{};
    std::uint32_t record_size = 0;
    bool operator==(const MinidumpHandleOperation &) const = default;
};
struct MinidumpHandleOperationList {
    FileOffset header_file_offset{};
    std::uint32_t header_size = 0, entry_size = 0;
    std::vector<MinidumpHandleOperation> operations;
    bool operator==(const MinidumpHandleOperationList &) const = default;
};
// Token payloads can contain security-sensitive OS-specific information. Keep
// them opaque and expose only the validated record prefix and source extent.
struct MinidumpTokenInfo {
    std::uint32_t token_size = 0, token_id = 0;
    std::uint64_t token_handle = 0;
    FileOffset record_file_offset{}, payload_file_offset{};
    std::uint32_t payload_size = 0;
    bool operator==(const MinidumpTokenInfo &) const = default;
};
struct MinidumpTokenInfoList {
    FileOffset header_file_offset{};
    std::uint32_t stream_size = 0, list_header_size = 0, element_header_size = 0;
    std::vector<MinidumpTokenInfo> tokens;
    bool operator==(const MinidumpTokenInfoList &) const = default;
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
    // Present for MINIDUMP_THREAD_EX records; backing-store bytes are not
    // mapped unless another memory stream covers them.
    std::uint64_t backing_store_address = 0;
    std::uint32_t backing_store_size = 0, backing_store_rva = 0;
    bool extended_record = false;
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
    // MINIDUMP_MISC_INFO_2 processor fields are valid only when Flags1 bit
    // MINIDUMP_MISC1_PROCESSOR_POWER_INFO is set and the declared prefix covers them.
    std::optional<std::uint32_t> processor_max_mhz, processor_current_mhz, processor_mhz_limit;
    std::optional<std::uint32_t> processor_max_idle_state, processor_current_idle_state;
    FileOffset stream_file_offset{};
    std::array<FileOffset, 5> processor_power_field_offsets{};
    std::uint32_t declared_size = 0;
    bool operator==(const MinidumpProcessInfo &) const = default;
};
struct MinidumpVmCounters {
    std::uint16_t revision = 0, flags = 0;
    std::uint32_t page_fault_count = 0;
    // Revision 1 carries the first nine counters; revision 2 adds nine more.
    // Values are kept in the documented field order, without guessing units.
    std::array<std::uint64_t, 18> counters{};
    std::uint8_t counter_count = 0;
    std::uint32_t stream_size = 0;
    FileOffset stream_file_offset{};
    bool operator==(const MinidumpVmCounters &) const = default;
};
// The table's native descriptor and function entries are platform-specific.
// Preserve their validated source extents while decoding the generic range.
struct MinidumpFunctionTable {
    std::uint64_t minimum_address = 0, maximum_address = 0, base_address = 0;
    std::uint32_t entry_count = 0, align_pad_size = 0;
    FileOffset descriptor_file_offset{}, native_descriptor_file_offset{}, entries_file_offset{};
    bool operator==(const MinidumpFunctionTable &) const = default;
};
struct MinidumpFunctionTableList {
    FileOffset stream_file_offset{};
    std::uint32_t stream_size = 0, header_size = 0, descriptor_size = 0;
    std::uint32_t native_descriptor_size = 0, function_entry_size = 0, align_pad_size = 0;
    std::vector<MinidumpFunctionTable> tables;
    bool operator==(const MinidumpFunctionTableList &) const = default;
};
struct MinidumpSystemFileCacheInfo {
    std::uint64_t current_size = 0, peak_size = 0;
    std::uint32_t page_fault_count = 0;
    std::uint64_t minimum_working_set = 0, maximum_working_set = 0;
    std::uint64_t current_size_including_transition_pages = 0;
    std::uint64_t peak_size_including_transition_pages = 0;
    std::uint32_t transition_repurpose_count = 0, flags = 0;
    bool transition_repurpose_count_valid = false;
    bool operator==(const MinidumpSystemFileCacheInfo &) const = default;
};
struct MinidumpSystemBasicPerformanceInfo {
    std::uint64_t available_pages = 0, committed_pages = 0;
    std::uint64_t commit_limit = 0, peak_commitment = 0;
    bool operator==(const MinidumpSystemBasicPerformanceInfo &) const = default;
};
struct MinidumpSystemMemoryInfo {
    std::uint16_t revision = 0, flags = 0;
    std::uint32_t timer_resolution = 0, page_size = 0, physical_page_count = 0;
    std::uint32_t lowest_physical_page = 0, highest_physical_page = 0, allocation_granularity = 0;
    std::uint64_t minimum_user_address = 0, maximum_user_address = 0, active_processor_affinity = 0;
    std::uint32_t processor_count = 0, stream_size = 0;
    // Optional trailing groups are retained only when their complete extent is
    // available; the validity of the transition count is recorded separately.
    std::optional<MinidumpSystemFileCacheInfo> file_cache;
    std::optional<MinidumpSystemBasicPerformanceInfo> basic_performance;
    FileOffset stream_file_offset{};
    bool operator==(const MinidumpSystemMemoryInfo &) const = default;
};
struct MinidumpComment {
    std::uint32_t stream_type = 0, stream_size = 0;
    FileOffset stream_file_offset{};
    // Comment streams are retained as source bytes so their original encoding
    // and any non-text extensions are not silently normalized. CommentStreamW
    // additionally exposes decoded UTF-8 only when the captured UTF-16LE is
    // complete and well-formed.
    std::vector<std::byte> captured_bytes;
    std::optional<std::string> decoded_text;
    bool truncated = false;
    bool operator==(const MinidumpComment &) const = default;
};
struct MinidumpLinuxProcStatusField {
    std::string key, value;
    FileOffset line_file_offset{};
    bool operator==(const MinidumpLinuxProcStatusField &) const = default;
};
struct MinidumpLinuxProcStatus {
    FileOffset stream_file_offset{};
    std::uint32_t declared_size = 0;
    std::string captured_text;
    std::vector<MinidumpLinuxProcStatusField> fields;
    bool complete = true;
    bool operator==(const MinidumpLinuxProcStatus &) const = default;
};
struct MinidumpLinuxMemoryMap {
    std::uint64_t start = 0, end = 0, file_offset = 0, inode = 0;
    std::uint32_t device_major = 0, device_minor = 0;
    bool readable = false, writable = false, executable = false, shared = false;
    std::string permissions, path;
    FileOffset line_file_offset{};
    bool operator==(const MinidumpLinuxMemoryMap &) const = default;
};
struct MinidumpLinuxAuxvEntry {
    std::uint64_t type = 0, value = 0;
    FileOffset record_file_offset{};
    std::uint8_t word_size = 0;
    bool operator==(const MinidumpLinuxAuxvEntry &) const = default;
};
struct MinidumpLinuxTextStream {
    std::uint32_t stream_type = 0, declared_size = 0;
    FileOffset stream_file_offset{};
    // Breakpad Linux streams are retained byte-for-byte because cmdline and
    // environ use NUL separators and maps/cpuinfo have platform-specific text.
    std::vector<std::byte> captured_bytes;
    // Populated only for Breakpad's Linux maps stream. Invalid rows remain in
    // captured_bytes and make maps_complete false.
    std::vector<MinidumpLinuxMemoryMap> memory_maps;
    bool maps_complete = true;
    // Populated for Breakpad's binary auxiliary-vector stream when the
    // SystemInfo architecture gives an unambiguous native word width.
    std::vector<MinidumpLinuxAuxvEntry> auxiliary_values;
    bool auxiliary_values_complete = true;
    bool truncated = false;
    bool operator==(const MinidumpLinuxTextStream &) const = default;
};
struct MinidumpAssertionInfo {
    std::string expression, function, file;
    std::uint32_t line = 0, type = 0;
    FileOffset stream_file_offset{};
    bool operator==(const MinidumpAssertionInfo &) const = default;
};
struct MinidumpSystemInfo {
    std::uint16_t processor_architecture = 0xffff, processor_level = 0, processor_revision = 0;
    std::uint8_t processor_count = 0, product_type = 0;
    std::uint32_t major_version = 0, minor_version = 0, build_number = 0, platform_id = 0;
    std::uint16_t suite_mask = 0;
    std::string service_pack;
    // Architecture-specific CPU union bytes are preserved without assigning
    // meaning to a layout that may not match the advertised architecture.
    std::vector<std::byte> cpu_information;
    FileOffset cpu_information_file_offset{};
    struct X86CpuInfo {
        std::array<char, 12> vendor_id{};
        std::uint32_t version_information = 0, feature_information = 0;
        std::uint32_t amd_extended_cpu_features = 0;
        FileOffset source_file_offset{};
        bool operator==(const X86CpuInfo &) const = default;
    };
    std::optional<X86CpuInfo> x86_cpu_info;
    bool operator==(const MinidumpSystemInfo &) const = default;
};
struct MinidumpMetadata {
    std::uint16_t processor_architecture = 0xffff;
    std::uint8_t processor_count = 0;
    std::uint32_t timestamp = 0, flags_low = 0;
    std::uint64_t flags = 0;
    std::vector<MinidumpStream> streams;
    std::vector<MinidumpMemoryRegion> memory;
    // All MemoryInfoList records, including ranges with no captured bytes.
    std::vector<MinidumpMemoryInfo> memory_info;
    std::vector<MinidumpModule> modules;
    std::vector<MinidumpUnloadedModule> unloaded_modules;
    std::vector<MinidumpThread> threads;
    std::vector<MinidumpThreadName> thread_names;
    std::vector<MinidumpThreadInfo> thread_info;
    std::vector<MinidumpHandle> handles;
    // Presence preserves an explicitly captured empty operation list.
    std::optional<MinidumpHandleOperationList> handle_operations;
    std::optional<MinidumpTokenInfoList> token_info;
    std::optional<MinidumpException> exception;
    std::optional<MinidumpProcessInfo> process_info;
    std::optional<MinidumpVmCounters> vm_counters;
    std::optional<MinidumpSystemMemoryInfo> system_memory_info;
    std::optional<MinidumpFunctionTableList> function_tables;
    std::vector<MinidumpComment> comments;
    std::optional<MinidumpLinuxProcStatus> linux_proc_status;
    std::vector<MinidumpLinuxTextStream> linux_text_streams;
    std::optional<MinidumpAssertionInfo> assertion;
    std::optional<MinidumpSystemInfo> system_info;
    std::vector<std::string> diagnostics;
    bool operator==(const MinidumpMetadata &) const = default;
};
} // namespace hexlab
