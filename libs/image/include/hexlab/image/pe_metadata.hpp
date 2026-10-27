#pragma once
#include "hexlab/core/address.hpp"
#include "hexlab/image/pe_rtti.hpp"
#include <array>
#include <cstddef>
#include <cstdint>
#include <memory>
#include <optional>
#include <string>
#include <vector>

namespace hexlab {
enum class PeRuntimeArchitecture : std::uint8_t { arm64, x64_compatible };

struct PeImageCoffSymbol {
    std::string name;
    std::uint32_t table_index = 0, value = 0;
    std::int16_t section_number = 0;
    std::uint16_t type = 0;
    std::uint8_t storage_class = 0, auxiliary_count = 0;
    FileOffset source_file_offset{};
    std::optional<Address> address;
    bool operator==(const PeImageCoffSymbol &) const = default;
};

struct PeCertificateRecord {
    std::uint32_t length = 0;
    std::uint16_t revision = 0, type = 0;
    PeRecordSource source;
    std::vector<PeSourceSpan> payload;
    bool operator==(const PeCertificateRecord &) const = default;
};
struct PeCertificateTable {
    FileOffset file_offset{};
    std::uint32_t size = 0;
    PeRecordSource source;
    std::vector<PeCertificateRecord> records;
    bool operator==(const PeCertificateTable &) const = default;
};
struct PeImportSource {
    PeRecordSource descriptor;
    bool delay_load = false;
    std::vector<PeSourceSpan> lookup_thunk;
    std::vector<PeSourceSpan> iat_thunk;
    std::optional<std::vector<PeSourceSpan>> library_name;
    std::optional<std::vector<PeSourceSpan>> symbol_name;
    bool operator==(const PeImportSource &) const = default;
};
struct PeBoundImportForwarder {
    std::uint32_t timestamp = 0;
    std::string library;
    PeRecordSource descriptor;
    std::vector<PeSourceSpan> library_name;
    bool operator==(const PeBoundImportForwarder &) const = default;
};
struct PeBoundImport {
    std::uint32_t timestamp = 0;
    std::string library;
    PeRecordSource descriptor;
    std::vector<PeSourceSpan> library_name;
    std::vector<PeBoundImportForwarder> forwarders;
    bool operator==(const PeBoundImport &) const = default;
};
struct PeExportSource {
    PeRecordSource address_table;
    std::optional<PeRecordSource> name_table;
    std::optional<std::vector<PeSourceSpan>> name;
    std::optional<std::vector<PeSourceSpan>> forwarder;
    bool operator==(const PeExportSource &) const = default;
};
struct PeRelocationSource {
    PeRecordSource block_header;
    PeRecordSource entry;
    std::optional<std::int16_t> highadj_addend;
    std::optional<PeRecordSource> addend_entry;
    bool operator==(const PeRelocationSource &) const = default;
};
struct PeTlsCallback {
    std::uint64_t rva = 0;
    PeRecordSource source;
    bool operator==(const PeTlsCallback &) const = default;
};
// IMAGE_TLS_DIRECTORY fields are preferred-base VAs in the file. The public
// metadata stores normalized RVAs so it remains valid when the image is rebased.
struct PeTlsDirectory {
    std::uint64_t template_rva = 0, template_size = 0;
    std::uint64_t index_rva = 0, callbacks_rva = 0;
    std::uint32_t zero_fill = 0, characteristics = 0;
    PeRecordSource directory;
    std::vector<PeTlsCallback> callbacks;
    std::optional<PeRecordSource> callback_terminator;
    bool operator==(const PeTlsDirectory &) const = default;
};
struct PeGuardCfFunction {
    std::uint32_t rva = 0;
    std::vector<std::byte> metadata;
    PeRecordSource source;
    bool operator==(const PeGuardCfFunction &) const = default;
};
struct PeLoadConfigTarget {
    std::uint32_t rva = 0;
    PeRecordSource source;
    bool operator==(const PeLoadConfigTarget &) const = default;
};
enum class PeDynamicRelocationStatus : std::uint8_t { decoded_layout, unsupported, malformed };
enum class PeDynamicRelocationFixupKind : std::uint8_t { zero_fill, value, delta };
enum class PeDynamicRelocationApplicationStatus : std::uint8_t {
    not_attempted, applied, unsupported, conflict, malformed
};
struct PeDynamicRelocationAppliedFixup {
    std::uint32_t record_index = 0, fixup_index = 0;
    bool operator==(const PeDynamicRelocationAppliedFixup &) const = default;
};
struct PeDynamicRelocationFixup {
    PeDynamicRelocationFixupKind kind = PeDynamicRelocationFixupKind::zero_fill;
    std::uint8_t argument = 0;
    std::uint32_t rva = 0;
    std::uint8_t size = 0;
    // VALUE carries exact replacement bytes. DELTA is a signed, scaled
    // addition to a 32-bit target; ZERO_FILL has neither payload.
    std::vector<std::byte> value;
    std::optional<std::int32_t> delta;
    PeRecordSource source;
    bool operator==(const PeDynamicRelocationFixup &) const = default;
};
struct PeDynamicRelocationRecord {
    std::uint64_t symbol = 0;
    std::uint32_t symbol_group = 0, flags = 0;
    std::uint32_t header_size = 0, fixup_size = 0;
    std::uint32_t fixup_rva = 0;
    std::vector<PeSourceSpan> header_extension;
    std::vector<PeDynamicRelocationFixup> fixups;
    bool fixups_decoded = false;
    PeRecordSource source;
    std::optional<PeRecordSource> fixup_source;
    std::string diagnostic;
    bool operator==(const PeDynamicRelocationRecord &) const = default;
};
struct PeDynamicRelocationTable {
    PeDynamicRelocationStatus status = PeDynamicRelocationStatus::unsupported;
    std::uint32_t version = 0, size = 0;
    PeRecordSource source;
    std::vector<PeDynamicRelocationRecord> records;
    PeDynamicRelocationApplicationStatus application_status = PeDynamicRelocationApplicationStatus::not_attempted;
    std::vector<PeDynamicRelocationAppliedFixup> applied_fixups;
    std::string application_diagnostic;
    std::string diagnostic;
    bool operator==(const PeDynamicRelocationTable &) const = default;
};
enum class PeChpeCodeRangeKind : std::uint8_t { arm64, arm64ec, amd64 };
struct PeChpeCodeRange {
    std::uint32_t start_rva = 0, length = 0;
    PeChpeCodeRangeKind kind = PeChpeCodeRangeKind::arm64;
    PeRecordSource source;
    bool operator==(const PeChpeCodeRange &) const = default;
};
// CHPE metadata keeps code-map ranges in RVAs. The loader publishes validated,
// non-overlapping rows as an ImageExecutionProfile for range-aware decoding.
struct PeChpeMetadata {
    std::uint32_t version = 0, metadata_rva = 0, code_map_rva = 0;
    std::uint32_t code_map_count = 0;
    PeRecordSource source, code_map_source;
    std::vector<PeChpeCodeRange> code_ranges;
    bool operator==(const PeChpeMetadata &) const = default;
};
// Supported load-config pointer fields are normalized to RVAs; fields with
// per-record or table payloads retain their source spans and decoded rows.
// Unknown versioned tail fields remain opaque.
struct PeLoadConfiguration {
    std::uint32_t declared_size = 0, timestamp = 0;
    std::uint16_t major_version = 0, minor_version = 0;
    std::uint32_t guard_flags = 0;
    std::optional<std::uint64_t> dynamic_value_relocation_table_rva;
    std::optional<PeRecordSource> dynamic_value_relocation_table_pointer_source;
    std::optional<PeDynamicRelocationTable> dynamic_value_relocations;
    std::optional<PeChpeMetadata> chpe_metadata;
    std::optional<std::uint64_t> security_cookie_rva;
    std::optional<PeRecordSource> security_cookie_source;
    // PE32 SafeSEH handler table; entries are sorted executable RVAs.
    std::optional<std::uint64_t> safe_seh_table_rva;
    std::optional<PeRecordSource> safe_seh_table_source;
    std::vector<PeLoadConfigTarget> safe_seh_handlers;
    std::optional<std::uint64_t> guard_check_rva, guard_dispatch_rva;
    std::optional<std::uint64_t> guard_function_table_rva;
    std::optional<PeRecordSource> directory_source;
    std::vector<PeGuardCfFunction> guard_functions;
    std::optional<std::uint64_t> guard_address_taken_iat_table_rva;
    std::vector<PeLoadConfigTarget> guard_address_taken_iat_entries;
    std::optional<std::uint64_t> guard_long_jump_table_rva;
    std::vector<PeLoadConfigTarget> guard_long_jump_targets;
    std::optional<std::uint64_t> guard_eh_continuation_table_rva;
    std::vector<PeLoadConfigTarget> guard_eh_continuation_targets;
    // Guard XFG indirect-call helpers are preferred-base VAs in the file;
    // retain normalized RVAs only when each complete pointer field is present.
    std::optional<std::uint64_t> guard_xfg_check_rva;
    std::optional<std::uint64_t> guard_xfg_dispatch_rva;
    std::optional<std::uint64_t> guard_xfg_table_dispatch_rva;
    std::optional<std::uint64_t> cast_guard_failure_mode_rva;
    std::optional<std::uint64_t> guard_memcpy_rva;
    // Guard RF helper and metadata VAs are retained as normalized RVAs.
    std::optional<std::uint64_t> guard_rf_failure_routine_rva;
    std::optional<std::uint64_t> guard_rf_failure_routine_pointer_rva;
    std::optional<std::uint64_t> guard_rf_verify_stack_pointer_rva;
    std::optional<std::uint32_t> hot_patch_table_offset;
    std::optional<std::uint64_t> enclave_configuration_rva;
    std::optional<std::uint64_t> volatile_metadata_rva;
    std::optional<PeRecordSource> guard_rf_failure_routine_source;
    std::optional<PeRecordSource> guard_rf_failure_routine_pointer_source;
    std::optional<PeRecordSource> guard_rf_verify_stack_pointer_source;
    std::optional<PeRecordSource> hot_patch_table_offset_source;
    std::optional<PeRecordSource> enclave_configuration_source;
    std::optional<PeRecordSource> volatile_metadata_source;
    bool operator==(const PeLoadConfiguration &) const = default;
};
enum class PeUnwindOperationKind : std::uint8_t {
    push_nonvolatile,
    allocate_stack,
    set_frame_pointer,
    save_nonvolatile,
    save_xmm128,
    push_machine_frame
};
struct PeUnwindOperation {
    PeUnwindOperationKind kind = PeUnwindOperationKind::push_nonvolatile;
    std::uint8_t code_offset = 0;
    std::uint8_t register_number = 0;
    std::uint32_t stack_size = 0;
    std::uint32_t stack_offset = 0;
    bool machine_frame_has_error_code = false;
    PeRecordSource source;
    bool operator==(const PeUnwindOperation &) const = default;
};
enum class PeHandlerPayloadStatus : std::uint8_t {
    unresolved_handler,
    unsupported_handler,
    decoded_c_specific_scope_table,
    decoded_cxx_func_info,
    decoded_cxx_func_info4
};
struct PeScopeRecord {
    std::uint32_t begin_rva = 0, end_rva = 0, handler_rva = 0, jump_target_rva = 0;
    PeRecordSource source;
    bool operator==(const PeScopeRecord &) const = default;
};
struct PeCxxUnwindMapEntry {
    std::int32_t to_state = -1;
    std::uint32_t action_rva = 0;
    PeRecordSource source;
    bool operator==(const PeCxxUnwindMapEntry &) const = default;
};
struct PeCxxHandlerType {
    std::uint32_t adjectives = 0;
    std::optional<std::uint32_t> type_descriptor_rva; // Null type is a catch-all handler.
    std::optional<std::string> decorated_type_name;
    std::int32_t catch_object_offset = 0;
    std::uint32_t handler_rva = 0;
    std::int32_t frame_offset = 0;
    PeRecordSource source;
    std::optional<PeRecordSource> type_descriptor_source;
    bool operator==(const PeCxxHandlerType &) const = default;
};
struct PeCxxTryBlockMapEntry {
    std::int32_t try_low = 0;
    std::int32_t try_high = 0;
    std::int32_t catch_high = 0;
    std::vector<PeCxxHandlerType> handlers;
    PeRecordSource source;
    bool operator==(const PeCxxTryBlockMapEntry &) const = default;
};
struct PeCxxIpToStateEntry {
    std::uint32_t ip_rva = 0;
    std::int32_t state = -1;
    PeRecordSource source;
    bool operator==(const PeCxxIpToStateEntry &) const = default;
};
// One 20-byte AMD64 HandlerType record in a legacy dynamic exception-spec
// list. The loader retains type identity but does not enforce the spec.
struct PeCxxExceptionSpecType {
    std::uint32_t adjectives = 0;
    std::optional<std::uint32_t> type_descriptor_rva;
    std::optional<std::string> decorated_type_name;
    PeRecordSource source;
    std::optional<PeRecordSource> type_descriptor_source;
    bool operator==(const PeCxxExceptionSpecType &) const = default;
};
struct PeCxxExceptionSpecTypeList {
    std::uint32_t count = 0;
    std::uint32_t type_array_rva = 0;
    PeRecordSource source;
    std::optional<PeRecordSource> type_array_source;
    std::vector<PeCxxExceptionSpecType> types;
    bool operator==(const PeCxxExceptionSpecTypeList &) const = default;
};
struct PeCxxFuncInfo {
    std::uint32_t magic = 0;
    std::int32_t max_state = 0;
    std::uint32_t unwind_map_rva = 0;
    std::uint32_t try_block_count = 0;
    std::uint32_t try_block_map_rva = 0;
    std::uint32_t ip_map_count = 0;
    std::uint32_t ip_map_rva = 0;
    std::int32_t unwind_help = 0;
    std::uint32_t es_type_list_rva = 0;
    std::int32_t eh_flags = 0;
    // FuncInfo magic 0x19930522 makes these EHFlags bits meaningful.
    bool has_ehs_flag = false;
    bool has_dynamic_stack_alignment = false;
    bool is_noexcept = false;
    std::uint32_t unknown_eh_flags = 0;
    std::vector<PeCxxUnwindMapEntry> unwind_map;
    std::vector<PeCxxTryBlockMapEntry> try_blocks;
    std::vector<PeCxxIpToStateEntry> ip_to_state;
    std::optional<PeCxxExceptionSpecTypeList> exception_spec_types;
    PeRecordSource source;
    std::optional<PeRecordSource> eh_flags_source;
    bool operator==(const PeCxxFuncInfo &) const = default;
};
enum class PeCxxFuncInfo4Status : std::uint8_t { decoded_subset, unsupported, malformed };
struct PeCxxIpToState4Entry {
    std::uint32_t ip_rva = 0;
    std::int32_t state = -1;
    PeRecordSource source;
    bool operator==(const PeCxxIpToState4Entry &) const = default;
};
struct PeCxxSeparatedIpMap4Entry {
    std::uint32_t function_rva = 0;
    // Effective per-function IP map RVA (selected from separated_ip_maps when
    // the separated-map flag is present).
    std::uint32_t ip_map_rva = 0;
    PeRecordSource source;
    bool operator==(const PeCxxSeparatedIpMap4Entry &) const = default;
};
enum class PeCxxUnwindEntry4Type : std::uint8_t {
    no_action = 0,
    destructor_object = 1,
    destructor_pointer = 2,
    action_rva = 3
};
struct PeCxxUnwindMap4Entry {
    // Backward byte displacement to the prior compressed map entry. This is
    // descriptive metadata; the loader does not follow it to execute unwind.
    std::uint32_t previous_entry_offset = 0;
    PeCxxUnwindEntry4Type type = PeCxxUnwindEntry4Type::no_action;
    std::optional<std::uint32_t> action_rva;
    std::optional<std::uint32_t> object_offset;
    PeRecordSource source;
    std::optional<PeRecordSource> action_source;
    std::optional<PeRecordSource> object_source;
    // Resolved row index when the backward displacement points into this map.
    // A link before the map start is the runtime's null-link sentinel.
    std::optional<std::uint32_t> previous_entry_index;
    bool operator==(const PeCxxUnwindMap4Entry &) const = default;
};
struct PeCxxHandlerType4 {
    std::uint8_t header = 0;
    std::optional<std::uint32_t> adjectives;
    std::optional<std::uint32_t> type_descriptor_rva; // Zero denotes a catch-all type.
    std::optional<std::string> decorated_type_name;
    std::optional<std::uint32_t> catch_object_offset;
    std::uint32_t handler_rva = 0;
    bool continuation_addresses_are_rvas = false;
    std::vector<std::uint32_t> continuation_addresses;
    PeRecordSource source;
    std::optional<PeRecordSource> adjectives_source;
    std::optional<PeRecordSource> type_descriptor_source;
    std::optional<PeRecordSource> catch_object_source;
    std::optional<PeRecordSource> handler_source;
    std::vector<PeRecordSource> continuation_sources;
    bool operator==(const PeCxxHandlerType4 &) const = default;
};
struct PeCxxTryBlockMap4Entry {
    std::int32_t try_low = -1;
    std::int32_t try_high = -1;
    std::int32_t catch_high = -1;
    std::uint32_t handler_array_rva = 0;
    std::vector<PeCxxHandlerType4> handlers;
    PeRecordSource source;
    std::optional<PeRecordSource> handler_array_count_source;
    bool operator==(const PeCxxTryBlockMap4Entry &) const = default;
};
// FH4's byte header and optional scalar/RVA fields. Header bits are retained
// verbatim and the catch/EHs/noexcept bits are also named. Runtime evaluation
// consumes bounded records only; it never invokes target handler code.
struct PeCxxFuncInfo4 {
    PeCxxFuncInfo4Status status = PeCxxFuncInfo4Status::unsupported;
    std::uint8_t header = 0;
    bool is_catch_funclet = false;
    bool has_ehs_flag = false;
    bool is_noexcept = false;
    std::optional<PeRecordSource> catch_funclet_flag_source;
    std::optional<PeRecordSource> ehs_flag_source;
    std::optional<PeRecordSource> noexcept_flag_source;
    std::uint8_t unknown_header_flags = 0;
    std::optional<std::uint32_t> bbt_flags;
    std::optional<std::uint32_t> unwind_map_rva, try_block_map_rva;
    std::uint32_t ip_map_rva = 0;
    std::optional<std::uint32_t> separated_ip_map_rva;
    std::optional<PeRecordSource> separated_ip_map_count_source;
    std::vector<PeCxxSeparatedIpMap4Entry> separated_ip_maps;
    std::optional<PeRecordSource> unwind_map_count_source;
    std::vector<PeCxxUnwindMap4Entry> unwind_map;
    std::optional<PeRecordSource> try_block_count_source;
    std::vector<PeCxxTryBlockMap4Entry> try_blocks;
    std::optional<std::uint32_t> catch_frame;
    std::optional<PeRecordSource> ip_map_count_source;
    std::vector<PeCxxIpToState4Entry> ip_to_state;
    std::string diagnostic;
    PeRecordSource source;
    bool operator==(const PeCxxFuncInfo4 &) const = default;
};
struct PeHandlerPayload {
    PeHandlerPayloadStatus status = PeHandlerPayloadStatus::unresolved_handler;
    std::optional<std::string> handler_name;
    std::uint32_t payload_rva = 0;
    // Opaque preview is capped at 256 initialized bytes; it is not claimed to
    // represent the full payload when the handler schema is unknown.
    std::vector<std::byte> opaque_preview;
    std::vector<PeScopeRecord> c_specific_scopes;
    std::optional<PeCxxFuncInfo> cxx_func_info;
    std::optional<PeCxxFuncInfo4> cxx_func_info4;
    std::optional<PeRecordSource> source;
    bool operator==(const PeHandlerPayload &) const = default;
};
struct PeUnwindInfo;
bool pe_unwind_info_equal(const PeUnwindInfo &, const PeUnwindInfo &);
struct PeChainedRuntimeFunction {
    std::uint32_t begin_rva = 0, end_rva = 0, unwind_info_rva = 0;
    PeRecordSource source;
    std::shared_ptr<PeUnwindInfo> unwind_info;
    bool operator==(const PeChainedRuntimeFunction &other) const {
        if (begin_rva != other.begin_rva || end_rva != other.end_rva ||
            unwind_info_rva != other.unwind_info_rva || source != other.source ||
            static_cast<bool>(unwind_info) != static_cast<bool>(other.unwind_info)) return false;
        return !unwind_info || pe_unwind_info_equal(*unwind_info, *other.unwind_info);
    }
};
struct PeUnwindInfo {
    std::uint8_t version = 0, flags = 0, size_of_prolog = 0;
    std::uint8_t frame_register = 0, frame_offset = 0;
    std::vector<PeUnwindOperation> operations;
    std::optional<std::uint32_t> handler_rva;
    std::optional<PeRecordSource> handler_source;
    std::optional<PeHandlerPayload> handler_payload;
    std::shared_ptr<PeChainedRuntimeFunction> chained_function;
    PeRecordSource source;
    bool operator==(const PeUnwindInfo &other) const {
        if (version != other.version || flags != other.flags || size_of_prolog != other.size_of_prolog ||
            frame_register != other.frame_register || frame_offset != other.frame_offset ||
            operations != other.operations || handler_rva != other.handler_rva ||
            handler_source != other.handler_source || handler_payload != other.handler_payload || source != other.source ||
            static_cast<bool>(chained_function) != static_cast<bool>(other.chained_function)) return false;
        return !chained_function || *chained_function == *other.chained_function;
    }
};
inline bool pe_unwind_info_equal(const PeUnwindInfo &left, const PeUnwindInfo &right) {
    return left == right;
}
enum class PeArm64UnwindKind : std::uint8_t { xdata, packed_single, packed_fragment, pdata_link };
struct PeArm64UnwindCode {
    std::uint8_t opcode = 0;
    std::vector<std::uint8_t> encoding;
    PeRecordSource source;
    bool operator==(const PeArm64UnwindCode &) const = default;
};
struct PeArm64EpilogScope {
    std::uint32_t start_offset = 0;
    std::uint16_t unwind_code_index = 0;
    PeRecordSource source;
    bool operator==(const PeArm64EpilogScope &) const = default;
};
struct PeArm64Xdata {
    std::uint32_t function_length = 0;
    std::uint8_t version = 0;
    bool has_exception_data = false;
    bool single_epilog = false;
    std::uint16_t epilog_count = 0;
    std::uint8_t code_words = 0;
    bool extended_header = false;
    std::vector<PeArm64EpilogScope> epilog_scopes;
    std::vector<PeArm64UnwindCode> unwind_codes;
    std::optional<std::uint32_t> handler_rva;
    std::optional<PeRecordSource> handler_source;
    PeRecordSource source;
    bool operator==(const PeArm64Xdata &) const = default;
};
struct PeArm64PackedUnwind {
    // Encoded 4-byte units; PeArm64RuntimeFunction::function_length is bytes.
    std::uint16_t function_length = 0;
    std::uint8_t reg_f = 0, reg_i = 0, cr = 0;
    bool homes_parameters = false;
    std::uint16_t frame_size = 0;
    bool operator==(const PeArm64PackedUnwind &) const = default;
};
struct PeArm64RuntimeFunction {
    std::uint32_t begin_rva = 0;
    // Zero for pdata link rows, whose island extent is not encoded here.
    std::uint32_t function_length = 0;
    PeArm64UnwindKind kind = PeArm64UnwindKind::xdata;
    std::optional<PeArm64PackedUnwind> packed_unwind;
    std::optional<PeArm64Xdata> xdata;
    std::optional<std::uint32_t> linked_record_rva;
    std::optional<std::uint32_t> linked_record_index;
    PeRecordSource source;
    bool operator==(const PeArm64RuntimeFunction &) const = default;
};
// An AMD64 IMAGE_RUNTIME_FUNCTION_ENTRY describes one code range and its
// associated UNWIND_INFO RVA. Both table and decoded unwind provenance remain.
struct PeRuntimeFunction {
    std::uint32_t begin_rva = 0, end_rva = 0, unwind_info_rva = 0;
    PeRecordSource source;
    std::optional<PeUnwindInfo> unwind_info;
    bool operator==(const PeRuntimeFunction &) const = default;
};
struct PeResourceIdentifier {
    std::optional<std::uint16_t> id;
    std::optional<std::string> name;
    std::optional<std::vector<PeSourceSpan>> name_source;
    bool operator==(const PeResourceIdentifier &) const = default;
};
struct PeVersionString {
    std::string key;
    std::string value;
    std::uint16_t language = 0, code_page = 0;
    PeRecordSource source;
    bool operator==(const PeVersionString &) const = default;
};
struct PeVersionInfo {
    std::array<std::uint16_t, 4> file_version{};
    std::array<std::uint16_t, 4> product_version{};
    std::uint32_t file_flags = 0;
    std::uint32_t file_os = 0;
    std::uint32_t file_type = 0;
    std::uint32_t file_subtype = 0;
    PeRecordSource fixed_info;
    std::vector<PeVersionString> strings;
    bool string_tables_complete = true;
    bool operator==(const PeVersionInfo &) const = default;
};
struct PeResource {
    PeResourceIdentifier type, name, language;
    std::uint32_t data_rva = 0, size = 0, code_page = 0;
    PeRecordSource entry, data_entry;
    std::vector<PeSourceSpan> payload;
    // Decoded only for canonical RT_VERSION / VS_VERSION_INFO payloads.
    std::optional<PeVersionInfo> version_info;
    bool operator==(const PeResource &) const = default;
};
struct PeCodeViewIdentity {
    std::array<std::byte, 16> guid{};
    std::uint32_t age = 0;
    std::string path;
    PeRecordSource directory_entry;
    std::vector<PeSourceSpan> record;
    bool operator==(const PeCodeViewIdentity &) const = default;
};
// Common IMAGE_DEBUG_DIRECTORY fields are retained for every debug record;
// payloads with no specialized decoder remain inspectable as raw file spans.
struct PeDebugDirectoryEntry {
    std::uint32_t timestamp = 0;
    std::uint16_t major_version = 0, minor_version = 0;
    std::uint32_t type = 0, data_size = 0, data_rva = 0, raw_offset = 0;
    PeRecordSource entry;
    std::vector<PeSourceSpan> raw_data;
    bool operator==(const PeDebugDirectoryEntry &) const = default;
};
enum class PeFpoFrameKind : std::uint8_t { fpo, trap, task_state, non_fpo };
// Legacy x86 IMAGE_DEBUG_TYPE_FPO row. Local and parameter counts retain the
// format's DWORD units; no unwind execution is inferred from this metadata.
struct PeFpoRecord {
    std::uint32_t begin_rva = 0, code_size = 0;
    std::uint32_t local_dwords = 0;
    std::uint16_t parameter_dwords = 0;
    std::uint8_t prolog_size = 0, saved_register_count = 0;
    bool has_seh = false, uses_base_pointer = false;
    PeFpoFrameKind frame_kind = PeFpoFrameKind::fpo;
    PeRecordSource source;
    bool operator==(const PeFpoRecord &) const = default;
};
// A PDB C13 line row after optional section-to-RVA mapping. The original
// section coordinate and module/file provenance remain available even when
// the PE/PDB identity or section mapping cannot be established.
struct PeSourceLine {
    std::string source_path;
    std::uint32_t source_file_id = 0;
    std::uint8_t checksum_kind = 0;
    std::vector<std::byte> checksum;
    std::uint16_t section = 0;
    std::uint32_t reloc_offset = 0;
    std::uint32_t section_offset = 0;
    std::uint32_t contribution_size = 0;
    std::uint32_t block_size = 0;
    std::uint32_t line = 0, end_line = 0;
    std::uint16_t start_column = 0, end_column = 0;
    bool has_columns = false, is_statement = false;
    std::string module_name, object_name;
    std::uint16_t module_index = 0;
    std::uint32_t subsection_offset = 0;
    std::optional<Address> address;
    bool operator==(const PeSourceLine &) const = default;
};
enum class PePdbStatus : std::uint8_t { unavailable, missing, malformed, mismatch, matched };
struct PePdbSymbol {
    std::string name;
    bool procedure = false;
    std::uint16_t section = 0;
    std::uint32_t section_offset = 0, size = 0;
    std::optional<Address> address;
    std::string module_name, object_name;
    bool public_symbol = false, global_symbol = false;
    // Raw CodeView S_FRAMEPROC summary; section coordinates remain PDB-relative.
    std::uint32_t frame_size = 0, frame_padding_size = 0, frame_padding_offset = 0;
    std::uint32_t callee_saved_register_bytes = 0, exception_handler_offset = 0;
    std::uint16_t exception_handler_section = 0;
    std::uint32_t frame_flags = 0;
    bool has_frame_data = false;
    std::uint32_t type_index = 0;
    bool type_index_is_id = false;
    bool operator==(const PePdbSymbol &) const = default;
};
struct PePdbTypeField {
    std::uint16_t leaf = 0;
    std::uint32_t type = 0;
    std::uint64_t offset = 0;
    bool operator==(const PePdbTypeField &) const = default;
};
struct PePdbType {
    std::uint32_t index = 0;
    std::string name;
    std::uint16_t leaf = 0;
    std::uint64_t size = 0;
    bool field_layout_complete = false;
    std::vector<PePdbTypeField> fields;
    bool operator==(const PePdbType &) const = default;
};
enum class PePdbLocalLocationKind : std::uint8_t { unknown, frame_relative, register_relative, register_value };
struct PePdbLocalRangeGap { std::uint16_t offset = 0, size = 0; bool operator==(const PePdbLocalRangeGap &) const = default; };
struct PePdbLocalLiveRange {
    PePdbLocalLocationKind location_kind = PePdbLocalLocationKind::unknown;
    std::int32_t frame_offset = 0;
    std::uint16_t register_id = 0, section = 0;
    std::uint16_t offset_in_parent = 0;
    std::int32_t offset_in_udt = 0;
    bool spilled_udt_member = false, indirect = false, subfield_register = false, may_have_no_name = false;
    std::uint32_t section_offset = 0, size = 0;
    std::vector<PePdbLocalRangeGap> gaps;
    bool operator==(const PePdbLocalLiveRange &) const = default;
};
struct PePdbLocal {
    std::string name, procedure_name, module_name, object_name;
    std::uint32_t type_index = 0;
    bool parameter = false;
    // Nearest enclosing CodeView S_BLOCK32. These offsets are section-relative
    // and remain unresolved until the section is bound to the loaded image.
    bool has_lexical_scope = false;
    std::uint16_t lexical_scope_section = 0;
    std::uint32_t lexical_scope_offset = 0, lexical_scope_size = 0;
    // When set, this local belongs to a CodeView inlinee nested in the
    // enclosing procedure. The ID is an IPI index; the offset is module-local.
    std::optional<std::uint32_t> inlinee_id;
    std::optional<std::uint32_t> inline_site_record_offset;
    PePdbLocalLocationKind location_kind = PePdbLocalLocationKind::unknown;
    std::int32_t frame_offset = 0;
    std::uint16_t register_id = 0;
    std::uint16_t procedure_section = 0;
    std::uint32_t procedure_section_offset = 0, procedure_size = 0;
    std::optional<Address> procedure_address;
    std::uint16_t module_index = 0, record_kind = 0;
    std::uint32_t record_offset = 0;
    std::vector<PePdbLocalLiveRange> live_ranges;
    bool operator==(const PePdbLocal &) const = default;
};
struct PePdbInlineRange {
    std::uint64_t section_offset = 0;
    std::uint32_t size = 0;
    std::optional<Address> address;
    std::string source_path;
    std::uint32_t line = 0;
    bool operator==(const PePdbInlineRange &) const = default;
};
struct PePdbInlineSite {
    std::uint16_t module_index = 0, section = 0;
    std::uint32_t record_offset = 0, inlinee_id = 0, depth = 0;
    std::optional<std::uint32_t> parent_record_offset;
    std::optional<std::uint32_t> unsupported_opcode;
    std::uint32_t annotation_offset = 0;
    std::string procedure_name, inlinee_name, status;
    std::vector<PePdbInlineRange> ranges;
    bool operator==(const PePdbInlineSite &) const = default;
};
struct PeMetadata {
    // IMAGE_DIRECTORY_ENTRY_GLOBALPTR is an RVA whose directory size is zero.
    std::optional<std::uint32_t> global_pointer_rva;
    std::vector<PeImageCoffSymbol> coff_symbols;
    std::optional<PeMsvcRttiMetadata> msvc_rtti;
    std::optional<PeCertificateTable> certificate_table;
    std::vector<PeImportSource> imports;
    std::vector<PeBoundImport> bound_imports;
    std::vector<PeExportSource> exports;
    std::vector<PeRelocationSource> relocations;
    std::vector<PeRuntimeFunction> exception_functions;
    std::vector<PeArm64RuntimeFunction> arm64_exception_functions;
    std::optional<PeTlsDirectory> tls;
    std::optional<PeLoadConfiguration> load_configuration;
    std::vector<PeResource> resources;
    std::vector<PeCodeViewIdentity> codeview;
    std::vector<PeDebugDirectoryEntry> debug_directories;
    std::vector<PeFpoRecord> fpo_records;
    std::vector<PeSourceLine> source_lines;
    PePdbStatus pdb_status = PePdbStatus::unavailable;
    std::string pdb_path;
    std::vector<PePdbSymbol> pdb_symbols;
    std::vector<PePdbType> pdb_types;
    std::vector<PePdbLocal> pdb_locals;
    std::vector<PePdbInlineSite> pdb_inline_sites;
    bool operator==(const PeMetadata &) const = default;
};
} // namespace hexlab
