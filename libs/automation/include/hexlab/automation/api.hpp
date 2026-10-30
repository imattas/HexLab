#pragma once
#include "hexlab/automation/automation_export.hpp"
#include "hexlab/automation/history.hpp"
#include "hexlab/automation/workflow_state.hpp"
#include "hexlab/workspace/project.hpp"
#include "hexlab/workspace/export.hpp"
#include "hexlab/workspace/search.hpp"
#include "hexlab/analysis/graph.hpp"
#include "hexlab/analysis/references.hpp"
#include "hexlab/loaders/ar.hpp"
#include <thread>

namespace hexlab::automation {
inline constexpr std::uint32_t api_version = 1;
inline constexpr std::size_t maximum_read = 1024 * 1024;
inline constexpr std::size_t maximum_page = 4096;
struct MappedSegment {
    std::string name;
    Address begin;
    std::uint64_t size = 0;
    FileOffset file_begin;
    std::uint64_t file_size = 0;
    bool readable = false, writable = false, executable = false;
};
// Detached ELF dynamic-table row. Rows from multiple PT_DYNAMIC/SHT_DYNAMIC
// tables are concatenated in loader order; table identity is retained.
struct ElfDynamicEntryInfo {
    std::optional<std::uint32_t> section;
    std::uint64_t table_file_offset = 0;
    std::optional<Address> table_address;
    std::uint32_t index = 0;
    std::int64_t tag = 0;
    std::uint64_t value = 0;
    std::optional<std::string> string_value;
};
// Detached summary of the active loader mapping. Enum values are the public
// hexlab Architecture/ExecutionMode numeric values; addresses retain domains.
struct ImageInfo {
    bool mapped = false, metadata_complete = false;
    std::string format;
    std::uint16_t machine = 0;
    std::uint64_t preferred_base = 0, image_size = 0;
    std::uint32_t header_size = 0;
    std::uint8_t architecture = 0, mode = 0;
    std::size_t segment_count = 0, address_space_count = 0;
    std::vector<Address> entries;
};
// Detached block metadata. Nested tables have independent bounded page queries.
struct FunctionBlock {
    BlockId id;
    Address begin;
    std::size_t instruction_count = 0, successor_count = 0;
    std::optional<FunctionStop> stop;
    LocationPresentation presentation;
};
// Detached result from the common typed-IR cleanup and structured formatter.
struct Decompilation {
    Address entry;
    std::string text;
    bool complete = false;
    bool used_fallback = false;
    std::string fallback_reason;
    std::vector<std::string> diagnostics;
};
// Stable identity and entry for every recovered function that owns an address.
// Shared tails can have more than one candidate.
struct FunctionOwnerCandidate {
    FunctionId id;
    Address entry;
    bool operator==(const FunctionOwnerCandidate &) const = default;
};
// Detached stack-frame summary for a uniquely owned recovered function.
struct StackFrameInfo {
    FunctionId function;
    Address entry;
    std::optional<std::uint64_t> maximum_stack_allocation_bytes;
    std::size_t slot_count = 0;
    bool complete = false;
};
// A bounded-page view of one entry-SP-relative local/argument slot.
struct StackSlotInfo {
    std::int64_t offset_from_entry_sp = 0;
    std::uint16_t width = 0;
    std::size_t access_count = 0;
    bool read = false;
    bool written = false;
    bool address_taken = false;
    // ABI-qualified incoming stack arguments when their offset and access
    // direction meet the modeled architecture convention.
    bool incoming_argument = false;
    // Count of retained outgoing stack-source/call provenance rows.
    std::size_t outgoing_call_argument_count = 0;
    std::optional<StackArgumentAbi> incoming_argument_abi;
};
// One bounded-page outgoing argument provenance row linking a stack source to
// the direct or decoded call boundary that consumes it.
struct StackSlotCallArgumentInfo {
    // Compatibility alias for the source address. Prefer source_instruction
    // and source_kind when interpreting non-x86 sources.
    Address push_instruction;
    Address call_instruction;
    Address source_instruction;
    StackCallArgumentSourceKind source_kind = StackCallArgumentSourceKind::x86_push;
};
struct StackSlotAccessInfo {
    Address instruction;
    bool read = false;
    bool written = false;
    bool address_taken = false;
};
struct ArchiveSummary {
    std::size_t member_count = 0;
    std::size_t symbol_count = 0;
    bool has_symbol_index = false;
    bool symbol_index_complete = true;
    std::vector<std::string> diagnostics;
    bool thin = false;
    bool aix_big = false;
};
struct ArchiveMemberRecord {
    std::size_t index = 0;
    std::string name;
    FileOffset header_offset;
    FileOffset data_offset;
    std::uint64_t size = 0;
    ArMemberKind kind = ArMemberKind::regular;
};
struct ArchiveSymbolRecord {
    std::string name;
    std::size_t member_index = 0;
};
struct BackupInfo {
    database::SavedProject project;
    std::uint64_t created_unix_ms = 0;
};
struct BackupRotationInfo {
    database::SavedProject backup;
    std::size_t removed_generations = 0;
    bool retention_satisfied = true;
};
struct BackupPruneInfo {
    std::size_t remaining = 0, removed = 0;
    bool retention_satisfied = true;
};
struct BackupListInfo {
    std::vector<BackupInfo> backups;
    bool complete = true;
};
enum class DebugImportKind { symbols, dwarf };
// Dry-run counts come from the same workspace validator used by the commit.
// A read-only owner can preview; importing still requires a writable owner.
struct DebugImportPreview {
    database::ProjectUuid project_uuid{};
    std::uint64_t edit_revision = 0;
    bool ready = false, readonly = true;
    std::string reason;
    std::optional<ErrorCode> error_code;
    std::size_t changes = 0, annotations = 0, types = 0;
    std::size_t type_assignments = 0, functions = 0, variables = 0;
};
// Summary only: potentially large location lists and expressions are queried
// separately, so no nested debug-information table is silently truncated.
struct DebugVariableInfo {
    std::uint64_t id = 0;
    Address function_entry{};
    std::string name;
    std::optional<std::uint64_t> type_id;
    bool is_parameter = false;
    std::uint64_t scope_offset = 0;
    std::optional<std::uint64_t> address;
    std::optional<std::int64_t> cfa_offset;
    database::DwarfSourceOrigin origin;
    std::size_t expression_size = 0, operation_count = 0, location_range_count = 0;
};
struct DebugLocationRangeInfo {
    std::uint64_t begin = 0, end = 0;
    std::size_t expression_size = 0, operation_count = 0;
};
// Synchronous, thread-affine project ownership. Use a dedicated worker when
// embedding in a UI. This source API follows HexLab's rebuilt-consumer DLL ABI.
class Project {
public:
    HEXLAB_AUTOMATION_EXPORT static Result<std::shared_ptr<Project>> open(
        const std::filesystem::path&, bool readonly = true, std::uint32_t version = api_version,
        std::stop_token = {});
    HEXLAB_AUTOMATION_EXPORT static Result<std::shared_ptr<Project>> create(
        const std::filesystem::path&, const std::filesystem::path& input, const LoadRecipe&,
        std::uint32_t version = api_version, std::stop_token = {});
    HEXLAB_AUTOMATION_EXPORT Result<std::shared_ptr<const ProjectSnapshot>> snapshot() const;
    // Independent read-only owner retaining this exact workspace generation,
    // including effective bytes and derived facts. No database/session is held.
    // History queries, edits, analysis and project saves are unavailable.
    HEXLAB_AUTOMATION_EXPORT Result<std::shared_ptr<Project>> capture(
        std::optional<std::uint64_t> expected_revision={}, std::stop_token={}) const;
    HEXLAB_AUTOMATION_EXPORT Result<ImageInfo> image_info() const;
    HEXLAB_AUTOMATION_EXPORT Result<std::vector<database::Annotation>> annotations(std::size_t start=0, std::size_t count=256) const;
    HEXLAB_AUTOMATION_EXPORT Result<std::vector<database::TypeDefinition>> types(std::size_t start=0, std::size_t count=256) const;
    HEXLAB_AUTOMATION_EXPORT Result<std::vector<database::TypeAssignment>> type_assignments(std::size_t start=0, std::size_t count=256) const;
    HEXLAB_AUTOMATION_EXPORT Result<DebugImportPreview> preview_debug_import(
        DebugImportKind, std::stop_token={}) const;
    HEXLAB_AUTOMATION_EXPORT Result<std::shared_ptr<const ProjectSnapshot>> import_debug_info(
        DebugImportKind, std::uint64_t expected_edit_revision, std::uint64_t group=0, std::stop_token={});
    // Debug evidence reads use one immutable owner snapshot. An expected edit
    // revision pins separate pages, location tables, and expression chunks to
    // the same generation; cancellation never returns a partial page/read.
    HEXLAB_AUTOMATION_EXPORT Result<std::vector<DebugVariableInfo>> debug_variables(
        std::optional<Address> function_entry={}, std::size_t start=0, std::size_t count=256,
        std::optional<std::uint64_t> expected_revision={}, std::stop_token={}) const;
    HEXLAB_AUTOMATION_EXPORT Result<std::vector<DebugLocationRangeInfo>> debug_location_ranges(
        std::uint64_t variable_id, std::size_t start=0, std::size_t count=256,
        std::optional<std::uint64_t> expected_revision={}, std::stop_token={}) const;
    HEXLAB_AUTOMATION_EXPORT Result<std::vector<database::DebugLocationOperation>> debug_location_operations(
        std::uint64_t variable_id, std::optional<std::size_t> range_index={},
        std::size_t start=0, std::size_t count=256,
        std::optional<std::uint64_t> expected_revision={}, std::stop_token={}) const;
    HEXLAB_AUTOMATION_EXPORT Result<std::vector<std::byte>> read_debug_expression(
        std::uint64_t variable_id, std::size_t offset, std::size_t count,
        std::optional<std::size_t> range_index={},
        std::optional<std::uint64_t> expected_revision={}, std::stop_token={}) const;
    // The optional expected revision pins consecutive reads to one durable edit
    // generation; omitted values use this owner's current snapshot revision.
    HEXLAB_AUTOMATION_EXPORT Result<database::HistoryPage> history(
        std::uint64_t after_step=0, std::size_t count=256,
        std::optional<std::uint64_t> expected_revision={}, std::stop_token={}) const;
    // Read-only structural audit page. Resume with next_after_step and the
    // returned edit revision; the database validates payload pairs atomically.
    HEXLAB_AUTOMATION_EXPORT Result<database::HistoryAuditPage> audit_history(
        std::uint64_t after_step=0, database::HistoryAuditLimits={},
        std::optional<std::uint64_t> expected_revision={}, std::stop_token={}) const;
    HEXLAB_AUTOMATION_EXPORT Result<std::shared_ptr<const HistoricalState>> preview_history(
        std::uint64_t target_step, database::HistoryPreviewLimits={},
        std::optional<std::uint64_t> expected_revision={}, std::stop_token={}) const;
    HEXLAB_AUTOMATION_EXPORT Result<std::vector<std::byte>> read(Location, std::size_t, std::stop_token={}) const;
    HEXLAB_AUTOMATION_EXPORT Result<Address> logical(X86LogicalAddress) const;
    HEXLAB_AUTOMATION_EXPORT Result<std::vector<FunctionRecord>> functions(std::size_t start=0, std::size_t count=256) const;
    HEXLAB_AUTOMATION_EXPORT Result<std::optional<FunctionRecord>> function_at(Address) const;
    HEXLAB_AUTOMATION_EXPORT Result<std::vector<FunctionOwnerCandidate>> function_owners(Address) const;
    // Build a bounded, detached direct-call neighborhood for the unique
    // recovered function containing address. GraphOptions carries depth and
    // node/edge budgets; cancellation is checked throughout graph collection.
    HEXLAB_AUTOMATION_EXPORT Result<std::shared_ptr<const GraphModel>> call_graph(
        Address, GraphOptions = {}, std::stop_token = {}) const;
    HEXLAB_AUTOMATION_EXPORT Result<std::optional<StackFrameInfo>> stack_frame(Address) const;
    HEXLAB_AUTOMATION_EXPORT Result<std::vector<StackSlotInfo>> stack_slots(
        Address, std::size_t start=0, std::size_t count=256) const;
    HEXLAB_AUTOMATION_EXPORT Result<std::vector<StackSlotCallArgumentInfo>> stack_slot_call_arguments(
        Address, std::size_t slot_index, std::size_t start=0, std::size_t count=256) const;
    HEXLAB_AUTOMATION_EXPORT Result<std::vector<StackSlotAccessInfo>> stack_slot_accesses(
        Address, std::size_t slot_index, std::size_t start=0, std::size_t count=256) const;
    HEXLAB_AUTOMATION_EXPORT Result<Decompilation> decompile(Address) const;
    HEXLAB_AUTOMATION_EXPORT Result<LocationPresentation> presentation(Location) const;
    HEXLAB_AUTOMATION_EXPORT Result<std::vector<FunctionBlock>> function_blocks(Address, std::size_t start=0, std::size_t count=256) const;
    HEXLAB_AUTOMATION_EXPORT Result<std::vector<Instruction>> block_instructions(BlockId, std::size_t start=0, std::size_t count=256) const;
    HEXLAB_AUTOMATION_EXPORT Result<std::vector<BlockSuccessor>> block_successors(BlockId, std::size_t start=0, std::size_t count=256) const;
    HEXLAB_AUTOMATION_EXPORT Result<std::vector<Instruction>> instructions(std::size_t start=0, std::size_t count=256) const;
    HEXLAB_AUTOMATION_EXPORT Result<std::vector<MappedSegment>> segments(std::size_t start=0, std::size_t count=256) const;
    // Return every initialized virtual alias for one source file byte.
    HEXLAB_AUTOMATION_EXPORT Result<std::vector<Address>> addresses_for_file_offset(FileOffset) const;
    // Detached PE import/export tables. Non-PE images return empty pages.
    HEXLAB_AUTOMATION_EXPORT Result<std::vector<ImportSymbol>> pe_imports(std::size_t start=0, std::size_t count=256) const;
    HEXLAB_AUTOMATION_EXPORT Result<std::vector<ExportSymbol>> pe_exports(std::size_t start=0, std::size_t count=256) const;
    // ELF-only flattened dynamic entries; an image without ELF dynamic tables
    // returns an empty page. Rows are descriptive and do not apply relocations.
    HEXLAB_AUTOMATION_EXPORT Result<std::vector<ElfDynamicEntryInfo>> elf_dynamic_entries(
        std::size_t start=0, std::size_t count=256) const;
    HEXLAB_AUTOMATION_EXPORT Result<std::vector<Reference>> references(Location, std::size_t start=0, std::size_t count=256) const;
    HEXLAB_AUTOMATION_EXPORT Result<ReferencePage> incoming_references(Location, std::size_t start=0, std::size_t count=256) const;
    // Find references whose target or resolved association lies inside the
    // half-open virtual-address range [begin, begin + size).
    HEXLAB_AUTOMATION_EXPORT Result<ReferencePage> incoming_references_range(
        Address begin, std::uint64_t size, std::size_t start=0, std::size_t count=256) const;
    // Find references whose source lies inside the half-open virtual-address range.
    HEXLAB_AUTOMATION_EXPORT Result<ReferencePage> outgoing_references_range(
        Address begin, std::uint64_t size, std::size_t start=0, std::size_t count=256) const;
    HEXLAB_AUTOMATION_EXPORT Result<ReferencePage> all_references(std::size_t start=0, std::size_t count=256) const;
    HEXLAB_AUTOMATION_EXPORT Result<std::vector<StringRecord>> strings(std::size_t start=0, std::size_t count=256) const;
    HEXLAB_AUTOMATION_EXPORT Result<SearchPage> search(const SearchQuery&, std::optional<SearchCursor> = {},
        const SearchLimits& = {}, std::stop_token = {}, std::optional<Location> start = {}) const;
    HEXLAB_AUTOMATION_EXPORT Result<std::shared_ptr<const ProjectSnapshot>> execute(const ProjectCommand&, std::uint64_t group=0, std::stop_token={});
    // Validate and commit a bounded group of compatible project edits as one
    // history step. An optional revision rejects stale plans; stop is checked
    // during both batch accounting and native projected-state validation.
    HEXLAB_AUTOMATION_EXPORT Result<std::shared_ptr<const ProjectSnapshot>> execute_batch(
        const std::vector<ProjectCommand>&, std::uint64_t group=0,
        std::optional<std::uint64_t> expected_edit_revision={}, std::stop_token={});
    HEXLAB_AUTOMATION_EXPORT Result<std::shared_ptr<const ProjectSnapshot>> patch(
        Location, std::vector<std::byte>, std::uint64_t expected_edit_revision,
        std::uint64_t group=0, std::stop_token={});
    HEXLAB_AUTOMATION_EXPORT Result<std::shared_ptr<const ProjectSnapshot>> undo(std::stop_token={});
    HEXLAB_AUTOMATION_EXPORT Result<std::shared_ptr<const ProjectSnapshot>> redo(std::stop_token={});
    HEXLAB_AUTOMATION_EXPORT Result<std::shared_ptr<const ProjectSnapshot>> analyze(std::stop_token={});
    HEXLAB_AUTOMATION_EXPORT Result<std::shared_ptr<const ProjectSnapshot>> analyze(
        const AnalysisOptions &, std::stop_token={});
    HEXLAB_AUTOMATION_EXPORT Result<bool> save(std::stop_token={});
    // Publish an immutable, independently versioned application checkpoint.
    // Requires a live owner, but permits read-only projects. Existing paths are
    // never replaced. The expected revision rejects a stale application plan.
    HEXLAB_AUTOMATION_EXPORT Result<WorkflowState> save_workflow_state(
        const std::filesystem::path&, std::string application, std::uint32_t schema_version,
        std::span<const std::byte> payload, std::uint64_t expected_edit_revision,
        std::stop_token={}) const;
    // Verify checksum, envelope/application schemas, UUID, and current edit
    // revision before returning any payload. Works after reopening a project.
    HEXLAB_AUTOMATION_EXPORT Result<WorkflowState> load_workflow_state(
        const std::filesystem::path&, std::string application, std::uint32_t schema_version,
        std::stop_token={}) const;
    HEXLAB_AUTOMATION_EXPORT Result<database::SavedProject> save_as(const std::filesystem::path&, std::stop_token={});
    // Consistent restore-point backups preserve project UUID and history.
    HEXLAB_AUTOMATION_EXPORT Result<database::SavedProject> backup_to(
        const std::filesystem::path&, bool replace=false, std::stop_token={});
    HEXLAB_AUTOMATION_EXPORT Result<database::SourceArchiveResult> archive_external_source(
        const std::filesystem::path&, database::SourceArchiveOptions={}, std::stop_token={});
    HEXLAB_AUTOMATION_EXPORT Result<database::SourceArchiveVerification> verify_source_archive(
        const std::filesystem::path&, std::uint64_t max_bytes=database::source_archive_byte_limit,
        std::stop_token={}) const;
    HEXLAB_AUTOMATION_EXPORT Result<database::SourceArchiveRestore> restore_source_archive(
        const std::filesystem::path& archive, const std::filesystem::path& output,
        std::uint64_t max_bytes=database::source_archive_byte_limit, std::stop_token={}) const;
    HEXLAB_AUTOMATION_EXPORT Result<BackupRotationInfo> backup_to_rotating(
        const std::filesystem::path& base, std::size_t retain=5, std::stop_token={});
    HEXLAB_AUTOMATION_EXPORT Result<BackupListInfo> list_rotated_backups(
        const std::filesystem::path& base, std::stop_token={}) const;
    HEXLAB_AUTOMATION_EXPORT Result<BackupPruneInfo> prune_rotated_backups(
        const std::filesystem::path& base, std::size_t retain, std::stop_token={});
    // Requires all project connections to the target to be closed. The caller
    // must reopen it to refresh the workspace snapshot after replacement.
    HEXLAB_AUTOMATION_EXPORT static Result<database::SavedProject> restore_backup_in_place(
        const std::filesystem::path& backup, const std::filesystem::path& target,
        std::uint32_t version=api_version, std::stop_token={});
    // Read-only bounded discovery of complete HexLab staging recovery artifacts.
    HEXLAB_AUTOMATION_EXPORT static Result<database::ProjectRecoveryScan> inspect_recovery_directory(
        const std::filesystem::path& directory, std::uint32_t version=api_version, std::stop_token={});
    // Re-discovers one validated recovery artifact and restores it as a new
    // project with a fresh UUID. The artifact remains unchanged.
    HEXLAB_AUTOMATION_EXPORT static Result<database::SavedProject> restore_recovery_artifact(
        const std::filesystem::path& artifact, const std::filesystem::path& destination,
        bool replace=false, std::uint32_t version=api_version, std::stop_token={});
    HEXLAB_AUTOMATION_EXPORT Result<ExportReceipt> export_binary(const std::filesystem::path&, std::stop_token={});
private:
    Project(std::shared_ptr<database::ProjectStore> store, std::shared_ptr<ProjectSession> session)
      : store_(std::move(store)), session_(std::move(session)), owner_(std::this_thread::get_id()) {}
    explicit Project(std::shared_ptr<const ProjectSnapshot> captured)
      : captured_(std::move(captured)), owner_(std::this_thread::get_id()) {}
    Result<bool> owner() const;
    Result<bool> live_owner() const;
    std::shared_ptr<database::ProjectStore> store_;
    std::shared_ptr<ProjectSession> session_;
    std::shared_ptr<const ProjectSnapshot> captured_;
    std::thread::id owner_;
};

// Thread-affine, read-only access to a Unix ar archive. Member data is exposed
// through bounded reads so a caller can stream large objects without copying
// the full archive or holding a member-sized buffer.
class Archive {
public:
    HEXLAB_AUTOMATION_EXPORT static Result<std::shared_ptr<Archive>> open(
        const std::filesystem::path &, std::uint32_t version = api_version, std::stop_token = {});
    HEXLAB_AUTOMATION_EXPORT Result<ArchiveSummary> summary() const;
    HEXLAB_AUTOMATION_EXPORT Result<std::vector<ArchiveMemberRecord>> members(
        std::size_t start = 0, std::size_t count = 256) const;
    HEXLAB_AUTOMATION_EXPORT Result<std::vector<ArchiveSymbolRecord>> symbols(
        std::size_t start = 0, std::size_t count = 256) const;
    HEXLAB_AUTOMATION_EXPORT Result<std::vector<std::byte>> read_member(
        std::size_t index, std::uint64_t offset, std::size_t count) const;
private:
    Archive(std::shared_ptr<const ByteStorage> storage, ArArchive archive)
        : storage_(std::move(storage)), archive_(std::move(archive)), owner_(std::this_thread::get_id()) {}
    Result<bool> owner() const;
    std::shared_ptr<const ByteStorage> storage_;
    ArArchive archive_;
    std::thread::id owner_;
};
}
