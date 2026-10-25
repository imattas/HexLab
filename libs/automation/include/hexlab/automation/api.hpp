#pragma once
#include "hexlab/automation/automation_export.hpp"
#include "hexlab/automation/history.hpp"
#include "hexlab/workspace/project.hpp"
#include "hexlab/workspace/export.hpp"
#include "hexlab/workspace/search.hpp"
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
    HEXLAB_AUTOMATION_EXPORT Result<std::shared_ptr<const HistoricalState>> preview_history(
        std::uint64_t target_step, database::HistoryPreviewLimits={},
        std::optional<std::uint64_t> expected_revision={}, std::stop_token={}) const;
    HEXLAB_AUTOMATION_EXPORT Result<std::vector<std::byte>> read(Location, std::size_t, std::stop_token={}) const;
    HEXLAB_AUTOMATION_EXPORT Result<Address> logical(X86LogicalAddress) const;
    HEXLAB_AUTOMATION_EXPORT Result<std::vector<FunctionRecord>> functions(std::size_t start=0, std::size_t count=256) const;
    HEXLAB_AUTOMATION_EXPORT Result<std::optional<FunctionRecord>> function_at(Address) const;
    HEXLAB_AUTOMATION_EXPORT Result<std::vector<FunctionOwnerCandidate>> function_owners(Address) const;
    HEXLAB_AUTOMATION_EXPORT Result<std::optional<StackFrameInfo>> stack_frame(Address) const;
    HEXLAB_AUTOMATION_EXPORT Result<std::vector<StackSlotInfo>> stack_slots(
        Address, std::size_t start=0, std::size_t count=256) const;
    HEXLAB_AUTOMATION_EXPORT Result<std::vector<StackSlotAccessInfo>> stack_slot_accesses(
        Address, std::size_t slot_index, std::size_t start=0, std::size_t count=256) const;
    HEXLAB_AUTOMATION_EXPORT Result<Decompilation> decompile(Address) const;
    HEXLAB_AUTOMATION_EXPORT Result<LocationPresentation> presentation(Location) const;
    HEXLAB_AUTOMATION_EXPORT Result<std::vector<FunctionBlock>> function_blocks(Address, std::size_t start=0, std::size_t count=256) const;
    HEXLAB_AUTOMATION_EXPORT Result<std::vector<Instruction>> block_instructions(BlockId, std::size_t start=0, std::size_t count=256) const;
    HEXLAB_AUTOMATION_EXPORT Result<std::vector<BlockSuccessor>> block_successors(BlockId, std::size_t start=0, std::size_t count=256) const;
    HEXLAB_AUTOMATION_EXPORT Result<std::vector<Instruction>> instructions(std::size_t start=0, std::size_t count=256) const;
    HEXLAB_AUTOMATION_EXPORT Result<std::vector<MappedSegment>> segments(std::size_t start=0, std::size_t count=256) const;
    HEXLAB_AUTOMATION_EXPORT Result<std::vector<Reference>> references(Location, std::size_t start=0, std::size_t count=256) const;
    HEXLAB_AUTOMATION_EXPORT Result<ReferencePage> incoming_references(Location, std::size_t start=0, std::size_t count=256) const;
    HEXLAB_AUTOMATION_EXPORT Result<ReferencePage> all_references(std::size_t start=0, std::size_t count=256) const;
    HEXLAB_AUTOMATION_EXPORT Result<std::vector<StringRecord>> strings(std::size_t start=0, std::size_t count=256) const;
    HEXLAB_AUTOMATION_EXPORT Result<SearchPage> search(const SearchQuery&, std::optional<SearchCursor> = {}, const SearchLimits& = {}, std::stop_token = {}) const;
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
    HEXLAB_AUTOMATION_EXPORT Result<bool> save(std::stop_token={});
    HEXLAB_AUTOMATION_EXPORT Result<database::SavedProject> save_as(const std::filesystem::path&, std::stop_token={});
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
