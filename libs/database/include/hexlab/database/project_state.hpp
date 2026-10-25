#pragma once
#include "hexlab/database/connection.hpp"
#include "hexlab/analysis/decisions.hpp"
#include "hexlab/analysis/dependencies.hpp"
#include "hexlab/analysis/signatures.hpp"
#include "hexlab/image/patches.hpp"
#include "hexlab/loaders/recipe.hpp"
#include "hexlab/types/types.hpp"
#include <array>
#include <optional>
#include <span>
namespace hexlab {class ReferenceIndex;struct DerivedProposal;struct ImageMetadata;struct AnalysisOptions;}
namespace hexlab::database {
class ProjectCollaboration;
using ProjectUuid=std::array<std::byte,16>;
struct ProjectRevisions {std::uint64_t edit=0,bytes=0,decisions=0;bool operator==(const ProjectRevisions&)const=default;};
using ::hexlab::InputIdentity;
using ::hexlab::AnalysisKey;
enum class NativeEncoding {utf8=1,utf16le=2};
struct InputProvenance {NativeEncoding encoding;std::filesystem::path native_path;std::vector<std::byte> encoded_path;std::string relative_path;};
struct Annotation {std::uint64_t id;Location location;std::string name,comment;bool operator==(const Annotation&)const=default;};
struct Bookmark {std::uint64_t id;Location location;std::string label;bool operator==(const Bookmark&)const=default;};
enum class ProjectBreakpointKind : std::uint8_t { software, hardware, execute, read, write, access };
struct ProjectBreakpoint {
    std::uint64_t id=0;
    Address address{};
    ProjectBreakpointKind kind=ProjectBreakpointKind::software;
    bool enabled=true;
    std::uint8_t size=1;
    std::string condition;
    bool logpoint=false;
    std::string log_message;
    // Configured ignore threshold and runtime count. Hit counts are persisted
    // as debugger metadata, outside user-command history.
    std::uint64_t ignore_count=0;
    std::uint64_t hit_count=0;
    bool operator==(const ProjectBreakpoint& other)const {
        return id==other.id && address==other.address && kind==other.kind && enabled==other.enabled &&
               size==other.size && condition==other.condition && logpoint==other.logpoint &&
               log_message==other.log_message && ignore_count==other.ignore_count;
    }
};
struct BreakpointHitCount { std::uint64_t id=0, hit_count=0; bool operator==(const BreakpointHitCount&)const=default; };
struct DwarfSourceOrigin {
    std::string source_id, section;
    std::uint64_t unit_offset=0, record_offset=0, record_size=0;
    bool operator==(const DwarfSourceOrigin&)const=default;
};
enum class DeclarationKind : std::uint8_t { type, object, function };
inline bool declaration_type_matches(DeclarationKind kind, const types::Type* type) noexcept {
    if (!type || static_cast<unsigned>(kind) > static_cast<unsigned>(DeclarationKind::function)) return false;
    for (unsigned depth=0;type&&type->kind()==types::Kind::qualified&&depth<64;++depth) type=type->element().get();
    if (!type || type->kind()==types::Kind::qualified) return false;
    return kind==DeclarationKind::type || (kind==DeclarationKind::function ? type->kind()==types::Kind::function :
        type->kind()!=types::Kind::function&&type->kind()!=types::Kind::void_type);
}
struct TypeDefinition {
    std::uint64_t id;std::string name;types::TypePtr type;std::optional<DwarfSourceOrigin> origin;
    DeclarationKind declaration_kind=DeclarationKind::type;
    bool operator==(const TypeDefinition& other)const{return id==other.id&&name==other.name&&origin==other.origin&&declaration_kind==other.declaration_kind&&type&&other.type&&type->id()==other.type->id();}
};
struct TypeAssignment {std::uint64_t id;Location location;std::uint64_t type_id;bool operator==(const TypeAssignment&)const=default;};
struct DebugLocationOperation {
    std::uint8_t kind=0;
    std::uint64_t unsigned_operand=0;
    std::int64_t signed_operand=0;
    std::uint32_t expression_offset=0;
    std::uint64_t second_unsigned_operand=0;
    bool operator==(const DebugLocationOperation&)const=default;
};
struct DebugLocationRange {
    std::uint64_t begin=0,end=0; // half-open PC range
    std::vector<std::uint8_t> expression;
    std::vector<DebugLocationOperation> operations;
    bool operator==(const DebugLocationRange&)const=default;
};
struct DebugVariable {
    std::uint64_t id=0;
    Address function_entry{};
    std::string name;
    std::optional<std::uint64_t> type_id;
    bool is_parameter=false;
    std::uint64_t scope_offset=0;
    std::optional<std::uint64_t> address;
    std::vector<std::uint8_t> location_expression;
    std::vector<DebugLocationOperation> location_operations;
    DwarfSourceOrigin origin;
    std::optional<std::int64_t> cfa_offset;
    std::vector<DebugLocationRange> location_ranges;
    bool operator==(const DebugVariable&)const=default;
};
struct UserState {
    std::vector<Annotation> annotations;
    std::vector<Bookmark> bookmarks;
    std::vector<ProjectBreakpoint> breakpoints;
    std::vector<TypeDefinition> types;
    std::vector<TypeAssignment> type_assignments;
    std::vector<DebugVariable> debug_variables;
    AnalysisDecisions decisions;
    std::vector<PatchSpan> patches;
    bool operator==(const UserState&)const=default;
};
struct ProjectState {
    ProjectUuid uuid{};LoadRecipe recipe{Format::raw,RawOptions{Architecture::x86_64,ExecutionMode::x86_64,{{0},0},true,false,true,{}}};
    InputIdentity input;ProjectRevisions revisions;std::uint64_t history_cursor=0,next_entity=1,history_count=0;
    std::optional<InputProvenance> provenance;
    std::shared_ptr<const UserState> user=std::make_shared<const UserState>();
};
enum class ProjectMode {read_write,read_only,collaborative};
enum class ReplacePolicy {fail_if_exists,replace_existing};
struct SavedProject {std::filesystem::path path;ProjectUuid uuid;};
enum class RecoveryArtifactKind {interrupted_save,previous_version};
struct ProjectRecoveryCandidate {std::filesystem::path path;ProjectUuid uuid;RecoveryArtifactKind kind;};
struct StateDelta;
struct CommitAck {ProjectRevisions revisions;std::uint64_t history_cursor;};

inline constexpr std::size_t history_page_limit=1024;
inline constexpr std::size_t history_preview_step_limit=4096;
inline constexpr std::size_t history_preview_payload_limit=64*1024*1024;
inline constexpr std::size_t history_audit_step_limit=4096;
inline constexpr std::size_t history_audit_payload_limit=128*1024*1024;
struct HistoryEntry {
    std::uint64_t step=0,group_id=0;
    bool byte_change=false,decision_change=false,applied=false;
};
struct HistoryPage {
    ProjectUuid uuid{};
    ProjectRevisions source_revisions;
    std::uint64_t history_cursor=0,history_count=0,next_after_step=0;
    bool has_more=false;
    std::vector<HistoryEntry> entries;
};
struct HistoryPreviewLimits {
    std::size_t max_steps=256,max_delta_bytes=16*1024*1024;
};
struct HistoryPreview {
    ProjectUuid uuid{};
    // These revisions describe the durable source, not the historical state.
    ProjectRevisions source_revisions;
    std::uint64_t source_cursor=0,target_step=0,history_count=0;
    std::size_t replayed_steps=0,delta_bytes=0;
    std::shared_ptr<const UserState> user;
};
struct HistoryAuditLimits {
    std::size_t max_steps=256,max_delta_bytes=16*1024*1024;
};
struct HistoryAuditPage {
    ProjectUuid uuid{};
    ProjectRevisions source_revisions;
    std::uint64_t history_cursor=0,history_count=0,next_after_step=0;
    std::size_t entries_verified=0,delta_bytes=0;
    bool has_more=false;
};
enum class CacheStatus {hit,absent,stale,incompatible,corrupt};
struct CacheLookup {CacheStatus status;std::shared_ptr<const ReferenceIndex> index;std::string reason;};
struct DerivedCacheLookup {CacheStatus status;std::shared_ptr<const DerivedProposal> proposal;std::string reason;};
struct DerivedCacheBytes {CacheStatus status=CacheStatus::absent;std::shared_ptr<const std::vector<std::byte>> payload;std::string reason;};
struct FunctionRecognitionCache {CacheStatus status=CacheStatus::absent;std::shared_ptr<const FunctionRecognitionEvidence> evidence;std::string reason;};
class ProjectStore {
public:
    HEXLAB_DATABASE_EXPORT static Result<std::shared_ptr<ProjectStore>> create(const std::filesystem::path&,std::stop_token);
    HEXLAB_DATABASE_EXPORT static Result<std::shared_ptr<ProjectStore>> open(const std::filesystem::path&,ProjectMode,std::stop_token);
    // Opens an editable connection without the exclusive process lease. SQLite
    // serializes writers and edit-revision CAS rejects stale submissions.
    HEXLAB_DATABASE_EXPORT static Result<std::shared_ptr<ProjectStore>> open_collaborative(const std::filesystem::path&,std::stop_token);
    // Finds fully validated Save As temporaries and retained previous versions.
    // Discovery is read-only and never renames, deletes, or replaces an artifact.
    HEXLAB_DATABASE_EXPORT static Result<std::vector<ProjectRecoveryCandidate>> discover_recovery_candidates(const std::filesystem::path&,std::stop_token);
    // Revalidates a discovered recovery artifact and publishes a new project
    // copy to destination. The recovery artifact is retained unchanged.
    HEXLAB_DATABASE_EXPORT static Result<SavedProject> recover_candidate(const ProjectRecoveryCandidate&,const std::filesystem::path& destination,ReplacePolicy,std::stop_token);
    HEXLAB_DATABASE_EXPORT ~ProjectStore();
    ProjectStore(const ProjectStore&)=delete;ProjectStore& operator=(const ProjectStore&)=delete;
    HEXLAB_DATABASE_EXPORT Result<std::shared_ptr<const ProjectState>> snapshot() const;
    // Compare the persisted project identity and user-edit revisions against
    // this connection's current snapshot without materializing project rows.
    // Intended for low-frequency cross-process collaboration polling.
    HEXLAB_DATABASE_EXPORT Result<bool> external_changes_pending(std::stop_token) const;
    // Refresh the in-memory state from this store's SQLite connection after a
    // concurrent collaborative writer commits. The connection and write lease
    // remain owned by this ProjectStore.
    HEXLAB_DATABASE_EXPORT Result<std::shared_ptr<const ProjectState>> refresh_external(std::stop_token);
    HEXLAB_DATABASE_EXPORT Result<CommitAck> commit(std::uint64_t expected_edit,const StateDelta&,std::uint64_t group_id,std::stop_token);
    HEXLAB_DATABASE_EXPORT Result<CommitAck> undo(std::uint64_t expected_edit,std::stop_token);
    HEXLAB_DATABASE_EXPORT Result<CommitAck> redo(std::uint64_t expected_edit,std::stop_token);
    // Read-only projection for preparing a fallible application snapshot before undo/redo.
    HEXLAB_DATABASE_EXPORT Result<std::shared_ptr<const ProjectState>> preview_history(std::uint64_t expected_edit,bool redo,std::stop_token);
    // Ascending, exclusive step pagination, pinned to expected_edit. Includes
    // redo entries. Metadata only: no user rows or delta payloads are loaded.
    HEXLAB_DATABASE_EXPORT Result<HistoryPage> history_page(std::uint64_t expected_edit,std::uint64_t after_step,std::size_t limit,std::stop_token) const;
    // Exact durable step, including zero and positions inside command groups.
    // Available in read-only mode; never adopts the projection or edits history.
    HEXLAB_DATABASE_EXPORT Result<HistoryPreview> preview_history_at(std::uint64_t expected_edit,std::uint64_t target_step,HistoryPreviewLimits,std::stop_token) const;
    // Read-only, bounded audit of both payload directions in ascending steps.
    // Pass next_after_step to continue; this verifies payload decoding and
    // forward/inverse agreement without adopting or replaying the history.
    HEXLAB_DATABASE_EXPORT Result<HistoryAuditPage> audit_history(std::uint64_t expected_edit,std::uint64_t after_step,HistoryAuditLimits,std::stop_token) const;
    // Opening intent is resolved before writing identity/recipe; universal
    // projects store the concrete selected index rather than a default request.
    HEXLAB_DATABASE_EXPORT Result<bool> import_input(const ByteStorage&,const LoadRecipe&,const std::filesystem::path& native_provenance,std::stop_token);
    HEXLAB_DATABASE_EXPORT Result<std::shared_ptr<const ByteStorage>> materialize_input(std::stop_token);
    HEXLAB_DATABASE_EXPORT Result<SavedProject> save_as(const std::filesystem::path&,ReplacePolicy,std::stop_token);
    // Publishes an independent project at an exact history step, retaining the
    // complete undo/redo log and stable-ID allocation. Source is never edited.
    // Replay budgets and expected_edit refer to the coherent copied snapshot.
    HEXLAB_DATABASE_EXPORT Result<SavedProject> save_history_as(std::uint64_t expected_edit,std::uint64_t target_step,HistoryPreviewLimits,const std::filesystem::path&,ReplacePolicy,std::stop_token);
    // Publishes a validated, consistent SQLite backup while preserving the
    // logical project UUID and edit history. Unlike save_as(), this is a
    // restore point, not a new independent project identity.
    HEXLAB_DATABASE_EXPORT Result<SavedProject> backup_to(const std::filesystem::path&,ReplacePolicy,std::stop_token);
    HEXLAB_DATABASE_EXPORT ProjectMode mode() const noexcept;
    HEXLAB_DATABASE_EXPORT const std::filesystem::path& path()const noexcept;
    HEXLAB_DATABASE_EXPORT Result<CacheLookup> load_reference_cache(const AnalysisKey&,std::stop_token);
    HEXLAB_DATABASE_EXPORT Result<bool> store_reference_cache(const AnalysisKey&,const ReferenceIndex&,std::stop_token);
    HEXLAB_DATABASE_EXPORT Result<DerivedCacheLookup> load_derived_cache(const AnalysisKey&,const Image&,const ImageMetadata&,const AnalysisOptions&,std::stop_token);
    HEXLAB_DATABASE_EXPORT Result<bool> store_derived_cache(const DerivedProposal&,std::stop_token);
    HEXLAB_DATABASE_EXPORT Result<DerivedCacheBytes> read_derived_cache(const AnalysisKey&,std::stop_token);
    HEXLAB_DATABASE_EXPORT Result<bool> write_derived_cache(const AnalysisKey&,std::span<const std::byte>,std::stop_token);
    HEXLAB_DATABASE_EXPORT Result<FunctionRecognitionCache> read_function_recognition(const AnalysisKey&,FunctionRecognitionKind,std::stop_token);
    HEXLAB_DATABASE_EXPORT Result<bool> write_function_recognition(const AnalysisKey&,const FunctionRecognitionEvidence&,std::stop_token);
    // Runtime debugger metadata is committed atomically without changing edit
    // revisions or creating undo history.
    HEXLAB_DATABASE_EXPORT Result<bool> persist_breakpoint_hit_counts(std::span<const BreakpointHitCount>,std::stop_token);
    HEXLAB_DATABASE_EXPORT Result<bool> checkpoint(std::stop_token);
private:
    struct HistorySaveRequest {std::uint64_t expected_edit,target_step;HistoryPreviewLimits limits;};
    Result<SavedProject> save_as_impl(const std::filesystem::path&,ReplacePolicy,std::stop_token,std::optional<HistorySaveRequest>);
    friend class ProjectCollaboration;
    HEXLAB_DATABASE_EXPORT Result<CommitAck> commit_resolving_conflict(std::uint64_t conflict_id,std::uint64_t expected_edit,const StateDelta&,std::uint64_t group_id,std::stop_token);
    struct Impl;explicit ProjectStore(std::unique_ptr<Impl>);std::unique_ptr<Impl> impl_;
};
}
