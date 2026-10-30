#pragma once
#include "hexlab/database/connection.hpp"
#include "hexlab/core/sha256.hpp"
#include "hexlab/analysis/decisions.hpp"
#include "hexlab/analysis/dependencies.hpp"
#include "hexlab/analysis/signatures.hpp"
#include "hexlab/image/patches.hpp"
#include "hexlab/image/metadata.hpp"
#include "hexlab/loaders/recipe.hpp"
#include "hexlab/types/types.hpp"
#include <array>
#include <cstddef>
#include <optional>
#include <span>
#include <string>
#include <vector>
namespace hexlab {class ReferenceIndex;struct DerivedProposal;struct ImageMetadata;struct AnalysisOptions;}
namespace hexlab::database {
class ProjectCollaboration;
using ProjectUuid=std::array<std::byte,16>;
struct ProjectRevisions {std::uint64_t edit=0,bytes=0,decisions=0;bool operator==(const ProjectRevisions&)const=default;};
struct ProjectIntegrityReport {
    ProjectUuid uuid{};
    ProjectRevisions revisions{};
    bool consistent=false;
    bool complete=true;
    std::vector<std::string> issues;
};
inline constexpr int current_project_schema_version = 18;
enum class ProjectSchemaState : std::uint8_t { supported, newer_than_supported, invalid_or_unreadable };
struct ProjectSchemaCompatibilityReport {
    ProjectSchemaState state = ProjectSchemaState::invalid_or_unreadable;
    std::optional<int> stored_version;
    int current_version = current_project_schema_version;
    bool read_only_supported = false;
    bool writable_migration_available = false;
    std::string diagnostic;
};
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
    // Persistent rule setting; each runtime session arms its own one-shot copy.
    bool one_shot=false;
    std::uint64_t hit_count=0;
    bool operator==(const ProjectBreakpoint& other)const {
        return id==other.id && address==other.address && kind==other.kind && enabled==other.enabled &&
               size==other.size && condition==other.condition && logpoint==other.logpoint &&
               log_message==other.log_message && ignore_count==other.ignore_count && one_shot==other.one_shot;
    }
};
struct BreakpointHitCount { std::uint64_t id=0, hit_count=0; bool operator==(const BreakpointHitCount&)const=default; };
struct TypeImportDiagnostic {
    std::string source;
    DiagnosticSeverity severity=DiagnosticSeverity::warning;
    std::string message;
    std::optional<Address> location, function_entry;
    std::optional<AnalysisKey> source_key;
    bool operator==(const TypeImportDiagnostic&)const=default;
};
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
    // For DW_OP_implicit_value only: bytes are packed low-byte first into
    // unsigned_operand and this field records their length. Length 9 marks a
    // decoded block wider than the scalar evaluator can retain.
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
    // Loader-origin findings are durable import metadata, independent of the
    // undoable user state. Runtime relocation findings share the same lifecycle.
    std::vector<Diagnostic> loader_diagnostics, runtime_relocation_diagnostics;
    // The most recently completed type/debug-symbol import report is durable
    // metadata, not an undoable user edit.
    std::vector<TypeImportDiagnostic> type_import_diagnostics;
    // User triage state for issue rows, scoped to the current project.
    std::vector<std::string> reviewed_analysis_issue_keys;
    std::shared_ptr<const UserState> user=std::make_shared<const UserState>();
};
enum class ProjectMode {read_write,read_only,collaborative};
enum class ReplacePolicy {fail_if_exists,replace_existing};
// Controls whether a project backup also verifies its external source path
// against the input bytes embedded in the project database.
enum class ExternalSourcePolicy : std::uint8_t { preserve_provenance, require_matching_input };
struct ProjectBackupOptions {
    ExternalSourcePolicy external_source = ExternalSourcePolicy::preserve_provenance;
};
struct SavedProject {std::filesystem::path path;ProjectUuid uuid;};
inline constexpr std::uint64_t source_archive_byte_limit=UINT64_C(1024)*1024*1024;
struct SourceArchiveOptions {
    std::uint64_t max_bytes=UINT64_C(256)*1024*1024;
};
struct SourceArchiveResult {
    std::filesystem::path path,source;
    ProjectUuid uuid{};
    InputIdentity input;
};
struct SourceArchiveVerification {
    std::filesystem::path path;
    ProjectUuid project_uuid{};
    InputIdentity input;
    std::uint64_t bytes_verified=0;
};
struct SourceArchiveRestore {
    std::filesystem::path archive_path, restored_path;
    ProjectUuid project_uuid{};
    InputIdentity input;
};
// A portable directory bundle. The project database's source provenance is
// relative to `source.bin`, and the pair is published/restored as one directory.
struct ProjectBackupBundle {
    std::filesystem::path path;
    SavedProject project;
    SourceArchiveResult source;
};
struct ProjectBackupBundleRestore {
    std::filesystem::path path;
    SavedProject project;
    SourceArchiveRestore source;
};
struct SourceArchiveRotationResult {
    SourceArchiveResult archive;
    std::size_t removed_generations=0;
    bool retention_satisfied=true;
};
struct RotatedSourceArchive {
    SourceArchiveVerification archive;
    std::uint64_t created_unix_ms=0;
};
struct SourceArchiveListing { std::vector<RotatedSourceArchive> archives; bool complete=true; };
struct SourceArchivePruneResult { std::size_t remaining=0, removed=0; bool retention_satisfied=true; };
struct BackupVerification {
    SavedProject backup;
    InputIdentity input;
    std::uint64_t history_count=0,history_steps_verified=0,history_bytes_verified=0;
    bool history_complete=false;
};
struct BackupRotationResult { SavedProject backup; std::size_t removed_generations=0; bool retention_satisfied=true; };
struct RotatedBackup {
    SavedProject backup;
    std::uint64_t created_unix_ms=0;
    // Exact file identity pinned by the validating listing so prune can refuse
    // to delete a path that changed after the listing pass.
    std::uint64_t artifact_size=0;
    Sha256Digest artifact_sha256{};
};
struct BackupListing { std::vector<RotatedBackup> backups; bool complete=true; };
struct BackupPruneResult { std::size_t remaining=0, removed=0; bool retention_satisfied=true; };
enum class RecoveryArtifactKind {interrupted_save,previous_version};
struct ProjectRecoveryCandidate {
    std::filesystem::path path;
    ProjectUuid uuid;
    RecoveryArtifactKind kind;
    // Discovery pins the user-edit revisions so delayed restore requests fail
    // if the candidate changed after the read-only scan.
    ProjectRevisions revisions;
    // Exact staged-file identity, so a different valid database with the
    // same logical UUID/revisions cannot replace the discovered artifact.
    std::uint64_t artifact_size = 0;
    Sha256Digest artifact_sha256{};
};
struct ProjectRecoveryIssue {
    // Filename only: the scan's directory is already known and this keeps
    // diagnostics independent of long or sensitive parent paths.
    std::string name;
    std::string reason;
};
struct ProjectRecoveryScan {
    std::vector<ProjectRecoveryCandidate> candidates;
    std::vector<ProjectRecoveryIssue> issues;
    std::size_t visited_entries=0, matching_names=0, rejected_entries=0, omitted_issues=0;
    // False when entry or candidate caps prevented a complete directory scan.
    bool complete=true;
    std::size_t omitted_candidates=0;
};
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
    // Older projects have no recorded command time; migration leaves it empty
    // rather than inventing a timestamp for historical edits.
    std::optional<std::uint64_t> created_unix_ms;
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
enum class HistorySourceIdentityCheck : std::uint8_t {
    not_checked, no_recorded_path, unavailable, over_limit, size_mismatch, digest_mismatch, matches
};
inline constexpr std::uint64_t history_source_identity_check_limit=UINT64_C(256)*1024*1024;
struct HistoryAuditPage {
    ProjectUuid uuid{};
    ProjectRevisions source_revisions;
    std::uint64_t history_cursor=0,history_count=0,next_after_step=0;
    std::size_t entries_verified=0,delta_bytes=0;
    bool has_more=false;
    // Set on the first page only. This checks the current external file against
    // the immutable input identity embedded in the project, not historical bytes.
    HistorySourceIdentityCheck source_identity_check=HistorySourceIdentityCheck::not_checked;
};
// Whole-log semantic verification counts the rewind of the applied branch and
// the subsequent forward replay separately. No partial proof is returned.
struct HistoryReplayLimits {
    std::size_t max_steps=4096,max_delta_bytes=64u*1024u*1024u;
    std::uint64_t max_input_bytes=UINT64_C(256)*1024*1024;
    // Cumulative canonical state bytes plus original patch bytes checked.
    std::uint64_t max_validation_bytes=UINT64_C(256)*1024*1024;
};
struct HistoryReplayReport {
    ProjectUuid uuid{};
    ProjectRevisions source_revisions;
    InputIdentity input;
    std::uint64_t history_cursor=0,history_count=0;
    std::size_t rewound_steps=0,forward_steps=0,delta_bytes=0;
    std::uint64_t input_bytes_verified=0,validation_bytes=0,patch_bytes_verified=0;
};
enum class CacheStatus {hit,absent,stale,incompatible,corrupt};
struct CacheLookup {CacheStatus status;std::shared_ptr<const ReferenceIndex> index;std::string reason;};
struct DerivedCacheLookup {CacheStatus status;std::shared_ptr<const DerivedProposal> proposal;std::string reason;};
struct DerivedCacheBytes {CacheStatus status=CacheStatus::absent;std::shared_ptr<const std::vector<std::byte>> payload;std::string reason;};
struct FunctionRecognitionCache {CacheStatus status=CacheStatus::absent;std::shared_ptr<const FunctionRecognitionEvidence> evidence;std::string reason;};
class ProjectStore {
public:
    // Read-only compatibility probe. It pins one SQLite read snapshot, checks
    // the application/schema header, and validates known schema versions
    // without running migrations or loading project entities.
    HEXLAB_DATABASE_EXPORT static Result<ProjectSchemaCompatibilityReport> inspect_schema_compatibility(
        const std::filesystem::path&,std::stop_token);
    HEXLAB_DATABASE_EXPORT static Result<std::shared_ptr<ProjectStore>> create(const std::filesystem::path&,std::stop_token);
    HEXLAB_DATABASE_EXPORT static Result<std::shared_ptr<ProjectStore>> open(const std::filesystem::path&,ProjectMode,std::stop_token);
    // Opens an editable connection without the exclusive process lease. SQLite
    // serializes writers and edit-revision CAS rejects stale submissions.
    HEXLAB_DATABASE_EXPORT static Result<std::shared_ptr<ProjectStore>> open_collaborative(const std::filesystem::path&,std::stop_token);
    // Finds fully validated Save As temporaries and retained previous versions,
    // including their retained edit history within a scan-wide verification budget.
    // Discovery is read-only and never renames, deletes, or replaces an artifact.
    HEXLAB_DATABASE_EXPORT static Result<std::vector<ProjectRecoveryCandidate>> discover_recovery_candidates(const std::filesystem::path&,std::stop_token);
    // Read-only detailed scan. Candidates meet the same full validation rules
    // as discover_recovery_candidates; bounded issues explain rejected files
    // whose names look like HexLab staging artifacts or exceed the history budget.
    HEXLAB_DATABASE_EXPORT static Result<ProjectRecoveryScan> inspect_recovery_directory(const std::filesystem::path&,std::stop_token);
    // Revalidates a discovered recovery artifact and publishes a new project
    // copy to destination. The recovery artifact is retained unchanged.
    HEXLAB_DATABASE_EXPORT static Result<SavedProject> recover_candidate(const ProjectRecoveryCandidate&,const std::filesystem::path& destination,ReplacePolicy,std::stop_token);
    // Restores only a discovered previous-version artifact over the same
    // project identity. Candidate UUID/revisions are rechecked before publish.
    HEXLAB_DATABASE_EXPORT static Result<SavedProject> recover_candidate_in_place(
        const ProjectRecoveryCandidate&,const std::filesystem::path& target,std::stop_token);
    HEXLAB_DATABASE_EXPORT ~ProjectStore();
    ProjectStore(const ProjectStore&)=delete;ProjectStore& operator=(const ProjectStore&)=delete;
    HEXLAB_DATABASE_EXPORT Result<std::shared_ptr<const ProjectState>> snapshot() const;
    // Runs bounded SQLite integrity and foreign-key checks against one
    // read snapshot. Does not repair or mutate the project.
    HEXLAB_DATABASE_EXPORT Result<ProjectIntegrityReport> check_integrity(
        std::uint64_t expected_edit,std::size_t max_issues,std::stop_token) const;
    // Compare the persisted project identity and user-edit revisions against
    // this connection's current snapshot without materializing project rows.
    // Intended for low-frequency cross-process collaboration polling.
    HEXLAB_DATABASE_EXPORT Result<bool> external_changes_pending(std::stop_token) const;
    // Refresh the in-memory state from this store's SQLite connection after a
    // concurrent collaborative writer commits. The connection and write lease
    // remain owned by this ProjectStore. UUID/input changes are conflicts;
    // cancellation/failure rolls back the read transaction and retains the
    // prior in-memory state/input so this connection can be retried.
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
    // Rewinds to an empty step zero, then replays every retained command,
    // including redo. Checks current-state agreement, inverse pairing, actual
    // invalidation flags and original patch bytes against verified input.
    // Resource-limit/cancellation/errors return no partially verified report.
    HEXLAB_DATABASE_EXPORT Result<HistoryReplayReport> verify_history_replay(
        std::uint64_t expected_edit,HistoryReplayLimits,std::stop_token) const;
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
    HEXLAB_DATABASE_EXPORT Result<SavedProject> backup_to(const std::filesystem::path&,ReplacePolicy,std::stop_token,
                                                          ProjectBackupOptions);
    // Atomically publishes a new directory containing a validated same-UUID
    // project backup and its matching original source bytes. Existing paths
    // are rejected; the source payload is limited by SourceArchiveOptions.
    HEXLAB_DATABASE_EXPORT Result<ProjectBackupBundle> backup_bundle_to(
        const std::filesystem::path&,SourceArchiveOptions,std::stop_token);
    // Validates and restores both members into one newly published directory.
    // The restored project keeps the backup UUID and points to `source.bin`.
    HEXLAB_DATABASE_EXPORT static Result<ProjectBackupBundleRestore> restore_bundle_to(
        const std::filesystem::path& bundle,const std::filesystem::path& destination,
        std::uint64_t max_source_bytes,std::stop_token);
    // Copies the recorded external source, only if the streamed bytes match
    // the embedded original input identity. Never replaces an existing file,
    // changes provenance, or archives effective patched bytes. Max 1 GiB.
    HEXLAB_DATABASE_EXPORT Result<SourceArchiveResult> archive_external_source(
        const std::filesystem::path&,SourceArchiveOptions,std::stop_token);
    // Confirms a copied source archive byte-for-byte against the input identity
    // embedded in this open project, without importing or changing provenance.
    HEXLAB_DATABASE_EXPORT Result<SourceArchiveVerification> verify_source_archive(
        const std::filesystem::path&,std::uint64_t max_bytes,std::stop_token) const;
    // Restores a previously archived source to a new path only when its
    // streamed bytes match this project's embedded input identity. Existing
    // destinations and aliases of protected project/source/archive files are
    // rejected; project provenance is unchanged.
    HEXLAB_DATABASE_EXPORT Result<SourceArchiveRestore> restore_source_archive(
        const std::filesystem::path& archive,const std::filesystem::path& destination,
        std::uint64_t max_bytes,std::stop_token);
    // Timestamped source archives are verified against the project's embedded
    // original input identity before they can be listed or pruned.
    HEXLAB_DATABASE_EXPORT Result<SourceArchiveRotationResult> archive_external_source_rotating(
        const std::filesystem::path& base,std::size_t retain,SourceArchiveOptions,std::stop_token);
    HEXLAB_DATABASE_EXPORT Result<SourceArchiveListing> list_rotated_source_archives(
        const std::filesystem::path& base,std::uint64_t max_bytes,std::stop_token) const;
    HEXLAB_DATABASE_EXPORT Result<SourceArchivePruneResult> prune_rotated_source_archives(
        const std::filesystem::path& base,std::size_t retain,std::uint64_t max_bytes,std::stop_token);
    // Validates project/schema/input/patch integrity and audits bounded history
    // payload pages. history_complete is false when the caller's budget ends.
    HEXLAB_DATABASE_EXPORT static Result<BackupVerification> verify_backup(
        const std::filesystem::path&,std::size_t max_history_steps,
        std::size_t max_history_delta_bytes,std::stop_token);
    // Creates a timestamped sibling backup and prunes only validated backups
    // matching this base filename and project UUID. Retention is best-effort
    // when the directory exceeds the bounded scan/validation budget.
    HEXLAB_DATABASE_EXPORT Result<BackupRotationResult> backup_to_rotating(const std::filesystem::path& base,
        std::size_t retain,std::stop_token);
    HEXLAB_DATABASE_EXPORT Result<BackupListing> list_rotated_backups(const std::filesystem::path& base,
        std::stop_token) const;
    HEXLAB_DATABASE_EXPORT Result<BackupPruneResult> prune_rotated_backups(const std::filesystem::path& base,
        std::size_t retain,std::stop_token);
    // Replaces a closed target project from a validated same-UUID backup. The
    // caller must reopen the returned path to refresh its in-memory snapshot.
    HEXLAB_DATABASE_EXPORT static Result<SavedProject> restore_backup_in_place(
        const std::filesystem::path& backup,const std::filesystem::path& target,std::stop_token);
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
    HEXLAB_DATABASE_EXPORT Result<bool> replace_loader_diagnostics(std::span<const Diagnostic>,std::span<const Diagnostic>,std::stop_token);
    HEXLAB_DATABASE_EXPORT Result<bool> replace_type_import_diagnostics(std::span<const TypeImportDiagnostic>,std::stop_token);
    // Reserved source "Minidump register context"; replaces only this family,
    // retaining the exact AnalysisKey outside edit history. No guessed locations.
    HEXLAB_DATABASE_EXPORT Result<bool> replace_minidump_context_diagnostics(const AnalysisKey&,std::span<const TypeImportDiagnostic>,std::stop_token);
    // Replaces one decompiler function's findings for an exact analysis source.
    // Other functions and older analysis sources remain available for triage.
    HEXLAB_DATABASE_EXPORT Result<bool> upsert_decompiler_diagnostics(const AnalysisKey&,Address,std::span<const TypeImportDiagnostic>,std::stop_token);
    HEXLAB_DATABASE_EXPORT Result<bool> replace_reviewed_analysis_issue_keys(std::span<const std::string>,std::stop_token);
    // Per-project UI preferences, outside edit history. Keys are namespaced and
    // capped at 128 bytes; values are capped at 16 KiB.
    HEXLAB_DATABASE_EXPORT Result<std::optional<std::string>> read_preference(std::string_view key) const;
    HEXLAB_DATABASE_EXPORT Result<bool> write_preference(std::string_view key,std::string_view value,std::stop_token);
    HEXLAB_DATABASE_EXPORT Result<bool> checkpoint(std::stop_token);
private:
    struct HistorySaveRequest {std::uint64_t expected_edit,target_step;HistoryPreviewLimits limits;};
    Result<SavedProject> save_as_impl(const std::filesystem::path&,ReplacePolicy,std::stop_token,std::optional<HistorySaveRequest>,bool verify_history=false);
    static Result<SavedProject> restore_backup_in_place_checked(
        const std::filesystem::path&,const std::filesystem::path&,
        const ProjectRecoveryCandidate*,std::stop_token);
    friend class ProjectCollaboration;
    HEXLAB_DATABASE_EXPORT Result<CommitAck> commit_resolving_conflict(std::uint64_t conflict_id,std::uint64_t expected_edit,const StateDelta&,std::uint64_t group_id,std::stop_token);
    struct Impl;explicit ProjectStore(std::unique_ptr<Impl>);std::unique_ptr<Impl> impl_;
};
}
