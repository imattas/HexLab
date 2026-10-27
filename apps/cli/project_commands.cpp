#include "project_commands.hpp"
#include "project_arguments.hpp"
#include "project_exchange_cli.hpp"
#include "hexlab/workspace/project_exchange.hpp"
#include "hexlab/database/project_state.hpp"
#include <algorithm>
#include <fstream>
#include <functional>
#include <iomanip>
#include <ostream>
#include <set>
#include <sstream>
#include <unordered_set>
namespace hexlab::cli {
namespace {
std::string uuid_text(const database::ProjectUuid &uuid) {
    std::ostringstream text;
    text << std::hex << std::setfill('0');
    for (const auto byte : uuid)
        text << std::setw(2) << std::to_integer<unsigned>(byte);
    return text.str();
}

std::string path_utf8(const std::filesystem::path &path) {
    const auto encoded = path.generic_u8string();
    return std::string(reinterpret_cast<const char *>(encoded.data()), encoded.size());
}

std::string json_string(std::string_view value) {
    std::ostringstream out;
    out << '"';
    for (const unsigned char c : value) {
        switch (c) {
        case '"': out << "\\\""; break;
        case '\\': out << "\\\\"; break;
        case '\b': out << "\\b"; break;
        case '\f': out << "\\f"; break;
        case '\n': out << "\\n"; break;
        case '\r': out << "\\r"; break;
        case '\t': out << "\\t"; break;
        default:
            if (c < 0x20) out << "\\u00" << std::hex << std::setw(2) << std::setfill('0') << static_cast<unsigned>(c) << std::dec;
            else out << static_cast<char>(c);
        }
    }
    out << '"';
    return out.str();
}

std::string recovery_kind(database::RecoveryArtifactKind kind) {
    return kind == database::RecoveryArtifactKind::interrupted_save ? "interrupted_save" : "previous_version";
}

std::string exchange_kind_name(ExchangeRecordKind kind) {
    switch (kind) {
    case ExchangeRecordKind::annotation: return "annotation";
    case ExchangeRecordKind::bookmark: return "bookmark";
    case ExchangeRecordKind::reference: return "reference";
    case ExchangeRecordKind::region: return "region";
    case ExchangeRecordKind::function: return "function";
    case ExchangeRecordKind::type_definition: return "type_definition";
    case ExchangeRecordKind::type_assignment: return "type_assignment";
    case ExchangeRecordKind::debug_variable: return "debug_variable";
    }
    return "unknown";
}

std::string exchange_resolution_name(ExchangeConflictResolution resolution) {
    switch (resolution) {
    case ExchangeConflictResolution::kept_existing: return "kept_existing";
    case ExchangeConflictResolution::imported: return "imported";
    case ExchangeConflictResolution::preserved_both: return "preserved_both";
    }
    return "unknown";
}

void print_exchange_import_report(std::ostream &out, const ExchangeImport &plan, bool json,
                                  bool applied, bool would_fail) {
    constexpr std::size_t max_reported_conflicts = 1000;
    const auto reported = std::min(plan.conflicts.size(), max_reported_conflicts);
    if (json) {
        out << "{\"schema_version\":1,\"applied\":" << (applied ? "true" : "false")
            << ",\"would_fail\":" << (would_fail ? "true" : "false")
            << ",\"counts\":{\"annotations\":" << plan.annotations
            << ",\"bookmarks\":" << plan.bookmarks << ",\"references\":" << plan.references
            << ",\"regions\":" << plan.regions << ",\"functions\":" << plan.functions
            << ",\"types\":" << plan.type_definitions << ",\"type_assignments\":" << plan.type_assignments
            << ",\"debug_variables\":" << plan.debug_variables << ",\"skipped\":" << plan.skipped
            << ",\"conflicts\":" << plan.conflicts.size() << "},\"reported_conflicts\":" << reported
            << ",\"omitted_conflicts\":" << (plan.conflicts.size() - reported) << ",\"conflict_rows\":[";
        for (std::size_t i = 0; i < reported; ++i) {
            if (i) out << ',';
            const auto &conflict = plan.conflicts[i];
            out << "{\"kind\":" << json_string(exchange_kind_name(conflict.kind))
                << ",\"location\":" << json_string(project_detail::location(conflict.location))
                << ",\"related_location\":";
            if (conflict.related_location)
                out << json_string(project_detail::location(*conflict.related_location));
            else
                out << "null";
            out << ",\"resolution\":" << json_string(exchange_resolution_name(conflict.resolution)) << '}';
        }
        out << "]}\n";
        return;
    }

    out << (applied ? "Imported exchange" : "Exchange import preview")
        << ": annotations=" << plan.annotations << " bookmarks=" << plan.bookmarks
        << " references=" << plan.references << " regions=" << plan.regions << " functions=" << plan.functions
        << " types=" << plan.type_definitions << " type-assignments=" << plan.type_assignments
        << " debug-variables=" << plan.debug_variables << " skipped=" << plan.skipped
        << " conflicts=" << plan.conflicts.size();
    if (would_fail) out << " (selected fail policy would reject this import)";
    out << '\n';
    for (std::size_t i = 0; i < reported; ++i) {
        const auto &conflict = plan.conflicts[i];
        out << "  " << exchange_kind_name(conflict.kind) << " @ "
            << project_detail::location(conflict.location);
        if (conflict.related_location)
            out << " -> " << project_detail::location(*conflict.related_location);
        out << ": " << exchange_resolution_name(conflict.resolution) << '\n';
    }
    if (reported < plan.conflicts.size())
        out << "  ... " << (plan.conflicts.size() - reported) << " additional conflicts omitted\n";
}

int run_recovery_list(const project_detail::Arguments &args, std::ostream &out) {
    using namespace project_detail;
    const auto candidates = take(database::ProjectStore::discover_recovery_candidates(args.path, {}));
    if (args.recovery_json) {
        out << "{\"schema_version\":1,\"directory\":" << json_string(path_utf8(args.path)) << ",\"candidates\":[";
        for (std::size_t i = 0; i < candidates.size(); ++i) {
            if (i) out << ',';
            out << "{\"path\":" << json_string(path_utf8(candidates[i].path))
                << ",\"uuid\":" << json_string(uuid_text(candidates[i].uuid))
                << ",\"kind\":" << json_string(recovery_kind(candidates[i].kind)) << '}';
        }
        out << "]}\n";
    } else {
        out << "Validated project recovery artifacts in " << escape(path_utf8(args.path)) << ": " << candidates.size() << '\n';
        for (const auto &candidate : candidates)
            out << "  " << recovery_kind(candidate.kind) << " uuid=" << uuid_text(candidate.uuid)
                << " path=" << escape(path_utf8(candidate.path)) << '\n';
    }
    return 0;
}

int run_recovery_restore(const project_detail::Arguments &args, std::ostream &out) {
    using namespace project_detail;
    require(!args.readonly, "Cannot restore a recovery artifact with --readonly");
    const auto directory = args.path.has_parent_path() ? args.path.parent_path() : std::filesystem::path(".");
    const auto candidates = take(database::ProjectStore::discover_recovery_candidates(directory, {}));
    std::error_code error;
    const auto requested = std::filesystem::absolute(args.path, error).lexically_normal();
    if (error) throw Failure{{ErrorCode::io, "Cannot resolve recovery artifact path: " + error.message()}};
    const auto found = std::find_if(candidates.begin(), candidates.end(), [&](const auto &candidate) {
        std::error_code candidate_error;
        const auto discovered = std::filesystem::absolute(candidate.path, candidate_error).lexically_normal();
        return !candidate_error && discovered == requested;
    });
    require(found != candidates.end(), "Path is not a fully validated HexLab recovery artifact");
    const auto policy = args.replace ? database::ReplacePolicy::replace_existing : database::ReplacePolicy::fail_if_exists;
    const auto restored = take(database::ProjectStore::recover_candidate(*found, args.output, policy, {}));
    out << "Recovered project: " << escape(path_utf8(restored.path)) << " uuid=" << uuid_text(restored.uuid)
        << " (source artifact retained)\n";
    return 0;
}

int run_project_backup(const project_detail::Arguments &args, std::ostream &out) {
    using namespace project_detail;
    auto store = take(database::ProjectStore::open(args.path, database::ProjectMode::read_only, {}));
    const auto policy = args.replace ? database::ReplacePolicy::replace_existing
                                     : database::ReplacePolicy::fail_if_exists;
    const auto saved = take(store->backup_to(args.output, policy, {}));
    out << "Backed up project: " << escape(path_utf8(saved.path)) << " uuid=" << uuid_text(saved.uuid) << '\n';
    return 0;
}

int run_project_backup_restore(const project_detail::Arguments &args, std::ostream &out) {
    using namespace project_detail;
    // A restore point retains its source UUID. save_as() deliberately creates
    // a new UUID, making the restored output an independent project that can
    // be opened alongside the source or backup.
    auto store = take(database::ProjectStore::open(args.path, database::ProjectMode::read_only, {}));
    const auto policy = args.replace ? database::ReplacePolicy::replace_existing
                                     : database::ReplacePolicy::fail_if_exists;
    const auto restored = take(store->save_as(args.output, policy, {}));
    out << "Restored backup as independent project: " << escape(path_utf8(restored.path)
        ) << " uuid=" << uuid_text(restored.uuid) << '\n';
    return 0;
}

int run_project_backup_list(const project_detail::Arguments &args, std::ostream &out) {
    using namespace project_detail;
    auto store = take(database::ProjectStore::open(args.path, database::ProjectMode::read_only, {}));
    const auto listing = take(store->list_rotated_backups(args.backup_base, {}));
    if (args.backup_json) {
        out << "{\"complete\":" << (listing.complete ? "true" : "false") << ",\"backups\":[";
        for (std::size_t i=0;i<listing.backups.size();++i) {
            if (i) out << ',';
            const auto &row=listing.backups[i];
            out << "{\"path\":" << json_string(path_utf8(row.backup.path))
                << ",\"uuid\":" << json_string(uuid_text(row.backup.uuid))
                << ",\"created_unix_ms\":" << row.created_unix_ms << '}';
        }
        out << "]}\n";
    } else {
        out << "Validated rotated backups for " << escape(path_utf8(args.backup_base)) << ": " << listing.backups.size()
            << (listing.complete ? " (complete scan)\n" : " (scan incomplete)\n");
        for (const auto &row : listing.backups)
            out << escape(path_utf8(row.backup.path)) << " uuid=" << uuid_text(row.backup.uuid)
                << " created-unix-ms=" << row.created_unix_ms << '\n';
    }
    return listing.complete ? 0 : 3;
}

int run_project_backup_rotate(const project_detail::Arguments &args, std::ostream &out) {
    using namespace project_detail;
    auto store = take(database::ProjectStore::open(args.path, database::ProjectMode::read_only, {}));
    const auto result = take(store->backup_to_rotating(args.backup_base, args.backup_retention, {}));
    out << "Created rotated backup: " << escape(path_utf8(result.backup.path)) << " uuid=" << uuid_text(result.backup.uuid)
        << "; removed=" << result.removed_generations << "; retention=" << (result.retention_satisfied ? "satisfied" : "incomplete") << '\n';
    return result.retention_satisfied ? 0 : 3;
}

int run_project_backup_prune(const project_detail::Arguments &args, std::ostream &out) {
    using namespace project_detail;
    auto store = take(database::ProjectStore::open(args.path, database::ProjectMode::read_only, {}));
    const auto result = take(store->prune_rotated_backups(args.backup_base, args.backup_retention, {}));
    out << "Pruned rotated backups: removed=" << result.removed << " remaining=" << result.remaining
        << "; retention=" << (result.retention_satisfied ? "satisfied" : "incomplete") << '\n';
    return result.retention_satisfied ? 0 : 3;
}

int run_project_backup_restore_in_place(const project_detail::Arguments &args, std::ostream &out) {
    using namespace project_detail;
    const auto restored = take(database::ProjectStore::restore_backup_in_place(args.path, args.output, {}));
    out << "Restored project in place: " << escape(path_utf8(restored.path)) << " uuid=" << uuid_text(restored.uuid)
        << " (close all project connections before restore; reopen target afterward)\n";
    return 0;
}

int run_history_audit(const project_detail::Arguments &args, std::ostream &out, std::ostream &err) {
    using namespace project_detail;
    auto store = take(database::ProjectStore::open(args.path, database::ProjectMode::read_only, {}));
    auto snapshot = take(store->snapshot());
    const auto expected_edit = args.history_expected_edit.value_or(snapshot->revisions.edit);
    if (expected_edit != snapshot->revisions.edit)
        throw Failure{{ErrorCode::conflict, "Project edit revision changed; refresh before retrying"}};

    std::uint64_t cursor = args.history_after_step;
    std::size_t pages = 0, entries = 0, delta_bytes = 0;
    std::uint64_t history_cursor = 0, history_count = 0;
    bool has_more = true, byte_budget_limited = false;
    while (has_more && pages < args.history_max_pages) {
        const auto remaining = args.history_total_delta_bytes - delta_bytes;
        if (!remaining) { byte_budget_limited = true; break; }
        auto limits = args.history_audit_limits;
        limits.max_delta_bytes = std::min(limits.max_delta_bytes, remaining);
        auto result = store->audit_history(expected_edit, cursor, limits, {});
        if (!result) {
            // The last requested page may contain a single payload larger than
            // the remaining whole-command budget. Preserve the prior cursor so
            // the caller can resume with a larger total budget.
            if (pages && result.error().code == ErrorCode::resource_limit) {
                byte_budget_limited = true;
                break;
            }
            throw Failure{result.error()};
        }
        const auto &page = result.value();
        if (!pages) {
            history_cursor = page.history_cursor;
            history_count = page.history_count;
        }
        ++pages;
        entries += page.entries_verified;
        delta_bytes += page.delta_bytes;
        cursor = page.next_after_step;
        has_more = page.has_more;
        if (!args.history_json && (pages == 1 || pages % 32 == 0))
            err << "History audit page " << pages << ": " << page.entries_verified
                << " entries, " << page.delta_bytes << " delta bytes (through step " << cursor << ")\n";
    }

    const bool complete = !has_more;
    bool replay_verified = false;
    if (args.history_verify_replay && complete) {
        // This proves that the applied branch can be reversed from the stored
        // current state to the empty initial user state, within the preview cap.
        database::HistoryPreviewLimits limits;
        limits.max_steps = 4096;
        limits.max_delta_bytes = 64 * 1024 * 1024;
        auto preview = store->preview_history_at(expected_edit, 0, limits, {});
        if (!preview) throw Failure{preview.error()};
        if (!preview.value().user || *preview.value().user != database::UserState{})
            throw Failure{{ErrorCode::integrity, "History replay does not return to the empty initial user state"}};
        replay_verified = true;
    }
    if (args.history_json) {
        out << "{\"schema_version\":" << (args.history_verify_replay ? 2 : 1) << ",\"status\":\"" << (complete ? "complete" : "partial")
            << "\",\"project_uuid\":\"" << uuid_text(snapshot->uuid)
            << "\",\"expected_edit\":" << expected_edit
            << ",\"source_edit\":" << snapshot->revisions.edit
            << ",\"history_cursor\":" << history_cursor
            << ",\"history_count\":" << history_count
            << ",\"started_after_step\":" << args.history_after_step
            << ",\"next_after_step\":" << cursor
            << ",\"pages\":" << pages
            << ",\"entries_verified\":" << entries
            << ",\"delta_bytes\":" << delta_bytes
            << ",\"has_more\":" << (has_more ? "true" : "false")
            << ",\"byte_budget_limited\":" << (byte_budget_limited ? "true" : "false");
        if (args.history_verify_replay)
            out << ",\"replay_verified\":" << (replay_verified ? "true" : "false");
        out << "}\n";
    } else {
        out << "History audit " << (complete ? "complete" : "partial")
            << ": project=" << uuid_text(snapshot->uuid)
            << " edit=" << expected_edit << " cursor=" << history_cursor << '/' << history_count
            << " pages=" << pages << " entries=" << entries << " delta-bytes=" << delta_bytes;
        if (byte_budget_limited) out << " (a byte budget prevented completing the next page)";
        else if (has_more) out << " (page limit reached)";
        if (args.history_verify_replay && complete) out << " replay-to-empty=verified";
        else if (args.history_verify_replay) out << " replay-to-empty=not-run (history audit is partial)";
        out << '\n';
        if (has_more)
            out << "Resume with --expected-edit " << expected_edit << " --after-step " << cursor << '\n';
    }
    return complete ? 0 : 3;
}

struct HistoryStateCounts {
    std::size_t annotations, bookmarks, breakpoints, regions, functions, references, types,
                assignments, debug_variables, patch_spans;
    std::uint64_t patch_bytes;
};
HistoryStateCounts history_counts(const database::UserState &state) {
    std::uint64_t bytes = 0;
    for (const auto &patch : state.patches)
        bytes += static_cast<std::uint64_t>(patch.replacement.size());
    return {state.annotations.size(), state.bookmarks.size(), state.breakpoints.size(),
            state.decisions.regions.size(), state.decisions.functions.size(), state.decisions.references.size(),
            state.types.size(), state.type_assignments.size(), state.debug_variables.size(), state.patches.size(), bytes};
}
int run_history_save(const project_detail::Arguments &args, std::ostream &out) {
    using namespace project_detail;
    auto store = take(database::ProjectStore::open(args.path, database::ProjectMode::read_only, {}));
    const auto snapshot = take(store->snapshot());
    const auto expected = args.history_expected_edit.value_or(snapshot->revisions.edit);
    const auto policy = args.replace ? database::ReplacePolicy::replace_existing
                                     : database::ReplacePolicy::fail_if_exists;
    const auto saved = take(store->save_history_as(expected, args.history_target_step,
                                                  args.history_preview_limits, args.output, policy, {}));
    if (args.history_json) {
        out << "{\"schema_version\":1,\"source_uuid\":" << json_string(uuid_text(snapshot->uuid))
            << ",\"source_edit\":" << expected
            << ",\"target_step\":" << args.history_target_step
            << ",\"path\":" << json_string(path_utf8(saved.path))
            << ",\"project_uuid\":" << json_string(uuid_text(saved.uuid)) << "}\n";
    } else {
        out << "Saved historical project: " << escape(path_utf8(saved.path))
            << " uuid=" << uuid_text(saved.uuid) << " source-edit=" << expected
            << " step=" << args.history_target_step << " (source unchanged; undo/redo history retained)\n";
    }
    return 0;
}
int run_history_preview(const project_detail::Arguments &args, std::ostream &out) {
    using namespace project_detail;
    auto store = take(database::ProjectStore::open(args.path, database::ProjectMode::read_only, {}));
    auto snapshot = take(store->snapshot());
    auto preview = take(store->preview_history_at(snapshot->revisions.edit, args.history_target_step,
                                                  args.history_preview_limits, {}));
    require(bool(preview.user), "History preview returned no user state");
    const auto before = history_counts(*snapshot->user);
    const auto after = history_counts(*preview.user);
    if (args.history_json) {
        out << "{\"schema_version\":1,\"project_uuid\":\"" << uuid_text(snapshot->uuid)
            << "\",\"source_edit\":" << preview.source_revisions.edit
            << ",\"source_cursor\":" << preview.source_cursor
            << ",\"target_step\":" << preview.target_step
            << ",\"history_count\":" << preview.history_count
            << ",\"replayed_steps\":" << preview.replayed_steps
            << ",\"delta_bytes\":" << preview.delta_bytes
            << ",\"current\":{\"annotations\":" << before.annotations << ",\"bookmarks\":" << before.bookmarks
            << ",\"breakpoints\":" << before.breakpoints << ",\"regions\":" << before.regions
            << ",\"functions\":" << before.functions << ",\"references\":" << before.references
            << ",\"types\":" << before.types << ",\"assignments\":" << before.assignments
            << ",\"debug_variables\":" << before.debug_variables << ",\"patch_spans\":" << before.patch_spans
            << ",\"patch_bytes\":" << before.patch_bytes << "},\"preview\":{\"annotations\":" << after.annotations
            << ",\"bookmarks\":" << after.bookmarks << ",\"breakpoints\":" << after.breakpoints
            << ",\"regions\":" << after.regions << ",\"functions\":" << after.functions
            << ",\"references\":" << after.references << ",\"types\":" << after.types
            << ",\"assignments\":" << after.assignments << ",\"debug_variables\":" << after.debug_variables
            << ",\"patch_spans\":" << after.patch_spans << ",\"patch_bytes\":" << after.patch_bytes << "}}\n";
    } else {
        out << "History preview: project=" << uuid_text(snapshot->uuid)
            << " edit=" << preview.source_revisions.edit << " cursor=" << preview.source_cursor << '/' << preview.history_count
            << " target=" << preview.target_step << " replayed=" << preview.replayed_steps
            << " delta-bytes=" << preview.delta_bytes << '\n'
            << "Current: annotations=" << before.annotations << " bookmarks=" << before.bookmarks
            << " breakpoints=" << before.breakpoints << " regions=" << before.regions << " functions=" << before.functions
            << " references=" << before.references << " types=" << before.types << " assignments=" << before.assignments
            << " debug-variables=" << before.debug_variables << " patches=" << before.patch_spans << '/' << before.patch_bytes << "B\n"
            << "Preview: annotations=" << after.annotations << " bookmarks=" << after.bookmarks
            << " breakpoints=" << after.breakpoints << " regions=" << after.regions << " functions=" << after.functions
            << " references=" << after.references << " types=" << after.types << " assignments=" << after.assignments
            << " debug-variables=" << after.debug_variables << " patches=" << after.patch_spans << '/' << after.patch_bytes << "B\n";
    }
    return args.history_target_step == preview.source_cursor ? 0 : 3;
}
} // namespace

void project_usage(std::ostream &out) {
    out << "Usage: hexlab_cli project <action> <project.hxproj> [options]\n"
           "       hexlab_cli project history audit <project.hxproj> [--page-steps N] [--page-bytes N]\n"
           "           [--max-pages N] [--total-bytes N] [--expected-edit N --after-step N] [--verify-replay] [--json]\n"
           "       hexlab_cli project history preview <project.hxproj> --step N [--max-steps N] [--max-bytes N] [--json]\n"
           "       hexlab_cli project history save <project.hxproj> --step N --output <copy.hxproj>\n"
           "           [--expected-edit N] [--max-steps N] [--max-bytes N] [--replace] [--json]\n"
           "       hexlab_cli project recovery list <directory> [--json]\n"
           "       hexlab_cli project recovery restore <artifact.tmp> --output <project.hxproj> [--replace]\n"
           "       hexlab_cli project backup <project.hxproj> --output <backup.hxproj> [--replace]\n"
           "       hexlab_cli project backup restore <backup.hxproj> --output <new-project.hxproj> [--replace]\n"
           "       hexlab_cli project backup list <project.hxproj> --base <backup-name.hxproj> [--json]\n"
           "       hexlab_cli project backup rotate <project.hxproj> --base <backup-name.hxproj> [--retain N]\n"
           "       hexlab_cli project backup prune <project.hxproj> --base <backup-name.hxproj> [--retain N]\n"
           "       hexlab_cli project backup restore-in-place <backup.hxproj> --target <existing-project.hxproj>\n"
           "       hexlab_cli project exchange import <project> --input <file> [--conflict fail|skip|replace] [--dry-run] [--json]\n"
           "Actions: create inspect rename comment bookmark define undefine reference patch undo redo\n"
           "         save save-as export functions references switches stack graph search signatures signature-apply signature-create flirt flirt-apply fingerprints fingerprint-create recognition-evidence methods managed-types fields\n"
           "         exchange export|import <project> --output/--input <file> [--conflict fail|skip|replace]\n"
           "         types export|import <project> --output/--input <file> [--replace] [--replace-assignments] [--skip-assignments-on-mismatch]\n"
           "history audit: read-only paginated integrity check; --verify-replay also reverses the applied branch to empty state (max 4096 steps/64 MiB); JSON emits one summary; exit 3 means resume available\n"
           "history preview: read-only bounded replay to an exact step; reports current and preview record counts without changing the project; exit 3 means target differs from current cursor\n"
           "history save: publishes an independent project at an exact step with full undo/redo history; source stays unchanged\n"
           "recovery list: read-only scan for fully validated interrupted saves and retained previous versions\n"
           "recovery restore: revalidates an artifact and publishes an independent project copy; source artifact stays intact\n"
           "backup project: writes a consistent read-only SQLite snapshot while preserving project UUID and history\n"
           "backup restore: validates the backup and creates an independent project with a new UUID; the backup is retained\n"
           "backup rotate/prune: only same-UUID, validated generated siblings are pruned; incomplete bounded scans preserve files and return exit 3\n"
           "backup restore-in-place: requires a same-UUID backup and closed target connections; target retains its UUID and must be reopened\n"
           "exchange import --dry-run: read-only plan with bounded row-level conflict output; --json emits a machine-readable report\n"
           "create: --input <binary> [--format auto|pe|elf|raw|macho|wasm|ihex|srec] [--replace]\n"
           "        ihex/srec preserve firmware text and sparse data; CPU analysis and VA patches are unavailable\n"
           "        --slice <index> selects a Mach-O universal slice (auto or macho only)\n"
           "        PE: --pdb <file> selects a local PDB; --pdb-search <directory> adds a local search directory\n"
           "        ELF: --dwarf-supplementary-package <file> selects an explicit DWARF v5 supplementary DWP\n"
           "        raw requires --arch x86-32|x86-64|a64|6502|rv32|rv64|mips64|ppc32le|ppc32be|ppc64le|ppc64be --base <address> [--entry <address>]\n"
           "        or --profile <file> for segmented x86-16/32 (replaces arch/base/entry)\n"
           "        or --arm-profile <file> for ARM/Thumb/data declarations\n"
           "rename/comment/bookmark: --at <location> --name/--text/--label <text>\n"
           "bookmark/reference: --remove deletes the matching record\n"
           "patch: --at <location> --bytes <hex octets>\n"
           "define: --at va:<address> --kind code|data --size <bytes>\n"
           "        --kind function|suppress|unsuppress\n"
           "        --kind chunks --chunks va:<address>+<size>[,va:<address>+<size>...]\n"
           "undefine: --at va:<function-entry> --kind function resets the explicit function override and resumes automatic recovery\n"
           "reference: --at <location> --to <location> --kind code|data|call|jump|read|write|address\n"
           "save-as/export: --output <project/binary> [--replace]\n"
           "references: --at <location> [--direction incoming|outgoing] [--size N for ranges] [--mapped for file ranges] [--offset N] [--limit N]\n"
           "switches: --at va:<function-entry>; bounded x86 absolute-pointer and x64 RIP-relative-base tables\n"
           "stack: --at va:<function-entry>; conservative stack-relative local/argument slots\n"
           "graph: --kind cfg --at va:<entry> | --kind call | --kind function-calls --at va:<function-address> [--depth 1..4]\n"
           "       [--format json|dot] [--node-budget N] [--edge-budget N]; output goes to stdout\n"
           "       call is image-wide; function-calls emits the selected function's bounded caller/callee neighborhood\n"
           "search: --kind bytes --pattern <two-character hex octets; ? masks a nibble, e.g. 48 8B ?? A? ?F>\n"
           "        --kind text --text <literal> --encoding ascii|utf8|utf16le|utf16be|utf32le|utf32be\n"
           "        --kind immediate --value <integer> --width 8|16|32|64 [--signed|--unsigned]\n"
           "        [--limit N] [--candidate-budget N] [--cursor <continuation>]\n"
           "signatures: --definitions <file> [--function-entries] [--limit N] [--candidate-budget N] [--comparison-budget N]\n"
           "signature-apply: --definitions <file> [--limit N] [--candidate-budget N] [--comparison-budget N]\n"
           "signature-create: --at va:<entry> --name <name> --provenance <source> [--max-bytes N] [--min-exact-bytes N]\n"
           "flirt: --definitions <file.pat|file.pat.gz|file.sig> OR --definitions-list <utf8-path-list>; --provenance <source> [--catalog-byte-budget N] [--pattern-budget N]\n"
           "       [--function-budget N] [--candidate-budget N] [--comparison-budget N] [--reference-budget N] [--result-budget N]\n"
           "flirt-apply: same options; persist source-bound candidate evidence; [--rename-unique] applies only unique public names\n"
           "fingerprints: --definitions <file> [--function-budget N] [--instruction-budget N] [--token-budget N]\n"
           "fingerprint-create: --at va:<entry> --name <name> --provenance <source> [--max-instructions N] [--max-blocks N]\n"
           "recognition-evidence: --kind signatures|fingerprints|flirt; reads source-current persisted candidates and ambiguity\n"
           "        file lines: name|provenance|byte pattern|excluded pattern[;excluded pattern...]\n"
           "Locations: va:<address>, va:<space>:<address>, file:<offset>; decimal or 0x hex.\n"
           "           seg:<selector>:<offset> uses hexadecimal and a declared profile.\n"
           "Text arguments are Unicode; output escapes control and nonASCII bytes.\n"
           "Queries open read-only. Edits accept --readonly to request mutation refusal.\n"
           "Analysis: --instruction-budget N --string-budget N.\n"
           "Exit: 0 success, 1 IO/unsupported/read-only/conflict, 2 invalid arguments,\n"
           "      3 partial analysis or another result page available.\n";
}
int run_project_cli(std::span<const std::wstring_view> arguments, std::ostream &out, std::ostream &err) {
    using namespace project_detail;
    if (arguments.empty() || (arguments.size() == 1 && arguments[0] == L"--help")) {
        project_usage(out);
        return 0;
    }
    try {
        auto args = parse(arguments);
        if (args.action == L"history-audit")
            return run_history_audit(args, out, err);
        if (args.action == L"history-preview")
            return run_history_preview(args, out);
        if (args.action == L"history-save")
            return run_history_save(args, out);
        if (args.action == L"recovery-list")
            return run_recovery_list(args, out);
        if (args.action == L"recovery-restore")
            return run_recovery_restore(args, out);
        if (args.action == L"backup")
            return run_project_backup(args, out);
        if (args.action == L"backup-restore")
            return run_project_backup_restore(args, out);
        if (args.action == L"backup-list") return run_project_backup_list(args, out);
        if (args.action == L"backup-rotate") return run_project_backup_rotate(args, out);
        if (args.action == L"backup-prune") return run_project_backup_prune(args, out);
        if (args.action == L"backup-restore-in-place") return run_project_backup_restore_in_place(args, out);
        auto pool = std::make_shared<AnalysisPool>();
        auto actor = take(ProjectActor::create({{1}, 1}, pool));
        struct Close {
            std::shared_ptr<ProjectActor> actor;
            ~Close() {
                auto closing = actor->close();
                if (closing)
                    closing.value().result.wait();
            }
        } close{actor};
        auto reply = [&](Result<ProjectSubmission> submitted) {
            auto operation = take(std::move(submitted));
            return take(operation.result.get());
        };
        if (args.action == L"create") {
            reply(actor->import_binary(args.input));
            auto saved = reply(actor->save_as(args.path, args.replace ? database::ReplacePolicy::replace_existing
                                                                      : database::ReplacePolicy::fail_if_exists));
            if (saved.saved) {
                auto path = saved.saved->path.u8string();
                out << "Saved: " << std::string(reinterpret_cast<const char *>(path.data()), path.size()) << '\n';
            }
            if (!saved.adopted) {
                err << "Saved copy remains available; adoption failed: " << saved.adoption_error->message << '\n';
                return 1;
            }
            return 0;
        }
        bool query = args.action == L"exchange-export" || args.action == L"types-export" ||
                     (args.action == L"exchange-import" && args.exchange_dry_run) ||
                     args.action == L"inspect" || args.action == L"functions" || args.action == L"methods" || args.action == L"managed-types" || args.action == L"fields" || args.action == L"references" || args.action == L"stack" ||
                     args.action == L"switches" ||
                     args.action == L"graph" || args.action == L"search" || args.action == L"recognition-evidence" || (args.action == L"signatures" && !args.signature_function_entries) ||
                     args.action == L"signature-create" || args.action == L"flirt" ||
                     args.action == L"fingerprints" || args.action == L"fingerprint-create";
        auto opened = reply(actor->open_project(
            args.path, query || args.readonly ? database::ProjectMode::read_only : database::ProjectMode::read_write,
            args.analysis));
        if (args.action == L"exchange-export") {
            auto current = reply(actor->ready());
            auto written = take(write_exchange_file(*current.snapshot, args.output, args.replace));
            out << "Exported exchange: " << current.snapshot->state->user->annotations.size() << " annotations, "
                << current.snapshot->state->user->bookmarks.size() << " bookmarks, "
                << current.snapshot->state->user->decisions.references.size() << " references, "
                << current.snapshot->state->user->types.size() << " types, "
                << current.snapshot->state->user->type_assignments.size() << " type assignments, "
                << current.snapshot->state->user->debug_variables.size() << " debug variables\n";
            return written ? 0 : 1;
        }
        if (args.action == L"types-export") {
            auto current = reply(actor->ready());
            auto written = take(write_type_library_file(*current.snapshot, args.output, args.replace));
            out << "Exported type library: " << current.snapshot->state->user->types.size() << " definitions\n";
            return written ? 0 : 1;
        }
        if (args.action == L"types-import") {
            auto bundle = take(read_type_library_file(args.type_library_input));
            auto current = reply(actor->ready());
            bool compatible = false;
            if (bundle.source_identity) {
                auto recipe = take(encode_recipe(current.snapshot->state->recipe));
                Sha256 hash; take(hash.update(recipe));
                const auto &source = *bundle.source_identity;
                compatible = source.input_size == current.snapshot->state->input.size &&
                    source.input_sha256 == current.snapshot->state->input.sha256 &&
                    source.recipe_sha256 == hash.digest();
            }
            require(bundle.assignments.empty() || compatible || args.type_skip_assignments_on_mismatch,
                    "Type library source identity does not match this project; use --skip-assignments-on-mismatch to import definitions only");
            std::set<std::string, std::less<>> available;
            for (const auto &row : current.snapshot->state->user->types) available.insert(row.name);
            for (const auto &entry : bundle.entries) available.insert(entry.name);
            take(types::validate_library_references(bundle, available));
            ImportPortableTypes command;
            for (auto &entry : bundle.entries) {
                auto found = std::find_if(current.snapshot->state->user->types.begin(), current.snapshot->state->user->types.end(),
                                          [&](const auto &row) { return row.name == entry.name; });
                const auto existing = found == current.snapshot->state->user->types.end() ? std::optional<std::uint64_t>{}
                                                                                           : std::optional<std::uint64_t>{found->id};
                const auto declaration_kind = static_cast<database::DeclarationKind>(entry.declaration_kind);
                std::optional<database::DwarfSourceOrigin> origin;
                if (entry.origin) origin = database::DwarfSourceOrigin{entry.origin->source_id, entry.origin->section,
                    entry.origin->unit_offset, entry.origin->record_offset, entry.origin->record_size};
                command.definitions.push_back({std::move(entry.name), std::move(entry.type), existing, std::move(origin), declaration_kind});
            }
            if (compatible) {
                for (const auto &assignment : bundle.assignments) {
                    const auto target = std::find_if(current.snapshot->state->user->types.begin(), current.snapshot->state->user->types.end(),
                        [&](const auto &row) { return row.name == assignment.type_name; });
                    require(target != current.snapshot->state->user->types.end() || available.contains(assignment.type_name),
                            "Type assignment refers to missing definition " + assignment.type_name);
                    auto existing = std::find_if(current.snapshot->state->user->type_assignments.begin(), current.snapshot->state->user->type_assignments.end(),
                        [&](const auto &row) { return row.location == assignment.location; });
                    if (existing != current.snapshot->state->user->type_assignments.end()) {
                        auto old_type = std::find_if(current.snapshot->state->user->types.begin(), current.snapshot->state->user->types.end(),
                            [&](const auto &row) { return row.id == existing->type_id; });
                        const std::string old_name = old_type == current.snapshot->state->user->types.end() ? std::string{} : old_type->name;
                        require(old_name == assignment.type_name || args.type_replace_assignments,
                                "Type assignment conflict at " + location(assignment.location) + "; use --replace-assignments to replace it");
                    }
                    command.assignments.push_back({assignment.location, assignment.type_name});
                }
            }
            const auto definition_count = command.definitions.size(), assignment_count = command.assignments.size();
            if (definition_count || assignment_count)
                reply(actor->execute(ImportPortableTypes{std::move(command.definitions), std::move(command.assignments)}, 0));
            out << "Imported type library: " << definition_count << " definitions, " << assignment_count << " assignments\n";
            return 0;
        }
        if (args.action == L"exchange-import") {
            auto bytes = take(read_exchange_file(args.exchange_input));
            auto current = reply(actor->ready());
            const bool would_fail = args.exchange_dry_run && args.exchange_conflicts == ExchangeConflictPolicy::fail;
            // The fail policy normally stops at its first collision. A dry run
            // instead uses skip planning so it can report the complete conflict
            // set while still telling callers that the selected policy rejects it.
            const auto planning_policy = would_fail ? ExchangeConflictPolicy::skip : args.exchange_conflicts;
            auto plan = take(import_project_exchange(*current.snapshot, bytes, planning_policy));
            if (args.exchange_dry_run) {
                print_exchange_import_report(out, plan, args.exchange_json, false,
                                             would_fail && !plan.conflicts.empty());
                return 0;
            }
            if (!plan.commands.empty()) reply(actor->execute_batch(std::move(plan.commands)));
            print_exchange_import_report(out, plan, args.exchange_json, true, false);
            return 0;
        }
        if (args.action == L"inspect") {
            print_inspection(out, *opened.snapshot);
            return 0;
        }
        if (args.action == L"save-as") {
            auto saved = reply(actor->save_as(args.output, args.replace ? database::ReplacePolicy::replace_existing
                                                                        : database::ReplacePolicy::fail_if_exists));
            if (saved.saved) {
                auto path = saved.saved->path.u8string();
                out << "Saved: " << std::string(reinterpret_cast<const char *>(path.data()), path.size()) << '\n';
            }
            if (!saved.adopted) {
                err << "Saved copy remains available; adoption failed: " << saved.adoption_error->message << '\n';
                return 1;
            }
            return 0;
        }
        if (args.action == L"export") {
            auto receipt =
                reply(actor->export_binary(args.output, args.replace ? database::ReplacePolicy::replace_existing
                                                                     : database::ReplacePolicy::fail_if_exists));
            out << "Exported: " << receipt.exported->bytes << " bytes SHA256=" << digest_hex(receipt.exported->sha256)
                << "\nInput signatures and checksums are not repaired.\n";
            return 0;
        }
        if (args.action == L"save") {
            auto saved = reply(actor->save());
            out << "Edit revision: " << saved.snapshot->state->revisions.edit << '\n';
            return 0;
        }
        auto current = reply(actor->ready());
        if (args.at_expression)
            args.at = take(resolve_location(*current.snapshot, *args.at_expression));
        if (args.action == L"recognition-evidence") {
            auto evidence_reply = reply(actor->read_function_recognition(args.recognition_kind));
            require(bool(evidence_reply.recognition_cache), "Recognition evidence lookup returned no cache status");
            const auto &cache = *evidence_reply.recognition_cache;
            const auto status = cache.status == database::CacheStatus::hit ? "hit" :
                                cache.status == database::CacheStatus::absent ? "absent" :
                                cache.status == database::CacheStatus::stale ? "stale" :
                                cache.status == database::CacheStatus::incompatible ? "incompatible" : "corrupt";
            out << "Recognition evidence: kind="
                << (args.recognition_kind == FunctionRecognitionKind::byte_signatures ? "signatures" :
                    args.recognition_kind == FunctionRecognitionKind::normalized_fingerprints ? "fingerprints" : "flirt")
                << " status=" << status;
            if (!cache.reason.empty()) out << " reason=" << escape(cache.reason);
            out << '\n';
            if (cache.status != database::CacheStatus::hit || !cache.evidence) return 3;
            const auto &evidence = *cache.evidence;
            out << "Source: input=" << evidence.source_key.input.size << ":" << digest_hex(evidence.source_key.input.sha256)
                << " byte-revision=" << evidence.source_key.byte_revision
                << " decision-revision=" << evidence.source_key.decision_revision
                << " catalog-sha256=" << digest_hex(evidence.catalog_digest)
                << " complete=" << (evidence.complete ? "true" : "false") << '\n';
            for (const auto &function : evidence.functions) {
                out << "Function evidence: " << location(function.entry)
                    << " ambiguous=" << (function.ambiguous ? "true" : "false")
                    << " candidates=" << function.candidates.size() << '\n';
                for (const auto &candidate : function.candidates) {
                    out << "  Candidate: " << escape(candidate.name) << " provenance=" << escape(candidate.provenance)
                        << " constrained-bits=" << candidate.constrained_bits
                        << " pattern-bytes=" << candidate.pattern_bytes
                        << " instructions=" << candidate.instruction_count;
                    if (args.recognition_kind == FunctionRecognitionKind::flirt_patterns)
                        out << " symbol-kind="
                            << (candidate.symbol_kind == static_cast<std::uint8_t>(FlirtSymbolKind::local_name) ? "local" : "public")
                            << " matching-patterns=" << candidate.matching_patterns;
                    if (std::any_of(candidate.digest.begin(), candidate.digest.end(), [](std::byte byte) { return byte != std::byte{}; }))
                        out << " digest=" << digest_hex(candidate.digest);
                    out << '\n';
                }
            }
            return evidence.complete ? 0 : 3;
        }
        if (args.action == L"flirt-apply")
            return print_derived(out, args, *current.snapshot, *actor);
        if (args.action == L"signature-apply") {
            const auto &snapshot = *current.snapshot;
            require(bool(snapshot.loaded) && bool(snapshot.functions),
                    "Signature application requires a loaded image and recovered function facts");
            std::error_code ec;
            const auto size = std::filesystem::file_size(args.signature_definitions, ec);
            require(!ec && size <= 1024 * 1024, "Cannot read signature definitions or file exceeds 1 MiB");
            std::ifstream input(args.signature_definitions, std::ios::binary);
            require(bool(input), "Cannot open signature definitions");
            std::string text(static_cast<std::size_t>(size), '\0');
            require(!size || bool(input.read(text.data(), static_cast<std::streamsize>(size))), "Cannot read signature definitions");
            const auto catalog = take(parse_signature_catalog(text));
            const auto recognized = take(recognize_function_signatures(*snapshot.loaded->image, *snapshot.effective,
                *snapshot.functions, catalog, args.signature_limits));
            require(recognized.complete, "Signature recognition is incomplete; no changes were applied");
            const auto canonical=take(serialize_signature_catalog(catalog));Sha256 catalog_hash;
            take(catalog_hash.update(std::span(reinterpret_cast<const std::byte*>(canonical.data()),canonical.size())));
            auto evidence=take(make_function_recognition_evidence(*snapshot.functions,catalog_hash.digest(),recognized));
            auto evidence_write=take(actor->persist_function_recognition(std::move(evidence)));take(evidence_write.result.get());

            std::map<std::pair<std::uint32_t, std::string>, std::size_t> name_counts;
            for (const auto &function : recognized.functions)
                if (!function.ambiguous && function.candidates.size() == 1)
                    ++name_counts[{function.entry.space.value, function.candidates.front().name}];
            std::set<std::pair<std::uint32_t, std::string>> existing_names;
            for (const auto &annotation : snapshot.state->user->annotations)
                if (const auto address = std::get_if<Address>(&annotation.location); address && !annotation.name.empty())
                    existing_names.emplace(address->space.value, annotation.name);
            std::vector<ProjectCommand> batch;
            std::size_t ambiguous = 0, collisions = 0, named = 0, applied = 0;
            for (const auto &function : recognized.functions) {
                if (function.ambiguous || function.candidates.size() != 1) { ++ambiguous; continue; }
                const auto &match = function.candidates.front();
                if (name_counts[{function.entry.space.value, match.name}] > 1) { ++collisions; continue; }
                const auto annotation = std::find_if(snapshot.state->user->annotations.begin(),
                    snapshot.state->user->annotations.end(), [&](const auto &row) { return row.location == Location{function.entry}; });
                const bool has_name = annotation != snapshot.state->user->annotations.end() && !annotation->name.empty();
                if (has_name) { ++named; continue; }
                if (existing_names.contains({function.entry.space.value, match.name})) { ++collisions; continue; }
                const std::string marker = "signature provenance: " + match.provenance + " (" + match.name + ")";
                const std::string prior = annotation == snapshot.state->user->annotations.end() ? std::string{} : annotation->comment;
                if (prior.find(marker) == std::string::npos) {
                    const auto comment = prior.empty() ? marker : prior + "\n" + marker;
                    batch.emplace_back(Comment{Location{function.entry}, comment});
                }
                batch.emplace_back(Rename{Location{function.entry}, match.name});
                ++applied;
            }
            if (!batch.empty()) {
                auto edited = reply(actor->execute_batch(std::move(batch)));
                out << "Edit revision: " << edited.snapshot->state->revisions.edit << '\n';
            } else {
                out << "Edit revision: " << snapshot.state->revisions.edit << " (unchanged)\n";
            }
            out << "Signature application: " << applied << " applied, " << ambiguous << " ambiguous, "
                << collisions << " name collisions, " << named << " already named; "
                << recognized.functions.size() << " function entries recognized\n";
            return 0;
        }
        if (query)
            return print_derived(out, args, *current.snapshot,*actor);
        auto edited = args.command             ? reply(actor->execute(take(args.command(*current.snapshot))))
                      : args.action == L"undo" ? reply(actor->undo())
                                               : reply(actor->redo());
        out << "Edit revision: " << edited.snapshot->state->revisions.edit << '\n';
        return 0;
    } catch (const Failure &failure) {
        if (failure.error.code == ErrorCode::conflict)
            err << "Project conflict: ";
        else if (failure.error.code == ErrorCode::read_only)
            err << "Read-only project: ";
        else
            err << "Project: ";
        err << escape(failure.error.message) << '\n';
        return failure.error.code == ErrorCode::invalid_argument ? 2 : 1;
    } catch (const std::exception &error) {
        err << "Project: " << error.what() << '\n';
        return 1;
    }
}
} // namespace hexlab::cli
