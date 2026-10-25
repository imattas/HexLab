#pragma once
#include "hexlab/workspace/project_actor.hpp"
#include "hexlab/workspace/project_exchange.hpp"
#include "hexlab/workspace/search.hpp"
#include "hexlab/analysis/graph.hpp"
#include "hexlab/analysis/signatures.hpp"
#include "hexlab/analysis/flirt.hpp"
#include <map>
#include <span>
#include <string_view>
#include <functional>
namespace hexlab::cli::project_detail {
struct Failure {
    Error error;
};
template <class T> T take(Result<T> result) {
    if (!result)
        throw Failure{result.error()};
    return std::move(result.value());
}
inline void require(bool value, std::string reason) {
    if (!value)
        throw Failure{{ErrorCode::invalid_argument, std::move(reason)}};
}
using LocationExpression = std::variant<Location, X86LogicalAddress>;
using CommandFactory = std::function<Result<ProjectCommand>(const ProjectSnapshot &)>;
struct Arguments {
    std::wstring action;
    std::filesystem::path path, output, exchange_input, type_library_input;
    ExchangeConflictPolicy exchange_conflicts = ExchangeConflictPolicy::fail;
    bool readonly = false, replace = false;
    bool type_skip_assignments_on_mismatch = false, type_replace_assignments = false;
    bool exchange_dry_run = false, exchange_json = false;
    OpenRequest input;
    AnalysisOptions analysis;
    CommandFactory command;
    std::optional<LocationExpression> at_expression;
    std::optional<Location> at;
    bool incoming = false;
    bool reference_mapped_range = false;
    std::optional<std::uint64_t> reference_range_size;
    PageRequest page;
    GraphKind graph_kind = GraphKind::function_cfg;
    GraphOptions graph_options;
    bool dot = false;
    std::optional<SearchQuery> query;
    SearchLimits search_limits;
    std::filesystem::path signature_definitions;
    SignatureLimits signature_limits;
    bool signature_function_entries = false;
    FunctionRecognitionKind recognition_kind = FunctionRecognitionKind::byte_signatures;
    std::string signature_name, signature_provenance;
    FunctionSignatureOptions function_signature_options;
    std::filesystem::path fingerprint_definitions;
    FunctionFingerprintLimits fingerprint_limits;
    FunctionFingerprintOptions fingerprint_options;
    std::filesystem::path flirt_definitions, flirt_definitions_list;
    std::string flirt_provenance;
    bool flirt_rename_unique = false;
    FlirtCatalogLimits flirt_catalog_limits;
    FlirtRecognitionLimits flirt_limits;
    std::optional<SearchCursor> cursor;
    database::HistoryAuditLimits history_audit_limits;
    std::optional<std::uint64_t> history_expected_edit;
    std::uint64_t history_after_step = 0;
    std::size_t history_max_pages = 4096;
    std::size_t history_total_delta_bytes = 512 * 1024 * 1024;
    bool history_json = false;
    bool history_verify_replay = false;
    bool recovery_json = false;
    std::uint64_t history_target_step = 0;
    database::HistoryPreviewLimits history_preview_limits;
};
Arguments parse(std::span<const std::wstring_view>);
Result<Location> resolve_location(const ProjectSnapshot &, const LocationExpression &);
std::string utf8(std::wstring_view);
std::string escape(std::string_view);
std::string hex(std::uint64_t);
std::string location(Location);
std::string cursor_text(const SearchCursor &);
SearchCursor parse_cursor(std::wstring_view);
void print_inspection(std::ostream &, const ProjectSnapshot &);
int print_derived(std::ostream &, const Arguments &, const ProjectSnapshot &,ProjectActor&);
} // namespace hexlab::cli::project_detail
