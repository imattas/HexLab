#include "hexlab/workspace/project_analysis.hpp"
#include "hexlab/analysis/derived_cache.hpp"
#include "project_internal.hpp"
namespace hexlab {
Result<AnalysisKey> project_analysis_key(const ProjectSnapshot &snapshot, const AnalysisOptions &options) {
    return project_detail::guarded([&]() -> Result<AnalysisKey> {
        using namespace project_detail;
        require(bool(snapshot.state), "No project source is available");
        AnalysisKey key{snapshot.state->input,
                        snapshot.state->revisions.bytes,
                        snapshot.state->revisions.decisions,
                        {},
                        function_engine_fingerprint(options)};
        auto recipe = take(encode_recipe(snapshot.state->recipe));
        Sha256 hash;
        take(hash.update(recipe));
        key.recipe_fingerprint = hash.digest();
        return key;
    });
}
Result<ProjectAnalysis> compute_project_analysis(const ProjectAnalysisRequest &request, std::stop_token stop) {
    return project_detail::guarded([&]() -> Result<ProjectAnalysis> {
        using namespace project_detail;
        canceled(stop);
        require(request.snapshot && request.snapshot->loaded && request.snapshot->effective,
                "Analysis request requires a mapped immutable project snapshot");
        const auto &snapshot = *request.snapshot;
        require(take(project_analysis_key(snapshot, request.options)) == request.key,
                "Analysis request key differs from its immutable source", ErrorCode::conflict);
        ProjectAnalysis output;
        output.source_key = request.key;
        output.cache_status = request.cache.status;
        output.cache_reason = request.cache.reason;
        auto metadata = std::shared_ptr<const ImageMetadata>(snapshot.loaded, &snapshot.loaded->metadata);
        bool from_cache = false;
        auto derived = [&]() -> Result<DerivedProposal> {
            if (snapshot.loaded->metadata.firmware)
                return Error{ErrorCode::unsupported,
                    "Firmware records do not identify a processor mode; instruction analysis is unavailable"};
            if (!request.force_full && !snapshot.basis && request.cache.status == database::CacheStatus::hit &&
                request.cache.payload) {
                auto cached = decode_derived(*request.cache.payload, *snapshot.loaded->image, *metadata,
                                             snapshot.state->user->decisions, request.options, request.key, stop);
                if (cached) {
                    from_cache = true;
                    return cached;
                }
                if (cached.error().code == ErrorCode::canceled)
                    return cached.error();
                output.cache_status = cached.error().code == ErrorCode::unsupported
                                          ? database::CacheStatus::incompatible
                                          : database::CacheStatus::corrupt;
                output.cache_reason = "Derived cache recompute required: " + cached.error().message;
            }
            if (!request.force_full && snapshot.basis &&
                snapshot.basis->key.engine_fingerprint == request.key.engine_fingerprint) {
                auto changes = effective_changes(*snapshot.basis->image->storage(), *snapshot.effective,
                                                 snapshot.pending_byte_ranges, stop);
                auto plan = take(plan_invalidation(*snapshot.basis, changes.ranges(), snapshot.state->user->decisions,
                                                   request.key, stop, true, true));
                return reanalyze(*snapshot.basis, snapshot.loaded->image, metadata, snapshot.state->user->decisions,
                                 plan, request.key, stop);
            }
            return analyze_derived(snapshot.loaded->image, metadata, snapshot.state->user->decisions, request.options,
                                   request.key, stop);
        }();
        if (!derived) {
            if (derived.error().code != ErrorCode::unsupported)
                throw Failure{derived.error()};
            output.supported = false;
            output.reason = derived.error().message;
            output.derived.source_key = request.key;
            take(bind_derived_source(output.derived, *snapshot.loaded->image, stop));
            output.derived.strings =
                std::make_shared<const StringScan>(take(find_strings(*snapshot.loaded->image, request.options, stop)));
            output.derived.full_reason = output.reason;
        } else {
            output.derived = std::move(derived.value());
            if (!from_cache && request.encode_cache && snapshot.mode == database::ProjectMode::read_write) {
                auto encoded =
                    encode_derived(output.derived, stop, output.derived.counters.cache_serialization_decodes,
                                   request.options);
                if (encoded)
                    output.encoded_cache = std::make_shared<const std::vector<std::byte>>(std::move(encoded.value()));
                else {
                    if (encoded.error().code == ErrorCode::canceled)
                        return encoded.error();
                    output.cache_reason = "Optional derived cache encoding skipped: " + encoded.error().message;
                }
            }
        }
        if (snapshot.basis && snapshot.basis->key != request.key && output.cache_status == database::CacheStatus::hit)
            output.cache_status = database::CacheStatus::stale;
        canceled(stop);
        return output;
    });
}
} // namespace hexlab
namespace hexlab::project_detail {
std::shared_ptr<const ProjectSnapshot> adopt_project_analysis(const ProjectSnapshot &latest,
                                                              const ProjectAnalysis &analysis,
                                                              const AnalysisOptions &options, std::stop_token stop) {
    canceled(stop);
    auto key = take(project_analysis_key(latest, options));
    require(key == analysis.source_key && key == analysis.derived.source_key,
            "Worker proposal belongs to an earlier project source", ErrorCode::conflict);
    require(bool(latest.loaded), "Worker proposal cannot restore a file-only mapping", ErrorCode::conflict);
    take(validate_derived_source(analysis.derived, *latest.loaded->image, stop));
    require(bool(analysis.derived.strings), "Worker proposal omitted its string scan");
    if (analysis.supported)
        require(analysis.derived.functions && analysis.derived.references && analysis.derived.functions->key == key &&
                    analysis.derived.references->key() == key,
                "Worker proposal contains inconsistent source keys", ErrorCode::conflict);
    auto next = std::make_shared<ProjectSnapshot>(latest);
    next->derived_key = key;
    next->functions = analysis.derived.functions;
    next->references = analysis.derived.references;
    next->strings = analysis.derived.strings;
    next->stack_frames = analysis.derived.stack_frames;
    next->last_reanalysis = analysis.derived.counters;
    next->reanalysis_reason = analysis.derived.full_reason;
    next->string_rescan_reason = analysis.derived.string_reason;
    next->derived_cache_status = analysis.cache_status;
    next->derived_cache_reason = analysis.cache_reason;
    if (analysis.supported) {
        auto basis = std::make_shared<AnalysisBasis>();
        basis->image = latest.loaded->image;
        basis->metadata = std::shared_ptr<const ImageMetadata>(latest.loaded, &latest.loaded->metadata);
        basis->metadata_reads = latest.loaded->metadata_reads;
        basis->loader_metadata_complete = latest.loaded->metadata_complete;
        basis->decisions = latest.state->user->decisions;
        basis->options = options;
        basis->key = key;
        basis->functions = next->functions;
        basis->references = next->references;
        basis->strings = next->strings;
        basis->stack_frames = next->stack_frames;
        if (latest.basis && latest.basis->functions == next->functions)
            basis->dependency_index_cache = latest.basis->dependency_index_cache;
        if (!basis->dependency_index_cache)
            basis->dependency_index_cache = std::make_shared<DependencyIndexCache>();
        next->basis = std::move(basis);
        bool complete = analysis.derived.complete && latest.loaded->metadata_complete;
        next->status = complete ? DerivedStatus::fresh : DerivedStatus::incomplete;
        next->reason = complete ? "" : "Analysis contains incomplete or unresolved facts";
    } else {
        next->basis.reset();
        next->status = DerivedStatus::incomplete;
        next->reason = analysis.reason;
    }
    next->pending_byte_ranges = {};
    canceled(stop);
    return next;
}
} // namespace hexlab::project_detail
