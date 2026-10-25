#include "hexlab/workspace/project_analysis.hpp"
#include "hexlab/database/cache.hpp"
#include "support/checks.hpp"
#include "support/fixture_files.hpp"
#include "support/analysis_fixture.hpp"
#include <chrono>
#include <future>
using namespace hexlab;
using namespace hexlab::database;
using namespace hexlab_test;
using namespace std::chrono_literals;
namespace {
struct Fixture {
    FixtureFile marker{std::span<const std::byte>{}};
    std::filesystem::path path = marker.path.wstring() + L".hxproj";
    std::shared_ptr<ProjectStore> store;
    Fixture() {
        store = ProjectStore::create(path, {}).value();
        MemoryStorage input(bytes({0x90, 0xc3}));
        LoadRecipe recipe{
            Format::raw, RawOptions{Architecture::x86_64, ExecutionMode::x86_64, {{0}, 0x1000}, true, false, true, {}}};
        check(bool(store->import_input(input, recipe, {}, {})), "deferred analysis fixture imports");
    }
    ~Fixture() {
        store.reset();
        std::error_code ignored;
        std::filesystem::remove(path, ignored);
        for (auto suffix : {L"-wal", L"-shm"}) {
            auto side = path;
            side += suffix;
            std::filesystem::remove(side, ignored);
        }
    }
};
struct ReleasePromise {
    std::promise<bool> &promise;
    bool released = false;
    void release() {
        if (!released) {
            released = true;
            promise.set_value(true);
        }
    }
    ~ReleasePromise() {
        if (!released)
            try {
                release();
            } catch (...) {
            }
    }
};
void proposal_tests() {
    Fixture f;
    auto session = ProjectSession::attach_deferred(f.store, {}, {}).value();
    auto pending = session->snapshot();
    check(pending->loaded && pending->status == DerivedStatus::pending && !pending->functions && !pending->basis,
          "deferred session publishes mapping without running analysis or codec");
    auto key = project_analysis_key(*pending, {}).value();
    auto raw = f.store->read_derived_cache(key, {}).value();
    check(raw.status == CacheStatus::absent, "writer reads only optional cache bytes before worker starts");
    ProjectAnalysisRequest request;
    request.snapshot = pending;
    request.key = key;
    request.cache = raw;
    std::promise<bool> entered, release;
    auto started = entered.get_future();
    auto continue_work = release.get_future().share();
    auto work = std::async(std::launch::async, [request, &entered, continue_work]() -> Result<ProjectAnalysis> {
        entered.set_value(true);
        continue_work.wait();
        return compute_project_analysis(request, {});
    });
    ReleasePromise unblock{release};
    check(started.wait_for(3s) == std::future_status::ready, "worker captures immutable pending source before edit");
    auto renamed = session->execute(Rename{Address{{0}, 0x1000}, "latest_name"}, 0, {}).value();
    unblock.release();
    if (work.wait_for(3s) != std::future_status::ready)
        throw std::runtime_error("Pure analysis worker did not finish");
    auto analysis = work.get().value();
    auto adopted = session->adopt_analysis(analysis, {}).value();
    check(adopted->state == renamed->state && adopted->state->user->annotations[0].name == "latest_name" &&
              pending->state->user->annotations.empty(),
          "late analysis composes facts with latest annotations rather than restoring worker state");
    check(adopted->functions->instructions.size() == 2 && adopted->last_reanalysis.decoded_instructions == 2 &&
              analysis.encoded_cache,
          "worker produces actual decoded facts and optional encoded cache without SQL ownership");
    auto stored = f.store->write_derived_cache(key, *analysis.encoded_cache, {});
    check(bool(stored) && bool(session->record_cache_result(key, stored)),
          "writer persists worker cache bytes and records current cache result");
    auto cached = f.store->read_derived_cache(key, {}).value();
    check(cached.status == CacheStatus::hit && cached.payload &&
              cached.payload->size() == analysis.encoded_cache->size(),
          "cache transport returns immutable encoded bytes");
    auto wrong_context = analysis;
    wrong_context.derived.context = {Architecture::x86, ExecutionMode::x86_32, ByteOrder::little};
    auto before_context = session->snapshot();
    check(!session->adopt_analysis(wrong_context, {}) && session->snapshot() == before_context,
          "matching source key cannot publish a proposal for another processor context");
    auto wrong_mapping = analysis;
    wrong_mapping.derived.mapping_fingerprint.value()[0] ^= std::byte{1};
    check(!session->adopt_analysis(wrong_mapping, {}) && session->snapshot() == before_context,
          "worker mapping digest cannot be forged even under a matching source key");
    auto wrong_domain = analysis;
    wrong_domain.derived.domain_contexts[0].context.segmented_memory = true;
    check(!session->adopt_analysis(wrong_domain, {}) && session->snapshot() == before_context,
          "worker domain context table must match the actual image");
    auto changed = session->execute(PatchBytes{FileOffset{0}, bytes({0x91})}, 0, {}).value();
    ProjectAnalysisRequest reanalysis;
    reanalysis.snapshot = changed;
    reanalysis.key = project_analysis_key(*changed, {}).value();
    auto incremental = compute_project_analysis(reanalysis, {}).value();
    check(incremental.derived.counters.validated_reuse_instructions == 0 &&
              incremental.derived.counters.reused_instructions >= 1 &&
              incremental.derived.functions->instructions.size() == 2,
          "project worker uses its complete effective-byte diff proof to avoid duplicate per-instruction reads");
    check(!session->adopt_analysis(analysis, {}) && session->snapshot() == changed,
          "stale worker proposal cannot publish after byte revision changes");
    check(!session->record_cache_result(key, Result<bool>{true}) &&
              !f.store->write_derived_cache(key, *analysis.encoded_cache, {}),
          "stale cache result cannot mark or replace current source cache");
    auto fresh = session->snapshot();
    ProjectAnalysisRequest canceled;
    canceled.snapshot = fresh;
    canceled.key = project_analysis_key(*fresh, {}).value();
    std::stop_source stop;
    stop.request_stop();
    check(!compute_project_analysis(canceled, stop.get_token()), "pure worker honors pre-cancellation");
}
void cache_transport_tests() {
    Fixture f;
    auto session = ProjectSession::attach(f.store, {}, {}).value();
    auto key = project_analysis_key(*session->snapshot(), {}).value();
    auto encoded = f.store->read_derived_cache(key, {}).value();
    check(encoded.status == CacheStatus::hit && encoded.payload,
          "synchronous compatibility service uses complete cache transport");
    auto invalid = *encoded.payload;
    invalid.back() ^= std::byte{1};
    check(!f.store->write_derived_cache(key, invalid, {}),
          "writer rejects malformed encoded-cache envelope before SQL mutation");
    auto readonly = ProjectStore::open(f.path, ProjectMode::read_only, {}).value();
    auto deferred = ProjectSession::attach_deferred(readonly, {}, {}).value();
    ProjectAnalysisRequest request;
    request.snapshot = deferred->snapshot();
    request.key = project_analysis_key(*request.snapshot, {}).value();
    request.cache = readonly->read_derived_cache(request.key, {}).value();
    auto restored = compute_project_analysis(request, {}).value();
    check(restored.cache_status == CacheStatus::hit && !restored.encoded_cache &&
              restored.derived.counters.cache_validation_decodes >= 2,
          "readonly worker validates cache but produces no repair write");
    check(bool(deferred->adopt_analysis(restored, {})) && deferred->snapshot()->status == DerivedStatus::fresh,
          "readonly deferred adoption retains fresh cache facts");
    auto incompatible = *request.cache.payload;
    incompatible[5] = std::byte{1};
    Sha256 checksum;
    check(bool(checksum.update(std::span(incompatible).first(incompatible.size() - 32))),
          "cache envelope version fixture checksum updates");
    auto digest = checksum.digest();
    std::copy(digest.begin(), digest.end(), incompatible.end() - 32);
    auto old_request = request;
    old_request.cache.payload = std::make_shared<const std::vector<std::byte>>(std::move(incompatible));
    auto recomputed = compute_project_analysis(old_request, {});
    check(recomputed && recomputed.value().cache_status == CacheStatus::incompatible &&
              !recomputed.value().encoded_cache &&
              recomputed.value().derived.context == request.snapshot->loaded->image->decode_context(),
          "readonly worker classifies unsupported envelope as incompatible and recomputes authoritative context");
}
} // namespace
int main() {
    return run([] {
        proposal_tests();
        cache_transport_tests();
    });
}
