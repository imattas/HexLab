#include "hexlab/loaders/x86_raw_profile.hpp"
#include "hexlab/analysis/derived_cache.hpp"
#include "hexlab/workspace/project_analysis.hpp"
#include "hexlab/workspace/export.hpp"
#include "testing.hpp"
#include "support/checks.hpp"
#include "support/fixture_files.hpp"
#include "support/analysis_fixture.hpp"
#include <algorithm>
using namespace hexlab;
using namespace hexlab::database;
using namespace hexlab_test;
namespace {
template <class T> T take(Result<T> result) {
    if (!result)
        throw std::runtime_error(result.error().message);
    return std::move(result.value());
}
struct OwnedPaths {
    std::vector<std::filesystem::path> paths;
    ~OwnedPaths() {
        std::error_code ignored;
        for (const auto &path : paths)
            for (auto suffix : {L"", L"-wal", L"-shm"}) {
                auto side = path;
                side += suffix;
                std::filesystem::remove(side, ignored);
            }
    }
};
X86RawProfile profile(bool protected_mode) {
    X86RawProfile p{X86ImageEnvironment::real386,
                    A20Policy::enabled,
                    0x10010,
                    {{7}, 0x10},
                    {},
                    {{{7}, 0x1000, true, "code", {}}, {{2}, 0x1001, false, "alias", {}}}};
    if (protected_mode) {
        p.environment = X86ImageEnvironment::protected386;
        p.input_load_address = 0x10000;
        p.entry.offset = 0;
        p.stack_selector = std::uint16_t{0x10};
        p.domains = {{{7},
                      8,
                      true,
                      "code",
                      X86SegmentDescriptor{0x10000, 0xffff, true, true, true, false, false, false, false, 0}},
                     {{2},
                      0x10,
                      false,
                      "alias",
                      X86SegmentDescriptor{0x10000, 0xffff, true, false, true, true, false, true, false, 0}}};
    }
    return p;
}
void cache_contract(const std::shared_ptr<ProjectSession> &session, const X86RawProfile &p) {
    auto snapshot = session->snapshot();
    auto key = take(project_analysis_key(*snapshot, {}));
    ProjectAnalysisRequest request;
    request.snapshot = snapshot;
    request.key = key;
    auto analysis = take(compute_project_analysis(request, {}));
    const auto &proposal = analysis.derived;
    check(proposal.domain_contexts.size() == 2 && proposal.domain_contexts[0].space == AddressSpaceId{2} &&
              proposal.domain_contexts[0].context.mode == ExecutionMode::unknown &&
              proposal.domain_contexts[1].space == AddressSpaceId{7} && proposal.mapping_fingerprint,
          "cache binds sorted data/code domains even when primary domain is not first");
    const auto &image = *snapshot->loaded->image;
    const auto decode = [&](std::span<const std::byte> payload, const Image &source) {
        return decode_derived(payload, source, snapshot->loaded->metadata, snapshot->state->user->decisions, {}, key,
                              {});
    };
    auto payload = take(encode_derived(proposal, {}));
    check(bool(decode(payload, image)), "segmented canonical cache validates against its original source");
    auto forged = proposal;
    forged.domain_contexts[0].context.mode = ExecutionMode::x86_16;
    auto wrong_context = take(encode_derived(forged, {}));
    check(!decode(wrong_context, image), "validly encoded unused-domain context forgery fails actual-image validation");
    forged = proposal;
    (*forged.mapping_fingerprint)[0] ^= std::byte{1};
    check(!decode(take(encode_derived(forged, {})), image), "validly encoded mapping digest forgery fails adoption");
    auto changed = p;
    changed.domains[1].selector = p.environment == X86ImageEnvironment::real386 ? 0x1002 : 0x18;
    if (changed.stack_selector)
        changed.stack_selector = std::uint16_t{0x18};
    LoadRecipe recipe{Format::raw, take(make_x86_raw_options(changed))};
    auto loaded = take(load_image(snapshot->effective, recipe, {}));
    check(loaded.image->decode_context() == image.decode_context() && !decode(payload, *loaded.image),
          "nonprimary selector change rejects cache despite identical primary context and supplied key");
    auto new_key = key;
    Sha256 sha;
    take(sha.update(take(encode_recipe(recipe))));
    new_key.recipe_fingerprint = sha.digest();
    auto invalidation = take(plan_invalidation(*snapshot->basis, {}, snapshot->state->user->decisions, new_key, {}));
    auto rebuilt =
        take(reanalyze(*snapshot->basis, loaded.image, std::make_shared<const ImageMetadata>(loaded.metadata),
                       snapshot->state->user->decisions, invalidation, new_key, {}));
    check(invalidation.full_reason == "Load recipe changed" && rebuilt.counters.reused_instructions == 0 &&
              rebuilt.mapping_fingerprint != proposal.mapping_fingerprint &&
              bool(validate_derived_source(rebuilt, *loaded.image, {})),
          "profile recipe change fully invalidates facts and binds the replacement mapping");
}
void persistent_tests(bool protected_mode) {
    const auto original = bytes({0x90, 0xc3, 'H', 'E', 'L', 'L', 'O', 0});
    FixtureFile input(original), marker(std::span<const std::byte>{});
    auto p = profile(protected_mode);
    const auto text = take(format_x86_profile(p));
    FixtureFile external_profile(std::as_bytes(std::span(text)));
    const std::filesystem::path path = marker.path.wstring() + L".segmented.hxproj";
    const std::filesystem::path saved = marker.path.wstring() + L".saved.hxproj";
    const std::filesystem::path exported = marker.path.wstring() + L".patched.bin";
    OwnedPaths cleanup{{path, saved, exported}};
    auto store = take(ProjectStore::create(path, {}));
    auto parsed = take(read_x86_profile(external_profile.path, {}));
    LoadRecipe recipe{Format::raw, take(make_x86_raw_options(parsed))};
    auto source = take(FileStorage::open(input.path));
    take(store->import_input(*source, recipe, input.path, {}));
    source.reset();
    auto session = take(ProjectSession::attach(store, {}, {}));
    auto initial = session->snapshot();
    check(initial->functions && initial->functions->instructions.size() == 2 &&
              initial->loaded->image->decode_context() ==
                  DecodeContext{Architecture::x86, ExecutionMode::x86_16, ByteOrder::little,
                                static_cast<std::uint8_t>(protected_mode ? 32 : 16), true},
          "persistent segmented image analyzes code with explicit independent stack width");
    cache_contract(session, p);
    const Address alias{{2}, 0};
    take(session->execute(Rename{p.entry, "segmented_entry"}, 0, {}));
    take(session->execute(Comment{alias, "canonical file alias"}, 0, {}));
    take(session->execute(PatchBytes{alias, bytes({0xcc})}, 0, {}));
    auto patched = take(session->refresh_analysis({}));
    check(patched->loaded->image->read(p.entry, 1).value() == bytes({0xcc}) &&
              patched->loaded->image->read(alias, 1).value() == bytes({0xcc}),
          "one canonical patch appears in both logical aliases");
    take(session->undo({}));
    auto undone = take(session->refresh_analysis({}));
    check(take(undone->loaded->image->read(p.entry, 1)) == bytes({0x90}), "undo restores both logical aliases");
    take(session->redo({}));
    testing::fail_next_commit(ErrorCode::io);
    patched = take(session->refresh_analysis({}));
    check(patched->derived_cache_status != CacheStatus::hit &&
              take(patched->loaded->image->read(p.entry, 1)) == bytes({0xcc}) && patched->state->history_cursor == 3,
          "optional segmented cache write failure preserves accepted patch and history");
    ProjectAnalysisRequest repair;
    repair.snapshot = patched;
    repair.key = take(project_analysis_key(*patched, {}));
    auto repaired = take(compute_project_analysis(repair, {}));
    check(bool(store->store_derived_cache(repaired.derived, {})),
          "optional cache can be explicitly rebuilt after failure without changing user state");
    auto receipt = take(export_patched(*patched, exported, ReplacePolicy::fail_if_exists, {}));
    auto expected = original;
    expected[0] = std::byte{0xcc};
    check(std::ranges::equal(take(FileStorage::open(exported))->read_at({0}, expected.size()).value().bytes, expected),
          "segmented export retains exact canonical file ordering");
    check(std::ranges::equal(take(FileStorage::open(input.path))->read_at({0}, original.size()).value().bytes,
                             original) &&
              receipt.bytes == original.size(),
          "segmented export preserves the external original");
    auto copied = take(store->save_as(saved, ReplacePolicy::fail_if_exists, {}));
    check(copied.uuid != patched->state->uuid, "Save As assigns a new project identity");
    const auto revisions = patched->state->revisions;
    const auto history = patched->state->history_cursor;
    session.reset();
    store.reset();
    check(std::filesystem::remove(input.path) && std::filesystem::remove(external_profile.path),
          "owned source and external profile are removed before reopen");
    store = take(ProjectStore::open(saved, ProjectMode::read_only, {}));
    session = take(ProjectSession::attach(store, {}, {}));
    auto reopened = session->snapshot();
    check(take(format_x86_profile(*reopened->state->recipe.raw->x86_profile)) == text,
          "source-missing readonly Save As reopen retains canonical profile");
    check(reopened->state->revisions == revisions && reopened->state->history_cursor == history,
          "source-missing readonly Save As reopen retains revisions and history");
    check(presentation_name(*reopened, p.entry) == "segmented_entry" &&
              presentation_at(*reopened, alias).comment == "canonical file alias" &&
              take(reopened->loaded->image->read(p.entry, 1)) == bytes({0xcc}),
          "source-missing readonly Save As reopen retains alias annotations and patches");
    check(reopened->derived_cache_status == CacheStatus::hit && !session->execute(Comment{alias, "forbidden"}, 0, {}),
          "readonly segmented reopen adopts domain-bound cache and rejects edits");
}
} // namespace
int main() {
    return run([] {
        persistent_tests(false);
        persistent_tests(true);
    });
}
