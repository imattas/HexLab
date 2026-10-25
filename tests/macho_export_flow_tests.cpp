#include "hexlab/workspace/project.hpp"
#include "hexlab/analysis/derived_cache.hpp"
#include "support/macho_dyld_fixture.hpp"
#include "support/analysis_fixture.hpp"
#include "support/fixture_files.hpp"
#include "support/checks.hpp"
using namespace hexlab;
using namespace hexlab_test;
using namespace hexlab_test::macho_fixture;
namespace {
template <class T> T take(Result<T> value) {
    if (!value)
        throw std::runtime_error(value.error().message);
    return std::move(value.value());
}
constexpr Address entry{{0}, UINT64_C(0x100000100)}, resolver_at{{0}, entry.offset + 16};
std::vector<std::byte> exported(unsigned variant = 0) {
    auto data = dyld(true);
    put(data, symtab_command(true) + 12, 0, 4, false);
    segment(data, true, false, 32, entry.offset - 1024, 4096, 0, 4096, 7, 0, 3);
    put(data, 32 + 72 + 2 * 80 + 48, 784, 4, false);
    put(data, 32 + 72 + 2 * 80 + 64, 0, 4, false);
    data[1024] = data[1040] = std::byte{0xc3};
    if (variant == 0)
        stream(data, true, false, 4, {0, 1, '_', 'a', 'p', 'i', 0, 8, 3, 0, 0x80, 8, 0});
    else if (variant == 1)
        stream(data, true, false, 4, {0, 1, '_', 'a', 'p', 'i', 0, 8, 5, 0x10, 0x80, 8, 0x90, 8, 0});
    else if (variant == 2)
        stream(data, true, false, 4, {0, 1, '_', 'a', 'p', 'i', 0, 8, 3, 8, 1, 0, 0});
    else if (variant == 3)
        stream(data, true, false, 4, {0, 1, '_', 'a', 'p', 'i', 0, 8, 3, 1, 0x80, 8, 0});
    else if (variant == 4)
        stream(data, true, false, 4, {0, 1, '_', 'a', 'p', 'i', 0, 8, 3, 2, 0x80, 8, 0});
    else if (variant == 5)
        stream(data, true, false, 4, {0, 1, '_', 'a', 'p', 'i', 0, 8, 1, 0x20, 0});
    else
        stream(data, true, false, 4, {0, 1, '_', 'a', 'p', 'i', 0, 8, 3, 4, 0x80, 8, 0});
    return data;
}
void roots_and_names() {
    for (unsigned variant = 0; variant < 7; ++variant) {
        const auto loaded = take(load_macho(std::make_shared<MemoryStorage>(exported(variant)), {}, {}));
        const auto functions = take(recover_functions(*loaded.image, loaded.metadata, {}, {}, {}));
        const auto expected = variant == 0 || variant == 6 ? 1u : variant == 1 ? 2u : 0u;
        check(functions->functions.size() == expected,
              "export-only regular and resolver declarations seed code; reexport/TLS/absolute declarations do not");
        const auto coarse = take(analyze(*loaded.image, loaded.metadata, {}, {}));
        check(coarse.instructions.size() == expected,
              "coarse analysis and rooted recovery agree on actual executable export declarations");
        ProjectSnapshot snapshot;
        snapshot.loaded = std::make_shared<const LoadedImage>(loaded);
        check((presentation_name(snapshot, entry) == "_api") == (variant < 2 || variant == 6),
              "fallback presentation names only mapped complete export definitions");
        AnalysisKey key;
        key.input = {loaded.image->storage()->size(), take(hash_source(*loaded.image->storage(), {}))};
        key.engine_fingerprint = function_engine_fingerprint();
        const auto proposal = take(
            analyze_derived(loaded.image, std::make_shared<const ImageMetadata>(loaded.metadata), {}, {}, key, {}));
        check(bool(decode_derived(take(encode_derived(proposal, {})), *loaded.image, loaded.metadata, {}, {}, key, {})),
              "export-root derivation validates against original export trie source");
    }
    auto data = exported();
    put(data, 32 + 60, 3, 4, false);
    const auto loaded = take(load_macho(std::make_shared<MemoryStorage>(data), {}, {}));
    check(take(recover_functions(*loaded.image, loaded.metadata, {}, {}, {}))->functions.empty(),
          "export declaration cannot override segment execute permissions");
    ProjectSnapshot snapshot;
    snapshot.loaded = std::make_shared<const LoadedImage>(loaded);
    check(presentation_name(snapshot, entry) == "_api", "non-executable data exports still retain their original name");
}
void project_export_patch() {
    FixtureFile input(exported());
    const auto path = std::filesystem::path(input.path.wstring() + L".export.hxproj");
    auto store = take(database::ProjectStore::create(path, {}));
    auto source = take(FileStorage::open(input.path));
    take(store->import_input(*source, {Format::macho, {}, {}}, input.path, {}));
    source.reset();
    auto session = take(ProjectSession::attach(store, {}, {}));
    check(presentation_name(*session->snapshot(), entry) == "_api" &&
              session->snapshot()->functions->functions.size() == 1,
          "worker-owned project presentation indexes export-only names and roots");
    const auto before = session->snapshot();
    auto snapshot = take(session->execute(PatchBytes{FileOffset{3010}, bytes({0x90})}, 0, {}));
    snapshot = take(session->refresh_analysis({}));
    check(presentation_name(*snapshot, resolver_at) == "_api" && snapshot->functions->functions.size() == 1 &&
              snapshot->functions->functions[0]->entry == resolver_at &&
              before->loaded->metadata.macho->dyld_exports[0].address == entry,
          "export payload edit moves indexed name/root while retained snapshot stays immutable");
    take(session->undo({}));
    snapshot = take(session->refresh_analysis({}));
    check(presentation_name(*snapshot, entry) == "_api" && snapshot->functions->functions.size() == 1 &&
              snapshot->functions->functions[0]->entry == entry,
          "undo rebuilds original export-only root and automatic name");
    snapshot = take(session->execute(Rename{resolver_at, "_api"}, 0, {}));
    auto fallback = *snapshot;
    fallback.presentation.reset();
    check(presentation_name(*snapshot, entry) != "_api" &&
              presentation_name(*snapshot, entry) == presentation_name(fallback, entry),
          "worker and fallback presentation agree on collisions between user names and exported definitions");
    take(session->undo({}));
    snapshot = take(session->execute(Rename{entry, "owned_api"}, 0, {}));
    check(presentation_name(*snapshot, entry) == "owned_api", "user annotations override indexed export names");
    const auto state = snapshot->state;
    session.reset();
    store.reset();
    check(std::filesystem::remove(input.path), "owned export input removed before readonly cache reopen");
    store = take(database::ProjectStore::open(path, database::ProjectMode::read_only, {}));
    session = take(ProjectSession::attach(store, {}, {}));
    snapshot = session->snapshot();
    check(snapshot->derived_cache_status == database::CacheStatus::hit &&
              presentation_name(*snapshot, entry) == "owned_api" && snapshot->functions->functions.size() == 1 &&
              snapshot->state->uuid == state->uuid && snapshot->state->revisions == state->revisions &&
              *snapshot->state->user == *state->user && snapshot->state->history_cursor == state->history_cursor,
          "source-missing readonly reopen preserves actual export-derived cache and user history");
    session.reset();
    store.reset();
    snapshot.reset();
    std::error_code ignored;
    for (auto suffix : {L"", L"-wal", L"-shm"}) {
        auto file = path;
        file += suffix;
        std::filesystem::remove(file, ignored);
    }
}
} // namespace
int main() {
    return run([] {
        roots_and_names();
        project_export_patch();
    });
}
