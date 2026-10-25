#include "hexlab/workspace/project.hpp"
#include "hexlab/workspace/macho_presentation.hpp"
#include "support/macho_symbol_fixture.hpp"
#include "support/fixture_files.hpp"
#include "support/checks.hpp"
using namespace hexlab;
using namespace hexlab_test;
namespace {
template <class T> T take(Result<T> value) {
    if (!value)
        throw std::runtime_error(value.error().message);
    return std::move(value.value());
}
void project(bool wide) {
    FixtureFile input(macho_fixture::symbols(wide));
    const auto path = std::filesystem::path(input.path.wstring() + L".macho.hxproj");
    auto store = take(database::ProjectStore::create(path, {}));
    auto source = take(FileStorage::open(input.path));
    const auto recipe = take(resolve_load_recipe(*source, {Format::macho, {}, {}}, {}));
    take(store->import_input(*source, recipe, input.path, {}));
    source.reset();
    auto session = take(ProjectSession::attach(store, {}, {}));
    auto snapshot = session->snapshot();
    check(snapshot->loaded && snapshot->loaded->metadata.macho && snapshot->functions,
          "real saved project loads Mach-O symbols and derived roots");
    check(macho_metadata_row_count(*snapshot) == 18 && !macho_metadata_row_at(*snapshot, 18) &&
              !macho_metadata_row_at(*snapshot, UINT64_MAX),
          "indexed metadata bounds preserve exact row count");
    auto page = take(make_macho_metadata_page(*snapshot, 8, 256, {}));
    check(page.total == 18 && page.begin == 8 && page.rows.size() == 10 &&
              page.rows[1].kind == MachOMetadataKind::symbol && page.rows[3].index == 2 &&
              page.rows[3].source == FileOffset{1536 + 2 * (wide ? 16u : 12u)},
          "nonfirst metadata page preserves original symbol record identity and stride");
    check(!make_macho_metadata_page(*snapshot, 0, 257, {}) && !make_macho_metadata_page(*snapshot, UINT64_MAX, 1, {}) &&
              take(make_macho_metadata_page(*snapshot, 18, 256, {})).rows.empty(),
          "page limits reject oversized/overflowed requests and allow empty terminal page");
    std::stop_source stopped;
    stopped.request_stop();
    auto canceled_page = make_macho_metadata_page(*snapshot, 0, 1, stopped.get_token());
    check(!canceled_page && canceled_page.error().code == ErrorCode::canceled,
          "metadata page observes cancellation before publication");
    check(presentation_name(*snapshot, Address{{1}, 0}) == "_same" &&
              presentation_name(*snapshot, Address{{2}, 0}) == "_same",
          "worker presentation indexes independent same-valued object-domain names");
    take(session->execute(Rename{Address{{1}, 0}, "owned"}, 0, {}));
    check(bool(session->execute(Rename{Address{{2}, 0}, "owned"}, 0, {})),
          "identical user names in separate domains do not conflict");
    take(session->undo({}));
    snapshot = take(session->execute(PatchBytes{FileOffset{macho_fixture::strings_at + 1}, bytes({0x58})}, 0, {}));
    check(presentation_name(*snapshot, Address{{1}, 0}) == "owned" &&
              presentation_name(*snapshot, Address{{2}, 0}) == "Xsame",
          "metadata string edit refreshes automatic names while preserving committed annotation override");
    take(session->undo({}));
    snapshot = take(session->refresh_analysis({}));
    const auto uuid = snapshot->state->uuid;
    session.reset();
    store.reset();
    std::filesystem::remove(input.path);
    store = take(database::ProjectStore::open(path, database::ProjectMode::read_only, {}));
    session = take(ProjectSession::attach(store, {}, {}));
    snapshot = session->snapshot();
    check(snapshot->derived_cache_status == database::CacheStatus::hit && snapshot->state->uuid == uuid &&
              presentation_name(*snapshot, Address{{1}, 0}) == "owned" &&
              presentation_name(*snapshot, Address{{2}, 0}) == "_same",
          "source-missing readonly reopen preserves indexed names/domain ownership/cache/user history");
    session.reset();
    store.reset();
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
        project(false);
        project(true);
    });
}
