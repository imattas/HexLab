#include "hexlab/workspace/project.hpp"
#include "hexlab/workspace/navigation.hpp"
#include "hexlab/workspace/listing.hpp"
#include "hexlab/workspace/export.hpp"
#include "hexlab/loaders/elf.hpp"
#include "hexlab/loaders/macho.hpp"
#include "support/a64_image_fixture.hpp"
#include "support/checks.hpp"
using namespace hexlab;
using namespace hexlab_test;
namespace {
template <class T> T take(Result<T> result) {
    if (!result)
        throw std::runtime_error(result.error().message);
    return std::move(result.value());
}
void cleanup(const std::filesystem::path &path) {
    std::error_code ignored;
    for (auto suffix : {L"", L"-wal", L"-shm"}) {
        auto item = path;
        item += suffix;
        std::filesystem::remove(item, ignored);
    }
}
void project(std::vector<std::byte> bytes, LoadRecipe recipe, Address entry, std::uint64_t file) {
    FixtureFile input(bytes);
    const auto path = std::filesystem::path(input.path.wstring() + L".a64.hxproj");
    const auto saved = std::filesystem::path(input.path.wstring() + L".a64.saved.hxproj");
    const auto exported = std::filesystem::path(input.path.wstring() + L".a64.exported");
    {
        auto source = take(FileStorage::open(input.path));
        auto store = take(database::ProjectStore::create(path, {}));
        take(store->import_input(*source, recipe, input.path, {}));
        source.reset();
        auto session = take(ProjectSession::attach(store, {}, {}));
        auto snapshot = take(session->refresh_analysis({}));
        const Address callee{entry.space, entry.offset + 16};
        check(snapshot->loaded && snapshot->loaded->image->context_at(entry).value().mode == ExecutionMode::a64 &&
                  snapshot->functions->functions.size() == 2 && take(project_follow_target(*snapshot, entry)) == callee,
              "A64 saved project derives source-bound call target through shared Follow");
        take(session->execute(Rename{callee, "a64_owner"}, 0, {}));
        check(presentation_name(*session->snapshot(), callee) == "a64_owner",
              "A64 names use committed project presentation");
        auto patched = take(session->execute(
            PatchBytes{FileOffset{file}, {std::byte{0x1f}, std::byte{0x20}, std::byte{3}, std::byte{0xd5}}}, 0, {}));
        patched = take(session->refresh_analysis({}));
        check(!take(project_follow_target(*patched, entry)) && patched->functions->functions.size() == 1,
              "A64 call-to-NOP patch removes old callee and Follow proof");
        check(!export_patched(*patched, input.path, database::ReplacePolicy::replace_existing, {}),
              "export protects original A64 input");
        take(export_patched(*patched, exported, database::ReplacePolicy::fail_if_exists, {}));
        auto expected = bytes;
        const unsigned nop[]{0x1f, 0x20, 3, 0xd5};
        for (unsigned n = 0; n < 4; ++n)
            expected[file + n] = std::byte(nop[n]);
        const auto output = take(FileStorage::open(exported));
        const auto actual = take(output->read_at({0}, expected.size()));
        check(std::equal(expected.begin(), expected.end(), actual.bytes.begin()) && output->size() == bytes.size(),
              "A64 export preserves exact complete input with only overlay bytes changed");
        take(session->undo({}));
        snapshot = take(session->refresh_analysis({}));
        check(take(project_follow_target(*snapshot, entry)) == callee, "A64 undo restores canonical branch proof");
        take(session->redo({}));
        snapshot = take(session->refresh_analysis({}));
        check(!take(project_follow_target(*snapshot, entry)), "A64 redo removes proof again");
        take(session->undo({}));
        snapshot = take(session->refresh_analysis({}));
        DocumentSnapshot document;
        document.project = snapshot;
        document.image = snapshot->loaded->image;
        const auto listing = take(make_listing_page(document, entry, 1));
        check(listing.rows[0].instruction && listing.rows[0].control_target == callee,
              "manual listing and recovered A64 Follow agree");
        const auto state = snapshot->state;
        const auto copy = take(store->save_as(saved, database::ReplacePolicy::fail_if_exists, {}));
        check(copy.uuid != state->uuid, "A64 Save As creates independent project identity");
        session.reset();
        store.reset();
        check(std::filesystem::remove(input.path), "owned A64 external source removed before readonly reopen");
        auto readonly = take(database::ProjectStore::open(saved, database::ProjectMode::read_only, {}));
        auto reopened = take(ProjectSession::attach(readonly, {}, {}));
        const auto current = reopened->snapshot();
        check(
            current->derived_cache_status == database::CacheStatus::hit && current->state->uuid == copy.uuid &&
                current->state->revisions == state->revisions &&
                current->state->history_cursor == state->history_cursor && *current->state->user == *state->user &&
                presentation_name(*current, callee) == "a64_owner" &&
                take(project_follow_target(*current, entry)) == callee,
            "source-missing readonly A64 cache preserves mode, identity, annotations, history and original call proof");
        check(!reopened->execute(Rename{callee, "forbidden"}, 0, {}), "readonly A64 project refuses mutation");
    }
    cleanup(path);
    cleanup(saved);
    cleanup(exported);
}
void object_project(const std::filesystem::path &original, bool macho) {
    auto source = take(FileStorage::open(original));
    const auto loaded = macho ? take(load_macho(source, {}, {})) : take(load_elf(source, {}));
    Address owner{}, callee{};
    if (macho)
        for (const auto &symbol : loaded.metadata.macho->symbols) {
            if (symbol.name == "_owner" && symbol.address)
                owner = *symbol.address;
            if (symbol.name == "_callee" && symbol.address)
                callee = *symbol.address;
        }
    else
        for (const auto &symbol : loaded.metadata.elf->symbols) {
            if (symbol.name == "owner" && symbol.address)
                owner = *symbol.address;
            if (symbol.name == "callee" && symbol.address)
                callee = *symbol.address;
        }
    const auto view = take(source->read_at({0}, static_cast<std::size_t>(source->size())));
    FixtureFile input(view.bytes);
    const auto path = std::filesystem::path(input.path.wstring() + L".object-a64.hxproj");
    {
        auto store = take(database::ProjectStore::create(path, {}));
        auto input_source = take(FileStorage::open(input.path));
        take(store->import_input(*input_source, {macho ? Format::macho : Format::elf, {}}, input.path, {}));
        input_source.reset();
        auto session = take(ProjectSession::attach(store, {}, {}));
        auto snapshot = take(session->refresh_analysis({}));
        check(owner.space != callee.space && take(project_follow_target(*snapshot, owner)) == callee,
              "real compiler ARM relocation project Follow resolves original section-domain callee");
        take(session->execute(Rename{callee, "compiler_a64_callee"}, 0, {}));
        snapshot = take(session->refresh_analysis({}));
        const auto state = snapshot->state;
        session.reset();
        store.reset();
        check(std::filesystem::remove(input.path), "owned compiler object removed before cache-only reopen");
        auto readonly = take(database::ProjectStore::open(path, database::ProjectMode::read_only, {}));
        auto reopened = take(ProjectSession::attach(readonly, {}, {}));
        snapshot = reopened->snapshot();
        check(snapshot->derived_cache_status == database::CacheStatus::hit &&
                  take(project_follow_target(*snapshot, owner)) == callee,
              "embedded readonly real-object cache restores source-bound packed ARM relocation proof");
        check(snapshot->state->uuid == state->uuid && snapshot->state->revisions == state->revisions &&
                  *snapshot->state->user == *state->user &&
                  presentation_name(*snapshot, callee) == "compiler_a64_callee",
              "real-object cache adoption preserves identity, user history and annotations");
    }
    cleanup(path);
}
} // namespace
int main(int argc, char **argv) {
    if (argc != 3)
        return 2;
    return run([&] {
        RawOptions raw{Architecture::arm64, ExecutionMode::a64, {{7}, 0x1000}, true, false, true, {}};
        project(a64_fixture::program(), {Format::raw, raw}, raw.base, 0);
        project(a64_fixture::pe(), {Format::pe, {}}, {{0}, UINT64_C(0x140001000)}, 512);
        project(a64_fixture::elf(), {Format::elf, {}}, {{0}, 0x400000}, 256);
        project(a64_fixture::macho(), {Format::macho, {}}, {{0}, UINT64_C(0x100000300)}, 768);
        object_project(argv[1], false);
        object_project(argv[2], true);
    });
}
