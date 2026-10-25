#include "hexlab/workspace/project.hpp"
#include "hexlab/workspace/document.hpp"
#include "hexlab/workspace/open_recipe.hpp"
#include "hexlab/workspace/export.hpp"
#include "hexlab/workspace/listing.hpp"
#include "support/macho_fixture.hpp"
#include "support/analysis_fixture.hpp"
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
void clean_project(const std::filesystem::path &path) {
    std::error_code ignored;
    for (const auto suffix : {L"", L"-wal", L"-shm"}) {
        auto file = path;
        file += suffix;
        std::filesystem::remove(file, ignored);
    }
}
std::vector<std::byte> hybrid_thin() {
    auto data = macho_fixture::mapped_fat();
    const auto thin = macho_fixture::mapped(true);
    std::copy(thin.begin(), thin.end(), data.begin());
    return data;
}
void container_kind_patch(bool original_fat) {
    FixtureFile input(original_fat ? macho_fixture::mapped_fat() : hybrid_thin());
    const auto path = std::filesystem::path(input.path.wstring() + L".kind.hxproj");
    auto store = take(database::ProjectStore::create(path, {}));
    auto source = take(FileStorage::open(input.path));
    auto recipe = take(resolve_load_recipe(
        *source, {Format::macho, {}, original_fat ? std::optional{MachOOptions{0}} : std::nullopt}, {}));
    take(store->import_input(*source, recipe, input.path, {}));
    source.reset();
    auto session = take(ProjectSession::attach(store, {}, {}));
    const Address owner{{0}, original_fat ? UINT64_C(0x1000) : UINT64_C(0x100000000)};
    take(session->execute(Rename{owner, "kind_owner"}, 0, {}));
    const auto before = session->snapshot();
    auto replacement = original_fat ? macho_fixture::mapped(true) : macho_fixture::mapped_fat();
    if (!original_fat)
        replacement.resize(48);
    const auto changed = take(session->execute(PatchBytes{FileOffset{0}, replacement}, 0, {}));
    check(changed->status == DerivedStatus::file_only && !changed->loaded,
          "a source patch cannot silently change the saved thin/universal recipe kind");
    check(take(encode_recipe(changed->state->recipe)) == take(encode_recipe(before->state->recipe)) &&
              changed->state->uuid == before->state->uuid && presentation_name(*changed, owner) == "kind_owner",
          "invalid container mapping preserves saved recipe, UUID and annotations");
    auto restored = take(session->undo({}));
    check(restored->loaded && restored->loaded->metadata.macho->container.universal == original_fat &&
              restored->loaded->metadata.macho->selected_slice == 0,
          "undo restores the original bound container and selection");
    auto redone = take(session->redo({}));
    check(!redone->loaded && redone->status == DerivedStatus::file_only,
          "redo reinstates file-only state rather than selecting a new architecture");
    take(session->undo({}));
    take(session->refresh_analysis({}));
    session.reset();
    store.reset();
    clean_project(path);
}
void import_and_open() {
    FixtureFile input(macho_fixture::mapped_fat());
    OpenRequest request;
    request.path = input.path;
    auto automatic = load_document(request, {{1}, 1}, {});
    check(automatic && automatic.value()->metadata.macho && automatic.value()->metadata.macho->selected_slice == 1,
          "automatic inspection opening recognizes Mach-O and chooses the supported default slice");
    request.format = Format::macho;
    auto explicit_open = load_document(request, {{2}, 1}, {});
    check(explicit_open && explicit_open.value()->metadata.macho &&
              explicit_open.value()->metadata.macho->selected_slice == 1,
          "explicit Mach-O inspection uses the same shared request path");
    const auto path = std::filesystem::path(input.path.wstring() + L".import.hxproj");
    auto store = take(database::ProjectStore::create(path, {}));
    auto source = take(FileStorage::open(input.path));
    take(store->import_input(*source, {Format::macho, {}, {}}, input.path, {}));
    source.reset();
    const auto state = take(store->snapshot());
    check(state->recipe.macho && state->recipe.macho->slice_index == 1 &&
              take(encode_recipe(state->recipe)) == bytes({1, 0, 5, 1, 0, 0, 0, 1}),
          "database import persists actual default universal slice before storing input identity");
    auto session = take(ProjectSession::attach(store, {}, {}));
    check(session->snapshot()->loaded && session->snapshot()->loaded->metadata.macho->selected_slice == 1,
          "default universal import reopens through its concrete saved selection");
    session.reset();
    store.reset();
    clean_project(path);
}
class ShortMagic final : public ByteStorage {
    std::shared_ptr<const std::vector<std::byte>> data_ =
        std::make_shared<const std::vector<std::byte>>(bytes({0xcf, 0xfa}));

  public:
    mutable unsigned reads = 0;
    std::uint64_t size() const noexcept override { return 4; }
    Result<ByteView> read_at(FileOffset, std::size_t) const override {
        ++reads;
        return ByteView{data_, std::span(*data_)};
    }
};
void opening_contracts() {
    static_assert(static_cast<unsigned>(DetectedFormat::macho_candidate) == 3);
    for (const auto magic :
         {0xfeedfaceu, 0xcefaedfeu, 0xfeedfacfu, 0xcffaedfeu, 0xcafebabeu, 0xbebafecau, 0xcafebabfu, 0xbfbafecau}) {
        std::vector<std::byte> data(4);
        macho_fixture::put(data, 0, magic, 4, true);
        MemoryStorage source(data);
        check(
            take(detect_format(source)) == DetectedFormat::macho_candidate,
            "all eight Mach-O thin/universal class/order signatures are candidates without fabricating a valid image");
        check(!load_image(std::make_shared<MemoryStorage>(data), {Format::automatic, {}, {}}, {}),
              "recognized but truncated Mach-O candidates cannot become raw or valid images");
    }
    for (bool wide : {false, true})
        for (bool big : {false, true}) {
            FixtureFile input(macho_fixture::mapped(wide, big));
            OpenRequest request;
            request.path = input.path;
            request.run_analysis = false;
            const auto doc = take(load_document(request, {{3}, 1}, {}));
            check(doc->metadata.macho && doc->metadata.macho->container.slices[0].header.is_64 == wide &&
                      (doc->image->decode_context().mode == ExecutionMode::unknown) == big,
                  "automatic 32/64 both-order inspection keeps unsupported endian modes honest");
        }
    FixtureFile input(macho_fixture::mapped_fat());
    OpenRequest request;
    request.path = input.path;
    request.macho = MachOOptions{0};
    check(take(load_document(request, {{4}, 1}, {}))->metadata.macho->selected_slice == 0,
          "automatic worker opening can carry an explicit nondefault slice");
    request.format = Format::macho;
    check(take(load_document(request, {{5}, 1}, {}))->metadata.macho->selected_slice == 0,
          "explicit worker opening retains the requested nondefault slice");
    request.raw = RawOptions{Architecture::x86_64, ExecutionMode::x86_64, {{0}, 0}, true, false, true, {}};
    check(!resolve_open_recipe(request, {}), "Mach-O slice intent cannot consume raw coordinate options");
    request.raw.reset();
    request.format = Format::elf;
    check(!resolve_open_recipe(request, {}), "other explicit formats cannot silently consume slice options");
    MemoryStorage pe(bytes({0x4d, 0x5a, 0, 0}));
    check(!resolve_load_recipe(pe, {Format::automatic, {}, MachOOptions{0}}, {}),
          "automatic non-Mach-O input refuses Mach-O-only options");
    auto source = std::make_shared<MemoryStorage>(macho_fixture::mapped_fat());
    check(!load_durable_image(source, {Format::automatic, {}, {}}, {}) &&
              !load_durable_image(source, {Format::macho, {}, {}}, {}),
          "durable loading accepts neither unresolved automatic intent nor thin flags for a FAT source");
    auto thin = std::make_shared<MemoryStorage>(macho_fixture::mapped(true));
    check(bool(load_image(thin, {Format::macho, {}, MachOOptions{0}}, {})) &&
              !load_durable_image(thin, {Format::macho, {}, MachOOptions{0}}, {}),
          "thin slice-zero opening intent normalizes, while persisted universal-zero remains bound to FAT");
    ShortMagic short_source;
    const auto short_read = detect_format(short_source);
    check(!short_read && short_read.error().code == ErrorCode::io, "short prefix reads fail before signature indexing");
    std::stop_source canceled;
    canceled.request_stop();
    short_source.reads = 0;
    const auto stopped = resolve_load_recipe(short_source, {Format::automatic, {}, {}}, canceled.get_token());
    check(!stopped && stopped.error().code == ErrorCode::canceled && !short_source.reads,
          "canceled resolution stops before reading input");
    check(!load_durable_image(source, {Format::macho, {}, MachOOptions{1}}, canceled.get_token()),
          "durable loading honors cancellation");
}
void persistent_fat_workflow() {
    const auto original = macho_fixture::mapped_fat();
    FixtureFile input(original);
    const auto path = std::filesystem::path(input.path.wstring() + L".workflow.hxproj");
    const auto saved = std::filesystem::path(input.path.wstring() + L".saved.hxproj");
    const auto exported = std::filesystem::path(input.path.wstring() + L".export.bin");
    auto store = take(database::ProjectStore::create(path, {}));
    auto source = take(FileStorage::open(input.path));
    take(store->import_input(*source, {Format::automatic, {}, {}}, input.path, {}));
    source.reset();
    auto session = take(ProjectSession::attach(store, {}, {}));
    const Address owner{{0}, UINT64_C(0x100000000)};
    take(session->execute(Rename{owner, "fat_owner"}, 0, {}));
    take(session->execute(DefineFunction{owner}, 0, {}));
    auto snapshot = take(session->refresh_analysis({}));
    check(snapshot->state->recipe.macho->slice_index == 1 && snapshot->functions->instructions.size() == 2,
          "automatic import persists selected slice and recovers explicitly defined code");
    const auto parses = snapshot->loader_parses;
    snapshot = take(session->execute(PatchBytes{FileOffset{1792}, bytes({0x91})}, 0, {}));
    check(snapshot->loader_parses == parses && snapshot->loaded->metadata.macho->selected_slice == 1,
          "unselected-slice ordinary bytes cannot trigger selection or metadata reparsing");
    snapshot = take(session->execute(PatchBytes{FileOffset{2816}, bytes({0xcc})}, 0, {}));
    check(snapshot->loader_parses == parses, "selected ordinary code patch also avoids unnecessary metadata parsing");
    snapshot = take(session->refresh_analysis({}));
    check(snapshot->functions->instructions.size() == 1 &&
              snapshot->functions->instructions[0]->instruction.opcode == Opcode::int3,
          "selected code patch invalidates actual decoded facts");
    take(session->undo({}));
    snapshot = take(session->refresh_analysis({}));
    check(snapshot->functions->instructions.size() == 2, "undo restores selected-slice code facts");
    take(session->redo({}));
    snapshot = take(session->refresh_analysis({}));
    auto expected = original;
    expected[1792] = std::byte{0x91};
    expected[2816] = std::byte{0xcc};
    const auto receipt = take(export_patched(*snapshot, exported, database::ReplacePolicy::fail_if_exists, {}));
    auto output = take(FileStorage::open(exported));
    auto view = take(output->read_at({0}, expected.size()));
    check(receipt.bytes == expected.size() && std::ranges::equal(view.bytes, expected),
          "export preserves the entire universal container and exact selected/unselected patches");
    output.reset();
    view = {};
    auto untouched = take(FileStorage::open(input.path));
    auto original_view = take(untouched->read_at({0}, original.size()));
    check(std::ranges::equal(original_view.bytes, original),
          "patch/export leaves original universal source bytes unchanged");
    original_view = {};
    untouched.reset();
    const auto copy = take(store->save_as(saved, database::ReplacePolicy::fail_if_exists, {}));
    const auto before = snapshot->state;
    check(copy.uuid != before->uuid, "Mach-O Save As creates an independent project UUID");
    snapshot.reset();
    session.reset();
    store.reset();
    check(std::filesystem::remove(input.path), "owned universal source removed before embedded readonly reopen");
    store = take(database::ProjectStore::open(saved, database::ProjectMode::read_only, {}));
    session = take(ProjectSession::attach(store, {}, {}));
    snapshot = session->snapshot();
    check(snapshot->derived_cache_status == database::CacheStatus::hit && snapshot->state->uuid == copy.uuid &&
              snapshot->loaded->metadata.macho->selected_slice == 1 &&
              presentation_name(*snapshot, owner) == "fat_owner" && snapshot->state->revisions == before->revisions &&
              *snapshot->state->user == *before->user && snapshot->state->history_cursor == before->history_cursor,
          "source-missing readonly Save As retains selected slice, cache, annotations, revisions and history");
    check(!session->execute(Comment{owner, "denied"}, 0, {}), "readonly Mach-O reopen refuses mutation");
    snapshot.reset();
    session.reset();
    store.reset();
    clean_project(path);
    clean_project(saved);
    std::error_code ignored;
    std::filesystem::remove(exported, ignored);
}
void pinned_slice_changes() {
    FixtureFile input(macho_fixture::mapped_fat());
    const auto path = std::filesystem::path(input.path.wstring() + L".pinned.hxproj");
    auto store = take(database::ProjectStore::create(path, {}));
    auto source = take(FileStorage::open(input.path));
    take(store->import_input(*source, {Format::automatic, {}, {}}, input.path, {}));
    source.reset();
    auto session = take(ProjectSession::attach(store, {}, {}));
    const Address owner{{0}, UINT64_C(0x100000000)};
    take(session->execute(DefineFunction{owner}, 0, {}));
    const auto before = take(session->refresh_analysis({}));
    const auto invalid = take(session->execute(PatchBytes{FileOffset{28}, bytes({1, 0, 0, 12})}, 0, {}));
    check(!invalid->loaded, "descriptor/header CPU disagreement cannot produce a selected mapping");
    const auto changed = take(session->execute(PatchBytes{FileOffset{2052}, bytes({12, 0, 0, 1})}, 0, {}));
    check(changed->loaded && changed->loaded->metadata.macho->selected_slice == 1 &&
              changed->loaded->image->decode_context().architecture == Architecture::arm64 &&
              changed->state->recipe.macho->slice_index == 1 &&
              before->loaded->image->decode_context().architecture == Architecture::x86_64,
          "saved slice stays selected when a patch changes its CPU and a different slice becomes preferred");
    const auto newly_resolved = take(resolve_load_recipe(*changed->effective, {Format::automatic, {}, {}}, {}));
    check(newly_resolved.macho->slice_index == 0, "ranking regression actually changes the preferred opening choice");
    DocumentSnapshot document;
    document.project = changed;
    document.image = changed->loaded->image;
    const auto page = take(make_listing_page(document, owner, 1));
    check(!page.rows[0].control_target &&
              (!page.rows[0].instruction ||
               (page.rows[0].instruction->context.architecture == Architecture::arm64 &&
                page.rows[0].instruction->opcode == Opcode::opaque && page.rows[0].instruction->operands.empty())),
          "patched CPU slice cannot reuse stale x64 facts; new A64 fallback is display-only");
    take(session->undo({}));
    take(session->undo({}));
    auto restored = take(session->refresh_analysis({}));
    check(restored->loaded->metadata.macho->selected_slice == 1 && restored->functions->instructions.size() == 2,
          "undo restores selected CPU and rederives the original instruction facts");
    const auto missing = take(session->execute(PatchBytes{FileOffset{7}, bytes({1})}, 0, {}));
    check(!missing->loaded && missing->state->recipe.macho->slice_index == 1,
          "removing the selected descriptor cannot auto-fall back to another slice");
    take(session->undo({}));
    session.reset();
    store.reset();
    clean_project(path);
}
} // namespace
int main() {
    return run([] {
        container_kind_patch(false);
        container_kind_patch(true);
        import_and_open();
        opening_contracts();
        persistent_fat_workflow();
        pinned_slice_changes();
    });
}
