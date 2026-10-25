#include "hexlab/workspace/open_recipe.hpp"
#include "hexlab/workspace/project_actor.hpp"
#include "hexlab/workspace/navigation.hpp"
#include "project_testing.hpp"
#include "support/elf_metadata_fixture.hpp"
#include "support/elf_retained_fixture.hpp"
#include "support/elf_dynamic_symbol_fixture.hpp"
#include "support/analysis_fixture.hpp"
#include "support/fixture_files.hpp"
#include "support/checks.hpp"
#include <chrono>
#include <semaphore>
#include <thread>
using namespace hexlab;
using namespace hexlab_test;
using namespace hexlab_test::elf_metadata_fixture;
using namespace std::chrono_literals;
namespace {
template <class T> T take(Result<T> value) {
    if (!value)
        throw std::runtime_error(value.error().message);
    return std::move(value.value());
}
ProjectReply reply(Result<ProjectSubmission> work) {
    auto submitted = take(std::move(work));
    if (submitted.result.wait_for(5s) != std::future_status::ready)
        throw std::runtime_error("ELF actor did not terminate");
    return take(submitted.result.get());
}
void routes() {
    for (bool wide : {false, true})
        for (bool big : {false, true}) {
            auto data = relocatable(wide, true, big);
            auto storage = std::make_shared<MemoryStorage>(data);
            check(static_cast<unsigned>(take(detect_format(*storage))) == 2,
                  "ELF magic selects appended ELF candidate");
            auto automatic = load_image(storage, {Format::automatic, {}}, {});
            check(automatic && automatic.value().metadata.elf.has_value(),
                  "automatic loader routes ELF32/64 both byte orders");
            FixtureFile file(data);
            OpenRequest request;
            request.path = file.path;
            request.run_analysis = false;
            auto document = load_document(request, {{19}, 7}, {});
            check(document && document.value()->metadata.elf && document.value()->id == DocumentId{19},
                  "inspection document shares automatic ELF loader");
            request.format = Format::elf;
            auto explicit_recipe = resolve_open_recipe(request, {});
            check(explicit_recipe && explicit_recipe.value().format == Format::elf,
                  "explicit ELF worker recipe accepted");
            request.raw = RawOptions{};
            check(!resolve_open_recipe(request, {}), "ELF cannot silently accept raw options");
        }
    auto truncated = std::make_shared<MemoryStorage>(bytes({0x7f, 0x45, 0x4c, 0x46}));
    check(static_cast<unsigned>(take(detect_format(*truncated))) == 2,
          "truncated ELF magic still routes to checked parser");
    auto bad = load_image(truncated, {Format::automatic, {}}, {});
    check(!bad && bad.error().code == ErrorCode::malformed, "malformed ELF never falls back to unknown/raw");
    check(take(encode_recipe({Format::elf, {}})) == bytes({1, 0, 4}),
          "ELF canonical durable recipe remains literal010004");
    check(take(encode_recipe({Format::pe, {}})) == bytes({1, 0, 2}), "PE durable recipe bytes preserved");
    std::stop_source stop;
    stop.request_stop();
    auto canceled = load_image(truncated, {Format::automatic, {}}, stop.get_token());
    check(!canceled && canceled.error().code == ErrorCode::canceled, "automatic ELF load honors pre-cancellation");
}
void imports() {
    for (bool wide : {false, true})
        for (auto format : {Format::automatic, Format::elf}) {
            FixtureFile file(relocatable(wide, true));
            OpenRequest request;
            request.path = file.path;
            request.format = format;
            auto actor = take(ProjectActor::create({{wide ? 41u : 40u}, 1}, std::make_shared<AnalysisPool>()));
            auto submitted = take(actor->import_binary(request));
            if (submitted.result.wait_for(5s) != std::future_status::ready)
                throw std::runtime_error("ELF import did not terminate");
            auto imported = submitted.result.get();
            check(bool(imported), "actor imports automatic and explicit ELF in worker");
            if (imported) {
                auto snapshot = imported.value().snapshot;
                check(snapshot && snapshot->state->recipe.format == Format::elf && snapshot->loaded &&
                          snapshot->loaded->metadata.elf,
                      "automatic import persists concrete ELF recipe and metadata");
                auto ready = reply(actor->ready());
                check(ready.snapshot->references && ready.snapshot->functions,
                      "worker analysis publishes ELF references/functions");
            }
            reply(actor->close());
        }
}
struct PersistentFixture {
    FixtureFile input;
    std::filesystem::path project = input.path.wstring() + L".hxproj", saved = input.path.wstring() + L".copy.hxproj",
                          exported = input.path.wstring() + L".export";
    std::shared_ptr<database::ProjectStore> store;
    std::shared_ptr<ProjectSession> session;
    explicit PersistentFixture(std::vector<std::byte> data) : input(data) {
        store = take(database::ProjectStore::create(project, {}));
        auto source = take(FileStorage::open(input.path));
        auto recipe = take(resolve_load_recipe(*source, {Format::automatic, {}}, {}));
        take(store->import_input(*source, recipe, input.path, {}));
        session = take(ProjectSession::attach(store, {}, {}));
    }
    ~PersistentFixture() {
        session.reset();
        store.reset();
        std::error_code ignored;
        for (auto path : {project, saved, exported})
            for (auto suffix : {L"", L"-wal", L"-shm"}) {
                auto item = path;
                item += suffix;
                std::filesystem::remove(item, ignored);
            }
    }
};
void mutations(bool wide, bool rela) {
    auto original = relocatable(wide, rela);
    PersistentFixture f(original);
    auto initial = f.session->snapshot();
    auto previous = initial->loader_parses;
    auto patched = take(f.session->execute(PatchBytes{FileOffset{3500}, bytes({0x56})}, 0, {}));
    check(patched->loader_parses == previous, "uninterpreted ELF file padding does not reparse metadata");
    take(f.session->undo({}));
    auto exercise = [&](std::uint64_t offset, std::vector<std::byte> replacement, auto verify, const char *message) {
        auto before = f.session->snapshot();
        auto after = take(f.session->execute(PatchBytes{FileOffset{offset}, std::move(replacement)}, 0, {}));
        check(after->loader_parses == before->loader_parses + 1 && verify(*after), message);
        check(before->loaded && before->loaded->metadata == initial->loaded->metadata,
              "retained pre-patch metadata snapshot stays immutable");
        auto undo = take(f.session->undo({}));
        check(undo->loaded && undo->loaded->metadata == initial->loaded->metadata,
              "undo restores exact ELF metadata facts");
    };
    exercise(
        0, bytes({0}), [](const auto &s) { return !s.loaded && s.status == DerivedStatus::file_only; },
        "ELF header corruption invalidates mappings instead of retaining stale facts");
    exercise(
        18, bytes({0, 0}),
        [](const auto &s) {
            return s.loaded && s.loaded->image->decode_context().architecture == Architecture::unknown;
        },
        "machine patch reparses ELF decoder context");
    exercise(
        strings_at + 1, bytes({0x43}),
        [](const auto &s) { return s.loaded && s.loaded->metadata.elf->symbols[1].name == "Callee"; },
        "symbol string patch refreshes declared names");
    std::vector<std::byte> value(wide ? 8 : 4);
    put(value, 0, 1, value.size());
    exercise(
        symbols_at + (wide ? 24 : 16) + (wide ? 8 : 4), value,
        [](const auto &s) { return s.loaded && s.loaded->metadata.elf->symbols[1].address == Address{{2}, 1}; },
        "symbol record patch refreshes section-domain address");
    std::vector<std::byte> info(wide ? 8 : 4);
    put(info, 0, wide ? (UINT64_C(2) << 32) | 2 : (2u << 8) | 2, info.size());
    exercise(
        relocations_at + (wide ? 8 : 4), info,
        [](const auto &s) { return s.loaded && s.loaded->metadata.elf->relocations[0].symbol_index == 2; },
        "relocation info patch refreshes exact symbol namespace index");
    if (rela) {
        std::vector<std::byte> addend(wide ? 8 : 4);
        put(addend, 0, UINT64_MAX - 2, addend.size());
        exercise(
            relocations_at + (wide ? 16 : 8), addend,
            [](const auto &s) { return s.loaded && s.loaded->metadata.elf->relocations[0].addend == -3; },
            "RELA explicit addend is a metadata dependency");
    } else
        exercise(
            257, bytes({0xfd}),
            [](const auto &s) { return s.loaded && s.loaded->metadata.elf->relocations[0].addend == -3; },
            "REL implicit encoded addend is a metadata dependency");
    // A non-relocated instruction byte is an analysis dependency, not ELF metadata.
    auto before = f.session->snapshot();
    patched = take(f.session->execute(PatchBytes{FileOffset{321}, bytes({0xcc})}, 0, {}));
    check(patched->loader_parses == before->loader_parses && patched->status == DerivedStatus::stale,
          "ordinary code patch invalidates analysis without reparsing ELF tables");
    take(f.session->undo({}));
    take(f.session->execute(Rename{Address{{1}, 0}, "owned_entry"}, 0, {}));
    take(f.session->execute(PatchBytes{FileOffset{strings_at + 1}, bytes({0x43})}, 0, {}));
    take(f.session->undo({}));
    take(f.session->redo({}));
    patched = take(f.session->refresh_analysis({}));
    check(patched->references && presentation_name(*patched, Address{{1}, 0}) == "owned_entry",
          "reanalysis after metadata edit preserves user presentation");
    auto expected = original;
    expected[strings_at + 1] = std::byte{0x43};
    auto receipt = take(export_patched(*patched, f.exported, database::ReplacePolicy::fail_if_exists, {}));
    auto exported = take(FileStorage::open(f.exported));
    auto exported_view = take(exported->read_at({0}, expected.size()));
    check(std::ranges::equal(exported_view.bytes, expected) && receipt.bytes == expected.size(),
          "ELF export contains exact canonical patched bytes");
    auto source = take(FileStorage::open(f.input.path));
    auto source_view = take(source->read_at({0}, original.size()));
    check(std::ranges::equal(source_view.bytes, original), "ELF metadata edits preserve original external bytes");
    source.reset();
    source_view = {};
    exported.reset();
    exported_view = {};
    auto copy = take(f.store->save_as(f.saved, database::ReplacePolicy::fail_if_exists, {}));
    check(copy.uuid != patched->state->uuid, "ELF Save As assigns independent UUID");
    auto state = patched->state;
    f.session.reset();
    f.store.reset();
    check(std::filesystem::remove(f.input.path), "ELF external source removed before readonly Save As reopen");
    f.store = take(database::ProjectStore::open(f.saved, database::ProjectMode::read_only, {}));
    f.session = take(ProjectSession::attach(f.store, {}, {}));
    auto reopened = f.session->snapshot();
    check(reopened->loaded && reopened->loaded->metadata.elf->symbols[1].name == "Callee" &&
              reopened->state->recipe.format == Format::elf,
          "source-missing readonly Save As retains concrete ELF recipe and patched metadata");
    check(reopened->state->revisions == state->revisions && reopened->state->history_cursor == state->history_cursor &&
              *reopened->state->user == *state->user,
          "ELF Save As reopen preserves history revisions and user state");
    check(reopened->derived_cache_status == database::CacheStatus::hit &&
              !f.session->execute(Comment{Address{{1}, 0}, "denied"}, 0, {}),
          "ELF readonly reopen adopts bound cache and rejects edits");
    std::stop_source stop;
    stop.request_stop();
    auto destination = f.exported.wstring() + L".canceled";
    auto canceled = export_patched(*reopened, destination, database::ReplacePolicy::fail_if_exists, stop.get_token());
    check(!canceled && canceled.error().code == ErrorCode::canceled && !std::filesystem::exists(destination),
          "canceled ELF export publishes no destination");
}
void cancellation() {
    FixtureFile input(bytes({0x7f, 0x45, 0x4c, 0x46}));
    OpenRequest request;
    request.path = input.path;
    SessionKey key{{88}, 1};
    auto actor = take(ProjectActor::create(key, std::make_shared<AnalysisPool>()));
    auto invalid = reply(actor->import_binary(request));
    check(invalid.snapshot && !invalid.snapshot->loaded && invalid.snapshot->status == DerivedStatus::file_only &&
              invalid.snapshot->state->recipe.format == Format::elf,
          "malformed ELF project preserves file-only bytes with concrete format and no guessed mapping");
    reply(actor->close());
    actor.reset();
    key = {{88}, 2};
    actor = take(ProjectActor::create(key, std::make_shared<AnalysisPool>()));
    struct Gate {
        std::promise<bool> entered;
        std::binary_semaphore released{0};
        std::atomic<bool> claimed = false, opened = false;
        void release() {
            if (!opened.exchange(true))
                released.release();
        }
    };
    auto gate = std::make_shared<Gate>();
    auto entered = gate->entered.get_future();
    auto caller = std::this_thread::get_id();
    struct Guard {
        SessionKey key;
        std::shared_ptr<Gate> gate;
        ~Guard() {
            gate->release();
            workspace_testing::clear_actor_hook(key);
        }
    } guard{key, gate};
    workspace_testing::set_actor_hook(key, [gate, caller](const auto &point) {
        if (point.phase == workspace_testing::ActorPhase::before_open && !gate->claimed.exchange(true)) {
            gate->entered.set_value(std::this_thread::get_id() != caller);
            gate->released.acquire();
        }
    });
    auto submitted = take(actor->import_binary(request));
    if (entered.wait_for(3s) != std::future_status::ready)
        throw std::runtime_error("ELF cancel barrier not reached");
    check(entered.get() && actor->cancel_operation(submitted.id), "ELF detection runs on cancelable actor worker");
    write_file(input.path, relocatable(true, true));
    gate->release();
    auto canceled = submitted.result.get();
    check(!canceled && canceled.error().code == ErrorCode::canceled && !actor->view().snapshot,
          "canceled ELF worker never adopts late mappings");
    workspace_testing::clear_actor_hook(key);
    auto retry = reply(actor->import_binary(request));
    check(retry.snapshot && retry.snapshot->state->recipe.format == Format::elf,
          "same worker retries ELF import after malformed and canceled attempts");
    reply(actor->close());
}
void dynamic_dependencies(bool wide) {
    namespace dyn = hexlab_test::elf_dynamic_symbol_fixture;
    auto original = dyn::fixture(wide, false, 3);
    const auto base = wide ? UINT64_C(0x100000000) : UINT64_C(0x10000);
    const auto word = wide ? 8u : 4u, stride = wide ? 24u : 12u;
    dyn::tag(original, wide, false, 6, 7, base + 5000);
    dyn::tag(original, wide, false, 7, 8, stride);
    dyn::tag(original, wide, false, 8, 9, stride);
    dyn::tag(original, wide, false, 9, 0, 0);
    program(original, wide, 1, 2, dyn::dynamic_at, base + dyn::dynamic_at, 10 * 2 * word, 10 * 2 * word, 6, word);
    put(original, 5000, base + 6000, word);
    put(original, 5000 + word, wide ? (UINT64_C(1) << 32) | 1 : (1u << 8) | 1, word);
    put(original, 5000 + 2 * word, 0, word);
    PersistentFixture f(original);
    auto initial = f.session->snapshot();
    check(initial->loaded && initial->loaded->metadata.elf->relocations.size() == 1,
          "sectionless dynamic project has canonical relocation without section headers");
    auto mutate = [&](std::uint64_t offset, std::vector<std::byte> replacement, auto verify, const char *name) {
        auto before = f.session->snapshot();
        auto after = take(f.session->execute(PatchBytes{FileOffset{offset}, std::move(replacement)}, 0, {}));
        check(after->loader_parses == before->loader_parses + 1 && verify(*after), name);
        auto undo = take(f.session->undo({}));
        check(undo->loaded && undo->loaded->metadata == initial->loaded->metadata,
              "undo restores sectionless dynamic metadata and source identity");
    };
    mutate(
        dyn::str + 1, bytes({0x44}),
        [](const auto &s) { return s.loaded && s.loaded->metadata.elf->symbols[1].name == "Defined"; },
        "dynamic string bytes invalidate sectionless symbol names");
    std::vector<std::byte> changed(word);
    put(changed, 0, base + 257, word);
    mutate(
        dyn::sym + (wide ? 24 : 16) + (wide ? 8 : 4), changed,
        [base](const auto &s) {
            return s.loaded && s.loaded->metadata.elf->symbols[1].address == Address{{0}, base + 257};
        },
        "dynamic symbol record patch refreshes declared address");
    mutate(
        dyn::sysv + 4, bytes({4, 0, 0, 0}),
        [](const auto &s) { return !s.loaded && s.status == DerivedStatus::file_only; },
        "inconsistent dynamic hash bounds cannot retain old symbols");
    changed.assign(word, std::byte{});
    put(changed, 0, base + original.size() + 16, word);
    mutate(
        dyn::dynamic_at + word, changed,
        [](const auto &s) { return !s.loaded && s.status == DerivedStatus::file_only; },
        "dynamic string pointer into unmapped gap invalidates metadata");
    changed.assign(word, std::byte{});
    put(changed, 0, 7, word);
    mutate(
        5000 + 2 * word, changed,
        [](const auto &s) { return s.loaded && s.loaded->metadata.elf->relocations[0].addend == 7; },
        "sectionless RELA addend is a registered metadata dependency");
    mutate(
        dyn::gnu + (wide ? 28 : 24), bytes({3, 0, 0, 0}),
        [](const auto &s) { return !s.loaded && s.status == DerivedStatus::file_only; },
        "GNU chain bound conflict invalidates sectionless dynamic metadata");
}
void indexed_metadata_rows() {
    for (bool wide : {false, true}) {
        const auto stride = wide ? 32u : 24u;
        PersistentFixture f(elf_dynamic_symbol_fixture::fixture(wide, false, 3, false, stride));
        const auto snapshot = f.session->snapshot();
        check(elf_symbol_record_at(*snapshot, 2) == FileOffset{elf_dynamic_symbol_fixture::sym + 2 * stride},
              "worker symbol index preserves padded physical record stride");
        check(!elf_symbol_record_at(*snapshot, 999), "indexed ELF symbol lookup checks row bounds");
        check(elf_dynamic_row_count(*snapshot) == 7, "worker exposes exact flattened dynamic row count");
        const auto row = elf_dynamic_row_at(*snapshot, 4);
        check(row && row->table == &snapshot->loaded->metadata.elf->dynamic_tables[0] && row->entry->tag == 4,
              "dynamic row lookup borrows exact immutable table/entry identity");
        check(!elf_dynamic_row_at(*snapshot, 999), "indexed dynamic lookup checks row bounds");
        auto split = elf_dynamic_symbol_fixture::fixture(wide);
        const auto minimum = wide ? 24u : 16u, extent = 3 * minimum;
        std::copy_n(split.begin() + elf_dynamic_symbol_fixture::sym + 20, extent - 20, split.begin() + 6000);
        const auto base = wide ? UINT64_C(0x100000000) : UINT64_C(0x10000);
        program(split, wide, 0, 1, 0, base, elf_dynamic_symbol_fixture::sym + 20, elf_dynamic_symbol_fixture::sym + 20,
                5, 1);
        program(split, wide, 2, 1, 6000, base + elf_dynamic_symbol_fixture::sym + 20, extent - 20, extent - 20, 4, 1);
        PersistentFixture split_project(split);
        check(elf_symbol_record_at(*split_project.session->snapshot(), 2) == FileOffset{6000 + 2 * minimum - 20},
              "symbol source navigation uses canonical discontiguous virtual backing");
        auto multiple = elf_dynamic_symbol_fixture::fixture(wide, false, 3);
        const auto table_size = 7 * (wide ? 16u : 8u);
        std::copy_n(multiple.begin() + elf_dynamic_symbol_fixture::dynamic_at, table_size, multiple.begin() + 7000);
        program(multiple, wide, 2, 2, 7000, base + 7000, table_size, table_size, 6, wide ? 8 : 4);
        PersistentFixture multiple_project(multiple);
        const auto second = elf_dynamic_row_at(*multiple_project.session->snapshot(), 7);
        check(elf_dynamic_row_count(*multiple_project.session->snapshot()) == 14 && second &&
                  second->table->source.file_offset == 7000 && second->entry->index == 0 && second->entry->tag == 5,
              "flattened metadata index preserves nonfirst dynamic table source identity");
    }
}
} // namespace
int main() {
    return run([] {
        for (bool wide : {false, true})
            for (bool rela : {false, true}) {
                PersistentFixture f(retained(wide, rela));
                auto verify = [&](const auto &snapshot) {
                    const auto &calls = snapshot->functions->calls;
                    check(std::any_of(calls.begin(), calls.end(),
                                      [](const auto &row) {
                                          return row.source == Address{{0}, 0x400000} &&
                                                 row.target == Address{{0}, 0x400006};
                                      }),
                          "persistent retained relocations preserve actual linked CALL target");
                };
                verify(take(f.session->refresh_analysis({})));
                f.session.reset();
                f.store.reset();
                std::filesystem::remove(f.input.path);
                f.store = take(database::ProjectStore::open(f.project, database::ProjectMode::read_only, {}));
                f.session = take(ProjectSession::attach(f.store, {}, {}));
                verify(take(f.session->refresh_analysis({})));
            }
        for (std::uint32_t count : {4095u, 4096u, 4100u}) {
            PersistentFixture f(many_domains(count));
            auto snapshot = take(f.session->refresh_analysis({}));
            check(snapshot->functions && snapshot->loaded->image->layout().domains.size() == count,
                  "persistent ELF analysis accepts section-domain counts across the old4096 boundary");
            check(bool(snapshot->loaded->image->context_at({{count}, 0})),
                  "nonfirst section-domain navigation retains its decode context");
            f.session.reset();
            f.store.reset();
            std::filesystem::remove(f.input.path);
            f.store = take(database::ProjectStore::open(f.project, database::ProjectMode::read_only, {}));
            f.session = take(ProjectSession::attach(f.store, {}, {}));
            snapshot = take(f.session->refresh_analysis({}));
            check(snapshot->functions && snapshot->derived_cache_status == database::CacheStatus::hit,
                  "large-domain derived cache reopens read-only without external source");
        }
        routes();
        imports();
        for (bool wide : {false, true}) {
            for (bool rela : {false, true})
                mutations(wide, rela);
            dynamic_dependencies(wide);
        }
        cancellation();
        indexed_metadata_rows();
    });
}
