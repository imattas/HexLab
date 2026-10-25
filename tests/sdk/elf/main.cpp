#include "hexlab/loaders/elf.hpp"
#include "hexlab/analysis/elf_relocations.hpp"
#include "hexlab/workspace/project.hpp"
#include "hexlab/workspace/navigation.hpp"
#include "hexlab/workspace/export.hpp"
#include <algorithm>
#include <chrono>
#include <fstream>
#include <iostream>
#ifdef _WIN32
#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <windows.h>
#endif
using namespace hexlab;
template <class T> T take(Result<T> value) {
    if (!value)
        throw std::runtime_error(value.error().message);
    return std::move(value.value());
}
void require(bool condition, const char *why) {
    if (!condition)
        throw std::runtime_error(why);
}
void object(const std::filesystem::path &input, const std::filesystem::path &root, bool wide) {
    auto source = take(FileStorage::open(input));
    auto source_hash = take(hash_source(*source, {}));
    auto recipe = take(resolve_load_recipe(*source, {Format::automatic, {}}, {}));
    require(recipe.format == Format::elf, "Installed detector did not select ELF");
    require(take(encode_recipe(recipe)) == std::vector<std::byte>({std::byte{1}, std::byte{0}, std::byte{4}}),
            "Installed durable ELF recipe changed");
    auto loaded = take(load_image(source, recipe, {}));
    require(loaded.metadata.elf && loaded.metadata.elf->header.is_64 == wide, "Installed class metadata mismatch");
    const auto owned = root / (wide ? "owned64.o" : "owned32.o"),
               project = root / (wide ? "object64.hxproj" : "object32.hxproj"),
               saved = root / (wide ? "saved64.hxproj" : "saved32.hxproj"),
               exported = root / (wide ? "patched64.o" : "patched32.o");
    auto original = take(source->read_at({0}, static_cast<std::size_t>(source->size())));
    {
        std::ofstream file(owned, std::ios::binary);
        file.write(reinterpret_cast<const char *>(original.bytes.data()),
                   static_cast<std::streamsize>(original.bytes.size()));
        require(bool(file), "Cannot create SDK-owned original");
    }
    auto store = take(database::ProjectStore::create(project, {}));
    {
        auto owner = take(FileStorage::open(owned));
        take(store->import_input(*owner, recipe, owned, {}));
    }
    auto session = take(ProjectSession::attach(store, {}, {}));
    auto snapshot = session->snapshot();
    require(take(project_follow_target(*snapshot, {{1}, 0})) == Address{{2}, 0},
            "Installed Follow lost section-domain ELF target");
    require(elf_symbol_record_at(*snapshot, 2) == FileOffset{1024 + 2 * (wide ? 24u : 16u)},
            "Installed undefined symbol record index mismatch");
    require(snapshot->references->incoming_elf_symbol({{5, 1024, {}}, 1}, {}).value().total == 1,
            "Installed ELF symbol namespace query mismatch");
    take(session->execute(Rename{Address{{1}, 0}, "sdk_caller"}, 0, {}));
    take(session->execute(Rename{Address{{2}, 0}, "sdk_callee"}, 0, {}));
    take(session->execute(PatchBytes{FileOffset{257}, {std::byte{0xfd}}}, 0, {}));
    take(session->undo({}));
    require(session->snapshot()->effective->read_at({257}, 1).value().bytes[0] == std::byte{0xfc},
            "Installed Undo did not restore original field");
    take(session->redo({}));
    snapshot = take(session->refresh_analysis({}));
    require(take(project_follow_target(*snapshot, {{1}, 0})) == Address{{2}, 0},
            "RELA explicit provenance was replaced by patched placeholder bytes");
    require(!export_patched(*snapshot, owned, database::ReplacePolicy::replace_existing, {}),
            "Installed export allowed replacing protected original");
    take(export_patched(*snapshot, exported, database::ReplacePolicy::fail_if_exists, {}));
    auto expected = std::vector<std::byte>(original.bytes.begin(), original.bytes.end());
    expected[257] = std::byte{0xfd};
    auto result = take(FileStorage::open(exported));
    const auto result_bytes = take(result->read_at({0}, expected.size()));
    require(std::ranges::equal(result_bytes.bytes, expected), "Installed ELF export differs beyond exact patch");
    auto copy = take(store->save_as(saved, database::ReplacePolicy::fail_if_exists, {}));
    require(copy.uuid != snapshot->state->uuid, "Installed Save As reused owner UUID");
    auto state = snapshot->state;
    session.reset();
    store.reset();
    require(std::filesystem::remove(owned), "Cannot remove SDK-owned source");
    store = take(database::ProjectStore::open(saved, database::ProjectMode::read_only, {}));
    session = take(ProjectSession::attach(store, {}, {}));
    snapshot = session->snapshot();
    require(snapshot->state->uuid == copy.uuid && snapshot->state->revisions == state->revisions &&
                snapshot->state->history_cursor == state->history_cursor && *snapshot->state->user == *state->user,
            "Installed readonly reopen lost identity/history/user state");
    require(snapshot->derived_cache_status == database::CacheStatus::hit &&
                presentation_name(*snapshot, Address{{1}, 0}) == "sdk_caller" &&
                presentation_name(*snapshot, Address{{2}, 0}) == "sdk_callee",
            "Installed source-missing reopen did not preserve bound cache and domain annotations");
    require(!session->execute(Comment{Address{{1}, 0}, "denied"}, 0, {}),
            "Installed readonly project accepted mutation");
    require(take(hash_source(*source, {})) == source_hash, "Installed analysis modified external ELF input");
    std::cout
        << (wide ? "ELF64" : "ELF32")
        << ": domains, provenance, source records, edits/history/export/SaveAs/missing-source readonly cache passed\n";
}
int wmain(int argc, wchar_t **argv) {
    try {
        require(argc == 6, "Expected object32 object64 shared64 artifacts prefix");
        const auto root = std::filesystem::path(argv[4]) /
                          std::to_string(std::chrono::steady_clock::now().time_since_epoch().count());
        std::filesystem::create_directories(root);
        object(argv[1], root, false);
        object(argv[2], root, true);
        auto loaded = take(load_elf(take(FileStorage::open(argv[3])), {}));
        require(loaded.metadata.elf && loaded.metadata.elf->header.object_type == 3 &&
                    loaded.metadata.elf->sections.empty(),
                "Installed sectionless DYN failed");
        auto store = take(database::ProjectStore::create(root / "dynamic.hxproj", {}));
        auto input = take(FileStorage::open(argv[3]));
        take(store->import_input(*input, {Format::elf, {}}, {}, {}));
        auto session = take(ProjectSession::attach(store, {}, {}));
        auto row = elf_dynamic_row_at(*session->snapshot(), 6);
        require(elf_dynamic_row_count(*session->snapshot()) == 10 && row && row->entry->tag == 1 &&
                    row->entry->string_value == "libfixture.so",
                "Installed dynamic worker row source/NEEDED mismatch");
#ifdef _WIN32
        for (const auto *name :
             {L"hexlab_core.dll", L"hexlab_image.dll", L"hexlab_processors.dll", L"hexlab_loaders.dll",
              L"hexlab_analysis.dll", L"hexlab_database.dll", L"hexlab_workspace.dll", L"hexlab_sqlite3.dll"}) {
            auto module = GetModuleHandleW(name);
            require(module != nullptr, "Installed SDK runtime module missing");
            std::wstring path(32768, L'\0');
            auto count = GetModuleFileNameW(module, path.data(), static_cast<DWORD>(path.size()));
            require(count && count < path.size(), "Cannot inspect installed SDK module path");
            path.resize(count);
            require(std::filesystem::equivalent(std::filesystem::path(path).parent_path(),
                                                std::filesystem::path(argv[5]) / "bin"),
                    "SDK runtime resolved outside installed bin");
            std::wcout << name << L" -> " << path << L'\n';
        }
#endif
        std::cout << "Installed public ELF SDK consumer passed; ELF inputs never executed\n";
        return 0;
    } catch (const std::exception &error) {
        std::cerr << error.what() << '\n';
        return 1;
    }
}
