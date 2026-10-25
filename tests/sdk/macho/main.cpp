#include "hexlab/workspace/project.hpp"
#include "hexlab/workspace/macho_presentation.hpp"
#include "hexlab/workspace/navigation.hpp"
#include "hexlab/workspace/export.hpp"
#include "hexlab/analysis/macho_dyld.hpp"
#include "hexlab/analysis/macho_relocations.hpp"
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
namespace {
template <class T> T take(Result<T> value) {
    if (!value)
        throw std::runtime_error(value.error().message);
    return std::move(value.value());
}
void require(bool value, const char *reason) {
    if (!value)
        throw std::runtime_error(reason);
}
void write(const std::filesystem::path &path, std::span<const std::byte> bytes) {
    std::ofstream file(path, std::ios::binary);
    file.write(reinterpret_cast<const char *>(bytes.data()), static_cast<std::streamsize>(bytes.size()));
    require(bool(file), "Cannot write SDK-owned input");
}
void project(const std::filesystem::path &fixture, const std::filesystem::path &root, bool wide,
             std::optional<std::uint32_t> slice, bool undefined = false) {
    auto source = take(FileStorage::open(fixture));
    const auto original_hash = take(hash_source(*source, {}));
    const auto bytes = take(source->read_at({0}, static_cast<std::size_t>(source->size())));
    const auto owned = root / (fixture.filename().wstring() + L".owned");
    const auto database_path = root / (fixture.filename().wstring() + L".hxproj");
    const auto saved = root / (fixture.filename().wstring() + L".saved.hxproj");
    const auto exported = root / (fixture.filename().wstring() + L".exported");
    write(owned, bytes.bytes);
    LoadRecipe requested{Format::automatic, {}, slice ? std::optional{MachOOptions{*slice}} : std::nullopt};
    const auto recipe = take(resolve_load_recipe(*source, requested, {}));
    require(recipe.format == Format::macho, "Installed automatic detector missed Mach-O");
    const auto wire = take(encode_recipe(recipe));
    std::vector<std::byte> expected_recipe{std::byte{1}, std::byte{0}, std::byte{5},
                                           slice ? std::byte{1} : std::byte{0}};
    if (slice)
        for (int shift : {24, 16, 8, 0})
            expected_recipe.push_back(std::byte(*slice >> shift));
    require(wire == expected_recipe, "Installed concrete slice recipe changed");
    auto loaded = take(load_durable_image(source, recipe, {}));
    const auto &metadata = *loaded.metadata.macho;
    const auto selected = slice.value_or(0);
    const auto offset = metadata.container.slices.at(selected).offset;
    require(metadata.selected_slice == selected && metadata.container.slices[selected].header.is_64 == wide &&
                metadata.container.slices[selected].header.cpu_type == (wide ? 0x01000007u : 7u),
            "Installed durable class/full CPU/slice mismatch");
    auto store = take(database::ProjectStore::create(database_path, {}));
    {
        auto input = take(FileStorage::open(owned));
        take(store->import_input(*input, recipe, owned, {}));
    }
    auto session = take(ProjectSession::attach(store, {}, {}));
    auto snapshot = session->snapshot();
    require(presentation_name(*snapshot, Address{{1}, 0}) == "_same" &&
                presentation_name(*snapshot, Address{{2}, 0}) == "_same",
            "Installed equal-address object domains collapsed");
    const auto page = take(make_macho_metadata_page(*snapshot, 0, 256, {}));
    require(page.total == macho_metadata_row_count(*snapshot) && page.rows.size() == page.total,
            "Installed public worker metadata page missing");
    bool undefined_record = false;
    for (const auto &row : page.rows)
        if (row.kind == MachOMetadataKind::symbol && row.index == 2)
            undefined_record = row.source == FileOffset{offset + 1536 + 2 * (wide ? 16u : 12u)};
    require(undefined_record && !make_macho_metadata_page(*snapshot, 0, 257, {}),
            "Installed metadata source index or page bound mismatch");
    if (!slice) {
        const auto followed = take(project_follow_target(*snapshot, {{1}, 0}));
        require(undefined ? !followed : followed == Address{{2}, 0},
                "Installed Follow invented undefined target or lost relocation domain");
        const MachOSymbolIdentity identity{0, {0}, 1, {1536}, undefined ? 2u : 1u};
        const auto resolver = take(MachORelocationResolver::create(loaded.metadata, {}));
        const auto fact = std::ranges::find_if(snapshot->functions->instructions, [](const auto &row) {
            return row->instruction.address == Address{{1}, 0};
        });
        require(fact != snapshot->functions->instructions.end(), "Installed caller instruction fact missing");
        const auto operand = take(resolver.operand((*fact)->instruction, 0, {}));
        require(operand.relocations == std::vector<std::uint64_t>{0} &&
                    operand.reason ==
                        (undefined ? MachOResolutionReason::undefined_symbol : MachOResolutionReason::resolved) &&
                    (undefined ? !operand.address : operand.address == Address{{2}, 0}) &&
                    take(resolver.control_target(*loaded.image, (*fact)->instruction, {})) == followed &&
                    resolver.symbol(0) && resolver.symbol(0)->index == identity.index && !resolver.symbol(99),
                "Installed public relocation resolver lost source binding, namespace or bounds");
        const auto references = take(snapshot->references->incoming_macho_symbol(identity, {}));
        require(references.total == 1 && references.rows.size() == 1,
                "Installed decoded reference symbol namespace count mismatch");
        const auto &reference = references.rows.front();
        require(reference.kind == ReferenceKind::call && reference.source == Location{Address{{1}, 0}} &&
                    reference.operand_index == 0 && reference.provenance.instruction_id != 0 &&
                    reference.provenance.macho && reference.provenance.macho->origins.size() == 1 &&
                    reference.provenance.macho->origins[0].symbol &&
                    reference.provenance.macho->origins[0].symbol->index == identity.index &&
                    reference.provenance.macho->origins[0].relocation.record_file_offset == 3072,
                "Installed decoded call lost original relocation proof or source domain");
    }
    take(session->execute(Rename{Address{{1}, 0}, "sdk_owner"}, 0, {}));
    take(session->execute(Comment{FileOffset{offset + 2049}, "public SDK metadata edit"}, 0, {}));
    take(session->execute(PatchBytes{FileOffset{offset + 2049}, {std::byte{0x58}}}, 0, {}));
    require(presentation_name(*session->snapshot(), Address{{2}, 0}) == "Xsame",
            "Installed metadata patch did not refresh names");
    take(session->undo({}));
    require(presentation_name(*session->snapshot(), Address{{2}, 0}) == "_same", "Installed Undo lost original name");
    take(session->redo({}));
    auto expected = std::vector<std::byte>(bytes.bytes.begin(), bytes.bytes.end());
    expected[static_cast<std::size_t>(offset + 2049)] = std::byte{0x58};
    if (slice) {
        const auto unselected = selected == 0 ? 8192u : 4096u;
        const auto parses = session->snapshot()->loader_parses;
        take(session->execute(PatchBytes{FileOffset{unselected + 800u}, {std::byte{0x5a}}}, 0, {}));
        require(session->snapshot()->loader_parses == parses &&
                    session->snapshot()->loaded->metadata.macho->selected_slice == selected,
                "Installed ordinary unselected byte reparsed metadata or changed saved slice");
        expected[unselected + 800u] = std::byte{0x5a};
        const auto before_kind = session->snapshot();
        const auto &header = metadata.container.slices[selected].header;
        const auto thin_prefix = take(source->read_at({offset}, (wide ? 32u : 28u) + header.command_bytes));
        const auto invalid = take(session->execute(
            PatchBytes{FileOffset{0}, std::vector<std::byte>(thin_prefix.bytes.begin(), thin_prefix.bytes.end())}, 0,
            {}));
        require(!invalid->loaded && invalid->status == DerivedStatus::file_only &&
                    macho_metadata_row_count(*invalid) == 0 &&
                    take(encode_recipe(invalid->state->recipe)) == expected_recipe &&
                    invalid->state->uuid == before_kind->state->uuid,
                "Installed kind change silently switched mapping or retained stale metadata");
        take(session->undo({}));
        require(session->snapshot()->loaded->metadata.macho->selected_slice == selected,
                "Installed kind Undo lost bound slice");
    }
    snapshot = take(session->refresh_analysis({}));
    require(!export_patched(*snapshot, owned, database::ReplacePolicy::replace_existing, {}),
            "Installed export overwrote protected source");
    take(export_patched(*snapshot, exported, database::ReplacePolicy::fail_if_exists, {}));
    {
        auto output = take(FileStorage::open(exported));
        const auto actual = take(output->read_at({0}, expected.size()));
        require(output->size() == expected.size() && std::ranges::equal(actual.bytes, expected),
                "Installed whole-container export changed extra bytes");
    }
    const auto state = snapshot->state;
    const auto copy = take(store->save_as(saved, database::ReplacePolicy::fail_if_exists, {}));
    require(copy.uuid != state->uuid, "Installed Save As reused project UUID");
    session.reset();
    store.reset();
    require(std::filesystem::remove(owned), "Cannot remove SDK-owned source");
    store = take(database::ProjectStore::open(saved, database::ProjectMode::read_only, {}));
    session = take(ProjectSession::attach(store, {}, {}));
    snapshot = session->snapshot();
    require(snapshot->state->uuid == copy.uuid && snapshot->state->revisions == state->revisions &&
                snapshot->state->history_cursor == state->history_cursor && *snapshot->state->user == *state->user &&
                take(encode_recipe(snapshot->state->recipe)) == expected_recipe &&
                snapshot->derived_cache_status == database::CacheStatus::hit &&
                presentation_name(*snapshot, Address{{1}, 0}) == "sdk_owner" &&
                presentation_name(*snapshot, Address{{2}, 0}) == "Xsame",
            "Installed embedded readonly reopen lost history/user/cache/slice/name identity");
    require(!session->execute(Rename{Address{{1}, 0}, "denied"}, 0, {}),
            "Installed readonly project accepted mutation");
    require(take(hash_source(*source, {})) == original_hash, "SDK analysis changed fixture source");
    std::cout
        << fixture.filename().string()
        << ": bound recipe, indexed metadata, names, references, edits/export/SaveAs/embedded readonly cache passed\n";
}
void modules(const std::filesystem::path &prefix) {
#ifdef _WIN32
    for (const auto *name :
         {L"hexlab_core.dll", L"hexlab_image.dll", L"hexlab_processors.dll", L"hexlab_loaders.dll",
          L"hexlab_analysis.dll", L"hexlab_database.dll", L"hexlab_workspace.dll", L"hexlab_sqlite3.dll"}) {
        const auto module = GetModuleHandleW(name);
        require(module != nullptr, "Installed SDK module missing");
        std::wstring path(32768, L'\0');
        const auto size = GetModuleFileNameW(module, path.data(), static_cast<DWORD>(path.size()));
        require(size && size < path.size(), "Cannot inspect installed SDK module path");
        path.resize(size);
        require(std::filesystem::equivalent(std::filesystem::path(path).parent_path(), prefix / "bin"),
                "SDK resolved runtime outside installed bin");
        std::wcout << name << L" -> " << path << L'\n';
    }
#endif
}
} // namespace
int wmain(int argc, wchar_t **argv) {
    try {
        require(argc == 4, "Expected installed fixture directory, artifacts and prefix");
        const auto fixtures = std::filesystem::path(argv[1]);
        const auto root = std::filesystem::path(argv[2]) /
                          std::to_string(std::chrono::steady_clock::now().time_since_epoch().count());
        std::filesystem::create_directories(root);
        std::cout << "SDK artifacts: " << root.string() << '\n';
        for (bool wide : {false, true}) {
            project(fixtures / (wide ? "call64.o" : "call32.o"), root, wide, {});
            project(fixtures / (wide ? "undefined-call64.o" : "undefined-call32.o"), root, wide, {}, true);
        }
        for (std::uint32_t slice : {0, 1}) {
            const auto directory = root / std::to_string(slice);
            std::filesystem::create_directories(directory);
            for (const auto *name : {"fat32.macho", "fat64-swapped.macho"})
                project(fixtures / name, directory, slice == 1, slice);
        }
        for (const auto *name : {"classic64.macho", "chained64.macho", "protected64.macho", "big64.macho"}) {
            auto loaded = take(load_macho(take(FileStorage::open(fixtures / name)), {}, {}));
            require(loaded.metadata.macho.has_value(), "Installed original metadata missing");
            const auto &m = *loaded.metadata.macho;
            if (std::string_view(name) == "classic64.macho" || std::string_view(name) == "chained64.macho") {
                const auto resolver = take(MachODyldResolver::create(*loaded.image, loaded.metadata, {}));
                const auto kind = m.chained_pointers.empty() ? MachODyldSource::classic : MachODyldSource::chained;
                const auto rebase = take(resolver.data({kind, 0}, {}));
                const auto binding = take(resolver.data({kind, 1}, {}));
                const Address slot{{0}, UINT64_C(0x100000000)};
                require(rebase.reason == MachODyldResolutionReason::resolved &&
                            rebase.address == Address{{0}, UINT64_C(0x100000008)} &&
                            take(resolver.slot(slot, 8, {})).address == rebase.address &&
                            binding.reason == MachODyldResolutionReason::runtime_binding && !binding.address &&
                            binding.binding && binding.binding->name == "_ext" && binding.binding->library_ordinal == 1,
                        "Installed public dyld resolver confused slot/preferred pointer or invented a runtime target");
            }
            if (std::string_view(name) == "classic64.macho")
                require(m.dyld_fixups.size() == 2 && m.dyld_exports.size() == 1 && m.dyld_exports[0].is_definition(),
                        "Installed classic dyld/export mismatch");
            if (std::string_view(name) == "chained64.macho")
                require(m.chained_imports.size() == 1 && m.chained_pointers.size() == 2,
                        "Installed chained metadata mismatch");
            if (std::string_view(name) == "protected64.macho")
                require(m.encryption.size() == 1 && m.data_in_code.size() == 1 && m.code_signatures.size() == 1 &&
                            !loaded.image->layout().encrypted_ranges.empty(),
                        "Installed original protection declarations missing");
            if (std::string_view(name) == "big64.macho")
                require(m.container.slices[0].header.order == ByteOrder::big,
                        "Installed unsupported-byte-order metadata missing");
        }
        modules(argv[3]);
        std::cout << "Installed public Mach-O SDK consumer passed; input files never executed\n";
        return 0;
    } catch (const std::exception &error) {
        std::cerr << error.what() << '\n';
        return 1;
    }
}
