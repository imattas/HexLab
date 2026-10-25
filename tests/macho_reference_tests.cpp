#include "hexlab/analysis/references.hpp"
#include "hexlab/analysis/derived_cache.hpp"
#include "hexlab/loaders/macho.hpp"
#include "hexlab/workspace/project.hpp"
#include "hexlab/workspace/navigation.hpp"
#include "support/macho_relocation_fixture.hpp"
#include "support/analysis_fixture.hpp"
#include "support/fixture_files.hpp"
#include "support/checks.hpp"
#include <algorithm>
using namespace hexlab;
using namespace hexlab_test;
using namespace hexlab_test::macho_fixture;
namespace {
template <class T> T take(Result<T> value) {
    if (!value)
        throw std::runtime_error(value.error().message);
    return std::move(value.value());
}
void source_binding() {
    for (bool defined : {false, true}) {
        auto data = relocated(true);
        symbol(data, true, false, 8, 52, 0x0f, 2, 0x80, 0x100);
        relocation(data, false, 0, 1, defined ? 1 : 2, 2, 2, true, true);
        auto loaded = take(load_macho(std::make_shared<MemoryStorage>(data), {}, {}));
        const auto functions = take(recover_functions(*loaded.image, loaded.metadata, {}, {}, {}));
        const auto refs = take(derive_references(*loaded.image, *functions, loaded.metadata, {}, {}));
        const auto page = take(refs->outgoing(Address{{1}, 0}, {}));
        check(page.total == 1, "one object CALL has one authoritative relocation reference");
        if (page.rows.size() != 1)
            continue;
        const auto &row = page.rows[0];
        check(row.provenance.kind == ReferenceProvenanceKind::macho_relocation && row.provenance.macho &&
                  !row.provenance.elf && row.provenance.macho->origins.size() == 1,
              "Mach-O source origin is owned and distinctly typed");
        if (!row.provenance.macho)
            continue;
        const auto &origin = row.provenance.macho->origins[0];
        check(origin.relocation == loaded.metadata.macho->relocations[0] &&
                  origin.table == loaded.metadata.macho->relocation_tables[0] && origin.symbol &&
                  origin.symbol->index == (defined ? 1u : 2u) && origin.symbol_table &&
                  origin.symbol_table->symbol_offset == FileOffset{symbols_at},
              "owned reference preserves full original record/table/symbol namespace and values");
        check(take(refs->incoming(Address{{2}, 0}, {})).total == (defined ? 1 : 0) &&
                  take(refs->incoming(Address{{1}, 5}, {})).total == 0,
              "incoming references index declared callee while suppressing placeholder address");
        MachOSymbolIdentity identity{0, {0}, 1, {symbols_at}, defined ? 1u : 2u};
        check(take(refs->incoming_macho_symbol(identity, {})).total == 1,
              "undefined and defined Mach-O symbols have namespaced indexed reference queries");
        const auto wire = take(encode_reference_index(*refs, {}));
        const auto decoded = take(decode_reference_index(wire, {}));
        check(take(encode_reference_index(*decoded, {})) == wire &&
                  decoded->all()[0].provenance.macho == row.provenance.macho,
              "owned Mach-O provenance roundtrips canonically without borrowed metadata");
        auto forged = std::vector<Reference>(refs->all().begin(), refs->all().end());
        forged[0].id = {0};
        forged[0].provenance.macho->origins[0].symbol->index += 1;
        check(!ReferenceIndex::create(forged, {}, true, {}),
              "symbol copy cannot escape original nlist namespace/index");
    }
}
void empty_names_and_pairs() {
    auto data = relocated(true);
    put(data, symtab_command(true) + 12, 2, 4, false);
    put(data, symtab_command(true) + 20, 0, 4, false);
    symbol(data, true, false, 0, 0, 0x0f, 1, 0, 0x100);
    symbol(data, true, false, 1, 0, 0x0f, 2, 0, 0x100);
    auto loaded = take(load_macho(std::make_shared<MemoryStorage>(data), {}, {}));
    const auto functions = take(recover_functions(*loaded.image, loaded.metadata, {}, {}, {}));
    const auto refs = derive_references(*loaded.image, *functions, loaded.metadata, {}, {});
    check(bool(refs), "n_strx0 remains valid with an empty string table in owned reference metadata");
    data = relocated(true);
    relocation_count(data, true, false, 2);
    relocation(data, false, 0, 0, 0, 5, 3, false, true);
    relocation(data, false, 1, 0, 8, 0, 3, false, true);
    symbol(data, true, false, 8, 52, 0x0f, 1, 0, 0x102);
    put(data, 768, 10, 8, false);
    loaded = take(load_macho(std::make_shared<MemoryStorage>(data), {}, {}));
    const FunctionSnapshot empty;
    const auto raw = take(derive_references(*loaded.image, empty, loaded.metadata, {}, {}));
    check(raw->all().size() == 1 && raw->all()[0].provenance.macho && raw->all()[0].provenance.macho->constant == 12 &&
              std::holds_alternative<UnresolvedTarget>(raw->all()[0].target),
          "paired subtractor has one owned scalar reference without fabricated pointer address");
    auto forged = std::vector<Reference>(raw->all().begin(), raw->all().end());
    forged[0].id = {0};
    forged[0].provenance.macho->constant = 13;
    check(!ReferenceIndex::create(forged, {}, true, {}),
          "copied constant must agree with original same-domain subtractor equation");
    forged[0] = raw->all()[0];
    forged[0].id = {0};
    std::reverse(forged[0].provenance.macho->origins.begin(), forged[0].provenance.macho->origins.end());
    check(!ReferenceIndex::create(forged, {}, true, {}),
          "reordered pair origins cannot create a second canonical reference identity");
}
void project_follow() {
    auto data = relocated(true);
    symbol(data, true, false, 8, 52, 0x0f, 2, 0x80, 0x100);
    FixtureFile input(data);
    const auto path = std::filesystem::path(input.path.wstring() + L".macho-reference.hxproj");
    auto store = take(database::ProjectStore::create(path, {}));
    auto source = take(FileStorage::open(input.path));
    take(store->import_input(*source, {Format::macho, {}, {}}, input.path, {}));
    source.reset();
    auto session = take(ProjectSession::attach(store, {}, {}));
    auto snapshot = session->snapshot();
    check(take(project_follow_target(*snapshot, Address{{1}, 0})) == Address{{2}, 0},
          "actual project Follow uses source-bound Mach-O reference target");
    const auto uuid = snapshot->state->uuid;
    take(session->execute(PatchBytes{FileOffset{relocations_at + 4}, bytes({2, 0, 0, 0x2d})}, 0, {}));
    snapshot = session->snapshot();
    const auto stale = project_follow_target(*snapshot, Address{{1}, 0});
    check(!stale && stale.error().code == ErrorCode::conflict,
          "accepted relocation patch makes old project Follow unavailable until current analysis completes");
    snapshot = take(session->refresh_analysis({}));
    check(!take(project_follow_target(*snapshot, Address{{1}, 0})),
          "metadata relocation symbol patch invalidates actual project Follow without exposing placeholder");
    take(session->undo({}));
    snapshot = take(session->refresh_analysis({}));
    check(take(project_follow_target(*snapshot, Address{{1}, 0})) == Address{{2}, 0} && snapshot->state->uuid == uuid,
          "undo recomputes original provenance and restores source-bound Follow with same project UUID");
    session.reset();
    store.reset();
    check(std::filesystem::remove(input.path), "owned external Mach-O source removed before readonly cache proof");
    store = take(database::ProjectStore::open(path, database::ProjectMode::read_only, {}));
    session = take(ProjectSession::attach(store, {}, {}));
    snapshot = session->snapshot();
    check(snapshot->derived_cache_status == database::CacheStatus::hit && snapshot->state->uuid == uuid &&
              take(project_follow_target(*snapshot, Address{{1}, 0})) == Address{{2}, 0} &&
              take(snapshot->references->incoming_macho_symbol({0, {0}, 1, {symbols_at}, 1}, {})).total == 1,
          "source-missing readonly project restores actual Mach-O provenance, indexed symbols and source-bound Follow "
          "from cache");
    session.reset();
    store.reset();
    std::error_code ignored;
    for (auto suffix : {L"", L"-wal", L"-shm"}) {
        auto file = path;
        file += suffix;
        std::filesystem::remove(file, ignored);
    }
}
void cache_forgery_and_memory() {
    auto data = relocated(true);
    symbol(data, true, false, 8, 52, 0x0f, 2, 0x80, 0x100);
    auto loaded = take(load_macho(std::make_shared<MemoryStorage>(data), {}, {}));
    AnalysisKey key;
    key.input = {loaded.image->storage()->size(), take(hash_source(*loaded.image->storage(), {}))};
    key.engine_fingerprint = function_engine_fingerprint();
    const auto proposal =
        take(analyze_derived(loaded.image, std::make_shared<const ImageMetadata>(loaded.metadata), {}, {}, key, {}));
    auto forged = proposal;
    std::vector<Reference> rows(proposal.references->all().begin(), proposal.references->all().end());
    rows[0].id = {0};
    rows[0].provenance.macho->origins[0].symbol->name = "forged";
    forged.references = take(ReferenceIndex::create(rows, key, proposal.references->complete(), {}));
    const auto wire = take(encode_derived(forged, {}));
    check(!decode_derived(wire, *loaded.image, loaded.metadata, {}, {}, key, {}),
          "valid full-cache checksum and recomputed reference ID cannot replace authoritative Mach-O symbol name");
    for (bool indirect : {false, true}) {
        data = relocated(true);
        symbol(data, true, false, 8, 52, 0x0f, 2, 0x80, 0x100);
        symbol(data, true, false, 1, 1, 0x0f, 3, 0, 0x110);
        data[768] = std::byte(indirect ? 0xff : 0xc7);
        data[769] = std::byte(indirect ? 0x15 : 0x05);
        relocation(data, false, 0, 2, 1, 1, 2, true, true);
        put(data, 770, indirect ? 0 : UINT32_C(0xfffffffc), 4, false);
        if (!indirect) {
            put(data, 32 + 72 + 40, 16, 8, false);
            put(data, 774, 0x12, 4, false);
            data[778] = std::byte{0xc3};
        } else
            data[774] = std::byte{0xc3};
        loaded = take(load_macho(std::make_shared<MemoryStorage>(data), {}, {}));
        const auto functions = take(recover_functions(*loaded.image, loaded.metadata, {}, {}, {}));
        const auto refs = take(derive_references(*loaded.image, *functions, loaded.metadata, {}, {}));
        const auto outgoing = take(refs->outgoing(Address{{1}, 0}, {}));
        check(take(refs->incoming(Address{{3}, 0}, {})).total >= 1 &&
                  take(refs->incoming(Address{{1}, 6}, {})).total == 0,
              "RIP memory references declare BSS association rather than zero-displacement placeholder");
        if (indirect) {
            const auto call = std::find_if(outgoing.rows.begin(), outgoing.rows.end(),
                                           [](const auto &row) { return row.kind == ReferenceKind::call; });
            check(call != outgoing.rows.end() && call->association == Location{Address{{3}, 0}} &&
                      std::holds_alternative<UnresolvedTarget>(call->target) &&
                      std::get<UnresolvedTarget>(call->target).reason == UnresolvedReason::memory_value,
                  "indirect relocated CALL owns pointer-slot association without claiming stored callee value");
        }
        const auto encoded = take(encode_reference_index(*refs, {}));
        check(take(encode_reference_index(*take(decode_reference_index(encoded, {})), {})) == encoded,
              "memory Mach-O provenance and indirect associations roundtrip canonically");
    }
}
} // namespace
int main() {
    return run([] {
        source_binding();
        empty_names_and_pairs();
        project_follow();
        cache_forgery_and_memory();
    });
}
