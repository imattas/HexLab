#include "hexlab/loaders/elf.hpp"
#include "hexlab/analysis/derived_cache.hpp"
#include "hexlab/analysis/elf_relocations.hpp"
#include "hexlab/workspace/project.hpp"
#include "hexlab/workspace/navigation.hpp"
#include "support/elf_metadata_fixture.hpp"
#include "support/elf_dynamic_symbol_fixture.hpp"
#include "support/analysis_fixture.hpp"
#include "support/checks.hpp"
#include "support/fixture_files.hpp"
using namespace hexlab;
using namespace hexlab_test;
using namespace hexlab_test::elf_metadata_fixture;
namespace {
template <class T> T take(Result<T> value) {
    if (!value)
        throw std::runtime_error(value.error().message);
    return std::move(value.value());
}
LoadedImage load(std::vector<std::byte> bytes) {
    auto result = load_elf(std::make_shared<MemoryStorage>(std::move(bytes)), {});
    if (!result)
        throw std::runtime_error(result.error().message);
    return std::move(result.value());
}
std::vector<std::byte> fixture(bool wide, bool rela) {
    auto data = relocatable(wide, rela);
    symbol(data, wide, false, 4, 21, 0x12, 1, 0, 6);
    relocation(data, wide, rela, false, 1, 8, 1, 1, 0);
    put(data, 264, 0, wide ? 8 : 4);
    return data;
}
std::shared_ptr<const ReferenceIndex> references(const LoadedImage &loaded) {
    auto functions = recover_functions(*loaded.image, loaded.metadata, {}, {}, {});
    if (!functions)
        throw std::runtime_error(functions.error().message);
    auto result = derive_references(*loaded.image, *functions.value(), loaded.metadata, {}, {});
    if (!result)
        throw std::runtime_error(result.error().message);
    return result.value();
}
void origins_and_data() {
    for (bool wide : {false, true})
        for (bool rela : {false, true}) {
            auto loaded = load(fixture(wide, rela));
            auto index = references(loaded);
            check(!index->complete(),
                  "opaque relocation metadata keeps the derived reference index explicitly incomplete");
            check(
                index->all().size() == 5,
                "decoded control plus unclaimed data relocations produce exact references without NONE or duplicates");
            const auto source = index->outgoing(Address{{1}, 8}, {}).value();
            check(source.rows.size() == 1 && source.rows[0].kind == ReferenceKind::relocation &&
                      source.rows[0].target.index() == 0 &&
                      std::get<Location>(source.rows[0].target) == Location{Address{{2}, 0}},
                  "absolute data field references its declared symbol in the correct section domain");
            if (source.rows.empty())
                continue;
            const auto &provenance = source.rows[0].provenance;
            check(provenance.kind == ReferenceProvenanceKind::elf_relocation && provenance.instruction_id == 0 &&
                      provenance.elf && provenance.elf->resolution == ElfResolutionReason::resolved &&
                      provenance.elf->origins.size() == 1 &&
                      provenance.elf->origins[0].relocation == loaded.metadata.elf->relocations[1] &&
                      provenance.elf->origins[0].symbol && provenance.elf->origins[0].symbol->name == "callee",
                  "data reference owns complete original relocation and declared symbol values");
            const auto external = index->outgoing(Address{{1}, 16}, {}).value();
            check(external.rows.size() == 1 && external.rows[0].provenance.elf &&
                      external.rows[0].provenance.elf->origins[0].symbol->name == "external" &&
                      external.rows[0].provenance.elf->origins[0].symbol->state == ElfSymbolState::undefined &&
                      std::holds_alternative<UnresolvedTarget>(external.rows[0].target),
                  "PLT data metadata retains undefined symbol identity without assigning a library or target");
            const auto &row = loaded.metadata.elf->relocations[0];
            check(index->incoming_elf_symbol({*row.symbol_table, row.symbol_index}, {}).value().total == 2,
                  "symbol query uses actual table namespace and index across code and data references");
            const auto encoded = encode_reference_index(*index, {}).value();
            const auto decoded = decode_reference_index(encoded, {}).value();
            check(encode_reference_index(*decoded, {}).value() == encoded &&
                      decoded->outgoing(Address{{1}, 8}, {}).value().rows[0].provenance.elf == provenance.elf,
                  "full relocation and symbol provenance survives canonical reference roundtrip");
            auto forged = source.rows[0];
            forged.id = {0};
            forged.provenance.elf->origins[0].symbol->index += 1;
            check(!ReferenceIndex::create({forged}, {}, true, {}),
                  "symbol copy cannot claim a different index than its relocation namespace");
            forged = source.rows[0];
            forged.id = {0};
            forged.provenance.elf->origins[0].relocation.record_file_offset += 1;
            check(!ReferenceIndex::create({forged}, {}, true, {}),
                  "section relocation provenance must agree with original record position and stride");
        }
}
void immediate_and_nonallocated() {
    for (bool wide : {false, true}) {
        auto data = fixture(wide, true);
        const auto stride = wide ? 24 : 12;
        section(data, wide, 7, 0, 4, 0, 0, relocations_at, stride, wide ? 8 : 4);
        links(data, wide, false, 7, 5, 1, stride);
        const auto code = wide ? bytes({0x48, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0xc3}) : bytes({0xb8, 0, 0, 0, 0, 0xc3});
        std::copy(code.begin(), code.end(), data.begin() + 256);
        symbol(data, wide, false, 4, 21, 0x12, 1, 0, code.size());
        relocation(data, wide, true, false, 0, wide ? 2 : 1, 1, 1, 0);
        auto loaded = load(data);
        auto index = references(loaded);
        const auto rows = index->outgoing(Address{{1}, 0}, {}).value();
        check(rows.rows.size() == 1 && rows.rows[0].kind == ReferenceKind::relocation &&
                  rows.rows[0].operand_index == 1u && rows.rows[0].provenance.instruction_id &&
                  rows.rows[0].provenance.elf && std::get<Location>(rows.rows[0].target) == Location{Address{{2}, 0}},
              "relocated immediate gets a source-bound operand reference without patching its raw value");
        check(index->all().size() == 1,
              "immediate relocation is claimed once instead of duplicated as a raw data field");
        links(data, wide, false, 7, 5, 4, stride);
        relocation(data, wide, true, false, 0, 8, 1, 1, 0);
        loaded = load(data);
        index = references(loaded);
        const auto raw = index->outgoing(FileOffset{392}, {}).value();
        check(raw.rows.size() == 1 && raw.rows[0].provenance.elf && !raw.rows[0].operand_index &&
                  raw.rows[0].provenance.instruction_id == 0,
              "nonallocated relocation target retains canonical file identity without a fabricated memory address");
    }
}
void resolver_limits() {
    auto loaded = load(fixture(true, true));
    auto resolver = ElfRelocationResolver::create(loaded.metadata, ElfResolutionLimits{1, 4096}, {}).value();
    const auto instruction = decode_at(*loaded.image, {{1}, 0}).value().instruction.value();
    auto bounded = resolver.operand(instruction, 0, {});
    check(!bounded && bounded.error().code == ErrorCode::resource_limit,
          "lookup work budget bounds interval traversal across repeated queries");
    auto ordinary = ElfRelocationResolver::create(loaded.metadata, {}).value();
    const auto data = ordinary.data(1, {}).value();
    check(data.reason == ElfResolutionReason::resolved && data.address == Address{{2}, 0} &&
              ordinary.symbol(1)->name == "callee",
          "data lookup and symbol provenance share the same indexed resolver");
    std::stop_source stop;
    stop.request_stop();
    check(!ordinary.data(1, stop.get_token()), "raw data relocation lookup honors cancellation");
    auto bytes = fixture(true, true);
    relocation(bytes, true, true, false, 1, 1, 2, 2, UINT64_MAX - 3);
    auto overlapping = load(bytes);
    auto limited =
        ElfRelocationResolver::create(overlapping.metadata, ElfResolutionLimits{64 * 1024 * 1024, 1}, {}).value();
    const auto matches = limited.operand(instruction, 0, {});
    check(!matches && matches.error().code == ErrorCode::resource_limit,
          "independent overlapping origins obey a separate match count bound");
}
void symbol_namespaces_and_hostile_counts() {
    auto data = fixture(true, true);
    const auto original = data;
    section(data, true, 7, 0, 4, 0, 0, relocations_at, 24, 8);
    links(data, true, false, 7, 5, 1, 24);
    section(data, true, 8, 0, 2, 0, 0, 2304, 48, 8);
    links(data, true, false, 8, 6, 1, 24);
    section(data, true, 9, 0, 4, 0, 0, 2512, 24, 8);
    links(data, true, false, 9, 8, 1, 24);
    std::copy_n(data.begin() + 512, 10 * 64, data.begin() + 3072);
    put(data, 40, 3072, 8);
    std::copy_n(original.begin() + symbols_at, 5 * 24, data.begin() + symbols_at);
    std::copy_n(original.begin() + symbols_at, 2 * 24, data.begin() + 2304);
    put(data, 2304 + 24 + 8, 1, 8);
    put(data, 2304 + 24 + 16, 1, 8);
    auto record = original;
    relocation(record, true, true, false, 0, 8, 1, 1, 0);
    std::copy_n(record.begin() + relocations_at, 24, data.begin() + 2512);
    auto loaded = load(data);
    auto index = references(loaded);
    const auto first = index->incoming_elf_symbol({{5, symbols_at, {}}, 1}, {}).value();
    const auto second = index->incoming_elf_symbol({{8, 2304, {}}, 1}, {}).value();
    check(first.total == 1 && second.total == 1 && first.rows[0].provenance.elf->origins[0].symbol->name == "callee" &&
              second.rows[0].provenance.elf->origins[0].symbol->name == "callee" &&
              std::get<Location>(first.rows[0].target) != std::get<Location>(second.rows[0].target),
          "equal symbol names in distinct real SHT_SYMTAB namespaces never merge identities or targets");
    const auto data_ref = second.rows[0];
    auto one = ReferenceIndex::create({data_ref}, {}, true, {}).value();
    auto payload = encode_reference_index(*one, {}).value();
    // Payload v19 stores producer-graph fields before the ELF provenance
    // record. The unkeyed, single-record header ends at byte 16 and the
    // record's fixed fields place the embedded ELF length at bytes 71..74.
    constexpr std::size_t elf_length_offset = 71;
    const auto elf_payload_size = payload.size() >= elf_length_offset + 4 + 32
                                      ? (std::to_integer<std::uint32_t>(payload[elf_length_offset]) << 24) |
                                            (std::to_integer<std::uint32_t>(payload[elf_length_offset + 1]) << 16) |
                                            (std::to_integer<std::uint32_t>(payload[elf_length_offset + 2]) << 8) |
                                            std::to_integer<std::uint32_t>(payload[elf_length_offset + 3])
                                      : 0;
    check(elf_payload_size > 0 && payload.size() == elf_length_offset + 4 + elf_payload_size + 32,
          "unkeyed raw ELF provenance record has a bounded length-prefixed origin payload");
    for (std::size_t i = elf_length_offset; i < elf_length_offset + 4; ++i)
        payload[i] = std::byte{0xff};
    Sha256 hash;
    hash.update(std::span(payload).first(payload.size() - 32)).value();
    const auto digest = hash.digest();
    std::copy(digest.begin(), digest.end(), payload.end() - 32);
    check(!decode_reference_index(payload, {}),
          "checksum-valid hostile origin count is rejected before unbounded allocation");
    auto huge = data_ref;
    huge.id = {0};
    huge.provenance.elf->origins.resize(4097, huge.provenance.elf->origins[0]);
    check(!ReferenceIndex::create({huge}, {}, true, {}),
          "in-memory provenance origin count is bounded before encoding");
}
void dynamic_namespace_aliases_and_extremes() {
    namespace dynamic = hexlab_test::elf_dynamic_symbol_fixture;
    auto data = dynamic::fixture(true);
    constexpr auto base = UINT64_C(0x100000000);
    dynamic::tag(data, true, false, 5, 7, base + 5000);
    dynamic::tag(data, true, false, 6, 8, 24);
    dynamic::tag(data, true, false, 7, 9, 24);
    dynamic::tag(data, true, false, 8, 0, 0);
    program(data, true, 1, 2, dynamic::dynamic_at, base + dynamic::dynamic_at, 144, 144, 6, 8);
    std::copy_n(data.begin() + dynamic::sym, 72, data.begin() + 2304);
    std::copy_n(data.begin() + dynamic::dynamic_at, 144, data.begin() + 2800);
    put(data, 2800 + 2 * 16 + 8, base + 2304, 8);
    program(data, true, 2, 2, 2800, base + 2800, 144, 144, 6, 8);
    put(data, 5000, base + 7600, 8);
    put(data, 5008, (UINT64_C(1) << 32) | 1, 8);
    put(data, 5016, 0, 8);
    auto loaded = load(data);
    auto index = references(loaded);
    check(
        loaded.metadata.elf->relocations.size() == 2 && index->all().size() == 1 && index->all()[0].provenance.elf &&
            index->all()[0].provenance.elf->resolution == ElfResolutionReason::ambiguous &&
            index->all()[0].provenance.elf->origins.size() == 2,
        "same physical dynamic record with distinct symbol namespaces retains both legitimate interpretation origins");
    const auto encoded = encode_reference_index(*index, {}).value();
    check(encode_reference_index(*decode_reference_index(encoded, {}).value(), {}).value() == encoded,
          "dynamic relocation alias namespaces survive canonical provenance serialization");
    data = relocatable(true, true);
    symbol(data, true, false, 4, 21, 0x10, 0xfff1, UINT64_MAX, 0);
    relocation(data, true, true, false, 1, 8, 1, 4, UINT64_C(0x8000000000000000));
    loaded = load(data);
    index = references(loaded);
    const auto rows = index->outgoing(Address{{1}, 8}, {}).value();
    const auto roundtrip = decode_reference_index(encode_reference_index(*index, {}).value(), {})
                               .value()
                               ->outgoing(Address{{1}, 8}, {})
                               .value();
    check(rows.rows.size() == 1 && rows.rows[0].provenance.elf->origins[0].relocation.addend == INT64_MIN &&
              roundtrip.rows[0].provenance.elf->origins[0].symbol->value == UINT64_MAX &&
              roundtrip.rows[0].provenance.elf == rows.rows[0].provenance.elf,
          "minimum signed addend and maximum unsigned symbol value retain exact original bits without inventing an "
          "absolute-domain target");
}
void absolute_arithmetic() {
    namespace dynamic = hexlab_test::elf_dynamic_symbol_fixture;
    constexpr auto base = UINT64_C(0x100000000);
    struct Case {
        std::uint32_t type;
        std::uint64_t symbol, addend;
        std::optional<std::uint64_t> target;
    };
    const std::vector<Case> cases{{11, 0, UINT64_MAX - 3, UINT64_MAX - 3},
                                  {10, 0, UINT64_MAX - 3, {}},
                                  {11, 0, 0x7fffffff, 0x7fffffff},
                                  {11, 0, 0x80000000, {}},
                                  {10, 0, 0xffffffff, 0xffffffff},
                                  {11, 0, 0xffffffff, {}},
                                  {1, 0, UINT64_MAX - 3, UINT64_MAX - 3},
                                  {1, UINT64_MAX, 1, 0},
                                  {1, UINT64_C(0x8000000000000000), UINT64_C(0x8000000000000000), 0},
                                  {12, 0, 0x12345, 0x12345},
                                  {14, 0, 0x1234, 0x1234}};
    for (const auto &example : cases) {
        auto bytes = dynamic::fixture(true);
        put(bytes, dynamic::sym + 24 + 4, 0, 1);
        put(bytes, dynamic::sym + 24 + 6, 0xfff1, 2);
        put(bytes, dynamic::sym + 24 + 8, example.symbol, 8);
        put(bytes, dynamic::sym + 24 + 16, 0, 8);
        dynamic::tag(bytes, true, false, 5, 7, base + 5000);
        dynamic::tag(bytes, true, false, 6, 8, 24);
        dynamic::tag(bytes, true, false, 7, 9, 24);
        dynamic::tag(bytes, true, false, 8, 0, 0);
        program(bytes, true, 1, 2, dynamic::dynamic_at, base + dynamic::dynamic_at, 144, 144, 6, 8);
        put(bytes, 5000, base + 6000, 8);
        put(bytes, 5008, (UINT64_C(1) << 32) | example.type, 8);
        put(bytes, 5016, example.addend, 8);
        const auto loaded = load(bytes);
        const auto resolver = ElfRelocationResolver::create(loaded.metadata, {}).value();
        const auto result = resolver.data(0, {}).value();
        check(example.target
                  ? (result.reason == ElfResolutionReason::resolved && result.address == Address{{0}, *example.target})
                  : (result.reason == ElfResolutionReason::overflow && !result.address),
              "absolute S+A preserves 64-bit patterns and applies distinct zero/sign-extension checks for32/32S");
    }
}
void cache_provenance() {
    auto loaded = load(fixture(true, true));
    AnalysisKey key;
    key.input = {loaded.image->storage()->size(), hash_source(*loaded.image->storage(), {}).value()};
    key.engine_fingerprint = function_engine_fingerprint();
    const auto proposal =
        analyze_derived(loaded.image, std::make_shared<const ImageMetadata>(loaded.metadata), {}, {}, key, {}).value();
    const auto wire = encode_derived(proposal, {}).value();
    check(bool(decode_derived(wire, *loaded.image, loaded.metadata, {}, {}, key, {})),
          "full provenance cache roundtrips against authoritative ELF metadata");
    auto forged = proposal;
    std::vector<Reference> values(proposal.references->all().begin(), proposal.references->all().end());
    for (auto &value : values)
        if (value.provenance.elf && value.provenance.elf->origins[0].symbol) {
            value.id = {0};
            value.provenance.elf->origins[0].symbol->name = "forged";
            break;
        }
    forged.references = ReferenceIndex::create(std::move(values), key, proposal.references->complete(), {}).value();
    const auto hostile = encode_derived(forged, {}).value();
    check(!decode_derived(hostile, *loaded.image, loaded.metadata, {}, {}, key, {}),
          "correctly checksummed cache cannot substitute another declared ELF symbol name or provenance");
}
void write_project(const std::filesystem::path &path) {
    auto store = take(database::ProjectStore::create(path, {}));
    MemoryStorage input(fixture(true, true));
    take(store->import_input(input, {Format::elf, {}}, {}, {}));
}
struct ProjectFixture {
    FixtureFile input{fixture(true, true)};
    std::filesystem::path path = input.path.wstring() + L".hxproj";
    std::shared_ptr<database::ProjectStore> store;
    std::shared_ptr<ProjectSession> session;
    ~ProjectFixture() {
        session.reset();
        store.reset();
        std::error_code ignored;
        for (auto suffix : {L"", L"-wal", L"-shm"}) {
            auto file = path;
            file += suffix;
            std::filesystem::remove(file, ignored);
        }
    }
};
void project_follow_and_reopen() {
    ProjectFixture f;
    f.store = take(database::ProjectStore::create(f.path, {}));
    auto input = take(FileStorage::open(f.input.path));
    take(f.store->import_input(*input, {Format::elf, {}}, f.input.path, {}));
    input.reset();
    f.session = take(ProjectSession::attach(f.store, {}, {}));
    auto snapshot = f.session->snapshot();
    check(take(project_follow_target(*snapshot, {{1}, 0})) == Address{{2}, 0},
          "current project Follow accepts ELF-origin decoded control references");
    auto stale = *snapshot;
    stale.status = DerivedStatus::stale;
    check(!project_follow_target(stale, {{1}, 0}), "ELF-origin references do not bypass stale-source Follow barriers");
    auto wrong = *snapshot;
    wrong.derived_key->byte_revision += 1;
    check(!project_follow_target(wrong, {{1}, 0}), "ELF-origin Follow rejects mismatched source keys");
    snapshot = take(f.session->execute(Rename{Address{{1}, 0}, "owner"}, 0, {}));
    const auto before = snapshot->state;
    auto proposal =
        take(analyze_derived(snapshot->loaded->image, std::make_shared<const ImageMetadata>(snapshot->loaded->metadata),
                             snapshot->state->user->decisions, snapshot->analysis_options, *snapshot->derived_key, {}));
    take(f.store->store_derived_cache(proposal, {}));
    f.session.reset();
    f.store.reset();
    check(std::filesystem::remove(f.input.path), "owned external ELF source removed before durable provenance reopen");
    f.store = take(database::ProjectStore::open(f.path, database::ProjectMode::read_only, {}));
    f.session = take(ProjectSession::attach(f.store, {}, {}));
    const auto reopened = f.session->snapshot();
    check(reopened->derived_cache_status == database::CacheStatus::hit &&
              take(project_follow_target(*reopened, {{1}, 0})) == Address{{2}, 0} &&
              reopened->references->incoming_elf_symbol({{5, symbols_at, {}}, 1}, {}).value().total == 2,
          "source-missing readonly project restores canonical ELF origins, symbol queries and Follow targets");
    check(reopened->state->uuid == before->uuid && reopened->state->revisions == before->revisions &&
              reopened->state->history_cursor == before->history_cursor && *reopened->state->user == *before->user,
          "durable provenance cache preserves user annotations, UUID, revisions and history");
}
} // namespace
int main(int argc, char **argv) {
    if (argc == 3 && std::string_view(argv[1]) == "--write-project")
        return run([&] { write_project(std::filesystem::u8path(argv[2])); });
    if (argc != 1)
        return 2;
    return run([] {
        origins_and_data();
        immediate_and_nonallocated();
        resolver_limits();
        symbol_namespaces_and_hostile_counts();
        dynamic_namespace_aliases_and_extremes();
        absolute_arithmetic();
        cache_provenance();
        project_follow_and_reopen();
    });
}
