#include "hexlab/database/cache.hpp"
#include "hexlab/analysis/derived_cache.hpp"
#include "hexlab/workspace/project.hpp"
#include "testing.hpp"
#include "support/checks.hpp"
#include "support/fixture_files.hpp"
#include "support/analysis_fixture.hpp"
#include "hexlab/core/encoding.hpp"
using namespace hexlab;
using namespace hexlab::database;
using namespace hexlab_test;
namespace {
struct Fixture {
    FixtureFile marker{std::span<const std::byte>{}};
    std::filesystem::path path = marker.path.wstring() + L".hxproj";
    std::shared_ptr<ProjectStore> store;
    std::shared_ptr<const Image> image;
    ImageMetadata metadata;
    AnalysisOptions options;
    AnalysisKey key;
    DerivedProposal derived;
    explicit Fixture(const std::filesystem::path &elf_source = {},
                     std::string_view source_sha = "679b30fbdecfe6d1e6ab439b9a9ef953733ee7d8f0c4185e89c6762cce1463e3") {
        store = ProjectStore::create(path, {}).value();
        MemoryStorage original(bytes({0xe8, 1, 0, 0, 0, 0xc3, 0xc3}));
        LoadRecipe recipe{
            Format::raw, RawOptions{Architecture::x86_64, ExecutionMode::x86_64, {{0}, 0x1000}, true, false, true, {}}};
        if (elf_source.empty()) {
            check(bool(store->import_input(original, recipe, {}, {})), "persistent derived fixture imports original");
        } else {
            recipe = {Format::elf, {}};
            auto source = FileStorage::open(elf_source).value();
            check(digest_hex(hash_source(*source, {}).value()) == source_sha,
                  "historical ELF source matches independently captured original");
            check(bool(store->import_input(*source, recipe, {}, {})),
                  "historical ELF cache fixture imports its actual owned source");
        }
        auto state = store->snapshot().value();
        key.input = state->input;
        key.engine_fingerprint = function_engine_fingerprint(options);
        Sha256 fingerprint;
        check(bool(fingerprint.update(encode_recipe(recipe).value())), "recipe fingerprint computes for full cache");
        key.recipe_fingerprint = fingerprint.digest();
        auto loaded = load_image(store->materialize_input({}).value(), recipe, {}).value();
        image = loaded.image;
        metadata = loaded.metadata;
        derived = analyze_derived(image, std::make_shared<const ImageMetadata>(metadata), {}, options, key, {}).value();
    }
    ~Fixture() {
        store.reset();
        std::error_code ignored;
        std::filesystem::remove(path, ignored);
        for (auto suffix : {L"-wal", L"-shm"}) {
            auto side = path;
            side += suffix;
            std::filesystem::remove(side, ignored);
        }
    }
};
void backend_tests() {
    Fixture f;
    auto absent = f.store->load_derived_cache(f.key, *f.image, f.metadata, f.options, {}).value();
    check(absent.status == CacheStatus::absent && !absent.proposal, "missing complete cache reports absent");
    check(bool(f.store->store_reference_cache(f.key, *f.derived.references, {})),
          "separate reference-cache kind coexists with complete cache");
    auto before = f.store->snapshot().value();
    check(bool(f.store->store_derived_cache(f.derived, {})) && f.store->snapshot().value() == before,
          "complete derived cache writes no user state/history snapshot");
    auto hit = f.store->load_derived_cache(f.key, *f.image, f.metadata, f.options, {}).value();
    check(hit.status == CacheStatus::hit && hit.proposal && hit.proposal->functions->functions.size() == 2 &&
              hit.proposal->references->incoming(Address{{0}, 0x1006}, {}).value().total == 1,
          "persisted full cache reconstructs actual functions and reference queries");
    Annotation annotation{1, Address{{0}, 0x1000}, "persisted_name", "keep me"};
    check(bool(f.store->commit(0, StateDelta{{AnnotationChange{{}, annotation}}}, 0, {})),
          "cache fixture annotation commits");
    check(f.store->load_derived_cache(f.key, *f.image, f.metadata, f.options, {}).value().status == CacheStatus::hit,
          "annotation revision keeps complete cache source current");
    auto sql = Connection::open(f.path, OpenMode::read_write, {}).value();
    check(bool(sql->execute("UPDATE derived_cache SET engine_version=100 WHERE kind=2")),
          "incompatible full cache fixture created");
    sql.reset();
    check(f.store->load_derived_cache(f.key, *f.image, f.metadata, f.options, {}).value().status ==
              CacheStatus::incompatible,
          "complete cache version mismatch is a recompute miss");
    testing::fail_next_commit(ErrorCode::io);
    check(!f.store->store_derived_cache(f.derived, {}) &&
              f.store->load_derived_cache(f.key, *f.image, f.metadata, f.options, {}).value().status ==
                  CacheStatus::incompatible,
          "failed optional cache transaction preserves preceding row");
    check(bool(f.store->store_derived_cache(f.derived, {})), "complete cache can be repaired after recomputation");
    sql = Connection::open(f.path, OpenMode::read_write, {}).value();
    check(bool(sql->execute("UPDATE derived_cache SET payload=x'00' WHERE kind=2")),
          "corrupt full cache fixture created");
    sql.reset();
    auto readonly = ProjectStore::open(f.path, ProjectMode::read_only, {}).value();
    auto corrupt = readonly->load_derived_cache(f.key, *f.image, f.metadata, f.options, {}).value();
    check(corrupt.status == CacheStatus::corrupt && !corrupt.proposal && !readonly->store_derived_cache(f.derived, {}),
          "readonly cache miss cannot repair optional tables");
    auto inspection = ProjectSession::attach(readonly, {}, {}).value();
    check(inspection->snapshot()->derived_cache_status == CacheStatus::corrupt &&
              inspection->snapshot()->functions->functions.size() == 2 &&
              inspection->snapshot()->state->user->annotations[0] == annotation,
          "readonly session recomputes corrupt cache without losing user records");
    inspection.reset();
    check(readonly->load_derived_cache(f.key, *f.image, f.metadata, f.options, {}).value().status ==
                  CacheStatus::corrupt &&
              readonly->load_reference_cache(f.key, {}).value().status == CacheStatus::hit,
          "readonly recomputation repairs neither corrupt cache nor unrelated reference cache");
    readonly.reset();
    check(f.store->snapshot().value()->revisions.edit == 1 && f.store->snapshot().value()->history_cursor == 1 &&
              f.store->snapshot().value()->user->annotations[0] == annotation,
          "cache incompatibility/corruption/failures preserve user annotation and history");
    check(bool(f.store->store_derived_cache(f.derived, {})), "cache restored before byte revision change");
    check(bool(f.store->commit(1, StateDelta{{PatchChange{{}, {{{0}, bytes({0xe8}), bytes({0xe9})}}}}}, 0, {})),
          "effective source changes independently of old cache");
    check(f.store->load_derived_cache(f.key, *f.image, f.metadata, f.options, {}).value().status ==
                  CacheStatus::stale &&
              !f.store->store_derived_cache(f.derived, {}),
          "stale complete cache cannot replace current derived state");
}
void legacy_readonly_tests(const std::filesystem::path &path, int version, std::size_t size,
                           const std::filesystem::path &source = {}) {
    Fixture f(source);
    auto payload = FileStorage::open(path).value()->read_at({0}, size).value();
    check(payload.bytes.size() == size && payload.bytes[4] == std::byte{0} &&
              payload.bytes[5] == static_cast<std::byte>(version),
          "genuine historical fixture retains its original version header and length");
    if (version == 3 || version == 4) {
        auto file = FileStorage::open(path).value();
        check(digest_hex(hash_source(*file, {}).value()) ==
                  (version == 3 ? "bef86a0f2c897c96bd0ed01cb4e2be0c7a21e8cd9fb14a24ad2c51231062a977"
                                : "49333b76ac0b7e343cc67c2659f9d68bfcb58454eab77d3bbfe8a796ad15f6c0"),
              "historical cache retains captured producer bytes without changing its version field");
        const auto key = inspect_derived_key(payload.bytes, {});
        check(!key && key.error().code == ErrorCode::unsupported,
              "genuine historical records require recomputation under provenance format v5");
    }
    Annotation annotation{1, Address{{0}, 0x1000}, "old_cache_name", "retained history"};
    check(bool(f.store->commit(0, StateDelta{{AnnotationChange{{}, annotation}}}, 0, {})),
          "legacy cache fixture has committed user history");
    check(bool(f.store->store_derived_cache(f.derived, {})),
          "new source key row exists for isolated legacy-version fixture");
    auto sql = Connection::open(f.path, OpenMode::read_write, {}).value();
    auto update =
        sql->prepare("UPDATE derived_cache SET engine_version=" + std::to_string(version) + ",payload=?1 WHERE kind=2")
            .value();
    check(bool(update->bind_blob(1, payload.bytes)) && bool(update->step()),
          "genuine historical bytes transplanted under the current row key for version-rejection test");
    update.reset();
    sql.reset();
    auto schema_before_open = Connection::open(f.path, OpenMode::read_only, {}).value();
    auto schema_version = schema_before_open->prepare("PRAGMA user_version").value();
    check(schema_version->step().value(), "pre-open user schema version is readable");
    const auto user_schema_version = schema_version->integer(0).value();
    schema_version.reset();
    schema_before_open.reset();
    auto before = f.store->snapshot().value();
    auto readonly = ProjectStore::open(f.path, ProjectMode::read_only, {}).value();
    auto session = ProjectSession::attach(readonly, {}, {}).value();
    auto snapshot = session->snapshot();
    check(snapshot->derived_cache_status == CacheStatus::incompatible && snapshot->functions &&
              snapshot->functions->functions.size() == f.derived.functions->functions.size(),
          "readonly old-cache version recomputes current functions");
    if (version == 3 || version == 4)
        check(snapshot->loaded->metadata.elf && snapshot->functions->functions.size() == 1 &&
                  snapshot->functions->functions[0]->seeds[0].kind == FunctionSeedKind::symbol,
              "old ELF v3 cache recomputes actual symbol-rooted functions from its durable original source");
    check(snapshot->state->uuid == before->uuid && snapshot->state->revisions == before->revisions &&
              snapshot->state->history_cursor == 1 && *snapshot->state->user == *before->user,
          "old-cache recompute changes neither annotation nor UUID/revisions/history");
    auto inspection = Connection::open(f.path, OpenMode::read_only, {}).value();
    auto row = inspection->prepare("SELECT engine_version,payload FROM derived_cache WHERE kind=2").value();
    check(row->step().value() && row->integer(0).value() == version &&
              row->blob(1).value() == std::vector<std::byte>(payload.bytes.begin(), payload.bytes.end()),
          "readonly legacy-cache recompute does not repair the optional row");
    auto schema = inspection->prepare("PRAGMA user_version").value();
    check(schema->step().value() && schema->integer(0).value() == user_schema_version,
          "cache engine upgrade does not migrate the existing user schema");
}
void session_tests() {
    Fixture f;
    check(bool(f.store->store_derived_cache(f.derived, {})), "session cache fixture persists");
    f.store.reset();
    auto readonly = ProjectStore::open(f.path, ProjectMode::read_only, {}).value();
    auto session = ProjectSession::attach(readonly, {}, {}).value();
    auto restored = session->snapshot();
    check(restored->derived_cache_status == CacheStatus::hit &&
              restored->last_reanalysis.cache_validation_decodes >= restored->functions->instructions.size() &&
              restored->last_reanalysis.cache_validation_recovery_walks == 1,
          "readonly project reopen validates and adopts full persistent cache");
    check(restored->state->revisions.edit == 0 && restored->state->history_cursor == 0,
          "cache adoption creates no user undo record");
    session.reset();
    readonly.reset();
    f.store = ProjectStore::open(f.path, ProjectMode::read_write, {}).value();
    session = ProjectSession::attach(f.store, {}, {}).value();
    check(bool(session->execute(PatchBytes{FileOffset{0}, bytes({0xe9})}, 0, {})),
          "user patch commits before optional derived cache failure");
    auto accepted = session->snapshot();
    check(accepted->derived_cache_status == CacheStatus::stale,
          "byte edit marks preceding persistent cache stale immediately");
    testing::fail_next_commit(ErrorCode::io);
    auto refreshed = session->refresh_analysis({});
    check(bool(refreshed) && refreshed.value()->state->revisions == accepted->state->revisions &&
              refreshed.value()->state->user->patches == accepted->state->user->patches &&
              !refreshed.value()->derived_cache_reason.empty() &&
              refreshed.value()->derived_cache_status != CacheStatus::hit,
          "optional cache failure cannot undo or fail accepted user patch/reanalysis");
    session.reset();
    f.store.reset();
    readonly = ProjectStore::open(f.path, ProjectMode::read_only, {}).value();
    session = ProjectSession::attach(readonly, {}, {}).value();
    check(session->snapshot()->state->revisions.bytes == 1 &&
              session->snapshot()->effective->read_at({0}, 1).value().bytes[0] == std::byte{0xe9} &&
              session->snapshot()->functions->functions.size() == 1,
          "reopen recomputes missing derived cache while preserving accepted patch");
    session.reset();
    readonly.reset();
}
void prior_engine_tests(const std::filesystem::path &payload_path, const std::filesystem::path &source_path) {
    auto payload_file = FileStorage::open(payload_path).value();
    check(payload_file->size() == 4898 && digest_hex(hash_source(*payload_file, {}).value()) ==
                                              "29b38f8e1f9702e5c114af4b0e3211b128bea819a1b9f2fc851e14e0fe13bbc4",
          "genuine v5 producer payload retains original bytes and hash");
    const auto payload = payload_file->read_at({0}, 4898).value();
    auto original = FileStorage::open(source_path).value();
    const auto source = original->read_at({0}, static_cast<std::size_t>(original->size())).value();
    for (bool rekey : {false, true}) {
        FixtureFile owned(source.bytes);
        Fixture f(owned.path, "702c191fbeab72770b4c56f3e9b14810eaaa8cec48469d8d050373722d1f99bd");
        const auto inspected = inspect_derived_key(payload.bytes, {});
        check(!inspected && inspected.error().code == ErrorCode::unsupported,
              "genuine v5 envelope is rejected by provenance-v6 key inspection");
        // Read the independently captured legacy envelope's identity without
        // changing any version, key or checksum bytes in that payload.
        AnalysisKey prior;
        prior.input.size = decode_u64(payload.bytes.subspan(6, 8)).value();
        std::copy_n(payload.bytes.begin() + 14, 32, prior.input.sha256.begin());
        prior.byte_revision = decode_u64(payload.bytes.subspan(46, 8)).value();
        prior.decision_revision = decode_u64(payload.bytes.subspan(54, 8)).value();
        std::copy_n(payload.bytes.begin() + 62, 32, prior.recipe_fingerprint.begin());
        std::copy_n(payload.bytes.begin() + 94, 32, prior.engine_fingerprint.begin());
        std::vector<std::byte> prior_database_key{std::byte{1}, std::byte{2}};
        prior_database_key.insert(prior_database_key.end(), payload.bytes.begin() + 6, payload.bytes.begin() + 126);
        check(prior.input == f.key.input && prior.recipe_fingerprint == f.key.recipe_fingerprint &&
                  prior.engine_fingerprint != f.key.engine_fingerprint,
              "genuine legacy v5 payload binds actual source and prior arithmetic engine fingerprint");
        Annotation annotation{1, f.derived.functions->functions[0]->entry, "prior_engine_owner", "preserve history"};
        check(bool(f.store->commit(0, StateDelta{{AnnotationChange{{}, annotation}}}, 0, {})),
              "prior-engine fixture has actual user history");
        const auto incompatible_write = f.store->write_derived_cache(prior, payload.bytes, {});
        check(!incompatible_write && incompatible_write.error().code == ErrorCode::unsupported,
              "current writer cannot relabel a genuine legacy v5 payload as current provenance");
        check(bool(f.store->store_derived_cache(f.derived, {})),
              "current cache row prepared for historical-cache transplant");
        {
            auto sql = Connection::open(f.path, OpenMode::read_write, {}).value();
            auto update =
                sql->prepare(rekey ? "UPDATE derived_cache SET engine_version=5,payload=?1 WHERE kind=2"
                                   : "UPDATE derived_cache SET engine_version=5,payload=?1,cache_key=?2 WHERE kind=2")
                    .value();
            check(bool(update->bind_blob(1, payload.bytes)) &&
                      (rekey || bool(update->bind_blob(2, prior_database_key))) && bool(update->step()),
                  "genuine v5 key/version/payload transplanted without modifying producer bytes");
        }
        const auto before = f.store->snapshot().value();
        check(std::filesystem::remove(owned.path), "owned v5 original removed before readonly engine-migration reopen");
        auto readonly = ProjectStore::open(f.path, ProjectMode::read_only, {}).value();
        auto session = ProjectSession::attach(readonly, {}, {}).value();
        auto snapshot = session->snapshot();
        check(snapshot->derived_cache_status == (rekey ? CacheStatus::incompatible : CacheStatus::absent) &&
                  snapshot->functions && snapshot->references &&
                  snapshot->derived_key->engine_fingerprint == f.key.engine_fingerprint,
              "readonly v5 prior-engine key miss or forged key recomputes current facts");
        check(snapshot->state->uuid == before->uuid && snapshot->state->revisions == before->revisions &&
                  snapshot->state->history_cursor == before->history_cursor && *snapshot->state->user == *before->user,
              "same-wire engine migration preserves UUID user state revisions and history");
        auto sql = Connection::open(f.path, OpenMode::read_only, {}).value();
        auto row = sql->prepare("SELECT engine_version,payload FROM derived_cache WHERE kind=2").value();
        check(row->step().value() && row->integer(0).value() == 5 &&
                  row->blob(1).value() == std::vector<std::byte>(payload.bytes.begin(), payload.bytes.end()),
              "readonly migration preserves genuine v5 historical cache bytes and version");
    }
}
} // namespace
int main(int argc, char **argv) {
    if (argc != 8)
        return 2;
    return run([&] {
        backend_tests();
        legacy_readonly_tests(std::filesystem::path(argv[1]), 1, 991);
        legacy_readonly_tests(std::filesystem::path(argv[2]), 2, 1893);
        legacy_readonly_tests(std::filesystem::path(argv[3]), 3, 4337, std::filesystem::path(argv[4]));
        legacy_readonly_tests(std::filesystem::path(argv[5]), 4, 4352, std::filesystem::path(argv[4]));
        session_tests();
        prior_engine_tests(std::filesystem::path(argv[6]), std::filesystem::path(argv[7]));
    });
}
