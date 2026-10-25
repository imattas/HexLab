#include "hexlab/workspace/project.hpp"
#include "hexlab/analysis/derived_cache.hpp"
#include "hexlab/database/cache.hpp"
#include "support/fixture_files.hpp"
#include "support/checks.hpp"
using namespace hexlab;
using namespace hexlab_test;
namespace {
template <class T> T take(Result<T> result) {
    if (!result)
        throw std::runtime_error(result.error().message);
    return std::move(result.value());
}
void historical(const std::filesystem::path &cache_path, const std::filesystem::path &input_path,
                const std::filesystem::path &refs_path, unsigned generation) {
    const auto version = std::array{8, 9, 10, 11, 11}[generation];
    const auto payload_size = generation ? 5459 : 5452;
    const auto source = take(FileStorage::open(input_path));
    const auto encoded = take(FileStorage::open(cache_path));
    const auto refs = take(FileStorage::open(refs_path));
    check(source->size() == 984 && digest_hex(take(hash_source(*source, {}))) ==
                                       "9d454fd08d2d9ec500e01fb7a5ded4bb07d27021e7a5fff94220912b6ead1cd1",
          "genuine22 A64 compiler input retains original hash");
    check(encoded->size() == payload_size &&
              digest_hex(take(hash_source(*encoded, {}))) ==
                  (generation == 4   ? "c91c27a8daaeb5d3e900bba2b83289f0378df6f50e935bf4144868c3117404b7"
                   : generation == 3 ? "c72713d8b638a8df5579b62682c47bdb329d4da56621308603c78735a0d4a058"
                   : generation == 2 ? "5115c4eb99fe3e1887f3fc121695d1783b542ea916476f4bdcf3c5e28b4301a7"
                   : generation      ? "2e00dc5e77393060a24273c31e40013beb5ba906cc86144517a2b02e2d5bebe1"
                                     : "5be683c0607c240f4dd3797bcd1789fa9011a37146e0a6ea550bf57f8de5177b"),
          "genuine prior envelope retains original hash");
    check(refs->size() == 1669 &&
              digest_hex(take(hash_source(*refs, {}))) ==
                  (generation == 4   ? "346c3d3d1c020ef78ee9213a9daddc8246aa1ed3ca7b68ce39c13711c37f5517"
                   : generation == 3 ? "934d3f35c26689bfa1b98c80032f92494ead8adcecedbd4c44ab924988bf941b"
                   : generation == 2 ? "965c6023bb3d1e4403fe368b129847fa059238ca4ed86f378ede2fa138426c37"
                   : generation      ? "3894a8d5b2ed27505e3e930cf1fbbb4906e20031f4253c9f9248b9782ef3e740"
                                     : "4bf751058b9ee6b409638424804194942edd7fd8ffc5e396e0ed56e02a36d640"),
          "genuine22 owned reference payload is unchanged");
    const auto raw = take(source->read_at({0}, 984));
    const auto payload = take(encoded->read_at({0}, payload_size));
    const auto reference = take(refs->read_at({0}, 1669));
    const auto old_index = take(decode_reference_index(reference.bytes, {}));
    check(old_index->all().size() == 6 && old_index->key() &&
              digest_hex(old_index->key()->engine_fingerprint) ==
                  (generation == 4   ? "5e5ad067fb4879e5ef58235651cd907b6c24e89f729d77ef53a200379d683c72"
                   : generation == 3 ? "ecab2427ac7a9c43c33eaf54d7b5c247ca949d43fd8c0c9900c534bac32344de"
                   : generation == 2 ? "4a07ad14be558792c32341d40a24aac3e49bcfdc0a2a94754d6c1479ad6f66ec"
                   : generation      ? "7b9ea34957341f88d01afcebe32849570b6d37b01b6db2b70da752e57fc07ffe"
                                     : "5330b1ba4b202ee4975fa23fed9e7d39e3ec8c154e47eb63d399e73dc3e24845"),
          "unchanged reference wire remains inspectable under its actual old source key");
    std::vector<std::byte> old_key{std::byte{1}, std::byte{2}};
    old_key.insert(old_key.end(), payload.bytes.begin() + 6, payload.bytes.begin() + 126);
    for (bool rekey : {false, true}) {
        FixtureFile owned(raw.bytes);
        const auto path = std::filesystem::path(owned.path.wstring() + L".arm-v22.hxproj");
        auto store = take(database::ProjectStore::create(path, {}));
        auto input = take(FileStorage::open(owned.path));
        take(store->import_input(*input, {Format::elf, {}}, owned.path, {}));
        input.reset();
        auto session = take(ProjectSession::attach(store, {}, {}));
        const Address callee{{4}, 0};
        take(session->execute(Rename{callee, "preserved_arm_owner"}, 0, {}));
        const auto before = session->snapshot()->state;
        check(session->snapshot()->derived_key->engine_fingerprint != old_index->key()->engine_fingerprint,
              "current engine identity differs from actual prior producer");
        session.reset();
        auto sql = take(database::Connection::open(path, database::OpenMode::read_write, {}));
        auto update =
            take(sql->prepare(std::string("UPDATE derived_cache SET payload=?1,") + (rekey ? "" : "cache_key=?2,") +
                              "engine_version=" + std::to_string(version) + " WHERE kind=2"));
        take(update->bind_blob(1, payload.bytes));
        if (!rekey)
            take(update->bind_blob(2, old_key));
        take(update->step());
        update.reset();
        sql.reset();
        store.reset();
        check(std::filesystem::remove(owned.path), "owned external A64 input removed before readonly migration");
        store = take(database::ProjectStore::open(path, database::ProjectMode::read_only, {}));
        session = take(ProjectSession::attach(store, {}, {}));
        const auto snapshot = session->snapshot();
        check(snapshot->derived_cache_status == (!rekey ? database::CacheStatus::absent
                                                 : version == derived_cache_version
                                                     ? database::CacheStatus::corrupt
                                                     : database::CacheStatus::incompatible),
              "actual prior A64 cache causes readonly recomputation under new source identity/schema");
        check(snapshot->loaded->image->decode_context().mode == ExecutionMode::a64 &&
                  snapshot->functions->instructions.size() == 7 && snapshot->references->all().size() == 6,
              "current engine reconstructs typed A64 context and owned packed relocations");
        check(snapshot->state->uuid == before->uuid && snapshot->state->revisions == before->revisions &&
                  snapshot->state->history_cursor == before->history_cursor &&
                  *snapshot->state->user == *before->user &&
                  presentation_name(*snapshot, callee) == "preserved_arm_owner",
              "readonly A64 migration preserves user identity, history and annotation");
        sql = take(database::Connection::open(path, database::OpenMode::read_only, {}));
        auto row = take(sql->prepare("SELECT engine_version,payload FROM derived_cache WHERE kind=2"));
        check(take(row->step()) && take(row->integer(0)) == version &&
                  take(row->blob(1)) == std::vector<std::byte>(payload.bytes.begin(), payload.bytes.end()),
              "readonly recomputation never rewrites actual prior envelope or version");
        row.reset();
        sql.reset();
        session.reset();
        store.reset();
        std::error_code ignored;
        for (auto suffix : {L"", L"-wal", L"-shm"}) {
            auto item = path;
            item += suffix;
            std::filesystem::remove(item, ignored);
        }
    }
}
} // namespace
int main(int argc, char **argv) {
    if (argc != 16)
        return 2;
    return run([&] {
        historical(argv[1], argv[2], argv[3], 0);
        historical(argv[4], argv[5], argv[6], 1);
        historical(argv[7], argv[8], argv[9], 2);
        historical(argv[10], argv[11], argv[12], 3);
        historical(argv[13], argv[14], argv[15], 4);
    });
}
