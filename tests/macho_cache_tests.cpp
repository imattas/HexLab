#include "hexlab/workspace/project.hpp"
#include "hexlab/database/cache.hpp"
#include "support/fixture_files.hpp"
#include "support/checks.hpp"
#include <algorithm>
#include <array>
using namespace hexlab;
using namespace hexlab_test;
namespace {
template <class T> T take(Result<T> value) {
    if (!value)
        throw std::runtime_error(value.error().message);
    return std::move(value.value());
}
void historical(const std::filesystem::path &payload_path, const std::filesystem::path &input_path,
                unsigned generation) {
    static_assert(derived_cache_version == 12, "Thumb packed relatives require a distinct cache schema");
    const auto prior_version = std::array{5u, 6u, 7u, 8u, 8u, 8u, 8u, 8u}[generation];
    const bool relocated = generation != 0;
    const auto payload_size = std::array{3011u, 3215u, 100131u, 6019u, 6175u, 6175u, 6175u, 6175u}[generation];
    const auto payload_file = take(FileStorage::open(payload_path));
    const auto original = take(FileStorage::open(input_path));
    check(payload_file->size() == payload_size &&
              digest_hex(take(hash_source(*payload_file, {}))) ==
                  (generation == 7   ? "08e0d6f61b8fcfcc7f29d8e3257112472f28e870f20c0dca6a83367e55dfa007"
                   : generation == 6 ? "c504408a2e8ec553774644e15644031332b5a821a9d8a8ab72046f3232ab6c04"
                   : generation == 5 ? "789d2fd9e94dfe4fd9a3aab0be310083d742f4e41ca35c5b0567bd47536c1d8b"
                   : generation == 4 ? "6e3ee89d40e58dc289074b176737d8770540d49e6e3892980962cf0d353bea4d"
                   : generation == 3 ? "aa60c2d083e79069bc5b382b55bb5d2514050be7b1c8a3258693249899b4ea33"
                   : generation == 2 ? "976f33b520adc9f2c1b7dbd442c1ea09ac7c6883a2fe4c2d67887bc174129ede"
                   : relocated       ? "5289ffa0d3448156f52e12059040ef82f3c97c311d4374582e14e86a7e9c1727"
                                     : "8f68d4f08d2596a9d77aa268a1451de9991ab8a8a0e4ccc326e52c54882b288a"),
          "genuine historical Mach-O payload retains captured length/hash without rewritten bytes");
    check(original->size() == 4096 &&
              digest_hex(take(hash_source(*original, {}))) ==
                  (generation >= 4   ? "563f4e55990c5e96acf01b2aef41c81db185548c5077fa8d3355a47b3fd7e85a"
                   : generation == 3 ? "c04a2f5e0fc4a1f99702176b8c05acc235ec35c608cce6e44f9084311db9f254"
                   : generation == 2 ? "c521e2bcbc613ee5670134f2fc67361aa004c724ff2bffa5134edaaf9c1d4261"
                   : relocated       ? "1a1caa0faa21743ad4e34741c2424b0ce69a647c83affdec098e8ca9a7e8a1bc"
                                     : "7f3ff3e4b323b90f40f2c6a2068fa9979aeff3df0bd9aa64d9e0d34e6290073b"),
          "historical Mach-O producer input retains captured length/hash");
    const auto payload = take(payload_file->read_at({0}, payload_size));
    const auto input = take(original->read_at({0}, 4096));
    // The independently captured envelopes stores its120-byte key after
    // magic/version. Preserve its actual database identity, including the
    // original engine digest, even after the current wire version changes.
    std::vector<std::byte> old_key{std::byte{1}, std::byte{2}};
    old_key.insert(old_key.end(), payload.bytes.begin() + 6, payload.bytes.begin() + 126);
    Sha256Digest prior_engine{};
    std::copy_n(payload.bytes.begin() + 94, 32, prior_engine.begin());
    check(digest_hex(prior_engine) ==
              (generation == 7   ? "236b9c95ed2ac6e903e6cd173d11e600c5775f723f0582ee02b203778028fecb"
               : generation == 6 ? "9222b688ffd6dba6952b65c732464e7c4ade8a4f448f912de161739a750efc25"
               : generation == 5 ? "c881c2f9fac59e81cefa6de6f7eddb4738a67b48a184f7527bd7af882e0b6ce5"
               : generation == 4 ? "0519351ab313de722470329aff5d73f0ed030f24df81524d2f926315cf8ee5f2"
               : generation == 3 ? "21ca9fdafadd85b2200aedb425b07b5ec3fb4e8a1c7fe439405e2781f0b475ad"
               : generation == 2 ? "69464eb07957a5d66ee191420028d6276e11209b2973213a43274d28dede1a7f"
               : relocated       ? "2474a7727de4646d76b971b6cc7604f9ee7e34d0f7f59b14f8fc51eb19a435d6"
                                 : "fc0c91524098eb478e2be6db343742e44d2c847aa73e6e0738120eec28a2407e"),
          "captured original key matches independently recorded original engine fingerprint");
    for (bool rekey : {false, true}) {
        FixtureFile owned(input.bytes);
        const auto path = std::filesystem::path(owned.path.wstring() + L".macho-cache.hxproj");
        auto store = take(database::ProjectStore::create(path, {}));
        const LoadRecipe recipe{Format::macho, {}, {}};
        auto source = take(FileStorage::open(owned.path));
        take(store->import_input(*source, recipe, owned.path, {}));
        source.reset();
        auto session = take(ProjectSession::attach(store, {}, {}));
        const Address owner = generation >= 2 ? Address{{0}, UINT64_C(0x100000000)} : Address{{1}, 0};
        take(session->execute(Rename{owner, "preserved_owner"}, 0, {}));
        const auto before = session->snapshot()->state;
        const auto current = *session->snapshot()->derived_key;
        check(current.engine_fingerprint != prior_engine,
              "current shared analysis requires a distinct engine identity from the genuine prior producer");
        session.reset();
        auto sql = take(database::Connection::open(path, database::OpenMode::read_write, {}));
        auto update = take(
            sql->prepare(rekey ? "UPDATE derived_cache SET payload=?1,engine_version=?3 WHERE kind=2"
                               : "UPDATE derived_cache SET payload=?1,engine_version=?3,cache_key=?2 WHERE kind=2"));
        take(update->bind_integer(3, prior_version));
        take(update->bind_blob(1, payload.bytes));
        if (!rekey)
            take(update->bind_blob(2, old_key));
        take(update->step());
        update.reset();
        sql.reset();
        store.reset();
        check(std::filesystem::remove(owned.path), "owned external input removed before readonly compatibility reopen");
        store = take(database::ProjectStore::open(path, database::ProjectMode::read_only, {}));
        session = take(ProjectSession::attach(store, {}, {}));
        const auto snapshot = session->snapshot();
        // Only a matching wire version can reach source-key validation;
        // earlier genuine versions are incompatible before that validation.
        const auto expected = !rekey                                   ? database::CacheStatus::absent
                              : prior_version == derived_cache_version ? database::CacheStatus::corrupt
                                                                       : database::CacheStatus::incompatible;
        check(snapshot->derived_cache_status == expected && snapshot->functions && snapshot->references &&
                  snapshot->derived_key->engine_fingerprint == current.engine_fingerprint,
              "actual old key or unchanged old payload under new key causes readonly recomputation");
        check(snapshot->state->uuid == before->uuid && snapshot->state->revisions == before->revisions &&
                  snapshot->state->history_cursor == before->history_cursor &&
                  *snapshot->state->user == *before->user && presentation_name(*snapshot, owner) == "preserved_owner",
              "cache migration preserves UUID/domain annotation/revisions/user history with embedded input");
        sql = take(database::Connection::open(path, database::OpenMode::read_only, {}));
        auto row = take(sql->prepare("SELECT cache_key,engine_version,payload FROM derived_cache WHERE kind=2"));
        check(take(row->step()) && take(row->integer(1)) == prior_version &&
                  take(row->blob(2)) == std::vector<std::byte>(payload.bytes.begin(), payload.bytes.end()) &&
                  (rekey || take(row->blob(0)) == old_key),
              "readonly recomputation never rewrites genuine prior cache key/version/payload bytes");
        row.reset();
        sql.reset();
        session.reset();
        store.reset();
        std::error_code ignored;
        for (auto suffix : {L"", L"-wal", L"-shm"}) {
            auto file = path;
            file += suffix;
            std::filesystem::remove(file, ignored);
        }
    }
}
} // namespace
int main(int argc, char **argv) {
    if (argc != 17)
        return 2;
    return run([&] {
        historical(argv[1], argv[2], 0);
        historical(argv[3], argv[4], 1);
        historical(argv[5], argv[6], 2);
        historical(argv[7], argv[8], 3);
        historical(argv[9], argv[10], 4);
        historical(argv[11], argv[12], 5);
        historical(argv[13], argv[14], 6);
        historical(argv[15], argv[16], 7);
    });
}
