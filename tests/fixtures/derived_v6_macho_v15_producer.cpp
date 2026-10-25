#include "hexlab/workspace/project.hpp"
#include "hexlab/analysis/derived_cache.hpp"
#include "tests/support/macho_relocation_fixture.hpp"
#include <fstream>
#include <iostream>
#include <algorithm>
using namespace hexlab;
template <class T> T take(Result<T> r) {
    if (!r) throw std::runtime_error(r.error().message);
    return std::move(r.value());
}
int wmain(int argc, wchar_t **argv) {
    try {
        if (argc != 2) return 2;
        const std::filesystem::path root(argv[1]);
        const auto input = root / "input.o", project = root / "producer.hxproj";
        if (std::filesystem::exists(project) || std::filesystem::exists(root / "derived_v6_macho_v15.hxdc"))
            throw std::runtime_error("Historical capture already exists; never overwrite it");
        auto bytes = hexlab_test::macho_fixture::relocated(true);
        hexlab_test::macho_fixture::symbol(bytes, true, false, 8, 52, 0x0f, 2, 0x80, 0x100);
        { std::ofstream out(input, std::ios::binary); out.write(reinterpret_cast<const char *>(bytes.data()), bytes.size());
          if (!out) throw std::runtime_error("Cannot write original capture input"); }
        auto source = take(FileStorage::open(input));
        auto store = take(database::ProjectStore::create(project, {}));
        take(store->import_input(*source, {Format::macho, {}, {}}, input, {}));
        auto session = take(ProjectSession::attach(store, {}, {}));
        take(session->execute(Rename{Address{{1}, 0}, "captured_owner"}, 0, {}));
        auto snapshot = take(session->refresh_analysis({}));
        if (derived_cache_version != 6 || !snapshot->derived_key || !snapshot->functions || !snapshot->references ||
            std::none_of(snapshot->references->all().begin(), snapshot->references->all().end(),
                         [](const auto &r) { return r.provenance.macho.has_value(); }) ||
            std::none_of(snapshot->functions->calls.begin(), snapshot->functions->calls.end(),
                         [](const auto &call) { return call.source == Address{{1}, 0} && call.target == Address{{2}, 0}; }))
            throw std::runtime_error("Need actual v6 Mach-O provenance and resolved object CALL");
        const auto cache = take(store->read_derived_cache(*snapshot->derived_key, {}));
        if (cache.status != database::CacheStatus::hit || !cache.payload) throw std::runtime_error("No real stored cache");
        { std::ofstream out(root / "derived_v6_macho_v15.hxdc", std::ios::binary);
          out.write(reinterpret_cast<const char *>(cache.payload->data()), cache.payload->size());
          if (!out) throw std::runtime_error("Cannot write captured payload"); }
        std::cout << "engine_sha256=" << digest_hex(snapshot->derived_key->engine_fingerprint)
                  << "\nsource_sha256=" << digest_hex(snapshot->state->input.sha256)
                  << "\npayload_bytes=" << cache.payload->size() << "\nfunctions=" << snapshot->functions->functions.size()
                  << "\nreference_count=" << snapshot->references->all().size() << '\n';
        return 0;
    } catch (const std::exception &e) { std::cerr << e.what() << '\n'; return 1; }
}
