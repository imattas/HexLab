#include "hexlab/workspace/project.hpp"
#include "hexlab/analysis/derived_cache.hpp"
#include "hexlab/workspace/navigation.hpp"
#include "tests/support/macho_chained_fixture.hpp"
#include <fstream>
#include <iostream>
using namespace hexlab;
template <class T> T take(Result<T> r) {
    if (!r) throw std::runtime_error(r.error().message);
    return std::move(r.value());
}
int wmain(int argc, wchar_t **argv) {
    try {
        if (argc != 2) return 2;
        const std::filesystem::path root(argv[1]);
        const auto input = root / "input.macho";
        const auto project = root / "producer.hxproj";
        const auto payload_path = root / "derived_v8_macho_v17.hxdc";
        const auto references_path = root / "references_v7_macho_v17.hxrf";
        for (const auto &path : {input, project, payload_path, references_path})
            if (std::filesystem::exists(path)) throw std::runtime_error("Historical capture already exists; never overwrite it");
        auto bytes = hexlab_test::macho_fixture::chained();
        using namespace hexlab_test::macho_fixture;
        constexpr std::uint64_t base = UINT64_C(0x100000000), callee = base + 332, entry = base + 256;
        put(bytes, symtab_command(true) + 12, 0, 4, false);
        const auto main = append_command(bytes, true, false, 0x80000028, 24);
        put(bytes, main + 8, 1024, 8, false);
        put(bytes, 768, (UINT64_C(2) << 51) | callee, 8, false);
        for (unsigned index = 0; index < 2; ++index) {
            const auto at = 1024 + index * 6;
            bytes[at] = std::byte{0xff};
            bytes[at + 1] = std::byte{0x15};
            put(bytes, at + 2, static_cast<std::uint32_t>(base + index * 8 - (entry + index * 6 + 6)), 4, false);
        }
        bytes[1036] = bytes[1100] = std::byte{0xc3};
        {
            std::ofstream out(input, std::ios::binary);
            out.write(reinterpret_cast<const char *>(bytes.data()), bytes.size());
            if (!out) throw std::runtime_error("Cannot write original capture input");
        }
        auto source = take(FileStorage::open(input));
        auto store = take(database::ProjectStore::create(project, {}));
        take(store->import_input(*source, {Format::macho, {}, {}}, input, {}));
        auto session = take(ProjectSession::attach(store, {}, {}));
        constexpr Address slot{{0}, UINT64_C(0x100000000)};
        take(session->execute(Rename{slot, "captured_dyld_flow_owner"}, 0, {}));
        const auto snapshot = take(session->refresh_analysis({}));
        unsigned dyld_references = 0;
        bool rebase = false, binding = false;
        if (!snapshot->derived_key || !snapshot->references || !snapshot->functions || derived_cache_version != 8 || reference_cache_version != 8)
            throw std::runtime_error("Need real current v17/schema8 rooted analysis");
        for (const auto &ref : snapshot->references->all()) {
            if (ref.kind != ReferenceKind::dyld_fixup) continue;
            ++dyld_references;
            if (!ref.provenance.dyld) throw std::runtime_error("Missing owned dyld proof");
            const auto &p = *ref.provenance.dyld;
            if (p.resolution.reason == MachODyldResolutionReason::resolved)
                rebase = p.resolution.address == Address{{0}, slot.offset + 332};
            if (p.resolution.reason == MachODyldResolutionReason::runtime_binding && p.resolution.binding)
                binding = p.resolution.binding->name == "_ext" && p.resolution.binding->library_ordinal == 1;
        }
        if (dyld_references != 2 || !rebase || !binding || presentation_name(*snapshot, slot) != "captured_dyld_flow_owner")
            throw std::runtime_error("Need actual preferred pointer, raw binding and preserved user annotation");
        if (take(project_follow_target(*snapshot, Address{{0}, entry})) != Address{{0}, callee} ||
            take(project_follow_target(*snapshot, Address{{0}, entry + 6})))
            throw std::runtime_error("Need actual decoded rebase Follow and unresolved bound call");
        unsigned decoded_dyld = 0;
        for (const auto &ref : snapshot->references->all())
            if (ref.provenance.dyld && ref.provenance.instruction_id) ++decoded_dyld;
        if (decoded_dyld != 4) throw std::runtime_error("Need two owned storage reads and two owned control uses");
        const auto cache = take(store->read_derived_cache(*snapshot->derived_key, {}));
        if (cache.status != database::CacheStatus::hit || !cache.payload)
            throw std::runtime_error("No actual stored derived cache");
        const auto references = take(encode_reference_index(*snapshot->references, {}));
        {
            std::ofstream out(payload_path, std::ios::binary);
            out.write(reinterpret_cast<const char *>(cache.payload->data()), cache.payload->size());
            if (!out) throw std::runtime_error("Cannot write actual captured derived payload");
        }
        {
            std::ofstream out(references_path, std::ios::binary);
            out.write(reinterpret_cast<const char *>(references.data()), references.size());
            if (!out) throw std::runtime_error("Cannot write actual captured reference payload");
        }
        std::cout << "engine_sha256=" << digest_hex(snapshot->derived_key->engine_fingerprint)
                  << "\nsource_sha256=" << digest_hex(snapshot->state->input.sha256)
                  << "\npayload_bytes=" << cache.payload->size() << "\nreferences_bytes=" << references.size()
                  << "\nfunctions=" << snapshot->functions->functions.size()
                  << "\nreference_count=" << snapshot->references->all().size()
                  << "\ndyld_references=" << dyld_references << '\n';
        return 0;
    } catch (const std::exception &e) { std::cerr << e.what() << '\n'; return 1; }
}
