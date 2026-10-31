#include "hexlab/analysis/derived_cache.hpp"
#include "hexlab/loaders/macho.hpp"
#include "hexlab/workspace/project.hpp"
#include "hexlab/workspace/navigation.hpp"
#include "support/fixture_files.hpp"
#include "support/macho_chained_fixture.hpp"
#include "support/analysis_fixture.hpp"
#include "support/checks.hpp"
using namespace hexlab;
using namespace hexlab_test;
using namespace hexlab_test::macho_fixture;
namespace {
template <class T> T take(Result<T> value) {
    if (!value)
        throw std::runtime_error(value.error().message);
    return std::move(value.value());
}
LoadedImage load(std::vector<std::byte> bytes) {
    return take(load_macho(std::make_shared<MemoryStorage>(std::move(bytes)), {}, {}));
}
std::shared_ptr<MachODyldReferenceProvenance> edit_proof(Reference &ref) {
    auto proof = std::make_shared<MachODyldReferenceProvenance>(*ref.provenance.dyld);
    ref.provenance.dyld = proof;
    ref.id = {0};
    return proof;
}
void raw_references() {
    for (bool classic : {false, true}) {
        auto bytes = classic ? dyld(true) : chained();
        constexpr auto base = UINT64_C(0x100000000);
        if (classic) {
            stream(bytes, true, false, 0, {0x11, 0x20, 0, 0x51, 0});
            stream(bytes, true, false, 1, {0x11, 0x40, '_', 'e', 'x', 't', 0, 0x70, 8, 0x90, 0});
            put(bytes, 768, base + 8, 8, false);
        }
        const auto loaded = load(bytes);
        FunctionSnapshot functions;
        const auto refs = take(derive_references(*loaded.image, functions, loaded.metadata, {}, {}));
        check(refs->all().size() == 2, "raw dyld fields become owned references without requiring instruction roots");
        bool rebase = false, bind = false;
        for (const auto &ref : refs->all()) {
            check(ref.kind == ReferenceKind::dyld_fixup && ref.provenance.kind == ReferenceProvenanceKind::macho_dyld &&
                      ref.provenance.dyld && !ref.operand_index && !ref.association,
                  "dyld provenance is distinct from relocation_info and decoded pointer-slot associations");
            if (!ref.provenance.dyld)
                continue;
            const auto &p = *ref.provenance.dyld;
            check(p.origins.size() == 1 && p.context.slice_offset == 0 &&
                      p.origins[0].identity.source == (classic ? MachODyldSource::classic : MachODyldSource::chained),
                  "owned provenance retains selected-slice and original namespace identity");
            if (p.resolution.reason == MachODyldResolutionReason::resolved)
                rebase = std::get<Location>(ref.target) == Location{Address{{0}, base + 8}};
            else if (p.resolution.reason == MachODyldResolutionReason::runtime_binding) {
                const auto *unknown = std::get_if<UnresolvedTarget>(&ref.target);
                bind = unknown && unknown->reason == UnresolvedReason::macho_dyld && p.resolution.binding &&
                       p.resolution.binding->name == "_ext";
            }
        }
        check(rebase && bind, "rebases carry actual preferred pointer values while imports remain typed unresolved");
        const auto wire = take(encode_reference_index(*refs, {}));
        check(wire[0] == std::byte{19}, "dyld provenance uses reference payload version 19");
        const auto restored = take(decode_reference_index(wire, {}));
        check(take(encode_reference_index(*restored, {})) == wire, "owned dyld provenance roundtrips canonically");
    }
}
void source_bound_forgery() {
    const auto loaded = load(chained());
    AnalysisKey key;
    key.input = {loaded.image->storage()->size(), take(hash_source(*loaded.image->storage(), {}))};
    key.engine_fingerprint = function_engine_fingerprint();
    auto proposal =
        take(analyze_derived(loaded.image, std::make_shared<const ImageMetadata>(loaded.metadata), {}, {}, key, {}));
    const auto original = take(encode_derived(proposal, {}));
    check(bool(decode_derived(original, *loaded.image, loaded.metadata, {}, {}, key, {})),
          "dyld derived cache validates against its original source");
    auto rows = std::vector<Reference>(proposal.references->all().begin(), proposal.references->all().end());
    bool changed = false;
    for (auto &ref : rows) {
        if (!ref.provenance.dyld || !ref.provenance.dyld->resolution.binding)
            continue;
        const auto edited = edit_proof(ref);
        auto &p = *edited;
        p.resolution.binding->name = "_forged";
        std::get<MachODyldChainedOrigin>(p.origins[0].record).import->name = "_forged";
        ref.id = {0};
        changed = true;
    }
    check(changed, "forgery test actually changes an owned original chained import name");
    proposal.references = take(ReferenceIndex::create(std::move(rows), key, proposal.references->complete(), {}));
    const auto forged = take(encode_derived(proposal, {}));
    check(!decode_derived(forged, *loaded.image, loaded.metadata, {}, {}, key, {}),
          "recomputed reference IDs and valid cache checksum cannot forge original dyld symbol provenance");
}
void owned_word_forgery() {
    const auto loaded = load(chained());
    const auto refs = take(derive_references(*loaded.image, FunctionSnapshot{}, loaded.metadata, {}, {}));
    for (bool bind : {false, true}) {
        auto rows = std::vector<Reference>(refs->all().begin(), refs->all().end());
        for (auto &ref : rows) {
            if (bool(ref.provenance.dyld->resolution.binding) != bind)
                continue;
            const auto edited = edit_proof(ref);
            auto &p = *edited;
            auto &chain = std::get<MachODyldChainedOrigin>(p.origins[0].record);
            if (bind) {
                ++chain.import->library_ordinal;
                ++*p.resolution.binding->library_ordinal;
            } else {
                ++*chain.pointer.target;
                ++p.resolution.address->offset;
                ref.target = Location{*p.resolution.address};
            }
            ref.id = {0};
        }
        check(!ReferenceIndex::create(std::move(rows), {}, true, {}),
              "owned dyld semantic fields cannot contradict original pointer/import words even with regenerated IDs");
    }
    auto data = dyld(false);
    stream(data, false, false, 0, {0x11, 0x20, 0, 0x51, 0});
    put(data, 768, 0x1008, 4, false);
    const auto narrow = load(data);
    const auto narrow_refs = take(derive_references(*narrow.image, FunctionSnapshot{}, narrow.metadata, {}, {}));
    auto rows = std::vector<Reference>(narrow_refs->all().begin(), narrow_refs->all().end());
    auto &ref = rows[0];
    const auto edited = edit_proof(ref);
    auto &p = *edited;
    *std::get<MachODyldClassicOrigin>(p.origins[0].record).fixup.encoded_value |= UINT64_C(1) << 32;
    p.resolution.address->offset |= UINT64_C(1) << 32;
    ref.target = Location{*p.resolution.address};
    ref.id = {0};
    check(!ReferenceIndex::create(std::move(rows), {}, true, {}),
          "owned four-byte classic pointer cannot claim high bits absent from its original field");
}
void layout_roundtrips() {
    for (const auto format : {1u, 2u, 3u, 6u, 9u, 12u}) {
        const bool wide = format != 3;
        auto bytes = chained(wide, static_cast<std::uint16_t>(format), 3);
        if (format == 1 || format == 9 || format == 12) {
            put(bytes, 768, (UINT64_C(1) << 51) | (format == 1 ? UINT64_C(0x100000008) : 776), 8, false);
            put(bytes, 776, UINT64_C(1) << 62, 8, false);
        }
        const auto loaded = load(bytes);
        const auto refs = take(derive_references(*loaded.image, FunctionSnapshot{}, loaded.metadata, {}, {}));
        const auto wire = take(encode_reference_index(*refs, {}));
        check(take(encode_reference_index(*take(decode_reference_index(wire, {})), {})) == wire,
              "every supported chained pointer layout preserves owned records canonically");
    }
    for (bool wide : {false, true})
        for (bool big : {false, true}) {
            auto bytes = dyld(wide, big);
            stream(bytes, wide, big, 0, {0x11, 0x20, 0, 0x51, 0});
            put(bytes, 768, wide ? UINT64_C(0x100000008) : UINT64_C(0x1008), wide ? 8 : 4, big);
            const auto loaded = load(bytes);
            const auto refs = take(derive_references(*loaded.image, FunctionSnapshot{}, loaded.metadata, {}, {}));
            check(bool(decode_reference_index(take(encode_reference_index(*refs, {})), {})),
                  "classic32/64 both-order owned references preserve raw pointer bits");
        }
}
void partial_roundtrips() {
    for (unsigned variant = 0; variant < 4; ++variant) {
        auto data = variant == 0 ? chained(false, 3) : chained(true, variant == 1 ? 1 : 2);
        if (variant == 0) {
            put(data, chains_at + 52, 0x1000, 4, false);
            put(data, 768, 0x2000, 4, false);
        }
        if (variant == 1)
            put(data, 768, (UINT64_C(1) << 63) | 8, 8, false);
        if (variant == 2) {
            put(data, 768, 123, 4, false);
            put(data, 772, 0x80000, 8, false);
        }
        if (variant == 3)
            compress_chained_symbol_pool(data);
        const auto loaded = load(data);
        const auto refs = take(derive_references(*loaded.image, FunctionSnapshot{}, loaded.metadata, {}, {}));
        const auto wire = take(encode_reference_index(*refs, {}));
        check(!refs->all().empty() && take(encode_reference_index(*take(decode_reference_index(wire, {})), {})) == wire,
              "scalar, authenticated, overlapping and compressed-name partial states remain inspectable owned facts");
    }
}
void immutable_index_ownership() {
    const auto loaded = load(chained());
    const auto refs = take(derive_references(*loaded.image, FunctionSnapshot{}, loaded.metadata, {}, {}));
    for (const auto &original : refs->all()) {
        if (!original.provenance.dyld->resolution.binding)
            continue;
        auto row = original;
        const auto caller_owned = edit_proof(row);
        const auto isolated = take(ReferenceIndex::create({row}, {}, true, {}));
        caller_owned->resolution.binding->name = "_after_publication";
        std::get<MachODyldChainedOrigin>(caller_owned->origins[0].record).import->name = "_after_publication";
        check(isolated->all()[0].provenance.dyld->resolution.binding->name == "_ext",
              "a caller-retained mutable proof cannot change a published index or its canonical IDs");
    }
}
Address stored_target(const ProjectSnapshot &snapshot) {
    for (const auto &ref : snapshot.references->all())
        if (ref.kind == ReferenceKind::dyld_fixup && ref.source == Location{Address{{0}, UINT64_C(0x100000000)}})
            return std::get<Address>(std::get<Location>(ref.target));
    throw std::runtime_error("missing raw dyld pointer reference");
}
void project_cache_and_patch() {
    FixtureFile input(chained());
    const auto path = std::filesystem::path(input.path.wstring() + L".dyld.hxproj");
    auto store = take(database::ProjectStore::create(path, {}));
    auto source = take(FileStorage::open(input.path));
    take(store->import_input(*source, {Format::macho, {}, {}}, input.path, {}));
    source.reset();
    auto session = take(ProjectSession::attach(store, {}, {}));
    constexpr Address slot{{0}, UINT64_C(0x100000000)};
    take(session->execute(Rename{slot, "dyld_owner"}, 0, {}));
    const auto uuid = session->snapshot()->state->uuid;
    check(stored_target(*session->snapshot()) == Address{{0}, slot.offset + 8},
          "actual project derives preferred pointer from original chained word");
    take(session->execute(PatchBytes{FileOffset{768}, bytes({0x10})}, 0, {}));
    const auto stale = project_follow_target(*session->snapshot(), slot);
    check(!stale && stale.error().code == ErrorCode::conflict,
          "dyld pointer patch invalidates the project source barrier immediately");
    take(session->refresh_analysis({}));
    check(stored_target(*session->snapshot()) == Address{{0}, slot.offset + 16},
          "tracked pointer bytes invalidate owned dyld facts and rebuild the new target");
    take(session->undo({}));
    take(session->refresh_analysis({}));
    check(stored_target(*session->snapshot()) == Address{{0}, slot.offset + 8},
          "undo restores original raw pointer provenance");
    const auto before = session->snapshot()->state;
    session.reset();
    store.reset();
    check(std::filesystem::remove(input.path), "owned external source removed before dyld readonly cache reopen");
    store = take(database::ProjectStore::open(path, database::ProjectMode::read_only, {}));
    session = take(ProjectSession::attach(store, {}, {}));
    const auto snapshot = session->snapshot();
    check(snapshot->derived_cache_status == database::CacheStatus::hit &&
              stored_target(*snapshot) == Address{{0}, slot.offset + 8} && snapshot->state->uuid == uuid &&
              snapshot->state->revisions == before->revisions &&
              snapshot->state->history_cursor == before->history_cursor && *snapshot->state->user == *before->user &&
              presentation_name(*snapshot, slot) == "dyld_owner",
          "embedded-input readonly reopen restores actual dyld cache, annotations, revisions and user history");
    session.reset();
    store.reset();
    std::error_code ignored;
    for (auto suffix : {L"", L"-wal", L"-shm"}) {
        auto file = path;
        file += suffix;
        std::filesystem::remove(file, ignored);
    }
}
} // namespace
void historical_reference(const std::filesystem::path &path) {
    const auto source = take(FileStorage::open(path));
    check(source->size() == 29262 && digest_hex(take(hash_source(*source, {}))) ==
                                         "b39a67a192bce7fd5670ad8b94a2c35eaa05a8f7a22c91f41a97e9b36610a067",
          "actual v16 reference payload retains original length/hash without rewriting bytes");
    const auto bytes = take(source->read_at({0}, 29262));
    check(!decode_reference_index(bytes.bytes, {}),
          "incompatible genuine v16 provenance is rejected rather than reinterpreted");
}
int main(int argc, char **argv) {
    if (argc != 2)
        return 2;
    return run([&] {
        // Current optional ELF/Mach-O source records, producer graph headers,
        // and target-mode marker occupy 392 bytes on MSVC x64. Keep a tight
        // 400-byte cap so future fields cannot silently bloat every row.
        check(sizeof(ReferenceProvenance) <= 400,
              "expanded source provenance remains within its bounded inline footprint");
        raw_references();
        source_bound_forgery();
        owned_word_forgery();
        layout_roundtrips();
        partial_roundtrips();
        immutable_index_ownership();
        project_cache_and_patch();
        historical_reference(argv[1]);
    });
}
