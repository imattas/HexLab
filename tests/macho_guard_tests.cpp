#include "hexlab/workspace/project.hpp"
#include "hexlab/workspace/listing.hpp"
#include "hexlab/workspace/navigation.hpp"
#include "hexlab/analysis/derived_cache.hpp"
#include "hexlab/analysis/relocations.hpp"
#include "support/macho_chained_fixture.hpp"
#include "support/macho_relocation_fixture.hpp"
#include "support/macho_dyld_fixture.hpp"
#include "support/analysis_fixture.hpp"
#include "support/fixture_files.hpp"
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
constexpr std::size_t table_at = 3500;
Address entry(bool wide) { return {{0}, (wide ? UINT64_C(0x100000000) : UINT64_C(0x1000)) + 256}; }
std::vector<std::byte> guarded(bool wide, bool encrypted, unsigned start, unsigned length, unsigned cryptid = 1,
                               bool big = false) {
    auto data = dyld(wide, big);
    put(data, symtab_command(wide) + 12, 0, 4, big);
    const auto header = wide ? 32u : 28u;
    segment(data, wide, big, header, entry(wide).offset - 1024, 4096, 0, 4096, 7, 0, 3);
    const auto bss = header + (wide ? 72u : 56u) + 2 * (wide ? 80u : 68u);
    put(data, bss + (wide ? 48 : 40), 784, 4, big);
    put(data, bss + (wide ? 64 : 56), 0, 4, big);
    const auto main = append_command(data, wide, big, 0x80000028, 24);
    put(data, main + 8, 1024, 8, big);
    const auto guard =
        append_command(data, wide, big, encrypted ? wide ? 0x2c : 0x21 : 0x29, encrypted ? wide ? 24 : 20 : 16);
    put(data, guard + 8, encrypted ? start : table_at, 4, big);
    put(data, guard + 12, encrypted ? length : 8, 4, big);
    if (encrypted)
        put(data, guard + 16, cryptid, 4, big);
    else {
        put(data, table_at, start, 4, big);
        put(data, table_at + 4, length, 2, big);
        put(data, table_at + 6, 1, 2, big);
    }
    data[1024] = std::byte{0xe8};
    put(data, 1025, 11, 4, false);
    data[1029] = data[1040] = std::byte{0xc3};
    return data;
}
void decode_guards() {
    for (bool wide : {false, true})
        for (bool encrypted : {false, true})
            for (unsigned start : {1024u, 1025u, 1040u}) {
                const auto data = guarded(wide, encrypted, start, 4);
                const auto loaded = take(load_macho(std::make_shared<MemoryStorage>(data), {}, {}));
                const auto at = entry(wide);
                const auto pure = take(decode_at(*loaded.image, at));
                check(bool(pure.instruction) == (start == 1040),
                      "image decode refuses both excluded starts and instruction windows crossing data/encryption");
                const auto functions = take(recover_functions(*loaded.image, loaded.metadata, {}, {}, {}));
                const auto coarse = take(analyze(*loaded.image, loaded.metadata, {}, {}));
                check(functions->instructions.size() == (start == 1040 ? 2u : 0u) &&
                          coarse.instructions.size() == functions->instructions.size(),
                      "rooted/coarse traversal cannot decode declared data or encrypted source/target bytes");
                DocumentSnapshot doc;
                doc.image = loaded.image;
                doc.metadata = loaded.metadata;
                const auto page = take(make_listing_page(doc, at, 1));
                check(page.rows.size() == 1 && bool(page.rows[0].instruction) == (start == 1040) &&
                          !page.rows[0].control_target,
                      "manual listing uses the same window policy and never offers Follow into excluded targets");
                check(loaded.image->segment_at(at)->executable && take(loaded.image->read(at, 1))[0] == std::byte{0xe8},
                      "code exclusion preserves declared segment permissions and original bytes");
            }
    const auto data = guarded(true, true, 1024, 5, 0);
    const auto clear = take(load_macho(std::make_shared<MemoryStorage>(data), {}, {}));
    check(take(recover_functions(*clear.image, clear.metadata, {}, {}, {}))->instructions.size() == 3,
          "cryptid zero declares unencrypted bytes and does not suppress valid code");
    const auto preceding = take(load_macho(std::make_shared<MemoryStorage>(guarded(true, false, 1020, 4)), {}, {}));
    check(take(decode_at(*preceding.image, entry(true))).instruction.has_value(),
          "a data range ending exactly at an instruction start does not overblock it");
}
void project_guard_patch() {
    FixtureFile input(guarded(true, true, 1024, 5));
    const auto path = std::filesystem::path(input.path.wstring() + L".guard.hxproj");
    auto store = take(database::ProjectStore::create(path, {}));
    auto source = take(FileStorage::open(input.path));
    take(store->import_input(*source, {Format::macho, {}, {}}, input.path, {}));
    source.reset();
    auto session = take(ProjectSession::attach(store, {}, {}));
    const auto at = entry(true);
    take(session->execute(Rename{at, "encrypted_owner"}, 0, {}));
    check(!take(project_follow_target(*session->snapshot(), at)), "project Follow excludes encrypted instructions");
    const auto &commands = session->snapshot()->loaded->metadata.macho->container.slices[0].header.commands;
    const auto cryptid_at = commands.back().file_offset + 16;
    take(session->execute(PatchBytes{FileOffset{cryptid_at}, bytes({0})}, 0, {}));
    const auto stale = project_follow_target(*session->snapshot(), at);
    check(!stale && stale.error().code == ErrorCode::conflict, "encryption declaration patch blocks stale Follow");
    auto snapshot = take(session->refresh_analysis({}));
    check(take(project_follow_target(*snapshot, at)) == Address{{0}, at.offset + 16},
          "cryptid-zero patch rebuilds actual clear instruction/callee facts");
    take(session->undo({}));
    snapshot = take(session->refresh_analysis({}));
    check(snapshot->functions->instructions.empty() && !take(project_follow_target(*snapshot, at)),
          "undo reinstates encryption policy and removes formerly reusable code facts");
    const auto before = snapshot->state;
    session.reset();
    store.reset();
    snapshot.reset();
    check(std::filesystem::remove(input.path), "owned encrypted source removed before readonly reopen");
    store = take(database::ProjectStore::open(path, database::ProjectMode::read_only, {}));
    session = take(ProjectSession::attach(store, {}, {}));
    snapshot = session->snapshot();
    check(snapshot->derived_cache_status == database::CacheStatus::hit && snapshot->functions->instructions.empty() &&
              !take(project_follow_target(*snapshot, at)) && snapshot->state->uuid == before->uuid &&
              snapshot->state->revisions == before->revisions && *snapshot->state->user == *before->user &&
              snapshot->state->history_cursor == before->history_cursor &&
              presentation_name(*snapshot, at) == "encrypted_owner",
          "source-missing readonly cache preserves exclusions, annotations and history");
    session.reset();
    store.reset();
    snapshot.reset();
    std::error_code ignored;
    for (auto suffix : {L"", L"-wal", L"-shm"}) {
        auto file = path;
        file += suffix;
        std::filesystem::remove(file, ignored);
    }
}
} // namespace
void independent_object(const std::filesystem::path &path) {
    const auto source = take(FileStorage::open(path));
    check(digest_hex(take(hash_source(*source, {}))) ==
              "d2e82a2bd995313d1eaf25da0e1c6a9f7972f584e007c77d0196cf15a386f1ff",
          "independently compiled object retains its recorded original hash");
    const auto loaded = take(load_macho(source, {}, {}));
    const auto &m = *loaded.metadata.macho;
    check(m.sections.size() == 1 && m.sections[0].address == 0 && m.sections[0].file_offset == FileOffset{320} &&
              m.data_in_code.size() == 1 && m.data_in_code[0].raw_offset == 5 &&
              m.data_in_code[0].offset == FileOffset{325},
          "actual LLVM object data-in-code coordinates resolve through section VM origin, not the Mach header file "
          "offset");
    check(loaded.image->code_window({{1}, 0}, 15) == 5 && !loaded.image->code_window({{1}, 5}, 1) &&
              loaded.image->code_window({{1}, 9}, 1) == 1 && loaded.image->plaintext_window({{1}, 5}, 1) == 1,
          "object section-domain code exclusion is exact and does not imply encryption");
}
void encrypted_pointer_sources() {
    for (bool chain : {false, true}) {
        auto data = chain ? chained() : dyld(true);
        if (!chain)
            stream(data, true, false, 0, {0x11, 0x20, 0, 0x51, 0});
        put(data, 768, UINT64_MAX, 8, false);
        const auto command = append_command(data, true, false, 0x2c, 24);
        put(data, command + 8, 768, 4, false);
        put(data, command + 12, 8, 4, false);
        put(data, command + 16, 1, 4, false);
        auto result = load_macho(std::make_shared<MemoryStorage>(data), {}, {});
        check(bool(result), "encrypted chained next/import bits cannot force traversal or semantic ordinal rejection");
        if (!result)
            continue;
        const auto &loaded = result.value();
        const auto index = take(MachODyldResolver::create(*loaded.image, loaded.metadata, {}));
        const auto resolution = take(index.slot({{0}, UINT64_C(0x100000000)}, 8, {}));
        check(resolution.reason == MachODyldResolutionReason::unsupported && !resolution.address && !resolution.binding,
              "ciphertext field bits cannot prove a static dyld pointer value or binding");
        const auto refs = take(derive_references(*loaded.image, FunctionSnapshot{}, loaded.metadata, {}, {}));
        check(refs->all().size() == 1 && std::holds_alternative<UnresolvedTarget>(refs->all()[0].target) &&
                  bool(decode_reference_index(take(encode_reference_index(*refs, {})), {})),
              "encrypted fixup retains owned raw evidence and roundtrips without a fabricated numeric reference");
    }
}
void canonical_policy() {
    const auto loaded = take(load_macho(std::make_shared<MemoryStorage>(guarded(true, true, 1024, 5, 0)), {}, {}));
    auto layout = loaded.image->layout();
    const auto at = entry(true);
    layout.code_exclusions = {
        {{at.space, at.offset + 3}, 4}, {{at.space, at.offset + 1}, 3}, {{at.space, at.offset + 7}, 1}};
    layout.encrypted_ranges = {{{at.space, at.offset + 4}, 2}};
    const auto image = take(Image::create(loaded.image->storage(), layout));
    const auto again = take(Image::create(loaded.image->storage(), image->layout()));
    check(image->layout().code_exclusions.size() == 1 && image->code_window(at, 15) == 1 &&
              image->plaintext_window(at, 15) == 4 && image->plaintext_window({at.space, at.offset + 6}, 1) == 1,
          "overlapping/adjacent exclusions normalize without extending encrypted semantics into ordinary data");
    check(take(image->mapping_fingerprint()) == take(again->mapping_fingerprint()) &&
              take(image->mapping_fingerprint()) != take(loaded.image->mapping_fingerprint()),
          "canonical policy identity is stable across recreation and differs from unguarded mapping identity");
    layout.code_exclusions = {{{{99}, 0}, 1}};
    check(!Image::create(loaded.image->storage(), layout), "policy cannot name an undeclared address domain");
    layout.code_exclusions = {{{at.space, UINT64_MAX}, 2}};
    check(!Image::create(loaded.image->storage(), layout), "policy interval overflow is checked before indexing");
}
void declarations_and_bounds() {
    for (bool wide : {false, true})
        for (bool big : {false, true})
            for (bool encrypted : {false, true}) {
                const auto loaded = take(
                    load_macho(std::make_shared<MemoryStorage>(guarded(wide, encrypted, 1025, 4, 7, big)), {}, {}));
                const auto &m = *loaded.metadata.macho;
                check(
                    loaded.image->code_window(entry(wide), 15) == 1 &&
                        (encrypted ? m.encryption.size() == 1 && m.encryption[0].cryptid == 7 &&
                                         m.encryption[0].offset == FileOffset{1025} && m.encryption[0].size == 4
                                   : m.data_in_code.size() == 1 && m.data_in_code[0].length == 4 &&
                                         m.data_in_code[0].kind == 1 && m.data_in_code[0].offset == FileOffset{1025} &&
                                         m.data_in_code[0].record_file_offset == table_at),
                    "32/64 both-order protection records preserve exact original scalar widths and source coordinates");
                if (!encrypted)
                    check(take(loaded.metadata_reads.intersects({table_at}, 8)),
                          "data-in-code payload bytes participate in tracked metadata dependencies");
            }
    for (bool fat64 : {false, true})
        for (bool big : {false, true}) {
            const auto inner = guarded(true, false, 1025, 4);
            std::vector<std::byte> data(8192);
            put(data, 0, fat64 ? 0xcafebabf : 0xcafebabe, 4, big);
            put(data, 4, 1, 4, big);
            put(data, 8, 0x01000007, 4, big);
            put(data, 12, 0x80000003, 4, big);
            put(data, 16, 4096, fat64 ? 8 : 4, big);
            put(data, fat64 ? 24 : 20, 4096, fat64 ? 8 : 4, big);
            put(data, fat64 ? 32 : 24, 12, 4, big);
            std::copy(inner.begin(), inner.end(), data.begin() + 4096);
            const auto loaded = take(load_macho(std::make_shared<MemoryStorage>(data), {}, {}));
            check(loaded.metadata.macho->data_in_code[0].offset == FileOffset{5121} &&
                      loaded.metadata.macho->data_in_code[0].record_file_offset == 7596 &&
                      loaded.image->code_window(entry(true), 15) == 1,
                  "FAT32/64 native/swapped protection records remain selected-slice relative with absolute exposed "
                  "file positions");
        }
    auto data = guarded(true, false, 1024, 4);
    const auto last = 32 + field32(data, 20) - 16;
    put(data, last + 12, 7, 4, false);
    check(!load_macho(std::make_shared<MemoryStorage>(data), {}, {}), "partial data-in-code record is rejected");
    data = guarded(true, false, 4094, 4);
    check(!load_macho(std::make_shared<MemoryStorage>(data), {}, {}),
          "linked data range cannot cross selected slice boundary");
    data = guarded(true, true, 4095, 2);
    check(!load_macho(std::make_shared<MemoryStorage>(data), {}, {}),
          "encrypted extent cannot escape its selected slice");
    data = guarded(true, false, 1024, 4);
    put(data, last + 4, 8, 4, false);
    put(data, 20, field32(data, 20) - 8, 4, false);
    check(!load_macho(std::make_shared<MemoryStorage>(data), {}, {}),
          "protection command-specific minimum is checked after envelope validation");
    data = guarded(true, false, 1024, 4);
    put(data, table_at + 6, 0xffff, 2, false);
    auto loaded = take(load_macho(std::make_shared<MemoryStorage>(data), {}, {}));
    check(!loaded.metadata.macho->protections_complete && !loaded.image->code_window(entry(true), 1),
          "unknown data kind remains explicit and never grants code permission");
    data = guarded(true, true, 1024, 4, 0);
    const auto signature = append_command(data, true, false, 0x1d, 16);
    put(data, signature + 8, 3600, 4, false);
    put(data, signature + 12, 16, 4, false);
    loaded = take(load_macho(std::make_shared<MemoryStorage>(data), {}, {}));
    check(loaded.metadata.macho->code_signatures.size() == 1 &&
              loaded.metadata.macho->code_signatures[0].offset == FileOffset{3600} && !loaded.metadata_complete &&
              loaded.image->code_window(entry(true), 15) == 15,
          "signature blob is a bounded declaration, never authentication or a code permission change");
    std::stop_source canceled;
    canceled.request_stop();
    const auto stopped = load_macho(std::make_shared<MemoryStorage>(data), {}, canceled.get_token());
    check(!stopped && stopped.error().code == ErrorCode::canceled, "protection parsing honors cancellation");
    auto layout = loaded.image->layout();
    layout.code_exclusions.resize(1000001);
    const auto limited = Image::create(loaded.image->storage(), std::move(layout));
    check(!limited && limited.error().code == ErrorCode::resource_limit,
          "code-policy count budget is checked before indexing");
}
void object_intersections() {
    auto data = macho_fixture::symbols(true, false, true);
    // Adjacent VM declarations retain separate object domains and file backing.
    put(data, 32 + 72 + 80 + 32, 0x108, 8, false);
    const auto table = append_command(data, true, false, 0x29, 16);
    put(data, table + 8, table_at, 4, false);
    put(data, table + 12, 8, 4, false);
    put(data, table_at, 0x106, 4, false);
    put(data, table_at + 4, 4, 2, false);
    put(data, table_at + 6, 1, 2, false);
    const auto loaded = take(load_macho(std::make_shared<MemoryStorage>(data), {}, {}));
    check(!loaded.image->code_window({{1}, 6}, 1) && !loaded.image->code_window({{2}, 0}, 1) &&
              loaded.image->code_window({{2}, 2}, 1) == 1,
          "a partial object data declaration excludes every mapped section intersection");
}
void forged_policy_cache() {
    const auto loaded = take(load_macho(std::make_shared<MemoryStorage>(guarded(true, true, 1024, 5)), {}, {}));
    auto layout = loaded.image->layout();
    layout.code_exclusions.clear();
    layout.encrypted_ranges.clear();
    const auto unguarded = take(Image::create(loaded.image->storage(), std::move(layout)));
    AnalysisKey key;
    key.input = {loaded.image->storage()->size(), take(hash_source(*loaded.image->storage(), {}))};
    key.engine_fingerprint = function_engine_fingerprint();
    auto proposal =
        take(analyze_derived(unguarded, std::make_shared<const ImageMetadata>(loaded.metadata), {}, {}, key, {}));
    check(!proposal.functions->instructions.empty(),
          "hostile cache fixture actually contains code suppressed by authoritative policy");
    check(!derive_references(*loaded.image, *proposal.functions, loaded.metadata, {}, {}),
          "reference derivation rejects caller-supplied code facts crossing exclusions");
    proposal.mapping_fingerprint = take(loaded.image->mapping_fingerprint());
    check(!validate_derived_source(proposal, *loaded.image, {}),
          "source binding rejects excluded code even when attacker supplies the authoritative mapping hash");
    const auto wire = take(encode_derived(proposal, {}));
    const auto decoded = decode_derived(wire, *loaded.image, loaded.metadata, {}, {}, key, {});
    check(!decoded && decoded.error().message.find("policy") != std::string::npos,
          "valid checksum and mapping hash cannot authorize decoding cached ciphertext instructions");
}
void aliases_and_highvm() {
    auto data = guarded(true, false, 1025, 4);
    put(data, 32 + 32, 8192, 8, false);
    put(data, 32 + 68, 1, 4, false);
    auto loaded = take(load_macho(std::make_shared<MemoryStorage>(data), {}, {}));
    const Address high{{0}, entry(true).offset + 4096};
    check(loaded.image->code_window(high, 15) == 1 && !take(decode_at(*loaded.image, high)).instruction,
          "SG_HIGHVM exclusions follow initialized high-placement file backing");
    data = guarded(true, true, 1025, 4);
    const auto alias = append_command(data, true, false, 0x19, 72);
    constexpr auto alias_base = UINT64_C(0x200000000);
    segment(data, true, false, alias, alias_base, 4096, 0, 4096, 7);
    loaded = take(load_macho(std::make_shared<MemoryStorage>(data), {}, {}));
    check(loaded.image->code_window(entry(true), 15) == 1 &&
              loaded.image->code_window({{0}, alias_base + 1024}, 15) == 1 &&
              !loaded.image->plaintext_window({{0}, alias_base + 1025}, 1),
          "every initialized virtual alias of encrypted file bytes receives the same hard policy");
    const auto narrow = take(load_macho(std::make_shared<MemoryStorage>(guarded(false, true, 1024, 4, 0)), {}, {}));
    auto layout = narrow.image->layout();
    layout.code_exclusions = {{{{0}, UINT64_C(0x100000000)}, 1}};
    check(!Image::create(narrow.image->storage(), std::move(layout)),
          "policy extent cannot escape a 32-bit image domain");
}
void encrypted_relocation_source() {
    auto data = relocated(true);
    relocation(data, false, 0, 0, 1, 0, 3, false, true);
    put(data, 768, 0, 8, false);
    const auto command = append_command(data, true, false, 0x2c, 24);
    put(data, command + 8, 768, 4, false);
    put(data, command + 12, 8, 4, false);
    put(data, command + 16, 1, 4, false);
    const auto loaded = take(load_macho(std::make_shared<MemoryStorage>(data), {}, {}));
    auto layout = loaded.image->layout();
    layout.code_exclusions.clear();
    layout.encrypted_ranges.clear();
    const auto unguarded = take(Image::create(loaded.image->storage(), std::move(layout)));
    auto clear_metadata = loaded.metadata;
    clear_metadata.macho->encryption.clear();
    const auto plain = take(RelocationResolver::create(*unguarded, clear_metadata, {}));
    const auto guarded_resolver = take(RelocationResolver::create(*loaded.image, loaded.metadata, {}));
    const auto pure = take(MachORelocationResolver::create(loaded.metadata, {}));
    check(!take(pure.data(0, {})).address,
          "metadata-only relocation API cannot use encrypted source addends as plaintext");
    const auto encrypted = take(guarded_resolver.data(0, {}));
    check(take(plain.data(0, {})).address.has_value() && !encrypted.address && !encrypted.constant &&
              std::get<MachOResolutionReason>(encrypted.reason) == MachOResolutionReason::unsupported,
          "encrypted relocation field cannot supply a plaintext addend or preferred target");
    const auto refs = take(derive_references(*loaded.image, FunctionSnapshot{}, loaded.metadata, {}, {}));
    check(refs->all().size() == 1 && std::holds_alternative<UnresolvedTarget>(refs->all()[0].target) &&
              bool(decode_reference_index(take(encode_reference_index(*refs, {})), {})),
          "encrypted relocation retains raw source provenance without a numeric data reference");
}
int main(int argc, char **argv) {
    if (argc != 2)
        return 2;
    return run([&] {
        decode_guards();
        project_guard_patch();
        independent_object(argv[1]);
        encrypted_pointer_sources();
        canonical_policy();
        declarations_and_bounds();
        object_intersections();
        forged_policy_cache();
        aliases_and_highvm();
        encrypted_relocation_source();
    });
}
