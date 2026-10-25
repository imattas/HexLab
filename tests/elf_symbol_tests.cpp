#include "hexlab/loaders/elf.hpp"
#include "hexlab/analysis/functions.hpp"
#include "hexlab/workspace/project.hpp"
#include "hexlab/analysis/derived_cache.hpp"
#include "hexlab/workspace/project_analysis.hpp"
#include "support/elf_fixture.hpp"
#include "support/analysis_fixture.hpp"
#include "support/checks.hpp"
#include "support/fixture_files.hpp"
#include <algorithm>
#include <array>
using namespace hexlab;
using namespace hexlab_test;
using namespace hexlab_test::elf_fixture;
namespace {
template <class T> T take(Result<T> value) {
    if (!value)
        throw std::runtime_error(value.error().message);
    return std::move(value.value());
}
constexpr std::size_t symoff = 1024, stroff = 1536, indexoff = 1792;
void symbol(std::vector<std::byte> &data, bool wide, bool big, std::size_t i, std::uint32_t name, std::uint8_t info,
            std::uint8_t other, std::uint16_t section, std::uint64_t value, std::uint64_t size) {
    const auto at = symoff + i * (wide ? 24 : 16);
    put(data, at, name, 4, big);
    put(data, at + (wide ? 4 : 12), info, 1);
    put(data, at + (wide ? 5 : 13), other, 1);
    put(data, at + (wide ? 6 : 14), section, 2, big);
    put(data, at + (wide ? 8 : 4), value, wide ? 8 : 4, big);
    put(data, at + (wide ? 16 : 8), size, wide ? 8 : 4, big);
}
void links(std::vector<std::byte> &data, bool wide, bool big, std::size_t index, std::uint32_t link, std::uint32_t info,
           std::uint64_t stride) {
    const auto at = 512 + index * (wide ? 64 : 40);
    put(data, at + (wide ? 40 : 24), link, 4, big);
    put(data, at + (wide ? 44 : 28), info, 4, big);
    put(data, at + (wide ? 56 : 36), stride, wide ? 8 : 4, big);
}
std::vector<std::byte> fixture(bool wide, bool big = false, bool dynamic = false) {
    auto data = object(wide, big);
    data.resize(4096);
    data[258] = std::byte{0xc3};
    data[259] = std::byte{0xc3};
    data[272] = std::byte{0x90};
    std::string strings(1, '\0');
    const auto name = [&](std::string_view text) {
        auto at = strings.size();
        strings += text;
        strings += '\0';
        return static_cast<std::uint32_t>(at);
    };
    symbol(data, wide, big, 1, name("same"), 2, 0, 1, 0, 2);
    symbol(data, wide, big, 2, 1, 2, 0, 2, 0, 2);
    symbol(data, wide, big, 3, name("tls"), 6, 0, 3, 0, 4);
    symbol(data, wide, big, 4, name("external"), 0x12, 0, 0, 0, 0);
    symbol(data, wide, big, 5, name("absolute"), 0x10, 0, 0xfff1, 0x1234, 0);
    symbol(data, wide, big, 6, name("common"), 0x11, 0, 0xfff2, 16, 32);
    symbol(data, wide, big, 7, name("weak"), 0x22, 2, 1, 2, 1);
    symbol(data, wide, big, 8, name("object"), 0x11, 0, 3, 4, 4);
    symbol(data, wide, big, 9, name("resolver"), 0x1a, 0, 1, 3, 1);
    symbol(data, wide, big, 10, name("filedata"), 0x10, 0, 6, 0, 1);
    symbol(data, wide, big, 11, name("end"), 0x10, 0, 1, 4, 0);
    for (std::size_t i = 0; i < strings.size(); ++i)
        data[stroff + i] = std::byte(strings[i]);
    section(data, wide, 5, 0, dynamic ? 11 : 2, 0, 0, symoff, 12 * (wide ? 24 : 16), wide ? 8 : 4, big);
    section(data, wide, 6, 0, 3, 0, 0, stroff, strings.size(), 1, big);
    links(data, wide, big, 5, 6, 4, wide ? 24 : 16);
    return data;
}
Result<LoadedImage> load(std::vector<std::byte> data) {
    return load_elf(std::make_shared<MemoryStorage>(std::move(data)), {});
}
void records() {
    for (bool wide : {false, true})
        for (bool big : {false, true})
            for (bool dynamic : {false, true}) {
                auto data = fixture(wide, big, dynamic);
                auto result = load(data);
                check(bool(result), "literal32/64 LE/BE SYMTAB/DYNSYM parsed");
                if (!result)
                    continue;
                const auto &loaded = result.value();
                const auto &symbols = loaded.metadata.elf->symbols;
                check(symbols.size() == 12 && loaded.metadata.exports.empty(),
                      "ELF symbols retain own table without fabricated PE exports");
                check(loaded.metadata_complete == !big,
                      "symbol metadata parsed while unsupported decoder diagnostics remain explicit");
                check(symbols[1].table == 5 && symbols[1].index == 1 && symbols[1].name == "same" &&
                          symbols[1].binding == 0 && symbols[1].type == 2 && symbols[1].address == Address{{1}, 0} &&
                          symbols[2].address == Address{{2}, 0},
                      "table identity and duplicate same-offset definitions retain section domains");
                check(symbols[3].state == ElfSymbolState::tls && !symbols[3].address && symbols[3].type == 6,
                      "TLS offset remains typed instead of fabricated virtual address");
                check(symbols[4].state == ElfSymbolState::undefined && !symbols[4].address &&
                          symbols[4].name == "external",
                      "undefined function remains symbolic");
                check(symbols[5].state == ElfSymbolState::absolute && symbols[5].value == 0x1234 && !symbols[5].address,
                      "absolute value is not forced into memory coordinates");
                check(symbols[6].state == ElfSymbolState::common && symbols[6].value == 16 && symbols[6].size == 32 &&
                          !symbols[6].address,
                      "unallocated common preserves alignment and size");
                check(symbols[7].binding == 2 && symbols[7].visibility == 2 && symbols[7].address == Address{{1}, 2},
                      "weak binding and hidden visibility retained");
                check(symbols[8].address == Address{{3}, 4} && !loaded.image->to_file_offset(*symbols[8].address),
                      "defined BSS symbol has address but no canonical patch bytes");
                check(symbols[9].type == 10 && !symbols[10].address && !symbols[11].address,
                      "IFUNC kind preserved; nonallocated and section-end labels get no mapped address");
                check(loaded.metadata_reads.intersects({symoff}, 12 * (wide ? 24 : 16)).value() &&
                          loaded.metadata_reads.intersects({stroff}, 1).value(),
                      "symbol and string bytes register metadata dependencies");
                auto raw = data;
                put(raw, symoff + (wide ? 5 : 13) + 7 * (wide ? 24 : 16), 0xfd, 1);
                auto other = load(raw);
                check(other && other.value().metadata.elf->symbols[7].other == 0xfd &&
                          other.value().metadata.elf->symbols[7].visibility == 5,
                      "other raw bits and current visibility mask preserved");
            }
}
void malformed() {
    for (bool wide : {false, true})
        for (bool big : {false, true}) {
            const auto data = fixture(wide, big);
            auto bad = data;
            links(bad, wide, big, 5, 99, 4, wide ? 24 : 16);
            check(!load(bad), "symbol string-table link bounded");
            bad = data;
            links(bad, wide, big, 5, 1, 4, wide ? 24 : 16);
            check(!load(bad), "symbol names link must target STRTAB");
            bad = data;
            links(bad, wide, big, 5, 6, 4, wide ? 23 : 15);
            check(!load(bad), "symbol entry stride cannot truncate required fields");
            bad = data;
            section(bad, wide, 5, 0, 2, 0, 0, symoff, 12 * (wide ? 24 : 16) - 1, 8, big);
            check(!load(bad), "symbol table requires whole records");
            bad = data;
            put(bad, symoff + (wide ? 24 : 16), 999, 4, big);
            check(!load(bad), "symbol name offset bounded");
            bad = data;
            bad[stroff] = std::byte{'x'};
            check(!load(bad), "symbol STRTAB starts with empty string");
            bad = data;
            symbol(bad, wide, big, 1, 1, 2, 0, 99, 0, 2);
            check(!load(bad), "symbol section index bounded");
            bad = data;
            symbol(bad, wide, big, 1, 1, 2, 0, 1, 3, 2);
            check(!load(bad), "defined symbol extent bounded by declared section");
            bad = data;
            symbol(bad, wide, big, 0, 1, 0, 0, 0, 0, 0);
            check(!load(bad), "reserved first symbol has literal zero identity");
            bad = data;
            links(bad, wide, big, 5, 6, 13, wide ? 24 : 16);
            check(!load(bad), "first nonlocal boundary bounded by symbol count");
            bad = data;
            links(bad, wide, big, 5, 6, 3, wide ? 24 : 16);
            check(!load(bad), "local/nonlocal partition agrees with table boundary");
            bad = data;
            symbol(bad, wide, big, 1, 1, 2, 0, 0xffff, 0, 2);
            check(!load(bad), "XINDEX requires linked companion table");
            bad = data;
            symbol(bad, wide, big, 1, 1, 2, 0, 0xff10, 0, 2);
            auto reserved = load(bad);
            check(reserved && reserved.value().metadata.elf->symbols[1].state == ElfSymbolState::reserved &&
                      !reserved.value().metadata.elf->symbols[1].address,
                  "reserved processor section index stays unresolved");
        }
}
void extended() {
    for (bool wide : {false, true})
        for (bool big : {false, true}) {
            auto data = fixture(wide, big);
            symbol(data, wide, big, 1, 1, 2, 0, 0xffff, 0, 2);
            section(data, wide, 7, 0, 18, 0, 0, indexoff, 12 * 4, 4, big);
            links(data, wide, big, 7, 5, 0, 4);
            put(data, indexoff + 4, 1, 4, big);
            auto result = load(data);
            check(result && result.value().metadata.elf->symbols[1].raw_section == 0xffff &&
                      result.value().metadata.elf->symbols[1].section_index == 1 &&
                      result.value().metadata.elf->symbols[1].address == Address{{1}, 0},
                  "SHNDX companion resolves actual section while preserving raw escape");
            if (result)
                check(result.value().metadata_reads.intersects({indexoff}, 12 * 4).value(),
                      "extended-index bytes register dependencies");
            auto bad = data;
            put(bad, indexoff + 8, 1, 4, big);
            check(!load(bad), "unused SHNDX companion entries must be zero");
            bad = data;
            put(bad, indexoff + 4, 99, 4, big);
            check(!load(bad), "extended actual section index bounded");
            bad = data;
            section(bad, wide, 7, 0, 18, 0, 0, indexoff, 11 * 4, 4, big);
            check(!load(bad), "companion has one entry per symbol");
        }
}
void orphan_and_recovery() {
    auto orphan = object(true);
    orphan.resize(4096);
    section(orphan, true, 5, 0, 18, 0, 0, indexoff, 4, 4);
    links(orphan, true, false, 5, 0, 0, 4);
    check(!load(orphan), "orphan SHNDX cannot claim valid metadata without a symbol table");
    const auto loaded = load(fixture(true)).value();
    const auto functions = recover_functions(*loaded.image, loaded.metadata, {}, {}, {}).value();
    check(functions->functions.size() == 3,
          "local and weak executable FUNC definitions seed recovery without an ELF entry");
    check(std::all_of(
              functions->functions.begin(), functions->functions.end(),
              [](const auto &f) { return f->seeds.size() == 1 && f->seeds.front().kind == FunctionSeedKind::symbol; }),
          "symbol function seeds have an explicit provenance kind rather than an entry/export disguise");
    check(std::none_of(functions->functions.begin(), functions->functions.end(),
                       [](const auto &f) { return f->entry == Address{{1}, 3}; }),
          "IFUNC resolver metadata never becomes an ordinary FUNC seed");
    ProjectSnapshot snapshot;
    snapshot.loaded = std::make_shared<const LoadedImage>(loaded);
    check(presentation_name(snapshot, Address{{1}, 0}) == "same" &&
              presentation_name(snapshot, Address{{2}, 0}) == "same",
          "ELF local names preserve domain identity in shared presentation");
    auto state = std::make_shared<database::ProjectState>();
    auto user = std::make_shared<database::UserState>();
    user->annotations.push_back({1, Address{{1}, 0}, "chosen", {}});
    state->user = user;
    snapshot.state = state;
    check(presentation_name(snapshot, Address{{1}, 0}) == "chosen" &&
              presentation_name(snapshot, Address{{2}, 0}) == "same",
          "user name overrides one ELF domain without crossing into another");
}
struct ProjectFixture {
    FixtureFile input{fixture(true)};
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
void project_names_and_cache() {
    const LoadRecipe recipe{Format::elf, {}};
    const auto encoded = take(encode_recipe(recipe));
    check(encoded == bytes({1, 0, 4}) && take(decode_recipe(encoded)).format == Format::elf,
          "ELF durable recipe has a literal separate tag");
    check(take(encode_recipe({Format::pe, {}})) == bytes({1, 0, 2}),
          "existing PE recipe literal remains byte-identical");
    check(!decode_recipe(bytes({1, 0, 4, 0})), "ELF recipe refuses trailing bytes");
    ProjectFixture f;
    f.store = take(database::ProjectStore::create(f.path, {}));
    auto source = take(FileStorage::open(f.input.path));
    take(f.store->import_input(*source, recipe, f.input.path, {}));
    source.reset();
    f.session = take(ProjectSession::attach(f.store, {}, {}));
    auto snapshot = f.session->snapshot();
    check(snapshot->presentation && snapshot->functions && snapshot->functions->functions.size() == 3 &&
              presentation_name(*snapshot, Address{{1}, 0}) == "same" &&
              presentation_name(*snapshot, Address{{2}, 0}) == "same",
          "real ELF project builds indexed section-aware symbol names and recovered functions");
    auto collision = take(f.session->execute(Rename{Address{{1}, 2}, "same"}, 0, {}));
    check(presentation_name(*collision, Address{{1}, 0}) == "same_1_0" &&
              presentation_name(*collision, Address{{1}, 2}) == "same" &&
              presentation_name(*collision, Address{{2}, 0}) == "same" &&
              presentation_name(*snapshot, Address{{1}, 0}) == "same",
          "indexed automatic ELF names disambiguate against user names only within their domain");
    take(f.session->undo({}));
    auto renamed = take(f.session->execute(Rename{Address{{1}, 0}, "user_first"}, 0, {}));
    check(presentation_name(*renamed, Address{{1}, 0}) == "user_first" &&
              presentation_name(*renamed, Address{{2}, 0}) == "same",
          "indexed ELF user override stays in its own domain");
    auto retained = renamed;
    auto undone = take(f.session->undo({}));
    check(presentation_name(*undone, Address{{1}, 0}) == "same" &&
              presentation_name(*retained, Address{{1}, 0}) == "user_first",
          "undo restores symbol fallback while retained index stays immutable");
    auto redone = take(f.session->redo({}));
    const auto key = take(project_analysis_key(*redone, {}));
    const auto proposal =
        take(analyze_derived(redone->loaded->image, std::make_shared<const ImageMetadata>(redone->loaded->metadata),
                             redone->state->user->decisions, {}, key, {}));
    const auto wire = take(encode_derived(proposal, {}));
    auto decoded = decode_derived(wire, *redone->loaded->image, redone->loaded->metadata,
                                  redone->state->user->decisions, {}, key, {});
    check(decoded && decoded.value().functions->functions.size() == 3,
          "canonical cache roundtrips explicit ELF symbol roots");
    auto missing = redone->loaded->metadata;
    missing.elf->symbols.clear();
    check(!decode_derived(wire, *redone->loaded->image, missing, redone->state->user->decisions, {}, key, {}),
          "correctly checksummed cache cannot invent roots absent from authoritative ELF metadata");
    auto forged = proposal;
    auto functions = std::make_shared<FunctionSnapshot>(*proposal.functions);
    for (auto &row : functions->functions) {
        auto copy = std::make_shared<FunctionRecord>(*row);
        for (auto &seed : copy->seeds)
            seed.kind = FunctionSeedKind::entry;
        row = copy;
    }
    forged.functions = functions;
    check(!decode_derived(take(encode_derived(forged, {})), *redone->loaded->image, redone->loaded->metadata,
                          redone->state->user->decisions, {}, key, {}),
          "forged valid entry seed kind cannot replace ELF symbol provenance");
    const auto before = take(f.store->snapshot());
    take(f.store->store_derived_cache(proposal, {}));
    check(take(f.store->snapshot()) == before, "ELF cache writes preserve authoritative user history");
    const auto revisions = redone->state->revisions;
    const auto cursor = redone->state->history_cursor;
    f.session.reset();
    f.store.reset();
    check(std::filesystem::remove(f.input.path), "owned external ELF source removed before readonly reopen");
    f.store = take(database::ProjectStore::open(f.path, database::ProjectMode::read_only, {}));
    f.session = take(ProjectSession::attach(f.store, {}, {}));
    auto reopened = f.session->snapshot();
    check(reopened->derived_cache_status == database::CacheStatus::hit && reopened->functions->functions.size() == 3 &&
              presentation_name(*reopened, Address{{1}, 0}) == "user_first" &&
              presentation_name(*reopened, Address{{2}, 0}) == "same",
          "source-missing readonly project restores indexed ELF names and validated symbol cache");
    check(reopened->state->revisions == revisions && reopened->state->history_cursor == cursor &&
              !f.session->execute(Rename{Address{{2}, 0}, "forbidden"}, 0, {}),
          "readonly ELF name refusal preserves revision/history");
}
void special_forms() {
    for (bool wide : {false, true})
        for (bool big : {false, true}) {
            const auto original = fixture(wide, big);
            auto data = original;
            const auto stride = wide ? 24u : 16u;
            std::fill(data.begin() + symoff, data.begin() + symoff + 12 * 32, std::byte{0xa5});
            for (std::size_t i = 0; i < 12; ++i)
                std::copy_n(original.begin() + symoff + i * stride, stride, data.begin() + symoff + i * 32);
            section(data, wide, 5, 0, 2, 0, 0, symoff, 12 * 32, 8, big);
            links(data, wide, big, 5, 6, 4, 32);
            auto loaded = load(data);
            check(loaded && loaded.value().metadata.elf->symbols[7].address == Address{{1}, 2},
                  "larger symbol stride ignores extension padding without losing entries");
            data = original;
            data[stroff + 1] = std::byte{'a'};
            data[stroff + 2] = std::byte{0xff};
            data[stroff + 3] = std::byte{'\n'};
            data[stroff + 4] = std::byte{'b'};
            loaded = load(data);
            check(loaded && loaded.value().metadata.elf->symbols[1].name == std::string("a\xff\nb", 4),
                  "ELF names preserve raw non-UTF8 and control bytes for safe frontend escaping");
            if (wide) {
                data = original;
                symbol(data, true, big, 5, 0, 0x10, 0, 0xfff1, UINT64_C(0x123456789abc), 0);
                loaded = load(data);
                check(loaded && loaded.value().metadata.elf->symbols[5].value == UINT64_C(0x123456789abc),
                      "ELF64 symbol value remains full width");
            }
        }
    for (bool wide : {false, true})
        for (auto type : {2u, 3u}) {
            auto data = fixture(wide);
            const auto base = wide ? UINT64_C(0x140001000) : UINT64_C(0x8048000);
            put(data, 16, type, 2);
            program(data, wide, 0, 1, 256, base, 20, 40, 7, 16);
            section(data, wide, 1, 1, 1, 6, base, 256, 4, 16);
            section(data, wide, 2, 7, 1, 6, base + 16, 272, 4, 16);
            section(data, wide, 3, 14, 8, 3, base + 32, 0xffff, 8, 8);
            symbol(data, wide, false, 1, 1, 2, 0, 1, base, 2);
            symbol(data, wide, false, 2, 1, 2, 0, 2, base + 16, 2);
            symbol(data, wide, false, 6, 0, 0x10, 0, 0xfff1, 16, 32);
            symbol(data, wide, false, 7, 0, 0x22, 2, 1, base + 2, 1);
            symbol(data, wide, false, 8, 0, 0x11, 0, 3, base + 36, 4);
            symbol(data, wide, false, 9, 0, 0x1a, 0, 1, base + 3, 1);
            symbol(data, wide, false, 11, 0, 0x10, 0, 1, base + 4, 0);
            auto result = load(data);
            check(result && result.value().metadata.elf->symbols[1].address == Address{{0}, base} &&
                      result.value().metadata.elf->symbols[2].address == Address{{0}, base + 16},
                  "EXEC/DYN symbol values are virtual coordinates rather than section-relative offsets");
            if (result)
                check(result.value().metadata.elf->symbols[3].state == ElfSymbolState::tls &&
                          !result.value().metadata.elf->symbols[3].address &&
                          recover_functions(*result.value().image, result.value().metadata, {}, {}, {})
                                  .value()
                                  ->functions.size() == 3,
                      "EXEC/DYN recovery uses valid FUNC roots and does not invent TLS or IFUNC targets");
        }
}
class CancelStorage final : public ByteStorage {
    MemoryStorage source_{fixture(true)};
    std::stop_source &stop_;

  public:
    explicit CancelStorage(std::stop_source &stop) : stop_(stop) {}
    std::uint64_t size() const noexcept override { return source_.size(); }
    Result<ByteView> read_at(FileOffset at, std::size_t n) const override {
        if (at.value == symoff)
            stop_.request_stop();
        return source_.read_at(at, n);
    }
};
void cancellation() {
    std::stop_source stop;
    auto source = std::make_shared<CancelStorage>(stop);
    auto result = load_elf(source, stop.get_token());
    check(!result && result.error().code == ErrorCode::canceled,
          "cancellation during actual symbol records publishes no partial image");
    check(bool(load_elf(source, {})), "canceled symbol import leaves no parser state preventing a retry");
}
void high_section_index() {
    // Actual extended indexes may numerically overlap the reserved16-bit tags.
    // Index65521 here names a real section; it must not become SHN_ABS.
    constexpr std::uint32_t target = 0xfff1, section_count = target + 1;
    constexpr std::size_t table_end = 512 + std::size_t{section_count} * 64;
    constexpr auto symbols_at = table_end + 256, strings_at = symbols_at + 64, indices_at = strings_at + 16;
    auto data = base(true, false, 1);
    data.resize(indices_at + 8);
    section(data, true, 0, 0, 0, 0, 0, 0, section_count, 0);
    section(data, true, 1, 0, 2, 0, 0, symbols_at, 48, 8);
    links(data, true, false, 1, 3, 1, 24);
    section(data, true, 2, 0, 18, 0, 0, indices_at, 8, 4);
    links(data, true, false, 2, 1, 0, 4);
    section(data, true, 3, 0, 3, 0, 0, strings_at, 6, 1);
    section(data, true, target, 0, 1, 6, 0, 256, 2, 1);
    put(data, 60, 0, 2);
    put(data, symbols_at + 24, 1, 4);
    put(data, symbols_at + 28, 0x12, 1);
    put(data, symbols_at + 30, 0xffff, 2);
    put(data, symbols_at + 40, 2, 8);
    put(data, indices_at + 4, target, 4);
    constexpr std::string_view name("\0high\0", 6);
    for (std::size_t i = 0; i < name.size(); ++i)
        data[strings_at + i] = std::byte(name[i]);
    data[256] = std::byte{0x90};
    data[257] = std::byte{0xc3};
    auto result = load(std::move(data));
    check(result && result.value().metadata.elf->symbols[1].state == ElfSymbolState::defined &&
              result.value().metadata.elf->symbols[1].section_index == target &&
              result.value().metadata.elf->symbols[1].address == Address{{target}, 0},
          "genuine extended section index bypasses reserved16-bit tag semantics");
    if (result) {
        const auto functions = recover_functions(*result.value().image, result.value().metadata, {}, {}, {});
        check(functions && functions.value()->functions.size() == 1 &&
                  functions.value()->functions.front()->entry == Address{{target}, 0},
              "high-index ELF symbol seeds actual section-domain recovery");
    }
}
void arm_thumb_function_address() {
    auto data = fixture(false);
    put(data, 18, 40, 2); // EM_ARM
    symbol(data, false, false, 1, 1, 2, 0, 1, 1, 2);
    auto result = load(std::move(data));
    check(bool(result), "ARM ELF32 function with Thumb state bit loads");
    if (!result)
        return;
    const auto &function = result.value().metadata.elf->symbols[1];
    check(function.value == 1, "raw odd ELF function value preserves the Thumb state bit");
    check(function.address == Address{{1}, 0},
          "ELF function image address clears the Thumb state bit before section mapping");
}
std::vector<std::byte> arm_mapping_fixture(bool conflict = false) {
    auto data = object(false);
    data.resize(4096);
    put(data, 18, 40, 2); // EM_ARM
    section(data, false, 1, 1, 1, 6, 0, 256, 12, 4);
    std::string strings("\0", 1);
    const auto name = [&](std::string_view text) {
        const auto offset = static_cast<std::uint32_t>(strings.size());
        strings.append(text);
        strings.push_back('\0');
        return offset;
    };
    const auto a = name("$a");
    const auto t = name("$t.entry");
    const auto d = name("$d");
    const auto alias = conflict ? name("$a.alias") : 0;
    const auto function = name("thumb_function");
    symbol(data, false, false, 1, a, 0, 0, 1, 0, 0);
    symbol(data, false, false, 2, t, 0, 0, 1, 4, 0);
    symbol(data, false, false, 3, d, 0, 0, 1, 8, 0);
    if (conflict)
        symbol(data, false, false, 4, alias, 0, 0, 1, 4, 0);
    symbol(data, false, false, conflict ? 5 : 4, function, 0x12, 0, 1, 5, 2);
    section(data, false, 5, 0, 2, 0, 0, symoff, (conflict ? 6 : 5) * 16, 4);
    links(data, false, false, 5, 6, conflict ? 5 : 4, 16);
    section(data, false, 6, 0, 3, 0, 0, stroff, strings.size(), 1);
    for (std::size_t i = 0; i < strings.size(); ++i)
        data[stroff + i] = std::byte(strings[i]);
    return data;
}
std::vector<std::byte> arm_executable_mapping_fixture() {
    auto data = arm_mapping_fixture();
    put(data, 16, 2, 2);      // ET_EXEC
    put(data, 24, 0x1005, 4); // Odd entry denotes Thumb.
    program(data, false, 0, 1, 256, 0x1000, 12, 12, 5, 1);
    section(data, false, 1, 1, 1, 6, 0x1000, 256, 12, 4);
    for (const auto &[index, value] :
         std::array<std::pair<std::size_t, std::uint32_t>, 4>{{{1, 0x1000}, {2, 0x1004}, {3, 0x1008}, {4, 0x1005}}})
        put(data, symoff + index * 16 + 4, value, 4);
    return data;
}
void arm_odd_elf_entry_is_stateful_physical_root() {
    auto result = load(arm_executable_mapping_fixture());
    check(bool(result), "ARM executable with Thumb ELF entry loads");
    if (!result)
        return;
    const auto &image = *result.value().image;
    check(std::find(image.layout().entries.begin(), image.layout().entries.end(), Address{{0}, 0x1004}) !=
              image.layout().entries.end(),
          "odd ELF entry canonicalizes to the even physical image address");
    check(image.layout().arm_profile.has_value(), "ELF mapping declarations construct an executable context profile");
    if (!image.layout().arm_profile)
        return;
    const auto root = std::find_if(image.layout().arm_profile->roots.begin(), image.layout().arm_profile->roots.end(),
                                   [](const auto &row) { return row.at == Address{{0}, 0x1004}; });
    check(root != image.layout().arm_profile->roots.end() && root->mode == ExecutionMode::thumb &&
              root->known_thumb_it_clear &&
              std::any_of(root->sources.begin(), root->sources.end(),
                          [](const auto &source) {
                              return source.kind == ArmContextSourceKind::platform_entry &&
                                     source.evidence == ArmSourceEvidence{{24}, 4};
                          }),
          "Thumb ELF entry contributes a known-clear platform root with header-byte provenance");
}
void arm_mapping_disagreement_is_conflict() {
    auto result = load(arm_mapping_fixture(true));
    check(bool(result), "conflicting ARM mapping sources remain loadable metadata");
    if (!result)
        return;
    const auto &image = *result.value().image;
    const auto *range = image.arm_code_at({{1}, 4});
    check(range && range->kind == ArmCodeKind::conflict && range->sources.size() == 2,
          "different same-address ELF mapping symbols create an explicit conflict");
    auto context = image.context_at({{1}, 4});
    check(!context && context.error().code == ErrorCode::conflict,
          "conflicting ELF mapping declarations cannot select one decoder mode");
    check(image.layout().arm_profile && image.layout().arm_profile->roots.empty(),
          "function root inside a conflicted mapping interval is not published");
}
void arm_mapping_symbols_define_context() {
    auto result = load(arm_mapping_fixture());
    check(bool(result), "ARM mapping-symbol ELF fixture loads");
    if (!result)
        return;
    const auto &image = *result.value().image;
    check(image.layout().arm_profile.has_value(), "ARM mapping symbols create an image context profile");
    check(image.context_at({{1}, 0}) && image.context_at({{1}, 0}).value().mode == ExecutionMode::a32,
          "$a mapping symbol bounds an A32 interval in its section domain");
    check(image.context_at({{1}, 4}) && image.context_at({{1}, 4}).value().mode == ExecutionMode::thumb,
          "$t mapping symbol bounds a Thumb interval in its section domain");
    check(image.context_at({{1}, 8}) && image.context_at({{1}, 8}).value().mode == ExecutionMode::unknown &&
              image.arm_code_at({{1}, 8}) && image.arm_code_at({{1}, 8})->kind == ArmCodeKind::data,
          "$d mapping symbol creates a hard data interval with no decoder context");
    check(image.layout().arm_profile && image.layout().arm_profile->roots.size() == 1 &&
              image.layout().arm_profile->roots[0].at == Address{{1}, 4} &&
              image.layout().arm_profile->roots[0].mode == ExecutionMode::thumb &&
              image.layout().arm_profile->roots[0].known_thumb_it_clear,
          "odd ARM function value becomes an even Thumb root with a source-derived clear IT state");
    if (image.layout().arm_profile && !image.layout().arm_profile->ranges.empty()) {
        const auto &source = image.layout().arm_profile->ranges[0].sources[0];
        check(source.kind == ArmContextSourceKind::elf_mapping_symbol && source.namespace_id == 5 &&
                  source.record_index == 1 && source.evidence == ArmSourceEvidence{{symoff + 16}, 16},
              "mapping interval retains its exact ELF symbol-table record identity and bytes");
    }
}
} // namespace
int main() {
    return run([] {
        records();
        malformed();
        extended();
        orphan_and_recovery();
        project_names_and_cache();
        special_forms();
        cancellation();
        high_section_index();
        arm_thumb_function_address();
        arm_mapping_symbols_define_context();
        arm_mapping_disagreement_is_conflict();
        arm_odd_elf_entry_is_stateful_physical_root();
    });
}
