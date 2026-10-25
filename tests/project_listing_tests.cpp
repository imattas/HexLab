#include "hexlab/workspace/listing.hpp"
#include "hexlab/workspace/project.hpp"
#include "support/checks.hpp"
#include "support/fixture_files.hpp"
#include "support/analysis_fixture.hpp"
using namespace hexlab;
using namespace hexlab::database;
using namespace hexlab_test;
namespace {
template <class T> T take(Result<T> result) {
    if (!result)
        throw std::runtime_error(result.error().message);
    return std::move(result.value());
}
struct Fixture {
    FixtureFile file{std::span<const std::byte>{}};
    std::filesystem::path path = file.path.wstring() + L".listing.hxproj";
    std::shared_ptr<ProjectStore> store;
    std::shared_ptr<ProjectSession> session;
    Fixture(std::vector<std::byte> bytes, bool executable = true) {
        store = take(ProjectStore::create(path, {}));
        MemoryStorage input(std::move(bytes));
        take(store->import_input(
            input,
            {Format::raw,
             RawOptions{Architecture::x86_64, ExecutionMode::x86_64, {{0}, 0x1000}, true, false, executable, {}}},
            {}, {}));
        session = take(ProjectSession::attach(store, {}, {}));
    }
    ~Fixture() {
        session.reset();
        store.reset();
        std::error_code ignored;
        for (auto suffix : {L"", L"-wal", L"-shm"}) {
            auto item = path;
            item += suffix;
            std::filesystem::remove(item, ignored);
        }
    }
    DocumentSnapshot document() {
        DocumentSnapshot doc;
        doc.project = session->snapshot();
        doc.image = doc.project->loaded->image;
        return doc;
    }
};
void manual_tests() {
    Fixture f(bytes({0xc3, 0x90, 0xc3}));
    auto doc = f.document();
    auto preview = take(make_listing_page(doc, Address{{0}, 0x1001}, 2, ListingOptions{false, {}}));
    check(!preview.rows[0].instruction && preview.rows[0].bytes == bytes({0x90}),
          "GUI preview returns actual bytes without manual decoding");
    auto decoded = take(make_listing_page(doc, Address{{0}, 0x1001}, 2, ListingOptions{true, {}}));
    check(decoded.rows[0].instruction && decoded.rows[0].instruction->opcode == Opcode::nop &&
              decoded.rows[0].status == "manual decode",
          "worker listing service retains explicit manual decoding");
    take(f.session->execute(DefineRegion{Address{{0}, 0x1001}, 1, RegionKind::data}, 0, {}));
    take(f.session->refresh_analysis({}));
    auto data = take(make_listing_page(f.document(), Address{{0}, 0x1001}, 2, ListingOptions{true, {}}));
    check(!data.rows[0].instruction && data.rows[0].status == "manual data",
          "manual listing respects authoritative data decision");
    std::stop_source stop;
    stop.request_stop();
    auto canceled = make_listing_page(f.document(), Address{{0}, 0x1000}, 2, ListingOptions{true, stop.get_token()});
    check(!canceled && canceled.error().code == ErrorCode::canceled, "manual listing observes pool cancellation");
    Fixture nonexec(bytes({0xc3, 0x90, 0xc3}), false);
    take(nonexec.session->execute(DefineRegion{Address{{0}, 0x1000}, 3, RegionKind::code}, 0, {}));
    take(nonexec.session->refresh_analysis({}));
    auto code = take(make_listing_page(nonexec.document(), Address{{0}, 0x1001}, 2, ListingOptions{true, {}}));
    check(code.rows[0].instruction && code.rows[0].instruction->opcode == Opcode::nop,
          "manual code honors recorded override for non-executable initialized bytes");
    Fixture boundary(bytes({0xc3, 0xb0, 0xff, 0xc3}));
    take(boundary.session->execute(DefineRegion{Address{{0}, 0x1002}, 1, RegionKind::data}, 0, {}));
    take(boundary.session->refresh_analysis({}));
    auto cut = take(make_listing_page(boundary.document(), Address{{0}, 0x1001}, 2, ListingOptions{true, {}}));
    check(!cut.rows[0].instruction, "manual decode cannot consume bytes across an explicit data boundary");
}
void short_read_tests() {
    struct Short : ByteStorage {
        uint64_t size() const noexcept override { return 1; }
        Result<ByteView> read_at(FileOffset, std::size_t) const override {
            static auto owner = std::make_shared<const std::vector<std::byte>>();
            return ByteView{owner, *owner};
        }
    };
    auto source = std::make_shared<Short>();
    DocumentSnapshot doc;
    doc.image = take(Image::create(source, {{{0}, 64, 1, ByteOrder::little},
                                            Architecture::x86_64,
                                            ExecutionMode::x86_64,
                                            {{"short", {{0}, 0x1000}, 1, {0}, 1, true, false, true}},
                                            {}}));
    auto page = make_bytes_page(doc, FileOffset{0}, 1);
    check(!page && page.error().code == ErrorCode::io, "byte preview rejects successful short source read");
    auto listing = make_listing_page(doc, FileOffset{0}, 1, ListingOptions{false, {}});
    check(!listing && listing.error().code == ErrorCode::io, "listing preview rejects successful short source read");
    auto image_bytes = doc.image->read(Address{{0}, 0x1000}, 1);
    check(!image_bytes && image_bytes.error().code == ErrorCode::io,
          "initialized image backing rejects a short source read instead of inventing zero fill");
}
} // namespace
void domain_listing_tests() {
    auto input = std::make_shared<MemoryStorage>(bytes({0x40, 0xc3}));
    ImageLayout layout{{{1}, 64, 1, ByteOrder::little},
                       Architecture::x86_64,
                       ExecutionMode::x86_64,
                       {{"long", {{1}, 0x1000}, 2, {0}, 2, true, false, true},
                        {"legacy", {{2}, 0x1000}, 2, {0}, 2, true, false, true}},
                       {{{1}, 0x1000}, {{2}, 0x1000}}};
    layout.domains = {{{{2}, 32, 1, ByteOrder::little}, {Architecture::x86, ExecutionMode::x86_32, ByteOrder::little}}};
    DocumentSnapshot doc;
    doc.image = take(Image::create(input, layout));
    doc.analysis = take(analyze(*doc.image, {}, {}));
    check(doc.analysis->instructions.size() == 3, "reachable analysis visits equal offsets in both domains");
    auto page = take(make_listing_page(doc, Address{{2}, 0x1000}, 1, ListingOptions{false, {}}));
    check(page.rows[0].instruction && page.rows[0].instruction->opcode == Opcode::inc && page.rows[0].reachable,
          "listing lookup selects second-domain fact at repeated offset");
    auto manual = take(decode_at(*doc.image, {{2}, 0x1000}));
    check(manual.instruction && manual.instruction->opcode == Opcode::inc,
          "manual decode uses requested domain context");
    auto stop = take(make_listing_page(doc, Address{{2}, 0x1001}, 1, ListingOptions{false, {}}));
    check(stop.rows[0].instruction && stop.rows[0].instruction->opcode == Opcode::ret,
          "later instruction stays in second domain");
    layout.segments[1].begin.offset = 0;
    layout.entries[1].offset = 0;
    doc.image = take(Image::create(input, layout));
    doc.analysis = take(analyze(*doc.image, {}, {}));
    check(doc.analysis->instructions.size() == 3 && doc.analysis->instructions.front().address == Address{{1}, 0x1000},
          "analysis sorts by space before offset");
    page = take(make_listing_page(doc, Address{{2}, 0}, 1, ListingOptions{false, {}}));
    check(page.rows[0].instruction && page.rows[0].instruction->opcode == Opcode::inc,
          "lookup handles nonmonotonic numeric offsets across domains");
}
int main() {
    return run([] {
        manual_tests();
        short_read_tests();
        domain_listing_tests();
    });
}
