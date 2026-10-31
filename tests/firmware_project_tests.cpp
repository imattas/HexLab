#include "hexlab/loaders/recipe.hpp"
#include "hexlab/workspace/document.hpp"
#include "hexlab/workspace/project.hpp"
#include "hexlab/workspace/listing.hpp"
#include "hexlab/workspace/search.hpp"
#include "hexlab/workspace/project_exchange.hpp"
#include "hexlab/workspace/workspace.hpp"
#include "support/checks.hpp"
#include "support/fixture_files.hpp"
using namespace hexlab;
using namespace hexlab_test;
namespace {
template<class T> T take(Result<T> value) {
    if (!value) throw std::runtime_error(value.error().message);
    return std::move(value.value());
}
std::vector<std::byte> text_bytes(std::string_view text) {
    auto data = std::as_bytes(std::span(text));
    return {data.begin(), data.end()};
}
struct ProjectFile {
    FixtureFile marker{std::span<const std::byte>{}};
    std::filesystem::path path = marker.path.wstring() + L".firmware.hxproj";
    ~ProjectFile() {
        std::error_code ignored;
        for (auto suffix : {L"", L"-wal", L"-shm"}) {
            auto file = path; file += suffix; std::filesystem::remove(file, ignored);
        }
    }
};
void project_roundtrip(unsigned tag, std::string_view text, Address address, unsigned octet) {
    auto decoded = decode_recipe(bytes({5, 0, tag}));
    check(bool(decoded), "a durable firmware recipe decodes before project import");
    if (!decoded) return;
    check(take(encode_recipe(decoded.value())) == bytes({5, 0, tag}),
          "firmware recipes keep an explicit stable format on roundtrip");
    auto extra = bytes({5, 0, tag, 0});
    check(!decode_recipe(extra), "trailing firmware recipe fields cannot be silently ignored");
    FixtureFile input(text_bytes(text));
    ProjectFile project;
    auto store = take(database::ProjectStore::create(project.path, {}));
    auto source = take(FileStorage::open(input.path));
    take(store->import_input(*source, decoded.value(), input.path, {}));
    source.reset();
    auto session = take(ProjectSession::attach(store, {}, {}));
    auto snapshot = session->snapshot();
    check(snapshot->loaded && snapshot->loaded->metadata.firmware &&
              take(snapshot->loaded->image->read(address, 1))[0] == std::byte(octet),
          "project attachment parses embedded firmware into sparse target bytes");
    check(snapshot->effective->size() == text.size() &&
              take(snapshot->effective->read_at({0}, text.size())).bytes[0] == std::byte(text[0]),
          "the authoritative embedded input remains original record text");
    check(snapshot->status == DerivedStatus::incomplete && !snapshot->functions,
          "firmware projects report unsupported CPU analysis without invented instructions");
    take(session->execute(Rename{address, "firmware_start"}, 0, {}));
    check(!export_project_exchange(*session->snapshot()),
          "virtual annotation exchange cannot mistake packed backing offsets for text file offsets");
    auto patched = session->execute(PatchBytes{address, bytes({0xcc})}, 0, {});
    auto patched_snapshot = session->snapshot();
    check(patched && patched_snapshot->state->revisions.edit == 2 &&
              action_availability(patched_snapshot.get(), ProjectActionKind::patch, address).enabled,
          "target-memory patches update the owning firmware data record");
    const auto patched_source = take(patched_snapshot->effective->read_at({0}, text.size()));
    const auto patched_text = std::string(reinterpret_cast<const char *>(patched_source.bytes.data()),
                                          patched_source.bytes.size());
    auto expected_text = std::string(text);
    const auto data = expected_text.find("AA");
    const auto line_end = expected_text.find('\n');
    if (data != std::string::npos && line_end != std::string::npos) {
        expected_text.replace(data, 2, "CC");
        expected_text.replace(line_end - 2, 2, text.starts_with(":") ? "23" : "1F");
    }
    check(patched_text == expected_text,
          "firmware record patch preserves unrelated source text and recalculates its checksum");
    session.reset(); patched_snapshot.reset(); snapshot.reset(); store.reset();
    check(std::filesystem::remove(input.path), "project reopen does not need the external firmware file");
    store = take(database::ProjectStore::open(project.path, database::ProjectMode::read_only, {}));
    session = take(ProjectSession::attach(store, {}, {}));
    snapshot = session->snapshot();
    check(snapshot->loaded && snapshot->loaded->metadata.firmware &&
              take(snapshot->loaded->image->read(address, 1))[0] == std::byte{0xcc} &&
              presentation_name(*snapshot, address) == "firmware_start",
          "readonly reopen restores firmware bytes and virtual annotations from embedded input");
}
void source_coordinates_and_reparse() {
    const std::string text = ":01001000AA45\n:0400000500000010E7\n:00000001FF\n";
    auto recipe = decode_recipe(bytes({5, 0, 8}));
    if (!recipe) return;
    FixtureFile input(text_bytes(text)); ProjectFile project;
    auto store = take(database::ProjectStore::create(project.path, {}));
    take(store->import_input(*take(FileStorage::open(input.path)), recipe.value(), input.path, {}));
    auto session = take(ProjectSession::attach(store, {}, {}));
    auto snapshot = session->snapshot();
    OpenRequest request; request.path = input.path; request.format = recipe.value().format;
    Workspace workspace; const auto ticket = workspace.begin_open();
    check(workspace.finish_open(ticket, load_document(request, ticket, {})) &&
              workspace.navigate(FileOffset{text.size() - 1}).has_value(),
          "inspection navigation accepts original source offsets beyond the packed payload extent");
    const auto inspection_source = take(make_bytes_page(*workspace.current(), FileOffset{0}, 1));
    check(inspection_source.cells[0].value == std::byte{':'} && !inspection_source.cells[0].address,
          "nonproject firmware inspection retains the same source coordinate semantics");
    DocumentSnapshot document; document.project = snapshot; document.image = snapshot->loaded->image;
    const auto source = take(make_bytes_page(document, FileOffset{0}, text.size()));
    check(source.cells.size() == text.size() && source.cells[0].value == std::byte{':'} &&
              !source.cells[0].address && source.cells[0].file_offset == FileOffset{0},
          "file preview uses record text and does not alias packed firmware addresses");
    const auto memory = take(make_bytes_page(document, Address{{0}, 0x10}, 1));
    check(memory.cells[0].value == std::byte{0xaa} && !memory.cells[0].file_offset &&
              memory.cells[0].address == Address{{0}, 0x10} && memory.cells[0].initialized,
          "memory preview shows decoded bytes without fabricated source file offsets");
    const auto matches = take(search(*snapshot, BytePattern{"3A"}, {}, {}, {}));
    check(matches.matches.size() == 3 && !matches.matches[0].address,
          "byte search scans original text without mapping a packed backing offset to a target address");
    // Source offsets 9..12 contain data AA and checksum 45. BB requires checksum 34.
    auto changed = take(session->execute(PatchBytes{FileOffset{9}, text_bytes("BB34")}, 0, {}));
    check(changed->loaded && changed->loader_parses == snapshot->loader_parses + 1 &&
              take(changed->loaded->image->read({{0}, 0x10}, 1))[0] == std::byte{0xbb},
          "source text changes rebuild packed firmware bytes using parser dependencies");
    auto broken = take(session->execute(PatchBytes{FileOffset{11}, text_bytes("00")}, 0, {}));
    check(!broken->loaded && broken->status == DerivedStatus::file_only,
          "an invalid source checksum publishes file-only state instead of stale target bytes");
    auto restored = take(session->undo({}));
    check(restored->loaded && take(restored->loaded->image->read({{0}, 0x10}, 1))[0] == std::byte{0xbb},
          "undo reparses and restores a valid firmware mapping after malformed text");
    auto original = take(session->undo({}));
    check(original->loaded && take(original->loaded->image->read({{0}, 0x10}, 1))[0] == std::byte{0xaa},
          "undo restores original firmware payload rather than rebinding the text as packed data");
}
void bounded_recipe_loading() {
    auto recipe = decode_recipe(bytes({5, 0, 8}));
    if (!recipe) return;
    struct OversizedText final : ByteStorage {
        mutable bool read = false;
        std::uint64_t size() const noexcept override { return UINT64_C(1024) * 1024 * 1024 + 1; }
        Result<ByteView> read_at(FileOffset, std::size_t) const override {
            read = true; return Error{ErrorCode::io, "oversized input must not be read"};
        }
    };
    auto huge = std::make_shared<OversizedText>();
    const auto bounded = load_durable_image(huge, recipe.value(), {});
    check(!bounded && bounded.error().code == ErrorCode::resource_limit && !huge->read,
          "durable firmware rejects oversized text before requesting or allocating a source view");
    std::stop_source stop; stop.request_stop();
    const auto canceled = load_durable_image(huge, recipe.value(), stop.get_token());
    check(!canceled && canceled.error().code == ErrorCode::canceled && !huge->read,
          "durable firmware loading honors cancellation before input reads");
    auto invalid = recipe.value(); invalid.raw = RawOptions{};
    check(!encode_recipe(invalid), "firmware recipes cannot silently drop incompatible raw options");
}
}
int main() { return run([] {
    project_roundtrip(8, ":01001000AA45\n:0400000500000010E7\n:00000001FF\n", {{0}, 0x10}, 0xaa);
    project_roundtrip(9, "S1040010AA41\nS9030010EC\n", {{0}, 0x10}, 0xaa);
    source_coordinates_and_reparse();
    bounded_recipe_loading();
}); }
