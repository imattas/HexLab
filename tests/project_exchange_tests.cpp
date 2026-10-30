#include "hexlab/workspace/project_exchange.hpp"
#include "support/checks.hpp"
#include "hexlab/image/image.hpp"
#include "hexlab/loaders/loaded_image.hpp"
using namespace hexlab;
using namespace hexlab_test;
namespace {
std::shared_ptr<const Image> mapped_image(std::uint64_t base);
ProjectSnapshot sample() {
    auto state = std::make_shared<database::ProjectState>();
    state->input.size = 256;
    for (unsigned n = 0; n < state->input.sha256.size(); ++n) state->input.sha256[n] = std::byte(n);
    auto user = std::make_shared<database::UserState>();
    user->annotations.push_back({77, FileOffset{4}, {}, "note"});
    user->bookmarks.push_back({99, FileOffset{12}, "bookmark"});
    user->decisions.references.push_back({321, FileOffset{20}, FileOffset{24}, UserReferenceKind::read});
    state->user = user;
    ProjectSnapshot result; result.state = state;
    return result;
}
void roundtrip() {
    auto source = sample();
    auto source_user = std::make_shared<database::UserState>(*source.state->user);
    source_user->decisions.regions.push_back({654, Address{{0}, 0x1000}, 16, RegionKind::code});
    source_user->decisions.functions.push_back({655, Address{{0}, 0x1000}, true,
                                                 std::vector<DecisionRange>{{Address{{0}, 0x1000}, 8}}});
    auto source_state = std::make_shared<database::ProjectState>(*source.state);
    source_state->user = source_user;
    source.state = source_state;
    auto source_loaded = std::make_shared<LoadedImage>();
    source_loaded->image = mapped_image(0x1000);
    source.loaded = source_loaded;
    auto encoded = export_project_exchange(source);
    check(bool(encoded), "exports supported user rows");
    if (!encoded) return;
    auto encoded_again = export_project_exchange(source);
    check(encoded_again && encoded_again.value() == encoded.value(), "exchange encoding is deterministic");
    check(encoded.value().size() >= 60 && encoded.value()[0] == std::byte{'H'} && encoded.value()[3] == std::byte{'X'},
          "exchange has fixed magic and versioned header");
    auto legacy_v3=encoded.value();
    // Versions 6-9 append three count fields after the v3 header's seven
    // counts. Remove those header fields before changing the version marker.
    legacy_v3.erase(legacy_v3.begin() + 76, legacy_v3.begin() + 88);
    legacy_v3[4]=std::byte{3};
    auto legacy_import=import_project_exchange(source,legacy_v3,ExchangeConflictPolicy::replace);
    check(legacy_import&&legacy_import.value().commands.empty(),"v3 type-exchange payloads without provenance remain importable");
    auto empty_state = std::make_shared<database::ProjectState>(*source.state);
    empty_state->user = std::make_shared<database::UserState>();
    auto empty_target = source; empty_target.state = empty_state;
    auto target_loaded = std::make_shared<LoadedImage>();
    target_loaded->image = mapped_image(0x5000);
    empty_target.loaded = target_loaded;
    auto imported = import_project_exchange(empty_target, encoded.value());
    check(bool(imported), "parses its own exchange payload");
    if (imported) {
        check(imported.value().annotations == 1, "one annotation imported");
        check(imported.value().bookmarks == 1, "one bookmark imported");
        check(imported.value().references == 1, "one reference imported");
        check(imported.value().regions == 1 && imported.value().functions == 1,
              "analysis region and function decision imported");
        check(imported.value().commands.size() == 6, "annotation, bookmark, reference, region and function commands emitted");
        check(std::get<DefineRegion>(imported.value().commands[3]).begin == Address{{0}, 0x5000},
              "region decision address is rebased through file provenance");
        check(std::get<SuppressFunction>(imported.value().commands[4]).entry == Address{{0}, 0x5000} &&
                  std::get<SetFunctionChunks>(imported.value().commands[5]).chunks[0].begin == Address{{0}, 0x5000},
              "function entry and chunks are rebased through file provenance");
    }
    if (imported && imported.value().commands.size() == 6) {
        check(std::holds_alternative<Comment>(imported.value().commands[0]) &&
                  std::holds_alternative<BookmarkCommand>(imported.value().commands[1]) &&
                  std::holds_alternative<SetReference>(imported.value().commands[2]),
              "import yields ordinary validated project commands");
        auto same = import_project_exchange(source, encoded.value(), ExchangeConflictPolicy::replace);
        check(same && same.value().commands.empty() && same.value().skipped == 5,
              "identical existing rows are idempotently skipped");
    }
}
void conflicts_and_limits() {
    auto source = sample(); auto encoded = export_project_exchange(source);
    if (!encoded) return;
    auto user = std::make_shared<database::UserState>(*source.state->user);
    user->annotations[0].comment = "local";
    auto changed = std::make_shared<database::ProjectState>(*source.state); changed->user = user;
    auto target = source; target.state = changed;
    auto fail = import_project_exchange(target, encoded.value());
    check(!fail && fail.error().code == ErrorCode::conflict, "default policy rejects conflicting annotation");
    auto skip = import_project_exchange(target, encoded.value(), ExchangeConflictPolicy::skip);
    check(skip && skip.value().skipped == 3 && skip.value().commands.empty(), "skip policy preserves conflicts and identical rows");
    check(skip && skip.value().conflicts.size() == 1 &&
              skip.value().conflicts[0].kind == ExchangeRecordKind::annotation &&
              skip.value().conflicts[0].location == Location{FileOffset{4}} &&
              skip.value().conflicts[0].resolution == ExchangeConflictResolution::kept_existing,
          "skip reports a stable conflict record with the deterministic kept-existing resolution");
    auto replace = import_project_exchange(target, encoded.value(), ExchangeConflictPolicy::replace);
    check(replace && replace.value().annotations == 1 && replace.value().commands.size() == 1 &&
              std::get<Comment>(replace.value().commands[0]).text == "note", "replace policy emits change command");
    check(replace && replace.value().conflicts.size() == 1 &&
              replace.value().conflicts[0].resolution == ExchangeConflictResolution::imported,
          "replace reports that the incoming row deterministically won");
    check(!export_project_exchange(source, 20), "export output limit is enforced");
    check(!import_project_exchange(source, encoded.value(), ExchangeConflictPolicy::fail, encoded.value().size() - 1),
          "import input limit is enforced");
    auto other = sample(); auto state = std::make_shared<database::ProjectState>(*other.state); state->input.sha256[0] ^= std::byte{0xff}; other.state = state;
    auto wrong_input = import_project_exchange(other, encoded.value());
    check(!wrong_input && wrong_input.error().code == ErrorCode::conflict, "exchange is bound to exact input identity");
}
class TestStorage final : public ByteStorage {
public:
    explicit TestStorage(std::size_t size) : bytes_(size) {}
    std::uint64_t size() const noexcept override { return bytes_.size(); }
    Result<ByteView> read_at(FileOffset at, std::size_t count) const override {
        if (at.value > bytes_.size() || count > bytes_.size() - at.value) return Error{ErrorCode::invalid_argument, "outside"};
        auto owner = std::make_shared<std::vector<std::byte>>(bytes_);
        return ByteView{owner, std::span<const std::byte>(*owner).subspan(static_cast<std::size_t>(at.value), count)};
    }
private:
    std::vector<std::byte> bytes_;
};
std::shared_ptr<const Image> mapped_image(std::uint64_t base) {
    ImageLayout layout{};
    layout.space = {{0}, 64, 1, ByteOrder::little};
    layout.architecture = Architecture::x86_64;
    layout.mode = ExecutionMode::x86_64;
    layout.segments.push_back({"text", {{0}, base}, 256, {0}, 256, true, false, true});
    auto image = Image::create(std::make_shared<TestStorage>(256), std::move(layout));
    return image ? image.value() : nullptr;
}
void reference_conflicts_preserve_both() {
    auto source = sample();
    auto source_user = std::make_shared<database::UserState>(*source.state->user);
    source_user->decisions.references.push_back({322, FileOffset{20}, FileOffset{28}, UserReferenceKind::read});
    auto source_state = std::make_shared<database::ProjectState>(*source.state); source_state->user = source_user; source.state = source_state;
    auto encoded = export_project_exchange(source);
    check(bool(encoded), "exports a reference set with alternate targets");
    if (!encoded) return;
    auto target = sample();
    auto imported = import_project_exchange(target, encoded.value(), ExchangeConflictPolicy::skip);
    check(imported && imported.value().references == 1 && imported.value().conflicts.size() == 1 &&
              imported.value().conflicts[0].kind == ExchangeRecordKind::reference &&
              imported.value().conflicts[0].resolution == ExchangeConflictResolution::preserved_both &&
              imported.value().conflicts[0].location == Location{FileOffset{20}} &&
              imported.value().conflicts[0].related_location == Location{FileOffset{28}},
          "alternate references from one source are retained together and explicitly reported");
}
void replacing_function_chunks_with_empty_list() {
    auto source = sample();
    auto source_user = std::make_shared<database::UserState>();
    source_user->decisions.functions.push_back({700, Address{{0}, 0x1000}, false, {}});
    auto source_state = std::make_shared<database::ProjectState>(*source.state);
    source_state->user = source_user;
    source.state = source_state;
    auto source_loaded = std::make_shared<LoadedImage>();
    source_loaded->image = mapped_image(0x1000);
    source.loaded = source_loaded;

    auto encoded = export_project_exchange(source);
    check(bool(encoded), "exports a function decision with no explicit chunks");
    if (!encoded) return;

    auto target = sample();
    auto target_user = std::make_shared<database::UserState>();
    target_user->decisions.functions.push_back({701, Address{{0}, 0x5000}, false,
                                                  {{Address{{0}, 0x5000}, 8}}});
    auto target_state = std::make_shared<database::ProjectState>(*target.state);
    target_state->user = target_user;
    target.state = target_state;
    auto target_loaded = std::make_shared<LoadedImage>();
    target_loaded->image = mapped_image(0x5000);
    target.loaded = target_loaded;

    auto imported = import_project_exchange(target, encoded.value(), ExchangeConflictPolicy::replace);
    check(imported && imported.value().functions == 1 && imported.value().commands.size() == 1 &&
              std::holds_alternative<SetFunctionChunks>(imported.value().commands[0]) &&
              std::get<SetFunctionChunks>(imported.value().commands[0]).entry == Address{{0}, 0x5000} &&
              std::get<SetFunctionChunks>(imported.value().commands[0]).chunks.empty(),
          "replace emits a rebased clear-chunks command when the incoming function has no explicit chunks");
}
void mapped_addresses() {
    auto source = sample();
    auto user = std::make_shared<database::UserState>();
    user->annotations.push_back({900, Address{{0}, 0x1004}, "entry", "mapped"});
    user->bookmarks.push_back({901, Address{{0}, 0x1008}, "VA bookmark"});
    auto source_state = std::make_shared<database::ProjectState>(*source.state); source_state->user = user; source.state = source_state;
    auto source_loaded = std::make_shared<LoadedImage>(); source_loaded->image = mapped_image(0x1000); source.loaded = source_loaded;
    auto encoded = export_project_exchange(source);
    check(bool(encoded), "encodes mapped virtual locations as source file offsets");
    if (!encoded) return;
    auto target_state = std::make_shared<database::ProjectState>(*source.state); target_state->user = std::make_shared<database::UserState>();
    auto target = source; target.state = target_state;
    auto target_loaded = std::make_shared<LoadedImage>(); target_loaded->image = mapped_image(0x5000); target.loaded = target_loaded;
    auto imported = import_project_exchange(target, encoded.value());
    check(imported && imported.value().commands.size() == 3, "resolves virtual records through destination mapping");
    if (imported && imported.value().commands.size() == 6) {
        check(std::get<Rename>(imported.value().commands[0]).location == Location{Address{{0}, 0x5004}},
              "remapped name preserves file-relative address");
        check(std::get<Comment>(imported.value().commands[1]).location == Location{Address{{0}, 0x5004}},
              "remapped comment preserves file-relative address");
        check(std::get<BookmarkCommand>(imported.value().commands[2]).location == Location{Address{{0}, 0x5008}},
              "remapped bookmark preserves file-relative address");
    }
}
void portable_type_graph_roundtrip() {
    auto base = types::Type::integer("u32", 4, 4, false);
    auto aggregate = base ? types::Type::structure("Pair", {{"left", base.value(), 0}, {"right", base.value(), 4}}, 8, 4)
                          : Result<types::TypePtr>{Error{ErrorCode::invalid_argument, "base"}};
    check(bool(aggregate), "builds a portable aggregate type");
    if (!aggregate) return;
    auto source = sample();
    auto source_user = std::make_shared<database::UserState>();
    source_user->types.push_back({700, "Pair", aggregate.value(),database::DwarfSourceOrigin{"pair.o",".debug_info",12,80,20}});
    source_user->type_assignments.push_back({701, Address{{0}, 0x1004}, 700});
    auto source_state = std::make_shared<database::ProjectState>(*source.state); source_state->user = source_user; source.state = source_state;
    auto source_loaded = std::make_shared<LoadedImage>(); source_loaded->image = mapped_image(0x1000); source.loaded = source_loaded;
    auto encoded = export_project_exchange(source);
    check(bool(encoded), "exports portable type definitions and type assignments");
    if (!encoded) return;
    auto target = source;
    auto target_state = std::make_shared<database::ProjectState>(*source.state);
    target_state->user = std::make_shared<database::UserState>(); target.state = target_state;
    auto target_loaded = std::make_shared<LoadedImage>(); target_loaded->image = mapped_image(0x5000); target.loaded = target_loaded;
    target.mode = database::ProjectMode::read_write;
    target.original = std::make_shared<TestStorage>(256); target.effective = target.original;
    auto imported = import_project_exchange(target, encoded.value());
    check(imported && imported.value().type_definitions == 1 && imported.value().type_assignments == 1 && imported.value().commands.size() == 1,
          "round trip plans one atomic type graph command");
    if (!imported || imported.value().commands.size() != 1) return;
    auto graph = std::get_if<ImportPortableTypes>(&imported.value().commands[0]);
    check(graph && graph->definitions.size() == 1 && graph->assignments.size() == 1 &&
              graph->assignments[0].location == Location{Address{{0}, 0x5004}} &&
              graph->definitions[0].origin==source_user->types[0].origin,
          "portable type assignment rebases and preserves the named type DIE origin");
    auto delta = validate_command(target, imported.value().commands[0]);
    check(bool(delta) && delta.value().changes.size() == 2, "atomic type graph validates and creates definition plus assignment");
    if (delta) {
        std::uint64_t created_type = 0, assigned_type = 0;
        for (const auto &change : delta.value().changes) std::visit([&](const auto &row) {
            using T = std::decay_t<decltype(row)>;
            if constexpr (std::is_same_v<T, database::TypeDefinitionChange>) { if (row.after) created_type = row.after->id; }
            else if constexpr (std::is_same_v<T, database::TypeAssignmentChange>) { if (row.after) assigned_type = row.after->type_id; }
        }, change);
        check(created_type != 0 && created_type == assigned_type, "new assignment binds to the destination-generated type identity");
    }
    auto stale_state = std::make_shared<database::ProjectState>(*target.state);
    auto stale_user = std::make_shared<database::UserState>(*target.state->user);
    stale_user->types.push_back({900, "Pair", types::Type::void_type()});
    stale_state->user = stale_user;
    auto stale_target = target; stale_target.state = stale_state;
    auto stale = validate_command(stale_target, imported.value().commands[0]);
    check(!stale && stale.error().code == ErrorCode::conflict && stale_target.state->user->types.size() == 1 &&
              stale_target.state->user->type_assignments.empty(),
          "destination type-name changes reject the compound plan before applying any assignment");
    auto malformed = encoded.value();
    const auto encoded_kind = std::size_t{80} + std::string_view("Pair").size() + 4;
    malformed[encoded_kind] = std::byte{0xff};
    check(!import_project_exchange(target, malformed), "malformed serialized type is rejected before command planning");
}
void portable_type_conflicts() {
    auto u8 = types::Type::integer("u8", 1, 1, false);
    auto u16 = types::Type::integer("u16", 2, 2, false);
    if (!u8 || !u16) return;
    auto source = sample(); auto source_user = std::make_shared<database::UserState>();
    source_user->types.push_back({700, "Scalar", u8.value()});
    source_user->type_assignments.push_back({701, Address{{0}, 0x1004}, 700});
    auto source_state = std::make_shared<database::ProjectState>(*source.state); source_state->user = source_user; source.state = source_state;
    auto source_loaded = std::make_shared<LoadedImage>(); source_loaded->image = mapped_image(0x1000); source.loaded = source_loaded;
    auto encoded = export_project_exchange(source); check(bool(encoded), "exports type conflict fixture"); if (!encoded) return;
    auto target = source; auto user = std::make_shared<database::UserState>();
    user->types.push_back({800, "Scalar", u16.value()}); user->types.push_back({801, "Other", u8.value()});
    user->type_assignments.push_back({802, Address{{0}, 0x5004}, 801});
    auto state = std::make_shared<database::ProjectState>(*source.state); state->user = user; target.state = state;
    auto loaded = std::make_shared<LoadedImage>(); loaded->image = mapped_image(0x5000); target.loaded = loaded;
    auto fail = import_project_exchange(target, encoded.value());
    check(!fail && fail.error().code == ErrorCode::conflict, "default policy rejects conflicting imported type definitions");
    auto skip = import_project_exchange(target, encoded.value(), ExchangeConflictPolicy::skip);
    check(skip && skip.value().conflicts.size() == 2 && skip.value().conflicts[0].kind == ExchangeRecordKind::type_definition &&
              skip.value().conflicts[1].kind == ExchangeRecordKind::type_assignment && skip.value().commands.empty(),
          "skip policy preserves both conflicting local type and assignment records");
    auto replace = import_project_exchange(target, encoded.value(), ExchangeConflictPolicy::replace);
    check(replace && replace.value().type_definitions == 1 && replace.value().type_assignments == 1 && replace.value().commands.size() == 1,
          "replace policy plans an atomic update of type graph conflicts");
    if (replace && replace.value().commands.size() == 1) {
        target.mode = database::ProjectMode::read_write; target.original = std::make_shared<TestStorage>(256); target.effective = target.original;
        auto delta = validate_command(target, replace.value().commands[0]);
        check(bool(delta) && delta.value().changes.size() == 2, "replacement validates both type and assignment updates together");
    }
}
void malformed() {
    auto project = sample(); auto encoded = export_project_exchange(project); if (!encoded) return;
    auto altered = encoded.value(); altered.resize(59);
    check(!import_project_exchange(project, altered), "truncated header is rejected");
    altered = encoded.value(); altered[4] = std::byte{5};
    check(!import_project_exchange(project, altered), "unknown format version is rejected");
    altered = encoded.value(); altered[6] = std::byte{1};
    check(!import_project_exchange(project, altered), "reserved header bits are rejected");
    altered = encoded.value(); altered[68] = std::byte{0xff}; altered[69] = std::byte{0xff};
    check(!import_project_exchange(project, altered), "oversized record count is rejected");
    altered = encoded.value(); altered.push_back(std::byte{0});
    check(!import_project_exchange(project, altered), "trailing payload is rejected");
    altered = encoded.value(); altered[76] = std::byte{7};
    check(!import_project_exchange(project, altered), "unknown portable location tag is rejected");
    altered = encoded.value(); altered[93] = std::byte{0xff};
    check(!import_project_exchange(project, altered), "malformed UTF-8 text is rejected");
}
void legacy_v1() {
    auto project = sample();
    std::vector<std::byte> bytes;
    for (auto value : {std::byte{'H'}, std::byte{'X'}, std::byte{'E'}, std::byte{'X'}}) bytes.push_back(value);
    auto put = [&](std::uint64_t value, unsigned count) { for (unsigned i = 0; i < count; ++i) bytes.push_back(std::byte(value >> (i * 8))); };
    put(1, 2); put(0, 2); put(project.state->input.size, 8);
    bytes.insert(bytes.end(), project.state->input.sha256.begin(), project.state->input.sha256.end());
    put(0, 4); put(0, 4); put(0, 4);
    auto imported = import_project_exchange(project, bytes);
    check(imported && imported.value().commands.empty(), "v2 importer remains compatible with empty v1 exchange payloads");
}
} // namespace
int main() { return run([] { roundtrip(); conflicts_and_limits(); reference_conflicts_preserve_both(); replacing_function_chunks_with_empty_list(); mapped_addresses(); portable_type_graph_roundtrip(); portable_type_conflicts(); malformed(); legacy_v1(); }); }
