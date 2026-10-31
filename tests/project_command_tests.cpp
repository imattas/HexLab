#include "hexlab/workspace/project.hpp"
#include "hexlab/workspace/commands.hpp"
#include "hexlab/workspace/debug_variables.hpp"
#include "hexlab/types/header_import.hpp"
#include "hexlab/types/layout.hpp"
#include "support/checks.hpp"
#include "support/fixture_files.hpp"
#include "support/pe_fixture.hpp"
#include "support/elf_dwarf_fixture.hpp"
#include "testing.hpp"
#include <iostream>
using namespace hexlab;
using namespace hexlab::database;
using namespace hexlab_test;
struct ProjectFixture {
    FixtureFile input;
    std::filesystem::path path;
    std::shared_ptr<ProjectStore> store;
    std::shared_ptr<ProjectSession> session;
    explicit ProjectFixture(
        std::vector<std::byte> data,
        LoadRecipe recipe = {Format::raw,
                             RawOptions{
                                 Architecture::x86_64, ExecutionMode::x86_64, {{0}, 0x1000}, true, true, true, {}}})
        : input(data), path(input.path.wstring() + L".hxproj") {
        store = ProjectStore::create(path, {}).value();
        auto source = FileStorage::open(input.path).value();
        check(bool(store->import_input(*source, recipe, input.path, {})), "command fixture embeds input");
        session = ProjectSession::attach(store, {}, {}).value();
    }
    ~ProjectFixture() {
        session.reset();
        store.reset();
        std::error_code ignored;
        std::filesystem::remove(path, ignored);
        auto wal = path;
        wal += L"-wal";
        std::filesystem::remove(wal, ignored);
        auto shm = path;
        shm += L"-shm";
        std::filesystem::remove(shm, ignored);
    }
};
void annotation_tests() {
    ProjectFixture f(bytes({0x90, 0xc3}));
    auto initial = f.session->snapshot();
    check(initial->status == DerivedStatus::fresh && initial->loaded->metadata_complete,
          "raw mapping has complete metadata and fresh analysis");
    auto named = f.session->execute(Rename{Address{{0}, 0x1000}, "start"}, 0, {}).value();
    check(named->state->user->annotations[0].name == "start" && named->functions == initial->functions &&
              named->references == initial->references,
          "rename preserves shared derived snapshots");
    auto failed = f.session->execute(Rename{Address{{0}, 0x1001}, "start"}, 0, {});
    check(!failed && failed.error().code == ErrorCode::conflict && f.store->snapshot().value()->revisions.edit == 1,
          "duplicate name fails atomically with conflict");
    check(!f.session->execute(Rename{Address{{0}, 0x1000}, std::string(513, 'x')}, 0, {}), "overlong name rejected");
    check(!f.session->execute(Rename{Address{{0}, 0x1000}, "bad\nname"}, 0, {}), "control characters in name rejected");
    check(bool(f.session->execute(Comment{FileOffset{1}, "first\nsecond"}, 12, {})),
          "file-offset multiline comment accepted");
    check(bool(f.session->execute(BookmarkCommand{FileOffset{1}, "here", false}, 12, {})),
          "file-offset bookmark shares command group");
    auto undo = f.session->undo({}).value();
    check(undo->state->user->bookmarks.empty() && undo->state->user->annotations.size() == 1,
          "grouped annotation undo removes both edits");
    check(bool(f.session->redo({})), "grouped annotation redo works");
    auto clear = f.session->execute(Rename{Address{{0}, 0x1000}, ""}, 0, {}).value();
    check(clear->state->user->annotations.size() == 1 && presentation_at(*clear, Address{{0}, 0x1000}).name != "start",
          "clearing override restores automatic fallback");
    auto snapshot = f.session->snapshot();
    check(!f.session->execute(Comment{FileOffset{0}, std::string("x\0y", 3)}, 0, {}) &&
              f.session->snapshot() == snapshot,
          "NUL comment failure leaves published snapshot unchanged");
    f.session.reset();
    f.store.reset();
    auto reopened = ProjectStore::open(f.path, ProjectMode::read_only, {}).value();
    auto session = ProjectSession::attach(reopened, {}, {}).value();
    check(session->snapshot()->state->user->bookmarks.size() == 1 &&
              session->snapshot()->state->user->annotations[0].comment == "first\nsecond",
          "accepted edits persist through independent reopen");
    auto availability = command_availability(*session->snapshot(), Comment{FileOffset{0}, "blocked"});
    check(!availability.enabled && !availability.reason.empty() &&
              !session->execute(Comment{FileOffset{0}, "blocked"}, 0, {}),
          "read-only mutation explains prerequisite");
}
void decision_tests() {
    ProjectFixture f(bytes({0x48, 0x89, 0xd8, 0x90, 0xc3}));
    auto initial = f.session->snapshot();
    check(!f.session->execute(DefineFunction{Address{{0}, 0x1001}}, 0, {}),
          "function entry inside an instruction rejected");
    check(!f.session->execute(SuppressFunction{Address{{0}, 0x1003}, true}, 0, {}),
          "suppression requires an established function entry");
    check(!f.session->execute(DefineRegion{Address{{0}, 0x1001}, 1, RegionKind::data}, 0, {}),
          "data range cutting instruction rejected");
    check(bool(f.session->execute(DefineFunction{Address{{0}, 0x1000}}, 0, {})),
          "valid instruction boundary defines function");
    check(bool(f.session->refresh_analysis({})), "function definition refreshes before more boundary edits");
    auto current = f.session->snapshot();
    check(!f.session->execute(
              SetFunctionChunks{Address{{0}, 0x1000}, {{Address{{0}, 0x1000}, 4}, {Address{{0}, 0x1003}, 2}}}, 0, {}),
          "overlapping chunks rejected atomically");
    auto data = f.session->execute(DefineRegion{Address{{0}, 0x1003}, 1, RegionKind::data}, 0, {}).value();
    check(data->status == DerivedStatus::stale && data->functions == current->functions,
          "decision edit marks prior facts stale without claiming reanalysis");
    auto unavailable = command_availability(*data, DefineFunction{Address{{0}, 0x1003}});
    check(!unavailable.enabled && !unavailable.reason.empty(),
          "stale analysis cannot validate new instruction boundary");
    check(bool(f.session->refresh_analysis({})), "explicit reanalysis uses effective decisions");
    check(bool(f.session->execute(SuppressFunction{Address{{0}, 0x1000}, true}, 0, {})),
          "suppression persists as decision");
    check(bool(f.session->refresh_analysis({})) && f.session->snapshot()->functions->functions.empty(),
          "suppressed entry does not recover");
}
void chunk_clear_tests() {
    ProjectFixture f(bytes({0x90, 0x90, 0xc3}));
    const Address entry{{0}, 0x1000};
    auto restricted = f.session->execute(SetFunctionChunks{entry, {{entry, 1}}}, 0, {});
    check(bool(restricted), "explicit chunk restriction accepted");
    check(bool(f.session->refresh_analysis({})) && f.session->snapshot()->functions->instructions.size() == 1,
          "chunk restricts automatic recovery extent");
    const auto identity = f.session->snapshot()->state->user->decisions.functions[0].id;
    auto cleared = f.session->execute(SetFunctionChunks{entry, {}}, 0, {});
    check(bool(cleared), "empty explicit chunks clear an existing restriction");
    if (!cleared)
        return;
    check(cleared.value()->state->user->decisions.functions[0].chunks.empty() &&
              cleared.value()->state->user->decisions.functions[0].id == identity,
          "clear preserves explicit function identity and removes only its chunks");
    check(bool(f.session->refresh_analysis({})) && f.session->snapshot()->functions->instructions.size() == 3,
          "clearing chunks resumes recovery through the return");
    auto undo = f.session->undo({});
    check(bool(undo) &&
              undo.value()->state->user->decisions.functions[0].chunks == std::vector<DecisionRange>{{entry, 1}},
          "undo restores the exact restriction");
    f.session.reset();
    f.store.reset();
    f.store = ProjectStore::open(f.path, ProjectMode::read_write, {}).value();
    f.session = ProjectSession::attach(f.store, {}, {}).value();
    check(f.session->snapshot()->functions->instructions.size() == 1, "reopened undo retains restricted recovery");
    auto redo = f.session->redo({});
    check(bool(redo) && redo.value()->state->user->decisions.functions[0].chunks.empty(),
          "persistent redo clears chunks after reopen");
    check(bool(f.session->refresh_analysis({})) && f.session->snapshot()->functions->instructions.size() == 3,
          "reopened redo restores automatic recovery");
    check(!f.session->execute(SetFunctionChunks{entry, {}}, 0, {}),
          "clearing an already empty restriction does not create history");
}
void patch_tests() {
    ProjectFixture f(bytes({0x90, 0xc3}));
    auto initial = f.session->snapshot();
    check(bool(f.session->execute(PatchBytes{Address{{0}, 0x1000}, bytes({0xcc})}, 7, {})),
          "VA patch maps to embedded bytes");
    auto patched = f.session->execute(PatchBytes{FileOffset{1}, bytes({0x90})}, 7, {}).value();
    check(patched->effective->read_at({0}, 2).value().bytes[0] == std::byte{0xcc} &&
              patched->status == DerivedStatus::stale,
          "all effective consumers see grouped patches and stale state");
    auto undone = f.session->undo({}).value();
    check(undone->state->user->patches.empty() &&
              undone->effective->read_at({0}, 2).value().bytes[0] == std::byte{0x90},
          "grouped patch undo restores original");
    auto before = f.store->snapshot().value();
    check(!f.session->execute(PatchBytes{FileOffset{2}, bytes({1})}, 0, {}) &&
              f.store->snapshot().value()->revisions == before->revisions,
          "out-of-file patch fails without history change");
    std::stop_source stop;
    stop.request_stop();
    check(!f.session->execute(Comment{FileOffset{0}, "cancel"}, 0, stop.get_token()),
          "canceled command does not commit");
}
void file_only_tests() {
    ProjectFixture f(pe_fixture(), {Format::pe, {}});
    const Address entry{{0}, 0x140001000};
    check(bool(f.session->execute(Rename{entry, "saved_entry"}, 0, {})), "PE entry name accepted");
    auto broken = f.session->execute(PatchBytes{FileOffset{0}, bytes({0})}, 0, {}).value();
    check(broken->status == DerivedStatus::file_only && !broken->loaded &&
              broken->effective->read_at({0}, 1).value().bytes[0] == std::byte{0},
          "invalid edited header retains effective file-only bytes");
    auto presentation = presentation_at(*broken, entry);
    check(presentation.orphaned && presentation.name == "saved_entry",
          "disappearing address annotation remains visibly orphaned");
    check(!f.session->execute(DefineFunction{entry}, 0, {}) &&
              !f.session->execute(PatchBytes{entry, bytes({0xcc})}, 0, {}),
          "file-only mapping disables address decisions and address patches");
    check(bool(f.session->execute(Comment{FileOffset{0}, "bad header"}, 0, {})),
          "file-only byte annotations remain available");
    check(bool(f.session->undo({})), "file-only annotation undo works");
    auto restored = f.session->undo({}).value();
    check(restored->loaded && !presentation_at(*restored, entry).orphaned &&
              restored->effective->read_at({0}, 1).value().bytes[0] == std::byte{0x4d},
          "header undo restores mapping and annotation location");
    check(!f.session->execute(PatchBytes{Address{{0}, 0x140001200}, bytes({1})}, 0, {}),
          "zero-fill VA patch cannot become a file edit");
}
void failure_tests() {
    ProjectFixture f(bytes({0x90, 0xc3}));
    auto before = f.session->snapshot();
    auto no_history = f.session->undo({});
    check(!no_history && no_history.error().code == ErrorCode::invalid_argument && f.session->snapshot() == before,
          "empty history is an unavailable command rather than a corrupt project");
    testing::fail_next_commit(ErrorCode::io);
    auto failure = f.session->execute(PatchBytes{FileOffset{0}, bytes({0xcc})}, 0, {});
    check(!failure && failure.error().code == ErrorCode::io && f.session->snapshot() == before &&
              f.store->snapshot().value()->revisions.edit == 0,
          "failed patch commit preserves SQL and published effective snapshot");
    check(bool(f.session->execute(Comment{FileOffset{0}, "undo me"}, 0, {})), "undo failure fixture commits");
    before = f.session->snapshot();
    testing::fail_next_commit(ErrorCode::io);
    auto undo = f.session->undo({});
    check(!undo && f.session->snapshot() == before &&
              f.store->snapshot().value()->revisions == before->state->revisions,
          "failed undo preserves preceding published snapshot");
    check(bool(f.session->execute(SetReference{Address{{0}, 0x1000}, FileOffset{1}, UserReferenceKind::data, false}, 0,
                                  {})),
          "typed explicit reference command accepted");
    check(bool(f.session->refresh_analysis({})) &&
              f.session->snapshot()->references->incoming(FileOffset{1}, {}).value().total == 1,
          "reference command appears in derived index");
    check(bool(f.session->execute(SetReference{Address{{0}, 0x1000}, FileOffset{1}, UserReferenceKind::data, true}, 0,
                                  {})),
          "explicit reference removal accepted");
    auto unsupported_pe=pe_fixture(false);put(unsupported_pe,0x84,0xaa64,2);
    ProjectFixture unsupported(unsupported_pe, {Format::pe, {}});
    check(!unsupported.session->execute(DefineRegion{Address{{0}, 0x401000}, 1, RegionKind::code}, 0, {}),
          "unsupported processor code decisions report unavailable");
    LoadRecipe nonexec{Format::raw,
                       RawOptions{Architecture::x86_64, ExecutionMode::x86_64, {{0}, 0x1000}, true, true, false, {}}};
    ProjectFixture manual(bytes({0x90, 0xc3}), nonexec);
    check(!manual.session->execute(DefineFunction{Address{{0}, 0x1000}}, 0, {}),
          "non-executable function requests a recorded code decision first");
    check(bool(manual.session->execute(DefineRegion{Address{{0}, 0x1000}, 2, RegionKind::code}, 0, {})),
          "explicit code decision overrides initialized non-executable permission");
    check(bool(manual.session->refresh_analysis({})) && manual.session->snapshot()->functions->functions.size() == 1 &&
              manual.session->snapshot()->functions->functions[0]->complete,
          "explicit non-executable code is actually recovered through return");
    check(bool(manual.session->execute(DefineFunction{Address{{0}, 0x1000}}, 0, {})),
          "function can be defined in recorded explicit code");
}
void symbol_tests() {
    ProjectFixture f(pe_metadata_fixture(), {Format::pe, {}});
    const Address entry{{0}, 0x140001000};
    auto before = f.session->snapshot();
    check(presentation_at(*before, entry).name == "entry", "automatic export symbol is presented");
    check(bool(f.session->execute(Rename{Address{{0}, 0x140001001}, "entry"}, 0, {})),
          "user name can override another automatic spelling");
    auto current = f.session->snapshot();
    auto disambiguated = presentation_at(*current, entry).name;
    check(disambiguated != "entry", "automatic symbol yields to explicit user spelling");
    check(bool(f.session->execute(Rename{Address{{0}, 0x140001002}, disambiguated}, 0, {})),
          "second user name can match previous automatic disambiguation");
    current = f.session->snapshot();
    auto automatic = presentation_at(*current, entry).name;
    check(automatic != "entry" && automatic != disambiguated,
          "automatic fallback remains unique after chained user collisions");
}
void decompiler_edit_tests() {
    ProjectFixture f(bytes({0x90, 0xc3}));
    auto before = f.session->snapshot();
    check(before->functions && !before->functions->functions.empty(),
          "decompiler editing fixture has a recovered function");
    const Address function{{0}, 0x1000};
    const Address local_site{{0}, 0x1001};
    f.session->execute(Rename{function, "calculate"}, 74, {}).value();
    f.session->execute(Rename{local_site, "counter"}, 74, {}).value();
    auto commented = f.session->execute(Comment{local_site, "increments the local counter"}, 74, {}).value();
    check(presentation_name(*commented, function) == "calculate" &&
              presentation_name(*commented, local_site) == "counter" &&
              annotation_at(*commented, local_site)->comment == "increments the local counter",
          "decompiler names and comments resolve through shared project presentation annotations");
    check(commented->functions == before->functions && commented->references == before->references,
          "presentation edits synchronize without invalidating recovered code or reference snapshots");
    check(bool(f.session->undo({})) && f.session->snapshot()->state->user->annotations.empty(),
          "one decompiler edit group undoes function/local names and comments together");
    check(bool(f.session->redo({})) && presentation_name(*f.session->snapshot(), function) == "calculate" &&
              annotation_at(*f.session->snapshot(), local_site)->comment == "increments the local counter",
          "decompiler edit group redoes with the same project presentation");
    auto local_type = types::Type::integer("u32", 4, 4, false).value();
    auto type_defined = f.session->execute(DefineType{"u32", local_type}, 0, {}).value();
    const auto local_type_id = type_defined->state->user->types.front().id;
    auto type_assigned = f.session->execute(AssignType{local_site, local_type_id, false}, 0, {}).value();
    check(type_assignment(*type_assigned, local_site) &&
              type_definition(*type_assigned, local_type_id)->type->id() == local_type->id(),
          "pseudocode variable type attachment resolves through its defining instruction address");
    check(bool(f.session->undo({})) && !type_assignment(*f.session->snapshot(), local_site) &&
              bool(f.session->redo({})) && type_assignment(*f.session->snapshot(), local_site),
          "pseudocode variable type assignment participates in project undo and redo");
    f.session.reset();
    f.store.reset();
    auto reopened = ProjectStore::open(f.path, ProjectMode::read_only, {}).value();
    auto session = ProjectSession::attach(reopened, {}, {}).value();
    check(presentation_name(*session->snapshot(), function) == "calculate" &&
              presentation_name(*session->snapshot(), local_site) == "counter" &&
              annotation_at(*session->snapshot(), local_site)->comment == "increments the local counter" &&
              type_assignment(*session->snapshot(), local_site) &&
              type_definition(*session->snapshot(), local_type_id),
          "decompiler edits survive project save and independent reopen");
}
void type_symbol_import_tests() {
    ProjectFixture f(pe_metadata_fixture(), {Format::pe, {}});
    auto integer=types::Type::integer("u32",4,4,false).value();
    auto pointer=types::Type::pointer(integer,8,8).value();
    auto structure=types::Type::structure("Node",{{"next",pointer,0}},8,8).value();
    auto defined=f.session->execute(DefineType{"Node",structure},0,{}).value();
    const auto type_id=defined->state->user->types.front().id;
    const Address entry{{0},0x140001000};
    auto assigned=f.session->execute(AssignType{entry,type_id,false},0,{}).value();
    check(type_assignment(*assigned,entry) && type_definition(*assigned,type_id) &&
              type_definition(*assigned,type_id)->type->id()==structure->id(),
          "immutable aggregate type can be assigned to an address and queried");
    check(bool(f.session->execute(ImportSymbols{},0,{})) &&
              presentation_at(*f.session->snapshot(),entry).user_name,
          "binary symbol import creates durable user annotations");
    f.session.reset();f.store.reset();
    f.store=ProjectStore::open(f.path,ProjectMode::read_write,{}).value();
    f.session=ProjectSession::attach(f.store,{},{}).value();
    auto reopened=f.session->snapshot();
    check(type_assignment(*reopened,entry) && type_definition(*reopened,type_id) &&
              type_definition(*reopened,type_id)->type->id()==structure->id() &&
              presentation_at(*reopened,entry).user_name,
          "type graph, address assignment, and imported name survive project reopen");
    auto undone=f.session->undo({}).value();
    check(!presentation_at(*undone,entry).user_name && type_assignment(*undone,entry),
          "symbol import is an independent reversible project command");
    undone=f.session->undo({}).value();
    check(!type_assignment(*undone,entry),"type assignment undo removes assignment");
    undone=f.session->undo({}).value();
    check(!type_definition(*undone,type_id),"type definition undo removes its project row");
    auto redone=f.session->redo({}).value();
    check(type_definition(*redone,type_id),"type definition redo restores the immutable graph");
    redone=f.session->redo({}).value();
    check(type_assignment(*redone,entry),"type assignment redo restores assignment");
    redone=f.session->redo({}).value();
    check(presentation_at(*redone,entry).user_name,"symbol import redo restores the explicit name");
    check(bool(f.session->execute(AssignType{entry,type_id,true},0,{})) &&
              !type_assignment(*f.session->snapshot(),entry),
          "type assignment can be explicitly removed");
}
void packed_header_project_roundtrip_tests() {
    ProjectFixture f(pe_metadata_fixture(), {Format::pe, {}});
    const auto imported=types::import_c_header(R"(
#pragma pack(push, 2)
struct OnDiskHeader { char kind; int length; short flags; };
#pragma pack(pop)
    )");
    check(bool(imported), "header importer accepts compiler packing directives before workspace import");
    if(!imported)return;
    const auto type=imported.value().symbols.at("struct OnDiskHeader").type;
    check(type->size()==8&&type->alignment()==2&&type->members()[1].offset==2&&type->members()[2].offset==6,
          "imported compiler packing is represented as exact aggregate size, alignment, and member offsets");
    auto defined=f.session->execute(DefineType{"struct OnDiskHeader",type},0,{});
    check(bool(defined), "packed imported aggregate can be stored as a workspace type definition");
    if(!defined)return;
    const auto id=defined.value()->state->user->types.back().id;
    f.session.reset();f.store.reset();
    f.store=ProjectStore::open(f.path,ProjectMode::read_write,{}).value();
    f.session=ProjectSession::attach(f.store,{},{}).value();
    const auto *restored=type_definition(*f.session->snapshot(),id);
    const auto restored_layout=restored?types::layout(*restored->type,types::Abi::x86_64):Result<types::TypeLayout>(Error{ErrorCode::malformed,"missing restored type"});
    check(restored&&restored->type->size()==8&&restored->type->alignment()==2&&
              restored->type->members().size()==3&&restored->type->members()[1].offset==2&&
              restored->type->members()[2].offset==6,
          "workspace save/reopen preserves compiler-derived packed layout semantics");
    check(restored_layout&&restored_layout.value().size==8&&restored_layout.value().alignment==2&&
              restored_layout.value().members[1].offset==2&&restored_layout.value().members[2].offset==6,
          "workspace-restored type retains packing when laid out by the reusable ABI layout engine");
}
void dwarf_info_project_import_tests() {
    ProjectFixture f(elf_fixture::executable_with_dwarf_info(), {Format::elf, {}});
    auto initial = f.session->snapshot();
    check(initial->loaded && initial->loaded->metadata.elf && initial->loaded->metadata.elf->dwarf_info,
          "project loader makes ELF DWARF records available to the import action");
    auto imported = f.session->execute(ImportDwarfInfo{}, 0, {});
    check(bool(imported), "DWARF project import persists named types, names, and prototypes");
    if (!imported) return;
    f.session.reset();
    f.store.reset();
    f.store = ProjectStore::open(f.path, ProjectMode::read_write, {}).value();
    f.session = ProjectSession::attach(f.store, {}, {}).value();
    const auto reopened = f.session->snapshot();
    const auto named_type = std::find_if(reopened->state->user->types.begin(), reopened->state->user->types.end(),
        [](const auto &row) { return row.name == "int"; });
    check(named_type != reopened->state->user->types.end() && named_type->type->size() == 4 && named_type->origin &&
              named_type->origin->source_id == "ELF .debug_info" && named_type->origin->section == ".debug_info" &&
              named_type->origin->unit_offset == 0 && named_type->origin->record_size > 0,
          "DWARF named type and its source DIE origin survive project reopen");
    const Address entry{{0}, 0x400000};
    const auto assigned = type_assignment(*reopened, entry);
    const auto *prototype=assigned?type_definition(*reopened,assigned->type_id):nullptr;
    check(assigned && prototype && prototype->type->kind() == types::Kind::function && prototype->origin &&
              prototype->origin->section==".debug_info" && prototype->origin->record_size>0 &&
              presentation_at(*reopened, entry).user_name,
          "DWARF subprogram name, prototype assignment, and function DIE origin survive project reopen");
    if(named_type!=reopened->state->user->types.end()&&named_type->origin){
        const auto edited=f.session->execute(UpdateType{named_type->id,"renamed_int",named_type->type},0,{});
        const auto updated=edited?type_definition(*f.session->snapshot(),named_type->id):nullptr;
        check(updated&&updated->origin==named_type->origin,"editing a named type retains its imported DIE provenance");
    }
    check(std::any_of(reopened->state->user->decisions.functions.begin(),
                      reopened->state->user->decisions.functions.end(),
                      [&](const auto &row) { return row.entry == entry; }),
          "mapped DWARF subprogram start becomes a persisted function-analysis root");

    ProjectFixture v5(elf_fixture::executable_with_dwarf_info(false,false,false,false,true),{Format::elf,{}});
    auto v5_loaded=v5.session->snapshot();
    check(v5_loaded->loaded&&v5_loaded->loaded->metadata.elf&&v5_loaded->loaded->metadata.elf->dwarf_info,
          "DWARF v5 records reach the same project import workflow as v4");
    auto v5_imported=v5.session->execute(ImportDwarfInfo{},0,{});
    check(bool(v5_imported),"DWARF v5 named types and prototypes persist through workspace import");
    if(v5_imported){const auto snap=v5.session->snapshot();const Address v5_entry{{0},0x400000};check(type_assignment(*snap,v5_entry)&&presentation_at(*snap,v5_entry).user_name,
            "DWARF v5 function name and prototype are persisted at the mapped entry");}
}
void dwarf_variable_project_import_tests() {
    ProjectFixture f(elf_fixture::executable_with_dwarf_info(false, true, true, false, false, true), {Format::elf, {}});
    auto initial = f.session->snapshot();
    check(initial->loaded && initial->loaded->metadata.elf && initial->loaded->metadata.elf->dwarf_info,
          "variable fixture exposes parsed DWARF through the ELF loader");
    auto imported = f.session->execute(ImportDwarfInfo{}, 0, {});
    check(bool(imported), "DWARF variables import into durable project state");
    if (!imported) return;
    auto state = f.session->snapshot()->state;
    check(state->user->debug_variables.size() == 4, "all scoped parameters and locals are persisted while an unscoped DIE is skipped");
    const auto find_variable = [&](std::string_view name) -> const DebugVariable * {
        auto found = std::find_if(state->user->debug_variables.begin(), state->user->debug_variables.end(),
            [&](const auto &row) { return row.name == name; });
        return found == state->user->debug_variables.end() ? nullptr : &*found;
    };
    const auto *parameter = find_variable("arg");
    const auto *register_local = find_variable("reg_local");
    const auto *split_local = find_variable("split_local");
    const auto *optimized_out = find_variable("optimized_out");
    check(find_variable("global_value")==nullptr,"a variable with no enclosing subprogram is not attached to an arbitrary function");
    check(parameter && parameter->is_parameter && parameter->function_entry.offset == 0x400000 &&
              parameter->location_expression == std::vector<std::uint8_t>{0x91, 0x78} &&
              parameter->cfa_offset == -8,
          "parameter retains its raw expression and derives CFA-relative offset from the function frame base");
    if(parameter){symbols::LocationEvaluationContext frame;frame.frame_base=0x1000;const auto location=evaluate_debug_variable(*parameter,0x400004,frame);check(location&&location.value()==symbols::EvaluatedLocation{symbols::EvaluatedLocationKind::memory,0xff8},"persisted frame-relative parameter evaluates from caller-provided frame base");}
    const auto *source_parameter = [&]() -> const symbols::ImportedVariable * {
        const auto &rows=initial->loaded->metadata.elf->dwarf_info->variables;
        const auto found=std::find_if(rows.begin(),rows.end(),[](const auto &row){return row.name=="arg";});
        return found==rows.end()?nullptr:&*found;
    }();
    check(source_parameter && source_parameter->cfa_offset == -8,
          "DWARF import derives fbreg only with an explicit CFA frame-base expression");
    check(register_local && !register_local->is_parameter &&
              register_local->location_expression == std::vector<std::uint8_t>{0x50},
          "register-local expression remains raw and unevaluated");
    check(split_local && split_local->location_operations.size() == 4,
          "piece operations remain inspectable without inventing a contiguous address");
    check(optimized_out && !optimized_out->address && optimized_out->location_expression.empty(),
          "location-less variables remain present without fabricated addresses");
    if (parameter) {
        const auto source_variable=std::find_if(initial->loaded->metadata.elf->dwarf_info->variables.begin(),initial->loaded->metadata.elf->dwarf_info->variables.end(),[](const auto& row){return row.name=="arg";});
        check(source_variable!=initial->loaded->metadata.elf->dwarf_info->variables.end(),"DWARF fixture includes its parameter source DIE");
        if(source_variable==initial->loaded->metadata.elf->dwarf_info->variables.end())return;
        const auto source = source_variable->origin;
        check(parameter->origin.source_id == source.source_id && parameter->origin.section == source.section &&
                  parameter->origin.unit_offset == source.unit_offset && parameter->origin.record_offset == source.record_offset &&
                  parameter->origin.record_size == source.record_size,
              "variable import preserves its originating DWARF DIE identity");
    }
    const auto count = state->user->debug_variables.size();
    auto duplicate = f.session->execute(ImportDwarfInfo{}, 1, {});
    check(!duplicate && duplicate.error().code == ErrorCode::invalid_argument &&
              f.session->snapshot()->state->user->debug_variables.size() == count,
          "reimport is idempotent when every source DIE already exists");
    auto undone = f.session->undo({});
    check(bool(undone) && f.session->snapshot()->state->user->debug_variables.empty(),
          "undo removes the imported debug-variable rows");
    auto redone = f.session->redo({});
    check(bool(redone) && f.session->snapshot()->state->user->debug_variables.size() == count,
          "redo restores debug-variable rows");
    f.session.reset();
    f.store.reset();
    f.store = ProjectStore::open(f.path, ProjectMode::read_write, {}).value();
    f.session = ProjectSession::attach(f.store, {}, {}).value();
    const auto reopened_variables=f.session->snapshot()->state->user->debug_variables;
    check(reopened_variables.size() == count &&
              std::find_if(reopened_variables.begin(),reopened_variables.end(),[](const auto &row){return row.name=="arg"&&row.cfa_offset==-8;})!=reopened_variables.end(),
          "debug-variable raw, decoded, and CFA-relative records survive save and reopen");
}
void dwarf_v5_location_list_project_tests() {
    ProjectFixture f(elf_fixture::executable_with_dwarf_info(false,true,false,false,true,false,true),{Format::elf,{}});
    const auto before=f.session->snapshot();
    if(!before->loaded)std::cerr<<"DWARF location fixture has no loaded image; snapshot reason: "<<before->reason<<'\n';
    else if(!before->loaded->metadata.elf)std::cerr<<"DWARF location fixture has no ELF metadata; diagnostics: "<<before->loaded->diagnostics.size()<<'\n';
    if(before->loaded&&before->loaded->metadata.elf&&!before->loaded->metadata.elf->dwarf_info)for(const auto& diagnostic:before->loaded->diagnostics)std::cerr<<"DWARF location fixture diagnostic: "<<diagnostic.message<<'\n';
    check(before->loaded&&before->loaded->metadata.elf&&before->loaded->metadata.elf->dwarf_info,
          "DWARF v5 location-list fixture reaches ELF metadata");
    if(!before->loaded||!before->loaded->metadata.elf||!before->loaded->metadata.elf->dwarf_info)return;
    const auto& imported_variables=before->loaded->metadata.elf->dwarf_info->variables;
    const auto source=std::find_if(imported_variables.begin(),imported_variables.end(),[](const auto& row){return row.name=="ranged_local";});
    check(source!=imported_variables.end()&&source->location_ranges.size()==2&&
              source->location_ranges[0].begin==0x400000&&source->location_ranges[0].end==0x400008&&
              source->location_ranges[0].expression==std::vector<std::uint8_t>{0x50}&&
              source->location_ranges[1].begin==0x400008&&source->location_ranges[1].end==0x400010&&
              source->location_ranges[1].expression==std::vector<std::uint8_t>{0x51},
          "DWARF v5 location-list entries preserve both exclusive PC ranges and their expressions");
    const auto imported=f.session->execute(ImportDwarfInfo{},0,{});
    check(bool(imported),"DWARF v5 location ranges import into project state");
    if(!imported)return;
    const auto state=f.session->snapshot()->state;
    const auto row=std::find_if(state->user->debug_variables.begin(),state->user->debug_variables.end(),[](const auto& item){return item.name=="ranged_local";});
    check(row!=state->user->debug_variables.end()&&row->location_ranges.size()==2,
          "project variable persistence retains every DWARF location range");
    ProjectSnapshot view;view.state=state;
    const Address owner{{0},0x400000};
    const auto first_pc=debug_variables_at(view,owner,0x400004);
    const auto second_pc=debug_variables_at(view,owner,0x40000c);
    const auto gap_pc=debug_variables_at(view,owner,0x400010);
    const auto has_ranged=[](const auto& rows){return std::any_of(rows.begin(),rows.end(),[](const auto* item){return item->name=="ranged_local";});};
    check(has_ranged(first_pc)&&has_ranged(second_pc)&&!has_ranged(gap_pc),
          "project PC query selects either half-open location range and excludes its end boundary");
    symbols::LocationEvaluationContext registers;registers.read_register=[](std::uint64_t reg)->std::optional<std::uint64_t>{return reg==0?std::optional<std::uint64_t>{0x111}:reg==1?std::optional<std::uint64_t>{0x222}:std::nullopt;};
    const auto first_location=row==state->user->debug_variables.end()?Result<symbols::EvaluatedLocation>{Error{ErrorCode::unsupported,"missing fixture row"}}:evaluate_debug_variable(*row,0x400004,registers);
    const auto second_location=row==state->user->debug_variables.end()?Result<symbols::EvaluatedLocation>{Error{ErrorCode::unsupported,"missing fixture row"}}:evaluate_debug_variable(*row,0x40000c,registers);
    const auto outside_location=row==state->user->debug_variables.end()?Result<symbols::EvaluatedLocation>{Error{ErrorCode::unsupported,"missing fixture row"}}:evaluate_debug_variable(*row,0x400010,registers);
    check(first_location&&first_location.value()==symbols::EvaluatedLocation{symbols::EvaluatedLocationKind::register_location,0}&&
              second_location&&second_location.value()==symbols::EvaluatedLocation{symbols::EvaluatedLocationKind::register_location,1}&&
              !outside_location,
          "persisted location operations evaluate with caller registers and reject PCs outside all ranges");
    const auto count=state->user->debug_variables.size();
    const auto undone=f.session->undo({});
    check(bool(undone)&&f.session->snapshot()->state->user->debug_variables.empty(),"undo removes durable location ranges with their variable rows");
    const auto redone=f.session->redo({});
    check(bool(redone)&&f.session->snapshot()->state->user->debug_variables.size()==count,"redo restores durable location ranges");
    f.session.reset();f.store.reset();f.store=ProjectStore::open(f.path,ProjectMode::read_write,{}).value();f.session=ProjectSession::attach(f.store,{},{}).value();
    const auto reopened=f.session->snapshot()->state->user->debug_variables;
    const auto restored=std::find_if(reopened.begin(),reopened.end(),[](const auto& item){return item.name=="ranged_local";});
    check(restored!=reopened.end()&&restored->location_ranges.size()==2&&restored->location_ranges[1].expression==std::vector<std::uint8_t>{0x51},
          "location ranges and decoded operations survive project save/reopen");

    ProjectFixture indexed(elf_fixture::executable_with_dwarf_info(false,true,false,false,true,false,true,true),{Format::elf,{}});
    const auto indexed_snapshot=indexed.session->snapshot();
    check(indexed_snapshot->loaded&&indexed_snapshot->loaded->metadata.elf&&indexed_snapshot->loaded->metadata.elf->dwarf_info,
          "DW_FORM_loclistx fixture reaches ELF metadata");
    if(indexed_snapshot->loaded&&indexed_snapshot->loaded->metadata.elf&&indexed_snapshot->loaded->metadata.elf->dwarf_info){
        const auto& indexed_rows=indexed_snapshot->loaded->metadata.elf->dwarf_info->variables;
        const auto indexed_variable=std::find_if(indexed_rows.begin(),indexed_rows.end(),[](const auto& item){return item.name=="ranged_local";});
        check(indexed_variable!=indexed_rows.end()&&indexed_variable->location_ranges.size()==2&&
                  indexed_variable->location_ranges[0].begin==0x400000&&indexed_variable->location_ranges[1].end==0x400010,
              "DW_FORM_loclistx resolves through DW_AT_loclists_base and preserves both entries");
    }
}
void dwarf_legacy_location_list_project_tests() {
    ProjectFixture f(elf_fixture::executable_with_dwarf_info(false,true,false,false,false,false,false,false,true),{Format::elf,{}});
    const auto before=f.session->snapshot();
    if(!before->loaded)std::cerr<<"legacy DWARF fixture has no loaded image; snapshot reason: "<<before->reason<<'\n';
    else if(!before->loaded->metadata.elf)std::cerr<<"legacy DWARF fixture has no ELF metadata; diagnostics: "<<before->loaded->diagnostics.size()<<'\n';
    if(before->loaded&&before->loaded->metadata.elf&&!before->loaded->metadata.elf->dwarf_info){for(const auto& section:before->loaded->metadata.elf->sections)std::cerr<<"legacy fixture section '"<<section.name<<"' size="<<section.size<<'\n';for(const auto& diagnostic:before->loaded->diagnostics)std::cerr<<"legacy DWARF fixture diagnostic: "<<diagnostic.message<<'\n';}
    check(before->loaded&&before->loaded->metadata.elf&&before->loaded->metadata.elf->dwarf_info,
          "legacy .debug_loc fixture reaches ELF DWARF metadata");
    if(!before->loaded||!before->loaded->metadata.elf||!before->loaded->metadata.elf->dwarf_info)return;
    const auto& variables=before->loaded->metadata.elf->dwarf_info->variables;
    const auto source=std::find_if(variables.begin(),variables.end(),[](const auto& row){return row.name=="legacy_ranged_local";});
    check(source!=variables.end()&&source->location_ranges.size()==2&&
              source->location_ranges[0].begin==0x400000&&source->location_ranges[0].end==0x400008&&
              source->location_ranges[0].expression==std::vector<std::uint8_t>{0x50}&&
              source->location_ranges[1].begin==0x400008&&source->location_ranges[1].end==0x400010&&
              source->location_ranges[1].expression==std::vector<std::uint8_t>{0x51},
          "ELF .debug_loc base selection resolves both DWARF v2-v4 variable PC ranges");
    const auto imported=f.session->execute(ImportDwarfInfo{},0,{});
    check(bool(imported),"legacy DWARF variable location ranges persist through the project import action");
    if(!imported)return;
    const auto& rows=f.session->snapshot()->state->user->debug_variables;
    const auto restored=std::find_if(rows.begin(),rows.end(),[](const auto& row){return row.name=="legacy_ranged_local";});
    check(restored!=rows.end()&&restored->location_ranges.size()==2&&restored->location_ranges[1].expression==std::vector<std::uint8_t>{0x51},
          "legacy DWARF ranges survive conversion to durable project variable records");
}
void malformed_dwarf_variable_type_tests() {
    ProjectFixture f(elf_fixture::executable_with_dwarf_info(false,true,false,true),{Format::elf,{}});
    const auto snapshot=f.session->snapshot();
    check(snapshot->loaded&&snapshot->loaded->metadata.elf&&!snapshot->loaded->metadata.elf->dwarf_info&&
              !snapshot->loaded->diagnostics.empty(),
          "malformed variable type reference is diagnosed without invalidating the loaded ELF image");
    auto imported=f.session->execute(ImportDwarfInfo{},0,{});
    check(!imported&&imported.error().code==ErrorCode::unsupported&&
              f.session->snapshot()->state->user->debug_variables.empty(),
          "a rejected DWARF type reference cannot create orphaned project variables");
}
void compound_type_edit_tests() {
    ProjectFixture f(pe_metadata_fixture(), {Format::pe, {}});
    auto u32 = types::Type::integer("u32", 4, 4, false).value();
    auto ptr = types::Type::pointer(u32, 8, 8).value();
    auto array = types::Type::array(ptr, 3).value();
    auto enumeration = types::Type::enumeration_with_values("Mode", u32,
        {{"Idle", 0}, {"Busy", 3}, {"Error", 7}}).value();
    auto function = types::Type::function(u32, {{"items", array}, {"mode", enumeration}}, true).value();
    const std::vector<std::pair<std::string, types::TypePtr>> compound{
        {"Pointer", ptr}, {"Array", array}, {"Mode", enumeration}, {"Callback", function}};
    std::vector<std::uint64_t> ids;
    for (const auto &[name, type] : compound) {
        auto saved = f.session->execute(DefineType{name, type}, 0, {});
        check(bool(saved), "compound type definition is accepted");
        if (saved) ids.push_back(saved.value()->state->user->types.back().id);
    }
    if (ids.size() != compound.size()) return;
    const Address entry{{0}, 0x140001000};
    auto assigned_compound = f.session->execute(AssignType{entry, ids[0], false}, 0, {});
    check(bool(assigned_compound) && type_assignment(*f.session->snapshot(), entry) != nullptr,
          "compound type can be assigned before editing its definition");
    auto replacement = types::Type::pointer(enumeration, 4, 4).value();
    auto updated = f.session->execute(UpdateType{ids[0], "Pointer", replacement}, 0, {});
    const auto *updated_assignment = updated ? type_assignment(*updated.value(), entry) : nullptr;
    check(bool(updated) && updated.value()->state->user->types.front().id == ids[0] &&
              updated.value()->state->user->types.front().type->id() == replacement->id() &&
              updated_assignment && updated_assignment->type_id == ids[0],
          "type edit preserves definition identity and existing assignments");
    check(f.session->snapshot()->state->user->type_assignments.size() == 1,
          "type edit leaves assignment in live project state");
    check(!f.session->execute(UpdateType{ids[0], "Array", replacement}, 0, {}),
          "type edit rejects another definition's name");
    check(!f.session->execute(UpdateType{ids[0], "Pointer", {}}, 0, {}),
          "type edit rejects an empty graph");
    check(!f.session->execute(UpdateType{999999, "Missing", replacement}, 0, {}),
          "type edit rejects an unknown definition identity");
    f.session.reset(); f.store.reset();
    f.store = ProjectStore::open(f.path, ProjectMode::read_write, {}).value();
    f.session = ProjectSession::attach(f.store, {}, {}).value();
    auto reopened = f.session->snapshot();
    const auto *reopened_edited = type_definition(*reopened, ids[0]);
    const auto *reopened_assignment = type_assignment(*reopened, entry);
    const auto *reopened_array = type_definition(*reopened, ids[1]);
    const auto *reopened_enum = type_definition(*reopened, ids[2]);
    const auto *reopened_function = type_definition(*reopened, ids[3]);
    check(reopened->state->user->types.size() == compound.size(), "compound definition count persists through reopen");
    check(reopened_edited && reopened_edited->type->id() == replacement->id(), "edited compound graph persists through reopen");
    check(reopened_assignment && reopened_assignment->type_id == ids[0],
          "type assignment survives edited definition persistence and reopen");
    check(reopened_array && reopened_array->type->kind() == types::Kind::array, "array graph persists through reopen");
    check(reopened_enum && reopened_enum->type->kind() == types::Kind::enumeration, "enum graph persists through reopen");
    check(reopened_enum && reopened_enum->type->enumerator_values() == enumeration->enumerator_values(),
          "explicit enum values persist through project save and reopen");
    check(reopened_function && reopened_function->type->kind() == types::Kind::function, "function graph persists through reopen");
    auto undo = f.session->undo({});
    const auto *undo_type = undo ? type_definition(*undo.value(), ids[0]) : nullptr;
    check(bool(undo) && undo_type && undo_type->type->id() == ptr->id(),
          "compound definition update is reversible after reopen");
    auto redo = f.session->redo({});
    const auto *redo_type = redo ? type_definition(*redo.value(), ids[0]) : nullptr;
    check(bool(redo) && redo_type && redo_type->type->id() == replacement->id(),
          "compound definition update redoes after reopen");
    auto removed = f.session->execute(AssignType{entry, ids[0], true}, 0, {});
    check(bool(removed) && !type_assignment(*removed.value(), entry),
          "assignment can be removed after editing and reopening its type");
}
void session_reuse_tests() {
    auto data = std::vector<std::byte>(18);
    data[0] = std::byte{0xc3};
    data[16] = std::byte{0x90};
    data[17] = std::byte{0xc3};
    ProjectFixture f(data);
    check(bool(f.session->execute(DefineFunction{Address{{0}, 0x1010}}, 0, {})) &&
              bool(f.session->refresh_analysis({})),
          "second user-rooted function is analyzed");
    auto before = f.session->snapshot();
    std::shared_ptr<const FunctionRecord> unrelated;
    for (auto &function : before->functions->functions)
        if (function->entry.offset == 0x1010)
            unrelated = function;
    check(bool(unrelated), "independent session function exists");
    check(bool(f.session->execute(PatchBytes{FileOffset{0}, bytes({0xcc})}, 0, {})) &&
              bool(f.session->refresh_analysis({})),
          "session refresh processes local trap patch");
    auto after = f.session->snapshot();
    std::shared_ptr<const FunctionRecord> retained;
    for (auto &function : after->functions->functions)
        if (function->entry.offset == 0x1010)
            retained = function;
    check(retained == unrelated, "actual project refresh preserves unrelated function record pointer");
    check(after->last_reanalysis.decoded_instructions == 1 && after->last_reanalysis.reused_instructions == 2 &&
              after->last_reanalysis.reused_functions >= 1,
          "project exposes actual decode reuse counters");
    ProjectFixture pe(pe_fixture(), {Format::pe, {}});
    auto initial = pe.session->snapshot();
    check(bool(pe.session->execute(PatchBytes{FileOffset{0xd1}, bytes({0x30})}, 0, {})) &&
              bool(pe.session->refresh_analysis({})),
          "valid image-size header patch reparses and refreshes");
    auto header = pe.session->snapshot();
    check(header->loader_parses == initial->loader_parses + 1 && header->loaded->metadata.image_size == 0x3000,
          "changed recorded header read triggers exactly one loader parse");
    auto code = pe.session->execute(PatchBytes{FileOffset{0x200}, bytes({0xcc})}, 0, {}).value();
    check(code->loader_parses == header->loader_parses + 1 &&
              code->loaded->metadata.pe->image_checksum->computed != header->loaded->metadata.pe->image_checksum->computed,
          "code-byte patch reparses because PE checksum metadata covers the entire input");
    auto baseline = f.session->snapshot();
    check(bool(f.session->execute(PatchBytes{FileOffset{16}, bytes({0xcc})}, 0, {})) && bool(f.session->undo({})) &&
              bool(f.session->refresh_analysis({})),
          "patch reverted before analysis still refreshes source keys");
    auto reverted = f.session->snapshot();
    check(reverted->last_reanalysis.decoded_instructions == 0 &&
              reverted->functions->instructions.size() == baseline->functions->instructions.size(),
          "net byte revert avoids decoding and retains original instruction set");
}
void presentation_index_tests() {
    ProjectFixture f(bytes({0x90, 0xc3}));
    Address entry{{0}, 0x1000};
    auto original = f.session->snapshot();
    check(bool(original->presentation) && presentation_name(*original, entry) == "sub_0_1000" &&
              !annotation_at(*original, entry),
          "project prepares indexed automatic label without inventing a user annotation");
    auto named = f.session->execute(Rename{entry, "indexed"}, 0, {}).value();
    auto retained = annotation_at(*named, entry);
    check(retained && retained->name == "indexed" && presentation_name(*named, entry) == "indexed",
          "indexed lookup returns authoritative explicit name");
    auto patched = f.session->execute(PatchBytes{FileOffset{0}, bytes({0xcc})}, 0, {}).value();
    check(patched->presentation == named->presentation, "byte-only edits share unchanged presentation index");
    auto commented = f.session->execute(Comment{entry, "visible"}, 0, {}).value();
    check(commented->presentation != patched->presentation && annotation_at(*commented, entry)->comment == "visible" &&
              retained->comment.empty(),
          "new comment rebuilds presentation while retained lookup stays immutable");
}
void action_availability_tests() {
    check(!action_availability(nullptr, ProjectActionKind::rename, Address{{0}, 0x1000}).enabled,
          "no-document action has an explicit unavailable reason");
    ProjectFixture f(bytes({0x90, 0xc3}));
    auto current = f.session->snapshot();
    check(action_availability(current.get(), ProjectActionKind::rename, Address{{0}, 0x1000}).enabled &&
              !action_availability(current.get(), ProjectActionKind::rename, FileOffset{0}).enabled,
          "rename preconditions require a virtual location");
    check(!action_availability(current.get(), ProjectActionKind::undo, {}).enabled &&
              !action_availability(current.get(), ProjectActionKind::redo, {}).enabled,
          "empty history disables undo and redo");
    auto edited = f.session->execute(Comment{FileOffset{0}, "edit"}, 0, {}).value();
    check(edited->state->history_count == 1 && action_availability(edited.get(), ProjectActionKind::undo, {}).enabled &&
              !action_availability(edited.get(), ProjectActionKind::redo, {}).enabled,
          "accepted edit updates immutable history availability");
    auto undone = f.session->undo({}).value();
    check(undone->state->history_count == 1 &&
              !action_availability(undone.get(), ProjectActionKind::undo, {}).enabled &&
              action_availability(undone.get(), ProjectActionKind::redo, {}).enabled,
          "undo preserves redo extent");
    auto branched = f.session->execute(Comment{FileOffset{0}, "branch"}, 0, {}).value();
    check(branched->state->history_count == 1 &&
              !action_availability(branched.get(), ProjectActionKind::redo, {}).enabled,
          "new edit after undo drops redo branch availability");
    auto pending = f.session->execute(PatchBytes{FileOffset{0}, bytes({0xcc})}, 0, {}).value();
    check(!action_availability(pending.get(), ProjectActionKind::define_code, Address{{0}, 0x1000}).enabled &&
              action_availability(pending.get(), ProjectActionKind::comment, FileOffset{0}).enabled,
          "pending boundaries disable code decisions while annotations remain available");
    check(action_availability(current.get(), ProjectActionKind::reanalyze, {}).enabled,
          "explicit analysis is available without a selection");
    ProjectSnapshot readonly = *current;
    readonly.mode = ProjectMode::read_only;
    check(!action_availability(&readonly, ProjectActionKind::patch, FileOffset{0}).enabled &&
              action_availability(&readonly, ProjectActionKind::export_binary, {}).enabled &&
              action_availability(&readonly, ProjectActionKind::save_as, {}).enabled,
          "readonly disables edits while allowing separate export and project copy");
    check(action_availability(&readonly, ProjectActionKind::reanalyze, {}).enabled,
          "read-only project can rerun analysis");
    struct Counting : ByteStorage {
        std::shared_ptr<const ByteStorage> source;
        mutable std::size_t reads = 0;
        uint64_t size() const noexcept override { return source->size(); }
        Result<ByteView> read_at(FileOffset at, std::size_t count) const override {
            ++reads;
            return source->read_at(at, count);
        }
    };
    auto storage = std::make_shared<Counting>();
    storage->source = current->effective;
    ProjectSnapshot lightweight = *current;
    lightweight.original = storage;
    lightweight.effective = storage;
    for (auto kind :
         {ProjectActionKind::rename, ProjectActionKind::comment, ProjectActionKind::bookmark, ProjectActionKind::patch,
          ProjectActionKind::define_code, ProjectActionKind::define_data, ProjectActionKind::define_function,
          ProjectActionKind::function_chunks, ProjectActionKind::suppress_function, ProjectActionKind::reference}) {
        auto result = action_availability(&lightweight, kind, Address{{0}, 0x1000});
        (void)result;
    }
    check(storage->reads == 0, "menu action preconditions never read or decode input bytes");
}
int main() {
    return run([] {
        annotation_tests();
        decompiler_edit_tests();
        decision_tests();
        chunk_clear_tests();
        patch_tests();
        file_only_tests();
        failure_tests();
        symbol_tests();
        type_symbol_import_tests();
        packed_header_project_roundtrip_tests();
        dwarf_info_project_import_tests();
        dwarf_variable_project_import_tests();
        dwarf_v5_location_list_project_tests();
        dwarf_legacy_location_list_project_tests();
        malformed_dwarf_variable_type_tests();
        compound_type_edit_tests();
        session_reuse_tests();
        presentation_index_tests();
        action_availability_tests();
    });
}
