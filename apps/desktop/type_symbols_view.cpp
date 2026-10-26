#include "type_symbols_view.hpp"
#include "type_workflow.hpp"
#include "type_editor.hpp"
#include <wx/button.h>
#include <wx/choice.h>
#include <wx/choicdlg.h>
#include <wx/msgdlg.h>
#include <wx/filedlg.h>
#include <wx/wfstream.h>
#include <wx/sizer.h>
#include <wx/textdlg.h>
#include <wx/dialog.h>
#include <wx/stattext.h>
#include <algorithm>
#include <array>
#include <string_view>
#include <map>
#include <charconv>
#include <sstream>
#include <iomanip>
#include <fstream>
#include <limits>
#include <filesystem>
#include <set>
#include <system_error>
#include <unordered_set>
#include "hexlab/types/types.hpp"
#include "hexlab/types/type_library.hpp"
#include "hexlab/types/header_import.hpp"
#include "hexlab/types/pdb.hpp"
#include "hexlab/types/pdb_import.hpp"
#include "hexlab/types/layout.hpp"
#include "hexlab/symbols/dwarf.hpp"
#include "hexlab/loaders/recipe.hpp"
#include "hexlab/image/file_publication.hpp"

namespace hexlab::desktop {
namespace {
std::string utf8(const wxString &value) {
    auto encoded = value.utf8_str();
    return {encoded.data(), encoded.length()};
}

std::string pdb_declaration_kind(types::PdbAggregateDeclarationKind kind) {
    switch (kind) {
    case types::PdbAggregateDeclarationKind::static_data: return "static data";
    case types::PdbAggregateDeclarationKind::nested_type: return "nested type";
    case types::PdbAggregateDeclarationKind::method: return "method";
    case types::PdbAggregateDeclarationKind::vftable_pointer: return "virtual table pointer type";
    }
    return "unknown";
}

std::string pdb_dispatch_kind(types::PdbVirtualDispatchKind kind) {
    switch (kind) {
    case types::PdbVirtualDispatchKind::non_virtual: return "non-virtual";
    case types::PdbVirtualDispatchKind::virtual_method: return "virtual";
    case types::PdbVirtualDispatchKind::introducing_virtual: return "introducing virtual";
    case types::PdbVirtualDispatchKind::pure_virtual: return "pure virtual";
    case types::PdbVirtualDispatchKind::pure_introducing_virtual: return "pure introducing virtual";
    case types::PdbVirtualDispatchKind::unknown: return "unknown";
    }
    return "unknown";
}

std::string location_operation(const database::DebugLocationOperation &operation) {
    using Kind=symbols::LocationOperationKind;
    switch(static_cast<Kind>(operation.kind)){
    case Kind::address:return "DW_OP_addr 0x"+[] (std::uint64_t n){std::ostringstream s;s<<std::hex<<n;return s.str();}(operation.unsigned_operand);
    case Kind::literal:return "DW_OP_lit"+std::to_string(operation.unsigned_operand);
    case Kind::register_location:return "DW_OP_reg"+std::to_string(operation.unsigned_operand);
    case Kind::base_register_plus_offset:return "DW_OP_breg"+std::to_string(operation.unsigned_operand)+(operation.signed_operand<0?" ":" +")+std::to_string(operation.signed_operand);
    case Kind::frame_base_relative:return "DW_OP_fbreg "+std::to_string(operation.signed_operand);
    case Kind::call_frame_cfa:return "DW_OP_call_frame_cfa";
    case Kind::unsigned_constant:return "DW_OP_constu "+std::to_string(operation.unsigned_operand);
    case Kind::signed_constant:return "DW_OP_consts "+std::to_string(operation.signed_operand);
    case Kind::dereference:return "DW_OP_deref";
    case Kind::dereference_sized:return "DW_OP_deref_size "+std::to_string(operation.unsigned_operand);
    case Kind::plus:return "DW_OP_plus";
    case Kind::plus_unsigned:return "DW_OP_plus_uconst "+std::to_string(operation.unsigned_operand);
    case Kind::piece:return "DW_OP_piece "+std::to_string(operation.unsigned_operand);
    case Kind::bit_piece:return "DW_OP_bit_piece "+std::to_string(operation.unsigned_operand)+" offset "+std::to_string(operation.second_unsigned_operand);
    case Kind::stack_value:return "DW_OP_stack_value";
    case Kind::branch:return "DW_OP_skip -> +0x"+[] (std::uint64_t n){std::ostringstream s;s<<std::hex<<n;return s.str();}(operation.second_unsigned_operand);
    case Kind::branch_if_nonzero:return "DW_OP_bra -> +0x"+[] (std::uint64_t n){std::ostringstream s;s<<std::hex<<n;return s.str();}(operation.second_unsigned_operand);
    case Kind::stack_operation:{static const std::map<std::uint64_t,const char*> names{{0x19,"DW_OP_abs"},{0x1a,"DW_OP_and"},{0x1b,"DW_OP_div"},{0x1c,"DW_OP_minus"},{0x1d,"DW_OP_mod"},{0x1e,"DW_OP_mul"},{0x1f,"DW_OP_neg"},{0x20,"DW_OP_not"},{0x21,"DW_OP_or"},{0x24,"DW_OP_shl"},{0x25,"DW_OP_shr"},{0x26,"DW_OP_shra"},{0x27,"DW_OP_xor"},{0x29,"DW_OP_eq"},{0x2a,"DW_OP_ge"},{0x2b,"DW_OP_gt"},{0x2c,"DW_OP_le"},{0x2d,"DW_OP_lt"},{0x2e,"DW_OP_ne"},{0x96,"DW_OP_nop"}};const auto it=names.find(operation.unsigned_operand);return it==names.end()?"DWARF stack operation":it->second;}
    }
    return "unknown DWARF location operation";
}
std::string location_summary(const database::DebugVariable &variable, std::optional<std::uint64_t> pc = {}) {
    if(!variable.location_ranges.empty()){
        if(pc)for(const auto& range:variable.location_ranges)if(*pc>=range.begin&&*pc<range.end){if(range.operations.empty())return "range expression (unevaluated)";return location_operation(range.operations.front())+(range.operations.size()>1?" ...":"")+" (PC range)";}
        return pc?"no location at selected PC":std::to_string(variable.location_ranges.size())+" PC ranges";
    }
    if(variable.address){std::ostringstream out;out<<"direct address 0x"<<std::hex<<*variable.address;return out.str();}
    if(variable.cfa_offset){
        const auto offset=*variable.cfa_offset;
        const auto magnitude=offset<0?static_cast<std::uint64_t>(-(offset+1))+1:static_cast<std::uint64_t>(offset);
        std::ostringstream out;out<<"CFA"<<(offset<0?'-':'+')<<"0x"<<std::hex<<magnitude<<" (frame-relative)";return out.str();
    }
    if(variable.location_expression.empty())return "unavailable (no expression bytes)";
    if(variable.location_operations.empty())return "unevaluated expression";
    return location_operation(variable.location_operations.front())+(variable.location_operations.size()>1?" â€¦":"")+" (unevaluated)";
}
}

namespace {
constexpr std::size_t portable_type_library_limit = 16u * 1024u * 1024u;

Result<std::vector<std::byte>> read_portable_type_library(const std::filesystem::path &path) {
    std::error_code error;
    const auto size = std::filesystem::file_size(path, error);
    if (error) return Error{ErrorCode::io, "Cannot inspect type library: " + error.message()};
    if (size > portable_type_library_limit)
        return Error{ErrorCode::resource_limit, "Type library exceeds the 16 MiB limit"};
    std::ifstream file(path, std::ios::binary);
    if (!file) return Error{ErrorCode::io, "Cannot open type library"};
    std::vector<std::byte> bytes(static_cast<std::size_t>(size));
    if (!bytes.empty()) file.read(reinterpret_cast<char *>(bytes.data()), static_cast<std::streamsize>(bytes.size()));
    if (!file || file.gcount() != static_cast<std::streamsize>(bytes.size()))
        return Error{ErrorCode::io, "Cannot read complete type library"};
    return bytes;
}

Result<types::LibrarySourceIdentity> portable_source_identity(const ProjectSnapshot &project) {
    if (!project.state) return Error{ErrorCode::invalid_argument, "No project is open"};
    auto recipe = encode_recipe(project.state->recipe);
    if (!recipe) return recipe.error();
    Sha256 hash;
    auto updated = hash.update(recipe.value());
    if (!updated) return updated.error();
    return types::LibrarySourceIdentity{project.state->input.size, project.state->input.sha256, hash.digest()};
}

Result<bool> validate_portable_type_references(const types::LibraryBundle &bundle,
                                              const database::UserState &destination) {
    std::set<std::string, std::less<>> available;
    for (const auto &row : destination.types) available.insert(row.name);
    for (const auto &entry : bundle.entries) available.insert(entry.name);
    std::vector<const types::Type *> pending;
    for (const auto &entry : bundle.entries) {
        if (!entry.type) return Error{ErrorCode::malformed, "Type library contains an empty definition"};
        pending.push_back(entry.type.get());
    }
    std::unordered_set<const types::Type *> visited;
    while (!pending.empty()) {
        const auto *type = pending.back();
        pending.pop_back();
        if (!type || !visited.insert(type).second) continue;
        if (visited.size() > 262144)
            return Error{ErrorCode::resource_limit, "Type library graph exceeds the 262,144-node limit"};
        if (type->kind() == types::Kind::named_reference && !available.contains(type->name()))
            return Error{ErrorCode::malformed, "Type library refers to missing definition " + type->name()};
        if (type->element()) pending.push_back(type->element().get());
        if (type->result_type()) pending.push_back(type->result_type().get());
        for (const auto &member : type->members()) if (member.type) pending.push_back(member.type.get());
        for (const auto &parameter : type->parameters()) if (parameter.type) pending.push_back(parameter.type.get());
        for (const auto &method : type->methods()) {
            if (method.signature) pending.push_back(method.signature.get());
            if (method.this_type) pending.push_back(method.this_type.get());
        }
        for (const auto &member : type->static_data_members()) if (member.type) pending.push_back(member.type.get());
    }
    for (const auto &assignment : bundle.assignments)
        if (assignment.type_name.empty() || !available.contains(assignment.type_name))
            return Error{ErrorCode::malformed, "Type assignment refers to missing definition " + assignment.type_name};
    return true;
}
}

void TypeSymbolsView::portable_type_library() {
    if (!project_ || !project_->state || !project_->state->user || !submit_) return;
    wxArrayString choices;
    choices.Add("Export current types and assignments");
    choices.Add("Import a type library");
    wxSingleChoiceDialog action(this, "Choose a portable type-library operation.", "Type Library", choices);
    if (action.ShowModal() != wxID_OK) return;
    if (action.GetSelection() == 0) {
        wxFileDialog dialog(this, "Export type library", {}, "types.hxtl", "HexLab type libraries (*.hxtl)|*.hxtl",
                            wxFD_SAVE | wxFD_OVERWRITE_PROMPT);
        if (dialog.ShowModal() != wxID_OK) return;
        types::LibraryBundle bundle;
        auto identity = portable_source_identity(*project_);
        if (!identity) { wxMessageBox(wxString::FromUTF8(identity.error().message), "Type Library", wxOK | wxICON_ERROR, this); return; }
        bundle.source_identity = identity.value();
        for (const auto &row : project_->state->user->types) {
            std::optional<types::LibraryTypeOrigin> origin;
            if (row.origin) origin = types::LibraryTypeOrigin{row.origin->source_id, row.origin->section,
                row.origin->unit_offset, row.origin->record_offset, row.origin->record_size};
            bundle.entries.push_back({row.name, row.type, std::move(origin),
                static_cast<types::LibraryDeclarationKind>(row.declaration_kind)});
        }
        for (const auto &assignment : project_->state->user->type_assignments) {
            const auto *address = std::get_if<Address>(&assignment.location);
            if (!address) { wxMessageBox("An assignment uses a non-address location and cannot be exported.", "Type Library", wxOK | wxICON_ERROR, this); return; }
            const auto found = std::find_if(project_->state->user->types.begin(), project_->state->user->types.end(),
                [&](const auto &row) { return row.id == assignment.type_id; });
            if (found == project_->state->user->types.end()) { wxMessageBox("An assignment refers to a missing type definition.", "Type Library", wxOK | wxICON_ERROR, this); return; }
            bundle.assignments.push_back({*address, found->name});
        }
        auto bytes = types::encode_library_bundle(bundle, portable_type_library_limit);
        if (!bytes) { wxMessageBox(wxString::FromUTF8(bytes.error().message), "Type Library", wxOK | wxICON_ERROR, this); return; }
        const auto path = std::filesystem::path(dialog.GetPath().ToStdWstring());
        const bool replacing = std::filesystem::exists(path);
        auto publication = FilePublication::create(path, replacing ? ExistingFilePolicy::replace : ExistingFilePolicy::reject,
                                                    project_->protected_paths, {});
        if (!publication) { wxMessageBox(wxString::FromUTF8(publication.error().message), "Type Library", wxOK | wxICON_ERROR, this); return; }
        auto written = publication.value()->append(bytes.value());
        if (!written) { wxMessageBox(wxString::FromUTF8(written.error().message), "Type Library", wxOK | wxICON_ERROR, this); return; }
        auto published = publication.value()->publish();
        if (!published) { wxMessageBox(wxString::FromUTF8(published.error().message), "Type Library", wxOK | wxICON_ERROR, this); return; }
        wxMessageBox(wxString::Format("Exported %llu type definitions and %llu address assignments.",
            static_cast<unsigned long long>(bundle.entries.size()), static_cast<unsigned long long>(bundle.assignments.size())),
            "Type Library", wxOK | wxICON_INFORMATION, this);
        return;
    }

    wxFileDialog dialog(this, "Import type library", {}, {}, "HexLab type libraries (*.hxtl)|*.hxtl|All files (*.*)|*.*", wxFD_OPEN | wxFD_FILE_MUST_EXIST);
    if (dialog.ShowModal() != wxID_OK) return;
    auto bytes = read_portable_type_library(std::filesystem::path(dialog.GetPath().ToStdWstring()));
    if (!bytes) { wxMessageBox(wxString::FromUTF8(bytes.error().message), "Type Library", wxOK | wxICON_ERROR, this); return; }
    auto decoded = types::decode_library_bundle(bytes.value(), portable_type_library_limit);
    if (!decoded) { wxMessageBox(wxString::FromUTF8(decoded.error().message), "Type Library", wxOK | wxICON_ERROR, this); return; }
    auto &bundle = decoded.value();
    auto graph = validate_portable_type_references(bundle, *project_->state->user);
    if (!graph) { wxMessageBox(wxString::FromUTF8(graph.error().message), "Type Library", wxOK | wxICON_ERROR, this); return; }
    const auto current_identity = portable_source_identity(*project_);
    const bool identity_matches = current_identity && bundle.source_identity && *bundle.source_identity == current_identity.value();
    const std::size_t skipped_assignments = identity_matches ? 0 : bundle.assignments.size();
    std::map<std::string, const database::TypeDefinition *, std::less<>> existing;
    for (const auto &row : project_->state->user->types) existing.emplace(row.name, &row);
    std::size_t new_count = 0, same_count = 0, conflict_count = 0;
    for (const auto &entry : bundle.entries) {
        auto found = existing.find(entry.name);
        if (found == existing.end()) { ++new_count; continue; }
        auto a = types::encode(*found->second->type), b = types::encode(*entry.type);
        if (a && b && a.value() == b.value() && found->second->origin == (entry.origin ? std::optional<database::DwarfSourceOrigin>{{entry.origin->source_id, entry.origin->section, entry.origin->unit_offset, entry.origin->record_offset, entry.origin->record_size}} : std::nullopt) &&
            found->second->declaration_kind == static_cast<database::DeclarationKind>(entry.declaration_kind)) ++same_count;
        else ++conflict_count;
    }
    std::size_t assignment_same = 0, assignment_conflicts = 0;
    if (identity_matches) for (const auto &assignment : bundle.assignments) {
        auto found = std::find_if(project_->state->user->type_assignments.begin(), project_->state->user->type_assignments.end(),
            [&](const auto &row) { return row.location == Location{assignment.location}; });
        if (found == project_->state->user->type_assignments.end()) continue;
        auto target = std::find_if(project_->state->user->types.begin(), project_->state->user->types.end(), [&](const auto &row) { return row.id == found->type_id; });
        if (target != project_->state->user->types.end() && target->name == assignment.type_name) ++assignment_same;
        else ++assignment_conflicts;
    }
    wxString summary = wxString::Format("Definitions: %llu new, %llu identical, %llu conflicting. Assignments: %llu compatible, %llu identical, %llu conflicting.",
        static_cast<unsigned long long>(new_count), static_cast<unsigned long long>(same_count), static_cast<unsigned long long>(conflict_count),
        static_cast<unsigned long long>(identity_matches ? bundle.assignments.size() : 0), static_cast<unsigned long long>(assignment_same), static_cast<unsigned long long>(assignment_conflicts));
    if (skipped_assignments) summary += wxString::Format("\n\nSource identity does not match this project; %llu assignments will be skipped. Definitions remain importable.", static_cast<unsigned long long>(skipped_assignments));
    summary += "\n\nChoose how conflicting rows should be handled.";
    wxArrayString policies; policies.Add("Keep existing rows"); policies.Add("Replace conflicting rows");
    wxSingleChoiceDialog policy(this, summary, "Preview type-library import", policies);
    if (policy.ShowModal() != wxID_OK) return;
    const bool replace = policy.GetSelection() == 1;
    ImportPortableTypes command;
    for (const auto &entry : bundle.entries) {
        auto found = existing.find(entry.name);
        std::optional<std::uint64_t> existing_id;
        std::optional<database::TypeDefinition> expected;
        if (found != existing.end()) {
            auto a = types::encode(*found->second->type), b = types::encode(*entry.type);
            const auto origin = entry.origin ? std::optional<database::DwarfSourceOrigin>{{entry.origin->source_id, entry.origin->section, entry.origin->unit_offset, entry.origin->record_offset, entry.origin->record_size}} : std::nullopt;
            if (a && b && a.value() == b.value() && found->second->origin == origin && found->second->declaration_kind == static_cast<database::DeclarationKind>(entry.declaration_kind)) continue;
            if (!replace) continue;
            existing_id = found->second->id; expected = *found->second;
        }
        std::optional<database::DwarfSourceOrigin> origin;
        if (entry.origin) origin = database::DwarfSourceOrigin{entry.origin->source_id, entry.origin->section, entry.origin->unit_offset, entry.origin->record_offset, entry.origin->record_size};
        command.definitions.push_back({entry.name, entry.type, existing_id, std::move(origin), static_cast<database::DeclarationKind>(entry.declaration_kind), std::move(expected)});
    }
    if (identity_matches) for (const auto &assignment : bundle.assignments) {
        auto current = std::find_if(project_->state->user->type_assignments.begin(), project_->state->user->type_assignments.end(),
            [&](const auto &row) { return row.location == Location{assignment.location}; });
        if (current != project_->state->user->type_assignments.end()) {
            auto target = std::find_if(project_->state->user->types.begin(), project_->state->user->types.end(), [&](const auto &row) { return row.id == current->type_id; });
            if (target != project_->state->user->types.end() && target->name == assignment.type_name) continue;
            if (!replace) continue;
        }
        command.assignments.push_back({assignment.location, assignment.type_name});
    }
    if (command.definitions.empty() && command.assignments.empty()) { wxMessageBox("The selected policy leaves no changes to apply.", "Type Library", wxOK | wxICON_INFORMATION, this); return; }
    auto valid = validate_command(*project_, ProjectCommand{command});
    if (!valid) { wxMessageBox(wxString::FromUTF8(valid.error().message), "Type Library", wxOK | wxICON_ERROR, this); return; }
    const auto definitions_applied = command.definitions.size(), assignments_applied = command.assignments.size();
    submit_(std::move(command));
    wxMessageBox(wxString::Format("Queued an atomic, undoable import of %llu definitions and %llu assignments.",
        static_cast<unsigned long long>(definitions_applied), static_cast<unsigned long long>(assignments_applied)),
        "Type Library", wxOK | wxICON_INFORMATION, this);
}

TypeSymbolsView::TypeSymbolsView(wxWindow *parent) : wxPanel(parent) {
    auto *root = new wxBoxSizer(wxVERTICAL);
    auto *actions = new wxBoxSizer(wxHORIZONTAL);
    define_ = new wxButton(this, wxID_ANY, "New integer type");
    define_->SetName("type-define");
    define_struct_ = new wxButton(this, wxID_ANY, "New structure");
    define_struct_->SetName("type-define-structure");
    define_compound_ = new wxButton(this, wxID_ANY, "New compound type");
    define_compound_->SetName("type-define-compound");
    edit_ = new wxButton(this, wxID_ANY, "Edit selected type");
    edit_->SetName("type-edit");
    assign_ = new wxButton(this, wxID_ANY, "Assign to selection");
    assign_->SetName("type-assign");
    remove_ = new wxButton(this, wxID_ANY, "Clear assignment");
    remove_->SetName("type-remove-assignment");
    import_ = new wxButton(this, wxID_ANY, "Import symbols");
    import_->SetName("symbols-import");
    import_header_ = new wxButton(this, wxID_ANY, "Import C Header");
    import_header_->SetName("types-import-header");
    import_pdb_types_ = new wxButton(this, wxID_ANY, "Import PDB Types");
    import_pdb_types_->SetName("types-import-pdb");
    import_dwarf_ = new wxButton(this, wxID_ANY, "Import DWARF Info");
    import_dwarf_->SetName("types-import-dwarf");
    portable_library_ = new wxButton(this, wxID_ANY, "Type Library...");
    portable_library_->SetName("types-portable-library");
    for (auto *button : {define_, define_struct_, define_compound_, edit_, assign_, remove_, import_, import_header_, import_pdb_types_, import_dwarf_, portable_library_})
        actions->Add(button, 0, wxRIGHT | wxBOTTOM, FromDIP(4));
    root->Add(actions, 0, wxEXPAND | wxALL, FromDIP(5));
    pages_ = new wxNotebook(this, wxID_ANY);
    auto *type_page = new wxPanel(pages_);
    auto *type_layout = new wxBoxSizer(wxVERTICAL);
    auto *type_search_bar = new wxBoxSizer(wxHORIZONTAL);
    type_search_bar->Add(new wxStaticText(type_page, wxID_ANY, "Find type:"), 0,
                         wxALIGN_CENTER_VERTICAL | wxRIGHT, FromDIP(5));
    type_filter_ = new wxTextCtrl(type_page, wxID_ANY);
    type_filter_->SetName("type-definition-filter");
    type_filter_->SetHint("Filter by name or type shape");
    type_search_bar->Add(type_filter_, 1, wxEXPAND);
    type_layout->Add(type_search_bar, 0, wxEXPAND | wxALL, FromDIP(4));
    wxArrayString abi_choices{"x86-32", "x86-64", "AArch64"};
    layout_abi_ = new wxChoice(type_page, wxID_ANY, wxDefaultPosition, wxDefaultSize, abi_choices);
    layout_abi_->SetName("type-layout-abi");
    layout_abi_->SetSelection(1);
    type_layout->Add(layout_abi_, 0, wxEXPAND | wxALL, FromDIP(4));
    layout_details_ = new wxTextCtrl(type_page, wxID_ANY, "Select a type to inspect its ABI layout.",
                                     wxDefaultPosition, FromDIP(wxSize(-1, 130)),
                                     wxTE_MULTILINE | wxTE_READONLY | wxTE_DONTWRAP);
    layout_details_->SetName("type-layout-details");
    type_layout->Add(layout_details_, 0, wxEXPAND | wxLEFT | wxRIGHT | wxBOTTOM, FromDIP(4));
    types_ = new VirtualTable(type_page, "type-definitions", {"Name", "Type", "Size"});
    type_layout->Add(types_, 1, wxEXPAND | wxALL, FromDIP(4));
    type_page->SetSizer(type_layout);
    auto *assignment_page = new wxPanel(pages_);
    auto *assignment_layout = new wxBoxSizer(wxVERTICAL);
    auto *assignment_search_bar = new wxBoxSizer(wxHORIZONTAL);
    assignment_search_bar->Add(new wxStaticText(assignment_page, wxID_ANY, "Find assignment:"), 0,
                               wxALIGN_CENTER_VERTICAL | wxRIGHT, FromDIP(5));
    assignment_filter_ = new wxTextCtrl(assignment_page, wxID_ANY);
    assignment_filter_->SetName("type-assignment-filter");
    assignment_filter_->SetHint("Filter by address or type name");
    assignment_search_bar->Add(assignment_filter_, 1, wxEXPAND);
    assignment_layout->Add(assignment_search_bar, 0, wxEXPAND | wxALL, FromDIP(4));
    assignments_ = new VirtualTable(assignment_page, "type-assignments", {"Address", "Type"});
    assignment_layout->Add(assignments_, 1, wxEXPAND | wxLEFT | wxRIGHT | wxBOTTOM, FromDIP(4));
    assignment_page->SetSizer(assignment_layout);
    auto *symbol_page = new wxPanel(pages_);
    auto *symbol_layout = new wxBoxSizer(wxVERTICAL);
    auto *symbol_search_bar = new wxBoxSizer(wxHORIZONTAL);
    symbol_search_bar->Add(new wxStaticText(symbol_page, wxID_ANY, "Find imported symbol:"), 0,
                           wxALIGN_CENTER_VERTICAL | wxRIGHT, FromDIP(5));
    symbol_filter_ = new wxTextCtrl(symbol_page, wxID_ANY);
    symbol_filter_->SetName("importable-symbol-filter");
    symbol_filter_->SetHint("Filter by symbol name or address");
    symbol_search_bar->Add(symbol_filter_, 1, wxEXPAND);
    symbol_layout->Add(symbol_search_bar, 0, wxEXPAND | wxALL, FromDIP(4));
    symbols_ = new VirtualTable(symbol_page, "importable-symbols", {"Address", "Symbol"});
    symbol_layout->Add(symbols_, 1, wxEXPAND | wxLEFT | wxRIGHT | wxBOTTOM, FromDIP(4));
    symbol_page->SetSizer(symbol_layout);
    auto *variable_page=new wxPanel(pages_);auto *variable_layout=new wxBoxSizer(wxVERTICAL);
    variables_=new VirtualTable(variable_page,"debug-variables",{"Function","Name","Kind","Type","Scope DIE","Location"});
    variable_layout->Add(variables_,1,wxEXPAND|wxALL,FromDIP(4));
    variable_details_=new wxTextCtrl(variable_page,wxID_ANY,"Select a variable to inspect its DWARF source and unevaluated location expression.",wxDefaultPosition,FromDIP(wxSize(-1,100)),wxTE_MULTILINE|wxTE_READONLY|wxTE_DONTWRAP);
    variable_details_->SetName("debug-variable-details");variable_layout->Add(variable_details_,0,wxEXPAND|wxLEFT|wxRIGHT|wxBOTTOM,FromDIP(4));
    go_to_variable_function_ = new wxButton(variable_page, wxID_ANY, "Go to owning function");
    go_to_variable_function_->SetName("debug-variable-go-to-function");
    variable_layout->Add(go_to_variable_function_, 0, wxLEFT | wxRIGHT | wxBOTTOM, FromDIP(4));
    go_to_variable_function_->Disable();
    variable_page->SetSizer(variable_layout);
    auto *pdb_id_page = new wxPanel(pages_);
    auto *pdb_id_layout = new wxBoxSizer(wxVERTICAL);
    pdb_id_layout->Add(new wxStaticText(pdb_id_page, wxID_ANY,
        "CodeView IPI function identifiers and build/source metadata are inspected with their exact record references. Resolved prototypes are imported as named project types; no function names or assignments are changed."),
        0, wxEXPAND | wxALL, FromDIP(4));
    pdb_ids_ = new VirtualTable(pdb_id_page, "pdb-function-identifiers",
        {"IPI index", "Kind", "Name", "TPI function", "Record offset", "Status"});
    pdb_ids_->SetColumnWidth(0, FromDIP(95));
    pdb_ids_->SetColumnWidth(1, FromDIP(105));
    pdb_ids_->SetColumnWidth(2, FromDIP(280));
    pdb_ids_->SetColumnWidth(3, FromDIP(115));
    pdb_ids_->SetColumnWidth(4, FromDIP(120));
    pdb_id_layout->Add(pdb_ids_, 1, wxEXPAND | wxLEFT | wxRIGHT | wxBOTTOM, FromDIP(4));
    pdb_id_details_ = new wxTextCtrl(pdb_id_page, wxID_ANY,
        "Import PDB Types to inspect the selected PDB's IPI records.",
        wxDefaultPosition, FromDIP(wxSize(-1, 105)), wxTE_MULTILINE | wxTE_READONLY | wxTE_DONTWRAP);
    pdb_id_details_->SetName("pdb-function-id-details");
    pdb_id_layout->Add(pdb_id_details_, 0, wxEXPAND | wxLEFT | wxRIGHT | wxBOTTOM, FromDIP(4));
    pdb_id_page->SetSizer(pdb_id_layout);
    auto *pdb_declaration_page = new wxPanel(pages_);
    auto *pdb_declaration_layout = new wxBoxSizer(wxVERTICAL);
    pdb_declaration_status_ = new wxStaticText(pdb_declaration_page, wxID_ANY,
        "Import PDB Types to inspect source-scoped class declarations. These rows are preview-only and are not persisted in project aggregate types or layout.");
    pdb_declaration_status_->SetName("pdb-aggregate-declaration-status");
    pdb_declaration_layout->Add(pdb_declaration_status_, 0, wxEXPAND | wxALL, FromDIP(4));
    pdb_declarations_ = new VirtualTable(pdb_declaration_page, "pdb-aggregate-declarations",
        {"Owner", "Aggregate TPI", "Kind", "Name", "Type", "Access", "Dispatch", "Virtual slot", "This type", "Ordinal"});
    pdb_declarations_->SetColumnWidth(0, FromDIP(230));
    pdb_declarations_->SetColumnWidth(1, FromDIP(120));
    pdb_declarations_->SetColumnWidth(2, FromDIP(95));
    pdb_declarations_->SetColumnWidth(3, FromDIP(220));
    pdb_declarations_->SetColumnWidth(4, FromDIP(300));
    pdb_declaration_layout->Add(pdb_declarations_, 1, wxEXPAND | wxLEFT | wxRIGHT | wxBOTTOM, FromDIP(4));
    pdb_declaration_page->SetSizer(pdb_declaration_layout);
    auto *pdb_data_symbol_page = new wxPanel(pages_);
    auto *pdb_data_symbol_layout = new wxBoxSizer(wxVERTICAL);
    pdb_data_symbol_status_ = new wxStaticText(pdb_data_symbol_page, wxID_ANY,
        "Import PDB Types to inspect typed CodeView global and module data symbols. Navigation requires a uniquely matching loaded PE.");
    pdb_data_symbol_status_->SetName("pdb-data-symbol-status");
    pdb_data_symbol_layout->Add(pdb_data_symbol_status_, 0, wxEXPAND | wxALL, FromDIP(4));
    pdb_data_symbols_ = new VirtualTable(pdb_data_symbol_page, "pdb-data-symbols",
        {"Name", "Type", "Section", "Section offset", "TPI index", "Source", "Module / object", "Status"});
    pdb_data_symbols_->SetColumnWidth(0, FromDIP(240));
    pdb_data_symbols_->SetColumnWidth(1, FromDIP(300));
    pdb_data_symbols_->SetColumnWidth(2, FromDIP(70));
    pdb_data_symbols_->SetColumnWidth(3, FromDIP(120));
    pdb_data_symbols_->SetColumnWidth(4, FromDIP(105));
    pdb_data_symbol_layout->Add(pdb_data_symbols_, 1, wxEXPAND | wxLEFT | wxRIGHT | wxBOTTOM, FromDIP(4));
    pdb_data_symbol_details_ = new wxTextCtrl(pdb_data_symbol_page, wxID_ANY,
        "Select a data symbol to inspect its exact CodeView type reference and source provenance.",
        wxDefaultPosition, FromDIP(wxSize(-1, 110)), wxTE_MULTILINE | wxTE_READONLY | wxTE_DONTWRAP);
    pdb_data_symbol_details_->SetName("pdb-data-symbol-details");
    pdb_data_symbol_layout->Add(pdb_data_symbol_details_, 0, wxEXPAND | wxLEFT | wxRIGHT | wxBOTTOM, FromDIP(4));
    pdb_data_symbol_page->SetSizer(pdb_data_symbol_layout);
    pages_->AddPage(type_page, "Types");
    pages_->AddPage(assignment_page, "Assignments");
    pages_->AddPage(symbol_page, "Importable symbols");
    pages_->AddPage(variable_page,"Variables");
    pages_->AddPage(pdb_id_page, "PDB function IDs");
    pages_->AddPage(pdb_declaration_page, "PDB declarations");
    pages_->AddPage(pdb_data_symbol_page, "PDB data symbols");
    root->Add(pages_, 1, wxEXPAND | wxLEFT | wxRIGHT | wxBOTTOM, FromDIP(5));
    SetSizer(root);
    define_->Bind(wxEVT_BUTTON, [this](wxCommandEvent &) { define_type(); });
    define_struct_->Bind(wxEVT_BUTTON, [this](wxCommandEvent &) { define_structure(); });
    define_compound_->Bind(wxEVT_BUTTON, [this](wxCommandEvent &) { define_compound(); });
    edit_->Bind(wxEVT_BUTTON, [this](wxCommandEvent &) { edit_type(); });
    types_->Bind(wxEVT_LIST_ITEM_SELECTED, [this](wxListEvent &) {
        if (refreshing_types_) return;
        if (const auto row = types_->selected_row(); row && *row < visible_type_definition_indices_.size() &&
            project_ && project_->state) {
            const auto index = visible_type_definition_indices_[*row];
            if (index < project_->state->user->types.size())
                selected_type_id_ = project_->state->user->types[index].id;
        }
        edit_->Enable(project_ && project_->mode == database::ProjectMode::read_write && static_cast<bool>(submit_));
        refresh_layout();
    });
    pdb_ids_->Bind(wxEVT_LIST_ITEM_SELECTED, [this](wxListEvent &) { refresh_pdb_function_id_details(); });
    pdb_ids_->Bind(wxEVT_LIST_ITEM_DESELECTED, [this](wxListEvent &) { refresh_pdb_function_id_details(); });
    types_->Bind(wxEVT_LIST_ITEM_DESELECTED, [this](wxListEvent &) {
        if (refreshing_types_) return;
        edit_->Enable(project_ && project_->mode == database::ProjectMode::read_write && static_cast<bool>(submit_) &&
                      types_->GetNextItem(-1, wxLIST_NEXT_ALL, wxLIST_STATE_SELECTED) >= 0);
        if (types_->GetNextItem(-1, wxLIST_NEXT_ALL, wxLIST_STATE_SELECTED) < 0)
            selected_type_id_.reset();
        refresh_layout();
    });
    type_filter_->Bind(wxEVT_TEXT, [this](wxCommandEvent &) { refresh_types(); });
    assignment_filter_->Bind(wxEVT_TEXT, [this](wxCommandEvent &) { refresh(); });
    layout_abi_->Bind(wxEVT_CHOICE, [this](wxCommandEvent &) { refresh_layout(); });
    assign_->Bind(wxEVT_BUTTON, [this](wxCommandEvent &) { assign_type(); });
    remove_->Bind(wxEVT_BUTTON, [this](wxCommandEvent &) { remove_assignment(); });
    import_->Bind(wxEVT_BUTTON, [this](wxCommandEvent &) { import_symbols(); });
    import_header_->Bind(wxEVT_BUTTON, [this](wxCommandEvent &) { import_header(); });
    import_pdb_types_->Bind(wxEVT_BUTTON, [this](wxCommandEvent &) { import_pdb_types(); });
    import_dwarf_->Bind(wxEVT_BUTTON, [this](wxCommandEvent &) { import_dwarf_info(); });
    portable_library_->Bind(wxEVT_BUTTON, [this](wxCommandEvent &) { portable_type_library(); });
    symbol_filter_->Bind(wxEVT_TEXT, [this](wxCommandEvent &) { refresh_symbols(); });
    pdb_data_symbols_->activate = [this](std::size_t row) {
        if (document_ && row < pdb_data_symbol_rows_.size() && pdb_data_symbol_rows_[row].address && navigate)
            navigate(*document_, project_, Location{*pdb_data_symbol_rows_[row].address});
    };
    pdb_data_symbols_->Bind(wxEVT_LIST_ITEM_SELECTED, [this](wxListEvent &) { refresh_pdb_data_symbol_details(); });
    pdb_data_symbols_->Bind(wxEVT_LIST_ITEM_DESELECTED, [this](wxListEvent &) { refresh_pdb_data_symbol_details(); });
    variables_->Bind(wxEVT_LIST_ITEM_SELECTED,[this](wxListEvent &){refresh_variable_details();});
    variables_->Bind(wxEVT_LIST_ITEM_DESELECTED,[this](wxListEvent &){refresh_variable_details();});
    go_to_variable_function_->Bind(wxEVT_BUTTON, [this](wxCommandEvent &) {
        if (!document_ || !project_ || !project_->state || !navigate)
            return;
        const auto selected = variables_->selected_row();
        if (!selected || *selected >= project_->state->user->debug_variables.size())
            return;
        navigate(*document_, project_, Location{project_->state->user->debug_variables[*selected].function_entry});
    });
    assignments_->activate = [this](std::size_t row) {
        if (!document_ || !project_ || !project_->state || row >= visible_assignment_indices_.size() || !navigate)
            return;
        const auto index = visible_assignment_indices_[row];
        if (index < project_->state->user->type_assignments.size())
            navigate(*document_, project_, project_->state->user->type_assignments[index].location);
    };
    refresh();
}
void TypeSymbolsView::update(std::optional<DocumentId> document, std::shared_ptr<const ProjectSnapshot> project,
                             std::optional<Location> selection,
                             std::function<void(ProjectCommand)> submit) {
    const bool project_changed = document != document_ || !project || !project->state || !project_ || !project_->state ||
        project->state->uuid != project_->state->uuid;
    if (project_changed) {
        selected_type_id_.reset();
        pdb_function_ids_.clear();
        pdb_aggregate_declarations_.clear();
        pdb_data_symbol_rows_.clear();
        pdb_declarations_omitted_ = 0;
        pdb_data_symbols_omitted_ = 0;
        pdb_data_symbols_resolved_ = 0;
        pdb_data_symbols_unresolved_ = 0;
        pdb_id_identity_.clear();
        pdb_id_diagnostic_.clear();
        pdb_data_symbol_diagnostic_.clear();
    }
    document_ = document;
    project_ = std::move(project);
    submit_ = std::move(submit);
    selected_address_.reset();
    if (project_ && selection) {
        if (auto address = std::get_if<Address>(&*selection))
            selected_address_ = *address;
        else if (project_->loaded && project_->loaded->image) {
            auto mapped = project_->loaded->image->to_address(std::get<FileOffset>(*selection));
            if (mapped)
                selected_address_ = mapped.value();
        }
    }
    if (!layout_abi_initialized_ && project_ && project_->loaded && project_->loaded->image) {
        switch (project_->loaded->image->layout().architecture) {
        case Architecture::x86: layout_abi_->SetSelection(0); break;
        case Architecture::x86_64: layout_abi_->SetSelection(1); break;
        case Architecture::arm64: layout_abi_->SetSelection(2); break;
        default: break;
        }
        layout_abi_initialized_ = true;
    }
    if (project_changed) refresh_pdb_function_ids();
    refresh();
}
void TypeSymbolsView::refresh() {
    auto project = project_;
    const auto definitions = project && project->state ? project->state->user->types.size() : 0;
    refresh_types();
    const auto *all_assignments = project && project->state ? &project->state->user->type_assignments : nullptr;
    visible_assignment_indices_.clear();
    auto assignment_query = assignment_filter_ ? assignment_filter_->GetValue() : wxString{};
    assignment_query.Trim(true).Trim(false);
    assignment_query.MakeLower();
    if (all_assignments) for (std::size_t index = 0; index < all_assignments->size(); ++index) {
        const auto &item = (*all_assignments)[index];
        auto address = location_text(item.location);
        auto name = wxString{};
        if (project) if (auto *definition = type_definition(*project, item.type_id)) name = text(definition->name);
        address.MakeLower();
        name.MakeLower();
        if (!assignment_query.empty() && address.Find(assignment_query) == wxNOT_FOUND &&
            name.Find(assignment_query) == wxNOT_FOUND) continue;
        visible_assignment_indices_.push_back(index);
    }
    assignments_->populate(visible_assignment_indices_.size(), [this, project](std::size_t row, int column) {
        if (!project || !project->state || row >= visible_assignment_indices_.size()) return wxString{};
        const auto &item = project->state->user->type_assignments[visible_assignment_indices_[row]];
        if (column == 0) return location_text(item.location);
        if (auto *definition = type_definition(*project, item.type_id)) return text(definition->name);
        return wxString::Format("<missing type %llu>", static_cast<unsigned long long>(item.type_id));
    });
    if (selected_address_ && project && project->state) {
        const auto &rows = project->state->user->type_assignments;
        for (std::size_t row = 0; row < visible_assignment_indices_.size(); ++row)
            if (rows[visible_assignment_indices_[row]].location == Location{*selected_address_}) {
                assignments_->select_row(row);
                break;
            }
    }
    symbol_candidates_ = project ? importable_symbols(*project) : std::vector<SymbolCandidate>{};
    refresh_symbols();
    const auto variable_count=project&&project->state?project->state->user->debug_variables.size():0;
    const auto selected_pc=selected_address_?std::optional<std::uint64_t>(selected_address_->offset):std::nullopt;
    variables_->populate(variable_count,[project,selected_pc](std::size_t row,int column){
        const auto& item=project->state->user->debug_variables[row];
        if(column==0)return location_text(item.function_entry);
        if(column==1)return text(item.name);
        if(column==2)return item.is_parameter?wxString("parameter"):wxString("local");
        if(column==3){if(item.type_id)if(const auto* definition=type_definition(*project,*item.type_id))return text(definition->name);return wxString("<unresolved type>");}
        if(column==4)return wxString::Format("0x%llx",static_cast<unsigned long long>(item.scope_offset));
        return text(location_summary(item,selected_pc));
    });
    refresh_pdb_aggregate_declarations();
    refresh_pdb_data_symbols();
    const bool writable = project && project->mode == database::ProjectMode::read_write && static_cast<bool>(submit_);
    define_->Enable(writable);
    define_struct_->Enable(writable && definitions != 0);
    define_compound_->Enable(writable);
    const auto selected_type_row = selected_type_index();
    edit_->Enable(writable && selected_type_row.has_value());
    assign_->Enable(writable && selected_address_ && definitions != 0);
    const auto selected_type = project && project->state && selected_type_row && *selected_type_row < definitions
        ? std::optional<std::uint64_t>(project->state->user->types[*selected_type_row].id) : std::nullopt;
    assign_->SetLabel(selected_type ? "Assign selected type" : "Assign type to selection");
    if (selected_type) {
        const auto &definition = project->state->user->types[*selected_type_row];
        assign_->SetToolTip("Assign '" + text(definition.name) + "' to the selected address");
    } else {
        assign_->SetToolTip("Choose a type for the selected address");
    }
    remove_->Enable(writable && selected_address_ && type_assignment(*project, *selected_address_));
    import_->Enable(writable && !symbol_candidates_.empty());
    import_header_->Enable(writable);
    import_pdb_types_->Enable(writable);
    import_dwarf_->Enable(writable && project->loaded && project->loaded->metadata.elf &&
                          project->loaded->metadata.elf->dwarf_info.has_value());
    portable_library_->Enable(writable);
    refresh_layout();
    refresh_variable_details();
}
void TypeSymbolsView::refresh_types() {
    if (!types_) return;
    const auto project = project_;
    const auto *definitions = project && project->state ? &project->state->user->types : nullptr;
    visible_type_definition_indices_.clear();
    const auto count = definitions ? definitions->size() : 0;
    auto query = type_filter_ ? type_filter_->GetValue() : wxString{};
    query.Trim(true).Trim(false);
    query.MakeLower();
    visible_type_definition_indices_.reserve(count);
    for (std::size_t index = 0; index < count; ++index) {
        const auto &definition = (*definitions)[index];
        if (!query.empty()) {
            auto name = text(definition.name);
            auto shape = text(types::format(*definition.type));
            auto size = definition.type->size()
                ? wxString::Format("%llu", static_cast<unsigned long long>(*definition.type->size()))
                : wxString("dynamic");
            name.MakeLower();
            shape.MakeLower();
            size.MakeLower();
            if (name.Find(query) == wxNOT_FOUND && shape.Find(query) == wxNOT_FOUND &&
                size.Find(query) == wxNOT_FOUND)
                continue;
        }
        visible_type_definition_indices_.push_back(index);
    }
    refreshing_types_ = true;
    types_->populate(visible_type_definition_indices_.size(), [this, project](std::size_t row, int column) {
        if (!project || !project->state || row >= visible_type_definition_indices_.size()) return wxString{};
        const auto index = visible_type_definition_indices_[row];
        if (index >= project->state->user->types.size()) return wxString{};
        const auto &item = project->state->user->types[index];
        if (column == 0) return text(item.name);
        if (column == 1) return text(types::format(*item.type));
        return item.type->size() ? wxString::Format("%llu", static_cast<unsigned long long>(*item.type->size()))
                                 : wxString("dynamic");
    });
    types_->fit_columns({0, 1, 2});
    if (selected_type_id_ && definitions) {
        const auto selected = std::find_if(definitions->begin(), definitions->end(), [&](const auto &definition) {
            return definition.id == *selected_type_id_;
        });
        if (selected == definitions->end()) {
            selected_type_id_.reset();
        } else {
            const auto index = static_cast<std::size_t>(selected - definitions->begin());
            const auto visible = std::find(visible_type_definition_indices_.begin(),
                                           visible_type_definition_indices_.end(), index);
            if (visible != visible_type_definition_indices_.end())
                types_->select_row(static_cast<std::size_t>(visible - visible_type_definition_indices_.begin()));
        }
    } else if (!definitions) {
        selected_type_id_.reset();
    }
    refreshing_types_ = false;
    const auto writable = project && project->mode == database::ProjectMode::read_write && static_cast<bool>(submit_);
    const auto selected_index = selected_type_index();
    edit_->Enable(writable && selected_index.has_value());
    if (selected_index && definitions) {
        const auto &definition = (*definitions)[*selected_index];
        assign_->SetLabel("Assign selected type");
        assign_->SetToolTip("Assign '" + text(definition.name) + "' to the selected address");
    } else {
        assign_->SetLabel("Assign type to selection");
        assign_->SetToolTip("Choose a type for the selected address");
    }
    refresh_layout();
}
std::optional<std::size_t> TypeSymbolsView::selected_type_index() const {
    if (!selected_type_id_ || !project_ || !project_->state) return {};
    const auto &definitions = project_->state->user->types;
    const auto selected = std::find_if(definitions.begin(), definitions.end(), [&](const auto &definition) {
        return definition.id == *selected_type_id_;
    });
    if (selected == definitions.end()) return {};
    const auto index = static_cast<std::size_t>(selected - definitions.begin());
    if (std::find(visible_type_definition_indices_.begin(), visible_type_definition_indices_.end(), index) ==
        visible_type_definition_indices_.end())
        return {};
    return index;
}
void TypeSymbolsView::refresh_symbols() {
    visible_symbol_candidate_indices_.clear();
    auto query = symbol_filter_ ? symbol_filter_->GetValue() : wxString{};
    query.Trim(true).Trim(false);
    query.MakeLower();
    visible_symbol_candidate_indices_.reserve(symbol_candidates_.size());
    for (std::size_t index = 0; index < symbol_candidates_.size(); ++index) {
        const auto &candidate = symbol_candidates_[index];
        if (!query.empty()) {
            auto name = text(candidate.name);
            name.MakeLower();
            auto address = location_text(candidate.address);
            address.MakeLower();
            if (name.Find(query) == wxNOT_FOUND && address.Find(query) == wxNOT_FOUND)
                continue;
        }
        visible_symbol_candidate_indices_.push_back(index);
    }
    symbols_->populate(visible_symbol_candidate_indices_.size(), [this](std::size_t row, int column) {
        if (row >= visible_symbol_candidate_indices_.size()) return wxString{};
        const auto &candidate = symbol_candidates_[visible_symbol_candidate_indices_[row]];
        return column == 0 ? location_text(candidate.address) : text(candidate.name);
    });
    symbols_->fit_columns({0, 1});
    symbols_->activate = [this](std::size_t row) {
        if (document_ && row < visible_symbol_candidate_indices_.size() && navigate)
            navigate(*document_, project_, Location{symbol_candidates_[visible_symbol_candidate_indices_[row]].address});
    };
}
void TypeSymbolsView::refresh_layout() {
    if (!layout_details_) return;
    if (!project_ || !project_->state) {
        layout_details_->SetValue("Open a project and select a type to inspect its layout.");
        return;
    }
    const auto row = selected_type_index();
    if (!row || *row >= project_->state->user->types.size()) {
        layout_details_->SetValue("Select a type to inspect its ABI layout.");
        return;
    }
    types::Abi abi = layout_abi_->GetSelection() == 0 ? types::Abi::x86_32
                     : layout_abi_->GetSelection() == 2 ? types::Abi::aarch64 : types::Abi::x86_64;
    const auto &definition = project_->state->user->types[*row];
    auto computed = calculate_type_layout(*project_, definition.id, abi);
    if (!computed) {
        layout_details_->SetValue("Type: " + text(definition.name) + "\nLayout unavailable: " + text(computed.error().message));
        return;
    }
    const char *abi_name = abi == types::Abi::x86_32 ? "x86-32" : abi == types::Abi::x86_64 ? "x86-64" : "AArch64";
    std::ostringstream report;
    report << "Type: " << definition.name << "\nABI: " << abi_name << "\nSize: " << computed.value().size
           << " bytes\nAlignment: " << computed.value().alignment << " bytes\n";
    if (definition.type->size())
        report << "Stored size: " << *definition.type->size() << " bytes"
               << (computed.value().size == *definition.type->size() ? " (matches)\n" : " (differs)\n");
    for (std::size_t i = 0; i < computed.value().members.size(); ++i) {
        const auto &member = computed.value().members[i];
        report << member.name << " @ " << member.offset << " size=" << member.size
               << " align=" << member.alignment;
        if (member.bit_width && member.bit_offset)
            report << " bits=" << *member.bit_width << " bit-offset=" << *member.bit_offset;
        if (definition.type->kind() == types::Kind::structure && i < definition.type->members().size() &&
            definition.type->members()[i].offset != member.offset)
            report << " (stored offset " << definition.type->members()[i].offset << ')';
        report << '\n';
    }
    for (const auto &padding : computed.value().padding)
        report << "padding @ " << padding.offset << " size=" << padding.size << '\n';
    if (!definition.type->methods().empty()) {
        report << "\nMethod declarations (not part of object layout):\n";
        for (const auto &method : definition.type->methods()) {
            report << method.name << " : " << types::format(*method.signature);
            switch (method.access) {
            case types::MemberAccess::private_: report << " [private]"; break;
            case types::MemberAccess::protected_: report << " [protected]"; break;
            case types::MemberAccess::public_: report << " [public]"; break;
            default: report << " [access unknown]"; break;
            }
            if (method.is_static) report << " [static]";
            switch (method.dispatch) {
            case types::MemberDispatch::non_virtual: report << " [non-virtual]"; break;
            case types::MemberDispatch::virtual_method: report << " [virtual]"; break;
            case types::MemberDispatch::introducing_virtual: report << " [introducing virtual]"; break;
            case types::MemberDispatch::pure_virtual: report << " [pure virtual]"; break;
            case types::MemberDispatch::pure_introducing_virtual: report << " [pure introducing virtual]"; break;
            default: report << " [dispatch unknown]"; break;
            }
            if (method.introducing_vtable_offset) report << " slot-offset=" << *method.introducing_vtable_offset;
            if (method.this_type) report << " this=" << types::format(*method.this_type);
            if (method.this_adjustment) report << " this-adjust=" << method.this_adjustment;
            report << '\n';
        }
    }
    layout_details_->SetValue(text(report.str()));
}
void TypeSymbolsView::refresh_variable_details() {
    if(!variable_details_)return;
    if(!project_||!project_->state){variable_details_->SetValue("Open a project and select a DWARF variable.");go_to_variable_function_->Disable();return;}
    const auto selected=variables_->selected_row();
    if(!selected||*selected>=project_->state->user->debug_variables.size()){
        variable_details_->SetValue("Select a variable to inspect its DWARF source and unevaluated location expression.");go_to_variable_function_->Disable();return;
    }
    go_to_variable_function_->Enable(static_cast<bool>(navigate));
    const auto& variable=project_->state->user->debug_variables[*selected];
    std::ostringstream details;details<<variable.name<<" â€” "<<(variable.is_parameter?"parameter":"local")
        <<" in function 0x"<<std::hex<<variable.function_entry.offset<<"\nSource: "<<variable.origin.source_id
        <<" "<<variable.origin.section<<" unit 0x"<<variable.origin.unit_offset<<" DIE 0x"<<variable.origin.record_offset
        <<" ("<<std::dec<<variable.origin.record_size<<" bytes)\nScope DIE: 0x"<<std::hex<<variable.scope_offset<<"\n";
    if(!variable.location_ranges.empty()){
        details<<"Location-list ranges: "<<std::dec<<variable.location_ranges.size()<<"\n";
        if(selected_address_)details<<"Selected PC: 0x"<<std::hex<<selected_address_->offset<<"\n";
        bool matched=false;for(std::size_t i=0;i<variable.location_ranges.size();++i){const auto& range=variable.location_ranges[i];const bool active=selected_address_&&selected_address_->offset>=range.begin&&selected_address_->offset<range.end;matched|=active;
            details<<(active?"Selected ":"Range ")<<i<<": [0x"<<std::hex<<range.begin<<", 0x"<<range.end<<")"<<(active?" (active at selected PC)":"")<<"\n";
            if(active||!selected_address_){details<<"  Raw expression: ";for(std::size_t j=0;j<range.expression.size();++j){if(j)details<<' ';details<<std::setw(2)<<std::setfill('0')<<static_cast<unsigned>(range.expression[j]);}details<<"\n  Decoded operations:\n";for(const auto& op:range.operations)details<<"    +0x"<<std::hex<<op.expression_offset<<"  "<<location_operation(op)<<"\n";}
        }
        if(selected_address_&&!matched)details<<"No location-list entry covers the selected PC.\n";
    }
    else if(variable.address)details<<"Direct address: 0x"<<std::hex<<*variable.address<<"\n";
    if(variable.cfa_offset){
        const auto offset=*variable.cfa_offset;
        const auto magnitude=offset<0?static_cast<std::uint64_t>(-(offset+1))+1:static_cast<std::uint64_t>(offset);
        details<<"Derived CFA-relative location: CFA"<<(offset<0?'-':'+')<<"0x"<<std::hex<<magnitude
               <<" (not an absolute address; requires a frame context)\n";
    }
    else if(!variable.location_ranges.empty()){}
    else if(variable.location_expression.empty())details<<"Location: unavailable; DWARF may omit a location or provide an empty expression.\n";
    else{
        details<<"Raw expression: ";for(std::size_t i=0;i<variable.location_expression.size();++i){if(i)details<<' ';details<<std::setw(2)<<std::setfill('0')<<std::hex<<static_cast<unsigned>(variable.location_expression[i]);}
        details<<"\nDecoded operations (description only):\n";for(const auto& operation:variable.location_operations)details<<"  +0x"<<std::hex<<operation.expression_offset<<"  "<<location_operation(operation)<<'\n';
    }
    details<<"\nRuntime evaluation requires a live frame, registers, and memory context; this view does not evaluate expressions.";
    variable_details_->SetValue(text(details.str()));
}
void TypeSymbolsView::define_compound() {
    if (!project_ || !project_->state || !submit_) return;
    if (auto edited = show_type_editor(this, *project_))
        submit_(DefineType{std::move(edited->name), std::move(edited->type)});
}
void TypeSymbolsView::edit_type() {
    if (!project_ || !project_->state || !submit_) return;
    const auto row = selected_type_index();
    if (!row || *row >= project_->state->user->types.size()) return;
    const auto &definition = project_->state->user->types[*row];
    if (auto edited = show_type_editor(this, *project_, &definition))
        submit_(UpdateType{definition.id, std::move(edited->name), std::move(edited->type)});
}
void TypeSymbolsView::author_compound(std::optional<std::uint64_t> type_id, int initial_kind) {
    if (!project_ || !project_->state || !submit_) return;
    const auto *original = type_id ? type_definition(*project_, *type_id) : nullptr;
    if (type_id && !original) return;
    if (auto edited = show_type_editor(this, *project_, original, initial_kind)) {
        if (type_id) submit_(UpdateType{*type_id, std::move(edited->name), std::move(edited->type)});
        else submit_(DefineType{std::move(edited->name), std::move(edited->type)});
    }
}
void TypeSymbolsView::author_aggregate(std::optional<std::uint64_t> type_id, bool is_union) {
    author_compound(type_id, is_union ? 8 : 7);
}
void TypeSymbolsView::define_type() { author_compound(std::nullopt, 0); }
void TypeSymbolsView::define_structure() { author_compound(std::nullopt, 7); }
void TypeSymbolsView::assign_type() {
    if (!project_ || !project_->state || !submit_) return;
    const auto selected_row = selected_type_index();
    const auto selected_id = selected_row && *selected_row < project_->state->user->types.size()
        ? std::optional<std::uint64_t>(project_->state->user->types[*selected_row].id) : std::nullopt;
    const auto intent = resolve_type_assignment_intent(selected_address_, selected_id);
    if (intent.kind == TypeAssignmentIntent::Kind::unavailable) return;
    if (intent.kind == TypeAssignmentIntent::Kind::assign_selected) {
        const auto *current = type_assignment(*project_, intent.address);
        if (current && current->type_id == intent.type_id) return;
        submit_(AssignType{intent.address, intent.type_id, false});
        return;
    }
    wxArrayString choices;
    for (const auto &definition : project_->state->user->types)
        choices.Add(text(definition.name) + " â€” " + text(types::format(*definition.type)));
    wxSingleChoiceDialog choice(this, "Choose a type for the selected address", "Assign type", choices);
    if (choice.ShowModal() != wxID_OK) return;
    const auto index = static_cast<std::size_t>(choice.GetSelection());
    if (index < project_->state->user->types.size())
        submit_(AssignType{intent.address, project_->state->user->types[index].id, false});
}
void TypeSymbolsView::remove_assignment() {
    if (!project_ || !selected_address_ || !submit_) return;
    auto *assignment = type_assignment(*project_, *selected_address_);
    if (assignment) submit_(AssignType{*selected_address_, assignment->type_id, true});
}
void TypeSymbolsView::import_symbols() {
    if (submit_ && project_ && !importable_symbols(*project_).empty())
        submit_(ImportSymbols{});
}
void TypeSymbolsView::import_dwarf_info() {
    if (submit_ && project_ && project_->mode == database::ProjectMode::read_write &&
        project_->loaded && project_->loaded->metadata.elf &&
        project_->loaded->metadata.elf->dwarf_info)
        submit_(ImportDwarfInfo{});
}
void TypeSymbolsView::import_header() {
    if (!project_ || !submit_ || project_->mode != database::ProjectMode::read_write) return;
    wxFileDialog picker(this, "Import C header", {}, {}, "C/C++ headers (*.h;*.hpp;*.hh)|*.h;*.hpp;*.hh|All files (*.*)|*.*",
                        wxFD_OPEN | wxFD_FILE_MUST_EXIST);
    if (picker.ShowModal() != wxID_OK) return;
    const std::filesystem::path path(picker.GetPath().ToStdWstring());
    std::error_code file_error;
    const auto file_size = std::filesystem::file_size(path, file_error);
    if (file_error || file_size > types::HeaderImportOptions{}.max_input_bytes) {
        wxMessageBox(file_error ? "The selected header size could not be read."
                                : "The selected header exceeds the 4 MiB import limit.",
                     "Header import", wxOK | wxICON_ERROR, this);
        return;
    }
    wxFileInputStream input(picker.GetPath());
    if (!input.IsOk()) {
        wxMessageBox("The selected header could not be opened.", "Header import", wxOK | wxICON_ERROR, this);
        return;
    }
    std::string source(static_cast<std::size_t>(file_size), '\0');
    if (!source.empty()) {
        input.Read(source.data(), source.size());
        if (input.LastRead() != source.size()) {
            wxMessageBox("The selected header could not be read completely.", "Header import", wxOK | wxICON_ERROR, this);
            return;
        }
    }
    char extra = 0;
    input.Read(&extra, 1);
    if (input.LastRead() != 0) {
        wxMessageBox("The selected header could not be read completely.", "Header import", wxOK | wxICON_ERROR, this);
        return;
    }
    wxArrayString targets;
    targets.Add("Windows x64 (LLP64)");
    targets.Add("Linux / macOS 64-bit (LP64)");
    targets.Add("32-bit x86 (ILP32)");
    targets.Add("AArch64 (LP64)");
    wxSingleChoiceDialog target(this, "Choose the target data model for layout calculations.", "Header target ABI", targets);
    target.SetSelection(0);
    if (target.ShowModal() != wxID_OK) return;
    types::HeaderImportOptions options;
    options.target_abi = target.GetSelection() == 2 ? types::Abi::x86_32
                         : target.GetSelection() == 3 ? types::Abi::aarch64 : types::Abi::x86_64;
    if (target.GetSelection() == 0) options.long_bytes = 4;
    else if (target.GetSelection() == 2) { options.pointer_bytes = 4; options.long_bytes = 4; }
    auto parsed = types::import_c_header(source, options);
    if (!parsed) {
        if (diagnostics_changed) diagnostics_changed({{"Header import", DiagnosticSeverity::error, parsed.error().message, {}, {}}});
        wxMessageBox(text(parsed.error().message), "Header import failed", wxOK | wxICON_ERROR, this);
        return;
    }
    if (diagnostics_changed) {
        std::vector<AnalysisIssueDiagnostic> diagnostics;
        const auto source_name = path.filename().string();
        for (const auto &message : parsed.value().diagnostics)
            diagnostics.push_back({"Header import (" + source_name + ")", DiagnosticSeverity::warning, message, {}, {}});
        diagnostics_changed(std::move(diagnostics));
    }
    std::set<std::string, std::less<>> existing;
    for (const auto &definition : project_->state->user->types) existing.insert(definition.name);
    std::size_t added = 0, skipped = 0;
    for (const auto &[name, symbol] : parsed.value().symbols) {
        if (!symbol.type || !existing.insert(name).second) { ++skipped; continue; }
        submit_(DefineType{name, symbol.type});
        ++added;
    }
    wxString message = wxString::Format("Queued %llu type definitions.", static_cast<unsigned long long>(added));
    if (skipped) message += wxString::Format(" %llu names already existed and were skipped.",
                                             static_cast<unsigned long long>(skipped));
    if (!parsed.value().enum_constants.empty())
        message += " Numeric enum constants are available through the importer API; project type storage retains enum names only.";
    wxMessageBox(message, "Header import", wxOK | (added ? wxICON_INFORMATION : wxICON_WARNING), this);
}
void TypeSymbolsView::refresh_pdb_function_ids() {
    if (!pdb_ids_) return;
    pdb_ids_->clear_selection();
    pdb_ids_->populate(pdb_function_ids_.size(), [this](std::size_t row, int column) {
        if (row >= pdb_function_ids_.size()) return wxString{};
        const auto& item = pdb_function_ids_[row];
        switch (column) {
        case 0: return wxString::Format("0x%08x", static_cast<unsigned>(item.index));
        case 1: return text(item.kind);
        case 2: return text(item.name);
        case 3: return wxString::Format("0x%08x", static_cast<unsigned>(item.function_type));
        case 4: return wxString::Format("0x%08x", static_cast<unsigned>(item.record_offset));
        case 5: return text(item.status);
        default: return wxString{};
        }
    });
    pdb_ids_->fit_columns({0, 1, 2, 3, 4, 5});
    refresh_pdb_function_id_details();
}

void TypeSymbolsView::refresh_pdb_function_id_details() {
    if (!pdb_id_details_) return;
    const auto selected = pdb_ids_ ? pdb_ids_->selected_row() : std::nullopt;
    if (!selected || *selected >= pdb_function_ids_.size()) {
        if (pdb_function_ids_.empty()) {
            if (pdb_id_diagnostic_.empty())
                pdb_id_details_->ChangeValue("Import PDB Types to inspect the selected PDB's IPI records.");
            else
                pdb_id_details_->ChangeValue(text(pdb_id_identity_ + "\n" + pdb_id_diagnostic_));
        } else {
            pdb_id_details_->ChangeValue(text("PDB identity: " + pdb_id_identity_ +
                "\nSelect an IPI record to inspect its exact references, source extent, and decoded metadata."));
        }
        return;
    }
    const auto& item = pdb_function_ids_[*selected];
    std::ostringstream details;
    details << "PDB identity: " << pdb_id_identity_ << "\n"
            << "IPI index: 0x" << std::hex << item.index << "\n"
            << "Kind: " << item.kind << " (leaf 0x" << item.leaf << ")\n"
            << "Source IPI bytes: [0x" << item.record_offset << ", 0x"
            << static_cast<std::uint64_t>(item.record_offset) + item.record_size << ")\n";
    const auto id_name = [&](std::uint32_t id) -> const std::string * {
        const auto found = std::lower_bound(pdb_function_ids_.begin(), pdb_function_ids_.end(), id,
            [](const auto &candidate, std::uint32_t index) { return candidate.index < index; });
        return found != pdb_function_ids_.end() && found->kind == "string ID" ? &found->name : nullptr;
    };
    if (item.kind == "function" || item.kind == "member function") {
        details << "Name: " << item.name << "\nParent IPI scope: ";
        if (item.parent_scope) details << "0x" << item.parent_scope;
        else details << "none (global)";
        details << "\nClass TPI index: ";
        if (item.class_type) details << "0x" << item.class_type;
        else details << "none";
        details << "\nFunction TPI index: 0x" << item.function_type
                << "\nStatus: " << item.status;
        if (!item.signature.empty()) details << "\nSignature: " << item.signature;
        if (item.imported) details << "\nImported as a source-scoped project function type.";
        else if (item.resolved) details << "\nSignature resolved but not imported (project type already exists or import budget was reached).";
    } else if (item.kind == "build info") {
        static constexpr std::array<std::string_view, 5> fields{
            "Current directory", "Build tool", "Source file", "Program database", "Command line"};
        details << "Build metadata:\n";
        for (std::size_t i = 0; i < item.references.size(); ++i) {
            details << "  " << (i < fields.size() ? fields[i] : std::string_view("Unknown field"))
                    << " (IPI 0x" << item.references[i] << "): ";
            const auto value = id_name(item.references[i]);
            details << (value ? *value : "<missing or non-string LF_STRING_ID>") << "\n";
        }
        details << "Status: " << item.status;
    } else if (item.kind == "string ID") {
        details << "String: " << item.name << "\nParent substring-list IPI index: ";
        if (item.parent_string_id) details << "0x" << item.parent_string_id;
        else details << "none";
        details << "\nStatus: " << item.status;
    } else if (item.kind == "substring list") {
        details << "String-fragment count: " << item.reference_count << "\nFragments (bounded preview):\n";
        for (const auto ref : item.references) {
            const auto value = id_name(ref);
            details << "  IPI 0x" << ref << ": "
                    << (value ? *value : "<missing or non-string LF_STRING_ID>") << "\n";
        }
        if (item.reference_count > item.references.size())
            details << "  ... " << (item.reference_count - item.references.size()) << " additional references omitted\n";
        details << "Status: " << item.status;
    } else if (item.kind == "UDT source line" || item.kind == "UDT module source line") {
        details << "UDT TPI index: 0x" << item.related_type << "\nSource file IPI index: 0x"
                << item.source_file_id << "\nSource file: ";
        const auto value = id_name(item.source_file_id);
        details << (value ? *value : "<missing or non-string LF_STRING_ID>")
                << "\nLine: " << std::dec << item.line_number;
        if (item.kind == "UDT module source line") details << "\nDBI module index: " << item.module_index;
        details << "\nStatus: " << item.status;
    } else {
        details << "Name: " << item.name << "\nStatus: " << item.status;
    }
    pdb_id_details_->ChangeValue(text(details.str()));
}

void TypeSymbolsView::refresh_pdb_aggregate_declarations() {
    if (!pdb_declarations_) return;
    const auto count = pdb_aggregate_declarations_.size();
    wxString status = pdb_id_identity_.empty()
        ? wxString("Import PDB Types to inspect source-scoped class declarations.")
        : text("PDB identity: " + pdb_id_identity_ + ". ");
    status += wxString::Format("%llu declaration(s) shown", static_cast<unsigned long long>(count));
    if (pdb_declarations_omitted_)
        status += wxString::Format("; %llu omitted by the 50,000-row preview cap",
                                   static_cast<unsigned long long>(pdb_declarations_omitted_));
    status += ". These rows are preview-only and are not persisted in project aggregate types or layout.";
    if (pdb_declaration_status_) pdb_declaration_status_->SetLabel(status);
    pdb_declarations_->clear_selection();
    pdb_declarations_->populate(count, [this](std::size_t row, int column) {
        if (row >= pdb_aggregate_declarations_.size()) return wxString{};
        const auto &item = pdb_aggregate_declarations_[row];
        std::string value;
        switch (column) {
        case 0: value = item.owner; break;
        case 1: return wxString::Format("%u:0x%08x", static_cast<unsigned>(item.name_space),
                                        static_cast<unsigned>(item.aggregate_type_index));
        case 2: value = item.kind; break;
        case 3: value = item.name; break;
        case 4: value = item.type; break;
        case 5: value = item.access; break;
        case 6: value = item.dispatch; break;
        case 7: value = item.virtual_slot; break;
        case 8: value = item.this_type; break;
        case 9: return wxString::Format("%u", static_cast<unsigned>(item.declaration_ordinal));
        default: return wxString{};
        }
        auto rendered = text(value);
        if (rendered.length() > 512) rendered = rendered.Left(509) + "...";
        return rendered;
    });
    pdb_declarations_->fit_columns({0, 1, 2, 3, 4, 5, 6, 7, 8, 9});
}

void TypeSymbolsView::refresh_pdb_data_symbols() {
    if (!pdb_data_symbols_) return;
    if (pdb_data_symbol_status_) {
        wxString status = pdb_id_identity_.empty()
            ? wxString("Import PDB Types to inspect typed CodeView data symbols.")
            : text("PDB identity: " + pdb_id_identity_ + ". ");
        status += wxString::Format("%llu data symbol(s) shown",
            static_cast<unsigned long long>(pdb_data_symbol_rows_.size()));
        status += wxString::Format(" (%llu resolved, %llu unresolved)",
            static_cast<unsigned long long>(pdb_data_symbols_resolved_),
            static_cast<unsigned long long>(pdb_data_symbols_unresolved_));
        if (pdb_data_symbols_omitted_)
            status += wxString::Format("; %llu omitted by the 50,000-row preview cap",
                static_cast<unsigned long long>(pdb_data_symbols_omitted_));
        status += ". Unresolved TPI references remain visible with diagnostics.";
        if (!pdb_data_symbol_diagnostic_.empty())
            status += " " + text(pdb_data_symbol_diagnostic_);
        pdb_data_symbol_status_->SetLabel(status);
    }
    pdb_data_symbols_->clear_selection();
    pdb_data_symbols_->populate(pdb_data_symbol_rows_.size(), [this](std::size_t row, int column) {
        if (row >= pdb_data_symbol_rows_.size()) return wxString{};
        const auto &item = pdb_data_symbol_rows_[row];
        const auto bounded = [](const std::string &value, long limit) {
            auto rendered = text(value);
            if (rendered.length() > limit) rendered = rendered.Left(limit - 3) + "...";
            return rendered;
        };
        switch (column) {
        case 0: return bounded(item.name, 256);
        case 1: return bounded(item.type.empty() ? "<unresolved>" : item.type, 256);
        case 2: return wxString::Format("%u", static_cast<unsigned>(item.section));
        case 3: return wxString::Format("0x%08x", static_cast<unsigned>(item.section_offset));
        case 4: return wxString::Format("0x%08x", static_cast<unsigned>(item.type_index));
        case 5: return text(item.source);
        case 6: return bounded(item.module + (item.object.empty() ? "" : " / " + item.object), 256);
        case 7: return bounded(item.status, 256);
        default: return wxString{};
        }
    });
    pdb_data_symbols_->fit_columns({0, 1, 2, 3, 4, 5, 6, 7});
    refresh_pdb_data_symbol_details();
}

void TypeSymbolsView::refresh_pdb_data_symbol_details() {
    if (!pdb_data_symbol_details_ || !pdb_data_symbols_) return;
    const auto selected = pdb_data_symbols_->selected_row();
    if (!selected || *selected >= pdb_data_symbol_rows_.size()) {
        pdb_data_symbol_details_->ChangeValue(
            "Select a data symbol to inspect its exact CodeView type reference and source provenance.");
        return;
    }
    const auto &item = pdb_data_symbol_rows_[*selected];
    std::ostringstream detail;
    detail << "Name: " << item.name << "\nType: "
           << (item.type.empty() ? "unresolved" : item.type)
           << "\nStatus: " << item.status
           << "\nCodeView TPI index: 0x" << std::hex << item.type_index
           << "\nSection: " << std::dec << item.section
           << "\nSection offset: 0x" << std::hex << item.section_offset
           << "\nSource: " << item.source
           << "\nPublic symbol: " << (item.public_symbol ? "yes" : "no")
           << "\nModule index: " << std::dec << item.module_index
           << "\nModule: " << item.module
           << "\nObject: " << item.object
           << "\nRecord kind: 0x" << std::hex << item.record_kind
           << "\nRecord offset: 0x" << item.record_offset;
    if (item.reference_record_kind || item.reference_record_offset)
        detail << "\nGlobal-stream reference kind: 0x" << item.reference_record_kind
               << "\nGlobal-stream reference offset: 0x" << item.reference_record_offset;
    if (item.address)
        detail << "\nMapped address: 0x" << std::hex << item.address->offset;
    else
        detail << "\nMapped address: unavailable (PDB identity or section mapping is not proven)";
    auto value = text(detail.str());
    if (value.length() > 4096) value = value.Left(4093) + "...";
    pdb_data_symbol_details_->ChangeValue(value);
}

void TypeSymbolsView::import_pdb_types() {
    if (!project_ || !submit_ || project_->mode != database::ProjectMode::read_write) return;
    pdb_function_ids_.clear();
    pdb_aggregate_declarations_.clear();
    pdb_data_symbol_rows_.clear();
    pdb_declarations_omitted_ = 0;
    pdb_data_symbols_omitted_ = 0;
    pdb_data_symbols_resolved_ = 0;
    pdb_data_symbols_unresolved_ = 0;
    pdb_id_identity_.clear();
    pdb_id_diagnostic_.clear();
    pdb_data_symbol_diagnostic_.clear();
    refresh_pdb_function_ids();
    refresh_pdb_aggregate_declarations();
    refresh_pdb_data_symbols();
    wxFileDialog picker(this, "Import types from PDB", {}, {}, "Program database files (*.pdb)|*.pdb|All files (*.*)|*.*",
                        wxFD_OPEN | wxFD_FILE_MUST_EXIST);
    if (picker.ShowModal() != wxID_OK) return;
    std::error_code file_error;
    const auto file_size = std::filesystem::file_size(std::filesystem::path(picker.GetPath().ToStdWstring()), file_error);
    constexpr std::uint64_t max_pdb_bytes = 512ull * 1024 * 1024;
    if (file_error || !file_size || file_size > max_pdb_bytes) {
        wxMessageBox(file_error ? "The selected PDB size could not be read."
                                : "The selected PDB is empty or exceeds the 512 MiB import limit.",
                     "PDB type import", wxOK | wxICON_ERROR, this);
        return;
    }
    wxFileInputStream input(picker.GetPath());
    if (!input.IsOk()) {
        wxMessageBox("The selected PDB could not be opened.", "PDB type import", wxOK | wxICON_ERROR, this);
        return;
    }
    std::vector<std::byte> bytes(static_cast<std::size_t>(file_size));
    input.Read(bytes.data(), bytes.size());
    if (input.LastRead() != bytes.size()) {
        wxMessageBox("The selected PDB could not be read completely.", "PDB type import", wxOK | wxICON_ERROR, this);
        return;
    }
    const auto root_pdb_path = std::filesystem::path(picker.GetPath().ToStdWstring());
    auto database = types::parse_pdb(bytes);
    if (!database) {
        if (diagnostics_changed) diagnostics_changed({{"PDB type import", DiagnosticSeverity::error, database.error().message, {}, {}}});
        wxMessageBox(text(database.error().message), "PDB type import failed", wxOK | wxICON_ERROR, this);
        pdb_id_diagnostic_ = "PDB parse failed: " + database.error().message;
        refresh_pdb_function_ids();
        return;
    }
    std::ostringstream identity_text;
    identity_text << std::hex << std::setfill('0');
    for (const auto byte : database.value().info.guid)
        identity_text << std::setw(2) << std::to_integer<unsigned>(byte);
    pdb_id_identity_ = identity_text.str() + " age " + std::to_string(database.value().info.age);
    auto id_stream = types::parse_pdb_ids(database.value());
    if (!id_stream) {
        pdb_id_diagnostic_ = "IPI stream unavailable: " + id_stream.error().message;
    } else {
        pdb_function_ids_.reserve(id_stream.value().records.size());
        for (const auto& source : id_stream.value().records) {
            PdbFunctionIdRow row;
            row.index = source.index;
            row.leaf = source.leaf;
            row.parent_scope = source.parent_scope;
            row.class_type = source.class_type;
            row.function_type = source.function_type;
            row.parent_string_id = source.parent_string_id;
            row.related_type = source.related_type;
            row.source_file_id = source.source_file_id;
            row.line_number = source.line_number;
            row.module_index = source.module_index;
            row.reference_count = static_cast<std::uint32_t>(std::min<std::size_t>(source.references.size(), UINT32_MAX));
            if (source.kind == types::CodeViewIdKind::build_info) row.references = source.references;
            else if (source.kind == types::CodeViewIdKind::substring_list) {
                constexpr std::size_t preview_limit = 8;
                row.references.assign(source.references.begin(),
                    source.references.begin() + static_cast<std::ptrdiff_t>(std::min(preview_limit, source.references.size())));
            }
            row.record_offset = source.record_offset;
            row.record_size = source.record_size;
            row.name = source.name;
            switch (source.kind) {
            case types::CodeViewIdKind::function: row.kind = "function"; break;
            case types::CodeViewIdKind::member_function: row.kind = "member function"; break;
            case types::CodeViewIdKind::build_info: row.kind = "build info"; break;
            case types::CodeViewIdKind::substring_list: row.kind = "substring list"; break;
            case types::CodeViewIdKind::string_id: row.kind = "string ID"; break;
            case types::CodeViewIdKind::udt_source_line: row.kind = "UDT source line"; break;
            case types::CodeViewIdKind::udt_module_source_line: row.kind = "UDT module source line"; break;
            default: row.kind = "unsupported"; break;
            }
            row.status = source.kind == types::CodeViewIdKind::unsupported
                ? "unsupported IPI leaf; inspect raw leaf and record extent"
                : (source.kind == types::CodeViewIdKind::function || source.kind == types::CodeViewIdKind::member_function
                    ? "not joined to TPI yet" : "metadata references not joined yet");
            pdb_function_ids_.push_back(std::move(row));
        }
    }
    refresh_pdb_function_ids();
    auto symbol_table = types::parse_pdb_symbols(database.value());
    std::map<std::pair<std::uint8_t, std::uint32_t>, types::TypePtr> function_types;
    std::map<std::pair<std::uint8_t, std::uint32_t>, types::TypePtr> data_types_by_index;
    std::vector<std::pair<std::uint8_t, std::uint8_t>> root_namespace_map;
    auto stream = types::parse_pdb_types(database.value());
    if (!stream) {
        if (diagnostics_changed) diagnostics_changed({{"PDB type import", DiagnosticSeverity::error, stream.error().message, {}, {}}});
        wxMessageBox(text(stream.error().message), "PDB type import failed", wxOK | wxICON_ERROR, this);
        pdb_id_diagnostic_ = "TPI parse failed; IPI records remain unjoined: " + stream.error().message;
        refresh_pdb_function_ids();
        return;
    }
    auto graph = types::resolve_pdb_type_graph(stream.value());
    if (!graph) {
        if (diagnostics_changed) diagnostics_changed({{"PDB type import", DiagnosticSeverity::error, graph.error().message, {}, {}}});
        wxMessageBox(text(graph.error().message), "PDB type import failed", wxOK | wxICON_ERROR, this);
        pdb_id_diagnostic_ = "TPI graph resolution failed; IPI records remain unjoined: " + graph.error().message;
        refresh_pdb_function_ids();
        return;
    }
    std::map<std::string, types::TypePtr, std::less<>> definitions;
    std::vector<PdbAggregateDeclarationRow> declaration_rows;
    std::size_t declaration_rows_omitted = 0;
    constexpr std::size_t max_declaration_preview_rows = 50'000;
    const auto collect_declarations = [&](const types::PdbTypeImportResult &imported,
                                          const types::PdbTypeGraph &source_graph,
                                          std::optional<std::uint8_t> namespace_override) {
        std::map<std::pair<std::uint8_t, std::uint32_t>, std::string> owners;
        for (const auto &node : source_graph.nodes) {
            const auto kind = node.record.kind;
            if (kind == types::CodeViewTypeKind::structure || kind == types::CodeViewTypeKind::class_type ||
                kind == types::CodeViewTypeKind::union_type)
                owners.emplace(std::pair{node.name_space, node.record.index}, node.record.name);
        }
        for (const auto &declaration : imported.aggregate_declarations) {
            if (declaration_rows.size() >= max_declaration_preview_rows) {
                ++declaration_rows_omitted;
                continue;
            }
            PdbAggregateDeclarationRow row;
            row.name_space = namespace_override.value_or(declaration.name_space);
            row.aggregate_type_index = declaration.aggregate_type_index;
            row.declaration_ordinal = declaration.declaration_ordinal;
            const auto owner = owners.find({declaration.name_space, declaration.aggregate_type_index});
            if (owner != owners.end() && !owner->second.empty())
                row.owner = owner->second;
            else
                row.owner = "<unnamed aggregate>";
            if (namespace_override)
                row.owner = "type-server " + std::to_string(*namespace_override) + " :: " + row.owner;
            row.kind = pdb_declaration_kind(declaration.kind);
            row.name = declaration.name;
            if (declaration.type) row.type = types::format(*declaration.type);
            switch (declaration.attributes & 3u) {
            case 1: row.access = "private"; break;
            case 2: row.access = "protected"; break;
            case 3: row.access = "public"; break;
            default: row.access = "unknown"; break;
            }
            row.dispatch = declaration.kind == types::PdbAggregateDeclarationKind::method
                ? pdb_dispatch_kind(declaration.virtual_dispatch) : "-";
            if (declaration.introducing_vtable_offset)
                row.virtual_slot = "0x" + [] (std::uint32_t value) {
                    std::ostringstream out; out << std::hex << value; return out.str();
                }(*declaration.introducing_vtable_offset);
            else
                row.virtual_slot = "-";
            if (declaration.member_this_type)
                row.this_type = types::format(*declaration.member_this_type);
            else
                row.this_type = "-";
            declaration_rows.push_back(std::move(row));
        }
    };
    std::size_t skipped = 0;
    std::size_t resolved_server_count = 0;
    std::string server_warning;
    bool combined_graph_imported = false;
    bool root_graph_attempted = false;
    bool root_graph_imported = false;
    const auto import_root_graph = [&] {
        if (root_graph_attempted) return root_graph_imported;
        root_graph_attempted = true;
        auto root_import = types::import_pdb_type_graph(graph.value());
        if (!root_import) {
            if (!server_warning.empty()) server_warning += "; ";
            server_warning += "root TPI: " + root_import.error().message;
            return false;
        }
        collect_declarations(root_import.value(), graph.value(), std::nullopt);
        definitions = std::move(root_import.value().definitions);
        function_types = std::move(root_import.value().function_types);
        data_types_by_index = std::move(root_import.value().types_by_index);
        skipped = root_import.value().skipped_unnamed + root_import.value().skipped_unsupported +
            root_import.value().skipped_duplicates + root_import.value().skipped_ambiguous;
        root_graph_imported = true;
        return true;
    };
    std::uint64_t server_bytes_left = 512ull * 1024 * 1024;
    const auto pdb_directory = std::filesystem::weakly_canonical(root_pdb_path.parent_path(), file_error);
    if (!file_error) {
        const types::PdbTypeServerResolver resolver = [&](const types::PdbTypeServerRequest &request)
            -> Result<types::PdbDatabase> {
            try {
                std::string portable_path = request.path;
                std::replace(portable_path.begin(), portable_path.end(), '\\', '/');
                const auto filename = std::filesystem::u8path(portable_path).filename();
                if (filename.empty() || filename == "." || filename == "..")
                    return Error{ErrorCode::invalid_argument, "PDB type-server path has no safe sidecar filename"};
                std::error_code path_error;
                const auto candidate = std::filesystem::weakly_canonical(pdb_directory / filename, path_error);
                if (path_error || candidate.parent_path() != pdb_directory)
                    return Error{ErrorCode::io, "PDB type-server sidecar is not in the selected PDB directory"};
                const auto size = std::filesystem::file_size(candidate, path_error);
                if (path_error || !size)
                    return Error{ErrorCode::io, "PDB type-server sidecar is missing or empty"};
                constexpr std::uint64_t per_server_limit = 128ull * 1024 * 1024;
                if (size > per_server_limit || size > server_bytes_left)
                    return Error{ErrorCode::resource_limit, "PDB type-server sidecar exceeds the bounded import budget"};
                std::ifstream input(candidate, std::ios::binary);
                if (!input) return Error{ErrorCode::io, "Cannot open adjacent PDB type-server sidecar"};
                std::vector<std::byte> server_data(static_cast<std::size_t>(size));
                if (!input.read(reinterpret_cast<char *>(server_data.data()), static_cast<std::streamsize>(server_data.size())))
                    return Error{ErrorCode::io, "Cannot read complete PDB type-server sidecar"};
                server_bytes_left -= size;
                return types::parse_pdb(server_data);
            } catch (const std::filesystem::filesystem_error &) {
                return Error{ErrorCode::io, "PDB type-server sidecar path is invalid"};
            } catch (const std::bad_alloc &) {
                return Error{ErrorCode::resource_limit, "Cannot allocate PDB type-server sidecar"};
            }
        };
        auto servers = types::resolve_pdb_type_server_map(database.value(), resolver, 32);
        if (servers && !servers.value().namespaces.empty()) {
            auto combined_graph = types::resolve_pdb_type_graph(stream.value(), servers.value());
            if (!combined_graph) {
                server_warning = combined_graph.error().message;
            } else {
                auto combined_import = types::import_pdb_type_graph(combined_graph.value());
                if (!combined_import) {
                    server_warning = combined_import.error().message;
                } else {
                    collect_declarations(combined_import.value(), combined_graph.value(), std::nullopt);
                    definitions = std::move(combined_import.value().definitions);
                    function_types = std::move(combined_import.value().function_types);
                    data_types_by_index = std::move(combined_import.value().types_by_index);
                    root_namespace_map = servers.value().root_namespace_map;
                    skipped = combined_import.value().skipped_unnamed + combined_import.value().skipped_unsupported +
                        combined_import.value().skipped_duplicates + combined_import.value().skipped_ambiguous;
                    resolved_server_count = servers.value().namespaces.size();
                    combined_graph_imported = true;
                }
            }
        } else {
            if (!servers) server_warning = servers.error().message;
            import_root_graph();

            // LF_TYPESERVER2 remains a separate legacy resolver path. DBI TSM
            // namespaces use the combined graph above so cross-namespace
            // references are resolved before importing types.
            auto legacy_servers = types::resolve_pdb_type_servers(database.value(), resolver, 32);
            if (!legacy_servers) {
                if (!server_warning.empty()) server_warning += "; ";
                server_warning += legacy_servers.error().message;
            } else {
                for (const auto &server : legacy_servers.value().namespaces) {
                    auto server_graph = types::resolve_pdb_type_graph(server.types);
                    if (!server_graph) {
                        server_warning = server_graph.error().message;
                        continue;
                    }
                    auto server_import = types::import_pdb_type_graph(server_graph.value());
                    if (!server_import) {
                        server_warning = server_import.error().message;
                        continue;
                    }
                    collect_declarations(server_import.value(), server_graph.value(), server.index);
                    for (const auto &[key, type] : server_import.value().types_by_index)
                        data_types_by_index.insert_or_assign({server.index, key.second}, type);
                    ++resolved_server_count;
                    skipped += server_import.value().skipped_unnamed + server_import.value().skipped_unsupported +
                        server_import.value().skipped_duplicates + server_import.value().skipped_ambiguous;
                    for (const auto &[name, type] : server_import.value().definitions)
                        if (!definitions.emplace(name, type).second) ++skipped;
                }
            }
        }
    } else {
        server_warning = "The selected PDB directory could not be resolved; type-server files were skipped.";
        import_root_graph();
    }
    if (!combined_graph_imported && !root_graph_attempted) import_root_graph();

    std::optional<types::PdbFunctionIdImportResult> function_id_import;
    if (id_stream) {
        types::PdbTypeImportResult imported_for_ids;
        imported_for_ids.function_types = function_types;
        auto joined = types::import_pdb_function_ids(id_stream.value(), stream.value(), imported_for_ids);
        if (joined) {
            function_id_import = std::move(joined.value());
            std::map<std::uint32_t, const types::PdbImportedFunctionId *> by_index;
            for (const auto &record : function_id_import->records) by_index.emplace(record.index, &record);
            for (auto &row : pdb_function_ids_) {
                if (row.kind == "unsupported") continue;
                const auto found = by_index.find(row.index);
                if (found == by_index.end()) {
                    row.status = "unresolved: IPI join produced no record";
                    continue;
                }
                row.resolved = found->second->resolved;
                if (row.kind == "function" || row.kind == "member function") {
                    if (row.resolved && found->second->signature) {
                        row.signature = types::format(*found->second->signature);
                        row.status = "resolved; awaiting project import";
                    } else {
                        row.resolved = false;
                        row.status = "unresolved: " + found->second->diagnostic;
                    }
                } else if (row.resolved) {
                    row.status = "metadata references resolved";
                } else {
                    row.status = "unresolved: " + found->second->diagnostic;
                }
            }
        } else {
            pdb_id_diagnostic_ = "IPI/TPI join failed: " + joined.error().message;
            for (auto &row : pdb_function_ids_)
                if (row.kind != "unsupported") row.status = "unresolved: " + joined.error().message;
        }
    }

    std::set<std::string, std::less<>> existing;
    std::map<std::string, std::uint64_t, std::less<>> existing_type_ids;
    for (const auto &definition : project_->state->user->types) {
        existing.insert(definition.name);
        existing_type_ids.emplace(definition.name, definition.type ? definition.type->id() : 0);
    }
    std::map<std::uint32_t, PdbFunctionIdRow *> id_rows_by_index;
    for (auto &row : pdb_function_ids_) id_rows_by_index.emplace(row.index, &row);
    std::size_t imported_id_prototypes = 0, id_prototypes_over_budget = 0, id_prototypes_already_present = 0;
    std::map<std::uint32_t, std::pair<std::string, types::TypePtr>> imported_id_types;
    if (function_id_import) {
        constexpr std::size_t max_ipi_prototype_definitions = 4096;
        for (const auto &record : function_id_import->records) {
            if (!record.resolved || !record.signature) continue;
            const auto row_found = id_rows_by_index.find(record.index);
            auto *row = row_found == id_rows_by_index.end() ? nullptr : row_found->second;
            if (imported_id_prototypes >= max_ipi_prototype_definitions) {
                ++id_prototypes_over_budget;
                if (row) row->status = "resolved; prototype import page limit reached";
                continue;
            }
            std::string safe_name;
            safe_name.reserve(96);
            for (const unsigned char ch : record.name) {
                const bool ascii_letter = (ch >= 'a' && ch <= 'z') || (ch >= 'A' && ch <= 'Z');
                const bool ascii_digit = ch >= '0' && ch <= '9';
                if (ascii_letter || ascii_digit || ch == '_') safe_name.push_back(static_cast<char>(ch));
                else if (safe_name.empty() || safe_name.back() != '_') safe_name.push_back('_');
                if (safe_name.size() == 96) break;
            }
            while (!safe_name.empty() && safe_name.back() == '_') safe_name.pop_back();
            if (safe_name.empty()) safe_name = "unnamed";
            std::ostringstream type_name;
            type_name << "__pdb_" << pdb_id_identity_.substr(0, pdb_id_identity_.find(" age "))
                      << '_' << database.value().info.age << "_ipi_" << std::hex << record.index
                      << '_' << safe_name;
            const auto stable_name = type_name.str();
            if (existing.contains(stable_name)) {
                ++id_prototypes_already_present;
                const auto prior = existing_type_ids.find(stable_name);
                if (prior != existing_type_ids.end() && prior->second == record.signature->id())
                    imported_id_types.emplace(record.index, std::pair{stable_name, record.signature});
                if (row) row->status = "resolved; existing project type preserved";
                continue;
            }
            const auto [stored, inserted] = definitions.emplace(stable_name, record.signature);
            (void)stored;
            if (inserted || definitions.at(stable_name)->id() == record.signature->id())
                imported_id_types.emplace(record.index, std::pair{stable_name, record.signature});
            if (inserted) {
                ++imported_id_prototypes;
                if (row) {
                    row->imported = true;
                    row->status = "resolved; named prototype queued for project import";
                }
            } else if (row) {
                row->status = "resolved; duplicate project type key preserved";
            }
        }
    }
    refresh_pdb_function_ids();
    std::vector<PortableTypeAssignment> portable_assignments;
    std::size_t matched_prototypes = 0;
    const PeMetadata *loaded_pe = project_->loaded && project_->loaded->metadata.pe
        ? &*project_->loaded->metadata.pe : nullptr;
    bool selected_pdb_matches_image = loaded_pe && loaded_pe->pdb_status == PePdbStatus::matched;
    if (selected_pdb_matches_image) {
        std::size_t identity_matches = 0;
        for (const auto &codeview : loaded_pe->codeview)
            if (codeview.guid == database.value().info.guid && codeview.age == database.value().info.age)
                ++identity_matches;
        selected_pdb_matches_image = identity_matches == 1;
    }
    if (symbol_table) {
        types::PdbTypeImportResult imported_data_types;
        for (const auto &[key, type] : data_types_by_index)
            if (key.first == 0) imported_data_types.types_by_index.emplace(key, type);
        std::map<std::uint8_t, std::uint8_t> selector_targets;
        std::set<std::uint8_t> ambiguous_selectors;
        for (const auto &[selector, target_namespace] : root_namespace_map) {
            if (!selector) continue;
            const auto [found, inserted] = selector_targets.emplace(selector, target_namespace);
            if (!inserted && found->second != target_namespace) ambiguous_selectors.insert(selector);
        }
        for (const auto &[selector, target_namespace] : selector_targets) {
            const auto erase_selector = [&] {
                auto found = imported_data_types.types_by_index.lower_bound({selector, 0});
                while (found != imported_data_types.types_by_index.end() && found->first.first == selector)
                    found = imported_data_types.types_by_index.erase(found);
            };
            if (ambiguous_selectors.contains(selector)) {
                erase_selector();
                pdb_data_symbol_diagnostic_ = "Ambiguous CodeView type-server selector " +
                    std::to_string(selector) + " was left unresolved.";
                continue;
            }
            erase_selector();
            for (const auto &[key, type] : data_types_by_index)
                if (key.first == target_namespace)
                    imported_data_types.types_by_index.insert_or_assign({selector, key.second}, type);
        }
        auto imported_data = types::import_pdb_data_symbols(symbol_table.value(), imported_data_types);
        if (!imported_data) {
            pdb_data_symbol_diagnostic_ = "Data-symbol type joining failed: " + imported_data.error().message;
        } else {
            constexpr std::size_t max_data_symbol_preview_rows = 50'000;
            pdb_data_symbols_unresolved_ = imported_data.value().unresolved + imported_data.value().unsupported;
            pdb_data_symbols_resolved_ = imported_data.value().symbols.size() - pdb_data_symbols_unresolved_;
            const auto section_address = [&](std::uint16_t section_number,
                                             std::uint32_t section_offset) -> std::optional<Address> {
                if (!selected_pdb_matches_image || !project_->loaded || !project_->loaded->image ||
                    !section_number || section_number > project_->loaded->metadata.sections.size())
                    return std::nullopt;
                const auto &metadata = project_->loaded->metadata;
                const auto &section = metadata.sections[section_number - 1];
                const auto extent = std::max<std::uint64_t>(section.virtual_size, section.raw_size);
                if (section_offset >= extent) return std::nullopt;
                const auto rva = std::uint64_t(section.rva.value) + section_offset;
                if (rva >= metadata.image_size || metadata.preferred_base > UINT64_MAX - rva)
                    return std::nullopt;
                return Address{{0}, metadata.preferred_base + rva};
            };
            for (const auto &source : imported_data.value().symbols) {
                if (pdb_data_symbol_rows_.size() >= max_data_symbol_preview_rows) {
                    ++pdb_data_symbols_omitted_;
                    continue;
                }
                PdbDataSymbolRow row;
                row.name = source.symbol.name;
                row.type_index = source.symbol.type_index;
                row.section = source.symbol.section;
                row.section_offset = source.symbol.section_offset;
                row.record_kind = source.symbol.record_kind;
                row.record_offset = source.symbol.record_offset;
                row.reference_record_kind = source.symbol.reference_record_kind;
                row.reference_record_offset = source.symbol.reference_record_offset;
                row.module_index = source.symbol.module_index;
                row.public_symbol = source.symbol.public_symbol;
                row.source = source.symbol.source == types::PdbSymbolSource::module ? "module stream" : "global stream";
                row.module = source.symbol.module_name;
                row.object = source.symbol.object_name;
                row.resolved = source.resolved;
                row.status = source.resolved ? "resolved" : "unresolved: " + source.diagnostic;
                if (source.resolved && source.type) {
                    row.type = types::format(*source.type);
                    if (row.type.size() > 512) {
                        std::size_t prefix = 509;
                        while (prefix &&
                               (static_cast<unsigned char>(row.type[prefix]) & 0xc0) == 0x80)
                            --prefix;
                        row.type.resize(prefix);
                        row.type += "...";
                    }
                }
                row.address = section_address(source.symbol.section, source.symbol.section_offset);
                pdb_data_symbol_rows_.push_back(std::move(row));
            }
            if (imported_data.value().unsupported) {
                if (!pdb_data_symbol_diagnostic_.empty()) pdb_data_symbol_diagnostic_ += " ";
                pdb_data_symbol_diagnostic_ += std::to_string(imported_data.value().unsupported) +
                    " unsupported primitive data-symbol type(s) remain unresolved.";
            }
        }
    } else {
        pdb_data_symbol_diagnostic_ = "PDB data-symbol stream unavailable: " + symbol_table.error().message;
    }
    refresh_pdb_data_symbols();
    if (selected_pdb_matches_image && symbol_table) {
        std::ostringstream guid_text;
        guid_text << std::hex << std::setfill('0');
        for (const auto byte : database.value().info.guid)
            guid_text << std::setw(2) << std::to_integer<unsigned>(byte);
        const auto type_name = [&](const types::TypePtr &type) {
            std::ostringstream name;
            name << "__pdb_" << guid_text.str() << '_' << database.value().info.age
                 << "_sig_" << std::hex << type->id();
            return name.str();
        };
        using AddressKey = std::pair<std::uint32_t, std::uint64_t>;
        struct PendingSignature {
            Address address;
            std::uint64_t type_id;
            std::string name;
            types::TypePtr type;
            std::vector<std::uint32_t> ipi_indices;
        };
        std::map<AddressKey, PendingSignature> pending;
        std::set<AddressKey> ambiguous;
        std::set<std::uint32_t> assigned_ipi_indices;
        std::set<std::uint32_t> preserved_ipi_indices;
        const auto resolve_type_namespace = [&](std::uint32_t encoded_index) -> std::optional<std::pair<std::uint8_t, std::uint32_t>> {
            const auto selector = static_cast<std::uint8_t>(encoded_index >> 24);
            const auto index = encoded_index & 0x00ffffffu;
            if (selector == 0) return std::pair<std::uint8_t, std::uint32_t>{0, index};
            const auto mapped = std::find_if(root_namespace_map.begin(), root_namespace_map.end(),
                [&](const auto &entry) { return entry.first == selector; });
            if (mapped == root_namespace_map.end()) return std::nullopt;
            return std::pair<std::uint8_t, std::uint32_t>{mapped->second, index};
        };
        for (const auto &symbol : symbol_table.value().symbols) {
            if (symbol.kind != types::PdbSymbolKind::procedure || !symbol.type_index) continue;
            types::TypePtr signature;
            std::string name;
            if (symbol.type_index_is_id) {
                const auto found = imported_id_types.find(symbol.type_index);
                if (found == imported_id_types.end()) continue;
                name = found->second.first;
                signature = found->second.second;
            } else {
                const auto type_key = resolve_type_namespace(symbol.type_index);
                if (!type_key) continue;
                const auto found_type = function_types.find(*type_key);
                if (found_type == function_types.end() || !found_type->second ||
                    found_type->second->kind() != types::Kind::function) continue;
                signature = found_type->second;
                name = type_name(signature);
            }
            const auto existing_name = existing_type_ids.find(name);
            if (existing_name != existing_type_ids.end() && existing_name->second != signature->id()) continue;
            const auto imported_name = definitions.find(name);
            if (imported_name != definitions.end() && imported_name->second->id() != signature->id()) continue;
            for (const auto &image_symbol : loaded_pe->pdb_symbols) {
                if (!image_symbol.procedure || !image_symbol.address || image_symbol.name != symbol.name ||
                    image_symbol.section != symbol.section || image_symbol.section_offset != symbol.section_offset)
                    continue;
                if (type_assignment(*project_, *image_symbol.address)) {
                    if (symbol.type_index_is_id) preserved_ipi_indices.insert(symbol.type_index);
                    continue;
                }
                const AddressKey key{image_symbol.address->space.value, image_symbol.address->offset};
                if (ambiguous.contains(key)) continue;
                auto [entry, inserted] = pending.emplace(key, PendingSignature{
                    *image_symbol.address, signature->id(), name, signature,
                    symbol.type_index_is_id ? std::vector<std::uint32_t>{symbol.type_index} : std::vector<std::uint32_t>{}});
                if (!inserted && entry->second.type_id != signature->id()) {
                    pending.erase(entry);
                    ambiguous.insert(key);
                } else if (!inserted && symbol.type_index_is_id &&
                           std::find(entry->second.ipi_indices.begin(), entry->second.ipi_indices.end(), symbol.type_index) ==
                               entry->second.ipi_indices.end()) {
                    entry->second.ipi_indices.push_back(symbol.type_index);
                }
            }
        }
        for (auto &[key, signature] : pending) {
            (void)key;
            const auto [definition, inserted] = definitions.emplace(signature.name, signature.type);
            if (!inserted && definition->second->id() != signature.type_id) continue;
            portable_assignments.push_back({signature.address, signature.name});
            assigned_ipi_indices.insert(signature.ipi_indices.begin(), signature.ipi_indices.end());
        }
        for (const auto index : assigned_ipi_indices)
            if (const auto found = id_rows_by_index.find(index); found != id_rows_by_index.end())
                found->second->status = "resolved; prototype assigned to matching function";
        for (const auto index : preserved_ipi_indices)
            if (!assigned_ipi_indices.contains(index))
                if (const auto found = id_rows_by_index.find(index); found != id_rows_by_index.end())
                    found->second->status = "resolved; existing function type assignment preserved";
        matched_prototypes = portable_assignments.size();
    }
    std::vector<PortableTypeDefinition> portable_definitions;
    portable_definitions.reserve(definitions.size());
    for (const auto &[name, type] : definitions) {
        if (!existing.insert(name).second) { ++skipped; continue; }
        portable_definitions.push_back({name, type, {}, {}});
    }
    const auto added = portable_definitions.size();
    if (added || !portable_assignments.empty())
        submit_(ImportPortableTypes{std::move(portable_definitions), std::move(portable_assignments)});
    pdb_aggregate_declarations_ = std::move(declaration_rows);
    pdb_declarations_omitted_ = declaration_rows_omitted;
    refresh_pdb_aggregate_declarations();
    const auto &identity = database.value().info;
    std::ostringstream pdb_identity;
    pdb_identity << std::hex;
    for (const auto byte : identity.guid)
        pdb_identity << std::setw(2) << std::setfill('0') << std::to_integer<unsigned>(byte);
    const auto resolved_id_count = static_cast<std::size_t>(std::count_if(pdb_function_ids_.begin(), pdb_function_ids_.end(),
        [](const auto &row) { return row.resolved; }));
    const auto unsupported_id_count = static_cast<std::size_t>(std::count_if(pdb_function_ids_.begin(), pdb_function_ids_.end(),
        [](const auto &row) { return row.kind == "unsupported"; }));
    const auto unresolved_id_count = pdb_function_ids_.size() - resolved_id_count - unsupported_id_count;
    wxString message = wxString::Format("PDB %s age %u: queued %llu named type definitions (%llu IPI prototypes) and %llu matched function prototypes; resolved %llu adjacent type-server PDBs.",
                                        text(pdb_identity.str()), identity.age,
                                        static_cast<unsigned long long>(added),
                                        static_cast<unsigned long long>(imported_id_prototypes),
                                        static_cast<unsigned long long>(matched_prototypes),
                                        static_cast<unsigned long long>(resolved_server_count));
    message += wxString::Format(" Previewed %llu aggregate declarations.",
        static_cast<unsigned long long>(pdb_aggregate_declarations_.size()));
    message += wxString::Format(" IPI records: %llu resolved, %llu unresolved, %llu unsupported; %llu prototypes already existed.",
        static_cast<unsigned long long>(resolved_id_count),
        static_cast<unsigned long long>(unresolved_id_count),
        static_cast<unsigned long long>(unsupported_id_count),
        static_cast<unsigned long long>(id_prototypes_already_present));
    if (id_prototypes_over_budget)
        message += wxString::Format(" %llu additional resolved prototypes were left out by the 4096-definition import cap.",
            static_cast<unsigned long long>(id_prototypes_over_budget));
    if (!pdb_id_diagnostic_.empty()) message += " " + text(pdb_id_diagnostic_);
    if (!symbol_table) message += " PDB procedure symbols were unavailable: " + text(symbol_table.error().message);
    else if (loaded_pe && !selected_pdb_matches_image)
        message += " Function assignments were skipped because the selected PDB does not uniquely match this PE identity.";
    if (skipped) message += wxString::Format(" %llu unsupported, unnamed, duplicate, ambiguous, or existing names were skipped.",
                                             static_cast<unsigned long long>(skipped));
    if (!server_warning.empty()) message += " Type-server loading was partial: " + text(server_warning);
    if (diagnostics_changed) {
        std::vector<AnalysisIssueDiagnostic> diagnostics;
        const auto source_name = "PDB type import (" + root_pdb_path.filename().string() + ")";
        if (!pdb_id_diagnostic_.empty()) diagnostics.push_back({source_name, DiagnosticSeverity::warning, pdb_id_diagnostic_, {}, {}});
        if (!server_warning.empty()) diagnostics.push_back({source_name, DiagnosticSeverity::warning, "Type-server loading was partial: " + server_warning, {}, {}});
        if (unresolved_id_count || unsupported_id_count)
            diagnostics.push_back({source_name, DiagnosticSeverity::warning,
                "IPI records: " + std::to_string(unresolved_id_count) + " unresolved and " +
                std::to_string(unsupported_id_count) + " unsupported.", {}, {}});
        for (const auto &row : pdb_data_symbol_rows_) {
            if (row.resolved || row.status.empty()) continue;
            diagnostics.push_back({source_name, DiagnosticSeverity::warning,
                "Data symbol " + row.name + ": " + row.status, row.address, {}});
            if (diagnostics.size() >= 2048) break;
        }
        diagnostics_changed(std::move(diagnostics));
    }
    wxMessageBox(message, "PDB type import", wxOK | (added ? wxICON_INFORMATION : wxICON_WARNING), this);
}
}
