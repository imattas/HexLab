#pragma once
#include "hexlab/workspace/project.hpp"
#include "analysis_issue_diagnostic.hpp"
#include "data_views.hpp"
#include <wx/notebook.h>
#include <wx/panel.h>
#include <wx/button.h>
#include <wx/choice.h>
#include <wx/textctrl.h>
#include <wx/stattext.h>
#include <cstdint>
#include <memory>
#include <string>
#include <vector>

namespace hexlab::desktop {
struct PdbFunctionIdRow {
    std::uint32_t index = 0, leaf = 0, parent_scope = 0, class_type = 0, function_type = 0;
    std::uint32_t record_offset = 0, record_size = 0;
    std::string kind, name, signature, status;
    bool resolved = false, imported = false;
};

struct PdbAggregateDeclarationRow {
    std::string owner, kind, name, type, access, dispatch, virtual_slot, this_type;
    std::uint8_t name_space = 0;
    std::uint32_t aggregate_type_index = 0, declaration_ordinal = 0;
};

struct PdbDataSymbolRow {
    std::string name, type, source, module, object, status;
    std::uint32_t type_index = 0, section_offset = 0, record_offset = 0;
    std::uint32_t reference_record_offset = 0;
    std::uint16_t section = 0, record_kind = 0, module_index = 0, reference_record_kind = 0;
    std::optional<Address> address;
    bool resolved = false, public_symbol = false;
};

class TypeSymbolsView final : public wxPanel {
  public:
    explicit TypeSymbolsView(wxWindow *parent);
    void update(std::shared_ptr<const ProjectSnapshot> project, std::optional<Location> selection,
                std::function<void(ProjectCommand)> submit);
    std::function<void(Location)> navigate;
    std::function<void(std::vector<AnalysisIssueDiagnostic>)> diagnostics_changed;

  private:
    wxNotebook *pages_ = nullptr;
    VirtualTable *types_ = nullptr, *assignments_ = nullptr, *symbols_ = nullptr, *variables_ = nullptr,
                 *pdb_ids_ = nullptr, *pdb_declarations_ = nullptr, *pdb_data_symbols_ = nullptr;
    wxTextCtrl *type_filter_ = nullptr, *symbol_filter_ = nullptr, *assignment_filter_ = nullptr;
    std::vector<std::size_t> visible_type_definition_indices_;
    std::vector<std::size_t> visible_assignment_indices_;
    std::vector<SymbolCandidate> symbol_candidates_;
    std::vector<std::size_t> visible_symbol_candidate_indices_;
    std::vector<PdbFunctionIdRow> pdb_function_ids_;
    std::vector<PdbAggregateDeclarationRow> pdb_aggregate_declarations_;
    std::vector<PdbDataSymbolRow> pdb_data_symbol_rows_;
    std::size_t pdb_declarations_omitted_ = 0, pdb_data_symbols_omitted_ = 0,
                pdb_data_symbols_resolved_ = 0, pdb_data_symbols_unresolved_ = 0;
    std::string pdb_id_identity_, pdb_id_diagnostic_, pdb_data_symbol_diagnostic_;
    wxChoice *layout_abi_ = nullptr;
    wxTextCtrl *layout_details_ = nullptr, *variable_details_ = nullptr, *pdb_id_details_ = nullptr,
               *pdb_data_symbol_details_ = nullptr;
    wxStaticText *pdb_declaration_status_ = nullptr, *pdb_data_symbol_status_ = nullptr;
    wxButton *define_ = nullptr, *define_struct_ = nullptr, *define_compound_ = nullptr, *edit_ = nullptr,
             *assign_ = nullptr, *remove_ = nullptr,
             *import_ = nullptr, *import_header_ = nullptr, *import_pdb_types_ = nullptr,
             *import_dwarf_ = nullptr, *portable_library_ = nullptr, *go_to_variable_function_ = nullptr;
    std::shared_ptr<const ProjectSnapshot> project_;
    std::optional<Address> selected_address_;
    std::optional<std::uint64_t> selected_type_id_;
    bool refreshing_types_ = false;
    std::function<void(ProjectCommand)> submit_;
    bool layout_abi_initialized_ = false;
    void define_type();
    void define_structure();
    void define_compound();
    void edit_type();
    void author_compound(std::optional<std::uint64_t> type_id, int kind = -1);
    void author_aggregate(std::optional<std::uint64_t> type_id, bool is_union);
    void assign_type();
    void remove_assignment();
    void import_symbols();
    void import_header();
    void import_pdb_types();
    void import_dwarf_info();
    void portable_type_library();
    void refresh();
    void refresh_types();
    std::optional<std::size_t> selected_type_index() const;
    void refresh_symbols();
    void refresh_layout();
    void refresh_variable_details();
    void refresh_pdb_function_ids();
    void refresh_pdb_function_id_details();
    void refresh_pdb_aggregate_declarations();
    void refresh_pdb_data_symbols();
    void refresh_pdb_data_symbol_details();
};
}
