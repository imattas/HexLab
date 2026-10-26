#pragma once

#include "hexlab/analysis/functions.hpp"
#include "hexlab/analysis/stack.hpp"
#include "hexlab/workspace/project.hpp"
#include "analysis_issue_diagnostic.hpp"
#include "hexlab/workspace/commands.hpp"
#include "hexlab/workspace/document_manager.hpp"
#include <wx/listctrl.h>
#include <wx/panel.h>
#include <wx/stattext.h>
#include <wx/textctrl.h>
#include <wx/textctrl.h>
#include <functional>
#include <cstdint>
#include <wx/button.h>

namespace hexlab::desktop {

struct PseudocodeVariableEdit {
    std::string token;
    Address definition;
    std::string display;
    bool editable = true;
    bool function_entry_collision = false;
    std::vector<Address> access_sites;
};
struct PseudocodeNavigationToken {
    DocumentId document;
    std::uint64_t document_revision = 0;
    std::optional<database::ProjectUuid> project_uuid;
    database::ProjectRevisions project_revisions{};
};

class PseudocodeView final : public wxPanel {
  public:
    explicit PseudocodeView(wxWindow *);
    void update(const FunctionSnapshot *, std::optional<Location>, const Image *, const ProjectSnapshot * = nullptr,
                std::function<void(ProjectCommand)> submit = {});
    void update_document(std::optional<DocumentId>, std::shared_ptr<const ProjectSnapshot>, std::uint64_t document_revision,
                         std::optional<Location>,
                         std::function<void(ProjectCommand)> submit = {});
    void retain_documents(std::span<const DocumentInfo>);
    std::function<void(Location)> navigate;
    std::function<void(std::vector<AnalysisIssueDiagnostic>)> diagnostics_changed;
    std::function<void(const PseudocodeNavigationToken &, Location)> navigate_document;
    std::function<std::optional<wxString>(const wxString &, const wxString &, bool)> prompt;

  private:
    wxListCtrl *addresses_;
    wxListCtrl *stack_slots_;
    wxListCtrl *variables_list_;
    wxTextCtrl *source_;
    wxStaticText *status_;
    wxButton *rename_function_ = nullptr, *rename_local_ = nullptr, *comment_local_ = nullptr, *edit_comment_ = nullptr;
    wxButton *rename_variable_ = nullptr, *assign_type_ = nullptr;
    wxButton *definition_ = nullptr, *previous_use_ = nullptr, *next_use_ = nullptr;
    wxButton *copy_pseudocode_ = nullptr, *save_pseudocode_ = nullptr;
    wxStaticText *variable_status_ = nullptr;
    std::vector<Address> rows_;
    struct SourceOriginLine {
        Address address;
        long begin = 0, end = 0;
    };
    std::vector<SourceOriginLine> source_origins_;
    std::optional<Address> current_instruction_;
    std::vector<Address> stack_access_rows_;
    std::vector<std::vector<Address>> stack_access_sites_;
    std::vector<std::uint8_t> stack_access_editable_;
    std::vector<Address> variable_definition_rows_;
    const FunctionRecord *function_ = nullptr;
    const ProjectSnapshot *project_ = nullptr;
    std::function<void(ProjectCommand)> submit_;
    std::vector<PseudocodeVariableEdit> variables_;
    struct VariableLink {
        std::string token, display;
        Address address;
        std::optional<std::size_t> editable;
        bool shared_origin = false;
        bool function_entry_collision = false;
    };
    std::vector<VariableLink> variable_links_;
    std::optional<std::size_t> selected_variable_;
    struct SourceState {
        Address function;
        long begin = 0, end = 0;
        std::optional<std::string> variable;
    };
    std::map<std::uint64_t, std::vector<SourceState>> source_states_;
    std::optional<DocumentId> document_;
    std::uint64_t document_revision_ = 0, rendered_document_revision_ = 0;
    std::shared_ptr<const ProjectSnapshot> owner_;
    const FunctionSnapshot *rendered_snapshot_ = nullptr;
    const ProjectSnapshot *rendered_project_ = nullptr;
    const Image *rendered_image_ = nullptr;
    std::optional<Address> rendered_function_;
    bool model_ready_ = false;
    std::uint64_t render_serial_ = 0;
    bool updating_ = false;
    void navigate_to(Location);
    void remember_source();
    void restore_source();
    void rebuild_source_origins();
    const SourceOriginLine *source_origin_at(long begin, long end) const;
    void select_address(Address);
    void source_selection_changed();
    void select_variable(std::size_t, bool follow);
    void update_variable_actions();
    void go_to_definition();
    void move_occurrence(bool next);
    void copy_pseudocode();
    void save_pseudocode();
    std::vector<std::pair<long, long>> variable_occurrences(std::size_t) const;
    const PseudocodeVariableEdit *editable_variable() const;
    void rename_function();
    void rename_local();
    void comment_local();
    void edit_comment();
    void rename_variable();
    void assign_variable_type();
};

} // namespace hexlab::desktop
