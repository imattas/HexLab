#pragma once

#include "data_views.hpp"
#include "analysis_issue_diagnostic.hpp"
#include "hexlab/workspace/project.hpp"
#include "hexlab/workspace/document.hpp"
#include "hexlab/workspace/document_manager.hpp"

#include <wx/choice.h>
#include <wx/button.h>
#include <wx/stattext.h>
#include <wx/textctrl.h>
#include <cstdint>
#include <map>
#include <span>
#include <string>
#include <unordered_set>
#include <memory>
#include <functional>
#include <vector>

namespace hexlab::desktop {

class AnalysisIssuesView final : public wxPanel {
  public:
    explicit AnalysisIssuesView(wxWindow *parent);

    void update(std::shared_ptr<const ProjectSnapshot> project);
    void update(std::optional<DocumentId>, std::shared_ptr<const ProjectSnapshot>, std::optional<Location>,
                std::shared_ptr<const DocumentSnapshot> document_snapshot = {});
    void retain_documents(std::span<const DocumentInfo>);
    void set_type_diagnostics(std::optional<DocumentId>, std::vector<AnalysisIssueDiagnostic>);
    void set_decompiler_diagnostics(std::optional<DocumentId>, std::vector<AnalysisIssueDiagnostic>);
    std::function<void(Location)> navigate;
    std::function<void(std::vector<std::string>)> reviewed_changed;

  private:
    enum class Kind { function_stop, candidate, overlap, incomplete_function, loader_diagnostic,
                      runtime_relocation_diagnostic, file_inspection_diagnostic,
                      file_analysis_diagnostic,
                      type_import_diagnostic, decompiler_diagnostic, minidump_context_diagnostic };
    struct Row {
        Kind kind;
        std::optional<Address> address;
        std::optional<Address> related;
        std::optional<Address> function_entry;
        wxString detail;
        DiagnosticSeverity severity = DiagnosticSeverity::warning;
        std::uint64_t duplicate_ordinal = 0;
        std::string source_identity;
        wxString source_label;
        bool stale_import = false;
        bool operator==(const Row &) const = default;
    };
    struct Preference {
        int filter = 0;
        int severity = 0;
        int review_filter = 0;
        int location_filter = 0;
        wxString query;
        std::optional<Address> function;
        std::optional<Row> selected;
        std::shared_ptr<std::unordered_set<std::string>> reviewed;
    };
    struct ScopeRange { Address begin; std::uint64_t size; };

    static constexpr std::size_t max_rows = 20000;
    static constexpr std::size_t max_loader_rows = 2048;
    static constexpr std::size_t max_functions_scanned = 100000;
    static constexpr std::size_t max_chunks_scanned = 100000;

    wxChoice *filter_ = nullptr;
    wxChoice *severity_ = nullptr;
    wxChoice *review_filter_ = nullptr;
    wxChoice *location_filter_ = nullptr;
    wxTextCtrl *search_ = nullptr;
    wxStaticText *status_ = nullptr;
    wxStaticText *selection_detail_ = nullptr;
    wxButton *go_related_ = nullptr;
    wxButton *go_function_ = nullptr;
    wxButton *copy_issue_ = nullptr;
    wxButton *copy_issue_json_ = nullptr;
    wxButton *copy_visible_ = nullptr;
    wxButton *copy_visible_json_ = nullptr;
    wxButton *mark_reviewed_ = nullptr;
    wxButton *review_visible_ = nullptr;
    wxButton *reopen_visible_ = nullptr;
    wxButton *export_ = nullptr;
    wxButton *previous_ = nullptr;
    wxButton *next_ = nullptr;
    wxButton *scope_cursor_ = nullptr;
    wxButton *scope_all_ = nullptr;
    wxStaticText *scope_context_ = nullptr;
    wxTextCtrl *detail_ = nullptr;
    VirtualTable *table_ = nullptr;
    std::shared_ptr<const ProjectSnapshot> project_;
    std::shared_ptr<const DocumentSnapshot> document_snapshot_;
    const FunctionSnapshot *source_ = nullptr;
    const LoadedImage *loader_source_ = nullptr;
    std::map<std::uint64_t, std::vector<AnalysisIssueDiagnostic>> type_diagnostics_, decompiler_diagnostics_;
    std::vector<Row> rows_;
    std::vector<std::string> row_review_keys_;
    std::vector<std::size_t> visible_rows_;
    bool capped_ = false;
    std::optional<DocumentId> document_;
    std::optional<Location> cursor_;
    std::map<std::uint64_t, Preference> preferences_;
    std::optional<Row> selection_key_;
    std::shared_ptr<std::unordered_set<std::string>> reviewed_;
    std::optional<Address> scope_entry_;
    std::vector<ScopeRange> scope_ranges_;
    bool scope_available_ = false;
    bool scope_partial_ = false;
    wxString scope_error_;

    void rebuild();
    void render();
    void update_selection();
    const Image *active_image() const noexcept;
    void remember_preference();
    void rebuild_scope();
    void update_scope_context();
    void scope_to_cursor();
    bool scope_contains(Address) const;
    bool matches_scope(const Row &) const;
    void step(bool forward);
    void toggle_reviewed();
    void set_visible_reviewed(bool reviewed);
    void activate_row(std::size_t);
    static std::string review_key(const Row &);
    bool is_reviewed(const Row &) const;
    wxString finding_text(const Row &) const;
    const Row *selected_issue() const;
    wxString kind_text(Kind) const;
    wxString cell(std::size_t row, int column) const;
    wxString export_text() const;
    std::optional<std::string> export_json_text(std::size_t row_limit = max_rows,
                                                std::size_t byte_limit = 16 * 1024 * 1024) const;
    void export_visible();
    void copy_visible();
    void copy_visible_json();
    void copy_issue_json();
};

} // namespace hexlab::desktop
