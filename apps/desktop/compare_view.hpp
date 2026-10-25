#pragma once
#include "hexlab/compare/session.hpp"
#include <wx/frame.h>
#include <wx/listctrl.h>
#include <wx/checkbox.h>
#include <wx/stattext.h>
#include <wx/textctrl.h>
#include <wx/choice.h>
#include <wx/spinctrl.h>
#include <functional>
#include <optional>
#include <span>
#include <string>
#include <vector>

namespace hexlab { struct Instruction; }
namespace hexlab::desktop {
std::optional<std::uint64_t> compare_instruction_fingerprint(const hexlab::Instruction &);
wxString compare_kind_text(compare::ChangeKind);
wxString compare_run_text(const compare::ChangeRun &);
wxString compare_function_kind_text(compare::FunctionMatchKind);
wxString compare_function_text(const compare::FunctionMatch &);
struct CompareRunFilter {
    bool show_changed = true, show_added = true, show_removed = true;
    std::string text;
};
struct CompareFunctionFilter {
    std::optional<compare::FunctionMatchKind> kind;
    unsigned minimum_confidence = 0;
    std::string text;
};
std::vector<std::size_t> filter_compare_runs(std::span<const compare::ChangeRun>, const CompareRunFilter &);
std::vector<std::size_t> filter_compare_functions(std::span<const compare::FunctionMatch>,
                                                  const CompareFunctionFilter &);
std::optional<std::size_t> next_navigable_compare_run(std::span<const compare::ChangeRun>,
    std::span<const std::size_t> visible, std::optional<std::size_t> current_position, int direction);
compare::Result<bool> save_compare_session(const std::filesystem::path &, const compare::Session &);
compare::Result<compare::Session> load_compare_session(const std::filesystem::path &);

class CompareView final : public wxFrame {
  public:
    CompareView(wxWindow *parent, compare::Report report, wxString old_name, wxString new_name,
                std::vector<compare::FunctionMatch> functions,
                std::function<void(const compare::ChangeRun &)> navigate_old,
                std::function<void(const compare::FunctionMatch &)> navigate_old_function,
                std::vector<compare::FunctionBodyDiff> function_body_diffs = {},
                std::function<void(const compare::ChangeRun &)> navigate_new = {},
                std::function<void(const compare::FunctionMatch &)> navigate_new_function = {});
  private:
    compare::Report report_;
    std::vector<compare::FunctionMatch> function_matches_;
    std::vector<compare::FunctionBodyDiff> function_body_diffs_;
    wxString old_name_, new_name_;
    std::function<void(const compare::ChangeRun &)> navigate_old_;
    std::function<void(const compare::FunctionMatch &)> navigate_old_function_;
    std::function<void(const compare::ChangeRun &)> navigate_new_;
    std::function<void(const compare::FunctionMatch &)> navigate_new_function_;
    wxListCtrl *runs_ = nullptr;
    wxListCtrl *functions_ = nullptr;
    wxListCtrl *function_diff_runs_ = nullptr;
    wxStaticText *function_diff_summary_ = nullptr;
    wxStaticText *function_count_ = nullptr;
    wxTextCtrl *run_search_ = nullptr;
    wxTextCtrl *function_search_ = nullptr;
    wxChoice *function_kind_filter_ = nullptr;
    wxSpinCtrl *function_confidence_filter_ = nullptr;
    wxStaticText *run_count_ = nullptr;
    wxCheckBox *show_changed_ = nullptr, *show_added_ = nullptr, *show_removed_ = nullptr;
    std::vector<std::size_t> visible_runs_;
    std::vector<std::size_t> visible_functions_;
    void refresh_runs();
    void refresh_functions();
    void show_function_diff(std::size_t index);
    void navigate_visible_run(int direction);
    void activate_run(std::size_t index);
    void activate_run_new(std::size_t index);
    void save_session_as();
    void export_csv();
    void open_session();
};
}
