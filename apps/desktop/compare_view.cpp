#include "compare_view.hpp"
#include "hexlab/processors/instruction.hpp"
#include <wx/sizer.h>
#include <wx/stattext.h>
#include <wx/notebook.h>
#include <wx/panel.h>
#include <wx/button.h>
#include <wx/textctrl.h>
#include <wx/filedlg.h>
#include <wx/menu.h>
#include <wx/msgdlg.h>
#include <algorithm>
#include <cctype>
#include <type_traits>
#include <fstream>

namespace hexlab::desktop {
namespace {
struct Fingerprint {
    std::uint64_t value = UINT64_C(14695981039346656037);
    void add(std::uint64_t part) {
        for (unsigned i = 0; i < 8; ++i) {
            value ^= static_cast<std::uint8_t>(part >> (i * 8));
            value *= UINT64_C(1099511628211);
        }
    }
    void reg(const RegisterOperand &operand) {
        add(static_cast<std::uint64_t>(operand.bank));
        add(operand.width);
        add(operand.high_byte);
    }
    void memory(const MemoryOperand &operand) {
        add(operand.data_width); add(operand.address_width); add(operand.scale);
        add(operand.segment.has_value());
        if (operand.segment) reg(*operand.segment);
        add(operand.base.has_value());
        if (operand.base) reg(*operand.base);
        add(operand.index.has_value());
        if (operand.index) reg(*operand.index);
        add(operand.ip_relative);
        add(operand.resolved_address.has_value());
        if (!operand.ip_relative && !operand.resolved_address)
            add(static_cast<std::uint64_t>(operand.displacement));
    }
};
wxString from_utf8(std::string_view value) { return wxString::FromUTF8(value.data(), value.size()); }
wxString number(std::uint64_t value) { return wxString::Format("%llu", static_cast<unsigned long long>(value)); }
wxString address(const std::optional<std::uint64_t> &value) {
    return value ? wxString::Format("0x%llX", static_cast<unsigned long long>(*value)) : wxString("-");
}
wxString function_address(const std::optional<std::uint64_t> &value, std::uint32_t space) {
    if (!value) return "-";
    return space ? wxString::Format("%u:0x%llX", space, static_cast<unsigned long long>(*value))
                 : address(value);
}
wxString confidence(std::uint32_t value) { return wxString::Format("%u%%", value); }
wxString function_diff_kind_text(compare::InstructionDiffKind kind) {
    switch (kind) {
    case compare::InstructionDiffKind::equal: return "Equal";
    case compare::InstructionDiffKind::changed: return "Changed";
    case compare::InstructionDiffKind::removed: return "Removed";
    case compare::InstructionDiffKind::added: return "Added";
    }
    return "Unknown";
}
wxString instruction_range(std::uint64_t start, std::uint64_t count) {
    if (!count) return "-";
    return number(start) + ".." + number(start + count);
}
std::string lower_ascii(std::string value) {
    std::transform(value.begin(), value.end(), value.begin(), [](unsigned char c) {
        return static_cast<char>(std::tolower(c));
    });
    return value;
}
std::string utf8(const wxString &value) {
    const auto encoded = value.ToUTF8();
    return encoded ? std::string(encoded.data(), encoded.length()) : std::string{};
}
std::string csv_field(std::string_view value) {
    std::string result = "\"";
    for (const char c : value) {
        if (c == '"') result += "\"\"";
        else result += c;
    }
    result += '"';
    return result;
}
std::string csv_row(std::initializer_list<std::string> fields) {
    std::string result;
    bool first = true;
    for (const auto &field : fields) {
        if (!first) result += ',';
        first = false;
        result += csv_field(field);
    }
    result += "\r\n";
    return result;
}
std::string csv_address(const std::optional<std::uint64_t> &value) {
    return value ? wxString::Format("0x%llX", static_cast<unsigned long long>(*value)).ToStdString() : std::string{};
}
}
std::optional<std::uint64_t> compare_instruction_fingerprint(const Instruction &instruction) {
    if (instruction.opcode == Opcode::opaque || instruction.opcode == Opcode::x86_opaque)
        return {};
    Fingerprint hash;
    hash.add(1); // Fingerprint schema version.
    hash.add(static_cast<std::uint64_t>(instruction.opcode));
    hash.add(static_cast<std::uint64_t>(instruction.flow));
    hash.add(static_cast<std::uint64_t>(instruction.context.mode));
    hash.add(instruction.condition);
    hash.add(instruction.x86_condition ? static_cast<std::uint64_t>(*instruction.x86_condition) + 1 : 0);
    hash.add(instruction.operands.size());
    for (const auto &operand : instruction.operands) {
        hash.add(operand.index());
        std::visit([&](const auto &value) {
            using T = std::decay_t<decltype(value)>;
            if constexpr (std::is_same_v<T, RegisterOperand>) hash.reg(value);
            else if constexpr (std::is_same_v<T, MemoryOperand>) hash.memory(value);
            else if constexpr (std::is_same_v<T, ImmediateOperand>) {
                hash.add(value.value); hash.add(value.effective_width); hash.add(value.is_signed);
            } else if constexpr (std::is_same_v<T, RelativeOperand>) {
                hash.add(value.effective_width);
            } else if constexpr (std::is_same_v<T, FarPointerOperand>) {
                hash.add(value.selector); hash.add(value.offset_width);
            } else if constexpr (std::is_same_v<T, FarMemoryOperand>) {
                hash.memory(value.address); hash.add(value.offset_width);
            } else if constexpr (std::is_same_v<T, ArmShiftedRegisterOperand>) {
                hash.reg(value.source); hash.add(static_cast<std::uint64_t>(value.shift)); hash.add(value.amount);
                hash.add(value.amount_register.has_value());
                if (value.amount_register) hash.reg(*value.amount_register);
            } else if constexpr (std::is_same_v<T, ArmMemoryOperand>) {
                hash.reg(value.base); hash.add(value.offset.index()); hash.add(value.add);
                hash.add(value.pre_index); hash.add(value.writeback); hash.add(value.data_width); hash.add(value.sign_extend);
                if (const auto *immediate = std::get_if<std::uint32_t>(&value.offset)) hash.add(*immediate);
                else {
                    const auto &shifted = std::get<ArmShiftedRegisterOperand>(value.offset);
                    hash.reg(shifted.source); hash.add(static_cast<std::uint64_t>(shifted.shift));
                    hash.add(shifted.amount); hash.add(shifted.amount_register.has_value());
                    if (shifted.amount_register) hash.reg(*shifted.amount_register);
                }
            } else if constexpr (std::is_same_v<T, ArmRegisterListOperand>) hash.add(value.mask);
            else if constexpr (std::is_same_v<T, ThumbRelativeOperand>) { /* encoded width is layout-only */ }
        }, operand);
    }
    hash.add(instruction.access.size());
    for (const auto access : instruction.access) hash.add(static_cast<std::uint64_t>(access));
    hash.add(instruction.memory_read); hash.add(instruction.memory_write); hash.add(instruction.lock_prefix);
    hash.add(instruction.delay_slots);
    if (instruction.arm) {
        hash.add(static_cast<std::uint64_t>(instruction.arm->predicate));
        hash.add(static_cast<std::uint64_t>(instruction.arm->exchange));
        hash.add(instruction.arm->flags_written); hash.add(instruction.arm->flags_known);
        hash.add(instruction.arm->writes_pc); hash.add(instruction.arm->writeback);
    } else hash.add(UINT64_MAX);
    return hash.value;
}
compare::Result<bool> save_compare_session(const std::filesystem::path &path, const compare::Session &session) {
    if (path.empty()) return compare::Error{compare::ErrorCode::invalid_argument, "comparison session path is empty"};
    if (session.old_name.empty() || session.new_name.empty())
        return compare::Error{compare::ErrorCode::invalid_argument, "comparison session must name both inputs"};
    return compare::save_session(path, session);
}
compare::Result<compare::Session> load_compare_session(const std::filesystem::path &path) {
    if (path.empty()) return compare::Error{compare::ErrorCode::invalid_argument, "comparison session path is empty"};
    auto loaded = compare::load_session(path);
    if (!loaded) return loaded.error();
    if (loaded.value().old_name.empty() || loaded.value().new_name.empty())
        return compare::Error{compare::ErrorCode::invalid_argument, "comparison session is missing input names"};
    return loaded;
}
wxString compare_kind_text(compare::ChangeKind kind) {
    switch (kind) {
    case compare::ChangeKind::added: return "Added";
    case compare::ChangeKind::removed: return "Removed";
    case compare::ChangeKind::changed: return "Changed";
    }
    return "Unknown";
}
wxString compare_run_text(const compare::ChangeRun &run) {
    return compare_kind_text(run.kind) + " " + from_utf8(run.region_key) + " " + address(run.old_address) + " -> " +
           address(run.new_address) + " (" + number(run.size) + " bytes)";
}
wxString compare_function_kind_text(compare::FunctionMatchKind kind) {
    switch (kind) {
    case compare::FunctionMatchKind::matched: return "Matched";
    case compare::FunctionMatchKind::added: return "Added";
    case compare::FunctionMatchKind::removed: return "Removed";
    case compare::FunctionMatchKind::ambiguous: return "Ambiguous";
    }
    return "Unknown";
}
wxString compare_function_text(const compare::FunctionMatch &match) {
    return compare_function_kind_text(match.kind) + " " + function_address(match.old_entry, match.old_space) + " -> " +
           function_address(match.new_entry, match.new_space) + " (" + confidence(match.confidence) + ")";
}
std::vector<std::size_t> filter_compare_runs(std::span<const compare::ChangeRun> runs,
                                             const CompareRunFilter &filter) {
    const auto query = lower_ascii(filter.text);
    std::vector<std::size_t> result;
    for (std::size_t i = 0; i < runs.size(); ++i) {
        const auto &run = runs[i];
        if ((run.kind == compare::ChangeKind::changed && !filter.show_changed) ||
            (run.kind == compare::ChangeKind::added && !filter.show_added) ||
            (run.kind == compare::ChangeKind::removed && !filter.show_removed)) continue;
        if (!query.empty() && lower_ascii(compare_run_text(run).ToStdString()).find(query) == std::string::npos)
            continue;
        result.push_back(i);
    }
    return result;
}
std::vector<std::size_t> filter_compare_functions(std::span<const compare::FunctionMatch> functions,
                                                  const CompareFunctionFilter &filter) {
    const auto query = lower_ascii(filter.text);
    std::vector<std::size_t> result;
    result.reserve(functions.size());
    for (std::size_t i = 0; i < functions.size(); ++i) {
        const auto &match = functions[i];
        if (filter.kind && match.kind != *filter.kind) continue;
        if (filter.minimum_confidence &&
            (match.kind == compare::FunctionMatchKind::matched ||
             match.kind == compare::FunctionMatchKind::ambiguous) &&
            match.confidence < filter.minimum_confidence) continue;
        if (!query.empty()) {
            const auto description = lower_ascii(utf8(compare_function_text(match)));
            if (description.find(query) == std::string::npos &&
                lower_ascii(match.old_name).find(query) == std::string::npos &&
                lower_ascii(match.new_name).find(query) == std::string::npos) continue;
        }
        result.push_back(i);
    }
    return result;
}
std::optional<std::size_t> next_navigable_compare_run(std::span<const compare::ChangeRun> runs,
    std::span<const std::size_t> visible, std::optional<std::size_t> current_position, int direction) {
    if (visible.empty() || direction == 0) return {};
    const auto step = direction > 0 ? 1 : -1;
    std::int64_t position;
    if (current_position && *current_position < visible.size())
        position = static_cast<std::int64_t>(*current_position);
    else
        position = step > 0 ? -1 : static_cast<std::int64_t>(visible.size());
    for (std::size_t count = 0; count < visible.size(); ++count) {
        position = (position + step + static_cast<std::int64_t>(visible.size())) % static_cast<std::int64_t>(visible.size());
        const auto index = visible[static_cast<std::size_t>(position)];
        if (index < runs.size() && runs[index].old_address) return index;
    }
    return {};
}
CompareView::CompareView(wxWindow *parent, compare::Report report, wxString old_name, wxString new_name,
                         std::vector<compare::FunctionMatch> functions,
                         std::function<void(const compare::ChangeRun &)> navigate_old,
                         std::function<void(const compare::FunctionMatch &)> navigate_old_function,
                         std::vector<compare::FunctionBodyDiff> function_body_diffs,
                         std::function<void(const compare::ChangeRun &)> navigate_new,
                         std::function<void(const compare::FunctionMatch &)> navigate_new_function)
    : wxFrame(parent, wxID_ANY, "Binary Comparison", wxDefaultPosition, wxSize(900, 560)),
      report_(std::move(report)), function_matches_(std::move(functions)),
      function_body_diffs_(std::move(function_body_diffs)),
      old_name_(std::move(old_name)), new_name_(std::move(new_name)), navigate_old_(std::move(navigate_old)),
      navigate_old_function_(std::move(navigate_old_function)), navigate_new_(std::move(navigate_new)),
      navigate_new_function_(std::move(navigate_new_function)) {
    SetName("binary-compare-view");
    CreateStatusBar();
    auto *menu_bar = new wxMenuBar;
    auto *file = new wxMenu;
    file->Append(wxID_SAVEAS, "Save Comparison Session As...");
    const auto export_csv_id = wxWindow::NewControlId();
    file->Append(export_csv_id, "Export Comparison CSV...");
    file->Append(wxID_OPEN, "Open Comparison Session...");
    menu_bar->Append(file, "&File");
    SetMenuBar(menu_bar);
    Bind(wxEVT_MENU, [this](wxCommandEvent &) { save_session_as(); }, wxID_SAVEAS);
    Bind(wxEVT_MENU, [this](wxCommandEvent &) { export_csv(); }, export_csv_id);
    Bind(wxEVT_MENU, [this](wxCommandEvent &) { open_session(); }, wxID_OPEN);
    auto *box = new wxBoxSizer(wxVERTICAL);
    auto &s = report_.summary;
    auto summary = wxString("Old: ") + old_name_ + "    New: " + new_name_ + "\n" +
                   "Compared " + number(s.compared_bytes) + " bytes; equal " + number(s.equal_bytes) +
                   ", changed " + number(s.changed_bytes) + ", added " + number(s.added_bytes) +
                   ", removed " + number(s.removed_bytes) + "\nMatched regions " + number(s.matched_regions) +
                   ", added regions " + number(s.added_regions) + ", removed regions " + number(s.removed_regions);
    box->Add(new wxStaticText(this, wxID_ANY, summary), 0, wxEXPAND | wxALL, FromDIP(8));
    auto *pages = new wxNotebook(this, wxID_ANY);
    auto *byte_page = new wxPanel(pages);
    auto *byte_box = new wxBoxSizer(wxVERTICAL);
    runs_ = new wxListCtrl(byte_page, wxID_ANY, wxDefaultPosition, wxDefaultSize, wxLC_REPORT | wxLC_SINGLE_SEL);
    runs_->SetName("compare-runs");
    for (auto [title, width] : {std::pair{"Kind", 90}, {"Region", 240}, {"Old address", 150}, {"New address", 150}, {"Bytes", 100}})
        runs_->AppendColumn(title, wxLIST_FORMAT_LEFT, FromDIP(width));
    auto *controls = new wxBoxSizer(wxHORIZONTAL);
    run_search_ = new wxTextCtrl(byte_page, wxID_ANY);
    run_search_->SetHint("Filter by kind, region, or address");
    run_search_->SetName("compare-run-search");
    controls->Add(run_search_, 1, wxALIGN_CENTER_VERTICAL | wxRIGHT, FromDIP(8));
    show_changed_ = new wxCheckBox(byte_page, wxID_ANY, "Changed");
    show_added_ = new wxCheckBox(byte_page, wxID_ANY, "Added");
    show_removed_ = new wxCheckBox(byte_page, wxID_ANY, "Removed");
    show_changed_->SetValue(true); show_added_->SetValue(true); show_removed_->SetValue(true);
    controls->Add(show_changed_, 0, wxALIGN_CENTER_VERTICAL | wxRIGHT, FromDIP(8));
    controls->Add(show_added_, 0, wxALIGN_CENTER_VERTICAL | wxRIGHT, FromDIP(8));
    controls->Add(show_removed_, 0, wxALIGN_CENTER_VERTICAL | wxRIGHT, FromDIP(8));
    run_count_ = new wxStaticText(byte_page, wxID_ANY, "");
    controls->Add(run_count_, 0, wxALIGN_CENTER_VERTICAL | wxRIGHT, FromDIP(8));
    auto *previous = new wxButton(byte_page, wxID_ANY, "Previous");
    auto *next = new wxButton(byte_page, wxID_ANY, "Next");
    auto *go_old = new wxButton(byte_page, wxID_ANY, "Go to old side");
    auto *go_new = new wxButton(byte_page, wxID_ANY, "Go to new side");
    previous->SetName("compare-run-previous"); next->SetName("compare-run-next");
    controls->Add(previous, 0, wxRIGHT, FromDIP(4));
    controls->Add(next, 0);
    controls->Add(go_old, 0, wxLEFT, FromDIP(8));
    controls->Add(go_new, 0, wxLEFT, FromDIP(4));
    byte_box->Add(controls, 0, wxEXPAND | wxALL, FromDIP(8));
    byte_box->Add(runs_, 1, wxEXPAND | wxLEFT | wxRIGHT | wxBOTTOM, FromDIP(8));
    refresh_runs();
    const auto refresh = [this](wxCommandEvent &) { refresh_runs(); };
    run_search_->Bind(wxEVT_TEXT, refresh);
    show_changed_->Bind(wxEVT_CHECKBOX, refresh);
    show_added_->Bind(wxEVT_CHECKBOX, refresh);
    show_removed_->Bind(wxEVT_CHECKBOX, refresh);
    previous->Bind(wxEVT_BUTTON, [this](wxCommandEvent &) { navigate_visible_run(-1); });
    next->Bind(wxEVT_BUTTON, [this](wxCommandEvent &) { navigate_visible_run(1); });
    go_old->Bind(wxEVT_BUTTON, [this](wxCommandEvent &) { auto row = runs_->GetNextItem(-1, wxLIST_NEXT_ALL, wxLIST_STATE_SELECTED); if (row >= 0 && static_cast<std::size_t>(row) < visible_runs_.size()) activate_run(visible_runs_[static_cast<std::size_t>(row)]); });
    go_new->Bind(wxEVT_BUTTON, [this](wxCommandEvent &) { auto row = runs_->GetNextItem(-1, wxLIST_NEXT_ALL, wxLIST_STATE_SELECTED); if (row >= 0 && static_cast<std::size_t>(row) < visible_runs_.size()) activate_run_new(visible_runs_[static_cast<std::size_t>(row)]); });
    byte_page->SetSizer(byte_box);
    pages->AddPage(byte_page, "Bytes");

    auto *function_page = new wxPanel(pages);
    auto *function_box = new wxBoxSizer(wxVERTICAL);
    auto *function_filters = new wxBoxSizer(wxHORIZONTAL);
    function_kind_filter_ = new wxChoice(function_page, wxID_ANY);
    function_kind_filter_->SetName("compare-function-kind-filter");
    for (const auto *label : {"All statuses", "Matched", "Added", "Removed", "Ambiguous"})
        function_kind_filter_->Append(label);
    function_kind_filter_->SetSelection(0);
    function_filters->Add(function_kind_filter_, 0, wxRIGHT | wxALIGN_CENTER_VERTICAL, FromDIP(6));
    function_confidence_filter_ = new wxSpinCtrl(function_page, wxID_ANY, wxString{}, wxDefaultPosition,
        wxSize(FromDIP(76), -1), wxSP_ARROW_KEYS, 0, 100, 0);
    function_confidence_filter_->SetName("compare-function-min-confidence");
    function_confidence_filter_->SetToolTip("Minimum confidence for matched or ambiguous candidates (0-100)");
    function_filters->Add(new wxStaticText(function_page, wxID_ANY, "Min confidence"),
                          0, wxRIGHT | wxALIGN_CENTER_VERTICAL, FromDIP(4));
    function_filters->Add(function_confidence_filter_, 0, wxRIGHT | wxALIGN_CENTER_VERTICAL, FromDIP(8));
    function_search_ = new wxTextCtrl(function_page, wxID_ANY);
    function_search_->SetName("compare-function-search");
    function_search_->SetHint("Filter by status, name, or address");
    function_filters->Add(function_search_, 1, wxALIGN_CENTER_VERTICAL);
    function_box->Add(function_filters, 0, wxEXPAND | wxALL, FromDIP(8));
    function_count_ = new wxStaticText(function_page, wxID_ANY, "0 visible / 0 total");
    function_count_->SetName("compare-function-count");
    function_box->Add(function_count_, 0, wxLEFT | wxRIGHT | wxBOTTOM, FromDIP(8));
    functions_ = new wxListCtrl(function_page, wxID_ANY, wxDefaultPosition, wxDefaultSize,
                                wxLC_REPORT | wxLC_SINGLE_SEL);
    functions_->SetName("compare-functions");
    for (auto [title, width] : {std::pair{"Status", 105}, {"Old name", 180}, {"Old entry", 140},
                                {"New name", 180}, {"New entry", 140}, {"Confidence", 90},
                                {"Base", 70}, {"Call links", 80}, {"Round", 60}, {"Body diff", 90}})
        functions_->AppendColumn(title, wxLIST_FORMAT_LEFT, FromDIP(width));
    function_box->Add(functions_, 1, wxEXPAND | wxLEFT | wxRIGHT | wxTOP, FromDIP(8));
    refresh_functions();
    const auto refresh_functions = [this](wxCommandEvent &) { this->refresh_functions(); };
    function_kind_filter_->Bind(wxEVT_CHOICE, refresh_functions);
    function_confidence_filter_->Bind(wxEVT_SPINCTRL, refresh_functions);
    function_confidence_filter_->Bind(wxEVT_TEXT, refresh_functions);
    function_search_->Bind(wxEVT_TEXT, refresh_functions);
    auto selected_function = [this]() -> std::optional<std::size_t> {
        const auto row = functions_->GetNextItem(-1, wxLIST_NEXT_ALL, wxLIST_STATE_SELECTED);
        if (row < 0 || static_cast<std::size_t>(row) >= visible_functions_.size()) return {};
        return visible_functions_[static_cast<std::size_t>(row)];
    };
    auto *function_navigation = new wxBoxSizer(wxHORIZONTAL);
    auto *function_old = new wxButton(function_page, wxID_ANY, "Go to old function");
    auto *function_new = new wxButton(function_page, wxID_ANY, "Go to new function");
    function_navigation->Add(function_old, 0, wxRIGHT, FromDIP(4));
    function_navigation->Add(function_new, 0);
    function_box->Add(function_navigation, 0, wxLEFT | wxRIGHT | wxTOP, FromDIP(8));
    function_old->Bind(wxEVT_BUTTON, [this, selected_function](wxCommandEvent &) { const auto index = selected_function(); if (index && navigate_old_function_) navigate_old_function_(function_matches_[*index]); });
    function_new->Bind(wxEVT_BUTTON, [this, selected_function](wxCommandEvent &) { const auto index = selected_function(); if (index && navigate_new_function_) navigate_new_function_(function_matches_[*index]); });
    function_diff_summary_ = new wxStaticText(function_page, wxID_ANY,
        "Select a matched function to inspect its instruction alignment.");
    function_diff_summary_->SetName("compare-function-diff-summary");
    function_box->Add(function_diff_summary_, 0, wxEXPAND | wxLEFT | wxRIGHT | wxTOP, FromDIP(8));
    function_diff_runs_ = new wxListCtrl(function_page, wxID_ANY, wxDefaultPosition, wxDefaultSize,
                                         wxLC_REPORT | wxLC_SINGLE_SEL);
    function_diff_runs_->SetName("compare-function-diff-runs");
    function_diff_runs_->AppendColumn("Change", wxLIST_FORMAT_LEFT, FromDIP(100));
    function_diff_runs_->AppendColumn("Old index / range", wxLIST_FORMAT_LEFT, FromDIP(220));
    function_diff_runs_->AppendColumn("New index / range", wxLIST_FORMAT_LEFT, FromDIP(220));
    function_box->Add(function_diff_runs_, 1, wxEXPAND | wxALL, FromDIP(8));
    function_page->SetSizer(function_box);
    pages->AddPage(function_page, "Functions");
    box->Add(pages, 1, wxEXPAND | wxALL, FromDIP(8));
    SetSizer(box);
    runs_->Bind(wxEVT_LIST_ITEM_ACTIVATED, [this](wxListEvent &event) {
        const auto row = static_cast<std::size_t>(event.GetIndex());
        if (row < visible_runs_.size()) activate_run(visible_runs_[row]);
    });
    functions_->Bind(wxEVT_LIST_ITEM_ACTIVATED, [this](wxListEvent &event) {
        const auto row = static_cast<std::size_t>(event.GetIndex());
        if (row < visible_functions_.size()) {
            const auto index = visible_functions_[row];
            if (index < function_matches_.size() && function_matches_[index].old_entry && navigate_old_function_)
                navigate_old_function_(function_matches_[index]);
        }
    });
    functions_->Bind(wxEVT_LIST_ITEM_SELECTED, [this](wxListEvent &event) {
        const auto row = event.GetIndex();
        if (row >= 0 && static_cast<std::size_t>(row) < visible_functions_.size())
            show_function_diff(visible_functions_[static_cast<std::size_t>(row)]);
    });
}
void CompareView::export_csv() {
    wxFileDialog picker(this, "Export comparison as CSV", {}, {},
                        "CSV files (*.csv)|*.csv|All files (*.*)|*.*", wxFD_SAVE | wxFD_OVERWRITE_PROMPT);
    if (picker.ShowModal() != wxID_OK) return;
    const auto path = std::filesystem::path(picker.GetPath().ToStdWstring());
    std::ofstream output(path, std::ios::binary | std::ios::trunc);
    if (!output) {
        wxMessageBox("Could not open the CSV file for writing.", "Comparison export", wxOK | wxICON_ERROR, this);
        return;
    }
    output << csv_row({"record_type", "old_input", "new_input", "status", "region", "old_address",
                       "new_address", "size_bytes", "confidence_percent", "base_confidence_percent",
                       "supporting_call_neighbors", "call_graph_round", "old_name", "new_name",
                       "summary_metric", "summary_value", "old_instruction_start", "old_instruction_count",
                       "new_instruction_start", "new_instruction_count"});
    const auto &summary = report_.summary;
    const auto summary_row = [&](std::string label, std::uint64_t value) {
        output << csv_row({"summary", utf8(old_name_), utf8(new_name_), {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {},
                           std::move(label), std::to_string(value), {}, {}, {}, {}});
    };
    summary_row("Compared bytes", summary.compared_bytes);
    summary_row("Equal bytes", summary.equal_bytes);
    summary_row("Changed bytes", summary.changed_bytes);
    summary_row("Added bytes", summary.added_bytes);
    summary_row("Removed bytes", summary.removed_bytes);
    summary_row("Matched regions", summary.matched_regions);
    summary_row("Added regions", summary.added_regions);
    summary_row("Removed regions", summary.removed_regions);
    for (const auto &run : report_.runs)
        output << csv_row({"byte_run", utf8(old_name_), utf8(new_name_), utf8(compare_kind_text(run.kind)), run.region_key,
                           csv_address(run.old_address), csv_address(run.new_address), std::to_string(run.size), {}, {}, {}, {}, {}, {}, {}, {},
                           {}, {}, {}, {}});
    for (const auto &match : function_matches_)
        output << csv_row({"function", utf8(old_name_), utf8(new_name_), utf8(compare_function_kind_text(match.kind)), {},
                           function_address(match.old_entry, match.old_space).ToStdString(),
                           function_address(match.new_entry, match.new_space).ToStdString(), {},
                           std::to_string(match.confidence), std::to_string(match.evidence.base_confidence),
                           std::to_string(match.evidence.supporting_call_neighbors),
                           std::to_string(match.evidence.call_graph_round), match.old_name, match.new_name, {}, {},
                           {}, {}, {}, {}});
    for (const auto &body : function_body_diffs_) {
        const auto match = std::find_if(function_matches_.begin(), function_matches_.end(), [&](const auto &value) {
            return value.old_entry && value.new_entry && *value.old_entry == body.old_entry &&
                *value.new_entry == body.new_entry && value.old_space == body.old_space &&
                value.new_space == body.new_space;
        });
        const std::string old_function = match == function_matches_.end() ? std::string{} : match->old_name;
        const std::string new_function = match == function_matches_.end() ? std::string{} : match->new_name;
        for (const auto &run : body.diff.runs)
            output << csv_row({"function_instruction_run", utf8(old_name_), utf8(new_name_),
                utf8(function_diff_kind_text(run.kind)), {},
                wxString::Format("0x%llX", static_cast<unsigned long long>(body.old_entry)).ToStdString(),
                wxString::Format("0x%llX", static_cast<unsigned long long>(body.new_entry)).ToStdString(),
                {}, {}, {}, {}, {}, old_function, new_function, {}, {},
                std::to_string(run.old_start), std::to_string(run.old_count),
                std::to_string(run.new_start), std::to_string(run.new_count)});
    }
    output.flush();
    if (!output) {
        wxMessageBox("The comparison CSV could not be written completely.", "Comparison export", wxOK | wxICON_ERROR, this);
        return;
    }
    SetStatusText("Comparison CSV exported");
}
void CompareView::save_session_as() {
    wxFileDialog picker(this, "Save comparison session", {}, {},
                        "HexLab comparison sessions (*.hxcmp)|*.hxcmp|All files (*.*)|*.*",
                        wxFD_SAVE);
    if (picker.ShowModal() != wxID_OK) return;
    auto path = std::filesystem::path(picker.GetPath().ToStdWstring());
    std::error_code ec;
    if (std::filesystem::exists(path, ec)) {
        wxMessageBox("That file already exists. Choose a new session path.", "Comparison session",
                     wxOK | wxICON_WARNING, this);
        return;
    }
    compare::Session session{utf8(old_name_), utf8(new_name_), report_, function_matches_, function_body_diffs_};
    auto saved = save_compare_session(path, session);
    if (!saved) {
        wxMessageBox(wxString::FromUTF8(saved.error().message), "Could not save comparison session",
                     wxOK | wxICON_ERROR, this);
        return;
    }
    SetStatusText("Comparison session saved");
}
void CompareView::open_session() {
    wxFileDialog picker(this, "Open comparison session", {}, {},
                        "HexLab comparison sessions (*.hxcmp)|*.hxcmp|All files (*.*)|*.*",
                        wxFD_OPEN | wxFD_FILE_MUST_EXIST);
    if (picker.ShowModal() != wxID_OK) return;
    const auto path = std::filesystem::path(picker.GetPath().ToStdWstring());
    auto loaded = load_compare_session(path);
    if (!loaded) {
        wxMessageBox(wxString::FromUTF8(loaded.error().message), "Could not open comparison session",
                     wxOK | wxICON_ERROR, this);
        return;
    }
    auto session = std::move(loaded.value());
    auto *view = new CompareView(this, std::move(session.report), wxString::FromUTF8(session.old_name),
        wxString::FromUTF8(session.new_name), std::move(session.functions), {}, {},
        std::move(session.function_body_diffs));
    view->Show();
}
void CompareView::refresh_runs() {
    CompareRunFilter filter;
    filter.show_changed = show_changed_ ? show_changed_->GetValue() : true;
    filter.show_added = show_added_ ? show_added_->GetValue() : true;
    filter.show_removed = show_removed_ ? show_removed_->GetValue() : true;
    if (run_search_) {
        const auto utf8 = run_search_->GetValue().ToUTF8();
        if (utf8) filter.text.assign(utf8.data(), utf8.length());
    }
    visible_runs_ = filter_compare_runs(report_.runs, filter);
    if (!runs_) return;
    runs_->DeleteAllItems();
    for (std::size_t row = 0; row < visible_runs_.size(); ++row) {
        const auto &run = report_.runs[visible_runs_[row]];
        const auto item = runs_->InsertItem(static_cast<long>(row), compare_kind_text(run.kind));
        runs_->SetItem(item, 1, from_utf8(run.region_key));
        runs_->SetItem(item, 2, address(run.old_address));
        runs_->SetItem(item, 3, address(run.new_address));
        runs_->SetItem(item, 4, number(run.size));
    }
    if (run_count_) run_count_->SetLabel(number(visible_runs_.size()) + " / " + number(report_.runs.size()));
}
void CompareView::activate_run(std::size_t index) {
    if (index < report_.runs.size() && report_.runs[index].old_address && navigate_old_)
        navigate_old_(report_.runs[index]);
}
void CompareView::activate_run_new(std::size_t index) {
    if (index < report_.runs.size() && report_.runs[index].new_address && navigate_new_)
        navigate_new_(report_.runs[index]);
}
void CompareView::show_function_diff(std::size_t index) {
    function_diff_runs_->DeleteAllItems();
    if (index >= function_matches_.size()) {
        function_diff_summary_->SetLabel("Select a function match to inspect its instruction alignment.");
        return;
    }
    const auto &match = function_matches_[index];
    if (match.kind != compare::FunctionMatchKind::matched || !match.old_entry || !match.new_entry) {
        function_diff_summary_->SetLabel("Instruction alignment requires an unambiguous matched function.");
        return;
    }
    const auto found = std::find_if(function_body_diffs_.begin(), function_body_diffs_.end(), [&](const auto &body) {
        return body.old_entry == *match.old_entry && body.new_entry == *match.new_entry &&
            body.old_space == match.old_space && body.new_space == match.new_space;
    });
    if (found == function_body_diffs_.end()) {
        function_diff_summary_->SetLabel(
            "No body diff was stored; fingerprints may be unavailable or the bounded instruction-diff budget was exhausted.");
        return;
    }
    const auto &diff = found->diff;
    auto summary = wxString::Format(
        "Instructions: equal %llu; changed %llu; removed %llu; added %llu. Blocks: matched %llu; added %llu; removed %llu; ambiguous %llu.",
        static_cast<unsigned long long>(diff.equal_instructions),
        static_cast<unsigned long long>(diff.changed_instructions),
        static_cast<unsigned long long>(diff.removed_instructions),
        static_cast<unsigned long long>(diff.added_instructions),
        static_cast<unsigned long long>(found->block_correspondence.matched),
        static_cast<unsigned long long>(found->block_correspondence.added),
        static_cast<unsigned long long>(found->block_correspondence.removed),
        static_cast<unsigned long long>(found->block_correspondence.ambiguous));
    if (found->block_correspondence.budget_exhausted) summary += " Block matching budget exhausted; unresolved blocks remain ambiguous.";
    if (found->block_correspondence.instruction_diff_budget_exhausted)
        summary += " Block instruction diff budget exhausted; unresolved instruction summaries are omitted.";
    function_diff_summary_->SetLabel(summary);
    for (const auto &run : diff.runs) {
        const auto row = function_diff_runs_->InsertItem(function_diff_runs_->GetItemCount(),
                                                         function_diff_kind_text(run.kind));
        function_diff_runs_->SetItem(row, 1, instruction_range(run.old_start, run.old_count));
        function_diff_runs_->SetItem(row, 2, instruction_range(run.new_start, run.new_count));
    }
    constexpr std::size_t visible_block_rows = 2000;
    const auto &block_rows = found->block_correspondence.blocks;
    const auto count = std::min(block_rows.size(), visible_block_rows);
    for (std::size_t i = 0; i < count; ++i) {
        const auto &block = block_rows[i];
        const char *kind = block.kind == compare::BlockMatchKind::matched ? "Block matched" :
                           block.kind == compare::BlockMatchKind::added ? "Block added" :
                           block.kind == compare::BlockMatchKind::removed ? "Block removed" : "Block ambiguous";
        wxString block_label = kind;
        if (block.instruction_diff_available) {
            const auto &local = block.instruction_diff;
            block_label += wxString::Format(
                " (instructions equal %llu, changed %llu, removed %llu, added %llu)",
                static_cast<unsigned long long>(local.equal_instructions),
                static_cast<unsigned long long>(local.changed_instructions),
                static_cast<unsigned long long>(local.removed_instructions),
                static_cast<unsigned long long>(local.added_instructions));
        } else if (block.instruction_diff_budget_exhausted) {
            block_label += " (instruction diff omitted: budget)";
        }
        const auto row = function_diff_runs_->InsertItem(function_diff_runs_->GetItemCount(), block_label);
        function_diff_runs_->SetItem(row, 1, block.old_block ? from_utf8(std::to_string(*block.old_block)) : wxString("-"));
        function_diff_runs_->SetItem(row, 2, block.new_block ? from_utf8(std::to_string(*block.new_block)) : wxString("-"));
    }
    if (block_rows.size() > count) {
        const auto row = function_diff_runs_->InsertItem(function_diff_runs_->GetItemCount(), "Block rows omitted");
        function_diff_runs_->SetItem(row, 1, from_utf8(std::to_string(block_rows.size() - count)));
    }
}
void CompareView::refresh_functions() {
    if (!functions_) return;
    CompareFunctionFilter filter;
    if (function_kind_filter_ && function_kind_filter_->GetSelection() > 0) {
        switch (function_kind_filter_->GetSelection()) {
        case 1: filter.kind = compare::FunctionMatchKind::matched; break;
        case 2: filter.kind = compare::FunctionMatchKind::added; break;
        case 3: filter.kind = compare::FunctionMatchKind::removed; break;
        case 4: filter.kind = compare::FunctionMatchKind::ambiguous; break;
        default: break;
        }
    }
    if (function_confidence_filter_)
        filter.minimum_confidence = static_cast<unsigned>(function_confidence_filter_->GetValue());
    if (function_search_) filter.text = utf8(function_search_->GetValue());
    visible_functions_ = filter_compare_functions(function_matches_, filter);
    functions_->DeleteAllItems();
    if (function_count_)
        function_count_->SetLabel(wxString::Format("%zu visible / %zu total",
            visible_functions_.size(), function_matches_.size()));
    for (std::size_t row_index = 0; row_index < visible_functions_.size(); ++row_index) {
        const auto index = visible_functions_[row_index];
        if (index >= function_matches_.size()) continue;
        const auto &match = function_matches_[index];
        const auto row = functions_->InsertItem(static_cast<long>(row_index), compare_function_kind_text(match.kind));
        functions_->SetItem(row, 1, from_utf8(match.old_name));
        functions_->SetItem(row, 2, function_address(match.old_entry, match.old_space));
        functions_->SetItem(row, 3, from_utf8(match.new_name));
        functions_->SetItem(row, 4, function_address(match.new_entry, match.new_space));
        functions_->SetItem(row, 5, confidence(match.confidence));
        functions_->SetItem(row, 6, confidence(match.evidence.base_confidence));
        functions_->SetItem(row, 7, number(match.evidence.supporting_call_neighbors));
        functions_->SetItem(row, 8, number(match.evidence.call_graph_round));
        const auto has_body_diff = std::find_if(function_body_diffs_.begin(), function_body_diffs_.end(),
            [&](const auto &body) {
                return match.old_entry && match.new_entry && body.old_entry == *match.old_entry &&
                    body.new_entry == *match.new_entry && body.old_space == match.old_space &&
                    body.new_space == match.new_space;
            }) != function_body_diffs_.end();
        functions_->SetItem(row, 9, has_body_diff ? "Available" : "Unavailable");
    }
    if (function_diff_runs_) function_diff_runs_->DeleteAllItems();
    if (function_diff_summary_)
        function_diff_summary_->SetLabel("Select a matched function to inspect its instruction alignment.");
}
void CompareView::navigate_visible_run(int direction) {
    std::optional<std::size_t> current;
    const auto selected = runs_->GetNextItem(-1, wxLIST_NEXT_ALL, wxLIST_STATE_SELECTED);
    if (selected >= 0) current = static_cast<std::size_t>(selected);
    const auto next = next_navigable_compare_run(report_.runs, visible_runs_, current, direction);
    if (!next) return;
    const auto found = std::find(visible_runs_.begin(), visible_runs_.end(), *next);
    if (found == visible_runs_.end()) return;
    const auto row = static_cast<long>(std::distance(visible_runs_.begin(), found));
    runs_->SetItemState(row, wxLIST_STATE_SELECTED | wxLIST_STATE_FOCUSED,
                        wxLIST_STATE_SELECTED | wxLIST_STATE_FOCUSED);
    runs_->EnsureVisible(row);
    activate_run(*next);
}
}
