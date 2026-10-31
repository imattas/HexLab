#include "search_view.hpp"
#include "hexlab/workspace/navigation.hpp"
#include "hexlab/image/file_publication.hpp"
#include <wx/choice.h>
#include <wx/checkbox.h>
#include <wx/textctrl.h>
#include <wx/sizer.h>
#include <wx/dialog.h>
#include <wx/clipbrd.h>
#include <wx/dataobj.h>
#include <wx/filedlg.h>
#include <wx/msgdlg.h>
#include <wx/settings.h>
#include <wx/config.h>
#include <algorithm>
#include <array>
#include <atomic>
#include <condition_variable>
#include <mutex>
#include <thread>
namespace hexlab::desktop {
namespace {
constexpr std::size_t recent_find_limit = 16, recent_find_value_limit = 4096;
struct RecentFind {
    wxString value;
    long kind = 0, encoding = 1, width = 3, results = 256, positions = 1048576;
    bool signed_value = false, case_sensitive = true;
    bool operator==(const RecentFind&) const = default;
};
bool valid_recent_find(const RecentFind& setup) {
    if (setup.kind < 0 || setup.kind > 2 || setup.encoding < 0 || setup.encoding > 7 ||
        setup.width < 0 || setup.width > 3 || setup.results < 1 || setup.results > 4096 ||
        setup.positions < 1 || setup.positions > 16777216 || setup.value.length() > recent_find_value_limit)
        return false;
    const auto value = setup.value.utf8_string();
    if (value.size() > recent_find_value_limit || value.find('\0') != std::string::npos) return false;
    constexpr TextEncoding encodings[] = {TextEncoding::ascii, TextEncoding::utf8, TextEncoding::utf16le,
                                          TextEncoding::utf16be, TextEncoding::utf32le, TextEncoding::utf32be,
                                          TextEncoding::windows1252, TextEncoding::iso8859_1};
    constexpr std::uint16_t widths[] = {8, 16, 32, 64};
    SearchQuery query = BytePattern{value};
    if (setup.kind == 1) query = TextQuery{value, encodings[setup.encoding], setup.case_sensitive};
    else if (setup.kind == 2) query = ImmediateQuery{value, widths[setup.width], setup.signed_value
        ? ImmediateInterpretation::signed_value : ImmediateInterpretation::unsigned_value};
    return static_cast<bool>(search_query_fingerprint(query));
}
std::vector<RecentFind> load_recent_finds() {
    std::vector<RecentFind> result;
    auto* config = wxConfigBase::Get(false);
    long version = 0, count = 0;
    if (!config || !config->Read("/Search/Recent/Version", &version) || version != 1 ||
        !config->Read("/Search/Recent/Count", &count) || count < 0 || count > static_cast<long>(recent_find_limit)) return result;
    for (long index = 0; index < count; ++index) {
        const auto prefix = wxString::Format("/Search/Recent/%ld/", index);
        RecentFind setup;
        if (config->Read(prefix + "Value", &setup.value) && config->Read(prefix + "Kind", &setup.kind) &&
            config->Read(prefix + "Encoding", &setup.encoding) && config->Read(prefix + "Width", &setup.width) &&
            config->Read(prefix + "Signed", &setup.signed_value) && config->Read(prefix + "Results", &setup.results) &&
            config->Read(prefix + "Positions", &setup.positions)) {
            // Older recent records predate this setting; keep their historical
            // case-sensitive behavior when the key is absent.
            (void)config->Read(prefix + "CaseSensitive", &setup.case_sensitive);
            if (valid_recent_find(setup) && std::find(result.begin(), result.end(), setup) == result.end())
                result.push_back(std::move(setup));
        }
    }
    return result;
}
void remember_find(RecentFind setup, std::vector<RecentFind> recent) {
    if (!valid_recent_find(setup)) return; // Larger searches still run; only persistence is capped.
    auto* config = wxConfigBase::Get(false);
    if (!config) return;
    std::erase(recent, setup);
    recent.insert(recent.begin(), std::move(setup));
    if (recent.size() > recent_find_limit) recent.resize(recent_find_limit);
    (void)config->DeleteGroup("/Search/Recent");
    for (std::size_t index = 0; index < recent.size(); ++index) {
        const auto prefix = wxString::Format("/Search/Recent/%zu/", index);
        const auto& item = recent[index];
        (void)config->Write(prefix + "Value", item.value);
        (void)config->Write(prefix + "Kind", item.kind);
        (void)config->Write(prefix + "Encoding", item.encoding);
        (void)config->Write(prefix + "Width", item.width);
        (void)config->Write(prefix + "Signed", item.signed_value);
        (void)config->Write(prefix + "CaseSensitive", item.case_sensitive);
        (void)config->Write(prefix + "Results", item.results);
        (void)config->Write(prefix + "Positions", item.positions);
    }
    (void)config->Write("/Search/Recent/Version", 1L);
    (void)config->Write("/Search/Recent/Count", static_cast<long>(recent.size()));
    (void)config->Flush();
}
wxString recent_find_label(const RecentFind& item) {
    auto label = item.value.Left(80);
    label.Replace("\r", " "); label.Replace("\n", " "); label.Replace("\t", " ");
    return (item.kind == 0 ? "Bytes: " : item.kind == 1 ? "Text: " : "Immediate: ") + label;
}
bool save_recent_finds(const std::vector<RecentFind>& recent) {
    auto* config = wxConfigBase::Get(false);
    if (!config) return false;
    if (!config->DeleteGroup("/Search/Recent")) return false;
    for (std::size_t index = 0; index < recent.size(); ++index) {
        const auto prefix = wxString::Format("/Search/Recent/%zu/", index);
        const auto& item = recent[index];
        if (!config->Write(prefix + "Value", item.value) || !config->Write(prefix + "Kind", item.kind) ||
            !config->Write(prefix + "Encoding", item.encoding) || !config->Write(prefix + "Width", item.width) ||
            !config->Write(prefix + "Signed", item.signed_value) ||
            !config->Write(prefix + "CaseSensitive", item.case_sensitive) ||
            !config->Write(prefix + "Results", item.results) || !config->Write(prefix + "Positions", item.positions))
            return false;
    }
    return config->Write("/Search/Recent/Version", 1L) &&
        config->Write("/Search/Recent/Count", static_cast<long>(recent.size())) && config->Flush();
}
wxString number(std::uint64_t value) {
    return wxString::Format("%llu", static_cast<unsigned long long>(value));
}
// Keep each TSV field on one physical line, including labels supplied by files.
wxString tsv_field(wxString value) {
    value.Replace("\\", "\\\\");
    value.Replace("\t", "\\t");
    value.Replace("\r", "\\r");
    value.Replace("\n", "\\n");
    return value;
}
} // namespace
std::optional<FindRequest> find_dialog(wxWindow *parent) {
    wxDialog dialog(parent, wxID_ANY, "Find in effective input", wxDefaultPosition, wxDefaultSize,
                    wxDEFAULT_DIALOG_STYLE | wxRESIZE_BORDER);
    const int pad = dialog.FromDIP(10);
    auto *box = new wxBoxSizer(wxVERTICAL);
    auto recent = load_recent_finds();
    auto* recent_bar = new wxBoxSizer(wxHORIZONTAL);
    recent_bar->Add(new wxStaticText(&dialog, wxID_ANY, "Recent searches"), 0, wxALIGN_CENTER_VERTICAL | wxRIGHT, pad);
    auto* recent_choice = new wxChoice(&dialog, wxID_ANY);
    recent_choice->SetName("search-recent");
    recent_choice->SetToolTip("Restore a validated setup without starting a search. The last 16 setups up to 4 KiB are stored locally.");
    for (const auto& item : recent) recent_choice->Append(recent_find_label(item));
    recent_choice->Enable(!recent.empty());
    recent_bar->Add(recent_choice, 1, wxRIGHT, pad);
    auto* forget_recent = new wxButton(&dialog, wxID_ANY, "Forget selected");
    forget_recent->SetName("search-forget-recent");
    forget_recent->Enable(false);
    recent_bar->Add(forget_recent, 0, wxRIGHT, pad);
    auto* clear_recent = new wxButton(&dialog, wxID_ANY, "Clear recent");
    clear_recent->SetName("search-clear-recent");
    clear_recent->Enable(!recent.empty());
    recent_bar->Add(clear_recent);
    box->Add(recent_bar, 0, wxEXPAND | wxALL, pad);
    auto choice = [&](const wxString &label, const wxString &name, std::initializer_list<wxString> entries,
                      int selected) {
        box->Add(new wxStaticText(&dialog, wxID_ANY, label), 0, wxLEFT | wxRIGHT | wxTOP, pad);
        wxArrayString items;
        for (auto &item : entries)
            items.Add(item);
        auto *control = new wxChoice(&dialog, wxID_ANY, wxDefaultPosition, wxDefaultSize, items);
        control->SetName(name);
        control->SetSelection(selected);
        box->Add(control, 0, wxEXPAND | wxLEFT | wxRIGHT, pad);
        return control;
    };
    auto *kind = choice("Search for", "search-kind", {"Byte pattern", "Literal text", "Immediate operand"}, 0);
    auto *value =
        new wxTextCtrl(&dialog, wxID_ANY, "", wxDefaultPosition, dialog.FromDIP(wxSize(480, 90)), wxTE_MULTILINE);
    value->SetName("search-value");
    value->SetHint("Byte patterns support nibble wildcards, e.g. 48 8B ?? A? ?F");
    value->SetToolTip("Search value. For byte patterns, ? matches one nibble and ?? matches one byte.");
    box->Add(value, 1, wxEXPAND | wxALL, pad);
    auto *encoding = choice("Text encoding", "search-encoding", {"ASCII", "UTF-8", "UTF-16LE", "UTF-16BE", "UTF-32LE", "UTF-32BE", "Windows-1252", "ISO-8859-1"}, 1);
    auto *case_sensitive = new wxCheckBox(&dialog, wxID_ANY, "Case-sensitive text search");
    case_sensitive->SetName("search-case-sensitive");
    case_sensitive->SetValue(true);
    case_sensitive->SetToolTip("Match text letter case. Uncheck for ASCII-only case folding.");
    box->Add(case_sensitive, 0, wxLEFT | wxRIGHT | wxBOTTOM, pad);
    auto *width = choice("Immediate effective width", "search-width", {"8", "16", "32", "64"}, 3);
    auto *sign = new wxCheckBox(&dialog, wxID_ANY, "Interpret immediate input as signed");
    sign->SetName("search-signed");
    box->Add(sign, 0, wxALL, pad);
    auto *all_documents = new wxCheckBox(&dialog, wxID_ANY, "Search all open documents");
    all_documents->SetName("search-all-documents");
    box->Add(all_documents, 0, wxLEFT | wxRIGHT | wxBOTTOM, pad);
    auto *from_selection = new wxCheckBox(&dialog, wxID_ANY, "Start at the current selection and search forward");
    from_selection->SetName("search-from-selection");
    from_selection->SetToolTip("Begin at the current file offset or mapped instruction and search forward, optionally stopping at the exclusive end offset.");
    box->Add(from_selection, 0, wxLEFT | wxRIGHT | wxBOTTOM, pad);
    auto number = [&](const wxString &label, const wxString &name, const wxString &initial) {
        box->Add(new wxStaticText(&dialog, wxID_ANY, label), 0, wxLEFT | wxRIGHT, pad);
        auto *field = new wxTextCtrl(&dialog, wxID_ANY, initial);
        field->SetName(name);
        field->SetToolTip(label);
        box->Add(field, 0, wxEXPAND | wxLEFT | wxRIGHT, pad);
        return field;
    };
    auto *limit = number("Matches per page (1..4096)", "search-limit", "256");
    auto *budget = number("Positions examined per page (1..16777216)", "search-budget", "1048576");
    auto *end_offset = number("Exclusive end file offset (optional; hexadecimal or decimal)", "search-end-offset", "");
    auto *error = new wxStaticText(&dialog, wxID_ANY, "");
    error->SetName("search-error");
    error->SetToolTip("Search validation message. Correct the value before starting the search.");
    box->Add(error, 0, wxALL, pad);
    box->Add(dialog.CreateButtonSizer(wxOK | wxCANCEL), 0, wxALL | wxALIGN_RIGHT, pad);
    dialog.SetSizerAndFit(box);
    std::optional<FindRequest> result;
    auto update = [&] {
        encoding->Enable(kind->GetSelection() == 1);
        case_sensitive->Enable(kind->GetSelection() == 1);
        width->Enable(kind->GetSelection() == 2);
        sign->Enable(kind->GetSelection() == 2);
        if (from_selection->IsChecked()) all_documents->SetValue(false);
        all_documents->Enable(!from_selection->IsChecked());
    };
    kind->Bind(wxEVT_CHOICE, [&](wxCommandEvent &) { update(); });
    from_selection->Bind(wxEVT_CHECKBOX, [&](wxCommandEvent &) { update(); });
    const auto restore_recent = [&](std::size_t index) {
        if (index >= recent.size()) return;
        const auto& item = recent[index];
        kind->SetSelection(static_cast<int>(item.kind)); encoding->SetSelection(static_cast<int>(item.encoding));
        width->SetSelection(static_cast<int>(item.width)); sign->SetValue(item.signed_value);
        case_sensitive->SetValue(item.case_sensitive);
        value->ChangeValue(item.value);
        limit->ChangeValue(wxString::Format("%ld", item.results));
        budget->ChangeValue(wxString::Format("%ld", item.positions));
        error->SetLabel({}); update();
    };
    recent_choice->Bind(wxEVT_CHOICE, [&](wxCommandEvent &) {
        const auto selection = recent_choice->GetSelection();
        forget_recent->Enable(selection >= 0 && static_cast<std::size_t>(selection) < recent.size());
        if (selection >= 0) restore_recent(static_cast<std::size_t>(selection));
    });
    forget_recent->Bind(wxEVT_BUTTON, [&](wxCommandEvent &) {
        const auto selection = recent_choice->GetSelection();
        if (selection < 0 || static_cast<std::size_t>(selection) >= recent.size()) return;
        auto updated = recent;
        updated.erase(updated.begin() + selection);
        if (!save_recent_finds(updated)) {
            error->SetLabel("Could not update stored recent searches."); dialog.Layout(); return;
        }
        recent = std::move(updated);
        recent_choice->Clear();
        for (const auto& item : recent) recent_choice->Append(recent_find_label(item));
        recent_choice->SetSelection(wxNOT_FOUND);
        recent_choice->Enable(!recent.empty());
        forget_recent->Disable();
        clear_recent->Enable(!recent.empty());
        error->SetLabel("Selected recent search removed. The current query is still editable.");
        dialog.Layout();
    });
    clear_recent->Bind(wxEVT_BUTTON, [&](wxCommandEvent &) {
        auto* config = wxConfigBase::Get(false);
        if (!config || !config->DeleteGroup("/Search/Recent") || !config->Flush()) {
            error->SetLabel("Could not clear stored recent searches."); dialog.Layout(); return;
        }
        recent.clear(); recent_choice->Clear(); recent_choice->Disable(); clear_recent->Disable();
        forget_recent->Disable();
        error->SetLabel("Stored recent searches cleared. The current query is still editable.");
        dialog.Layout();
    });
    if (!recent.empty()) { recent_choice->SetSelection(0); restore_recent(0); }
    update();
    dialog.Bind(
        wxEVT_BUTTON,
        [&](wxCommandEvent &) {
            std::string input = value->GetValue().utf8_string();
            SearchQuery query = BytePattern{input};
            if (kind->GetSelection() == 1) {
                constexpr TextEncoding encodings[] = {TextEncoding::ascii, TextEncoding::utf8, TextEncoding::utf16le,
                                                      TextEncoding::utf16be, TextEncoding::utf32le, TextEncoding::utf32be,
                                                      TextEncoding::windows1252, TextEncoding::iso8859_1};
                const auto selection = std::clamp(encoding->GetSelection(), 0, int(std::size(encodings)) - 1);
                query = TextQuery{input, encodings[selection], case_sensitive->IsChecked()};
            } else if (kind->GetSelection() == 2) {
                constexpr uint16_t widths[] = {8, 16, 32, 64};
                query = ImmediateQuery{input, widths[width->GetSelection()],
                                       sign->IsChecked() ? ImmediateInterpretation::signed_value
                                                         : ImmediateInterpretation::unsigned_value};
            }
            auto valid = search_query_fingerprint(query);
            if (!valid) {
                error->SetLabel(text(valid.error().message));
                dialog.Layout();
                return;
            }
            auto count = parse_address(limit->GetValue().ToStdWstring()),
                 positions = parse_address(budget->GetValue().ToStdWstring());
            if (!count || !positions || !count.value() || count.value() > 4096 || !positions.value() ||
                positions.value() > 16777216) {
                error->SetLabel("Enter page limits in the displayed ranges.");
                dialog.Layout();
                return;
            }
            SearchLimits limits;
            limits.max_results = std::size_t(count.value());
            limits.max_candidates = positions.value();
            if (!end_offset->GetValue().empty()) {
                auto parsed_end = parse_address(end_offset->GetValue().ToStdWstring());
                if (!parsed_end) {
                    error->SetLabel("Enter a valid exclusive end file offset, or leave it blank.");
                    dialog.Layout();
                    return;
                }
                limits.end_offset = parsed_end.value();
            }
            remember_find({value->GetValue(), kind->GetSelection(), encoding->GetSelection(), width->GetSelection(),
                static_cast<long>(count.value()), static_cast<long>(positions.value()), sign->IsChecked(),
                kind->GetSelection() != 1 || case_sensitive->IsChecked()}, recent);
            result = FindRequest{std::move(query), limits, all_documents->IsChecked(), from_selection->IsChecked()};
            dialog.EndModal(wxID_OK);
        },
        wxID_OK);
    value->SetFocus();
    if (dialog.ShowModal() != wxID_OK)
        return {};
    return result;
}
struct SearchView::Rows {
    struct Item {
        DocumentId document;
        std::size_t index;
        SearchMatch match;
        wxString label;
        std::shared_ptr<const Image> image;
        std::shared_ptr<const ProjectSnapshot> project;
        std::shared_ptr<const SearchPage> page;
        std::array<wxString, 6> cells;
        std::string metadata;
    };
    std::vector<Item> items;
    std::vector<std::filesystem::path> protected_paths;
    bool searched = false;
};
struct SearchView::FilterWork {
    struct Request {
        std::uint64_t generation = 0;
        std::shared_ptr<const Rows> rows;
        std::string needle;
    };
    struct Completion {
        std::uint64_t generation = 0;
        std::shared_ptr<const Rows> rows;
        std::vector<std::size_t> visible;
    };
    std::atomic<std::uint64_t> generation{0};
    std::mutex mutex;
    std::condition_variable_any ready;
    std::optional<Request> request;
    std::optional<Completion> completion;
    std::jthread worker;
};
SearchView::SearchView(wxWindow *parent) : wxPanel(parent), filter_work_(std::make_shared<FilterWork>()),
                                           filter_timer_(this) {
    SetName("search-view");
    const int pad = FromDIP(4);
    auto *box = new wxBoxSizer(wxVERTICAL);
    auto *bar = new wxBoxSizer(wxHORIZONTAL);
    status_ = new wxStaticText(this, wxID_ANY, "No search in this document");
    status_->SetName("search-status");
    status_->SetToolTip("Search status and loaded result count.");
    more_ = new wxButton(this, wxID_ANY, "More results");
    more_->SetName("search-more");
    more_->SetToolTip("Load the next page of search results.");
    more_->Disable();
    bar->Add(status_, 1, wxALL | wxALIGN_CENTER_VERTICAL, pad);
    bar->Add(more_, 0, wxALL, pad);
    box->Add(bar, 0, wxEXPAND);
    auto *tools = new wxBoxSizer(wxHORIZONTAL);
    tools->Add(new wxStaticText(this, wxID_ANY, "Filter loaded results"), 0, wxALL | wxALIGN_CENTER_VERTICAL, pad);
    filter_ = new wxTextCtrl(this, wxID_ANY);
    filter_->SetName("search-result-filter");
    filter_->SetHint("Document, offset, address, size, operand index or history result (case-insensitive)");
    filter_->SetToolTip("Matches loaded result metadata only. Clear the filter to see every loaded result.");
    tools->Add(filter_, 1, wxALL | wxEXPAND, pad);
    auto *clear = new wxButton(this, wxID_ANY, "Clear");
    clear->SetName("search-filter-clear");
    clear->SetToolTip("Clear the loaded-results filter.");
    tools->Add(clear, 0, wxALL, pad);
    box->Add(tools, 0, wxEXPAND);
    auto *actions = new wxBoxSizer(wxHORIZONTAL);
    previous_ = new wxButton(this, wxID_ANY, "Previous visible");
    next_ = new wxButton(this, wxID_ANY, "Next visible");
    copy_ = new wxButton(this, wxID_ANY, "Copy filtered TSV");
    export_ = new wxButton(this, wxID_ANY, "Export filtered TSV...");
    previous_->SetName("search-previous-visible");
    next_->SetName("search-next-visible");
    copy_->SetName("search-copy-filtered");
    export_->SetName("search-export-filtered");
    previous_->SetToolTip("Select the previous result visible under the current filter. Alt+Up also works.");
    next_->SetToolTip("Select the next result visible under the current filter. Alt+Down also works.");
    copy_->SetToolTip("Copy the currently filtered results as tab-separated values.");
    export_->SetToolTip("Save the currently filtered results as tab-separated values.");
    for (auto *button : {previous_, next_, copy_, export_}) {
        button->Disable();
        actions->Add(button, 0, wxALL, pad);
    }
    box->Add(actions, 0, wxEXPAND);
    table_ = new VirtualTable(this, "search-results", {"Document", "File offset", "Virtual address", "Bytes", "Operand", "History result"});
    table_->SetColumnWidth(0, FromDIP(170));
    table_->SetColumnWidth(1, FromDIP(130));
    table_->SetColumnWidth(2, FromDIP(150));
    table_->SetColumnWidth(3, FromDIP(80));
    box->Add(table_, 1, wxEXPAND);
    preview_ = new wxTextCtrl(this, wxID_ANY, "Select a result to preview up to 64 effective source bytes.",
                              wxDefaultPosition, FromDIP(wxSize(440, 92)), wxTE_MULTILINE | wxTE_READONLY | wxTE_DONTWRAP);
    preview_->SetName("search-result-preview");
    preview_->SetToolTip("Read-only preview of the selected result's effective source bytes.");
    preview_->SetFont(wxSystemSettings::GetFont(wxSYS_ANSI_FIXED_FONT));
    box->Add(preview_, 0, wxEXPAND | wxALL, pad);
    SetSizer(box);
    table_->activate = [this](std::size_t row) {
        if (rows_ && visible_ && row < visible_->size()) {
            const auto item = rows_->items[(*visible_)[row]];
            selected_document_ = item.document;
            selected_page_ = item.page;
            selected_index_ = item.index;
            show_preview();
            // The filtered row number must never replace the per-document history index.
            if (navigate) navigate(item.document, item.index, item.match);
        }
    };
    filter_->Bind(wxEVT_TEXT, [this](wxCommandEvent &) { render(); });
    Bind(wxEVT_TIMER, [this](wxTimerEvent &) { poll_filter(); }, filter_timer_.GetId());
    clear->Bind(wxEVT_BUTTON, [this](wxCommandEvent &) { filter_->SetValue(""); });
    previous_->Bind(wxEVT_BUTTON, [this](wxCommandEvent &) { step(false); });
    next_->Bind(wxEVT_BUTTON, [this](wxCommandEvent &) { step(true); });
    copy_->Bind(wxEVT_BUTTON, [this](wxCommandEvent &) { copy_results(); });
    export_->Bind(wxEVT_BUTTON, [this](wxCommandEvent &) { export_results(); });
    more_->Bind(wxEVT_BUTTON, [this](wxCommandEvent &) {
        if (all_documents_ && more_all)
            more_all();
        else if (document_ && more)
            more(*document_);
    });
    Bind(wxEVT_CHAR_HOOK, [this](wxKeyEvent &event) {
        if (event.ControlDown() && !event.AltDown() && !event.ShiftDown() &&
            (event.GetKeyCode() == 'L' || event.GetKeyCode() == 'l')) {
            filter_->SetFocus();
            filter_->SelectAll();
            return;
        }
        if (event.AltDown() && event.GetKeyCode() == WXK_UP) {
            step(false);
            return;
        }
        if (event.AltDown() && event.GetKeyCode() == WXK_DOWN) {
            step(true);
            return;
        }
        event.Skip();
    });
    table_->SetToolTip("Search results. Use Up/Down to select a result; Enter or double-click navigates. Alt+Up/Down moves to the previous/next visible result.");
    filter_->SetToolTip("Filter loaded result metadata. Ctrl+L focuses this field; Enter the document, offset, address, size, operand index, or history text to narrow the list.");
    auto *work = filter_work_.get();
    work->worker = std::jthread([work](std::stop_token stop) {
        while (!stop.stop_requested()) {
            FilterWork::Request request;
            {
                std::unique_lock lock(work->mutex);
                work->ready.wait(lock, stop, [&] { return work->request.has_value(); });
                if (stop.stop_requested()) return;
                request = std::move(*work->request);
                work->request.reset();
            }
            FilterWork::Completion completion;
            completion.generation = request.generation;
            completion.rows = std::move(request.rows);
            if (completion.rows) {
                completion.visible.reserve(completion.rows->items.size());
                for (std::size_t index = 0; index < completion.rows->items.size(); ++index) {
                    if ((index & 255u) == 0 &&
                        (stop.stop_requested() || work->generation.load(std::memory_order_acquire) != completion.generation))
                        break;
                    const auto &item = completion.rows->items[index];
                    if (request.needle.empty() || item.metadata.find(request.needle) != std::string::npos)
                        completion.visible.push_back(index);
                }
            }
            if (stop.stop_requested()) return;
            if (work->generation.load(std::memory_order_acquire) != completion.generation) continue;
            {
                std::lock_guard lock(work->mutex);
                if (work->generation.load(std::memory_order_relaxed) == completion.generation)
                    work->completion = std::move(completion);
            }
        }
    });
}
SearchView::~SearchView() {
    filter_timer_.Stop();
    if (filter_work_ && filter_work_->worker.joinable()) {
        filter_work_->worker.request_stop();
        filter_work_->ready.notify_all();
    }
}
void SearchView::update(std::optional<DocumentId> document, const SearchHistory *history, bool pending,
                        const wxString &reason, std::shared_ptr<const Image> image,
                        std::shared_ptr<const ProjectSnapshot> project) {
    all_documents_ = false;
    document_ = document;
    std::vector<SearchDocumentView> views;
    if (document) views.push_back({*document, "Active document", history, pending, reason, std::move(image), std::move(project)});
    update_all(views);
    all_documents_ = false;
}
void SearchView::update_all(const std::vector<SearchDocumentView> &documents) {
    all_documents_ = true;
    auto rows = std::make_shared<Rows>();
    std::size_t pending = 0, remaining = 0, partial = 0, complete = 0, no_page = 0;
    bool continuation = false;
    wxString reasons;
    std::optional<std::size_t> history_selection;
    for (const auto &document : documents) {
        rows->searched = rows->searched || document.pending || (document.history && document.history->query().has_value());
        if (document.project)
            rows->protected_paths.insert(rows->protected_paths.end(), document.project->protected_paths.begin(),
                                         document.project->protected_paths.end());
        pending += document.pending ? 1 : 0;
        if (!document.reason.empty()) {
            if (!reasons.empty()) reasons += "; ";
            reasons += document.label + ": " + document.reason.Left(160);
        }
        if (!document.history || document.history->pages().empty()) {
            ++no_page;
            continue;
        }
        const auto &last = document.history->pages().back();
        continuation = continuation || (document.history->continuation().has_value() && !document.pending);
        remaining += !last->complete ? 1 : 0;
        const bool source_partial = std::any_of(document.history->pages().begin(), document.history->pages().end(),
            [](const auto &page) { return !page->source_complete; });
        partial += source_partial ? 1 : 0;
        complete += last->complete && !source_partial && !document.pending && document.reason.empty() ? 1 : 0;
        if (!last->reason.empty() && reasons.size() < 512) {
            if (!reasons.empty()) reasons += "; ";
            reasons += document.label + ": " + text(last->reason).Left(160);
        }
        std::size_t index = 0;
        for (const auto &page : document.history->pages())
            for (const auto &match : page->matches) {
                if (document.history->selected_index() == index &&
                    (!history_selection || (selected_document_ && document.id == *selected_document_)))
                    history_selection = rows->items.size();
                const auto address = match.instruction_address ? match.instruction_address : match.address;
                Rows::Item item{document.id, index++, match, document.label, document.image, document.project, page};
                item.cells = {document.label, location_text(match.offset),
                              address ? location_text(*address, document.image.get()) : wxString("file only"),
                              number(match.size), match.operand_index ? number(*match.operand_index) : wxString{},
                              number(item.index + 1)};
                wxString metadata;
                for (const auto &cell : item.cells) metadata += cell + "\n";
                metadata.MakeLower();
                const auto encoded_metadata = metadata.utf8_string();
                item.metadata.assign(encoded_metadata.data(), encoded_metadata.length());
                rows->items.push_back(std::move(item));
            }
    }
    const bool retained = selected_document_ && std::any_of(rows->items.begin(), rows->items.end(), [this](const auto &item) {
        return item.document == *selected_document_ && item.index == selected_index_ && item.page == selected_page_;
    });
    if (!retained) {
        selected_document_.reset();
        selected_page_.reset();
    }
    if (history_selection && (!retained || rows->items[*history_selection].document == selected_document_)) {
        const auto &item = rows->items[*history_selection];
        selected_document_ = item.document;
        selected_index_ = item.index;
        selected_page_ = item.page;
    }
    rows_ = rows;
    more_->Enable(continuation);
    coverage_ = documents.empty() ? wxString("No searchable documents in this scope")
                                : number(complete) + "/" + number(documents.size()) + " documents complete";
    if (pending) coverage_ += "; " + number(pending) + " pending";
    if (remaining) coverage_ += "; " + number(remaining) + " with more input remaining";
    if (partial) coverage_ += "; " + number(partial) + " partial decoded source";
    if (no_page) coverage_ += "; " + number(no_page) + " without a loaded page";
    if (!reasons.empty()) coverage_ += "; " + reasons.Left(512);
    render();
}
void SearchView::render() {
    if (!filter_work_) return;
    const auto generation = filter_work_->generation.fetch_add(1, std::memory_order_acq_rel) + 1;
    const auto needle = filter_->GetValue().Lower().utf8_string();
    {
        std::lock_guard lock(filter_work_->mutex);
        filter_work_->request = FilterWork::Request{generation, rows_, needle};
        filter_work_->completion.reset();
    }
    // While a new filter is being computed, remove all selectable rows so an
    // old filter can never navigate to a result that no longer matches.
    visible_.reset();
    table_->populate(0, {});
    previous_->Disable();
    next_->Disable();
    copy_->Disable();
    export_->Disable();
    const auto status = wxString("Filtering ") + number(rows_ ? rows_->items.size() : 0) + " loaded search results…";
    status_->SetLabel(status);
    status_->SetToolTip(status);
    preview_->ChangeValue("Filtering loaded search results; navigation is paused until the current filter finishes.");
    if (!filter_timer_.IsRunning()) filter_timer_.Start(25);
    filter_work_->ready.notify_one();
}
void SearchView::poll_filter() {
    if (!filter_work_) return;
    std::optional<FilterWork::Completion> completion;
    {
        std::lock_guard lock(filter_work_->mutex);
        if (filter_work_->completion) {
            completion = std::move(filter_work_->completion);
            filter_work_->completion.reset();
        }
    }
    if (!completion || completion->generation != filter_work_->generation.load(std::memory_order_acquire) ||
        completion->rows != rows_) return;
    filter_timer_.Stop();
    auto visible = std::make_shared<std::vector<std::size_t>>(std::move(completion->visible));
    std::optional<std::size_t> selected;
    const auto rows = rows_;
    if (rows) for (std::size_t row = 0; row < visible->size(); ++row) {
        const auto &item = rows->items[(*visible)[row]];
        if (selected_document_ && item.document == *selected_document_ && item.index == selected_index_ && item.page == selected_page_)
            selected = row;
    }
    visible_ = visible;
    table_->populate(visible->size(), [rows, visible](std::size_t row, int column) {
        if (!rows || row >= visible->size() || column < 0 || column >= 6) return wxString{};
        return rows->items[(*visible)[row]].cells[column];
    });
    table_->fit_columns({0, 1, 2}, {});
    if (selected) table_->select_row(*selected);
    const auto status = number(visible->size()) + " visible / " + number(rows ? rows->items.size() : 0) +
                        " loaded matches; " + coverage_;
    status_->SetLabel(status);
    status_->SetToolTip(status);
    copy_->Enable(rows && rows->searched);
    // An empty export is useful evidence when a metadata filter matches no loaded rows.
    export_->Enable(rows && rows->searched);
    show_preview();
    Layout();
}
void SearchView::step(bool forward) {
    if (!visible_ || visible_->empty()) return;
    const auto selected = table_->selected_row();
    const auto row = !selected ? (forward ? 0 : visible_->size() - 1)
                              : (forward ? std::min(*selected + 1, visible_->size() - 1)
                                         : (*selected ? *selected - 1 : 0));
    table_->select_row(row);
    table_->activate(row);
}
void SearchView::show_preview() {
    const auto selected = table_->selected_row();
    const bool valid = rows_ && visible_ && selected && *selected < visible_->size();
    previous_->Enable(visible_ && !visible_->empty() && (!valid || *selected > 0));
    next_->Enable(visible_ && !visible_->empty() && (!valid || *selected + 1 < visible_->size()));
    if (!valid) {
        preview_->ChangeValue(selected_page_ ? "Selected result is hidden by the filter. Clear it to restore selection."
                                            : "Select a result to preview up to 64 effective source bytes.");
        return;
    }
    const auto &item = rows_->items[(*visible_)[*selected]];
    wxString result = item.label + "; history result " + number(item.index + 1) + "; " + item.cells[1] +
                      "; " + item.cells[2] + "; " + number(item.match.size) + " matched bytes\n";
    if (!item.project || !item.project->effective || !item.project->state ||
        item.project->state->revisions.bytes != item.page->source_key.byte_revision) {
        preview_->ChangeValue(result + "Effective-byte preview unavailable for this source revision.");
        return;
    }
    // A selected result is the only place bytes are read. Split instruction backing
    // stays in instruction order, with both bytes and ranges bounded independently.
    constexpr std::size_t max_bytes = 64, max_ranges = 64;
    std::size_t shown = 0, ranges = 0;
    bool truncated = item.match.size > max_bytes;
    const auto append = [&](const FileRange &range) {
        if (shown == max_bytes || ranges == max_ranges) { truncated = true; return false; }
        ++ranges;
        const auto count = static_cast<std::size_t>(std::min<std::uint64_t>(range.size, max_bytes - shown));
        if (!count) return true;
        if (range.begin.value > item.project->effective->size() ||
            count > item.project->effective->size() - range.begin.value) {
            result += "Effective source range unavailable at " + location_text(range.begin) + ".\n";
            return false;
        }
        const auto bytes = item.project->effective->read_at(range.begin, count);
        if (!bytes || bytes.value().bytes.size() != count) {
            result += "Effective source read failed at " + location_text(range.begin) + ".\n";
            return false;
        }
        for (std::size_t start = 0; start < count; start += 16) {
            const auto line = bytes.value().bytes.subspan(start, std::min<std::size_t>(16, count - start));
            auto hex = hex_bytes(line);
            wxString ascii;
            for (const auto byte : line) {
                const auto value = std::to_integer<unsigned>(byte);
                ascii += value >= 32 && value <= 126 ? wxChar(value) : wxChar('.');
            }
            result += location_text(FileOffset{range.begin.value + start}) + "  " + hex.Pad(47 - hex.size()) + "  |" + ascii + "|\n";
        }
        shown += count;
        truncated = truncated || count < range.size;
        return true;
    };
    if (item.match.file_ranges.empty()) append({item.match.offset, item.match.size});
    else for (const auto &range : item.match.file_ranges) if (!append(range)) break;
    result += "Effective bytes shown: " + number(shown) + (truncated ? " (preview capped at 64 bytes / 64 ranges)." : ".");
    if (item.match.instruction_address) result += " Immediate result: bytes belong to the instruction backing.";
    preview_->ChangeValue(result);
}
wxString SearchView::export_text() const {
    wxString result = "# HexLab loaded search results (TSV; escaped backslash, tab, CR and LF)\n";
    result += wxString("# Scope\t") + (all_documents_ ? "All open search documents" : "Active document") + "\n";
    result += "# Coverage\t" + tsv_field(coverage_) + "\n";
    result += "# Metadata filter (case-insensitive)\t" + tsv_field(filter_->GetValue()) + "\n";
    result += "# Rows\t" + number(visible_ ? visible_->size() : 0) + " visible / " + number(rows_ ? rows_->items.size() : 0) + " loaded\n";
    result += "document_id\tdocument\thistory_result\tfile_offset\tvirtual_address\tbyte_size\toperand\tbyte_revision\tdecision_revision\n";
    if (rows_ && visible_) for (const auto index : *visible_) {
        const auto &item = rows_->items[index];
        const std::array<wxString, 9> fields{number(item.document.value), item.label, number(item.index + 1),
            item.cells[1], item.cells[2], number(item.match.size), item.cells[4],
            number(item.page->source_key.byte_revision), number(item.page->source_key.decision_revision)};
        for (std::size_t column = 0; column < fields.size(); ++column) {
            if (column) result += '\t';
            result += tsv_field(fields[column]);
        }
        result += '\n';
    }
    return result;
}
void SearchView::copy_results() {
    if (!rows_ || !visible_ || !rows_->searched) return;
    if (!wxTheClipboard || !wxTheClipboard->Open()) {
        wxMessageBox("Could not open the clipboard.", "Copy search results", wxOK | wxICON_ERROR, this);
        return;
    }
    const bool copied = wxTheClipboard->SetData(new wxTextDataObject(export_text()));
    wxTheClipboard->Close();
    if (!copied) wxMessageBox("Could not copy search results.", "Copy search results", wxOK | wxICON_ERROR, this);
}
void SearchView::export_results() {
    if (!rows_ || !visible_) return;
    // Snapshot before the modal dialog: completion of background pages while the
    // picker is open must not silently change the rows or coverage being exported.
    const auto output = export_text();
    const auto protected_paths = rows_->protected_paths;
    wxFileDialog dialog(this, "Export filtered loaded search results", "", "search-results.tsv",
                        "TSV files (*.tsv)|*.tsv|All files (*.*)|*.*", wxFD_SAVE | wxFD_OVERWRITE_PROMPT);
    if (dialog.ShowModal() != wxID_OK) return;
    auto publication = FilePublication::create(std::filesystem::path(dialog.GetPath().ToStdWstring()),
                                               ExistingFilePolicy::replace, protected_paths, {});
    if (!publication) {
        wxMessageBox(text(publication.error().message), "Export search results", wxOK | wxICON_ERROR, this);
        return;
    }
    const auto encoded = output.utf8_str();
    const auto written = publication.value()->append(std::as_bytes(std::span(encoded.data(), encoded.length())));
    if (!written) {
        wxMessageBox(text(written.error().message), "Export search results", wxOK | wxICON_ERROR, this);
        return;
    }
    const auto published = publication.value()->publish();
    if (!published) wxMessageBox(text(published.error().message), "Export search results", wxOK | wxICON_ERROR, this);
}
} // namespace hexlab::desktop
