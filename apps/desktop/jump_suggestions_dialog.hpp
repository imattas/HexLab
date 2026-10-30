#pragma once

#include "jump_resolver.hpp"
#include <wx/button.h>
#include <wx/choice.h>
#include <wx/clipbrd.h>
#include <wx/config.h>
#include <wx/dataobj.h>
#include <wx/dialog.h>
#include <wx/listbox.h>
#include <wx/sizer.h>
#include <wx/stattext.h>
#include <wx/textctrl.h>
#include <wx/timer.h>
#include <algorithm>
#include <functional>
#include <optional>
#include <mutex>
#include <thread>
#include <cstdint>
#include <atomic>

namespace hexlab::desktop {

// Each refinement searches the original captured sources, rather than the
// previous capped results. The caller revalidates source ownership on navigation.
class JumpSuggestionsDialog final : public wxDialog {
public:
    using Search = std::function<NamedLocationSearch(const wxString &, NamedLocationScope, NamedLocationSearchMode,
                                                      const std::atomic_bool &)>;
    using Describe = std::function<wxString(const NamedLocationCandidate &)>;
    JumpSuggestionsDialog(wxWindow *parent, const wxString &query, Search search, Describe describe,
                          NamedLocationSearchMode initial_mode = NamedLocationSearchMode::contains,
                          const wxString &title = "Jump name suggestions",
                          const wxString &instructions = "Search this document's captured names, then choose a destination:",
                          bool allow_fuzzy = true, bool background_search = false)
        : wxDialog(parent, wxID_ANY, title, wxDefaultPosition, wxDefaultSize,
                   wxDEFAULT_DIALOG_STYLE | wxRESIZE_BORDER),
          search_(std::move(search)), describe_(std::move(describe)), timer_(this),
          poll_timer_(this), background_search_(background_search), async_state_(std::make_shared<AsyncState>()) {
        auto *layout = new wxBoxSizer(wxVERTICAL);
        auto *instructions_label = new wxStaticText(this, wxID_ANY, instructions);
        instructions_label->Wrap(FromDIP(640));
        layout->Add(instructions_label, 0, wxALL, FromDIP(10));
        query_ = new wxTextCtrl(this, wxID_ANY, query.Left(256), wxDefaultPosition, wxDefaultSize, wxTE_PROCESS_ENTER);
        query_->SetName("jump-name-query");
        query_->SetMaxLength(256);
        layout->Add(query_, 0, wxLEFT | wxRIGHT | wxBOTTOM | wxEXPAND, FromDIP(10));
        auto *options = new wxBoxSizer(wxHORIZONTAL);
        scope_ = new wxChoice(this, wxID_ANY);
        scope_->SetName("jump-name-source");
        for (const auto *label : {"All name sources", "Image symbols", "Annotation names", "Bookmarks",
                                 "Recovered functions", "Sections / segments"}) scope_->Append(label);
        scope_->SetSelection(0);
        mode_ = new wxChoice(this, wxID_ANY);
        mode_->SetName("jump-name-match-mode");
        for (const auto *label : {"Contains", "Starts with", "Exact name"}) mode_->Append(label);
        if (allow_fuzzy) mode_->Append("Fuzzy (ranked)");
        mode_->SetSelection(static_cast<int>(initial_mode));
        load_preferences(query);
        options->Add(scope_, 1, wxRIGHT, FromDIP(8));
        options->Add(mode_, 1);
        layout->Add(options, 0, wxLEFT | wxRIGHT | wxBOTTOM | wxEXPAND, FromDIP(10));
        list_ = new wxListBox(this, wxID_ANY);
        list_->SetName("jump-name-results");
        layout->Add(list_, 1, wxLEFT | wxRIGHT | wxEXPAND, FromDIP(10));
        preview_ = new wxTextCtrl(this, wxID_ANY, {}, wxDefaultPosition, FromDIP(wxSize(-1, 56)),
                                  wxTE_MULTILINE | wxTE_READONLY);
        preview_->SetName("jump-name-destination-preview");
        layout->Add(preview_, 0, wxALL | wxEXPAND, FromDIP(10));
        status_ = new wxStaticText(this, wxID_ANY, "");
        status_->SetName("jump-name-result-status");
        layout->Add(status_, 0, wxLEFT | wxRIGHT | wxBOTTOM, FromDIP(10));
        auto *buttons = new wxBoxSizer(wxHORIZONTAL);
        auto *reset_search = new wxButton(this, wxID_ANY, "Reset search");
        reset_search->SetName("jump-name-reset-search");
        buttons->Add(reset_search, 0, wxRIGHT, FromDIP(8));
        copy_selected_ = new wxButton(this, wxID_ANY, "Copy selected destination");
        copy_selected_->SetName("jump-name-copy-selected");
        copy_selected_->Enable(false);
        buttons->Add(copy_selected_, 0, wxRIGHT, FromDIP(8));
        buttons->AddStretchSpacer();
        buttons->Add(new wxButton(this, wxID_CANCEL, "Cancel"), 0, wxRIGHT, FromDIP(8));
        accept_ = new wxButton(this, wxID_OK, "Go to selected");
        accept_->Enable(false);
        buttons->Add(accept_);
        layout->Add(buttons, 0, wxALL | wxEXPAND, FromDIP(10));
        SetSizer(layout);
        SetSize(FromDIP(wxSize(700, 580)));
        SetMinSize(FromDIP(wxSize(540, 420)));
        CentreOnParent();

        query_->Bind(wxEVT_TEXT, [this](wxCommandEvent &) {
            // A pending query must never navigate a result from the old text.
            ++generation_;
            candidates_.clear(); list_->Clear(); update_accept();
            status_->SetLabel("Waiting for search refinement...");
            timer_.StartOnce(120);
        });
        for (auto *choice : {scope_, mode_})
            choice->Bind(wxEVT_CHOICE, [this](wxCommandEvent &) { refresh(); });
        reset_search->Bind(wxEVT_BUTTON, [this](wxCommandEvent &) {
            ++generation_;
            query_->ChangeValue({});
            scope_->SetSelection(0);
            mode_->SetSelection(0);
            refresh();
            query_->SetFocus();
        });
        copy_selected_->Bind(wxEVT_BUTTON, [this](wxCommandEvent &) { copy_selected_destination(); });
        Bind(wxEVT_TIMER, [this](wxTimerEvent &) { refresh(); }, timer_.GetId());
        Bind(wxEVT_TIMER, [this](wxTimerEvent &) { poll_background_search(); }, poll_timer_.GetId());
        list_->Bind(wxEVT_LISTBOX, [this](wxCommandEvent &) { update_accept(); });
        list_->Bind(wxEVT_LISTBOX_DCLICK, [this](wxCommandEvent &) {
            if (selected_candidate()) EndModal(wxID_OK);
        });
        query_->Bind(wxEVT_TEXT_ENTER, [this](wxCommandEvent &) {
            if (timer_.IsRunning()) refresh();
            if (candidates_.size() == 1) EndModal(wxID_OK);
            else list_->SetFocus();
        });
        Bind(wxEVT_CHAR_HOOK, [this](wxKeyEvent &event) {
            if (query_->HasFocus() && !candidates_.empty() &&
                (event.GetKeyCode() == WXK_DOWN || event.GetKeyCode() == WXK_UP)) {
                const auto current = std::max(0, list_->GetSelection());
                const auto next = std::clamp(current + (event.GetKeyCode() == WXK_DOWN ? 1 : -1),
                                             0, static_cast<int>(candidates_.size()) - 1);
                list_->SetSelection(next); list_->SetFirstItem(next); update_accept();
                return;
            }
            if (list_->HasFocus() && event.GetKeyCode() == WXK_RETURN && selected_candidate()) {
                EndModal(wxID_OK); return;
            }
            event.Skip();
        });
        refresh();
        if (background_search_) poll_timer_.Start(25);
    }
    ~JumpSuggestionsDialog() override {
        timer_.Stop();
        poll_timer_.Stop();
        {
            std::lock_guard lock(async_state_->mutex);
            async_state_->closing = true;
            if (async_state_->active_cancel)
                async_state_->active_cancel->store(true, std::memory_order_relaxed);
            async_state_->queued.reset();
        }
        save_preferences();
    }

    std::optional<NamedLocationCandidate> selected_candidate() const {
        const int selected = list_->GetSelection();
        if (selected == wxNOT_FOUND || static_cast<std::size_t>(selected) >= candidates_.size()) return {};
        return candidates_[static_cast<std::size_t>(selected)];
    }

private:
    struct AsyncRequest {
        std::uint64_t generation = 0;
        wxString query;
        NamedLocationScope scope = NamedLocationScope::all;
        NamedLocationSearchMode mode = NamedLocationSearchMode::contains;
        std::shared_ptr<std::atomic_bool> cancelled = std::make_shared<std::atomic_bool>(false);
    };
    struct AsyncResult {
        std::uint64_t generation = 0;
        NamedLocationSearch search;
    };
    struct AsyncState {
        std::mutex mutex;
        std::optional<AsyncRequest> queued;
        std::optional<AsyncResult> completed;
        bool running = false;
        bool closing = false;
        std::shared_ptr<std::atomic_bool> active_cancel;
    };
    static void launch_async(const std::shared_ptr<AsyncState> &state, Search search, AsyncRequest request) {
        try {
            std::thread([state, search = std::move(search), request = std::move(request)]() mutable {
                NamedLocationSearch result;
                try {
                    result = search(request.query, request.scope, request.mode, *request.cancelled);
                } catch (...) {
                    result.truncated = true;
                    result.limitation = "background name search failed";
                }
                std::optional<AsyncRequest> next;
                {
                    std::lock_guard lock(state->mutex);
                    state->running = false;
                    if (state->closing) return;
                    state->completed = AsyncResult{request.generation, std::move(result)};
                    if (state->queued) {
                        next = std::move(state->queued);
                        state->queued.reset();
                        state->running = true;
                        state->active_cancel = next->cancelled;
                    } else {
                        state->active_cancel.reset();
                    }
                }
                if (next) launch_async(state, std::move(search), std::move(*next));
            }).detach();
        } catch (...) {
            NamedLocationSearch result;
            result.truncated = true;
            result.limitation = "background name search could not start";
            std::lock_guard lock(state->mutex);
            state->running = false;
            if (!state->closing) state->completed = AsyncResult{request.generation, std::move(result)};
        }
    }
    void request_background_search() {
        AsyncRequest request{++generation_, query_->GetValue(),
            static_cast<NamedLocationScope>(scope_->GetSelection()),
            static_cast<NamedLocationSearchMode>(mode_->GetSelection())};
        candidates_.clear();
        list_->Clear();
        update_accept();
        status_->SetLabel("Searching captured names in the background...");
        {
            std::lock_guard lock(async_state_->mutex);
            if (async_state_->closing) return;
            if (async_state_->running) {
                if (async_state_->active_cancel)
                    async_state_->active_cancel->store(true, std::memory_order_relaxed);
                async_state_->queued = std::move(request);
                return;
            }
            async_state_->running = true;
            async_state_->active_cancel = request.cancelled;
        }
        launch_async(async_state_, search_, std::move(request));
    }
    void poll_background_search() {
        if (!background_search_) return;
        std::optional<AsyncResult> completed;
        {
            std::lock_guard lock(async_state_->mutex);
            completed = std::move(async_state_->completed);
            async_state_->completed.reset();
        }
        if (completed && completed->generation == generation_)
            show_result(std::move(completed->search));
    }
    void load_preferences(const wxString &initial_query) {
        auto *config = wxConfigBase::Get(false);
        if (!config) return;
        long saved_scope = 0;
        if (config->Read("JumpNameSearch/Scope", &saved_scope) && saved_scope >= 0 && saved_scope <= 5)
            scope_->SetSelection(static_cast<int>(saved_scope));
        long saved_mode = -1;
        const long maximum_mode = mode_->GetCount() > 3 ? 3 : 2;
        if (config->Read("JumpNameSearch/Mode", &saved_mode) && saved_mode >= 0 && saved_mode <= maximum_mode)
            mode_->SetSelection(static_cast<int>(saved_mode));
        if (initial_query.empty()) {
            wxString saved_query;
            if (config->Read("JumpNameSearch/Query", &saved_query) && saved_query.length() <= 256)
                query_->ChangeValue(saved_query);
        }
    }
    void save_preferences() {
        auto *config = wxConfigBase::Get(false);
        if (!config) return;
        config->Write("JumpNameSearch/Scope", static_cast<long>(scope_->GetSelection()));
        config->Write("JumpNameSearch/Mode", static_cast<long>(mode_->GetSelection()));
        config->Write("JumpNameSearch/Query", query_->GetValue().Left(256));
        config->Flush();
    }
    void refresh() {
        timer_.Stop();
        if (background_search_) {
            request_background_search();
            return;
        }
        const std::atomic_bool not_cancelled{false};
        show_result(search_(query_->GetValue(), static_cast<NamedLocationScope>(scope_->GetSelection()),
                            static_cast<NamedLocationSearchMode>(mode_->GetSelection()), not_cancelled));
    }
    void show_result(NamedLocationSearch result) {
        const auto selected = selected_candidate();
        candidates_ = std::move(result.candidates);
        wxArrayString rows;
        int preserved = 0;
        for (std::size_t i = 0; i < candidates_.size(); ++i) {
            rows.Add(describe_(candidates_[i]));
            if (selected && candidates_[i].location == selected->location &&
                candidates_[i].document == selected->document) preserved = static_cast<int>(i);
        }
        list_->Set(rows);
        if (!candidates_.empty()) list_->SetSelection(preserved);
        auto needle = query_->GetValue(); needle.Trim(true).Trim(false);
        const auto required = mode_->GetSelection() == static_cast<int>(NamedLocationSearchMode::exact) ? 1u : 2u;
        status_->SetLabel(needle.length() < required
            ? wxString("Enter at least two characters, or one character for Exact name.")
            : wxString::Format("%zu destination(s)", candidates_.size()) +
                (!result.limitation.empty() ? "; " + result.limitation : result.truncated
                ? wxString("; result limit reached. Refine to search the captured sources again.") : wxString{}));
        status_->Wrap(FromDIP(640));
        update_accept();
        Layout();
    }
    void update_accept() {
        const auto selected = selected_candidate();
        accept_->Enable(selected.has_value());
        copy_selected_->Enable(selected.has_value());
        preview_->ChangeValue(selected ? describe_(*selected) : wxString("Select a destination to inspect its name and location."));
    }
    void copy_selected_destination() {
        const auto selected = selected_candidate();
        if (!selected) {
            status_->SetLabel("Select a destination before copying it.");
            return;
        }
        const auto output = wxString("Name: ") + selected->name + "\nDestination: " + describe_(*selected);
        const auto encoded = output.ToUTF8();
        if (!encoded || encoded.length() > 8u * 1024u) {
            status_->SetLabel("The selected destination exceeds the 8 KiB clipboard limit.");
            return;
        }
        if (!wxTheClipboard || !wxTheClipboard->Open()) {
            status_->SetLabel("The system clipboard is unavailable; no destination was copied.");
            return;
        }
        const bool copied = wxTheClipboard->SetData(new wxTextDataObject(output));
        wxTheClipboard->Close();
        status_->SetLabel(copied ? "Copied selected destination." : "Could not copy selected destination.");
    }
    Search search_;
    Describe describe_;
    std::vector<NamedLocationCandidate> candidates_;
    wxTextCtrl *query_ = nullptr, *preview_ = nullptr;
    wxChoice *scope_ = nullptr, *mode_ = nullptr;
    wxListBox *list_ = nullptr;
    wxStaticText *status_ = nullptr;
    wxButton *accept_ = nullptr;
    wxButton *copy_selected_ = nullptr;
    wxTimer timer_;
    wxTimer poll_timer_;
    bool background_search_ = false;
    std::uint64_t generation_ = 0;
    std::shared_ptr<AsyncState> async_state_;
};
} // namespace hexlab::desktop
