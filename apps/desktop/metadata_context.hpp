#pragma once

#include "data_views.hpp"
#include "hexlab/workspace/document.hpp"
#include <algorithm>
#include <set>
#include <wx/sizer.h>
#include <wx/textctrl.h>
#include <wx/tglbtn.h>
#include <wx/wrapsizer.h>
#include <wx/clipbrd.h>
#include <wx/dataobj.h>
#include <wx/msgdlg.h>

namespace hexlab::desktop {
// A bounded unfiltered address index distinguishes a filter-hidden row from
// no known exact match without rescanning all metadata on every cursor move.
class MetadataContextIndex {
public:
    void bind(std::shared_ptr<const DocumentSnapshot> document) {
        if (document == document_) return;
        document_ = std::move(document);
        imports_.clear(); exports_.clear();
        imports_complete = exports_complete = true;
        if (!document_) return;
        const auto &metadata = document_->metadata_view();
        imports_complete = metadata.imports.size() <= record_limit;
        exports_complete = metadata.exports.size() <= record_limit;
        for (std::size_t row = 0; row < std::min(metadata.imports.size(), record_limit); ++row)
            imports_.insert(key(metadata.imports[row].iat));
        for (std::size_t row = 0; row < std::min(metadata.exports.size(), record_limit); ++row)
            if (metadata.exports[row].address) exports_.insert(key(*metadata.exports[row].address));
    }
    bool has_import(Address address) const { return imports_.contains(key(address)); }
    bool has_export(Address address) const { return exports_.contains(key(address)); }
    bool imports_complete = true, exports_complete = true;
private:
    static constexpr std::size_t record_limit = 65536;
    using Key = std::pair<std::uint32_t, std::uint64_t>;
    static Key key(Address address) { return {address.space.value, address.offset}; }
    std::shared_ptr<const DocumentSnapshot> document_;
    std::set<Key> imports_, exports_;
};

class MetadataContextBar final : public wxPanel {
public:
    explicit MetadataContextBar(wxWindow *parent, const wxString &name, bool can_reveal)
        : wxPanel(parent) {
        SetName(name);
        auto *layout = new wxBoxSizer(wxVERTICAL);
        status_ = new wxTextCtrl(this, wxID_ANY, "No document selection", wxDefaultPosition,
            FromDIP(wxSize(-1, 54)), wxTE_READONLY | wxTE_MULTILINE | wxTE_WORDWRAP);
        status_->SetName(name + "-status");
        layout->Add(status_, 0, wxEXPAND | wxALL, FromDIP(4));
        auto *actions = new wxWrapSizer(wxHORIZONTAL);
        pin_ = new wxToggleButton(this, wxID_ANY, "Pin summary");
        pin_->SetName(name + "-pin-summary");
        pin_->SetToolTip("Keep this read-only summary while the cursor moves. Unpin to follow the cursor and use its actions.");
        actions->Add(pin_, 0, wxRIGHT, FromDIP(4));
        pin_->Bind(wxEVT_TOGGLEBUTTON, [this](wxCommandEvent &) {
            if (pin_->GetValue()) {
                if (!document_ || !selection_) { pin_->SetValue(false); return; }
                pinned_summary_ = status_->GetValue().Left(summary_limit);
            }
            update(latest_document_, latest_selection_, latest_description_, latest_hidden_match_);
        });
        copy_ = new wxButton(this, wxID_ANY, "Copy summary");
        copy_->SetName(name + "-copy-summary");
        copy_->SetToolTip("Copy the visible live or pinned cursor summary to the clipboard.");
        actions->Add(copy_, 0, wxRIGHT, FromDIP(4));
        copy_->Bind(wxEVT_BUTTON, [this](wxCommandEvent &) {
            if (status_->GetValue().empty()) return;
            if (!wxTheClipboard || !wxTheClipboard->Open()) {
                wxMessageBox("Could not open the clipboard; the context summary was not copied.",
                             "Copy context summary", wxOK | wxICON_WARNING, this);
                return;
            }
            const bool copied = wxTheClipboard->SetData(new wxTextDataObject(status_->GetValue()));
            wxTheClipboard->Close();
            if (!copied)
                wxMessageBox("The clipboard rejected the context summary.",
                             "Copy context summary", wxOK | wxICON_WARNING, this);
        });
        if (can_reveal) {
            reveal_ = new wxButton(this, wxID_ANY, "Reveal cursor row");
            reveal_->SetName(name + "-reveal");
            reveal_->SetToolTip("Clear this page's filter and highlight its exact cursor match without moving the cursor.");
            actions->Add(reveal_, 0, wxRIGHT, FromDIP(4));
            reveal_->Bind(wxEVT_BUTTON, [this](wxCommandEvent &) {
                if (reveal && document_ && selection_) reveal(document_, *selection_);
            });
        }
        address_ = new wxButton(this, wxID_ANY, "Show address");
        file_ = new wxButton(this, wxID_ANY, "Show file offset");
        address_->SetName(name + "-address");
        file_->SetName(name + "-file-offset");
        address_->SetToolTip("Show the cursor's unique mapped address in Disassembly.");
        file_->SetToolTip("Show the cursor's verified original/effective source-file offset in Bytes.");
        actions->Add(address_, 0, wxRIGHT, FromDIP(4));
        actions->Add(file_);
        layout->Add(actions, 0, wxLEFT | wxRIGHT | wxBOTTOM, FromDIP(4));
        SetSizer(layout);
        address_->Bind(wxEVT_BUTTON, [this](wxCommandEvent &) {
            if (navigate && document_ && selection_ && mapped_address_)
                navigate(document_, *selection_, Location{*mapped_address_});
        });
        file_->Bind(wxEVT_BUTTON, [this](wxCommandEvent &) {
            if (navigate && document_ && selection_ && mapped_file_)
                navigate(document_, *selection_, Location{*mapped_file_});
        });
        update({}, {}, {}, false);
    }
    void update(std::shared_ptr<const DocumentSnapshot> document, std::optional<Location> selection,
                const wxString &description, bool hidden_match) {
        latest_document_ = document;
        latest_selection_ = selection;
        latest_description_ = description.Left(summary_limit);
        latest_hidden_match_ = hidden_match;
        if (pin_->GetValue() && document_ && document == document_) {
            status_->ChangeValue("Pinned summary (cursor actions paused; unpin to follow)\n" + pinned_summary_);
            copy_->Enable(true);
            if (reveal_) reveal_->Enable(false);
            address_->Enable(false); file_->Enable(false);
            return;
        }
        // The immutable owner changed: an old pin must not cross tabs, project
        // revisions, input replacement, or document closure.
        pin_->SetValue(false);
        pinned_summary_.clear();
        document_ = std::move(document);
        selection_ = std::move(selection);
        mapped_address_.reset(); mapped_file_.reset();
        wxString status = "No document selection";
        if (document_ && document_->image && selection_) {
            const bool same_backing = document_->image->storage().get() == &document_->file_storage();
            status = wxString::Format("Document %llu: ", static_cast<unsigned long long>(document_->id.value)) +
                location_text(*selection_, document_->image.get());
            if (const auto *address = std::get_if<Address>(&*selection_)) {
                if (document_->image->segment_at(*address)) mapped_address_ = *address;
                if (same_backing) {
                    auto file = document_->image->to_file_offset(*address);
                    if (file && file.value().value < document_->file_storage().size()) mapped_file_ = file.value();
                }
            } else {
                const auto file = std::get<FileOffset>(*selection_);
                if (file.value < document_->file_storage().size()) mapped_file_ = file;
                if (same_backing) {
                auto mapped = document_->image->to_address(file);
                if (mapped) mapped_address_ = mapped.value();
                }
            }
            if (!description.empty()) status += "\n" + description;
            if (!mapped_file_) status += " | No verified source-file offset";
            if (!mapped_address_) status += " | No unique mapped virtual address";
        }
        status_->ChangeValue(status);
        pin_->Enable(document_ && document_->image && selection_);
        copy_->Enable(document_ && document_->image && selection_);
        if (reveal_) reveal_->Enable(document_ && selection_ && hidden_match);
        address_->Enable(mapped_address_.has_value());
        file_->Enable(mapped_file_.has_value());
    }
    std::function<void(std::shared_ptr<const DocumentSnapshot>, Location)> reveal;
    std::function<void(std::shared_ptr<const DocumentSnapshot>, Location, Location)> navigate;
private:
    static constexpr std::size_t summary_limit = 8192;
    std::shared_ptr<const DocumentSnapshot> document_;
    std::shared_ptr<const DocumentSnapshot> latest_document_;
    std::optional<Location> selection_;
    std::optional<Location> latest_selection_;
    wxString latest_description_, pinned_summary_;
    bool latest_hidden_match_ = false;
    std::optional<Address> mapped_address_;
    std::optional<FileOffset> mapped_file_;
    wxTextCtrl *status_ = nullptr;
    wxToggleButton *pin_ = nullptr;
    wxButton *copy_ = nullptr, *reveal_ = nullptr, *address_ = nullptr, *file_ = nullptr;
};
} // namespace hexlab::desktop
