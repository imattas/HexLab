#include "archive_view.hpp"
#include <wx/listctrl.h>
#include <wx/sizer.h>
#include <wx/button.h>
#include <wx/settings.h>
#include <wx/stattext.h>

namespace hexlab::desktop {
ArchiveView::ArchiveView(wxWindow* parent, const ArArchive& archive)
    : wxDialog(parent, wxID_ANY, "Browse ar archive", wxDefaultPosition, wxDefaultSize, wxDEFAULT_DIALOG_STYLE | wxRESIZE_BORDER) {
    auto* box = new wxBoxSizer(wxVERTICAL);
    members_ = new wxListCtrl(this, wxID_ANY, wxDefaultPosition, wxDefaultSize, wxLC_REPORT | wxLC_SINGLE_SEL);
    members_->SetName("ar-member-list");
    members_->SetToolTip("Archive members. Use Up/Down to select and Enter or double-click to open a regular member.");
    members_->AppendColumn("Index", wxLIST_FORMAT_RIGHT, FromDIP(64));
    members_->AppendColumn("Member", wxLIST_FORMAT_LEFT, FromDIP(390));
    members_->AppendColumn("Size", wxLIST_FORMAT_RIGHT, FromDIP(110));
    members_->AppendColumn("Kind", wxLIST_FORMAT_LEFT, FromDIP(130));
    regular_.reserve(archive.members.size());
    for (std::size_t i = 0; i < archive.members.size(); ++i) {
        const auto& member = archive.members[i];
        regular_.push_back(member.kind == ArMemberKind::regular);
        long row = members_->InsertItem(static_cast<long>(i), wxString::Format("%llu", static_cast<unsigned long long>(i)));
        members_->SetItem(row, 1, wxString::FromUTF8(member.name.c_str()));
        members_->SetItem(row, 2, wxString::Format("%llu", static_cast<unsigned long long>(member.size)));
        const char* kind = member.kind == ArMemberKind::regular ? "regular" :
                           member.kind == ArMemberKind::thin_external ? "external thin member" :
                           member.kind == ArMemberKind::symbol_index ? "symbol index" :
                           member.kind == ArMemberKind::member_table ? "member table" : "long-name table";
        members_->SetItem(row, 3, kind);
        members_->SetItemData(row, static_cast<long>(i));
        if (member.kind != ArMemberKind::regular)
            members_->SetItemTextColour(row, wxSystemSettings::GetColour(wxSYS_COLOUR_GRAYTEXT));
    }
    box->Add(members_, 1, wxEXPAND | wxLEFT | wxRIGHT | wxTOP, FromDIP(8));
    index_status_ = new wxStaticText(this, wxID_ANY, archive.thin
        ? "GNU thin archive: external member contents are not resolved"
        : "Indexed symbols");
    index_status_->SetName("ar-index-status");
    box->Add(index_status_, 0, wxEXPAND | wxLEFT | wxRIGHT | wxTOP, FromDIP(8));
    symbols_ = new wxListCtrl(this, wxID_ANY, wxDefaultPosition, wxSize(-1, FromDIP(130)), wxLC_REPORT | wxLC_SINGLE_SEL);
    symbols_->SetName("ar-symbol-list");
    symbols_->SetToolTip("Indexed symbols. Use Up/Down to select; selecting a symbol also selects its member above.");
    symbols_->AppendColumn("Symbol", wxLIST_FORMAT_LEFT, FromDIP(300));
    symbols_->AppendColumn("Member", wxLIST_FORMAT_LEFT, FromDIP(300));
    symbols_->AppendColumn("Member index", wxLIST_FORMAT_RIGHT, FromDIP(100));
    for (const auto& symbol : archive.symbols) {
        if (symbol.member_index >= archive.members.size()) continue;
        const long row = symbols_->InsertItem(symbols_->GetItemCount(), wxString::FromUTF8(symbol.name.c_str()));
        symbols_->SetItem(row, 1, wxString::FromUTF8(archive.members[symbol.member_index].name.c_str()));
        symbols_->SetItem(row, 2, wxString::Format("%llu", static_cast<unsigned long long>(symbol.member_index)));
        symbols_->SetItemData(row, static_cast<long>(symbol.member_index));
    }
    if (!archive.has_symbol_index) {
        index_status_->SetLabel("Archive has no supported symbol index");
    } else if (!archive.symbol_index_complete) {
        index_status_->SetLabel(wxString::Format("Indexed symbols (index incomplete; %llu entries available)",
            static_cast<unsigned long long>(symbols_->GetItemCount())));
    } else {
        index_status_->SetLabel(wxString::Format("Indexed symbols (%llu)",
            static_cast<unsigned long long>(symbols_->GetItemCount())));
    }
    box->Add(symbols_, 0, wxEXPAND | wxLEFT | wxRIGHT, FromDIP(8));
    auto* buttons = new wxStdDialogButtonSizer();
    auto* open = new wxButton(this, wxID_OK, "Open Member");
    open->SetName("ar-open-member");
    buttons->AddButton(open);
    buttons->AddButton(new wxButton(this, wxID_CANCEL));
    buttons->Realize();
    box->Add(buttons, 0, wxEXPAND | wxALL, FromDIP(8));
    SetSizer(box);
    SetClientSize(FromDIP(wxSize(760, 440)));
    Bind(wxEVT_LIST_ITEM_ACTIVATED, [this](wxListEvent&) { if (selected_member()) EndModal(wxID_OK); }, members_->GetId());
    Bind(wxEVT_LIST_ITEM_SELECTED, [this](wxListEvent& event) {
        const auto member = static_cast<long>(event.GetData());
        for (long row = 0; row < members_->GetItemCount(); ++row) {
            if (members_->GetItemData(row) == member) {
                members_->SetItemState(row, wxLIST_STATE_SELECTED, wxLIST_STATE_SELECTED);
                members_->EnsureVisible(row);
                break;
            }
        }
    }, symbols_->GetId());
    Bind(wxEVT_BUTTON, [this](wxCommandEvent& event) {
        if (event.GetId() == wxID_OK && !selected_member()) return;
        EndModal(event.GetId());
    });
    SetName("ar-archive-browser");
}
std::optional<std::size_t> ArchiveView::selected_member() const {
    const long row = members_->GetNextItem(-1, wxLIST_NEXT_ALL, wxLIST_STATE_SELECTED);
    if (row < 0) return {};
    const auto index = static_cast<std::size_t>(members_->GetItemData(row));
    if (index >= regular_.size() || !regular_[index]) return {};
    return index;
}
}
