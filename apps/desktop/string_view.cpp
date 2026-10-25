#include "string_view.hpp"

#include "hexlab/analysis/references.hpp"
#include "hexlab/image/image.hpp"
#include "hexlab/workspace/project.hpp"
#include <algorithm>
#include <wx/sizer.h>

namespace hexlab::desktop {
namespace {
wxString encoding_text(StringEncoding encoding) {
    switch (encoding) {
    case StringEncoding::ascii: return "ASCII";
    case StringEncoding::utf16le: return "UTF-16 LE";
    case StringEncoding::utf8: return "UTF-8";
    case StringEncoding::utf16be: return "UTF-16 BE";
    case StringEncoding::utf32le: return "UTF-32 LE";
    case StringEncoding::utf32be: return "UTF-32 BE";
    case StringEncoding::windows1252: return "Windows-1252";
    case StringEncoding::windows1251: return "Windows-1251";
    case StringEncoding::windows1250: return "Windows-1250";
    }
    return "unknown";
}
wxString reference_kind_text(ReferenceKind kind) {
    switch (kind) {
    case ReferenceKind::call: return "call";
    case ReferenceKind::jump: return "jump";
    case ReferenceKind::conditional_jump: return "conditional jump";
    case ReferenceKind::memory_read: return "read";
    case ReferenceKind::memory_write: return "write";
    case ReferenceKind::memory_read_write: return "read/write";
    case ReferenceKind::memory_address: return "address";
    case ReferenceKind::imported_call: return "imported call";
    case ReferenceKind::imported_jump: return "imported jump";
    case ReferenceKind::user_code: return "user code";
    case ReferenceKind::user_data: return "user data";
    case ReferenceKind::relocation: return "relocation";
    case ReferenceKind::dyld_fixup: return "dyld fixup";
    }
    return "unknown";
}
}

StringBrowserView::StringBrowserView(wxWindow *parent) : wxPanel(parent), filter_timer_(this) {
    auto *layout = new wxBoxSizer(wxVERTICAL);
    filter_ = new wxTextCtrl(this, wxID_ANY, {}, wxDefaultPosition, wxDefaultSize, wxTE_PROCESS_ENTER);
    filter_->SetName("strings-filter");
    filter_->SetHint("Filter strings by text, address, or encoding");
    layout->Add(filter_, 0, wxEXPAND | wxALL, FromDIP(4));

    auto *splitter = new wxSplitterWindow(this, wxID_ANY, wxDefaultPosition, wxDefaultSize,
                                           wxSP_LIVE_UPDATE | wxSP_3D);
    auto *string_panel = new wxPanel(splitter);
    auto *string_layout = new wxBoxSizer(wxVERTICAL);
    strings_ = new VirtualTable(string_panel, "strings-list", {"Address / offset", "Text", "Encoding", "Bytes"});
    string_layout->Add(strings_, 1, wxEXPAND);
    string_panel->SetSizer(string_layout);

    auto *reference_panel = new wxPanel(splitter);
    auto *reference_layout = new wxBoxSizer(wxVERTICAL);
    reference_summary_ = new wxStaticText(reference_panel, wxID_ANY, "Select a string to browse incoming references");
    reference_summary_->SetName("string-reference-summary");
    reference_layout->Add(reference_summary_, 0, wxEXPAND | wxALL, FromDIP(4));
    references_ = new VirtualTable(reference_panel, "string-references", {"Source", "Kind", "Operand"});
    reference_layout->Add(references_, 1, wxEXPAND);
    auto *paging = new wxBoxSizer(wxHORIZONTAL);
    previous_references_ = new wxButton(reference_panel, wxID_ANY, "Previous");
    previous_references_->SetName("string-references-previous");
    next_references_ = new wxButton(reference_panel, wxID_ANY, "Next");
    next_references_->SetName("string-references-next");
    previous_references_->Enable(false);
    next_references_->Enable(false);
    paging->Add(previous_references_, 0, wxALL, FromDIP(3));
    paging->Add(next_references_, 0, wxALL, FromDIP(3));
    reference_layout->Add(paging, 0, wxALIGN_RIGHT);
    reference_panel->SetSizer(reference_layout);

    splitter->SplitVertically(string_panel, reference_panel, FromDIP(560));
    splitter->SetMinimumPaneSize(FromDIP(180));
    layout->Add(splitter, 1, wxEXPAND | wxALL, FromDIP(4));
    SetSizer(layout);

    filter_->Bind(wxEVT_TEXT, [this](wxCommandEvent &) { filter_timer_.StartOnce(120); });
    filter_->Bind(wxEVT_TEXT_ENTER, [this](wxCommandEvent &) {
        filter_timer_.Stop();
        refresh_strings();
        if (!visible_strings_.empty()) {
            strings_->select_row(0);
            choose_string(visible_strings_.front(), true);
        }
    });
    Bind(wxEVT_TIMER, [this](wxTimerEvent &) { refresh_strings(); }, filter_timer_.GetId());
    strings_->activate = [this](std::size_t row) {
        if (row < visible_strings_.size())
            choose_string(visible_strings_[row], true);
    };
    references_->activate = [this](std::size_t row) {
        if (!document_ || !reference_page_ || row >= reference_page_->rows.size())
            return;
        if (navigate)
            navigate(reference_page_->rows[row].source);
    };
    previous_references_->Bind(wxEVT_BUTTON, [this](wxCommandEvent &) {
        if (reference_offset_ >= reference_page_size_) {
            reference_offset_ -= reference_page_size_;
            refresh_references();
        }
    });
    next_references_->Bind(wxEVT_BUTTON, [this](wxCommandEvent &) {
        if (reference_page_ && reference_offset_ + reference_page_->rows.size() < reference_page_->total) {
            reference_offset_ += reference_page_size_;
            refresh_references();
        }
    });
}

void StringBrowserView::set_document(std::shared_ptr<const DocumentSnapshot> document) {
    document_ = std::move(document);
    selected_string_.reset();
    reference_offset_ = 0;
    strings_->clear_selection();
    refresh_strings();
    refresh_references();
}

std::optional<Location> StringBrowserView::string_location(std::size_t record_index) const {
    if (!document_ || record_index >= document_->strings().records.size())
        return {};
    const auto &record = document_->strings().records[record_index];
    if (record.address)
        return Location{*record.address};
    return Location{record.file_offset};
}

void StringBrowserView::refresh_strings() {
    filter_timer_.Stop();
    const auto previous = selected_string_;
    visible_strings_.clear();
    if (document_) {
        auto query = filter_->GetValue();
        query.Trim(true).Trim(false).MakeLower();
        const auto &records = document_->strings().records;
        visible_strings_.reserve(records.size());
        for (std::size_t i = 0; i < records.size(); ++i) {
            if (!query.empty()) {
                auto preview = text(records[i].preview);
                auto address = string_location(i) ? location_text(*string_location(i), document_->image.get()) : wxString{};
                auto encoding = encoding_text(records[i].encoding);
                preview.MakeLower();
                address.MakeLower();
                encoding.MakeLower();
                if (preview.Find(query) == wxNOT_FOUND && address.Find(query) == wxNOT_FOUND &&
                    encoding.Find(query) == wxNOT_FOUND)
                    continue;
            }
            visible_strings_.push_back(i);
        }
    }
    strings_->populate(visible_strings_.size(), [this](std::size_t row, int column) {
        if (!document_ || row >= visible_strings_.size())
            return wxString{};
        const auto index = visible_strings_[row];
        const auto &record = document_->strings().records[index];
        switch (column) {
        case 0:
            return location_text(record.address ? Location{*record.address} : Location{record.file_offset},
                                 document_->image.get());
        case 1: return text(record.preview);
        case 2: return encoding_text(record.encoding);
        default: return wxString::Format("%llu", static_cast<unsigned long long>(record.byte_length));
        }
    });
    if (previous) {
        const auto visible = std::find(visible_strings_.begin(), visible_strings_.end(), *previous);
        if (visible != visible_strings_.end()) {
            const auto row = static_cast<std::size_t>(std::distance(visible_strings_.begin(), visible));
            strings_->select_row(row);
            return;
        }
        selected_string_.reset();
        reference_offset_ = 0;
        refresh_references();
    }
}

void StringBrowserView::choose_string(std::size_t record_index, bool navigate_to_string) {
    if (!document_ || record_index >= document_->strings().records.size())
        return;
    selected_string_ = record_index;
    reference_offset_ = 0;
    refresh_references();
    if (navigate_to_string && navigate) {
        const auto location = string_location(record_index);
        if (location)
            navigate(*location);
    }
}

void StringBrowserView::refresh_references() {
    reference_page_.reset();
    references_->populate(0, {});
    previous_references_->Enable(false);
    next_references_->Enable(false);
    if (!document_ || !selected_string_ || *selected_string_ >= document_->strings().records.size()) {
        reference_summary_->SetLabel("Select a string to browse incoming references");
        return;
    }
    if (!document_->project || !document_->project->references) {
        reference_summary_->SetLabel("Reference browsing requires an indexed project document");
        return;
    }
    if (document_->project->status != DerivedStatus::fresh &&
        document_->project->status != DerivedStatus::incomplete) {
        reference_summary_->SetLabel("Reference index is stale or analysis is pending");
        return;
    }
    const auto &record = document_->strings().records[*selected_string_];
    const auto request = PageRequest{reference_offset_, reference_page_size_};
    auto page = record.address
        ? document_->project->references->incoming_mapped_file_range(*document_->image, record.file_offset,
                                                                       record.byte_length, request)
        : document_->project->references->incoming_file_range(record.file_offset, record.byte_length, request);
    if (!page) {
        reference_summary_->SetLabel(text(page.error().message));
        return;
    }
    reference_page_ = std::move(page.value());
    const auto incomplete = document_->project->status == DerivedStatus::incomplete ||
                            !document_->strings().complete || !document_->project->references->complete();
    auto reference_label = wxString::Format("%llu incoming references",
        static_cast<unsigned long long>(reference_page_->total));
    if (incomplete)
        reference_label += " (partial analysis)";
    reference_summary_->SetLabel(reference_label);
    references_->populate(reference_page_->rows.size(), [this](std::size_t row, int column) {
        if (!document_ || !reference_page_ || row >= reference_page_->rows.size())
            return wxString{};
        const auto &reference = reference_page_->rows[row];
        switch (column) {
        case 0: return location_text(reference.source, document_->image.get());
        case 1: return reference_kind_text(reference.kind);
        default:
            return reference.operand_index
                       ? wxString::Format("%u", *reference.operand_index)
                       : wxString{};
        }
    });
    previous_references_->Enable(reference_offset_ > 0);
    next_references_->Enable(reference_offset_ + reference_page_->rows.size() < reference_page_->total);
}

void StringBrowserView::select(Location location) {
    if (!document_)
        return;
    std::optional<FileOffset> file;
    if (const auto *offset = std::get_if<FileOffset>(&location))
        file = *offset;
    else if (const auto *address = std::get_if<Address>(&location)) {
        auto mapped = document_->image->to_file_offset(*address);
        if (mapped)
            file = mapped.value();
    }
    if (!file)
        return;
    const auto &records = document_->strings().records;
    for (std::size_t i = 0; i < records.size(); ++i) {
        const auto &record = records[i];
        if (file->value < record.file_offset.value || file->value - record.file_offset.value >= record.byte_length)
            continue;
        auto query = filter_->GetValue();
        if (!query.empty()) {
            filter_->ChangeValue({});
            refresh_strings();
        }
        auto visible = std::find(visible_strings_.begin(), visible_strings_.end(), i);
        if (visible == visible_strings_.end())
            return;
        const auto row = static_cast<std::size_t>(std::distance(visible_strings_.begin(), visible));
        strings_->select_row(row);
        choose_string(i, false);
        return;
    }
}

void StringBrowserView::clear_selection() {
    strings_->clear_selection();
    references_->clear_selection();
    selected_string_.reset();
    reference_offset_ = 0;
    refresh_references();
}

} // namespace hexlab::desktop
