#include "string_view.hpp"

#include "hexlab/analysis/references.hpp"
#include "hexlab/image/file_publication.hpp"
#include "hexlab/image/file_storage.hpp"
#include "hexlab/image/image.hpp"
#include "hexlab/workspace/project.hpp"
#include <algorithm>
#include <filesystem>
#include <span>
#include <string>
#include <string_view>
#include <vector>
#include <wx/filedlg.h>
#include <wx/msgdlg.h>
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
    case StringEncoding::windows1254: return "Windows-1254";
    case StringEncoding::windows1253: return "Windows-1253";
    case StringEncoding::windows1255: return "Windows-1255";
    case StringEncoding::windows1256: return "Windows-1256";
    case StringEncoding::windows1257: return "Windows-1257";
    case StringEncoding::windows1258: return "Windows-1258";
    case StringEncoding::iso8859_2: return "ISO-8859-2";
    case StringEncoding::iso8859_5: return "ISO-8859-5";
    case StringEncoding::dos437: return "DOS-437";
    case StringEncoding::dos850: return "DOS-850";
    case StringEncoding::iso8859_15: return "ISO-8859-15";
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
std::string csv_row(const std::vector<std::string> &fields) {
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
std::string decimal(std::uint64_t value) {
    return std::to_string(value);
}
std::string hex(std::uint64_t value) {
    return utf8(wxString::Format("0x%llX", static_cast<unsigned long long>(value)));
}
}

StringBrowserView::StringBrowserView(wxWindow *parent) : wxPanel(parent), filter_timer_(this) {
    auto *layout = new wxBoxSizer(wxVERTICAL);
    auto *filter_row = new wxBoxSizer(wxHORIZONTAL);
    filter_ = new wxTextCtrl(this, wxID_ANY, {}, wxDefaultPosition, wxDefaultSize, wxTE_PROCESS_ENTER);
    filter_->SetName("strings-filter");
    filter_->SetHint("Filter strings by text, address, or encoding");
    filter_row->Add(filter_, 1, wxEXPAND | wxRIGHT, FromDIP(4));
    export_ = new wxButton(this, wxID_ANY, "Export filtered CSV...");
    export_->SetName("strings-export");
    export_->Enable(false);
    filter_row->Add(export_, 0, wxEXPAND);
    export_all_ = new wxButton(this, wxID_ANY, "Export all CSV...");
    export_all_->SetName("strings-export-all");
    export_all_->Enable(false);
    filter_row->Add(export_all_, 0, wxEXPAND | wxLEFT, FromDIP(4));
    comment_ = new wxButton(this, wxID_ANY, "Comment selected string...");
    comment_->SetName("strings-comment");
    comment_->Enable(false);
    filter_row->Add(comment_, 0, wxEXPAND | wxLEFT, FromDIP(4));
    layout->Add(filter_row, 0, wxEXPAND | wxALL, FromDIP(4));

    auto *splitter = new wxSplitterWindow(this, wxID_ANY, wxDefaultPosition, wxDefaultSize,
                                           wxSP_LIVE_UPDATE | wxSP_3D);
    auto *string_panel = new wxPanel(splitter);
    auto *string_layout = new wxBoxSizer(wxVERTICAL);
    strings_ = new VirtualTable(string_panel, "strings-list", {"Address / offset", "Text", "Encoding", "Bytes", "Comment"});
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
    export_->Bind(wxEVT_BUTTON, [this](wxCommandEvent &) { export_strings(true); });
    export_all_->Bind(wxEVT_BUTTON, [this](wxCommandEvent &) { export_strings(false); });
    comment_->Bind(wxEVT_BUTTON, [this](wxCommandEvent &) {
        if (!selected_string_ || !comment) return;
        const auto location = string_location(*selected_string_);
        if (location) comment(*location);
    });
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
        case 3: return wxString::Format("%llu", static_cast<unsigned long long>(record.byte_length));
        default: {
            if (!document_->project) return wxString{};
            const auto location = record.address ? Location{*record.address} : Location{record.file_offset};
            const auto *annotation = annotation_at(*document_->project, location);
            return annotation ? text(annotation->comment) : wxString{};
        }
        }
    });
    export_->Enable(document_ && !visible_strings_.empty());
    export_all_->Enable(document_ && !document_->strings().records.empty());
    comment_->Enable(document_ && selected_string_ && *selected_string_ < document_->strings().records.size() &&
                     static_cast<bool>(comment));
    if (previous) {
        const auto visible = std::find(visible_strings_.begin(), visible_strings_.end(), *previous);
        if (visible != visible_strings_.end()) {
            const auto row = static_cast<std::size_t>(std::distance(visible_strings_.begin(), visible));
            strings_->select_row(row);
            return;
        }
        selected_string_.reset();
        comment_->Enable(false);
        reference_offset_ = 0;
        refresh_references();
    }
}

void StringBrowserView::export_strings(bool filtered) {
    if (!document_)
        return;
    filter_timer_.Stop();
    refresh_strings();
    const auto document = document_;
    std::vector<std::size_t> records;
    if (filtered) {
        records = visible_strings_;
    } else {
        records.resize(document->strings().records.size());
        for (std::size_t i = 0; i < records.size(); ++i)
            records[i] = i;
    }
    if (records.empty())
        return;

    std::vector<std::filesystem::path> protected_paths = document->project
        ? document->project->protected_paths : std::vector<std::filesystem::path>{};
    if (const auto file = std::dynamic_pointer_cast<const FileStorage>(document->input_storage))
        protected_paths.push_back(file->backing_path());
    const auto title = filtered ? "Export filtered strings and incoming references" :
                                  "Export all strings and incoming references";
    wxFileDialog dialog(this, title, {}, filtered ? "strings-filtered.csv" : "strings-all.csv",
                        "CSV files (*.csv)|*.csv|All files (*.*)|*.*", wxFD_SAVE | wxFD_OVERWRITE_PROMPT);
    if (dialog.ShowModal() != wxID_OK)
        return;
    auto publication = FilePublication::create(std::filesystem::path(dialog.GetPath().ToStdWstring()),
                                               ExistingFilePolicy::replace, protected_paths, {});
    if (!publication) {
        wxMessageBox(text(publication.error().message), "Export strings", wxOK | wxICON_ERROR, this);
        return;
    }
    const auto append = [&](std::string_view bytes) -> bool {
        const auto written = publication.value()->append(std::as_bytes(std::span(bytes.data(), bytes.size())));
        if (!written) {
            wxMessageBox(text(written.error().message), "Export strings", wxOK | wxICON_ERROR, this);
            return false;
        }
        return true;
    };
    if (!append(csv_row({"string_address", "file_offset", "encoding", "byte_length", "characters",
                         "terminated", "preview", "incoming_source", "reference_kind", "operand_index",
                         "reference_status"})))
        return;

    const auto *index = document->project ? document->project->references.get() : nullptr;
    const auto status = document->project ? document->project->status : DerivedStatus::fresh;
    const bool references_available = index &&
        (status == DerivedStatus::fresh || status == DerivedStatus::incomplete);
    const bool partial_references = references_available &&
        (status == DerivedStatus::incomplete || !document->strings().complete || !index->complete());
    const std::string available_status = partial_references ? "partial analysis" : "available";
    const std::string unavailable = !document->project ? "unavailable: standalone document" :
        !index ? "unavailable: no reference index" :
        status == DerivedStatus::stale ? "unavailable: stale analysis" :
        status == DerivedStatus::pending ? "unavailable: analysis pending" :
        status == DerivedStatus::file_only ? "unavailable: file-only document" :
        "unavailable: reference index is not current";
    constexpr std::size_t export_page_size = 128;
    for (const auto record_index : records) {
        if (record_index >= document->strings().records.size())
            continue;
        const auto &record = document->strings().records[record_index];
        const auto address = record.address ? location_text(Location{*record.address}, document->image.get()) :
            location_text(Location{record.file_offset}, document->image.get());
        const std::vector<std::string> prefix = {utf8(address), hex(record.file_offset.value),
            utf8(encoding_text(record.encoding)), decimal(record.byte_length), decimal(record.characters),
            record.terminated ? "true" : "false", utf8(text(record.preview))};
        if (!references_available) {
            auto fields = prefix;
            fields.insert(fields.end(), {"", "", "", unavailable});
            if (!append(csv_row(fields)))
                return;
            continue;
        }

        std::uint64_t offset = 0;
        bool wrote_reference = false;
        while (true) {
            auto page = record.address
                ? index->incoming_mapped_file_range(*document->image, record.file_offset, record.byte_length,
                                                    {offset, export_page_size})
                : index->incoming_file_range(record.file_offset, record.byte_length, {offset, export_page_size});
            if (!page) {
                wxMessageBox(text(page.error().message), "Export strings", wxOK | wxICON_ERROR, this);
                return;
            }
            for (const auto &reference : page.value().rows) {
                wrote_reference = true;
                auto fields = prefix;
                fields.push_back(utf8(location_text(reference.source, document->image.get())));
                fields.push_back(utf8(reference_kind_text(reference.kind)));
                fields.push_back(reference.operand_index ? std::to_string(*reference.operand_index) : std::string{});
                fields.push_back(available_status);
                if (!append(csv_row(fields)))
                    return;
            }
            if (!page.value().next_offset)
                break;
            if (page.value().rows.empty() || *page.value().next_offset <= offset) {
                wxMessageBox("The reference index returned an invalid page sequence.", "Export strings",
                             wxOK | wxICON_ERROR, this);
                return;
            }
            offset = *page.value().next_offset;
        }
        if (!wrote_reference) {
            auto fields = prefix;
            fields.insert(fields.end(), {"", "", "", partial_references
                ? "partial analysis: no indexed incoming references" : "available: no incoming references"});
            if (!append(csv_row(fields)))
                return;
        }
    }
    const auto published = publication.value()->publish();
    if (!published)
        wxMessageBox(text(published.error().message), "Export strings", wxOK | wxICON_ERROR, this);
}

void StringBrowserView::choose_string(std::size_t record_index, bool navigate_to_string) {
    if (!document_ || record_index >= document_->strings().records.size())
        return;
    selected_string_ = record_index;
    comment_->Enable(static_cast<bool>(comment));
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
    comment_->Enable(false);
    reference_offset_ = 0;
    refresh_references();
}

} // namespace hexlab::desktop
