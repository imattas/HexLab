#include "string_view.hpp"

#include "hexlab/analysis/references.hpp"
#include "hexlab/image/file_publication.hpp"
#include "hexlab/image/file_storage.hpp"
#include "hexlab/image/image.hpp"
#include "hexlab/workspace/project.hpp"
#include "hexlab/core/sha256.hpp"
#include "hexlab/loaders/recipe.hpp"
#include <algorithm>
#include <array>
#include <charconv>
#include <filesystem>
#include <fstream>
#include <memory>
#include <span>
#include <string>
#include <string_view>
#include <system_error>
#include <vector>
#include <wx/clipbrd.h>
#include <wx/dataobj.h>
#include <wx/filedlg.h>
#include <wx/msgdlg.h>
#include <wx/choicdlg.h>
#include <wx/sizer.h>
#include <wx/settings.h>
#include <wx/wrapsizer.h>

namespace hexlab::desktop {
namespace {
constexpr std::size_t string_byte_preview_limit = 64;
constexpr std::uint64_t string_export_byte_limit = 64ull * 1024 * 1024;
constexpr std::size_t maximum_string_preferences = 512;
constexpr std::size_t maximum_string_query = 2048;
constexpr std::size_t maximum_preference_token = 256;
constexpr std::size_t maximum_standalone_comments = 2048;
constexpr std::size_t maximum_standalone_dispositions = 2048;
constexpr std::size_t maximum_standalone_comment_bytes = 4096;
constexpr std::size_t maximum_standalone_comment_total = 1024 * 1024;
constexpr std::size_t maximum_standalone_comment_serialized = 2 * 1024 * 1024;
constexpr std::size_t maximum_standalone_annotation_inputs = 16;
constexpr std::array string_encodings{
    StringEncoding::ascii, StringEncoding::utf8, StringEncoding::utf16le, StringEncoding::utf16be,
    StringEncoding::utf32le, StringEncoding::utf32be, StringEncoding::windows1252, StringEncoding::windows1251,
    StringEncoding::windows1250, StringEncoding::windows1254, StringEncoding::windows1253,
    StringEncoding::windows1255, StringEncoding::windows1256, StringEncoding::windows1257,
    StringEncoding::windows1258, StringEncoding::iso8859_2, StringEncoding::iso8859_5,
    StringEncoding::dos437, StringEncoding::dos850, StringEncoding::iso8859_15, StringEncoding::iso8859_9,
    StringEncoding::dos866, StringEncoding::dos852, StringEncoding::koi8_r, StringEncoding::koi8_u, StringEncoding::mac_roman,
    StringEncoding::iso8859_1, StringEncoding::iso8859_3, StringEncoding::iso8859_4,
    StringEncoding::iso8859_6, StringEncoding::iso8859_7, StringEncoding::iso8859_10,
    StringEncoding::iso8859_13, StringEncoding::iso8859_14, StringEncoding::iso8859_16,
    StringEncoding::iso8859_8, StringEncoding::iso8859_11, StringEncoding::windows874,
    StringEncoding::mac_cyrillic, StringEncoding::ebcdic_cp037, StringEncoding::ebcdic_cp500,
    StringEncoding::ebcdic_cp1047, StringEncoding::windows932, StringEncoding::windows936,
    StringEncoding::windows949};

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
    case StringEncoding::iso8859_9: return "ISO-8859-9";
    case StringEncoding::dos866: return "DOS-866";
    case StringEncoding::dos852: return "DOS-852";
    case StringEncoding::koi8_r: return "KOI8-R";
    case StringEncoding::koi8_u: return "KOI8-U";
    case StringEncoding::mac_roman: return "Mac Roman";
    case StringEncoding::iso8859_1: return "ISO-8859-1";
    case StringEncoding::iso8859_3: return "ISO-8859-3";
    case StringEncoding::iso8859_4: return "ISO-8859-4";
    case StringEncoding::iso8859_6: return "ISO-8859-6";
    case StringEncoding::iso8859_7: return "ISO-8859-7";
    case StringEncoding::iso8859_10: return "ISO-8859-10";
    case StringEncoding::iso8859_13: return "ISO-8859-13";
    case StringEncoding::iso8859_14: return "ISO-8859-14";
    case StringEncoding::iso8859_16: return "ISO-8859-16";
    case StringEncoding::iso8859_8: return "ISO-8859-8";
    case StringEncoding::iso8859_11: return "ISO-8859-11";
    case StringEncoding::windows874: return "Windows-874";
    case StringEncoding::mac_cyrillic: return "Mac Cyrillic";
    case StringEncoding::ebcdic_cp037: return "EBCDIC CP037";
    case StringEncoding::ebcdic_cp500: return "EBCDIC CP500";
    case StringEncoding::ebcdic_cp1047: return "EBCDIC CP1047";
    case StringEncoding::windows932: return "Windows-932";
    case StringEncoding::windows936: return "Windows-936 (GBK)";
    case StringEncoding::windows949: return "Windows-949 (UHC)";
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
std::optional<std::string> preference_identity(const ProjectSnapshot &project, bool include_uuid) {
    if (!project.state) return {};
    auto recipe = encode_recipe(project.state->recipe);
    if (!recipe || recipe.value().size() > 65536) return {};
    Sha256 hash;
    if (!hash.update(recipe.value())) return {};
    std::string identity;
    constexpr char digits[] = "0123456789abcdef";
    if (include_uuid)
        for (const auto byte : project.state->uuid) {
            const auto value = std::to_integer<unsigned>(byte);
            identity += digits[value >> 4];
            identity += digits[value & 15];
        }
    identity += ':' + std::to_string(project.state->input.size) + ':' + digest_hex(project.state->input.sha256);
    identity += ':' + digest_hex(hash.digest());
    return identity;
}
std::optional<std::string> standalone_annotation_key(const ProjectSnapshot &project) {
    const auto identity = preference_identity(project, false);
    if (!identity) return {};
    Sha256 hash;
    if (!hash.update(std::as_bytes(std::span(identity->data(), identity->size())))) return {};
    return digest_hex(hash.digest());
}
std::string selection_prefix(const StringRecord &record, const ProjectSnapshot &project) {
    return std::to_string(record.file_offset.value) + ':' + std::to_string(static_cast<unsigned>(record.encoding)) +
        ':' + std::to_string(record.byte_length) + ':' + std::to_string(record.characters) + ':' +
        (record.terminated ? "1:" : "0:") + std::to_string(project.state->revisions.bytes) + ':';
}
std::string selection_key(const StringRecord &record, const ProjectSnapshot &project) {
    Sha256 hash;
    if (!hash.update(std::as_bytes(std::span(record.preview.data(), record.preview.size())))) return {};
    return selection_prefix(record, project) + digest_hex(hash.digest());
}
std::optional<std::uint64_t> unsigned_bound(const wxString &value, std::uint64_t empty_value) {
    auto trimmed = value;
    trimmed.Trim(true).Trim(false);
    const auto encoded = utf8(trimmed);
    if (encoded.empty()) return empty_value;
    if (encoded.size() > 20 || !std::all_of(encoded.begin(), encoded.end(), [](char c) {
            return c >= '0' && c <= '9';
        })) return {};
    std::uint64_t parsed = 0;
    const auto result = std::from_chars(encoded.data(), encoded.data() + encoded.size(), parsed);
    if (result.ec != std::errc{} || result.ptr != encoded.data() + encoded.size()) return {};
    return parsed;
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
std::string tsv_field(std::string_view value) {
    constexpr char hex_digits[] = "0123456789abcdef";
    std::string result;
    result.reserve(value.size());
    for (const unsigned char c : value) {
        if (c == '\\') result += "\\\\";
        else if (c == '\t') result += "\\t";
        else if (c == '\r') result += "\\r";
        else if (c == '\n') result += "\\n";
        else if (c < 0x20 || c == 0x7f) {
            result += "\\x";
            result.push_back(hex_digits[c >> 4]);
            result.push_back(hex_digits[c & 0x0f]);
        } else result.push_back(static_cast<char>(c));
    }
    return result;
}
std::string decimal(std::uint64_t value) {
    return std::to_string(value);
}
std::string hex(std::uint64_t value) {
    return utf8(wxString::Format("0x%llX", static_cast<unsigned long long>(value)));
}
std::string hex_bytes(std::string_view value) {
    constexpr char digits[]="0123456789abcdef";std::string out;out.reserve(value.size()*2);
    for(unsigned char c:value){out.push_back(digits[c>>4]);out.push_back(digits[c&15]);}return out;
}
std::optional<std::string> unhex_bytes(std::string_view value) {
    if(value.size()%2)return {};auto digit=[](char c)->int{if(c>='0'&&c<='9')return c-'0';if(c>='a'&&c<='f')return c-'a'+10;return -1;};
    std::string out;out.reserve(value.size()/2);for(size_t i=0;i<value.size();i+=2){int a=digit(value[i]),b=digit(value[i+1]);if(a<0||b<0)return {};out.push_back(static_cast<char>((a<<4)|b));}return out;
}
}

StringBrowserView::StringBrowserView(wxWindow *parent) : wxPanel(parent), filter_timer_(this) {
    auto *layout = new wxBoxSizer(wxVERTICAL);
    auto *filter_row = new wxBoxSizer(wxHORIZONTAL);
    filter_ = new wxTextCtrl(this, wxID_ANY, {}, wxDefaultPosition, wxDefaultSize, wxTE_PROCESS_ENTER);
    filter_->SetName("strings-filter");
    filter_->SetMaxLength(maximum_string_query);
    filter_->SetHint("Filter strings by text, address, encoding, or comment");
    filter_->SetToolTip("Filter loaded strings by preview text, location, encoding, termination, and comments. Ctrl+F focuses this field.");
    filter_row->Add(filter_, 1, wxEXPAND | wxRIGHT, FromDIP(4));
    export_ = new wxButton(this, wxID_ANY, "Export filtered CSV...");
    export_->SetName("strings-export");
    export_->Enable(false);
    filter_row->Add(export_, 0, wxEXPAND);
    export_all_ = new wxButton(this, wxID_ANY, "Export all CSV...");
    export_all_->SetName("strings-export-all");
    export_all_->Enable(false);
    filter_row->Add(export_all_, 0, wxEXPAND | wxLEFT, FromDIP(4));
    copy_ = new wxButton(this, wxID_ANY, "Copy selected row");
    copy_->SetName("strings-copy-row");
    copy_->Enable(false);
    filter_row->Add(copy_, 0, wxEXPAND | wxLEFT, FromDIP(4));
    comment_ = new wxButton(this, wxID_ANY, "Comment selected string...");
    comment_->SetName("strings-comment");
    comment_->Enable(false);
    classify_ = new wxButton(this, wxID_ANY, "Classify selected...");
    classify_->SetName("strings-classify");
    classify_->Enable(false);
    export_notes_ = new wxButton(this, wxID_ANY, "Export standalone notes...");
    export_notes_->SetName("strings-export-notes");
    export_notes_->Enable(false);
    import_notes_ = new wxButton(this, wxID_ANY, "Import standalone notes...");
    import_notes_->SetName("strings-import-notes");
    import_notes_->Enable(false);
    layout->Add(filter_row, 0, wxEXPAND | wxALL, FromDIP(4));
    auto *annotation_row = new wxBoxSizer(wxHORIZONTAL);
    annotation_row->Add(comment_, 0, wxEXPAND | wxRIGHT, FromDIP(4));
    annotation_row->Add(classify_, 0, wxEXPAND | wxRIGHT, FromDIP(4));
    annotation_row->Add(export_notes_, 0, wxEXPAND | wxRIGHT, FromDIP(4));
    annotation_row->Add(import_notes_, 0, wxEXPAND);
    layout->Add(annotation_row, 0, wxEXPAND | wxLEFT | wxRIGHT | wxBOTTOM, FromDIP(4));
    auto *facets = new wxWrapSizer(wxHORIZONTAL);
    encoding_ = new wxChoice(this, wxID_ANY);
    encoding_->SetName("strings-encoding");
    encoding_->Append("Any encoding");
    for (const auto encoding : string_encodings) encoding_->Append(encoding_text(encoding));
    encoding_->SetSelection(0);
    mapping_ = new wxChoice(this, wxID_ANY);
    mapping_->SetName("strings-mapping");
    for (const auto *label : {"Any mapping", "Mapped address", "File offset only"}) mapping_->Append(label);
    mapping_->SetSelection(0);
    termination_ = new wxChoice(this, wxID_ANY);
    termination_->SetName("strings-termination");
    for (const auto *label : {"Any termination", "Terminated", "Unterminated"}) termination_->Append(label);
    termination_->SetSelection(0);
    sort_ = new wxChoice(this, wxID_ANY);
    sort_->SetName("strings-sort");
    for (const auto *label : {"Discovery order", "File offset: low to high", "Bytes: shortest first",
                             "Bytes: longest first", "Characters: longest first", "Text: ascending"})
        sort_->Append(label);
    sort_->SetSelection(0);
    for (auto *choice : {encoding_, mapping_, termination_, sort_})
        facets->Add(choice, 0, wxRIGHT | wxBOTTOM, FromDIP(4));
    facets->Add(new wxStaticText(this, wxID_ANY, "Bytes min:"), 0, wxALIGN_CENTER_VERTICAL | wxRIGHT, FromDIP(4));
    minimum_bytes_ = new wxTextCtrl(this, wxID_ANY, "0", wxDefaultPosition, FromDIP(wxSize(100, -1)));
    minimum_bytes_->SetName("strings-minimum-bytes");
    minimum_bytes_->SetMaxLength(20);
    minimum_bytes_->SetToolTip("Inclusive minimum source byte length, as an unsigned decimal integer. Blank means zero.");
    facets->Add(minimum_bytes_, 0, wxRIGHT | wxBOTTOM, FromDIP(4));
    facets->Add(new wxStaticText(this, wxID_ANY, "Max:"), 0, wxALIGN_CENTER_VERTICAL | wxRIGHT, FromDIP(4));
    maximum_bytes_ = new wxTextCtrl(this, wxID_ANY, {}, wxDefaultPosition, FromDIP(wxSize(100, -1)));
    maximum_bytes_->SetName("strings-maximum-bytes");
    maximum_bytes_->SetMaxLength(20);
    maximum_bytes_->SetHint("No limit");
    maximum_bytes_->SetToolTip("Inclusive maximum source byte length, as an unsigned decimal integer. Blank means no limit.");
    facets->Add(maximum_bytes_, 0, wxRIGHT | wxBOTTOM, FromDIP(4));
    facets->Add(new wxStaticText(this, wxID_ANY, "Characters min:"), 0, wxALIGN_CENTER_VERTICAL | wxRIGHT, FromDIP(4));
    minimum_characters_ = new wxTextCtrl(this, wxID_ANY, "0", wxDefaultPosition, FromDIP(wxSize(100, -1)));
    minimum_characters_->SetName("strings-minimum-characters");
    minimum_characters_->SetMaxLength(20);
    minimum_characters_->SetToolTip("Inclusive minimum decoded character count, as an unsigned decimal integer. Blank means zero.");
    facets->Add(minimum_characters_, 0, wxRIGHT | wxBOTTOM, FromDIP(4));
    facets->Add(new wxStaticText(this, wxID_ANY, "Max:"), 0, wxALIGN_CENTER_VERTICAL | wxRIGHT, FromDIP(4));
    maximum_characters_ = new wxTextCtrl(this, wxID_ANY, {}, wxDefaultPosition, FromDIP(wxSize(100, -1)));
    maximum_characters_->SetName("strings-maximum-characters");
    maximum_characters_->SetMaxLength(20);
    maximum_characters_->SetHint("No limit");
    maximum_characters_->SetToolTip("Inclusive maximum decoded character count, as an unsigned decimal integer. Blank means no limit.");
    facets->Add(maximum_characters_, 0, wxRIGHT | wxBOTTOM, FromDIP(4));
    auto *reset = new wxButton(this, wxID_ANY, "Reset filters");
    reset->SetName("strings-reset-filters");
    facets->Add(reset, 0, wxBOTTOM, FromDIP(4));
    layout->Add(facets, 0, wxEXPAND | wxLEFT | wxRIGHT, FromDIP(4));
    filter_summary_ = new wxStaticText(this, wxID_ANY, "No document");
    filter_summary_->SetName("strings-filter-summary");
    layout->Add(filter_summary_, 0, wxEXPAND | wxLEFT | wxRIGHT | wxBOTTOM, FromDIP(4));
    auto *cursor_row = new wxBoxSizer(wxHORIZONTAL);
    cursor_summary_ = new wxStaticText(this, wxID_ANY, "No shared cursor selection");
    cursor_summary_->SetName("strings-cursor-summary");
    cursor_row->Add(cursor_summary_, 1, wxALIGN_CENTER_VERTICAL | wxRIGHT, FromDIP(4));
    reveal_cursor_ = new wxButton(this, wxID_ANY, "Reveal cursor string");
    reveal_cursor_->SetName("strings-reveal-cursor");
    reveal_cursor_->SetToolTip("Clear string filters and select the string containing the shared cursor without navigating.");
    reveal_cursor_->Enable(false);
    cursor_row->Add(reveal_cursor_, 0);
    layout->Add(cursor_row, 0, wxEXPAND | wxLEFT | wxRIGHT | wxBOTTOM, FromDIP(4));
    reveal_cursor_->Bind(wxEVT_BUTTON, [this](wxCommandEvent &) {
        if (!document_ || !synchronized_context_) return;
        reset_filters(false);
        select(*synchronized_context_);
        refresh_cursor_context();
    });
    action_status_ = new wxStaticText(this, wxID_ANY, "Select a string to copy or comment");
    action_status_->SetName("strings-action-status");
    layout->Add(action_status_, 0, wxEXPAND | wxLEFT | wxRIGHT | wxBOTTOM, FromDIP(4));
    auto *byte_preview_row = new wxBoxSizer(wxHORIZONTAL);
    auto *byte_preview_label = new wxStaticText(this, wxID_ANY, "Selected string bytes (first 64 bytes):");
    byte_preview_row->Add(byte_preview_label, 1, wxALIGN_CENTER_VERTICAL | wxRIGHT, FromDIP(4));
    copy_byte_preview_ = new wxButton(this, wxID_ANY, "Copy byte preview as hex");
    copy_byte_preview_->SetName("strings-copy-byte-preview");
    copy_byte_preview_->Enable(false);
    byte_preview_row->Add(copy_byte_preview_, 0);
    copy_text_preview_ = new wxButton(this, wxID_ANY, "Copy preview text");
    copy_text_preview_->SetName("strings-copy-text-preview");
    copy_text_preview_->SetToolTip("Copy the selected string's decoded, possibly truncated preview as plain text.");
    copy_text_preview_->Enable(false);
    byte_preview_row->Add(copy_text_preview_, 0, wxLEFT, FromDIP(4));
    copy_json_preview_ = new wxButton(this, wxID_ANY, "Copy preview as JSON string");
    copy_json_preview_->SetName("strings-copy-json-preview");
    copy_json_preview_->SetToolTip("Copy the selected string's decoded, possibly truncated preview as a quoted JSON string.");
    copy_json_preview_->Enable(false);
    byte_preview_row->Add(copy_json_preview_, 0, wxLEFT, FromDIP(4));
    export_bytes_ = new wxButton(this, wxID_ANY, "Export full bytes...");
    export_bytes_->SetName("strings-export-bytes");
    export_bytes_->Enable(false);
    byte_preview_row->Add(export_bytes_, 0, wxLEFT, FromDIP(4));
    layout->Add(byte_preview_row, 0, wxEXPAND | wxLEFT | wxRIGHT, FromDIP(4));
    byte_preview_ = new wxTextCtrl(this, wxID_ANY, {}, wxDefaultPosition,
                                   wxSize(-1, FromDIP(46)), wxTE_MULTILINE | wxTE_READONLY | wxTE_DONTWRAP);
    byte_preview_->SetName("strings-byte-preview");
    byte_preview_->SetFont(wxSystemSettings::GetFont(wxSYS_ANSI_FIXED_FONT));
    layout->Add(byte_preview_, 0, wxEXPAND | wxLEFT | wxRIGHT | wxBOTTOM, FromDIP(4));

    auto *splitter = new wxSplitterWindow(this, wxID_ANY, wxDefaultPosition, wxDefaultSize,
                                           wxSP_LIVE_UPDATE | wxSP_3D);
    auto *string_panel = new wxPanel(splitter);
    auto *string_layout = new wxBoxSizer(wxVERTICAL);
    strings_ = new VirtualTable(string_panel, "strings-list", {"Address / offset", "Text", "Encoding", "Bytes",
                                                             "Characters", "Terminated", "Comment", "Disposition"});
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
    copy_reference_ = new wxButton(reference_panel, wxID_ANY, "Copy selected reference");
    copy_reference_->SetName("string-reference-copy");
    copy_reference_->Enable(false);
    paging->Add(copy_reference_, 0, wxALL, FromDIP(3));
    copy_reference_page_ = new wxButton(reference_panel, wxID_ANY, "Copy page as TSV");
    copy_reference_page_->SetName("string-reference-copy-page");
    copy_reference_page_->Enable(false);
    paging->Add(copy_reference_page_, 0, wxALL, FromDIP(3));
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

    Bind(wxEVT_CHAR_HOOK, [this](wxKeyEvent &event) {
        if (event.ControlDown() && !event.AltDown() && !event.ShiftDown() &&
            (event.GetKeyCode() == 'F' || event.GetKeyCode() == 'f')) {
            filter_->SetFocus();
            filter_->SelectAll();
            return;
        }
        event.Skip();
    });

    filter_->Bind(wxEVT_TEXT, [this](wxCommandEvent &) {
        pending_selection_.clear();
        filter_timer_.StartOnce(120);
    });
    for (auto *choice : {encoding_, mapping_, termination_, sort_})
        choice->Bind(wxEVT_CHOICE, [this](wxCommandEvent &) {
            pending_selection_.clear();
            refresh_strings();
        });
    for (auto *bound : {minimum_bytes_, maximum_bytes_, minimum_characters_, maximum_characters_})
        bound->Bind(wxEVT_TEXT, [this](wxCommandEvent &) {
            pending_selection_.clear();
            filter_timer_.StartOnce(120);
        });
    reset->Bind(wxEVT_BUTTON, [this](wxCommandEvent &) { reset_filters(); });
    export_->Bind(wxEVT_BUTTON, [this](wxCommandEvent &) { export_strings(true); });
    export_all_->Bind(wxEVT_BUTTON, [this](wxCommandEvent &) { export_strings(false); });
    copy_->Bind(wxEVT_BUTTON, [this](wxCommandEvent &) { copy_selected_row(); });
    copy_byte_preview_->Bind(wxEVT_BUTTON, [this](wxCommandEvent &) { copy_byte_preview(); });
    copy_text_preview_->Bind(wxEVT_BUTTON, [this](wxCommandEvent &) { copy_text_preview(); });
    copy_json_preview_->Bind(wxEVT_BUTTON, [this](wxCommandEvent &) { copy_json_preview(); });
    export_bytes_->Bind(wxEVT_BUTTON, [this](wxCommandEvent &) { export_selected_bytes(); });
    comment_->Bind(wxEVT_BUTTON, [this](wxCommandEvent &) {
        if (!selected_string_ || !comment) return;
        const auto location = string_location(*selected_string_);
        if (location) comment(*location);
    });
    export_notes_->Bind(wxEVT_BUTTON, [this](wxCommandEvent &) { export_standalone_notes(); });
    import_notes_->Bind(wxEVT_BUTTON, [this](wxCommandEvent &) { import_standalone_notes(); });
    classify_->Bind(wxEVT_BUTTON, [this](wxCommandEvent &) {
        if (!standalone_document_ || !selected_string_ || !document_) return;
        const wxString labels[] = {"Unclassified", "Confirmed string", "Not a string", "Review"};
        const auto current = disposition_for_record(*document_, *selected_string_);
        int choice = 0;
        for (int i = 0; i < 4; ++i) if (labels[i] == current) choice = i;
        wxSingleChoiceDialog dialog(this, "Set a local review disposition for this string.",
                                    "Classify string", 4, labels);
        dialog.SetSelection(choice);
        if (dialog.ShowModal() != wxID_OK) return;
        const int selected = dialog.GetSelection();
        if (selected >= 0 && selected <= 3)
            if (const auto location = string_location(*selected_string_))
                (void)set_standalone_disposition(*location, static_cast<std::uint8_t>(selected));
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
    strings_->SetToolTip("Discovered strings. Up/Down selects a row; Enter opens its references. Ctrl+C copies the selected row.");
    strings_->Bind(wxEVT_CHAR_HOOK, [this](wxKeyEvent &event) {
        if (event.ControlDown() && !event.AltDown() && !event.ShiftDown() &&
            (event.GetKeyCode() == 'C' || event.GetKeyCode() == 'c') && copy_->IsEnabled()) {
            copy_selected_row();
            return;
        }
        event.Skip();
    });
    references_->activate = [this](std::size_t row) {
        if (!document_ || !reference_page_ || row >= reference_page_->rows.size())
            return;
        if (navigate)
            navigate(reference_page_->rows[row].source);
    };
    copy_reference_->Bind(wxEVT_BUTTON, [this](wxCommandEvent &) { copy_selected_reference(); });
    copy_reference_page_->Bind(wxEVT_BUTTON, [this](wxCommandEvent &) { copy_reference_page(); });
    references_->SetToolTip("Incoming references. Enter navigates to the source; Ctrl+C copies the selected reference as TSV. Copy page as TSV copies all rows on the current page.");
    references_->Bind(wxEVT_CHAR_HOOK, [this](wxKeyEvent &event) {
        if (event.ControlDown() && !event.AltDown() && !event.ShiftDown() &&
            (event.GetKeyCode() == 'C' || event.GetKeyCode() == 'c')) {
            copy_selected_reference();
            return;
        }
        event.Skip();
    });
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

void StringBrowserView::set_document(std::shared_ptr<const DocumentSnapshot> document, bool standalone) {
    remember_preferences();
    document_ = std::move(document);
    standalone_document_ = document_ && standalone;
    export_notes_->Enable(standalone_document_);
    import_notes_->Enable(standalone_document_);
    selected_string_.reset();
    pending_selection_.clear();
    synchronized_context_.reset();
    context_known_ = false;
    preserve_context_once_ = false;
    reference_offset_ = 0;
    strings_->clear_selection();
    action_status_->SetLabel("Select a string to copy or comment");
    filter_->ChangeValue({});
    minimum_bytes_->ChangeValue("0");
    maximum_bytes_->ChangeValue({});
    minimum_characters_->ChangeValue("0");
    maximum_characters_->ChangeValue({});
    for (auto *choice : {encoding_, mapping_, termination_, sort_}) choice->SetSelection(0);
    if (document_ && document_->project) {
        const auto found = preferences_.find(document_->id.value);
        if (found != preferences_.end()) {
            const auto identity = preference_identity(*document_->project, found->second.match_project_uuid);
            if (identity && *identity == found->second.identity) {
                const auto &saved = found->second;
                filter_->ChangeValue(saved.query);
                minimum_bytes_->ChangeValue(saved.minimum);
                maximum_bytes_->ChangeValue(saved.maximum);
                minimum_characters_->ChangeValue(saved.minimum_characters);
                maximum_characters_->ChangeValue(saved.maximum_characters);
                for (std::size_t i = 0; i < string_encodings.size(); ++i)
                    if (static_cast<int>(string_encodings[i]) == saved.encoding)
                        encoding_->SetSelection(static_cast<int>(i + 1));
                mapping_->SetSelection(saved.mapping);
                termination_->SetSelection(saved.termination);
                sort_->SetSelection(saved.sort);
                pending_selection_ = saved.selected;
                synchronized_context_ = saved.context;
                context_known_ = saved.context_known;
                preserve_context_once_ = !context_known_;
            } else {
                preferences_.erase(found);
                action_status_->SetLabel("Saved Strings preferences skipped: document identity changed");
            }
        }
    }
    restore_standalone_annotations();
    refresh_strings();
    restore_selected_string();
    refresh_byte_preview();
    refresh_references();
}

void StringBrowserView::remember_preferences() {
    if (!document_ || !document_->project || !document_->project->state) return;
    const auto previous = preferences_.find(document_->id.value);
    const bool match_uuid = previous == preferences_.end() ? true : previous->second.match_project_uuid;
    const auto identity = preference_identity(*document_->project, match_uuid);
    if (!identity || (!preferences_.contains(document_->id.value) && preferences_.size() >= maximum_string_preferences))
        return;
    Preferences saved;
    saved.identity = *identity;
    saved.match_project_uuid = match_uuid;
    saved.query = filter_->GetValue().Left(maximum_string_query);
    saved.minimum = minimum_bytes_->GetValue().Left(20);
    saved.maximum = maximum_bytes_->GetValue().Left(20);
    saved.minimum_characters = minimum_characters_->GetValue().Left(20);
    saved.maximum_characters = maximum_characters_->GetValue().Left(20);
    const auto encoding = encoding_->GetSelection();
    if (encoding > 0 && static_cast<std::size_t>(encoding) <= string_encodings.size())
        saved.encoding = static_cast<int>(string_encodings[static_cast<std::size_t>(encoding - 1)]);
    saved.mapping = mapping_->GetSelection();
    saved.termination = termination_->GetSelection();
    saved.sort = sort_->GetSelection();
    saved.selected = pending_selection_;
    if (selected_string_ && *selected_string_ < document_->strings().records.size())
        saved.selected = selection_key(document_->strings().records[*selected_string_], *document_->project);
    saved.context = synchronized_context_;
    saved.context_known = context_known_;
    if (previous != preferences_.end() && previous->second.identity == *identity)
        saved.standalone_comments = previous->second.standalone_comments;
    if (previous != preferences_.end() && previous->second.identity == *identity)
        saved.standalone_dispositions = previous->second.standalone_dispositions;
    preferences_.insert_or_assign(document_->id.value, std::move(saved));
}

void StringBrowserView::restore_standalone_annotations() {
    if (!standalone_document_ || !document_ || !document_->project || !document_->project->state) return;
    auto *config = wxConfigBase::Get(false);
    const auto input_identity = standalone_annotation_key(*document_->project);
    const auto input_fingerprint = preference_identity(*document_->project, false);
    if (!config || !input_identity || !input_fingerprint) return;

    const auto previous_path = config->GetPath();
    const auto store_path = "/Desktop/StandaloneStringAnnotations/" + *input_identity;
    config->SetPath(wxString::FromUTF8(store_path));
    long slot = -1;
    const bool has_current_slot = config->Read("Current", &slot) && (slot == 0 || slot == 1);
    const std::array<long, 2> candidates = has_current_slot ? std::array<long, 2>{slot, 1 - slot}
                                                            : std::array<long, 2>{0, 1};
    const auto token_character = [](char c) {
        return (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || c == ':';
    };
    std::optional<std::map<std::string, wxString>> restored;
    std::map<std::string, std::uint8_t> restored_dispositions;
    for (const auto candidate : candidates) {
        config->SetPath(wxString::FromUTF8(store_path + "/Slot" + std::to_string(candidate)));
        long version = 0, count = 0;
        wxString saved_identity;
        std::map<std::string, wxString> comments;
        bool valid = config->Read("Version", &version) && (version == 1 || version == 2) &&
            config->Read("Identity", &saved_identity) && utf8(saved_identity) == *input_fingerprint &&
            config->Read("Count", &count) && count >= 0 &&
            static_cast<std::size_t>(count) <= maximum_standalone_comments;
        std::size_t total_bytes = 0, serialized_bytes = 0;
        for (long index = 0; valid && index < count; ++index) {
            wxString key, annotation_text;
            const auto key_name = wxString::Format("Comment%ldKey", index);
            const auto text_name = wxString::Format("Comment%ldText", index);
            if (!config->Read(key_name, &key) || key.empty() || key.length() > maximum_preference_token ||
                !config->Read(text_name, &annotation_text)) {
                valid = false;
                break;
            }
            const auto encoded_key = utf8(key);
            const auto encoded_comment = utf8(annotation_text);
            if (!std::all_of(encoded_key.begin(), encoded_key.end(), token_character) || encoded_comment.empty() ||
                encoded_comment.size() > maximum_standalone_comment_bytes ||
                encoded_comment.size() > maximum_standalone_comment_total - total_bytes ||
                encoded_key.size() > maximum_standalone_comment_serialized - serialized_bytes ||
                encoded_comment.size() > maximum_standalone_comment_serialized - serialized_bytes - encoded_key.size() ||
                64 > maximum_standalone_comment_serialized - serialized_bytes - encoded_key.size() - encoded_comment.size() ||
                !comments.emplace(encoded_key, annotation_text).second) {
                valid = false;
                break;
            }
            total_bytes += encoded_comment.size();
            serialized_bytes += encoded_key.size() + encoded_comment.size() + 64;
        }
        std::map<std::string, std::uint8_t> dispositions;
        long disposition_count = 0;
        if (valid && version >= 2 && (!config->Read("DispositionCount", &disposition_count) || disposition_count < 0 ||
                static_cast<std::size_t>(disposition_count) > maximum_standalone_dispositions)) valid = false;
        for (long index = 0; valid && index < disposition_count; ++index) {
            wxString key;
            long value = 0;
            if (!config->Read(wxString::Format("Disposition%ldKey", index), &key) || key.empty() ||
                key.length() > maximum_preference_token || !config->Read(wxString::Format("Disposition%ldValue", index), &value) ||
                value < 1 || value > 3) { valid = false; break; }
            const auto encoded_key = utf8(key);
            if (!std::all_of(encoded_key.begin(), encoded_key.end(), token_character) ||
                !dispositions.emplace(encoded_key, static_cast<std::uint8_t>(value)).second) valid = false;
        }
        if (valid) {
            restored = std::move(comments);
            restored_dispositions = std::move(dispositions);
            break;
        }
    }
    config->SetPath(previous_path);
    if (!restored) return;

    const auto id = document_->id.value;
    auto found = preferences_.find(id);
    const auto uuid_identity = preference_identity(*document_->project, true);
    if (!uuid_identity) return;
    Preferences updated;
    if (found != preferences_.end()) {
        const auto existing_identity = preference_identity(*document_->project, found->second.match_project_uuid);
        if (!existing_identity || *existing_identity != found->second.identity) return;
        updated = found->second;
    } else {
        if (preferences_.size() >= maximum_string_preferences) return;
        updated.identity = *uuid_identity;
        updated.match_project_uuid = true;
    }
    updated.standalone_comments = std::move(*restored);
    updated.standalone_dispositions = std::move(restored_dispositions);
    preferences_.insert_or_assign(id, std::move(updated));
}

bool StringBrowserView::persist_standalone_annotations(const Preferences &preferences) const {
    if (!standalone_document_ || !document_ || !document_->project || !document_->project->state) return false;
    auto *config = wxConfigBase::Get(false);
    const auto input_identity = standalone_annotation_key(*document_->project);
    const auto input_fingerprint = preference_identity(*document_->project, false);
    if (!config || !input_identity || !input_fingerprint || preferences.standalone_comments.size() > maximum_standalone_comments ||
        preferences.standalone_dispositions.size() > maximum_standalone_dispositions)
        return false;

    std::size_t total_bytes = 0, serialized_bytes = 0;
    for (const auto &[key, annotation_text] : preferences.standalone_comments) {
        const auto value_bytes = utf8(annotation_text).size();
        if (key.empty() || key.size() > maximum_preference_token ||
            !std::all_of(key.begin(), key.end(), [](char c) {
                return (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || c == ':';
            }) || value_bytes > maximum_standalone_comment_bytes ||
            value_bytes > maximum_standalone_comment_total - total_bytes ||
            key.size() > maximum_standalone_comment_serialized - serialized_bytes ||
            value_bytes > maximum_standalone_comment_serialized - serialized_bytes - key.size() ||
            64 > maximum_standalone_comment_serialized - serialized_bytes - key.size() - value_bytes)
            return false;
        total_bytes += value_bytes;
        serialized_bytes += key.size() + value_bytes + 64;
    }
    for (const auto &[key, value] : preferences.standalone_dispositions) {
        if (key.empty() || key.size() > maximum_preference_token || value < 1 || value > 3 ||
            !std::all_of(key.begin(), key.end(), [](char c) {
                return (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || c == ':';
            }) || key.size() > maximum_standalone_comment_serialized - serialized_bytes ||
            68 > maximum_standalone_comment_serialized - serialized_bytes - key.size()) return false;
        serialized_bytes += key.size() + 68;
    }
    const auto previous_path = config->GetPath();
    const auto root = wxString("/Desktop/StandaloneStringAnnotations");
    const auto store = root + "/" + wxString::FromUTF8(*input_identity);
    config->SetPath(store);
    long current_slot = -1;
    (void)config->Read("Current", &current_slot);
    const long next_slot = current_slot == 0 ? 1 : 0;
    config->DeleteGroup(wxString::Format("Slot%ld", next_slot));
    const auto slot_path = store + wxString::Format("/Slot%ld", next_slot);
    config->SetPath(slot_path);
    bool written = config->Write("Version", 2L) &&
        config->Write("Identity", wxString::FromUTF8(*input_fingerprint)) &&
        config->Write("Count", static_cast<long>(preferences.standalone_comments.size())) &&
        config->Write("DispositionCount", static_cast<long>(preferences.standalone_dispositions.size()));
    std::size_t index = 0;
    for (const auto &[key, annotation_text] : preferences.standalone_comments) {
        written = config->Write(wxString::Format("Comment%ldKey", static_cast<long>(index)), wxString::FromUTF8(key)) && written;
        written = config->Write(wxString::Format("Comment%ldText", static_cast<long>(index)), annotation_text) && written;
        ++index;
    }
    index = 0;
    for (const auto &[key, value] : preferences.standalone_dispositions) {
        written = config->Write(wxString::Format("Disposition%ldKey", static_cast<long>(index)), wxString::FromUTF8(key)) && written;
        written = config->Write(wxString::Format("Disposition%ldValue", static_cast<long>(index)), static_cast<long>(value)) && written;
        ++index;
    }
    config->SetPath(previous_path);
    if (!written || !config->Flush()) return false;

    config->SetPath(root);
    wxString saved_order;
    (void)config->Read("Order", &saved_order);
    std::vector<std::string> order;
    const auto order_text = utf8(saved_order);
    std::size_t start = 0;
    while (order_text.size() <= maximum_standalone_annotation_inputs * 65 &&
           start < order_text.size() && order.size() < maximum_standalone_annotation_inputs) {
        const auto end = order_text.find('\n', start);
        const auto item = order_text.substr(start, end == std::string::npos ? order_text.size() - start : end - start);
        if (item.size() == 64 && std::all_of(item.begin(), item.end(), [](char c) {
                return (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f');
            }) && std::find(order.begin(), order.end(), item) == order.end())
            order.push_back(item);
        if (end == std::string::npos) break;
        start = end + 1;
    }
    std::erase(order, *input_identity);
    order.push_back(*input_identity);
    while (order.size() > maximum_standalone_annotation_inputs) {
        config->DeleteGroup(wxString::FromUTF8(order.front()));
        order.erase(order.begin());
    }
    std::string encoded_order;
    for (std::size_t item = 0; item < order.size(); ++item) {
        if (item) encoded_order.push_back('\n');
        encoded_order += order[item];
    }
    config->Write("Order", wxString::FromUTF8(encoded_order));
    if (!config->Flush()) {
        config->SetPath(previous_path);
        return false;
    }
    config->SetPath(store);
    const bool pointer_written = config->Write("Current", next_slot);
    config->SetPath(previous_path);
    return pointer_written && config->Flush();
}

void StringBrowserView::restore_selected_string() {
    if (pending_selection_.empty() || !document_ || !document_->project || !document_->project->state) return;
    for (std::size_t row = 0; row < visible_strings_.size(); ++row) {
        const auto index = visible_strings_[row];
        const auto &record = document_->strings().records[index];
        // Hash a preview only after the cheap offset/encoding/length/revision check.
        if (pending_selection_.starts_with(selection_prefix(record, *document_->project)) &&
            pending_selection_ == selection_key(record, *document_->project)) {
            pending_selection_.clear();
            strings_->select_row(row);
            choose_string(index, false);
            return;
        }
    }
    // Loading/analysis publications can arrive before the string scan. Retain
    // the key until a current scan exists, never substitute a nearby row.
    if (document_->project->status != DerivedStatus::pending && document_->project->status != DerivedStatus::stale) {
        pending_selection_.clear();
        action_status_->SetLabel("Saved string selection is no longer visible or has changed");
    }
}

void StringBrowserView::retain_documents(std::span<const DocumentInfo> documents) {
    if (document_ && std::none_of(documents.begin(), documents.end(), [&](const DocumentInfo &document) {
            return document.id == document_->id;
        })) document_.reset();
    for (auto it = preferences_.begin(); it != preferences_.end();) {
        if (std::none_of(documents.begin(), documents.end(), [&](const DocumentInfo &document) {
                return document.id.value == it->first;
            })) it = preferences_.erase(it);
        else ++it;
    }
}

void StringBrowserView::synchronize_selection(std::optional<Location> location, bool restoring_workspace) {
    // The workspace applies saved cursors only after asynchronous opens finish.
    // Do not consume the first-context guard using an interim loader cursor.
    if (!document_ || restoring_workspace) return;
    if (preserve_context_once_) {
        preserve_context_once_ = false;
        synchronized_context_ = location;
        context_known_ = true;
        refresh_cursor_context();
        return;
    }
    if (context_known_ && synchronized_context_ == location) {
        refresh_cursor_context();
        return;
    }
    synchronized_context_ = location;
    context_known_ = true;
    clear_selection();
    if (location) select(*location);
    refresh_cursor_context();
}

void StringBrowserView::save_preferences(wxConfigBase &config, const wxString &group, DocumentId id,
                                        const ProjectSnapshot &project, bool saved_project) {
    remember_preferences();
    const auto previous_path = config.GetPath();
    config.DeleteGroup(group);
    const auto found = preferences_.find(id.value);
    const auto cached_identity = found == preferences_.end() ? std::optional<std::string>{}
        : preference_identity(project, found->second.match_project_uuid);
    const auto persisted_identity = preference_identity(project, saved_project);
    if (found == preferences_.end() || !cached_identity || !persisted_identity ||
        found->second.identity != *cached_identity) return;
    config.SetPath(group);
    const auto &saved = found->second;
    config.Write("Version", 2L);
    config.Write("Identity", wxString::FromUTF8(*persisted_identity));
    config.Write("Query", saved.query);
    config.Write("Minimum", saved.minimum);
    config.Write("Maximum", saved.maximum);
    config.Write("MinimumCharacters", saved.minimum_characters);
    config.Write("MaximumCharacters", saved.maximum_characters);
    config.Write("Encoding", static_cast<long>(saved.encoding));
    config.Write("Mapping", static_cast<long>(saved.mapping));
    config.Write("Termination", static_cast<long>(saved.termination));
    config.Write("Sort", static_cast<long>(saved.sort));
    config.Write("Selected", wxString::FromUTF8(saved.selected));
    if (!saved_project) {
        config.Write("StandaloneCommentCount", static_cast<long>(saved.standalone_comments.size()));
        std::size_t index = 0;
        for (const auto &[key, annotation_text] : saved.standalone_comments) {
            config.Write(wxString::Format("StandaloneComment%ldKey", static_cast<long>(index)), wxString::FromUTF8(key));
            config.Write(wxString::Format("StandaloneComment%ldText", static_cast<long>(index)), annotation_text);
            ++index;
        }
        config.Write("StandaloneDispositionCount", static_cast<long>(saved.standalone_dispositions.size()));
        index = 0;
        for (const auto &[key, value] : saved.standalone_dispositions) {
            config.Write(wxString::Format("StandaloneDisposition%ldKey", static_cast<long>(index)), wxString::FromUTF8(key));
            config.Write(wxString::Format("StandaloneDisposition%ldValue", static_cast<long>(index)), static_cast<long>(value));
            ++index;
        }
    }
    config.SetPath(previous_path);
}

void StringBrowserView::restore_preferences(wxConfigBase &config, const wxString &group, DocumentId id,
                                           bool saved_project) {
    if (preferences_.size() >= maximum_string_preferences && !preferences_.contains(id.value)) return;
    const auto previous_path = config.GetPath();
    config.SetPath(group);
    auto read = [&]() -> std::optional<Preferences> {
        long version = 0, encoding = -1, mapping = 0, termination = 0, sort = 0;
        wxString identity, selected;
        Preferences saved;
        if (!config.Read("Version", &version) || (version != 1 && version != 2) ||
            !config.Read("Identity", &identity) || identity.empty() || identity.length() > maximum_preference_token ||
            !config.Read("Query", &saved.query) || saved.query.length() > maximum_string_query ||
            !config.Read("Minimum", &saved.minimum) || saved.minimum.length() > 20 ||
            !config.Read("Maximum", &saved.maximum) || saved.maximum.length() > 20 ||
            !config.Read("Encoding", &encoding) || !config.Read("Mapping", &mapping) ||
            !config.Read("Termination", &termination) || !config.Read("Sort", &sort) ||
            !config.Read("Selected", &selected) || selected.length() > maximum_preference_token ||
            mapping < 0 || mapping > 2 || termination < 0 || termination > 2 || sort < 0 || sort > 5)
            return {};
        if (!config.Read("MinimumCharacters", &saved.minimum_characters)) saved.minimum_characters = "0";
        if (!config.Read("MaximumCharacters", &saved.maximum_characters)) saved.maximum_characters.clear();
        if (saved.minimum_characters.length() > 20 || saved.maximum_characters.length() > 20) return {};
        if (encoding != -1 && std::none_of(string_encodings.begin(), string_encodings.end(), [encoding](auto item) {
                return static_cast<long>(item) == encoding;
            })) return {};
        saved.encoding = static_cast<int>(encoding);
        saved.mapping = static_cast<int>(mapping);
        saved.termination = static_cast<int>(termination);
        saved.sort = static_cast<int>(sort);
        saved.identity = utf8(identity);
        saved.selected = utf8(selected);
        const auto token_character = [](char c) {
            return (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || c == ':';
        };
        if (!std::all_of(saved.identity.begin(), saved.identity.end(), token_character) ||
            !std::all_of(saved.selected.begin(), saved.selected.end(), token_character)) return {};
        if (version >= 2 && !saved_project) {
            long comment_count = 0;
            if (!config.Read("StandaloneCommentCount", &comment_count) || comment_count < 0 ||
                static_cast<std::size_t>(comment_count) > maximum_standalone_comments)
                return {};
            std::size_t total_comment_bytes = 0, serialized_comment_bytes = 0;
            for (long index = 0; index < comment_count; ++index) {
                wxString key, comment;
                const auto key_name = wxString::Format("StandaloneComment%ldKey", index);
                const auto text_name = wxString::Format("StandaloneComment%ldText", index);
                if (!config.Read(key_name, &key) || key.empty() || key.length() > maximum_preference_token ||
                    !config.Read(text_name, &comment)) return {};
                auto encoded_key = utf8(key);
                auto encoded_comment = utf8(comment);
        if (!std::all_of(encoded_key.begin(), encoded_key.end(), token_character) || encoded_comment.empty() ||
                    encoded_key.size() > maximum_standalone_comment_serialized - serialized_comment_bytes ||
                    encoded_comment.size() > maximum_standalone_comment_serialized - serialized_comment_bytes - encoded_key.size() ||
                    64 > maximum_standalone_comment_serialized - serialized_comment_bytes - encoded_key.size() - encoded_comment.size() ||
                    encoded_comment.size() > maximum_standalone_comment_bytes ||
                    encoded_comment.size() > maximum_standalone_comment_total - total_comment_bytes ||
                    !saved.standalone_comments.emplace(encoded_key, comment).second)
                    return {};
                total_comment_bytes += encoded_comment.size();
                serialized_comment_bytes += encoded_key.size() + encoded_comment.size() + 64;
            }
            long disposition_count = 0;
            if (!config.Read("StandaloneDispositionCount", &disposition_count)) disposition_count = 0;
            if (disposition_count < 0 || static_cast<std::size_t>(disposition_count) > maximum_standalone_dispositions)
                return {};
            for (long index = 0; index < disposition_count; ++index) {
                wxString key;
                long value = 0;
                if (!config.Read(wxString::Format("StandaloneDisposition%ldKey", index), &key) || key.empty() ||
                    key.length() > maximum_preference_token ||
                    !config.Read(wxString::Format("StandaloneDisposition%ldValue", index), &value) || value < 1 || value > 3)
                    return {};
                const auto encoded_key = utf8(key);
                if (!std::all_of(encoded_key.begin(), encoded_key.end(), token_character) ||
                    !saved.standalone_dispositions.emplace(encoded_key, static_cast<std::uint8_t>(value)).second) return {};
            }
        }
        saved.match_project_uuid = saved_project;
        return saved;
    };
    if (auto saved = read()) preferences_.insert_or_assign(id.value, std::move(*saved));
    config.SetPath(previous_path);
}

std::string StringBrowserView::project_preference_payload(DocumentId id,const ProjectSnapshot &project) {
    remember_preferences();auto it=preferences_.find(id.value);Preferences defaults;
    if(it==preferences_.end()) {auto identity=preference_identity(project,true);if(!identity)return {};defaults.identity=*identity;}
    const auto &p=it==preferences_.end()?defaults:it->second;const auto query=utf8(p.query);const auto selected=p.selected;
    std::string out="3|"+p.identity+"|"+hex_bytes(query)+"|"+utf8(p.minimum)+"|"+utf8(p.maximum)+"|"+
        std::to_string(p.encoding)+"|"+std::to_string(p.mapping)+"|"+std::to_string(p.termination)+"|"+
        std::to_string(p.sort)+"|"+hex_bytes(selected)+"|"+utf8(p.minimum_characters)+"|"+
        utf8(p.maximum_characters);
    const auto expected=preference_identity(project,true);if(!expected||*expected!=p.identity||out.size()>16384)return {};
    return out;
}
void StringBrowserView::restore_project_preference(std::string_view payload,DocumentId id,const ProjectSnapshot &project) {
    if(payload.empty()||payload.size()>16384||preferences_.size()>=maximum_string_preferences&&!preferences_.contains(id.value))return;
    std::vector<std::string_view> fields;fields.reserve(12);size_t start=0;
    while (start <= payload.size()) {
        const auto end = payload.find('|', start);
        fields.push_back(payload.substr(start, end == std::string_view::npos ? payload.size() - start : end - start));
        if (end == std::string_view::npos) break;
        start = end + 1;
    }
    if (fields.empty()) return;
    const bool legacy = fields[0] == "2" && fields.size() == 10;
    const bool current = fields[0] == "3" && fields.size() == 12;
    if (!legacy && !current) return;
    const auto identity=preference_identity(project,true);if(!identity||fields[1]!=*identity||fields[2].size()>maximum_string_query*8||fields[3].size()>20||fields[4].size()>20||fields[9].size()>maximum_preference_token*2||
        (current && (fields[10].size()>20||fields[11].size()>20)))return;
    auto query=unhex_bytes(fields[2]),selected=unhex_bytes(fields[9]);if(!query||!selected||query->size()>maximum_string_query*4||selected->size()>maximum_preference_token)return;
    auto parse=[](std::string_view s,int &v){auto [ptr,ec]=std::from_chars(s.data(),s.data()+s.size(),v);return ec==std::errc{}&&ptr==s.data()+s.size();};
    Preferences p;int encoding=-1,mapping=0,termination=0,sort=0;
    if(!parse(fields[5],encoding)||!parse(fields[6],mapping)||!parse(fields[7],termination)||!parse(fields[8],sort)||mapping<0||mapping>2||termination<0||termination>2||sort<0||sort>5)return;
    if(encoding!=-1&&std::none_of(string_encodings.begin(),string_encodings.end(),[&](auto x){return static_cast<int>(x)==encoding;}))return;
    const auto token_character=[](char c){return(c>='0'&&c<='9')||(c>='a'&&c<='f')||c==':';};
    if(!std::all_of(selected->begin(),selected->end(),token_character))return;
    p.identity=*identity;p.query=wxString::FromUTF8(*query);p.minimum=wxString::FromUTF8(std::string(fields[3]));p.maximum=wxString::FromUTF8(std::string(fields[4]));
    if (current) {
        p.minimum_characters=wxString::FromUTF8(std::string(fields[10]));
        p.maximum_characters=wxString::FromUTF8(std::string(fields[11]));
    }
    p.encoding=encoding;p.mapping=mapping;p.termination=termination;p.sort=sort;p.selected=std::move(*selected);p.match_project_uuid=true;
    preferences_.insert_or_assign(id.value,std::move(p));
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
    const auto minimum = unsigned_bound(minimum_bytes_->GetValue(), 0);
    const auto maximum = unsigned_bound(maximum_bytes_->GetValue(), UINT64_MAX);
    const auto minimum_characters = unsigned_bound(minimum_characters_->GetValue(), 0);
    const auto maximum_characters = unsigned_bound(maximum_characters_->GetValue(), UINT64_MAX);
    const bool valid_byte_bounds = minimum && maximum && *minimum <= *maximum;
    const bool valid_character_bounds = minimum_characters && maximum_characters &&
                                        *minimum_characters <= *maximum_characters;
    const bool valid_bounds = valid_byte_bounds && valid_character_bounds;
    if (!valid_byte_bounds)
        filter_summary_->SetLabel("Invalid byte range: enter unsigned decimal bounds with minimum <= maximum. Blank maximum means no limit.");
    else if (!valid_character_bounds)
        filter_summary_->SetLabel("Invalid character range: enter unsigned decimal bounds with minimum <= maximum. Blank maximum means no limit.");
    if (document_ && valid_bounds) {
        auto query = filter_->GetValue();
        query.Trim(true).Trim(false).MakeLower();
        const auto &records = document_->strings().records;
        visible_strings_.reserve(records.size());
        for (std::size_t i = 0; i < records.size(); ++i) {
            const auto &record = records[i];
            const auto encoding = encoding_->GetSelection();
            if (encoding > 0 && (static_cast<std::size_t>(encoding) > string_encodings.size() ||
                                 record.encoding != string_encodings[static_cast<std::size_t>(encoding - 1)]))
                continue;
            if ((mapping_->GetSelection() == 1 && !record.address) ||
                (mapping_->GetSelection() == 2 && record.address) ||
                (termination_->GetSelection() == 1 && !record.terminated) ||
                (termination_->GetSelection() == 2 && record.terminated) ||
                record.byte_length < *minimum || record.byte_length > *maximum ||
                record.characters < *minimum_characters || record.characters > *maximum_characters)
                continue;
            if (!query.empty()) {
                auto preview = text(records[i].preview);
                const auto location = string_location(i);
                auto address = location ? location_text(*location, document_->image.get()) : wxString{};
                auto encoding_name = encoding_text(records[i].encoding);
                auto project_comment = comment_for_record(*document_, i);
                auto disposition = disposition_for_record(*document_, i);
                preview.MakeLower();
                address.MakeLower();
                encoding_name.MakeLower();
                project_comment.MakeLower();
                disposition.MakeLower();
                if (preview.Find(query) == wxNOT_FOUND && address.Find(query) == wxNOT_FOUND &&
                    encoding_name.Find(query) == wxNOT_FOUND && project_comment.Find(query) == wxNOT_FOUND &&
                    disposition.Find(query) == wxNOT_FOUND)
                    continue;
            }
            visible_strings_.push_back(i);
        }
        const auto order = sort_->GetSelection();
        if (order > 0)
            std::sort(visible_strings_.begin(), visible_strings_.end(), [&](std::size_t left, std::size_t right) {
                const auto &a = records[left];
                const auto &b = records[right];
                switch (order) {
                case 1: if (a.file_offset != b.file_offset) return a.file_offset.value < b.file_offset.value; break;
                case 2: if (a.byte_length != b.byte_length) return a.byte_length < b.byte_length; break;
                case 3: if (a.byte_length != b.byte_length) return a.byte_length > b.byte_length; break;
                case 4: if (a.characters != b.characters) return a.characters > b.characters; break;
                case 5: if (a.preview != b.preview) return a.preview < b.preview; break;
                }
                return left < right;
            });
        filter_summary_->SetLabel(wxString::Format("%zu of %zu discovered strings%s", visible_strings_.size(),
            records.size(), document_->strings().complete ? "" : " (partial scan; more strings may exist)"));
    }
    if (!document_ && valid_bounds) filter_summary_->SetLabel("No document");
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
        case 4: return wxString::Format("%llu", static_cast<unsigned long long>(record.characters));
        case 5: return record.terminated ? wxString("Yes") : wxString("No");
        case 6: return comment_for_record(*document_, index);
        default: {
            return disposition_for_record(*document_, index);
        }
        }
    });
    export_->Enable(document_ && !visible_strings_.empty());
    export_all_->Enable(document_ && !document_->strings().records.empty());
    const bool has_selection = document_ && selected_string_ &&
        *selected_string_ < document_->strings().records.size();
    comment_->Enable(has_selection && static_cast<bool>(comment));
    classify_->Enable(has_selection && standalone_document_);
    copy_->Enable(has_selection);
    copy_text_preview_->Enable(has_selection);
    copy_json_preview_->Enable(has_selection);
    export_bytes_->Enable(has_selection && document_->strings().records[*selected_string_].byte_length > 0 &&
                          document_->strings().records[*selected_string_].byte_length <= string_export_byte_limit);
    if (previous) {
        const auto visible = std::find(visible_strings_.begin(), visible_strings_.end(), *previous);
        if (visible != visible_strings_.end()) {
            const auto row = static_cast<std::size_t>(std::distance(visible_strings_.begin(), visible));
            strings_->select_row(row);
            return;
        }
        selected_string_.reset();
        comment_->Enable(false);
        classify_->Enable(false);
        copy_->Enable(false);
        copy_text_preview_->Enable(false);
        copy_json_preview_->Enable(false);
        refresh_byte_preview();
        reference_offset_ = 0;
        refresh_references();
    }
    refresh_cursor_context();
}

void StringBrowserView::refresh_cursor_context() {
    if (!cursor_summary_ || !reveal_cursor_) return;
    reveal_cursor_->Enable(false);
    if (!document_ || !context_known_ || !synchronized_context_) {
        cursor_summary_->SetLabel("No shared cursor selection");
        return;
    }
    std::optional<FileOffset> file;
    if (const auto *offset = std::get_if<FileOffset>(&*synchronized_context_)) {
        if (offset->value < document_->file_storage().size()) file = *offset;
    } else if (const auto *address = std::get_if<Address>(&*synchronized_context_); address && document_->image) {
        auto mapped = document_->image->to_file_offset(*address);
        if (mapped && mapped.value().value < document_->file_storage().size()) file = mapped.value();
    }
    const auto prefix = wxString("Cursor ") + location_text(*synchronized_context_, document_->image.get()) + ": ";
    if (!file) {
        cursor_summary_->SetLabel(prefix + "no verified source-file mapping");
        return;
    }
    const auto &records = document_->strings().records;
    std::optional<std::size_t> match;
    for (std::size_t index = 0; index < records.size(); ++index) {
        const auto &record = records[index];
        if (file->value >= record.file_offset.value && file->value - record.file_offset.value < record.byte_length) {
            if (!match) match = index;
            if (selected_string_ == index) break;
        }
    }
    if (!match) {
        cursor_summary_->SetLabel(prefix + (document_->strings().complete
            ? "no discovered string contains this byte"
            : "no discovered string contains this byte (scan is partial)"));
        return;
    }
    const bool visible = std::find(visible_strings_.begin(), visible_strings_.end(), *match) != visible_strings_.end();
    const auto &record = records[*match];
    cursor_summary_->SetLabel(prefix + (visible ? "string row is visible: " : "matching string is hidden by filters: ") +
        text(record.preview).Left(120));
    reveal_cursor_->Enable(!visible);
}

void StringBrowserView::reset_filters(bool reset_order) {
    pending_selection_.clear();
    filter_->ChangeValue({});
    encoding_->SetSelection(0);
    mapping_->SetSelection(0);
    termination_->SetSelection(0);
    if (reset_order) sort_->SetSelection(0);
    minimum_bytes_->ChangeValue("0");
    maximum_bytes_->ChangeValue({});
    minimum_characters_->ChangeValue("0");
    maximum_characters_->ChangeValue({});
    refresh_strings();
}

void StringBrowserView::copy_selected_row() {
    if (!document_ || !selected_string_ || *selected_string_ >= document_->strings().records.size()) {
        action_status_->SetLabel("Select a string row first");
        return;
    }
    const auto &record = document_->strings().records[*selected_string_];
    const auto location = string_location(*selected_string_);
    const std::vector<std::string> fields = {
        location ? utf8(location_text(*location, document_->image.get())) : std::string{},
        utf8(text(record.preview)),
        utf8(encoding_text(record.encoding)),
        decimal(record.byte_length),
        decimal(record.characters),
        record.terminated ? "Yes" : "No",
        utf8(comment_for_record(*document_, *selected_string_))
    };
    std::string row;
    for (std::size_t i = 0; i < fields.size(); ++i) {
        if (i) row.push_back('\t');
        row += tsv_field(fields[i]);
    }
    if (!wxTheClipboard || !wxTheClipboard->Open()) {
        action_status_->SetLabel("Clipboard is unavailable");
        return;
    }
    auto data = std::make_unique<wxTextDataObject>(wxString::FromUTF8(row.data(), row.size()));
    const bool copied = wxTheClipboard->SetData(data.get());
    if (copied)
        data.release();
    wxTheClipboard->Close();
    action_status_->SetLabel(copied ? "Copied selected string row as TSV" : "Clipboard copy failed");
}

void StringBrowserView::copy_byte_preview() {
    if (!document_ || !document_->image || !selected_string_ ||
        *selected_string_ >= document_->strings().records.size()) {
        action_status_->SetLabel("Select a string row first");
        return;
    }
    const auto &record = document_->strings().records[*selected_string_];
    const auto count = static_cast<std::size_t>(std::min<std::uint64_t>(
        record.byte_length, string_byte_preview_limit));
    const auto bytes = document_->image->storage()->read_at(record.file_offset, count);
    if (!bytes) {
        action_status_->SetLabel("Could not read string bytes: " + text(bytes.error().message));
        return;
    }
    std::string raw;
    raw.reserve(bytes.value().bytes.size());
    for (const auto byte : bytes.value().bytes)
        raw.push_back(static_cast<char>(std::to_integer<unsigned char>(byte)));
    const auto value = hex_bytes(raw);
    if (!wxTheClipboard || !wxTheClipboard->Open()) {
        action_status_->SetLabel("Clipboard is unavailable");
        return;
    }
    auto data = std::make_unique<wxTextDataObject>(wxString::FromUTF8(value.data(), value.size()));
    const bool copied = wxTheClipboard->SetData(data.get());
    if (copied)
        data.release();
    wxTheClipboard->Close();
    action_status_->SetLabel(copied
        ? wxString::Format("Copied %zu string bytes as hex%s", bytes.value().bytes.size(),
                           record.byte_length > bytes.value().bytes.size() ? " (preview only)" : "")
        : wxString("Clipboard copy failed"));
}

void StringBrowserView::copy_text_preview() {
    if (!document_ || !selected_string_ || *selected_string_ >= document_->strings().records.size()) {
        action_status_->SetLabel("Select a string row first");
        return;
    }
    const auto &record = document_->strings().records[*selected_string_];
    const auto preview = text(record.preview);
    const auto encoded = preview.utf8_str();
    if (encoded.length() > 64 * 1024) {
        action_status_->SetLabel("Decoded string preview exceeds the 64 KiB clipboard limit");
        return;
    }
    if (!wxTheClipboard || !wxTheClipboard->Open()) {
        action_status_->SetLabel("Clipboard is unavailable");
        return;
    }
    auto data = std::make_unique<wxTextDataObject>(preview);
    const bool copied = wxTheClipboard->SetData(data.get());
    if (copied) data.release();
    wxTheClipboard->Close();
    action_status_->SetLabel(!copied ? wxString("Clipboard copy failed") :
        record.characters > 256 ? wxString("Copied decoded string preview (truncated at 256 characters)")
                                : wxString("Copied decoded string text"));
}

void StringBrowserView::copy_json_preview() {
    if (!document_ || !selected_string_ || *selected_string_ >= document_->strings().records.size()) {
        action_status_->SetLabel("Select a string row first");
        return;
    }
    const auto &record = document_->strings().records[*selected_string_];
    const auto preview = text(record.preview);
    const auto bytes = utf8(preview);
    const auto round_trip = wxString::FromUTF8(bytes.data(), bytes.size());
    if (utf8(round_trip) != bytes) {
        action_status_->SetLabel("Decoded string preview is not valid UTF-8");
        return;
    }

    constexpr std::size_t clipboard_limit = 64 * 1024;
    std::string json;
    json.reserve(bytes.size() + 2);
    json.push_back('"');
    constexpr char hex[] = "0123456789ABCDEF";
    for (const unsigned char byte : bytes) {
        switch (byte) {
        case '"': json += "\\\""; break;
        case '\\': json += "\\\\"; break;
        case '\b': json += "\\b"; break;
        case '\f': json += "\\f"; break;
        case '\n': json += "\\n"; break;
        case '\r': json += "\\r"; break;
        case '\t': json += "\\t"; break;
        default:
            if (byte < 0x20 || byte == 0x7f) {
                json += "\\u00";
                json.push_back(hex[byte >> 4]);
                json.push_back(hex[byte & 0x0f]);
            } else {
                json.push_back(static_cast<char>(byte));
            }
            break;
        }
        if (json.size() > clipboard_limit) {
            action_status_->SetLabel("Quoted JSON preview exceeds the 64 KiB clipboard limit");
            return;
        }
    }
    json.push_back('"');
    if (json.size() > clipboard_limit) {
        action_status_->SetLabel("Quoted JSON preview exceeds the 64 KiB clipboard limit");
        return;
    }
    const auto json_text = wxString::FromUTF8(json.data(), json.size());
    if (utf8(json_text) != json) {
        action_status_->SetLabel("Could not encode quoted preview as UTF-8");
        return;
    }
    if (!wxTheClipboard || !wxTheClipboard->Open()) {
        action_status_->SetLabel("Clipboard is unavailable");
        return;
    }
    auto data = std::make_unique<wxTextDataObject>(json_text);
    const bool copied = wxTheClipboard->SetData(data.get());
    if (copied)
        data.release();
    wxTheClipboard->Close();
    action_status_->SetLabel(!copied ? wxString("Clipboard copy failed") :
        record.characters > 256 ? wxString("Copied JSON string preview (truncated at 256 characters)")
                                : wxString("Copied decoded preview as JSON string"));
}

void StringBrowserView::export_selected_bytes() {
    if (!document_ || !document_->image || !selected_string_ ||
        *selected_string_ >= document_->strings().records.size()) {
        action_status_->SetLabel("Select a string row first");
        return;
    }
    const auto document = document_;
    const auto selected = *selected_string_;
    const auto &record = document->strings().records[selected];
    if (!record.byte_length || record.byte_length > string_export_byte_limit) {
        action_status_->SetLabel(wxString::Format("String byte export is limited to %llu bytes",
            static_cast<unsigned long long>(string_export_byte_limit)));
        return;
    }
    const auto storage = document->image->storage();
    if (!storage || record.file_offset.value > storage->size() ||
        record.byte_length > storage->size() - record.file_offset.value) {
        action_status_->SetLabel("Selected string byte range is outside the current input");
        return;
    }
    const auto suggested = wxString::Format("string-%llX.bin",
        static_cast<unsigned long long>(record.file_offset.value));
    wxFileDialog dialog(this, "Export selected string bytes", {}, suggested,
                        "Binary files (*.bin)|*.bin|All files (*.*)|*.*", wxFD_SAVE | wxFD_OVERWRITE_PROMPT);
    if (dialog.ShowModal() != wxID_OK) return;
    if (document_ != document || selected_string_ != selected) {
        action_status_->SetLabel("The document or selection changed while the save dialog was open; export canceled");
        return;
    }
    auto path = std::filesystem::path(dialog.GetPath().ToStdWstring());
    auto protected_paths = document->project ? document->project->protected_paths
                                             : std::vector<std::filesystem::path>{};
    if (const auto file = std::dynamic_pointer_cast<const FileStorage>(document->input_storage))
        protected_paths.push_back(file->backing_path());
    auto publication = FilePublication::create(path, ExistingFilePolicy::replace, protected_paths, {});
    if (!publication) {
        action_status_->SetLabel("Could not create byte export: " + text(publication.error().message));
        return;
    }
    constexpr std::size_t chunk_size = 64 * 1024;
    std::uint64_t offset = 0;
    while (offset < record.byte_length) {
        const auto count = static_cast<std::size_t>(std::min<std::uint64_t>(
            chunk_size, record.byte_length - offset));
        auto bytes = storage->read_at(FileOffset{record.file_offset.value + offset}, count);
        if (!bytes || bytes.value().bytes.size() != count) {
            if (bytes)
                action_status_->SetLabel("Input returned a short read while exporting string bytes");
            else
                action_status_->SetLabel("Could not read selected string bytes: " + text(bytes.error().message));
            return;
        }
        auto written = publication.value()->append(std::span<const std::byte>(
            bytes.value().bytes.data(), bytes.value().bytes.size()));
        if (!written) {
            action_status_->SetLabel("Could not write selected string bytes: " + text(written.error().message));
            return;
        }
        offset += count;
    }
    auto published = publication.value()->publish();
    if (!published) {
        action_status_->SetLabel("Could not publish selected string bytes: " + text(published.error().message));
        return;
    }
    action_status_->SetLabel(wxString::Format("Exported %llu original bytes from offset 0x%llX",
        static_cast<unsigned long long>(record.byte_length),
        static_cast<unsigned long long>(record.file_offset.value)));
}

void StringBrowserView::copy_selected_reference() {
    const auto selected = references_->selected_row();
    if (!document_ || !selected_string_ || !reference_page_ || !selected ||
        *selected >= reference_page_->rows.size() || *selected_string_ >= document_->strings().records.size()) {
        action_status_->SetLabel("Select an incoming reference row first");
        return;
    }
    const auto &record = document_->strings().records[*selected_string_];
    const auto &reference = reference_page_->rows[*selected];
    const auto string_at = string_location(*selected_string_);
    const std::vector<std::string> fields = {
        string_at ? utf8(location_text(*string_at, document_->image.get())) : std::string{},
        utf8(text(record.preview)),
        utf8(location_text(reference.source, document_->image.get())),
        utf8(reference_kind_text(reference.kind)),
        reference.operand_index ? std::to_string(*reference.operand_index) : std::string{}
    };
    std::string row;
    for (std::size_t i = 0; i < fields.size(); ++i) {
        if (i) row.push_back('\t');
        row += tsv_field(fields[i]);
    }
    if (!wxTheClipboard || !wxTheClipboard->Open()) {
        action_status_->SetLabel("Clipboard is unavailable");
        return;
    }
    auto data = std::make_unique<wxTextDataObject>(wxString::FromUTF8(row.data(), row.size()));
    const bool copied = wxTheClipboard->SetData(data.get());
    if (copied) data.release();
    wxTheClipboard->Close();
    action_status_->SetLabel(copied ? "Copied selected string reference as TSV" : "Clipboard copy failed");
}

void StringBrowserView::copy_reference_page() {
    if (!document_ || !selected_string_ || !reference_page_ || reference_page_->rows.empty() ||
        *selected_string_ >= document_->strings().records.size()) {
        action_status_->SetLabel("No incoming reference page to copy");
        return;
    }
    const auto &record = document_->strings().records[*selected_string_];
    const auto string_at = string_location(*selected_string_);
    const std::vector<std::string> prefix = {
        string_at ? utf8(location_text(*string_at, document_->image.get())) : std::string{},
        utf8(text(record.preview))
    };
    std::string rows = "string_address\tstring_preview\tsource\tkind\toperand\r\n";
    for (const auto &reference : reference_page_->rows) {
        const std::vector<std::string> fields = {
            prefix[0], prefix[1], utf8(location_text(reference.source, document_->image.get())),
            utf8(reference_kind_text(reference.kind)),
            reference.operand_index ? std::to_string(*reference.operand_index) : std::string{}
        };
        for (std::size_t i = 0; i < fields.size(); ++i) {
            if (i) rows.push_back('\t');
            rows += tsv_field(fields[i]);
        }
        rows += "\r\n";
    }
    if (!wxTheClipboard || !wxTheClipboard->Open()) {
        action_status_->SetLabel("Clipboard is unavailable");
        return;
    }
    auto data = std::make_unique<wxTextDataObject>(wxString::FromUTF8(rows.data(), rows.size()));
    const bool copied = wxTheClipboard->SetData(data.get());
    if (copied) data.release();
    wxTheClipboard->Close();
    action_status_->SetLabel(copied
        ? wxString::Format("Copied %zu incoming references as TSV", reference_page_->rows.size())
        : wxString("Clipboard copy failed"));
}

void StringBrowserView::refresh_byte_preview() {
    if (!byte_preview_) return;
    if (!document_ || !document_->image || !selected_string_ ||
        *selected_string_ >= document_->strings().records.size()) {
        byte_preview_->ChangeValue("Select a string to inspect its original bytes");
        return;
    }
    const auto &record = document_->strings().records[*selected_string_];
    const auto count = static_cast<std::size_t>(std::min<std::uint64_t>(
        record.byte_length, string_byte_preview_limit));
    const auto bytes = document_->image->storage()->read_at(record.file_offset, count);
    if (!bytes) {
        byte_preview_->ChangeValue("Could not read string bytes: " + text(bytes.error().message));
        return;
    }
    wxString rendered;
    for (const auto byte : bytes.value().bytes) {
        if (!rendered.empty()) rendered += ' ';
        rendered += wxString::Format("%02X", std::to_integer<unsigned>(byte));
    }
    if (record.byte_length > bytes.value().bytes.size()) rendered += " ...";
    byte_preview_->ChangeValue(wxString::Format("%s  [%llu bytes; %s]",
        rendered, static_cast<unsigned long long>(record.byte_length), encoding_text(record.encoding)));
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
    // Document snapshots may be replaced when tabs switch or project analysis
    // publishes while the native save dialog is open. Never export a snapshot
    // that is no longer the active document.
    if (document_ != document) {
        wxMessageBox("The active document or its analysis changed while the save dialog was open. "
                     "No strings were exported; review the current document and try again.",
                     "Export strings", wxOK | wxICON_WARNING, this);
        return;
    }
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
                         "terminated", "preview", "comment", "incoming_source", "reference_kind",
                         "operand_index", "reference_status"})))
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
        const auto string_location = record.address ? Location{*record.address} : Location{record.file_offset};
        const std::vector<std::string> prefix = {utf8(address), hex(record.file_offset.value),
            utf8(encoding_text(record.encoding)), decimal(record.byte_length), decimal(record.characters),
            record.terminated ? "true" : "false", utf8(text(record.preview)),
            utf8(comment_for_record(*document, record_index))};
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
    const auto &record = document_->strings().records[record_index];
    selected_string_ = record_index;
    pending_selection_.clear();
    comment_->Enable(static_cast<bool>(comment));
    classify_->Enable(standalone_document_);
    copy_->Enable(true);
    copy_byte_preview_->Enable(true);
    copy_text_preview_->Enable(true);
    copy_json_preview_->Enable(true);
    export_bytes_->Enable(record.byte_length > 0 && record.byte_length <= string_export_byte_limit);
    action_status_->SetLabel("Selected string ready to copy");
    refresh_byte_preview();
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
    copy_reference_->Enable(false);
    copy_reference_page_->Enable(false);
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
    copy_reference_->Enable(false);
    copy_reference_page_->Enable(!reference_page_->rows.empty());
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
    const auto contains = [&](std::size_t index) {
        if (index >= records.size()) return false;
        const auto &record = records[index];
        return file->value >= record.file_offset.value && file->value - record.file_offset.value < record.byte_length;
    };
    // Encodings can overlap at the same offset. Keep the selected visible
    // interpretation, then prefer a visible candidate before clearing facets.
    std::optional<std::size_t> candidate;
    if (selected_string_ && contains(*selected_string_) &&
        std::find(visible_strings_.begin(), visible_strings_.end(), *selected_string_) != visible_strings_.end())
        candidate = selected_string_;
    if (!candidate)
        for (const auto index : visible_strings_)
            if (contains(index)) { candidate = index; break; }
    if (!candidate)
        for (std::size_t i = 0; i < records.size(); ++i)
            if (contains(i)) { candidate = i; break; }
    if (!candidate) return;
    auto visible = std::find(visible_strings_.begin(), visible_strings_.end(), *candidate);
    if (visible == visible_strings_.end()) return;
    strings_->select_row(static_cast<std::size_t>(std::distance(visible_strings_.begin(), visible)));
    choose_string(*candidate, false);
}

void StringBrowserView::clear_selection() {
    pending_selection_.clear();
    strings_->clear_selection();
    references_->clear_selection();
    selected_string_.reset();
    comment_->Enable(false);
    classify_->Enable(false);
    copy_->Enable(false);
    copy_byte_preview_->Enable(false);
    copy_text_preview_->Enable(false);
    copy_json_preview_->Enable(false);
    export_bytes_->Enable(false);
    action_status_->SetLabel("Select a string to copy or comment");
    refresh_byte_preview();
    reference_offset_ = 0;
    refresh_references();
}

wxString StringBrowserView::comment_for_record(const DocumentSnapshot &document,
                                               std::size_t record_index) const {
    if (record_index >= document.strings().records.size()) return {};
    const auto &record = document.strings().records[record_index];
    const auto location = record.address ? Location{*record.address} : Location{record.file_offset};
    if (document.project) {
        const auto *annotation = annotation_at(*document.project, location);
        if (annotation) return text(annotation->comment);
    }
    if (!standalone_document_ || !document_ || document_->id != document.id ||
        !document.project || !document.project->state) return {};
    const auto saved = preferences_.find(document.id.value);
    if (saved == preferences_.end()) return {};
    const auto identity = preference_identity(*document.project, saved->second.match_project_uuid);
    if (!identity || *identity != saved->second.identity) return {};
    const auto key = selection_key(record, *document.project);
    const auto comment_entry = saved->second.standalone_comments.find(key);
    return comment_entry == saved->second.standalone_comments.end() ? wxString{} : comment_entry->second;
}

wxString StringBrowserView::disposition_for_record(const DocumentSnapshot &document,
                                                    std::size_t record_index) const {
    if (record_index >= document.strings().records.size() || !standalone_document_ || !document_ ||
        document_->id != document.id || !document.project || !document.project->state) return "Unclassified";
    const auto saved = preferences_.find(document.id.value);
    if (saved == preferences_.end()) return "Unclassified";
    const auto identity = preference_identity(*document.project, saved->second.match_project_uuid);
    if (!identity || *identity != saved->second.identity) return "Unclassified";
    const auto key = selection_key(document.strings().records[record_index], *document.project);
    const auto found = saved->second.standalone_dispositions.find(key);
    if (found == saved->second.standalone_dispositions.end()) return "Unclassified";
    switch (found->second) {
    case 1: return "Confirmed string";
    case 2: return "Not a string";
    case 3: return "Review";
    default: return "Unclassified";
    }
}

bool StringBrowserView::set_standalone_disposition(Location location, std::uint8_t value) {
    if (!standalone_document_ || !document_ || !document_->project || !document_->project->state || value > 3) return false;
    std::optional<std::string> key;
    for (std::size_t index = 0; index < document_->strings().records.size(); ++index)
        if (string_location(index) == location) {
            key = selection_key(document_->strings().records[index], *document_->project);
            break;
        }
    if (!key || key->empty() || key->size() > maximum_preference_token) return false;
    auto found = preferences_.find(document_->id.value);
    auto identity = preference_identity(*document_->project, false);
    if (!identity) return false;
    Preferences updated;
    if (found != preferences_.end()) {
        const auto existing_identity = preference_identity(*document_->project, found->second.match_project_uuid);
        if (existing_identity && *existing_identity == found->second.identity) updated = found->second;
    }
    if (updated.identity.empty()) {
        if (preferences_.size() >= maximum_string_preferences && found == preferences_.end()) return false;
        updated.identity = *identity;
        updated.match_project_uuid = false;
    }
    if (value == 0) updated.standalone_dispositions.erase(*key);
    else {
        if (!updated.standalone_dispositions.contains(*key) &&
            updated.standalone_dispositions.size() >= maximum_standalone_dispositions) return false;
        updated.standalone_dispositions.insert_or_assign(*key, value);
    }
    if (!persist_standalone_annotations(updated)) return false;
    preferences_.insert_or_assign(document_->id.value, std::move(updated));
    remember_preferences();
    refresh_strings();
    action_status_->SetLabel(value == 0 ? "Standalone string disposition cleared" : "Standalone string disposition saved for this input");
    return true;
}

std::optional<wxString> StringBrowserView::standalone_comment(Location location) const {
    if (!standalone_document_ || !document_ || !document_->project || !document_->project->state) return {};
    for (std::size_t index = 0; index < document_->strings().records.size(); ++index)
        if (string_location(index) == location) {
            const auto value = comment_for_record(*document_, index);
            return value.empty() ? std::optional<wxString>{} : std::optional<wxString>{value};
        }
    return {};
}

void StringBrowserView::export_standalone_notes() {
    if (!standalone_document_ || !document_ || !document_->project || !document_->project->state) return;
    const auto document = document_;
    const auto input_key = standalone_annotation_key(*document->project);
    const auto found = preferences_.find(document->id.value);
    if (!input_key || found == preferences_.end()) {
        wxMessageBox("There are no standalone string notes to export.", "Export standalone notes",
                     wxOK | wxICON_INFORMATION, this);
        return;
    }
    const auto preference_identity_value = preference_identity(*document->project, found->second.match_project_uuid);
    if (!preference_identity_value || *preference_identity_value != found->second.identity) {
        wxMessageBox("The active input identity changed. Reopen the document before exporting notes.",
                     "Export standalone notes", wxOK | wxICON_WARNING, this);
        return;
    }

    std::string payload = "HEXLAB-STRING-NOTES\t1\nINPUT\t" + *input_key + "\n";
    for (const auto &[key, value] : found->second.standalone_comments) {
        const auto encoded_value = utf8(value);
        payload += key + "\t" + hex_bytes(encoded_value) + "\n";
        if (payload.size() > 4 * 1024 * 1024) {
            wxMessageBox("The standalone note export exceeds the portable file limit.", "Export standalone notes",
                         wxOK | wxICON_WARNING, this);
            return;
        }
    }
    wxFileDialog dialog(this, "Export standalone string notes", {}, "hexlab-string-notes.txt",
                        "HexLab note files (*.txt)|*.txt|All files (*.*)|*.*", wxFD_SAVE | wxFD_OVERWRITE_PROMPT);
    if (dialog.ShowModal() != wxID_OK) return;
    if (document_ != document) {
        wxMessageBox("The active document changed while the save dialog was open. No notes were exported.",
                     "Export standalone notes", wxOK | wxICON_WARNING, this);
        return;
    }
    std::vector<std::filesystem::path> protected_paths = document->project->protected_paths;
    if (const auto file = std::dynamic_pointer_cast<const FileStorage>(document->input_storage))
        protected_paths.push_back(file->backing_path());
    auto publication = FilePublication::create(std::filesystem::path(dialog.GetPath().ToStdWstring()),
                                               ExistingFilePolicy::replace, protected_paths, {});
    if (!publication) {
        wxMessageBox(text(publication.error().message), "Export standalone notes", wxOK | wxICON_ERROR, this);
        return;
    }
    const auto written = publication.value()->append(std::as_bytes(std::span(payload.data(), payload.size())));
    if (!written) {
        wxMessageBox(text(written.error().message), "Export standalone notes", wxOK | wxICON_ERROR, this);
        return;
    }
    const auto published = publication.value()->publish();
    if (!published) {
        wxMessageBox(text(published.error().message), "Export standalone notes", wxOK | wxICON_ERROR, this);
        return;
    }
    action_status_->SetLabel(wxString::Format("Exported %llu standalone string notes",
        static_cast<unsigned long long>(found->second.standalone_comments.size())));
}

void StringBrowserView::import_standalone_notes() {
    if (!standalone_document_ || !document_ || !document_->project || !document_->project->state) return;
    const auto document = document_;
    wxFileDialog dialog(this, "Import standalone string notes", {}, {},
                        "HexLab note files (*.txt)|*.txt|All files (*.*)|*.*", wxFD_OPEN | wxFD_FILE_MUST_EXIST);
    if (dialog.ShowModal() != wxID_OK) return;
    if (document_ != document) {
        wxMessageBox("The active document changed while the open dialog was shown. No notes were imported.",
                     "Import standalone notes", wxOK | wxICON_WARNING, this);
        return;
    }
    const auto input_key = standalone_annotation_key(*document->project);
    if (!input_key) {
        wxMessageBox("The active input identity could not be verified.", "Import standalone notes",
                     wxOK | wxICON_ERROR, this);
        return;
    }
    const std::filesystem::path path(dialog.GetPath().ToStdWstring());
    std::error_code file_error;
    const auto file_size = std::filesystem::file_size(path, file_error);
    if (file_error || file_size > 4 * 1024 * 1024) {
        wxMessageBox("The note file is unavailable or exceeds the 4 MiB import limit.",
                     "Import standalone notes", wxOK | wxICON_ERROR, this);
        return;
    }
    std::ifstream input(path, std::ios::binary);
    if (!input) {
        wxMessageBox("The selected note file could not be opened.", "Import standalone notes",
                     wxOK | wxICON_ERROR, this);
        return;
    }
    std::string payload(static_cast<std::size_t>(file_size), '\0');
    if (!payload.empty()) input.read(payload.data(), static_cast<std::streamsize>(payload.size()));
    if (!input || input.peek() != std::char_traits<char>::eof()) {
        wxMessageBox("The note file changed or could not be read completely.", "Import standalone notes",
                     wxOK | wxICON_ERROR, this);
        return;
    }
    const auto line_at = [&](std::size_t &position) -> std::optional<std::string_view> {
        if (position > payload.size()) return {};
        const auto end = payload.find('\n', position);
        auto line = std::string_view(payload).substr(position,
            end == std::string::npos ? payload.size() - position : end - position);
        if (!line.empty() && line.back() == '\r') line.remove_suffix(1);
        position = end == std::string::npos ? payload.size() + 1 : end + 1;
        return line;
    };
    std::size_t cursor = 0;
    const auto magic = line_at(cursor);
    const auto identity_line = line_at(cursor);
    if (!magic || *magic != "HEXLAB-STRING-NOTES\t1" || !identity_line ||
        !identity_line->starts_with("INPUT\t") || identity_line->substr(6) != *input_key) {
        wxMessageBox("These notes were not exported for this exact input and loader recipe.",
                     "Import standalone notes", wxOK | wxICON_WARNING, this);
        return;
    }

    std::map<std::string, wxString> imported;
    std::size_t total_text_bytes = 0, serialized_bytes = 0;
    const auto valid_key = [](std::string_view key) {
        if (key.size() > maximum_preference_token) return false;
        std::array<std::string_view, 7> fields{};
        std::size_t start = 0;
        for (std::size_t index = 0; index < 6; ++index) {
            const auto end = key.find(':', start);
            if (end == std::string_view::npos || end == start) return false;
            fields[index] = key.substr(start, end - start);
            start = end + 1;
        }
        fields.back() = key.substr(start);
        if (fields.back().size() != 64 ||
            !std::all_of(fields.back().begin(), fields.back().end(), [](char c) {
                return (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f');
            })) return false;
        std::array<std::uint64_t, 6> numbers{};
        for (std::size_t index = 0; index < numbers.size(); ++index) {
            if (!std::all_of(fields[index].begin(), fields[index].end(), [](char c) {
                    return c >= '0' && c <= '9';
                })) return false;
            const auto parsed = std::from_chars(fields[index].data(), fields[index].data() + fields[index].size(), numbers[index]);
            if (parsed.ec != std::errc{} || parsed.ptr != fields[index].data() + fields[index].size()) return false;
        }
        return numbers[2] > 0 && numbers[4] <= 1 &&
            std::any_of(string_encodings.begin(), string_encodings.end(), [&](auto encoding) {
                return static_cast<std::uint64_t>(encoding) == numbers[1];
            });
    };
    while (cursor <= payload.size()) {
        const auto line = line_at(cursor);
        if (!line) break;
        if (line->empty()) {
            if (cursor <= payload.size()) {
                wxMessageBox("The note file contains an unexpected blank record.", "Import standalone notes",
                             wxOK | wxICON_ERROR, this);
                return;
            }
            break;
        }
        const auto separator = line->find('\t');
        if (separator == std::string_view::npos || line->find('\t', separator + 1) != std::string_view::npos) {
            wxMessageBox("The note file contains a malformed record.", "Import standalone notes",
                         wxOK | wxICON_ERROR, this);
            return;
        }
        const auto key = line->substr(0, separator);
        const auto hex_text = line->substr(separator + 1);
        if (!valid_key(key) || hex_text.size() > 2 * maximum_standalone_comment_bytes) {
            wxMessageBox("A note has an invalid string fingerprint or exceeds the size limit.",
                         "Import standalone notes", wxOK | wxICON_ERROR, this);
            return;
        }
        const auto decoded = unhex_bytes(hex_text);
        if (!decoded || decoded->empty() || decoded->find('\0') != std::string::npos ||
            decoded->size() > maximum_standalone_comment_bytes ||
            decoded->size() > maximum_standalone_comment_total - total_text_bytes ||
            key.size() > maximum_standalone_comment_serialized - serialized_bytes ||
            decoded->size() > maximum_standalone_comment_serialized - serialized_bytes - key.size() ||
            64 > maximum_standalone_comment_serialized - serialized_bytes - key.size() - decoded->size()) {
            wxMessageBox("The note file contains invalid UTF-8, empty text, or exceeds the note limits.",
                         "Import standalone notes", wxOK | wxICON_ERROR, this);
            return;
        }
        const auto note = wxString::FromUTF8(decoded->data(), decoded->size());
        if (utf8(note) != *decoded || !imported.emplace(std::string(key), note).second) {
            wxMessageBox("The note file contains invalid text or duplicate string records.",
                         "Import standalone notes", wxOK | wxICON_ERROR, this);
            return;
        }
        total_text_bytes += decoded->size();
        serialized_bytes += key.size() + decoded->size() + 64;
        if (imported.size() > maximum_standalone_comments) {
            wxMessageBox("The note file exceeds the 2,048 note limit.", "Import standalone notes",
                         wxOK | wxICON_ERROR, this);
            return;
        }
    }
    if (imported.empty()) {
        wxMessageBox("The note file contains no notes.", "Import standalone notes",
                     wxOK | wxICON_INFORMATION, this);
        return;
    }
    if (wxMessageBox(wxString::Format("Merge %llu notes into this input? Matching existing notes will be replaced.",
                          static_cast<unsigned long long>(imported.size())),
                     "Import standalone notes", wxYES_NO | wxICON_QUESTION, this) != wxYES)
        return;

    const auto existing = preferences_.find(document->id.value);
    if (existing == preferences_.end() && preferences_.size() >= maximum_string_preferences) {
        wxMessageBox("The workspace already retains the maximum number of Strings document records.",
                     "Import standalone notes", wxOK | wxICON_WARNING, this);
        return;
    }
    const auto identity = preference_identity(*document->project, existing == preferences_.end()
        ? true : existing->second.match_project_uuid);
    if (!identity) return;
    Preferences updated;
    if (existing != preferences_.end()) {
        const auto existing_identity = preference_identity(*document->project, existing->second.match_project_uuid);
        if (existing_identity && *existing_identity == existing->second.identity) updated = existing->second;
    }
    if (updated.identity.empty()) {
        updated.identity = *identity;
        updated.match_project_uuid = existing == preferences_.end() ? true : existing->second.match_project_uuid;
    }
    for (auto &[key, value] : imported) updated.standalone_comments.insert_or_assign(std::move(key), std::move(value));
    if (updated.standalone_comments.size() > maximum_standalone_comments) {
        wxMessageBox("Merging these notes would exceed the 2,048 note limit.", "Import standalone notes",
                     wxOK | wxICON_ERROR, this);
        return;
    }
    std::size_t merged_bytes = 0;
    for (const auto &[key, value] : updated.standalone_comments) {
        const auto bytes = utf8(value).size();
        if (bytes > maximum_standalone_comment_total - merged_bytes) {
            wxMessageBox("Merging these notes would exceed the 1 MiB text limit.", "Import standalone notes",
                         wxOK | wxICON_ERROR, this);
            return;
        }
        merged_bytes += bytes;
    }
    if (!persist_standalone_annotations(updated)) {
        wxMessageBox("The merged notes could not be saved to local workspace preferences.",
                     "Import standalone notes", wxOK | wxICON_ERROR, this);
        return;
    }
    preferences_.insert_or_assign(document->id.value, std::move(updated));
    refresh_strings();
    action_status_->SetLabel(wxString::Format("Imported %llu standalone string notes",
        static_cast<unsigned long long>(imported.size())));
}

bool StringBrowserView::set_standalone_comment(Location location, const wxString &comment_text) {
    if (!standalone_document_ || !document_ || !document_->project || !document_->project->state) return false;
    const auto encoded_comment = utf8(comment_text);
    if (encoded_comment.size() > maximum_standalone_comment_bytes) return false;
    std::optional<std::string> key;
    for (std::size_t index = 0; index < document_->strings().records.size(); ++index)
        if (string_location(index) == location) {
            key = selection_key(document_->strings().records[index], *document_->project);
            break;
        }
    if (!key || key->empty() || key->size() > maximum_preference_token) return false;

    auto found = preferences_.find(document_->id.value);
    bool match_uuid = found == preferences_.end() ? true : found->second.match_project_uuid;
    auto identity = preference_identity(*document_->project, match_uuid);
    if (!identity) return false;
    Preferences updated;
    if (found != preferences_.end()) {
        const auto existing_identity = preference_identity(*document_->project, found->second.match_project_uuid);
        if (existing_identity && *existing_identity == found->second.identity)
            updated = found->second;
        else
            found = preferences_.end();
    }
    if (found == preferences_.end()) {
        if (preferences_.size() >= maximum_string_preferences) return false;
        match_uuid = true;
        identity = preference_identity(*document_->project, match_uuid);
        if (!identity) return false;
        updated.match_project_uuid = match_uuid;
        updated.identity = *identity;
    }
    const auto existing = updated.standalone_comments.find(*key);
    if (encoded_comment.empty()) {
        if (existing == updated.standalone_comments.end()) return true;
        updated.standalone_comments.erase(existing);
    } else {
        std::size_t total = encoded_comment.size();
        std::size_t serialized = encoded_comment.size() + key->size() + 64;
        for (const auto &[other_key, value] : updated.standalone_comments) {
            if (other_key == *key) continue;
            const auto bytes = utf8(value).size();
            if (bytes > maximum_standalone_comment_total - total) return false;
            total += bytes;
            if (other_key.size() > maximum_standalone_comment_serialized - serialized ||
                bytes > maximum_standalone_comment_serialized - serialized - other_key.size() ||
                64 > maximum_standalone_comment_serialized - serialized - other_key.size() - bytes) return false;
            serialized += other_key.size() + bytes + 64;
        }
        if (total > maximum_standalone_comment_total || serialized > maximum_standalone_comment_serialized ||
            (existing == updated.standalone_comments.end() &&
             updated.standalone_comments.size() >= maximum_standalone_comments)) return false;
        updated.standalone_comments.insert_or_assign(*key, comment_text);
    }
    if (!persist_standalone_annotations(updated)) return false;
    preferences_.insert_or_assign(document_->id.value, std::move(updated));
    remember_preferences();
    refresh_strings();
    action_status_->SetLabel(encoded_comment.empty() ? "Standalone string comment removed" :
                             "Standalone string comment saved for this input");
    return true;
}

} // namespace hexlab::desktop
