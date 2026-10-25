#include "edit_dialogs.hpp"
#include "hexlab/analysis/search.hpp"
#include "hexlab/workspace/navigation.hpp"
#include "data_views.hpp"
#include <wx/textctrl.h>
#include <wx/stattext.h>
#include <wx/sizer.h>
#include <charconv>
#include <sstream>
namespace hexlab::desktop {
std::optional<ProjectCommand> edit_dialog(wxWindow *parent, const wxString &title, const wxString &explanation,
                                          const wxString &initial, bool multiline, EditBuilder build) {
    wxDialog dialog(parent, wxID_ANY, title, wxDefaultPosition, wxDefaultSize,
                    wxDEFAULT_DIALOG_STYLE | wxRESIZE_BORDER);
    auto *box = new wxBoxSizer(wxVERTICAL);
    box->Add(new wxStaticText(&dialog, wxID_ANY, explanation), 0, wxALL, 10);
    auto *value = new wxTextCtrl(&dialog, wxID_ANY, initial, wxDefaultPosition,
                                 dialog.FromDIP(wxSize(460, multiline ? 180 : 30)), multiline ? wxTE_MULTILINE : 0);
    value->SetName("edit-value");
    box->Add(value, 1, wxEXPAND | wxLEFT | wxRIGHT, 10);
    auto *error = new wxStaticText(&dialog, wxID_ANY, "");
    error->SetName("edit-error");
    box->Add(error, 0, wxALL, 10);
    box->Add(dialog.CreateButtonSizer(wxOK | wxCANCEL), 0, wxALL | wxALIGN_RIGHT, 10);
    dialog.SetSizerAndFit(box);
    std::optional<ProjectCommand> result;
    dialog.Bind(
        wxEVT_BUTTON,
        [&](wxCommandEvent &) {
            auto parsed = build(value->GetValue());
            if (!parsed) {
                error->SetLabel(text(parsed.error().message));
                dialog.Layout();
                return;
            }
            result = std::move(parsed.value());
            dialog.EndModal(wxID_OK);
        },
        wxID_OK);
    value->SetFocus();
    if (!multiline)
        value->SelectAll();
    if (dialog.ShowModal() != wxID_OK)
        return {};
    return result;
}
Result<std::vector<std::byte>> parse_patch_text(const wxString &text_value) {
    auto encoded = text_value.utf8_str();
    std::string text_bytes(encoded.data(), encoded.length());
    auto valid = search_query_fingerprint(BytePattern{text_bytes});
    if (!valid)
        return valid.error();
    std::istringstream input(text_bytes);
    std::string octet;
    std::vector<std::byte> bytes;
    while (input >> octet) {
        if (octet == "??")
            return Error{ErrorCode::invalid_argument, "Patch bytes cannot contain wildcards"};
        unsigned value = 0;
        auto parsed = std::from_chars(octet.data(), octet.data() + octet.size(), value, 16);
        if (parsed.ec != std::errc{} || parsed.ptr != octet.data() + octet.size())
            return Error{ErrorCode::invalid_argument, "Use hexadecimal octets separated by spaces"};
        if (value > 0xFF)
            return Error{ErrorCode::invalid_argument, "Each patch value must fit in one byte (00 to FF)"};
        bytes.push_back(std::byte(value));
    }
    return bytes;
}
Result<std::vector<DecisionRange>> parse_chunk_text(const wxString &text_value, AddressSpaceId space) {
    std::wstring encoded = text_value.ToStdWstring();
    std::wstring_view remaining = encoded;
    std::vector<DecisionRange> chunks;
    if (remaining.empty())
        return chunks;
    while (!remaining.empty()) {
        auto comma = remaining.find(L',');
        auto item = remaining.substr(0, comma);
        auto plus = item.find(L'+');
        if (plus == item.npos)
            return Error{ErrorCode::invalid_argument, "Use address+size pairs separated by commas"};
        auto begin = parse_address(item.substr(0, plus)), size = parse_address(item.substr(plus + 1));
        if (!begin)
            return begin.error();
        if (!size)
            return size.error();
        if (!size.value())
            return Error{ErrorCode::invalid_argument, "Chunk size must be positive"};
        chunks.push_back({{space, begin.value()}, size.value()});
        if (comma == remaining.npos)
            break;
        remaining.remove_prefix(comma + 1);
        if (remaining.empty())
            return Error{ErrorCode::invalid_argument, "Missing chunk after comma"};
    }
    return chunks;
}
} // namespace hexlab::desktop
