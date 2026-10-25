#include "reference_dialog.hpp"
#include "hexlab/workspace/navigation.hpp"
#include "data_views.hpp"
#include <wx/dialog.h>
#include <wx/choice.h>
#include <wx/checkbox.h>
#include <wx/textctrl.h>
#include <wx/stattext.h>
#include <wx/sizer.h>
namespace hexlab::desktop {
std::optional<ProjectCommand> reference_dialog(wxWindow *parent, Location source, AddressSpaceId space,
                                               std::shared_ptr<const Image> image) {
    wxDialog dialog(parent, wxID_ANY, "Explicit reference");
    dialog.SetName("reference-dialog");
    auto *box = new wxBoxSizer(wxVERTICAL);
    box->Add(new wxStaticText(&dialog, wxID_ANY, "Source: " + location_text(source, image.get())), 0, wxALL, 10);
    wxArrayString domains;
    domains.Add("Virtual address");
    domains.Add("File offset");
    if (image && image->layout().x86_profile)
        domains.Add("Selector:offset (hex)");
    auto *domain = new wxChoice(&dialog, wxID_ANY, wxDefaultPosition, wxDefaultSize, domains);
    domain->SetName("reference-domain");
    domain->SetSelection(std::holds_alternative<FileOffset>(source) ? 1 : 0);
    box->Add(domain, 0, wxEXPAND | wxLEFT | wxRIGHT, 10);
    auto *target = new wxTextCtrl(&dialog, wxID_ANY, "0x", wxDefaultPosition, dialog.FromDIP(wxSize(380, 30)));
    target->SetName("reference-target");
    box->Add(target, 0, wxEXPAND | wxALL, 10);
    wxArrayString kinds;
    for (auto value : {"Code", "Data", "Call", "Jump", "Read", "Write", "Address"})
        kinds.Add(value);
    auto *kind = new wxChoice(&dialog, wxID_ANY, wxDefaultPosition, wxDefaultSize, kinds);
    kind->SetName("reference-kind");
    kind->SetSelection(6);
    box->Add(kind, 0, wxEXPAND | wxLEFT | wxRIGHT, 10);
    auto *remove = new wxCheckBox(&dialog, wxID_ANY, "Remove this matching explicit reference");
    remove->SetName("reference-remove");
    box->Add(remove, 0, wxALL, 10);
    auto *error = new wxStaticText(&dialog, wxID_ANY, "");
    error->SetName("reference-error");
    box->Add(error, 0, wxLEFT | wxRIGHT, 10);
    box->Add(dialog.CreateButtonSizer(wxOK | wxCANCEL), 0, wxALL | wxALIGN_RIGHT, 10);
    dialog.SetSizerAndFit(box);
    std::optional<ProjectCommand> result;
    dialog.Bind(
        wxEVT_BUTTON,
        [&](wxCommandEvent &) {
            constexpr UserReferenceKind values[] = {
                UserReferenceKind::code, UserReferenceKind::data,  UserReferenceKind::call,   UserReferenceKind::jump,
                UserReferenceKind::read, UserReferenceKind::write, UserReferenceKind::address};
            if (kind->GetSelection() < 0 || kind->GetSelection() > 6 || domain->GetSelection() < 0 ||
                static_cast<unsigned>(domain->GetSelection()) >= domain->GetCount()) {
                error->SetLabel("Select a target domain and reference kind");
                return;
            }
            const auto parse = [&]() -> Result<Location> {
                const auto input = target->GetValue().ToStdWstring();
                if (domain->GetSelection() == 2) {
                    auto parsed = parse_segment_address(*image, input);
                    if (!parsed)
                        return parsed.error();
                    return Location{parsed.value()};
                }
                auto parsed = parse_address(input);
                if (!parsed)
                    return parsed.error();
                return domain->GetSelection() == 0 ? Location{Address{space, parsed.value()}}
                                                   : Location{FileOffset{parsed.value()}};
            };
            auto destination = parse();
            if (!destination) {
                error->SetLabel(text(destination.error().message));
                dialog.Layout();
                return;
            }
            result = SetReference{source, destination.value(), values[kind->GetSelection()], remove->IsChecked()};
            dialog.EndModal(wxID_OK);
        },
        wxID_OK);
    target->SetFocus();
    if (dialog.ShowModal() != wxID_OK)
        return {};
    return result;
}
} // namespace hexlab::desktop
