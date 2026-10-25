#include "open_dialogs.hpp"
#include "data_views.hpp"
#include <wx/dialog.h>
#include <wx/sizer.h>
#include <wx/stattext.h>
#include <wx/textctrl.h>
#include <wx/choice.h>
#include <wx/button.h>
#include <wx/filedlg.h>

namespace hexlab::desktop {
bool configure_raw_mapping(wxWindow *parent, OpenRequest &request) {
    wxDialog dialog(parent, wxID_ANY, "Open raw binary");
    auto *box = new wxBoxSizer(wxVERTICAL);
    box->Add(new wxStaticText(&dialog, wxID_ANY, "Processor mode (read + execute mapping)"), 0, wxALL, 10);
    auto *mode = new wxChoice(&dialog, wxID_ANY);
    mode->SetName("raw-mode");
    mode->Append("x86-64 (64-bit)");
    mode->Append("x86-32 (32-bit)");
    mode->Append("Segmented x86 (16/32-bit profile)");
    mode->Append("AArch64 (A64 scalar)");
    mode->Append("MOS 6502 (NMOS scalar subset)");
    mode->Append("RISC-V RV32I (base integer)");
    mode->Append("RISC-V RV64I (base integer)");
    mode->Append("MIPS64 (little-endian scalar)");
    mode->Append("PowerPC PPC32 little-endian");
    mode->Append("PowerPC PPC32 big-endian");
    mode->Append("PowerPC PPC64 little-endian");
    mode->Append("PowerPC PPC64 big-endian");
    mode->SetSelection(0);
    box->Add(mode, 0, wxEXPAND | wxLEFT | wxRIGHT | wxBOTTOM, 10);
    box->Add(new wxStaticText(&dialog, wxID_ANY, "Base address (decimal or 0x hexadecimal)"), 0, wxLEFT | wxRIGHT, 10);
    auto *base = new wxTextCtrl(&dialog, wxID_ANY, "0x1000");
    base->SetName("raw-base");
    box->Add(base, 0, wxEXPAND | wxALL, 10);
    box->Add(new wxStaticText(&dialog, wxID_ANY, "Entry address (blank uses base)"), 0, wxLEFT | wxRIGHT, 10);
    auto *entry = new wxTextCtrl(&dialog, wxID_ANY);
    entry->SetName("raw-entry");
    box->Add(entry, 0, wxEXPAND | wxALL, 10);
    box->Add(new wxStaticText(&dialog, wxID_ANY, "Segmented profile file"), 0, wxLEFT | wxRIGHT, 10);
    auto *profile_row = new wxBoxSizer(wxHORIZONTAL);
    auto *profile = new wxTextCtrl(&dialog, wxID_ANY);
    profile->SetName("raw-profile");
    auto *browse = new wxButton(&dialog, wxID_ANY, "Browse...");
    browse->SetName("raw-profile-browse");
    profile_row->Add(profile, 1, wxEXPAND | wxRIGHT, 8);
    profile_row->Add(browse, 0);
    box->Add(profile_row, 0, wxEXPAND | wxALL, 10);
    const auto update = [&] {
        const bool segmented = mode->GetSelection() == 2;
        base->Enable(!segmented);
        entry->Enable(!segmented);
        profile->Enable(segmented);
        browse->Enable(segmented);
    };
    mode->Bind(wxEVT_CHOICE, [&](wxCommandEvent &) { update(); });
    browse->Bind(wxEVT_BUTTON, [&](wxCommandEvent &) {
        wxFileDialog picker(&dialog, "Choose x86 profile", "", "", "Profile files|*.profile;*.txt|All files|*.*",
                            wxFD_OPEN | wxFD_FILE_MUST_EXIST);
        if (picker.ShowModal() == wxID_OK)
            profile->SetValue(picker.GetPath());
    });
    if (request.x86_profile_path) {
        profile->SetValue(wxString(request.x86_profile_path->wstring()));
        mode->SetSelection(2);
    }
    update();
    auto *error = new wxStaticText(&dialog, wxID_ANY, "");
    error->SetName("raw-error");
    box->Add(error, 0, wxALL, 10);
    box->Add(dialog.CreateButtonSizer(wxOK | wxCANCEL), 0, wxALL, 10);
    dialog.SetSizerAndFit(box);
    dialog.Bind(
        wxEVT_BUTTON,
        [&](wxCommandEvent &) {
            if (mode->GetSelection() == 2) {
                const auto path = profile->GetValue().ToStdWstring();
                if (path.empty() || path.find(wchar_t{}) != path.npos) {
                    error->SetLabel("Choose a profile file.");
                    dialog.Fit();
                    return;
                }
                request.format = Format::raw;
                request.raw.reset();
                request.x86_profile_path = std::filesystem::path(path);
                dialog.EndModal(wxID_OK);
                return;
            }
            auto parsed = parse_address(base->GetValue().ToStdWstring());
            if (!parsed) {
                error->SetLabel(text(parsed.error().message));
                dialog.Fit();
                return;
            }
            const bool legacy = mode->GetSelection() == 1;
            const bool a64 = mode->GetSelection() == 3;
            const bool m6502 = mode->GetSelection() == 4;
            const bool rv32 = mode->GetSelection() == 5;
            const bool rv64 = mode->GetSelection() == 6;
            const bool mips64 = mode->GetSelection() == 7;
            const int ppc_choice = mode->GetSelection() - 8;
            const bool ppc32 = ppc_choice == 0 || ppc_choice == 1;
            const bool ppc64 = ppc_choice == 2 || ppc_choice == 3;
            RawOptions raw{a64       ? Architecture::arm64
                           : legacy  ? Architecture::x86
                           : m6502   ? Architecture::mos6502
                           : rv32    ? Architecture::riscv32
                           : rv64    ? Architecture::riscv64
                           : mips64  ? Architecture::mips64
                           : ppc32 || ppc64 ? Architecture::powerpc
                                     : Architecture::x86_64,
                           a64       ? ExecutionMode::a64
                           : legacy  ? ExecutionMode::x86_32
                           : m6502   ? ExecutionMode::m6502
                           : rv32    ? ExecutionMode::rv32
                           : rv64    ? ExecutionMode::rv64
                           : mips64  ? ExecutionMode::mips64
                           : ppc32 ? ExecutionMode::ppc32
                           : ppc64 ? ExecutionMode::ppc64
                                     : ExecutionMode::x86_64,
                           {{0}, parsed.value()},
                           true,
                           false,
                           true,
                           {}};
            if (ppc32 || ppc64)
                raw.order = (ppc_choice == 1 || ppc_choice == 3) ? ByteOrder::big : ByteOrder::little;
            if (!entry->IsEmpty()) {
                auto number = parse_address(entry->GetValue().ToStdWstring());
                if (!number) {
                    error->SetLabel(text(number.error().message));
                    dialog.Fit();
                    return;
                }
                raw.entry = Address{{0}, number.value()};
            }
            auto valid = validate_raw_coordinates(raw);
            if (!valid) {
                error->SetLabel(text(valid.error().message));
                dialog.Fit();
                return;
            }
            request.format = Format::raw;
            request.raw = raw;
            request.x86_profile_path.reset();
            dialog.EndModal(wxID_OK);
        },
        wxID_OK);
    return dialog.ShowModal() == wxID_OK;
}
} // namespace hexlab::desktop
