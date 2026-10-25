#pragma once
#include "hexlab/loaders/ar.hpp"
#include <wx/dialog.h>
#include <optional>
#include <vector>
class wxListCtrl;
class wxStaticText;

namespace hexlab::desktop {
class ArchiveView final : public wxDialog {
public:
    ArchiveView(wxWindow*, const ArArchive&);
    std::optional<std::size_t> selected_member() const;
private:
    wxListCtrl* members_ = nullptr;
    wxListCtrl* symbols_ = nullptr;
    wxStaticText* index_status_ = nullptr;
    std::vector<bool> regular_;
};
}
