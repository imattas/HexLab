#pragma once
#include "data_views.hpp"
#include "hexlab/workspace/document.hpp"
#include <wx/textctrl.h>

namespace hexlab::desktop {
class MinidumpView final : public wxPanel {
  public:
    explicit MinidumpView(wxWindow *parent);
    void set_document(std::shared_ptr<const DocumentSnapshot> document);
    std::function<void(Location)> navigate;

  private:
    std::shared_ptr<const DocumentSnapshot> document_;
    VirtualTable *contexts_ = nullptr, *registers_ = nullptr;
    wxStaticText *status_ = nullptr, *register_status_ = nullptr;
    wxTextCtrl *details_ = nullptr;
    wxButton *register_go_ = nullptr, *register_bytes_ = nullptr;
    wxButton *context_bytes_ = nullptr, *record_go_ = nullptr;
    std::optional<std::size_t> context_row_;
    std::optional<Location> register_target_, register_source_, context_source_, record_target_;
    const MinidumpContext *selected_context() const;
    wxString context_cell(std::size_t row, int column) const;
    void select_context(std::size_t row);
    void select_register(std::size_t row);
};
} // namespace hexlab::desktop
