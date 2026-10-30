#pragma once
#include "data_views.hpp"
#include "hexlab/workspace/document.hpp"
#include <wx/textctrl.h>
#include <vector>

namespace hexlab::desktop {
class MinidumpView final : public wxPanel {
  public:
    explicit MinidumpView(wxWindow *parent);
    void set_document(std::shared_ptr<const DocumentSnapshot> document);
    std::function<void(Location)> navigate;

  private:
    std::shared_ptr<const DocumentSnapshot> document_;
    VirtualTable *modules_ = nullptr, *contexts_ = nullptr, *registers_ = nullptr, *handle_operations_ = nullptr;
    wxStaticText *status_ = nullptr, *register_status_ = nullptr, *handle_operation_status_ = nullptr;
    wxTextCtrl *details_ = nullptr, *handle_operation_details_ = nullptr;
    wxButton *register_go_ = nullptr, *register_bytes_ = nullptr;
    wxButton *context_bytes_ = nullptr, *record_go_ = nullptr;
    wxButton *handle_record_go_ = nullptr, *handle_return_go_ = nullptr;
    std::optional<std::size_t> context_row_;
    std::optional<Location> register_target_, register_source_, context_source_, record_target_;
    std::optional<Location> handle_record_source_, handle_return_target_;
    std::vector<bool> repeated_handle_rows_;
    const MinidumpContext *selected_context() const;
    wxString context_cell(std::size_t row, int column) const;
    void select_context(std::size_t row);
    void select_register(std::size_t row);
    void select_handle_operation(std::size_t row);
};
} // namespace hexlab::desktop
