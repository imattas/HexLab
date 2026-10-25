#pragma once
#include "data_views.hpp"
#include "hexlab/workspace/document.hpp"
#include <wx/notebook.h>
#include <wx/stattext.h>
#include <wx/button.h>
#include <functional>

namespace hexlab::desktop {
class PeView final : public wxPanel {
  public:
    explicit PeView(wxWindow *parent);
    void set_document(std::shared_ptr<const DocumentSnapshot> document);
    std::function<void(Location)> navigate;
    std::function<void(PeRuntimeArchitecture)> open_runtime_view;

  private:
    std::shared_ptr<const DocumentSnapshot> document_;
    VirtualTable *directories_ = nullptr;
    VirtualTable *resources_ = nullptr;
    wxStaticText *resource_status_ = nullptr;
    VirtualTable *bound_imports_ = nullptr;
    VirtualTable *certificates_ = nullptr;
    wxStaticText *certificate_status_ = nullptr;
    VirtualTable *safe_seh_ = nullptr;
    wxStaticText *load_config_status_ = nullptr;
    wxStaticText *runtime_view_status_ = nullptr;
    wxButton *open_arm64_view_ = nullptr, *open_x64_view_ = nullptr;
    VirtualTable *exceptions_ = nullptr;
    VirtualTable *pdb_symbols_ = nullptr, *pdb_types_ = nullptr, *pdb_lines_ = nullptr;
    VirtualTable *pdb_inline_ = nullptr;
    wxStaticText *pdb_status_ = nullptr;
};
} // namespace hexlab::desktop
