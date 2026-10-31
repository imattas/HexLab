#pragma once
#include "data_views.hpp"
#include "hexlab/workspace/document.hpp"
#include <wx/notebook.h>
#include <wx/stattext.h>
#include <wx/button.h>
#include <wx/timer.h>
#include <cstdint>
#include <functional>

namespace hexlab::desktop {
class PeView final : public wxPanel {
  public:
    explicit PeView(wxWindow *parent);
    ~PeView() override;
    void set_document(std::shared_ptr<const DocumentSnapshot> document);
    std::function<void(std::shared_ptr<const DocumentSnapshot>, Location)> navigate;
    std::function<void(PeRuntimeArchitecture)> open_runtime_view;

  private:
    std::shared_ptr<const DocumentSnapshot> document_;
    VirtualTable *directories_ = nullptr;
    VirtualTable *coff_symbols_ = nullptr;
    wxStaticText *coff_symbol_status_ = nullptr;
    VirtualTable *resources_ = nullptr;
    wxStaticText *resource_status_ = nullptr;
    VirtualTable *bound_imports_ = nullptr;
    VirtualTable *certificates_ = nullptr;
    wxStaticText *certificate_status_ = nullptr;
    wxButton *verify_authenticode_ = nullptr;
    wxStaticText *authenticode_status_ = nullptr;
    VirtualTable *authenticode_signers_ = nullptr;
    struct TrustWork;
    std::shared_ptr<TrustWork> trust_work_;
    wxTimer trust_timer_;
    std::uint64_t trust_generation_ = 0;
    bool trust_running_ = false;
    VirtualTable *safe_seh_ = nullptr;
    wxStaticText *load_config_status_ = nullptr;
    wxStaticText *runtime_view_status_ = nullptr;
    wxButton *open_arm64_view_ = nullptr, *open_x64_view_ = nullptr;
    VirtualTable *exceptions_ = nullptr;
    VirtualTable *pdb_symbols_ = nullptr, *pdb_types_ = nullptr, *pdb_lines_ = nullptr;
    VirtualTable *pdb_inline_ = nullptr;
    wxStaticText *pdb_status_ = nullptr;
    void begin_authenticode_verification();
    void poll_authenticode_verification();
    void update_authenticode_controls();
};
} // namespace hexlab::desktop
