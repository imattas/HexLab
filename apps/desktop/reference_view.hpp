#pragma once
#include "data_views.hpp"
#include "hexlab/workspace/document_manager.hpp"
#include <wx/choice.h>
#include <wx/button.h>
#include <wx/stattext.h>
#include <wx/checkbox.h>
#include <wx/textctrl.h>
#include <map>
namespace hexlab::desktop {
class ReferenceView final : public wxPanel {
  public:
    explicit ReferenceView(wxWindow *);
    void update(std::optional<DocumentId>, std::shared_ptr<const ProjectSnapshot>, std::optional<Location>);
    void retain_documents(std::span<const DocumentInfo>);
    void inspect(Location, bool incoming);
    std::function<void(DocumentId, std::shared_ptr<const ProjectSnapshot>, Location)> navigate;

  private:
    VirtualTable *table_;
    wxChoice *direction_;
    wxButton *previous_, *next_;
    wxButton *source_, *target_, *origin_;
    wxCheckBox *pin_;
    wxCheckBox *range_;
    wxCheckBox *mapped_range_;
    wxTextCtrl *range_size_;
    wxStaticText *context_;
    wxTextCtrl *detail_;
    wxStaticText *status_;
    std::optional<DocumentId> document_;
    std::shared_ptr<const ProjectSnapshot> project_;
    std::optional<Location> location_;
    std::optional<Location> selection_;
    struct Preference {
        bool incoming = false;
        bool range = false;
        bool mapped_range = false;
        std::uint64_t range_size = 16;
        std::uint64_t offset = 0;
        std::optional<Location> pinned, origin;
        std::optional<ReferenceId> selected;
    };
    std::map<std::uint64_t, Preference> preferences_;
    std::shared_ptr<const ReferencePage> rows_;
    void reload();
    const Reference *selected_reference() const;
    void update_actions();
    void update_detail();
    void follow_selected(bool target);
};
} // namespace hexlab::desktop
