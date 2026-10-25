#include "document_tabs.hpp"
#include "data_views.hpp"
#include <wx/menu.h>
namespace hexlab::desktop {
namespace {
constexpr int close_other_documents_id = wxID_HIGHEST + 712;
constexpr int close_all_documents_id = wxID_HIGHEST + 713;
}
DocumentTabs::DocumentTabs(wxWindow* parent):wxNotebook(parent,wxID_ANY,wxDefaultPosition,wxDefaultSize,wxNB_TOP){SetName("document-tabs");Bind(wxEVT_NOTEBOOK_PAGE_CHANGED,[this](wxBookCtrlEvent& event){if(!updating_ && event.GetSelection()>=0 && std::size_t(event.GetSelection())<ids_.size() && activate)activate(ids_[std::size_t(event.GetSelection())]);event.Skip();});
    auto close_at = [this](wxPoint position) {
        long flags = 0;
        const int page = HitTest(position, &flags);
        if (page < 0 || std::size_t(page) >= ids_.size() || !close)
            return;
        close(ids_[std::size_t(page)]);
    };
    Bind(wxEVT_MIDDLE_DOWN, [close_at](wxMouseEvent &event) { close_at(event.GetPosition()); });
    Bind(wxEVT_CONTEXT_MENU, [this](wxContextMenuEvent &event) {
        auto point = event.GetPosition();
        if (point != wxDefaultPosition)
            point = ScreenToClient(point);
        long flags = 0;
        int page = point == wxDefaultPosition ? GetSelection() : HitTest(point, &flags);
        if (page < 0 || std::size_t(page) >= ids_.size() || (!close && !close_many))
            return;
        wxMenu menu;
        menu.Append(wxID_CLOSE, "Close Document");
        if (ids_.size() > 1) {
            menu.Append(close_other_documents_id, "Close Other Documents");
            menu.Append(close_all_documents_id, "Close All Documents");
        }
        const int selected = GetPopupMenuSelectionFromUser(menu, point);
        const auto keep = ids_[std::size_t(page)];
        if (selected == wxID_CLOSE) {
            if (close) close(keep);
        } else if (selected == close_other_documents_id && close_many) {
            std::vector<DocumentId> targets;
            targets.reserve(ids_.size() - 1);
            for (auto id : ids_) if (id != keep) targets.push_back(id);
            close_many(std::move(targets));
        } else if (selected == close_all_documents_id && close_many) {
            close_many(ids_);
        }
    });
}
void DocumentTabs::update(const DocumentManager& manager){
    auto entries=manager.documents();bool same=entries.size()==ids_.size();for(std::size_t n=0;same && n<entries.size();++n)same=entries[n].id==ids_[n];updating_=true;
    if(!same){DeleteAllPages();ids_.clear();for(auto& entry:entries){auto* page=new wxPanel(this);AddPage(page,"");ids_.push_back(entry.id);}}
    for(std::size_t n=0;n<entries.size();++n){auto& entry=entries[n];wxString label=entry.path?wxString(entry.path->filename().wstring()):wxString("Untitled");if(!entry.path)if(auto project=manager.project(entry.id);project && project->state->provenance)label=wxString(project->state->provenance->native_path.filename().wstring());switch(entry.save_state){case DocumentSaveState::opening:label+=" (opening)";break;case DocumentSaveState::untitled:label+=" *";break;case DocumentSaveState::saving:label+=" (saving)";break;case DocumentSaveState::error:label+=" (error)";break;default:break;}if(entry.readonly)label+=" [read-only]";SetPageText(n,label);if(manager.active_document()==entry.id)ChangeSelection(n);}
    updating_=false;
}
}
