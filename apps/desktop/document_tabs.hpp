#pragma once
#include "hexlab/workspace/document_manager.hpp"
#include <wx/notebook.h>
#include <vector>
namespace hexlab::desktop {
class DocumentTabs final:public wxNotebook {
public:
    explicit DocumentTabs(wxWindow*);
    void update(const DocumentManager&);
    std::function<void(DocumentId)> activate;
    std::function<void(DocumentId)> close;
    std::function<void(std::vector<DocumentId>)> close_many;
private:
    bool updating_=false;std::vector<DocumentId> ids_;
};
}
