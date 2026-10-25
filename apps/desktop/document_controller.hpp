#pragma once
#include "hexlab/workspace/jobs.hpp"
#include "hexlab/workspace/workspace.hpp"
#include <wx/timer.h>
#include <functional>

namespace hexlab::desktop {
class DocumentController final:public wxEvtHandler {
public:
    explicit DocumentController(std::function<void()> changed);
    ~DocumentController() override;
    void open(OpenRequest);
    void cancel();
    void close();
    Workspace& state(){return workspace_;}
private:
    Workspace workspace_;
    DocumentJobs jobs_;
    wxTimer timer_{this};
    std::function<void()> changed_;
};
}
