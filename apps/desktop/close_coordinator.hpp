#pragma once
#include "session_controller.hpp"
#include <wx/frame.h>
#include <vector>
namespace hexlab::desktop {
// UI close waits for operation acknowledgements; SQL and publication stay on actors.
class CloseCoordinator {
  public:
    CloseCoordinator(wxFrame &, SessionController &);
    ~CloseCoordinator();
    void progress();
    void cancel_pending();
    void request_close(DocumentId);
    void request_close_many(std::vector<DocumentId>);
    bool closing_window()const noexcept{return frame_requested_ || approved_;}

  private:
    wxFrame &frame_;
    SessionController &controller_;
    std::vector<DocumentId> queue_;
    struct Waiting {
        DocumentId id;
        bool require_saved = false;
    };
    std::optional<Waiting> waiting_;
    bool frame_requested_ = false, approved_ = false, stepping_ = false,disabled_=false;
    void window_close(wxCloseEvent &);
    void document_close(wxCommandEvent &);
    void step(bool schedule_frame);
};
} // namespace hexlab::desktop
