#include "document_controller.hpp"
namespace hexlab::desktop {
DocumentController::DocumentController(std::function<void()> changed):changed_(std::move(changed)) {
    Bind(wxEVT_TIMER,[this](wxTimerEvent&){
        if(auto completion=jobs_.take_completed()){
            const bool opening=workspace_.opening();
            const bool committed=workspace_.finish_open(completion->ticket,std::move(completion->result));
            if(committed || (opening && !workspace_.opening()))changed_();
        }
        if(workspace_.opening())changed_();
    });
    timer_.Start(25);
}
DocumentController::~DocumentController(){timer_.Stop();workspace_.cancel_open();jobs_.cancel();}
void DocumentController::open(OpenRequest request){auto ticket=workspace_.begin_open();jobs_.submit(std::move(request),ticket);changed_();}
void DocumentController::cancel(){workspace_.cancel_open();jobs_.cancel();changed_();}
void DocumentController::close(){workspace_.close_document();jobs_.cancel();changed_();}
}
