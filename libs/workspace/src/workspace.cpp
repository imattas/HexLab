#include "hexlab/workspace/workspace.hpp"

namespace hexlab {
OpenTicket Workspace::begin_open() {
    if(generation_==UINT64_MAX || next_document_==UINT64_MAX)throw std::overflow_error("Workspace ticket space exhausted");
    OpenTicket ticket{{++next_document_},++generation_};
    pending_=ticket;error_.reset();return ticket;
}
bool Workspace::finish_open(OpenTicket ticket,Result<std::shared_ptr<const DocumentSnapshot>> result) {
    if(!pending_ || *pending_!=ticket)return false;
    if(!result){error_=result.error();pending_.reset();return false;}
    const auto& snapshot=result.value();
    if(!snapshot || !snapshot->image || snapshot->id!=ticket.document || snapshot->revision!=ticket.generation)return false;
    current_=snapshot;pending_.reset();error_.reset();selection_.reset();history_.clear();history_position_=0;
    if(!snapshot->image->layout().entries.empty())selection_=snapshot->image->layout().entries.front();
    else {
        for(const auto& segment:snapshot->image->layout().segments)if(segment.size){selection_=segment.begin;break;}
        if(!selection_ && snapshot->file_storage().size())selection_=FileOffset{0};
    }
    if(selection_)history_.push_back(*selection_);
    return true;
}
void Workspace::cancel_open() {pending_.reset();}
void Workspace::close_document() {
    pending_.reset();current_.reset();error_.reset();selection_.reset();history_.clear();history_position_=0;
}
Result<Location> Workspace::navigate(Location location) {
    if(!current_)return Error{ErrorCode::invalid_argument,"No document is open"};
    if(const auto* address=std::get_if<Address>(&location)) {
        if(!current_->image->segment_at(*address))return Error{ErrorCode::out_of_bounds,"Address is not mapped in this document"};
    } else if(std::get<FileOffset>(location).value>=current_->file_storage().size())
        return Error{ErrorCode::out_of_bounds,"File offset is outside this document"};
    if(selection_ && *selection_==location)return location;
    if(!history_.empty())history_.erase(history_.begin()+static_cast<std::ptrdiff_t>(history_position_+1),history_.end());
    history_.push_back(location);history_position_=history_.size()-1;selection_=location;
    return location;
}
Result<Location> Workspace::back() {
    if(history_.empty() || history_position_==0)return Error{ErrorCode::out_of_bounds,"No previous navigation location"};
    selection_=history_[--history_position_];return *selection_;
}
Result<Location> Workspace::forward() {
    if(history_.empty() || history_position_+1>=history_.size())return Error{ErrorCode::out_of_bounds,"No next navigation location"};
    selection_=history_[++history_position_];return *selection_;
}
}
