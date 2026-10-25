#pragma once
#include "hexlab/workspace/navigation.hpp"

namespace hexlab {
// State transitions belong to the owner thread. Workers deliver immutable
// results through the frontend's mailbox, never by mutating this object.
class Workspace {
public:
    HEXLAB_WORKSPACE_EXPORT OpenTicket begin_open();
    HEXLAB_WORKSPACE_EXPORT bool finish_open(OpenTicket,Result<std::shared_ptr<const DocumentSnapshot>>);
    HEXLAB_WORKSPACE_EXPORT void cancel_open();
    HEXLAB_WORKSPACE_EXPORT void close_document();
    std::shared_ptr<const DocumentSnapshot> current() const {return current_;}
    std::optional<Error> last_error() const {return error_;}
    std::optional<Location> selection() const {return selection_;}
    bool opening() const noexcept {return pending_.has_value();}
    bool can_back()const noexcept{return !history_.empty() && history_position_>0;}
    bool can_forward()const noexcept{return !history_.empty() && history_position_+1<history_.size();}
    HEXLAB_WORKSPACE_EXPORT Result<Location> navigate(Location);
    HEXLAB_WORKSPACE_EXPORT Result<Location> back();
    HEXLAB_WORKSPACE_EXPORT Result<Location> forward();
private:
    friend class DocumentManager;
    std::uint64_t generation_=0,next_document_=0;
    std::optional<OpenTicket> pending_;
    std::shared_ptr<const DocumentSnapshot> current_;
    std::optional<Error> error_;
    std::optional<Location> selection_;
    std::vector<Location> history_;
    std::size_t history_position_=0;
};
}
