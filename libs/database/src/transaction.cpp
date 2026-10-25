#include "history_internal.hpp"
#include "testing.hpp"
#include <algorithm>
namespace hexlab::database {
namespace {
using detail::take;using detail::require;using detail::Failure;
template<class T>auto& records(UserState& user){
    if constexpr(std::is_same_v<T,Annotation>)return user.annotations;
    else if constexpr(std::is_same_v<T,Bookmark>)return user.bookmarks;
    else if constexpr(std::is_same_v<T,RegionDecision>)return user.decisions.regions;
    else if constexpr(std::is_same_v<T,FunctionDecision>)return user.decisions.functions;
    else if constexpr(std::is_same_v<T,UserReference>)return user.decisions.references;
    else if constexpr(std::is_same_v<T,TypeDefinition>)return user.types;
    else if constexpr(std::is_same_v<T,TypeAssignment>)return user.type_assignments;
    else if constexpr(std::is_same_v<T,DebugVariable>)return user.debug_variables;
    else return user.breakpoints;
}
void conflict(bool condition,const char* message){if(!condition)throw Failure{{ErrorCode::conflict,message}};}
template<class T>void apply_entity(UserState& user,const EntityChange<T>& change,uint64_t& next,bool restore){
    require(change.before.has_value() || change.after.has_value(),"Empty entity delta");
    if(change.before && change.after)require(change.before->id==change.after->id,"Entity delta changes its stable ID");
    auto& rows=records<T>(user);const auto id=change.before?change.before->id:change.after->id;
    auto current=std::find_if(rows.begin(),rows.end(),[&](const auto& row){return row.id==id;});
    if (change.before) {
        if constexpr (std::is_same_v<T, TypeAssignment>) {
            if (current == rows.end())
                conflict(false, "Type assignment disappeared since command validation");
            if (*current != *change.before)
                throw Failure{{ErrorCode::conflict,
                    "Type assignment changed since command validation (expected type " +
                    std::to_string(change.before->type_id) + ", found type " + std::to_string(current->type_id) + ")"}};
        } else {
            conflict(current!=rows.end() && *current==*change.before,"Entity changed since command validation");
        }
    }
    else {
        conflict(current==rows.end(),"Entity already exists");
        if(restore)require(id>0 && id<next,"History restores an unallocated entity ID");
        else {require(id==next && next<UINT64_MAX-1,"New entity must use the next stable ID");++next;}
    }
    if(current!=rows.end()){
        if(change.after){
            if constexpr(std::is_same_v<T,ProjectBreakpoint>){auto replacement=*change.after;replacement.hit_count=current->hit_count;*current=std::move(replacement);}
            else *current=*change.after;
        }else rows.erase(current);
    }
    else rows.push_back(*change.after);
}
void apply_delta(UserState& user,const StateDelta& delta,uint64_t& next,bool restore){
    require(!delta.changes.empty() && delta.changes.size()<=project_record_limit,"Invalid command change count");
    for(const auto& change:delta.changes)std::visit([&](const auto& row){
        if constexpr(std::is_same_v<std::decay_t<decltype(row)>,PatchChange>){conflict(user.patches==row.before,"Patches changed since command validation");user.patches=row.after;}
        else apply_entity(user,row,next,restore);
    },change);
    const auto sort=[](auto& rows){std::sort(rows.begin(),rows.end(),[](const auto& a,const auto& b){return a.id<b.id;});};
    sort(user.annotations);sort(user.bookmarks);sort(user.types);sort(user.type_assignments);sort(user.debug_variables);sort(user.breakpoints);sort(user.decisions.regions);sort(user.decisions.functions);sort(user.decisions.references);take(validate_user_state(user));
}
void check_edit(const ProjectState& state,uint64_t expected){conflict(state.revisions.edit==expected,"Project edit revision changed; refresh before retrying");}
void check_mutation(ProjectMode mode,std::stop_token stop){if(mode==ProjectMode::read_only)throw Failure{{ErrorCode::read_only,"Project is read only"}};if(stop.stop_requested())throw Failure{{ErrorCode::canceled,"Project edit canceled"}};}
std::shared_ptr<ProjectState> next_state(const ProjectState& before,std::shared_ptr<const UserState> user,uint64_t next,uint64_t cursor){
    auto state=std::make_shared<ProjectState>(before);state->user=std::move(user);state->next_entity=next;state->history_cursor=cursor;
    state->revisions.edit=take(checked_add(before.revisions.edit,1));
    if(state->user->patches!=before.user->patches)state->revisions.bytes=take(checked_add(before.revisions.bytes,1));
    if(state->user->decisions!=before.user->decisions)state->revisions.decisions=take(checked_add(before.revisions.decisions,1));
    for(const auto& patch:state->user->patches)require(patch.begin.value<=state->input.size && patch.original.size()<=state->input.size-patch.begin.value,"Patch exceeds embedded original");
    return state;
}
void update_header(Connection& connection,const ProjectState& before,const ProjectState& after){
    auto update=take(connection.prepare("UPDATE project SET edit_revision=?1,byte_revision=?2,decision_revision=?3,history_cursor=?4,next_entity=?5 WHERE singleton=1 AND edit_revision=?6"));
    take(update->bind_blob(1,encode_u64(after.revisions.edit)));take(update->bind_blob(2,encode_u64(after.revisions.bytes)));take(update->bind_blob(3,encode_u64(after.revisions.decisions)));take(update->bind_blob(4,encode_u64(after.history_cursor)));take(update->bind_blob(5,encode_u64(after.next_entity)));take(update->bind_blob(6,encode_u64(before.revisions.edit)));take(update->step());
    auto affected=take(connection.prepare("SELECT changes()"));conflict(take(affected->step()) && take(affected->integer(0))==1,"Project revision compare and swap failed");
}
template<class Impl>CommitAck finish(Impl& impl,const ProjectState& before,std::shared_ptr<ProjectState> after,Transaction& transaction,std::stop_token stop){
    if(before.user->patches!=after->user->patches){if(!impl.original)impl.original=detail::extract_input(*impl.connection,before,stop);detail::verify_patches(*impl.original,*after->user);}
    detail::write_user_state(*impl.connection,*before.user,*after->user);update_header(*impl.connection,before,*after);
    take(transaction.commit());impl.state=std::move(after);return {impl.state->revisions,impl.state->history_cursor};
}
std::shared_ptr<ProjectState> prepare_history(Connection& connection,const ProjectState& before,bool redo){
        const auto rows=detail::history_rows(connection);require(before.history_cursor<=rows.size(),"History cursor exceeds durable history");
        if((redo && before.history_cursor==rows.size()) || (!redo && before.history_cursor==0))throw Failure{{ErrorCode::invalid_argument,redo?"No command to redo":"No command to undo"}};
        auto user=std::make_shared<UserState>(*before.user);auto next=before.next_entity;size_t cursor=static_cast<size_t>(before.history_cursor);
        const auto group=rows[redo?cursor:cursor-1].group;
        for(;;){
            const auto index=redo?cursor:cursor-1;auto delta=detail::read_history(connection,rows[index].step,!redo);apply_delta(*user,delta,next,true);
            if(redo)++cursor;else --cursor;
            if(group==0 || (redo?cursor==rows.size():cursor==0) || rows[redo?cursor:cursor-1].group!=group)break;
        }
        return next_state(before,std::move(user),next,cursor);
}
template<class Impl>Result<CommitAck> navigate_history(Impl& impl,uint64_t expected,std::stop_token stop,bool redo){
    return detail::guarded([&]()->Result<CommitAck>{
        std::lock_guard lock(impl.mutex);check_mutation(impl.mode,stop);detail::Cancellation cancellation(*impl.connection,stop);auto transaction=take(Transaction::begin(*impl.connection));auto before=detail::read_state(*impl.connection);check_edit(*before,expected);
        auto after=prepare_history(*impl.connection,*before,redo);return finish(impl,*before,std::move(after),*transaction,stop);
    });
}
}
Result<CommitAck> ProjectStore::commit(uint64_t expected,const StateDelta& delta,uint64_t group,std::stop_token stop){
    return detail::guarded([&]()->Result<CommitAck>{
        std::lock_guard lock(impl_->mutex);check_mutation(impl_->mode,stop);detail::Cancellation cancellation(*impl_->connection,stop);auto transaction=take(Transaction::begin(*impl_->connection));auto before=detail::read_state(*impl_->connection);check_edit(*before,expected);
#ifdef HEXLAB_DATABASE_TESTING
        testing::transaction_checkpoint(testing::TransactionPhase::before_write);
#endif
        auto rows=detail::history_rows(*impl_->connection);require(before->history_cursor<=rows.size() && before->history_cursor<project_record_limit,"Invalid or exhausted history cursor");
        auto user=std::make_shared<UserState>(*before->user);auto next=before->next_entity;apply_delta(*user,delta,next,false);
        if(*user==*before->user)return Error{ErrorCode::invalid_argument,"Command contains no changes"};
        auto after=next_state(*before,std::move(user),next,before->history_cursor+1);
        after->history_count=after->history_cursor;
        detail::append_history(*impl_->connection,after->history_cursor,group,after->revisions.bytes!=before->revisions.bytes,after->revisions.decisions!=before->revisions.decisions,delta);
        return finish(*impl_,*before,std::move(after),*transaction,stop);
    });
}
Result<CommitAck> ProjectStore::commit_resolving_conflict(uint64_t conflict_id,uint64_t expected,
    const StateDelta& delta,uint64_t group,std::stop_token stop){
    return detail::guarded([&]()->Result<CommitAck>{
        if(conflict_id==0 || conflict_id>static_cast<uint64_t>(std::numeric_limits<int64_t>::max()))
            return Error{ErrorCode::invalid_argument,"Invalid collaboration conflict ID"};
        std::lock_guard lock(impl_->mutex);check_mutation(impl_->mode,stop);
        detail::Cancellation cancellation(*impl_->connection,stop);
        auto transaction=take(Transaction::begin(*impl_->connection));
        auto before=detail::read_state(*impl_->connection);check_edit(*before,expected);
        const auto resolve_row=[&](uint64_t revision){
            auto update=take(impl_->connection->prepare("UPDATE collaboration_conflicts SET resolved=1,accepted=1,resolution_revision=?1 WHERE id=?2 AND resolved=0"));
            take(update->bind_blob(1,encode_u64(revision)));
            take(update->bind_integer(2,static_cast<int64_t>(conflict_id)));
            take(update->step());
            auto changed=take(impl_->connection->prepare("SELECT changes()"));
            conflict(take(changed->step()) && take(changed->integer(0))==1,"Collaboration conflict is unknown or already resolved");
        };
        // A concurrent head may already contain the proposal's intent. Accept
        // that as a resolved no-op, without manufacturing a history revision.
        if(delta.changes.empty()){
            resolve_row(before->revisions.edit);
            take(transaction->commit());impl_->state=before;
            return CommitAck{before->revisions,before->history_cursor};
        }
#ifdef HEXLAB_DATABASE_TESTING
        testing::transaction_checkpoint(testing::TransactionPhase::before_write);
#endif
        auto rows=detail::history_rows(*impl_->connection);require(before->history_cursor<=rows.size() && before->history_cursor<project_record_limit,"Invalid or exhausted history cursor");
        auto user=std::make_shared<UserState>(*before->user);auto next=before->next_entity;apply_delta(*user,delta,next,false);
        if(*user==*before->user)return Error{ErrorCode::invalid_argument,"Command contains no changes"};
        auto after=next_state(*before,std::move(user),next,before->history_cursor+1);after->history_count=after->history_cursor;
        detail::append_history(*impl_->connection,after->history_cursor,group,after->revisions.bytes!=before->revisions.bytes,after->revisions.decisions!=before->revisions.decisions,delta);
        resolve_row(after->revisions.edit);
        return finish(*impl_,*before,std::move(after),*transaction,stop);
    });
}
Result<CommitAck> ProjectStore::undo(uint64_t expected,std::stop_token stop){return navigate_history(*impl_,expected,stop,false);}
Result<CommitAck> ProjectStore::redo(uint64_t expected,std::stop_token stop){return navigate_history(*impl_,expected,stop,true);}
Result<std::shared_ptr<const ProjectState>> ProjectStore::preview_history(uint64_t expected,bool redo,std::stop_token stop){return detail::guarded([&]()->Result<std::shared_ptr<const ProjectState>>{
    std::lock_guard lock(impl_->mutex);check_mutation(impl_->mode,stop);detail::Cancellation cancellation(*impl_->connection,stop);auto transaction=take(Transaction::begin(*impl_->connection));auto before=detail::read_state(*impl_->connection);check_edit(*before,expected);return std::shared_ptr<const ProjectState>(prepare_history(*impl_->connection,*before,redo));
});}
Result<HistoryPreview> detail::project_history_at(Connection& connection,uint64_t expected,uint64_t target,HistoryPreviewLimits limits,std::stop_token stop){
    return detail::guarded([&]()->Result<HistoryPreview>{
        if(limits.max_steps>history_preview_step_limit || limits.max_delta_bytes>history_preview_payload_limit)
            return Error{ErrorCode::invalid_argument,"History preview limits exceed 4096 steps or 64 MiB of delta payload"};
        if(stop.stop_requested())return Error{ErrorCode::canceled,"History preview canceled"};
        const auto header=detail::read_history_header(connection);
        conflict(header.source_revisions.edit==expected,"Project edit revision changed; refresh before retrying");
        if(target>header.history_count)return Error{ErrorCode::invalid_argument,"History preview target exceeds durable history"};
        const auto distance=target>header.history_cursor?target-header.history_cursor:header.history_cursor-target;
        if(distance>limits.max_steps)return Error{ErrorCode::resource_limit,"History preview step budget exceeded"};
        auto before=detail::read_state(connection);
        // Bound every materialized projection with the same canonical state
        // codec used by command/history records, including intermediate steps.
        take(encode_user_state(*before->user));
        HistoryPreview preview{before->uuid,before->revisions,before->history_cursor,target,before->history_count,0,0,before->user};
        if(distance!=0){
            auto user=std::make_shared<UserState>(*before->user);
            auto next=before->next_entity,cursor=before->history_cursor;
            auto remaining=limits.max_delta_bytes;
            const bool forward=target>cursor;
            while(cursor!=target){
                if(stop.stop_requested())return Error{ErrorCode::canceled,"History preview canceled"};
                auto delta=detail::read_history_bounded(connection,forward?cursor+1:cursor,!forward,remaining);
                apply_delta(*user,delta,next,true);
                for(const auto& patch:user->patches)
                    require(patch.begin.value<=before->input.size && patch.original.size()<=before->input.size-patch.begin.value,"History preview patch exceeds embedded original");
                take(encode_user_state(*user));
                if(forward)++cursor;else --cursor;
                ++preview.replayed_steps;
            }
            preview.delta_bytes=limits.max_delta_bytes-remaining;
            preview.user=std::move(user);
        }
        if(stop.stop_requested())return Error{ErrorCode::canceled,"History preview canceled"};
        return preview;
    });
}
Result<HistoryPreview> ProjectStore::preview_history_at(uint64_t expected,uint64_t target,HistoryPreviewLimits limits,std::stop_token stop) const{
    return detail::guarded([&]()->Result<HistoryPreview>{
        if(limits.max_steps>history_preview_step_limit || limits.max_delta_bytes>history_preview_payload_limit)
            return Error{ErrorCode::invalid_argument,"History preview limits exceed 4096 steps or 64 MiB of delta payload"};
        std::lock_guard lock(impl_->mutex);
        if(stop.stop_requested())return Error{ErrorCode::canceled,"History preview canceled"};
        detail::Cancellation cancellation(*impl_->connection,stop);
        auto transaction=take(Transaction::begin_read(*impl_->connection));
        return detail::project_history_at(*impl_->connection,expected,target,limits,stop);
    });
}
void detail::restore_history_copy(Connection& connection,const HistoryPreview& preview){
    auto before=read_state(connection);
    require(before->uuid==preview.uuid && before->revisions==preview.source_revisions &&
            before->history_cursor==preview.source_cursor && before->history_count==preview.history_count,
            "Historical copy changed after projection");
    if(preview.target_step==before->history_cursor)return;
    auto after=next_state(*before,preview.user,before->next_entity,preview.target_step);
    write_user_state(connection,*before->user,*after->user);
    update_header(connection,*before,*after);
}
}
