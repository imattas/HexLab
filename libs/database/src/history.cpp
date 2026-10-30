#include "history_internal.hpp"
#include "hexlab/image/file_storage.hpp"
#include <algorithm>
#include <chrono>
#include <type_traits>
namespace hexlab::database {
Result<StateDelta> invert_delta(const StateDelta& delta){
    return detail::guarded([&]()->Result<StateDelta>{StateDelta inverse=delta;std::reverse(inverse.changes.begin(),inverse.changes.end());for(auto& change:inverse.changes)std::visit([](auto& row){std::swap(row.before,row.after);},change);return inverse;});
}
namespace detail {
namespace {
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
template<class T>std::vector<std::byte> entity_payload(const std::optional<T>& value){if(!value)return {};UserState user;if constexpr(std::is_same_v<T,TypeAssignment>){user.types.push_back({value->type_id,"history_type",types::Type::void_type()});user.type_assignments.push_back(*value);}else if constexpr(std::is_same_v<T,DebugVariable>){std::uint64_t function_id=1;while(function_id==value->id || (value->type_id && function_id==*value->type_id))++function_id;user.decisions.functions.push_back({function_id,value->function_entry,false,{}});if(value->type_id){std::uint64_t type_id=*value->type_id;user.types.push_back({type_id,"history_type",types::Type::void_type()});}records<T>(user).push_back(*value);}else records<T>(user).push_back(*value);return take(encode_user_state(user));}
template<class T>std::optional<T> entity_value(std::span<const std::byte> bytes){
    if(bytes.empty())return {};auto user=take(decode_user_state(bytes));auto& selected=records<T>(user);
    if constexpr(std::is_same_v<T,TypeAssignment>){require(selected.size()==1 && user.types.size()==1 && user.types[0].id==selected.front().type_id,"History type assignment reference mismatch");require(user.annotations.empty() && user.bookmarks.empty() && user.breakpoints.empty() && user.debug_variables.empty() && user.decisions.regions.empty() && user.decisions.functions.empty() && user.decisions.references.empty() && user.patches.empty(),"History type assignment payload has unrelated entities");return std::move(selected[0]);}
    const auto total=user.annotations.size()+user.bookmarks.size()+user.breakpoints.size()+user.types.size()+user.type_assignments.size()+user.debug_variables.size()+user.decisions.regions.size()+user.decisions.functions.size()+user.decisions.references.size();
    if constexpr(std::is_same_v<T,DebugVariable>){require(selected.size()==1 && user.decisions.functions.size()==1 && user.decisions.functions[0].entry==selected[0].function_entry && user.annotations.empty() && user.bookmarks.empty() && user.breakpoints.empty() && user.type_assignments.empty() && user.decisions.regions.empty() && user.decisions.references.empty() && user.patches.empty() && (selected[0].type_id ? user.types.size()==1 && user.types[0].id==*selected[0].type_id : user.types.empty()),"History debug-variable payload has an incompatible shape");return std::move(selected[0]);}
    require(total==1 && selected.size()==1 && user.patches.empty(),"History entity payload has an incompatible shape");return std::move(selected[0]);
}
struct Reader {
    std::span<const std::byte> bytes;size_t cursor=0;
    std::span<const std::byte> read(size_t count){require(count<=bytes.size()-cursor,"Truncated history payload");auto value=bytes.subspan(cursor,count);cursor+=count;return value;}
    uint32_t number(size_t width){uint32_t value=0;for(auto byte:read(width))value=(value<<8)|std::to_integer<unsigned>(byte);return value;}
    std::span<const std::byte> payload(){return read(number(4));}
};
}
std::vector<std::byte> encode_delta(const StateDelta& delta){
    require(!delta.changes.empty() && delta.changes.size()<=project_record_limit,"Invalid history change count");std::vector<std::byte> out{std::byte{1},std::byte{0}};
    const auto append=[&](std::span<const std::byte> bytes){require(bytes.size()<=project_payload_limit-out.size(),"History delta exceeds payload budget");out.insert(out.end(),bytes.begin(),bytes.end());};
    const auto number=[&](size_t value,size_t width){std::array<std::byte,4> bytes{};for(size_t i=0;i<width;++i)bytes[width-i-1]=std::byte(value>>(8*i));append(std::span(bytes).first(width));};
    number(delta.changes.size(),4);
    for(const auto& change:delta.changes){
        number(change.index(),1);
        std::visit([&](const auto& row){
            using T=std::decay_t<decltype(row)>;std::vector<std::byte> before,after;
            if constexpr(std::is_same_v<T,PatchChange>){UserState old_user,new_user;old_user.patches=row.before;new_user.patches=row.after;before=take(encode_user_state(old_user));after=take(encode_user_state(new_user));}
            else {before=entity_payload(row.before);after=entity_payload(row.after);}
            number(before.size(),4);append(before);number(after.size(),4);append(after);
        },change);
    }
    return out;
}
StateDelta decode_delta(std::span<const std::byte> bytes){
    require(bytes.size()<=project_payload_limit,"History delta exceeds payload budget");Reader reader{bytes};require(reader.number(1)==1 && reader.number(1)==0,"Unknown history version");const auto count=reader.number(4);require(count>0 && count<=project_record_limit && count<=(bytes.size()-reader.cursor)/9,"Invalid history change count");StateDelta delta;
    for(uint32_t i=0;i<count;++i){
        const auto tag=reader.number(1);const auto before=reader.payload(),after=reader.payload();
        switch(tag){
        case 0:delta.changes.push_back(AnnotationChange{entity_value<Annotation>(before),entity_value<Annotation>(after)});break;
        case 1:delta.changes.push_back(BookmarkChange{entity_value<Bookmark>(before),entity_value<Bookmark>(after)});break;
        case 2:delta.changes.push_back(RegionChange{entity_value<RegionDecision>(before),entity_value<RegionDecision>(after)});break;
        case 3:delta.changes.push_back(FunctionChange{entity_value<FunctionDecision>(before),entity_value<FunctionDecision>(after)});break;
        case 4:delta.changes.push_back(ReferenceChange{entity_value<UserReference>(before),entity_value<UserReference>(after)});break;
        case 5:{
            auto old_user=take(decode_user_state(before)),new_user=take(decode_user_state(after));
            const auto only_patches=[](const UserState& user){return user.annotations.empty() && user.bookmarks.empty() && user.breakpoints.empty() && user.types.empty() && user.type_assignments.empty() && user.debug_variables.empty() && user.decisions.regions.empty() && user.decisions.functions.empty() && user.decisions.references.empty();};
            require(only_patches(old_user) && only_patches(new_user),"History patch payload contains unrelated entities");delta.changes.push_back(PatchChange{std::move(old_user.patches),std::move(new_user.patches)});break;
        }
        case 6:delta.changes.push_back(TypeDefinitionChange{entity_value<TypeDefinition>(before),entity_value<TypeDefinition>(after)});break;
        case 7:delta.changes.push_back(TypeAssignmentChange{entity_value<TypeAssignment>(before),entity_value<TypeAssignment>(after)});break;
        case 8:delta.changes.push_back(DebugVariableChange{entity_value<DebugVariable>(before),entity_value<DebugVariable>(after)});break;
        case 9:delta.changes.push_back(ProjectBreakpointChange{entity_value<ProjectBreakpoint>(before),entity_value<ProjectBreakpoint>(after)});break;
        default:throw Failure{{ErrorCode::integrity,"Unknown history change kind"}};
        }
    }
    require(reader.cursor==bytes.size(),"Trailing history data");return delta;
}
void append_history(Connection& connection,uint64_t step,uint64_t group,bool bytes,bool decisions,const StateDelta& delta){
    const auto forward=encode_delta(delta),inverse=encode_delta(take(invert_delta(delta)));
    const auto now=std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::system_clock::now().time_since_epoch()).count();
    require(now>=0,"System clock predates Unix epoch while recording project history");
    auto remove=take(connection.prepare("DELETE FROM history WHERE step>=?1"));take(remove->bind_blob(1,encode_u64(step)));take(remove->step());
    auto row=take(connection.prepare("INSERT INTO history(step,group_id,byte_change,decision_change,created_unix_ms) VALUES(?1,?2,?3,?4,?5)"));take(row->bind_blob(1,encode_u64(step)));take(row->bind_blob(2,encode_u64(group)));take(row->bind_integer(3,bytes));take(row->bind_integer(4,decisions));take(row->bind_blob(5,encode_u64(static_cast<std::uint64_t>(now))));take(row->step());
    auto payload=take(connection.prepare("INSERT INTO history_payload VALUES(?1,?2,?3,?4)"));
    for(int side=0;side<2;++side){const auto& data=side?inverse:forward;size_t ordinal=0;for(size_t cursor=0;cursor<data.size();){const auto amount=std::min<size_t>(1024*1024,data.size()-cursor);take(payload->bind_blob(1,encode_u64(step)));take(payload->bind_integer(2,side));take(payload->bind_integer(3,ordinal++));take(payload->bind_blob(4,std::span(data).subspan(cursor,amount)));take(payload->step());take(payload->reset());cursor+=amount;}}
}
StateDelta read_history_bounded(Connection& connection,uint64_t step,bool inverse,size_t& remaining){
    auto payload=take(connection.prepare("SELECT ordinal,length(data),data,typeof(ordinal),typeof(data) FROM history_payload WHERE step=?1 AND side=?2 ORDER BY ordinal"));take(payload->bind_blob(1,encode_u64(step)));take(payload->bind_integer(2,inverse?1:0));
    std::vector<std::byte> data;size_t ordinal=0;
    while(take(payload->step())){
        require(take(payload->text(3))=="integer" && take(payload->text(4))=="blob","History chunk metadata has an invalid storage type");
        require(take(payload->integer(0))==static_cast<int64_t>(ordinal++),"Missing history payload chunk");
        const auto size=take(payload->integer(1));
        require(size>0 && size<=1024*1024 && static_cast<uint64_t>(size)<=project_payload_limit-data.size(),"Invalid history chunk extent");
        if(static_cast<uint64_t>(size)>remaining)throw Failure{{ErrorCode::resource_limit,"History delta payload budget exceeded"}};
        auto chunk=take(payload->blob(2));require(chunk.size()==static_cast<size_t>(size),"History chunk length mismatch");
        remaining-=chunk.size();data.insert(data.end(),chunk.begin(),chunk.end());
    }
    require(!data.empty(),"Missing history delta");return decode_delta(data);
}
void validate_history_payload_rows(Connection& connection,uint64_t step){
    // Read both sides below only where side is 0 or 1. First reject malformed
    // rows at this step so an extra side or CHECK-bypassing write cannot be
    // hidden from the audit's directional delta reads.
    auto invalid=take(connection.prepare(
        "SELECT 1 FROM history_payload WHERE step=?1 AND ("
        "typeof(side)!='integer' OR side NOT IN(0,1) OR "
        "typeof(ordinal)!='integer' OR ordinal<0 OR "
        "typeof(data)!='blob' OR length(data) NOT BETWEEN 1 AND 1048576) LIMIT 1"));
    take(invalid->bind_blob(1,encode_u64(step)));
    require(!take(invalid->step()),"Invalid history payload row metadata");
}
StateDelta read_history(Connection& connection,uint64_t step,bool inverse){
    size_t remaining=project_payload_limit;return read_history_bounded(connection,step,inverse,remaining);
}
HistoryPage read_history_header(Connection& connection, bool validate_full_history){
    HistoryPage page;
    const auto version=schema_version(connection);
    auto header=take(connection.prepare(version==0
        ? "SELECT uuid,edit_revision,byte_revision,X'0000000000000000',history_cursor FROM project WHERE singleton=1"
        : "SELECT uuid,edit_revision,byte_revision,decision_revision,history_cursor FROM project WHERE singleton=1"));
    require(take(header->step()),"Project header is missing");
    const auto uuid=take(header->blob(0));
    require(uuid.size()==page.uuid.size() && std::any_of(uuid.begin(),uuid.end(),[](auto value){return value!=std::byte{0};}),"Invalid project UUID");
    std::copy(uuid.begin(),uuid.end(),page.uuid.begin());
    page.source_revisions={take(decode_u64(take(header->blob(1)))),take(decode_u64(take(header->blob(2)))),take(decode_u64(take(header->blob(3))))};
    page.history_cursor=take(decode_u64(take(header->blob(4))));
    require(!take(header->step()),"Duplicate project header");
    require(page.source_revisions.bytes<=page.source_revisions.edit && page.source_revisions.decisions<=page.source_revisions.edit && page.history_cursor<=page.source_revisions.edit,"Inconsistent project revision header");
    if (validate_full_history) {
        const auto timestamp_check = version>=18
            ? "(created_unix_ms IS NOT NULL AND (typeof(created_unix_ms)!='blob' OR length(created_unix_ms)!=8))"
            : "0";
        auto extent=take(connection.prepare(
            "SELECT count(*),min(step),max(step),coalesce(sum(CASE WHEN "
            "typeof(step)!='blob' OR length(step)!=8 OR typeof(group_id)!='blob' OR length(group_id)!=8 OR "
            "typeof(byte_change)!='integer' OR byte_change NOT IN(0,1) OR "
            "typeof(decision_change)!='integer' OR decision_change NOT IN(0,1) OR "
            + std::string(timestamp_check) + " "
            "THEN 1 ELSE 0 END),0) FROM history"));
        require(take(extent->step()),"Cannot read history extent");
        const auto count=take(extent->integer(0));
        require(count>=0 && count<=project_record_limit && take(extent->integer(3))==0,"Invalid history metadata");
        page.history_count=static_cast<uint64_t>(count);
        if(count>0)require(take(decode_u64(take(extent->blob(1))))==1 && take(decode_u64(take(extent->blob(2))))==page.history_count,"History sequence has a gap");
    } else {
        // The primary-key index is ordered by fixed-width big-endian step,
        // so its final key gives the history endpoint without scanning every
        // row. The requested page validates its own rows and continuity.
        auto extent=take(connection.prepare("SELECT step FROM history ORDER BY step DESC LIMIT 1"));
        if(take(extent->step())) {
            page.history_count=take(decode_u64(take(extent->blob(0))));
            require(page.history_count>0 && page.history_count<=project_record_limit,"History entry count exceeds budget or starts at zero");
            require(!take(extent->step()),"Duplicate maximum history key");
        }
    }
    require(page.history_cursor<=page.history_count,"History cursor exceeds durable history");
    return page;
}
std::vector<HistoryRow> history_rows(Connection& connection){
    auto query=take(connection.prepare("SELECT step,group_id FROM history ORDER BY step"));std::vector<HistoryRow> rows;
    while(take(query->step())){require(rows.size()<project_record_limit,"History entry count exceeds budget");const auto step=take(decode_u64(take(query->blob(0)))),group=take(decode_u64(take(query->blob(1))));require(step==rows.size()+1,"History sequence has a gap");rows.push_back({step,group});}
    return rows;
}
Result<HistorySourceIdentityCheck> check_current_external_input(
    const ProjectState& state,const std::filesystem::path& project,std::stop_token stop) {
    if(!state.provenance)return HistorySourceIdentityCheck::no_recorded_path;
    const auto& provenance=*state.provenance;
    std::filesystem::path source_path;
    if(!provenance.relative_path.empty()) {
        const auto relative=std::filesystem::path(std::u8string(
            reinterpret_cast<const char8_t*>(provenance.relative_path.data()),provenance.relative_path.size()));
        source_path=(project.parent_path()/relative).lexically_normal();
    } else if(provenance.native_path.is_absolute()) {
        source_path=provenance.native_path;
    }
    if(source_path.empty())return HistorySourceIdentityCheck::no_recorded_path;
    if(stop.stop_requested())return Error{ErrorCode::canceled,"External source identity check canceled"};
    const auto opened=FileStorage::open(source_path);
    if(!opened)return HistorySourceIdentityCheck::unavailable;
    const auto& source=*opened.value();
    if(source.size()>history_source_identity_check_limit)return HistorySourceIdentityCheck::over_limit;
    if(source.size()!=state.input.size)return HistorySourceIdentityCheck::size_mismatch;
    Sha256 hash;
    for(std::uint64_t position=0;position<source.size();) {
        if(stop.stop_requested())return Error{ErrorCode::canceled,"External source identity check canceled"};
        const auto amount=static_cast<std::size_t>(std::min<std::uint64_t>(1024u*1024u,source.size()-position));
        const auto view=source.read_at({position},amount);
        if(!view || view.value().bytes.size()!=amount)return HistorySourceIdentityCheck::unavailable;
        const auto hashed=hash.update(view.value().bytes);
        if(!hashed)return HistorySourceIdentityCheck::unavailable;
        position+=amount;
    }
    if(stop.stop_requested())return Error{ErrorCode::canceled,"External source identity check canceled"};
    return hash.digest()==state.input.sha256 ? HistorySourceIdentityCheck::matches
                                              : HistorySourceIdentityCheck::digest_mismatch;
}
}
Result<HistoryPage> ProjectStore::history_page(uint64_t expected,uint64_t after,size_t limit,std::stop_token stop) const{
    return detail::guarded([&]()->Result<HistoryPage>{
        if(limit==0 || limit>history_page_limit)return Error{ErrorCode::invalid_argument,"History page limit must be between 1 and 1024"};
        std::lock_guard lock(impl_->mutex);
        if(stop.stop_requested())return Error{ErrorCode::canceled,"History metadata read canceled"};
        detail::Cancellation cancellation(*impl_->connection,stop);
        auto transaction=detail::take(Transaction::begin_read(*impl_->connection));
        auto page=detail::read_history_header(*impl_->connection, false);
        if(page.source_revisions.edit!=expected)return Error{ErrorCode::conflict,"Project edit revision changed; refresh before retrying"};
        if(after>page.history_count)return Error{ErrorCode::invalid_argument,"History page cursor exceeds durable history"};
        const auto history_schema=detail::schema_version(*impl_->connection);
        auto query=detail::take(impl_->connection->prepare(history_schema>=18
            ? "SELECT step,group_id,byte_change,decision_change,created_unix_ms,typeof(created_unix_ms) FROM history WHERE step>?1 ORDER BY step LIMIT ?2"
            : "SELECT step,group_id,byte_change,decision_change,NULL,'null' FROM history WHERE step>?1 ORDER BY step LIMIT ?2"));
        detail::take(query->bind_blob(1,encode_u64(after)));detail::take(query->bind_integer(2,static_cast<int64_t>(limit)));
        page.next_after_step=after;page.entries.reserve(limit);
        while(detail::take(query->step())){
            const auto step=detail::take(decode_u64(detail::take(query->blob(0))));
            detail::require(step==page.next_after_step+1,"History sequence has a gap");
            const auto group=detail::take(decode_u64(detail::take(query->blob(1))));
            const auto byte_change=detail::take(query->integer(2));
            const auto decision_change=detail::take(query->integer(3));
            detail::require((byte_change==0 || byte_change==1) && (decision_change==0 || decision_change==1),"Invalid history metadata flags");
            std::optional<std::uint64_t> created_unix_ms;
            if (!detail::take(query->is_null(4))) {
                detail::require(detail::take(query->text(5))=="blob","History timestamp has an invalid storage type");
                created_unix_ms=detail::take(decode_u64(detail::take(query->blob(4))));
            }
            page.entries.push_back({step,group,byte_change!=0,decision_change!=0,step<=page.history_cursor,created_unix_ms});
            page.next_after_step=step;
        }
        if(page.entries.size()<limit && page.next_after_step<page.history_count)
            return Error{ErrorCode::integrity,"History sequence has a gap"};
        page.has_more=page.next_after_step<page.history_count;
        if(stop.stop_requested())return Error{ErrorCode::canceled,"History metadata read canceled"};
        return page;
    });
}
Result<HistoryAuditPage> ProjectStore::audit_history(uint64_t expected,uint64_t after,HistoryAuditLimits limits,std::stop_token stop) const{
    return detail::guarded([&]()->Result<HistoryAuditPage>{
        if(limits.max_steps>history_audit_step_limit || limits.max_delta_bytes>history_audit_payload_limit)
            return Error{ErrorCode::invalid_argument,"History audit limits exceed 4096 steps or 128 MiB of delta payload"};
        std::lock_guard lock(impl_->mutex);
        if(stop.stop_requested())return Error{ErrorCode::canceled,"History audit canceled"};
        detail::Cancellation cancellation(*impl_->connection,stop);
        auto transaction=detail::take(Transaction::begin_read(*impl_->connection));
        auto header=detail::read_history_header(*impl_->connection,false);
        if(header.source_revisions.edit!=expected)return Error{ErrorCode::conflict,"Project edit revision changed; refresh before retrying"};
        if(after>header.history_count)return Error{ErrorCode::invalid_argument,"History audit cursor exceeds durable history"};
        auto orphan=detail::take(impl_->connection->prepare(
            "SELECT 1 FROM history_payload AS p LEFT JOIN history AS h ON h.step=p.step WHERE h.step IS NULL LIMIT 1"));
        if(detail::take(orphan->step()))return Error{ErrorCode::integrity,"History payload contains an orphan step key"};
        auto trailing=detail::take(impl_->connection->prepare("SELECT 1 FROM history WHERE step>?1 LIMIT 1"));
        detail::take(trailing->bind_blob(1,encode_u64(header.history_count)));
        if(detail::take(trailing->step()))return Error{ErrorCode::integrity,"History contains entries beyond the durable count"};
        HistoryAuditPage page{header.uuid,header.source_revisions,header.history_cursor,header.history_count,after,0,0,false};
        const auto history_schema=detail::schema_version(*impl_->connection);
        auto query=detail::take(impl_->connection->prepare(history_schema>=18
            ? "SELECT step,group_id,byte_change,decision_change,created_unix_ms,typeof(created_unix_ms) FROM history WHERE step>?1 ORDER BY step LIMIT ?2"
            : "SELECT step,group_id,byte_change,decision_change,NULL,'null' FROM history WHERE step>?1 ORDER BY step LIMIT ?2"));
        detail::take(query->bind_blob(1,encode_u64(after)));
        detail::take(query->bind_integer(2,static_cast<int64_t>(limits.max_steps)));
        // The bounded reader decrements this shared counter for every chunk
        // from both payload directions, so the budget covers the page total.
        auto remaining=limits.max_delta_bytes;
        while(detail::take(query->step())){
            if(stop.stop_requested())return Error{ErrorCode::canceled,"History audit canceled"};
            const auto step=detail::take(decode_u64(detail::take(query->blob(0))));
            detail::require(step==page.next_after_step+1,"History sequence has a gap");
            (void)detail::take(decode_u64(detail::take(query->blob(1))));
            detail::validate_history_payload_rows(*impl_->connection,step);
            const auto byte_change=detail::take(query->integer(2));
            const auto decision_change=detail::take(query->integer(3));
            detail::require((byte_change==0 || byte_change==1) && (decision_change==0 || decision_change==1),"Invalid history metadata flags");
            if (!detail::take(query->is_null(4))) {
                detail::require(detail::take(query->text(5))=="blob","History timestamp has an invalid storage type");
                (void)detail::take(decode_u64(detail::take(query->blob(4))));
            }
            const auto forward=detail::read_history_bounded(*impl_->connection,step,false,remaining);
            const auto inverse=detail::read_history_bounded(*impl_->connection,step,true,remaining);
            bool delta_changes_bytes=false,delta_changes_decisions=false;
            for(const auto& change:forward.changes)std::visit([&](const auto& row){
                using Change=std::decay_t<decltype(row)>;
                if constexpr(std::is_same_v<Change,PatchChange>)
                    delta_changes_bytes=delta_changes_bytes || row.before!=row.after;
                else if constexpr(std::is_same_v<Change,RegionChange> ||
                                  std::is_same_v<Change,FunctionChange> ||
                                  std::is_same_v<Change,ReferenceChange>)
                    delta_changes_decisions=delta_changes_decisions || row.before!=row.after;
            },change);
            detail::require((byte_change!=0)==delta_changes_bytes,
                            "History byte-change metadata disagrees with its forward delta");
            detail::require((decision_change!=0)==delta_changes_decisions,
                            "History decision-change metadata disagrees with its forward delta");
            const auto expected_inverse=detail::take(invert_delta(forward));
            detail::require(detail::encode_delta(expected_inverse)==detail::encode_delta(inverse),"History forward and inverse payloads disagree");
            page.next_after_step=step;
            ++page.entries_verified;
        }
        if(limits.max_steps!=0 && page.entries_verified<limits.max_steps && page.next_after_step<header.history_count)
            return Error{ErrorCode::integrity,"History sequence has a gap"};
        page.has_more=page.next_after_step<header.history_count;
        page.delta_bytes=limits.max_delta_bytes-remaining;
        if(stop.stop_requested())return Error{ErrorCode::canceled,"History audit canceled"};
        if(after==0)page.source_identity_check=detail::take(
            detail::check_current_external_input(*impl_->state,impl_->path,stop));
        return page;
    });
}
}
