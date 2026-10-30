#include "history_internal.hpp"
#include <algorithm>
#include <string>
#include <type_traits>
#include <utility>

namespace hexlab::database {
namespace {
using detail::take;
using detail::require;
using detail::Failure;

constexpr std::size_t replay_step_limit=2*project_record_limit;
constexpr std::size_t replay_delta_limit=512u*1024u*1024u;
constexpr std::uint64_t replay_validation_limit=UINT64_C(4)*1024*1024*1024;

void check_cancellation(std::stop_token stop){
    if(stop.stop_requested())throw Failure{{ErrorCode::canceled,"History semantic verification canceled"}};
}

struct VerifiedStep {
    StateDelta forward,inverse;
    bool byte_change=false,decision_change=false;
};

VerifiedStep read_step(Connection& connection,std::uint64_t step,std::size_t& remaining){
    auto metadata=take(connection.prepare(
        "SELECT group_id,byte_change,decision_change FROM history WHERE step=?1"));
    take(metadata->bind_blob(1,encode_u64(step)));
    require(take(metadata->step()),"History sequence has a gap");
    (void)take(decode_u64(take(metadata->blob(0))));
    const auto bytes=take(metadata->integer(1)),decisions=take(metadata->integer(2));
    require((bytes==0||bytes==1)&&(decisions==0||decisions==1),"Invalid history metadata flags");
    require(!take(metadata->step()),"Duplicate history step");
    detail::validate_history_payload_rows(connection,step);
    VerifiedStep result{detail::read_history_bounded(connection,step,false,remaining),
                        detail::read_history_bounded(connection,step,true,remaining),
                        bytes!=0,decisions!=0};
    const auto inverse=take(invert_delta(result.forward));
    require(detail::encode_delta(inverse)==detail::encode_delta(result.inverse),
            "History forward and inverse payloads disagree");
    return result;
}

void consume_validation(std::uint64_t amount,std::uint64_t& remaining){
    if(amount>remaining)throw Failure{{ErrorCode::resource_limit,
        "History semantic verification cumulative state/patch validation budget exceeded"}};
    remaining-=amount;
}

void validate_projection(const UserState& user,const ByteStorage& original,
                         std::uint64_t& remaining,HistoryReplayReport& report,std::stop_token stop){
    check_cancellation(stop);
    // The codec additionally enforces the per-state 64 MiB and field budgets.
    const auto canonical_size=take(encode_user_state(user)).size();
    consume_validation(canonical_size,remaining);
    for(const auto& patch:user.patches){
        check_cancellation(stop);
        require(patch.begin.value<=original.size()&&patch.original.size()<=original.size()-patch.begin.value,
                "Historical patch exceeds embedded original input");
        consume_validation(patch.original.size(),remaining);
        const auto view=take(original.read_at(patch.begin,patch.original.size()));
        require(view.bytes.size()==patch.original.size()&&
                std::equal(view.bytes.begin(),view.bytes.end(),patch.original.begin()),
                "Historical patch original bytes do not match embedded input");
        report.patch_bytes_verified+=patch.original.size();
    }
}

void apply_step(UserState& user,const VerifiedStep& step,bool inverse,std::uint64_t& next,
                std::uint64_t at,std::stop_token stop){
    // Keep only the collections needed to compare actual invalidation effects;
    // copying a full state for every command would double the replay working set.
    const auto previous_patches=user.patches;
    const auto previous_decisions=user.decisions;
    try {
        detail::apply_history_delta(user,inverse?step.inverse:step.forward,next,stop);
    } catch(const Failure& failure) {
        if(failure.error.code==ErrorCode::conflict)
            throw Failure{{ErrorCode::integrity,"History step "+std::to_string(at)+
                " does not apply to its recorded state: "+failure.error.message}};
        throw;
    }
    require((previous_patches!=user.patches)==step.byte_change,
            "History byte-change metadata disagrees with replayed state");
    require((previous_decisions!=user.decisions)==step.decision_change,
            "History decision-change metadata disagrees with replayed state");
}
}

Result<HistoryReplayReport> ProjectStore::verify_history_replay(
    std::uint64_t expected,HistoryReplayLimits limits,std::stop_token stop) const {
    return detail::guarded([&]()->Result<HistoryReplayReport>{
        if(limits.max_steps>replay_step_limit||limits.max_delta_bytes>replay_delta_limit||
           limits.max_input_bytes>source_archive_byte_limit||limits.max_validation_bytes>replay_validation_limit)
            return Error{ErrorCode::invalid_argument,
                "History semantic verification limits exceed 200000 transitions, 512 MiB of deltas, "
                "1 GiB of input or 4 GiB of cumulative state/patch validation"};
        check_cancellation(stop);
        std::lock_guard lock(impl_->mutex);
        detail::Cancellation cancellation(*impl_->connection,stop);
        auto transaction=take(Transaction::begin_read(*impl_->connection));
        auto& connection=*impl_->connection;
        const auto header=detail::read_history_header(connection);
        if(header.source_revisions.edit!=expected)
            return Error{ErrorCode::conflict,"Project edit revision changed; refresh before semantic verification"};
        auto state=detail::read_state(connection);
        if(state->uuid!=impl_->state->uuid||state->input!=impl_->state->input)
            return Error{ErrorCode::conflict,"Project identity changed before semantic verification"};
        if(state->history_cursor+state->history_count>limits.max_steps)
            return Error{ErrorCode::resource_limit,"History semantic verification transition budget exceeded"};
        if(state->input.size>limits.max_input_bytes)
            return Error{ErrorCode::resource_limit,"History semantic verification input budget exceeded"};

        auto orphan=take(connection.prepare(
            "SELECT 1 FROM history_payload AS p LEFT JOIN history AS h ON h.step=p.step WHERE h.step IS NULL LIMIT 1"));
        require(!take(orphan->step()),"History payload contains an orphan step key");
        orphan.reset();

        // Re-extract within this read transaction so neither a cached input nor
        // a prior open can hide changes to embedded bytes by another connection.
        // The owned temporary is local; it never replaces the store's backing.
        auto original=detail::extract_input(connection,*state,stop);
        HistoryReplayReport report;
        report.uuid=state->uuid;report.source_revisions=state->revisions;report.input=state->input;
        report.history_cursor=state->history_cursor;report.history_count=state->history_count;
        report.input_bytes_verified=state->input.size;
        auto delta_remaining=limits.max_delta_bytes;
        auto validation_remaining=limits.max_validation_bytes;
        auto user=*state->user;
        auto next=state->next_entity;
        validate_projection(user,*original,validation_remaining,report,stop);

        // Establish the real root from current state, using every applied
        // inverse. A structurally valid log must still lead to an empty root.
        for(auto cursor=state->history_cursor;cursor!=0;--cursor){
            check_cancellation(stop);
            const auto step=read_step(connection,cursor,delta_remaining);
            apply_step(user,step,true,next,cursor,stop);
            validate_projection(user,*original,validation_remaining,report,stop);
            ++report.rewound_steps;
        }
        require(user==UserState{},"History step zero contains user state not accounted for by retained history");
        if(state->history_cursor==0)
            require(user==*state->user,"Current project state disagrees with history cursor zero");

        // Replay from that root across both the applied branch and every redo
        // command. At the durable cursor, compare all undoable collections.
        std::uint64_t last_created_id=0;
        for(std::uint64_t cursor=1;cursor<=state->history_count;++cursor){
            check_cancellation(stop);
            const auto step=read_step(connection,cursor,delta_remaining);
            // A pruned redo branch may leave allocation gaps, but stable IDs
            // can never be reused or move backward in the retained timeline.
            for(const auto& change:step.forward.changes)std::visit([&](const auto& row){
                if constexpr(!std::is_same_v<std::decay_t<decltype(row)>,PatchChange>){
                    if(!row.before&&row.after){
                        require(row.after->id>last_created_id&&row.after->id<state->next_entity,
                                "History reuses or reverses a stable entity allocation");
                        last_created_id=row.after->id;
                    }
                }
            },change);
            apply_step(user,step,false,next,cursor,stop);
            validate_projection(user,*original,validation_remaining,report,stop);
            if(cursor==state->history_cursor)
                require(user==*state->user,"Current project user state disagrees with replay at its history cursor");
            ++report.forward_steps;
        }
        report.delta_bytes=limits.max_delta_bytes-delta_remaining;
        report.validation_bytes=limits.max_validation_bytes-validation_remaining;
        check_cancellation(stop);
        take(transaction->commit());
        return report;
    });
}
}
