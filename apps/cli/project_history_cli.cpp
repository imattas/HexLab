#include "project_history_cli.hpp"
#include "hexlab/core/sha256.hpp"
#include <iomanip>
#include <sstream>
#include <utility>

namespace hexlab::cli::project_detail {
namespace {
std::string uuid_text(const database::ProjectUuid& uuid){
    std::ostringstream text;
    text<<std::hex<<std::setfill('0');
    for(const auto byte:uuid)text<<std::setw(2)<<std::to_integer<unsigned>(byte);
    return text.str();
}
void json_string(std::ostream& out,std::string_view value){
    out<<'"';
    constexpr char digits[]="0123456789abcdef";
    for(const unsigned char c:value){
        if(c=='"'||c=='\\')out<<'\\'<<static_cast<char>(c);
        else if(c<32)out<<"\\u00"<<digits[c>>4]<<digits[c&15];
        else out<<static_cast<char>(c);
    }
    out<<'"';
}
std::string_view verification_status(const HistoryVerificationOutcome& outcome){
    return outcome.report?"verified":outcome.attempted?"budget_limited":"not_run";
}
}

HistoryVerificationOutcome verify_history_semantics(
    database::ProjectStore& store,std::uint64_t expected,database::HistoryReplayLimits limits){
    HistoryVerificationOutcome outcome;
    outcome.attempted=true;
    auto verification=store.verify_history_replay(expected,limits,{});
    if(verification)outcome.report=std::move(verification.value());
    else if(verification.error().code==ErrorCode::resource_limit)
        outcome.budget_diagnostic=verification.error().message;
    else throw Failure{verification.error()};
    return outcome;
}

void print_history_verification_json(std::ostream& out,const HistoryVerificationOutcome& outcome,
                                     database::HistoryReplayLimits limits){
    out<<"{\"status\":\""<<verification_status(outcome)<<"\",\"complete\":"
       <<(outcome.report?"true":"false")<<",\"limits\":{\"max_steps\":"<<limits.max_steps
       <<",\"max_delta_bytes\":"<<limits.max_delta_bytes<<",\"max_input_bytes\":"<<limits.max_input_bytes
       <<",\"max_validation_bytes\":"<<limits.max_validation_bytes<<"},\"report\":";
    if(outcome.report){
        const auto& report=*outcome.report;
        out<<"{\"project_uuid\":\""<<uuid_text(report.uuid)<<"\",\"source_revisions\":{\"edit\":"
           <<report.source_revisions.edit<<",\"bytes\":"<<report.source_revisions.bytes
           <<",\"decisions\":"<<report.source_revisions.decisions<<"},\"input\":{\"size\":"<<report.input.size
           <<",\"sha256\":\""<<digest_hex(report.input.sha256)<<"\"},\"history_cursor\":"<<report.history_cursor
           <<",\"history_count\":"<<report.history_count<<",\"rewound_steps\":"<<report.rewound_steps
           <<",\"forward_steps\":"<<report.forward_steps<<",\"delta_bytes\":"<<report.delta_bytes
           <<",\"input_bytes_verified\":"<<report.input_bytes_verified<<",\"validation_bytes\":"<<report.validation_bytes
           <<",\"patch_bytes_verified\":"<<report.patch_bytes_verified<<'}';
    }else out<<"null";
    out<<",\"diagnostic\":";
    if(!outcome.attempted)json_string(out,"Semantic verification waits for the structural audit to complete");
    else if(!outcome.report)json_string(out,outcome.budget_diagnostic);
    else out<<"null";
    out<<'}';
}

void print_history_verification_text(std::ostream& out,const HistoryVerificationOutcome& outcome){
    out<<" semantic-history="<<verification_status(outcome);
    if(outcome.report){
        const auto& report=*outcome.report;
        out<<" rewind="<<report.rewound_steps<<" forward="<<report.forward_steps
           <<" replay-delta-bytes="<<report.delta_bytes<<" input-bytes="<<report.input_bytes_verified
           <<" validation-bytes="<<report.validation_bytes<<" patch-bytes="<<report.patch_bytes_verified;
    }else if(outcome.attempted)out<<" ("<<escape(outcome.budget_diagnostic)<<"; increase replay budgets and retry)";
    else out<<" (structural audit is partial)";
}

int run_history_verify(const Arguments& args,std::ostream& out){
    auto store=take(database::ProjectStore::open(args.path,database::ProjectMode::read_only,{}));
    const auto snapshot=take(store->snapshot());
    const auto expected=args.history_expected_edit.value_or(snapshot->revisions.edit);
    if(expected!=snapshot->revisions.edit)
        throw Failure{{ErrorCode::conflict,"Project edit revision changed; refresh before semantic verification"}};
    const auto outcome=verify_history_semantics(*store,expected,args.history_semantic_limits);
    if(outcome.report&&(outcome.report->uuid!=snapshot->uuid||
       outcome.report->source_revisions!=snapshot->revisions||
       outcome.report->history_cursor!=snapshot->history_cursor||outcome.report->history_count!=snapshot->history_count))
        throw Failure{{ErrorCode::conflict,"Project history changed between open and semantic verification"}};
    if(args.history_json){
        out<<"{\"schema\":\"hexlab.project-history-verification.v1\",\"schema_version\":1,\"status\":\""
           <<verification_status(outcome)<<"\",\"project_uuid\":\""<<uuid_text(snapshot->uuid)
           <<"\",\"expected_edit\":"<<expected<<",\"history_cursor\":"<<snapshot->history_cursor
           <<",\"history_count\":"<<snapshot->history_count<<",\"semantic_verification\":";
        print_history_verification_json(out,outcome,args.history_semantic_limits);
        out<<"}\n";
    }else{
        out<<"History verification: project="<<uuid_text(snapshot->uuid)<<" edit="<<expected
           <<" cursor="<<snapshot->history_cursor<<'/'<<snapshot->history_count;
        print_history_verification_text(out,outcome);
        out<<'\n';
    }
    return outcome.report?0:3;
}
}
