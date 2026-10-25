#include "hexlab/automation/api.hpp"
#include <chrono>
#include <fstream>
#include <iostream>
#include <limits>
#include <stdexcept>
#include <thread>
using namespace hexlab;
void check(bool condition,const char* message){if(!condition)throw std::runtime_error(message);}
template<class T>T take(Result<T> result){if(!result)throw std::runtime_error(result.error().message);return std::move(result.value());}
int main(){
    const auto directory=std::filesystem::temp_directory_path()/("hexlab-graph-"+std::to_string(std::chrono::steady_clock::now().time_since_epoch().count()));
    std::filesystem::create_directory(directory);
    try{
        const auto source=directory/"branch.bin",path=directory/"branch.hxproj";
        {std::ofstream out(source,std::ios::binary);const unsigned char code[]={0x85,0xc0,0x74,0x02,0x90,0xc3,0xcc,0xc3};out.write(reinterpret_cast<const char*>(code),sizeof(code));}
        auto project=take(automation::Project::create(path,source,{Format::raw,RawOptions{Architecture::x86_64,ExecutionMode::x86_64,{{9},0x4000},true,false,true,{}}}));
        const Address entry{{9},0x4000};
        auto blocks=take(project->function_blocks(entry,0,1));
        check(blocks.size()==1 && blocks[0].begin==entry && blocks[0].instruction_count==2 && blocks[0].successor_count==2,"entry block describes the decoded conditional branch");
        const auto block_id=blocks[0].id;
        const auto detached=blocks[0];
        auto rest=take(project->function_blocks(Address{{9},0x4002},1,2));
        check(rest.size()==2 && rest[0].begin==Address{{9},0x4004} && rest[1].begin==Address{{9},0x4006},"block paging accepts an interior function address and retains deterministic order");
        check(take(project->function_blocks(entry,3,1)).empty() && take(project->function_blocks(entry,SIZE_MAX,1)).empty(),"end and oversized offsets return empty pages");
        auto instruction=take(project->block_instructions(block_id,1,1));
        check(instruction.size()==1 && instruction[0].address==Address{{9},0x4002} && instruction[0].direct_target==Address{{9},0x4006},"per-block instruction pages retain exact branch target");
        const auto edges=take(project->block_successors(block_id,0,2));
        check(edges.size()==2,"conditional branch has two successors");
        bool true_edge=false,false_edge=false;
        for(const auto& edge:edges){
            check(edge.source==Address{{9},0x4002} && edge.block.has_value(),"CFG edges retain branch source and resolved block identity");
            true_edge|=edge.kind==BlockEdgeKind::conditional_true && edge.target==Address{{9},0x4006};
            false_edge|=edge.kind==BlockEdgeKind::conditional_false && edge.target==Address{{9},0x4004};
        }
        check(true_edge && false_edge && take(project->block_successors(block_id,1,1)).size()==1,"taken and fallthrough successors survive bounded paging");
        check(rest[1].stop && rest[1].stop->reason==FunctionStopReason::trap,"terminal block exposes analysis stop evidence");
        take(project->execute(Rename{entry,"decision"},17));
        take(project->execute(Comment{entry,"branch review"},17));
        auto named=take(project->function_blocks(entry,0,1))[0];
        check(named.presentation.name=="decision" && named.presentation.comment=="branch review" && named.presentation.user_name,"graph presentation follows durable project edits");
        check(detached.presentation.name=="sub_9_4000" && detached.presentation.comment.empty() && !detached.presentation.user_name,"graph pages own detached presentation values");
        check(take(project->presentation(entry)).name=="decision","arbitrary location presentation uses effective project names");
        take(project->undo());
        check(take(project->presentation(entry)).comment.empty(),"grouped graph annotations participate in undo");
        take(project->redo());
        for(auto result:{project->function_blocks(entry,0,0),project->function_blocks(entry,0,automation::maximum_page+1)})check(!result && result.error().code==ErrorCode::resource_limit,"block page bounds rejected");
        check(!project->block_instructions(block_id,0,0) && !project->block_successors(block_id,0,automation::maximum_page+1),"nested graph pages remain bounded");
        check(!project->function_blocks(Address{{8},0x4000}) && !project->block_instructions(BlockId{UINT64_MAX}) && !project->block_successors(BlockId{UINT64_MAX}),"unknown functions and blocks rejected");
        bool rejected=false;
        std::thread other([&]{auto result=project->function_blocks(entry);rejected=!result && result.error().code==ErrorCode::conflict;});other.join();
        check(rejected,"graph queries obey project thread ownership");
        take(project->patch(entry,{std::byte{0x90}},take(project->snapshot())->state->revisions.edit));
        check(!project->function_blocks(entry) && !project->block_instructions(block_id) && !project->block_successors(block_id),"byte edits reject stale graph and block queries");
        check(take(project->presentation(entry)).comment=="branch review","presentation is available while analysis is stale");
        take(project->undo());take(project->analyze());project.reset();
        auto readonly=take(automation::Project::open(path));
        check(take(readonly->function_blocks(entry))[0].presentation.name=="decision","readonly reopen exposes persisted graph annotations");
        readonly.reset();std::filesystem::remove_all(directory);
        std::cout<<"Automation graph: bounded blocks/instructions/edges, presentation, history, stale facts and ownership passed\n";
        return 0;
    }catch(const std::exception& error){std::cerr<<error.what()<<'\n';std::filesystem::remove_all(directory);return 1;}
}
