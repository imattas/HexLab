#include "hexlab/analysis/functions.hpp"
#include "hexlab/analysis/dependencies.hpp"
#include "support/checks.hpp"
#include "support/fixture_files.hpp"
#include <algorithm>
#include <iostream>
#include <set>
#include <tuple>
using namespace hexlab;
using namespace hexlab_test;
struct MemorySource final:ByteStorage {
    std::shared_ptr<const std::vector<std::byte>> data;
    explicit MemorySource(std::vector<std::byte> value):data(std::make_shared<const std::vector<std::byte>>(std::move(value))){}
    uint64_t size()const noexcept override{return data->size();}
    Result<ByteView> read_at(FileOffset offset,size_t count)const override{
        if(offset.value>size() || count>size()-offset.value)return Error{ErrorCode::out_of_bounds,"Fixture read exceeds storage"};
        return ByteView{data,std::span(*data).subspan(static_cast<size_t>(offset.value),count)};
    }
};
std::shared_ptr<const Image> image(std::vector<std::byte> data,bool executable=true,uint64_t memory_size=0){
    auto source=std::make_shared<MemorySource>(std::move(data));const auto size=source->size();
    ImageLayout layout{{{0},64,1,ByteOrder::little},Architecture::x86_64,ExecutionMode::x86_64,{{"code",{{0},0x1000},memory_size?memory_size:size,{0},size,true,false,executable}},{{{0},0x1000}}};
    return Image::create(source,std::move(layout)).value();
}
std::shared_ptr<const Image> architecture_image(Architecture architecture,ExecutionMode mode,std::uint8_t width,
                                                std::vector<std::byte> data){
    auto source=std::make_shared<MemorySource>(std::move(data));const auto size=source->size();
    ImageLayout layout{{{0},width,1,ByteOrder::little},architecture,mode,
        {{"code",{{0},0x1000},size,{0},size,true,false,true}},{{{0},0x1000}}};
    return Image::create(source,std::move(layout)).value();
}
const FunctionRecord& function(const FunctionSnapshot& snapshot,uint64_t entry){for(const auto& value:snapshot.functions)if(value->entry.offset==entry)return *value;throw std::runtime_error("Expected function not found");}
const BasicBlock& block(const FunctionSnapshot& snapshot,uint64_t begin){for(const auto& value:snapshot.blocks)if(value->begin.offset==begin)return *value;throw std::runtime_error("Expected block not found");}
bool stopped(const FunctionSnapshot& snapshot,FunctionStopReason reason){for(const auto& value:snapshot.functions)for(const auto& stop:value->stops)if(stop.reason==reason)return true;for(const auto& value:snapshot.candidates)if(value.reason==reason)return true;return false;}
void partition_tests(){
    auto branch=recover_functions(*image(bytes({0xeb,3,0,0,0,0xc3})),{},{},{},{}).value();
    check(branch->functions.size()==1 && branch->blocks.size()==2 && branch->instructions.size()==2,"branch target becomes a block rather than an invented function");
    auto call=recover_functions(*image(bytes({0xe8,1,0,0,0,0xc3,0xc3})),{},{},{},{}).value();
    check(call->functions.size()==2 && function(*call,0x1000).blocks.size()==2 && function(*call,0x1006).blocks.size()==1,"direct call seeds a separate callee and continuation leader");
    check(call->calls.size()==1 && call->calls[0].target==Address{{0},0x1006} && !call->calls[0].tail_candidate,"direct call evidence retained without caller absorbing callee");
    auto diamond=recover_functions(*image(bytes({0x74,3,0x90,0xeb,1,0x90,0xc3})),{},{},{},{}).value();
    std::set<uint64_t> starts;for(const auto& value:diamond->blocks)starts.insert(value->begin.offset);
    check(starts==std::set<uint64_t>{0x1000,0x1002,0x1005,0x1006} && block(*diamond,0x1002).instructions.size()==2,"diamond partitions at branch successors and join leaders");
    check(function(*diamond,0x1000).chunks.size()==1 && function(*diamond,0x1000).chunks[0].size==7 && diamond->complete,"function chunk covers decoded extents without gaps");
    auto loop=recover_functions(*image(bytes({0xeb,0xfe})),{},{},{},{}).value();check(loop->functions.size()==1 && loop->blocks.size()==1 && block(*loop,0x1000).successors.size()==1 && loop->complete,"self-loop terminates traversal with a complete cyclic block");
}
void ownership_tests(){
    auto data=std::vector<std::byte>(17);data[0]=std::byte{0xeb};data[1]=std::byte{14};data[8]=std::byte{0xeb};data[9]=std::byte{6};data[16]=std::byte{0xc3};ImageMetadata metadata;metadata.exports.push_back({1,"second",Address{{0},0x1008},{}});
    auto result=recover_functions(*image(data),metadata,{},{},{}).value();
    check(result->functions.size()==2 && result->blocks.size()==3 && block(*result,0x1010).owners.size()==2,"shared non-entry tail has explicit multiple ownership");
    check(function(*result,0x1000).chunks.size()==2 && function(*result,0x1008).chunks.size()==2,"separate numeric gaps do not become function bytes");
    auto tail=image(bytes({0xeb,3,0,0,0,0xc3}));metadata.exports[0].address=Address{{0},0x1005};result=recover_functions(*tail,metadata,{},{},{}).value();
    check(result->functions.size()==2 && std::any_of(result->calls.begin(),result->calls.end(),[](const auto& call){return call.tail_candidate && call.target==Address{{0},0x1005};}),"jump to established entry is an evidenced tail-call candidate");
    check(function(*result,0x1000).thunk && function(*result,0x1000).complete,
          "single-instruction jump wrapper to an established entry is a complete thunk");
    auto wrapper=image(bytes({0x90,0xeb,1,0x90,0xc3}));metadata.exports[0].address=Address{{0},0x1004};
    result=recover_functions(*wrapper,metadata,{},{},{}).value();
    check(!function(*result,0x1000).thunk && std::any_of(result->calls.begin(),result->calls.end(),[](const auto& call){return call.tail_candidate && call.source==Address{{0},0x1001};}),
          "multi-instruction tail transfer remains a candidate rather than a thunk");
    auto conditional=image(bytes({0x74,3,0x90,0x90,0x90,0xc3}));
    metadata.exports[0].address=Address{{0},0x1005};
    result=recover_functions(*conditional,metadata,{},{},{}).value();
    check(std::none_of(result->calls.begin(),result->calls.end(),[](const auto& call){return call.tail_candidate && call.source==Address{{0},0x1000};}),
          "conditional transfer to an established entry is not classified as a tail call");
    metadata.exports[0].address=Address{{0},0x1001};result=recover_functions(*image(bytes({0xb8,0x90,0x90,0x90,0xc3})),metadata,{},{},{}).value();
    check(!result->conflicts.empty() && !result->complete && stopped(*result,FunctionStopReason::overlap),"entry inside instruction is a conflict instead of silent overwrite");
    // A separately defined entry ends at a manual chunk boundary. A speculative
    // call beyond that boundary must not manufacture a trusted callee function.
    auto constrained=bytes({0xeb,3,0,0,0,0x90,0xe8,1,0,0,0,0xc3,0xc3});AnalysisDecisions decision;
    decision.functions.push_back({1,{{0},0x1005},false,{{{{0},0x1005},1}}});
    result=recover_functions(*image(constrained),{},decision,{},{}).value();
    check(std::none_of(result->functions.begin(),result->functions.end(),[](const auto& value){return value->entry.offset==0x100c;}),"unowned speculative call cannot seed a trusted function");
}
void pdb_procedure_root_tests(){
    ImageMetadata metadata;
    metadata.pe.emplace();
    metadata.pe->pdb_status=PePdbStatus::matched;
    metadata.pe->pdb_symbols.push_back({"pdb_worker",true,1,3,2,Address{{0},0x1003},"mod","obj",false,true});
    auto result=recover_functions(*image(bytes({0x90,0x90,0x90,0xc3,0xc3})),metadata,{},{},{}).value();
    check(result->functions.size()==2 && function(*result,0x1003).seeds.size()==1 &&
          function(*result,0x1003).seeds[0].kind==FunctionSeedKind::symbol &&
          function(*result,0x1000).blocks.size()==1,
          "matched PDB procedure symbols establish independent function boundaries");

    metadata.pe->pdb_status=PePdbStatus::mismatch;
    result=recover_functions(*image(bytes({0x90,0x90,0x90,0xc3,0xc3})),metadata,{},{},{}).value();
    check(result->functions.size()==1,"PDB procedure roots are ignored when the PDB identity mismatches");
    metadata.pe->pdb_status=PePdbStatus::matched;
    metadata.pe->pdb_symbols[0].procedure=false;
    result=recover_functions(*image(bytes({0x90,0x90,0x90,0xc3,0xc3})),metadata,{},{},{}).value();
    check(result->functions.size()==1,"matched PDB public data symbols do not establish function boundaries");
}
void decision_tests(){
    AnalysisDecisions decisions;decisions.regions.push_back({1,{{0},0x1000},1,RegionKind::data});
    auto result=recover_functions(*image(bytes({0x90,0xc3})),{},decisions,{},{}).value();check(result->instructions.empty(),"explicit data blocks automatic instruction traversal");
    decisions.regions={{1,{{0},0x1000},2,RegionKind::code}};result=recover_functions(*image(bytes({0x90,0xc3}),false),{},decisions,{},{}).value();
    check(result->instructions.size()==2 && result->functions.size()==1 && result->complete,"explicit code permits initialized non-executable bytes");
    decisions={};decisions.functions.push_back({1,{{0},0x1000},true,{}});result=recover_functions(*image(bytes({0x90,0xc3})),{},decisions,{},{}).value();check(result->functions.empty(),"suppression excludes automatic entry across reanalysis");
    auto data=std::vector<std::byte>(17);data[0]=std::byte{0xeb};data[1]=std::byte{14};data[16]=std::byte{0xc3};decisions.functions={{1,{{0},0x1000},false,{{{{0},0x1000},2},{{{0},0x1010},1}}}};
    result=recover_functions(*image(data),{},decisions,{},{}).value();check(result->functions.size()==1 && function(*result,0x1000).chunks.size()==2 && result->instructions.size()==2,"explicit noncontiguous chunks stay with their declared function");
    decisions={};decisions.regions.push_back({1,{{0},0x1001},1,RegionKind::data});result=recover_functions(*image(bytes({0xb8,1,0,0,0,0xc3})),{},decisions,{},{}).value();
    bool depends_on_boundary=false;for(const auto& dependency:result->dependencies)if(dependency.fact.kind==FactKind::block && std::find(dependency.decisions.begin(),dependency.decisions.end(),1)!=dependency.decisions.end())depends_on_boundary=true;
    check(result->instructions.empty() && stopped(*result,FunctionStopReason::manual_data) && depends_on_boundary,"instruction crossing manual data retains the decision dependency that blocked decoding");
}
void boundary_tests(){
    auto result=recover_functions(*image(bytes({0xc5,0xf8,0x77})),{},{},{},{}).value();check(result->instructions.size()==1 && result->instructions[0]->instruction.opcode==Opcode::x86_opaque && stopped(*result,FunctionStopReason::unsupported) && !result->complete,"opaque decode preserves its known length while stopping analysis without invented semantics");
    result=recover_functions(*image(bytes({0xe8,1})),{},{},{},{}).value();check(result->instructions.empty() && stopped(*result,FunctionStopReason::truncated),"truncated path never invents continuation");
    result=recover_functions(*image(bytes({0x90}),true,2),{},{},{},{}).value();check(result->instructions.size()==1 && stopped(*result,FunctionStopReason::uninitialized),"zero-fill does not become automatic code");
    result=recover_functions(*image(bytes({0xff,0xe0})),{},{},{},{}).value();check(stopped(*result,FunctionStopReason::indirect) && !result->complete,"unresolved indirect jump remains explicit");
    AnalysisOptions options;options.instruction_budget=1;result=recover_functions(*image(bytes({0x90,0x90,0xc3})),{},{},options,{}).value();check(result->instructions.size()==1 && stopped(*result,FunctionStopReason::budget),"bounded analysis reports an incomplete frontier");
    std::stop_source stop;stop.request_stop();auto canceled=recover_functions(*image(bytes({0xc3})),{},{},{},stop.get_token());check(!canceled && canceled.error().code==ErrorCode::canceled,"function recovery observes cancellation");
    options={};options.function_budget=1;ImageMetadata exports;exports.exports.push_back({1,"next",Address{{0},0x1001},{}});
    result=recover_functions(*image(bytes({0x90,0xc3})),exports,{},options,{}).value();
    check(result->omitted_functions==1 && result->instructions.size()==1 && !result->functions[0]->complete,"function budget preserves an omitted established entry as an ownership boundary");
    options={};options.block_budget=0;result=recover_functions(*image(bytes({0x90,0xc3})),{},{},options,{}).value();check(result->blocks.empty() && result->omitted_blocks==1 && !result->complete,"block budget returns an explicit partial result");
    options={};options.membership_budget=0;result=recover_functions(*image(bytes({0x90,0xc3})),{},{},options,{}).value();check(result->instructions.empty() && stopped(*result,FunctionStopReason::budget) && !result->complete,"zero ownership budget stays bounded and explicit");
    auto backing=std::make_shared<MemorySource>(bytes({0x90,0xc3}));std::stop_source during;
    struct CancelOnRead final:ByteStorage {
        std::shared_ptr<const ByteStorage> source;std::stop_source& signal;
        CancelOnRead(std::shared_ptr<const ByteStorage> value,std::stop_source& stop):source(std::move(value)),signal(stop){}
        uint64_t size()const noexcept override{return source->size();}
        Result<ByteView> read_at(FileOffset at,size_t count)const override{signal.request_stop();return source->read_at(at,count);}
    };
    auto interrupted_image=Image::create(std::make_shared<CancelOnRead>(backing,during),image(bytes({0x90,0xc3}))->layout()).value();auto interrupted=recover_functions(*interrupted_image,{},{},{},during.get_token());check(!interrupted && interrupted.error().code==ErrorCode::canceled,"cancellation requested during source reads prevents snapshot publication");
}
void dependency_tests(){
    auto input=image(bytes({0x90,0xc3}));auto result=recover_functions(*input,{},{},{},{}).value();auto again=recover_functions(*input,{},{},{},{}).value();
    check(result->functions[0]->id==again->functions[0]->id && result->blocks[0]->id==again->blocks[0]->id && result->instructions[0]->id==again->instructions[0]->id,"unchanged entry block and instruction identities are deterministic");
    check(result->instructions[0]->reads.ranges().size()==1 && result->instructions[0]->reads.ranges()[0].begin==FileOffset{0} && result->instructions[0]->reads.ranges()[0].size==1,"instruction dependency records consumed bytes without unrelated prefetch");
    auto index=DependencyIndex::create(result->dependencies).value();auto affected=index->affected({0},1).value();
    check(std::find(affected.begin(),affected.end(),FactKey{FactKind::function,result->functions[0]->id.value})!=affected.end(),"byte invalidation reaches dependent blocks and functions");
    check(index->affected({2},1).value().empty() && !index->affected({UINT64_MAX},1),"dependency lookup respects unrelated bytes and overflow");
    std::vector<FactDependency> bad{{{static_cast<FactKind>(99),1},{},{},{}}};check(!DependencyIndex::create(bad),"unknown dependency fact domain is rejected");
    std::stop_source stop;stop.request_stop();check(!DependencyIndex::create(result->dependencies,stop.get_token()) && !index->affected({0},1,stop.get_token()),"dependency indexing and invalidation observe cancellation");
    AnalysisKey key;key.input.size=input->storage()->size();key.input.sha256=hash_source(*input->storage(),{}).value();key.byte_revision=7;key.decision_revision=4;key.engine_fingerprint=function_engine_fingerprint();
    auto keyed=recover_functions(*input,{},{},{},key,{}).value();check(keyed->key==key,"caller source identity and revisions are retained without SQL dependency");
    auto source=std::make_shared<MemorySource>(bytes({0x90,0xc3}));ImageLayout layout{{{0},64,1,ByteOrder::little},Architecture::x86_64,ExecutionMode::x86_64,{{"a",{{0},0x1000},2,{0},2,true,false,true},{"b",{{0},0x2000},2,{0},2,true,false,true}},{{{0},0x1000},{{0},0x2000}}};
    auto aliases=Image::create(source,layout).value();auto alias_facts=recover_functions(*aliases,{},{},{},{}).value();auto alias_index=DependencyIndex::create(alias_facts->dependencies).value();auto closure=alias_index->affected({0},1).value();
    check(std::count_if(closure.begin(),closure.end(),[](auto fact){return fact.kind==FactKind::function;})==2,"one file-byte patch invalidates both virtual-alias function owners");
    key.engine_fingerprint={};check(!recover_functions(*input,{},{},{},key,{}),"mismatched engine/config source key is rejected");
}
void mips_delay_slot_tests(){
    const auto mips = [](std::vector<std::byte> code) {
        return architecture_image(Architecture::mips32, ExecutionMode::mips32, 32, std::move(code));
    };
    auto result = recover_functions(*mips(bytes({0x01,0x00,0x00,0x10, 0x08,0x00,0x08,0x24,
                                                  0x08,0x00,0xe0,0x03, 0x00,0x00,0x00,0x00})),{},{},{},{}).value();
    check(result->instructions.size()==4 && result->instructions[1]->instruction.address.offset==0x1004 &&
              std::any_of(result->blocks.begin(),result->blocks.end(),[](const auto& b){
                  return std::any_of(b->successors.begin(),b->successors.end(),[](const auto& e){return e.kind==BlockEdgeKind::delay_slot;});
              }), "MIPS branch owns and traverses its delay slot before PC+8 successors");
    result = recover_functions(*mips(bytes({0x04,0x04,0x00,0x08, 0x08,0x00,0x08,0x24,
                                             0x08,0x00,0xe0,0x03, 0x00,0x00,0x00,0x00,
                                             0x08,0x00,0xe0,0x03})),{},{},{},{}).value();
    check(std::any_of(result->instructions.begin(),result->instructions.end(),[](const auto& f){return f->instruction.address.offset==0x1004;}) &&
              std::none_of(result->instructions.begin(),result->instructions.end(),[](const auto& f){return f->instruction.address.offset==0x1008;}),
          "MIPS direct jump executes its slot without inventing PC+8 fallthrough");
    result = recover_functions(*mips(bytes({0x03,0x04,0x00,0x0c, 0x08,0x00,0x08,0x24,
                                             0x08,0x00,0xe0,0x03, 0x00,0x00,0x00,0x00,
                                             0x08,0x00,0xe0,0x03,0x00,0x00,0x00,0x00})),{},{},{},{}).value();
    if (!(result->calls.size()==1 && result->calls[0].target==Address{{0},0x100c})) { std::cerr << "MIPS recovered calls=" << result->calls.size(); for(const auto &call:result->calls) if(call.target) std::cerr << ' ' << std::hex << call.target->offset; std::cerr << " functions=" << result->functions.size() << " instructions=" << result->instructions.size() << '\n'; }
    check(result->calls.size()==1 && result->calls[0].target==Address{{0},0x100c} &&
              std::any_of(result->instructions.begin(),result->instructions.end(),[](const auto& f){return f->instruction.address.offset==0x1004;}) &&
              std::any_of(result->instructions.begin(),result->instructions.end(),[](const auto& f){return f->instruction.address.offset==0x1008;}),
          "MIPS direct call owns its slot and recovers callee plus post-slot continuation");
    result = recover_functions(*mips(bytes({0x08,0x00,0xe0,0x03, 0x08,0x00,0x08,0x24})),{},{},{},{}).value();
    check(result->instructions.size()==2 && stopped(*result,FunctionStopReason::ret),
          "MIPS return executes its slot before terminating");
    result = recover_functions(*mips(bytes({0x02,0x10,0x00,0x08, 0x08,0x00,0xe0,0x03})),{},{},{},{}).value();
    check(stopped(*result,FunctionStopReason::unsupported), "MIPS control transfer in a delay slot is rejected explicitly");
    result = recover_functions(*mips(bytes({0x02,0x10,0x00,0x08, 0xff,0xff,0xff,0xff})),{},{},{},{}).value();
    check(stopped(*result,FunctionStopReason::invalid), "Malformed MIPS delay slot stops recovery explicitly");
    result = recover_functions(*mips(bytes({0x02,0x10,0x00,0x08})),{},{},{},{}).value();
    if (!(stopped(*result,FunctionStopReason::truncated) || stopped(*result,FunctionStopReason::uninitialized))) { std::cerr << "MIPS missing slot functions=" << result->functions.size() << " complete=" << result->complete; for(const auto &f:result->functions) { std::cerr << " stops"; for(const auto &s:f->stops) std::cerr << ' ' << std::hex << s.address.offset << ':' << static_cast<int>(s.reason); } std::cerr << '\n'; }
    check(stopped(*result,FunctionStopReason::truncated) || stopped(*result,FunctionStopReason::uninitialized) ||
              stopped(*result,FunctionStopReason::unmapped),
          "MIPS missing delay slot stops without inventing a target path");
    AnalysisDecisions data_slot; data_slot.regions.push_back({1,{{0},0x1004},4,RegionKind::data});
    result = recover_functions(*mips(bytes({0x02,0x10,0x00,0x08,0x08,0x00,0x08,0x24,
                                              0x08,0x00,0xe0,0x03,0x00,0x00,0x00,0x00})),{},data_slot,{},{ }).value();
    check(stopped(*result,FunctionStopReason::manual_data), "MIPS delay slot respects manual code/data boundaries");
}
void architecture_recovery_tests(){
    const auto verify_call=[](Architecture architecture,ExecutionMode mode,std::uint8_t width,
                              std::vector<std::byte> fixture,std::uint64_t target,const char* name){
        const auto result=recover_functions(*architecture_image(architecture,mode,width,std::move(fixture)),{},{},{},{}).value();
        check(result->functions.size()==2 && result->calls.size()==1 &&
              result->calls[0].target==Address{{0},target} && result->calls[0].callee.has_value() &&
              function(*result,0x1000).entry==Address{{0},0x1000} && function(*result,target).complete &&
              result->complete,name);
    };
    const auto verify_branch=[](Architecture architecture,ExecutionMode mode,std::uint8_t width,
                                std::vector<std::byte> fixture,const char* name){
        const auto result=recover_functions(*architecture_image(architecture,mode,width,std::move(fixture)),{},{},{},{}).value();
        check(result->functions.size()==1 && result->instructions.size()==3 && result->blocks.size()==3 &&
              result->complete && function(*result,0x1000).complete,name);
    };
    verify_call(Architecture::arm64,ExecutionMode::a64,64,
        bytes({0x02,0x00,0x00,0x94,0xc0,0x03,0x5f,0xd6,0xc0,0x03,0x5f,0xd6}),0x1008,
        "A64 direct BL creates a callee and preserves its return boundary");
    verify_call(Architecture::riscv32,ExecutionMode::rv32,32,
        bytes({0xef,0x00,0x80,0x00,0x67,0x80,0x00,0x00,0x67,0x80,0x00,0x00}),0x1008,
        "RV32 direct JAL creates a callee and preserves its return boundary");
    verify_call(Architecture::riscv64,ExecutionMode::rv64,64,
        bytes({0xef,0x00,0x80,0x00,0x67,0x80,0x00,0x00,0x67,0x80,0x00,0x00}),0x1008,
        "RV64 direct JAL creates a callee and preserves its return boundary");
    for (const auto [architecture, mode, width] :
         {std::tuple{Architecture::riscv32, ExecutionMode::rv32, std::uint8_t{32}},
          std::tuple{Architecture::riscv64, ExecutionMode::rv64, std::uint8_t{64}}}) {
        verify_call(architecture, mode, width,
            bytes({0x97,0x02,0x00,0x00, 0x93,0x82,0x02,0x01, 0xe7,0x80,0x02,0x00,
                   0x67,0x80,0x00,0x00, 0x67,0x80,0x00,0x00}),0x1010,
            width==32 ? "RV32 function recovery recognizes an AUIPC/ADDI/JALR callee"
                      : "RV64 function recovery recognizes an AUIPC/ADDI/JALR callee");
    }
    auto rv64c=recover_functions(*architecture_image(Architecture::riscv64,ExecutionMode::rv64c,64,
        bytes({0x01,0x00,0x82,0x80})),{},{},{},{}).value();
    check(rv64c->functions.size()==1 && rv64c->instructions.size()==2 && rv64c->complete &&
          function(*rv64c,0x1000).stops.front().reason==FunctionStopReason::ret,
          "RV64C compressed fallthrough and return preserve variable-length ownership");
    verify_call(Architecture::mos6502,ExecutionMode::m6502,16,
        bytes({0x20,0x05,0x10,0x60,0xea,0x60}),0x1005,
        "6502 direct JSR creates a callee and preserves its return boundary");
    verify_branch(Architecture::arm64,ExecutionMode::a64,64,
        bytes({0x40,0x00,0x00,0x34,0xc0,0x03,0x5f,0xd6,0xc0,0x03,0x5f,0xd6}),
        "A64 compare branch retains target and fallthrough ownership");
    verify_branch(Architecture::riscv32,ExecutionMode::rv32,32,
        bytes({0x63,0x04,0x00,0x00,0x67,0x80,0x00,0x00,0x67,0x80,0x00,0x00}),
        "RV32 conditional branch retains target and fallthrough ownership");
    verify_branch(Architecture::riscv64,ExecutionMode::rv64,64,
        bytes({0x63,0x04,0x00,0x00,0x67,0x80,0x00,0x00,0x67,0x80,0x00,0x00}),
        "RV64 conditional branch retains target and fallthrough ownership");
    verify_branch(Architecture::mos6502,ExecutionMode::m6502,16,
        bytes({0xd0,0x03,0x60,0xea,0xea,0x60}),
        "6502 conditional branch retains target and fallthrough ownership");

    auto a32=architecture_image(Architecture::arm,ExecutionMode::a32,32,
        bytes({0x1e,0xff,0x2f,0x11, 0x1e,0xff,0x2f,0xe1}));
    auto recovered=recover_functions(*a32,{},{},{},{});
    check(recovered && recovered.value()->instructions.size()==2 && recovered.value()->blocks.size()==2 &&
          std::any_of(recovered.value()->blocks.begin(),recovered.value()->blocks.end(),[](const auto& b){
              return b->begin.offset==0x1000 && b->successors.size()==1 &&
                     b->successors[0].kind==BlockEdgeKind::conditional_false &&
                     b->successors[0].target==Address{{0},0x1004};}),
          "conditional A32 return retains its guarded exit and sequential continuation");
    auto conditional_trap=architecture_image(Architecture::arm,ExecutionMode::a32,32,
        bytes({0x23,0x01,0x00,0x1f, 0x1e,0xff,0x2f,0xe1}));
    auto trap_recovered=recover_functions(*conditional_trap,{},{},{},{});
    check(trap_recovered && trap_recovered.value()->instructions.size()==2 &&
          std::any_of(trap_recovered.value()->blocks.begin(),trap_recovered.value()->blocks.end(),[](const auto& b){
              return b->begin.offset==0x1000 && b->successors.size()==1 &&
                     b->successors[0].kind==BlockEdgeKind::conditional_false &&
                     b->successors[0].target==Address{{0},0x1004};}) &&
          std::any_of(function(*trap_recovered.value(),0x1000).stops.begin(),
                      function(*trap_recovered.value(),0x1000).stops.end(),[](const auto& stop){
              return stop.address.offset==0x1000 && stop.reason==FunctionStopReason::trap;}),
          "conditional A32 SVC retains its trap and condition-false CFG successor");
    auto thumb=architecture_image(Architecture::arm,ExecutionMode::thumb,32,bytes({0x00,0xbf,0x70,0x47}));
    auto rejected=recover_functions(*thumb,{},{},{},{});
    check(rejected && rejected.value()->functions.empty() && !rejected.value()->candidates.empty() &&
          rejected.value()->candidates[0].reason==FunctionStopReason::unsupported,
          "Thumb recovery rejects a root without source-backed known-clear IT state");
    auto source=std::make_shared<MemorySource>(bytes({0x08,0xbf,0x01,0x20,0x70,0x47}));
    const Address thumb_entry{{0},0x1000};
    const ArmContextSource raw{ArmContextSourceKind::raw_declaration,1,1,{}};
    ImageLayout thumb_layout{{{0},32,1,ByteOrder::little},Architecture::arm,ExecutionMode::unknown,
        {{"thumb-code",thumb_entry,source->size(),{0},source->size(),true,false,true}},{thumb_entry}};
    thumb_layout.arm_profile=ArmImageProfile{
        {{thumb_entry,source->size(),ArmCodeKind::thumb,{raw}}},
        {{thumb_entry,ExecutionMode::thumb,true,{raw}}}};
    auto thumb_result=recover_functions(*Image::create(source,std::move(thumb_layout)).value(),{},{},{},{});
    check(thumb_result && thumb_result.value()->functions.size()==1 && thumb_result.value()->complete &&
          thumb_result.value()->instructions.size()==3 &&
          thumb_result.value()->instructions[1]->instruction.arm->predicate==ArmPredicate::condition &&
          thumb_result.value()->instructions[1]->instruction.arm->it_before==ThumbITState{true,0x08},
          "Thumb function discovery propagates a source-backed IT block to its guarded body and return");

    // A direct branch reaches 0x1004 with ITSTATE clear, while the fallthrough
    // path enters an IT block at 0x1002 and reaches 0x1004 with ITSTATE active.
    auto join_source=std::make_shared<MemorySource>(bytes({0x00,0xd0,0x08,0xbf,0x01,0x20,0x70,0x47}));
    const Address join_entry{{0},0x1000};
    ImageLayout join_layout{{{0},32,1,ByteOrder::little},Architecture::arm,ExecutionMode::unknown,
        {{"thumb-join",join_entry,join_source->size(),{0},join_source->size(),true,false,true}},{join_entry}};
    join_layout.arm_profile=ArmImageProfile{
        {{join_entry,join_source->size(),ArmCodeKind::thumb,{raw}}},
        {{join_entry,ExecutionMode::thumb,true,{raw}}}};
    auto joined=recover_functions(*Image::create(join_source,std::move(join_layout)).value(),{},{},{},{});
    check(joined && !joined.value()->complete && joined.value()->instructions.size()==2 &&
          std::any_of(function(*joined.value(),0x1000).stops.begin(),function(*joined.value(),0x1000).stops.end(),
              [](const auto& stop){return stop.address.offset==0x1004 && stop.reason==FunctionStopReason::unsupported &&
                  stop.detail.find("existing clear")!=std::string::npos &&
                  stop.detail.find("incoming mask 8")!=std::string::npos;}),
          "Thumb CFG join reports both ITSTATE paths, drops the ambiguous instruction, and stops trusted ownership");

    auto mode_source=std::make_shared<MemorySource>(bytes({0x00,0x00,0xa0,0xe1,0x70,0x47}));
    const Address a32_entry{{0},0x1000}, thumb_root{{0},0x1004};
    ImageLayout mode_layout{{{0},32,1,ByteOrder::little},Architecture::arm,ExecutionMode::unknown,
        {{"arm-modes",a32_entry,mode_source->size(),{0},mode_source->size(),true,false,true}},{a32_entry,thumb_root}};
    mode_layout.arm_profile=ArmImageProfile{
        {{a32_entry,4,ArmCodeKind::a32,{raw}},{thumb_root,2,ArmCodeKind::thumb,{raw}}},
        {{a32_entry,ExecutionMode::a32,false,{raw}},{thumb_root,ExecutionMode::thumb,true,{raw}}}};
    auto modes=recover_functions(*Image::create(mode_source,std::move(mode_layout)).value(),{},{},{},{});
    check(modes && modes.value()->functions.size()==2 && function(*modes.value(),0x1000).blocks.size()==1 &&
          function(*modes.value(),0x1004).blocks.size()==1 &&
          function(*modes.value(),0x1000).blocks.front()!=function(*modes.value(),0x1004).blocks.front() &&
          std::any_of(function(*modes.value(),0x1000).stops.begin(),function(*modes.value(),0x1000).stops.end(),
              [](const auto& stop){return stop.address.offset==0x1000 && stop.reason==FunctionStopReason::unsupported;}),
          "A32 sequential ownership stops at an adjacent Thumb region while the Thumb root remains separate");
}
int main(){return run([]{partition_tests();ownership_tests();pdb_procedure_root_tests();decision_tests();boundary_tests();mips_delay_slot_tests();dependency_tests();architecture_recovery_tests();});}
