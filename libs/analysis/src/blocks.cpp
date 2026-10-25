#include "functions_internal.hpp"
#include <algorithm>
namespace hexlab::function_detail {
void build_blocks(Recovery& recovery){
    AddressSet leaders;AddressMap<size_t> predecessors;
    for(const auto& [entry,function]:recovery.functions)if(recovery.owners.contains(entry))leaders.insert(entry);
    for(const auto& [at,owners]:recovery.owners){
        recovery.canceled();const auto& node=recovery.nodes.at(at);
        if(!node.fact || recovery.ambiguous.contains(at)){leaders.insert(at);continue;}
        for(const auto& edge:node.edges)if(edge.target && recovery.owners.contains(*edge.target)){
            ++predecessors[*edge.target];
            const auto linear_end=advance(at,node.fact->instruction.length);
            if(edge.kind!=BlockEdgeKind::fallthrough || !linear_end || *edge.target!=linear_end.value() || recovery.owners.at(*edge.target)!=owners)leaders.insert(*edge.target);
        }
    }
    for(const auto& [at,owners]:recovery.owners)if(predecessors[at]!=1)leaders.insert(at);
    std::map<FunctionId,std::shared_ptr<FunctionRecord>> functions;for(const auto& [entry,function]:recovery.functions)functions.emplace(function->id,function);
    std::set<FunctionId> budgeted;
    for(auto begin:leaders){
        recovery.canceled();if(recovery.node_blocks.contains(begin))continue;
        if(recovery.blocks.size()>=recovery.options.block_budget){
            ++recovery.output->omitted_blocks;
            for(auto owner:recovery.owners.at(begin))if(budgeted.insert(owner).second){auto& function=*functions.at(owner);function.complete=false;function.stops.push_back({begin,FunctionStopReason::budget,"Basic-block budget reached"});}
            continue;
        }
        auto block=std::make_shared<BasicBlock>();block->id={recovery.ids.make(FactKind::block,begin)};block->begin=begin;block->owners=recovery.owners.at(begin);auto current=begin;
        for(;;){
            recovery.canceled();recovery.node_blocks.emplace(current,block->id);const auto& node=recovery.nodes.at(current);
            if(recovery.ambiguous.contains(current)){block->stop=FunctionStop{current,FunctionStopReason::overlap,"Conflicting decode streams"};break;}
            if(!node.fact){block->stop=node.stop;break;}
            block->instructions.push_back(node.fact);if(node.stop)block->stop=node.stop;else if(node.call_issue)block->stop=node.call_issue;
            bool linear=false;
            if(node.edges.size()==1){const auto& edge=node.edges[0];auto next=advance(current,node.fact->instruction.length);
                linear=edge.kind==BlockEdgeKind::fallthrough && edge.target && next && *edge.target==next.value() && recovery.owners.contains(*edge.target) && recovery.owners.at(*edge.target)==block->owners && !leaders.contains(*edge.target) && !recovery.node_blocks.contains(*edge.target);
            }
            if(linear){current=*node.edges[0].target;continue;}
            for(const auto& edge:node.edges)block->successors.push_back({current,edge.target,{},edge.kind});break;
        }
        recovery.blocks.push_back(std::move(block));
    }
    AddressMap<std::shared_ptr<const InstructionFact>> instructions;
    for(auto& block:recovery.blocks){
        for(auto& edge:block->successors)if(edge.target){auto target=recovery.node_blocks.find(*edge.target);if(target!=recovery.node_blocks.end())edge.block=target->second;}
        for(const auto& fact:block->instructions)instructions.emplace(fact->instruction.address,fact);
        recovery.output->blocks.push_back(block);
    }
    for(auto& [address,fact]:instructions)recovery.output->instructions.push_back(std::move(fact));
}
void finish_functions(Recovery& recovery){
    std::map<BlockId,std::shared_ptr<BasicBlock>> blocks;for(auto& block:recovery.blocks)blocks.emplace(block->id,block);
    for(auto& [entry,function]:recovery.functions){
        recovery.canceled();std::set<BlockId> seen;
        for(const auto& at:recovery.function_nodes[function->id]){
            auto found=recovery.node_blocks.find(at);if(found==recovery.node_blocks.end())continue;
            if(seen.insert(found->second).second)function->blocks.push_back(found->second);
            const auto& node=recovery.nodes.at(at);if(!node.fact || recovery.ambiguous.contains(at))continue;
            const auto length=node.fact->instruction.length;
            if(function->chunks.empty() || function->chunks.back().begin.space!=at.space || function->chunks.back().begin.offset+function->chunks.back().size!=at.offset)function->chunks.push_back({at,length,{found->second}});
            else {auto& chunk=function->chunks.back();chunk.size+=length;if(chunk.blocks.empty() || chunk.blocks.back()!=found->second)chunk.blocks.push_back(found->second);}
        }
        std::sort(function->stops.begin(),function->stops.end(),[](const auto& a,const auto& b){return std::tie(a.address.space.value,a.address.offset,a.reason,a.detail)<std::tie(b.address.space.value,b.address.offset,b.reason,b.detail);});
        recovery.output->functions.push_back(function);
    }
}
void build_dependencies(Recovery& recovery){
    std::map<FactKey,FactDependency> facts;AddressMap<std::shared_ptr<const InstructionFact>> instructions;
    for(const auto& instruction:recovery.output->instructions){
        recovery.canceled();instructions.emplace(instruction->instruction.address,instruction);
        facts.emplace(FactKey{FactKind::instruction,instruction->id},FactDependency{{FactKind::instruction,instruction->id},instruction->reads,{},recovery.nodes.at(instruction->instruction.address).decisions});
    }
    for(const auto& block:recovery.blocks){
        FactDependency dependency{{FactKind::block,block->id.value},{},{},{}};
        for(const auto& instruction:block->instructions)dependency.prerequisites.push_back({FactKind::instruction,instruction->id});
        if(block->instructions.empty()){
            const auto& node=recovery.nodes.at(block->begin);dependency.reads=node.window;dependency.decisions=node.decisions;
        }
        facts.emplace(dependency.fact,std::move(dependency));
    }
    for(const auto& [entry,function]:recovery.functions){
        recovery.canceled();FactDependency dependency{{FactKind::function,function->id.value},{},{},{}};
        if(auto definition=recovery.definitions.find(entry);definition!=recovery.definitions.end())dependency.decisions.push_back(definition->second->id);
        for(auto block:function->blocks)dependency.prerequisites.push_back({FactKind::block,block.value});
        for(const auto& seed:function->seeds){
            std::vector<std::byte> extra{std::byte(static_cast<unsigned>(seed.kind)),std::byte(seed.source?1:0)};
            if(seed.source)for(auto value:{uint64_t(seed.source->space.value),seed.source->offset}){const auto encoded=encode_u64(value);extra.insert(extra.end(),encoded.begin(),encoded.end());}
            const auto decision=encode_u64(seed.decision.value_or(0));extra.insert(extra.end(),decision.begin(),decision.end());
            FactDependency seed_dependency{{FactKind::seed,recovery.ids.make(FactKind::seed,seed.entry,extra)},{},{},{}};
            if(seed.decision)seed_dependency.decisions.push_back(*seed.decision);
            if(seed.source){auto source=instructions.find(*seed.source);if(source!=instructions.end())seed_dependency.prerequisites.push_back({FactKind::instruction,source->second->id});}
            dependency.prerequisites.push_back(seed_dependency.fact);facts.emplace(seed_dependency.fact,std::move(seed_dependency));
        }
        facts.emplace(dependency.fact,std::move(dependency));
    }
    // Validate against the existing fact table without constructing a duplicate
    // full dependency index during recovery; consumers build their index once.
    for(const auto& [key,fact]:facts){recovery.canceled();for(auto prerequisite:fact.prerequisites)require(facts.contains(prerequisite),"Dependency references an unpublished fact");}
    for(auto& [key,fact]:facts){recovery.canceled();recovery.output->dependencies.push_back(std::move(fact));}
}
}
