#include "hexlab/analysis/dependencies.hpp"
#include <algorithm>
#include <deque>
#include <set>
#include <tuple>
namespace hexlab {
Result<std::shared_ptr<const DependencyIndex>> DependencyIndex::create(std::span<const FactDependency> facts,std::stop_token stop){
    if(stop.stop_requested())return Error{ErrorCode::canceled,"Dependency indexing canceled"};
    try{
        auto index=std::shared_ptr<DependencyIndex>(new DependencyIndex);std::set<FactKey> keys;
        for(const auto& fact:facts){if(stop.stop_requested())return Error{ErrorCode::canceled,"Dependency indexing canceled"};if(static_cast<unsigned>(fact.fact.kind)>static_cast<unsigned>(FactKind::seed) || fact.fact.id==0 || !keys.insert(fact.fact).second)return Error{ErrorCode::invalid_argument,"Invalid or duplicate dependency fact key"};}
        index->facts_.reserve(facts.size());for(const auto& fact:facts){if(stop.stop_requested())return Error{ErrorCode::canceled,"Dependency indexing canceled"};index->facts_.push_back(fact);}
        for(auto& fact:index->facts_){
            if(stop.stop_requested())return Error{ErrorCode::canceled,"Dependency indexing canceled"};
            std::sort(fact.prerequisites.begin(),fact.prerequisites.end());fact.prerequisites.erase(std::unique(fact.prerequisites.begin(),fact.prerequisites.end()),fact.prerequisites.end());
            for(auto key:fact.prerequisites){if(stop.stop_requested())return Error{ErrorCode::canceled,"Dependency indexing canceled"};if(!keys.contains(key))return Error{ErrorCode::invalid_argument,"Dependency references an unknown fact"};index->dependents_[key].push_back(fact.fact);}
            for(auto range:fact.reads.ranges()){
                if(stop.stop_requested())return Error{ErrorCode::canceled,"Dependency indexing canceled"};
                auto end=checked_add(range.begin.value,range.size);if(!end)return end.error();
                if(range.size)index->read_intervals_.push_back({range.begin.value,end.value(),fact.fact});
            }
        }
        std::sort(index->read_intervals_.begin(),index->read_intervals_.end(),[](const auto& a,const auto& b){return std::tie(a.begin,a.end,a.fact)<std::tie(b.begin,b.end,b.fact);});
        index->prefix_max_end_.reserve(index->read_intervals_.size());
        std::uint64_t maximum=0;
        for(std::size_t i=0;i<index->read_intervals_.size();++i){
            if(stop.stop_requested())return Error{ErrorCode::canceled,"Dependency indexing canceled"};
            maximum=std::max(maximum,index->read_intervals_[i].end);index->prefix_max_end_.push_back(maximum);
        }
        return std::shared_ptr<const DependencyIndex>(std::move(index));
    }catch(const std::bad_alloc&){return Error{ErrorCode::resource_limit,"Cannot allocate dependency index"};}
     catch(const std::length_error&){return Error{ErrorCode::resource_limit,"Dependency index exceeds host limits"};}
}
Result<std::vector<FactKey>> DependencyIndex::affected(FileOffset begin,uint64_t size,std::stop_token stop)const{
    ReadSet ranges;auto added=ranges.include(begin,size);if(!added)return added.error();return affected(ranges,stop);
}
Result<std::vector<FactKey>> DependencyIndex::affected(const ReadSet& ranges,std::stop_token stop)const{
    if(stop.stop_requested())return Error{ErrorCode::canceled,"Dependency invalidation canceled"};
    try{
        std::set<FactKey> visited;std::deque<FactKey> pending;
        for(auto changed:ranges.ranges()){
            if(stop.stop_requested())return Error{ErrorCode::canceled,"Dependency invalidation canceled"};
            auto changed_end=checked_add(changed.begin.value,changed.size);if(!changed_end)return changed_end.error();
            if(!changed.size)continue;
            // The first prefix maximum beyond the changed range's start is
            // the earliest interval that can overlap it, including an
            // interval whose start precedes the dirty bytes.
            auto first=std::upper_bound(prefix_max_end_.begin(),prefix_max_end_.end(),changed.begin.value);
            auto index=static_cast<std::size_t>(first-prefix_max_end_.begin());
            while(index<read_intervals_.size() && read_intervals_[index].begin<changed_end.value()){
                if(stop.stop_requested())return Error{ErrorCode::canceled,"Dependency invalidation canceled"};
                const auto& interval=read_intervals_[index++];
                if(interval.end>changed.begin.value && visited.insert(interval.fact).second)pending.push_back(interval.fact);
            }
        }
        while(!pending.empty()){if(stop.stop_requested())return Error{ErrorCode::canceled,"Dependency invalidation canceled"};const auto key=pending.front();pending.pop_front();auto found=dependents_.find(key);if(found==dependents_.end())continue;for(auto dependent:found->second){if(stop.stop_requested())return Error{ErrorCode::canceled,"Dependency invalidation canceled"};if(visited.insert(dependent).second)pending.push_back(dependent);}}
        return std::vector<FactKey>{visited.begin(),visited.end()};
    }catch(const std::bad_alloc&){return Error{ErrorCode::resource_limit,"Cannot allocate dependency closure"};}
}
}
