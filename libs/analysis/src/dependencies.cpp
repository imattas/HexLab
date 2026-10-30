#include "hexlab/analysis/dependencies.hpp"
#include <algorithm>
#include <deque>
#include <functional>
#include <set>
#include <tuple>
namespace hexlab {
namespace {
struct IndexCanceled {};
template <class Iterator, class Compare>
void cancellable_sort(Iterator begin, Iterator end, Compare compare, std::stop_token stop) {
    std::sort(begin, end, [&](const auto &left, const auto &right) {
        if (stop.stop_requested())
            throw IndexCanceled{};
        return compare(left, right);
    });
}
Result<std::vector<FactKey>> materialize(const std::set<FactKey> &facts, std::stop_token stop,
                                         const char *message) {
    std::vector<FactKey> result;
    result.reserve(facts.size());
    for (const auto fact : facts) {
        if (stop.stop_requested())
            return Error{ErrorCode::canceled, message};
        result.push_back(fact);
    }
    return result;
}
}
Result<std::shared_ptr<const DependencyIndex>> DependencyIndex::create(std::span<const FactDependency> facts,std::stop_token stop){
    if(stop.stop_requested())return Error{ErrorCode::canceled,"Dependency indexing canceled"};
    try{
        auto index=std::shared_ptr<DependencyIndex>(new DependencyIndex);std::set<FactKey> keys;
        for(const auto& fact:facts){if(stop.stop_requested())return Error{ErrorCode::canceled,"Dependency indexing canceled"};if(static_cast<unsigned>(fact.fact.kind)>static_cast<unsigned>(FactKind::seed) || fact.fact.id==0 || !keys.insert(fact.fact).second)return Error{ErrorCode::invalid_argument,"Invalid or duplicate dependency fact key"};}
        // Build the lookup structures directly from the caller-owned immutable
        // dependency snapshot. Retaining a second copy of every ReadSet and
        // edge vector duplicated potentially large allocations and made each
        // per-fact copy non-cancelable.
        for(const auto& fact:facts){
            if(stop.stop_requested())return Error{ErrorCode::canceled,"Dependency indexing canceled"};
            std::vector<FactKey> prerequisites;
            prerequisites.reserve(fact.prerequisites.size());
            for (const auto key : fact.prerequisites) {
                if (stop.stop_requested()) return Error{ErrorCode::canceled,"Dependency indexing canceled"};
                prerequisites.push_back(key);
            }
            cancellable_sort(prerequisites.begin(),prerequisites.end(),std::less<FactKey>{},stop);
            prerequisites.erase(std::unique(prerequisites.begin(),prerequisites.end()),prerequisites.end());
            for(auto key:prerequisites){if(stop.stop_requested())return Error{ErrorCode::canceled,"Dependency indexing canceled"};if(!keys.contains(key))return Error{ErrorCode::invalid_argument,"Dependency references an unknown fact"};index->dependents_[key].push_back(fact.fact);}
            std::vector<std::uint64_t> decisions;
            decisions.reserve(fact.decisions.size());
            for (const auto id : fact.decisions) {
                if (stop.stop_requested()) return Error{ErrorCode::canceled,"Dependency indexing canceled"};
                decisions.push_back(id);
            }
            cancellable_sort(decisions.begin(),decisions.end(),std::less<std::uint64_t>{},stop);
            decisions.erase(std::unique(decisions.begin(),decisions.end()),decisions.end());
            for(auto id:decisions){
                if(stop.stop_requested())return Error{ErrorCode::canceled,"Dependency indexing canceled"};
                if(!id)return Error{ErrorCode::invalid_argument,"Dependency references a zero decision identity"};
                index->decision_facts_[id].push_back(fact.fact);
            }
            for(auto range:fact.reads.ranges()){
                if(stop.stop_requested())return Error{ErrorCode::canceled,"Dependency indexing canceled"};
                auto end=checked_add(range.begin.value,range.size);if(!end)return end.error();
                if(range.size)index->read_intervals_.push_back({range.begin.value,end.value(),fact.fact});
            }
        }
        cancellable_sort(index->read_intervals_.begin(),index->read_intervals_.end(),[](const auto& a,const auto& b){return std::tie(a.begin,a.end,a.fact)<std::tie(b.begin,b.end,b.fact);},stop);
        index->prefix_max_end_.reserve(index->read_intervals_.size());
        std::uint64_t maximum=0;
        for(std::size_t i=0;i<index->read_intervals_.size();++i){
            if(stop.stop_requested())return Error{ErrorCode::canceled,"Dependency indexing canceled"};
            maximum=std::max(maximum,index->read_intervals_[i].end);index->prefix_max_end_.push_back(maximum);
        }
        if(stop.stop_requested())return Error{ErrorCode::canceled,"Dependency indexing canceled"};
        return std::shared_ptr<const DependencyIndex>(std::move(index));
    }catch(const IndexCanceled&){return Error{ErrorCode::canceled,"Dependency indexing canceled"};
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
        return materialize(visited,stop,"Dependency invalidation canceled");
    }catch(const std::bad_alloc&){return Error{ErrorCode::resource_limit,"Cannot allocate dependency closure"};}
}
Result<std::vector<FactKey>> DependencyIndex::affected_decisions(
    std::span<const std::uint64_t> decisions,std::stop_token stop)const{
    if(stop.stop_requested())return Error{ErrorCode::canceled,"Decision invalidation canceled"};
    try{
        std::set<FactKey> visited;std::deque<FactKey> pending;
        for(auto id:decisions){
            if(stop.stop_requested())return Error{ErrorCode::canceled,"Decision invalidation canceled"};
            if(!id)return Error{ErrorCode::invalid_argument,"Zero decision identity cannot be invalidated"};
            auto found=decision_facts_.find(id);
            if(found==decision_facts_.end())continue;
            for(auto fact:found->second){
                if(stop.stop_requested())return Error{ErrorCode::canceled,"Decision invalidation canceled"};
                if(visited.insert(fact).second)pending.push_back(fact);
            }
        }
        while(!pending.empty()){
            if(stop.stop_requested())return Error{ErrorCode::canceled,"Decision invalidation canceled"};
            const auto key=pending.front();pending.pop_front();
            auto found=dependents_.find(key);if(found==dependents_.end())continue;
            for(auto dependent:found->second){
                if(stop.stop_requested())return Error{ErrorCode::canceled,"Decision invalidation canceled"};
                if(visited.insert(dependent).second)pending.push_back(dependent);
            }
        }
        return materialize(visited,stop,"Decision invalidation canceled");
    }catch(const std::bad_alloc&){return Error{ErrorCode::resource_limit,"Cannot allocate decision invalidation closure"};}
}
}
