#include "hexlab/image/read_set.hpp"
#include <algorithm>
#include <mutex>
namespace hexlab {
Result<bool> ReadSet::include(FileOffset at,std::uint64_t size){
    auto extent=checked_add(at.value,size);if(!extent)return extent.error();if(!size)return true;
    try {
        auto first=std::lower_bound(ranges_.begin(),ranges_.end(),at.value,[](const auto& range,auto begin){return range.begin.value+range.size<begin;});
        auto finish=first;auto begin=at.value,end=extent.value();
        while(finish!=ranges_.end() && finish->begin.value<=end){begin=std::min(begin,finish->begin.value);end=std::max(end,finish->begin.value+finish->size);++finish;}
        const auto position=static_cast<std::size_t>(first-ranges_.begin());
        // Reserve before modifying so allocation failure preserves the old set.
        if(first==finish){ranges_.insert(first,{{begin},end-begin});}
        else {ranges_[position]={{begin},end-begin};ranges_.erase(ranges_.begin()+static_cast<std::ptrdiff_t>(position+1),finish);}
        return true;
    }catch(const std::bad_alloc&){return Error{ErrorCode::resource_limit,"Cannot allocate read dependencies"};}
     catch(const std::length_error&){return Error{ErrorCode::resource_limit,"Read dependencies exceed host limits"};}
}
Result<bool> ReadSet::intersects(FileOffset at,std::uint64_t size) const {
    auto extent=checked_add(at.value,size);if(!extent)return extent.error();if(!size)return false;
    auto found=std::lower_bound(ranges_.begin(),ranges_.end(),at.value,[](const auto& range,auto begin){return range.begin.value+range.size<=begin;});
    return found!=ranges_.end() && found->begin.value<extent.value();
}
struct TrackingStorage::Impl {std::shared_ptr<const ByteStorage> source;mutable std::mutex mutex;ReadSet reads;explicit Impl(std::shared_ptr<const ByteStorage> input):source(std::move(input)){};};
TrackingStorage::TrackingStorage(std::unique_ptr<Impl> impl):impl_(std::move(impl)){}
TrackingStorage::~TrackingStorage()=default;
Result<std::shared_ptr<TrackingStorage>> TrackingStorage::create(std::shared_ptr<const ByteStorage> source){
    if(!source)return Error{ErrorCode::invalid_argument,"Read tracking requires a source"};
    try{return std::shared_ptr<TrackingStorage>(new TrackingStorage(std::make_unique<Impl>(std::move(source))));}
    catch(const std::bad_alloc&){return Error{ErrorCode::resource_limit,"Cannot allocate read tracking"};}
}
std::uint64_t TrackingStorage::size() const noexcept{return impl_->source->size();}
Result<ByteView> TrackingStorage::read_at(FileOffset at,std::size_t count) const {
    auto view=impl_->source->read_at(at,count);if(!view)return view.error();
    if(view.value().bytes.size()!=count)return Error{ErrorCode::io,"Source returned incomplete tracked read"};
    std::lock_guard lock(impl_->mutex);auto recorded=impl_->reads.include(at,count);if(!recorded)return recorded.error();return view.value();
}
ReadSet TrackingStorage::reads() const{std::lock_guard lock(impl_->mutex);return impl_->reads;}
}
