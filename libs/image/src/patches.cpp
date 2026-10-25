#include "hexlab/image/patches.hpp"
#include <algorithm>
#include <map>

namespace hexlab {
namespace {
std::uint64_t end(const PatchSpan& span){return span.begin.value+span.replacement.size();}
PatchSpan slice(const PatchSpan& span,std::uint64_t begin,std::uint64_t finish){
    const auto offset=static_cast<std::size_t>(begin-span.begin.value),count=static_cast<std::size_t>(finish-begin);
    const auto original=std::span(span.original).subspan(offset,count),replacement=std::span(span.replacement).subspan(offset,count);
    return {{begin},{original.begin(),original.end()},{replacement.begin(),replacement.end()}};
}
void replace_interval(std::map<std::uint64_t,PatchSpan>& pieces,const PatchSpan& patch){
    const auto begin=patch.begin.value,finish=end(patch);if(begin==finish)return;
    auto it=pieces.lower_bound(begin);if(it!=pieces.begin() && end(std::prev(it)->second)>begin)--it;
    std::vector<PatchSpan> retained;
    while(it!=pieces.end() && it->first<finish){
        const auto& old=it->second;
        if(old.begin.value<begin)retained.push_back(slice(old,old.begin.value,begin));
        if(end(old)>finish)retained.push_back(slice(old,finish,end(old)));
        it=pieces.erase(it);
    }
    for(auto& piece:retained){const auto at=piece.begin.value;pieces.emplace(at,std::move(piece));}
    std::size_t cursor=0;
    while(cursor<patch.replacement.size()){
        while(cursor<patch.replacement.size() && patch.original[cursor]==patch.replacement[cursor])++cursor;
        const auto first=cursor;
        while(cursor<patch.replacement.size() && patch.original[cursor]!=patch.replacement[cursor])++cursor;
        if(first!=cursor){auto piece=slice(patch,begin+first,begin+cursor);pieces.emplace(piece.begin.value,std::move(piece));}
    }
}
std::vector<PatchSpan> normalize(const std::map<std::uint64_t,PatchSpan>& pieces){
    constexpr std::size_t chunk_size=1024*1024;std::vector<PatchSpan> result;
    for(const auto& [begin,piece]:pieces){
        std::size_t offset=0;
        while(offset<piece.replacement.size()){
            const auto at=begin+offset;
            if(result.empty() || end(result.back())!=at || result.back().replacement.size()==chunk_size)result.push_back({{at},{},{}});
            auto& current=result.back();const auto amount=std::min(chunk_size-current.replacement.size(),piece.replacement.size()-offset);
            const auto original=std::span(piece.original).subspan(offset,amount),replacement=std::span(piece.replacement).subspan(offset,amount);
            current.original.insert(current.original.end(),original.begin(),original.end());current.replacement.insert(current.replacement.end(),replacement.begin(),replacement.end());offset+=amount;
        }
    }
    return result;
}
class OverlayStorage final:public ByteStorage {
public:
    OverlayStorage(std::shared_ptr<const ByteStorage> original,std::shared_ptr<const PatchSet> patches):original_(std::move(original)),patches_(std::move(patches)){}
    std::uint64_t size() const noexcept override{return original_->size();}
    Result<ByteView> read_at(FileOffset at,std::size_t count) const override {
        if(at.value>size() || count>size()-at.value)return Error{ErrorCode::out_of_bounds,"Overlay read is outside input"};
        auto input=original_->read_at(at,count);if(!input)return input.error();
        if(input.value().bytes.size()!=count)return Error{ErrorCode::io,"Original source returned an incomplete overlay read"};
        if(!count)return input.value();
        const auto finish=at.value+count;const auto spans=patches_->spans();
        auto first=std::lower_bound(spans.begin(),spans.end(),at.value,[](const auto& span,auto begin){return end(span)<=begin;});
        if(first==spans.end() || first->begin.value>=finish)return input.value();
        try {
            auto output=std::make_shared<std::vector<std::byte>>(input.value().bytes.begin(),input.value().bytes.end());
            for(auto it=first;it!=spans.end() && it->begin.value<finish;++it){
                const auto begin=std::max(at.value,it->begin.value),limit=std::min(finish,end(*it));
                const auto bytes=std::span(it->replacement).subspan(static_cast<std::size_t>(begin-it->begin.value),static_cast<std::size_t>(limit-begin));
                std::copy(bytes.begin(),bytes.end(),output->begin()+static_cast<std::ptrdiff_t>(begin-at.value));
            }
            return ByteView{output,*output};
        }catch(const std::bad_alloc&){return Error{ErrorCode::resource_limit,"Cannot allocate overlay view"};}
         catch(const std::length_error&){return Error{ErrorCode::resource_limit,"Overlay view is too large"};}
    }
private:
    std::shared_ptr<const ByteStorage> original_;
    std::shared_ptr<const PatchSet> patches_;
};
}
Result<std::shared_ptr<const PatchSet>> PatchSet::create(const ByteStorage& source,std::span<const PatchSpan> patches){
    try {
        std::map<std::uint64_t,PatchSpan> pieces;
        for(const auto& patch:patches){
            if(patch.original.size()!=patch.replacement.size())return Error{ErrorCode::invalid_argument,"Patch changes input length"};
            const auto extent=checked_add(patch.begin.value,patch.original.size());if(!extent)return extent.error();
            if(extent.value()>source.size())return Error{ErrorCode::out_of_bounds,"Patch is outside input"};
            auto expected=source.read_at(patch.begin,patch.original.size());if(!expected)return expected.error();
            if(expected.value().bytes.size()!=patch.original.size() || !std::equal(patch.original.begin(),patch.original.end(),expected.value().bytes.begin()))return Error{ErrorCode::invalid_argument,"Patch original bytes do not match input"};
            replace_interval(pieces,patch);
        }
        return std::shared_ptr<const PatchSet>(new PatchSet(normalize(pieces)));
    }catch(const std::bad_alloc&){return Error{ErrorCode::resource_limit,"Cannot allocate patch set"};}
     catch(const std::length_error&){return Error{ErrorCode::resource_limit,"Patch set is too large"};}
}
Result<std::shared_ptr<const ByteStorage>> make_overlay(std::shared_ptr<const ByteStorage> original,std::span<const PatchSpan> spans){
    if(!original)return Error{ErrorCode::invalid_argument,"Overlay requires original storage"};
    auto patches=PatchSet::create(*original,spans);if(!patches)return patches.error();
    try{return std::shared_ptr<const ByteStorage>(std::make_shared<OverlayStorage>(std::move(original),std::move(patches.value())));}
    catch(const std::bad_alloc&){return Error{ErrorCode::resource_limit,"Cannot allocate overlay storage"};}
}
}
