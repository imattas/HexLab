#include "project_internal.hpp"
namespace hexlab::project_detail {
bool mapped_location(const ProjectSnapshot& snapshot,Location value){
    if(auto file=std::get_if<FileOffset>(&value))return snapshot.effective && file->value<snapshot.effective->size();
    return snapshot.loaded && snapshot.loaded->image && snapshot.loaded->image->segment_at(std::get<Address>(value));
}
void check_location(const ProjectSnapshot& s,Location location,bool allow_orphan){
    bool retained=allow_orphan && std::any_of(s.state->user->annotations.begin(),s.state->user->annotations.end(),[&](auto& row){return row.location==location;});
    require(mapped_location(s,location) || retained,"Location is outside the current input mapping");
}
void check_boundary(const ProjectSnapshot& s,Address address){
    require(s.loaded && s.loaded->image,"Command requires a valid image mapping");
    require(s.status==DerivedStatus::fresh || s.status==DerivedStatus::incomplete,"Command requires current instruction boundaries; reanalyze first");
    if(s.functions)for(auto& fact:s.functions->instructions){const auto& i=fact->instruction;if(i.address.space==address.space && i.address.offset<address.offset)require(address.offset-i.address.offset>=i.length,"Location cuts an existing instruction");}
}
Instruction decision_instruction(const ProjectSnapshot& s,Address address){
    check_boundary(s,address);const auto& image=*s.loaded->image;
    const auto context=take(image.context_at(address));
    require(processor_capabilities(context).can_decode,"Code decisions require a supported processor mode",ErrorCode::unsupported);
    std::array<std::byte,15> input{};size_t count=0;auto cursor=address;
    while(count<input.size()){
        auto segment=image.segment_at(cursor);if(!segment)break;auto offset=cursor.offset-segment->begin.offset;if(offset>=segment->file_size)break;
        auto amount=static_cast<size_t>(std::min<uint64_t>(input.size()-count,segment->file_size-offset));auto data=take(image.read(cursor,amount));std::copy(data.begin(),data.end(),input.begin()+count);count+=amount;if(count==input.size())break;auto next=advance(cursor,amount);if(!next)break;cursor=next.value();
    }
    auto decoded=decode_instruction(context,std::span(input).first(count),address);require(decoded.status==DecodeStatus::decoded && decoded.instruction.has_value(),"Decision entry cannot be decoded with the current processor");return std::move(*decoded.instruction);
}
void check_range(const ProjectSnapshot& s,Address begin,uint64_t size,bool boundaries){
    require(size>0,"Decision range must contain bytes");auto end=take(advance(begin,size));require(s.loaded && s.loaded->image,"Command requires a valid image mapping");auto& image=*s.loaded->image;
    auto cursor=begin;while(cursor.offset<end.offset){auto segment=image.segment_at(cursor);require(segment!=nullptr,"Decision range crosses a mapping gap");auto offset=cursor.offset-segment->begin.offset;require(offset<segment->file_size,"Decision range includes uninitialized bytes");auto amount=std::min(end.offset-cursor.offset,segment->file_size-offset);cursor=take(advance(cursor,amount));}
    if(boundaries){check_boundary(s,begin);check_boundary(s,end);}
}
}
