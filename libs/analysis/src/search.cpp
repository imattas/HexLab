#include "search_internal.hpp"
#include <set>
#include <tuple>
namespace hexlab {
namespace {
using namespace search_detail;
struct Mapping {std::uint64_t begin,end;Address address;};
std::vector<Mapping> mappings(const Image* image,std::stop_token stop){
    std::vector<Mapping> result;if(!image)return result;const auto& segments=image->layout().segments;require(segments.size()<=1000000,"Too many mapping segments",ErrorCode::resource_limit);struct Event{uint64_t at;std::size_t segment;bool begin;};std::vector<Event> events;events.reserve(segments.size()*2);
    for(std::size_t n=0;n<segments.size();++n){canceled(stop);auto& s=segments[n];if(s.file_size){events.push_back({s.file_begin.value,n,true});events.push_back({s.file_begin.value+s.file_size,n,false});}}
    std::sort(events.begin(),events.end(),[](auto a,auto b){return a.at<b.at;});std::set<std::size_t> active;uint64_t previous=0;
    for(std::size_t n=0;n<events.size();){canceled(stop);auto at=events[n].at;if(at>previous && active.size()==1){auto& s=segments[*active.begin()];Address address{s.begin.space,s.begin.offset+(previous-s.file_begin.value)};if(!result.empty() && result.back().end==previous && result.back().address.space==address.space && result.back().address.offset+(previous-result.back().begin)==address.offset)result.back().end=at;else result.push_back({previous,at,address});}while(n<events.size() && events[n].at==at){auto& event=events[n++];if(event.begin)active.insert(event.segment);else active.erase(event.segment);}previous=at;}
    return result;
}
std::optional<Address> mapped(const std::vector<Mapping>& ranges,uint64_t offset,uint64_t size){auto found=std::upper_bound(ranges.begin(),ranges.end(),offset,[](auto at,auto& range){return at<range.begin;});if(found==ranges.begin())return {};--found;if(offset<found->end && size<=found->end-offset)return Address{found->address.space,found->address.offset+(offset-found->begin)};return {};}
struct Reader {
    const ByteStorage& source;ByteView view;uint64_t start=0;
    std::byte byte(uint64_t at){if(!view.owner || at<start || at-start>=view.bytes.size()){start=(at/65536)*65536;auto count=std::size_t(std::min<uint64_t>(65536,source.size()-start));view=take(source.read_at({start},count));require(view.bytes.size()==count,"Storage returned a short search read",ErrorCode::io);}return view.bytes[std::size_t(at-start)];}
};
void scan_bytes(const SearchSource& source,const Compiled& query,SearchCursor& cursor,const SearchLimits& limits,const std::vector<Mapping>& maps,SearchPage& page,std::stop_token stop){
    require(cursor.next_instruction==0 && cursor.next_operand==0,"Byte search cursor has operand state");require(cursor.next_offset<=source.effective->size(),"Search cursor exceeds source");require(limits.max_comparisons>=query.pattern.size(),"Comparison budget is smaller than one candidate");auto size=source.effective->size();auto end=std::min(limits.end_offset.value_or(size),size);auto length=uint64_t(query.pattern.size());require(cursor.next_offset<=end,"Search start offset exceeds exclusive end offset");Reader reader{*source.effective};
    while(cursor.next_offset<=end && length<=end-cursor.next_offset){canceled(stop);if(page.matches.size()==limits.max_results || page.examined_candidates==limits.max_candidates || limits.max_comparisons-page.comparisons<length)break;auto offset=cursor.next_offset++;++page.examined_candidates;bool match=true;for(std::size_t n=0;n<query.pattern.size();++n){if((n&255)==0)canceled(stop);++page.comparisons;const auto octet=query.pattern[n];if(octet.mask!=std::byte{} && (reader.byte(offset+n)&octet.mask)!=octet.value){match=false;break;}}if(match)page.matches.push_back({{offset},length,mapped(maps,offset,length),{},{{{offset},length}}});}
    page.complete=cursor.next_offset>end || length>end-cursor.next_offset;if(!page.complete){page.next=cursor;page.reason="Page or work budget reached";}
}
void scan_immediates(const SearchSource& source,const Compiled& query,SearchCursor& cursor,const SearchLimits& limits,const std::vector<Mapping>& maps,SearchPage& page,std::stop_token stop){
    require(source.image && source.functions,"Immediate search requires decoded function facts",ErrorCode::unsupported);require(source.functions->key==source.key,"Immediate facts belong to another revision",ErrorCode::conflict);require(cursor.next_offset==0,"Immediate cursor has byte search state");require(source.functions->instructions.size()<=1000000,"Too many instructions to index",ErrorCode::resource_limit);
    struct Entry{FileOffset file;const Instruction* instruction;};std::vector<Entry> entries;entries.reserve(source.functions->instructions.size());for(auto& fact:source.functions->instructions){canceled(stop);require(bool(fact),"Null search instruction",ErrorCode::integrity);auto& instruction=fact->instruction;auto file=source.image->to_file_offset(instruction.address);if(file && instruction.byte_length())entries.push_back({file.value(),&instruction});}
    std::sort(entries.begin(),entries.end(),[](auto& a,auto& b){return std::tie(a.file.value,a.instruction->address.space.value,a.instruction->address.offset)<std::tie(b.file.value,b.instruction->address.space.value,b.instruction->address.offset);});const auto end_offset=std::min(limits.end_offset.value_or(source.effective->size()),source.effective->size());const auto range_end=static_cast<std::uint64_t>(std::lower_bound(entries.begin(),entries.end(),end_offset,[](const Entry& entry,std::uint64_t offset){return entry.file.value<offset;})-entries.begin());require(cursor.next_instruction<=entries.size(),"Immediate cursor exceeds instruction index");if(cursor.next_instruction>=range_end)require(cursor.next_operand==0,"Immediate cursor exceeds final instruction");
    if (limits.start_offset && !cursor.next_instruction) {
        const auto start = limits.start_address
                               ? std::lower_bound(entries.begin(), entries.end(),
                                                  std::tuple{*limits.start_offset, limits.start_address->space.value,
                                                             limits.start_address->offset},
                                                  [](const Entry &entry, const auto &target) {
                                                      return std::tuple{entry.file.value,
                                                                        entry.instruction->address.space.value,
                                                                        entry.instruction->address.offset} < target;
                                                  })
                               : std::lower_bound(entries.begin(), entries.end(), *limits.start_offset,
                                                  [](const Entry &entry, std::uint64_t offset) {
                                                      return entry.file.value < offset;
                                                  });
        cursor.next_instruction = std::min<std::uint64_t>(static_cast<std::uint64_t>(start - entries.begin()), range_end);
    }
    auto mask=query.immediate->width==64?UINT64_MAX:(uint64_t{1}<<query.immediate->width)-1;
    while(cursor.next_instruction<range_end){canceled(stop);auto& entry=entries[std::size_t(cursor.next_instruction)];auto& operands=entry.instruction->operands;require(operands.size()<=256 && cursor.next_operand<=operands.size(),"Invalid immediate operand cursor");if(cursor.next_operand==operands.size()){++cursor.next_instruction;cursor.next_operand=0;continue;}if(page.matches.size()==limits.max_results || page.examined_candidates==limits.max_candidates)break;auto n=cursor.next_operand++;++page.examined_candidates;if(auto operand=std::get_if<ImmediateOperand>(&operands[n]);operand && operand->effective_width==query.immediate->width && (operand->value&mask)==query.bits){
        SearchMatch hit{entry.file,entry.instruction->byte_length(),{},n,{},entry.instruction->address};for(uint64_t byte=0;byte<hit.size;++byte){auto at=take(advance(entry.instruction->address,byte));auto file=take(source.image->to_file_offset(at));if(!hit.file_ranges.empty() && hit.file_ranges.back().begin.value+hit.file_ranges.back().size==file.value)++hit.file_ranges.back().size;else hit.file_ranges.push_back({file,1});}if(hit.file_ranges.size()==1){auto address=mapped(maps,entry.file.value,hit.size);if(address==entry.instruction->address)hit.address=address;}page.matches.push_back(std::move(hit));
    }}
    page.complete=cursor.next_instruction>=range_end;page.source_complete=source.functions->complete;if(!page.complete){page.next=cursor;page.reason="Page or work budget reached";}if(!page.source_complete){if(!page.reason.empty())page.reason+="; ";page.reason+="Results cover the available partial decoded instruction set";}
}
}
Result<SearchPage> search(const SearchSource& source,const SearchQuery& query,std::optional<SearchCursor> start,const SearchLimits& limits,std::stop_token stop){return search_detail::guarded([&]()->Result<SearchPage>{
    canceled(stop);require(source.effective && source.effective->size()==source.key.input.size,"Search source extent does not match its identity");require(!source.image || source.image->storage()==source.effective,"Search mapping uses another byte source");require(limits.max_results && limits.max_results<=4096 && limits.max_candidates && limits.max_candidates<=16777216 && limits.max_comparisons && limits.max_comparisons<=67108864,"Search limits exceed supported bounds");const auto end=std::min(limits.end_offset.value_or(source.effective->size()),source.effective->size());if(limits.start_offset)require(*limits.start_offset<=end,"Search start offset exceeds exclusive end offset");auto compiled=compile(query);SearchCursor cursor{source.key,compiled.fingerprint};cursor.end_offset=end;auto page_limits=limits;if(start){require(start->source_key==source.key && start->query_fingerprint==compiled.fingerprint && start->end_offset==end,"Search continuation belongs to another source, query, or range",ErrorCode::conflict);cursor=*start;page_limits.start_offset.reset();page_limits.start_address.reset();}else if(limits.start_offset){require(*limits.start_offset<=source.effective->size(),"Search start offset exceeds source",ErrorCode::out_of_bounds);cursor.next_offset=*limits.start_offset;}SearchPage page;page.source_key=source.key;page.query_fingerprint=compiled.fingerprint;page.start=start;auto maps=mappings(source.image.get(),stop);if(compiled.immediate){cursor.next_offset=0;scan_immediates(source,compiled,cursor,page_limits,maps,page,stop);}else scan_bytes(source,compiled,cursor,page_limits,maps,page,stop);canceled(stop);return page;
});}
}
