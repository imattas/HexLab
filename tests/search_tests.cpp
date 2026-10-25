#include "hexlab/workspace/search.hpp"
#include "support/checks.hpp"
#include "support/analysis_fixture.hpp"
#include "support/fixture_files.hpp"
#include "hexlab/image/patches.hpp"
#include "hexlab/workspace/project_actor.hpp"
#include <random>
using namespace hexlab;using namespace hexlab_test;
namespace {
template<class T>T take(Result<T> result){if(!result)throw std::runtime_error(result.error().message);return std::move(result.value());}
SearchSource source(std::shared_ptr<const Image> image){SearchSource s;s.effective=image->storage();s.image=std::move(image);s.key.input={s.effective->size(),take(hash_source(*s.effective,{}))};s.key.engine_fingerprint=function_engine_fingerprint(AnalysisOptions{});return s;}
void bytes_tests(){
    auto s=source(memory_image(bytes({0xaa,0xaa,0xaa,0xab,0xaa})));
    SearchQuery q=BytePattern{"AA AA"};SearchLimits limits;limits.max_results=1;
    auto first=take(search(s,q,{},limits,{}));check(first.matches.size()==1 && first.matches[0].offset.value==0 && first.matches[0].address==Address{{0},0x1000} && first.next.has_value(),"first byte page retains canonical offset and mapping");
    auto second=take(search(s,q,first.next,limits,{}));check(second.matches.size()==1 && second.matches[0].offset.value==1,"continuation retains overlapping match");
    auto last=take(search(s,q,second.next,limits,{}));check(last.complete && last.matches.empty(),"last byte page terminates without duplicates");
    auto changed=s;changed.key.byte_revision++;check(!search(changed,q,first.next,limits,{}),"continuation rejects changed byte revision");check(!search(s,BytePattern{"AA AB"},first.next,limits,{}),"continuation rejects another query");
    for(auto pattern:{"","A","GG","0xAA","AA,BB"})check(!search(s,BytePattern{pattern},{},{},{}),"malformed octet pattern rejected");
    SearchLimits bounded;bounded.max_candidates=2;auto wildcard=take(search(s,BytePattern{"??"},{},bounded,{}));check(wildcard.matches.size()==2 && wildcard.next && !wildcard.complete && wildcard.examined_candidates==2,"all wildcard query honors finite work budget");
    std::stop_source stop;stop.request_stop();auto canceled=search(s,q,{},{},stop.get_token());check(!canceled && canceled.error().code==ErrorCode::canceled,"search cancellation is explicit");
    std::vector<std::byte> large(65540,std::byte{0});large[65535]=std::byte{0xde};large[65536]=std::byte{0xad};auto chunk=source(memory_image(large));auto crossing=take(search(chunk,BytePattern{"DE AD"},{},{},{}));check(crossing.matches.size()==1 && crossing.matches[0].offset.value==65535,"streaming matcher crosses 64 KiB read boundary");
}
void text_tests(){
    auto s=source(memory_image(bytes({0x41,0xc3,0xa9,0xf0,0x9f,0x98,0x80,0x41,0,0xe9,0,0x3d,0xd8,0,0xde})));
    auto utf8=take(search(s,TextQuery{"\xc3\xa9\xf0\x9f\x98\x80",TextEncoding::utf8},{},{},{}));check(utf8.matches.size()==1 && utf8.matches[0].offset.value==1 && utf8.matches[0].size==6,"UTF8 text preserves literal multibyte sequence");
    auto utf16=take(search(s,TextQuery{"A\xc3\xa9\xf0\x9f\x98\x80",TextEncoding::utf16le},{},{},{}));check(utf16.matches.size()==1 && utf16.matches[0].offset.value==7 && utf16.matches[0].size==8,"UTF16LE text encodes supplementary scalar as surrogate pair");
    for(auto invalid:{std::string("\xc0\xaf"),std::string("\xed\xa0\x80"),std::string("\xf4\x90\x80\x80"),std::string("\xc3")})check(!search(s,TextQuery{invalid,TextEncoding::utf8},{},{},{}),"invalid Unicode sequence rejected");check(!search(s,TextQuery{"\xc3\xa9",TextEncoding::ascii},{},{},{}),"ASCII query rejects nonASCII");
}
void mapping_tests(){
    auto original=std::make_shared<MemoryStorage>(bytes({0xaa,0xbb,0xcc,0xdd}));ImageLayout layout{{{0},64,1,ByteOrder::little},Architecture::x86_64,ExecutionMode::x86_64,{{"a",{{0},0x1000},2,{0},2,true,false,true},{"b",{{0},0x1002},2,{2},2,true,false,true}}, {}};
    auto contiguous=source(take(Image::create(original,layout)));check(take(search(contiguous,BytePattern{"BB CC"},{},{},{})).matches[0].address==Address{{0},0x1001},"match may map across adjacent contiguous segments");
    layout.segments[1].begin.offset=0x2000;auto gap=source(take(Image::create(original,layout)));check(!take(search(gap,BytePattern{"BB CC"},{},{},{})).matches[0].address,"virtual gap does not fabricate contiguous address");
    layout.segments.push_back({"alias",{{0},0x3000},1,{1},1,true,false,true});auto alias=source(take(Image::create(original,layout)));check(!take(search(alias,BytePattern{"BB"},{},{},{})).matches[0].address,"file aliases have canonical offsets without invented unique address");
}
void immediate_tests(){
    auto s=source(memory_image(bytes({0x48,0xc7,0xc0,0xff,0xff,0xff,0xff,0xb0,0xff,0xc3})));ImageMetadata metadata;auto facts=take(recover_functions(*s.image,metadata,{}, {},s.key,{}));s.functions=facts;
    auto wide=take(search(s,ImmediateQuery{"-1",64,ImmediateInterpretation::signed_value},{},{},{}));check(wide.matches.size()==1 && wide.matches[0].offset.value==0 && wide.matches[0].operand_index==std::uint32_t{1},"signed minus one uses effective64 width");
    auto narrow=take(search(s,ImmediateQuery{"0xFF",8,ImmediateInterpretation::unsigned_value},{},{},{}));check(narrow.matches.size()==1 && narrow.matches[0].offset.value==7,"FF width8 differs from signextended width64");
    check(take(search(s,ImmediateQuery{"18446744073709551615",64,ImmediateInterpretation::unsigned_value},{},{},{})).matches.size()==1,"unsigned full64 bit pattern matches signed operand bits");
    for(auto query:{ImmediateQuery{"256",8,ImmediateInterpretation::unsigned_value},ImmediateQuery{"128",8,ImmediateInterpretation::signed_value},ImmediateQuery{"-129",8,ImmediateInterpretation::signed_value},ImmediateQuery{"-1",8,ImmediateInterpretation::unsigned_value},ImmediateQuery{"1",7,ImmediateInterpretation::signed_value},ImmediateQuery{"18446744073709551616",64,ImmediateInterpretation::unsigned_value}})check(!search(s,query,{},{},{}),"out of range immediate input rejected");auto stale=s;stale.key.decision_revision++;check(!search(stale,ImmediateQuery{"1",8,ImmediateInterpretation::unsigned_value},{},{},{}),"immediate search refuses stale facts");
}
void state_tests(){
    auto s=source(memory_image(bytes({1,1,1})));SearchHistory first,second;auto page=std::make_shared<const SearchPage>(take(search(s,BytePattern{"01"},{},{},{})));take(first.begin(s.key,BytePattern{"01"}));take(first.append(page));check(first.next()->offset.value==0 && first.next()->offset.value==1 && first.previous()->offset.value==0,"per-document next and previous retain actual hit locations");check(!second.next(),"another document has independent search selection");auto changed=s.key;changed.byte_revision++;take(first.begin(changed,BytePattern{"01"}));check(!first.next(),"new revision clears old result selection");
}
void oracle_tests(){
    std::mt19937 random(0x51627);std::vector<std::byte> data(3073);for(auto& b:data)b=std::byte(random()%4);auto s=source(memory_image(data));
    for(auto pattern:{"00 01 00","?? 02","03 ?? 01","?? ??","00 00 00 00","01"}){
        // Independent literal oracle: no search compiler, cursor or scanner helpers.
        std::vector<int> mask;std::string_view text=pattern;for(std::size_t at=0;at<text.size();at+=3)mask.push_back(text[at]=='?'?-1:(text[at]-'0')*16+(text[at+1]-'0'));
        std::vector<std::uint64_t> expected,actual;for(std::size_t at=0;at+mask.size()<=data.size();++at){bool match=true;for(std::size_t n=0;n<mask.size();++n)if(mask[n]>=0 && int(std::to_integer<unsigned>(data[at+n]))!=mask[n])match=false;if(match)expected.push_back(at);}
        SearchLimits limits;limits.max_results=7;limits.max_candidates=23;limits.max_comparisons=47;std::optional<SearchCursor> cursor;std::size_t pages=0;do{auto page=take(search(s,BytePattern{pattern},cursor,limits,{}));for(auto& hit:page.matches)actual.push_back(hit.offset.value);check(page.examined_candidates<=23 && page.comparisons<=47 && page.matches.size()<=7,"each page respects independent count and comparison budgets");cursor=page.next;if(++pages>4000)throw std::runtime_error("Search continuation did not progress");}while(cursor);check(actual==expected,"paged masked search agrees with independent literal whole-input oracle");
    }
    auto q=BytePattern{"00"};auto page=take(search(s,q,{},SearchLimits{1,1,1},{}));auto invalid=*page.next;invalid.next_offset=s.effective->size()+1;check(!search(s,q,invalid,{},{}),"forged offset beyond source is rejected");
}
void failure_tests(){
    struct ShortStorage:ByteStorage {uint64_t size()const noexcept override{return 4;}Result<ByteView> read_at(FileOffset,std::size_t)const override{static auto data=std::make_shared<const std::vector<std::byte>>(bytes({1}));return ByteView{data,*data};}};SearchSource short_source;short_source.effective=std::make_shared<ShortStorage>();short_source.key.input.size=4;auto short_read=search(short_source,BytePattern{"01"},{},{},{});check(!short_read && short_read.error().code==ErrorCode::io,"successful short storage read returns a typed IO failure");
    auto empty=std::make_shared<MemoryStorage>(std::vector<std::byte>{});SearchSource s;s.effective=empty;check(take(search(s,BytePattern{"00"},{},{},{})).complete,"empty input produces complete empty page");check(!search(s,BytePattern{"00"},{},SearchLimits{0,1,1},{}),"zero page size is rejected");
    auto image=memory_image(bytes({0xb0,0xff,0xb0,0xff,0xc3}));auto partial=source(image);AnalysisOptions options;options.instruction_budget=1;partial.key.engine_fingerprint=function_engine_fingerprint(options);partial.functions=take(recover_functions(*image,{},{},options,partial.key,{}));auto page=take(search(partial,ImmediateQuery{"255",8,ImmediateInterpretation::unsigned_value},{},{},{}));check(page.complete && !page.source_complete && page.matches.size()==1 && !page.reason.empty(),"finished search over partial decoded facts retains incomplete-source label");
}
void split_instruction_tests(){
    auto storage=std::make_shared<MemoryStorage>(bytes({0xb0,0x90,0x90,0xff,0xc3}));ImageLayout layout{{{0},64,1,ByteOrder::little},Architecture::x86_64,ExecutionMode::x86_64,{{"start",{{0},0x1000},1,{0},1,true,false,true},{"rest",{{0},0x1001},2,{3},2,true,false,true}},{{{0},0x1000}}};auto image=take(Image::create(storage,layout));auto s=source(image);s.functions=take(recover_functions(*image,{},{},{},s.key,{}));auto page=take(search(s,ImmediateQuery{"255",8,ImmediateInterpretation::unsigned_value},{},{},{}));check(page.matches.size()==1 && page.matches[0].file_ranges.size()==2 && page.matches[0].file_ranges[1].begin.value==3 && !page.matches[0].address,"split instruction keeps actual file spans without fabricated contiguous mapping");
}
void project_tests(){
    using namespace hexlab::database;FixtureFile marker(std::span<const std::byte>{});auto path=marker.path.wstring()+L".search.hxproj";struct Cleanup{std::filesystem::path path;~Cleanup(){std::error_code ignored;for(auto suffix:{L"",L"-wal",L"-shm"}){auto file=path;file+=suffix;std::filesystem::remove(file,ignored);}}} cleanup{path};
    auto store=take(ProjectStore::create(path,{}));MemoryStorage input(bytes({0x48,0xc7,0xc0,0xff,0xff,0xff,0xff,0xb0,0xff,0xc3}));take(store->import_input(input,{Format::raw,RawOptions{Architecture::x86_64,ExecutionMode::x86_64,{{0},0x1000},true,true,true,{}}},{},{}));auto session=take(ProjectSession::attach(store,{},{}));SearchQuery q=BytePattern{"FF"};auto before=take(search(*session->snapshot(),q,{},SearchLimits{1,100,100},{}));take(session->execute(PatchBytes{FileOffset{8},bytes({0x7f})},0,{}));auto patched=take(search(*session->snapshot(),BytePattern{"7F"},{},{},{}));check(patched.matches.size()==1 && patched.matches[0].offset.value==8,"project search reads effective overlay bytes");check(!search(*session->snapshot(),q,before.next,{},{}),"patch rejects previous project continuation");check(!search(*session->snapshot(),ImmediateQuery{"127",8,ImmediateInterpretation::unsigned_value},{},{},{}),"pending project analysis refuses stale immediate facts");take(session->refresh_analysis({}));check(take(search(*session->snapshot(),ImmediateQuery{"127",8,ImmediateInterpretation::unsigned_value},{},{},{})).matches.size()==1,"immediate search observes patched operand after current analysis");
    auto page=std::make_shared<const SearchPage>(take(search(*session->snapshot(),q,{},{},{})));SearchHistory history;take(history.begin(page->source_key,q));take(history.append(page));check(!history.append(page),"history refuses duplicate complete page");take(session->undo({}));check(!history.append(std::make_shared<const SearchPage>(take(search(*session->snapshot(),q,{},{},{})))),"history refuses a page from undo revision");
}
}
int main(){return run([]{bytes_tests();text_tests();mapping_tests();immediate_tests();state_tests();oracle_tests();failure_tests();split_instruction_tests();project_tests();});}

