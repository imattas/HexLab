#include "hexlab/analysis/incremental.hpp"
#include "hexlab/analysis/graph.hpp"
#include "hexlab/image/patches.hpp"
#include "support/checks.hpp"
#include "support/fixture_files.hpp"
#include "support/analysis_fixture.hpp"
#include <algorithm>
using namespace hexlab;using namespace hexlab_test;
namespace {
class CancelOnReadStorage final : public ByteStorage {
    std::shared_ptr<const ByteStorage> source_;
    std::shared_ptr<std::stop_source> stop_;
public:
    CancelOnReadStorage(std::shared_ptr<const ByteStorage> source,std::shared_ptr<std::stop_source> stop)
        :source_(std::move(source)),stop_(std::move(stop)){}
    std::uint64_t size()const noexcept override{return source_->size();}
    Result<ByteView> read_at(FileOffset at,std::size_t count)const override{
        auto bytes=source_->read_at(at,count);
        stop_->request_stop();
        return bytes;
    }
};
AnalysisBasis basis(std::vector<std::byte> data,ImageMetadata metadata={}){
    AnalysisBasis value;value.image=memory_image(std::move(data));value.metadata=std::make_shared<const ImageMetadata>(std::move(metadata));value.metadata_reads_complete=true;value.key.input={value.image->storage()->size(),hash_source(*value.image->storage(),{}).value()};value.key.engine_fingerprint=function_engine_fingerprint(value.options);
    value.functions=recover_functions(*value.image,*value.metadata,value.decisions,value.options,value.key,{}).value();value.references=derive_references(*value.functions,*value.metadata,value.decisions,{}).value();value.strings=std::make_shared<const StringScan>(find_strings(*value.image,value.options,{}).value());return value;
}
std::shared_ptr<const Image> patch(const AnalysisBasis& old,uint64_t offset,std::vector<std::byte> data){auto original=old.image->storage()->read_at({offset},data.size()).value();PatchSpan row{{offset},{original.bytes.begin(),original.bytes.end()},std::move(data)};auto source=make_overlay(old.image->storage(),std::span(&row,1)).value();return Image::create(std::move(source),old.image->layout()).value();}
const FunctionRecord* function(const FunctionSnapshot& snapshot,uint64_t entry){for(auto& row:snapshot.functions)if(row->entry.offset==entry)return row.get();return nullptr;}
void reuse_tests(){
    auto data=bytes({0x74,3,0x90,0xeb,1,0x90,0xc3});data.resize(18,std::byte{0});data[16]=std::byte{0x90};data[17]=std::byte{0xc3};ImageMetadata metadata;metadata.exports.push_back({1,"unrelated",Address{{0},0x1010},{}});auto old=basis(data,metadata);const auto* unaffected=function(*old.functions,0x1010);check(unaffected!=nullptr,"independent exported function exists before patch");
    auto image=patch(old,1,bytes({4}));auto key=old.key;++key.byte_revision;FileRange changed{{1},1};auto plan=plan_invalidation(old,std::span(&changed,1),old.decisions,key,{}).value();check(!plan.metadata_invalid && plan.full_reason.empty() && !plan.functions.empty(),"local branch patch invalidates dependent function without full fallback");
    auto proposal=reanalyze(old,image,old.metadata,old.decisions,plan,key,{}).value();check(proposal.source_key==key && proposal.functions->key==key && proposal.references->key()==key,"incremental results carry exact source key");check(proposal.counters.reused_instructions>=2 && proposal.counters.decoded_instructions<old.functions->instructions.size(),"ordinary local patch actually skips unaffected decode work");check(proposal.counters.validated_reuse_instructions>=2,"unverified dirty ranges retain defensive per-instruction byte validation");check(function(*proposal.functions,0x1010)==unaffected && proposal.counters.reused_functions>=1,"unrelated immutable function pointer and ID survive patch");
    auto verified_plan=plan_invalidation(old,std::span(&changed,1),old.decisions,key,{},false,true).value();
    auto verified=reanalyze(old,image,old.metadata,old.decisions,verified_plan,key,{}).value();
    check(verified_plan.byte_ranges_verified && verified.counters.validated_reuse_instructions==0 &&
              verified.counters.reused_instructions>=2 && verified.functions->instructions.size()==proposal.functions->instructions.size(),
          "complete effective-byte diff proof skips per-instruction source revalidation while retaining local reuse");
    auto outgoing=proposal.references->outgoing(Address{{0},0x1000},{}).value();check(outgoing.rows.size()==1 && std::get<Address>(std::get<Location>(outgoing.rows[0].target)).offset==0x1006,"changed branch replaces previous outgoing reference target");
    auto no_change=plan_invalidation(old,{},old.decisions,old.key,{}).value();auto same=reanalyze(old,old.image,old.metadata,old.decisions,no_change,old.key,{}).value();check(same.functions==old.functions && same.references==old.references && same.strings==old.strings && same.counters.decoded_instructions==0,"annotation-only publication shares every derived snapshot without decode");
    auto equality_cancellation=std::make_shared<std::stop_source>();
    auto equivalent_image=Image::create(std::make_shared<CancelOnReadStorage>(old.image->storage(),equality_cancellation),
                                         old.image->layout()).value();
    auto canceled_equality=reanalyze(old,equivalent_image,old.metadata,old.decisions,no_change,old.key,
                                     equality_cancellation->get_token());
    check(!canceled_equality && canceled_equality.error().code==ErrorCode::canceled &&
              equality_cancellation->stop_requested(),
          "same-key effective-image verification observes cancellation during a storage read");
    auto unversioned_image=patch(old,1,bytes({4}));
    check(!reanalyze(old,unversioned_image,old.metadata,old.decisions,no_change,old.key,{}),
          "same-key no-op rejects a different effective image instead of publishing stale derived facts");
    auto wrong=key;++wrong.byte_revision;check(!reanalyze(old,image,old.metadata,old.decisions,plan,wrong,{}),"proposal cannot substitute a different revision than invalidation plan");std::stop_source stop;stop.request_stop();check(!reanalyze(old,image,old.metadata,old.decisions,plan,key,stop.get_token()),"canceled reanalysis does not publish partial facts");
}

void incomplete_dirty_range_tests() {
    auto data = bytes({0xe8,3,0,0,0,0xc3,0,0,0xc3,0,0,0,0xc3});
    data.resize(128, std::byte{0}); data[24] = std::byte{0x90}; data[25] = std::byte{0xc3};
    ImageMetadata metadata; metadata.exports.push_back({1,"unrelated",Address{{0},0x1018},{}});
    const auto old = basis(data, metadata);
    const auto before = function(*old.functions,0x1018);
    const auto image = patch(old,1,bytes({7}));
    auto key = old.key; ++key.byte_revision;
    // A caller omitted the real edit and supplied an unrelated dirty byte.
    // Retain incremental scheduling, but never reuse a stale decoded CALL.
    const FileRange unrelated{{127},1};
    const auto plan = plan_invalidation(old,std::span(&unrelated,1),old.decisions,key,{}).value();
    const auto changed = reanalyze(old,image,old.metadata,old.decisions,plan,key,{}).value();
    check(plan.full_reason.empty() && changed.counters.rejected_reuse_instructions == 1 &&
              changed.counters.decoded_instructions >= 1 && changed.counters.reused_instructions >= 2,
          "effective bytes reject an undeclared changed instruction while preserving unrelated decode reuse");
    check(function(*changed.functions,0x100c) && !function(*changed.functions,0x1008) &&
              function(*changed.functions,0x1018) == before,
          "undeclared CALL edit discovers the current callee and preserves the independent immutable function");
    check(changed.references->incoming(Address{{0},0x1008},{}).value().total == 0 &&
              changed.references->incoming(Address{{0},0x100c},{}).value().total == 1,
          "actual effective CALL bytes replace old reference targets despite incomplete invalidation hints");
    const auto fresh = analyze_derived(image,old.metadata,old.decisions,old.options,key,{}).value();
    check(changed.functions->instructions.size() == fresh.functions->instructions.size() &&
              std::equal(changed.references->all().begin(),changed.references->all().end(),
                         fresh.references->all().begin(),fresh.references->all().end(),
                         [](const auto &a,const auto &b){
                             const auto *left=std::get_if<Location>(&a.target);
                             const auto *right=std::get_if<Location>(&b.target);
                             return a.source==b.source && a.kind==b.kind && left && right && *left==*right;
                         }),
          "incomplete-range incremental result agrees with fresh analysis");
    check(function(*old.functions,0x1008) && !function(*old.functions,0x100c),
          "source-byte validation never mutates the previous immutable analysis snapshot");

    auto length_data = bytes({0x90,0x90,0x90,0xc3}); length_data.resize(64,std::byte{0});
    const auto length_old = basis(length_data);
    const auto length_image = patch(length_old,0,bytes({0x48,0x89,0xd8}));
    auto length_key = length_old.key; ++length_key.byte_revision;
    const FileRange length_hint{{63},1};
    const auto length_plan = plan_invalidation(length_old,std::span(&length_hint,1),length_old.decisions,length_key,{}).value();
    const auto length_changed = reanalyze(length_old,length_image,length_old.metadata,length_old.decisions,length_plan,length_key,{}).value();
    check(length_changed.counters.rejected_reuse_instructions == 3 && length_changed.functions->instructions.size() == 2 &&
              length_changed.functions->instructions[0]->instruction.length == 3 &&
              length_changed.references->outgoing(Address{{0},0x1001},{}).value().total == 0,
          "undeclared instruction-length edits remove obsolete interior facts rather than reusing old boundaries");

    const auto cancellation = std::make_shared<std::stop_source>();
    const auto cancel_source = std::make_shared<CancelOnReadStorage>(image->storage(),cancellation);
    const auto cancel_image = Image::create(cancel_source,image->layout()).value();
    check(!cancellation->stop_requested(), "source-read cancellation begins after reanalysis starts");
    const auto canceled = reanalyze(old,cancel_image,old.metadata,old.decisions,plan,key,cancellation->get_token());
    check(!canceled && canceled.error().code == ErrorCode::canceled && cancellation->stop_requested() &&
              function(*old.functions,0x1018) == before,
          "cancellation during effective-byte reuse validation publishes no partial proposal and preserves old facts");

    const auto missing = plan_invalidation(old,{},old.decisions,key,{}).value();
    const auto rebuilt = reanalyze(old,image,old.metadata,old.decisions,missing,key,{}).value();
    check(!missing.full_reason.empty() && !missing.string_ranges.ranges().empty() &&
              rebuilt.counters.reused_instructions == 0 && function(*rebuilt.functions,0x100c),
          "a byte revision without ranges explicitly rebuilds code and strings instead of trusting stale facts");
    auto verified_key = old.key;
    ++verified_key.byte_revision;
    const auto verified_empty = plan_invalidation(old, {}, old.decisions, verified_key, {}, true).value();
    const auto unchanged = reanalyze(old, old.image, old.metadata, old.decisions, verified_empty, verified_key, {}).value();
    check(verified_empty.full_reason.empty() && verified_empty.string_ranges.ranges().empty() &&
              unchanged.counters.decoded_instructions == 0 && unchanged.source_key == verified_key,
          "verified empty byte diff advances source revision without rebuilding unchanged facts");
    auto text_data = bytes({0xc3,0,'H','E','L','L','O',0});
    const auto text = basis(text_data);
    const auto changed_text = patch(text,2,bytes({'W','O','R','L','D'}));
    auto text_key = text.key; ++text_key.byte_revision;
    const auto text_plan = plan_invalidation(text,{},text.decisions,text_key,{}).value();
    const auto strings = reanalyze(text,changed_text,text.metadata,text.decisions,text_plan,text_key,{}).value();
    check(strings.strings != text.strings && !strings.strings->records.empty() &&
              strings.strings->records.front().preview == "WORLD",
          "missing dirty ranges cannot retain strings from an earlier byte revision");
    auto backwards = old.key;
    auto later = old;
    // Use a real later basis so key validation and revision validation both apply.
    later.image = image; later.functions = rebuilt.functions; later.references = rebuilt.references;
    later.strings = rebuilt.strings; later.key = key;
    check(!plan_invalidation(later,{},later.decisions,backwards,{}),
          "missing-range fallback cannot allow analysis revisions to move backwards");
}

void discovery_tests(){
    auto data=bytes({0xe8,3,0,0,0,0xc3,0,0,0xc3,0,0,0,0xc3});auto old=basis(data);check(function(*old.functions,0x1008)!=nullptr && !function(*old.functions,0x100c),"literal old call graph has only original callee");auto next=patch(old,1,bytes({7}));auto key=old.key;++key.byte_revision;FileRange range{{1},1};auto plan=plan_invalidation(old,std::span(&range,1),old.decisions,key,{}).value();auto proposal=reanalyze(old,next,old.metadata,old.decisions,plan,key,{}).value();check(function(*proposal.functions,0x100c)!=nullptr && !function(*proposal.functions,0x1008),"patch discovers new callee and removes unrooted old callee");check(proposal.references->incoming(Address{{0},0x1008},{}).value().total==0 && proposal.references->incoming(Address{{0},0x100c},{}).value().total==1,"callee change removes old reference index entries");
    auto length=basis(bytes({0x90,0x90,0x90,0xc3}));auto longer=patch(length,0,bytes({0x48,0x89,0xd8}));auto length_key=length.key;++length_key.byte_revision;FileRange extent{{0},3};auto invalid=plan_invalidation(length,std::span(&extent,1),length.decisions,length_key,{}).value();auto changed=reanalyze(length,longer,length.metadata,length.decisions,invalid,length_key,{}).value();check(changed.functions->instructions.size()==2 && changed.functions->instructions[0]->instruction.length==3 && changed.references->outgoing(Address{{0},0x1001},{}).value().total==0,"length change removes obsolete interior instruction facts");
    auto loop=basis(bytes({0xeb,0xfe}));auto graph=build_graph(*loop.functions,*loop.references,GraphKind::image_calls,{}, {},{},{}).value();check(graph->edges.empty(),"jump to own entry is a CFG loop rather than a call-graph tail candidate");
    auto recursion=basis(bytes({0xe8,0xfb,0xff,0xff,0xff,0xc3}));graph=build_graph(*recursion.functions,*recursion.references,GraphKind::image_calls,{}, {},{},{}).value();check(graph->edges.size()==1 && graph->edges[0].source==graph->edges[0].target && graph->edges[0].kind==GraphEdgeKind::call,"recursive call remains a real call-graph self-edge");
}
void ownership_and_decision_tests(){
    auto data=std::vector<std::byte>(17);data[0]=std::byte{0xeb};data[1]=std::byte{14};data[8]=std::byte{0xeb};data[9]=std::byte{6};data[16]=std::byte{0xc3};ImageMetadata metadata;metadata.exports.push_back({1,"second",Address{{0},0x1008},{}});auto old=basis(data,metadata);auto next=patch(old,16,bytes({0xcc}));auto key=old.key;++key.byte_revision;FileRange tail{{16},1};auto plan=plan_invalidation(old,std::span(&tail,1),old.decisions,key,{}).value();check(plan.functions.size()==2,"shared-tail byte dependency invalidates both owning functions");auto changed=reanalyze(old,next,old.metadata,old.decisions,plan,key,{}).value();bool shared=false;for(auto& block:changed.functions->blocks)if(block->begin.offset==0x1010)shared=block->owners.size()==2 && block->instructions.size()==1 && block->instructions[0]->instruction.opcode==Opcode::int3;check(shared && changed.counters.decoded_instructions==1,"shared tail decodes once and retains both ownerships");
    auto manual=basis(bytes({0x90,0xc3}));auto decisions=manual.decisions;decisions.regions.push_back({1,{{0},0x1000},1,RegionKind::data});auto decision_key=manual.key;++decision_key.decision_revision;auto invalid=plan_invalidation(manual,{},decisions,decision_key,{}).value();auto suppressed=reanalyze(manual,manual.image,manual.metadata,decisions,invalid,decision_key,{}).value();check(suppressed.functions->functions.empty() && suppressed.references->all().empty() && suppressed.strings==manual.strings,"data decision removes rooted code/references without rescanning identical bytes");
    decisions={};decisions.references.push_back({1,FileOffset{0},Address{{0},0x1001},UserReferenceKind::data});invalid=plan_invalidation(manual,{},decisions,decision_key,{}).value();auto referenced=reanalyze(manual,manual.image,manual.metadata,decisions,invalid,decision_key,{}).value();check(referenced.counters.decoded_instructions==0 && referenced.functions->functions[0]==manual.functions->functions[0] && referenced.references->incoming(Address{{0},0x1001},{}).value().total==1,"explicit reference change reuses code while rebuilding typed index");
    auto foreign=std::make_shared<ImageMetadata>(*manual.metadata);foreign->preferred_base=123;auto unchanged=plan_invalidation(manual,{},manual.decisions,manual.key,{}).value();check(!reanalyze(manual,manual.image,foreign,manual.decisions,unchanged,manual.key,{}),"unrelated metadata cannot bypass invalidation with an old source key");
}
void string_and_metadata_tests(){
    auto data=std::vector<std::byte>(140004,std::byte{'A'});data.back()=std::byte{0};data[0]=std::byte{0xc3};auto old=basis(data);auto next=patch(old,70000,bytes({0}));auto key=old.key;++key.byte_revision;FileRange range{{70000},1};auto plan=plan_invalidation(old,std::span(&range,1),old.decisions,key,{}).value();check(!plan.string_ranges.ranges().empty() && !plan.string_reason.empty(),"unbounded string run explicitly invalidates its established scan range");auto proposal=reanalyze(old,next,old.metadata,old.decisions,plan,key,{}).value();std::vector<StringRecord> ascii;for(auto& record:proposal.strings->records)if(record.encoding==StringEncoding::ascii)ascii.push_back(record);check(ascii.size()==2 && ascii[0].byte_length==69999 && ascii[1].file_offset.value==70001,"changed terminator splits long run across chunk boundaries");
    auto tracked=old;check(bool(tracked.metadata_reads.include({0},16)),"metadata read fixture recorded");FileRange header{{0},1};auto invalid=plan_invalidation(tracked,std::span(&header,1),tracked.decisions,key,{}).value();check(invalid.metadata_invalid && !invalid.full_reason.empty(),"metadata byte patch explicitly requests fresh mapping and full rebuild");
    ImageMetadata rooted;rooted.exports.push_back({1,"before",Address{{0},0x1000},{}});
    auto metadata_edit=basis(bytes({0x90,0x90,0xc3,0,0,0,0,0,0x11}),rooted);
    check(bool(metadata_edit.metadata_reads.include({8},1)),"metadata edit fixture records its loader dependency");
    metadata_edit.metadata_reads_complete=true;
    auto after_metadata=std::make_shared<ImageMetadata>(*metadata_edit.metadata);
    after_metadata->exports.clear();after_metadata->exports.push_back({2,"after",Address{{0},0x1001},{}});
    auto edited_image=patch(metadata_edit,8,bytes({0x12}));auto metadata_key=metadata_edit.key;++metadata_key.byte_revision;
    FileRange metadata_byte{{8},1};auto metadata_plan=plan_invalidation(metadata_edit,std::span(&metadata_byte,1),
        metadata_edit.decisions,metadata_key,{},false,true).value();
    auto metadata_proposal=reanalyze(metadata_edit,edited_image,after_metadata,metadata_edit.decisions,
        metadata_plan,metadata_key,{}).value();
    check(metadata_plan.metadata_invalid,"certified loader byte dependency marks the metadata snapshot dirty");
    check(metadata_proposal.counters.reused_instructions>=2 && metadata_proposal.counters.decoded_instructions==0,
          "certified metadata edit retains unaffected instruction decodes");
    check(function(*metadata_proposal.functions,0x1001),
          "certified metadata edit rebuilds roots at the refreshed export address");
    auto metadata_cancellation=std::make_shared<std::stop_source>();
    auto cancel_metadata_image=Image::create(std::make_shared<CancelOnReadStorage>(edited_image->storage(),
        metadata_cancellation),edited_image->layout()).value();
    auto canceled_metadata=reanalyze(metadata_edit,cancel_metadata_image,after_metadata,metadata_edit.decisions,
        metadata_plan,metadata_key,metadata_cancellation->get_token());
    check(!canceled_metadata && canceled_metadata.error().code==ErrorCode::canceled &&
          metadata_cancellation->stop_requested() && metadata_edit.functions->key==metadata_edit.key,
          "cancellation during certified metadata reuse publishes no partial proposal or mutates prior facts");
    auto stale_metadata_key=metadata_key;++stale_metadata_key.byte_revision;
    check(!reanalyze(metadata_edit,edited_image,after_metadata,metadata_edit.decisions,metadata_plan,
                     stale_metadata_key,{}),
          "metadata invalidation plan cannot publish under a different byte revision");
    auto engine=old.key;engine.engine_fingerprint[0]^=std::byte{1};auto incompatible=plan_invalidation(old,{},old.decisions,engine,{}).value();check(!incompatible.full_reason.empty(),"engine key changes cannot reuse old facts silently");check(!reanalyze(old,old.image,old.metadata,old.decisions,incompatible,engine,{}),"unknown engine fingerprint is rejected by enabled implementation");
    auto unicode=std::vector<std::byte>(24);unicode[0]=std::byte{0xc3};for(size_t i=0;i<8;++i)unicode[4+2*i]=std::byte('A'+i);auto utf16=basis(unicode);auto split=patch(utf16,12,bytes({0,0}));auto unicode_key=utf16.key;++unicode_key.byte_revision;FileRange utf_range{{12},2};auto utf_plan=plan_invalidation(utf16,std::span(&utf_range,1),utf16.decisions,unicode_key,{}).value();auto rescanned=reanalyze(utf16,split,utf16.metadata,utf16.decisions,utf_plan,unicode_key,{}).value();bool exact=false,obsolete=false;for(auto& record:rescanned.strings->records)if(record.encoding==StringEncoding::utf16le){exact=exact || (record.file_offset.value==4 && record.characters==4 && record.byte_length==8 && record.terminated);obsolete=obsolete || (record.file_offset.value==4 && record.characters==8);}check(exact && !obsolete,"UTF-16 terminator edit rescans alignment and removes obsolete full run");
}
void semantic_decoder_incremental_reads_test(){
    std::vector<std::byte> raw(32,std::byte{0});
    for (const auto offset : {0u, 16u}) {
        raw[offset+0]=std::byte{0xff}; raw[offset+1]=std::byte{0xff};
        raw[offset+2]=std::byte{0xff}; raw[offset+3]=std::byte{0xff};
    }
    // A built-in A64 function is independent of the host decoder's declared
    // image read at file offset 24.
    raw[8]=std::byte{0x1f}; raw[9]=std::byte{0x20}; raw[10]=std::byte{0x03}; raw[11]=std::byte{0xd5};
    raw[12]=std::byte{0xc0}; raw[13]=std::byte{0x03}; raw[14]=std::byte{0x5f}; raw[15]=std::byte{0xd6};
    auto storage=std::make_shared<MemoryStorage>(raw);
    Address entry{{0},0x1000};
    ImageLayout layout{{{0},64,1,ByteOrder::little},Architecture::arm64,ExecutionMode::a64,
        {{"a64",entry,raw.size(),{0},raw.size(),true,false,true}},{entry}};
    auto image=Image::create(storage,std::move(layout)).value();
    AnalysisOptions options;
    options.semantic_decoder=[](DecodeContext context,Address address,std::span<const std::byte> bytes)
        -> Result<std::optional<Instruction>> {
        if (address.offset!=0x1000 && address.offset!=0x1010) return std::optional<Instruction>{};
        Instruction value; value.context=context; value.address=address; value.length=4;
        value.opcode=Opcode::opaque; value.flow=FlowKind::ret;
        std::copy_n(bytes.begin(),4,value.bytes.begin());
        return std::optional<Instruction>{std::move(value)};
    };
    options.semantic_decoder_identity=[] { return std::vector<std::byte>{std::byte{1}}; };
    options.semantic_decoder_read_set=[] {
        AnalysisOptions::SemanticDecoderInput input;
        input.identity="host-table"; input.sha256[0]=std::byte{1};
        input.image_reads.push_back({{24},1});
        return std::vector<AnalysisOptions::SemanticDecoderInput>{input};
    };
    AnalysisBasis old; old.image=image; old.metadata=std::make_shared<const ImageMetadata>();
    old.options=options; old.metadata_reads_complete=true; old.key.input={storage->size(),hash_source(*storage,{}).value()};
    old.key.engine_fingerprint=function_engine_fingerprint(options);
    ImageMetadata metadata; metadata.exports.push_back({1,"extension_a",Address{{0},0x1000},{}});
    metadata.exports.push_back({2,"builtin",Address{{0},0x1008},{}});
    metadata.exports.push_back({3,"extension_b",Address{{0},0x1010},{}});
    old.metadata=std::make_shared<const ImageMetadata>(metadata);
    old.functions=recover_functions(*image,*old.metadata,old.decisions,options,old.key,{}).value();
    old.references=derive_references(*old.functions,*old.metadata,old.decisions,{}).value();
    old.strings=std::make_shared<const StringScan>(find_strings(*image,options,{}).value());
    check(old.functions->instructions.size()==4,"fixture has two host-decoded and two built-in instructions");
    auto next=patch(old,24,bytes({0x42})); auto key=old.key; ++key.byte_revision;
    const FileRange changed{{24},1};
    const auto plan=plan_invalidation(old,std::span(&changed,1),old.decisions,key,{},false,true).value();
    check(plan.full_reason.empty(),"a declared host-decoder byte read uses fact dependencies instead of forcing a whole-analysis rebuild");
    const auto updated=reanalyze(old,next,old.metadata,old.decisions,plan,key,{}).value();
    check(updated.counters.decoded_instructions==2 && updated.counters.reused_instructions==2,
          "host-decoder external reads invalidate only host-decoded instructions and retain unrelated built-in decodes");
}
}
int main(){return run([]{reuse_tests();incomplete_dirty_range_tests();discovery_tests();ownership_and_decision_tests();string_and_metadata_tests();semantic_decoder_incremental_reads_test();});}
