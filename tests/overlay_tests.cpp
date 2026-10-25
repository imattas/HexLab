#include "hexlab/image/patches.hpp"
#include "hexlab/image/read_set.hpp"
#include "hexlab/image/file_storage.hpp"
#include "hexlab/image/image.hpp"
#include "support/checks.hpp"
#include "support/fixture_files.hpp"
#include <algorithm>
using namespace hexlab;
using namespace hexlab_test;
void patch_tests(){
    FixtureFile input(bytes({0,1,2,3,4,5,6,7}));auto original=FileStorage::open(input.path).value();
    std::vector<PatchSpan> changes{{{1},bytes({1,2,3}),bytes({0xa1,0xa2,0xa3})},{{3},bytes({3,4}),bytes({0xb3,0xb4})}};
    auto patches=PatchSet::create(*original,changes).value();check(patches->spans().size()==1 && patches->spans()[0].begin==FileOffset{1} && patches->spans()[0].replacement==bytes({0xa1,0xa2,0xb3,0xb4}),"overlap order and adjacent spans normalize");
    auto overlay=make_overlay(original,changes).value();auto view=overlay->read_at({0},8).value();
    check(std::vector(view.bytes.begin(),view.bytes.end())==bytes({0,0xa1,0xa2,0xb3,0xb4,5,6,7}),"effective bytes apply each replacement");
    check(original->read_at({1},1).value().bytes[0]==std::byte{1},"original remains immutable");
    changes.push_back({{2},bytes({2,3}),bytes({2,3})});patches=PatchSet::create(*original,changes).value();
    check(patches->spans().size()==2 && patches->spans()[0].replacement==bytes({0xa1}) && patches->spans()[1].replacement==bytes({0xb4}),"reverting overlap removes patch entries");
    changes.push_back({{1},bytes({1,2,3,4}),bytes({1,2,3,4})});check(PatchSet::create(*original,changes).value()->spans().empty(),"complete revert has no overlay entries");
    check(!make_overlay(original,std::vector<PatchSpan>{{{1},bytes({0}),bytes({9})}}),"original-byte mismatch rejected");
    check(!make_overlay(original,std::vector<PatchSpan>{{{1},bytes({1}),bytes({9,9})}}),"length-changing patch rejected");
    check(!make_overlay(original,std::vector<PatchSpan>{{{UINT64_MAX},bytes({1}),bytes({9})}}),"overflow patch rejected");
    check(!make_overlay(original,std::vector<PatchSpan>{{{8},bytes({1}),bytes({9})}}),"out of input patch rejected");
    check(!overlay->read_at({UINT64_MAX},1) && !overlay->read_at({8},1) && overlay->read_at({8},0).value().bytes.empty(),"overlay range checks match source contract");
    auto unchanged=overlay->read_at({6},2).value();check(unchanged.bytes.data()==original->read_at({6},2).value().bytes.data(),"unchanged read remains zero-copy");
    overlay.reset();original.reset();check(view.bytes[3]==std::byte{0xb3} && unchanged.bytes[1]==std::byte{7},"patched and original views retain independent owners");
    FixtureFile alias(bytes({0x90,0xc3}));auto source=FileStorage::open(alias.path).value();auto effective=make_overlay(source,std::vector<PatchSpan>{{{0},bytes({0x90}),bytes({0xcc})}}).value();
    ImageLayout layout{{{0},64,1,ByteOrder::little},Architecture::x86_64,ExecutionMode::x86_64,{{"a",{{0},0x1000},2,{0},2,true,false,true},{"b",{{0},0x2000},2,{0},2,true,false,true}}, {}};
    auto image=Image::create(effective,layout).value();check(image->read({{0},0x1000},1).value()[0]==std::byte{0xcc} && image->read({{0},0x2000},1).value()[0]==std::byte{0xcc},"file overlay changes all virtual aliases");
    check(!make_overlay({},{}),"null original storage rejected");
}
void tracking_tests(){
    ReadSet set;check(bool(set.include({10},4)) && bool(set.include({0},3)) && bool(set.include({3},7)),"read ranges accepted");
    check(set.ranges().size()==1 && set.ranges()[0].begin==FileOffset{0} && set.ranges()[0].size==14,"overlap and adjacency union is canonical");
    check(!set.intersects({14},1).value() && set.intersects({13},1).value() && !set.intersects({3},0).value(),"read dependencies use half-open ranges");
    check(!set.include({UINT64_MAX},1) && !set.intersects({UINT64_MAX},1),"overflow dependency extents rejected");
    FixtureFile input(bytes({0,1,2,3,4}));auto tracking=TrackingStorage::create(FileStorage::open(input.path).value()).value();
    check(bool(tracking->read_at({1},2)) && !tracking->read_at({4},2) && bool(tracking->read_at({5},0)),"tracking delegates successful failed and empty reads");
    const auto reads=tracking->reads();check(reads.ranges().size()==1 && reads.ranges()[0].begin==FileOffset{1} && reads.ranges()[0].size==2,"tracking records successful actual bytes only");
    check(!TrackingStorage::create({}),"tracking requires a source");
}
void hash_tests(){
    FixtureFile input(bytes({'a','b','c'}));auto source=FileStorage::open(input.path).value();
    check(digest_hex(hash_source(*source,{}).value())=="ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad","byte-source hash matches published vector");
    auto overlay=make_overlay(source,std::vector<PatchSpan>{{{2},bytes({'c'}),bytes({'d'})}}).value();Sha256 independent;check(bool(independent.update(std::as_bytes(std::span("abd",3)))),"expected overlay hash accepted");
    check(hash_source(*overlay,{}).value()==independent.digest(),"effective source hash sees patches");
    std::stop_source stopped;stopped.request_stop();check(hash_source(*source,stopped.get_token()).error().code==ErrorCode::canceled,"hash cancellation observed");
}
void normalization_tests(){
    std::vector<std::byte> original(256);for(size_t i=0;i<original.size();++i)original[i]=std::byte(i);
    FixtureFile input(original);auto source=FileStorage::open(input.path).value();auto expected=original;
    std::vector<PatchSpan> changes;uint32_t random=0x5a17;
    auto next=[&]{random=random*1664525u+1013904223u;return random;};
    for(size_t n=0;n<300;++n){
        const size_t begin=next()%256;const size_t count=std::min<size_t>(next()%40,256-begin);
        PatchSpan patch{{begin},{original.begin()+begin,original.begin()+begin+count},{}};
        for(size_t i=0;i<count;++i){const auto value=n%4==0?original[begin+i]:std::byte(next());patch.replacement.push_back(value);expected[begin+i]=value;}
        changes.push_back(std::move(patch));
    }
    auto overlay=make_overlay(source,changes).value();auto actual=overlay->read_at({0},256).value();
    check(std::equal(actual.bytes.begin(),actual.bytes.end(),expected.begin()),"interval overlay agrees with independent per-byte model");
    auto patches=PatchSet::create(*source,changes).value();uint64_t end=0;
    for(const auto& patch:patches->spans()){check(patch.begin.value>=end && patch.original.size()==patch.replacement.size(),"normalized intervals are ordered and disjoint");end=patch.begin.value+patch.original.size();}
    std::vector<std::byte> big(1024*1024+3,std::byte{0x11});FixtureFile large(big);auto large_source=FileStorage::open(large.path).value();
    std::vector<PatchSpan> full{{{0},big,std::vector<std::byte>(big.size(),std::byte{0x22})}};
    auto chunks=PatchSet::create(*large_source,full).value();
    check(chunks->spans().size()==2 && chunks->spans()[0].replacement.size()==1024*1024 && chunks->spans()[1].replacement.size()==3,"normalized payloads are bounded to one MiB");
    auto boundary=make_overlay(large_source,full).value()->read_at({1024*1024-1},4).value();
    check(std::all_of(boundary.bytes.begin(),boundary.bytes.end(),[](auto value){return value==std::byte{0x22};}),"reads cross patch payload boundaries");
}
int main(){return run([]{patch_tests();tracking_tests();normalization_tests();hash_tests();});}
