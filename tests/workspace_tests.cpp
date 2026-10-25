#include "hexlab/workspace/workspace.hpp"
#include "hexlab/workspace/navigation.hpp"
#include "support/checks.hpp"
#include "support/fixture_files.hpp"
#include "support/pe_fixture.hpp"
using namespace hexlab;
using namespace hexlab_test;

OpenRequest raw_request(const std::filesystem::path& path) {
    OpenRequest r;r.path=path;r.format=Format::raw;
    r.raw=RawOptions{Architecture::x86_64,ExecutionMode::x86_64,{{0},0x1000},true,false,true,{}};
    return r;
}
void workspace_tests() {
    FixtureFile a(bytes({0x90,0xc3,0x90,0xc3})),b(pe_fixture());
    Workspace workspace;
    auto first=workspace.begin_open();
    check(workspace.finish_open(first,load_document(raw_request(a.path),first,{})),"initial document committed");
    const auto original=workspace.current();
    check(original->id==first.document && original->revision==first.generation && original->analysis.has_value(),"snapshot identity and common analysis");
    check(workspace.selection()==Location{Address{{0},0x1000}},"entry initially selected");
    check(workspace.navigate(Address{{0},0x1001}).has_value(),"navigate mapped VA");
    const auto pending=workspace.begin_open();
    auto missing=raw_request(a.path.parent_path()/"missing-input");
    check(!workspace.finish_open(pending,load_document(missing,pending,{})),"failed replacement not committed");
    check(workspace.current()==original && workspace.selection()==Location{Address{{0},0x1001}} && workspace.last_error().has_value(),"failed open preserves doc selection and error");
    check(workspace.back().value()==Location{Address{{0},0x1000}},"failed replacement preserves history");
    check(workspace.forward().value()==Location{Address{{0},0x1001}},"history forward");
    (void)workspace.back();(void)workspace.navigate(FileOffset{2});
    check(!workspace.forward(),"new navigation drops forward history");
    const auto selection=workspace.selection();
    check(!workspace.navigate(Address{{0},0x9999}) && !workspace.navigate(FileOffset{4}) && workspace.selection()==selection,"bad navigation is transactional");
    auto old_ticket=workspace.begin_open();auto old_result=load_document(raw_request(a.path),old_ticket,{});
    auto current_ticket=workspace.begin_open();OpenRequest pe;pe.path=b.path;
    auto current_result=load_document(pe,current_ticket,{});
    check(!workspace.finish_open(old_ticket,std::move(old_result)),"superseded completion rejected");
    check(workspace.finish_open(current_ticket,std::move(current_result)),"newest completion committed");
    check(workspace.current()->id!=original->id && !workspace.back(),"replacement has distinct id and history");
    auto canceled=workspace.begin_open();auto canceled_result=load_document(pe,canceled,{});workspace.cancel_open();
    check(!workspace.finish_open(canceled,std::move(canceled_result)),"canceled completion rejected");
    auto closing=workspace.begin_open();auto close_result=load_document(pe,closing,{});workspace.close_document();
    check(!workspace.finish_open(closing,std::move(close_result)) && !workspace.current() && !workspace.navigate(FileOffset{0}),"closed document cannot be revived");
    auto mismatch=workspace.begin_open();auto mismatch_result=load_document(pe,mismatch,{}).value();
    auto changed=std::make_shared<DocumentSnapshot>(*mismatch_result);changed->revision++;
    check(!workspace.finish_open(mismatch,std::shared_ptr<const DocumentSnapshot>(changed)),"snapshot ticket mismatch rejected");
    check(workspace.finish_open(mismatch,mismatch_result),"matching completion remains usable after rejected mismatch");
    FixtureFile with_overlay([]{auto d=pe_fixture();d.resize(0x410);return d;}());OpenRequest overlay;overlay.path=with_overlay.path;
    auto overlay_ticket=workspace.begin_open();check(workspace.finish_open(overlay_ticket,load_document(overlay,overlay_ticket,{})),"overlay document loaded");
    check(workspace.navigate(FileOffset{0x405}).has_value() && !workspace.current()->image->to_address({0x405}),"overlay file navigation has no fake VA");
    FixtureFile x86(pe_fixture(false));OpenRequest x86_request;x86_request.path=x86.path;
    const auto inspected=load_document(x86_request,{DocumentId{999},999},{}).value();
    check(inspected->metadata.machine==0x14c && inspected->analysis && inspected->analysis->instructions.size()==2,"PE32 metadata and legacy instruction analysis are available");
    FixtureFile truncated(bytes({'M','Z'}));OpenRequest candidate;candidate.path=truncated.path;
    check(load_document(candidate,{DocumentId{1000},1000},{}).error().code==ErrorCode::malformed,"bad PE candidate never silently raw");
    std::stop_source stop;stop.request_stop();
    check(load_document(pe,{DocumentId{1001},1001},stop.get_token()).error().code==ErrorCode::canceled,"document cancellation");
}
void numeric_tests() {
    check(parse_address(L"0x1000").value()==4096 && parse_address(L"4096").value()==4096,"hex and decimal addresses");
    check(parse_address(L"0XFFFFFFFFFFFFFFFF").value()==UINT64_MAX,"maximum hex address");
    check(!parse_address(L"18446744073709551616") && !parse_address(L"0x10000000000000000"),"address overflow rejected");
    for(auto text:{L"",L"0x",L"-1",L"+1",L"0x12x",L"12 ",L"1.0"})check(!parse_address(text),"numeric junk rejected");
}
int main() {return run([]{workspace_tests();numeric_tests();});}
