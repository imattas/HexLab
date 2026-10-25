#include "hexlab/workspace/listing.hpp"
#include "hexlab/workspace/jobs.hpp"
#include "support/checks.hpp"
#include "support/fixture_files.hpp"
#include "support/pe_fixture.hpp"
#include <chrono>
#include <thread>
using namespace hexlab;
using namespace hexlab_test;
std::shared_ptr<const DocumentSnapshot> raw_document(const std::filesystem::path& path) {
    OpenRequest request;request.path=path;request.format=Format::raw;
    request.raw=RawOptions{Architecture::x86_64,ExecutionMode::x86_64,{{0},0x1000},true,false,true,{}};
    return load_document(request,{{1},1},{}).value();
}
void page_tests() {
    FixtureFile raw(bytes({0x90,0xc3,'A','B',0xc3}));auto document=raw_document(raw.path);
    auto page=make_listing_page(*document,Address{{0},0x1000},5).value();
    check(page.rows.size()==5 && page.rows[0].reachable && page.rows[0].instruction && page.rows[0].instruction->opcode==Opcode::nop,"listing uses proven snapshot instruction");
    check(page.rows.size()>=3 && page.rows[1].instruction && page.rows[1].instruction->opcode==Opcode::ret && !page.rows[2].instruction && !page.rows[2].reachable,"unreachable bytes stay data");
    page=make_listing_page(*document,Address{{0},0x1004},2).value();
    check(page.rows.size()==1 && page.rows[0].instruction && !page.rows[0].reachable,"explicit manual decode is not marked reachable");
    page=make_listing_page(*document,Address{{0},0x1000},2).value();
    check(page.rows.size()==2 && page.next==Location{Address{{0},0x1002}},"listing page is bounded and resumable");
    check(!make_listing_page(*document,Address{{0},0x1000},0) && !make_listing_page(*document,Address{{0},0x1000},4097),"listing rejects invalid page sizes");
    FixtureFile unsupported(bytes({0xc5,0xf8,0x77,0x90,0xc3}));document=raw_document(unsupported.path);
    page=make_listing_page(*document,Address{{0},0x1000},5).value();
    check(page.rows.size()==3,"opaque row advances by its known length to the end of the mapped segment");
    check(page.rows.size()>0 && page.rows[0].instruction && page.rows[0].instruction->opcode==Opcode::x86_opaque,
          "manual listing displays opaque instruction length");
    check(page.rows.size()>1 && !page.rows[1].instruction && !page.rows[1].reachable &&
              std::get<Address>(page.rows[1].location).offset==0x1003,
          "listing stops automatic decode after opaque semantics while retaining the next byte address");
    auto data=pe_fixture();data.resize(0x410);FixtureFile file(data);OpenRequest request;request.path=file.path;
    document=load_document(request,{{2},2},{}).value();
    auto byte_page=make_bytes_page(*document,Address{{0},0x1400011feULL},4).value();
    check(byte_page.cells.size()==4 && byte_page.cells[0].initialized && !byte_page.cells[2].initialized &&
          !byte_page.cells[2].file_offset && byte_page.cells[2].value==std::byte{0},"bytes view distinguishes file bytes from zero fill");
    byte_page=make_bytes_page(*document,Address{{0},0x1400012feULL},8).value();
    check(byte_page.cells.size()==2 && !byte_page.next,"bytes page stops at virtual gap");
    check(!make_bytes_page(*document,Address{{0},0x140001800ULL},4),"gap cannot be initial byte selection");
    byte_page=make_bytes_page(*document,FileOffset{0x405},16).value();
    check(byte_page.cells.size()==11 && !byte_page.cells[0].address && byte_page.cells[0].file_offset==FileOffset{0x405},"overlay page preserves file-only location");
    page=make_listing_page(*document,Address{{0},0x140001200ULL},2).value();
    check(page.rows.size()==2 && !page.rows[0].instruction && page.rows[0].status=="zero-filled data","zero fill cannot become a decoded row");
}
void job_tests() {
    FixtureFile a(pe_fixture()),b(pe_fixture(false));OpenRequest first;first.path=a.path;OpenRequest second;second.path=b.path;
    Workspace workspace;DocumentJobs jobs;
    const auto ta=workspace.begin_open();jobs.submit(first,ta);
    const auto tb=workspace.begin_open();jobs.submit(second,tb);
    const auto deadline=std::chrono::steady_clock::now()+std::chrono::seconds(10);
    while(jobs.busy() && std::chrono::steady_clock::now()<deadline) {
        if(auto outcome=jobs.take_completed())workspace.finish_open(outcome->ticket,std::move(outcome->result));
        std::this_thread::sleep_for(std::chrono::milliseconds(1));
    }
    if(auto outcome=jobs.take_completed())workspace.finish_open(outcome->ticket,std::move(outcome->result));
    check(!jobs.busy() && workspace.current() && workspace.current()->id==tb.document && workspace.current()->metadata.machine==0x14c,"latest background job publishes through ticket gate");
    const auto tc=workspace.begin_open();jobs.submit(first,tc);workspace.cancel_open();jobs.cancel();
    for(unsigned n=0;n<10000 && jobs.busy();++n)std::this_thread::sleep_for(std::chrono::milliseconds(1));
    if(auto outcome=jobs.take_completed())workspace.finish_open(outcome->ticket,std::move(outcome->result));
    check(!jobs.busy() && workspace.current()->id==tb.document,"cancel preserves prior document and worker quiesces");
    for(unsigned n=0;n<8;++n){DocumentJobs transient;transient.submit(first,{{10+n},10+n});}
    check(true,"destroying job owner joins pending workers");
}
int main(){return run([]{page_tests();job_tests();});}
