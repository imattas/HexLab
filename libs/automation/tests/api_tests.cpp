#include "hexlab/automation/api.hpp"
#include <algorithm>
#include <chrono>
#include <fstream>
#include <iostream>
#include <stdexcept>
#ifdef _WIN32
#include <crtdbg.h>
#include <cstdlib>
#endif
using namespace hexlab;
void check(bool value, const char* message) { if (!value) throw std::runtime_error(message); }
template<class T> T take(Result<T> value) { if (!value) throw std::runtime_error(value.error().message); return std::move(value.value()); }
int main() {
#ifdef _WIN32
  _CrtSetReportMode(_CRT_ASSERT,_CRTDBG_MODE_FILE);
  _CrtSetReportFile(_CRT_ASSERT,_CRTDBG_FILE_STDERR);
  _set_abort_behavior(0,_WRITE_ABORT_MSG|_CALL_REPORTFAULT);
#endif
  auto directory=std::filesystem::temp_directory_path()/ ("hexlab-automation-"+std::to_string(std::chrono::steady_clock::now().time_since_epoch().count()));
  std::filesystem::create_directory(directory);
  try {
    auto input=directory/"raw.bin", project=directory/"sample.hxproj", output=directory/"patched.bin";
    {std::ofstream stream(input,std::ios::binary); const char data[]="\x90\xc3" "Hello SDK string";stream.write(data,static_cast<std::streamsize>(sizeof(data)-1));}
    LoadRecipe recipe{Format::raw,RawOptions{Architecture::x86_64,ExecutionMode::x86_64,{{7},0x1000},true,false,true,{}}};
    check(!automation::Project::create(project,input,recipe,99),"unknown API version fails before creating file");
    auto api=take(automation::Project::create(project,input,recipe));
    auto initial=take(api->snapshot());
    const auto initial_edit_revision=initial->state->revisions.edit;
    check(initial->functions->functions.size()==1,"real project function recovery");
    check(take(api->read(Address{{7},0x1000},2)).size()==2,"space-aware reads");
    auto segments=take(api->segments(0,8));check(segments.size()==1 && segments[0].name=="raw" && segments[0].begin==Address{{7},0x1000} && segments[0].size==sizeof("\x90\xc3" "Hello SDK string")-1 && segments[0].file_begin==FileOffset{0} && segments[0].file_size==segments[0].size && segments[0].readable && !segments[0].writable && segments[0].executable,"automation exposes mapped segment geometry, provenance, and permissions");
    check(!api->read(Address{{0},0x1000},1),"unknown space rejected");
    check(!api->read(FileOffset{0},automation::maximum_read+1),"read allocation bounded");
    check(take(api->functions(0,1)).size()==1 && take(api->functions(1,1)).empty(),"bounded function pages");
    auto containing=take(api->function_at(Address{{7},0x1001}));
    check(containing && containing->entry==Address{{7},0x1000} && !take(api->function_at(Address{{7},0x1002})),
          "analysis lookup maps an instruction address to its containing function");
    auto pseudocode=take(api->decompile(Address{{7},0x1001}));
    check(pseudocode.entry==Address{{7},0x1000} && !pseudocode.text.empty() && pseudocode.complete,
          "native automation decompiles an address within a recovered function");
    check(!api->decompile(Address{{7},0x1002}),"native automation rejects an address outside recovered functions");
    check(take(api->instructions(0,2)).size()==2,"real decoded instruction pages");
    SearchLimits search_limits;search_limits.max_results=1;
    auto first_search=take(api->search(BytePattern{"??"},{},search_limits));
    check(first_search.matches.size()==1 && first_search.matches[0].offset.value==0 && first_search.next,
          "native automation exposes a bounded real-project search page");
    auto second_search=take(api->search(BytePattern{"??"},first_search.next,search_limits));
    check(second_search.matches.size()==1 && second_search.matches[0].offset.value==1,
          "native automation continues a revision-bound search");
    const auto string_page=take(api->strings(0,16));
    check(std::any_of(string_page.begin(),string_page.end(),[](const auto& row){return row.preview=="Hello SDK string";}),
          "real paged string records retain their preview text");
    take(api->execute(Rename{Address{{7},0x1000},"automated"}));
    take(api->execute(Comment{FileOffset{0},"from bridge"},51));
    take(api->execute(BookmarkCommand{FileOffset{0},"grouped",false},51));
    take(api->undo());
    check(take(api->snapshot())->state->user->bookmarks.empty(),"grouped undo uses existing history");
    take(api->redo());
    auto stale_patch=api->patch(Address{{7},0x1000},{std::byte{0xcc}},initial_edit_revision);
    check(!stale_patch && stale_patch.error().code==ErrorCode::conflict,"stale expected edit revision rejects a byte patch");
    const auto current_revision=take(api->snapshot())->state->revisions.edit;
    take(api->patch(Address{{7},0x1000},{std::byte{0xcc}},current_revision));
    check(!api->instructions(0,1),"stale derived facts require explicit reanalysis");
    check(take(api->read(FileOffset{0},1))[0]==std::byte{0xcc},"canonical effective patches");
    check(initial->state->user->annotations.empty(),"retained immutable snapshot stays unchanged");
    take(api->analyze());
    take(api->export_binary(output));
    {std::ifstream stream(output,std::ios::binary);check(stream.get()==0xcc && stream.get()==0xc3,"exact exported original-byte layout");}
    take(api->save());api.reset();
    auto readonly=take(automation::Project::open(project,true));
    auto rejected=readonly->execute(Comment{FileOffset{0},"blocked"});
    check(!rejected && rejected.error().code==ErrorCode::read_only,"readonly command enforcement");
    check(take(readonly->snapshot())->state->user->bookmarks.size()==1,"persistent reopened state");
    check(!readonly->functions(0,0) && !readonly->instructions(0,automation::maximum_page+1) &&
          !readonly->strings(0,automation::maximum_page+1) && !readonly->segments(0,0) &&
          !readonly->segments(0,automation::maximum_page+1),"page bounds");
    readonly.reset();std::filesystem::remove_all(directory);
    std::cout<<"Automation API: real projects, snapshots, pages, commands, history, persistence, export passed\n";
    return 0;
  } catch(const std::exception& e) {std::cerr<<e.what()<<'\n';std::filesystem::remove_all(directory);return 1;}
}
