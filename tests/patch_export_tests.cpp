#include "hexlab/workspace/export.hpp"
#include "support/checks.hpp"
#include "support/fixture_files.hpp"
#include "support/pe_fixture.hpp"
#include "support/test_entrypoint.hpp"
#include "image_testing.hpp"
#include <algorithm>
using namespace hexlab;using namespace hexlab::database;using namespace hexlab_test;
namespace {
struct Fixture {
    FixtureFile input;std::filesystem::path project;std::shared_ptr<ProjectStore> store;std::shared_ptr<ProjectSession> session;
    explicit Fixture(std::vector<std::byte> data,LoadRecipe recipe={Format::raw,RawOptions{Architecture::x86_64,ExecutionMode::x86_64,{{0},0x1000},true,true,false,{}}}):input(data),project(input.path.wstring()+L".hxproj"){
        store=ProjectStore::create(project,{}).value();auto source=FileStorage::open(input.path).value();check(bool(store->import_input(*source,recipe,input.path,{})),"export fixture imports original");AnalysisOptions options;options.instruction_budget=32;options.string_budget=32;session=ProjectSession::attach(store,options,{}).value();
    }
    ~Fixture(){session.reset();store.reset();std::error_code ignored;std::filesystem::remove(project,ignored);for(auto suffix:{L"-wal",L"-shm"}){auto side=project;side+=suffix;std::filesystem::remove(side,ignored);}}
};
std::vector<std::byte> read_file(const std::filesystem::path& path){std::ifstream file(path,std::ios::binary);if(!file.good())throw std::runtime_error("Cannot read exported fixture");auto size=std::filesystem::file_size(path);std::vector<std::byte> data(static_cast<size_t>(size));if(size)file.read(reinterpret_cast<char*>(data.data()),static_cast<std::streamsize>(size));if(!file.good())throw std::runtime_error("Cannot finish exported fixture read");return data;}
class InterruptedSource final:public ByteStorage {
public:
    std::shared_ptr<const ByteStorage> source;std::stop_source* cancel=nullptr;bool short_read=false;
    explicit InterruptedSource(std::shared_ptr<const ByteStorage> value):source(std::move(value)){}
    uint64_t size()const noexcept override{return source->size();}
    Result<ByteView> read_at(FileOffset offset,size_t count)const override{auto view=source->read_at(offset,count);if(!view)return view.error();if(cancel && count)cancel->request_stop();if(short_read && count)view.value().bytes=view.value().bytes.first(count-1);return view;}
};
void exact_tests(const std::filesystem::path& directory){
    std::vector<std::byte> original(2*1024*1024+17);for(size_t i=0;i<original.size();++i)original[i]=std::byte((i*13+7)&255);auto expected=original;Fixture fixture(original);
    auto first=bytes({0xaa,0xbb,0xcc,0xdd,0xee});check(bool(fixture.session->execute(PatchBytes{FileOffset{65534},first},0,{})),"patch crosses streaming chunk boundary");std::copy(first.begin(),first.end(),expected.begin()+65534);
    auto second=bytes({1,2,3,4,5,6});check(bool(fixture.session->execute(PatchBytes{FileOffset{1024*1024-2},second},0,{})),"patch crosses input embedding boundary");std::copy(second.begin(),second.end(),expected.begin()+1024*1024-2);
    check(bool(fixture.session->execute(PatchBytes{FileOffset{65534},{original[65534]}},0,{})),"original-byte revert is accepted");expected[65534]=original[65534];
    const auto output=directory/L"patched.bin";std::error_code ignored;std::filesystem::remove(output,ignored);auto snapshot=fixture.session->snapshot();auto receipt=export_patched(*snapshot,output,ReplacePolicy::fail_if_exists,{}).value();
    check(read_file(output)==expected && receipt.bytes==expected.size() && receipt.revision==snapshot->state->revisions.edit,"export matches independently edited whole-file oracle");check(!receipt.caveat.empty(),"receipt states checksum and signature limitations");
    auto mapped=FileStorage::open(output).value();check(hash_source(*mapped,{}).value()==receipt.sha256,"receipt hash matches reopened output bytes");mapped.reset();std::ofstream(directory/L"patched.sha256",std::ios::binary)<<digest_hex(receipt.sha256);
    auto failed=export_patched(*snapshot,output,ReplacePolicy::fail_if_exists,{});check(!failed && read_file(output)==expected,"existing destination survives missing replacement policy");
    write_file(output,bytes({4,3,2,1}));check(bool(export_patched(*snapshot,output,ReplacePolicy::replace_existing,{})) && read_file(output)==expected,"explicit replacement publishes complete patched output");
    auto input_bytes=read_file(fixture.input.path);check(input_bytes==original,"export leaves external original untouched");
}
void failure_tests(const std::filesystem::path& directory){
    Fixture fixture(std::vector<std::byte>(65537,std::byte{0x21}));auto snapshot=fixture.session->snapshot();const auto output=directory/L"failure.bin";const auto baseline=bytes({9,8,7});write_file(output,baseline);
    std::stop_source stop;auto source=std::make_shared<InterruptedSource>(snapshot->original);source->cancel=&stop;auto interrupted=*snapshot;interrupted.original=source;auto canceled=export_patched(interrupted,output,ReplacePolicy::replace_existing,stop.get_token());check(!canceled && canceled.error().code==ErrorCode::canceled && read_file(output)==baseline,"midstream cancellation preserves existing output");
    source->cancel=nullptr;source->short_read=true;check(!export_patched(interrupted,output,ReplacePolicy::replace_existing,{}) && read_file(output)==baseline,"short original read preserves preceding output");
    auto state=std::make_shared<ProjectState>(*snapshot->state);state->input.sha256[0]^=std::byte{1};auto mismatched=*snapshot;mismatched.state=state;auto mismatch=export_patched(mismatched,output,ReplacePolicy::replace_existing,{});check(!mismatch && mismatch.error().code==ErrorCode::integrity && read_file(output)==baseline,"original identity is verified before publication");
    image_testing::fail_next_write();check(!export_patched(*snapshot,output,ReplacePolicy::replace_existing,{}) && read_file(output)==baseline,"injected write error preserves preceding output");
    image_testing::fail_next_publication();check(!export_patched(*snapshot,output,ReplacePolicy::replace_existing,{}) && read_file(output)==baseline,"injected publication error preserves preceding output");
    auto reader=FileStorage::open(output).value();auto locked=export_patched(*snapshot,output,ReplacePolicy::replace_existing,{});check(!locked && locked.error().code==ErrorCode::busy && read_file(output)==baseline,"native live reader prevents replacement without losing old output");reader.reset();
    auto wal=output;wal+=L"-wal";write_file(wal,bytes({1}));check(!export_patched(*snapshot,output,ReplacePolicy::replace_existing,{}) && read_file(output)==baseline && read_file(wal)==bytes({1}),"export cannot overwrite a database with journal companions");std::filesystem::remove(wal);
}
void alias_tests(const std::filesystem::path& directory){
    Fixture fixture(bytes({0x90,0xc3}));auto snapshot=fixture.session->snapshot();
    check(!export_patched(*snapshot,fixture.input.path,ReplacePolicy::replace_existing,{}),"external original path rejected");
    auto equivalent=fixture.input.path.parent_path()/L"."/fixture.input.path.filename();check(!export_patched(*snapshot,equivalent,ReplacePolicy::replace_existing,{}),"equivalent original path rejected");
    const auto alias=directory/L"original-alias.bin";std::error_code ignored;std::filesystem::remove(alias,ignored);std::filesystem::create_hard_link(fixture.input.path,alias);check(!export_patched(*snapshot,alias,ReplacePolicy::replace_existing,{}) && read_file(alias)==bytes({0x90,0xc3}),"original hard-link identity rejected");std::filesystem::remove(alias);
    check(!export_patched(*snapshot,fixture.project,ReplacePolicy::replace_existing,{}),"live project destination rejected");auto wal=fixture.project;wal+=L"-wal";check(!export_patched(*snapshot,wal,ReplacePolicy::replace_existing,{}),"project journal destination rejected");
    auto backing=std::dynamic_pointer_cast<const FileStorage>(snapshot->original);check(backing && !export_patched(*snapshot,backing->backing_path(),ReplacePolicy::replace_existing,{}),"mapped original backing rejected");
    check(std::filesystem::remove(fixture.input.path),"original may disappear after embedding");check(!export_patched(*snapshot,fixture.input.path,ReplacePolicy::fail_if_exists,{}) && !std::filesystem::exists(fixture.input.path),"removed original provenance cannot be recreated as export");
}
void empty_and_file_only_tests(const std::filesystem::path& directory){
    Fixture empty({});const auto zero=directory/L"empty.bin";std::error_code ignored;std::filesystem::remove(zero,ignored);auto receipt=export_patched(*empty.session->snapshot(),zero,ReplacePolicy::fail_if_exists,{}).value();check(receipt.bytes==0 && read_file(zero).empty() && receipt.sha256==Sha256{}.digest(),"empty original exports with literal empty digest");
    auto expected=pe_fixture();Fixture pe(expected,{Format::pe,{}});check(bool(pe.session->execute(PatchBytes{FileOffset{0},bytes({0})},0,{})),"file-only export fixture patches header");expected[0]=std::byte{0};const auto broken=directory/L"broken-header.bin";std::filesystem::remove(broken,ignored);check(pe.session->snapshot()->status==DerivedStatus::file_only && bool(export_patched(*pe.session->snapshot(),broken,ReplacePolicy::fail_if_exists,{})) && read_file(broken)==expected,"file-only project exports exact bytes without rebuilding headers");
}
void path_stability_tests(const std::filesystem::path& directory){
    FixtureFile input(bytes({0x90,0xc3}));const auto absolute_project=std::filesystem::path(input.path.wstring()+L".relative.hxproj");auto relative_project=std::filesystem::relative(absolute_project);auto relative_input=std::filesystem::relative(input.path);auto source=FileStorage::open(input.path).value();auto store=ProjectStore::create(relative_project,{}).value();LoadRecipe recipe{Format::raw,RawOptions{Architecture::x86_64,ExecutionMode::x86_64,{{0},0x1000},true,true,false,{}}};check(bool(store->import_input(*source,recipe,relative_input,{})),"relative input/project fixture imports");source.reset();
    check(store->path().is_absolute() && store->path().lexically_normal()==absolute_project.lexically_normal(),"project path identity is anchored at open time");
    const auto saved_directory=directory/L"relocated";std::filesystem::create_directories(saved_directory);const auto saved=saved_directory/L"saved.hxproj";std::error_code ignored;std::filesystem::remove(saved,ignored);for(auto suffix:{L"-wal",L"-shm"}){auto side=saved;side+=suffix;std::filesystem::remove(side,ignored);}check(bool(store->save_as(saved,ReplacePolicy::fail_if_exists,{})),"relative-provenance Save As succeeds");
    auto reopened=ProjectStore::open(saved,ProjectMode::read_only,{}).value();auto state=reopened->snapshot().value();const auto& relative=state->provenance->relative_path;auto reference=std::filesystem::path(std::u8string(reinterpret_cast<const char8_t*>(relative.data()),relative.size()));check((std::filesystem::absolute(saved).parent_path()/reference).lexically_normal()==input.path.lexically_normal(),"Save As rebases relative provenance without changing native bytes");check(state->provenance->native_path==relative_input,"Save As preserves the supplied native provenance encoding");
    struct RestoreDirectory{std::filesystem::path previous=std::filesystem::current_path();~RestoreDirectory(){std::error_code error;std::filesystem::current_path(previous,error);}} restore;
    std::filesystem::current_path(saved_directory);auto session=ProjectSession::attach(reopened,{},{}).value();auto guarded=export_patched(*session->snapshot(),input.path,ReplacePolicy::replace_existing,{});check(!guarded && guarded.error().code==ErrorCode::invalid_argument,"relocated readonly project protects original after cwd changes");auto unicode=saved_directory/L"patched-\u8d44\u6599-\u00e9.bin";std::filesystem::remove(unicode,ignored);check(bool(export_patched(*session->snapshot(),unicode,ReplacePolicy::fail_if_exists,{})) && read_file(unicode)==bytes({0x90,0xc3}),"native Unicode output succeeds after cwd changes");session.reset();reopened.reset();store.reset();std::filesystem::remove(absolute_project,ignored);for(auto suffix:{L"-wal",L"-shm"}){auto side=absolute_project;side+=suffix;std::filesystem::remove(side,ignored);}
}
void virtual_alias_tests(const std::filesystem::path& directory){
    auto data=pe_fixture();put(data,0x86,2,2);put(data,0xd0,0x3000,4);put_text(data,0x1b0,".alias");put(data,0x1b8,2,4);put(data,0x1bc,0x2000,4);put(data,0x1c0,0x200,4);put(data,0x1c4,0x200,4);put(data,0x1d4,0x60000020,4);
    Fixture fixture(data,{Format::pe,{}});auto initial=fixture.session->snapshot();if(!initial->loaded)throw std::runtime_error(initial->reason);auto patched=fixture.session->execute(PatchBytes{Address{{0},0x140002000},bytes({0xcc})},0,{});if(!patched)throw std::runtime_error(patched.error().message);check(true,"second PE virtual alias accepts a canonical file patch");auto snapshot=patched.value();if(!snapshot->loaded)throw std::runtime_error(snapshot->reason);check(snapshot->loaded->image->read(Address{{0},0x140001000},1).value()[0]==std::byte{0xcc} && snapshot->loaded->image->read(Address{{0},0x140002000},1).value()[0]==std::byte{0xcc},"both virtual aliases observe the same effective patch");data[0x200]=std::byte{0xcc};auto output=directory/L"alias-patched.bin";std::error_code ignored;std::filesystem::remove(output,ignored);check(bool(export_patched(*snapshot,output,ReplacePolicy::fail_if_exists,{})) && read_file(output)==data,"aliased VA patch exports exactly one changed file byte");
}
}
void persistent_round_trip_tests(const std::filesystem::path& directory){
    std::vector<std::byte> original(257);for(size_t i=0;i<original.size();++i)original[i]=std::byte((i*29+3)&255);
    Fixture fixture(original);auto expected=original;
    const auto equals=[&](const ByteStorage& storage,uint64_t offset,const std::vector<std::byte>& value){auto view=storage.read_at({offset},value.size());return view && std::equal(view.value().bytes.begin(),view.value().bytes.end(),value.begin(),value.end());};
    const auto first=bytes({0xcc,0x90,0xeb});
    check(bool(fixture.session->execute(PatchBytes{Address{{0},0x1000+31},first},0,{})),"address patch enters the persistent overlay");
    std::copy(first.begin(),first.end(),expected.begin()+31);
    const auto second=bytes({0x41,0x42,0x43,0x44});
    check(bool(fixture.session->execute(PatchBytes{FileOffset{33},second},0,{})),"overlapping file patch replaces the address patch");
    std::copy(second.begin(),second.end(),expected.begin()+33);
    check(bool(fixture.session->undo({})) && equals(*fixture.session->snapshot()->effective,31,first),
          "undo restores the preceding overlapping overlay");
    check(bool(fixture.session->redo({})),"redo reapplies the overlapping overlay");
    fixture.session.reset();fixture.store.reset();
    check(std::filesystem::remove(fixture.input.path),"persistent overlay no longer depends on the external input");
    auto reopened=ProjectStore::open(fixture.project,ProjectMode::read_write,{}).value();
    auto session=ProjectSession::attach(reopened,{},{}).value();
    check(equals(*session->snapshot()->effective,0,expected),
          "reopened project reconstructs exact current patched bytes");
    check(bool(session->undo({})),"reopened patch history remains undoable");
    auto previous=original;std::copy(first.begin(),first.end(),previous.begin()+31);
    check(equals(*session->snapshot()->effective,0,previous),
          "reopened undo reconstructs the exact prior overlay");
    check(bool(session->redo({})) && equals(*session->snapshot()->effective,0,expected),
          "reopened redo reconstructs the exact current overlay");
    const auto output=directory/L"persistent-round-trip.bin";std::error_code ignored;std::filesystem::remove(output,ignored);
    auto receipt=export_patched(*session->snapshot(),output,ReplacePolicy::fail_if_exists,{}).value();
    auto exported=read_file(output);
    check(exported==expected && receipt.bytes==expected.size() && hash_source(*FileStorage::open(output).value(),{}).value()==receipt.sha256,
          "round-trip export is byte exact and its receipt validates reopened output");
}
int HEXLAB_TEST_MAIN(int argc,hexlab_test_arg_char** argv){return run([&]{const auto directory=argc==2?hexlab_test_path(argv[1]):std::filesystem::current_path()/"patch-export-artifacts";std::filesystem::create_directories(directory);exact_tests(directory);failure_tests(directory);alias_tests(directory);empty_and_file_only_tests(directory);path_stability_tests(directory);virtual_alias_tests(directory);persistent_round_trip_tests(directory);});}
