#include "hexlab/database/input.hpp"
#include "hexlab/database/backup.hpp"
#include "hexlab/database/transaction.hpp"
#include "hexlab/core/encoding.hpp"
#include "testing.hpp"
#include "support/checks.hpp"
#include "support/fixture_files.hpp"
#include <algorithm>
using namespace hexlab;
using namespace hexlab::database;
using namespace hexlab_test;
struct ProjectFixture {
    FixtureFile marker{std::span<const std::byte>{}};std::filesystem::path path=marker.path.wstring()+L".hxproj";
    ~ProjectFixture(){std::error_code ignored;std::filesystem::remove(path,ignored);auto wal=path;wal+=L"-wal";std::filesystem::remove(wal,ignored);auto shm=path;shm+=L"-shm";std::filesystem::remove(shm,ignored);}
};
LoadRecipe raw_recipe(){return {Format::raw,RawOptions{Architecture::x86_64,ExecutionMode::x86_64,{{2},0x4000000000000000},true,true,false,Address{{2},0x4000000000000001}}};}
void input_tests(){
    std::vector<std::byte> data(1024*1024+13);for(size_t i=0;i<data.size();++i)data[i]=std::byte(i*13+7);
    FixtureFile input(data);auto unicode=input.path;unicode+=L"-\u8d44\u6599-\u00e9.bin";std::filesystem::rename(input.path,unicode);input.path=unicode;
    auto original=FileStorage::open(input.path).value();const auto identity=hash_source(*original,{}).value();
    ProjectFixture project;auto store=ProjectStore::create(project.path,{}).value();check(bool(store->import_input(*original,raw_recipe(),input.path,{})),"multichunk input imports with complete raw recipe");
    auto state=store->snapshot().value();check(state->input.size==data.size() && state->input.sha256==identity && encode_recipe(state->recipe).value()==encode_recipe(raw_recipe()).value(),"input identity and recipe persist together");
    check(state->provenance.has_value() && state->provenance->native_path==input.path,"native Unicode provenance preserved");
    auto sql=Connection::open(project.path,OpenMode::read_only,{}).value();auto chunks=sql->prepare("SELECT position,data FROM input_chunks ORDER BY position").value();size_t count=0,total=0;Sha256 embedded;
    while(chunks->step().value()){const auto at=decode_u64(chunks->blob(0).value()).value();const auto value=chunks->blob(1).value();check(at==total && value.size()<=1024*1024,"SQL chunks have independent canonical offsets and bounded extents");check(std::equal(value.begin(),value.end(),data.begin()+total),"embedded chunks equal literal source bytes");check(bool(embedded.update(value)),"embedded hash chunk accepted");total+=value.size();++count;}
    check(count==2 && total==data.size() && embedded.digest()==identity,"independent SQL reconstruction matches original stream identity");chunks.reset();sql.reset();original.reset();
    check(std::filesystem::remove(input.path),"external original can be removed after import");
    auto source=store->materialize_input({}).value();auto backing=std::dynamic_pointer_cast<const FileStorage>(source);check(bool(backing),"embedded source materializes to stable mapped storage");const auto backing_path=backing->backing_path();
    check(source->size()==data.size() && hash_source(*source,{}).value()==identity && source->read_at({1024*1024-1},4).value().bytes[0]==data[1024*1024-1],"mapped extraction verifies identity across chunk boundaries");
    auto retained=source->read_at({0},16).value();backing.reset();source.reset();store.reset();check(std::filesystem::exists(backing_path) && retained.bytes[0]==data[0],"last byte view retains temporary backing after store closes");retained={};check(!std::filesystem::exists(backing_path),"last view release closes mapping before removing owned backing");
    auto reopened=ProjectStore::open(project.path,ProjectMode::read_only,{}).value();check(reopened->mode()==ProjectMode::read_only && hash_source(*reopened->materialize_input({}).value(),{}).value()==identity,"readonly reopen needs no external original");
    std::stop_source stop;stop.request_stop();check(!reopened->materialize_input(stop.get_token()),"pre-canceled extraction returns cancellation even when cached");
}
void cancellation_tests(){
    FixtureFile input(std::vector<std::byte>(1024*1024+1,std::byte{7}));auto source=FileStorage::open(input.path).value();ProjectFixture project;auto store=ProjectStore::create(project.path,{}).value();
    check(bool(store->import_input(*source,raw_recipe(),input.path,{})),"cancellation fixture imported");check(!store->import_input(*source,raw_recipe(),input.path,{}),"input cannot be replaced underneath an initialized project");store.reset();
    std::stop_source stop;std::filesystem::path temporary;
    testing::set_input_callback([&](uint64_t offset,const std::filesystem::path& path){if(offset>0){temporary=path;stop.request_stop();}});
    auto canceled=ProjectStore::open(project.path,ProjectMode::read_only,stop.get_token());check(!canceled && canceled.error().code==ErrorCode::canceled,"open interrupts bounded input extraction");testing::set_input_callback({});
    check(!temporary.empty() && !std::filesystem::exists(temporary),"cancellation removes only its owned temporary backing");
    ProjectFixture empty;auto blank=ProjectStore::create(empty.path,{}).value();FixtureFile zero({});auto no_bytes=FileStorage::open(zero.path).value();auto recipe=raw_recipe();recipe.raw->entry.reset();check(bool(blank->import_input(*no_bytes,recipe,{},{})) && blank->materialize_input({}).value()->size()==0,"empty input import and extraction are valid");
}
void corruption_tests(){
    for(int kind=0;kind<4;++kind){
        FixtureFile input(std::vector<std::byte>(1024*1024+1,std::byte{9}));auto source=FileStorage::open(input.path).value();ProjectFixture project;auto store=ProjectStore::create(project.path,{}).value();check(bool(store->import_input(*source,raw_recipe(),input.path,{})),"corruption fixture imported");store.reset();
        auto sql=Connection::open(project.path,OpenMode::read_write,{}).value();
        if(kind==0)check(bool(sql->execute("DELETE FROM input_chunks WHERE position=x'0000000000100000'")),"missing final chunk fixture created");
        if(kind==1)check(bool(sql->execute("UPDATE input_chunks SET position=x'0000000000000001' WHERE position=x'0000000000000000'")),"noncontiguous chunk fixture created");
        if(kind==2)check(bool(sql->execute("UPDATE project SET input_sha256=zeroblob(32)")),"hash mismatch fixture created");
        if(kind==3)check(bool(sql->execute("PRAGMA ignore_check_constraints=ON")) && bool(sql->execute("UPDATE input_chunks SET data=zeroblob(1048577) WHERE position=x'0000000000000000'")),"oversized persisted chunk fixture created");sql.reset();
        check(!ProjectStore::open(project.path,ProjectMode::read_write,{}),"invalid embedded stream never publishes a project");
    }
}
void backup_tests(){
    FixtureFile input(bytes({0x90,0xc3}));auto source=FileStorage::open(input.path).value();ProjectFixture project,destination;auto store=ProjectStore::create(project.path,{}).value();check(bool(store->import_input(*source,raw_recipe(),input.path,{})),"backup fixture imported");
    const auto original_uuid=store->snapshot().value()->uuid;auto saved=store->save_as(destination.path,ReplacePolicy::fail_if_exists,{}).value();check(saved.uuid!=original_uuid && store->snapshot().value()->uuid==original_uuid,"Save As creates a new identity without changing source");
    auto reopened=ProjectStore::open(destination.path,ProjectMode::read_only,{}).value();check(reopened->snapshot().value()->uuid==saved.uuid && reopened->materialize_input({}).value()->size()==2,"published backup is self-contained and reopenable");reopened.reset();
    auto duplicate=store->save_as(destination.path,ReplacePolicy::fail_if_exists,{});check(!duplicate && duplicate.error().code==ErrorCode::conflict,"Save As preserves an existing target unless replace is explicit");
    check(!store->save_as(project.path,ReplacePolicy::replace_existing,{}),"Save As rejects its own source file identity");
    std::stop_source stop;stop.request_stop();auto canceled=store->save_as(destination.path,ReplacePolicy::replace_existing,stop.get_token());check(!canceled && canceled.error().code==ErrorCode::canceled,"canceled save does not publish");
    reopened=ProjectStore::open(destination.path,ProjectMode::read_only,{}).value();check(reopened->snapshot().value()->uuid==saved.uuid,"canceled save preserves preceding destination");reopened.reset();
    auto replacement_result=store->save_as(destination.path,ReplacePolicy::replace_existing,{});if(!replacement_result)throw std::runtime_error(replacement_result.error().message);
    auto replacement=replacement_result.value();check(replacement.uuid!=saved.uuid,"explicit replacement publishes another complete project identity");
    auto before_fault=hash_source(*FileStorage::open(destination.path).value(),{}).value();testing::fail_next_publication(ErrorCode::io);
    auto failed=store->save_as(destination.path,ReplacePolicy::replace_existing,{});check(!failed && failed.error().code==ErrorCode::io && hash_source(*FileStorage::open(destination.path).value(),{}).value()==before_fault,"publication failure restores preceding destination without changing its bytes");
    std::stop_source during;testing::set_backup_callback([&](auto phase,const auto&){if(phase==testing::BackupPhase::before_publish)during.request_stop();});
    auto stopped=store->save_as(destination.path,ReplacePolicy::replace_existing,during.get_token());testing::set_backup_callback({});check(!stopped && stopped.error().code==ErrorCode::canceled,"cancellation after backup and before publication preserves destination");
    reopened=ProjectStore::open(destination.path,ProjectMode::read_only,{}).value();check(reopened->snapshot().value()->uuid==replacement.uuid,"late cancellation leaves preceding project identity intact");reopened.reset();
    auto alias=project.path;alias+=L"-alias.hxproj";std::filesystem::create_hard_link(project.path,alias);check(!store->save_as(alias,ReplacePolicy::replace_existing,{}),"native file identity rejects a hard-link source alias");std::filesystem::remove(alias);
    auto live=ProjectStore::open(destination.path,ProjectMode::read_write,{}).value();auto busy=store->save_as(destination.path,ReplacePolicy::replace_existing,{});check(!busy && busy.error().code==ErrorCode::busy,"active destination cannot be replaced");live.reset();
    ProjectFixture published;bool after_publish_observed=false;
    testing::set_backup_callback([&](auto phase,const auto& path){if(phase==testing::BackupPhase::after_publish){auto recovered=ProjectStore::open(path,ProjectMode::read_only,{});after_publish_observed=bool(recovered) && recovered.value()->snapshot().value()->input.size==2;}});
    auto durable=store->save_as(published.path,ReplacePolicy::fail_if_exists,{});testing::set_backup_callback({});
    check(bool(durable) && after_publish_observed,"post-publication checkpoint sees a complete, reopenable project after native publication durability work");
    auto journal=destination.path;journal+=L"-wal";write_file(journal,bytes({1}));auto journal_error=store->save_as(destination.path,ReplacePolicy::replace_existing,{});check(!journal_error && journal_error.error().code==ErrorCode::busy && std::filesystem::file_size(journal)==1,"nonempty destination journal is never moved or deleted");std::filesystem::remove(journal);
}
void import_failure_tests(){
    struct ShortSource final:ByteStorage {
        std::shared_ptr<std::vector<std::byte>> data=std::make_shared<std::vector<std::byte>>(4,std::byte{1});
        uint64_t size()const noexcept override{return 4;}
        Result<ByteView> read_at(FileOffset,size_t)const override{return ByteView{data,std::span(*data).first(1)};}
    } short_source;
    ProjectFixture project;auto store=ProjectStore::create(project.path,{}).value();auto failed=store->import_input(short_source,raw_recipe(),{},{});check(!failed && failed.error().code==ErrorCode::io && store->snapshot().value()->input.size==0 && !store->snapshot().value()->provenance,"short source import rolls back all metadata");
    FixtureFile input(std::vector<std::byte>(1024*1024+1,std::byte{3}));auto original=FileStorage::open(input.path).value();std::stop_source stop;
    struct CancelSource final:ByteStorage {
        const ByteStorage& base;std::stop_source& stop;
        CancelSource(const ByteStorage& value,std::stop_source& signal):base(value),stop(signal){}
        uint64_t size()const noexcept override{return base.size();}
        Result<ByteView> read_at(FileOffset at,size_t count)const override{if(at.value>0)stop.request_stop();return base.read_at(at,count);}
    } canceled_source{*original,stop};
    auto canceled=store->import_input(canceled_source,raw_recipe(),input.path,stop.get_token());check(!canceled && canceled.error().code==ErrorCode::canceled,"midstream canceled import rolls back staged chunks");
    auto sql=Connection::open(project.path,OpenMode::read_only,{}).value();auto count=sql->prepare("SELECT count(*) FROM input_chunks").value();check(count->step().value() && count->integer(0).value()==0,"failed imports leave no embedded rows");count.reset();sql.reset();
    check(bool(store->import_input(*original,raw_recipe(),input.path,{})),"fresh import succeeds after failed attempts");
    auto mismatch=store->commit(0,StateDelta{{PatchChange{{},{{{0},bytes({0xff}),bytes({0xcc})}}}}},0,{});check(!mismatch && store->snapshot().value()->revisions.edit==0,"patch original bytes are checked against embedded input before commit");
}
int main(){return run([]{input_tests();cancellation_tests();corruption_tests();backup_tests();import_failure_tests();});}
