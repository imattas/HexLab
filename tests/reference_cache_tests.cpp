#include "hexlab/database/cache.hpp"
#include "hexlab/database/transaction.hpp"
#include "hexlab/analysis/references.hpp"
#include "testing.hpp"
#include "support/checks.hpp"
#include "support/fixture_files.hpp"
#include "support/analysis_fixture.hpp"
using namespace hexlab;
using namespace hexlab::database;
using namespace hexlab_test;
struct ProjectFixture {
    FixtureFile marker{std::span<const std::byte>{}};std::filesystem::path path=marker.path.wstring()+L".hxproj";
    ~ProjectFixture(){std::error_code ignored;std::filesystem::remove(path,ignored);auto wal=path;wal+=L"-wal";std::filesystem::remove(wal,ignored);auto shm=path;shm+=L"-shm";std::filesystem::remove(shm,ignored);}
};
int main(){return run([]{
    ProjectFixture project;auto store=ProjectStore::create(project.path,{}).value();MemoryStorage original(bytes({0xe8,1,0,0,0,0xc3,0xc3}));
    LoadRecipe recipe{Format::raw,RawOptions{Architecture::x86_64,ExecutionMode::x86_64,{{0},0x1000},true,false,true,{}}};check(bool(store->import_input(original,recipe,{},{})),"cache fixture imported");
    auto state=store->snapshot().value();AnalysisKey key;key.input=state->input;key.engine_fingerprint=function_engine_fingerprint();Sha256 recipe_hash;check(bool(recipe_hash.update(encode_recipe(recipe).value())),"canonical recipe fingerprint computed independently");key.recipe_fingerprint=recipe_hash.digest();
    auto loaded=load_image(store->materialize_input({}).value(),recipe,{}).value();auto functions=recover_functions(*loaded.image,loaded.metadata,{}, {},key,{}).value();auto references=derive_references(*functions,loaded.metadata,{},{}).value();
    auto missing=store->load_reference_cache(key,{}).value();check(missing.status==CacheStatus::absent && !missing.index && !missing.reason.empty(),"absent cache reports a recompute reason");
    check(bool(store->store_reference_cache(key,*references,{})),"keyed reference index persists without a user command");
    check(store->snapshot().value()->revisions.edit==0 && store->snapshot().value()->history_cursor==0,"cache write does not enter edit history");
    auto hit=store->load_reference_cache(key,{}).value();check(hit.status==CacheStatus::hit && hit.index && hit.index->all().size()==1 && hit.index->incoming(Address{{0},0x1006},{}).value().total==1,"cached typed references restore query indexes");
    Annotation annotation{1,Address{{0},0x1000},"cache_owner","preserve this user value"};StateDelta rename{{AnnotationChange{{},annotation}}};check(bool(store->commit(0,rename,0,{})),"annotation edit committed independently of derived facts");
    check(store->load_reference_cache(key,{}).value().status==CacheStatus::hit,"presentation-only edit keeps byte/decision cache current");
    auto sql=Connection::open(project.path,OpenMode::read_write,{}).value();check(bool(sql->execute("UPDATE derived_cache SET engine_version=10")),"previous reference algorithm cache version fixture written");sql.reset();
    auto incompatible=store->load_reference_cache(key,{}).value();check(incompatible.status==CacheStatus::incompatible && !incompatible.index && !incompatible.reason.empty(),"previous reference algorithm cache is discarded with a recompute reason");
    testing::fail_next_commit(ErrorCode::io);auto failed=store->store_reference_cache(key,*references,{});check(!failed && failed.error().code==ErrorCode::io && store->load_reference_cache(key,{}).value().status==CacheStatus::incompatible,"failed cache transaction preserves preceding row");
    check(bool(store->store_reference_cache(key,*references,{})),"valid recomputed cache replaces incompatible record");
    sql=Connection::open(project.path,OpenMode::read_write,{}).value();check(bool(sql->execute("UPDATE derived_cache SET payload=x'00'")),"corrupt cache fixture written");sql.reset();
    auto corrupt=store->load_reference_cache(key,{}).value();check(corrupt.status==CacheStatus::corrupt && !corrupt.index && !corrupt.reason.empty(),"corrupt payload requests recomputation without losing user state");
    auto readonly=ProjectStore::open(project.path,ProjectMode::read_only,{}).value();check(readonly->load_reference_cache(key,{}).value().status==CacheStatus::corrupt && !readonly->store_reference_cache(key,*references,{}),"readonly cache lookup never repairs or writes derived state");readonly.reset();
    check(store->snapshot().value()->user->annotations[0]==annotation && store->snapshot().value()->revisions.edit==1 && store->snapshot().value()->history_cursor==1,"cache misses and failures preserve exact annotation and history");
    check(bool(store->store_reference_cache(key,*references,{})),"cache restored before byte edit");StateDelta patch{{PatchChange{{},{{{0},bytes({0xe8}),bytes({0xe9})}}}}};check(bool(store->commit(1,patch,0,{})),"real byte edit changes cache source revision");
    check(store->load_reference_cache(key,{}).value().status==CacheStatus::stale && !store->store_reference_cache(key,*references,{}),"stale worker key cannot load or replace current derived facts");
    std::stop_source stop;stop.request_stop();auto canceled=store->load_reference_cache(key,stop.get_token());check(!canceled && canceled.error().code==ErrorCode::canceled,"cache operations observe cancellation");
});}
