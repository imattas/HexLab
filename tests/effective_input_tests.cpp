#include "hexlab/loaders/recipe.hpp"
#include "hexlab/image/patches.hpp"
#include "hexlab/analysis/analysis.hpp"
#include "support/checks.hpp"
#include "support/pe_fixture.hpp"
using namespace hexlab;
using namespace hexlab_test;
void recipe_tests(){
    auto literal=bytes({1,0,2});auto pe=decode_recipe(literal).value();
    check(pe.format==Format::pe && !pe.raw && encode_recipe(pe).value()==literal,"PE recipe has canonical literal version and format");
    check(!encode_recipe({Format::automatic,{}}),"automatic detection is not a durable recipe");
    LoadRecipe with_pdb{Format::pe, {}, {}, std::filesystem::path("symbols\\sample.pdb")};
    auto pdb_recipe = encode_recipe(with_pdb);
    check(pdb_recipe && decode_recipe(pdb_recipe.value()) &&
          decode_recipe(pdb_recipe.value()).value().pdb_path == with_pdb.pdb_path &&
          encode_recipe(decode_recipe(pdb_recipe.value()).value()).value() == pdb_recipe.value(),
          "PE recipe persists and roundtrips a local PDB path");
    auto invalid_pdb_recipe = pdb_recipe.value(); invalid_pdb_recipe[6] = std::byte{0};
    check(!decode_recipe(invalid_pdb_recipe), "PE recipe rejects an empty PDB path");
    check(!decode_recipe(bytes({2,0,2})) && !decode_recipe(bytes({1,0,99})) && !decode_recipe(bytes({1,0,2,0})),"unknown version format and trailing data rejected");
    RawOptions options{Architecture::x86_64,ExecutionMode::x86_64,{{0xffffffff},0xfffffffffffff000},true,false,true,Address{{0xffffffff},0xfffffffffffff001}};
    LoadRecipe raw{Format::raw,options};auto encoded=encode_recipe(raw).value();auto decoded=decode_recipe(encoded).value();
    check(encoded==bytes({1,0,1,2,3,5,255,255,255,255,255,255,255,255,255,255,240,0,1,255,255,255,255,255,255,255,255,255,255,240,1}),"raw recipe literal uses explicit flags and big endian unsigned fields");
    check(decoded.raw->base==options.base && decoded.raw->entry==options.entry && encode_recipe(decoded).value()==encoded,"raw recipe preserves full unsigned address and domain");
    for(size_t i=0;i<encoded.size();++i)check(!decode_recipe(std::span(encoded).first(i)),"every truncated recipe fails");
    FixtureFile empty({});auto source=FileStorage::open(empty.path).value();auto empty_raw=raw;empty_raw.raw->entry.reset();
    check(load_image(source,empty_raw,{}).value().image->storage()->size()==0,"raw recipe supports empty original");
    std::stop_source stopped;stopped.request_stop();check(load_image(source,raw,stopped.get_token()).error().code==ErrorCode::canceled,"recipe load cancellation propagated");
}
void effective_tests(){
    auto data=pe_metadata_fixture();put_text(data,0x220,"original-string");FixtureFile fixture(data);auto original=FileStorage::open(fixture.path).value();
    std::vector<PatchSpan> changes{{{0x200},bytes({0x90}),bytes({0xc3})},{{0x220},bytes({'o'}),bytes({'e'})},{{0x492},bytes({'F'}),bytes({'P'})}};
    auto source=make_overlay(original,changes).value();auto loaded=load_image(source,{Format::pe,{}},{}).value();
    check(loaded.image->storage()==source,"published image retains effective untracked storage");
    check(loaded.metadata.imports[0].name=="PixtureFn","import parsing reads effective bytes");
    check(loaded.metadata_reads.intersects({0x492},1).value(),"metadata dependency includes import name");
    check(!loaded.metadata_reads.intersects({0x220},1).value(),"code/string bytes are not header dependencies");
    auto analysis=analyze(*loaded.image,{},{}).value();
    check(analysis.instructions.size()==1,"code analysis sees replacement return");
    bool found=false;for(const auto& value:analysis.strings.records)if(value.preview=="eriginal-string")found=true;
    check(found,"string analysis sees effective bytes");
    check(!loaded.metadata_reads.intersects({0x220},1).value(),"later analysis cannot contaminate metadata dependencies");
    check(original->read_at({0x200},1).value().bytes[0]==std::byte{0x90},"loader never changes original bytes");
    auto moved=changes;moved.push_back({{0xb3},bytes({0x40}),bytes({0x50})});
    auto rebased=load_image(make_overlay(original,moved).value(),{Format::pe,{}},{}).value();
    check(rebased.metadata.preferred_base==0x150000000ULL && rebased.image->layout().entries[0].offset==0x150001000ULL,"effective header updates metadata and virtual mapping together");
    changes.push_back({{0},bytes({'M'}),bytes({'X'})});
    check(!load_image(make_overlay(original,changes).value(),{Format::pe,{}},{}),"invalid effective header returns loader error");
    auto automatic=load_image(source,{Format::automatic,{}},{}).value();check(automatic.metadata.format=="PE32+","automatic import resolves PE");
}
int main(){return run([]{recipe_tests();effective_tests();});}
