#include "hexlab/workspace/project.hpp"
#include "hexlab/workspace/navigation.hpp"
#include "hexlab/analysis/derived_cache.hpp"
#define NOMINMAX
#include <windows.h>
#include <fstream>
#include <iostream>
using namespace hexlab;
template<class T>T take(Result<T> result){if(!result)throw std::runtime_error(result.error().message);return std::move(result.value());}
void write(const std::filesystem::path &path,std::span<const std::byte> data){
    if(std::filesystem::exists(path))throw std::runtime_error("Immutable capture output already exists");
    std::ofstream out(path,std::ios::binary);out.write(reinterpret_cast<const char *>(data.data()),data.size());
    if(!out)throw std::runtime_error("Capture write failed");
}
int wmain(int argc,wchar_t **argv){try{
    if(argc!=2)return 2;
    const std::filesystem::path root(argv[1]);
    for(const auto *name:{L"hexlab_core.dll",L"hexlab_image.dll",L"hexlab_processors.dll",L"hexlab_loaders.dll",
                         L"hexlab_analysis.dll",L"hexlab_database.dll",L"hexlab_workspace.dll",L"hexlab_sqlite3.dll"}){
        wchar_t path[32768];const auto module=GetModuleHandleW(name);
        const auto length=module ? GetModuleFileNameW(module,path,32768):0;
        if(!length || length>=32768 || std::filesystem::weakly_canonical(std::filesystem::path(path))!=
            std::filesystem::weakly_canonical(root/L"bin"/name))throw std::runtime_error("Captured DLL path mismatch");
        std::wcout<<L"module="<<path<<L'\n';
    }
    const auto project=root/L"producer.hxproj";
    if(std::filesystem::exists(project))throw std::runtime_error("Never rerun over an immutable producer project");
    auto source=take(FileStorage::open(root/L"input.o"));
    auto store=take(database::ProjectStore::create(project,{}));
    take(store->import_input(*source,{Format::elf,{}},root/L"input.o",{}));
    auto session=take(ProjectSession::attach(store,{},{}));
    auto snapshot=take(session->refresh_analysis({}));
    if(!snapshot->loaded->metadata.elf || snapshot->loaded->metadata.elf->header.machine!=183 ||
        snapshot->loaded->image->decode_context().mode!=ExecutionMode::a64 || derived_cache_version!=11 || reference_cache_version!=10)
        throw std::runtime_error("Need real engine27 A64/schema11 state");
    std::optional<Address> owner,callee;
    for(const auto &symbol:snapshot->loaded->metadata.elf->symbols){
        if(symbol.name=="owner")owner=symbol.address;
        if(symbol.name=="callee")callee=symbol.address;
    }
    if(!owner || !callee || owner->space==callee->space)throw std::runtime_error("Need compiler section-domain symbols");
    take(session->execute(Rename{*callee,"captured_a64_callee"},0,{}));
    snapshot=take(session->refresh_analysis({}));
    if(take(project_follow_target(*snapshot,*owner))!=callee || presentation_name(*snapshot,*callee)!="captured_a64_callee")
        throw std::runtime_error("Need actual relocated A64 Follow and user annotation");
    unsigned packed=0,registers=0,owned=0;
    for(const auto &fact:snapshot->functions->instructions){
        if(fact->instruction.context.mode!=ExecutionMode::a64)throw std::runtime_error("Non-A64 fact in capture");
        for(const auto &op:fact->instruction.operands)if(auto relative=std::get_if<RelativeOperand>(&op))
            if(!relative->encoding && (relative->encoded_width==14 || relative->encoded_width==19 || relative->encoded_width==26))++packed;
        for(const auto &reg:fact->instruction.register_reads)if(reg.bank==RegisterBank::arm64_gpr)++registers;
    }
    for(const auto &ref:snapshot->references->all())if(ref.provenance.elf && ref.provenance.instruction_id)++owned;
    if(packed<4 || registers<2 || owned<4)throw std::runtime_error("Need real packed/register/owned relocation facts");
    const auto cache=take(store->read_derived_cache(*snapshot->derived_key,{}));
    if(cache.status!=database::CacheStatus::hit || !cache.payload)throw std::runtime_error("No genuine stored cache");
    const auto refs=take(encode_reference_index(*snapshot->references,{}));
    write(root/L"derived_v11_arm_v27.hxdc",*cache.payload);
    write(root/L"references_v9_arm_v27.hxrf",refs);
    std::cout<<"engine_sha256="<<digest_hex(snapshot->derived_key->engine_fingerprint)
             <<"\ninput_sha256="<<digest_hex(snapshot->state->input.sha256)
             <<"\ninput_bytes="<<source->size()<<"\npayload_bytes="<<cache.payload->size()
             <<"\nreferences_bytes="<<refs.size()<<"\nfunctions="<<snapshot->functions->functions.size()
             <<"\ninstructions="<<snapshot->functions->instructions.size()<<"\nreferences="<<snapshot->references->all().size()
             <<"\npacked_operands="<<packed<<"\nregister_reads="<<registers<<"\nowned_relocations="<<owned
             <<"\nowner="<<owner->space.value<<':'<<owner->offset<<"\ncallee="<<callee->space.value<<':'<<callee->offset<<'\n';
    return 0;
}catch(const std::exception &error){std::cerr<<error.what()<<'\n';return 1;}}

