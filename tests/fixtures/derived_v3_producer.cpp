#include <hexlab/loaders/elf.hpp>
#include <hexlab/loaders/recipe.hpp>
#include <hexlab/analysis/derived_cache.hpp>
#include <fstream>
#include <iostream>
#include <stdexcept>
using namespace hexlab;
template<class T> T take(Result<T> result){if(!result)throw std::runtime_error(result.error().message);return std::move(result.value());}
int wmain(int argc,wchar_t** argv) {
    try {
        if(argc!=3)throw std::runtime_error("Expected authored provider ELF and output payload");
        auto storage=take(FileStorage::open(argv[1]));
        auto loaded=take(load_elf(storage,{}));
        AnalysisKey key;
        key.input={storage->size(),take(hash_source(*storage,{}))};
        key.engine_fingerprint=function_engine_fingerprint();
        Sha256 recipe;take(recipe.update(take(encode_recipe({Format::elf,{}}))));key.recipe_fingerprint=recipe.digest();
        auto proposal=take(analyze_derived(loaded.image,std::make_shared<const ImageMetadata>(loaded.metadata),{}, {},key,{}));
        bool symbol_root=false;
        for(const auto& function:proposal.functions->functions)for(const auto& seed:function->seeds)
            if(seed.kind==FunctionSeedKind::symbol)symbol_root=true;
        if(!symbol_root || derived_cache_version!=3)throw std::runtime_error("Need genuine current v3 ELF-symbol-root producer");
        const auto payload=take(encode_derived(proposal,{}));
        const auto decoded=take(decode_derived(payload,*loaded.image,loaded.metadata,{}, {},key,{}));
        if(decoded.functions->functions.size()!=proposal.functions->functions.size())throw std::runtime_error("Live producer roundtrip failed");
        std::ofstream file(std::filesystem::path(argv[2]),std::ios::binary);
        file.write(reinterpret_cast<const char*>(payload.data()),static_cast<std::streamsize>(payload.size()));
        if(!file)throw std::runtime_error("Cannot write captured payload");
        std::cout<<"Genuine v3 payload with ELF symbol roots: "<<payload.size()<<" bytes; "<<proposal.functions->functions.size()<<" functions\n";
        return 0;
    } catch(const std::exception& error){std::cerr<<error.what()<<'\n';return 1;}
}
