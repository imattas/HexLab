#include <hexlab/loaders/raw.hpp>
#include <hexlab/analysis/graph.hpp>
#include <hexlab/workspace/navigation.hpp>
#include <windows.h>
#include <iostream>
#include <stdexcept>
#include <type_traits>

using namespace hexlab;
template<class T> T take(Result<T> result) {
    if(!result) throw std::runtime_error(result.error().message);
    return std::move(result.value());
}
void require(bool value, const char* message) {
    if(!value) throw std::runtime_error(message);
}
int wmain(int argc, wchar_t** argv) {
    try {
        static_assert(!std::is_same_v<X86LogicalAddress,X86LinearAddress>);
        static_assert(!std::is_same_v<X86LinearAddress,X86PhysicalAddress>);
        require(argc==3,"Expected installed prefix and authored raw fixture");
        const auto profile=take(parse_x86_profile(
            "hexlab-x86-profile 1\nenvironment real386\na20 enabled\nload 0x10010\n"
            "entry 7 0x10\nstack none\ndomains 2\ndomain 7 0x1000 code \"text\" real\n"
            "domain 2 0x1001 data \"alias\" real\n"));
        const auto options=take(make_x86_raw_options(profile));
        const auto storage=take(FileStorage::open(argv[2]));
        const auto image=take(load_raw(storage,options,{}));
        const auto address=take(parse_segment_address(*image,L"1000:0010"));
        require(address==Address{{7},0x10},"Selector resolves declared code domain");
        require(format_location(address,image.get())=="1000:0010","Installed formatter preserves selector");
        require(take(image->to_file_offset({{2},0})).value==0,"Alias shares canonical backing");
        require(!image->to_address({0}),"Reverse mapping refuses ambiguous alias");
        const auto decoded=take(decode_at(*image,address));
        require(decoded.instruction.has_value(),"Installed decoder accepts authored first instruction");
        const auto functions=take(recover_functions(*image,{}, {},{},{}));
        require(!functions->functions.empty(),"Installed recovery retains code root");
        const auto refs=take(derive_references(*image,*functions,{}, {},{}));
        std::size_t callbacks=0;
        GraphLabels labels;
        labels.location_formatter=[&](Location at){++callbacks;return format_location(at,image.get());};
        const auto graph=take(build_graph(*functions,*refs,GraphKind::function_cfg,
                                        functions->functions.front()->id,{},labels,{}));
        require(callbacks>0 && !graph->nodes.empty(),"Consumer formatter callback crosses DLL boundary");
        const auto bin=std::filesystem::weakly_canonical(std::filesystem::path(argv[1])/L"bin");
        for(const auto name:{L"hexlab_core.dll",L"hexlab_image.dll",L"hexlab_processors.dll",
                             L"hexlab_loaders.dll",L"hexlab_analysis.dll",L"hexlab_database.dll",
                             L"hexlab_workspace.dll",L"hexlab_sqlite3.dll"}) {
            wchar_t path[32768]{};
            const auto handle=GetModuleHandleW(name);
            require(handle && GetModuleFileNameW(handle,path,32768)>0,"Installed runtime is loaded");
            require(std::filesystem::equivalent(std::filesystem::path(path).parent_path(),bin),
                    "Runtime resolves from installed bin");
        }
        require(!GetModuleHandleW(L"wxbase32ud_vc_x64_custom.dll"),"SDK consumer remains GUI-free");
        std::cout<<"Installed segmented SDK: profiles, aliases, decode, recovery, graph callback and runtime paths passed\n";
        return 0;
    } catch(const std::exception& error) {
        std::cerr<<error.what()<<'\n';
        return 1;
    }
}
