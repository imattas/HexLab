#include "pe_internal.hpp"
#include <iterator>

namespace hexlab::pe_detail {
Result<std::size_t> read_imports(const Image& image,const Directory& directory,bool pe64,ImageMetadata& metadata,std::stop_token stop) {
    return guarded([&]() -> std::size_t {
        ImageReader r(image,metadata,stop);
        require(directory.size>=20,"Import directory is shorter than a descriptor");
        std::vector<ImportSymbol> imports;
        std::vector<PeImportSource> provenance;
        bool terminated=false;
        const std::uint64_t width=pe64?8:4;
        const std::uint64_t ordinal_bit=pe64?(std::uint64_t{1}<<63):(std::uint64_t{1}<<31);
        for (std::uint64_t offset=0;offset+20<=directory.size;offset+=20) {
            canceled(stop);
            const auto at=std::uint64_t{directory.location}+offset;
            const auto lookup=r.integer<std::uint32_t>(at);
            const auto timestamp=r.integer<std::uint32_t>(at+4);
            const auto chain=r.integer<std::uint32_t>(at+8);
            const auto name=r.integer<std::uint32_t>(at+12);
            const auto iat=r.integer<std::uint32_t>(at+16);
            if (!(lookup|timestamp|chain|name|iat)) {terminated=true;break;}
            require(name!=0 && iat!=0,"Import descriptor lacks library name or IAT");
            auto [library,library_source]=r.sourced_string(name);
            require(!library.empty(),"Empty import library name");
            const auto table=lookup?lookup:iat;
            bool thunk_end=false;
            (void)r.initialized_extent(table);
            const auto capacity=std::min<std::uint64_t>(record_limit,(metadata.image_size-table)/width);
            for (std::uint64_t index=0;index<capacity;++index) {
                canceled(stop);
                const auto thunk_at=std::uint64_t{table}+index*width;
                const auto iat_at=std::uint64_t{iat}+index*width;
                const auto value=pe64?r.integer<std::uint64_t>(thunk_at):r.integer<std::uint32_t>(thunk_at);
                if (value==0) {thunk_end=true;break;}
                (void)r.bytes(iat_at,static_cast<std::size_t>(width));
                ImportSymbol symbol{library,{},{},r.address(thunk_at),r.address(iat_at)};
                PeImportSource source;
                source.descriptor={static_cast<std::uint32_t>(offset/20),r.sources(at,20)};
                source.lookup_thunk=r.sources(thunk_at,width);
                source.iat_thunk=r.sources(iat_at,width);
                source.library_name=library_source;
                if (value&ordinal_bit) {
                    require((value&~(ordinal_bit|0xffffULL))==0,"Import ordinal thunk has reserved bits set");
                    symbol.ordinal=static_cast<std::uint16_t>(value&0xffff);
                } else {
                    require(value<=UINT32_MAX,"Import name thunk is not an RVA");
                    (void)r.integer<std::uint16_t>(value);
                    auto [symbol_name,symbol_source]=r.sourced_string(value+2);
                    symbol.name=std::move(symbol_name);
                    source.symbol_name=std::move(symbol_source);
                    require(!symbol.name->empty(),"Empty imported symbol name");
                }
                if (imports.size()>=record_limit) throw Failure{{ErrorCode::resource_limit,"Import record budget reached"}};
                imports.push_back(std::move(symbol));
                provenance.push_back(std::move(source));
            }
            require(thunk_end,"Import thunk table lacks a bounded terminator");
        }
        require(terminated,"Import descriptor table lacks a directory-bounded terminator");
        const auto count=imports.size();
        metadata.imports.insert(metadata.imports.end(),std::make_move_iterator(imports.begin()),std::make_move_iterator(imports.end()));
        if (!metadata.pe) metadata.pe.emplace();
        metadata.pe->imports.insert(metadata.pe->imports.end(),std::make_move_iterator(provenance.begin()),std::make_move_iterator(provenance.end()));
        return count;
    });
}
}
