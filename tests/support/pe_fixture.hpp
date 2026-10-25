#pragma once
#include "fixture_files.hpp"
#include <cstdint>
#include <string_view>
namespace hexlab_test {
inline void put(std::vector<std::byte>& data,std::size_t offset,std::uint64_t value,std::size_t width) {
    if (offset>data.size() || width>data.size()-offset) throw std::runtime_error("Fixture write outside buffer");
    for (std::size_t i=0;i<width;++i) data[offset+i]=static_cast<std::byte>((value>>(8*i))&0xff);
}
inline void put_text(std::vector<std::byte>& data,std::size_t offset,std::string_view text) {
    if (offset>data.size() || text.size()>data.size()-offset) throw std::runtime_error("Fixture string outside buffer");
    for (std::size_t i=0;i<text.size();++i) data[offset+i]=static_cast<std::byte>(text[i]);
}
inline std::vector<std::byte> pe_fixture(bool pe64=true) {
    std::vector<std::byte> data(0x400);
    put_text(data,0,"MZ"); put(data,0x3c,0x80,4); put_text(data,0x80,"PE");
    put(data,0x84,pe64?0x8664:0x14c,2); put(data,0x86,1,2);
    put(data,0x94,pe64?0xf0:0xe0,2); put(data,0x96,0x22,2);
    put(data,0x98,pe64?0x20b:0x10b,2); put(data,0xa8,0x1000,4); put(data,0xac,0x1000,4);
    put(data,pe64?0xb0:0xb4,pe64?0x140000000ULL:0x400000,pe64?8:4);
    put(data,0xb8,0x1000,4); put(data,0xbc,0x200,4);
    put(data,0xd0,0x2000,4); put(data,0xd4,0x200,4); put(data,0xdc,3,2);
    put(data,pe64?0x104:0xf4,16,4);
    const std::size_t section=pe64?0x188:0x178;
    put_text(data,section,".text"); put(data,section+8,0x300,4); put(data,section+12,0x1000,4);
    put(data,section+16,0x200,4); put(data,section+20,0x200,4); put(data,section+36,0x60000020,4);
    data[0x200]=std::byte{0x90}; data[0x201]=std::byte{0xc3};
    return data;
}
inline std::vector<std::byte> pe_metadata_fixture(bool pe64=true) {
    auto data=pe_fixture(pe64); data.resize(0xa00);
    put(data,0x86,2,2); put(data,0xd0,0x3000,4);
    const auto section=pe64?0x1b0u:0x1a0u;
    put_text(data,section,".rdata"); put(data,section+8,0x600,4);put(data,section+12,0x2000,4);
    put(data,section+16,0x600,4);put(data,section+20,0x400,4);put(data,section+36,0x40000040,4);
    const auto dirs=pe64?0x108u:0xf8u;
    put(data,dirs,0x2200,4); put(data,dirs+4,0x100,4);
    put(data,dirs+8,0x2000,4);put(data,dirs+12,40,4);
    put(data,dirs+40,0x2400,4);put(data,dirs+44,12,4);
    put(data,0x400,0x2040,4);put(data,0x40c,0x2080,4);put(data,0x410,0x2060,4);
    const auto width=pe64?8u:4u;
    put(data,0x440,0x2090,width);put(data,0x440+width,pe64?0x8000000000000007ULL:0x80000007,width);
    put(data,0x460,0x2090,width);put(data,0x460+width,pe64?0x8000000000000007ULL:0x80000007,width);
    put_text(data,0x480,"fixture.dll");put_text(data,0x492,"FixtureFn");
    put(data,0x60c,0x2230,4);put(data,0x610,1,4);put(data,0x614,3,4);put(data,0x618,1,4);
    put(data,0x61c,0x2240,4);put(data,0x620,0x2260,4);put(data,0x624,0x2268,4);
    put_text(data,0x630,"fixture.exe");
    put(data,0x640,0x1000,4);put(data,0x644,0x2280,4);put(data,0x648,0x1010,4);
    put(data,0x660,0x2270,4);put(data,0x668,0,2);put_text(data,0x670,"entry");put_text(data,0x680,"other.Target");
    put(data,0x800,0x1000,4);put(data,0x804,12,4);put(data,0x808,pe64?0xa010:0x3010,2);
    return data;
}
inline std::vector<std::byte> pe_delay_import_fixture(bool pe64=true, bool rva_mode=true) {
    auto data=pe_metadata_fixture(pe64);
    const auto dirs=pe64?0x108u:0xf8u;
    put(data,dirs+13*8,0x2300,4); put(data,dirs+13*8+4,64,4);
    const auto base=pe64?0x140000000ULL:0x400000ULL;
    const auto pointer=[&](std::uint32_t rva) { return rva_mode?rva:static_cast<std::uint32_t>(base+rva); };
    put(data,0x700,rva_mode?1:0,4); // RVA-based descriptor (bit zero), or legacy VA-based.
    put(data,0x704,pointer(0x2480),4); // library name
    put(data,0x70c,pointer(0x2460),4); // IAT
    put(data,0x710,pointer(0x2440),4); // INT
    const auto width=pe64?8u:4u;
    const auto name_thunk=pe64?std::uint64_t{0x2490}:pointer(0x2490);
    put(data,0x840,name_thunk,width); put(data,0x840+width,pe64?0x8000000000000009ULL:0x80000009ULL,width);
    put(data,0x860,name_thunk,width); put(data,0x860+width,pe64?0x8000000000000009ULL:0x80000009ULL,width);
    put_text(data,0x880,"delay.dll"); put_text(data,0x892,"DelayedFn");
    return data;
}
inline std::vector<std::byte> pe_codeview_fixture(bool pe64=true) {
    auto data=pe_metadata_fixture(pe64);
    const auto dirs=pe64?0x108u:0xf8u;
    put(data,dirs+6*8,0x2300,4); put(data,dirs+6*8+4,28,4);
    put(data,0x70c,2,4); // IMAGE_DEBUG_TYPE_CODEVIEW
    constexpr std::string_view path="C:\\symbols\\sample.pdb";
    constexpr std::uint32_t record_size=4+16+4+static_cast<std::uint32_t>(path.size())+1;
    put(data,0x710,record_size,4);
    put(data,0x714,0x2320,4); // AddressOfRawData
    put(data,0x718,0x720,4); // PointerToRawData
    put_text(data,0x720,"RSDS");
    for(std::size_t i=0;i<16;++i)data[0x724+i]=static_cast<std::byte>(i+1);
    put(data,0x734,7,4);
    put_text(data,0x738,path);
    return data;
}
inline std::vector<std::byte> pe_bound_import_fixture(bool pe64=true) {
    auto data=pe_metadata_fixture(pe64);
    const auto dirs=pe64?0x108u:0xf8u;
    put(data,dirs+11*8,0x2300,4); put(data,dirs+11*8+4,0x44,4);
    // One bound module, one forwarder reference, then the required zero descriptor.
    put(data,0x700,0x12345678,4); put(data,0x704,0x30,2); put(data,0x706,1,2);
    put(data,0x708,0x87654321,4); put(data,0x70c,0x3c,2); put(data,0x70e,0,2);
    put_text(data,0x730,"fixture.dll"); put_text(data,0x73c,"fwd.dll");
    return data;
}
}
