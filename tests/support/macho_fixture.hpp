#pragma once
#include <cstddef>
#include <cstdint>
#include <vector>
#include <string_view>
namespace hexlab_test::macho_fixture {
inline void put(std::vector<std::byte> &data, std::size_t at, std::uint64_t value, std::size_t count, bool big) {
    for (std::size_t i = 0; i < count; ++i)
        data.at(at + i) = std::byte(value >> (8 * (big ? count - i - 1 : i)));
}
inline std::vector<std::byte> thin(bool wide, bool big) {
    const auto header = wide ? 32u : 28u;
    std::vector<std::byte> data(header + 24);
    put(data, 0, wide ? 0xfeedfacfu : 0xfeedfaceu, 4, big);
    put(data, 4, wide ? 0x01000007u : 7u, 4, big);
    put(data, 8, 0x80000003, 4, big);
    put(data, 12, 1, 4, big);
    put(data, 16, 2, 4, big);
    put(data, 20, 24, 4, big);
    put(data, 24, 0x80002000, 4, big);
    if (wide)
        put(data, 28, 0x12345678, 4, big);
    put(data, header, 0x70000001, 4, big);
    put(data, header + 4, 8, 4, big);
    put(data, header + 8, 0x70000002, 4, big);
    put(data, header + 12, 16, 4, big);
    return data;
}
inline std::vector<std::byte> universal(bool wide, bool big) {
    const auto a = thin(false, false), b = thin(true, true);
    std::vector<std::byte> data(1024);
    put(data, 0, wide ? 0xcafebabfu : 0xcafebabeu, 4, big);
    put(data, 4, 2, 4, big);
    for (std::size_t i = 0; i < 2; ++i) {
        const auto at = 8 + i * (wide ? 32 : 20);
        put(data, at, i ? 0x01000007u : 7u, 4, big);
        put(data, at + 4, 0x80000003, 4, big);
        put(data, at + 8, i ? 512 : 256, wide ? 8 : 4, big);
        put(data, at + (wide ? 16 : 12), i ? b.size() : a.size(), wide ? 8 : 4, big);
        put(data, at + (wide ? 24 : 16), 8, 4, big);
        if (wide)
            put(data, at + 28, 0x0badf00d, 4, big);
    }
    for (std::size_t i = 0; i < a.size(); ++i)
        data[256 + i] = a[i];
    for (std::size_t i = 0; i < b.size(); ++i)
        data[512 + i] = b[i];
    return data;
}
inline void name(std::vector<std::byte> &data, std::size_t at, std::string_view text) {
    for (std::size_t i = 0; i < 16; ++i)
        data.at(at + i) = i < text.size() ? std::byte(text[i]) : std::byte{0};
}
inline void segment(std::vector<std::byte> &data, bool wide, bool big, std::size_t at, std::uint64_t address,
                    std::uint64_t memory, std::uint64_t file, std::uint64_t initialized, std::uint32_t protections = 5,
                    std::uint32_t flags = 0, std::uint32_t sections = 0) {
    const auto command = (wide ? 72 : 56) + sections * (wide ? 80 : 68);
    put(data, at, wide ? 0x19 : 1, 4, big);
    put(data, at + 4, command, 4, big);
    name(data, at + 8, "__TEXT");
    put(data, at + 24, address, wide ? 8 : 4, big);
    put(data, at + (wide ? 32 : 28), memory, wide ? 8 : 4, big);
    put(data, at + (wide ? 40 : 32), file, wide ? 8 : 4, big);
    put(data, at + (wide ? 48 : 36), initialized, wide ? 8 : 4, big);
    put(data, at + (wide ? 56 : 40), 7, 4, big);
    put(data, at + (wide ? 60 : 44), protections, 4, big);
    put(data, at + (wide ? 64 : 48), sections, 4, big);
    put(data, at + (wide ? 68 : 52), flags, 4, big);
}
inline void section(std::vector<std::byte> &data, bool wide, bool big, std::size_t at, std::string_view label,
                    std::uint64_t address, std::uint64_t size, std::uint32_t offset, std::uint32_t flags) {
    name(data, at, label);
    name(data, at + 16, "__TEXT");
    put(data, at + 32, address, wide ? 8 : 4, big);
    put(data, at + (wide ? 40 : 36), size, wide ? 8 : 4, big);
    put(data, at + (wide ? 48 : 40), offset, 4, big);
    put(data, at + (wide ? 64 : 56), flags, 4, big);
}
inline std::vector<std::uint8_t> dwarf_line(std::uint64_t address,std::size_t address_size,bool big=false,bool malformed=false) {
    std::vector<std::uint8_t>b;auto u32=[&](std::uint32_t n){for(unsigned i=0;i<4;++i)b.push_back(static_cast<std::uint8_t>(n>>(8*(big?3-i:i))));};u32(0);const auto unit=b.size();b.insert(b.end(),{static_cast<std::uint8_t>(big?0:4),static_cast<std::uint8_t>(big?4:0)});u32(0);const auto prologue=b.size();b.insert(b.end(),{1,1,1,0xfb,14,13});for(int i=0;i<12;++i)b.push_back(i==1?0:1);b.push_back(0);b.insert(b.end(),{'s','r','c','.','c',0,0,0,0,0});const auto header_size=static_cast<std::uint32_t>(b.size()-prologue);for(unsigned i=0;i<4;++i)b[unit+2+i]=static_cast<std::uint8_t>(header_size>>(8*(big?3-i:i)));
    b.push_back(0);b.push_back(static_cast<std::uint8_t>(1+address_size));b.push_back(2);for(std::size_t i=0;i<address_size;++i)b.push_back(static_cast<std::uint8_t>(address>>(8*(big?address_size-1-i:i))));b.insert(b.end(),{1,0,1,1});const auto length=static_cast<std::uint32_t>(b.size()-4);for(unsigned i=0;i<4;++i)b[i]=static_cast<std::uint8_t>(length>>(8*(big?3-i:i)));if(malformed)b[0]=0xff;return b;
}
inline std::vector<std::byte> mapped(bool wide, bool big, bool object);
inline std::vector<std::byte> mapped_with_dwarf_lines(bool wide=false,bool big=false,bool object=false,bool malformed=false) {
    auto data=mapped(wide,big,object);data.resize(2048);const auto header=wide?32u:28u,stride=wide?80u:68u,first=header+(wide?72u:56u),extent=(wide?72u:56u)+4*stride;const auto base=object?UINT64_C(0x100):wide?UINT64_C(0x100000000):UINT64_C(0x1000);const auto debug=dwarf_line(base,wide?8:4,big,malformed);put(data,header+4,extent,4,big);put(data,20,extent,4,big);put(data,header+(wide?64:48),4,4,big);section(data,wide,big,first+3*stride,"__debug_line",0,debug.size(),800,0x02000000);for(std::size_t i=0;i<debug.size();++i)data[800+i]=std::byte(debug[i]);return data;
}
inline std::vector<std::byte> mapped(bool wide, bool big = false, bool object = false) {
    auto data = thin(wide, big);
    data.resize(1024);
    const auto header = wide ? 32u : 28u;
    // thin() deliberately uses a nonzero reserved field for header-validation
    // tests. Mapped-image fixtures represent valid inputs and clear it.
    if (wide)
        put(data, 28, 0, 4, big);
    const auto extent = (wide ? 72 : 56) + 3 * (wide ? 80 : 68);
    put(data, 12, object ? 1 : 2, 4, big);
    put(data, 16, 1, 4, big);
    put(data, 20, extent, 4, big);
    const auto base = object ? UINT64_C(0x100) : wide ? UINT64_C(0x100000000) : UINT64_C(0x1000);
    segment(data, wide, big, header, base, 32, 768, 16, 7, 0, 3);
    const auto first = header + (wide ? 72 : 56), stride = wide ? 80u : 68u;
    section(data, wide, big, first, "__text", base, 8, 768, 0x80000400);
    section(data, wide, big, first + stride, "__other", object ? base : base + 8, 8, 776, 0x80000400);
    section(data, wide, big, first + 2 * stride, "__bss", base + 16, 16, 0xfffffff0, 1);
    data[768] = data[776] = std::byte{0x90};
    data[769] = data[777] = std::byte{0xc3};
    return data;
}
inline std::vector<std::byte> mapped_fat() {
    auto a = mapped(false), b = mapped(true);
    std::vector<std::byte> data(3072);
    put(data, 0, 0xcafebabe, 4, true);
    put(data, 4, 2, 4, true);
    for (std::size_t i = 0; i < 2; ++i) {
        const auto at = 8 + i * 20;
        put(data, at, i ? 0x01000007 : 7, 4, true);
        put(data, at + 4, 0x80000003, 4, true);
        put(data, at + 8, i ? 2048 : 1024, 4, true);
        put(data, at + 12, 1024, 4, true);
        put(data, at + 16, 10, 4, true);
    }
    std::copy(a.begin(), a.end(), data.begin() + 1024);
    std::copy(b.begin(), b.end(), data.begin() + 2048);
    return data;
}
} // namespace hexlab_test::macho_fixture
