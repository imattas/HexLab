#pragma once
#include "elf_fixture.hpp"

namespace hexlab_test::elf_fixture {
inline std::vector<std::byte> executable_with_dwarf_info(bool malformed = false, bool with_variables = false,
                                                         bool with_unscoped_variable = false,
                                                         bool malformed_variable_type = false, bool v5 = false,
                                                         bool with_cfa_frame_base = false,
                                                         bool with_v5_location_list = false,
                                                         bool indexed_v5_location_list = false,
                                                         bool with_legacy_location_list = false) {
    auto data = executable(true, false);
    data.resize(2400);
    constexpr std::string_view names("\0.text\0.debug_info\0.debug_abbrev\0.debug_str\0.shstrtab\0.debug_loclists\0.debug_loc\0", 81);
    for (std::size_t i = 0; i < names.size(); ++i) data[2200 + i] = std::byte(names[i]);
    const auto section_at = [&](std::size_t i, std::uint32_t name, std::uint32_t type, std::uint64_t flags,
                                std::uint64_t address, std::uint64_t offset, std::uint64_t size) {
        const auto a = 512 + i * 64;
        put(data, a, name, 4); put(data, a + 4, type, 4); put(data, a + 8, flags, 8);
        put(data, a + 16, address, 8); put(data, a + 24, offset, 8); put(data, a + 32, size, 8);
        put(data, a + 48, 1, 8);
    };
    std::vector<std::uint8_t> abbrev;
    const auto uleb = [](std::vector<std::uint8_t>& out, std::uint64_t value) {
        do { auto b = static_cast<std::uint8_t>(value & 0x7f); value >>= 7; if (value) b |= 0x80; out.push_back(b); } while (value);
    };
    const auto string = [](std::vector<std::uint8_t>& out, std::string_view value) {
        for (char c : value) out.push_back(static_cast<std::uint8_t>(c));
        out.push_back(0);
    };
    // CU(name, children), base_type(name,size,encoding), subprogram(name,low_pc,high_pc).
    uleb(abbrev,1); uleb(abbrev,0x11); abbrev.push_back(1); uleb(abbrev,3); uleb(abbrev,8);
    if(indexed_v5_location_list){uleb(abbrev,0x8c);uleb(abbrev,0x17);} // DW_AT_loclists_base sec_offset
    uleb(abbrev,0); uleb(abbrev,0);
    uleb(abbrev,2); uleb(abbrev,0x24); abbrev.push_back(0); uleb(abbrev,3); uleb(abbrev,8);
    uleb(abbrev,0x0b); uleb(abbrev,0x0b); uleb(abbrev,0x3e); uleb(abbrev,0x0b); uleb(abbrev,0); uleb(abbrev,0);
    uleb(abbrev,3); uleb(abbrev,0x2e); abbrev.push_back(with_variables ? 1 : 0); uleb(abbrev,3); uleb(abbrev,8);
    uleb(abbrev,0x11); uleb(abbrev,1); uleb(abbrev,0x12); uleb(abbrev,6);
    if(with_cfa_frame_base){uleb(abbrev,0x40);uleb(abbrev,0x18);} // DW_AT_frame_base exprloc
    uleb(abbrev,0); uleb(abbrev,0);
    if (with_variables) {
        uleb(abbrev,4); uleb(abbrev,0x05); abbrev.push_back(0); uleb(abbrev,3); uleb(abbrev,8);
        uleb(abbrev,0x49); uleb(abbrev,0x13); uleb(abbrev,2); uleb(abbrev,0x18); uleb(abbrev,0); uleb(abbrev,0);
        uleb(abbrev,5); uleb(abbrev,0x34); abbrev.push_back(0); uleb(abbrev,3); uleb(abbrev,8);
        uleb(abbrev,0x49); uleb(abbrev,0x13); uleb(abbrev,2); uleb(abbrev,0x18); uleb(abbrev,0); uleb(abbrev,0);
        uleb(abbrev,6); uleb(abbrev,0x34); abbrev.push_back(0); uleb(abbrev,3); uleb(abbrev,8);
        uleb(abbrev,0x49); uleb(abbrev,0x13);
        if(with_v5_location_list||with_legacy_location_list){uleb(abbrev,0x02);uleb(abbrev,indexed_v5_location_list?0x22:0x17);}
        uleb(abbrev,0); uleb(abbrev,0);
    }
    if(with_unscoped_variable){uleb(abbrev,7);uleb(abbrev,0x34);abbrev.push_back(0);uleb(abbrev,3);uleb(abbrev,8);uleb(abbrev,0x49);uleb(abbrev,0x13);uleb(abbrev,0);uleb(abbrev,0);}
    uleb(abbrev,0);
    std::vector<std::uint8_t> info(4);
    const auto append = [&](std::uint64_t value, unsigned size) {
        for (unsigned i = 0; i < size; ++i) info.push_back(static_cast<std::uint8_t>(value >> (8 * i)));
    };
    if(v5){append(5,2);info.push_back(1);info.push_back(8);append(0,4);}else{append(4,2);append(0,4);info.push_back(8);} uleb(info,1); string(info,"sample.c");
    if(indexed_v5_location_list)append(12,4);
    const auto int_offset = static_cast<std::uint32_t>(info.size());
    uleb(info,2); string(info,"int"); info.push_back(4); info.push_back(5);
    uleb(info,3); string(info,"entry"); append(0x400000,8); append(with_variables ? 16 : 2,4);
    if(with_cfa_frame_base){info.push_back(1);info.push_back(0x9c);} // DW_OP_call_frame_cfa
    if (with_variables) {
        const auto reference = int_offset;
        uleb(info,4); string(info,"arg"); append(malformed_variable_type?0xffffffffu:reference,4); info.push_back(2); info.push_back(0x91); info.push_back(0x78); // fbreg -8
        uleb(info,5); string(info,"reg_local"); append(reference,4); info.push_back(1); info.push_back(0x50); // reg0
        uleb(info,5); string(info,"split_local"); append(reference,4); info.push_back(6); info.push_back(0x50); info.push_back(0x93); info.push_back(4); info.push_back(0x51); info.push_back(0x93); info.push_back(4);
        uleb(info,6); string(info,with_v5_location_list?"ranged_local":with_legacy_location_list?"legacy_ranged_local":"optimized_out"); append(reference,4);
        if(with_v5_location_list||with_legacy_location_list){if(indexed_v5_location_list)uleb(info,0);else append(with_legacy_location_list?0:12,4);}
        uleb(info,0);
    }
    if(with_unscoped_variable){uleb(info,7);string(info,"global_value");append(int_offset,4);}
    uleb(info,0);
    const auto length = static_cast<std::uint32_t>(info.size() - 4);
    for (unsigned i = 0; i < 4; ++i) info[i] = static_cast<std::uint8_t>(length >> (8 * i));
    if (malformed) info.pop_back();
    for (std::size_t i = 0; i < info.size(); ++i) data[1100 + i] = std::byte(info[i]);
    for (std::size_t i = 0; i < abbrev.size(); ++i) data[1300 + i] = std::byte(abbrev[i]);
    constexpr std::string_view strings("sample.c\0int\0entry\0", 19);
    for (std::size_t i = 0; i < strings.size(); ++i) data[1500 + i] = std::byte(strings[i]);
    std::vector<std::uint8_t> location_lists;
    if(with_v5_location_list){
        location_lists.resize(4);
        const auto fixed=[&](std::uint64_t value,unsigned width){for(unsigned i=0;i<width;++i)location_lists.push_back(static_cast<std::uint8_t>(value>>(8*i)));};
        const auto range=[&](std::uint64_t begin,std::uint64_t end,std::uint8_t reg){location_lists.push_back(7);fixed(begin,8);fixed(end,8);location_lists.push_back(1);location_lists.push_back(reg);};
        fixed(5,2);location_lists.push_back(8);location_lists.push_back(0);fixed(indexed_v5_location_list?1:0,4);
        if(indexed_v5_location_list)fixed(16,4); // loclistx[0], relative to contribution start
        range(0x400000,0x400008,0x50);range(0x400008,0x400010,0x51);location_lists.push_back(0);
        const auto list_length=static_cast<std::uint32_t>(location_lists.size()-4);
        for(unsigned i=0;i<4;++i)location_lists[i]=static_cast<std::uint8_t>(list_length>>(8*i));
    }
    std::vector<std::uint8_t> locations;
    if(with_legacy_location_list){
        const auto fixed=[&](std::uint64_t value,unsigned width){for(unsigned i=0;i<width;++i)locations.push_back(static_cast<std::uint8_t>(value>>(8*i)));};
        const auto range=[&](std::uint64_t begin,std::uint64_t end,std::uint8_t reg){fixed(begin,8);fixed(end,8);fixed(1,2);locations.push_back(reg);};
        fixed(UINT64_MAX,8);fixed(0x400000,8); // base-selection entry
        range(0,8,0x50);range(8,16,0x51);fixed(0,8);fixed(0,8); // list terminator
    }
    section_at(1,1,1,6,0x400000,256,16); section_at(2,7,1,0,0,1100,info.size());
    section_at(3,19,1,0,0,1300,abbrev.size()); section_at(4,33,3,0,0,1500,strings.size());
    section_at(5,44,3,0,0,2200,names.size());
    if(with_v5_location_list){section_at(6,54,1,0,0,1600,location_lists.size());for(std::size_t i=0;i<location_lists.size();++i)data[1600+i]=std::byte(location_lists[i]);}
    if(with_legacy_location_list){section_at(7,70,1,0,0,1600,locations.size());for(std::size_t i=0;i<locations.size();++i)data[1600+i]=std::byte(locations[i]);}
    put(data,40,512,8); put(data,58,64,2); put(data,60,with_legacy_location_list?8:with_v5_location_list?7:6,2); put(data,62,5,2);
    return data;
}
} // namespace hexlab_test::elf_fixture
