#include "hexlab/symbols/dwarf.hpp"
#include <cassert>
#include <cstdint>
#include <iostream>
#include <vector>
using namespace hexlab::symbols;
namespace {
void u32(std::vector<std::uint8_t>&b,std::uint32_t n){for(unsigned i=0;i<4;++i)b.push_back(static_cast<std::uint8_t>((n>>(8*i))&255));}
void uleb(std::vector<std::uint8_t>&b,std::uint64_t n){do{auto x=static_cast<std::uint8_t>(n&127);n>>=7;b.push_back(static_cast<std::uint8_t>(x|(n?128:0)));}while(n);}
std::vector<std::uint8_t> make(unsigned version=4){std::vector<std::uint8_t>b;u32(b,0);auto unit=b.size();b.push_back(version);b.push_back(0);u32(b,0);auto hdr=b.size();b.push_back(1);if(version>=4)b.push_back(1);b.insert(b.end(),{1,1,0xfb,14,13});for(int i=0;i<12;++i)b.push_back(i==1?0:1);b.push_back(0);b.insert(b.end(),{'a','.','c',0,0,0,0,0});auto hl=b.size()-hdr;for(int i=0;i<4;++i)b[unit+2+i]=(hl>>(i*8))&255;
 b.insert(b.end(),{0,9,2});for(int i=0;i<8;++i)b.push_back(i==0?0x20:0);b.push_back(1);b.insert(b.end(),{2,5,3,2,1});b.insert(b.end(),{0,1,1});auto len=b.size()-4;for(int i=0;i<4;++i)b[i]=(len>>(i*8))&255;return b;}
std::vector<std::uint8_t> make_v5(bool alternate=false){std::vector<std::uint8_t>b;u32(b,0);auto u=b.size();b.insert(b.end(),{5,0,8,0});u32(b,0);auto h=b.size();b.insert(b.end(),{1,1,1,0xfb,14,13});for(int i=0;i<12;++i)b.push_back(i==1?0:1);if(!alternate){b.insert(b.end(),{1,1,8,1});b.insert(b.end(),{'s','r','c',0});b.insert(b.end(),{3,1,8,3,0x0f,4,0x0f,1});b.insert(b.end(),{'a','.','c',0});uleb(b,0);uleb(b,7);}else{b.insert(b.end(),{1,1,8,1,'d',0,3,1,8,3,0x05,4,0x06,1,'b',0,2,0,3,0,0,0});}auto hl=b.size()-h;for(int i=0;i<4;++i)b[u+4+i]=(hl>>(8*i))&255;b.insert(b.end(),{0,9,2});for(int i=0;i<8;++i)b.push_back(i==0?0x40:0);b.push_back(1);b.insert(b.end(),{2,3,3,1,1,0,1,1});auto len=b.size()-4;for(int i=0;i<4;++i)b[i]=(len>>(8*i))&255;return b;}
}
int main(){
 DwarfLineUnit lookup_unit;
 lookup_unit.rows={{0x100,1,10,0,false},{0x104,1,11,0,false},{0x104,1,12,0,false},
                   {0x110,1,20,0,false},{0x118,1,20,0,true},
                   {0x200,1,30,0,false},{0x210,1,30,0,true}};
 auto at_start=dwarf_line_row_at(lookup_unit,0x100);assert(at_start&&at_start->line==10);
 auto duplicate=dwarf_line_row_at(lookup_unit,0x104);assert(duplicate&&duplicate->line==12);
 auto before_end=dwarf_line_row_at(lookup_unit,0x117);assert(before_end&&before_end->line==20);
 assert(!dwarf_line_row_at(lookup_unit,0x118));
 auto second_sequence=dwarf_line_row_at(lookup_unit,0x205);assert(second_sequence&&second_sequence->line==30);
 assert(!dwarf_line_row_at(lookup_unit,0x210));
 DwarfLineUnit incomplete;incomplete.rows={{0x300,1,40,0,false}};
 assert(!dwarf_line_row_at(incomplete,0x400));
 DwarfLineUnit unordered;unordered.rows={{0x400,1,50,0,false},{0x3f0,1,51,0,false},{0x410,1,51,0,true}};
 assert(!dwarf_line_row_at(unordered,0x405));
 for(unsigned version=2;version<=4;++version){auto bytes=make(version);auto got=import_dwarf_line_v2_v4({"synthetic",bytes,8,true});if(!got){std::cerr<<"DWARF line v"<<version<<": "<<got.error().message<<'\n';return 1;}assert(got.value().size()==1);const auto&u=got.value()[0];assert(u.version==version&&u.files.size()==1&&u.files[0].name=="a.c");assert(u.rows.size()==3);assert(u.rows[0].address==0x20&&u.rows[0].file==1&&u.rows[0].line==1);assert(u.rows[1].address==0x25&&u.rows[1].line==3);assert(u.rows[2].end_sequence);}
 auto bytes=make();
 auto truncated=bytes;truncated.pop_back();auto bad=import_dwarf_line_v2_v4({"truncated",truncated,8,true});assert(!bad);
 auto v5bytes=make_v5();auto v5=import_dwarf_line_v2_v5({"v5",v5bytes,8,true});if(!v5){std::cerr<<"DWARF v5: "<<v5.error().message<<'\n';return 1;}if(v5.value().empty()){std::cerr<<"DWARF v5: no units\n";return 1;}assert(v5.value()[0].version==5&&v5.value()[0].files.size()==1&&v5.value()[0].rows.size()==3);auto legacy_v5=import_dwarf_line_v2_v4({"legacy-v5",v5bytes,8,true});assert(!legacy_v5&&legacy_v5.error().code==hexlab::ErrorCode::unsupported);auto v5altbytes=make_v5(true);auto v5alt=import_dwarf_line_v2_v5({"v5-alt",v5altbytes,8,true});if(!v5alt){std::cerr<<"DWARF v5 alternate: "<<v5alt.error().message<<'\n';return 1;}if(v5alt.value().empty()){std::cerr<<"DWARF v5 alternate: no units\n";return 1;}assert(v5alt.value()[0].files[0].modification_time==2&&v5alt.value()[0].files[0].size==3);auto v5truncated=v5bytes;v5truncated.pop_back();assert(!import_dwarf_line_v2_v5({"v5-truncated",v5truncated,8,true}));auto v5bounded=import_dwarf_line_v2_v5({"v5-bounded",v5bytes,8,true,1});assert(!v5bounded&&v5bounded.error().code==hexlab::ErrorCode::resource_limit);
 auto bounded=import_dwarf_line_v2_v4({"bounded",bytes,8,true,1});assert(!bounded&&bounded.error().code==hexlab::ErrorCode::resource_limit);
}
