#include "hexlab/symbols/dwarf.hpp"

#include <cassert>
#include <cstdint>
#include <vector>

namespace {
using namespace hexlab;
using namespace hexlab::symbols;
void fixed(std::vector<std::uint8_t>& out, std::uint64_t v, unsigned n) {
    for (unsigned i=0;i<n;++i) out.push_back(static_cast<std::uint8_t>(v>>(8*i)));
}
void uleb(std::vector<std::uint8_t>& out, std::uint64_t v) {
    do { auto b=static_cast<std::uint8_t>(v&0x7f); v>>=7; if(v)b|=0x80; out.push_back(b); } while(v);
}
void pair(std::vector<std::uint8_t>& out, std::uint64_t name, std::uint64_t form) { uleb(out,name); uleb(out,form); }
struct Fixture { std::vector<std::uint8_t> info, abbrev, locations; };
Fixture build() {
    Fixture f;
    uleb(f.abbrev,1);uleb(f.abbrev,0x11);f.abbrev.push_back(1);
    pair(f.abbrev,0x11,1); pair(f.abbrev,0,0);
    uleb(f.abbrev,2);uleb(f.abbrev,0x24);f.abbrev.push_back(0);
    pair(f.abbrev,3,8);pair(f.abbrev,0x0b,0x0b);pair(f.abbrev,0x3e,0x0b);pair(f.abbrev,0,0);
    uleb(f.abbrev,3);uleb(f.abbrev,0x2e);f.abbrev.push_back(1);
    pair(f.abbrev,3,8);pair(f.abbrev,0x11,1);pair(f.abbrev,0x12,6);pair(f.abbrev,0,0);
    uleb(f.abbrev,4);uleb(f.abbrev,0x34);f.abbrev.push_back(0);
    pair(f.abbrev,3,8);pair(f.abbrev,0x49,0x13);pair(f.abbrev,2,0x17);pair(f.abbrev,0,0);uleb(f.abbrev,0);
    fixed(f.info,0,4);fixed(f.info,4,2);fixed(f.info,0,4);f.info.push_back(8);
    uleb(f.info,1);fixed(f.info,0x401000,8);
    const auto type=f.info.size();uleb(f.info,2);f.info.insert(f.info.end(),{'i','n','t',0});f.info.push_back(4);f.info.push_back(5);
    uleb(f.info,3);f.info.insert(f.info.end(),{'f','n',0});fixed(f.info,0x401000,8);fixed(f.info,0x40,4);
    uleb(f.info,4);f.info.insert(f.info.end(),{'x',0});fixed(f.info,type,4);fixed(f.info,0,4);uleb(f.info,0);uleb(f.info,0);
    const auto length=static_cast<std::uint32_t>(f.info.size()-4);for(unsigned i=0;i<4;++i)f.info[i]=static_cast<std::uint8_t>(length>>(8*i));
    // Offset pairs use the CU low_pc as their initial base; the base-selection
    // entry then changes it for the second range.
    fixed(f.locations,0,8);fixed(f.locations,0x10,8);fixed(f.locations,1,2);f.locations.push_back(0x53);
    fixed(f.locations,UINT64_MAX,8);fixed(f.locations,0x402000,8);
    fixed(f.locations,4,8);fixed(f.locations,0x14,8);fixed(f.locations,1,2);f.locations.push_back(0x54);
    fixed(f.locations,0,8);fixed(f.locations,0,8);
    return f;
}
}
int main() {
    const auto f=build();
    DwarfSections sections{"legacy-loc.o",f.info,f.abbrev,{}, {}, {}, {}, {}, {}, {}};
    // Dedicated legacy location data will be supplied through the final section field.
    sections.locations=f.locations;
    auto imported=import_dwarf(sections);
    if (!imported || imported.value().variables.size()!=1) return 1;
    const auto& variable=imported.value().variables.front();
    assert(variable.location_ranges.size()==2);
    assert(variable.location_ranges[0].begin==0x401000 && variable.location_ranges[0].end==0x401010);
    assert(variable.location_ranges[1].begin==0x402004 && variable.location_ranges[1].end==0x402014);
    LocationEvaluationContext context;
    context.read_register=[](std::uint64_t reg)->std::optional<std::uint64_t>{return reg==3?std::optional<std::uint64_t>(0x5000):std::nullopt;};
    auto first=evaluate_imported_variable_location(variable,0x401004,context);
    assert((first && first.value()==EvaluatedLocation{EvaluatedLocationKind::register_location,3}));
    auto second=evaluate_imported_variable_location(variable,0x402004,context);
    assert((second && second.value()==EvaluatedLocation{EvaluatedLocationKind::register_location,4}));
    auto gap=evaluate_imported_variable_location(variable,0x401010,context);
    assert(!gap && gap.error().code==ErrorCode::unsupported);

    DwarfV4Sections v4{"legacy-loc-v4.o",f.info,f.abbrev,{}, {},f.locations};
    auto imported_v4=import_dwarf_v4(v4);
    assert(imported_v4 && imported_v4.value().variables.front().location_ranges.size()==2);
    auto missing=sections; missing.locations={};
    auto no_section=import_dwarf(missing);
    assert(!no_section && no_section.error().code==ErrorCode::unsupported);
    auto malformed=f; malformed.locations.resize(malformed.locations.size()-1);
    sections.locations=malformed.locations;
    auto truncated=import_dwarf(sections);
    assert(!truncated && truncated.error().code==ErrorCode::malformed);
}
