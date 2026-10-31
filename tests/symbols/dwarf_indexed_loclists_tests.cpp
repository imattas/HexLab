#include "hexlab/symbols/dwarf.hpp"

#include <cassert>
#include <cstdint>
#include <string>
#include <vector>

namespace {
using namespace hexlab;
using namespace hexlab::symbols;

void fixed(std::vector<std::uint8_t>& out, std::uint64_t value, unsigned width) {
    for (unsigned i = 0; i < width; ++i) out.push_back(static_cast<std::uint8_t>(value >> (8 * i)));
}
void uleb(std::vector<std::uint8_t>& out, std::uint64_t value) {
    do { auto byte = static_cast<std::uint8_t>(value & 0x7f); value >>= 7; if (value) byte |= 0x80; out.push_back(byte); } while (value);
}
void pair(std::vector<std::uint8_t>& out, std::uint64_t name, std::uint64_t form) { uleb(out, name); uleb(out, form); }

struct Fixture {
    std::vector<std::uint8_t> info, abbrev, addresses, locations;
};

Fixture build(std::vector<std::uint8_t> list, std::vector<std::uint64_t> addresses = {0x401000, 0x401020}) {
    Fixture f;
    // DWARF v5 CU: root, int type, function, and a local with loclistx[0].
    uleb(f.abbrev, 1); uleb(f.abbrev, 0x11); f.abbrev.push_back(1);
    pair(f.abbrev, 0x8c, 0x17); pair(f.abbrev, 0x73, 0x17); pair(f.abbrev, 0, 0);
    uleb(f.abbrev, 2); uleb(f.abbrev, 0x24); f.abbrev.push_back(0);
    pair(f.abbrev, 3, 8); pair(f.abbrev, 0x0b, 0x0b); pair(f.abbrev, 0x3e, 0x0b); pair(f.abbrev, 0, 0);
    uleb(f.abbrev, 3); uleb(f.abbrev, 0x2e); f.abbrev.push_back(1);
    pair(f.abbrev, 3, 8); pair(f.abbrev, 0x11, 1); pair(f.abbrev, 0x12, 6); pair(f.abbrev, 0, 0);
    uleb(f.abbrev, 4); uleb(f.abbrev, 0x34); f.abbrev.push_back(0);
    pair(f.abbrev, 3, 8); pair(f.abbrev, 0x49, 0x13); pair(f.abbrev, 2, 0x22); pair(f.abbrev, 0, 0);
    uleb(f.abbrev, 0);

    fixed(f.info, 0, 4); fixed(f.info, 5, 2); f.info.push_back(1); f.info.push_back(8); fixed(f.info, 0, 4);
    uleb(f.info, 1); fixed(f.info, 12, 4); fixed(f.info, 8, 4); // loclists_base, addr_base
    const auto type_offset = f.info.size();
    uleb(f.info, 2); f.info.insert(f.info.end(), {'i','n','t',0}); f.info.push_back(4); f.info.push_back(5);
    uleb(f.info, 3); f.info.insert(f.info.end(), {'f','n',0}); fixed(f.info, 0x401000, 8); fixed(f.info, 0x40, 4);
    uleb(f.info, 4); f.info.insert(f.info.end(), {'x',0}); fixed(f.info, type_offset, 4); uleb(f.info, 0); uleb(f.info, 0); uleb(f.info, 0);
    const auto unit_length = static_cast<std::uint32_t>(f.info.size() - 4);
    for (unsigned i = 0; i < 4; ++i) f.info[i] = static_cast<std::uint8_t>(unit_length >> (i * 8));

    fixed(f.addresses, static_cast<std::uint32_t>(4 + addresses.size() * 8), 4);
    fixed(f.addresses, 5, 2); f.addresses.push_back(8); f.addresses.push_back(0);
    for (auto address : addresses) fixed(f.addresses, address, 8);

    fixed(f.locations, static_cast<std::uint32_t>(12 + list.size()), 4);
    fixed(f.locations, 5, 2); f.locations.push_back(8); f.locations.push_back(0); fixed(f.locations, 1, 4);
    fixed(f.locations, 16, 4); // loclistx offset, relative to contribution start
    f.locations.insert(f.locations.end(), list.begin(), list.end());
    return f;
}

Result<ImportResult> import(const Fixture& f) {
    DwarfSections sections;
    sections.source_id = "indexed-loclists.o";
    sections.info = f.info;
    sections.abbrev = f.abbrev;
    sections.addresses = f.addresses;
    sections.location_lists = f.locations;
    return import_dwarf(sections);
}
std::vector<std::uint8_t> expression(std::uint8_t literal) { return {literal}; }
void add_expression(std::vector<std::uint8_t>& list, std::uint8_t literal) { uleb(list, 1); list.push_back(literal); }
}

int main() {
    std::vector<std::uint8_t> list;
    list.push_back(0x01); uleb(list, 1); // base_addressx = 0x401020
    list.push_back(0x02); uleb(list, 0); uleb(list, 1); uleb(list, 2); list.insert(list.end(), {0x73, 0x78}); // breg3 -8
    list.push_back(0x03); uleb(list, 0); uleb(list, 0x10); add_expression(list, 0x31); // startx_length
    list.push_back(0x01); uleb(list, 1);
    list.push_back(0x04); uleb(list, 0); uleb(list, 0x10); add_expression(list, 0x32); // base-address follow-on
    list.push_back(0x00);
    auto fixture = build(list);
    auto result = import(fixture);
    assert(result && result.value().variables.size() == 1);
    const auto& ranges = result.value().variables[0].location_ranges;
    assert(ranges.size() == 3);
    assert(ranges[0].begin == 0x401000 && ranges[0].end == 0x401020 && ranges[0].expression == std::vector<std::uint8_t>({0x73, 0x78}));
    assert(ranges[1].begin == 0x401000 && ranges[1].end == 0x401010 && ranges[1].expression == expression(0x31));
    assert(ranges[2].begin == 0x401020 && ranges[2].end == 0x401030 && ranges[2].expression == expression(0x32));

    LocationEvaluationContext context;
    context.address_size = 8;
    context.read_register = [](std::uint64_t reg) -> std::optional<std::uint64_t> {
        return reg == 3 ? std::optional<std::uint64_t>(0x5000) : std::nullopt;
    };
    auto live = evaluate_imported_variable_location(result.value().variables[0], 0x401010, context);
    assert((live && live.value() == EvaluatedLocation{EvaluatedLocationKind::memory, 0x4ff8}));
    auto at_boundary = evaluate_imported_variable_location(result.value().variables[0], 0x401020, context);
    assert((at_boundary && at_boundary.value() == EvaluatedLocation{EvaluatedLocationKind::memory, 2}));
    auto unavailable = evaluate_imported_variable_location(result.value().variables[0], 0x401030, context);
    assert(!unavailable && unavailable.error().code == ErrorCode::unsupported);
    ImportedVariable static_variable;
    static_variable.address = 0x7000;
    auto static_location = evaluate_imported_variable_location(static_variable, 0, context);
    assert((static_location && static_location.value() == EvaluatedLocation{EvaluatedLocationKind::memory, 0x7000}));
    ImportedVariable absent_variable;
    auto absent_location = evaluate_imported_variable_location(absent_variable, 0x401000, context);
    assert(!absent_location && absent_location.error().code == ErrorCode::unsupported);

    auto bad_index_list = std::vector<std::uint8_t>{0x03}; uleb(bad_index_list, 2); uleb(bad_index_list, 1); add_expression(bad_index_list, 0x30); bad_index_list.push_back(0);
    auto bad_index = import(build(bad_index_list));
    assert(!bad_index && bad_index.error().code == ErrorCode::malformed);

    auto truncated_list = std::vector<std::uint8_t>{0x02, 0x80};
    auto truncated = import(build(truncated_list));
    assert(!truncated && truncated.error().code == ErrorCode::malformed);

    auto reversed_list = std::vector<std::uint8_t>{0x02, 0x01, 0x00}; add_expression(reversed_list, 0x30); reversed_list.push_back(0);
    auto reversed = import(build(reversed_list));
    assert(!reversed && reversed.error().code == ErrorCode::malformed);

    auto overflow_list = std::vector<std::uint8_t>{0x03, 0x00, 0x08}; add_expression(overflow_list, 0x30); overflow_list.push_back(0);
    auto overflow = import(build(overflow_list, {UINT64_MAX - 3}));
    assert(!overflow && overflow.error().code == ErrorCode::malformed);
}
