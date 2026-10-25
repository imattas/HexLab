#include "hexlab/symbols/dwarf.hpp"

#include <cstdint>
#include <iostream>
#include <span>
#include <stop_token>
#include <string>
#include <vector>

namespace {
void append(std::vector<std::uint8_t> &out, std::uint64_t value, unsigned count) {
    for (unsigned i = 0; i < count; ++i)
        out.push_back(static_cast<std::uint8_t>(value >> (i * 8)));
}
void uleb(std::vector<std::uint8_t> &out, std::uint64_t value) {
    do {
        auto byte = static_cast<std::uint8_t>(value & 0x7f);
        value >>= 7;
        if (value) byte |= 0x80;
        out.push_back(byte);
    } while (value);
}
void string(std::vector<std::uint8_t> &out, const std::string &value) {
    out.insert(out.end(), value.begin(), value.end());
    out.push_back(0);
}
struct Fixture {
    std::vector<std::uint8_t> info;
    std::vector<std::uint8_t> abbrev;
    std::vector<std::uint8_t> strings;
};
Fixture fixture(std::uint16_t version = 4) {
    Fixture f;
    // Abbrev 1: compile_unit(name:string, children yes)
    uleb(f.abbrev, 1); uleb(f.abbrev, 0x11); f.abbrev.push_back(1);
    uleb(f.abbrev, 0x03); uleb(f.abbrev, 0x08); uleb(f.abbrev, 0); uleb(f.abbrev, 0);
    // Abbrev 2: base_type(name:string, byte_size:data1, encoding:data1)
    uleb(f.abbrev, 2); uleb(f.abbrev, 0x24); f.abbrev.push_back(0);
    uleb(f.abbrev, 0x03); uleb(f.abbrev, 0x08);
    uleb(f.abbrev, 0x0b); uleb(f.abbrev, 0x0b);
    uleb(f.abbrev, 0x3e); uleb(f.abbrev, 0x0b);
    uleb(f.abbrev, 0); uleb(f.abbrev, 0);
    // Abbrev 3: subprogram(name:string, low_pc:addr, high_pc:data4)
    uleb(f.abbrev, 3); uleb(f.abbrev, 0x2e); f.abbrev.push_back(0);
    uleb(f.abbrev, 0x03); uleb(f.abbrev, 0x08);
    uleb(f.abbrev, 0x11); uleb(f.abbrev, 0x01);
    uleb(f.abbrev, 0x12); uleb(f.abbrev, 0x06);
    uleb(f.abbrev, 0); uleb(f.abbrev, 0);
    uleb(f.abbrev, 0);

    const auto length_at = f.info.size(); append(f.info, 0, 4);
    append(f.info, version, 2); append(f.info, 0, 4); f.info.push_back(4);
    uleb(f.info, 1); string(f.info, "sample.c");
    uleb(f.info, 2); string(f.info, "int"); f.info.push_back(4); f.info.push_back(0x05);
    uleb(f.info, 3); string(f.info, "main"); append(f.info, 0x401000, 4); append(f.info, 0x20, 4);
    uleb(f.info, 0); // end compile_unit children
    const auto length = f.info.size() - 4;
    for (unsigned i = 0; i < 4; ++i) f.info[length_at + i] = static_cast<std::uint8_t>(length >> (i * 8));
    return f;
}
bool check(bool condition, const char *message) {
    if (!condition) std::cerr << message << '\n';
    return condition;
}

bool imports_symbols_and_source_attributed_types() {
    auto data = fixture();
    auto result = hexlab::symbols::import_dwarf_v4({"fixture.o", data.info, data.abbrev, data.strings});
    bool ok = check(result.has_value(), "valid DWARF v4 fixture was rejected");
    if (!result) return false;
    const auto &out = result.value();
    ok &= check(out.symbols.size() == 1, "subprogram symbol not imported");
    if (!out.symbols.empty()) {
        const auto &symbol = out.symbols.front();
        ok &= check(symbol.name == "main" && symbol.address == 0x401000 && symbol.size == 0x20,
                    "function name/address/range was not decoded");
        ok &= check(symbol.origin.source_id == "fixture.o" && symbol.origin.section == ".debug_info" &&
                    symbol.origin.record_offset > 0 && symbol.origin.record_size > 0,
                    "symbol lost its DIE provenance");
    }
    ok &= check(out.types.size() == 1, "base type not imported");
    if (!out.types.empty()) {
        const auto &type = out.types.front();
        ok &= check(type.type && type.type->name() == "int" && type.type->size() == 4 && type.type->is_signed(),
                    "base type shape incorrect");
        ok &= check(type.origin.source_id == "fixture.o" && type.origin.section == ".debug_info" &&
                    type.origin.record_size > 0, "type lost its DIE provenance");
        ok &= check(type.alignment_is_inferred && type.type->alignment() == 1,
                    "type alignment uncertainty was not exposed");
    }
    return ok;
}

bool rejects_truncated_units_and_unsupported_versions() {
    auto truncated = fixture();
    truncated.info.resize(8);
    auto bad_length = hexlab::symbols::import_dwarf_v4({"truncated", truncated.info, truncated.abbrev, {}});
    bool ok = check(!bad_length && bad_length.error().code == hexlab::ErrorCode::malformed,
                    "truncated unit was not rejected as malformed");
    auto version = fixture(5);
    auto bad_version = hexlab::symbols::import_dwarf_v4({"version5", version.info, version.abbrev, {}});
    ok &= check(!bad_version && bad_version.error().code == hexlab::ErrorCode::unsupported,
                "unsupported DWARF version was not rejected explicitly");
    return ok;
}

bool rejects_missing_abbreviations_and_string_bounds() {
    auto missing = fixture();
    // Corrupt the first DIE abbreviation code.
    missing.info[11] = 99;
    auto bad_code = hexlab::symbols::import_dwarf_v4({"bad-code", missing.info, missing.abbrev, {}});
    bool ok = check(!bad_code && bad_code.error().code == hexlab::ErrorCode::malformed,
                    "missing abbreviation code was not rejected");
    auto bad_string = fixture();
    // Replace the CU name form from inline string to strp and supply an invalid offset.
    bad_string.abbrev.clear();
    uleb(bad_string.abbrev, 1); uleb(bad_string.abbrev, 0x11); bad_string.abbrev.push_back(1);
    uleb(bad_string.abbrev, 0x03); uleb(bad_string.abbrev, 0x0e); uleb(bad_string.abbrev, 0); uleb(bad_string.abbrev, 0);
    uleb(bad_string.abbrev, 0);
    // Unit's CU name is now read as an offset at its first byte; keep the unit bounded.
    bad_string.info[12] = 0xff; bad_string.info[13] = 0xff; bad_string.info[14] = 0xff; bad_string.info[15] = 0xff;
    auto bad_offset = hexlab::symbols::import_dwarf_v4({"bad-string", bad_string.info, bad_string.abbrev, {}});
    ok &= check(!bad_offset && bad_offset.error().code == hexlab::ErrorCode::malformed,
                "out-of-range .debug_str reference was not rejected");
    return ok;
}
bool cancellation_is_observed() {
    auto data = fixture();
    std::stop_source stop;
    stop.request_stop();
    auto result = hexlab::symbols::import_dwarf_v4({"canceled", data.info, data.abbrev, data.strings, stop.get_token()});
    return check(!result && result.error().code == hexlab::ErrorCode::canceled,
                 "DWARF v4 import observes cancellation before processing a unit");
}
} // namespace

int main() {
    return imports_symbols_and_source_attributed_types() && rejects_truncated_units_and_unsupported_versions() &&
                   rejects_missing_abbreviations_and_string_bounds() && cancellation_is_observed()
               ? 0 : 1;
}
