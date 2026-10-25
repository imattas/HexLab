#include "hexlab/types/enum_authoring.hpp"
#include <cstdint>
#include <limits>
#include <string>

int main() {
    using namespace hexlab::types;
    auto i32 = Type::integer("i32", 4, 4, true);
    auto parsed = parse_enumerators("None, Ready = 3, Error = -1, Again, Top = 0x7fffffff", i32.value());
    if (!parsed || parsed.value() != std::vector<Enumerator>{{"None", 0}, {"Ready", 3}, {"Error", UINT64_MAX},
                                                               {"Again", 0}, {"Top", 0x7fffffff}})
        return 1;
    auto u8 = Type::integer("u8", 1, 1, false);
    auto unsigned_values = parse_enumerators("Zero, Max = 255", u8.value());
    if (!unsigned_values || unsigned_values.value().back().value != 255) return 2;
    if (parse_enumerators("TooBig = 256", u8.value())) return 3;
    if (parse_enumerators("Negative = -1", u8.value())) return 4;
    if (parse_enumerators("TooSmall = -129", Type::integer("i8", 1, 1, true).value())) return 5;
    if (parse_enumerators("A, A", i32.value())) return 6;
    if (parse_enumerators("A = 1, B =", i32.value())) return 7;
    if (parse_enumerators("A,", i32.value())) return 8;
    if (parse_enumerators("Last = 2147483647, Next", i32.value())) return 9;
    auto enum_type = Type::enumeration_with_values("Status", i32.value(), parsed.value());
    if (!enum_type) return 10;
    auto bad_model_value = Type::enumeration_with_values("Bad", u8.value(), {{"TooBig", 256}});
    if (bad_model_value) return 11;
    return 0;
}
