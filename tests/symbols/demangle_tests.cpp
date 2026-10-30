#include "hexlab/symbols/demangle.hpp"

#include <cassert>
#include <string>

using namespace hexlab::symbols;

int main() {
    auto plain = demangle_cpp_name("??_C@_05ABC@Hello?$AA@");
    assert(plain.status == DemangleStatus::demangled);
    assert(plain.text == "char string literal \"Hello\\0\" (6 bytes)");

    auto escaped = demangle_symbol_name("??_C@_04ABC@A?0?$AA?7?$AA@");
    assert(escaped.status == DemangleStatus::demangled);
    assert(escaped.text == "char string literal \"A,\\0\\t\\0\" (5 bytes)");

    auto wide = demangle_cpp_name("??_C@_13ABC@A?$AA?$AA?$AA@");
    assert(wide.status == DemangleStatus::demangled);
    assert(wide.text == "wchar_t string literal \"A\\0\\0\\0\" (4 bytes)");

    auto truncated = demangle_cpp_name("??_C@_06ABC@Hello?$AA@");
    assert(truncated.status == DemangleStatus::demangled);
    assert(truncated.text == "char string literal \"Hello\\0...\" (7 bytes, truncated)");

    for (const auto *bad : {"??_C@_05ABC@Hi?@", "??_C@_05ABC@Hi?$A@", "??_C@_05ABC@Hi"}) {
        const std::string input(bad);
        auto result = demangle_cpp_name(input);
        assert(result.status != DemangleStatus::demangled);
        assert(result.text == input);
    }

    DemangleLimits small;
    small.max_output_bytes = 8;
    auto limited = demangle_cpp_name("??_C@_05ABC@Hello?$AA@", small);
    assert(limited.status == DemangleStatus::resource_limit);
    assert(limited.text == "??_C@_05ABC@Hello?$AA@");
}
