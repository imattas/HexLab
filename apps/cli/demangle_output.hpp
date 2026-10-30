#pragma once
#include "hexlab/symbols/demangle.hpp"
#include <string>
#include <string_view>

namespace hexlab::cli {
inline std::string demangled_name(std::string_view raw) {
    auto result = hexlab::symbols::demangle_symbol_name(raw);
    return result.status == hexlab::symbols::DemangleStatus::demangled ? result.text : std::string{};
}
} // namespace hexlab::cli
