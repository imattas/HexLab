#pragma once

#include "hexlab/symbols/symbols_export.hpp"

#include <cstddef>
#include <string>
#include <string_view>

namespace hexlab::symbols {

enum class DemangleStatus { not_mangled, demangled, unsupported, malformed, resource_limit };

struct DemangleResult {
    DemangleStatus status = DemangleStatus::not_mangled;
    // Original spelling for every non-demangled status; callers can always
    // render this field without losing the symbol's stored identity.
    std::string text;
};

struct DemangleLimits {
    std::size_t max_input_bytes = 4096;
    std::size_t max_output_bytes = 16384;
    std::size_t max_nesting = 32;
    std::size_t max_components = 128;
    // Itanium compression dictionary limits, independent from output size.
    std::size_t max_substitutions = 256;
    std::size_t max_substitution_bytes = 64 * 1024;
};

// Bounded, allocation-contained presentation parser for common Itanium and
// Microsoft C++ ABI spellings. It never changes symbol identity or metadata.
HEXLAB_SYMBOLS_EXPORT DemangleResult demangle_cpp_name(std::string_view raw,
                                                        DemangleLimits limits = {});

// Conservative presentation support for Rust's v0 symbol format. This is a
// separate entry point because v0 names are not C++ ABI spellings.
HEXLAB_SYMBOLS_EXPORT DemangleResult demangle_rust_v0_name(std::string_view raw,
                                                            DemangleLimits limits = {});

// Dispatches supported Rust v0 names to the Rust parser and other names to the
// existing C++ ABI parser.
HEXLAB_SYMBOLS_EXPORT DemangleResult demangle_symbol_name(std::string_view raw,
                                                           DemangleLimits limits = {});

} // namespace hexlab::symbols
