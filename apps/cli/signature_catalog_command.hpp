#pragma once

#include "hexlab/analysis/signatures.hpp"

namespace hexlab::cli {

// Extracts and serializes one bounded catalog containing all recovered
// functions, preserving snapshot order.
Result<std::string> create_all_function_signature_catalog(
    const Image &, const ByteStorage &, const FunctionSnapshot &,
    std::string provenance, const FunctionSignatureOptions &);

} // namespace hexlab::cli
