#pragma once
#include "hexlab/loaders/loader.hpp"
#include <span>
#include <stop_token>
#include <string_view>
#include <vector>

namespace hexlab {

struct CoffLinkLimits {
    std::size_t max_objects = 100'000;
    std::size_t max_symbols = 2'000'000;
    std::size_t max_relocations = 4'000'000;
    std::size_t max_runtime_functions = 4'000'000;
    std::uint64_t max_output_bytes = 512ULL * 1024 * 1024;
};

// Architecture-selected static PE32+ linking. All inputs must have the same
// supported machine (AMD64 or ordinary ARM64 COFF). ARM64 supports initialized
// .text/.rdata/.data and zero-filled .bss, common/COMDAT selection, checked
// absolute/relative fields, branches, ADR/ADRP and page-offset instructions.
// ARM64 BigObj, unwind, imports, TLS and unsupported relocations reject.
HEXLAB_LOADERS_EXPORT Result<std::vector<std::byte>> link_coff_executable(
    std::span<const std::shared_ptr<const ByteStorage>>, std::string_view entry_symbol,
    std::stop_token = {}, CoffLinkLimits = {});

// AMD64-only compatibility entry point. Links ordinary and BigObj AMD64 COFF
// .obj inputs into a static PE32+ console image; other machines still reject.
// The bounded subset supports initialized .text/.rdata/.data/.pdata/.xdata,
// uninitialized .bss, long section names, deterministic subsection merging,
// external/common symbols, supported COMDAT selection, and AMD64 ADDR64,
// ADDR32, ADDR32NB, and REL32 through REL32_5 relocations. Common symbols are
// coalesced into zero-filled .bss. AMD64 unwind contributions are merged,
// relocated, checked, sorted, and published in the PE exception directory.
// AMD64 import/short-import records are emitted into a grouped PE import table
// and writable IAT, with import-by-name/ordinal entries and function jump
// thunks. Other import architectures, delay imports, TLS, base relocations,
// weak-external aliases, and CRT remain unsupported.
HEXLAB_LOADERS_EXPORT Result<std::vector<std::byte>> link_coff_amd64_executable(
    std::span<const std::shared_ptr<const ByteStorage>>, std::string_view entry_symbol,
    std::stop_token = {}, CoffLinkLimits = {});

} // namespace hexlab
