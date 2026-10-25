#pragma once

#include "hexlab/analysis/analysis_export.hpp"
#include "hexlab/analysis/signatures.hpp"
#include "hexlab/image/image.hpp"

#include <cstddef>
#include <cstdint>
#include <optional>
#include <span>
#include <stop_token>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

namespace hexlab {

enum class FlirtSymbolKind : std::uint8_t { public_name, local_name, reference };

struct FlirtSymbol {
    FlirtSymbolKind kind = FlirtSymbolKind::public_name;
    std::int32_t offset = 0;
    std::string name;
    bool operator==(const FlirtSymbol &) const = default;
};

struct FlirtPatternDefinition {
    std::vector<SignatureByte> head; // Exactly 32 bytes in the FLAIR .pat format.
    std::uint8_t crc_length = 0;
    std::uint16_t crc16 = 0;
    std::uint32_t module_length = 0;
    std::vector<FlirtSymbol> symbols;
    std::vector<SignatureByte> tail;
    // Binary .sig tail bytes have sparse offsets relative to the first byte
    // after the CRC window. Text .pat tails remain represented by `tail`.
    std::vector<std::pair<std::uint32_t, SignatureByte>> sparse_tail;
};

struct FlirtCatalog {
    std::uint32_t format_version = 1;
    std::uint8_t source_format_version = 0; // 0 for .pat, original IDASGN version for .sig.
    Architecture target_architecture = Architecture::unknown;
    ExecutionMode target_mode = ExecutionMode::unknown;
    std::string provenance;
    std::vector<FlirtPatternDefinition> patterns;
    // Exact temporary expansion size for compressed inputs, used by callers
    // aggregating several catalogs under one inflated-byte budget.
    std::size_t inflated_body_bytes = 0;
};

struct FlirtCatalogLimits {
    std::size_t max_bytes = 64 * 1024 * 1024;
    std::size_t max_inflated_bytes = 64 * 1024 * 1024;
    std::size_t max_patterns = 65536;
    std::size_t max_symbols_per_pattern = 128;
    std::size_t max_name_bytes = 256;
    std::size_t max_tail_bytes = 256;
};

// Imports the human-readable FLAIR .pat form. The catalog target and
// provenance are supplied out of band because .pat lines do not carry them.
// Reference names and non-entry symbols are retained for cross-reference
// filtering during recognition. Every symbol/reference offset must be less
// than the declared module length; out-of-module records are rejected.
HEXLAB_ANALYSIS_EXPORT Result<FlirtCatalog>
parse_flirt_pat(std::string_view, Architecture, ExecutionMode, std::string provenance,
                const FlirtCatalogLimits & = {}, std::stop_token = {});

// Imports gzip-wrapped FLAIR text catalogs, including optional RFC 1952
// header fields. Compressed and inflated data are bounded independently.
HEXLAB_ANALYSIS_EXPORT Result<FlirtCatalog>
parse_flirt_pat_gz(std::span<const std::byte>, Architecture, ExecutionMode,
                   std::string provenance, const FlirtCatalogLimits & = {}, std::stop_token = {});

// Imports binary IDA FLIRT catalogs, versions 5 through 10. Compressed zlib
// bodies are inflated in cancellable chunks within max_inflated_bytes.
HEXLAB_ANALYSIS_EXPORT Result<FlirtCatalog>
parse_flirt_sig(std::span<const std::byte>, std::string provenance,
                const FlirtCatalogLimits & = {}, std::stop_token = {});

struct FlirtRecognitionLimits {
    std::size_t max_functions = 100000;
    std::uint64_t max_pattern_candidates = 16777216;
    std::uint64_t max_comparisons = 67108864;
    std::uint64_t max_reference_checks = 16777216;
    std::size_t max_results = 100000;
    std::size_t max_catalogs = 256;
    std::size_t max_patterns = 65536;
};

struct FlirtCandidate {
    std::string name;
    std::string provenance;
    FlirtSymbolKind kind = FlirtSymbolKind::public_name;
    std::uint32_t matching_patterns = 1;
    // Index in the ordered catalog span supplied to recognize_flirt_catalogs.
    // Zero for the single-catalog overload.
    std::size_t catalog_index = 0;
};

struct FunctionFlirtMatch {
    FunctionId function{0};
    Address entry{{0}, 0};
    std::vector<FlirtCandidate> candidates;
    bool ambiguous = false;
};

struct FlirtRecognition {
    std::vector<FunctionFlirtMatch> functions;
    std::uint64_t pattern_candidates = 0;
    std::uint64_t comparisons = 0;
    bool complete = true;
    std::optional<AnalysisKey> source_key;
};

// Matches only recovered function entries. A FLAIR reference constraint is
// accepted only when the corresponding direct call reaches a function with
// the requested signature name; unresolved/cyclic candidate chains are
// dropped conservatively. Every symbol record is revalidated against its
// pattern's module extent, including catalogs constructed by API callers.
// Recognition never mutates names.
HEXLAB_ANALYSIS_EXPORT Result<FlirtRecognition>
recognize_flirt_catalog(const Image &, const ByteStorage &, const FunctionSnapshot &,
                        const FlirtCatalog &, const FlirtRecognitionLimits & = {},
                        std::stop_token = {});
// Recognizes an ordered in-memory set without merging catalog provenance.
// Catalog order and duplicates are preserved; references may resolve across
// catalogs, and all work/result limits apply to the whole set.
HEXLAB_ANALYSIS_EXPORT Result<FlirtRecognition>
recognize_flirt_catalogs(const Image &, const ByteStorage &, const FunctionSnapshot &,
                         std::span<const FlirtCatalog>, const FlirtRecognitionLimits & = {},
                         std::stop_token = {});

HEXLAB_ANALYSIS_EXPORT Result<FunctionRecognitionEvidence>
make_function_recognition_evidence(const FunctionSnapshot &, const Sha256Digest &,
                                   const FlirtRecognition &, std::stop_token = {});

} // namespace hexlab

