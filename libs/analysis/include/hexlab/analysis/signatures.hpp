#pragma once
#include "hexlab/analysis/analysis_export.hpp"
#include "hexlab/image/image.hpp"
#include "hexlab/analysis/functions.hpp"
#include "hexlab/core/sha256.hpp"
#include <cstddef>
#include <cstdint>
#include <span>
#include <stop_token>
#include <string>
#include <string_view>
#include <vector>

namespace hexlab {

// One byte is represented by a value and a bit mask. A zero mask bit is a
// wildcard, so nibble patterns such as A? and ?F are supported.
struct SignatureByte {
    std::byte value{};
    std::byte mask{};
    bool operator==(const SignatureByte &) const = default;
};
struct SignatureDefinition {
    std::string name;
    std::string provenance;
    std::vector<SignatureByte> pattern;
    std::vector<std::vector<SignatureByte>> exclusions;
    bool operator==(const SignatureDefinition &) const = default;
};
// Versioned, portable container for multiple reusable definitions. `format_version`
// is fixed at 1 by this API; legacy definition files remain accepted separately.
struct SignatureCatalog {
    std::uint32_t format_version = 1;
    std::vector<SignatureDefinition> definitions;
    // Version 2 catalogs bind byte patterns to the processor decode domain.
    // Version 1 remains accepted as an explicitly unscoped legacy format.
    Architecture target_architecture = Architecture::unknown;
    ExecutionMode target_mode = ExecutionMode::unknown;
};
// In-memory ordered composition. This has no separate file format: each
// catalog keeps its own target and provenance, and scans share one work budget.
struct SignatureCatalogSet {
    std::vector<SignatureCatalog> catalogs;
};
struct SignatureMatch {
    std::string name, provenance;
    FileOffset offset;
    Address address;
    std::size_t definition_index = 0;
    // Describes encoded pattern specificity; this is evidence metadata, not a
    // probability or a policy for selecting among competing definitions.
    std::uint32_t constrained_bits = 0;
    std::uint32_t pattern_bytes = 0;
    // Zero for the existing single-catalog/definition overloads; otherwise
    // the index in the ordered SignatureCatalogSet used for recognition.
    std::size_t catalog_index = 0;
};
struct SignatureLimits {
    std::size_t max_results = 4096;
    std::uint64_t max_candidates = 16777216;
    std::uint64_t max_comparisons = 67108864;
    std::uint64_t max_scanned_bytes = 67108864;
};
struct SignatureScan {
    std::vector<SignatureMatch> matches;
    std::uint64_t candidates = 0, comparisons = 0;
    bool complete = true;
    std::string reason;
};

// Definition format: name|provenance|positive-pattern|excluded-pattern[;...]
// Blank lines and lines beginning with # are ignored. Pattern bytes use two
// hexadecimal digits, ??, A?, or ?F, separated by whitespace. Exclusions are
// tested at the same start offset as the positive pattern.
HEXLAB_ANALYSIS_EXPORT Result<std::vector<SignatureDefinition>> parse_signature_definitions(std::string_view);
HEXLAB_ANALYSIS_EXPORT Result<SignatureCatalog> parse_signature_catalog(std::string_view);
HEXLAB_ANALYSIS_EXPORT Result<std::string> serialize_signature_catalog(const SignatureCatalog &);
HEXLAB_ANALYSIS_EXPORT Result<SignatureScan>
scan_executable_signatures(const Image &, const ByteStorage &, std::span<const SignatureDefinition>,
                           const SignatureLimits & = {}, std::stop_token = {});
HEXLAB_ANALYSIS_EXPORT Result<SignatureScan>
scan_executable_signatures(const Image &, const ByteStorage &, const SignatureCatalog &,
                           const SignatureLimits & = {}, std::stop_token = {});
HEXLAB_ANALYSIS_EXPORT Result<SignatureScan>
scan_executable_signatures(const Image &, const ByteStorage &, const SignatureCatalogSet &,
                           const SignatureLimits & = {}, std::stop_token = {});

struct FunctionSignatureOptions {
    std::size_t max_bytes = 128;
    std::size_t min_exact_bytes = 8;
};
// Builds a verified entry prefix through contiguous call/fallthrough blocks.
// Relative branch/call and statically addressed memory displacement fields are
// wildcarded when the decoder provides byte-contiguous encoding metadata;
// other encoded address fields and ordinary constants remain exact.
HEXLAB_ANALYSIS_EXPORT Result<SignatureDefinition>
create_function_signature(const Image &, const ByteStorage &, const FunctionRecord &, const FunctionSnapshot &,
                          std::string name, std::string provenance, const FunctionSignatureOptions & = {},
                          std::stop_token = {});
// Canonical four-field text, accepted by parse_signature_definitions.
HEXLAB_ANALYSIS_EXPORT Result<std::string> serialize_signature_definitions(std::span<const SignatureDefinition>);
struct FunctionSignatureMatch {
    FunctionId function{0};
    Address entry{{0}, 0};
    std::vector<SignatureMatch> candidates;
    bool ambiguous = false;
};
struct FunctionSignatureRecognition {
    std::vector<FunctionSignatureMatch> functions;
    std::uint64_t candidates = 0, comparisons = 0;
    bool complete = true;
    std::optional<AnalysisKey> source_key;
};
// Retains every matching catalog definition at recovered function entries.
// Multiple candidates are explicit ambiguity, never an automatic rename.
HEXLAB_ANALYSIS_EXPORT Result<FunctionSignatureRecognition>
recognize_function_signatures(const Image &, const ByteStorage &, const FunctionSnapshot &,
                             std::span<const SignatureDefinition>, const SignatureLimits & = {}, std::stop_token = {});
HEXLAB_ANALYSIS_EXPORT Result<FunctionSignatureRecognition>
recognize_function_signatures(const Image &, const ByteStorage &, const FunctionSnapshot &,
                             const SignatureCatalog &, const SignatureLimits & = {}, std::stop_token = {});
HEXLAB_ANALYSIS_EXPORT Result<FunctionSignatureRecognition>
recognize_function_signatures(const Image &, const ByteStorage &, const FunctionSnapshot &,
                             const SignatureCatalogSet &, const SignatureLimits & = {}, std::stop_token = {});

// Instruction-normalized fingerprints complement byte masks. They hash the
// bounded typed instruction/CFG shape; only relative or static-address fields
// with valid decoder-provided byte spans are normalized.
struct FunctionFingerprintOptions {
    std::size_t max_instructions = 512;
    std::size_t max_blocks = 1024;
    std::size_t max_token_bytes = 1024 * 1024;
};
struct FunctionFingerprintDefinition {
    std::string name, provenance;
    Architecture target_architecture = Architecture::unknown;
    ExecutionMode target_mode = ExecutionMode::unknown;
    std::uint32_t instruction_count = 0;
    Sha256Digest digest{};
    bool operator==(const FunctionFingerprintDefinition &) const = default;
};
struct FunctionFingerprintCatalog {
    std::uint32_t format_version = 1;
    Architecture target_architecture = Architecture::unknown;
    ExecutionMode target_mode = ExecutionMode::unknown;
    std::vector<FunctionFingerprintDefinition> definitions;
};
struct FunctionFingerprintLimits {
    std::size_t max_functions = 100000;
    std::uint64_t max_instructions = 4000000;
    std::uint64_t max_token_bytes = 256ull * 1024 * 1024;
    FunctionFingerprintOptions per_function;
};
struct FunctionFingerprintCandidate {
    std::string name, provenance;
    std::uint32_t instruction_count = 0;
    Sha256Digest digest{};
};
struct FunctionFingerprintMatch {
    FunctionId function{0};
    Address entry{{0}, 0};
    std::vector<FunctionFingerprintCandidate> candidates;
    bool ambiguous = false;
};
struct FunctionFingerprintRecognition {
    std::vector<FunctionFingerprintMatch> functions;
    std::uint64_t functions_scanned = 0, instructions_scanned = 0, token_bytes = 0;
    bool complete = true;
    std::optional<AnalysisKey> source_key;
};
HEXLAB_ANALYSIS_EXPORT Result<FunctionFingerprintDefinition>
create_function_fingerprint(const Image &, const ByteStorage &, const FunctionRecord &,
                            const FunctionSnapshot &, std::string name, std::string provenance,
                            const FunctionFingerprintOptions & = {}, std::stop_token = {});
HEXLAB_ANALYSIS_EXPORT Result<std::string> serialize_function_fingerprint_catalog(const FunctionFingerprintCatalog &);
HEXLAB_ANALYSIS_EXPORT Result<FunctionFingerprintCatalog> parse_function_fingerprint_catalog(std::string_view);
HEXLAB_ANALYSIS_EXPORT Result<FunctionFingerprintRecognition>
recognize_function_fingerprints(const Image &, const ByteStorage &, const FunctionSnapshot &,
                                const FunctionFingerprintCatalog &, const FunctionFingerprintLimits & = {},
                                std::stop_token = {});

enum class FunctionRecognitionKind : std::uint8_t {
    byte_signatures=1,
    normalized_fingerprints=2,
    flirt_patterns=3
};
struct FunctionRecognitionCandidateEvidence {
    std::string name,provenance;
    std::uint32_t constrained_bits=0,pattern_bytes=0,instruction_count=0;
    Sha256Digest digest{};
    // Added in evidence format 2 for FLAIR public/local names.
    std::uint8_t symbol_kind=0;
    std::uint32_t matching_patterns=0;
    bool operator==(const FunctionRecognitionCandidateEvidence&)const=default;
};
struct FunctionRecognitionRecord {
    FunctionId function{0};Address entry{{0},0};
    std::vector<FunctionRecognitionCandidateEvidence> candidates;
    bool ambiguous=false;
    bool operator==(const FunctionRecognitionRecord&)const=default;
};
// Persisted evidence is bound to the full project AnalysisKey and catalog
// digest. It records all candidates, including ambiguity, without naming edits.
struct FunctionRecognitionEvidence {
    std::uint32_t format_version=1;
    FunctionRecognitionKind kind=FunctionRecognitionKind::byte_signatures;
    AnalysisKey source_key;
    Sha256Digest catalog_digest{};
    std::vector<FunctionRecognitionRecord> functions;
    bool complete=true;
};
HEXLAB_ANALYSIS_EXPORT Result<FunctionRecognitionEvidence>
make_function_recognition_evidence(const FunctionSnapshot&,const Sha256Digest&,const FunctionSignatureRecognition&,std::stop_token={});
HEXLAB_ANALYSIS_EXPORT Result<FunctionRecognitionEvidence>
make_function_recognition_evidence(const FunctionSnapshot&,const Sha256Digest&,const FunctionFingerprintRecognition&,std::stop_token={});
HEXLAB_ANALYSIS_EXPORT Result<bool>
validate_function_recognition_evidence(const FunctionRecognitionEvidence&,const AnalysisKey&,const FunctionSnapshot&,std::stop_token={});
HEXLAB_ANALYSIS_EXPORT Result<std::vector<std::byte>>
encode_function_recognition_evidence(const FunctionRecognitionEvidence&,std::stop_token={});
HEXLAB_ANALYSIS_EXPORT Result<FunctionRecognitionEvidence>
decode_function_recognition_evidence(std::span<const std::byte>,const AnalysisKey&,FunctionRecognitionKind,std::stop_token={});

} // namespace hexlab
