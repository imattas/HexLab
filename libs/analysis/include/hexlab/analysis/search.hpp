#pragma once
#include "hexlab/analysis/functions.hpp"
#include <optional>
namespace hexlab {
struct BytePattern {std::string text;bool operator==(const BytePattern&)const=default;};
enum class TextEncoding {ascii,utf8,utf16le,utf16be,utf32le,utf32be,windows1252,iso8859_1};
struct TextQuery {std::string text;TextEncoding encoding=TextEncoding::utf8;bool case_sensitive=true;bool operator==(const TextQuery&)const=default;}; // Case folding is ASCII-only for every encoding.
enum class ImmediateInterpretation {signed_value,unsigned_value};
struct ImmediateQuery {std::string value;std::uint16_t width=64;ImmediateInterpretation interpretation=ImmediateInterpretation::unsigned_value;bool operator==(const ImmediateQuery&)const=default;};
using SearchQuery=std::variant<BytePattern,TextQuery,ImmediateQuery>;
struct SearchSource {
    std::shared_ptr<const ByteStorage> effective;std::shared_ptr<const Image> image;
    std::shared_ptr<const FunctionSnapshot> functions;AnalysisKey key;
};
struct SearchCursor {
    AnalysisKey source_key;Sha256Digest query_fingerprint{};
    std::uint64_t next_offset=0,next_instruction=0;std::uint32_t next_operand=0;
    std::optional<std::uint64_t> end_offset;
    bool operator==(const SearchCursor&)const=default;
};
struct SearchMatch {
    FileOffset offset;std::uint64_t size;std::optional<Address> address;std::optional<std::uint32_t> operand_index;
    // In instruction order. An immediate's instruction may have disjoint file backing.
    std::vector<FileRange> file_ranges;
    // Decoded immediate provenance, including aliases and split file backing.
    // address above remains a unique contiguous reverse file mapping.
    std::optional<Address> instruction_address;
};
inline Location search_match_location(const SearchMatch& match) {
    if (match.instruction_address) return *match.instruction_address;
    if (match.address) return *match.address;
    return match.offset;
}
struct SearchLimits {
    std::size_t max_results=256;
    std::uint64_t max_candidates=1048576,max_comparisons=8388608;
    // Optional inclusive file offset where the first page begins. Continuation
    // cursors carry their own position and take precedence over this value.
    std::optional<std::uint64_t> start_offset;
    // If the offset came from a VA selection, use it to disambiguate decoded
    // instructions that alias the same file byte in immediate searches.
    std::optional<Address> start_address;
    // Optional exclusive file offset; values past this document's extent are
    // clipped to its size so one bound can be used across multiple documents.
    std::optional<std::uint64_t> end_offset;
};
struct SearchPage {
    AnalysisKey source_key;Sha256Digest query_fingerprint{};
    std::optional<SearchCursor> start,next;std::vector<SearchMatch> matches;
    std::uint64_t examined_candidates=0,comparisons=0;
    bool complete=false,source_complete=true;std::string reason;
};
struct SearchResults {SearchQuery query;SearchPage page;};
// Text is supplied as strict UTF-8, then encoded according to TextEncoding.
HEXLAB_ANALYSIS_EXPORT Result<Sha256Digest> search_query_fingerprint(const SearchQuery&);
HEXLAB_ANALYSIS_EXPORT Result<SearchPage> search(const SearchSource&,const SearchQuery&,std::optional<SearchCursor> = {},const SearchLimits& = {},std::stop_token = {});
}
