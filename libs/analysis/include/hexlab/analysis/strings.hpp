#pragma once
#include "hexlab/image/metadata.hpp"
#include "hexlab/analysis/analysis_export.hpp"
#include "hexlab/processors/instruction.hpp"
#include <stop_token>
#include <functional>
#include <limits>
#include <span>

namespace hexlab {
struct AnalysisOptions {
    std::size_t min_string_characters=4;
    std::size_t instruction_budget=1000000;
    std::size_t string_budget=1000000;
    // Maximum byte inspections across all string encodings in one scan.
    // SIZE_MAX preserves exhaustive scanning; a smaller value returns a
    // partial StringScan with complete=false when exhausted.
    std::size_t string_scan_work_budget=std::numeric_limits<std::size_t>::max();
    std::size_t function_budget=100000,block_budget=1000000,membership_budget=8000000;
    using SemanticDecoder = std::function<Result<std::optional<Instruction>>(
        DecodeContext, Address, std::span<const std::byte>)>;
    using DecoderIdentity = std::function<std::vector<std::byte>()>;
    // Optional host-provided decoder. It is consulted only after the built-in
    // decoder reports unsupported, and its identity participates in cache keys.
    SemanticDecoder semantic_decoder;
    DecoderIdentity semantic_decoder_identity;
};
// Existing values are stable because cached records persist this byte value.
enum class StringEncoding : std::uint8_t {
    ascii = 0, utf16le = 1, utf8 = 2, utf16be = 3, utf32le = 4, utf32be = 5,
    windows1252 = 6, windows1251 = 7, windows1250 = 8, windows1254 = 9,
    windows1253 = 10, windows1255 = 11, windows1256 = 12
};
struct StringRecord {
    StringEncoding encoding;
    std::string preview;
    std::uint64_t characters,byte_length;
    FileOffset file_offset;
    std::optional<Address> address;
    bool terminated;
};
struct StringScan {
    std::vector<StringRecord> records;
    std::vector<Diagnostic> diagnostics;
    bool complete=true;
};
HEXLAB_ANALYSIS_EXPORT Result<StringScan> find_strings(const Image&,const AnalysisOptions&,std::stop_token);
}
