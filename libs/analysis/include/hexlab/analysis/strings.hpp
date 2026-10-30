#pragma once
#include "hexlab/image/metadata.hpp"
#include "hexlab/image/read_set.hpp"
#include "hexlab/analysis/analysis_export.hpp"
#include "hexlab/processors/instruction.hpp"
#include <stop_token>
#include <functional>
#include <limits>
#include <span>
#include <string>
#include <string_view>
#include <vector>

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
    struct SemanticDecoderInput {
        // Stable caller-selected name for one immutable external input.
        std::string identity;
        Sha256Digest sha256{};
        // Primary-image file ranges read while consulting this input. If an
        // edit intersects any declared range, incremental analysis rebuilds
        // all semantic-decoder-derived facts.
        std::vector<FileRange> image_reads;
        bool operator==(const SemanticDecoderInput&) const = default;
    };
    // Returns a complete manifest of external inputs read by semantic_decoder.
    // An empty vector certifies that it reads no external inputs. Missing,
    // throwing, or over-limit manifests are treated as unknown.
    using SemanticDecoderReadSet = std::function<std::vector<SemanticDecoderInput>()>;
    // Optional coarse function-recovery progress. Stages are currently
    // "instruction-discovery" and "complete"; returning false cancels the
    // operation. This runtime callback is excluded from analysis cache keys.
    using Progress = std::function<bool(std::string_view, std::uint64_t, std::uint64_t)>;
    Progress progress;
    // Optional host-provided decoder. It is consulted only after the built-in
    // decoder reports unsupported, and its identity participates in cache keys.
    SemanticDecoder semantic_decoder;
    DecoderIdentity semantic_decoder_identity;
    SemanticDecoderReadSet semantic_decoder_read_set;
};
HEXLAB_ANALYSIS_EXPORT bool semantic_decoder_read_set_complete(const AnalysisOptions&) noexcept;
HEXLAB_ANALYSIS_EXPORT bool semantic_decoder_image_reads_intersect(
    const AnalysisOptions&, std::span<const FileRange> changed_ranges, std::uint64_t image_size) noexcept;
// Existing values are stable because cached records persist this byte value.
enum class StringEncoding : std::uint8_t {
    ascii = 0, utf16le = 1, utf8 = 2, utf16be = 3, utf32le = 4, utf32be = 5,
    windows1252 = 6, windows1251 = 7, windows1250 = 8, windows1254 = 9,
    windows1253 = 10, windows1255 = 11, windows1256 = 12, windows1257 = 13,
    windows1258 = 14, iso8859_2 = 15, iso8859_5 = 16,
    dos437 = 17, dos850 = 18, iso8859_15 = 19, iso8859_9 = 20,
    dos866 = 21, dos852 = 22, koi8_r = 23, mac_roman = 24, iso8859_1 = 25,
    iso8859_3 = 26, iso8859_4 = 27, iso8859_6 = 28, iso8859_7 = 29, iso8859_10 = 30,
    iso8859_13 = 31, iso8859_14 = 32, iso8859_16 = 33, iso8859_8 = 34,
    iso8859_11 = 35, windows874 = 36, koi8_u = 37, mac_cyrillic = 38,
    ebcdic_cp037 = 39, ebcdic_cp500 = 40, ebcdic_cp1047 = 41, ebcdic_cp1140 = 42,
    windows932 = 43, windows936 = 44
};
// Coarse script-family hint derived from the retained UTF-8 preview. This is
// not a locale, language, or source-encoding determination.
enum class StringScript : std::uint8_t {
    unknown = 0, latin = 1, cyrillic = 2, greek = 3, hebrew = 4, arabic = 5,
    thai = 6, han = 7, kana = 8, hangul = 9, other = 10, mixed = 11,
    armenian = 12, devanagari = 13, bengali = 14, gurmukhi = 15, gujarati = 16,
    odia = 17, tamil = 18, telugu = 19, kannada = 20, malayalam = 21,
    sinhala = 22, lao = 23, tibetan = 24, myanmar = 25, georgian = 26,
    ethiopic = 27, cherokee = 28, canadian_aboriginal = 29, khmer = 30,
    mongolian = 31, syriac = 32, thaana = 33, nko = 34, tifinagh = 35,
    vai = 36, yi = 37, adlam = 38, osage = 39, ol_chiki = 40
};
HEXLAB_ANALYSIS_EXPORT StringScript classify_string_script(std::string_view utf8_preview) noexcept;
HEXLAB_ANALYSIS_EXPORT std::string_view string_script_name(StringScript) noexcept;
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
