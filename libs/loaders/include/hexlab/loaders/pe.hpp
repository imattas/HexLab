#pragma once
#include "hexlab/core/sha256.hpp"
#include "hexlab/loaders/loaded_image.hpp"
#include <array>
#include <cstddef>
#include <cstdint>
#include <optional>
#include <stop_token>
#include <string>
#include <vector>
namespace hexlab {
HEXLAB_LOADERS_EXPORT Result<LoadedImage> load_pe(std::shared_ptr<const ByteStorage>, std::stop_token);
// Maps at an explicit runtime base, applying supported PE base relocations
// through an immutable source overlay.
HEXLAB_LOADERS_EXPORT Result<LoadedImage> load_pe_at_base(std::shared_ptr<const ByteStorage>, std::uint64_t,
                                                          std::stop_token);
// Select the image bytes and decode context for a Windows-on-Arm process.
// Metadata remains tied to the original PE file and source locations.
HEXLAB_LOADERS_EXPORT Result<std::shared_ptr<const Image>> select_pe_runtime_view(
    const LoadedImage &, PeRuntimeArchitecture);

// COFF symbols are optional records embedded after the PE headers. They are
// not part of the PE image mapping, so this bounded reader exposes them
// separately from ImageMetadata.
struct PeCoffSymbol {
    std::string name;
    std::uint32_t raw_index = 0, value = 0;
    std::int16_t section_number = 0;
    std::uint16_t type = 0;
    std::uint8_t storage_class = 0;
    // Present for a valid positive section number when Value falls inside the
    // section's declared image extent.
    std::optional<std::uint32_t> section_rva;
    // Decoded only for function-typed external/static symbols whose first
    // auxiliary record describes a bounded file-backed executable extent.
    std::optional<std::uint32_t> function_size;
    FileOffset function_aux_file_offset{};
    std::optional<PeCoffSectionDefinition> section_definition;
    // Present only for validated IMAGE_SYM_CLASS_WEAK_EXTERNAL records.
    // The tag index refers to another primary symbol's raw table index.
    std::optional<std::uint32_t> weak_external_tag_index;
    std::optional<PeWeakExternalSearch> weak_external_search;
    std::optional<std::string> weak_external_target_name;
    std::vector<std::array<std::byte, 18>> auxiliary_records;
    FileOffset source_file_offset{};
    bool operator==(const PeCoffSymbol &) const = default;
};
struct PeCoffSymbolTable {
    FileOffset symbol_table_file_offset{};
    FileOffset string_table_file_offset{};
    std::uint32_t declared_record_count = 0, string_table_size = 0;
    std::vector<PeCoffSymbol> symbols;
    bool operator==(const PeCoffSymbolTable &) const = default;
};
// Reads the optional COFF symbol table from a PE file, preserving auxiliary
// records and resolving section-relative values to RVAs when they are in range.
HEXLAB_LOADERS_EXPORT Result<PeCoffSymbolTable> read_pe_coff_symbols(const LoadedImage &, std::stop_token = {});

// Computes SHA-256 and legacy SHA-1 Authenticode PE image digests from the
// loaded image's original file bytes. This calculates image digests only; it does not
// parse CMS/PKCS#7 signatures or establish certificate trust.
struct PeAuthenticodeImageDigest {
    Sha256Digest sha256{};
    std::array<std::byte, 20> sha1{};
    std::uint64_t hashed_byte_count = 0;
    bool operator==(const PeAuthenticodeImageDigest &) const = default;
};
HEXLAB_LOADERS_EXPORT Result<PeAuthenticodeImageDigest> compute_pe_authenticode_sha256(
    const Image &, const ImageMetadata &, std::stop_token = {});

// Extracts and compares a SHA-1 or SHA-256 image digest carried by a PKCS#7
// Authenticode WIN_CERTIFICATE. This does not validate the CMS signer,
// certificate chain, timestamp, revocation state, or publisher trust.
struct PeAuthenticodeDigestMatch {
    Sha256Digest signed_digest{};
    Sha256Digest image_digest{};
    std::uint8_t digest_size = 32;
    std::string digest_algorithm;
    bool matches = false;
    std::uint64_t hashed_byte_count = 0;
    bool operator==(const PeAuthenticodeDigestMatch &) const = default;
};
HEXLAB_LOADERS_EXPORT Result<PeAuthenticodeDigestMatch> inspect_pe_authenticode_digest(
    const Image &, const ImageMetadata &, std::size_t certificate_record,
    std::stop_token = {});

enum class PeAuthenticodeSignerIdKind : std::uint8_t { issuer_and_serial, subject_key_identifier };
struct PeAuthenticodeSignerInfo {
    std::uint32_t version = 0;
    PeAuthenticodeSignerIdKind id_kind = PeAuthenticodeSignerIdKind::issuer_and_serial;
    std::uint64_t issuer_der_bytes = 0;
    std::string serial_number_hex;
    std::string subject_key_identifier_hex;
    std::string digest_algorithm_oid;
    std::string signature_algorithm_oid;
    std::uint64_t signature_file_offset = 0;
    std::uint64_t signature_size = 0;
    bool signed_attributes_present = false;
    bool unsigned_attributes_present = false;
    bool operator==(const PeAuthenticodeSignerInfo &) const = default;
};
struct PeAuthenticodeSignerInventory {
    std::size_t certificate_record = 0;
    std::vector<PeAuthenticodeSignerInfo> signers;
};
// Parses bounded CMS/PKCS#7 SignerInfo metadata from one PKCS#7
// WIN_CERTIFICATE. It does not verify signatures or establish trust.
HEXLAB_LOADERS_EXPORT Result<PeAuthenticodeSignerInventory> inspect_pe_authenticode_signers(
    const Image &, const ImageMetadata &, std::size_t certificate_record,
    std::stop_token = {});

struct PeAuthenticodeSignerVerification {
    bool signature_valid = false;
    std::uint32_t provider_error = 0;
    bool operator==(const PeAuthenticodeSignerVerification &) const = default;
};
struct PeAuthenticodeSignatureVerification {
    std::size_t certificate_record = 0;
    std::vector<PeAuthenticodeSignerVerification> signers;
};
// Verifies each CMS signer signature using signer certificates embedded in
// the PKCS#7 message. This does not build a certificate chain or establish
// publisher trust; non-Windows providers report unsupported.
HEXLAB_LOADERS_EXPORT Result<PeAuthenticodeSignatureVerification> verify_pe_authenticode_signatures(
    const Image &, const ImageMetadata &, std::size_t certificate_record,
    std::stop_token = {});

// Decoded compiler product/count pair from the XOR-encoded Rich header in the
// DOS stub. The product id and build number are the high and low 16 bits of
// comp_id, respectively. This is provenance metadata, not a verified compiler
// identity.
struct PeRichHeaderRecord {
    std::uint32_t comp_id = 0;
    std::uint32_t count = 0;
    bool operator==(const PeRichHeaderRecord &) const = default;
};
struct PeRichHeader {
    FileOffset source_file_offset{};
    std::uint32_t byte_size = 0;
    std::uint32_t xor_key = 0;
    std::vector<PeRichHeaderRecord> records;
    bool operator==(const PeRichHeader &) const = default;
};
HEXLAB_LOADERS_EXPORT Result<std::optional<PeRichHeader>> inspect_pe_rich_header(
    const ByteStorage &, std::stop_token = {});

// Materializes the PE TLS template for one thread as template bytes followed
// by zero_fill zero bytes. This does not write AddressOfIndex or run callbacks.
HEXLAB_LOADERS_EXPORT Result<std::vector<std::byte>> materialize_pe_tls_template(
    const LoadedImage &, std::uint64_t maximum_size = 64ULL * 1024 * 1024);

// Summarizes each PE section's file-backed bytes and memory permissions.
// Entropy is Shannon bits/byte over the declared raw section extent.
struct PeSectionProfile {
    std::string name;
    Rva rva{};
    std::uint32_t virtual_size = 0, raw_size = 0, characteristics = 0;
    double entropy_bits_per_byte = 0.0;
    bool readable = false, writable = false, executable = false;
    bool operator==(const PeSectionProfile &) const = default;
};
HEXLAB_LOADERS_EXPORT Result<std::vector<PeSectionProfile>> analyze_pe_sections(
    const ByteStorage &, const ImageMetadata &, std::stop_token = {});
}
