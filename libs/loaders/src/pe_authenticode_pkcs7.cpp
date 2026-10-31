#include "hexlab/loaders/pe.hpp"
#include "hexlab/image/pe_metadata.hpp"
#include <algorithm>
#include <initializer_list>
#include <limits>
#include <span>
#include <string>

namespace hexlab {
namespace {
struct DerNode {
    std::uint8_t tag = 0;
    std::span<const std::byte> content;
    std::span<const std::byte> encoded;
};

Result<DerNode> der_node(std::span<const std::byte> bytes, std::size_t &cursor) {
    if (cursor > bytes.size() || bytes.size() - cursor < 2)
        return Error{ErrorCode::malformed, "Truncated DER tag or length"};
    const auto start = cursor;
    DerNode result;
    result.tag = std::to_integer<std::uint8_t>(bytes[cursor++]);
    const auto first_length = std::to_integer<std::uint8_t>(bytes[cursor++]);
    std::size_t length = first_length;
    if (first_length & 0x80u) {
        const auto count = first_length & 0x7fu;
        if (count == 0 || count > sizeof(std::size_t) || count > bytes.size() - cursor)
            return Error{ErrorCode::malformed, "Invalid or truncated DER length"};
        if (bytes[cursor] == std::byte{0})
            return Error{ErrorCode::malformed, "DER length has a leading zero"};
        length = 0;
        for (unsigned i = 0; i < count; ++i) {
            if (length > (std::numeric_limits<std::size_t>::max() >> 8))
                return Error{ErrorCode::overflow, "DER length overflows the host size"};
            length = (length << 8) | std::to_integer<std::uint8_t>(bytes[cursor++]);
        }
        if (length < 128)
            return Error{ErrorCode::malformed, "DER long-form length is not minimal"};
    }
    if (length > bytes.size() - cursor)
        return Error{ErrorCode::malformed, "DER value exceeds its containing extent"};
    result.content = bytes.subspan(cursor, length);
    cursor += length;
    result.encoded = bytes.subspan(start, cursor - start);
    return result;
}

bool is_oid(const DerNode &node, std::initializer_list<std::uint8_t> oid) {
    return node.tag == 0x06 && node.content.size() == oid.size() &&
        std::equal(node.content.begin(), node.content.end(), oid.begin(), [](std::byte a, std::uint8_t b) {
            return std::to_integer<std::uint8_t>(a) == b;
        });
}

Result<DerNode> only_child(const DerNode &parent, std::uint8_t tag, const char *what) {
    std::size_t cursor = 0;
    auto child = der_node(parent.content, cursor);
    if (!child) return child.error();
    if (child.value().tag != tag || cursor != parent.content.size())
        return Error{ErrorCode::malformed, std::string("Invalid ") + what + " DER wrapper"};
    return child.value();
}

Result<PeAuthenticodeDigestMatch> parse_signed_digest(
    const Image &image, const ImageMetadata &metadata, const PeCertificateRecord &record,
    std::stop_token stop) {
    if (!metadata.pe || !metadata.pe->certificate_table)
        return Error{ErrorCode::invalid_argument, "PE certificate table is unavailable"};
    if (record.type != 0x0002)
        return Error{ErrorCode::unsupported, "WIN_CERTIFICATE is not PKCS#7 signed data"};
    if (record.payload.size() != 1 || record.payload.front().size > 64ull * 1024 * 1024 ||
        record.payload.front().size > std::numeric_limits<std::size_t>::max())
        return Error{ErrorCode::resource_limit, "PKCS#7 payload is fragmented or exceeds 64 MiB"};
    if (stop.stop_requested()) return Error{ErrorCode::canceled, "Authenticode digest inspection canceled"};
    const auto &payload_range = record.payload.front();
    auto payload_view = image.storage()->read_at(payload_range.offset,
        static_cast<std::size_t>(payload_range.size));
    if (!payload_view) return payload_view.error();
    const auto payload = payload_view.value().bytes;
    if (payload.size() != payload_range.size)
        return Error{ErrorCode::malformed, "PKCS#7 payload read returned a short range"};

    std::size_t cursor = 0;
    auto content_info = der_node(payload, cursor);
    if (!content_info) return content_info.error();
    if (content_info.value().tag != 0x30 || cursor != payload.size())
        return Error{ErrorCode::malformed, "PKCS#7 ContentInfo is not one complete DER sequence"};
    cursor = 0;
    auto content_type = der_node(content_info.value().content, cursor);
    auto explicit_signed_data = der_node(content_info.value().content, cursor);
    if (!content_type || !explicit_signed_data) return Error{ErrorCode::malformed, "Truncated PKCS#7 ContentInfo"};
    if (!is_oid(content_type.value(), {0x2a,0x86,0x48,0x86,0xf7,0x0d,0x01,0x07,0x02}) ||
        explicit_signed_data.value().tag != 0xa0 || cursor != content_info.value().content.size())
        return Error{ErrorCode::unsupported, "PKCS#7 ContentInfo is not SignedData"};
    auto signed_data = only_child(explicit_signed_data.value(), 0x30, "SignedData");
    if (!signed_data) return signed_data.error();

    // SignedData starts with version and digestAlgorithms. Its encapsulated
    // content is the next sequence; signer and certificate sets are not needed
    // for the image-digest comparison and are never interpreted as trusted.
    cursor = 0;
    auto version = der_node(signed_data.value().content, cursor);
    auto algorithms = der_node(signed_data.value().content, cursor);
    auto encapsulated = der_node(signed_data.value().content, cursor);
    if (!version || !algorithms || !encapsulated || version.value().tag != 0x02 ||
        algorithms.value().tag != 0x31 || encapsulated.value().tag != 0x30)
        return Error{ErrorCode::malformed, "Invalid PKCS#7 SignedData prefix"};
    std::size_t eci_cursor = 0;
    auto econtent_type = der_node(encapsulated.value().content, eci_cursor);
    auto explicit_content = der_node(encapsulated.value().content, eci_cursor);
    if (!econtent_type || !explicit_content || explicit_content.value().tag != 0xa0 ||
        eci_cursor != encapsulated.value().content.size())
        return Error{ErrorCode::malformed, "Invalid Authenticode encapsulated content"};
    if (!is_oid(econtent_type.value(), {0x2b,0x06,0x01,0x04,0x01,0x82,0x37,0x02,0x01,0x04}))
        return Error{ErrorCode::unsupported, "PKCS#7 content is not SpcIndirectDataContent"};
    auto octets = only_child(explicit_content.value(), 0x04, "encapsulated OCTET STRING");
    if (!octets) return octets.error();
    cursor = 0;
    auto indirect_data = der_node(octets.value().content, cursor);
    if (!indirect_data || indirect_data.value().tag != 0x30 || cursor != octets.value().content.size())
        return Error{ErrorCode::malformed, "Invalid SpcIndirectDataContent sequence"};
    cursor = 0;
    auto data = der_node(indirect_data.value().content, cursor);
    auto digest_info = der_node(indirect_data.value().content, cursor);
    if (!data || !digest_info || data.value().tag != 0x30 || digest_info.value().tag != 0x30 ||
        cursor != indirect_data.value().content.size())
        return Error{ErrorCode::malformed, "Invalid SpcIndirectDataContent fields"};
    cursor = 0;
    auto algorithm = der_node(digest_info.value().content, cursor);
    auto digest_value = der_node(digest_info.value().content, cursor);
    if (!algorithm || !digest_value || algorithm.value().tag != 0x30 || digest_value.value().tag != 0x04 ||
        cursor != digest_info.value().content.size())
        return Error{ErrorCode::malformed, "Invalid Authenticode DigestInfo"};
    cursor = 0;
    auto digest_oid = der_node(algorithm.value().content, cursor);
    if (!digest_oid) return digest_oid.error();
    const bool sha1 = is_oid(digest_oid.value(), {0x2b,0x0e,0x03,0x02,0x1a});
    const bool sha256 = is_oid(digest_oid.value(), {0x60,0x86,0x48,0x01,0x65,0x03,0x04,0x02,0x01});
    if (!sha1 && !sha256)
        return Error{ErrorCode::unsupported, "Authenticode image digest algorithm is not SHA-1 or SHA-256"};
    if (cursor < algorithm.value().content.size()) {
        auto null_parameters = der_node(algorithm.value().content, cursor);
        if (!null_parameters || null_parameters.value().tag != 0x05 ||
            !null_parameters.value().content.empty() || cursor != algorithm.value().content.size())
            return Error{ErrorCode::unsupported, "Unsupported Authenticode digest AlgorithmIdentifier parameters"};
    }
    const auto digest_size = sha1 ? std::size_t{20} : Sha256Digest{}.size();
    if (digest_value.value().content.size() != digest_size)
        return Error{ErrorCode::malformed, sha1 ? "Authenticode SHA-1 digest is not 20 bytes" : "Authenticode SHA-256 digest is not 32 bytes"};
    if (stop.stop_requested()) return Error{ErrorCode::canceled, "Authenticode digest inspection canceled"};
    auto image_digest = compute_pe_authenticode_sha256(image, metadata, stop);
    if (!image_digest) return image_digest.error();
    PeAuthenticodeDigestMatch result;
    result.digest_size = static_cast<std::uint8_t>(digest_size);
    result.digest_algorithm = sha1 ? "SHA-1" : "SHA-256";
    std::copy(digest_value.value().content.begin(), digest_value.value().content.end(),
        result.signed_digest.begin());
    if (sha1)
        std::copy(image_digest.value().sha1.begin(), image_digest.value().sha1.end(), result.image_digest.begin());
    else
        result.image_digest = image_digest.value().sha256;
    result.hashed_byte_count = image_digest.value().hashed_byte_count;
    result.matches = std::equal(result.signed_digest.begin(), result.signed_digest.begin() + result.digest_size,
                                result.image_digest.begin());
    return result;
}

std::string hex_bytes(std::span<const std::byte> bytes) {
    constexpr char digits[] = "0123456789abcdef";
    std::string result;
    result.reserve(bytes.size() * 2);
    for (const auto byte : bytes) {
        const auto value = std::to_integer<unsigned>(byte);
        result.push_back(digits[value >> 4]);
        result.push_back(digits[value & 15]);
    }
    return result;
}

Result<std::string> oid_text(const DerNode &node) {
    if (node.tag != 0x06 || node.content.empty() || node.content.size() > 128)
        return Error{ErrorCode::malformed, "Invalid CMS algorithm object identifier"};
    std::vector<std::uint64_t> components;
    std::uint64_t value = 0;
    bool active = false;
    for (const auto byte : node.content) {
        const auto part = std::to_integer<std::uint8_t>(byte);
        if (value > (UINT64_MAX >> 7)) return Error{ErrorCode::overflow, "CMS object identifier component overflows"};
        value = (value << 7) | (part & 0x7fu);
        active = true;
        if (!(part & 0x80u)) {
            components.push_back(value);
            value = 0;
            active = false;
            if (components.size() > 64) return Error{ErrorCode::resource_limit, "CMS object identifier has too many components"};
        }
    }
    if (active || components.empty()) return Error{ErrorCode::malformed, "Truncated CMS object identifier"};
    const auto first = components.front();
    const auto first_arc = first < 40 ? 0u : first < 80 ? 1u : 2u;
    const auto second_arc = first_arc == 2 ? first - 80 : first % 40;
    std::string text = std::to_string(first_arc) + "." + std::to_string(second_arc);
    for (std::size_t i = 1; i < components.size(); ++i) text += "." + std::to_string(components[i]);
    return text;
}

Result<std::string> algorithm_oid(const DerNode &algorithm) {
    if (algorithm.tag != 0x30) return Error{ErrorCode::malformed, "CMS algorithm identifier is not a sequence"};
    std::size_t cursor = 0;
    auto oid = der_node(algorithm.content, cursor);
    if (!oid) return oid.error();
    auto text = oid_text(oid.value());
    if (!text) return text.error();
    if (cursor < algorithm.content.size()) {
        auto parameters = der_node(algorithm.content, cursor);
        if (!parameters || cursor != algorithm.content.size())
            return Error{ErrorCode::malformed, "CMS algorithm identifier has invalid parameters"};
    }
    return text.value();
}

Result<std::uint32_t> integer_u32(const DerNode &integer, const char *what) {
    if (integer.tag != 0x02 || integer.content.empty() || integer.content.size() > 5 ||
        (std::to_integer<std::uint8_t>(integer.content.front()) & 0x80u))
        return Error{ErrorCode::malformed, std::string("Invalid CMS ") + what};
    std::size_t first = integer.content.size() == 5 ? 1 : 0;
    if (first && integer.content.front() != std::byte{0})
        return Error{ErrorCode::overflow, std::string("CMS ") + what + " exceeds 32 bits"};
    std::uint32_t value = 0;
    for (; first < integer.content.size(); ++first)
        value = (value << 8) | std::to_integer<std::uint8_t>(integer.content[first]);
    return value;
}

Result<bool> validate_attributes(const DerNode &attributes) {
    std::size_t cursor = 0;
    while (cursor < attributes.content.size()) {
        auto attribute = der_node(attributes.content, cursor);
        if (!attribute || attribute.value().tag != 0x30)
            return Error{ErrorCode::malformed, "Invalid CMS attribute sequence"};
        std::size_t field = 0;
        auto oid = der_node(attribute.value().content, field);
        auto values = der_node(attribute.value().content, field);
        if (!oid || !oid_text(oid.value()) || !values || values.value().tag != 0x31 ||
            field != attribute.value().content.size())
            return Error{ErrorCode::malformed, "Invalid CMS attribute fields"};
        std::size_t value_cursor = 0;
        while (value_cursor < values.value().content.size())
            if (!der_node(values.value().content, value_cursor))
                return Error{ErrorCode::malformed, "Invalid CMS attribute value"};
        if (values.value().content.empty()) return Error{ErrorCode::malformed, "Empty CMS attribute value set"};
    }
    return true;
}

Result<PeAuthenticodeSignerInventory> parse_signers(
    const Image &image, const ImageMetadata &metadata, std::size_t record_index, std::stop_token stop) {
    if (!metadata.pe || !metadata.pe->certificate_table)
        return Error{ErrorCode::invalid_argument, "PE certificate table is unavailable"};
    const auto &records = metadata.pe->certificate_table->records;
    if (record_index >= records.size()) return Error{ErrorCode::out_of_bounds, "PE certificate record index is out of range"};
    const auto &record = records[record_index];
    if (record.type != 0x0002) return Error{ErrorCode::unsupported, "WIN_CERTIFICATE is not PKCS#7 signed data"};
    if (record.payload.size() != 1 || record.payload.front().size > 64ull * 1024 * 1024 ||
        record.payload.front().size > std::numeric_limits<std::size_t>::max())
        return Error{ErrorCode::resource_limit, "PKCS#7 payload is fragmented or exceeds 64 MiB"};
    if (stop.stop_requested()) return Error{ErrorCode::canceled, "Authenticode signer inspection canceled"};
    const auto &payload_range = record.payload.front();
    auto payload_view = image.storage()->read_at(payload_range.offset, static_cast<std::size_t>(payload_range.size));
    if (!payload_view) return payload_view.error();
    const auto payload = std::span<const std::byte>(payload_view.value().bytes);
    if (payload.size() != payload_range.size) return Error{ErrorCode::malformed, "PKCS#7 payload read returned a short range"};
    std::size_t cursor = 0;
    auto content = der_node(payload, cursor);
    if (!content || content.value().tag != 0x30 || cursor != payload.size())
        return Error{ErrorCode::malformed, "PKCS#7 ContentInfo is not one complete DER sequence"};
    cursor = 0;
    auto content_type = der_node(content.value().content, cursor);
    auto explicit_data = der_node(content.value().content, cursor);
    if (!content_type || !is_oid(content_type.value(), {0x2a,0x86,0x48,0x86,0xf7,0x0d,0x01,0x07,0x02}) ||
        !explicit_data || explicit_data.value().tag != 0xa0 || cursor != content.value().content.size())
        return Error{ErrorCode::unsupported, "PKCS#7 ContentInfo is not SignedData"};
    auto signed_data = only_child(explicit_data.value(), 0x30, "SignedData");
    if (!signed_data) return signed_data.error();
    cursor = 0;
    auto version = der_node(signed_data.value().content, cursor);
    auto digest_set = der_node(signed_data.value().content, cursor);
    auto encapsulated = der_node(signed_data.value().content, cursor);
    if (!version || !digest_set || digest_set.value().tag != 0x31 || !encapsulated || encapsulated.value().tag != 0x30)
        return Error{ErrorCode::malformed, "Invalid PKCS#7 SignedData prefix"};
    // Certificates and CRLs are optional context-specific fields before signerInfos.
    if (cursor < signed_data.value().content.size() && signed_data.value().content[cursor] == std::byte{0xa0}) {
        auto certificates = der_node(signed_data.value().content, cursor);
        if (!certificates) return certificates.error();
    }
    if (cursor < signed_data.value().content.size() && signed_data.value().content[cursor] == std::byte{0xa1}) {
        auto crls = der_node(signed_data.value().content, cursor);
        if (!crls) return crls.error();
    }
    auto signer_set = der_node(signed_data.value().content, cursor);
    if (!signer_set || signer_set.value().tag != 0x31 || cursor != signed_data.value().content.size())
        return Error{ErrorCode::malformed, "PKCS#7 signerInfos set is missing or malformed"};
    PeAuthenticodeSignerInventory inventory;
    inventory.certificate_record = record_index;
    std::size_t signer_cursor = 0;
    while (signer_cursor < signer_set.value().content.size()) {
        if (inventory.signers.size() == 1024) return Error{ErrorCode::resource_limit, "PKCS#7 signer count exceeds 1024"};
        if (stop.stop_requested()) return Error{ErrorCode::canceled, "Authenticode signer inspection canceled"};
        auto signer = der_node(signer_set.value().content, signer_cursor);
        if (!signer || signer.value().tag != 0x30) return Error{ErrorCode::malformed, "Invalid CMS SignerInfo sequence"};
        std::size_t field = 0;
        auto signer_version = der_node(signer.value().content, field);
        auto sid = der_node(signer.value().content, field);
        auto digest_algorithm = der_node(signer.value().content, field);
        if (!signer_version || !sid || !digest_algorithm) return Error{ErrorCode::malformed, "Truncated CMS SignerInfo"};
        auto parsed_version = integer_u32(signer_version.value(), "SignerInfo version");
        auto parsed_digest = algorithm_oid(digest_algorithm.value());
        if (!parsed_version || !parsed_digest) return !parsed_version ? parsed_version.error() : parsed_digest.error();
        PeAuthenticodeSignerInfo info;
        info.version = parsed_version.value();
        info.digest_algorithm_oid = parsed_digest.value();
        if (sid.value().tag == 0x30) {
            info.id_kind = PeAuthenticodeSignerIdKind::issuer_and_serial;
            std::size_t sid_cursor = 0;
            auto issuer = der_node(sid.value().content, sid_cursor);
            auto serial = der_node(sid.value().content, sid_cursor);
            if (!issuer || issuer.value().tag != 0x30 || !serial || serial.value().tag != 0x02 ||
                serial.value().content.empty() || sid_cursor != sid.value().content.size())
                return Error{ErrorCode::malformed, "Invalid issuer-and-serial SignerIdentifier"};
            info.issuer_der_bytes = issuer.value().encoded.size();
            info.serial_number_hex = hex_bytes(serial.value().content);
        } else if (sid.value().tag == 0x80 && !sid.value().content.empty()) {
            info.id_kind = PeAuthenticodeSignerIdKind::subject_key_identifier;
            info.subject_key_identifier_hex = hex_bytes(sid.value().content);
        } else {
            return Error{ErrorCode::unsupported, "Unsupported CMS SignerIdentifier choice"};
        }
        if (field < signer.value().content.size() && signer.value().content[field] == std::byte{0xa0}) {
            auto attrs = der_node(signer.value().content, field);
            if (!attrs) return attrs.error();
            auto valid = validate_attributes(attrs.value());
            if (!valid) return valid.error();
            info.signed_attributes_present = true;
        }
        auto signature_algorithm = der_node(signer.value().content, field);
        auto signature = der_node(signer.value().content, field);
        if (!signature_algorithm || !signature || signature.value().tag != 0x04)
            return Error{ErrorCode::malformed, "CMS SignerInfo signature fields are invalid"};
        auto parsed_signature_algorithm = algorithm_oid(signature_algorithm.value());
        if (!parsed_signature_algorithm) return parsed_signature_algorithm.error();
        info.signature_algorithm_oid = parsed_signature_algorithm.value();
        const auto payload_relative = static_cast<std::uint64_t>(signature.value().content.data() - payload.data());
        if (payload_range.offset.value > UINT64_MAX - payload_relative)
            return Error{ErrorCode::overflow, "CMS signature source offset overflows"};
        info.signature_file_offset = payload_range.offset.value + payload_relative;
        info.signature_size = signature.value().content.size();
        if (field < signer.value().content.size() && signer.value().content[field] == std::byte{0xa1}) {
            auto attrs = der_node(signer.value().content, field);
            if (!attrs) return attrs.error();
            auto valid = validate_attributes(attrs.value());
            if (!valid) return valid.error();
            info.unsigned_attributes_present = true;
        }
        if (field != signer.value().content.size()) return Error{ErrorCode::malformed, "Trailing fields in CMS SignerInfo"};
        inventory.signers.push_back(std::move(info));
    }
    return inventory;
}

Result<PeAuthenticodeCertificateInventory> parse_embedded_certificates(
    const Image &image, const ImageMetadata &metadata, std::size_t record_index, std::stop_token stop) {
    if (!metadata.pe || !metadata.pe->certificate_table)
        return Error{ErrorCode::invalid_argument, "PE certificate table is unavailable"};
    const auto &records = metadata.pe->certificate_table->records;
    if (record_index >= records.size())
        return Error{ErrorCode::out_of_bounds, "PE certificate record index is out of range"};
    const auto &record = records[record_index];
    if (record.type != 0x0002)
        return Error{ErrorCode::unsupported, "WIN_CERTIFICATE is not PKCS#7 signed data"};
    if (record.payload.size() != 1 || record.payload.front().size > 64ull * 1024 * 1024 ||
        record.payload.front().size > std::numeric_limits<std::size_t>::max())
        return Error{ErrorCode::resource_limit, "PKCS#7 payload is fragmented or exceeds 64 MiB"};
    if (stop.stop_requested()) return Error{ErrorCode::canceled, "Authenticode certificate inspection canceled"};
    const auto &range = record.payload.front();
    auto view = image.storage()->read_at(range.offset, static_cast<std::size_t>(range.size));
    if (!view) return view.error();
    const auto payload = std::span<const std::byte>(view.value().bytes);
    if (payload.size() != range.size)
        return Error{ErrorCode::malformed, "PKCS#7 payload read returned a short range"};
    std::size_t cursor = 0;
    auto content = der_node(payload, cursor);
    if (!content || content.value().tag != 0x30 || cursor != payload.size())
        return Error{ErrorCode::malformed, "PKCS#7 ContentInfo is not one complete DER sequence"};
    cursor = 0;
    auto content_type = der_node(content.value().content, cursor);
    auto explicit_data = der_node(content.value().content, cursor);
    if (!content_type || !is_oid(content_type.value(), {0x2a,0x86,0x48,0x86,0xf7,0x0d,0x01,0x07,0x02}) ||
        !explicit_data || explicit_data.value().tag != 0xa0 || cursor != content.value().content.size())
        return Error{ErrorCode::unsupported, "PKCS#7 ContentInfo is not SignedData"};
    auto signed_data = only_child(explicit_data.value(), 0x30, "SignedData");
    if (!signed_data) return signed_data.error();
    cursor = 0;
    auto version = der_node(signed_data.value().content, cursor);
    auto digest_set = der_node(signed_data.value().content, cursor);
    auto encapsulated = der_node(signed_data.value().content, cursor);
    if (!version || !digest_set || digest_set.value().tag != 0x31 || !encapsulated || encapsulated.value().tag != 0x30)
        return Error{ErrorCode::malformed, "Invalid PKCS#7 SignedData prefix"};
    if (cursor >= signed_data.value().content.size() || signed_data.value().content[cursor] != std::byte{0xa0})
        return Error{ErrorCode::unsupported, "PKCS#7 SignedData has no embedded certificate set"};
    auto cert_set = der_node(signed_data.value().content, cursor);
    if (!cert_set || cert_set.value().tag != 0xa0)
        return Error{ErrorCode::malformed, "PKCS#7 certificate set is malformed"};

    PeAuthenticodeCertificateInventory inventory;
    inventory.certificate_record = record_index;
    std::size_t cert_cursor = 0;
    while (cert_cursor < cert_set.value().content.size()) {
        if (inventory.certificates.size() == 1024)
            return Error{ErrorCode::resource_limit, "PKCS#7 certificate count exceeds 1024"};
        if (stop.stop_requested())
            return Error{ErrorCode::canceled, "Authenticode certificate inspection canceled"};
        auto certificate = der_node(cert_set.value().content, cert_cursor);
        if (!certificate) return certificate.error();
        if (certificate.value().tag != 0x30)
            return Error{ErrorCode::unsupported, "PKCS#7 certificate set contains a non-X.509 certificate choice"};
        std::size_t cert_field = 0;
        auto tbs = der_node(certificate.value().content, cert_field);
        auto outer_algorithm = der_node(certificate.value().content, cert_field);
        auto signature = der_node(certificate.value().content, cert_field);
        if (!tbs || tbs.value().tag != 0x30 || !outer_algorithm || !signature ||
            signature.value().tag != 0x03 || signature.value().content.empty() ||
            std::to_integer<unsigned>(signature.value().content.front()) > 7 ||
            cert_field != certificate.value().content.size())
            return Error{ErrorCode::malformed, "Embedded X.509 certificate envelope is malformed"};
        const auto unused_signature_bits = std::to_integer<unsigned>(signature.value().content.front());
        if (unused_signature_bits && (signature.value().content.size() < 2 ||
            (std::to_integer<unsigned>(signature.value().content.back()) & ((1u << unused_signature_bits) - 1u))))
            return Error{ErrorCode::malformed, "Embedded X.509 signature BIT STRING has invalid padding bits"};
        auto signature_oid = algorithm_oid(outer_algorithm.value());
        if (!signature_oid) return signature_oid.error();

        std::size_t tbs_field = 0;
        if (tbs.value().content.size() && tbs.value().content[tbs_field] == std::byte{0xa0}) {
            auto explicit_version = der_node(tbs.value().content, tbs_field);
            if (!explicit_version) return explicit_version.error();
            auto version_value = only_child(explicit_version.value(), 0x02, "X.509 version");
            if (!version_value) return version_value.error();
            auto parsed_version = integer_u32(version_value.value(), "X.509 version");
            if (!parsed_version || parsed_version.value() > 2)
                return Error{ErrorCode::malformed, "Embedded X.509 certificate version is invalid"};
        }
        auto serial = der_node(tbs.value().content, tbs_field);
        auto inner_algorithm = der_node(tbs.value().content, tbs_field);
        auto issuer = der_node(tbs.value().content, tbs_field);
        auto validity = der_node(tbs.value().content, tbs_field);
        auto subject = der_node(tbs.value().content, tbs_field);
        auto public_key = der_node(tbs.value().content, tbs_field);
        if (!serial || serial.value().tag != 0x02 || serial.value().content.empty() ||
            serial.value().content.size() > 64 ||
            (std::to_integer<unsigned>(serial.value().content.front()) & 0x80u) ||
            !inner_algorithm || inner_algorithm.value().tag != 0x30 || !issuer || issuer.value().tag != 0x30 ||
            !validity || validity.value().tag != 0x30 || !subject || subject.value().tag != 0x30 ||
            !public_key || public_key.value().tag != 0x30)
            return Error{ErrorCode::malformed, "Embedded X.509 TBS certificate fields are malformed"};
        auto inner_signature_oid = algorithm_oid(inner_algorithm.value());
        if (!inner_signature_oid || inner_signature_oid.value() != signature_oid.value())
            return Error{ErrorCode::malformed, "Embedded X.509 signature algorithms disagree"};
        std::size_t validity_cursor = 0;
        auto not_before = der_node(validity.value().content, validity_cursor);
        auto not_after = der_node(validity.value().content, validity_cursor);
        const auto time_text = [](const DerNode &time) -> Result<std::string> {
            if ((time.tag != 0x17 && time.tag != 0x18) || time.content.empty() || time.content.size() > 32)
                return Error{ErrorCode::malformed, "Embedded X.509 validity time is malformed"};
            std::string text;
            text.reserve(time.content.size());
            for (const auto byte : time.content) {
                const auto value = std::to_integer<unsigned char>(byte);
                if (value < 0x20 || value > 0x7e)
                    return Error{ErrorCode::malformed, "Embedded X.509 validity time is not printable ASCII"};
                text.push_back(static_cast<char>(value));
            }
            return text;
        };
        if (!not_before || !not_after || validity_cursor != validity.value().content.size())
            return Error{ErrorCode::malformed, "Embedded X.509 validity must contain exactly two times"};
        auto before_text = time_text(not_before.value());
        auto after_text = time_text(not_after.value());
        if (!before_text || !after_text) return !before_text ? before_text.error() : after_text.error();
        // Consume remaining TBS fields so malformed trailing DER cannot be hidden.
        while (tbs_field < tbs.value().content.size()) {
            auto extension = der_node(tbs.value().content, tbs_field);
            if (!extension) return extension.error();
        }
        const auto payload_offset = [&](std::span<const std::byte> bytes) {
            return static_cast<std::uint64_t>(bytes.data() - payload.data());
        };
        PeAuthenticodeEmbeddedCertificate item;
        const auto cert_relative = payload_offset(certificate.value().encoded);
        const auto issuer_relative = payload_offset(issuer.value().encoded);
        const auto subject_relative = payload_offset(subject.value().encoded);
        if (range.offset.value > UINT64_MAX - cert_relative || range.offset.value > UINT64_MAX - issuer_relative ||
            range.offset.value > UINT64_MAX - subject_relative)
            return Error{ErrorCode::overflow, "Embedded certificate source offset overflows"};
        item.certificate_file_offset = range.offset.value + cert_relative;
        item.certificate_size = certificate.value().encoded.size();
        item.serial_number_hex = hex_bytes(serial.value().content);
        item.issuer_file_offset = range.offset.value + issuer_relative;
        item.issuer_der_size = issuer.value().encoded.size();
        item.subject_file_offset = range.offset.value + subject_relative;
        item.subject_der_size = subject.value().encoded.size();
        item.not_before = std::move(before_text.value());
        item.not_after = std::move(after_text.value());
        item.signature_algorithm_oid = std::move(signature_oid.value());
        inventory.certificates.push_back(std::move(item));
    }
    return inventory;
}
} // namespace

Result<PeAuthenticodeDigestMatch> inspect_pe_authenticode_digest(
    const Image &image, const ImageMetadata &metadata, std::size_t certificate_record,
    std::stop_token stop) {
    if (!metadata.pe || !metadata.pe->certificate_table)
        return Error{ErrorCode::invalid_argument, "PE certificate table is unavailable"};
    const auto &records = metadata.pe->certificate_table->records;
    if (certificate_record >= records.size())
        return Error{ErrorCode::out_of_bounds, "PE certificate record index is out of range"};
    return parse_signed_digest(image, metadata, records[certificate_record], stop);
}

Result<PeAuthenticodeSignerInventory> inspect_pe_authenticode_signers(
    const Image &image, const ImageMetadata &metadata, std::size_t certificate_record,
    std::stop_token stop) {
    return parse_signers(image, metadata, certificate_record, stop);
}
Result<PeAuthenticodeCertificateInventory> inspect_pe_authenticode_certificates(
    const Image &image, const ImageMetadata &metadata, std::size_t certificate_record,
    std::stop_token stop) {
    return parse_embedded_certificates(image, metadata, certificate_record, stop);
}
} // namespace hexlab
