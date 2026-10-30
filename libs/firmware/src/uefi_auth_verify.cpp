#include "hexlab/firmware/uefi_capsule.hpp"
#include <algorithm>
#include <limits>

#ifdef _WIN32
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <wincrypt.h>
#endif

namespace hexlab::firmware {
namespace {
std::uint16_t read_u16(std::span<const std::byte> bytes, std::size_t offset) {
    return static_cast<std::uint16_t>(std::to_integer<std::uint8_t>(bytes[offset]) |
        (std::uint16_t(std::to_integer<std::uint8_t>(bytes[offset + 1])) << 8));
}
std::uint32_t read_u32(std::span<const std::byte> bytes, std::size_t offset) {
    return std::uint32_t(read_u16(bytes, offset)) | (std::uint32_t(read_u16(bytes, offset + 2)) << 16);
}
constexpr std::array<std::uint8_t, 16> pkcs7_guid{
    0x9d,0xd2,0xaf,0x4a,0xdf,0x68,0xee,0x49,0x8a,0xa9,0x34,0x7d,0x37,0x56,0x65,0xa7};
}
Result<UefiFmpAuthenticationVerification> verify_uefi_fmp_authentication(
    std::span<const std::byte> capsule_bytes, const UefiCapsuleItem &item, std::stop_token stop) {
    if (item.kind != UefiCapsuleItemKind::fmp_payload || !item.authentication_present)
        return Error{ErrorCode::invalid_argument, "FMP item has no recognized authentication prefix"};
    constexpr std::uint64_t max_signature_bytes = 64ull * 1024 * 1024;
    if (!item.authentication_certificate_data_size ||
        item.authentication_certificate_data_size > max_signature_bytes ||
        item.authentication_certificate_data_size > UINT32_MAX ||
        item.authentication_certificate_data_offset > capsule_bytes.size() ||
        item.authentication_certificate_data_size > capsule_bytes.size() - item.authentication_certificate_data_offset)
        return Error{ErrorCode::out_of_bounds, "FMP PKCS#7 signature extent exceeds the input or verification budget"};
    if (item.authentication_header_size > item.update_image_size ||
        item.authentication_header_size < 32 || item.payload_offset < item.authentication_header_size)
        return Error{ErrorCode::malformed, "FMP authentication prefix does not match the update-image extent"};
    const auto count_offset = item.payload_offset - item.authentication_header_size;
    if (count_offset > UINT64_MAX - 32 ||
        item.authentication_certificate_offset != count_offset + 8 ||
        item.authentication_certificate_data_offset != count_offset + 32 ||
        item.authentication_certificate_size != item.authentication_header_size - 8 ||
        item.authentication_certificate_data_size != item.authentication_header_size - 32 ||
        item.authentication_certificate_guid != pkcs7_guid)
        return Error{ErrorCode::malformed, "FMP PKCS#7 range disagrees with its authentication prefix"};
    const auto signed_size = std::uint64_t(item.update_image_size) - item.authentication_header_size;
    if (count_offset > capsule_bytes.size() || 8 > capsule_bytes.size() - count_offset ||
        item.payload_offset > capsule_bytes.size() || signed_size > capsule_bytes.size() - item.payload_offset)
        return Error{ErrorCode::out_of_bounds, "FMP authenticated content extent exceeds the input"};
    const auto certificate_header = static_cast<std::size_t>(count_offset + 8);
    if (item.authentication_certificate_size < 24 ||
        item.authentication_certificate_size > capsule_bytes.size() - certificate_header ||
        read_u32(capsule_bytes, certificate_header) != item.authentication_certificate_size ||
        read_u16(capsule_bytes, certificate_header + 4) != 0x0200 ||
        read_u16(capsule_bytes, certificate_header + 6) != 0x0ef1 ||
        !std::equal(pkcs7_guid.begin(), pkcs7_guid.end(), capsule_bytes.begin() + certificate_header + 8,
            [](std::uint8_t expected, std::byte actual) { return expected == std::to_integer<std::uint8_t>(actual); }))
        return Error{ErrorCode::malformed, "FMP PKCS#7 WIN_CERTIFICATE header is inconsistent"};
    if (stop.stop_requested()) return Error{ErrorCode::canceled, "FMP authentication verification canceled"};
#ifdef _WIN32
    const auto signature = capsule_bytes.subspan(
        static_cast<std::size_t>(item.authentication_certificate_data_offset),
        static_cast<std::size_t>(item.authentication_certificate_data_size));
    HCRYPTMSG message = CryptMsgOpenToDecode(X509_ASN_ENCODING | PKCS_7_ASN_ENCODING,
        CMSG_DETACHED_FLAG, CMSG_SIGNED, 0, nullptr, nullptr);
    if (!message) return Error{ErrorCode::malformed, "Crypt32 could not open the detached FMP PKCS#7 message"};
    struct MessageGuard {
        HCRYPTMSG value;
        ~MessageGuard() { if (value) CryptMsgClose(value); }
    } message_guard{message};
    if (!CryptMsgUpdate(message, reinterpret_cast<const BYTE *>(signature.data()),
                        static_cast<DWORD>(signature.size()), TRUE))
        return Error{ErrorCode::malformed, "Crypt32 could not decode the detached FMP PKCS#7 message"};
    DWORD signer_count = 0, count_size = sizeof(signer_count);
    if (!CryptMsgGetParam(message, CMSG_SIGNER_COUNT_PARAM, 0, &signer_count, &count_size))
        return Error{ErrorCode::malformed, "Crypt32 could not read the FMP PKCS#7 signer count"};
    if (!signer_count) return Error{ErrorCode::malformed, "FMP PKCS#7 message contains no signers"};
    if (signer_count > 64)
        return Error{ErrorCode::resource_limit, "FMP PKCS#7 signer count exceeds 64"};

    const auto signed_count = capsule_bytes.subspan(static_cast<std::size_t>(count_offset), 8);
    const auto signed_image = capsule_bytes.subspan(static_cast<std::size_t>(item.payload_offset),
                                                    static_cast<std::size_t>(signed_size));
    const BYTE *signed_buffers[] = {
        reinterpret_cast<const BYTE *>(signed_count.data()),
        reinterpret_cast<const BYTE *>(signed_image.data())};
    DWORD signed_lengths[] = {
        static_cast<DWORD>(signed_count.size()), static_cast<DWORD>(signed_image.size())};
    CRYPT_VERIFY_MESSAGE_PARA verify_parameters{};
    verify_parameters.cbSize = sizeof(verify_parameters);
    verify_parameters.dwMsgAndCertEncodingType = X509_ASN_ENCODING | PKCS_7_ASN_ENCODING;

    UefiFmpAuthenticationVerification result;
    result.signers.reserve(signer_count);
    for (DWORD signer_index = 0; signer_index < signer_count; ++signer_index) {
        if (stop.stop_requested())
            return Error{ErrorCode::canceled, "FMP authentication verification canceled"};
        UefiFmpSignerVerification status;
        PCCERT_CONTEXT signer_certificate = nullptr;
        if (CryptVerifyDetachedMessageSignature(&verify_parameters, signer_index,
                reinterpret_cast<const BYTE *>(signature.data()), static_cast<DWORD>(signature.size()),
                2, signed_buffers, signed_lengths, &signer_certificate)) {
            status.signature_valid = true;
        } else {
            status.provider_error = GetLastError();
        }
        if (signer_certificate) CertFreeCertificateContext(signer_certificate);
        result.signers.push_back(status);
    }
    return result;
#else
    (void)capsule_bytes;
    (void)stop;
    return Error{ErrorCode::unsupported, "FMP detached PKCS#7 verification requires Windows Crypt32"};
#endif
}
} // namespace hexlab::firmware

