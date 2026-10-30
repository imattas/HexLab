#include "hexlab/loaders/pe.hpp"
#include "hexlab/image/pe_metadata.hpp"
#include <limits>

#ifdef _WIN32
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <wincrypt.h>
#endif

namespace hexlab {
Result<PeAuthenticodeSignatureVerification> verify_pe_authenticode_signatures(
    const Image &image, const ImageMetadata &metadata, std::size_t certificate_record,
    std::stop_token stop) {
    if (!metadata.pe || !metadata.pe->certificate_table)
        return Error{ErrorCode::invalid_argument, "PE certificate table is unavailable"};
    const auto &records = metadata.pe->certificate_table->records;
    if (certificate_record >= records.size())
        return Error{ErrorCode::out_of_bounds, "PE certificate record index is out of range"};
    const auto &record = records[certificate_record];
    if (record.type != 0x0002)
        return Error{ErrorCode::unsupported, "WIN_CERTIFICATE is not PKCS#7 signed data"};
    if (record.payload.size() != 1 || record.payload.front().size == 0 ||
        record.payload.front().size > 64ull * 1024 * 1024 ||
        record.payload.front().size > (std::numeric_limits<std::size_t>::max)() ||
        record.payload.front().size > UINT32_MAX)
        return Error{ErrorCode::resource_limit, "PKCS#7 payload is fragmented, empty, or exceeds the verification limit"};
    if (stop.stop_requested()) return Error{ErrorCode::canceled, "Authenticode signature verification canceled"};
#ifdef _WIN32
    const auto &payload_range = record.payload.front();
    auto payload_view = image.storage()->read_at(payload_range.offset,
        static_cast<std::size_t>(payload_range.size));
    if (!payload_view) return payload_view.error();
    if (payload_view.value().bytes.size() != payload_range.size)
        return Error{ErrorCode::malformed, "PKCS#7 payload read returned a short range"};

    HCRYPTMSG message = CryptMsgOpenToDecode(X509_ASN_ENCODING | PKCS_7_ASN_ENCODING,
        0, CMSG_SIGNED, 0, nullptr, nullptr);
    if (!message) return Error{ErrorCode::malformed, "Crypt32 could not open the PKCS#7 signed message"};
    struct MessageGuard {
        HCRYPTMSG value;
        ~MessageGuard() { if (value) CryptMsgClose(value); }
    } message_guard{message};
    const auto *encoded = reinterpret_cast<const BYTE *>(payload_view.value().bytes.data());
    if (!CryptMsgUpdate(message, encoded, static_cast<DWORD>(payload_view.value().bytes.size()), TRUE))
        return Error{ErrorCode::malformed, "Crypt32 could not decode the PKCS#7 signed message"};

    DWORD signer_count = 0, count_size = sizeof(signer_count);
    if (!CryptMsgGetParam(message, CMSG_SIGNER_COUNT_PARAM, 0,
                          &signer_count, &count_size))
        return Error{ErrorCode::malformed, "Crypt32 could not read the PKCS#7 signer count"};
    if (signer_count > 1024)
        return Error{ErrorCode::resource_limit, "PKCS#7 signer count exceeds 1024"};
    if (!signer_count)
        return Error{ErrorCode::malformed, "PKCS#7 signed message contains no signers"};

    PeAuthenticodeSignatureVerification result;
    result.certificate_record = certificate_record;
    result.signers.reserve(signer_count);
    for (DWORD signer_index = 0; signer_index < signer_count; ++signer_index) {
        if (stop.stop_requested())
            return Error{ErrorCode::canceled, "Authenticode signature verification canceled"};
        PeAuthenticodeSignerVerification status;
        DWORD selected_signer = signer_index;
        PCCERT_CONTEXT signer_certificate = nullptr;
        if (CryptMsgGetAndVerifySigner(message, 0, nullptr, CMSG_USE_SIGNER_INDEX_FLAG,
                                       &signer_certificate, &selected_signer)) {
            status.signature_valid = selected_signer == signer_index;
            if (!status.signature_valid) status.provider_error = ERROR_INVALID_DATA;
            if (signer_certificate) CertFreeCertificateContext(signer_certificate);
        } else {
            status.provider_error = GetLastError();
            if (signer_certificate) CertFreeCertificateContext(signer_certificate);
        }
        result.signers.push_back(status);
    }
    return result;
#else
    (void)image;
    (void)stop;
    return Error{ErrorCode::unsupported, "CMS signer verification requires the Windows Crypt32 provider"};
#endif
}
} // namespace hexlab
