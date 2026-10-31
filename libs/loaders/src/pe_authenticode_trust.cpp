#include "hexlab/loaders/pe.hpp"
#include "hexlab/image/pe_metadata.hpp"
#include <limits>

#ifdef _WIN32
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <wincrypt.h>
#endif

namespace hexlab {
Result<PeAuthenticodeTrustVerification> verify_pe_authenticode_trust(
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
        return Error{ErrorCode::resource_limit, "PKCS#7 payload is fragmented, empty, or exceeds the trust-verification limit"};
    if (stop.stop_requested())
        return Error{ErrorCode::canceled, "Authenticode trust verification canceled"};
#ifdef _WIN32
    const auto &payload_range = record.payload.front();
    auto payload_view = image.storage()->read_at(payload_range.offset,
        static_cast<std::size_t>(payload_range.size));
    if (!payload_view) return payload_view.error();
    if (payload_view.value().bytes.size() != payload_range.size)
        return Error{ErrorCode::malformed, "PKCS#7 payload read returned a short range"};

    HCRYPTMSG message = CryptMsgOpenToDecode(X509_ASN_ENCODING | PKCS_7_ASN_ENCODING,
        0, CMSG_SIGNED, 0, nullptr, nullptr);
    if (!message)
        return Error{ErrorCode::malformed, "Crypt32 could not open the PKCS#7 signed message"};
    struct MessageGuard {
        HCRYPTMSG value;
        ~MessageGuard() { if (value) CryptMsgClose(value); }
    } message_guard{message};
    const auto *encoded = reinterpret_cast<const BYTE *>(payload_view.value().bytes.data());
    if (!CryptMsgUpdate(message, encoded, static_cast<DWORD>(payload_view.value().bytes.size()), TRUE))
        return Error{ErrorCode::malformed, "Crypt32 could not decode the PKCS#7 signed message"};

    HCERTSTORE embedded = CertOpenStore(CERT_STORE_PROV_MSG,
        X509_ASN_ENCODING | PKCS_7_ASN_ENCODING, 0, CERT_STORE_OPEN_EXISTING_FLAG, message);
    if (!embedded)
        return Error{ErrorCode::malformed, "Crypt32 could not open the embedded certificate store"};
    struct StoreGuard {
        HCERTSTORE value;
        ~StoreGuard() { if (value) CertCloseStore(value, 0); }
    } store_guard{embedded};

    DWORD signer_count = 0, count_size = sizeof(signer_count);
    if (!CryptMsgGetParam(message, CMSG_SIGNER_COUNT_PARAM, 0, &signer_count, &count_size))
        return Error{ErrorCode::malformed, "Crypt32 could not read the PKCS#7 signer count"};
    if (!signer_count)
        return Error{ErrorCode::malformed, "PKCS#7 signed message contains no signers"};
    if (signer_count > 1024)
        return Error{ErrorCode::resource_limit, "PKCS#7 signer count exceeds 1024"};

    PeAuthenticodeTrustVerification result;
    result.certificate_record = certificate_record;
    result.signers.reserve(signer_count);
    for (DWORD index = 0; index < signer_count; ++index) {
        if (stop.stop_requested())
            return Error{ErrorCode::canceled, "Authenticode trust verification canceled"};
        PeAuthenticodeSignerTrust status;
        DWORD selected_signer = index;
        PCCERT_CONTEXT signer = nullptr;
        if (!CryptMsgGetAndVerifySigner(message, 0, nullptr, CMSG_USE_SIGNER_INDEX_FLAG,
                                        &signer, &selected_signer)) {
            status.signature_error = GetLastError();
            result.signers.push_back(status);
            continue;
        }
        struct CertificateGuard {
            PCCERT_CONTEXT value;
            ~CertificateGuard() { if (value) CertFreeCertificateContext(value); }
        } signer_guard{signer};
        status.signature_valid = selected_signer == index;
        if (!status.signature_valid) {
            status.signature_error = ERROR_INVALID_DATA;
            result.signers.push_back(status);
            continue;
        }

        CERT_CHAIN_PARA chain_parameters{};
        chain_parameters.cbSize = sizeof(chain_parameters);
        LPSTR code_signing_oid = const_cast<LPSTR>(szOID_PKIX_KP_CODE_SIGNING);
        chain_parameters.RequestedUsage.dwType = USAGE_MATCH_TYPE_AND;
        chain_parameters.RequestedUsage.Usage.cUsageIdentifier = 1;
        chain_parameters.RequestedUsage.Usage.rgpszUsageIdentifier = &code_signing_oid;
        PCCERT_CHAIN_CONTEXT chain = nullptr;
        const DWORD chain_flags = CERT_CHAIN_DISABLE_AIA | CERT_CHAIN_CACHE_ONLY_URL_RETRIEVAL;
        if (!CertGetCertificateChain(nullptr, signer, nullptr, embedded, &chain_parameters,
                                     chain_flags, nullptr, &chain)) {
            status.provider_error = GetLastError();
            result.signers.push_back(status);
            continue;
        }
        struct ChainGuard {
            PCCERT_CHAIN_CONTEXT value;
            ~ChainGuard() { if (value) CertFreeCertificateChain(value); }
        } chain_guard{chain};
        status.chain_built = true;
        status.chain_error_status = chain->TrustStatus.dwErrorStatus;

        CERT_CHAIN_POLICY_PARA policy_parameters{};
        policy_parameters.cbSize = sizeof(policy_parameters);
        CERT_CHAIN_POLICY_STATUS policy_status{};
        policy_status.cbSize = sizeof(policy_status);
        if (!CertVerifyCertificateChainPolicy(CERT_CHAIN_POLICY_AUTHENTICODE, chain,
                                              &policy_parameters, &policy_status)) {
            status.provider_error = GetLastError();
        } else {
            status.policy_error = policy_status.dwError;
            status.chain_trusted = status.chain_error_status == 0 && status.policy_error == 0;
        }
        // No revocation flags are passed to CertGetCertificateChain, so a
        // successful local chain-policy result must not be described as
        // revocation-checked.
        result.signers.push_back(status);
    }
    return result;
#else
    (void)image;
    (void)stop;
    return Error{ErrorCode::unsupported, "Authenticode chain verification requires the Windows Crypt32 provider"};
#endif
}
} // namespace hexlab
