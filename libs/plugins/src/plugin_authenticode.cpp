#include "hexlab/plugins/plugins.hpp"

#ifdef _WIN32
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <wincrypt.h>
#include <softpub.h>
#include <wintrust.h>
#include <array>
#include <string>
#endif

namespace hexlab::plugins {

#ifdef _WIN32
namespace {
using ProviderDataFromState = CRYPT_PROVIDER_DATA *(WINAPI *)(HANDLE);
using ProviderSignerFromChain = CRYPT_PROVIDER_SGNR *(WINAPI *)(CRYPT_PROVIDER_DATA *, DWORD, BOOL, DWORD);

struct TrustModule {
    HMODULE handle = nullptr;
    bool owned = false;
    ~TrustModule() { if (owned && handle) FreeLibrary(handle); }
};

std::string utf8_name(PCCERT_CONTEXT certificate, DWORD flags) {
    const DWORD length = CertGetNameStringW(certificate, CERT_NAME_SIMPLE_DISPLAY_TYPE,
                                             flags, nullptr, nullptr, 0);
    if (length <= 1 || length > 32768) return {};
    std::wstring value(length, L'\0');
    const DWORD written = CertGetNameStringW(certificate, CERT_NAME_SIMPLE_DISPLAY_TYPE,
                                              flags, nullptr, value.data(), length);
    if (written <= 1 || written != length) return {};
    value.resize(written - 1);
    const int required = WideCharToMultiByte(CP_UTF8, WC_ERR_INVALID_CHARS,
        value.data(), static_cast<int>(value.size()), nullptr, 0, nullptr, nullptr);
    if (required <= 0 || required > 65536) return {};
    std::string result(static_cast<std::size_t>(required), '\0');
    if (WideCharToMultiByte(CP_UTF8, WC_ERR_INVALID_CHARS, value.data(),
            static_cast<int>(value.size()), result.data(), required, nullptr, nullptr) != required)
        return {};
    return result;
}

std::string certificate_sha256(PCCERT_CONTEXT certificate) {
    DWORD bytes = 0;
    if (!CertGetCertificateContextProperty(certificate, CERT_SHA256_HASH_PROP_ID, nullptr, &bytes) ||
        bytes != 32)
        return {};
    std::array<BYTE, 32> digest{};
    if (!CertGetCertificateContextProperty(certificate, CERT_SHA256_HASH_PROP_ID,
            digest.data(), &bytes) || bytes != digest.size())
        return {};
    constexpr char digits[] = "0123456789abcdef";
    std::string result;
    result.reserve(digest.size() * 2);
    for (const BYTE byte : digest) {
        result.push_back(digits[byte >> 4]);
        result.push_back(digits[byte & 0xf]);
    }
    return result;
}

void attach_signer_identity(HANDLE state, PluginAuthenticodeTrust &result) {
    TrustModule module{GetModuleHandleW(L"wintrust.dll"), false};
    if (!module.handle) {
        module.handle = LoadLibraryW(L"wintrust.dll");
        module.owned = module.handle != nullptr;
    }
    if (!module.handle) return;
    const auto get_data = reinterpret_cast<ProviderDataFromState>(
        GetProcAddress(module.handle, "WTHelperProvDataFromStateData"));
    const auto get_signer = reinterpret_cast<ProviderSignerFromChain>(
        GetProcAddress(module.handle, "WTHelperGetProvSignerFromChain"));
    if (!get_data || !get_signer) return;
    auto *provider_data = get_data(state);
    if (!provider_data) return;
    auto *signer = get_signer(provider_data, 0, FALSE, 0);
    if (!signer || !signer->pasCertChain || signer->csCertChain == 0) return;
    const auto *certificate = signer->pasCertChain[0].pCert;
    if (!certificate) return;
    result.signer_subject = utf8_name(certificate, 0);
    result.signer_issuer = utf8_name(certificate, CERT_NAME_ISSUER_FLAG);
    result.signer_certificate_sha256 = certificate_sha256(certificate);
}
} // namespace
#endif

Result<PluginAuthenticodeTrust> verify_plugin_authenticode_trust(
    const std::filesystem::path& module_path) {
    if (module_path.empty())
        return Error{ErrorCode::invalid_argument, "Plugin module path is empty"};
#ifdef _WIN32
    const auto native_path = module_path.native();
    if (native_path.find(L'\0') != std::wstring::npos)
        return Error{ErrorCode::invalid_argument, "Plugin module path contains an embedded NUL"};

    WINTRUST_FILE_INFO file{};
    file.cbStruct = sizeof(file);
    file.pcwszFilePath = native_path.c_str();

    WINTRUST_DATA trust{};
    trust.cbStruct = sizeof(trust);
    trust.dwUIChoice = WTD_UI_NONE;
    trust.fdwRevocationChecks = WTD_REVOKE_NONE;
    trust.dwUnionChoice = WTD_CHOICE_FILE;
    trust.pFile = &file;
    trust.dwStateAction = WTD_STATEACTION_VERIFY;
    trust.dwProvFlags = WTD_CACHE_ONLY_URL_RETRIEVAL;

    GUID policy = WINTRUST_ACTION_GENERIC_VERIFY_V2;
    const auto status = WinVerifyTrust(nullptr, &policy, &trust);
    PluginAuthenticodeTrust result;
    result.status = status == ERROR_SUCCESS ? PluginAuthenticodeTrustStatus::trusted
                                            : PluginAuthenticodeTrustStatus::not_trusted;
    result.provider_status = static_cast<std::int32_t>(status);
    result.provider = "Windows Authenticode policy (cache-only, no revocation check)";
    if (trust.hWVTStateData) attach_signer_identity(trust.hWVTStateData, result);
    trust.dwStateAction = WTD_STATEACTION_CLOSE;
    (void)WinVerifyTrust(nullptr, &policy, &trust);
    return result;
#else
    (void)module_path;
    PluginAuthenticodeTrust result;
    result.status = PluginAuthenticodeTrustStatus::unsupported;
    result.provider = "No native Authenticode trust provider on this platform";
    return result;
#endif
}

} // namespace hexlab::plugins
