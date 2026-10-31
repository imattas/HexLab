#include "hexlab/plugins/plugins.hpp"

#ifdef _WIN32
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <softpub.h>
#include <wintrust.h>
#endif

namespace hexlab::plugins {

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
    trust.dwStateAction = WTD_STATEACTION_CLOSE;
    (void)WinVerifyTrust(nullptr, &policy, &trust);

    PluginAuthenticodeTrust result;
    result.status = status == ERROR_SUCCESS ? PluginAuthenticodeTrustStatus::trusted
                                            : PluginAuthenticodeTrustStatus::not_trusted;
    result.provider_status = static_cast<std::int32_t>(status);
    result.provider = "Windows Authenticode policy (cache-only, no revocation check)";
    return result;
#else
    (void)module_path;
    return PluginAuthenticodeTrust{PluginAuthenticodeTrustStatus::unsupported, 0,
                                   "No native Authenticode trust provider on this platform"};
#endif
}

} // namespace hexlab::plugins
