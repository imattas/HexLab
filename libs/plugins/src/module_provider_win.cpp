#include "hexlab/plugins/plugins.hpp"

#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <filesystem>
#include <string>

namespace hexlab::plugins {
namespace {
class NativeProvider final : public ModuleProvider {
public:
    Result<Module> open(const std::string& path) override {
        std::wstring wide_path;
        try {
            wide_path = std::filesystem::u8path(path).wstring();
        } catch (const std::filesystem::filesystem_error& error) {
            return Error{ErrorCode::invalid_argument,
                std::string("plugin path cannot be converted to a Windows path: ") + error.what()};
        }
        // Keep dependency resolution scoped to the plugin's directory and the
        // standard Windows locations. In particular, do not search the
        // process working directory for a same-named dependency.
        auto* module = LoadLibraryExW(wide_path.c_str(), nullptr,
            LOAD_LIBRARY_SEARCH_DLL_LOAD_DIR | LOAD_LIBRARY_SEARCH_DEFAULT_DIRS);
        if (!module) {
            const auto code = GetLastError();
            return Error{ErrorCode::io, "LoadLibraryEx failed for plugin module (Windows error " +
                std::to_string(code) + ")"};
        }
        return Module{module, &lookup, &close};
    }
private:
    static void* lookup(void* module, const char* symbol) {
        return reinterpret_cast<void*>(GetProcAddress(static_cast<HMODULE>(module), symbol));
    }
    static void close(void* module) { FreeLibrary(static_cast<HMODULE>(module)); }
};
}
std::shared_ptr<ModuleProvider> make_native_module_provider() { return std::make_shared<NativeProvider>(); }
}
