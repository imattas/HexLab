#include "hexlab/plugins/plugins.hpp"

#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <filesystem>

namespace hexlab::plugins {
namespace {
class NativeProvider final : public ModuleProvider {
public:
    Result<Module> open(const std::string& path) override {
        const auto wide_path = std::filesystem::u8path(path).wstring();
        auto* module = LoadLibraryW(wide_path.c_str());
        if (!module) return Error{ErrorCode::io, "LoadLibrary failed for plugin module"};
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
