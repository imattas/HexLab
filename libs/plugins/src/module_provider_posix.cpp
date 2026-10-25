#include "hexlab/plugins/plugins.hpp"

#include <dlfcn.h>

namespace hexlab::plugins {
namespace {
class NativeProvider final : public ModuleProvider {
public:
    Result<Module> open(const std::string& path) override {
        auto* module = dlopen(path.c_str(), RTLD_NOW | RTLD_LOCAL);
        if (!module) {
            const char* error = dlerror();
            return Error{ErrorCode::io, error ? error : "dlopen failed for plugin module"};
        }
        return Module{module, &lookup, &close};
    }
private:
    static void* lookup(void* module, const char* symbol) { return dlsym(module, symbol); }
    static void close(void* module) { dlclose(module); }
};
}
std::shared_ptr<ModuleProvider> make_native_module_provider() { return std::make_shared<NativeProvider>(); }
}
