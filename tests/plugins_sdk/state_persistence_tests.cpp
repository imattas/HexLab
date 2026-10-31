#include "hexlab/plugins/plugins.hpp"

#include <chrono>
#include <cstdlib>
#include <iostream>
#include <stdexcept>

namespace {
bool set_environment(const char *key, const std::string &value) {
#if defined(_WIN32)
    return _putenv_s(key, value.c_str()) == 0;
#else
    return setenv(key, value.c_str(), 1) == 0;
#endif
}

bool run_phase(const std::string &phase, const std::string &plugin_path,
               const std::filesystem::path &state_path) {
    if (!set_environment("HEXLAB_PLUGIN_STATE_TEST_PHASE", phase)) return false;
    hexlab::plugins::PluginManager manager(hexlab::plugins::make_native_module_provider(), state_path);
    const auto loaded = manager.load(plugin_path);
    if (!loaded || loaded.value().id != "org.hexlab.state-test") {
        if (!loaded) std::cerr << "plugin load failed in " << phase << ": " << loaded.error().message << '\n';
        return false;
    }
    const auto unloaded = manager.unload("org.hexlab.state-test");
    if (!unloaded) std::cerr << "plugin unload failed in " << phase << ": " << unloaded.error().message << '\n';
    return static_cast<bool>(unloaded);
}
} // namespace

int main(int argc, char **argv) {
    if (argc != 2) return 2;
    const auto root = std::filesystem::temp_directory_path() /
        ("hexlab-plugin-state-" + std::to_string(
            std::chrono::steady_clock::now().time_since_epoch().count()));
    std::error_code error;
    std::filesystem::create_directories(root, error);
    if (error) return 1;
    const auto state_path = root / "plugin-state.bin";
    bool passed = run_phase("seed", argv[1], state_path) &&
                  std::filesystem::is_regular_file(state_path) &&
                  run_phase("resume", argv[1], state_path) &&
                  run_phase("verify", argv[1], state_path);
    set_environment("HEXLAB_PLUGIN_STATE_TEST_PHASE", "");
    std::filesystem::remove_all(root, error);
    if (!passed) {
        std::cerr << "plugin state did not survive manager restart with CAS tombstones\n";
        return 1;
    }
    std::cout << "Plugin state persisted across manager restarts with tombstone revisions\n";
    return 0;
}
