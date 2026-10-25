#include "hexlab/plugins/plugins.hpp"
#include "hexlab/plugins/sdk.hpp"
#include "hexlab/automation/api.hpp"
#include "../support/elf_fixture.hpp"
#include <algorithm>
#include <array>
#include <filesystem>
#include <fstream>
#include <vector>

#include <cstdlib>
#include <iostream>

namespace {
struct Fake { int closed = 0; int renamed = 0; int commented = 0; int bookmarked = 0; };
int32_t fake_open(void*, const char*, uint8_t, void** out) { *out = reinterpret_cast<void*>(1); return 0; }
void fake_close(void* context, void*) { ++static_cast<Fake*>(context)->closed; }
int32_t fake_create(void*, const char*, const char*, uint32_t, void** out) { *out = reinterpret_cast<void*>(1); return 0; }
int32_t fake_analyze(void*, void*) { return 0; }
int32_t fake_summary(void*, void*, HexLabProjectSummary* summary) { summary->input_size = 7; return 0; }
int32_t fake_functions(void*, void*, uint64_t, uint32_t, HexLabFunction*, uint32_t* written) { *written = 0; return 0; }
int32_t fake_instructions(void*, void*, uint64_t, uint32_t, HexLabInstruction*, uint32_t* written) { *written = 0; return 0; }
int32_t fake_references(void*, void*, uint32_t, uint64_t, uint64_t, uint32_t, HexLabReference*, uint32_t* written) { *written = 0; return 0; }
int32_t fake_strings(void*, void*, uint64_t, uint32_t, HexLabString*, uint32_t* written) { *written = 0; return 0; }
int32_t fake_rename(void* context, void*, uint32_t, uint64_t, const char*) { ++static_cast<Fake*>(context)->renamed; return 0; }
int32_t fake_comment(void* context, void*, const HexLabProjectLocation*, const char*) { ++static_cast<Fake*>(context)->commented; return 0; }
int32_t fake_bookmark(void* context, void*, const HexLabProjectLocation*, const char*, uint8_t) { ++static_cast<Fake*>(context)->bookmarked; return 0; }
bool set_environment(const char* key, const std::string& value) {
#if defined(_WIN32)
    return _putenv_s(key, value.c_str()) == 0;
#else
    return setenv(key, value.c_str(), 1) == 0;
#endif
}
int fail(int line) { std::cerr << "SDK test failed at line " << line << '\n'; return 1; }
}

int main(int argc, char **argv) {
    static_assert(hexlab::plugins::sdk::abi_major == 1u);
    static const HexLabCapability sdk_capability{sizeof(HexLabCapability), 1, 0, 0, "test.capability"};
    const auto descriptor = hexlab::plugins::sdk::make_api("test", "test", "1", nullptr, 0,
                                                            nullptr, nullptr, &sdk_capability, 1);
    if (descriptor.struct_size != sizeof(HexLabPluginApi) || descriptor.abi_major != 1u ||
        descriptor.abi_minor != 6u || descriptor.declared_capabilities != &sdk_capability ||
        descriptor.declared_capability_count != 1) return fail(__LINE__);
    if (argc != 6) return 2;
    Fake fake;
    HexLabProjectApi fake_api{sizeof(HexLabProjectApi), HEXLAB_PROJECT_API_VERSION, &fake,
        fake_create, fake_open, fake_close, fake_analyze, fake_summary, fake_functions,
        fake_instructions, fake_references, fake_strings, fake_rename, fake_comment, fake_bookmark};
    HexLabHostApi fake_host{};
    fake_host.struct_size = sizeof(fake_host);
    fake_host.project_api = &fake_api;
    {
        hexlab::plugins::sdk::ProjectClient client(&fake_host);
        if (!client.available() || client.open("contract") != 0) return fail(__LINE__);
        hexlab::plugins::sdk::ProjectClient moved(std::move(client));
        if (client.available() || !moved.available()) return fail(__LINE__);
        HexLabProjectSummary summary{};
        if (moved.summary(summary) != 0 || summary.input_size != 7) return fail(__LINE__);
        HexLabString row{}; row.struct_size = sizeof(row);
        uint32_t written = 7;
        if (!moved.supports_strings() || moved.strings(0, 1, &row, written) != 0 || written != 0) return fail(__LINE__);
        HexLabProjectLocation location{sizeof(HexLabProjectLocation), HEXLAB_PROJECT_LOCATION_ADDRESS, 0, 0, 0x1000};
        if (!moved.supports_edits() || moved.rename(0, 0x1000, "entry") != 0 ||
            moved.comment(location, "note") != 0 || moved.bookmark(location, "bookmark") != 0) return fail(__LINE__);
    }
    if (fake.closed != 1 || fake.renamed != 1 || fake.commented != 1 || fake.bookmarked != 1) return fail(__LINE__);

    const auto root = std::filesystem::temp_directory_path() / "hexlab_native_sdk_workflow";
    std::error_code ignored;
    std::filesystem::remove_all(root, ignored);
    std::filesystem::create_directories(root);
    const auto input = root / "sample.elf";
    const auto project_path = root / "sample.hxproj";
    auto bytes = hexlab_test::elf_fixture::executable(true);
    hexlab_test::elf_fixture::program(bytes, true, 0, 1, 256, 0x400000, 32, 32, 5, 256);
    bytes[256] = std::byte{0xe8}; bytes[257] = std::byte{1}; bytes[258] = std::byte{0};
    bytes[259] = std::byte{0}; bytes[260] = std::byte{0}; bytes[261] = std::byte{0xc3};
    bytes[262] = std::byte{0xc3};
    constexpr char embedded[] = "HexLab SDK string";
    for (std::size_t i = 0; i < sizeof(embedded); ++i) bytes[263 + i] = std::byte(embedded[i]);
    { std::ofstream file(input, std::ios::binary); file.write(reinterpret_cast<const char*>(bytes.data()), static_cast<std::streamsize>(bytes.size())); }
    if (!set_environment("HEXLAB_SDK_INPUT", input.string()) ||
        !set_environment("HEXLAB_SDK_PROJECT", project_path.string())) return fail(__LINE__);
    hexlab::plugins::PluginManager manager(hexlab::plugins::make_native_module_provider());
    auto loaded = manager.load(argv[1]);
    if (!loaded) std::cerr << "plugin load failed: " << loaded.error().message << '\n';
    if (!loaded || loaded.value().id != "org.hexlab.example" ||
        loaded.value().capabilities != std::vector<std::string>{"example.inspect"}) return fail(__LINE__);
    if (loaded.value().declared_capabilities.size() != 2 ||
        loaded.value().declared_capabilities[0].id != "analysis.project.read" ||
        loaded.value().declared_capabilities[0].major_version != 1 ||
        loaded.value().declared_capabilities[1].id != "processor.decode.display" ||
        loaded.value().declared_capabilities[1].minor_version != 1) return fail(__LINE__);
    const auto actions = manager.actions();
    if (actions.size() != 1 || actions[0].id != "sample.inspect" ||
        !manager.invoke_action("org.hexlab.example", "sample.inspect")) return fail(__LINE__);
    auto edited_project = hexlab::automation::Project::open(project_path, true);
    if (!edited_project) return fail(__LINE__);
    auto edited_snapshot = edited_project.value()->snapshot();
    if (!edited_snapshot || !edited_snapshot.value()->state || !edited_snapshot.value()->state->user) return fail(__LINE__);
    const auto& annotations = edited_snapshot.value()->state->user->annotations;
    const auto annotation = std::find_if(annotations.begin(), annotations.end(), [](const auto& row) {
        const auto* address = std::get_if<hexlab::Address>(&row.location);
        return address && address->space.value == 0 && address->offset == 0x400000;
    });
    const auto& bookmarks = edited_snapshot.value()->state->user->bookmarks;
    const auto bookmark = std::find_if(bookmarks.begin(), bookmarks.end(), [](const auto& row) {
        const auto* address = std::get_if<hexlab::Address>(&row.location);
        return address && address->space.value == 0 && address->offset == 0x400000;
    });
    if (annotation == annotations.end() || annotation->name != "sdk_entry" ||
        annotation->comment != "written by native plugin" || bookmark == bookmarks.end() ||
        bookmark->label != "SDK bookmark") return fail(__LINE__);
    const auto loaders = manager.loader_extensions();
    const auto processors = manager.processor_extensions();
    if (loaders.size() != 2 || loaders[0].extension_id != "sample.loader" ||
        loaders[0].format_id != "test-format" || processors.size() != 2 ||
        processors[0].extension_id != "sample.processor" || processors[0].architecture_id != "example" ||
        processors[0].mode_id != "mode32" || processors[1].extension_id != "sample.semantic") return fail(__LINE__);
    const std::array<std::uint8_t, 3> recognized_loader{'H', 'X', '!' };
    const auto loader_result = manager.probe_loaders(recognized_loader, "test-format");
    if (!loader_result || !loader_result.value() || loader_result.value()->confidence != 900 ||
        loader_result.value()->plugin_id != "org.hexlab.example" ||
        loader_result.value()->extension_id != "sample.loader") return fail(__LINE__);
    if (manager.probe_loaders(recognized_loader, "wrong-format").value().has_value()) return fail(__LINE__);
    std::vector<std::uint8_t> large_image(5000, static_cast<std::uint8_t>('X'));
    large_image[0] = 'H'; large_image[1] = 'X';
    if (!manager.probe_loaders(large_image, "test-format").value().has_value()) return fail(__LINE__);
    const std::array<std::uint8_t, 3> code{0x90, 0x90, 0x90};
    const auto decoded = manager.decode_processor("example", "mode32", 0x401000, code);
    if (!decoded || !decoded.value() || decoded.value()->length != 1 || decoded.value()->mnemonic != "nop" ||
        decoded.value()->flow != HEXLAB_INSTRUCTION_FLOW_NORMAL) return fail(__LINE__);
    std::vector<std::uint8_t> long_code(64, 0x90);
    const auto bounded_decode = manager.decode_processor("example", "mode32", 0x401000, long_code);
    if (!bounded_decode || !bounded_decode.value() || bounded_decode.value()->length != 1) return fail(__LINE__);
    const std::array<std::uint8_t, 1> unknown_code{0x01};
    if (manager.decode_processor("example", "mode32", 0, unknown_code).value().has_value()) return fail(__LINE__);
    const std::array<std::uint8_t, 1> bad_code{0xff};
    const auto failed_decode = manager.decode_processor("example", "mode32", 0, bad_code);
    if (failed_decode || failed_decode.error().code != hexlab::ErrorCode::io) return fail(__LINE__);
    const std::array<std::byte, 1> semantic_code{std::byte{0xcc}};
    const auto semantic_decode = manager.decode_processor_semantic(
        {hexlab::Architecture::x86_64, hexlab::ExecutionMode::x86_64}, {{0}, 0x401000}, semantic_code);
    if (!semantic_decode || !semantic_decode.value() || semantic_decode.value()->length != 1 ||
        semantic_decode.value()->mnemonic_override != "sample-sem" ||
        semantic_decode.value()->register_writes.size() != 1 || semantic_decode.value()->access.size() != 2) return fail(__LINE__);
    auto legacy = manager.load(argv[2]);
    if (!legacy || legacy.value().id != "org.hexlab.legacy" ||
        legacy.value().name != "Legacy ABI 1.0" || !legacy.value().declared_capabilities.empty() ||
        !manager.invoke_action("org.hexlab.legacy", "legacy.ping")) return fail(__LINE__);
    if (!manager.unload("org.hexlab.legacy")) return fail(__LINE__);
    if (!manager.unload("org.hexlab.example") || !manager.plugins().empty()) return fail(__LINE__);
    if (!manager.loader_extensions().empty() || !manager.processor_extensions().empty() ||
        !manager.probe_loaders(recognized_loader) || manager.probe_loaders(recognized_loader).value().has_value() ||
        !manager.decode_processor("example", "mode32", 0, code) ||
        manager.decode_processor("example", "mode32", 0, code).value().has_value()) return fail(__LINE__);
    if (!manager.decode_processor_semantic({hexlab::Architecture::x86_64, hexlab::ExecutionMode::x86_64},
                                           {{0}, 0x401000}, semantic_code) ||
        manager.decode_processor_semantic({hexlab::Architecture::x86_64, hexlab::ExecutionMode::x86_64},
                                          {{0}, 0x401000}, semantic_code).value().has_value()) return fail(__LINE__);

    {
        hexlab::plugins::PluginManager faults(hexlab::plugins::make_native_module_provider());
        const auto query_marker = root / "query-stop.txt";
        if (!set_environment("HEXLAB_PLUGIN_STOP_MARKER", query_marker.string())) return fail(__LINE__);
        const auto query_fault = faults.load(argv[3]);
        if (query_fault || query_fault.error().code != hexlab::ErrorCode::io || !faults.plugins().empty()) {
            if (!query_fault) std::cerr << "query exception result: " << query_fault.error().message << '\n';
            else std::cerr << "query exception unexpectedly loaded plugin\n";
            return fail(__LINE__);
        }
        if (std::filesystem::exists(query_marker)) return fail(__LINE__);

        const auto start_marker = root / "start-stop.txt";
        if (!set_environment("HEXLAB_PLUGIN_STOP_MARKER", start_marker.string())) return fail(__LINE__);
        const auto start_fault = faults.load(argv[4]);
        if (start_fault || start_fault.error().code != hexlab::ErrorCode::io ||
            !std::filesystem::exists(start_marker)) return fail(__LINE__);
        {
            std::ifstream marker(start_marker, std::ios::binary);
            std::string value((std::istreambuf_iterator<char>(marker)), {});
            if (value != "s") return fail(__LINE__);
        }

        const auto stop_marker = root / "callback-stop.txt";
        if (!set_environment("HEXLAB_PLUGIN_STOP_MARKER", stop_marker.string())) return fail(__LINE__);
        const auto callback_plugin = faults.load(argv[5]);
        if (!callback_plugin || callback_plugin.value().id != "test.throw-callback" ||
            faults.actions().size() != 1 || faults.loader_extensions().size() != 1 ||
            faults.processor_extensions().size() != 1) return fail(__LINE__);
        const auto action_fault = faults.invoke_action("test.throw-callback", "throw.action");
        if (action_fault || action_fault.error().code != hexlab::ErrorCode::io) return fail(__LINE__);
        const std::array<std::uint8_t, 2> probe_bytes{0x7f, 0x45};
        const auto probe_fault = faults.probe_loaders(probe_bytes);
        if (probe_fault || probe_fault.error().code != hexlab::ErrorCode::io) return fail(__LINE__);
        const std::array<std::uint8_t, 1> decode_bytes{0x90};
        const auto decode_fault = faults.decode_processor("x86_64", "x86_64", 0x1000, decode_bytes);
        if (decode_fault || decode_fault.error().code != hexlab::ErrorCode::io) return fail(__LINE__);
        if (!faults.unload("test.throw-callback") || !faults.plugins().empty() ||
            !faults.actions().empty() || !faults.loader_extensions().empty() ||
            !faults.processor_extensions().empty() || !std::filesystem::exists(stop_marker)) return fail(__LINE__);
        {
            std::ifstream marker(stop_marker, std::ios::binary);
            std::string value((std::istreambuf_iterator<char>(marker)), {});
            if (value != "s") return fail(__LINE__);
        }
    }
    set_environment("HEXLAB_PLUGIN_STOP_MARKER", "");
    std::filesystem::remove_all(root, ignored);
    std::cout << "Native C and C++ plugins loaded, validated, invoked, and unloaded safely\n";
    return 0;
}
