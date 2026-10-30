#include <hexlab/plugins/sdk.hpp>

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <iomanip>
#include <sstream>
#include <string>

namespace {
struct PluginState {
    const HexLabHostApi* host;
};

void report(const PluginState* state, int32_t level, const std::string& message) {
    if (!state || !state->host) return;
    constexpr auto required = offsetof(HexLabHostApi, log) + sizeof(HexLabHostApi::log);
    if (state->host->struct_size >= required && state->host->log)
        state->host->log(state->host->host_context, level, message.c_str());
}

std::string fixed_text(const char* text, std::size_t capacity) {
    const auto* end = static_cast<const char*>(std::memchr(text, '\0', capacity));
    return std::string(text, end ? static_cast<std::size_t>(end - text) : capacity);
}

bool register_value(const HexLabDebugRegister& reg, std::uint64_t& value) {
    if (!reg.byte_count || reg.byte_count > sizeof(value)) return false;
    if (reg.byte_order != HEXLAB_DEBUGGER_BYTE_ORDER_LITTLE &&
        reg.byte_order != HEXLAB_DEBUGGER_BYTE_ORDER_BIG) return false;
    value = 0;
    for (std::uint32_t i = 0; i < reg.byte_count; ++i) {
        const auto index = reg.byte_order == HEXLAB_DEBUGGER_BYTE_ORDER_LITTLE
            ? i : reg.byte_count - 1 - i;
        value |= static_cast<std::uint64_t>(reg.bytes[index]) << (i * 8);
    }
    return true;
}

void inspect_active_debugger(void* context) {
    const auto* state = static_cast<const PluginState*>(context);
    if (!state) return;

    hexlab::plugins::sdk::ActiveDebuggerClient client(state->host);
    if (!client.available()) {
        report(state, 2, "The host does not provide the active-debugger API.");
        return;
    }

    HexLabActiveDebuggerInfo snapshot{};
    const auto query_status = client.query(snapshot);
    if (query_status != HEXLAB_ACTIVE_DEBUGGER_OK) {
        report(state, 2, "No active debugger session is available.");
        return;
    }
    if (snapshot.state != HEXLAB_DEBUGGER_STATE_STOPPED || !snapshot.has_process) {
        report(state, 1, "The active debugger has no stopped process to inspect.");
        return;
    }

    std::array<HexLabDebugThread, 64> threads{};
    for (auto& thread : threads) thread.struct_size = sizeof(thread);
    std::uint32_t thread_count = 0;
    const auto thread_status = client.threads(snapshot.token, 0,
        static_cast<std::uint32_t>(threads.size()), threads.data(), &thread_count);
    if (thread_status != HEXLAB_ACTIVE_DEBUGGER_OK) {
        report(state, 2, thread_status == HEXLAB_ACTIVE_DEBUGGER_STALE
            ? "The debugger snapshot became stale; invoke the action again."
            : "The stopped thread list could not be read.");
        return;
    }
    if (!thread_count) {
        report(state, 1, "The stopped process has no inspectable threads.");
        return;
    }

    std::array<HexLabDebugRegister, 96> registers{};
    for (auto& reg : registers) reg.struct_size = sizeof(reg);
    std::uint32_t register_count = 0;
    const auto register_status = client.read_registers(snapshot.token, threads[0].id, 0,
        static_cast<std::uint32_t>(registers.size()), registers.data(), &register_count);
    if (register_status != HEXLAB_ACTIVE_DEBUGGER_OK) {
        report(state, 2, register_status == HEXLAB_ACTIVE_DEBUGGER_STALE
            ? "The debugger snapshot became stale; invoke the action again."
            : "Registers for the first stopped thread could not be read.");
        return;
    }

    std::uint64_t pc = 0;
    bool has_pc = false;
    for (std::uint32_t i = 0; i < register_count; ++i) {
        const auto name = fixed_text(registers[i].name, sizeof(registers[i].name));
        if (name == "pc" || name == "rip" || name == "eip")
            has_pc = register_value(registers[i], pc);
        if (has_pc) break;
    }

    std::ostringstream message;
    message << "Stopped process " << fixed_text(snapshot.process.name, sizeof(snapshot.process.name))
            << ": " << thread_count << " thread(s) in first page; inspected thread "
            << threads[0].id << " has " << register_count << " register(s)";
    if (thread_count == threads.size()) message << " (page may have more)";
    if (has_pc) {
        std::array<std::uint8_t, 16> bytes{};
        const auto status = client.read_memory(snapshot.token, pc,
            static_cast<std::uint32_t>(bytes.size()), bytes.data());
        if (status == HEXLAB_ACTIVE_DEBUGGER_OK) {
            message << "; bytes at PC 0x" << std::hex << pc << ':';
            for (const auto byte : bytes)
                message << ' ' << std::setw(2) << std::setfill('0') << static_cast<unsigned>(byte);
        } else if (status == HEXLAB_ACTIVE_DEBUGGER_STALE) {
            report(state, 2, "The debugger resumed during inspection; invoke the action again.");
            return;
        } else {
            message << "; PC memory is unavailable";
        }
    } else {
        message << "; no recognized PC register was available";
    }
    report(state, 1, message.str());
}

int32_t start(const HexLabHostApi* host, void** instance) {
    if (instance) *instance = nullptr;
    constexpr auto required = offsetof(HexLabHostApi, register_action) +
                              sizeof(HexLabHostApi::register_action);
    if (!host || !instance || host->struct_size < required || !host->register_action)
        return -1;

    auto* state = new PluginState{host};
    *instance = state;
    if (host->register_action(host->host_context, "inspect-active-debugger",
                              "Inspect Active Debugger", state,
                              inspect_active_debugger) != 0) {
        delete state;
        *instance = nullptr;
        return -1;
    }
    return 0;
}

void stop(void* instance) { delete static_cast<PluginState*>(instance); }
} // namespace

extern "C" HEXLAB_PLUGIN_EXPORT int32_t hexlab_plugin_query(
    uint32_t host_abi_major, const HexLabHostApi*, HexLabPluginApi* plugin_api) {
    if (host_abi_major != HEXLAB_PLUGIN_ABI_MAJOR || !plugin_api ||
        plugin_api->struct_size < offsetof(HexLabPluginApi, stop) +
                                  sizeof(HexLabPluginApi::stop))
        return -1;

    const auto available_size = plugin_api->struct_size;
    auto api = hexlab::plugins::sdk::make_api(
        "org.hexlab.example.active-debugger-cpp", "Active Debugger C++ Example",
        "1.0.0", nullptr, 0, start, stop);
    if (available_size < offsetof(HexLabPluginApi, declared_capability_count) +
                         sizeof(HexLabPluginApi::declared_capability_count)) {
        api.declared_capabilities = nullptr;
        api.declared_capability_count = 0;
        api.required_capabilities = nullptr;
        api.required_capability_count = 0;
    }
    if (available_size < offsetof(HexLabPluginApi, required_capability_count) +
                         sizeof(HexLabPluginApi::required_capability_count)) {
        api.required_capabilities = nullptr;
        api.required_capability_count = 0;
    }
    api.struct_size = available_size < sizeof(api) ? available_size : sizeof(api);
    std::memcpy(plugin_api, &api, api.struct_size);
    return 0;
}
