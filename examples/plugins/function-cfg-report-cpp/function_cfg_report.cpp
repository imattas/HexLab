#include <hexlab/plugins/sdk.hpp>

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <cstring>

namespace {
constexpr std::uint64_t max_functions = 64;
constexpr std::uint64_t max_blocks = 2048;
const HexLabCapability requirements[] = {
    {sizeof(HexLabCapability), 1, 0, 0, "project.api"},
    {sizeof(HexLabCapability), 1, 21, 0, "project.cfg"},
    {sizeof(HexLabCapability), 1, 30, 0, "project.instruction-text"},
    {sizeof(HexLabCapability), 1, 32, 0, "project.string-preview"},
    {sizeof(HexLabCapability), 1, 0, 0, "project.references.range"}
};

int32_t report_cfg(void*, const HexLabProjectApi* project_api, const char* path,
                   char* output, std::uint32_t capacity) {
    if (!project_api || !path || !output || !capacity) return -1;

    HexLabHostApi host{};
    host.struct_size = sizeof(host);
    host.abi_major = HEXLAB_PLUGIN_ABI_MAJOR;
    host.abi_minor = HEXLAB_PLUGIN_ABI_MINOR;
    host.project_api = project_api;
    hexlab::plugins::sdk::ProjectClient project(&host);
    if (!project.available() || !project.supports_control_flow() ||
        !project.supports_instruction_text() || !project.supports_string_preview() ||
        !project.supports_outgoing_references_range()) return -1;
    if (project.open(path, true) != 0 || project.analyze() != 0) return -1;

    HexLabProjectSummary summary{};
    if (project.summary(summary) != 0) return -1;

    const auto function_limit = std::min(summary.function_count, max_functions);
    std::uint64_t functions_read = 0;
    std::uint64_t blocks_read = 0;
    std::uint64_t edges_read = 0;
    std::uint64_t instructions_read = 0;
    std::uint64_t string_previews_read = 0;
    std::uint64_t longest_preview_bytes = 0;
    std::uint64_t unresolved_edges = 0;
    std::uint64_t reference_sources_queried = 0;
    std::uint64_t outgoing_references_read = 0;
    bool truncated = summary.function_count > function_limit;

    std::array<HexLabFunction, 32> functions{};
    for (std::uint64_t cursor = 0; cursor < function_limit;) {
        const auto requested = static_cast<std::uint32_t>(
            std::min<std::uint64_t>(functions.size(), function_limit - cursor));
        std::uint32_t written = 0;
        if (project.functions(cursor, requested, functions.data(), written) != 0 ||
            !written || written > requested)
            return -1;
        for (std::uint32_t i = 0; i < written && blocks_read < max_blocks; ++i) {
            ++functions_read;
            std::uint64_t block_cursor = 0;
            while (blocks_read < max_blocks) {
                std::array<HexLabBasicBlock, 32> blocks{};
                const auto block_capacity = static_cast<std::uint32_t>(blocks.size());
                std::uint32_t block_count = 0;
                if (project.function_blocks(functions[i].address_space, functions[i].entry,
                        block_cursor, block_capacity, blocks.data(), block_count) != 0 ||
                    block_count > block_capacity)
                    return -1;
                if (!block_count) break;
                for (std::uint32_t b = 0; b < block_count && blocks_read < max_blocks; ++b) {
                    ++blocks_read;
                    // Query outgoing xrefs for the first byte of each block.
                    // The range is half-open and deliberately narrow so this
                    // example does not assume a block extent from its start.
                    std::array<HexLabReference, 16> references{};
                    std::uint32_t reference_count = 0;
                    if (project.outgoing_references_range(blocks[b].address_space,
                            blocks[b].address, 1, 0,
                            static_cast<std::uint32_t>(references.size()),
                            references.data(), reference_count) != 0 ||
                        reference_count > references.size())
                        return -1;
                    ++reference_sources_queried;
                    outgoing_references_read += reference_count;
                    if (reference_count == references.size()) truncated = true;
                    if (blocks[b].successor_count) {
                        std::array<HexLabBlockSuccessor, 32> successors{};
                        const auto edge_capacity = static_cast<std::uint32_t>(
                            std::min<std::uint64_t>(successors.size(), blocks[b].successor_count));
                        std::uint32_t edge_count = 0;
                        if (project.block_successors(blocks[b].id, 0, edge_capacity,
                                successors.data(), edge_count) != 0 || edge_count > edge_capacity)
                            return -1;
                        edges_read += edge_count;
                        for (std::uint32_t e = 0; e < edge_count; ++e)
                            unresolved_edges += !successors[e].has_target;
                        if (blocks[b].successor_count > edge_capacity) truncated = true;
                    }
                    if (blocks[b].instruction_count) {
                        std::array<HexLabInstructionText, 32> instructions{};
                        const auto instruction_capacity = static_cast<std::uint32_t>(
                            std::min<std::uint64_t>(instructions.size(), blocks[b].instruction_count));
                        std::uint32_t instruction_count = 0;
                        if (project.block_instructions_text(blocks[b].id, 0, instruction_capacity,
                                instructions.data(), instruction_count) != 0 ||
                            instruction_count > instruction_capacity)
                            return -1;
                        instructions_read += instruction_count;
                        if (blocks[b].instruction_count > instruction_capacity) truncated = true;
                    }
                }
                block_cursor += block_count;
                if (block_count < block_capacity) break;
                if (blocks_read == max_blocks) truncated = true;
            }
        }
        cursor += written;
        if (written < requested) break;
        if (blocks_read == max_blocks) {
            truncated = true;
            break;
        }
    }
    if (functions_read < summary.function_count) truncated = true;

    constexpr std::uint64_t max_string_previews = 64;
    std::array<HexLabStringText, 16> strings{};
    for (std::uint64_t cursor = 0; cursor < max_string_previews;) {
        const auto requested = static_cast<std::uint32_t>(
            std::min<std::uint64_t>(strings.size(), max_string_previews - cursor));
        std::uint32_t written = 0;
        if (project.strings_preview(cursor, requested, strings.data(), written) != 0 ||
            written > requested)
            return -1;
        for (std::uint32_t i = 0; i < written; ++i) {
            ++string_previews_read;
            longest_preview_bytes = std::max<std::uint64_t>(
                longest_preview_bytes, std::strlen(strings[i].preview));
        }
        cursor += written;
        if (written < requested) break;
    }
    if (string_previews_read == max_string_previews) truncated = true;

    const int length = std::snprintf(output, capacity,
        "Function CFG report\nFunctions inspected: %llu of %llu\n"
        "Basic blocks inspected: %llu\nInstructions paged: %llu\n"
        "String previews paged: %llu (longest %llu bytes)\n"
        "Block-entry reference ranges queried: %llu (outgoing rows %llu)\n"
        "Successor edges inspected: %llu\nEdges without resolved address: %llu\n"
        "Truncated by example limits: %s",
        static_cast<unsigned long long>(functions_read),
        static_cast<unsigned long long>(summary.function_count),
        static_cast<unsigned long long>(blocks_read),
        static_cast<unsigned long long>(instructions_read),
        static_cast<unsigned long long>(string_previews_read),
        static_cast<unsigned long long>(longest_preview_bytes),
        static_cast<unsigned long long>(reference_sources_queried),
        static_cast<unsigned long long>(outgoing_references_read),
        static_cast<unsigned long long>(edges_read),
        static_cast<unsigned long long>(unresolved_edges), truncated ? "yes" : "no");
    return length >= 0 && static_cast<std::uint32_t>(length) < capacity ? 0 : -1;
}

int32_t start(const HexLabHostApi* host, void** instance) {
    if (instance) *instance = nullptr;
    if (!host || !instance ||
        !HEXLAB_PLUGIN_HAS_FIELD(host, HexLabHostApi, register_analysis_provider) ||
        !host->register_analysis_provider) return -1;
    const HexLabAnalysisProvider provider{
        sizeof(HexLabAnalysisProvider), HEXLAB_ANALYSIS_PROVIDER_API_VERSION,
        "function-cfg-report", "Function CFG Report", nullptr, report_cfg
    };
    return host->register_analysis_provider(host->host_context, &provider);
}

void stop(void*) {}
} // namespace

extern "C" HEXLAB_PLUGIN_EXPORT int32_t hexlab_plugin_query(
    std::uint32_t host_abi_major, const HexLabHostApi*, HexLabPluginApi* plugin_api) {
    if (host_abi_major != HEXLAB_PLUGIN_ABI_MAJOR || !plugin_api ||
        plugin_api->struct_size < offsetof(HexLabPluginApi, stop) + sizeof(HexLabPluginApi::stop))
        return -1;
    const auto available_size = plugin_api->struct_size;
    auto api = hexlab::plugins::sdk::make_api(
        "org.hexlab.example.function-cfg-report-cpp", "Function CFG Report C++ Example",
        "1.0.0", nullptr, 0, start, stop, nullptr, 0,
        requirements, 5);
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
