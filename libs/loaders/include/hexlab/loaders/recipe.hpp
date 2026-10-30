#pragma once
#include "hexlab/loaders/raw.hpp"
#include "hexlab/loaders/pe.hpp"
#include "hexlab/loaders/macho.hpp"
#include "hexlab/loaders/ar.hpp"
#include <filesystem>
#include <functional>
#include <vector>
namespace hexlab {
struct PluginImageIdentity {
    std::string plugin_id, plugin_version, extension_id, format_id;
    std::uint32_t api_version = 1;
    bool operator==(const PluginImageIdentity &) const = default;
};
struct LoadRecipe {
    Format format;
    std::optional<RawOptions> raw;
    std::optional<MachOOptions> macho;
    // Optional, exact local PDB binding. Persisted in project recipes so a
    // reopened project resolves the same sidecar without a symbol server.
    std::optional<std::filesystem::path> pdb_path;
    std::optional<PluginImageIdentity> plugin;
    // Selects the effective byte/decode view for an ARM64X PE image. Persisted
    // with the project recipe so reopening uses the same process architecture.
    std::optional<PeRuntimeArchitecture> pe_runtime_architecture;
    // Exact caller-selected supplementary ELF object or DWARF v5 DWP. Persisted
    // so saved projects reopen with the same type-reference source.
    std::optional<std::filesystem::path> dwarf_supplementary_package_path;
    // Ordered exact-identity Minidump PDB candidates selected during open.
    // Appended to preserve existing positional aggregate initializers.
    std::vector<std::filesystem::path> minidump_pdb_paths;
    bool minidump_pdb_search_truncated = false;
};
using PluginImageLoader = std::function<Result<LoadedImage>(
    std::shared_ptr<const ByteStorage>, std::stop_token)>;
using PluginImageProbe = std::function<Result<std::optional<std::uint32_t>>(
    std::span<const std::byte>, std::uint64_t, std::stop_token)>;
// The returned ownership token publishes the provider until it is destroyed.
// Dispatch never holds the registry lock while invoking a provider. Providers
// must serialize their callback with module unload and reject expired owners.
HEXLAB_LOADERS_EXPORT Result<std::shared_ptr<void>> register_plugin_image_provider(
    const PluginImageIdentity &, PluginImageLoader, PluginImageProbe = {});
HEXLAB_LOADERS_EXPORT Result<std::vector<std::byte>> encode_recipe(const LoadRecipe &);
HEXLAB_LOADERS_EXPORT Result<LoadRecipe> decode_recipe(std::span<const std::byte>);
// Resolve opening intent before persistence, making a universal selection concrete.
HEXLAB_LOADERS_EXPORT Result<LoadRecipe> resolve_load_recipe(const ByteStorage &, const LoadRecipe &, std::stop_token);
HEXLAB_LOADERS_EXPORT Result<LoadedImage> load_image(std::shared_ptr<const ByteStorage>, const LoadRecipe &,
                                                     std::stop_token);
// A saved Mach-O flag0 binds a thin container; flag1 binds a universal index.
// Never resolve/rank a new container kind when refreshing or reopening a project.
HEXLAB_LOADERS_EXPORT Result<LoadedImage> load_durable_image(std::shared_ptr<const ByteStorage>, const LoadRecipe &,
                                                             std::stop_token);
// Archive containers have no single image/address space; open them through this
// parallel durable path and select/extract regular members explicitly.
HEXLAB_LOADERS_EXPORT Result<LoadedArchive> load_archive(std::shared_ptr<const ByteStorage>, const LoadRecipe &,
                                                        std::stop_token, ArLimits = {});
} // namespace hexlab
