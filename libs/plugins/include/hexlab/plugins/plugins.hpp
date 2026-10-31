#pragma once

#include "hexlab/core/result.hpp"
#include "hexlab/plugins/plugin_abi.h"
#include "hexlab/plugins/plugins_export.hpp"
#include "hexlab/processors/instruction.hpp"
#include "hexlab/decompiler/decompiler.hpp"
#include "hexlab/analysis/strings.hpp"
#include "hexlab/loaders/recipe.hpp"

#include <cstdint>
#include <cstddef>
#include <functional>
#include <filesystem>
#include <memory>
#include <optional>
#include <span>
#include <string>
#include <vector>

namespace hexlab::plugins {
using Status = Result<std::monostate>;
struct HEXLAB_PLUGINS_EXPORT PluginInfo {
    std::string id;
    std::string name;
    std::string version;
    std::vector<std::string> capabilities;
    struct VersionedCapability {
        std::string id;
        std::uint32_t major_version = 0;
        std::uint32_t minor_version = 0;
        std::uint32_t flags = 0;
    };
    std::vector<VersionedCapability> declared_capabilities;
    std::vector<VersionedCapability> required_capabilities;
    // IDs of loaded plugins that satisfy required capabilities at activation.
    // Host-provided capabilities do not appear in this list.
    std::vector<std::string> resolved_dependencies;
    // Exact UTF-8 path requested for this loaded module. This is diagnostic
    // provenance only; it does not establish publisher identity or trust.
    std::string module_path;
};
enum class PluginRequirementResolution : std::uint8_t {
    host,
    loaded_plugin,
    unavailable,
    ambiguous,
    candidate_plugin
};
struct HEXLAB_PLUGINS_EXPORT PluginRequirementPreflight {
    PluginInfo::VersionedCapability capability;
    PluginRequirementResolution resolution = PluginRequirementResolution::unavailable;
    // Set only for a unique loaded_plugin or candidate_plugin provider.
    std::string provider_plugin_id;
};
/* A candidate discovered by scanning one directory. Discovery never loads
   the module or executes code; callers explicitly choose load or dependency activation. */
struct HEXLAB_PLUGINS_EXPORT PluginCandidate {
    std::string path;
    struct Manifest {
        std::string id;
        std::string name;
        std::string version;
        // Optional lowercase SHA-256 pin for the adjacent module file. This is
        // advisory integrity metadata, not a publisher signature.
        std::string sha256;
        std::vector<PluginInfo::VersionedCapability> capabilities;
        std::vector<PluginInfo::VersionedCapability> required_capabilities;
    };
    std::optional<Manifest> manifest;
    // A malformed sidecar does not hide a native module candidate. Hosts can
    // display this diagnostic before the user explicitly chooses to load it.
    std::string manifest_error;
    // Populated only when a valid manifest declares sha256. Hashing is
    // data-only; mismatch/read-limit failures are reported here.
    std::string module_sha256;
    std::string integrity_error;
    // Advisory snapshot of host, loaded and supplied candidate providers. This
    // does not verify native modules or transitive dependency feasibility.
    // Refresh after lifecycle changes; activation always replans and validates.
    std::vector<PluginRequirementPreflight> requirement_preflight;
};
struct HEXLAB_PLUGINS_EXPORT PluginActionInfo {
    std::string plugin_id;
    std::string id;
    std::string label;
};
struct HEXLAB_PLUGINS_EXPORT PluginMenuActionInfo {
    std::string plugin_id;
    std::string menu_path;
    std::string id;
    std::string label;
};
struct HEXLAB_PLUGINS_EXPORT LoaderExtensionInfo {
    std::string plugin_id, extension_id, format_id;
};
struct HEXLAB_PLUGINS_EXPORT ProcessorExtensionInfo {
    std::string plugin_id, extension_id, architecture_id, mode_id;
};
struct HEXLAB_PLUGINS_EXPORT PluginExtensionFailure {
    std::string plugin_id, extension_id, kind, reason;
};
struct HEXLAB_PLUGINS_EXPORT AnalysisProviderInfo {
    std::string plugin_id, provider_id, display_name;
};
struct PluginUnloadPlan {
    std::weak_ptr<const void> manager_identity;
    std::uint64_t generation = 0;
    std::string root_plugin_id;
    bool all = false;
    std::vector<std::string> plugin_ids; // exact consumer-first removal order
    std::vector<std::string> retained_provider_ids;
};
struct PluginUnloadResult {
    std::vector<std::string> removed;
    std::optional<Error> failure; // partial cleanup must still invalidate clients
};
struct HEXLAB_PLUGINS_EXPORT LoaderProbeResult {
    std::string plugin_id, extension_id, format_id;
    std::uint32_t confidence = 0;
};
struct HEXLAB_PLUGINS_EXPORT ProcessorDecodeResult {
    std::string plugin_id, extension_id, architecture_id, mode_id;
    std::uint32_t length = 0;
    HexLabInstructionFlow flow = HEXLAB_INSTRUCTION_FLOW_NORMAL;
    std::string mnemonic, operands;
};

/* Desktop-owned bridge for the optional ABI 1.15 active-document table.
   Query/read may be called on plugin worker threads; navigate is marshalled by
   the desktop adapter to its owner thread. No host object crosses the C ABI. */
struct ActiveDocumentServices {
    std::function<std::int32_t(HexLabActiveDocumentInfo&)> query;
    std::function<std::int32_t(const HexLabDocumentToken&, const HexLabProjectLocation&,
                               std::uint32_t, std::uint8_t*)> read;
    std::function<std::int32_t(const HexLabDocumentToken&, const HexLabProjectLocation&)> navigate;
};

/* Desktop-owned bridge for ABI 1.18 durable breakpoints. Callbacks validate
   the active-project token and submit edits through workspace commands. */
struct ActiveProjectBreakpointServices {
    std::function<std::int32_t(HexLabActiveProjectToken&)> snapshot;
    std::function<std::int32_t(const HexLabActiveProjectToken&, std::uint64_t, std::uint32_t,
                               HexLabProjectBreakpointRecord*, std::uint32_t&)> query;
    std::function<std::int32_t(const HexLabActiveProjectToken&, std::uint32_t, std::uint64_t,
                               std::uint32_t, std::uint8_t, std::uint8_t, std::uint8_t)> set;
};

/* Desktop-owned, read-only adapter for the ABI 1.17 active debugger table.
   Implementations must validate the complete session/stop/document token. */
struct ActiveDebuggerServices {
    std::function<std::int32_t(HexLabActiveDebuggerInfo&)> query;
    std::function<std::int32_t(const HexLabActiveDebuggerToken&, std::uint64_t, std::uint32_t,
                               HexLabDebugThread*, std::uint32_t*)> threads;
    std::function<std::int32_t(const HexLabActiveDebuggerToken&, std::uint64_t, std::uint64_t,
                               std::uint32_t, HexLabDebugRegister*, std::uint32_t*)> read_registers;
    std::function<std::int32_t(const HexLabActiveDebuggerToken&, std::uint64_t,
                               std::uint32_t, std::uint8_t*)> read_memory;
};

// A loader seam for deterministic tests and alternate module systems.
class HEXLAB_PLUGINS_EXPORT ModuleProvider {
public:
    struct Module {
        void* handle = nullptr;
        void* (*lookup)(void* handle, const char* symbol) = nullptr;
        void (*close)(void* handle) = nullptr;
    };
    virtual ~ModuleProvider() = default;
    virtual Result<Module> open(const std::string& path) = 0;
};

class HEXLAB_PLUGINS_EXPORT PluginManager {
public:
    explicit PluginManager(std::shared_ptr<ModuleProvider> provider);
    /* Persistent plugin.state store. The file is host-owned and scoped to the
       current user profile; an empty path disables persistence. */
    PluginManager(std::shared_ptr<ModuleProvider> provider, std::filesystem::path state_store_path);
    ~PluginManager();
    PluginManager(const PluginManager&) = delete;
    PluginManager& operator=(const PluginManager&) = delete;
    PluginManager(PluginManager&&) noexcept;
    PluginManager& operator=(PluginManager&&) noexcept;

    Result<PluginInfo> load(const std::string& path);
    /* Loads a scanned candidate against its sidecar snapshot. A declared
       SHA-256 pin is checked immediately before and after native module open,
       and identity/capability declarations are checked before start. */
    Result<PluginInfo> load_candidate(const PluginCandidate& candidate);
    /* Enumerates only direct native-module candidates (macOS .bundle directories
       are supported). Symlinks and unrelated nested directories are skipped;
       scanning is bounded and does not load or execute any candidate. */
    Result<std::vector<PluginCandidate>> scan_directory(
        const std::string& directory, std::size_t max_entries = 4096) const;
    /* Recomputes per-requirement advisory statuses in caller-owned candidates
       without reading manifests or opening modules. Host and loaded providers
       take precedence over candidate providers. Does not plan transitive loads.
       At most 16384 candidates, with 256 capabilities/requirements each. */
    Status refresh_requirement_preflight(std::span<PluginCandidate> candidates) const;
    /* Data-only, provider-first activation plan for one candidate and its
       transitive requirements. Uses only supplied manifests and loaded metadata;
       rejects missing/ambiguous providers, duplicate identities and cycles.
       Input is bounded to 4096 candidates and the selected closure to 256. */
    Result<std::vector<PluginCandidate>> plan_activation(
        std::span<const PluginCandidate> candidates, const std::string& root_path) const;
    /* Replans against the current loaded set under one lifecycle lock. Every
       module's queried metadata must match its planned manifest before start.
       On failure, only plugins added by this call are stopped in reverse order.
       Native module/query/start side effects cannot be undone by rollback. */
    Result<std::vector<PluginInfo>> load_with_dependencies(
        std::span<const PluginCandidate> candidates, const std::string& root_path);
    Status unload(const std::string& plugin_id);
    /* Consumer-first unload of a plugin and all transitive loaded dependents.
       Providers that are merely dependencies of the selected plugin stay loaded. */
    Result<std::vector<std::string>> unload_with_dependents(const std::string& plugin_id);
    // Data-only cleanup review: at most 256 loaded modules, 4096 resolved
    // dependency edges and 64 KiB of loaded IDs. all ignores root_plugin_id.
    Result<PluginUnloadPlan> plan_unload(const std::string& root_plugin_id, bool all = false) const;
    // Rejects another manager or changed generations/plans before removal. Reports partial removals
    // explicitly if a later removal fails; providers outside the plan remain.
    Result<PluginUnloadResult> unload_reviewed(const PluginUnloadPlan&);
    // Stop all plugins in reverse activation order, including their dependents.
    Status unload_all();
    std::vector<PluginInfo> plugins() const;
    bool supports_capability(const std::string& plugin_id, const std::string& capability_id,
                             std::uint32_t major_version, std::uint32_t minimum_minor_version = 0) const;
    std::vector<PluginActionInfo> actions() const;
    std::vector<PluginMenuActionInfo> menu_actions() const;
    Status invoke_action(const std::string& plugin_id, const std::string& action_id);
    std::vector<LoaderExtensionInfo> loader_extensions() const;
    std::vector<ProcessorExtensionInfo> processor_extensions() const;
    std::vector<PluginExtensionFailure> extension_failures() const;
    std::vector<AnalysisProviderInfo> analysis_providers() const;
    Result<std::string> run_analysis_provider(const std::string& plugin_id,
                                              const std::string& provider_id,
                                              const std::string& project_path) const;
    Result<std::optional<LoaderProbeResult>> probe_loaders(
        std::span<const std::uint8_t> input, const std::string& requested_format = {},
        std::uint64_t total_size = 0) const;
    // Resolve a registered image provider into an exact durable recipe. Pass
    // this recipe to load_image or automation::Project::create; normal project
    // reopen resolves the same provider while its manager remains alive.
    Result<LoadRecipe> image_recipe(const std::string& plugin_id, const std::string& extension_id) const;
    Result<LoadedImage> load_plugin_image(std::shared_ptr<const ByteStorage>,
        const PluginImageIdentity&, std::stop_token = {}) const;
    Result<std::optional<ProcessorDecodeResult>> decode_processor(
        const std::string& architecture_id, const std::string& mode_id, std::uint64_t address,
        std::span<const std::uint8_t> input) const;
    Result<std::optional<Instruction>> decode_processor_semantic(
        DecodeContext, Address, std::span<const std::byte>) const;
    // Re-request a pure scalar program only under the exact analysis decoder
    // identity. Returned expressions are host-owned and retain no module code.
    Result<std::optional<decompiler::Intrinsic>> instruction_ir(
        const Instruction &, std::span<const std::byte> expected_semantic_identity) const;
    AnalysisOptions analysis_options(AnalysisOptions = {}) const;
    void set_active_document_services(ActiveDocumentServices);
    void set_active_debugger_services(ActiveDebuggerServices);
    void set_active_project_breakpoint_services(ActiveProjectBreakpointServices);

private:
    struct Impl;
    Result<PluginInfo> load_locked(const std::string&, const PluginCandidate::Manifest* = nullptr);
    Status unload_locked(const std::string&);
    Result<PluginUnloadPlan> plan_unload_locked(const std::string&, bool) const;
    Result<std::vector<PluginCandidate>> plan_activation_locked(
        std::span<const PluginCandidate>, const std::string&) const;
    explicit PluginManager(std::shared_ptr<Impl> impl) : impl_(std::move(impl)) {}
    std::shared_ptr<Impl> impl_;
};

/* Returns the per-user default plugin.state file location, or an empty path
   when no user data directory can be determined. */
HEXLAB_PLUGINS_EXPORT std::filesystem::path default_plugin_state_path();

HEXLAB_PLUGINS_EXPORT std::shared_ptr<ModuleProvider> make_native_module_provider();
// Reads a bounded, data-only `.hexlab-plugin` manifest. This never opens the
// native module; metadata remains advisory until the loaded ABI is compared.
HEXLAB_PLUGINS_EXPORT Result<PluginCandidate::Manifest> read_manifest(const std::string& path);
// Compares advisory sidecar fields to the module identity returned by query.
HEXLAB_PLUGINS_EXPORT bool manifest_matches(const PluginCandidate::Manifest&, const PluginInfo&);

enum class PluginAuthenticodeTrustStatus : std::uint8_t { trusted, not_trusted, unsupported };
struct HEXLAB_PLUGINS_EXPORT PluginAuthenticodeTrust {
    PluginAuthenticodeTrustStatus status = PluginAuthenticodeTrustStatus::unsupported;
    std::int32_t provider_status = 0;
    std::string provider;
};
// Uses the host platform's Authenticode trust policy when available. This is
// informational and does not prevent activation or provide process isolation.
HEXLAB_PLUGINS_EXPORT Result<PluginAuthenticodeTrust> verify_plugin_authenticode_trust(
    const std::filesystem::path& module_path);
} // namespace hexlab::plugins
