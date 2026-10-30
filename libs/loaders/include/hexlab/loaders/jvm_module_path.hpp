#pragma once
#include "hexlab/loaders/jar.hpp"
#include <cstddef>
#include <cstdint>
#include <filesystem>
#include <optional>
#include <span>
#include <stop_token>
#include <string>
#include <string_view>
#include <vector>

namespace hexlab {

enum class JvmPathRootKind : std::uint8_t { module_path, class_path };
struct JvmPathRoot {
    std::filesystem::path path;
    JvmPathRootKind kind = JvmPathRootKind::module_path;
};
enum class JvmPathRootStatus : std::uint8_t { linked, missing_module_descriptor };
struct JvmPathRootResult {
    std::filesystem::path path;
    JvmPathRootKind kind = JvmPathRootKind::module_path;
    JvmPathRootStatus status = JvmPathRootStatus::linked;
    std::optional<std::string> module_name;
    std::size_t files = 0, classes = 0;
    bool multi_release_active = false;
    std::size_t selected_versioned_classes = 0;
};
struct JvmPathVersionedClassSelection {
    std::size_t root_index = 0;
    std::string logical_path, archive_path;
    std::uint16_t release = 0;
    std::uint64_t data_file_offset = 0, uncompressed_size = 0;
};
enum class JvmClassPathReferenceStatus : std::uint8_t {
    resolved, not_supplied, ambiguous, malformed_uri, unsupported_uri, cycle
};
struct JvmClassPathReference {
    std::size_t declaring_root_index = 0;
    std::string uri;
    JvmClassPathReferenceStatus status = JvmClassPathReferenceStatus::not_supplied;
    std::optional<std::size_t> target_root_index;
};
struct JvmPathClassDefinition {
    std::size_t root_index = 0;
    std::string class_name; // Internal slash-form name from the class file.
    std::string resource_path; // Logical class path selected by the root.
    std::optional<std::string> archive_path;
    std::uint64_t data_file_offset = 0, uncompressed_size = 0;
    bool class_name_matches_path = true;
    std::optional<std::size_t> module_definition;
};
enum class JvmNestRelationKind : std::uint8_t { member_declares_host, host_declares_member };
enum class JvmNestRelationStatus : std::uint8_t { resolved, missing, ambiguous, not_reciprocal, cross_package };
struct JvmNestRelation {
    JvmNestRelationKind kind = JvmNestRelationKind::member_declares_host;
    JvmNestRelationStatus status = JvmNestRelationStatus::missing;
    std::string source_class, target_class;
    std::size_t source_metadata_index = 0;
    std::optional<std::size_t> target_metadata_index;
    FileOffset source_file_offset{};
};
enum class JvmClassPathLookupStatus : std::uint8_t { resolved, not_found, class_name_mismatch };
struct JvmClassPathLookup {
    std::string requested_binary_name;
    JvmClassPathLookupStatus status = JvmClassPathLookupStatus::not_found;
    std::optional<std::size_t> selected_definition;
    // Later matching definitions shadowed by the first class-path entry.
    std::vector<std::size_t> shadowed_definitions;
    std::optional<std::size_t> module_definition;
};
struct JvmModulePathLimits {
    std::size_t max_roots = 256;
    std::size_t max_files = 100'000;
    std::size_t max_classes = 50'000;
    std::uint64_t max_file_bytes = 128ULL * 1024 * 1024;
    std::uint64_t max_total_input_bytes = 2ULL * 1024 * 1024 * 1024;
    std::uint64_t max_total_class_bytes = 512ULL * 1024 * 1024;
    std::uint64_t max_service_bytes = 16ULL * 1024 * 1024;
    std::size_t max_service_rows = 65'536;
    std::uint64_t max_manifest_bytes = 1024 * 1024;
    std::size_t max_class_path_references = 4096;
    std::size_t max_class_path_uri_bytes = 4 * 1024 * 1024;
    std::size_t max_selection_path_bytes = 16 * 1024 * 1024;
    std::optional<std::uint16_t> target_release;
    JarLimits archive{};
    JvmModuleLinkLimits linking{};
};
struct JvmModulePathWorkspace {
    JvmModuleWorkspaceGraph graph;
    std::vector<JvmPathRootResult> roots;
    std::vector<JvmPathVersionedClassSelection> versioned_classes;
    std::optional<std::size_t> unnamed_classpath_module;
    // Effective class-path order after recursively expanding supported
    // manifest Class-Path references. Indexes address `roots`.
    std::vector<std::size_t> class_path_search_order;
    std::vector<JvmClassPathReference> class_path_references;
    std::vector<JvmPathClassDefinition> class_path_classes;
    // NestHost/NestMembers links cross-checked over the supplied class files.
    // Duplicate class names are ambiguous; the linker never chooses a loader.
    std::vector<JvmNestRelation> nest_relations;
};
struct JvmModuleConfigurationRoot {
    std::string name;
    JvmModuleLinkStatus status = JvmModuleLinkStatus::missing;
    std::optional<std::size_t> module_definition;
};
struct JvmModuleConfiguration {
    std::vector<JvmModuleConfigurationRoot> roots;
    // Deterministic breadth-first closure, in caller root order and descriptor
    // requires-row order. Indexes address workspace.graph.module_graph.modules.
    std::vector<std::size_t> resolved_modules;
    // Edge indexes whose required dependency is missing, ambiguous, or otherwise unresolved.
    std::vector<std::size_t> unresolved_required_edges;
    // Missing `requires static` edges do not enter the runtime closure.
    std::vector<std::size_t> omitted_optional_edges;
    bool complete = true;
};

// Inventories ordered caller-supplied directories and ZIP/JAR files. Directory
// traversal is recursive, sorted by generic relative path, and does not follow
// symlinks. A module-path root must contain a root module-info.class; automatic
// module names are not inferred. All class-path roots share one explicit
// synthetic unnamed module. Class ownership is augmented from root provenance
// before invoking link_jvm_metadata_workspace. This reports metadata ownership,
// duplicate names, split packages, service references, and descriptor-derived
// direct/transitive readability. Relative manifest Class-Path references are
// expanded only when their targets are among caller-supplied class-path roots;
// the loader does not implicitly open paths named by manifests. This does not
// emulate runtime JPMS resolution, exports/access checks, or full class-loader
// behavior.
HEXLAB_LOADERS_EXPORT Result<JvmModulePathWorkspace> link_jvm_path_workspace(
    std::span<const JvmPathRoot>, std::stop_token = {}, JvmModulePathLimits = {});
// Resolves a Java binary class name against the workspace's effective class-
// path order. This consults only classes already inventoried from caller-
// supplied roots and reports later matches as shadowed definitions.
HEXLAB_LOADERS_EXPORT Result<JvmClassPathLookup> resolve_jvm_class_path_class(
    const JvmModulePathWorkspace &, std::string_view binary_name);
// Computes a bounded caller-rooted module closure from already inventoried
// module descriptors. It does not discover modules or emulate full JPMS
// resolution, service binding, readability, or access checks.
HEXLAB_LOADERS_EXPORT Result<JvmModuleConfiguration> resolve_jvm_module_configuration(
    const JvmModulePathWorkspace &, std::span<const std::string_view> root_module_names,
    std::stop_token = {}, std::size_t max_modules = 4096,
    std::size_t max_work = 1'000'000);

} // namespace hexlab
