#pragma once
#include "hexlab/loaders/loaded_image.hpp"
#include "hexlab/image/jvm_metadata.hpp"
#include <cstddef>
#include <cstdint>
#include <memory>
#include <optional>
#include <span>
#include <stop_token>
#include <vector>
#include <string_view>
namespace hexlab {
// Bounded JVM class-file loader. Each method Code array receives a private
// byte-addressed address space so its branch offsets stay method-relative.
// JvmCode::stack_map_table retains bounded, expanded verifier frames from
// StackMapTable and pre-version-50 StackMap, including class indices and
// uninitialized states; loading does not prove bytecode safety.
HEXLAB_LOADERS_EXPORT Result<LoadedImage> load_jvm_class(std::shared_ptr<const ByteStorage>, std::stop_token);
// Parses the JVMS generic Signature grammar only, without class linking,
// descriptor-erasure checks or type-variable binding. At most 65535 bytes,
// 1024 nodes and 32 nested type levels are accepted.
HEXLAB_LOADERS_EXPORT Result<JvmGenericSignature> parse_jvm_generic_signature(
    std::string_view, JvmGenericSignatureKind, std::stop_token = {});

enum class JvmModuleLinkEdgeKind : std::uint8_t { requires_module, qualified_export, qualified_open };
enum class JvmModuleLinkStatus : std::uint8_t {
    resolved, missing, missing_optional, duplicate_definition, unresolved_ownership, ambiguous_ownership
};
struct JvmModuleLinkNode {
    std::string name;
    bool duplicate_definition = false;
};
struct JvmModuleLinkEdge {
    std::size_t source_definition = 0;
    std::string target_name;
    JvmModuleLinkEdgeKind kind = JvmModuleLinkEdgeKind::requires_module;
    JvmModuleLinkStatus status = JvmModuleLinkStatus::missing;
    std::optional<std::size_t> target_definition;
    bool transitive = false;
};
struct JvmModuleReadability {
    std::size_t source_definition = 0, target_definition = 0;
    bool direct = false;
};
struct JvmModuleLinkGraph {
    std::vector<JvmModuleLinkNode> modules;
    std::vector<JvmModuleLinkEdge> edges;
    // Direct requirements plus the bounded closure through `requires transitive`.
    // Self-readability is implicit and is not emitted as a row.
    std::vector<JvmModuleReadability> readability;
    // Each entry is one detected cycle, with the first module repeated last.
    std::vector<std::vector<std::string>> requires_cycles;
};
struct JvmModuleLinkLimits {
    std::size_t max_modules = 4096;
    std::size_t max_edges = 65536;
    std::size_t max_readability_edges = 262144;
    std::size_t max_readability_work = 1'000'000;
    std::size_t max_cycles = 4096;
    std::size_t max_cycle_members = 65536;
    std::size_t max_cycle_name_bytes = 4 * 1024 * 1024;
    std::size_t max_name_bytes = 4 * 1024 * 1024;
    std::size_t max_classes = 100000;
    std::size_t max_service_references = 65536;
};
// Links module descriptors supplied by the caller. The result records missing
// and duplicate module definitions instead of guessing which definition wins.
// Requires cycles and descriptor-derived readability are reported; this does
// not resolve runtime configurations, class access, or module-path behavior.
HEXLAB_LOADERS_EXPORT Result<JvmModuleLinkGraph> link_jvm_modules(
    std::span<const JvmModule>, std::stop_token = {}, JvmModuleLinkLimits = {});
struct JvmModuleClassInput { std::string module_name, class_name; };
enum class JvmServiceLinkKind : std::uint8_t { uses_service, provides_service, provider_class };
struct JvmServiceLink {
    std::size_t source_definition = 0;
    JvmServiceLinkKind kind = JvmServiceLinkKind::uses_service;
    std::string class_name;
    JvmModuleLinkStatus status = JvmModuleLinkStatus::missing;
    std::optional<std::size_t> class_definition;
};
struct JvmPackageOwnership {
    std::string package_name;
    std::vector<std::size_t> module_definitions;
    bool split_package = false;
};
struct JvmModuleClassOwnership {
    std::string module_name, class_name;
    JvmModuleLinkStatus status = JvmModuleLinkStatus::missing;
    std::optional<std::size_t> module_definition;
};
enum class JvmPermittedClassStatus : std::uint8_t { resolved, missing, ambiguous, not_direct_subtype };
struct JvmPermittedClassLink {
    std::size_t source_metadata_index = 0;
    std::optional<std::size_t> target_metadata_index;
    std::string source_class, target_class;
    JvmPermittedClassStatus status = JvmPermittedClassStatus::missing;
    FileOffset source_file_offset{};
};
struct JvmModuleWorkspaceGraph {
    JvmModuleLinkGraph module_graph;
    std::vector<JvmModuleClassOwnership> class_ownership;
    std::vector<JvmPackageOwnership> packages;
    std::vector<JvmServiceLink> services;
    std::vector<JvmPermittedClassLink> permitted_classes;
};
// Extends descriptor linking with caller-supplied class ownership facts. These
// facts support split-package and service-class inventory checks, not runtime
// class loading or module readability/access enforcement.
HEXLAB_LOADERS_EXPORT Result<JvmModuleWorkspaceGraph> link_jvm_workspace(
    std::span<const JvmModule>, std::span<const JvmModuleClassInput>,
    std::stop_token = {}, JvmModuleLinkLimits = {});
// Convenience entrypoint over loaded class metadata. Module descriptors come
// from module-info metadata; ordinary classes are assigned only when exactly
// one unique module declares their package in ModulePackages.
HEXLAB_LOADERS_EXPORT Result<JvmModuleWorkspaceGraph> link_jvm_metadata_workspace(
    std::span<const JvmMetadata>, std::stop_token = {}, JvmModuleLinkLimits = {});
}
