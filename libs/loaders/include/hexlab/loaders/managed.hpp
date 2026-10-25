#pragma once
#include "hexlab/loaders/loaders_export.hpp"
#include "hexlab/core/result.hpp"
#include <cstddef>
#include <cstdint>
#include <map>
#include <memory>
#include <optional>
#include <span>
#include <string>
#include <vector>
namespace hexlab {
struct LoadedImage;
struct ManagedStream { std::uint32_t offset=0, size=0; };
struct ManagedTables { std::uint8_t major=0, minor=0, heap_sizes=0; std::uint64_t valid=0, sorted=0; std::size_t data_offset=0; std::map<std::uint8_t,std::uint32_t> row_counts; std::map<std::uint8_t,std::uint32_t> row_sizes; };
struct ManagedMetadataRoot { std::string version; std::map<std::string,ManagedStream,std::less<>> streams; ManagedTables tables; };
struct ManagedPeInfo { std::uint16_t major=0, minor=0; std::uint32_t flags=0, entry_point_token=0; ManagedMetadataRoot metadata; };
struct ManagedGenericParameter {
  std::uint32_t token=0, owner_token=0;
  std::uint16_t number=0, flags=0;
  std::string name;
  // TypeDef, TypeRef, or TypeSpec metadata tokens from GenericParamConstraint.
  std::vector<std::uint32_t> constraint_tokens;
};
// Lossless, bounded subset of the CLR signature type grammar. `element_type`
// retains the raw ELEMENT_TYPE byte; VAR/MVAR use `generic_index`, token types
// retain the compressed TypeDefOrRef coded index, and wrapper/instantiation
// nodes retain their children in order.
struct ManagedTypeSignature {
  std::uint8_t element_type=0;
  bool generic_instance_is_value_type=false;
  // False only when a locally known generic TypeDef's arity disagrees with
  // this GENERICINST node. Preserve the token/arguments but do not type values
  // from an invalid instantiation.
  bool generic_instance_arity_valid=true;
  std::uint32_t generic_index=0, metadata_type_coded_index=0, metadata_type_token=0, array_rank=0;
  // Resolved display identity when a metadata catalog is available. External
  // assembly/module scopes remain explicitly marked unresolved.
  std::string metadata_type_name, metadata_type_scope;
  bool metadata_type_external_unresolved=false;
  std::shared_ptr<ManagedTypeSignature> type_spec_signature;
  std::vector<ManagedTypeSignature> children;
};
struct ManagedMethod { std::uint32_t token=0, rva=0; std::uint16_t impl_flags=0, flags=0; std::string name; std::uint32_t signature_index=0; std::string declaring_type; std::vector<ManagedGenericParameter> generic_parameters, declaring_type_generic_parameters; };
struct ManagedMethodSignature { std::uint32_t parameter_count=0; bool has_this=false, returns_value=false; std::uint32_t generic_arity=0; ManagedTypeSignature return_type; std::vector<ManagedTypeSignature> parameter_types, method_spec_arguments, declaring_type_arguments; std::uint32_t declaring_type_token=0; std::string declaring_type_name; std::optional<bool> declaring_type_is_value_type; bool declaring_type_generic_arguments_valid=true; };
using ManagedUserStringCatalog = std::map<std::uint32_t, std::u16string>;
// Decodes a FieldSig blob payload (including the 0x06 FIELD calling-convention
// byte). Metadata-token names are resolved when parsed through parse_managed_fields.
HEXLAB_LOADERS_EXPORT Result<ManagedTypeSignature> decode_managed_field_signature(std::span<const std::byte> signature_blob);
HEXLAB_LOADERS_EXPORT Result<ManagedMethodSignature> decode_managed_method_signature(std::span<const std::byte> signature_blob);
// Decodes a method signature used by calli. In addition to managed default
// and vararg conventions, this accepts the ECMA-335 unmanaged call-site
// conventions whose stack shape is still described by the signature blob.
HEXLAB_LOADERS_EXPORT Result<ManagedMethodSignature> decode_managed_call_site_signature(std::span<const std::byte> signature_blob);
HEXLAB_LOADERS_EXPORT Result<std::map<std::uint32_t,ManagedMethodSignature>> parse_managed_call_signatures(std::span<const std::byte> metadata_root);
// Parses #US heap entries as UTF-16 code units, keyed by their complete
// 0x70xxxxxx user-string metadata token. The trailing kind byte is validated
// and omitted from the returned string.
HEXLAB_LOADERS_EXPORT Result<ManagedUserStringCatalog> parse_managed_user_strings(std::span<const std::byte> metadata_root);
struct ManagedField {
  std::uint32_t token=0, flags=0, signature_index=0;
  std::string name, declaring_type;
  std::optional<ManagedTypeSignature> type_signature;
  std::string signature_diagnostic;
  // Closed generic owner arguments for MemberRef field references. Definition
  // fields have no substitution context and keep this empty.
  std::vector<ManagedTypeSignature> declaring_type_arguments;
  bool declaring_type_generic_arguments_valid=true;
};
struct ManagedTypeDefinition {
  std::uint32_t token=0, flags=0;
  // Zero for top-level types; otherwise the owning TypeDef token from
  // ECMA-335 NestedClass metadata.
  std::uint32_t enclosing_type_token=0;
  // Resolved TypeDefOrRef identity from the Extends column, if present.
  std::uint32_t base_type_token=0;
  // Implemented TypeDefOrRef identities from InterfaceImpl rows.
  std::vector<std::uint32_t> interface_tokens;
  std::string name, namespace_name, full_name;
  std::vector<std::uint32_t> method_tokens;
  std::vector<ManagedGenericParameter> generic_parameters;
};
struct ManagedAssemblyIdentity {
  std::string name, culture;
  std::uint16_t major=0, minor=0, build=0, revision=0;
  std::uint32_t flags=0;
  // The #Blob value is the full public key when flags bit 0 is set, otherwise
  // the public-key token. It is retained byte-for-byte for exact binding.
  std::vector<std::byte> public_key_or_token;
  bool operator==(const ManagedAssemblyIdentity&) const = default;
};
enum class ManagedTypeResolutionScopeKind { module, module_ref, assembly_ref, nested_type_ref, null_scope };
struct ManagedTypeReference {
  std::uint32_t token=0, resolution_scope_coded_index=0, resolution_scope_token=0;
  ManagedTypeResolutionScopeKind resolution_scope_kind=ManagedTypeResolutionScopeKind::null_scope;
  std::string name, namespace_name, full_name, unresolved_scope;
  std::optional<ManagedAssemblyIdentity> assembly_scope;
  std::optional<std::uint32_t> resolved_catalog_index, resolved_definition_token;
  bool external_scope_unresolved=false;
};
struct ManagedTypeSpecification {
  std::uint32_t token=0;
  ManagedTypeSignature signature;
};
struct ManagedTypeCatalog {
  std::optional<ManagedAssemblyIdentity> assembly_identity;
  std::vector<ManagedTypeDefinition> definitions;
  std::vector<ManagedTypeReference> references;
  std::vector<ManagedTypeSpecification> specifications;
};
// Returns true only when `candidate` is proven assignable to `target` through
// the bounded in-module TypeDef base/interface graph. Unknown/external edges
// and unresolved TypeSpecs return false.
HEXLAB_LOADERS_EXPORT bool managed_type_is_assignable(const ManagedTypeCatalog&,std::uint32_t candidate,std::uint32_t target);
// Binds exact AssemblyRef identities to a unique catalog and a unique TypeDef
// full name. Missing and ambiguous inputs remain unbound. The operation is
// deterministic and does not load assemblies from disk.
HEXLAB_LOADERS_EXPORT Result<bool> bind_managed_type_references(std::span<ManagedTypeCatalog> catalogs);
// Like the in-module query above, but follows uniquely bound TypeRefs across
// the supplied catalogs. Tokens are interpreted in the catalog identified by
// the corresponding index. Unknown and ambiguous edges return false.
HEXLAB_LOADERS_EXPORT bool managed_type_is_assignable_across_catalogs(
    std::span<const ManagedTypeCatalog> catalogs, std::uint32_t candidate_catalog,
    std::uint32_t candidate, std::uint32_t target_catalog, std::uint32_t target);
enum class CilExceptionKind { catch_clause, filter, finally_clause, fault_clause };
struct CilExceptionClause {
  CilExceptionKind kind=CilExceptionKind::catch_clause;
  std::uint32_t try_offset=0, try_length=0, handler_offset=0, handler_length=0;
  // Catch clauses carry a type token; filter clauses carry filter_offset.
  std::uint32_t class_token=0, filter_offset=0;
  // Provenance is relative to the method header, not the first IL byte.
  // Zero defaults allow independently supplied, already decoded clauses.
  std::uint32_t raw_flags=0, section_offset=0, clause_offset=0;
  bool fat_encoding=false;
};
struct CilMethodDataSection {
  std::uint32_t offset=0, size=0;
  std::uint8_t kind=0;
  bool fat_encoding=false, more_sections=false;
  std::uint32_t first_clause=0, clause_count=0;
};
struct CilMethodBody {
  std::uint16_t max_stack=0;
  std::uint32_t code_size=0;
  bool init_locals=false, has_more_sections=false;
  std::uint32_t local_signature_token=0;
  std::vector<std::byte> il;
  std::vector<CilExceptionClause> exception_clauses;
  std::vector<CilMethodDataSection> data_sections;
};
HEXLAB_LOADERS_EXPORT Result<ManagedMetadataRoot> parse_cli_metadata(std::span<const std::byte> bytes);
HEXLAB_LOADERS_EXPORT Result<ManagedPeInfo> parse_managed_pe(const LoadedImage& loaded);
HEXLAB_LOADERS_EXPORT Result<std::vector<ManagedMethod>> parse_managed_methods(std::span<const std::byte> metadata_root);
HEXLAB_LOADERS_EXPORT Result<std::vector<ManagedField>> parse_managed_fields(std::span<const std::byte> metadata_root);
// Includes FieldDef declarations and field-shaped MemberRef rows. MemberRef
// staticness is not encoded in metadata and must be inferred from the IL opcode.
HEXLAB_LOADERS_EXPORT Result<std::vector<ManagedField>> parse_managed_field_references(std::span<const std::byte> metadata_root);
HEXLAB_LOADERS_EXPORT Result<std::vector<ManagedGenericParameter>> parse_managed_generic_parameters(std::span<const std::byte> metadata_root);
HEXLAB_LOADERS_EXPORT Result<std::vector<ManagedTypeDefinition>> parse_managed_types(std::span<const std::byte> metadata_root);
HEXLAB_LOADERS_EXPORT Result<ManagedTypeCatalog> parse_managed_type_catalog(std::span<const std::byte> metadata_root);
HEXLAB_LOADERS_EXPORT Result<CilMethodBody> parse_cil_method_body(std::span<const std::byte> bytes);
}
