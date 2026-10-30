#pragma once
#include "hexlab/loaders/loaders_export.hpp"
#include "hexlab/core/result.hpp"
#include <cstddef>
#include <cstdint>
#include <map>
#include <memory>
#include <optional>
#include <span>
#include <stop_token>
#include <string>
#include <vector>
namespace hexlab {
struct LoadedImage;
struct ManagedTypeSignature;
struct ManagedStream { std::uint32_t offset=0, size=0; };
struct ManagedTables { std::uint8_t major=0, minor=0, heap_sizes=0; std::uint64_t valid=0, sorted=0; std::size_t data_offset=0; std::map<std::uint8_t,std::uint32_t> row_counts; std::map<std::uint8_t,std::uint32_t> row_sizes; };
struct ManagedMetadataRoot { std::string version; std::map<std::string,ManagedStream,std::less<>> streams; ManagedTables tables; };
struct ManagedPeInfo {
  std::uint16_t major=0, minor=0;
  std::uint32_t flags=0, entry_point_token=0;
  ManagedMetadataRoot metadata;
  // IMAGE_COR20_HEADER.Resources. Zero means the PE has no embedded resource directory.
  std::uint32_t resources_rva=0, resources_size=0;
};
struct ManagedGenericParameter {
  std::uint32_t token=0, owner_token=0;
  std::uint16_t number=0, flags=0;
  std::string name;
  // GenericParam row location relative to the metadata root.
  std::uint64_t metadata_offset=0;
  // TypeDef, TypeRef, or TypeSpec metadata tokens from GenericParamConstraint.
  std::vector<std::uint32_t> constraint_tokens;
  // Row locations relative to the metadata root, parallel to constraint_tokens.
  std::vector<std::uint64_t> constraint_metadata_offsets;
  // Resolved identities in catalog contexts. The token list above remains the
  // authoritative metadata provenance; unresolved external scopes stay marked.
  struct ConstraintIdentity {
    std::uint32_t token=0;
    std::string name, scope;
    bool external_unresolved=false;
    std::shared_ptr<ManagedTypeSignature> signature;
  };
  std::vector<ConstraintIdentity> resolved_constraints;
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
  // When a TypeRef binds across the caller-supplied catalog set, retain the
  // exact definition identity alongside the source TypeRef token. The local
  // token remains authoritative provenance; these indexes are a derived link.
  std::optional<std::uint32_t> resolved_type_catalog_index, resolved_type_definition_token;
  std::shared_ptr<ManagedTypeSignature> type_spec_signature;
  std::vector<ManagedTypeSignature> children;
};
// Constant table payloads retain exact integer/IEEE floating-point bits and
// UTF-16 code units. ELEMENT_TYPE_CLASS (0x12) denotes a validated null value.
// Parent tokens are Field (0x04), Param (0x08), or Property (0x17).
struct ManagedConstant {
  std::uint32_t token=0, parent_token=0, blob_index=0;
  std::uint8_t element_type=0;
  std::uint64_t scalar_bits=0;
  std::u16string string_value;
};
HEXLAB_LOADERS_EXPORT Result<std::vector<ManagedConstant>> parse_managed_constants(std::span<const std::byte> metadata_root);
// Custom-attribute values are retained as bounded opaque serialized payloads;
// this catalog validates parent/constructor tokens and the required prolog.
struct ManagedCustomAttribute {
  std::uint32_t token=0, parent_token=0, constructor_token=0, value_blob_index=0;
  std::uint64_t metadata_offset=0;
  std::vector<std::byte> serialized_value;
};
HEXLAB_LOADERS_EXPORT Result<std::vector<ManagedCustomAttribute>> parse_managed_custom_attributes(std::span<const std::byte> metadata_root);
// Declarative-security rows retain their HasDeclSecurity parent and the raw
// permission-set blob. Permission attributes are not evaluated as policy.
struct ManagedDeclarativeSecurity {
  std::uint32_t token=0, parent_token=0, permission_set_blob_index=0;
  std::uint16_t action=0;
  std::uint64_t metadata_offset=0, permission_set_blob_offset=0;
  std::vector<std::byte> permission_set;
};
HEXLAB_LOADERS_EXPORT Result<std::vector<ManagedDeclarativeSecurity>> parse_managed_declarative_security(
    std::span<const std::byte> metadata_root);
// MethodImpl rows bind a class-local method body to a MethodDef or MemberRef
// declaration. Tokens and row provenance are retained without inferring runtime
// dispatch or resolving external MemberRefs.
struct ManagedMethodImplementation {
  std::uint32_t token=0, class_token=0, body_token=0, declaration_token=0;
  std::uint64_t metadata_offset=0;
};
HEXLAB_LOADERS_EXPORT Result<std::vector<ManagedMethodImplementation>> parse_managed_method_implementations(std::span<const std::byte> metadata_root);
enum class ManagedMarshalDescriptorStatus : std::uint8_t {
  decoded_scalar, decoded_array, decoded_custom_marshaler, opaque_unknown
};
// FieldMarshal NativeType blobs remain authoritative and are always retained
// verbatim. Recognized descriptor fields are a bounded derived view.
struct ManagedMarshalDescriptor {
  std::uint32_t token=0, parent_token=0, blob_index=0;
  std::uint64_t metadata_offset=0, blob_data_offset=0;
  std::vector<std::byte> native_type;
  ManagedMarshalDescriptorStatus decode_status=ManagedMarshalDescriptorStatus::opaque_unknown;
  std::string native_type_name;
  std::optional<std::uint8_t> array_element_type;
  std::optional<std::uint32_t> array_parameter_index, array_element_count;
  // Four CustomMarshaler SerStrings in wire order: GUID, unmanaged type,
  // managed type, cookie. Null SerStrings remain empty optionals.
  std::vector<std::optional<std::string>> custom_marshaler_strings;
};
HEXLAB_LOADERS_EXPORT Result<std::vector<ManagedMarshalDescriptor>> parse_managed_marshal_descriptors(std::span<const std::byte> metadata_root);
enum class ManagedResourceImplementationKind : std::uint8_t { embedded, file, assembly_ref, exported_type };
enum class ManagedResourceResolutionState : std::uint8_t {
  embedded, unresolved, resolved_file, resolved_assembly, ambiguous, hash_mismatch, unsupported_hash
};
enum class ManagedResourcePayloadFormat : std::uint8_t { opaque, dotnet_resources_v2, unsupported_dotnet_resources };
enum class ManagedResourceValueKind : std::uint8_t {
  null_value, string_value, boolean, character, signed_integer, unsigned_integer,
  single, double_value, decimal, date_time, time_span, byte_array, stream, user_type, unsupported
};
struct ManagedResourceRecord {
  std::string name;
  std::uint32_t type_code=0;
  std::string type_name;
  ManagedResourceValueKind kind=ManagedResourceValueKind::unsupported;
  // Scalar records expose the low 64 serialized bits here. Their exact bytes,
  // including 128-bit Decimal values, remain available through data_offset /
  // data_size. String text is UTF-8 after strict validation; byte/stream/opaque
  // data refers into the owning ManagedResource::payload without duplication.
  std::uint64_t scalar_bits=0;
  std::string string_value;
  std::uint32_t data_offset=0, data_size=0;
  bool supported=false;
};
struct ManagedAssemblyIdentity {
  std::string name, culture;
  std::uint16_t major=0, minor=0, build=0, revision=0;
  std::uint32_t flags=0;
  // The #Blob value is the full public key when flags bit 0 is set, otherwise
  // the public-key token. It is retained byte-for-byte for exact binding.
  std::vector<std::byte> public_key_or_token;
  // Present for the module's Assembly manifest row; AssemblyRef identities
  // leave these source-local fields unset.
  std::optional<std::uint32_t> hash_algorithm_id, public_key_blob_index;
  std::optional<std::uint64_t> metadata_offset, public_key_blob_offset;
  bool operator==(const ManagedAssemblyIdentity&) const = default;
};
struct ManagedResource {
  std::uint32_t token=0, flags=0, implementation_coded_index=0, implementation_token=0;
  std::uint32_t data_offset=0, data_size=0;
  ManagedResourceImplementationKind implementation=ManagedResourceImplementationKind::embedded;
  std::string name;
  // External ManifestResource implementations retain their metadata identity.
  std::string implementation_name, implementation_culture;
  std::uint16_t implementation_major=0, implementation_minor=0;
  std::uint16_t implementation_build=0, implementation_revision=0;
  std::uint32_t implementation_flags=0;
  std::uint32_t implementation_key_or_token_blob_index=0, implementation_hash_blob_index=0;
  std::uint32_t implementation_hash_algorithm=0;
  std::vector<std::byte> implementation_key_or_token, implementation_hash;
  bool implementation_file_contains_metadata=false;
  ManagedResourceResolutionState resolution=ManagedResourceResolutionState::embedded;
  std::string resolution_diagnostic;
  // Metadata offset points at ManifestResource row. For embedded resources,
  // payload preserves the exact bytes after the length prefix.
  std::uint64_t metadata_offset=0;
  std::uint32_t row_size=0;
  std::vector<std::byte> payload;
  ManagedResourcePayloadFormat payload_format=ManagedResourcePayloadFormat::opaque;
  std::string payload_diagnostic;
  std::vector<ManagedResourceRecord> records;
};
HEXLAB_LOADERS_EXPORT Result<std::vector<ManagedResource>> parse_managed_resources(
    std::span<const std::byte> metadata_root);
HEXLAB_LOADERS_EXPORT Result<std::vector<ManagedResource>> inspect_managed_resources(
    const LoadedImage& loaded);
class ByteStorage;
struct ManagedResourceInput {
  // Exact caller-supplied leaf name used to bind File table entries.
  std::string file_name;
  std::shared_ptr<const ByteStorage> storage;
  // Required for AssemblyRef providers and File rows marked ContainsMetadata.
  const LoadedImage* loaded_image=nullptr;
};
struct ManagedResourceResolutionLimits {
  std::size_t max_inputs=256;
  std::uint64_t max_input_bytes=512u*1024u*1024u;
  std::uint64_t max_payload_bytes=64u*1024u*1024u;
};
// Resolves external resource entries only against explicitly supplied inputs.
// File candidates require an exact name and supported, matching Assembly
// HashAlgId/File.HashValue. AssemblyRef candidates require an exact identity
// and unique resource-name match. No host paths are searched.
HEXLAB_LOADERS_EXPORT Result<std::vector<ManagedResource>> inspect_managed_resources(
    const LoadedImage& loaded, std::span<const ManagedResourceInput> supplied,
    const ManagedResourceResolutionLimits& limits={}, std::stop_token stop={});
struct ManagedParameter {
  std::uint32_t token=0;
  // Sequence zero denotes the method return parameter; positive values are
  // one-based signature parameter indexes.
  std::uint16_t sequence=0, flags=0;
  std::string name;
  std::optional<ManagedConstant> default_value;
  // FieldMarshal row associated with this Param token, when present.
  std::optional<ManagedMarshalDescriptor> marshal_descriptor;
};
struct ManagedMethodImport {
  std::uint16_t flags=0;
  std::string import_name, module_name;
  std::uint32_t module_token=0;
};
struct ManagedMethod { std::uint32_t token=0, rva=0; std::uint16_t impl_flags=0, flags=0; std::string name; std::uint32_t signature_index=0; std::string declaring_type; std::optional<ManagedMethodImport> import_map; std::vector<ManagedGenericParameter> generic_parameters, declaring_type_generic_parameters; std::vector<ManagedParameter> parameters; };
struct ManagedMethodSignature { std::uint32_t parameter_count=0; bool has_this=false, returns_value=false; std::uint32_t generic_arity=0; ManagedTypeSignature return_type; std::vector<ManagedTypeSignature> parameter_types, method_spec_arguments, declaring_type_arguments; std::uint32_t declaring_type_token=0; std::string declaring_type_name; std::optional<bool> declaring_type_is_value_type; bool declaring_type_generic_arguments_valid=true; };
struct ManagedLocalVariable { ManagedTypeSignature type; bool pinned=false; };
// ECMA-335 LocalVarSig entries keyed by their StandAloneSig metadata token.
using ManagedLocalSignature = std::vector<ManagedLocalVariable>;
HEXLAB_LOADERS_EXPORT Result<ManagedLocalSignature> decode_managed_local_signature(std::span<const std::byte> signature_blob);
HEXLAB_LOADERS_EXPORT Result<std::map<std::uint32_t,ManagedLocalSignature>> parse_managed_local_signatures(std::span<const std::byte> metadata_root);
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
  std::optional<ManagedConstant> default_value;
  // FieldMarshal row associated with this FieldDef token, when present.
  std::optional<ManagedMarshalDescriptor> marshal_descriptor;
  // FieldRVA location and metadata-row provenance for initialized static data.
  std::optional<std::uint32_t> rva;
  std::optional<std::uint64_t> rva_metadata_offset;
  // FieldLayout offset and row provenance, when the explicit-layout table has one.
  std::optional<std::uint32_t> explicit_layout_offset;
  std::optional<std::uint64_t> layout_metadata_offset;
};
struct ManagedFieldLayout {
  std::uint32_t field_token=0, offset=0;
  std::uint64_t metadata_offset=0;
};
HEXLAB_LOADERS_EXPORT Result<std::vector<ManagedFieldLayout>> parse_managed_field_layouts(std::span<const std::byte> metadata_root);
struct ManagedFieldRva {
  std::uint32_t field_token=0, rva=0;
  std::uint64_t metadata_offset=0;
};
HEXLAB_LOADERS_EXPORT Result<std::vector<ManagedFieldRva>> parse_managed_field_rvas(std::span<const std::byte> metadata_root);
struct ManagedPropertySignature {
  bool has_this=false;
  ManagedTypeSignature property_type;
  std::vector<ManagedTypeSignature> index_parameter_types;
};
enum class ManagedPropertyAccessorValidation : std::uint8_t { not_applicable, valid, invalid, unsupported };
struct ManagedPropertyAccessor {
  std::uint32_t method_token=0, semantics_token=0;
  // Setter=1, Getter=2, Other=4. No accessor execution is inferred.
  std::uint16_t semantics=0;
  std::uint64_t metadata_offset=0;
  std::uint32_t signature_index=0, signature_size=0;
  std::uint64_t signature_metadata_offset=0;
  ManagedPropertyAccessorValidation validation=ManagedPropertyAccessorValidation::not_applicable;
  std::string validation_diagnostic;
};
struct ManagedProperty {
  std::uint32_t token=0, declaring_type_token=0, signature_index=0;
  std::uint16_t flags=0;
  std::string name, declaring_type, signature_diagnostic;
  std::optional<ManagedPropertySignature> signature;
  std::vector<ManagedPropertyAccessor> accessors;
  std::optional<ManagedConstant> default_value;
  // Offsets are relative to the original CLR metadata root, not PE RVAs.
  std::uint64_t metadata_offset=0, signature_metadata_offset=0;
  std::uint32_t row_size=0, signature_size=0;
};
HEXLAB_LOADERS_EXPORT Result<ManagedPropertySignature> decode_managed_property_signature(std::span<const std::byte> signature_blob);
HEXLAB_LOADERS_EXPORT Result<std::vector<ManagedProperty>> parse_managed_properties(std::span<const std::byte> metadata_root);
enum class ManagedEventAccessorRole : std::uint16_t { other = 4, add_on = 8, remove_on = 16, fire = 32 };
struct ManagedEventAccessor {
  std::uint32_t method_token=0, semantics_token=0;
  std::uint16_t semantics=0;
  std::uint64_t metadata_offset=0;
};
struct ManagedEvent {
  std::uint32_t token=0, declaring_type_token=0;
  std::uint32_t event_type_coded_index=0, event_type_token=0;
  std::uint16_t flags=0;
  std::string name, declaring_type;
  std::vector<ManagedEventAccessor> accessors;
  // Offsets are relative to the original CLR metadata root.
  std::uint64_t metadata_offset=0;
  std::uint32_t row_size=0;
};
HEXLAB_LOADERS_EXPORT Result<std::vector<ManagedEvent>> parse_managed_events(std::span<const std::byte> metadata_root);
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
  // ClassLayout row values; absent means the type has no explicit ClassLayout row.
  std::optional<std::uint16_t> packing_size;
  std::optional<std::uint32_t> declared_class_size;
  std::optional<std::uint64_t> layout_metadata_offset;
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
enum class ManagedExportedTypeImplementationKind { file, assembly_ref, exported_type };
struct ManagedExportedType {
  std::uint32_t token=0, flags=0, type_def_id=0;
  std::uint32_t implementation_coded_index=0, implementation_token=0;
  ManagedExportedTypeImplementationKind implementation_kind=ManagedExportedTypeImplementationKind::file;
  std::string name, namespace_name, full_name;
  bool forwarding_valid=false;
  // Present only when this row (or its enclosing ExportedType) names an
  // AssemblyRef. File implementations retain their token but stay unresolved.
  std::optional<ManagedAssemblyIdentity> assembly_scope;
};
struct ManagedTypeCatalog {
  std::optional<ManagedAssemblyIdentity> assembly_identity;
  std::vector<ManagedTypeDefinition> definitions;
  std::vector<ManagedTypeReference> references;
  std::vector<ManagedExportedType> exported_types;
  std::vector<ManagedTypeSpecification> specifications;
  // MethodDef-owned generic parameters are retained here so their constraint
  // identities can be refreshed when TypeRefs bind across catalogs.
  std::vector<ManagedGenericParameter> method_generic_parameters;
};
// Returns true only when `candidate` is proven assignable to `target` through
// the bounded in-module TypeDef base/interface graph. Unknown/external edges
// and unresolved TypeSpecs return false.
HEXLAB_LOADERS_EXPORT bool managed_type_is_assignable(const ManagedTypeCatalog&,std::uint32_t candidate,std::uint32_t target);
// Binds exact AssemblyRef identities through unique TypeDefs or supported
// ExportedType forwarders in the supplied catalogs. Missing, ambiguous,
// unsupported, and cyclic paths remain unbound with an unresolved_scope
// diagnostic. The operation never loads assemblies from disk.
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
