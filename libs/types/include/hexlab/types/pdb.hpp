#pragma once
#include "hexlab/core/result.hpp"
#include "hexlab/types/types_export.hpp"
#include <array>
#include <cstddef>
#include <cstdint>
#include <functional>
#include <map>
#include <optional>
#include <span>
#include <stop_token>
#include <string>
#include <utility>
#include <vector>

namespace hexlab::types {

struct PdbInfo {
    std::uint32_t version = 0;
    std::uint32_t signature = 0;
    std::uint32_t age = 0;
    std::array<std::byte, 16> guid{};
};

struct PdbDatabase {
    std::uint32_t block_size = 0;
    std::vector<std::optional<std::vector<std::byte>>> streams;
    PdbInfo info;
    std::map<std::string, std::uint32_t> named_streams;
};

enum class CodeViewTypeKind : std::uint8_t { primitive, pointer, array, structure, class_type, union_type, enumeration, field_list, typedef_type, modifier, bitfield, type_server, unsupported, procedure, argument_list, method_list, member_function, vftable_shape, vftable };
struct CodeViewField { std::uint16_t leaf = 0; std::uint32_t type = 0; std::uint16_t attributes = 0; std::uint64_t offset = 0; std::string name; std::uint64_t value = 0; std::uint32_t auxiliary_type = 0; };
struct CodeViewTypeRecord {
    std::uint32_t index = 0;
    std::uint16_t leaf = 0;
    CodeViewTypeKind kind = CodeViewTypeKind::unsupported;
    std::uint32_t record_offset = 0; // Byte offset in the source TPI stream.
    std::uint32_t record_size = 0;   // Includes length, leaf, payload, and padding.
    std::uint32_t referenced_type = 0;
    std::uint32_t field_list = 0;
    std::uint32_t derivation_list = 0;
    std::uint32_t vtable_shape = 0;
    std::uint32_t underlying_type = 0;
    std::uint64_t size = 0; // Aggregate/array extent or LF_POINTER byte size.
    std::uint8_t pointer_kind = 0; // CodeView CV_ptrtype_e value.
    std::uint8_t pointer_mode = 0; // CodeView CV_ptrmode_e value.
    std::uint32_t pointer_options = 0; // CodeView pointer modifiers and flags.
    std::uint8_t qualifier_bits = 0; // Qualifier bit values from types::Qualifier.
    std::uint8_t bitfield_width = 0; // LF_BITFIELD length in bits.
    std::uint8_t bitfield_position = 0; // LSB-relative position in the underlying storage type.
    std::uint8_t calling_convention = 0; // CV_call_e value for LF_PROCEDURE/LF_MFUNCTION.
    std::uint8_t function_options = 0; // Function option flags for procedure/member-function records.
    std::uint32_t member_class_type = 0; // LF_MFUNCTION containing class type index.
    std::uint32_t member_this_type = 0; // LF_MFUNCTION implicit this pointer type index.
    std::uint32_t vftable_complete_class_type = 0;
    std::uint32_t vftable_overridden_type = 0;
    std::uint32_t vftable_vfptr_offset = 0;
    std::vector<std::uint8_t> vftable_slot_kinds; // Four-bit CV_VTS_desc values expanded to bytes.
    std::vector<std::string> vftable_names; // LF_VFTABLE: table name followed by ordered slot names.
    std::int32_t this_adjustment = 0; // LF_MFUNCTION signed this-pointer adjustment.
    std::uint16_t parameter_count = 0;
    std::string name;
    // CodeView's ODR-qualified name (present when the unique-name property is set).
    // Used for forward resolution and import collision checks; displayed names remain stable.
    std::string unique_name;
    std::array<std::byte, 16> type_server_guid{};
    std::uint32_t type_server_age = 0;
    std::vector<CodeViewField> fields;
    std::vector<std::uint32_t> field_list_continuations;
    bool forward_declaration = false;
};
struct PdbTypeStream { std::uint32_t type_index_begin = 0; std::uint32_t type_index_end = 0; std::vector<CodeViewTypeRecord> records; };

// IPI records use a separate type-index namespace from TPI. Recognized
// compiler-generated IDs decode their references; other leaves retain extent.
enum class CodeViewIdKind : std::uint8_t { function, member_function, build_info, substring_list, string_id, udt_source_line, udt_module_source_line, unsupported };
struct CodeViewIdRecord {
    std::uint32_t index = 0;
    std::uint16_t leaf = 0;
    CodeViewIdKind kind = CodeViewIdKind::unsupported;
    std::uint32_t parent_scope = 0; // LF_FUNC_ID parent ID; zero means global scope.
    std::uint32_t class_type = 0;   // LF_MFUNC_ID owner in the TPI namespace.
    std::uint32_t function_type = 0; // LF_PROCEDURE or LF_MFUNCTION in TPI.
    std::uint32_t parent_string_id = 0; // LF_STRING_ID parent list, in IPI.
    std::uint32_t related_type = 0; // UDT type index in TPI for source-line records.
    std::uint32_t source_file_id = 0; // LF_UDT_SRC_LINE source LF_STRING_ID.
    std::uint32_t line_number = 0;
    std::uint16_t module_index = 0;
    std::vector<std::uint32_t> references; // Build-info IDs or substring-list IDs.
    std::string name;
    std::uint32_t record_offset = 0; // Byte offset within IPI stream 4.
    std::uint32_t record_size = 0;   // Includes length, leaf, payload, and padding.
};
struct PdbIdStream {
    std::uint32_t type_index_begin = 0;
    std::uint32_t type_index_end = 0;
    std::vector<CodeViewIdRecord> records;
};

enum class PdbTypeReferenceKind : std::uint8_t { pointee, array_element, array_index, member, enum_underlying, typedef_target, qualifier_base, field_list, field_list_continuation, bitfield_underlying, nested_type, base_class, virtual_base_class, virtual_base_pointer_type, function_result, function_argument_list, argument_type, method_type, method_list, member_function_class, member_function_this, class_vtable_shape, vftable_complete_class, vftable_overridden_table, class_derivation_list, vftable_pointer_type };
struct PdbTypeReference {
    std::uint32_t source_index = 0, target_index = 0;
    PdbTypeReferenceKind kind = PdbTypeReferenceKind::member;
    bool primitive = false; // Simple CodeView types are encoded inline below 0x1000.
    bool resolved = false;  // Complex references resolve within the recorded target namespace.
    std::uint8_t source_namespace = 0, target_namespace = 0;
    bool target_namespace_mapped = true; // False when a nested TSM selector has no owning namespace.
};
struct PdbTypeGraphNode {
    CodeViewTypeRecord record;
    std::uint32_t canonical_index = 0; // Forward declarations point at a matching full definition.
    std::vector<CodeViewField> expanded_fields; // Field-list continuations flattened with cycle/size limits.
    std::uint8_t name_space = 0; // Type-server map index; zero is this PDB's TPI.
};
struct PdbTypeGraph {
    std::vector<PdbTypeGraphNode> nodes;
    std::vector<PdbTypeReference> references;
};

struct PdbTypeServerRequest {
    std::array<std::byte, 16> guid{};
    std::uint32_t age = 0;
    std::string path;
    std::uint32_t signature = 0; // DBI TSM uses the legacy 32-bit PDB signature.
};
using PdbTypeServerResolver = std::function<Result<PdbDatabase>(const PdbTypeServerRequest &)>;
struct PdbTypeServerMapEntry {
    std::uint8_t index = 0;
    std::uint32_t type_base = 0; // TSM::tiBase; selector is the entry's stream ordinal.
    std::uint32_t signature = 0, age = 0;
    std::string name, path;
};
struct PdbTypeServerNamespace {
    PdbTypeServerRequest request;
    PdbDatabase database;
    PdbTypeStream types;
    std::uint8_t index = 0; // Global namespace selector in the combined graph.
    // For a server PDB's own DBI map, translate its local TSM selectors into
    // the flattened selector space. Selector zero always identifies this TPI.
    std::vector<std::pair<std::uint8_t, std::uint8_t>> namespace_map;
};
struct PdbTypeServerSet {
    std::vector<PdbTypeServerNamespace> namespaces;
    // If populated, this maps the root PDB's DBI TSM selectors into the
    // combined namespace graph and prevents invalid selectors from aliasing
    // flattened nested namespaces.
    std::vector<std::pair<std::uint8_t, std::uint8_t>> root_namespace_map;
};

// A symbol address is retained as an image section number plus section offset;
// it is not an RVA until matched to the corresponding PE section table.
enum class PdbSymbolKind : std::uint8_t { procedure, data };
enum class PdbSymbolSource : std::uint8_t { module, global_stream };
struct PdbSymbol {
    PdbSymbolKind kind = PdbSymbolKind::data;
    PdbSymbolSource source = PdbSymbolSource::module;
    bool public_symbol = false;
    std::string name;
    std::uint16_t section = 0;
    std::uint32_t section_offset = 0;
    std::uint32_t size = 0; // Procedure extent; zero when unavailable for data.
    std::string module_name;
    std::string object_name;
    std::uint16_t module_index = 0;
    std::uint16_t record_kind = 0;
    std::uint32_t record_offset = 0; // Offset in the module symbol substream when module_index is known.
    // Global S_PROCREF/S_LPROCREF/S_DATAREF rows retain the identity of both
    // records: record_kind/record_offset identify the resolved module record,
    // while these fields identify the referring record in SymRecordStream.
    std::uint16_t reference_record_kind = 0;
    std::uint32_t reference_record_offset = 0;
    std::uint32_t type_index = 0; // CodeView procedure type index, when present.
    // S_*PROC32_ID stores a CodeView IPI index here instead of a TPI index.
    bool type_index_is_id = false;
    // Optional S_FRAMEPROC metadata attached to the immediately owning procedure.
    std::uint32_t frame_size = 0, frame_padding_size = 0, frame_padding_offset = 0;
    std::uint32_t callee_saved_register_bytes = 0, exception_handler_offset = 0;
    std::uint16_t exception_handler_section = 0;
    std::uint32_t frame_flags = 0;
    bool has_frame_data = false;
};
struct PdbSymbolTable { std::vector<PdbSymbol> symbols; };

enum class PdbLocalLocationKind : std::uint8_t { unknown, frame_relative, register_relative, register_value };
struct PdbLocalRangeGap { std::uint16_t offset = 0, size = 0; };
struct PdbLocalLiveRange {
    PdbLocalLocationKind location_kind = PdbLocalLocationKind::unknown;
    std::int32_t frame_offset = 0;
    std::uint16_t register_id = 0, section = 0;
    // CodeView can describe a field of an aggregate local independently of
    // the parent value. This is a byte offset, limited by the on-disk 12-bit
    // OffsetInParent field where that field is present.
    std::uint16_t offset_in_parent = 0;
    // Register-relative indirect ranges dereference register + frame_offset,
    // then add this byte offset within the pointed-to object.
    std::int32_t offset_in_udt = 0;
    bool spilled_udt_member = false;
    bool indirect = false;
    bool subfield_register = false;
    bool may_have_no_name = false;
    std::uint32_t section_offset = 0;
    std::uint32_t size = 0;
    std::vector<PdbLocalRangeGap> gaps;
};
struct PdbLocalSymbol {
    std::string name, procedure_name, module_name, object_name;
    std::uint32_t type_index = 0;
    bool parameter = false;
    // Present when the local is nested under an S_INLINESITE record. The ID
    // is an IPI index (not a TPI type index); the offset identifies the exact
    // inline-site symbol record within its module stream.
    std::optional<std::uint32_t> inlinee_id;
    std::optional<std::uint32_t> inline_site_record_offset;
    PdbLocalLocationKind location_kind = PdbLocalLocationKind::unknown;
    std::int32_t frame_offset = 0;
    std::uint16_t register_id = 0;
    std::uint16_t procedure_section = 0;
    std::uint32_t procedure_section_offset = 0, procedure_size = 0;
    // Nearest enclosing S_BLOCK32 lexical scope. Procedure-level locals leave
    // has_lexical_scope false; scope extents remain section-relative.
    bool has_lexical_scope = false;
    std::uint16_t lexical_scope_section = 0;
    std::uint32_t lexical_scope_offset = 0, lexical_scope_size = 0;
    std::uint16_t module_index = 0, record_kind = 0;
    std::uint32_t record_offset = 0;
    std::vector<PdbLocalLiveRange> live_ranges;
};
struct PdbInlineRange {
    std::uint32_t code_offset = 0, size = 0; // Relative to the outer procedure.
    std::int64_t line_delta = 0;
    std::optional<std::uint32_t> source_file_id;
};
struct PdbInlineSite {
    std::uint16_t module_index = 0, procedure_section = 0;
    std::uint32_t record_offset = 0, inlinee_id = 0;
    std::uint32_t procedure_offset = 0, procedure_size = 0;
    std::optional<std::uint32_t> parent_record_offset;
    std::uint32_t depth = 0;
    std::string procedure_name;
    // Only explicit code-length annotations produce ranges. An unsupported
    // opcode invalidates all ranges for this site, without hiding its identity.
    std::optional<std::uint32_t> unsupported_opcode;
    std::uint32_t annotation_offset = 0;
    std::vector<PdbInlineRange> ranges;
};
struct PdbLocalTable {
    std::vector<PdbLocalSymbol> locals;
    std::vector<PdbInlineSite> inline_sites;
};

// A C13 line address is a module-relative section number and offset. It is not
// an RVA until the matching PE section table is applied.
struct PdbSourceLine {
    std::string source_path;
    std::uint32_t source_file_id = 0; // Offset of the checksum record in C13 FileChecksums.
    std::uint8_t checksum_kind = 0;
    std::vector<std::byte> checksum;
    std::uint16_t section = 0;
    std::uint32_t reloc_offset = 0; // Start of the C13 section contribution.
    std::uint32_t section_offset = 0;
    std::uint32_t contribution_size = 0;
    std::uint32_t block_size = 0;
    std::uint32_t line = 0;
    std::uint32_t end_line = 0;
    std::uint16_t start_column = 0;
    std::uint16_t end_column = 0;
    bool has_columns = false;
    bool is_statement = false;
    bool end_sequence = false; // C13 line rows do not encode DWARF-style end-sequence markers.
    std::string module_name;
    std::string object_name;
    std::uint16_t module_index = 0;
    std::uint32_t subsection_offset = 0; // Absolute byte offset of the C13 lines subsection in its module stream.
};
struct PdbInlineeLine {
    std::uint16_t module_index = 0;
    std::uint32_t inlinee_id = 0, source_file_id = 0, line = 0;
};
struct PdbSourceFile {
    std::uint16_t module_index = 0;
    std::uint32_t source_file_id = 0;
    std::string path;
};
struct PdbSourceLineTable {
    std::vector<PdbSourceLine> lines;
    std::vector<PdbInlineeLine> inlinees;
    std::vector<PdbSourceFile> files;
    // Unknown InlineeLines signatures are retained per module and not decoded.
    std::vector<std::pair<std::uint16_t, std::uint32_t>> unsupported_inlinee_signatures;
};

// Reads the bounded MSF 7.0 container and its PDB information stream. Stream 1
// supplies the database GUID and age used to match PE CodeView records.
HEXLAB_TYPES_EXPORT Result<PdbDatabase> parse_pdb(std::span<const std::byte> file,
                                                  std::stop_token stop = {});
// Decodes a bounded useful subset of TPI CodeView records. Unknown leaf kinds
// remain present as explicit `unsupported` records with their original leaf id.
HEXLAB_TYPES_EXPORT Result<PdbTypeStream> parse_pdb_types(const PdbDatabase &database,
                                                          std::stop_token stop = {});
// Parses the bounded CodeView IPI stream (MSF stream 4). LF_FUNC_ID and
// LF_MFUNC_ID references remain indices until joined with parsed TPI data.
// Other ID leaves retain their leaf ID and original record byte extent.
HEXLAB_TYPES_EXPORT Result<PdbIdStream> parse_pdb_ids(const PdbDatabase &database,
                                                     std::stop_token stop = {});
// Resolve LF_TYPESERVER2 through a caller supplied bounded resolver. Each returned TPI remains a separate index namespace; exact GUID+age is required. Nested server chains are followed with cycle and count bounds.
HEXLAB_TYPES_EXPORT Result<PdbTypeServerSet> resolve_pdb_type_servers(const PdbDatabase &, const PdbTypeServerResolver &, std::size_t max_servers = 64, std::stop_token stop = {});
// Parse and resolve the bounded DBI Type Server Map. Namespace selectors are
// entry ordinals (zero is this PDB's TPI); TSM::tiBase is retained separately.
// Nonzero entries are checked against the server PDB signature and age. Nested
// maps are flattened, with each PDB's local selectors retained for graph import.
HEXLAB_TYPES_EXPORT Result<std::vector<PdbTypeServerMapEntry>> parse_pdb_type_server_map(const PdbDatabase &, std::stop_token stop = {});
HEXLAB_TYPES_EXPORT Result<PdbTypeServerSet> resolve_pdb_type_server_map(const PdbDatabase &, const PdbTypeServerResolver &, std::size_t max_servers = 64, std::stop_token stop = {});
// Resolves TPI record references without recursive expansion. Cyclic pointer/member
// graphs are represented as edges; malformed or absent targets remain unresolved.
HEXLAB_TYPES_EXPORT Result<PdbTypeGraph> resolve_pdb_type_graph(const PdbTypeStream &stream,
                                                               std::stop_token stop = {});
// Combines root and resolved DBI type-server TPI namespaces while preserving
// high-byte TypeServerMap selectors on cross-namespace references.
HEXLAB_TYPES_EXPORT Result<PdbTypeGraph> resolve_pdb_type_graph(const PdbTypeStream &stream,
                                                               const PdbTypeServerSet &servers,
                                                               std::stop_token stop = {});
// Imports bounded DBI module and symbol-record-stream procedure/data/public
// records. Unknown CodeView records are skipped by their validated record length.
// Addresses remain section-relative.
HEXLAB_TYPES_EXPORT Result<PdbSymbolTable> parse_pdb_symbols(const PdbDatabase &database,
                                                             std::stop_token stop = {});
// Imports bounded lexical local/parameter records and selected CodeView defranges
// (register, frame-pointer-relative, register-relative, register subfield, and
// register-relative-indirect) from DBI module streams. Parent-member offsets,
// spilled-member and conditional-name metadata are retained. Ranges remain
// section-relative and are not converted to PE RVAs. Locals nested in S_BLOCK32
// retain the nearest lexical block's section-relative start and extent. DIA-
// program defranges are not interpreted. Inline scopes also retain bounded
// explicit-length annotation ranges relative to the outer procedure.
HEXLAB_TYPES_EXPORT Result<PdbLocalTable> parse_pdb_locals(const PdbDatabase &database,
                                                          std::stop_token stop = {});
// Imports bounded C13 string, checksum, line and InlineeLines subsections from DBI module streams.
// Source addresses remain section-relative; no RVA conversion is performed.
HEXLAB_TYPES_EXPORT Result<PdbSourceLineTable> parse_pdb_source_lines(const PdbDatabase &database,
                                                                      std::stop_token stop = {});

} // namespace hexlab::types
