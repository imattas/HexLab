#pragma once

#include "hexlab/types/pdb.hpp"
#include "hexlab/types/types.hpp"

#include <map>
#include <string>
#include <utility>

namespace hexlab::types {

enum class PdbAggregateDeclarationKind : std::uint8_t { static_data, nested_type, method };
enum class PdbVirtualDispatchKind : std::uint8_t { non_virtual, virtual_method, introducing_virtual, pure_virtual, pure_introducing_virtual, unknown };
struct PdbAggregateDeclaration {
    std::uint8_t name_space = 0;
    std::uint32_t aggregate_type_index = 0;
    std::uint32_t declaration_ordinal = 0; // Position in flattened CodeView field-list order.
    PdbAggregateDeclarationKind kind = PdbAggregateDeclarationKind::static_data;
    std::string name;
    TypePtr type;
    std::uint16_t attributes = 0;
    PdbVirtualDispatchKind virtual_dispatch = PdbVirtualDispatchKind::non_virtual;
    MemberAccess access = MemberAccess::unknown;
    bool is_static = false;
    std::optional<std::uint32_t> introducing_vtable_offset;
    // Present for LF_MFUNCTION signatures; the ordinary Type function model
    // stores explicit arguments and calling convention, while these fields
    // retain the implicit this-pointer type and adjustment separately.
    TypePtr member_this_type;
    std::int32_t this_adjustment = 0;
    // Accepted LF_MFUNCTION option bits (C++ return-by-UDT/constructor flags).
    std::uint8_t function_options = 0;
};

struct PdbImportedVTableSlot {
    std::uint8_t owner_namespace = 0;
    std::uint32_t owner_type_index = 0;
    std::uint8_t source_namespace = 0;
    std::uint32_t source_type_index = 0;
    std::uint32_t source_record_offset = 0;
    std::uint32_t vfptr_offset = 0;
    std::uint32_t slot_index = 0;
    std::string table_name;
    std::string method_name; // Raw slot name from LF_VFTABLE.
    std::vector<std::uint32_t> matched_declaration_ordinals;
};

struct PdbTypeImportResult {
    // Keys are portable workspace storage names. For same-display-name
    // aggregates with distinct CodeView unique names, keys receive a stable
    // digest suffix while each Type retains its original display name.
    std::map<std::string, TypePtr, std::less<>> definitions;
    // Procedure and member-function signatures are kept by their exact TPI
    // namespace and index; records must not resolve them by display name.
    std::map<std::pair<std::uint8_t, std::uint32_t>, TypePtr> function_types;
    // Successfully converted TPI nodes keyed by their exact type-server
    // namespace and local type index. Simple CodeView types are resolved by
    // the data-symbol importer and do not appear in this map.
    std::map<std::pair<std::uint8_t, std::uint32_t>, TypePtr> types_by_index;
    // Static members and declarations stay outside instance layout. Keys use
    // the owning TPI namespace/index plus flattened declaration ordinal.
    std::vector<PdbAggregateDeclaration> aggregate_declarations;
    // Exact LF_VFTABLE entry order with source type-record provenance. Method
    // slots are also copied into a uniquely named declaration's Type metadata
    // where possible, while unmatched/inherited names stay visible here.
    std::vector<PdbImportedVTableSlot> vtable_slots;
    std::size_t skipped_unnamed = 0;
    std::size_t skipped_unsupported = 0;
    std::size_t skipped_duplicates = 0;
    std::size_t skipped_ambiguous = 0;
};

struct PdbImportedDataSymbol {
    PdbSymbol symbol;
    TypePtr type;
    bool resolved = false;
    std::string diagnostic;
};
struct PdbDataSymbolImportResult {
    // Data-symbol order and duplicate module/global rows are preserved so
    // callers can retain original DBI/global-stream provenance.
    std::vector<PdbImportedDataSymbol> symbols;
    std::size_t unresolved = 0;
    std::size_t unsupported = 0;
};

struct PdbImportedFunctionId {
    std::uint32_t index = 0;
    std::uint16_t leaf = 0;
    CodeViewIdKind kind = CodeViewIdKind::unsupported;
    std::uint32_t parent_scope = 0;
    std::uint32_t class_type = 0;
    std::uint32_t function_type = 0;
    std::string name;
    std::uint32_t record_offset = 0, record_size = 0;
    TypePtr signature;
    // A false value keeps the parsed record visible while explaining why it
    // could not be joined to a usable TPI function or scope.
    bool resolved = false;
    std::string diagnostic;
};
struct PdbFunctionIdImportResult {
    std::vector<PdbImportedFunctionId> records;
    std::size_t unresolved = 0;
    std::size_t unsupported = 0;
};

// Converts the bounded CodeView graph subset that maps directly to the
// immutable project type model. Named types with unsupported dependencies are
// skipped, including references into an unavailable external TPI namespace;
// malformed or unresolved references within the source TPI fail the import.
HEXLAB_TYPES_EXPORT Result<PdbTypeImportResult> import_pdb_type_graph(const PdbTypeGraph &graph);
// Joins IPI function IDs to exact TPI function records and signatures. Missing
// or mismatched references are retained as unresolved records with diagnostics.
HEXLAB_TYPES_EXPORT Result<PdbFunctionIdImportResult> import_pdb_function_ids(
    const PdbIdStream &ids, const PdbTypeStream &types, const PdbTypeImportResult &imported);
// Joins parsed CodeView data-symbol rows to exact converted TPI records. It
// does not pair by displayed name; unresolved or unsupported TPI references
// remain visible with a per-row diagnostic.
HEXLAB_TYPES_EXPORT Result<PdbDataSymbolImportResult> import_pdb_data_symbols(
    const PdbSymbolTable &symbols, const PdbTypeImportResult &imported);

} // namespace hexlab::types
