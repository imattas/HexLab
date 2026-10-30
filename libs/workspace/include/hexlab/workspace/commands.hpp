#pragma once
#include "hexlab/database/transaction.hpp"
#include "hexlab/workspace/workspace_export.hpp"
#include <stop_token>
namespace hexlab {
struct Rename {Location location;std::string name;};
struct Comment {Location location;std::string text;};
struct BookmarkCommand {Location location;std::string label;bool remove=false;};
struct SetProjectBreakpoint {
    Address address;
    database::ProjectBreakpointKind kind=database::ProjectBreakpointKind::software;
    std::uint8_t size=1;
    bool enabled=true;
    bool remove=false;
    std::string condition;
    bool logpoint=false;
    std::string log_message;
    std::uint64_t ignore_count=0;
    bool one_shot=false;
};
struct DefineRegion {Address begin;std::uint64_t size;RegionKind kind;};
struct DefineFunction {Address entry;};
struct SetFunctionChunks {Address entry;std::vector<DecisionRange> chunks;};
struct SuppressFunction {Address entry;bool suppressed=true;};
struct ResetFunctionOverride {Address entry;};
struct SetReference {Location source,target;UserReferenceKind kind;bool remove=false;};
struct PatchBytes {Location location;std::vector<std::byte> replacement;};
struct DefineType {std::string name;types::TypePtr type;};
struct UpdateType {std::uint64_t type_id;std::string name;types::TypePtr type;};
struct AssignType {Address location;std::uint64_t type_id;bool remove=false;};
// Apply one logical stack-local edit to every recovered access site in a single
// project history step. The rows remain address keyed for compatibility.
struct RenameStackLocal {std::vector<Address> access_sites;std::string expected_name;std::string name;};
struct AssignStackLocalType {
    std::vector<Address> access_sites;std::optional<std::uint64_t> expected_type_id;
    std::uint64_t type_id=0;bool remove=false;
};
struct PortableTypeDefinition {
    std::string name;types::TypePtr type;std::optional<std::uint64_t> existing_id;
    std::optional<database::DwarfSourceOrigin> origin;
    database::DeclarationKind declaration_kind=database::DeclarationKind::type;
    // Snapshot-planned replacements provide the complete before-row. Empty keeps
    // the legacy explicit replacement contract, guarded by name/entity identity.
    std::optional<database::TypeDefinition> expected_existing;
};
struct PortableTypeAssignment {Location location;std::string type_name;};
struct ImportPortableTypes {std::vector<PortableTypeDefinition> definitions;std::vector<PortableTypeAssignment> assignments;};
struct PortableDebugVariable {
    Address function_entry{};
    std::string name;
    std::optional<std::string> type_name;
    bool is_parameter = false;
    std::uint64_t scope_offset = 0;
    std::optional<Address> address;
    std::vector<std::uint8_t> location_expression;
    std::vector<database::DebugLocationOperation> location_operations;
    database::DwarfSourceOrigin origin;
    std::optional<std::int64_t> cfa_offset;
    std::vector<database::DebugLocationRange> location_ranges;
    std::optional<database::DebugVariable> expected_existing;
    bool expected_absent = false;
};
struct ImportPortableDebugVariables {std::vector<PortableDebugVariable> variables;};
struct ImportSymbols {};
struct ImportDwarfInfo {};
using ProjectCommand=std::variant<Rename,Comment,BookmarkCommand,SetProjectBreakpoint,DefineRegion,DefineFunction,SetFunctionChunks,SuppressFunction,ResetFunctionOverride,SetReference,PatchBytes,DefineType,UpdateType,AssignType,RenameStackLocal,AssignStackLocalType,ImportPortableTypes,ImportPortableDebugVariables,ImportSymbols,ImportDwarfInfo>;
struct CommandAvailability {bool enabled=false;std::string reason;};
struct ProjectSnapshot;
enum class ProjectActionKind {rename,comment,bookmark,define_code,define_data,define_function,function_chunks,suppress_function,reference,patch,undo,redo,save,save_as,export_binary,search,reanalyze,define_type,assign_type,import_symbols,import_dwarf,reset_function};
// Lightweight prerequisites only: no byte reads, decoding, SQL or user-state clone.
HEXLAB_WORKSPACE_EXPORT CommandAvailability action_availability(const ProjectSnapshot*,ProjectActionKind,std::optional<Location>);
HEXLAB_WORKSPACE_EXPORT Result<database::StateDelta> validate_command(const ProjectSnapshot&,const ProjectCommand&,
                                                                       std::stop_token stop = {});
HEXLAB_WORKSPACE_EXPORT CommandAvailability command_availability(const ProjectSnapshot&,const ProjectCommand&);
}
