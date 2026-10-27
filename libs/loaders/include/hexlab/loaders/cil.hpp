#pragma once
#include "hexlab/loaders/loaders_export.hpp"
#include "hexlab/loaders/managed.hpp"
#include "hexlab/core/result.hpp"
#include <cstddef>
#include <cstdint>
#include <optional>
#include <map>
#include <memory>
#include <span>
#include <stop_token>
#include <string>
#include <variant>
#include <vector>

namespace hexlab {
enum class CilInstructionStatus { decoded, unsupported, unknown };
struct CilTokenOperand { std::uint32_t token=0; };
struct CilBranchOperand { std::int32_t displacement=0; std::uint32_t target_offset=0; };
struct CilSwitchOperand { std::vector<std::int32_t> displacements; std::vector<std::uint32_t> target_offsets; };
using CilOperand = std::variant<std::monostate,std::int8_t,std::uint8_t,std::uint16_t,std::int32_t,std::int64_t,float,double,
                                CilTokenOperand,CilBranchOperand,CilSwitchOperand,std::vector<std::byte>>;
struct CilInstruction {
    std::uint32_t offset=0;
    std::uint16_t opcode=0;
    std::uint32_t size=0;
    CilInstructionStatus status=CilInstructionStatus::unknown;
    const char* mnemonic="unknown";
    CilOperand operand;
    std::vector<std::byte> encoding;
};
// Offsets and branch targets are relative to the first IL byte, excluding the CIL method header.
// Unknown opcode bytes remain separate instructions; known unsupported opcodes retain raw/typed operands.
HEXLAB_LOADERS_EXPORT Result<std::vector<CilInstruction>> decode_cil_instructions(std::span<const std::byte> il);

struct LoadedImage;
enum class ManagedMethodStatus { decoded, no_body, unsupported, malformed };
struct ManagedMethodAnalysis {
    ManagedMethod method;
    ManagedMethodStatus status=ManagedMethodStatus::unsupported;
    std::string diagnostic;
    std::optional<CilMethodBody> body;
    std::vector<CilInstruction> instructions;
    std::map<std::uint32_t,ManagedMethodSignature> resolved_call_signatures;
    std::map<std::uint32_t,ManagedField> resolved_fields;
    std::map<std::uint32_t,std::string> resolved_exception_type_names;
    // Exact AssemblyRef identity for external TypeRefs used by catch clauses.
    // This preserves identity provenance without claiming external assignability.
    std::map<std::uint32_t,ManagedAssemblyIdentity> resolved_exception_type_assemblies;
    std::shared_ptr<const ManagedTypeCatalog> resolved_exception_types;
    std::shared_ptr<const ManagedUserStringCatalog> resolved_user_strings;
};
// Rebuilds a bounded CLR method catalog from a loaded PE on every call; results
// are derived data and need not be persisted in the project database.
HEXLAB_LOADERS_EXPORT Result<std::vector<ManagedMethodAnalysis>> inspect_managed_methods(const LoadedImage&,std::stop_token={});
HEXLAB_LOADERS_EXPORT Result<std::vector<ManagedTypeDefinition>> inspect_managed_types(const LoadedImage&);
HEXLAB_LOADERS_EXPORT Result<std::vector<ManagedField>> inspect_managed_fields(const LoadedImage&);
}
