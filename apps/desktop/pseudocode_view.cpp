#include "pseudocode_view.hpp"

#include "hexlab/decompiler/decompiler.hpp"
#include "hexlab/decompiler/type_recovery.hpp"
#include "hexlab/loaders/loaded_image.hpp"
#include "hexlab/types/types.hpp"
#include "hexlab/workspace/debug_variables.hpp"
#include "data_views.hpp"
#include "project_view.hpp"

#include <wx/sizer.h>
#include <wx/stattext.h>
#include <wx/textdlg.h>
#include <wx/clipbrd.h>
#include <wx/dataobj.h>
#include <wx/filedlg.h>
#include <wx/file.h>
#include <wx/msgdlg.h>
#include <algorithm>
#include <charconv>
#include <cctype>
#include <cstdint>
#include <map>
#include <set>
#include <sstream>
#include <type_traits>

namespace hexlab::desktop {
namespace {
std::optional<Address> selected_address(std::optional<Location> selection, const Image *image) {
    if (!selection)
        return {};
    if (const auto *address = std::get_if<Address>(&*selection))
        return *address;
    if (image) {
        auto mapped = image->to_address(std::get<FileOffset>(*selection));
        if (mapped)
            return mapped.value();
    }
    return {};
}

struct Match {
    const FunctionRecord *function = nullptr;
    Address instruction{{0}, 0};
};

wxString stack_offset(std::int64_t value) {
    if (value < 0) {
        const auto magnitude = static_cast<unsigned long long>(-(value + 1)) + 1;
        return wxString::Format("-0x%llx", magnitude);
    }
    return wxString::Format("+0x%llx", static_cast<unsigned long long>(value));
}

std::string register_token(RegisterOperand reg, std::optional<std::uint32_t> version) {
    std::string result;
    if (reg.bank == RegisterBank::flags || reg.bank == RegisterBank::arm_flags) result = "flags";
    else if (reg.bank == RegisterBank::ip) result = "ip";
    else if (reg.bank == RegisterBank::segment) result = "seg" + std::to_string(reg.index);
    else result = "r" + std::to_string(reg.index);
    if (version) result += "_" + std::to_string(*version);
    return result;
}

std::pair<std::uint32_t, std::uint64_t> address_identity(Address address) {
    return {address.space.value, address.offset};
}

bool source_identifier(std::string_view name);

void collect_stack_accesses(const decompiler::ExpressionPtr &expression,
                            std::map<std::string, std::vector<Address>> &accesses, Address at) {
    if (!expression) return;
    std::visit([&](const auto &value) {
        using T = std::decay_t<decltype(value)>;
        if constexpr (std::is_same_v<T, decompiler::MemoryValue>) {
            if (value.stack_variable) accesses[*value.stack_variable].push_back(at);
        } else if constexpr (std::is_same_v<T, decompiler::UnaryValue>) {
            collect_stack_accesses(value.operand, accesses, at);
        } else if constexpr (std::is_same_v<T, decompiler::BinaryValue>) {
            collect_stack_accesses(value.left, accesses, at);
            collect_stack_accesses(value.right, accesses, at);
        }
    }, expression->value);
}

std::map<std::string, std::vector<Address>> stack_access_sites(const decompiler::LiftedFunction &function) {
    std::map<std::string, std::vector<Address>> accesses;
    for (const auto &block : function.blocks) for (const auto &instruction : block.instructions) {
        std::visit([&](const auto &statement) {
            using T = std::decay_t<decltype(statement)>;
            if constexpr (std::is_same_v<T, decompiler::Assign>)
                collect_stack_accesses(statement.value, accesses, instruction.origin.address);
            else if constexpr (std::is_same_v<T, decompiler::Store>) {
                collect_stack_accesses(statement.address, accesses, instruction.origin.address);
                collect_stack_accesses(statement.value, accesses, instruction.origin.address);
            } else if constexpr (std::is_same_v<T, decompiler::Call>)
                collect_stack_accesses(statement.indirect_target, accesses, instruction.origin.address);
            else if constexpr (std::is_same_v<T, decompiler::Branch>)
                collect_stack_accesses(statement.predicate, accesses, instruction.origin.address);
            else if constexpr (std::is_same_v<T, decompiler::Return>)
                collect_stack_accesses(statement.value, accesses, instruction.origin.address);
            else if constexpr (std::is_same_v<T, decompiler::Intrinsic>)
                for (const auto &operand : statement.operands)
                    collect_stack_accesses(operand, accesses, instruction.origin.address);
        }, instruction.statement);
    }
    for (auto &[name, sites] : accesses) {
        (void)name;
        std::sort(sites.begin(), sites.end(), [](Address left, Address right) {
            return std::pair{left.space.value, left.offset} < std::pair{right.space.value, right.offset};
        });
        sites.erase(std::unique(sites.begin(), sites.end()), sites.end());
    }
    return accesses;
}

std::map<std::pair<std::uint32_t, std::uint64_t>, std::vector<std::string>>
global_data_access_evidence(const decompiler::LiftedFunction &function, const ProjectSnapshot *project) {
    std::map<std::pair<std::uint32_t, std::uint64_t>, std::vector<std::string>> result;
    if (!project || !project->loaded || !project->loaded->metadata.pe || !project->references ||
        !project->state || !project->state->user) return result;
    const auto &pe = *project->loaded->metadata.pe;
    std::map<std::pair<std::uint32_t, std::uint64_t>, const PePdbSymbol *> symbols;
    std::set<std::pair<std::uint32_t, std::uint64_t>> ambiguous_symbols;
    for (const auto &symbol : pe.pdb_symbols) {
        if (symbol.procedure || !symbol.address || !source_identifier(symbol.name)) continue;
        const auto key = address_identity(*symbol.address);
        if (!symbols.emplace(key, &symbol).second) ambiguous_symbols.insert(key);
    }
    for (const auto &key : ambiguous_symbols) symbols.erase(key);

    const auto inspect_memory = [&](const decompiler::ExpressionPtr &expression,
                                    std::vector<std::pair<Address, std::uint16_t>> &accesses,
                                    auto &&self) -> void {
        if (!expression) return;
        std::visit([&](const auto &value) {
            using T = std::decay_t<decltype(value)>;
            if constexpr (std::is_same_v<T, decompiler::MemoryValue>) {
                if (value.absolute && value.type.bits && value.type.bits % 8 == 0)
                    accesses.emplace_back(*value.absolute, value.type.bits);
            } else if constexpr (std::is_same_v<T, decompiler::UnaryValue>) self(value.operand, accesses, self);
            else if constexpr (std::is_same_v<T, decompiler::BinaryValue>) {
                self(value.left, accesses, self);
                self(value.right, accesses, self);
            }
        }, expression->value);
    };
    for (const auto &block : function.blocks) for (const auto &instruction : block.instructions) {
        std::vector<std::pair<Address, std::uint16_t>> accesses;
        std::visit([&](const auto &statement) {
            using T = std::decay_t<decltype(statement)>;
            if constexpr (std::is_same_v<T, decompiler::Assign>) inspect_memory(statement.value, accesses, inspect_memory);
            else if constexpr (std::is_same_v<T, decompiler::Store>) {
                // A store address is an effective-address expression, not a
                // load. Its pointer-width type must not be mistaken for the
                // width of the memory write.
                if (statement.address && statement.value && statement.value->type.bits &&
                    statement.value->type.bits % 8 == 0) {
                    if (const auto *address = std::get_if<decompiler::MemoryValue>(&statement.address->value);
                        address && address->absolute)
                        accesses.emplace_back(*address->absolute, statement.value->type.bits);
                }
                inspect_memory(statement.value, accesses, inspect_memory);
            } else if constexpr (std::is_same_v<T, decompiler::Call>) inspect_memory(statement.indirect_target, accesses, inspect_memory);
            else if constexpr (std::is_same_v<T, decompiler::Branch>) inspect_memory(statement.predicate, accesses, inspect_memory);
            else if constexpr (std::is_same_v<T, decompiler::Return>) inspect_memory(statement.value, accesses, inspect_memory);
            else if constexpr (std::is_same_v<T, decompiler::Intrinsic>)
                for (const auto &operand : statement.operands) inspect_memory(operand, accesses, inspect_memory);
        }, instruction.statement);

        std::set<std::string> proven;
        for (const auto &[target, bits] : accesses) {
            const auto key = address_identity(target);
            const auto symbol = symbols.find(key);
            if (symbol == symbols.end()) continue;
            const auto *assignment = type_assignment(*project, target);
            const auto *definition = assignment ? type_definition(*project, assignment->type_id) : nullptr;
            if (!definition || !definition->type || !definition->type->size() ||
                *definition->type->size() != bits / 8) continue;

            // PDB symbol addresses are section-mapped image addresses. Require
            // the analysis xref to independently resolve this instruction to
            // that same address before attaching the name/type.
            const auto outgoing = project->references->outgoing(Location{instruction.origin.address}, {0, 4096});
            if (!outgoing) continue;
            const bool exact_memory_reference = std::any_of(outgoing.value().rows.begin(), outgoing.value().rows.end(),
                [&](const Reference &reference) {
                    const auto *resolved = std::get_if<Location>(&reference.target);
                    const auto *address = resolved ? std::get_if<Address>(resolved) : nullptr;
                    return address && *address == target &&
                        (reference.kind == ReferenceKind::memory_read || reference.kind == ReferenceKind::memory_write ||
                         reference.kind == ReferenceKind::memory_read_write);
                });
            if (!exact_memory_reference) continue;

            const auto &pdb_symbol = *symbol->second;
            if (!pdb_symbol.type_index_is_id) {
                const auto pdb_type = std::find_if(pe.pdb_types.begin(), pe.pdb_types.end(), [&](const auto &type) {
                    return type.index == pdb_symbol.type_index;
                });
                if (pdb_type != pe.pdb_types.end()) {
                    std::string_view pdb_name = pdb_type->name;
                    for (const auto prefix : {std::string_view("class "), std::string_view("struct "),
                                              std::string_view("union "), std::string_view("enum ")})
                        if (pdb_name.starts_with(prefix)) { pdb_name.remove_prefix(prefix.size()); break; }
                    if (pdb_type->size != *definition->type->size() ||
                        (!pdb_name.empty() && definition->name != pdb_name &&
                         definition->type->name() != pdb_name)) continue;
                }
            } else {
                // IPI symbols do not identify data types in the TPI namespace.
                continue;
            }
            auto type_name = definition->type->name().empty() ? types::format(*definition->type)
                                                               : definition->type->name();
            std::replace(type_name.begin(), type_name.end(), '\r', ' ');
            std::replace(type_name.begin(), type_name.end(), '\n', ' ');
            for (std::size_t position = 0; (position = type_name.find("*/", position)) != std::string::npos; position += 3)
                type_name.replace(position, 2, "* /");
            proven.insert("global " + pdb_symbol.name + " : " + type_name);
        }
        if (!proven.empty())
            result[address_identity(instruction.origin.address)] = {proven.begin(), proven.end()};
    }
    return result;
}

std::vector<decompiler::StackLocalTypeEvidence>
stack_local_type_evidence(const decompiler::LiftedFunction &function, const ProjectSnapshot *project) {
    if (!project) return {};
    const auto sites = stack_access_sites(function);
    std::map<std::pair<std::uint32_t, std::uint64_t>, std::set<std::string>> locals_at;
    for (const auto &[name, addresses] : sites)
        for (const auto address : addresses) locals_at[{address.space.value, address.offset}].insert(name);

    std::map<std::string, decompiler::StackLocalTypeEvidence> evidence;
    for (const auto &[key, names] : locals_at) {
        const Address address{AddressSpaceId{key.first}, key.second};
        const auto *assignment = type_assignment(*project, address);
        if (!assignment) continue;
        if (names.size() != 1) {
            for (const auto &name : names) {
                auto [it, inserted] = evidence.try_emplace(name, decompiler::StackLocalTypeEvidence{name, {}, true});
                (void)it;
                (void)inserted;
            }
            continue;
        }
        const auto &name = *names.begin();
        const auto *definition = type_definition(*project, assignment->type_id);
        auto [it, inserted] = evidence.try_emplace(name, decompiler::StackLocalTypeEvidence{name, {}, false});
        if (!definition || !definition->type) {
            it->second.ambiguous = true;
            it->second.type.reset();
        } else if (inserted) {
            it->second.type = definition->type;
        } else if (!it->second.type || it->second.type->id() != definition->type->id()) {
            it->second.ambiguous = true;
            it->second.type.reset();
        }
    }
    std::vector<decompiler::StackLocalTypeEvidence> result;
    result.reserve(evidence.size());
    for (auto &[name, value] : evidence) {
        (void)name;
        result.push_back(std::move(value));
    }
    return result;
}

bool source_identifier(std::string_view name) {
    if (name.empty() || !((name.front() >= 'a' && name.front() <= 'z') ||
        (name.front() >= 'A' && name.front() <= 'Z') || name.front() == '_')) return false;
    return std::all_of(name.begin() + 1, name.end(), [](char c) {
        return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
               (c >= '0' && c <= '9') || c == '_';
    });
}

std::optional<RegisterOperand> dwarf_register_for_architecture(Architecture architecture,
                                                               std::uint64_t number) {
    if (architecture == Architecture::x86) {
        static constexpr std::uint8_t dwarf_to_internal[] = {0, 1, 2, 3, 4, 5, 6, 7};
        if (number < std::size(dwarf_to_internal))
            return RegisterOperand{RegisterBank::gpr, dwarf_to_internal[number], 32, false};
    } else if (architecture == Architecture::x86_64) {
        // DWARF x86-64 orders RDX/RCX and RSI/RDI differently from HexLab's
        // normalized x86 register indices.
        static constexpr std::uint8_t dwarf_to_internal[] = {
            0, 2, 1, 3, 6, 7, 5, 4, 8, 9, 10, 11, 12, 13, 14, 15
        };
        if (number < std::size(dwarf_to_internal))
            return RegisterOperand{RegisterBank::gpr, dwarf_to_internal[number], 64, false};
    } else if (architecture == Architecture::arm) {
        if (number <= 15) return RegisterOperand{RegisterBank::arm32_gpr, static_cast<std::uint8_t>(number), 32, false};
    } else if (architecture == Architecture::arm64) {
        if (number <= 30) return RegisterOperand{RegisterBank::arm64_gpr, static_cast<std::uint8_t>(number), 64, false};
        if (number == 31) return RegisterOperand{RegisterBank::arm64_sp, 0, 64, false};
    } else if (architecture == Architecture::riscv32 || architecture == Architecture::riscv64) {
        if (number <= 31) return RegisterOperand{RegisterBank::riscv_gpr, static_cast<std::uint8_t>(number),
            static_cast<std::uint16_t>(architecture == Architecture::riscv32 ? 32 : 64), false};
    } else if (architecture == Architecture::mips32 || architecture == Architecture::mips64) {
        if (number <= 31) return RegisterOperand{RegisterBank::mips_gpr, static_cast<std::uint8_t>(number),
            static_cast<std::uint16_t>(architecture == Architecture::mips32 ? 32 : 64), false};
    }
    return {};
}

const std::vector<database::DebugLocationOperation> *debug_operations_at(
    const database::DebugVariable &variable, std::uint64_t pc) {
    if (variable.location_ranges.empty()) return &variable.location_operations;
    const database::DebugLocationRange *fallback = nullptr;
    for (const auto &range : variable.location_ranges) {
        if (range.begin == UINT64_MAX && range.end == UINT64_MAX) {
            if (!fallback) fallback = &range;
        } else if (range.begin <= pc && pc < range.end) {
            return &range.operations;
        }
    }
    return fallback ? &fallback->operations : nullptr;
}

std::optional<std::int32_t> dwarf_frame_slot_offset(const database::DebugVariable &variable,
                                                    std::uint64_t pc,
                                                    Architecture architecture,
                                                    RegisterOperand frame_register) {
    const auto *operations = debug_operations_at(variable, pc);
    if (!operations || operations->size() != 1) return {};
    const auto &operation = operations->front();
    if (operation.kind != static_cast<std::uint8_t>(symbols::LocationOperationKind::base_register_plus_offset)) return {};
    const auto mapped = dwarf_register_for_architecture(architecture, operation.unsigned_operand);
    if (!mapped || *mapped != frame_register ||
        operation.signed_operand < std::numeric_limits<std::int32_t>::min() ||
        operation.signed_operand > std::numeric_limits<std::int32_t>::max()) return {};
    return static_cast<std::int32_t>(operation.signed_operand);
}

std::optional<RegisterOperand> pdb_frame_register(Architecture architecture) {
    switch (architecture) {
    case Architecture::x86: return RegisterOperand{RegisterBank::gpr, 5, 32, false};
    case Architecture::x86_64: return RegisterOperand{RegisterBank::gpr, 5, 64, false};
    case Architecture::arm: return RegisterOperand{RegisterBank::arm32_gpr, 11, 32, false};
    case Architecture::arm64: return RegisterOperand{RegisterBank::arm64_gpr, 29, 64, false};
    default: return {};
    }
}

std::optional<std::pair<PePdbLocalLocationKind, std::uint16_t>> pdb_local_location_at(
    const PePdbLocal &local, Address function_entry) {
    if (!local.procedure_address || *local.procedure_address != function_entry) return {};
    if (local.live_ranges.empty()) return std::pair{local.location_kind, local.register_id};
    const PePdbLocalLiveRange *active = nullptr;
    for (const auto &range : local.live_ranges) {
        if (range.section != local.procedure_section ||
            local.procedure_section_offset < range.section_offset ||
            std::uint64_t{local.procedure_section_offset} - range.section_offset >= range.size) continue;
        const auto relative = std::uint64_t{local.procedure_section_offset} - range.section_offset;
        const bool in_gap = std::any_of(range.gaps.begin(), range.gaps.end(), [&](const auto &gap) {
            return relative >= gap.offset && relative - gap.offset < gap.size;
        });
        if (in_gap) continue;
        if (active) return {};
        active = &range;
    }
    if (!active || active->indirect || active->subfield_register || active->spilled_udt_member ||
        active->may_have_no_name) return {};
    return std::pair{active->location_kind, active->register_id};
}

std::optional<RegisterOperand> pdb_register_for_architecture(Architecture architecture,
                                                             std::uint16_t cv_register) {
    std::optional<std::uint64_t> dwarf_number;
    if (architecture == Architecture::x86_64) {
        static constexpr std::uint8_t cv_to_dwarf[] = {0, 3, 2, 1, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15};
        if (cv_register >= 328 && cv_register <= 343) dwarf_number = cv_to_dwarf[cv_register - 328];
    } else if (architecture == Architecture::x86) {
        static constexpr std::uint16_t cv_to_dwarf[] = {17, 18, 19, 20, 21, 22, 23, 24};
        const auto found = std::find(std::begin(cv_to_dwarf), std::end(cv_to_dwarf), cv_register);
        if (found != std::end(cv_to_dwarf)) dwarf_number = static_cast<std::uint64_t>(found - std::begin(cv_to_dwarf));
    }
    return dwarf_number ? dwarf_register_for_architecture(architecture, *dwarf_number) : std::nullopt;
}

bool identifier_char(char value);

std::map<std::size_t, std::string> imported_parameter_names(
    const FunctionRecord &owner, const ProjectSnapshot *project,
    Architecture architecture, const decompiler::AbiDescription &abi,
    const types::TypePtr &prototype) {
    std::map<std::size_t, std::set<std::string, std::less<>>> candidates;
    if (!project || !project->state || !project->state->user) return {};
    const auto offer = [&](RegisterOperand reg, std::string_view name) {
        if (!source_identifier(name)) return;
        for (const auto &slot : abi.arguments)
            if (slot.reg && *slot.reg == reg && slot.parameter_index)
                candidates[*slot.parameter_index].insert(std::string(name));
    };
    for (const auto *variable : debug_variables_at(*project, owner.entry, owner.entry.offset)) {
        if (!variable->is_parameter) continue;
        const auto *operations = debug_operations_at(*variable, owner.entry.offset);
        if (!operations || operations->size() != 1) continue;
        const auto &operation = operations->front();
        if (operation.kind != static_cast<std::uint8_t>(symbols::LocationOperationKind::register_location)) continue;
        const auto reg = dwarf_register_for_architecture(architecture, operation.unsigned_operand);
        if (reg) offer(*reg, variable->name);
    }
    if (project->loaded && project->loaded->metadata.pe) {
        const auto &pe = *project->loaded->metadata.pe;
        if (pe.pdb_locals.size() > 100'000) return {};
        for (const auto &variable : pe.pdb_locals) {
            if (!variable.parameter) continue;
            const auto location = pdb_local_location_at(variable, owner.entry);
            if (!location || location->first != PePdbLocalLocationKind::register_value) continue;
            const auto reg = pdb_register_for_architecture(architecture, location->second);
            if (reg) offer(*reg, variable.name);
        }
    }
    std::set<std::string, std::less<>> all_names;
    for (const auto &[index, names] : candidates) {
        (void)index;
        if (names.size() == 1) all_names.insert(*names.begin());
    }
    std::map<std::size_t, std::string> result;
    for (const auto &[index, names] : candidates) {
        if (names.size() != 1) continue;
        const auto &name = *names.begin();
        if (all_names.count(name) != 1) continue;
        if (prototype && prototype->kind() == types::Kind::function &&
            index < prototype->parameters().size() &&
            prototype->parameters()[index].name != "arg" + std::to_string(index)) continue;
        result.emplace(index, name);
    }
    return result;
}

void render_parameter_names(std::string &rendered,
                            const std::map<std::size_t, std::string> &names) {
    for (const auto &[index, name] : names) {
        const auto body = rendered.find("{\n");
        if (body == std::string::npos) return;
        const auto token = "arg" + std::to_string(index);
        std::size_t position = 0;
        while ((position = rendered.find(token, position)) != std::string::npos && position < body) {
            const auto end = position + token.size();
            if ((position && identifier_char(rendered[position - 1])) ||
                (end < body && identifier_char(rendered[end]))) { position = end; continue; }
            rendered.replace(position, token.size(), name);
            position += name.size();
        }
    }
}

std::optional<std::int32_t> pdb_frame_slot_offset(const ImageMetadata &metadata,
                                                  const PePdbLocal &local,
                                                  Address pc) {
    if (!local.procedure_address || local.procedure_address->space != pc.space ||
        pc.offset < local.procedure_address->offset || !local.procedure_size ||
        pc.offset - local.procedure_address->offset >= local.procedure_size) return {};
    std::uint64_t section_offset = local.procedure_section_offset +
        (pc.offset - local.procedure_address->offset);
    PePdbLocalLocationKind kind = local.location_kind;
    std::int32_t frame_offset = local.frame_offset;
    if (!local.live_ranges.empty()) {
        const PePdbLocalLiveRange *active = nullptr;
        for (const auto &range : local.live_ranges) {
            if (range.section != local.procedure_section || section_offset < range.section_offset ||
                section_offset - range.section_offset >= range.size) continue;
            const auto relative = section_offset - range.section_offset;
            const bool in_gap = std::any_of(range.gaps.begin(), range.gaps.end(), [&](const auto &gap) {
                return relative >= gap.offset && relative - gap.offset < gap.size;
            });
            if (in_gap) continue;
            if (active) return {};
            active = &range;
        }
        if (!active) return {};
        kind = active->location_kind;
        frame_offset = active->frame_offset;
        if (active->spilled_udt_member || active->indirect || active->subfield_register ||
            active->may_have_no_name) return {};
    }
    if (kind != PePdbLocalLocationKind::frame_relative) return {};
    (void)metadata;
    return frame_offset;
}

types::TypePtr imported_pdb_local_type(const ProjectSnapshot *project, const PeMetadata &pe,
                                       std::uint32_t type_index) {
    if (!project || !project->state || !project->state->user) return {};
    const auto source = std::find_if(pe.pdb_types.begin(), pe.pdb_types.end(),
        [&](const auto &type) { return type.index == type_index && !type.name.empty() && type.size; });
    if (source == pe.pdb_types.end()) return {};
    std::string_view name = source->name;
    for (const auto prefix : {std::string_view("class "), std::string_view("struct "),
                              std::string_view("union "), std::string_view("enum ")})
        if (name.starts_with(prefix)) { name.remove_prefix(prefix.size()); break; }
    types::TypePtr match;
    for (const auto &definition : project->state->user->types) {
        if (!definition.type || !definition.type->size() || *definition.type->size() != source->size ||
            (definition.name != name && definition.type->name() != name)) continue;
        if (match && match->id() != definition.type->id()) return {};
        match = definition.type;
    }
    return match;
}

struct ImportedStackVariableEvidence {
    std::map<std::string, std::string, std::less<>> names;
    std::vector<decompiler::StackLocalTypeEvidence> types;
};

ImportedStackVariableEvidence imported_stack_variable_evidence(
    const decompiler::LiftedFunction &function, const FunctionRecord &owner,
    const ProjectSnapshot *project, Architecture architecture,
    std::span<const decompiler::RecoveredStackVariable> stack_variables) {
    ImportedStackVariableEvidence result;
    if (!project || !project->state || !project->state->user) return result;
    struct Candidate { std::string name; types::TypePtr type; };
    std::map<std::string, std::vector<Candidate>, std::less<>> candidates;
    const auto accesses = stack_access_sites(function);
    const auto frame = pdb_frame_register(architecture);
    const PeMetadata *pe = project->loaded && project->loaded->metadata.pe
        ? &*project->loaded->metadata.pe : nullptr;
    std::vector<const database::DebugVariable *> dwarf_variables;
    constexpr std::size_t max_debug_variables = 100'000;
    constexpr std::size_t max_variable_mapping_work = 2'000'000;
    if (project->state->user->debug_variables.size() > max_debug_variables ||
        (pe && pe->pdb_locals.size() > max_debug_variables)) return result;
    for (const auto &variable : project->state->user->debug_variables)
        if (variable.function_entry == owner.entry && variable.location_ranges.size() <= 4096)
            dwarf_variables.push_back(&variable);
    std::size_t mapping_work = 0;
    const auto active_at = [](const database::DebugVariable &variable, std::uint64_t pc) {
        if (variable.location_ranges.empty()) return true;
        bool has_default = false;
        for (const auto &range : variable.location_ranges) {
            if (range.begin == UINT64_MAX && range.end == UINT64_MAX) has_default = true;
            else if (range.begin <= pc && pc < range.end) return true;
        }
        return has_default;
    };
    const auto add = [&](const std::string &local, std::string name, types::TypePtr type) {
        if (!source_identifier(name)) return;
        auto &items = candidates[local];
        if (std::none_of(items.begin(), items.end(), [&](const auto &item) {
                return item.name == name && ((!item.type && !type) ||
                    (item.type && type && item.type->id() == type->id()));
            })) items.push_back({std::move(name), std::move(type)});
    };
    for (const auto &slot : stack_variables) {
        const auto site_list = accesses.find(slot.name);
        if (site_list == accesses.end()) continue;
        for (const auto pc : site_list->second) {
            if (slot.frame_register.bank == RegisterBank::gpr || slot.frame_register.bank == RegisterBank::arm32_gpr ||
                slot.frame_register.bank == RegisterBank::arm64_gpr || slot.frame_register.bank == RegisterBank::arm64_sp ||
                slot.frame_register.bank == RegisterBank::riscv_gpr || slot.frame_register.bank == RegisterBank::mips_gpr) {
                for (const auto *variable : dwarf_variables) {
                    if (++mapping_work > max_variable_mapping_work) return {};
                    if (!active_at(*variable, pc.offset)) continue;
                    const auto offset = dwarf_frame_slot_offset(*variable, pc.offset, architecture, slot.frame_register);
                    if (!offset || slot.offset != *offset) continue;
                    const auto *definition = variable->type_id ? type_definition(*project, *variable->type_id) : nullptr;
                    add(slot.name, variable->name, definition ? definition->type : types::TypePtr{});
                }
            }
            if (pe && frame && slot.frame_register == *frame) {
                for (const auto &variable : pe->pdb_locals) {
                    if (++mapping_work > max_variable_mapping_work) return {};
                    if (variable.name.empty() || !variable.procedure_address ||
                        variable.procedure_address->space != pc.space || variable.procedure_address != owner.entry)
                        continue;
                    const auto offset = pdb_frame_slot_offset(project->loaded->metadata, variable, pc);
                    if (!offset || slot.offset != *offset) continue;
                    add(slot.name, variable.name, imported_pdb_local_type(project, *pe, variable.type_index));
                }
            }
        }
    }
    std::map<std::string, std::size_t, std::less<>> source_name_counts;
    for (const auto &[local, items] : candidates) {
        std::set<std::string, std::less<>> names;
        for (const auto &item : items) names.insert(item.name);
        if (names.size() == 1) ++source_name_counts[*names.begin()];
    }
    for (const auto &[local, items] : candidates) {
        std::set<std::string, std::less<>> names;
        std::map<std::uint64_t, types::TypePtr> types_by_id;
        for (const auto &item : items) {
            names.insert(item.name);
            if (item.type) types_by_id.emplace(item.type->id(), item.type);
        }
        if (names.size() != 1 || source_name_counts[*names.begin()] != 1) continue;
        result.names.emplace(local, *names.begin());
        if (types_by_id.size() == 1)
            result.types.push_back({local, types_by_id.begin()->second, false});
    }
    return result;
}

types::TypePtr function_prototype_at(const ProjectSnapshot *project, Address entry) {
    if (!project) return {};
    const auto *assignment = type_assignment(*project, entry);
    const auto *definition = assignment ? type_definition(*project, assignment->type_id) : nullptr;
    if (!definition || !definition->type || definition->type->kind() != types::Kind::function) return {};
    return definition->type;
}

std::uint16_t pointer_width(const FunctionRecord &function, const FunctionSnapshot &snapshot) {
    std::optional<std::uint16_t> width;
    for (const auto &block_id : function.blocks) {
        const auto block = std::find_if(snapshot.blocks.begin(), snapshot.blocks.end(),
                                        [&](const auto &candidate) { return candidate && candidate->id == block_id; });
        if (block == snapshot.blocks.end()) continue;
        for (const auto &fact : (*block)->instructions) {
            if (!fact) continue;
            const auto &instruction = fact->instruction;
            std::uint16_t current = 0;
            switch (instruction.context.mode) {
            case ExecutionMode::x86_16:
            case ExecutionMode::m6502: current = 16; break;
            case ExecutionMode::x86_64:
            case ExecutionMode::a64:
            case ExecutionMode::rv64:
            case ExecutionMode::rv64c:
            case ExecutionMode::mips64:
            case ExecutionMode::ppc64: current = 64; break;
            case ExecutionMode::x86_32:
            case ExecutionMode::a32:
            case ExecutionMode::thumb:
            case ExecutionMode::rv32:
            case ExecutionMode::mips32:
            case ExecutionMode::ppc32: current = 32; break;
            case ExecutionMode::unknown: break;
            }
            if (!current) continue;
            if (width && *width != current) return 0;
            width = current;
        }
    }
    return width.value_or(0);
}

decompiler::AbiDescription recovery_abi(const FunctionRecord &function, const FunctionSnapshot &snapshot,
                                        const Image *image, const ProjectSnapshot *project,
                                        const types::TypePtr &prototype) {
    auto abi = decompiler::AbiDescription{};
    abi.pointer_bits = pointer_width(function, snapshot);
    auto architecture = image ? image->layout().architecture : Architecture::unknown;
    if (architecture == Architecture::unknown) {
        for (const auto &block_id : function.blocks) {
            const auto block = std::find_if(snapshot.blocks.begin(), snapshot.blocks.end(),
                                            [&](const auto &candidate) { return candidate && candidate->id == block_id; });
            if (block == snapshot.blocks.end()) continue;
            for (const auto &fact : (*block)->instructions) {
                if (fact && fact->instruction.context.architecture != Architecture::unknown) {
                    architecture = fact->instruction.context.architecture;
                    break;
                }
            }
            if (architecture != Architecture::unknown) break;
        }
    }
    if (architecture == Architecture::x86_64) {
        if (prototype && prototype->kind() == types::Kind::function) {
            if (prototype->function_convention() == types::FunctionConvention::sysv_abi)
                return decompiler::x86_64_system_v_abi();
            if (prototype->function_convention() == types::FunctionConvention::ms_abi)
                return decompiler::x86_64_windows_abi();
        }
        const bool pe_image = project && project->loaded && project->loaded->metadata.pe.has_value();
        return pe_image ? decompiler::x86_64_windows_abi() : decompiler::x86_64_system_v_abi();
    }
    if (architecture == Architecture::x86 && abi.pointer_bits == 32)
        return decompiler::x86_32_cdecl_abi();
    if (architecture == Architecture::arm) return decompiler::arm32_aapcs_abi();
    if (architecture == Architecture::arm64) return decompiler::aarch64_abi();
    if (architecture == Architecture::riscv32) return decompiler::riscv32_ilp32_abi();
    if (architecture == Architecture::riscv64) return decompiler::riscv64_lp64_abi();
    if (architecture == Architecture::mips32) return decompiler::mips32_o32_abi();
    if (architecture == Architecture::mips64)
        return image && image->layout().space.width_bits == 32
            ? decompiler::mips_n32_abi() : decompiler::mips64_n64_abi();
    if (architecture == Architecture::powerpc && abi.pointer_bits == 64 && project &&
        project->loaded && project->loaded->metadata.elf) {
        const auto &header = project->loaded->metadata.elf->header;
        if (header.is_64 && header.machine == 21 && header.order == ByteOrder::little &&
            (header.flags & 3u) == 2u)
            return decompiler::ppc64le_elfv2_abi();
    }
    return abi;
}

std::string recovered_type_text(const types::TypePtr &type, std::uint16_t width) {
    if (!type) return {};
    auto result = types::format(*type);
    if (type->kind() == types::Kind::integer &&
        (result == "signed" || result == "unsigned") && type->size()) {
        const auto bits = *type->size() * 8;
        result = std::string(type->is_signed() ? "i" : "u") + std::to_string(bits);
    }
    const bool integer_width_in_name = type->kind() == types::Kind::integer &&
        result.size() > 1 && (result.front() == 'i' || result.front() == 'u') &&
        std::all_of(result.begin() + 1, result.end(), [](char c) { return c >= '0' && c <= '9'; });
    if (!integer_width_in_name && !width && type->size())
        width = static_cast<std::uint16_t>(*type->size() * 8);
    if (!integer_width_in_name && width)
        result += " (" + std::to_string(width) + " bits)";
    return result;
}

bool identifier_char(char value) {
    return (value >= 'a' && value <= 'z') || (value >= 'A' && value <= 'Z') ||
           (value >= '0' && value <= '9') || value == '_';
}

std::string render_user_variables(const decompiler::LiftedFunction &function, std::string rendered,
                                  const ProjectSnapshot *project,
                                  std::vector<PseudocodeVariableEdit> &variables,
                                  const std::map<std::string, std::string> &local_types,
                                  const std::map<std::string, std::string> &local_names,
                                  const std::map<std::string, std::string> &local_comments) {
    std::map<std::string, Address> definitions;
    std::set<std::string> ambiguous;
    const auto define = [&](RegisterOperand reg, std::optional<std::uint32_t> version, Address at) {
        if (!version) return;
        const auto token = register_token(reg, version);
        if (!definitions.emplace(token, at).second) ambiguous.insert(token);
    };
    for (const auto &block : function.blocks) for (const auto &instruction : block.instructions) {
        std::visit([&](const auto &statement) {
            using T = std::decay_t<decltype(statement)>;
            if constexpr (std::is_same_v<T, decompiler::Assign>)
                define(statement.destination, statement.destination_version, instruction.origin.address);
            else if constexpr (std::is_same_v<T, decompiler::Call>) {
                for (std::size_t i = 0; i < statement.register_output_versions.size() && i < statement.register_writes.size(); ++i)
                    define(statement.register_writes[i], statement.register_output_versions[i], instruction.origin.address);
                if (statement.return_register &&
                    std::find(statement.register_writes.begin(), statement.register_writes.end(),
                              *statement.return_register) == statement.register_writes.end())
                    define(*statement.return_register, statement.return_version, instruction.origin.address);
            } else if constexpr (std::is_same_v<T, decompiler::Intrinsic>) {
                if (statement.register_writes.size() == statement.register_output_versions.size())
                    for (std::size_t i = 0; i < statement.register_writes.size(); ++i)
                        define(statement.register_writes[i], statement.register_output_versions[i], instruction.origin.address);
            }
        }, instruction.statement);
    }
    for (const auto &token : ambiguous) definitions.erase(token);
    std::map<std::string, std::string> replacements;
    for (const auto &[token, address] : definitions) {
        const auto *annotation = project ? annotation_at(*project, address) : nullptr;
        const auto *assignment = project ? type_assignment(*project, address) : nullptr;
        const auto *definition = assignment ? type_definition(*project, assignment->type_id) : nullptr;
        std::string display = annotation && !annotation->name.empty() ? annotation->name : token;
        if (definition) display += " /* " + (definition->type->name().empty()
                                                   ? types::format(*definition->type) : definition->type->name()) + " */";
        replacements.emplace(token, display);
        variables.push_back({token, address, annotation && !annotation->name.empty() ? annotation->name : token});
    }
    for (const auto &[token, display] : replacements) {
        std::size_t position = 0;
        while ((position = rendered.find(token, position)) != std::string::npos) {
            const auto end = position + token.size();
            if ((position && identifier_char(rendered[position - 1])) ||
                (end < rendered.size() && identifier_char(rendered[end]))) { position = end; continue; }
            rendered.replace(position, token.size(), display);
            position += display.size();
        }
    }
    std::set<std::string> stack_local_names;
    for (const auto &[name, type] : local_types) { (void)type; stack_local_names.insert(name); }
    for (const auto &[name, comment] : local_comments) { (void)comment; stack_local_names.insert(name); }
    for (const auto &name : stack_local_names) {
        const auto named = local_names.find(name);
        const auto display_name = named == local_names.end() ? name : named->second;
        std::string display = display_name;
        if (const auto type = local_types.find(name); type != local_types.end() && !type->second.empty())
            display += " /* " + type->second + " */";
        if (const auto comment = local_comments.find(name); comment != local_comments.end() && !comment->second.empty()) {
            auto safe_comment = comment->second;
            std::size_t position = 0;
            while ((position = safe_comment.find("*/", position)) != std::string::npos) {
                safe_comment.replace(position, 2, "* /");
                position += 3;
            }
            std::replace(safe_comment.begin(), safe_comment.end(), '\r', ' ');
            std::replace(safe_comment.begin(), safe_comment.end(), '\n', ' ');
            display += " /* " + safe_comment + " */";
        }
        std::size_t position = 0;
        while ((position = rendered.find(name, position)) != std::string::npos) {
            const auto end = position + name.size();
            if ((position && identifier_char(rendered[position - 1])) ||
                (end < rendered.size() && identifier_char(rendered[end]))) { position = end; continue; }
            rendered.replace(position, name.size(), display);
            position += display.size();
        }
    }
    const auto globals = global_data_access_evidence(function, project);
    for (const auto &[key, evidence] : globals) {
        std::ostringstream marker;
        marker << " // 0x" << std::hex << key.second;
        std::string annotation = " /* ";
        for (std::size_t index = 0; index < evidence.size(); ++index) {
            if (index) annotation += "; ";
            annotation += evidence[index];
        }
        annotation += " */";
        std::size_t position = 0;
        while ((position = rendered.find(marker.str(), position)) != std::string::npos) {
            rendered.insert(position, annotation);
            position += annotation.size() + marker.str().size();
        }
    }
    return rendered;
}

std::optional<Match> match_function(const FunctionSnapshot &snapshot, Address address) {
    for (const auto &function : snapshot.functions) {
        if (!function)
            continue;
        for (const auto &block_id : function->blocks) {
            auto block = std::find_if(snapshot.blocks.begin(), snapshot.blocks.end(),
                                      [&](const auto &candidate) { return candidate && candidate->id == block_id; });
            if (block == snapshot.blocks.end())
                continue;
            for (const auto &fact : (*block)->instructions) {
                if (!fact)
                    continue;
                const auto &instruction = fact->instruction;
                const auto length = std::max<std::uint32_t>(instruction.byte_length(), 1);
                if (instruction.address.space == address.space && address.offset >= instruction.address.offset &&
                    address.offset - instruction.address.offset < length)
                    return Match{function.get(), instruction.address};
            }
        }
    }
    return {};
}
} // namespace

PseudocodeView::PseudocodeView(wxWindow *parent) : wxPanel(parent) {
    SetName("pseudocode-view");
    auto *layout = new wxBoxSizer(wxVERTICAL);
    status_ = new wxStaticText(this, wxID_ANY, "Select an address inside a recovered function");
    status_->SetName("pseudocode-status");
    auto *content = new wxBoxSizer(wxHORIZONTAL);
    addresses_ = new wxListCtrl(this, wxID_ANY, wxDefaultPosition, wxDefaultSize,
                                wxLC_REPORT | wxLC_SINGLE_SEL);
    addresses_->SetName("pseudocode-addresses");
    addresses_->InsertColumn(0, "Instruction", wxLIST_FORMAT_LEFT, FromDIP(150));
    addresses_->InsertColumn(1, "Name / comment", wxLIST_FORMAT_LEFT, FromDIP(220));
    source_ = new wxTextCtrl(this, wxID_ANY, "", wxDefaultPosition, wxDefaultSize,
                             wxTE_MULTILINE | wxTE_READONLY | wxTE_RICH2 | wxHSCROLL);
    source_->SetName("pseudocode-source");
    content->Add(addresses_, 0, wxEXPAND | wxALL, FromDIP(4));
    content->Add(source_, 1, wxEXPAND | wxALL, FromDIP(4));
    layout->Add(status_, 0, wxEXPAND | wxALL, FromDIP(4));
    layout->Add(content, 1, wxEXPAND);
    auto *navigation = new wxBoxSizer(wxHORIZONTAL);
    definition_ = new wxButton(this, wxID_ANY, "Go to definition");
    definition_->SetName("pseudocode-definition");
    definition_->SetToolTip("Navigate to the selected variable's instruction origin (Ctrl+B in source).");
    previous_use_ = new wxButton(this, wxID_ANY, "Previous occurrence");
    previous_use_->SetName("pseudocode-previous-occurrence");
    next_use_ = new wxButton(this, wxID_ANY, "Next occurrence");
    next_use_->SetName("pseudocode-next-occurrence");
    copy_pseudocode_ = new wxButton(this, wxID_ANY, "Copy pseudocode");
    copy_pseudocode_->SetName("pseudocode-copy");
    save_pseudocode_ = new wxButton(this, wxID_ANY, "Save pseudocode...");
    save_pseudocode_->SetName("pseudocode-save");
    variable_status_ = new wxStaticText(this, wxID_ANY, "Select a variable in source or the table",
                                       wxDefaultPosition, wxDefaultSize, wxST_ELLIPSIZE_END);
    variable_status_->SetName("pseudocode-variable-status");
    for (auto *button : {definition_, previous_use_, next_use_, copy_pseudocode_, save_pseudocode_})
        navigation->Add(button, 0, wxRIGHT, FromDIP(4));
    navigation->Add(variable_status_, 1, wxALIGN_CENTER_VERTICAL);
    layout->Add(navigation, 0, wxEXPAND | wxALL, FromDIP(4));
    auto *stack_panel = new wxBoxSizer(wxVERTICAL);
    stack_panel->Add(new wxStaticText(this, wxID_ANY, "Stack slots (entry SP relative)"), 0,
                     wxLEFT | wxRIGHT | wxTOP, FromDIP(4));
    stack_slots_ = new wxListCtrl(this, wxID_ANY, wxDefaultPosition, wxSize(-1, FromDIP(110)),
                                  wxLC_REPORT | wxLC_SINGLE_SEL | wxLC_HRULES);
    stack_slots_->SetName("pseudocode-stack-slots");
    stack_slots_->InsertColumn(0, "Offset", wxLIST_FORMAT_LEFT, FromDIP(110));
    stack_slots_->InsertColumn(1, "Width (bits)", wxLIST_FORMAT_LEFT, FromDIP(100));
    stack_slots_->InsertColumn(2, "Access", wxLIST_FORMAT_LEFT, FromDIP(100));
    stack_slots_->InsertColumn(3, "Sites", wxLIST_FORMAT_LEFT, FromDIP(70));
    stack_slots_->InsertColumn(4, "Local name", wxLIST_FORMAT_LEFT, FromDIP(150));
    stack_panel->Add(stack_slots_, 1, wxEXPAND | wxALL, FromDIP(4));
    auto *variables_panel = new wxBoxSizer(wxVERTICAL);
    variables_panel->Add(new wxStaticText(this, wxID_ANY, "Variables (definition sites)"), 0,
                         wxLEFT | wxRIGHT | wxTOP, FromDIP(4));
    variables_list_ = new wxListCtrl(this, wxID_ANY, wxDefaultPosition, wxSize(-1, FromDIP(110)),
                                     wxLC_REPORT | wxLC_SINGLE_SEL | wxLC_HRULES);
    variables_list_->SetName("pseudocode-variables");
    variables_list_->InsertColumn(0, "Name", wxLIST_FORMAT_LEFT, FromDIP(140));
    variables_list_->InsertColumn(1, "Type", wxLIST_FORMAT_LEFT, FromDIP(120));
    variables_list_->InsertColumn(2, "Definition", wxLIST_FORMAT_LEFT, FromDIP(110));
    variables_list_->InsertColumn(3, "SSA / local identity", wxLIST_FORMAT_LEFT, FromDIP(150));
    variables_panel->Add(variables_list_, 1, wxEXPAND | wxALL, FromDIP(4));
    auto *data_panels = new wxBoxSizer(wxHORIZONTAL);
    data_panels->Add(stack_panel, 1, wxEXPAND);
    data_panels->Add(variables_panel, 1, wxEXPAND);
    auto *editors = new wxBoxSizer(wxHORIZONTAL);
    rename_function_ = new wxButton(this, wxID_ANY, "Rename function...");
    rename_function_->SetName("pseudocode-rename-function");
    rename_local_ = new wxButton(this, wxID_ANY, "Rename selected local...");
    rename_local_->SetName("pseudocode-rename-local");
    comment_local_ = new wxButton(this, wxID_ANY, "Comment selected local...");
    comment_local_->SetName("pseudocode-comment-local");
    edit_comment_ = new wxButton(this, wxID_ANY, "Comment instruction...");
    edit_comment_->SetName("pseudocode-edit-comment");
    rename_variable_ = new wxButton(this, wxID_ANY, "Rename selected variable...");
    rename_variable_->SetName("pseudocode-rename-variable");
    assign_type_ = new wxButton(this, wxID_ANY, "Assign variable type...");
    assign_type_->SetName("pseudocode-assign-type");
    editors->Add(rename_function_, 0, wxRIGHT, FromDIP(4));
    editors->Add(rename_local_, 0, wxRIGHT, FromDIP(4));
    editors->Add(comment_local_, 0, wxRIGHT, FromDIP(4));
    editors->Add(edit_comment_, 0);
    editors->Add(rename_variable_, 0, wxLEFT, FromDIP(4));
    editors->Add(assign_type_, 0, wxLEFT, FromDIP(4));
    layout->Add(editors, 0, wxEXPAND | wxALL, FromDIP(4));
    layout->Add(data_panels, 0, wxEXPAND);
    SetSizer(layout);
    addresses_->Bind(wxEVT_LIST_ITEM_SELECTED, [this](wxListEvent &event) {
        if (!updating_ && event.GetIndex() >= 0 && static_cast<std::size_t>(event.GetIndex()) < rows_.size())
            navigate_to(rows_[static_cast<std::size_t>(event.GetIndex())]);
    });
    stack_slots_->Bind(wxEVT_LIST_ITEM_SELECTED, [this](wxListEvent &event) {
        if (updating_) return;
        const auto row = event.GetIndex();
        const bool selected = row >= 0 && static_cast<std::size_t>(row) < stack_access_rows_.size() &&
            static_cast<std::size_t>(row) < stack_access_editable_.size() &&
            stack_access_editable_[static_cast<std::size_t>(row)] != 0;
        const bool writable = project_ && project_->state &&
            project_->mode == database::ProjectMode::read_write && static_cast<bool>(submit_);
        rename_local_->Enable(writable && selected);
        comment_local_->Enable(writable && selected);
        if (selected) navigate_to(stack_access_rows_[static_cast<std::size_t>(row)]);
    });
    variables_list_->Bind(wxEVT_LIST_ITEM_SELECTED, [this](wxListEvent &event) {
        if (!updating_ && event.GetIndex() >= 0 &&
            static_cast<std::size_t>(event.GetIndex()) < variable_links_.size())
            select_variable(static_cast<std::size_t>(event.GetIndex()), true);
    });
    rename_function_->Bind(wxEVT_BUTTON, [this](wxCommandEvent &) { rename_function(); });
    rename_local_->Bind(wxEVT_BUTTON, [this](wxCommandEvent &) { rename_local(); });
    comment_local_->Bind(wxEVT_BUTTON, [this](wxCommandEvent &) { comment_local(); });
    edit_comment_->Bind(wxEVT_BUTTON, [this](wxCommandEvent &) { edit_comment(); });
    rename_variable_->Bind(wxEVT_BUTTON, [this](wxCommandEvent &) { rename_variable(); });
    assign_type_->Bind(wxEVT_BUTTON, [this](wxCommandEvent &) { assign_variable_type(); });
    definition_->Bind(wxEVT_BUTTON, [this](wxCommandEvent &) { go_to_definition(); });
    previous_use_->Bind(wxEVT_BUTTON, [this](wxCommandEvent &) { move_occurrence(false); });
    next_use_->Bind(wxEVT_BUTTON, [this](wxCommandEvent &) { move_occurrence(true); });
    copy_pseudocode_->Bind(wxEVT_BUTTON, [this](wxCommandEvent &) { copy_pseudocode(); });
    save_pseudocode_->Bind(wxEVT_BUTTON, [this](wxCommandEvent &) { save_pseudocode(); });
    const auto deferred_selection = [this] {
        const auto id = document_;
        const auto serial = render_serial_;
        CallAfter([this, id, serial] {
            if (document_ == id && render_serial_ == serial && model_ready_ && !updating_)
                source_selection_changed();
        });
    };
    source_->Bind(wxEVT_LEFT_UP, [deferred_selection](wxMouseEvent &event) { event.Skip(); deferred_selection(); });
    source_->Bind(wxEVT_KEY_UP, [deferred_selection](wxKeyEvent &event) { event.Skip(); deferred_selection(); });
    source_->Bind(wxEVT_CHAR_HOOK, [this](wxKeyEvent &event) {
        if (event.ControlDown() && !event.AltDown() && (event.GetKeyCode() == 'B' || event.GetKeyCode() == 'b')) {
            source_selection_changed();
            go_to_definition();
        } else event.Skip();
    });
    update_variable_actions();
}

void PseudocodeView::copy_pseudocode() {
    if (!model_ready_ || source_->GetValue().empty() || !wxTheClipboard->Open()) return;
    wxTheClipboard->SetData(new wxTextDataObject(source_->GetValue()));
    wxTheClipboard->Close();
}

void PseudocodeView::save_pseudocode() {
    if (!model_ready_ || source_->GetValue().empty()) return;
    wxFileDialog dialog(this, "Save pseudocode", {}, {},
                        "C/C++ source (*.c;*.cpp)|*.c;*.cpp|Text files (*.txt)|*.txt|All files (*.*)|*.*",
                        wxFD_SAVE | wxFD_OVERWRITE_PROMPT);
    if (dialog.ShowModal() != wxID_OK) return;
    const auto encoded = source_->GetValue().utf8_str();
    wxFile file;
    if (!file.Create(dialog.GetPath(), true)) {
        wxMessageBox("Could not write the pseudocode file.", "Save pseudocode", wxOK | wxICON_ERROR, this);
        return;
    }
    const bool written = file.Write(encoded.data(), encoded.length());
    const bool closed = file.Close();
    if (!written || !closed)
        wxMessageBox("Could not write the pseudocode file.", "Save pseudocode", wxOK | wxICON_ERROR, this);
}

void PseudocodeView::update_document(std::optional<DocumentId> id, std::shared_ptr<const ProjectSnapshot> project,
                                      std::uint64_t document_revision, std::optional<Location> selection,
                                      std::function<void(ProjectCommand)> submit) {
    if (id != document_) {
        remember_source();
        model_ready_ = false;
        rendered_function_.reset();
    }
    document_ = id;
    document_revision_ = document_revision;
    if (id) source_states_.try_emplace(id->value);
    owner_ = std::move(project);
    const bool current = owner_ && (owner_->status == DerivedStatus::fresh || owner_->status == DerivedStatus::incomplete);
    update(current && owner_->functions ? owner_->functions.get() : nullptr, selection,
           owner_ && owner_->loaded ? owner_->loaded->image.get() : nullptr, owner_.get(), std::move(submit));
    if (owner_ && !current) status_->SetLabel("Pseudocode unavailable: " + analysis_state_text(*owner_));
}
void PseudocodeView::retain_documents(std::span<const DocumentInfo> documents) {
    for (auto it = source_states_.begin(); it != source_states_.end();)
        if (std::none_of(documents.begin(), documents.end(), [&](const auto &document) { return document.id.value == it->first; }))
            it = source_states_.erase(it);
        else ++it;
}
void PseudocodeView::navigate_to(Location location) {
    if (document_) {
        if (!model_ready_ || !rendered_function_) return;
        if (navigate_document) {
            PseudocodeNavigationToken token;
            token.document = *document_;
            token.document_revision = rendered_document_revision_;
            if (rendered_project_ && rendered_project_->state) {
                token.project_uuid = rendered_project_->state->uuid;
                token.project_revisions = rendered_project_->state->revisions;
            }
            navigate_document(token, location);
        }
    } else if (navigate) navigate(location);
}
void PseudocodeView::update(const FunctionSnapshot *snapshot, std::optional<Location> selection, const Image *image,
                            const ProjectSnapshot *project, std::function<void(ProjectCommand)> submit) {
    project_ = project;
    submit_ = std::move(submit);
    const auto address = selected_address(selection, image);
    const auto match = snapshot && address ? match_function(*snapshot, *address) : std::nullopt;
    current_instruction_ = match ? std::optional<Address>{match->instruction} : address;
    if (document_ && owner_ && model_ready_ && match && rendered_snapshot_ == snapshot &&
        rendered_project_ == project && rendered_image_ == image && rendered_function_ == match->function->entry) {
        rendered_document_revision_ = document_revision_;
        select_address(match->instruction);
        return;
    }
    remember_source();
    ++render_serial_;
    model_ready_ = false;
    rendered_function_.reset();
    selected_variable_.reset();
    updating_ = true;
    function_ = nullptr;
    rows_.clear();
    source_origins_.clear();
    variables_.clear();
    stack_access_rows_.clear();
    stack_access_sites_.clear();
    stack_access_editable_.clear();
    variable_definition_rows_.clear();
    variable_links_.clear();
    addresses_->DeleteAllItems();
    stack_slots_->DeleteAllItems();
    variables_list_->DeleteAllItems();
    source_->ChangeValue({});
    update_variable_actions();
    if (!snapshot || !address) {
        if (diagnostics_changed) diagnostics_changed({});
        status_->SetLabel("Select an address inside a recovered function");
        rename_function_->Enable(false); rename_local_->Enable(false); comment_local_->Enable(false); edit_comment_->Enable(false);
        rename_variable_->Enable(false); assign_type_->Enable(false);
        updating_ = false;
        return;
    }
    if (!match) {
        if (diagnostics_changed) diagnostics_changed({});
        status_->SetLabel("No recovered function contains the selected address");
        rename_function_->Enable(false); rename_local_->Enable(false); comment_local_->Enable(false); edit_comment_->Enable(false);
        rename_variable_->Enable(false); assign_type_->Enable(false);
        updating_ = false;
        return;
    }
    function_ = match->function;
    const auto report_decompiler_failure = [&](const std::string &message) {
        if (diagnostics_changed)
            diagnostics_changed({{"Decompiler", DiagnosticSeverity::error, message, {}, match->function->entry}});
    };
    const bool editable = project_ && project_->state && project_->mode == database::ProjectMode::read_write && submit_;
    rename_function_->Enable(editable);
    const auto selected_stack_row = stack_slots_->GetNextItem(-1, wxLIST_NEXT_ALL, wxLIST_STATE_SELECTED);
    const bool has_selected_stack = selected_stack_row >= 0 &&
        static_cast<std::size_t>(selected_stack_row) < stack_access_rows_.size() &&
        static_cast<std::size_t>(selected_stack_row) < stack_access_editable_.size() &&
        stack_access_editable_[static_cast<std::size_t>(selected_stack_row)] != 0;
    rename_local_->Enable(editable && has_selected_stack);
    comment_local_->Enable(editable && has_selected_stack);
    edit_comment_->Enable(editable);
    rename_variable_->Enable(false);
    assign_type_->Enable(false);
    const auto *jvm_metadata = project_ && project_->loaded && project_->loaded->metadata.jvm
                                   ? &*project_->loaded->metadata.jvm : nullptr;
    const auto *wasm_metadata = project_ && project_->loaded && project_->loaded->metadata.wasm
                                    ? &*project_->loaded->metadata.wasm : nullptr;
    auto lifted = decompiler::lift_function(*match->function, *snapshot, jvm_metadata, wasm_metadata);
    if (!lifted) {
        report_decompiler_failure(lifted.error().message);
        status_->SetLabel("Could not lift the selected function: " + text(lifted.error().message));
        updating_ = false;
        return;
    }
    if (image) {
        auto switches = project_ && project_->loaded
                            ? analyze_switch_tables(*image, project_->loaded->metadata, *match->function, *snapshot, {})
                            : analyze_switch_tables(*image, *match->function, *snapshot, {});
        if (switches) decompiler::attach_switch_analysis(lifted.value(), switches.value());
    }
    const auto prototype = function_prototype_at(project_, match->function->entry);
    const auto abi = recovery_abi(*match->function, *snapshot, image, project_, prototype);
    auto call_effects = decompiler::prepare_call_effects(lifted.value(), abi);
    if (!call_effects) {
        report_decompiler_failure(call_effects.error().message);
        status_->SetLabel("Could not prepare call effects: " + text(call_effects.error().message));
        updating_ = false;
        return;
    }
    auto call_arguments = abi.integer_argument_registers;
    call_arguments.insert(call_arguments.end(), abi.floating_argument_registers.begin(), abi.floating_argument_registers.end());
    call_arguments.insert(call_arguments.end(), abi.vector_argument_registers.begin(), abi.vector_argument_registers.end());
    auto ssa = decompiler::to_ssa(call_effects.value(), call_arguments);
    if (!ssa) {
        report_decompiler_failure(ssa.error().message);
        status_->SetLabel("Could not convert the selected function to SSA: " + text(ssa.error().message));
        updating_ = false;
        return;
    }
    auto constants_simplified = decompiler::simplify_constants(ssa.value());
    if (!constants_simplified) {
        report_decompiler_failure(constants_simplified.error().message);
        status_->SetLabel("Could not simplify the selected function: " + text(constants_simplified.error().message));
        updating_ = false;
        return;
    }
    auto simplified = decompiler::simplify_identities(constants_simplified.value());
    if (!simplified) {
        report_decompiler_failure(simplified.error().message);
        status_->SetLabel("Could not simplify identities in the selected function: " + text(simplified.error().message));
        updating_ = false;
        return;
    }
    auto named_stack = decompiler::recover_stack_variables(simplified.value());
    auto recovered_types = decompiler::recover_types(simplified.value(), abi, prototype);
    const auto &pseudocode_function = named_stack ? named_stack.value() : simplified.value();
    std::map<std::string, std::string> recovered_local_types;
    std::map<std::string, std::string> recovered_local_names;
    std::map<std::string, std::string> recovered_local_comments;
    const DexMethodDebug *dex_debug = nullptr;
    if (project_ && project_->loaded && project_->loaded->metadata.dex &&
        match->function->entry.space.value > 0 &&
        match->function->entry.space.value - 1 <= UINT32_MAX) {
        const auto method_index = static_cast<std::uint32_t>(match->function->entry.space.value - 1);
        const auto &methods = project_->loaded->metadata.dex->methods;
        const auto found = std::find_if(methods.begin(), methods.end(), [&](const auto &method) {
            return method.method_index == method_index;
        });
        if (found != methods.end()) dex_debug = &*found;
    }
    if (dex_debug && dex_debug->locals.size() <= 100'000) {
        std::map<std::string, std::set<std::string, std::less<>>, std::less<>> candidates;
        const auto offer_register = [&](RegisterOperand reg, std::optional<std::uint32_t> version, Address at) {
            if (reg.bank != RegisterBank::dex_vreg || !version || reg.index > 255) return;
            for (const auto &local : dex_debug->locals) {
                if (local.register_index != reg.index || !local.name || !source_identifier(*local.name) ||
                    at.space != match->function->entry.space || at.offset < local.begin || at.offset >= local.end)
                    continue;
                candidates[register_token(reg, version)].insert(*local.name);
            }
        };
        for (const auto &block : pseudocode_function.blocks) {
            for (const auto &phi : block.phis)
                offer_register(phi.destination, phi.version, block.begin);
            for (const auto &instruction : block.instructions) {
                std::visit([&](const auto &statement) {
                    using T = std::decay_t<decltype(statement)>;
                    if constexpr (std::is_same_v<T, decompiler::Assign>) {
                        offer_register(statement.destination, statement.destination_version, instruction.origin.address);
                    } else if constexpr (std::is_same_v<T, decompiler::Call>) {
                        for (std::size_t i = 0; i < statement.register_output_versions.size() &&
                             i < statement.register_writes.size(); ++i)
                            offer_register(statement.register_writes[i], statement.register_output_versions[i],
                                           instruction.origin.address);
                        if (statement.return_register &&
                            std::find(statement.register_writes.begin(), statement.register_writes.end(),
                                      *statement.return_register) == statement.register_writes.end())
                            offer_register(*statement.return_register, statement.return_version,
                                           instruction.origin.address);
                    } else if constexpr (std::is_same_v<T, decompiler::Intrinsic>) {
                        if (statement.register_writes.size() == statement.register_output_versions.size())
                            for (std::size_t i = 0; i < statement.register_writes.size(); ++i)
                                offer_register(statement.register_writes[i], statement.register_output_versions[i],
                                               instruction.origin.address);
                    }
                }, instruction.statement);
            }
        }
        for (const auto &[token, names] : candidates) if (names.size() == 1) {
            recovered_local_types.emplace(token, std::string{});
            recovered_local_names.emplace(token, *names.begin());
        }
    }
    if (recovered_types) for (const auto &variable : recovered_types.value().stack_variables)
        recovered_local_types.emplace(variable.name, recovered_type_text(variable.type, variable.bits));
    auto local_type_evidence = named_stack
        ? stack_local_type_evidence(named_stack.value(), project_) : std::vector<decompiler::StackLocalTypeEvidence>{};
    if (named_stack) {
        const auto access_sites = stack_access_sites(named_stack.value());
        for (const auto &[name, access] : access_sites) {
            const auto *annotation = project_ && !access.empty() ? annotation_at(*project_, access.front()) : nullptr;
            if (annotation && !annotation->name.empty()) recovered_local_names.emplace(name, annotation->name);
            if (annotation && !annotation->comment.empty()) recovered_local_comments.emplace(name, annotation->comment);
        }
        // Stack locals already have a stable identity in the lifter (their
        // recovered frame slot name). Keep every access site so edits can be
        // applied atomically without relying on which use happens to be first.
        if (recovered_types) {
            for (const auto &variable : recovered_types.value().stack_variables) {
                const auto sites = access_sites.find(variable.name);
                if (sites == access_sites.end() || sites->second.empty()) continue;
                auto variable_accesses = sites->second;
                std::sort(variable_accesses.begin(), variable_accesses.end(), [](Address left, Address right) {
                    return std::pair{left.space.value, left.offset} < std::pair{right.space.value, right.offset};
                });
                variable_accesses.erase(std::unique(variable_accesses.begin(), variable_accesses.end()),
                                        variable_accesses.end());
                if (variable_accesses.empty()) continue;
                const auto *annotation = project_ ? annotation_at(*project_, variable_accesses.front()) : nullptr;
                const auto display = annotation && !annotation->name.empty() ? annotation->name : variable.name;
                variables_.push_back({variable.name, variable_accesses.front(), display, true, false,
                                      std::move(variable_accesses)});
            }
        }
    }
    if (named_stack && recovered_types && image) {
        const auto imported = imported_stack_variable_evidence(
            pseudocode_function, *match->function, project_, image->layout().architecture,
            recovered_types.value().stack_variables);
        for (const auto &[local, name] : imported.names)
            recovered_local_names.try_emplace(local, name);
        for (const auto &evidence : imported.types) {
            const auto existing = std::find_if(local_type_evidence.begin(), local_type_evidence.end(),
                [&](const auto &candidate) { return candidate.name == evidence.name; });
            if (existing != local_type_evidence.end()) continue; // An address assignment remains authoritative.
            local_type_evidence.push_back(evidence);
            recovered_local_types.insert_or_assign(evidence.name, recovered_type_text(evidence.type, 0));
        }
    }
    for (const auto &evidence : local_type_evidence)
        if (evidence.type && !evidence.ambiguous)
            recovered_local_types.insert_or_assign(evidence.name, recovered_type_text(evidence.type, 0));
    std::map<std::pair<std::uint32_t, std::uint64_t>, std::size_t> variable_origin_counts;
    for (const auto &variable : variables_) {
        if (variable.access_sites.empty())
            ++variable_origin_counts[address_identity(variable.definition)];
        else
            for (const auto site_address : variable.access_sites)
                ++variable_origin_counts[address_identity(site_address)];
    }
    for (auto &variable : variables_) {
        const bool shared_origin = variable.access_sites.empty()
            ? variable_origin_counts[address_identity(variable.definition)] != 1
            : std::any_of(variable.access_sites.begin(), variable.access_sites.end(), [&](Address site_address) {
                  return variable_origin_counts[address_identity(site_address)] != 1;
              });
        variable.function_entry_collision = variable.definition == match->function->entry;
        variable.editable = !shared_origin && !variable.function_entry_collision;
    }
    std::set<std::pair<std::uint32_t, std::uint64_t>> origins;
    for (const auto block_id : match->function->blocks) {
        const auto block = std::find_if(snapshot->blocks.begin(), snapshot->blocks.end(),
            [&](const auto &candidate) { return candidate && candidate->id == block_id; });
        if (block == snapshot->blocks.end()) continue;
        for (const auto &fact : (*block)->instructions)
            if (fact && origins.emplace(fact->instruction.address.space.value, fact->instruction.address.offset).second)
                rows_.push_back(fact->instruction.address);
    }
    for (std::size_t i = 0; i < rows_.size(); ++i) {
        const auto row = addresses_->InsertItem(static_cast<long>(i), location_text(rows_[i], image));
        if (project_) {
            const auto annotation = annotation_at(*project_, rows_[i]);
            const auto name = presentation_name(*project_, rows_[i]);
            wxString detail;
            if (annotation && !annotation->comment.empty()) detail = text(annotation->comment);
            if (text(name) != location_text(rows_[i], image)) {
                if (!detail.empty()) detail += " ";
                detail += text(name) + ":";
            }
            addresses_->SetItem(row, 1, detail);
        }
        if (rows_[i] == match->instruction)
            addresses_->SetItemState(row, wxLIST_STATE_SELECTED, wxLIST_STATE_SELECTED);
    }
    auto typed_source = decompiler::format_pseudocode_with_types(
        pseudocode_function, abi, prototype,
        std::span<const decompiler::StackLocalTypeEvidence>(local_type_evidence));
    auto source_text = typed_source ? std::move(typed_source.value())
                                    : decompiler::format_structured_pseudocode(pseudocode_function).text;
    render_parameter_names(source_text, imported_parameter_names(
        *match->function, project_, image ? image->layout().architecture : Architecture::unknown,
        abi, prototype));
    source_->ChangeValue(text(render_user_variables(pseudocode_function, std::move(source_text), project_,
                                                    variables_, recovered_local_types, recovered_local_names,
                                                    recovered_local_comments)));
    for (const auto &variable : variables_) {
        const auto row = variables_list_->InsertItem(variables_list_->GetItemCount(), text(variable.display));
        const auto *assignment = project_ ? type_assignment(*project_, variable.definition) : nullptr;
        const auto *definition = assignment ? type_definition(*project_, assignment->type_id) : nullptr;
        auto type_name = definition
                             ? (definition->type->name().empty() ? types::format(*definition->type)
                                                                 : definition->type->name())
                             : std::string{};
        if (type_name.empty()) {
            const auto inferred = recovered_local_types.find(variable.token);
            if (inferred != recovered_local_types.end()) type_name = inferred->second;
        }
        variables_list_->SetItem(row, 1, text(type_name));
        variables_list_->SetItem(row, 2, location_text(variable.definition, image));
        const auto read_only_label = variable.function_entry_collision
            ? std::string(" (function entry; read-only)")
            : (variable.editable ? std::string{} : std::string(" (shared instruction origin; read-only)"));
        variables_list_->SetItem(row, 3, text(variable.token + read_only_label));
        const auto editable_index = variable.editable
            ? std::optional<std::size_t>{variable_links_.size()} : std::nullopt;
        variable_links_.push_back({variable.token, variable.display, variable.definition,
                                   editable_index,
                                   !variable.editable && !variable.function_entry_collision,
                                   variable.function_entry_collision});
        variable_definition_rows_.push_back(variable.definition);
    }
    if (recovered_types) {
        for (const auto &variable : recovered_types.value().variables) {
            if (!variable.parameter_index) continue;
            const auto row = variables_list_->InsertItem(variables_list_->GetItemCount(),
                                                          text(variable.name.empty()
                                                                   ? "arg" + std::to_string(*variable.parameter_index)
                                                                   : variable.name));
            const auto width = variable.type && variable.type->size()
                                   ? static_cast<std::uint16_t>(*variable.type->size() * 8) : 0;
            variables_list_->SetItem(row, 1, text(recovered_type_text(variable.type, width)));
            variables_list_->SetItem(row, 2, location_text(match->function->entry, image));
            const auto token = variable.name.empty() ? "arg" + std::to_string(*variable.parameter_index) : variable.name;
            variables_list_->SetItem(row, 3, text(token));
            variable_links_.push_back({token, token, match->function->entry, {}});
            variable_definition_rows_.push_back(match->function->entry);
        }
    }
    if (dex_debug && dex_debug->locals.size() <= 100'000) {
        for (const auto &local : dex_debug->locals) {
            const auto name = local.name && !local.name->empty() ? *local.name
                                                                 : "v" + std::to_string(local.register_index);
            const auto row = variables_list_->InsertItem(variables_list_->GetItemCount(), text(name));
            variables_list_->SetItem(row, 1, text(local.type.value_or("")));
            variables_list_->SetItem(row, 2,
                location_text(Address{match->function->entry.space, local.begin}, image));
            const auto range_label = wxString::Format(
                "DEX v%u [0x%llx, 0x%llx) (read-only debug range)",
                static_cast<unsigned>(local.register_index),
                static_cast<unsigned long long>(local.begin),
                static_cast<unsigned long long>(local.end));
            variables_list_->SetItem(row, 3, range_label);
        }
    }
    if (dex_debug) {
        for (std::size_t i = 0; i < dex_debug->parameter_names.size() && i < 255; ++i) {
            if (!dex_debug->parameter_names[i] || dex_debug->parameter_names[i]->empty()) continue;
            const auto row = variables_list_->InsertItem(variables_list_->GetItemCount(),
                                                         text(*dex_debug->parameter_names[i]));
            variables_list_->SetItem(row, 2, text("DEX parameter #" + std::to_string(i)));
            variables_list_->SetItem(row, 3, text("parameter name (register binding unresolved)"));
        }
    }
    rename_variable_->Enable(editable && !variables_.empty());
    assign_type_->Enable(editable && !variables_.empty());
    const StackFrameAnalysis *stack = nullptr;
    if (project_) {
        const auto frame = std::find_if(project_->stack_frames.begin(), project_->stack_frames.end(),
            [&](const auto &record) { return record.function == match->function->id; });
        if (frame != project_->stack_frames.end()) stack = &frame->frame;
    }
    if (stack) {
        std::vector<std::vector<Address>> normalized_accesses;
        normalized_accesses.reserve(stack->slots.size());
        std::map<std::pair<std::uint32_t, std::uint64_t>, std::size_t> stack_origin_counts;
        for (const auto &slot : stack->slots) {
            auto accesses = slot.accesses;
            std::sort(accesses.begin(), accesses.end(), [](Address left, Address right) {
                return std::pair{left.space.value, left.offset} < std::pair{right.space.value, right.offset};
            });
            accesses.erase(std::unique(accesses.begin(), accesses.end()), accesses.end());
            for (const auto site_address : accesses) ++stack_origin_counts[address_identity(site_address)];
            normalized_accesses.push_back(std::move(accesses));
        }
        for (std::size_t slot_index = 0; slot_index < stack->slots.size(); ++slot_index) {
            const auto &slot = stack->slots[slot_index];
            const auto &accesses = normalized_accesses[slot_index];
            const auto row = stack_slots_->InsertItem(stack_slots_->GetItemCount(), stack_offset(slot.offset_from_entry_sp));
            stack_slots_->SetItem(row, 1, slot.width ? wxString::Format("%u", slot.width) : wxString("?"));
            wxString access_text;
            if (slot.address_taken)
                access_text = "address";
            if (slot.read)
                access_text += access_text.empty() ? "read" : "/read";
            if (slot.written)
                access_text += access_text.empty() ? "write" : "/write";
            stack_slots_->SetItem(row, 2, access_text);
            stack_slots_->SetItem(row, 3,
                                  wxString::Format("%llu", static_cast<unsigned long long>(slot.accesses.size())));
            const auto access = accesses.empty() ? match->function->entry : accesses.front();
            stack_access_rows_.push_back(access);
            stack_access_sites_.push_back(accesses);
            const bool unique_origin = !accesses.empty() &&
                access != match->function->entry &&
                std::all_of(accesses.begin(), accesses.end(), [&](Address site) {
                    return site != match->function->entry &&
                           stack_origin_counts[address_identity(site)] == 1 &&
                           variable_origin_counts[address_identity(site)] == 1;
                });
            stack_access_editable_.push_back(unique_origin ? 1 : 0);
            auto local_name = project_ ? text(presentation_name(*project_, access)) : wxString{};
            if (!unique_origin) local_name += " (read-only: ambiguous origin)";
            stack_slots_->SetItem(row, 4, local_name);
        }
    }
    auto function_label = project_ ? text(presentation_name(*project_, match->function->entry)) : wxString{};
    status_->SetLabel("Function " + location_text(match->function->entry, image) +
                      (function_label.empty() ? wxString{} : wxString(" (") + function_label + ")") +
                      (match->function->complete ? "" : " (partial recovery)") +
                      (stack && !stack->complete ? " (partial stack offsets)" : ""));
    rendered_function_ = match->function->entry;
    if (diagnostics_changed) {
        std::vector<AnalysisIssueDiagnostic> diagnostics;
        diagnostics.reserve(lifted.value().diagnostics.size());
        for (const auto &message : lifted.value().diagnostics)
            diagnostics.push_back({"Decompiler", DiagnosticSeverity::warning, message, {}, match->function->entry});
        diagnostics_changed(std::move(diagnostics));
    }
    rendered_snapshot_ = snapshot;
    rendered_project_ = project;
    rendered_image_ = image;
    rendered_document_revision_ = document_revision_;
    rebuild_source_origins();
    model_ready_ = true;
    restore_source();
    updating_ = false;
    select_address(match->instruction);
    update_variable_actions();
}

void PseudocodeView::remember_source() {
    if (!model_ready_ || !document_ || !rendered_function_) return;
    const auto found = source_states_.find(document_->value);
    if (found == source_states_.end()) return; // A closed document must not recreate its state.
    SourceState state{*rendered_function_};
    source_->GetSelection(&state.begin, &state.end);
    if (selected_variable_ && *selected_variable_ < variable_links_.size())
        state.variable = variable_links_[*selected_variable_].token;
    auto &states = found->second;
    std::erase_if(states, [&](const auto &saved) { return saved.function == state.function; });
    states.push_back(std::move(state));
    if (states.size() > 32) states.erase(states.begin());
}
void PseudocodeView::restore_source() {
    if (!document_ || !rendered_function_) return;
    const auto found = source_states_.find(document_->value);
    if (found == source_states_.end()) return;
    const auto state = std::find_if(found->second.begin(), found->second.end(),
        [&](const auto &saved) { return saved.function == *rendered_function_; });
    if (state == found->second.end()) return;
    const auto length = source_->GetLastPosition();
    source_->SetSelection(std::clamp(state->begin, 0L, length), std::clamp(state->end, 0L, length));
    source_->ShowPosition(std::clamp(state->begin, 0L, length));
    if (state->variable)
        for (std::size_t i = 0; i < variable_links_.size(); ++i)
            if (variable_links_[i].token == *state->variable) { selected_variable_ = i; break; }
}
void PseudocodeView::rebuild_source_origins() {
    source_origins_.clear();
    if (!rendered_function_) return;
    const auto line_count = source_->GetNumberOfLines();
    for (long line_number = 0; line_number < line_count; ++line_number) {
        const auto line = source_->GetLineText(line_number);
        const auto marker = line.rfind(" // 0x");
        if (marker == wxString::npos) continue;
        const auto digits = line.Mid(marker + 6).ToStdString();
        if (digits.empty() || !std::all_of(digits.begin(), digits.end(), [](unsigned char value) {
                return std::isxdigit(value) != 0;
            })) continue;
        std::uint64_t offset = 0;
        const auto parsed = std::from_chars(digits.data(), digits.data() + digits.size(), offset, 16);
        if (parsed.ec != std::errc{} || parsed.ptr != digits.data() + digits.size()) continue;
        const Address address{rendered_function_->space, offset};
        if (std::find(rows_.begin(), rows_.end(), address) == rows_.end()) continue;
        const auto begin = source_->XYToPosition(0, line_number);
        const auto end = source_->XYToPosition(static_cast<long>(line.length()), line_number);
        if (begin < 0 || end < begin) continue;
        source_origins_.push_back({address, begin, end});
    }
}
const PseudocodeView::SourceOriginLine *PseudocodeView::source_origin_at(long begin, long end) const {
    for (const auto &origin : source_origins_) {
        const bool contains = begin == end ? begin >= origin.begin && begin <= origin.end
                                          : begin < origin.end && end > origin.begin;
        if (contains) return &origin;
    }
    return nullptr;
}
void PseudocodeView::select_address(Address address) {
    const auto was_updating = updating_;
    updating_ = true;
    addresses_->SetItemState(-1, 0, wxLIST_STATE_SELECTED | wxLIST_STATE_FOCUSED);
    for (std::size_t i = 0; i < rows_.size(); ++i)
        if (rows_[i] == address) {
            addresses_->SetItemState(static_cast<long>(i), wxLIST_STATE_SELECTED, wxLIST_STATE_SELECTED);
            addresses_->EnsureVisible(static_cast<long>(i));
            break;
        }
    if (!selected_variable_ || *selected_variable_ >= variable_links_.size() ||
        variable_links_[*selected_variable_].address != address) {
        selected_variable_.reset();
        for (std::size_t i = 0; i < variable_links_.size(); ++i)
            if (variable_links_[i].address == address) {
                if (selected_variable_) { selected_variable_.reset(); break; }
                selected_variable_ = i;
            }
    }
    variables_list_->SetItemState(-1, 0, wxLIST_STATE_SELECTED | wxLIST_STATE_FOCUSED);
    if (selected_variable_) {
        variables_list_->SetItemState(static_cast<long>(*selected_variable_), wxLIST_STATE_SELECTED, wxLIST_STATE_SELECTED);
        variables_list_->EnsureVisible(static_cast<long>(*selected_variable_));
    }
    const auto origin = std::find_if(source_origins_.begin(), source_origins_.end(),
        [&](const auto &candidate) { return candidate.address == address; });
    if (origin != source_origins_.end()) {
        long begin = 0, end = 0;
        source_->GetSelection(&begin, &end);
        const bool already_on_line = begin >= origin->begin && begin <= origin->end && end <= origin->end;
        if (!already_on_line) source_->SetSelection(origin->begin, origin->begin);
        source_->ShowPosition(origin->begin);
    }
    updating_ = was_updating;
    update_variable_actions();
}
std::vector<std::pair<long, long>> PseudocodeView::variable_occurrences(std::size_t row) const {
    std::vector<std::pair<long, long>> result;
    if (row >= variable_links_.size()) return result;
    const auto word = text(variable_links_[row].display);
    if (word.empty() || word.Contains('\n') || word.Contains('\r')) return result;
    const auto value = source_->GetValue();
    const auto limit = std::min<std::size_t>(value.length(), 1024 * 1024);
    const auto identifier = [](wxUniChar ch) {
        const auto c = ch.GetValue();
        return c == '_' || (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c >= 128;
    };
    if (!identifier(word[0]) || (word[0] >= '0' && word[0] <= '9') ||
        std::any_of(word.begin(), word.end(), [&](wxUniChar ch) { return !identifier(ch); })) return result;
    std::size_t i = 0;
    long column = 0, line = 0;
    bool line_comment = false, block_comment = false, escaped = false;
    wxUniChar quote(0);
    const auto advance = [&](std::size_t count) {
        for (std::size_t n = 0; n < count && i < limit; ++n, ++i)
            if (value[i] == '\n') { ++line; column = 0; line_comment = false; }
            else ++column;
    };
    while (i < limit && result.size() < 65536) {
        const auto ch = value[i];
        const auto next = i + 1 < limit ? value[i + 1] : wxUniChar(0);
        if (line_comment) { advance(1); continue; }
        if (block_comment) {
            if (ch == '*' && next == '/') { block_comment = false; advance(2); }
            else advance(1);
            continue;
        }
        if (quote != wxUniChar(0)) {
            if (!escaped && ch == quote) quote = wxUniChar(0);
            if (!escaped && ch == '\\') escaped = true; else escaped = false;
            advance(1); continue;
        }
        if (ch == '/' && next == '/') { line_comment = true; advance(2); continue; }
        if (ch == '/' && next == '*') { block_comment = true; advance(2); continue; }
        if (ch == '"' || ch == '\'') { quote = ch; escaped = false; advance(1); continue; }
        if (ch == word[0] && word.length() <= limit - i && value.Mid(i, word.length()) == word &&
            (!i || !identifier(value[i - 1])) && (i + word.length() == value.length() || !identifier(value[i + word.length()]))) {
            // Text-control positions are native positions, including MSW CRLF.
            const auto begin = source_->XYToPosition(column, line);
            const auto end = source_->XYToPosition(column + static_cast<long>(word.length()), line);
            if (begin >= 0 && end > begin) result.emplace_back(begin, end);
            advance(word.length());
        } else advance(1);
    }
    return result;
}
void PseudocodeView::source_selection_changed() {
    if (!model_ready_ || updating_) return;
    long begin = 0, end = 0;
    source_->GetSelection(&begin, &end);
    auto word = source_->GetStringSelection();
    if (begin == end) {
        long column = 0, line = 0;
        if (source_->PositionToXY(begin, &column, &line)) {
            const auto value = source_->GetLineText(line);
            const auto identifier = [](wxUniChar ch) {
                const auto c = ch.GetValue();
                return c == '_' || (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c >= 128;
            };
            auto first = std::min<std::size_t>(static_cast<std::size_t>(std::max(0L, column)), value.length());
            auto last = first;
            while (first && identifier(value[first - 1])) --first;
            while (last < value.length() && identifier(value[last])) ++last;
            word = value.Mid(first, last - first);
        }
    }
    selected_variable_.reset();
    bool ambiguous = false;
    for (std::size_t i = 0; i < variable_links_.size(); ++i)
        if (!word.empty() && text(variable_links_[i].display) == word) {
            const auto occurrences = variable_occurrences(i);
            if (std::none_of(occurrences.begin(), occurrences.end(), [&](const auto &range) {
                return begin == end ? begin >= range.first && begin <= range.second : begin == range.first && end == range.second;
            })) continue;
            if (selected_variable_) { selected_variable_.reset(); ambiguous = true; break; }
            selected_variable_ = i;
        }
    updating_ = true;
    variables_list_->SetItemState(-1, 0, wxLIST_STATE_SELECTED | wxLIST_STATE_FOCUSED);
    if (selected_variable_)
        variables_list_->SetItemState(static_cast<long>(*selected_variable_), wxLIST_STATE_SELECTED, wxLIST_STATE_SELECTED);
    updating_ = false;
    update_variable_actions();
    if (ambiguous) variable_status_->SetLabel("Ambiguous name; choose an SSA identity in the variable table");
    if (const auto *origin = source_origin_at(begin, end); origin) {
        current_instruction_ = origin->address;
        navigate_to(Location{origin->address});
    }
}
void PseudocodeView::select_variable(std::size_t row, bool follow) {
    if (!model_ready_ || row >= variable_links_.size()) return;
    selected_variable_ = row;
    const auto occurrences = variable_occurrences(row);
    if (!occurrences.empty()) {
        source_->SetSelection(occurrences.front().first, occurrences.front().second);
        source_->ShowPosition(occurrences.front().first);
    }
    update_variable_actions();
    if (follow) navigate_to(variable_links_[row].address);
}
const PseudocodeVariableEdit *PseudocodeView::editable_variable() const {
    if (!model_ready_ || !selected_variable_ || *selected_variable_ >= variable_links_.size()) return nullptr;
    const auto editable = variable_links_[*selected_variable_].editable;
    return editable && *editable < variables_.size() ? &variables_[*editable] : nullptr;
}
void PseudocodeView::update_variable_actions() {
    const bool pseudocode_available = model_ready_ && !source_->GetValue().empty();
    copy_pseudocode_->Enable(pseudocode_available);
    save_pseudocode_->Enable(pseudocode_available);
    const auto *link = model_ready_ && selected_variable_ && *selected_variable_ < variable_links_.size()
                           ? &variable_links_[*selected_variable_] : nullptr;
    definition_->Enable(link != nullptr);
    definition_->SetLabel(link && !link->editable ? "Go to origin" : "Go to definition");
    const bool editable = project_ && project_->state && project_->mode == database::ProjectMode::read_write && submit_ && editable_variable();
    rename_variable_->Enable(editable);
    assign_type_->Enable(editable);
    previous_use_->Disable(); next_use_->Disable();
    if (!link) { variable_status_->SetLabel("Select a unique variable in source or the table"); return; }
    long begin = 0, end = 0;
    source_->GetSelection(&begin, &end);
    const auto occurrences = variable_occurrences(*selected_variable_);
    previous_use_->Enable(std::any_of(occurrences.begin(), occurrences.end(), [&](const auto &range) { return range.second <= begin; }));
    next_use_->Enable(std::any_of(occurrences.begin(), occurrences.end(), [&](const auto &range) { return range.first >= end; }));
    if (link->function_entry_collision)
        variable_status_->SetLabel("Read-only: function entry also stores the function name/prototype");
    else if (link->shared_origin)
        variable_status_->SetLabel("Read-only: multiple variables share instruction origin " + location_text(link->address));
    else
        variable_status_->SetLabel(text(link->token) + (link->editable ? " defined at " : " origin ") + location_text(link->address));
}
void PseudocodeView::go_to_definition() {
    if (model_ready_ && selected_variable_ && *selected_variable_ < variable_links_.size())
        navigate_to(variable_links_[*selected_variable_].address);
}
void PseudocodeView::move_occurrence(bool next) {
    if (!model_ready_ || !selected_variable_ || *selected_variable_ >= variable_links_.size()) return;
    long begin = 0, end = 0;
    source_->GetSelection(&begin, &end);
    const auto occurrences = variable_occurrences(*selected_variable_);
    std::optional<std::pair<long, long>> destination;
    if (next) {
        const auto found = std::find_if(occurrences.begin(), occurrences.end(), [&](const auto &range) { return range.first >= end; });
        if (found != occurrences.end()) destination = *found;
    } else {
        const auto found = std::find_if(occurrences.rbegin(), occurrences.rend(), [&](const auto &range) { return range.second <= begin; });
        if (found != occurrences.rend()) destination = *found;
    }
    if (destination) { source_->SetSelection(destination->first, destination->second); source_->ShowPosition(destination->first); }
    update_variable_actions();
}

namespace {
std::string utf8(const wxString &value) {
    const auto encoded = value.utf8_str();
    return {encoded.data(), encoded.length()};
}
std::optional<wxString> ask(PseudocodeView &view, const wxString &title, const wxString &label,
                            const wxString &initial, bool multiline) {
    if (view.prompt) return view.prompt(title, initial, multiline);
    wxTextEntryDialog dialog(&view, label, title, initial, wxOK | wxCANCEL | (multiline ? wxTE_MULTILINE : 0));
    if (dialog.ShowModal() != wxID_OK) return {};
    return dialog.GetValue();
}
}
void PseudocodeView::rename_function() {
    if (!function_ || !project_ || !submit_) return;
    const auto at = function_->entry;
    const auto submit = submit_;
    const auto current = text(presentation_name(*project_, function_->entry));
    const auto value = ask(*this, "Rename function", "Function name:", current, false);
    if (value) submit(Rename{at, utf8(*value)});
}
void PseudocodeView::rename_local() {
    const auto row = stack_slots_->GetNextItem(-1, wxLIST_NEXT_ALL, wxLIST_STATE_SELECTED);
    if (row < 0 || static_cast<std::size_t>(row) >= stack_access_rows_.size() ||
        static_cast<std::size_t>(row) >= stack_access_editable_.size() || !stack_access_editable_[static_cast<std::size_t>(row)] ||
        !project_ || !submit_) return;
    const auto at = stack_access_rows_[static_cast<std::size_t>(row)];
    const auto submit = submit_;
    const auto current = text(presentation_name(*project_, at));
    const auto value = ask(*this, "Rename local", "Local name (stored at its first stack access):", current, false);
    if (value) {
        const auto index = static_cast<std::size_t>(row);
        if (index < stack_access_sites_.size() && !stack_access_sites_[index].empty())
            submit(RenameStackLocal{stack_access_sites_[index], utf8(current), utf8(*value)});
        else
            submit(Rename{at, utf8(*value)});
    }
}
void PseudocodeView::comment_local() {
    const auto row = stack_slots_->GetNextItem(-1, wxLIST_NEXT_ALL, wxLIST_STATE_SELECTED);
    if (row < 0 || static_cast<std::size_t>(row) >= stack_access_rows_.size() ||
        static_cast<std::size_t>(row) >= stack_access_editable_.size() || !stack_access_editable_[static_cast<std::size_t>(row)] ||
        !project_ || !submit_) return;
    const auto at = stack_access_rows_[static_cast<std::size_t>(row)];
    const auto submit = submit_;
    const auto annotation = annotation_at(*project_, at);
    const auto value = ask(*this, "Comment local", "Comment for this stack local:",
                           annotation ? text(annotation->comment) : wxString{}, true);
    if (value) submit(Comment{at, utf8(*value)});
}
void PseudocodeView::edit_comment() {
    const auto row = addresses_->GetNextItem(-1, wxLIST_NEXT_ALL, wxLIST_STATE_SELECTED);
    if (row < 0 || static_cast<std::size_t>(row) >= rows_.size() || !project_ || !submit_) return;
    const auto at = rows_[static_cast<std::size_t>(row)];
    const auto submit = submit_;
    const auto annotation = annotation_at(*project_, at);
    const auto value = ask(*this, "Comment instruction", "Comment:",
                           annotation ? text(annotation->comment) : wxString{}, true);
    if (value) submit(Comment{at, utf8(*value)});
}

void PseudocodeView::rename_variable() {
    if (!project_ || !submit_) return;
    const auto selection = source_->GetStringSelection();
    if (!selection.empty() && (!selected_variable_ || *selected_variable_ >= variable_links_.size() ||
        text(variable_links_[*selected_variable_].display) != selection)) source_selection_changed();
    const auto *match = editable_variable();
    if (!match) return;
    const auto at = match->definition;
    const auto submit = submit_;
    const auto value = ask(*this, "Rename pseudocode variable", "Variable name:", text(match->display), false);
    if (value) {
        if (!match->access_sites.empty())
            submit(RenameStackLocal{match->access_sites, match->display, utf8(*value)});
        else
            submit(Rename{at, utf8(*value)});
    }
}

void PseudocodeView::assign_variable_type() {
    if (!project_ || !project_->state || !submit_) return;
    const auto selection = source_->GetStringSelection();
    if (!selection.empty() && (!selected_variable_ || *selected_variable_ >= variable_links_.size() ||
        text(variable_links_[*selected_variable_].display) != selection)) source_selection_changed();
    const auto *match = editable_variable();
    if (!match) return;
    const auto at = match->definition;
    const auto submit = submit_;
    const auto state = project_->state;
    const auto *assigned = type_assignment(*project_, match->definition);
    if (!assigned && !match->access_sites.empty())
        for (const auto address : match->access_sites)
            if ((assigned = type_assignment(*project_, address))) break;
    const auto assigned_id = assigned ? std::optional<std::uint64_t>(assigned->type_id) : std::nullopt;
    const auto *current = assigned ? type_definition(*project_, assigned->type_id) : nullptr;
    const auto initial = current ? current->name : std::string{};
    const auto value = ask(*this, "Assign pseudocode variable type",
                           "Type name from the project (blank removes an assignment):", text(initial), false);
    if (!value) return;
    const auto name = utf8(*value);
    if (name.empty()) {
        if (assigned_id) {
            if (!match->access_sites.empty())
                submit(AssignStackLocalType{match->access_sites, assigned_id, *assigned_id, true});
            else
                submit(AssignType{at, *assigned_id, true});
        }
        return;
    }
    const auto found = std::find_if(state->user->types.begin(), state->user->types.end(),
                                    [&](const auto &type) { return type.name == name; });
    if (found != state->user->types.end()) {
        if (!match->access_sites.empty())
            submit(AssignStackLocalType{match->access_sites, assigned_id, found->id, false});
        else
            submit(AssignType{at, found->id, false});
    }
}

} // namespace hexlab::desktop
