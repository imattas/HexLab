#include "hexlab/decompiler/decompiler.hpp"

#include <algorithm>
#include <iomanip>
#include <map>
#include <set>
#include <sstream>
#include <type_traits>

namespace hexlab::decompiler {
namespace {
ValueType integer_type(std::uint16_t bits) { return {TypeKind::integer, bits, false}; }

ExpressionPtr reg_expr(RegisterOperand reg) {
    return std::make_shared<Expression>(Expression{integer_type(reg.width), RegisterValue{reg}});
}
ExpressionPtr constant_expr(std::uint64_t value, std::uint16_t bits) {
    return std::make_shared<Expression>(Expression{integer_type(bits), ConstantValue{value, integer_type(bits)}});
}
ExpressionPtr unknown_expr(std::string name, std::uint16_t bits = 0) {
    return std::make_shared<Expression>(Expression{integer_type(bits), UnknownValue{std::move(name)}});
}

std::string register_name(RegisterOperand reg) {
    if (reg.bank == RegisterBank::flags || reg.bank == RegisterBank::arm_flags)
        return "flags";
    if (reg.bank == RegisterBank::ip)
        return "ip";
    if (reg.bank == RegisterBank::segment)
        return "seg" + std::to_string(reg.index);
    return "r" + std::to_string(reg.index);
}
std::string register_name(RegisterOperand reg, std::optional<std::uint32_t> version) {
    auto name = register_name(reg);
    if (version) name += "_" + std::to_string(*version);
    return name;
}

ExpressionPtr memory_expr(const MemoryOperand &memory) {
    MemoryValue value;
    value.type = integer_type(memory.data_width);
    value.base = memory.base;
    value.index = memory.index;
    value.scale = memory.scale;
    value.displacement = memory.displacement;
    value.absolute = memory.resolved_address;
    return std::make_shared<Expression>(Expression{value.type, std::move(value)});
}

ExpressionPtr memory_expr(const ArmMemoryOperand &memory) {
    MemoryValue value;
    value.type = integer_type(memory.data_width);
    value.base = memory.base;
    value.absolute = memory.resolved_address;
    if (const auto *offset = std::get_if<std::uint32_t>(&memory.offset)) {
        value.displacement = memory.add ? static_cast<std::int64_t>(*offset)
                                        : -static_cast<std::int64_t>(*offset);
    } else {
        const auto &shifted = std::get<ArmShiftedRegisterOperand>(memory.offset);
        value.index = shifted.source;
        value.index_add = memory.add;
        value.index_shift = shifted.shift == ArmShift::lsl ? "lsl" : shifted.shift == ArmShift::lsr ? "lsr"
                           : shifted.shift == ArmShift::asr ? "asr" : "ror";
        value.index_shift_amount = shifted.amount;
        // Register-controlled shifts and post-index/writeback addressing are
        // retained as an explicit unknown because this IR has no side-effect
        // statement for the base register update yet.
        if (shifted.amount_register) return unknown_expr("arm-register-shift-amount", memory.data_width);
    }
    if (!memory.pre_index || memory.writeback)
        return unknown_expr("arm-memory-writeback", memory.data_width);
    return std::make_shared<Expression>(Expression{value.type, std::move(value)});
}

ExpressionPtr operand_expr(const Operand &operand) {
    return std::visit([](const auto &value) -> ExpressionPtr {
        using T = std::decay_t<decltype(value)>;
        if constexpr (std::is_same_v<T, RegisterOperand>) {
            return reg_expr(value);
        } else if constexpr (std::is_same_v<T, ImmediateOperand>) {
            return constant_expr(value.value, value.effective_width);
        } else if constexpr (std::is_same_v<T, RelativeOperand>) {
            return constant_expr(static_cast<std::uint64_t>(value.displacement), value.effective_width);
        } else if constexpr (std::is_same_v<T, ThumbRelativeOperand>) {
            return constant_expr(static_cast<std::uint64_t>(value.displacement), value.encoded_width);
        } else if constexpr (std::is_same_v<T, MemoryOperand>) {
            return memory_expr(value);
        } else if constexpr (std::is_same_v<T, ArmMemoryOperand>) {
            return memory_expr(value);
        } else if constexpr (std::is_same_v<T, ArmShiftedRegisterOperand>) {
            auto source = reg_expr(value.source);
            const auto operation = value.shift == ArmShift::lsl ? "lsl" : value.shift == ArmShift::lsr ? "lsr"
                                  : value.shift == ArmShift::asr ? "asr" : "ror";
            if (value.amount_register)
                return std::make_shared<Expression>(Expression{integer_type(value.source.width),
                    BinaryValue{operation, source, reg_expr(*value.amount_register)}});
            return std::make_shared<Expression>(Expression{integer_type(value.source.width),
                UnaryValue{std::string(operation) + "_" + std::to_string(value.amount), source}});
        } else if constexpr (std::is_same_v<T, ArmRegisterListOperand>) {
            return unknown_expr("arm-register-list", 32);
        } else if constexpr (std::is_same_v<T, FarPointerOperand>) {
            return constant_expr((std::uint64_t(value.selector) << 32) | value.offset, value.offset_width + 16);
        } else {
            return unknown_expr("far-memory", value.offset_width);
        }
    }, operand);
}

bool is_memory(const Operand &operand) {
    return std::holds_alternative<MemoryOperand>(operand) || std::holds_alternative<ArmMemoryOperand>(operand);
}

bool is_load(Opcode opcode) {
    switch (opcode) {
    case Opcode::mov: case Opcode::movzx: case Opcode::movsx: case Opcode::movsxd:
    case Opcode::a64_ldr: case Opcode::a64_ldrb: case Opcode::a64_ldrh:
    case Opcode::a32_ldr: case Opcode::a32_ldrb: case Opcode::a32_ldrh:
    case Opcode::a32_ldrsb: case Opcode::a32_ldrsh: return true;
    default: return false;
    }
}

bool is_store(Opcode opcode) {
    switch (opcode) {
    case Opcode::mov: case Opcode::a64_str: case Opcode::a64_strb: case Opcode::a64_strh:
    case Opcode::a32_str: case Opcode::a32_strb: case Opcode::a32_strh: return true;
    default: return false;
    }
}
std::optional<RegisterOperand> as_register(const Operand &operand) {
    if (const auto *reg = std::get_if<RegisterOperand>(&operand))
        return *reg;
    return {};
}

std::string operation_name(Opcode opcode) {
    switch (opcode) {
    case Opcode::add: case Opcode::a64_add: case Opcode::a32_add: return "add";
    case Opcode::sub: case Opcode::a64_sub: case Opcode::a32_sub: return "sub";
    case Opcode::bit_and: case Opcode::a32_and: return "and";
    case Opcode::bit_or: case Opcode::a32_orr: return "or";
    case Opcode::bit_xor: case Opcode::a32_eor: return "xor";
    case Opcode::imul: return "mul";
    case Opcode::shl: return "shl";
    case Opcode::shr: return "shr";
    case Opcode::sar: return "sar";
    case Opcode::cmp: case Opcode::a32_cmp: return "cmp";
    case Opcode::test: case Opcode::a32_tst: return "test";
    case Opcode::mov: case Opcode::a32_mov: return "mov";
    case Opcode::lea: return "lea";
    case Opcode::call: case Opcode::a64_bl: case Opcode::a64_blr: case Opcode::a32_bl: case Opcode::a32_blx:
    case Opcode::t32_bl: case Opcode::t32_blx: return "call";
    case Opcode::jmp: case Opcode::a64_b: case Opcode::a32_b: case Opcode::t32_b: return "goto";
    case Opcode::ret: case Opcode::a64_ret: return "return";
    case Opcode::nop: case Opcode::a64_nop: case Opcode::a32_nop: case Opcode::t32_nop: return "nop";
    default: return "opcode_" + std::to_string(static_cast<unsigned>(opcode));
    }
}

bool is_binary(Opcode opcode) {
    switch (opcode) {
    case Opcode::add: case Opcode::bit_or: case Opcode::adc: case Opcode::sbb: case Opcode::bit_and:
    case Opcode::sub: case Opcode::bit_xor: case Opcode::cmp: case Opcode::test: case Opcode::imul:
    case Opcode::rol: case Opcode::ror: case Opcode::rcl: case Opcode::rcr: case Opcode::shl: case Opcode::shr:
    case Opcode::sar: case Opcode::a64_add: case Opcode::a64_adds: case Opcode::a64_sub: case Opcode::a64_subs:
    case Opcode::a32_and: case Opcode::a32_eor: case Opcode::a32_sub: case Opcode::a32_rsb:
    case Opcode::a32_add: case Opcode::a32_adc: case Opcode::a32_sbc: case Opcode::a32_rsc:
    case Opcode::a32_tst: case Opcode::a32_teq: case Opcode::a32_cmp: case Opcode::a32_cmn:
    case Opcode::a32_orr: return true;
    default: return false;
    }
}

Statement lift_instruction(const Instruction &instruction, std::vector<std::string> &diagnostics) {
    std::vector<ExpressionPtr> operands;
    operands.reserve(instruction.operands.size());
    for (const auto &operand : instruction.operands)
        operands.push_back(operand_expr(operand));

    if (instruction.opcode == Opcode::ret || instruction.opcode == Opcode::a64_ret) {
        return Return{operands.empty() ? ExpressionPtr{} : operands.front()};
    }
    if (instruction.flow == FlowKind::call || operation_name(instruction.opcode) == "call") {
        ExpressionPtr indirect;
        if (instruction.direct_target || operands.empty()) {
            indirect.reset();
        } else {
            indirect = operands.front();
        }
        return Call{instruction.direct_target, std::move(indirect)};
    }
    if (instruction.flow == FlowKind::conditional_branch || instruction.flow == FlowKind::jump ||
        instruction.opcode == Opcode::a64_b_cond || instruction.opcode == Opcode::a64_cbz ||
        instruction.opcode == Opcode::a64_cbnz || instruction.opcode == Opcode::a64_tbz ||
        instruction.opcode == Opcode::a64_tbnz || instruction.opcode == Opcode::a32_b ||
        instruction.opcode == Opcode::t32_b || instruction.opcode == Opcode::t32_cbz ||
        instruction.opcode == Opcode::t32_cbnz) {
        const bool conditional = instruction.flow == FlowKind::conditional_branch ||
            instruction.opcode == Opcode::a64_b_cond || instruction.opcode == Opcode::a64_cbz ||
            instruction.opcode == Opcode::a64_cbnz || instruction.opcode == Opcode::a64_tbz ||
            instruction.opcode == Opcode::a64_tbnz || instruction.opcode == Opcode::t32_cbz ||
            instruction.opcode == Opcode::t32_cbnz;
        const std::string condition = conditional ? "condition_" + std::to_string(instruction.condition) : "true";
        return Branch{condition, instruction.direct_target, {}};
    }

    if (instruction.opcode == Opcode::nop || instruction.opcode == Opcode::a64_nop ||
        instruction.opcode == Opcode::a32_nop || instruction.opcode == Opcode::t32_nop)
        return Intrinsic{"nop", {}};

    if (!operands.empty() && as_register(instruction.operands.front())) {
        const auto destination = *as_register(instruction.operands.front());
        if (operands.size() == 2) {
            if (instruction.opcode == Opcode::mov || instruction.opcode == Opcode::a32_mov) {
                return Assign{destination, operands[1]};
            }
            if (instruction.opcode == Opcode::movzx || instruction.opcode == Opcode::movsx ||
                instruction.opcode == Opcode::movsxd) {
                const auto operation = instruction.opcode == Opcode::movzx ? "zext" : "sext";
                auto value = std::make_shared<Expression>(Expression{
                    integer_type(destination.width), UnaryValue{operation, operands[1]}});
                return Assign{destination, std::move(value)};
            }
            if (is_binary(instruction.opcode)) {
                auto left = reg_expr(destination);
                auto value = std::make_shared<Expression>(Expression{
                    integer_type(destination.width), BinaryValue{operation_name(instruction.opcode), left, operands[1]}});
                if (instruction.opcode == Opcode::cmp || instruction.opcode == Opcode::test ||
                    instruction.opcode == Opcode::a32_cmp || instruction.opcode == Opcode::a32_tst)
                    return Intrinsic{operation_name(instruction.opcode), {left, operands[1]}};
                return Assign{destination, std::move(value)};
            }
            if (is_load(instruction.opcode) && is_memory(instruction.operands[1]))
                return Assign{destination, operands[1]};
        }
        if (operands.size() == 1 && (instruction.opcode == Opcode::inc || instruction.opcode == Opcode::dec)) {
            auto value = std::make_shared<Expression>(Expression{integer_type(destination.width),
                BinaryValue{instruction.opcode == Opcode::inc ? "add" : "sub", reg_expr(destination), constant_expr(1, destination.width)}});
            return Assign{destination, std::move(value)};
        }
    }
    if (operands.size() == 2 && is_store(instruction.opcode) && is_memory(instruction.operands.front()))
        return Store{operands[0], operands[1]};

    diagnostics.push_back("instruction at 0x" + [&] { std::ostringstream s; s << std::hex << instruction.address.offset; return s.str(); }() +
                          " retained as an explicit intrinsic: " + operation_name(instruction.opcode));
    return Intrinsic{operation_name(instruction.opcode), std::move(operands)};
}

std::string expression_text(const Expression &expression);
std::string binary_symbol(const std::string &operation) {
    if (operation == "add") return "+";
    if (operation == "sub") return "-";
    if (operation == "mul") return "*";
    if (operation == "and") return "&";
    if (operation == "or") return "|";
    if (operation == "xor") return "^";
    if (operation == "shl") return "<<";
    if (operation == "shr") return ">>";
    if (operation == "sar") return ">>";
    return operation;
}
std::string address_text(const MemoryValue &memory) {
    if (memory.absolute) {
        std::ostringstream out;
        out << "0x" << std::hex << memory.absolute->offset;
        return out.str();
    }
    std::ostringstream out;
    bool has_term = false;
    if (memory.base) { out << register_name(*memory.base, memory.base_version); has_term = true; }
    if (memory.index) {
        if (has_term) out << (memory.index_add ? " + " : " - ");
        if (!memory.index_shift.empty()) {
            const auto op = memory.index_shift == "lsl" ? "<<" : memory.index_shift == "lsr" || memory.index_shift == "asr"
                              ? ">>" : "ror";
            if (memory.index_shift == "ror") out << "ror(" << register_name(*memory.index, memory.index_version)
                                                    << ", " << unsigned(memory.index_shift_amount) << ')';
            else out << '(' << register_name(*memory.index, memory.index_version) << ' ' << op << ' '
                     << unsigned(memory.index_shift_amount) << ')';
        } else {
            out << register_name(*memory.index, memory.index_version);
            if (memory.scale > 1) out << " * " << unsigned(memory.scale);
        }
        has_term = true;
    }
    if (memory.displacement || !has_term) {
        if (has_term && memory.displacement > 0) out << " + ";
        if (memory.displacement < 0) out << " - " << std::uint64_t(-(memory.displacement + 1)) + 1;
        else out << (has_term ? "0x" : "0x") << std::hex << std::uint64_t(memory.displacement);
    }
    return out.str();
}
std::string expression_text(const Expression &expression) {
    return std::visit([&](const auto &value) -> std::string {
        using T = std::decay_t<decltype(value)>;
        if constexpr (std::is_same_v<T, RegisterValue>) {
            return register_name(value.reg, value.version);
        } else if constexpr (std::is_same_v<T, ConstantValue>) {
            std::ostringstream out; out << "0x" << std::hex << value.value; return out.str();
        } else if constexpr (std::is_same_v<T, MemoryValue>) {
            return "*[(" + address_text(value) + ")]";
        } else if constexpr (std::is_same_v<T, UnaryValue>) {
            return value.operation + "(" + expression_text(*value.operand) + ")";
        } else if constexpr (std::is_same_v<T, BinaryValue>) {
            return "(" + expression_text(*value.left) + " " + binary_symbol(value.operation) + " " + expression_text(*value.right) + ")";
        } else {
            return "unknown(" + value.description + ")";
        }
    }, expression.value);
}

std::string address_label(Address address) {
    std::ostringstream out;
    out << "loc_" << std::hex << address.offset;
    return out.str();
}
std::string block_label(const LiftedFunction &function, BlockId id) {
    const auto found = std::find_if(function.blocks.begin(), function.blocks.end(),
                                    [&](const auto &block) { return block.id == id; });
    return found == function.blocks.end() ? "loc_unknown" : address_label(found->begin);
}
} // namespace

Result<LiftedFunction> lift_function(const FunctionRecord &function, const FunctionSnapshot &snapshot) {
    std::map<std::uint64_t, std::shared_ptr<const BasicBlock>> available;
    for (const auto &block : snapshot.blocks) {
        if (!block)
            return Error{ErrorCode::invalid_argument, "function snapshot contains a null basic block"};
        if (!available.emplace(block->id.value, block).second)
            return Error{ErrorCode::invalid_argument, "function snapshot contains duplicate basic block IDs"};
    }
    LiftedFunction result{function.id, function.entry, {}, {}};
    std::set<std::uint64_t> seen;
    for (const auto id : function.blocks) {
        if (!seen.insert(id.value).second)
            return Error{ErrorCode::invalid_argument, "function record contains duplicate basic block IDs"};
        const auto found = available.find(id.value);
        if (found == available.end())
            return Error{ErrorCode::invalid_argument, "function block is absent from the analysis snapshot"};
        const auto &source = *found->second;
        LiftedBlock block{id, source.begin, {}, source.successors};
        for (const auto &fact : source.instructions) {
            if (!fact)
                return Error{ErrorCode::invalid_argument, "basic block contains a null instruction fact"};
            auto statement = lift_instruction(fact->instruction, result.diagnostics);
            if (auto *branch = std::get_if<Branch>(&statement)) {
                for (const auto &successor : source.successors) {
                    if (!successor.target)
                        continue;
                    if (successor.kind == BlockEdgeKind::conditional_true || successor.kind == BlockEdgeKind::jump)
                        branch->true_target = successor.target;
                    else if (successor.kind == BlockEdgeKind::conditional_false || successor.kind == BlockEdgeKind::fallthrough)
                        branch->false_target = successor.target;
                }
            }
            block.instructions.push_back({{fact->instruction.address, fact->id}, std::move(statement)});
        }
        result.blocks.push_back(std::move(block));
    }
    if (result.blocks.empty())
        return Error{ErrorCode::invalid_argument, "function has no recovered blocks"};
    return result;
}

std::string format_pseudocode(const LiftedFunction &function) {
    std::ostringstream out;
    out << "function " << address_label(function.entry) << "() {\n";
    for (const auto &block : function.blocks) {
        out << address_label(block.begin) << ":\n";
        for (const auto &phi : block.phis) {
            out << "    " << register_name(phi.destination, phi.version) << " = phi(";
            for (std::size_t i = 0; i < phi.inputs.size(); ++i) {
                if (i) out << ", ";
                out << block_label(function, phi.inputs[i].predecessor) << ": "
                    << register_name(phi.destination, phi.inputs[i].version);
            }
            out << ");\n";
        }
        for (const auto &instruction : block.instructions) {
            out << "    ";
            std::visit([&](const auto &statement) {
                using T = std::decay_t<decltype(statement)>;
                if constexpr (std::is_same_v<T, Assign>)
                    out << register_name(statement.destination, statement.destination_version) << " = "
                        << expression_text(*statement.value) << ';';
                else if constexpr (std::is_same_v<T, Store>)
                    out << expression_text(*statement.address) << " = " << expression_text(*statement.value) << ';';
                else if constexpr (std::is_same_v<T, Call>) {
                    if (statement.direct_target) out << "call " << address_label(*statement.direct_target) << "();";
                    else if (statement.indirect_target) out << "call " << expression_text(*statement.indirect_target) << "();";
                    else out << "call unresolved();";
                } else if constexpr (std::is_same_v<T, Branch>) {
                    if (statement.condition == "true" && statement.true_target)
                        out << "goto " << address_label(*statement.true_target) << ';';
                    else if (statement.true_target) {
                        out << "if (" << statement.condition << ") goto " << address_label(*statement.true_target);
                        if (statement.false_target)
                            out << " else goto " << address_label(*statement.false_target);
                        out << ';';
                    }
                    else out << "branch unresolved;";
                } else if constexpr (std::is_same_v<T, Return>) {
                    out << "return";
                    if (statement.value) out << ' ' << expression_text(*statement.value);
                    out << ';';
                } else {
                    out << statement.name << '(';
                    for (std::size_t i = 0; i < statement.operands.size(); ++i) {
                        if (i) out << ", ";
                        out << expression_text(*statement.operands[i]);
                    }
                    out << ");";
                }
            }, instruction.statement);
            out << " // 0x" << std::hex << instruction.origin.address.offset << std::dec << '\n';
        }
    }
    out << "}\n";
    return out.str();
}

StructuredPseudocode format_structured_pseudocode(const LiftedFunction &function) {
    auto fallback = [&](std::string reason) {
        return StructuredPseudocode{format_pseudocode(function), true, std::move(reason)};
    };
    std::ostringstream out;
    auto emit_statement = [&](const LiftedInstruction &instruction, bool omit_branch, unsigned indent) {
        if (omit_branch && std::holds_alternative<Branch>(instruction.statement)) return;
        out << std::string(indent, ' ');
        std::visit([&](const auto &statement) {
            using T = std::decay_t<decltype(statement)>;
            if constexpr (std::is_same_v<T, Assign>) out << register_name(statement.destination, statement.destination_version)
                << " = " << expression_text(*statement.value) << ';';
            else if constexpr (std::is_same_v<T, Store>) out << expression_text(*statement.address) << " = "
                << expression_text(*statement.value) << ';';
            else if constexpr (std::is_same_v<T, Call>) {
                if (statement.direct_target) out << "call " << address_label(*statement.direct_target) << "();";
                else if (statement.indirect_target) out << "call " << expression_text(*statement.indirect_target) << "();";
                else out << "call unresolved();";
            } else if constexpr (std::is_same_v<T, Return>) {
                out << "return"; if (statement.value) out << ' ' << expression_text(*statement.value); out << ';';
            } else if constexpr (std::is_same_v<T, Intrinsic>) {
                out << statement.name << '(';
                for (std::size_t i = 0; i < statement.operands.size(); ++i) {
                    if (i) out << ", "; out << expression_text(*statement.operands[i]);
                }
                out << ");";
            } else out << "/* branch */";
        }, instruction.statement);
        out << " // 0x" << std::hex << instruction.origin.address.offset << std::dec << '\n';
    };
    auto emit_block = [&](const LiftedBlock &block, unsigned indent, bool omit_terminal_branch = false) {
        for (std::size_t i = 0; i < block.instructions.size(); ++i) {
            const bool omit = omit_terminal_branch && i + 1 == block.instructions.size() &&
                std::holds_alternative<Branch>(block.instructions[i].statement);
            emit_statement(block.instructions[i], omit, indent);
        }
    };
    auto find_block = [&](Address address) -> const LiftedBlock * {
        const auto found = std::find_if(function.blocks.begin(), function.blocks.end(),
            [&](const LiftedBlock &block) { return block.begin == address; });
        return found == function.blocks.end() ? nullptr : &*found;
    };
    auto terminal_conditional = [&](const LiftedBlock &block) -> const Branch * {
        if (block.instructions.empty() ||
            !std::holds_alternative<Branch>(block.instructions.back().statement)) return nullptr;
        const auto count = std::count_if(block.instructions.begin(), block.instructions.end(),
            [](const LiftedInstruction &item) { return std::holds_alternative<Branch>(item.statement); });
        const auto &branch = std::get<Branch>(block.instructions.back().statement);
        if (count != 1 || branch.condition == "true" || !branch.true_target || !branch.false_target ||
            *branch.true_target == *branch.false_target || block.successors.size() != 2) return nullptr;
        const bool has_true = std::any_of(block.successors.begin(), block.successors.end(), [&](const auto &edge) {
            return edge.kind == BlockEdgeKind::conditional_true && edge.target == branch.true_target;
        });
        const bool has_false = std::any_of(block.successors.begin(), block.successors.end(), [&](const auto &edge) {
            return (edge.kind == BlockEdgeKind::conditional_false || edge.kind == BlockEdgeKind::fallthrough) &&
                edge.target == branch.false_target;
        });
        return has_true && has_false ? &branch : nullptr;
    };
    auto contains_branch = [](const LiftedBlock &block) {
        return std::any_of(block.instructions.begin(), block.instructions.end(),
            [](const LiftedInstruction &instruction) { return std::holds_alternative<Branch>(instruction.statement); });
    };
    auto has_only_terminal_return = [](const LiftedBlock &block) {
        if (block.instructions.empty() || block.successors.size() != 0 ||
            !std::holds_alternative<Return>(block.instructions.back().statement)) return false;
        return std::none_of(block.instructions.begin(), block.instructions.end() - 1,
            [](const LiftedInstruction &instruction) {
                return std::holds_alternative<Branch>(instruction.statement) ||
                       std::holds_alternative<Return>(instruction.statement);
            });
    };
    auto contains_return = [](const LiftedBlock &block) {
        return std::any_of(block.instructions.begin(), block.instructions.end(),
            [](const LiftedInstruction &instruction) { return std::holds_alternative<Return>(instruction.statement); });
    };

    const auto *entry = find_block(function.entry);
    if (!entry) return fallback("function entry block is absent");

    // Recognize the small, unambiguous natural-loop forms before the acyclic
    // conditional structurer below. Keeping this deliberately narrow means a
    // graph with side exits, multiple latches, or nested control flow continues
    // to use the lossless label/goto representation.
    auto has_only_simple_statements = [&](const LiftedBlock &block) {
        std::size_t branches = 0;
        for (std::size_t i = 0; i < block.instructions.size(); ++i) {
            if (!std::holds_alternative<Branch>(block.instructions[i].statement)) continue;
            ++branches;
            if (i + 1 != block.instructions.size()) return false;
        }
        return branches <= 1;
    };
    auto has_unconditional_edge = [&](const LiftedBlock &block, Address target) {
        if (block.successors.size() != 1 || block.successors.front().target != std::optional<Address>{target})
            return false;
        if (block.instructions.empty() || !std::holds_alternative<Branch>(block.instructions.back().statement))
            return true;
        const auto &edge = std::get<Branch>(block.instructions.back().statement);
        return edge.condition == "true" && edge.true_target == std::optional<Address>{target} && !edge.false_target;
    };
    if (function.blocks.size() >= 4 && has_only_simple_statements(*entry) && entry->phis.empty() &&
        entry->successors.size() == 1 && entry->successors.front().target) {
        const auto *header = find_block(*entry->successors.front().target);
        const auto *condition = header ? terminal_conditional(*header) : nullptr;
        const auto *body_start = condition ? find_block(*condition->true_target) : nullptr;
        const auto *exit_block = condition ? find_block(*condition->false_target) : nullptr;
        std::vector<const LiftedBlock *> loop_body;
        std::set<std::uint64_t> loop_body_ids;
        bool loop_body_edges_valid = true;
        auto *body = body_start;
        while (body && body != header && body != entry && body != exit_block &&
               loop_body.size() < function.blocks.size() && loop_body_ids.insert(body->id.value).second &&
               body->phis.empty() && has_only_simple_statements(*body) &&
               body->successors.size() == 1 && body->successors.front().target) {
            const Address next_address = *body->successors.front().target;
            if (!has_unconditional_edge(*body, next_address)) {
                loop_body_edges_valid = false;
                break;
            }
            loop_body.push_back(body);
            if (next_address == header->begin) break;
            body = find_block(next_address);
        }
        const auto *latch = loop_body.empty() ? nullptr : loop_body.back();
        const bool closes_to_header = latch && latch->successors.size() == 1 &&
            latch->successors.front().target == std::optional<Address>{header->begin};
        if (header && condition && body_start && exit_block && latch && closes_to_header && loop_body_edges_valid &&
            header != entry && body_start != entry && exit_block != entry && body_start != header &&
            exit_block != header && exit_block != body_start &&
            header->instructions.size() == 1 && has_only_simple_statements(*header) &&
            has_unconditional_edge(*entry, header->begin) &&
            !contains_branch(*exit_block) && exit_block->phis.empty() && exit_block->successors.empty() &&
            has_only_terminal_return(*exit_block) &&
            std::all_of(function.blocks.begin(), function.blocks.end(), [&](const LiftedBlock &candidate) {
                return &candidate == entry || &candidate == header || &candidate == exit_block ||
                    loop_body_ids.contains(candidate.id.value);
            })) {
            std::vector<std::pair<std::string, std::string>> loop_phi_copies;
            bool valid_loop_phis = true;
            for (const auto &phi : header->phis) {
                if (phi.inputs.size() != 2) { valid_loop_phis = false; break; }
                const auto initial = std::find_if(phi.inputs.begin(), phi.inputs.end(), [&](const auto &input) {
                    return input.predecessor == entry->id;
                });
                const auto recurrent = std::find_if(phi.inputs.begin(), phi.inputs.end(), [&](const auto &input) {
                    return input.predecessor == latch->id;
                });
                if (initial == phi.inputs.end() || recurrent == phi.inputs.end()) { valid_loop_phis = false; break; }
                const auto destination = register_name(phi.destination, phi.version);
                loop_phi_copies.emplace_back(destination, register_name(phi.destination, initial->version));
                loop_phi_copies.emplace_back(destination, register_name(phi.destination, recurrent->version));
            }
            if (!valid_loop_phis) return fallback("loop header phi inputs do not match its preheader and back edge");
            out << "function " << address_label(function.entry) << "() {\n";
            emit_block(*entry, 4, true);
            for (std::size_t i = 0; i < loop_phi_copies.size(); i += 2)
                out << "    " << loop_phi_copies[i].first << " = " << loop_phi_copies[i].second << ";\n";
            out << "    while (" << condition->condition << ") {\n";
            emit_block(*header, 8, true);
            for (const auto *block : loop_body) emit_block(*block, 8, true);
            for (std::size_t i = 1; i < loop_phi_copies.size(); i += 2)
                out << "        " << loop_phi_copies[i].first << " = " << loop_phi_copies[i].second << ";\n";
            out << "    }\n";
            emit_block(*exit_block, 4);
            out << "}\n";
            return {out.str(), false, {}};
        }
    }
    if (function.blocks.size() == 3 && entry->successors.size() == 1 &&
        entry->successors.front().target && has_only_simple_statements(*entry)) {
        const auto *latch = find_block(*entry->successors.front().target);
        const auto *condition = latch ? terminal_conditional(*latch) : nullptr;
        if (latch && latch != entry && condition && latch->phis.empty() && entry->phis.empty()) {
            // The natural do-while edge may be either branch arm; identify the
            // non-loop edge as the sole exit and preserve the condition sense.
            const bool loops_on_true = condition->true_target == std::optional<Address>{entry->begin};
            const bool loops_on_false = condition->false_target == std::optional<Address>{entry->begin};
            const Address exit_address = loops_on_true ? *condition->false_target :
                                         loops_on_false ? *condition->true_target : Address{};
            const auto *exit_block = find_block(exit_address);
            const bool latch_is_linear = entry->successors.front().target == std::optional<Address>{latch->begin};
            if ((loops_on_true || loops_on_false) && latch_is_linear && exit_block && exit_block != entry &&
                exit_block != latch && has_unconditional_edge(*entry, latch->begin) &&
                has_only_simple_statements(*latch) && exit_block->phis.empty() &&
                exit_block->successors.empty() && has_only_terminal_return(*exit_block) &&
                std::all_of(function.blocks.begin(), function.blocks.end(), [&](const LiftedBlock &candidate) {
                    return &candidate == entry || &candidate == latch || &candidate == exit_block;
                })) {
                out << "function " << address_label(function.entry) << "() {\n";
                out << "    do {\n";
                emit_block(*entry, 8, true);
                emit_block(*latch, 8, true);
                out << "    } while (" << (loops_on_true ? condition->condition : "!(" + condition->condition + ")")
                    << ");\n";
                emit_block(*exit_block, 4);
                out << "}\n";
                return {out.str(), false, {}};
            }
        }
    }
    const auto *branch = terminal_conditional(*entry);
    if (!branch) return fallback("entry block lacks a unique terminal two-way conditional branch");
    if (!entry->phis.empty()) return fallback("entry block contains an unsupported phi node");
    const auto *true_start = find_block(*branch->true_target);
    const auto *false_start = find_block(*branch->false_target);
    if (!true_start || !false_start || true_start == false_start || true_start == entry || false_start == entry)
        return fallback("conditional targets do not identify distinct in-function blocks");

    // A terminating arm is the common `if (condition) return; next;` shape.
    const bool true_returns = has_only_terminal_return(*true_start);
    const bool false_returns = has_only_terminal_return(*false_start);
    if (function.blocks.size() == 3 && true_returns != false_returns &&
        ((true_returns && false_start->successors.empty()) ||
         (false_returns && true_start->successors.empty()))) {
        const bool return_on_true = true_returns;
        const auto *return_block = return_on_true ? true_start : false_start;
        const auto *continuation = return_on_true ? false_start : true_start;
        if (return_block->phis.empty() && continuation->phis.empty() && !contains_branch(*continuation) &&
            !contains_return(*continuation)) {
            out << "function " << address_label(function.entry) << "() {\n";
            emit_block(*entry, 4, true);
            out << "    if (" << (return_on_true ? branch->condition : "!(" + branch->condition + ")") << ") {\n";
            emit_block(*return_block, 8);
            out << "    }\n";
            emit_block(*continuation, 4);
            out << "}\n";
            return {out.str(), false, {}};
        }
    }

    auto trace = [&](const LiftedBlock *start) -> std::optional<std::vector<const LiftedBlock *>> {
        std::vector<const LiftedBlock *> path;
        std::set<std::uint64_t> visited;
        auto *current = start;
        while (current && path.size() <= function.blocks.size()) {
            if (!visited.insert(current->id.value).second) return {};
            path.push_back(current);
            if (current->successors.size() != 1 || !current->successors.front().target) break;
            current = find_block(*current->successors.front().target);
        }
        if (!current) return {};
        return path;
    };
    auto true_path = trace(true_start), false_path = trace(false_start);
    if (!true_path || !false_path) return fallback("conditional arm has a missing target or cycle");
    std::size_t true_join_index = 0, false_join_index = 0;
    bool found_join = false;
    for (std::size_t i = 0; i < true_path->size(); ++i) {
        for (std::size_t j = 0; j < false_path->size(); ++j) {
            if ((*true_path)[i] != (*false_path)[j]) continue;
            if (!found_join || i + j < true_join_index + false_join_index) {
                found_join = true;
                true_join_index = i;
                false_join_index = j;
            }
        }
    }
    if (!found_join) return fallback("conditional arms do not converge at a common post-dominator");
    const auto *join = (*true_path)[true_join_index];
    if (join == entry || true_join_index == 0 || false_join_index == 0 || !join->successors.empty() ||
        contains_branch(*join))
        return fallback("join block is empty of successors and control transfers only");
    std::vector<const LiftedBlock *> true_arm(true_path->begin(), true_path->begin() + true_join_index);
    std::vector<const LiftedBlock *> false_arm(false_path->begin(), false_path->begin() + false_join_index);
    std::set<std::uint64_t> accounted{entry->id.value, join->id.value};
    for (const auto *block : true_arm) accounted.insert(block->id.value);
    for (const auto *block : false_arm) accounted.insert(block->id.value);
    if (accounted.size() != function.blocks.size())
        return fallback("function contains blocks outside the single structured conditional region");
    if (std::any_of(true_arm.begin(), true_arm.end(), [](const auto *block) { return !block->phis.empty(); }) ||
        std::any_of(false_arm.begin(), false_arm.end(), [](const auto *block) { return !block->phis.empty(); }))
        return fallback("SSA phi nodes inside conditional arms are not supported");

    auto validate_arm = [&](const std::vector<const LiftedBlock *> &arm) {
        for (std::size_t i = 0; i < arm.size(); ++i) {
            const auto *block = arm[i];
            const auto *next = i + 1 < arm.size() ? arm[i + 1] : join;
            if (block->successors.size() != 1 || block->successors.front().target != std::optional<Address>{next->begin})
                return false;
            const auto branch_count = std::count_if(block->instructions.begin(), block->instructions.end(),
                [](const LiftedInstruction &item) { return std::holds_alternative<Branch>(item.statement); });
            if (branch_count == 0) continue;
            if (branch_count != 1 || !std::holds_alternative<Branch>(block->instructions.back().statement)) return false;
            const auto &edge_branch = std::get<Branch>(block->instructions.back().statement);
            if (edge_branch.condition != "true" || !edge_branch.true_target || edge_branch.false_target ||
                *edge_branch.true_target != next->begin) return false;
        }
        return true;
    };
    if (!validate_arm(true_arm) || !validate_arm(false_arm))
        return fallback("conditional arm contains a non-linear or unsupported control transfer");

    const auto *true_tail = true_arm.back();
    const auto *false_tail = false_arm.back();
    std::map<std::uint64_t, std::vector<std::pair<std::string, std::string>>> edge_copies;
    for (const auto &phi : join->phis) {
        if (phi.inputs.size() != 2)
            return fallback("join phi does not have exactly one input from each branch arm");
        const auto true_input = std::find_if(phi.inputs.begin(), phi.inputs.end(), [&](const auto &input) {
            return input.predecessor == true_tail->id;
        });
        const auto false_input = std::find_if(phi.inputs.begin(), phi.inputs.end(), [&](const auto &input) {
            return input.predecessor == false_tail->id;
        });
        if (true_input == phi.inputs.end() || false_input == phi.inputs.end())
            return fallback("join phi inputs do not match the final predecessor of each branch arm");
        const auto destination = register_name(phi.destination, phi.version);
        edge_copies[true_tail->id.value].emplace_back(destination, register_name(phi.destination, true_input->version));
        edge_copies[false_tail->id.value].emplace_back(destination, register_name(phi.destination, false_input->version));
    }

    out << "function " << address_label(function.entry) << "() {\n";
    emit_block(*entry, 4, true);
    out << "    if (" << branch->condition << ") {\n";
    for (const auto *block : true_arm) emit_block(*block, 8, true);
    for (const auto &[destination, source] : edge_copies[true_tail->id.value])
        out << "        " << destination << " = " << source << ";\n";
    out << "    } else {\n";
    for (const auto *block : false_arm) emit_block(*block, 8, true);
    for (const auto &[destination, source] : edge_copies[false_tail->id.value])
        out << "        " << destination << " = " << source << ";\n";
    out << "    }\n";
    emit_block(*join, 4);
    out << "}\n";
    return {out.str(), false, {}};
}
} // namespace hexlab::decompiler
