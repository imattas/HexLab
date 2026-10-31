#include "hexlab/decompiler/decompiler.hpp"
#include "hexlab/decompiler/dex_lifting.hpp"
#include "hexlab/decompiler/wasm_lifting.hpp"
#include "hexlab/decompiler/jvm_lifting.hpp"
#include "expression_type_context.hpp"
#include "hexlab/processors/riscv_semantics.hpp"
#include "hexlab/processors/x86_avx_semantics.hpp"
#include "hexlab/processors/x64_instruction_semantics.hpp"
#include "mips64_lifting.hpp"
#include "ppc_lifting.hpp"
#include "riscv_fp_lifting.hpp"
#include "hexlab/processors/m6502_semantics.hpp"

#include <algorithm>
#include <charconv>
#include <functional>
#include <iomanip>
#include <iterator>
#include <map>
#include <set>
#include <sstream>
#include <type_traits>

namespace hexlab::decompiler::detail {
namespace {
thread_local const ExpressionRegisterTypes *active_expression_types = nullptr;
ExpressionRegisterKey expression_register_key(RegisterOperand reg,
                                              std::optional<std::uint32_t> version) {
    return {static_cast<unsigned>(reg.bank), reg.index, reg.width, reg.high_byte,
            version.value_or(0), version.has_value()};
}
RegisterOperand x87_physical(RegisterOperand reg, std::uint8_t top) {
    if (reg.bank == RegisterBank::x87 && reg.index < 8)
        reg.index = static_cast<std::uint8_t>((top + reg.index) & 7);
    return reg;
}
ExpressionPtr remap_x87_expression(const ExpressionPtr &expression, std::uint8_t top) {
    if (!expression) return expression;
    auto copy = std::make_shared<Expression>(*expression);
    if (auto *reg = std::get_if<RegisterValue>(&copy->value)) {
        reg->reg = x87_physical(reg->reg, top);
    } else if (auto *memory = std::get_if<MemoryValue>(&copy->value)) {
        if (memory->base) memory->base = x87_physical(*memory->base, top);
        if (memory->index) memory->index = x87_physical(*memory->index, top);
    } else if (auto *unary = std::get_if<UnaryValue>(&copy->value)) {
        unary->operand = remap_x87_expression(unary->operand, top);
    } else if (auto *binary = std::get_if<BinaryValue>(&copy->value)) {
        binary->left = remap_x87_expression(binary->left, top);
        binary->right = remap_x87_expression(binary->right, top);
    }
    return copy;
}
void remap_x87_statement(Statement &statement, std::uint8_t top, std::uint8_t write_top) {
    std::visit([&](auto &node) {
        using T = std::decay_t<decltype(node)>;
        if constexpr (std::is_same_v<T, Assign>) {
            node.destination = x87_physical(node.destination, write_top);
            node.value = remap_x87_expression(node.value, top);
        } else if constexpr (std::is_same_v<T, Store>) {
            node.address = remap_x87_expression(node.address, top);
            node.value = remap_x87_expression(node.value, top);
        } else if constexpr (std::is_same_v<T, Call>) {
            node.indirect_target = remap_x87_expression(node.indirect_target, top);
            if (node.return_register) node.return_register = x87_physical(*node.return_register, top);
            for (auto &reg : node.register_writes) reg = x87_physical(reg, write_top);
            for (auto &reg : node.abi_upper_half_writes) reg = x87_physical(reg, top);
            for (auto &input : node.register_inputs) input.reg = x87_physical(input.reg, top);
        } else if constexpr (std::is_same_v<T, Branch>) {
            node.predicate = remap_x87_expression(node.predicate, top);
            node.indirect_target = remap_x87_expression(node.indirect_target, top);
        } else if constexpr (std::is_same_v<T, Return>) {
            node.value = remap_x87_expression(node.value, top);
        } else if constexpr (std::is_same_v<T, Intrinsic>) {
            for (auto &operand : node.operands) operand = remap_x87_expression(operand, top);
            for (auto &reg : node.register_writes) reg = x87_physical(reg, write_top);
            for (auto &value : node.register_output_values) value = remap_x87_expression(value, top);
        }
    }, statement);
}
void refine_x87_stack_writes(Statement &statement, const Instruction &instruction) {
    if (!instruction.x87_stack_delta) return;
    auto *intrinsic = std::get_if<Intrinsic>(&statement);
    if (!intrinsic) return;
    std::erase_if(intrinsic->register_writes,
        [](RegisterOperand reg) { return reg.bank == RegisterBank::x87; });
    const auto count = std::min(instruction.operands.size(), instruction.access.size());
    for (std::size_t i = 0; i < count; ++i) {
        if (instruction.access[i] == OperandAccess::read) continue;
        const auto *reg = std::get_if<RegisterOperand>(&instruction.operands[i]);
        if (reg && reg->bank == RegisterBank::x87 &&
            std::find(intrinsic->register_writes.begin(), intrinsic->register_writes.end(), *reg) ==
                intrinsic->register_writes.end())
            intrinsic->register_writes.push_back(*reg);
    }
    if (instruction.x87_stack_delta > 0) {
        const RegisterOperand new_top{RegisterBank::x87, 0, 80, false};
        if (std::find(intrinsic->register_writes.begin(), intrinsic->register_writes.end(), new_top) ==
            intrinsic->register_writes.end())
            intrinsic->register_writes.push_back(new_top);
    }
    if (instruction.mnemonic_override == "fld1" || instruction.mnemonic_override == "fldz") {
        const X87Binary80 literal = instruction.mnemonic_override == "fld1"
            ? X87Binary80{UINT64_C(0x8000000000000000), 0x3fff}
            : X87Binary80{};
        intrinsic->register_output_values.clear();
        for (const auto reg : intrinsic->register_writes) {
            if (reg.bank == RegisterBank::x87 && reg.index == 0) {
                intrinsic->register_output_values.push_back(std::make_shared<Expression>(Expression{
                    ValueType{TypeKind::floating, 80, false}, X87Binary80Value{literal}}));
            } else {
                intrinsic->register_output_values.push_back(std::make_shared<Expression>(Expression{
                    ValueType{TypeKind::integer, reg.width, false},
                    UnknownValue{"x87 environment output after " + instruction.mnemonic_override}}));
            }
        }
    }
}
} // namespace

ExpressionTypeScope::ExpressionTypeScope(std::span<const RecoveredVariable> variables)
    : previous_(active_expression_types) {
    for (const auto &variable : variables)
        if (variable.type)
            values_[expression_register_key(variable.reg, variable.version)] = variable.type;
    active_expression_types = &values_;
}

ExpressionTypeScope::~ExpressionTypeScope() { active_expression_types = previous_; }

const types::TypePtr *expression_register_type(RegisterOperand reg,
                                               std::optional<std::uint32_t> version) noexcept {
    if (!active_expression_types) return nullptr;
    const auto found = active_expression_types->find(expression_register_key(reg, version));
    return found == active_expression_types->end() ? nullptr : &found->second;
}
} // namespace hexlab::decompiler::detail

namespace hexlab::decompiler {
namespace {
bool x86_writes_flags(const Instruction &instruction) {
    return std::any_of(instruction.register_writes.begin(), instruction.register_writes.end(),
        [](RegisterOperand reg) { return reg.bank == RegisterBank::flags; });
}
ValueType integer_type(std::uint16_t bits) { return {TypeKind::integer, bits, false}; }
ValueType floating_type(std::uint16_t bits) { return {TypeKind::floating, bits, false}; }
ValueType vector_type(std::uint16_t bits, TypeKind element_kind = TypeKind::unknown,
                      std::uint16_t element_bits = 0, std::uint8_t lanes = 0,
                      bool element_signed = false) {
    return {TypeKind::vector, bits, element_signed, element_kind, element_bits, lanes};
}
std::string riscv_fp_name(Opcode op) {
    if (op == Opcode::rv_fleq_s) return "fleq.s";
    if (op == Opcode::rv_fltq_s) return "fltq.s";
    if (op == Opcode::rv_fleq_d) return "fleq.d";
    if (op == Opcode::rv_fltq_d) return "fltq.d";
    static constexpr const char *names[]{
        "flw","fld","fsw","fsd","fadd.s","fsub.s","fmul.s","fdiv.s","fsqrt.s","fsgnj.s","fsgnjn.s","fsgnjx.s","fmin.s","fmax.s","fmadd.s","fmsub.s","fnmsub.s","fnmadd.s","feq.s","flt.s","fle.s","fclass.s","fcvt.w.s","fcvt.wu.s","fcvt.l.s","fcvt.lu.s","fcvt.s.w","fcvt.s.wu","fcvt.s.l","fcvt.s.lu","fmv.x.w","fmv.w.x",
        "fadd.d","fsub.d","fmul.d","fdiv.d","fsqrt.d","fsgnj.d","fsgnjn.d","fsgnjx.d","fmin.d","fmax.d","fmadd.d","fmsub.d","fnmsub.d","fnmadd.d","feq.d","flt.d","fle.d","fclass.d","fcvt.w.d","fcvt.wu.d","fcvt.l.d","fcvt.lu.d","fcvt.d.w","fcvt.d.wu","fcvt.d.l","fcvt.d.lu","fcvt.s.d","fcvt.d.s","fmv.x.d","fmv.d.x"};
    return names[static_cast<std::size_t>(op) - static_cast<std::size_t>(Opcode::rv_flw)];
}

struct RiscvVectorEffect { const char* name; bool mask_result; bool floating = false; bool mask_inputs = false; };
std::optional<RiscvVectorEffect> riscv_vector_effect(Opcode opcode) {
    // Explicit opcode cases keep routing independent of serialized enum ranges.
    switch (opcode) {
#define RVV_PAIR(name, mask) \
    case Opcode::rv_##name##_vv: return RiscvVectorEffect{#name ".vv", mask}; \
    case Opcode::rv_##name##_vx: return RiscvVectorEffect{#name ".vx", mask}
#define RVV_TRIPLE(name, mask) RVV_PAIR(name, mask); \
    case Opcode::rv_##name##_vi: return RiscvVectorEffect{#name ".vi", mask}
#define RVV_SCALAR(name, mask) \
    case Opcode::rv_##name##_vx: return RiscvVectorEffect{#name ".vx", mask}; \
    case Opcode::rv_##name##_vi: return RiscvVectorEffect{#name ".vi", mask}
    RVV_TRIPLE(vadd, false);
    RVV_PAIR(vsub, false);
    RVV_SCALAR(vrsub, false);
    RVV_TRIPLE(vand, false);
    RVV_TRIPLE(vor, false);
    RVV_TRIPLE(vxor, false);
    case Opcode::rv_vredsum: return RiscvVectorEffect{"vredsum.vs", false};
    case Opcode::rv_vredand: return RiscvVectorEffect{"vredand.vs", false};
    case Opcode::rv_vredor: return RiscvVectorEffect{"vredor.vs", false};
    case Opcode::rv_vredxor: return RiscvVectorEffect{"vredxor.vs", false};
    case Opcode::rv_vredminu: return RiscvVectorEffect{"vredminu.vs", false};
    case Opcode::rv_vredmin: return RiscvVectorEffect{"vredmin.vs", false};
    case Opcode::rv_vredmaxu: return RiscvVectorEffect{"vredmaxu.vs", false};
    case Opcode::rv_vredmax: return RiscvVectorEffect{"vredmax.vs", false};
    case Opcode::rv_vmand_mm: return RiscvVectorEffect{"vmand.mm", true, false, true};
    case Opcode::rv_vmnand_mm: return RiscvVectorEffect{"vmnand.mm", true, false, true};
    case Opcode::rv_vmandn_mm: return RiscvVectorEffect{"vmandn.mm", true, false, true};
    case Opcode::rv_vmxor_mm: return RiscvVectorEffect{"vmxor.mm", true, false, true};
    case Opcode::rv_vmor_mm: return RiscvVectorEffect{"vmor.mm", true, false, true};
    case Opcode::rv_vmnor_mm: return RiscvVectorEffect{"vmnor.mm", true, false, true};
    case Opcode::rv_vmorn_mm: return RiscvVectorEffect{"vmorn.mm", true, false, true};
    case Opcode::rv_vmxnor_mm: return RiscvVectorEffect{"vmxnor.mm", true, false, true};
    case Opcode::rv_vfredusum: return RiscvVectorEffect{"vfredusum.vs", false, true};
    case Opcode::rv_vfredosum: return RiscvVectorEffect{"vfredosum.vs", false, true};
    case Opcode::rv_vfredmin: return RiscvVectorEffect{"vfredmin.vs", false, true};
    case Opcode::rv_vfredmax: return RiscvVectorEffect{"vfredmax.vs", false, true};
    case Opcode::rv_vfwredusum: return RiscvVectorEffect{"vfwredusum.vs", false, true};
    case Opcode::rv_vfwredosum: return RiscvVectorEffect{"vfwredosum.vs", false, true};
    RVV_TRIPLE(vsll, false);
    RVV_TRIPLE(vsrl, false);
    RVV_TRIPLE(vsra, false);
    RVV_PAIR(vminu, false);
    RVV_PAIR(vmin, false);
    RVV_PAIR(vmaxu, false);
    RVV_PAIR(vmax, false);
    RVV_PAIR(vmul, false);
    RVV_PAIR(vmulh, false);
    RVV_PAIR(vmulhu, false);
    RVV_PAIR(vmulhsu, false);
    RVV_PAIR(vdivu, false);
    RVV_PAIR(vdiv, false);
    RVV_PAIR(vremu, false);
    RVV_PAIR(vrem, false);
    RVV_PAIR(vmacc, false);
    RVV_PAIR(vnmsac, false);
    RVV_PAIR(vmadd, false);
    RVV_PAIR(vnmsub, false);
    RVV_PAIR(vwmaccu, false);
    RVV_PAIR(vwmacc, false);
    RVV_PAIR(vwmaccsu, false);
    case Opcode::rv_vwmaccus_vx: return RiscvVectorEffect{"vwmaccus.vx", false};
    RVV_PAIR(vwmulu, false);
    RVV_PAIR(vwmulsu, false);
    RVV_PAIR(vwmul, false);
    case Opcode::rv_vwadd_vv: return RiscvVectorEffect{"vwadd.vv", false};
    case Opcode::rv_vwadd_vx: return RiscvVectorEffect{"vwadd.vx", false};
    case Opcode::rv_vwadd_wv: return RiscvVectorEffect{"vwadd.wv", false};
    case Opcode::rv_vwadd_wx: return RiscvVectorEffect{"vwadd.wx", false};
    case Opcode::rv_vwaddu_vv: return RiscvVectorEffect{"vwaddu.vv", false};
    case Opcode::rv_vwaddu_vx: return RiscvVectorEffect{"vwaddu.vx", false};
    case Opcode::rv_vwaddu_wv: return RiscvVectorEffect{"vwaddu.wv", false};
    case Opcode::rv_vwaddu_wx: return RiscvVectorEffect{"vwaddu.wx", false};
    case Opcode::rv_vwsub_vv: return RiscvVectorEffect{"vwsub.vv", false};
    case Opcode::rv_vwsub_vx: return RiscvVectorEffect{"vwsub.vx", false};
    case Opcode::rv_vwsub_wv: return RiscvVectorEffect{"vwsub.wv", false};
    case Opcode::rv_vwsub_wx: return RiscvVectorEffect{"vwsub.wx", false};
    case Opcode::rv_vwsubu_vv: return RiscvVectorEffect{"vwsubu.vv", false};
    case Opcode::rv_vwsubu_vx: return RiscvVectorEffect{"vwsubu.vx", false};
    case Opcode::rv_vwsubu_wv: return RiscvVectorEffect{"vwsubu.wv", false};
    case Opcode::rv_vwsubu_wx: return RiscvVectorEffect{"vwsubu.wx", false};
    RVV_TRIPLE(vmseq, true);
    RVV_TRIPLE(vmsne, true);
    RVV_PAIR(vmsltu, true);
    RVV_PAIR(vmslt, true);
    RVV_TRIPLE(vmsleu, true);
    RVV_TRIPLE(vmsle, true);
    RVV_SCALAR(vmsgtu, true);
    RVV_SCALAR(vmsgt, true);
    case Opcode::rv_vfadd_vv: return RiscvVectorEffect{"vfadd.vv", false, true};
    case Opcode::rv_vfadd_vf: return RiscvVectorEffect{"vfadd.vf", false, true};
    case Opcode::rv_vfsub_vv: return RiscvVectorEffect{"vfsub.vv", false, true};
    case Opcode::rv_vfsub_vf: return RiscvVectorEffect{"vfsub.vf", false, true};
    case Opcode::rv_vfmul_vv: return RiscvVectorEffect{"vfmul.vv", false, true};
    case Opcode::rv_vfmul_vf: return RiscvVectorEffect{"vfmul.vf", false, true};
    case Opcode::rv_vfdiv_vv: return RiscvVectorEffect{"vfdiv.vv", false, true};
    case Opcode::rv_vfdiv_vf: return RiscvVectorEffect{"vfdiv.vf", false, true};
    case Opcode::rv_vfsgnj_vv: return RiscvVectorEffect{"vfsgnj.vv", false, true};
    case Opcode::rv_vfsgnj_vf: return RiscvVectorEffect{"vfsgnj.vf", false, true};
    case Opcode::rv_vfsgnjn_vv: return RiscvVectorEffect{"vfsgnjn.vv", false, true};
    case Opcode::rv_vfsgnjn_vf: return RiscvVectorEffect{"vfsgnjn.vf", false, true};
    case Opcode::rv_vfsgnjx_vv: return RiscvVectorEffect{"vfsgnjx.vv", false, true};
    case Opcode::rv_vfsgnjx_vf: return RiscvVectorEffect{"vfsgnjx.vf", false, true};
    case Opcode::rv_vfmin_vv: return RiscvVectorEffect{"vfmin.vv", false, true};
    case Opcode::rv_vfmin_vf: return RiscvVectorEffect{"vfmin.vf", false, true};
    case Opcode::rv_vfmax_vv: return RiscvVectorEffect{"vfmax.vv", false, true};
    case Opcode::rv_vfmax_vf: return RiscvVectorEffect{"vfmax.vf", false, true};
    case Opcode::rv_vfmacc_vv: return RiscvVectorEffect{"vfmacc.vv", false, true};
    case Opcode::rv_vfmacc_vf: return RiscvVectorEffect{"vfmacc.vf", false, true};
    case Opcode::rv_vfnmacc_vv: return RiscvVectorEffect{"vfnmacc.vv", false, true};
    case Opcode::rv_vfnmacc_vf: return RiscvVectorEffect{"vfnmacc.vf", false, true};
    case Opcode::rv_vfmsac_vv: return RiscvVectorEffect{"vfmsac.vv", false, true};
    case Opcode::rv_vfmsac_vf: return RiscvVectorEffect{"vfmsac.vf", false, true};
    case Opcode::rv_vfnmsac_vv: return RiscvVectorEffect{"vfnmsac.vv", false, true};
    case Opcode::rv_vfnmsac_vf: return RiscvVectorEffect{"vfnmsac.vf", false, true};
    case Opcode::rv_vfmadd_vv: return RiscvVectorEffect{"vfmadd.vv", false, true};
    case Opcode::rv_vfmadd_vf: return RiscvVectorEffect{"vfmadd.vf", false, true};
    case Opcode::rv_vfnmadd_vv: return RiscvVectorEffect{"vfnmadd.vv", false, true};
    case Opcode::rv_vfnmadd_vf: return RiscvVectorEffect{"vfnmadd.vf", false, true};
    case Opcode::rv_vfmsub_vv: return RiscvVectorEffect{"vfmsub.vv", false, true};
    case Opcode::rv_vfmsub_vf: return RiscvVectorEffect{"vfmsub.vf", false, true};
    case Opcode::rv_vfnmsub_vv: return RiscvVectorEffect{"vfnmsub.vv", false, true};
    case Opcode::rv_vfnmsub_vf: return RiscvVectorEffect{"vfnmsub.vf", false, true};
    case Opcode::rv_vfsqrt_v: return RiscvVectorEffect{"vfsqrt.v", false, true};
    case Opcode::rv_vfrsqrt7_v: return RiscvVectorEffect{"vfrsqrt7.v", false, true};
    case Opcode::rv_vfrec7_v: return RiscvVectorEffect{"vfrec7.v", false, true};
    case Opcode::rv_vfclass_v: return RiscvVectorEffect{"vfclass.v", false};
    case Opcode::rv_vmfeq_vv: return RiscvVectorEffect{"vmfeq.vv", true, true};
    case Opcode::rv_vmfeq_vf: return RiscvVectorEffect{"vmfeq.vf", true, true};
    case Opcode::rv_vmfne_vv: return RiscvVectorEffect{"vmfne.vv", true, true};
    case Opcode::rv_vmfne_vf: return RiscvVectorEffect{"vmfne.vf", true, true};
    case Opcode::rv_vmflt_vv: return RiscvVectorEffect{"vmflt.vv", true, true};
    case Opcode::rv_vmflt_vf: return RiscvVectorEffect{"vmflt.vf", true, true};
    case Opcode::rv_vmfle_vv: return RiscvVectorEffect{"vmfle.vv", true, true};
    case Opcode::rv_vmfle_vf: return RiscvVectorEffect{"vmfle.vf", true, true};
    case Opcode::rv_vmfgt_vf: return RiscvVectorEffect{"vmfgt.vf", true, true};
    case Opcode::rv_vmfge_vf: return RiscvVectorEffect{"vmfge.vf", true, true};
#undef RVV_SCALAR
#undef RVV_TRIPLE
#undef RVV_PAIR
    default: return {};
    }
}

bool mips_branch_likely(Opcode opcode) {
    switch (opcode) {
    case Opcode::mips_beql: case Opcode::mips_bnel: case Opcode::mips_blezl:
    case Opcode::mips_bgtzl: case Opcode::mips_bltzl: case Opcode::mips_bgezl:
    case Opcode::mips_bltzall: case Opcode::mips_bgezall:
    case Opcode::mips64_bltzall: case Opcode::mips64_bgezall:
    case Opcode::mips_bc1tl: case Opcode::mips_bc1fl:
    case Opcode::mips64_bc1tl: case Opcode::mips64_bc1fl:
        return true;
    default:
        return false;
    }
}

ExpressionPtr reg_expr(RegisterOperand reg) {
    if (reg.bank == RegisterBank::riscv_vpr)
        return std::make_shared<Expression>(Expression{vector_type(0), RegisterValue{reg}});
    const auto type = (reg.bank == RegisterBank::riscv_fpr || reg.bank == RegisterBank::mips_fpr ||
                       reg.bank == RegisterBank::arm32_vfp)
                          ? floating_type(reg.width) : integer_type(reg.width);
    return std::make_shared<Expression>(Expression{type, RegisterValue{reg}});
}
ExpressionPtr retag_expr(const ExpressionPtr &expression, ValueType type) {
    auto value = *expression;
    value.type = type;
    if (auto *memory = std::get_if<MemoryValue>(&value.value)) memory->type = type;
    return std::make_shared<Expression>(std::move(value));
}
ExpressionPtr constant_expr(std::uint64_t value, std::uint16_t bits) {
    return std::make_shared<Expression>(Expression{integer_type(bits), ConstantValue{value, integer_type(bits)}});
}
ExpressionPtr unknown_expr(std::string name, std::uint16_t bits = 0) {
    return std::make_shared<Expression>(Expression{integer_type(bits), UnknownValue{std::move(name)}});
}

std::optional<X86StackControlEffect> x86_stack_control_effect(const Instruction &instruction,
                                                              X86StackControlAction action) {
    const bool x86 = instruction.context.architecture == Architecture::x86 ||
                     instruction.context.architecture == Architecture::x86_64;
    if (!x86 || instruction.stack_slot_count != 1 || !instruction.stack_value_width ||
        instruction.stack_value_width % 8 != 0 || instruction.stack_value_width > 64)
        return {};
    const auto mode = instruction.context.mode;
    if (mode != ExecutionMode::x86_16 && mode != ExecutionMode::x86_32 && mode != ExecutionMode::x86_64)
        return {};
    if ((instruction.context.architecture == Architecture::x86_64) != (mode == ExecutionMode::x86_64))
        return {};
    if (action == X86StackControlAction::push_return_address &&
        (instruction.flow != FlowKind::call || !instruction.memory_write || !instruction.length))
        return {};
    if (action == X86StackControlAction::pop_return_address &&
        (instruction.opcode != Opcode::ret || instruction.flow != FlowKind::ret || !instruction.memory_read))
        return {};

    std::optional<RegisterOperand> stack_pointer;
    for (const auto reg : instruction.register_reads)
        if (reg.bank == RegisterBank::gpr && reg.index == 4) { stack_pointer = reg; break; }
    if (!stack_pointer)
        for (const auto reg : instruction.register_writes)
            if (reg.bank == RegisterBank::gpr && reg.index == 4) { stack_pointer = reg; break; }
    if (!stack_pointer || (stack_pointer->width != 16 && stack_pointer->width != 32 && stack_pointer->width != 64))
        return {};

    const auto byte_width = static_cast<std::int64_t>(instruction.stack_value_width / 8);
    X86StackControlEffect effect;
    effect.action = action;
    effect.stack_pointer = *stack_pointer;
    effect.stack_address_width = stack_pointer->width;
    effect.value_width = instruction.stack_value_width;
    for (const auto reg : instruction.register_reads)
        if (reg.bank == RegisterBank::segment && reg.index == 2) { effect.stack_segment = reg; break; }
    if (action == X86StackControlAction::push_return_address) {
        effect.slot_displacement = -byte_width;
        effect.stack_pointer_delta = -byte_width;
        const auto next = advance(instruction.address, instruction.length);
        if (next && !instruction.context.segmented_memory) {
            const auto max_value = instruction.stack_value_width == 64
                ? UINT64_MAX : ((UINT64_C(1) << instruction.stack_value_width) - 1);
            if (next.value().offset <= max_value)
                effect.return_address = next.value();
        }
    } else {
        if (instruction.operands.size() > 1)
            return {};
        if (!instruction.operands.empty()) {
            const auto *cleanup = std::get_if<ImmediateOperand>(&instruction.operands.front());
            if (!cleanup || cleanup->value > UINT16_MAX)
                return {};
            effect.caller_cleanup_bytes = static_cast<std::uint32_t>(cleanup->value);
        }
        effect.stack_pointer_delta = byte_width + effect.caller_cleanup_bytes;
    }
    return effect;
}

std::string register_name(RegisterOperand reg) {
    if (reg.bank == RegisterBank::x87)
        return "st(" + std::to_string(reg.index) + ")";
    if (reg.bank == RegisterBank::x87_status) return "fsw";
    if (reg.bank == RegisterBank::x87_control) return "fcw";
    if (reg.bank == RegisterBank::x87_tag) return "ftw";
    if (reg.bank == RegisterBank::mxcsr) return "mxcsr";
    if (reg.bank == RegisterBank::xmm) return "xmm" + std::to_string(reg.index);
    if (reg.bank == RegisterBank::ymm) return "ymm" + std::to_string(reg.index);
    if (reg.bank == RegisterBank::zmm) return "zmm" + std::to_string(reg.index);
    if (reg.bank == RegisterBank::opmask) return "k" + std::to_string(reg.index);
    if (reg.bank == RegisterBank::cil_stack)
        return "stack_" + std::to_string(reg.index);
    if (reg.bank == RegisterBank::jvm_stack)
        return "jvm_stack_" + std::to_string(reg.index);
    if (reg.bank == RegisterBank::jvm_local)
        return "jvm_local_" + std::to_string(reg.index);
    if (reg.bank == RegisterBank::wasm_stack)
        return "wasm_stack_" + std::to_string(reg.index);
    if (reg.bank == RegisterBank::wasm_local)
        return "wasm_local_" + std::to_string(reg.index);
    if (reg.bank == RegisterBank::cil_continuation)
        return "cil_continuation";
    if (reg.bank == RegisterBank::mos6502) {
        static constexpr const char *names[]{"A", "X", "Y", "P", "S"};
        if (reg.index < std::size(names)) return names[reg.index];
    }
    if (reg.bank == RegisterBank::arm64_gpr)
        return std::string(reg.width == 32 ? "w" : "x") + std::to_string(reg.index);
    if (reg.bank == RegisterBank::arm64_simd)
        return "v" + std::to_string(reg.index);
    if (reg.bank == RegisterBank::arm32_vfp)
        return std::string(reg.width == 64 ? "d" : "s") + std::to_string(reg.index);
    if (reg.bank == RegisterBank::arm64_sp)
        return reg.width == 32 ? "wsp" : "sp";
    if (reg.bank == RegisterBank::arm64_zero)
        return reg.width == 32 ? "wzr" : "xzr";
    if (reg.bank == RegisterBank::flags || reg.bank == RegisterBank::arm_flags)
        return "flags";
    if (reg.bank == RegisterBank::ip)
        return "ip";
    if (reg.bank == RegisterBank::riscv_gpr)
        return "x" + std::to_string(reg.index);
    if (reg.bank == RegisterBank::riscv_vpr)
        return "v" + std::to_string(reg.index);
    if (reg.bank == RegisterBank::riscv_vcsr)
        return reg.index == 0 ? "vl" : reg.index == 1 ? "vtype" : "vcsr" + std::to_string(reg.index);
    if (reg.bank == RegisterBank::riscv_fpr)
        return "f" + std::to_string(reg.index);
    if (reg.bank == RegisterBank::mips_fpr)
        return "f" + std::to_string(reg.index);
    if (reg.bank == RegisterBank::ppc_fpr)
        return "f" + std::to_string(reg.index);
    if (reg.bank == RegisterBank::ppc_vr)
        return "v" + std::to_string(reg.index);
    if (reg.bank == RegisterBank::ppc_fpscr)
        return "fpscr";
    if (reg.bank == RegisterBank::mips_fcsr)
        return "fcsr";
    if (reg.bank == RegisterBank::riscv_fstatus)
        return reg.index == 1 ? "frm" : "fflags";
    if (reg.bank == RegisterBank::mips_hilo)
        return reg.index == 0 ? "HI" : reg.index == 1 ? "LO" : "HILO" + std::to_string(reg.index);
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
    value.index_extend = memory.index_extend;
    value.index_shift_amount = memory.index_shift_amount;
    if (memory.index_shift_amount) value.index_shift = "lsl";
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
        value.displacement = memory.pre_index ? (memory.add ? static_cast<std::int64_t>(*offset)
                                                            : -static_cast<std::int64_t>(*offset)) : 0;
    } else {
        const auto &shifted = std::get<ArmShiftedRegisterOperand>(memory.offset);
        value.index = shifted.source;
        value.index_add = memory.add;
        value.index_shift = shifted.shift == ArmShift::lsl ? "lsl" : shifted.shift == ArmShift::lsr ? "lsr"
                           : shifted.shift == ArmShift::asr ? "asr" : shifted.shift == ArmShift::rrx ? "rrx" : "ror";
        value.index_shift_amount = shifted.amount;
        // Register-controlled shifts remain explicit unknowns because the
        // common memory expression has no variable shift-count field.
        if (shifted.amount_register) return unknown_expr("arm-register-shift-amount", memory.data_width);
    }
    return std::make_shared<Expression>(Expression{value.type, std::move(value)});
}

ExpressionPtr operand_expr(const Operand &operand) {
    return std::visit([](const auto &value) -> ExpressionPtr {
        using T = std::decay_t<decltype(value)>;
        if constexpr (std::is_same_v<T, RegisterOperand>) {
            if (value.bank == RegisterBank::arm64_zero ||
                ((value.bank == RegisterBank::riscv_gpr || value.bank == RegisterBank::mips_gpr) && value.index == 0))
                return constant_expr(0, value.width);
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
            if (value.shift == ArmShift::lsl && !value.amount && !value.amount_register)
                return source;
            const auto operation = value.shift == ArmShift::lsl ? "lsl" : value.shift == ArmShift::lsr ? "lsr"
                                  : value.shift == ArmShift::asr ? "asr" : value.shift == ArmShift::rrx ? "rrx" : "ror";
            if (value.shift == ArmShift::rrx)
                return std::make_shared<Expression>(Expression{integer_type(value.source.width),
                    BinaryValue{"rrx", source, std::make_shared<Expression>(Expression{integer_type(1),
                        UnaryValue{"carry_flag", reg_expr({RegisterBank::arm_flags, 0, 4, false})}})}});
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
    case Opcode::a64_ldr: case Opcode::a64_ldrb: case Opcode::a64_ldrh: case Opcode::a64_ldrsw:
    case Opcode::a32_ldr: case Opcode::a32_ldrb: case Opcode::a32_ldrh:
    case Opcode::a32_ldrsb: case Opcode::a32_ldrsh:
    case Opcode::mips_lb: case Opcode::mips_lh: case Opcode::mips_lw:
    case Opcode::mips_lbu: case Opcode::mips_lhu: return true;
    default: return false;
    }
}

bool is_store(Opcode opcode) {
    switch (opcode) {
    case Opcode::mov: case Opcode::a64_str: case Opcode::a64_strb: case Opcode::a64_strh:
    case Opcode::a32_str: case Opcode::a32_strb: case Opcode::a32_strh:
    case Opcode::mips_sb: case Opcode::mips_sh: case Opcode::mips_sw: return true;
    default: return false;
    }
}
std::optional<RegisterOperand> as_register(const Operand &operand) {
    if (const auto *reg = std::get_if<RegisterOperand>(&operand))
        return *reg;
    return {};
}

std::string operation_name(Opcode opcode) {
    if (opcode >= Opcode::rv_lr_w && opcode <= Opcode::rv_amomaxu_d) {
        static constexpr const char *atomic_names[]{
            "lr.w", "sc.w", "amoswap.w", "amoadd.w", "amoxor.w", "amoand.w", "amoor.w", "amomin.w",
            "amomax.w", "amominu.w", "amomaxu.w", "lr.d", "sc.d", "amoswap.d", "amoadd.d", "amoxor.d",
            "amoand.d", "amoor.d", "amomin.d", "amomax.d", "amominu.d", "amomaxu.d"};
        return atomic_names[static_cast<std::size_t>(opcode) - static_cast<std::size_t>(Opcode::rv_lr_w)];
    }
    switch (opcode) {
    case Opcode::m6502_lda: return "LDA"; case Opcode::m6502_ldx: return "LDX";
    case Opcode::m6502_ldy: return "LDY"; case Opcode::m6502_sta: return "STA";
    case Opcode::m6502_stx: return "STX"; case Opcode::m6502_sty: return "STY";
    case Opcode::m6502_adc: return "ADC"; case Opcode::m6502_sbc: return "SBC";
    case Opcode::m6502_and: return "AND"; case Opcode::m6502_ora: return "ORA";
    case Opcode::m6502_eor: return "EOR"; case Opcode::m6502_cmp: return "CMP";
    case Opcode::m6502_dcp: return "DCP";
    case Opcode::m6502_slo: return "SLO";
    case Opcode::m6502_rla: return "RLA";
    case Opcode::m6502_sre: return "SRE";
    case Opcode::m6502_rra: return "RRA";
    case Opcode::m6502_isc: return "ISC";
    case Opcode::m6502_las: return "LAS";
    case Opcode::m6502_anc: return "ANC";
    case Opcode::m6502_axs: return "AXS";
    case Opcode::m6502_lax: return "LAX";
    case Opcode::m6502_sax: return "SAX";
    case Opcode::m6502_cpx: return "CPX"; case Opcode::m6502_cpy: return "CPY";
    case Opcode::m6502_bit: return "BIT"; case Opcode::m6502_inc: return "INC";
    case Opcode::m6502_dec: return "DEC"; case Opcode::m6502_inx: return "INX";
    case Opcode::m6502_dex: return "DEX"; case Opcode::m6502_iny: return "INY";
    case Opcode::m6502_dey: return "DEY"; case Opcode::m6502_tax: return "TAX";
    case Opcode::m6502_tay: return "TAY"; case Opcode::m6502_txa: return "TXA";
    case Opcode::m6502_tya: return "TYA"; case Opcode::m6502_tsx: return "TSX";
    case Opcode::m6502_txs: return "TXS"; case Opcode::m6502_pha: return "PHA";
    case Opcode::m6502_php: return "PHP"; case Opcode::m6502_pla: return "PLA";
    case Opcode::m6502_plp: return "PLP"; case Opcode::m6502_jmp: return "JMP";
    case Opcode::m6502_jsr: return "JSR"; case Opcode::m6502_rts: return "RTS";
    case Opcode::m6502_rti: return "RTI"; case Opcode::m6502_brk: return "BRK";
    case Opcode::m6502_bpl: return "BPL"; case Opcode::m6502_bmi: return "BMI";
    case Opcode::m6502_bvc: return "BVC"; case Opcode::m6502_bvs: return "BVS";
    case Opcode::m6502_bcc: return "BCC"; case Opcode::m6502_bcs: return "BCS";
    case Opcode::m6502_bne: return "BNE"; case Opcode::m6502_beq: return "BEQ";
    case Opcode::m6502_clc: return "CLC"; case Opcode::m6502_sec: return "SEC";
    case Opcode::m6502_cli: return "CLI"; case Opcode::m6502_sei: return "SEI";
    case Opcode::m6502_clv: return "CLV"; case Opcode::m6502_cld: return "CLD";
    case Opcode::m6502_sed: return "SED"; case Opcode::m6502_asl: return "ASL";
    case Opcode::m6502_lsr: return "LSR"; case Opcode::m6502_rol: return "ROL";
    case Opcode::m6502_ror: return "ROR";
    case Opcode::add: case Opcode::a64_add: case Opcode::a32_add: case Opcode::t32_addw: return "add";
    case Opcode::a64_adc: return "adc"; case Opcode::a64_adcs: return "adcs";
    case Opcode::a64_sbc: return "sbc"; case Opcode::a64_sbcs: return "sbcs";
    case Opcode::sub: case Opcode::a64_sub: case Opcode::a32_sub: case Opcode::t32_subw: return "sub";
    case Opcode::a64_bfm: return "a64_bfm";
    case Opcode::a64_extr: return "extr";
    case Opcode::a32_rsb: return "rsb";
    case Opcode::a32_adc: return "adc";
    case Opcode::a32_sbc: return "sbc";
    case Opcode::a32_rsc: return "rsc";
    case Opcode::a32_bic: return "bic";
    case Opcode::a32_mvn: return "mvn";
    case Opcode::a32_teq: return "teq";
    case Opcode::a32_cmn: return "cmn";
    case Opcode::a32_bx: case Opcode::t32_bx: return "bx";
    case Opcode::a32_svc: case Opcode::t32_svc: return "svc";
    case Opcode::a32_bkpt: case Opcode::t32_bkpt: return "bkpt";
    case Opcode::t32_it: return "it";
    case Opcode::t32_adr: return "adr";
    case Opcode::t32_mul: return "mul";
    case Opcode::a32_ldr: case Opcode::a32_ldrb: case Opcode::a32_ldrh:
    case Opcode::a32_ldrsb: case Opcode::a32_ldrsh: return "ldr";
    case Opcode::a32_str: case Opcode::a32_strb: case Opcode::a32_strh: return "str";
    case Opcode::a32_ldm: return "ldm";
    case Opcode::a32_stm: return "stm";
    case Opcode::bit_and: case Opcode::a32_and: return "and";
    case Opcode::bit_or: case Opcode::a32_orr: return "or";
    case Opcode::bit_xor: case Opcode::a32_eor: return "xor";
    case Opcode::imul: case Opcode::rv_mul: return "mul";
    case Opcode::rv_mulw: return "mulw";
    case Opcode::rv_mulh: return "mulh"; case Opcode::rv_mulhsu: return "mulhsu"; case Opcode::rv_mulhu: return "mulhu";
    case Opcode::rv_div: return "div"; case Opcode::rv_divu: return "divu"; case Opcode::rv_rem: return "rem"; case Opcode::rv_remu: return "remu";
    case Opcode::rv_divw: return "divw"; case Opcode::rv_divuw: return "divuw"; case Opcode::rv_remw: return "remw"; case Opcode::rv_remuw: return "remuw";
    case Opcode::shl: return "shl";
    case Opcode::shr: return "shr";
    case Opcode::sar: return "sar";
    case Opcode::rol: return "rol";
    case Opcode::ror: return "ror";
    case Opcode::rcl: return "rcl";
    case Opcode::rcr: return "rcr";
    case Opcode::bt: return "bt";
    case Opcode::bts: return "bts";
    case Opcode::btr: return "btr";
    case Opcode::btc: return "btc";
    case Opcode::bsf: return "bsf";
    case Opcode::bsr: return "bsr";
    case Opcode::tzcnt: return "tzcnt";
    case Opcode::lzcnt: return "lzcnt";
    case Opcode::cmpxchg8b: return "cmpxchg8b";
    case Opcode::cmpxchg16b: return "cmpxchg16b";
    case Opcode::cpuid: return "cpuid";
    case Opcode::xchg: return "xchg";
    case Opcode::bzhi: return "bzhi";
    case Opcode::andn: return "andn";
    case Opcode::bextr: return "bextr";
    case Opcode::blsi: return "blsi";
    case Opcode::blsmsk: return "blsmsk";
    case Opcode::blsr: return "blsr";
    case Opcode::mulx: return "mulx";
    case Opcode::pdep: return "pdep";
    case Opcode::pext: return "pext";
    case Opcode::rorx: return "rorx";
    case Opcode::sarx: return "sarx";
    case Opcode::shlx: return "shlx";
    case Opcode::shrx: return "shrx";
    case Opcode::shld: return "shld";
    case Opcode::shrd: return "shrd";
    case Opcode::cmp: case Opcode::a32_cmp: return "cmp";
    case Opcode::test: case Opcode::a32_tst: return "test";
    case Opcode::mov: case Opcode::a32_mov: return "mov";
    case Opcode::lea: return "lea";
    case Opcode::call: case Opcode::a64_bl: case Opcode::a64_blr: case Opcode::a32_bl: case Opcode::a32_blx:
    case Opcode::t32_bl: case Opcode::t32_blx: return "call";
    case Opcode::jmp: case Opcode::a64_b: case Opcode::a32_b: case Opcode::t32_b: return "goto";
    case Opcode::ret: case Opcode::a64_ret: return "return";
    case Opcode::nop: case Opcode::a64_nop: case Opcode::a32_nop: case Opcode::t32_nop: return "nop";
    case Opcode::x86_movs: return "movs";
    case Opcode::x86_cmps: return "cmps";
    case Opcode::x86_stos: return "stos";
    case Opcode::x86_lods: return "lods";
    case Opcode::x86_scas: return "scas";
    case Opcode::x86_ins: return "ins";
    case Opcode::x86_outs: return "outs";
    case Opcode::paddd: return "paddd";
    case Opcode::paddq: return "paddq";
    case Opcode::psubd: return "psubd";
    case Opcode::psubq: return "psubq";
    case Opcode::pand: return "pand";
    case Opcode::por: return "por";
    case Opcode::pxor: return "pxor";
    case Opcode::pandn: return "pandn";
    case Opcode::paddb: return "paddb";
    case Opcode::paddw: return "paddw";
    case Opcode::paddsb: return "paddsb";
    case Opcode::paddsw: return "paddsw";
    case Opcode::paddusb: return "paddusb";
    case Opcode::paddusw: return "paddusw";
    case Opcode::psubb: return "psubb";
    case Opcode::psubw: return "psubw";
    case Opcode::psubsb: return "psubsb";
    case Opcode::psubsw: return "psubsw";
    case Opcode::psubusb: return "psubusb";
    case Opcode::psubusw: return "psubusw";
    case Opcode::psllw: return "psllw";
    case Opcode::pslld: return "pslld";
    case Opcode::psllq: return "psllq";
    case Opcode::psrlw: return "psrlw";
    case Opcode::psrld: return "psrld";
    case Opcode::psrlq: return "psrlq";
    case Opcode::psraw: return "psraw";
    case Opcode::psrad: return "psrad";
    case Opcode::pslldq: return "pslldq";
    case Opcode::psrldq: return "psrldq";
    case Opcode::pmullw: return "pmullw";
    case Opcode::pmulhw: return "pmulhw";
    case Opcode::pmulhuw: return "pmulhuw";
    case Opcode::pmuludq: return "pmuludq";
    case Opcode::pmaddwd: return "pmaddwd";
    case Opcode::pabsb: return "pabsb";
    case Opcode::pabsw: return "pabsw";
    case Opcode::pabsd: return "pabsd";
    case Opcode::psadbw: return "psadbw";
    case Opcode::pminub: return "pminub";
    case Opcode::pmaxub: return "pmaxub";
    case Opcode::pminsw: return "pminsw";
    case Opcode::pmaxsw: return "pmaxsw";
    case Opcode::pavgb: return "pavgb";
    case Opcode::pavgw: return "pavgw";
    case Opcode::pshufd: return "pshufd";
    case Opcode::pshufb: return "pshufb";
    case Opcode::pcmpeqb: return "pcmpeqb";
    case Opcode::pcmpeqw: return "pcmpeqw";
    case Opcode::pcmpeqd: return "pcmpeqd";
    case Opcode::pcmpgtb: return "pcmpgtb";
    case Opcode::pcmpgtw: return "pcmpgtw";
    case Opcode::pcmpgtd: return "pcmpgtd";
    case Opcode::pcmpgtq: return "pcmpgtq";
    case Opcode::cmpps: return "cmpps";
    case Opcode::cmppd: return "cmppd";
    case Opcode::cmpss: return "cmpss";
    case Opcode::cmpsd: return "cmpsd";
    case Opcode::vaddps: return "vaddps";
    case Opcode::vaddpd: return "vaddpd";
    case Opcode::vsubps: return "vsubps";
    case Opcode::vsubpd: return "vsubpd";
    case Opcode::vmulps: return "vmulps";
    case Opcode::vmulpd: return "vmulpd";
    case Opcode::vdivps: return "vdivps";
    case Opcode::vdivpd: return "vdivpd";
    case Opcode::vxorps: return "vxorps";
    case Opcode::vxorpd: return "vxorpd";
    case Opcode::vandps: return "vandps";
    case Opcode::vandpd: return "vandpd";
    case Opcode::vmovups: return "vmovups";
    case Opcode::vpaddb: return "vpaddb";
    case Opcode::vpsllvw: return "vpsllvw";
    case Opcode::vpsllvd: return "vpsllvd";
    case Opcode::vpsllvq: return "vpsllvq";
    case Opcode::vpsrlvw: return "vpsrlvw";
    case Opcode::vpsrlvd: return "vpsrlvd";
    case Opcode::vpsrlvq: return "vpsrlvq";
    case Opcode::vpsravw: return "vpsravw";
    case Opcode::vpsravd: return "vpsravd";
    case Opcode::vpsravq: return "vpsravq";
    case Opcode::vpsllw: return "vpsllw";
    case Opcode::vpslld: return "vpslld";
    case Opcode::vpsllq: return "vpsllq";
    case Opcode::vpsrlw: return "vpsrlw";
    case Opcode::vpsrld: return "vpsrld";
    case Opcode::vpsrlq: return "vpsrlq";
    case Opcode::vpsraw: return "vpsraw";
    case Opcode::vpsrad: return "vpsrad";
    case Opcode::vpslldq: return "vpslldq";
    case Opcode::vpsrldq: return "vpsrldq";
    case Opcode::vpaddw: return "vpaddw";
    case Opcode::vpaddsb: return "vpaddsb";
    case Opcode::vpaddsw: return "vpaddsw";
    case Opcode::vpaddusb: return "vpaddusb";
    case Opcode::vpaddusw: return "vpaddusw";
    case Opcode::vpaddd: return "vpaddd";
    case Opcode::vpaddq: return "vpaddq";
    case Opcode::vpand: return "vpand";
    case Opcode::vpor: return "vpor";
    case Opcode::vpxor: return "vpxor";
    case Opcode::vpandd: return "vpandd";
    case Opcode::vpandnd: return "vpandnd";
    case Opcode::vpandq: return "vpandq";
    case Opcode::vpandnq: return "vpandnq";
    case Opcode::vpord: return "vpord";
    case Opcode::vporq: return "vporq";
    case Opcode::vpxord: return "vpxord";
    case Opcode::vpxorq: return "vpxorq";
    case Opcode::vpsubb: return "vpsubb";
    case Opcode::vpsubw: return "vpsubw";
    case Opcode::vpsubsb: return "vpsubsb";
    case Opcode::vpsubsw: return "vpsubsw";
    case Opcode::vpsubusb: return "vpsubusb";
    case Opcode::vpsubusw: return "vpsubusw";
    case Opcode::vpsubd: return "vpsubd";
    case Opcode::vpsubq: return "vpsubq";
    case Opcode::vpcmpgtq: return "vpcmpgtq";
    case Opcode::vpmullw: return "vpmullw";
    case Opcode::vpmulhw: return "vpmulhw";
    case Opcode::vpmulhuw: return "vpmulhuw";
    case Opcode::vpminub: return "vpminub";
    case Opcode::vpminsw: return "vpminsw";
    case Opcode::vpmaxub: return "vpmaxub";
    case Opcode::vpmaxsw: return "vpmaxsw";
    case Opcode::vpandn: return "vpandn";
    case Opcode::vpavgb: return "vpavgb";
    case Opcode::vpavgw: return "vpavgw";
    case Opcode::vpminsb: return "vpminsb";
    case Opcode::vpminsd: return "vpminsd";
    case Opcode::vpminuw: return "vpminuw";
    case Opcode::vpminud: return "vpminud";
    case Opcode::vpmaxsb: return "vpmaxsb";
    case Opcode::vpmaxsd: return "vpmaxsd";
    case Opcode::vpmaxuw: return "vpmaxuw";
    case Opcode::vpmaxud: return "vpmaxud";
    case Opcode::vpmulld: return "vpmulld";
    case Opcode::vpmuldq: return "vpmuldq";
    case Opcode::vpmuludq: return "vpmuludq";
    case Opcode::vpmaddwd: return "vpmaddwd";
    case Opcode::vpmaddubsw: return "vpmaddubsw";
    case Opcode::vphaddw: return "vphaddw";
    case Opcode::vphaddd: return "vphaddd";
    case Opcode::vphaddsw: return "vphaddsw";
    case Opcode::vphsubw: return "vphsubw";
    case Opcode::vphsubd: return "vphsubd";
    case Opcode::vphsubsw: return "vphsubsw";
    case Opcode::vpsignb: return "vpsignb";
    case Opcode::vpsignw: return "vpsignw";
    case Opcode::vpsignd: return "vpsignd";
    case Opcode::vpabsb: return "vpabsb";
    case Opcode::vpabsw: return "vpabsw";
    case Opcode::vpabsd: return "vpabsd";
    case Opcode::vpunpcklbw: return "vpunpcklbw";
    case Opcode::vpunpcklwd: return "vpunpcklwd";
    case Opcode::vpunpckldq: return "vpunpckldq";
    case Opcode::vpunpcklqdq: return "vpunpcklqdq";
    case Opcode::vpunpckhbw: return "vpunpckhbw";
    case Opcode::vpunpckhwd: return "vpunpckhwd";
    case Opcode::vpunpckhdq: return "vpunpckhdq";
    case Opcode::vpunpckhqdq: return "vpunpckhqdq";
    case Opcode::vpacksswb: return "vpacksswb";
    case Opcode::vpackssdw: return "vpackssdw";
    case Opcode::vpackuswb: return "vpackuswb";
    case Opcode::vpackusdw: return "vpackusdw";
    case Opcode::vpshufb: return "vpshufb";
    case Opcode::movmskps: return "movmskps";
    case Opcode::movmskpd: return "movmskpd";
    case Opcode::pmovmskb: return "pmovmskb";
    case Opcode::vmovmskps: return "vmovmskps";
    case Opcode::vmovmskpd: return "vmovmskpd";
    case Opcode::vpmovmskb: return "vpmovmskb";
    case Opcode::vshufps: return "vshufps";
    case Opcode::vshufpd: return "vshufpd";
    case Opcode::vpshufd: return "vpshufd";
    case Opcode::vpsadbw: return "vpsadbw";
    case Opcode::vpermd: return "vpermd";
    case Opcode::vpermb: return "vpermb";
    case Opcode::vpternlogd: return "vpternlogd";
    case Opcode::vpternlogq: return "vpternlogq";
    case Opcode::vpmullq: return "vpmullq";
    case Opcode::vpminsq: return "vpminsq";
    case Opcode::vpminuq: return "vpminuq";
    case Opcode::vpmaxsq: return "vpmaxsq";
    case Opcode::vpmaxuq: return "vpmaxuq";
    case Opcode::vpmovm2b: return "vpmovm2b";
    case Opcode::vpmovm2w: return "vpmovm2w";
    case Opcode::vpmovm2d: return "vpmovm2d";
    case Opcode::vpmovm2q: return "vpmovm2q";
    case Opcode::vpmovb2m: return "vpmovb2m";
    case Opcode::vpmovw2m: return "vpmovw2m";
    case Opcode::vpmovd2m: return "vpmovd2m";
    case Opcode::vpmovq2m: return "vpmovq2m";
    case Opcode::vpopcntb: return "vpopcntb";
    case Opcode::vpopcntw: return "vpopcntw";
    case Opcode::vpopcntd: return "vpopcntd";
    case Opcode::vpopcntq: return "vpopcntq";
    case Opcode::vpcmpb: return "vpcmpb";
    case Opcode::vpcmpw: return "vpcmpw";
    case Opcode::vpcmpd: return "vpcmpd";
    case Opcode::vpcmpq: return "vpcmpq";
    case Opcode::vpcmpub: return "vpcmpub";
    case Opcode::vpcmpuw: return "vpcmpuw";
    case Opcode::vpcmpud: return "vpcmpud";
    case Opcode::vpcmpuq: return "vpcmpuq";
    case Opcode::movdqa: return "movdqa";
    case Opcode::movdqu: return "movdqu";
    case Opcode::movss: return "movss";
    case Opcode::movsd: return "movsd";
    case Opcode::addss: return "addss";
    case Opcode::addsd: return "addsd";
    case Opcode::subss: return "subss";
    case Opcode::subsd: return "subsd";
    case Opcode::mulss: return "mulss";
    case Opcode::mulsd: return "mulsd";
    case Opcode::divss: return "divss";
    case Opcode::divsd: return "divsd";
    default: return "opcode_" + std::to_string(static_cast<unsigned>(opcode));
    }
}

bool is_binary(Opcode opcode) {
    switch (opcode) {
    case Opcode::add: case Opcode::bit_or: case Opcode::adc: case Opcode::sbb: case Opcode::bit_and:
    case Opcode::sub: case Opcode::bit_xor: case Opcode::cmp: case Opcode::test: case Opcode::imul:
    case Opcode::rol: case Opcode::ror: case Opcode::rcl: case Opcode::rcr: case Opcode::shl: case Opcode::shr:
    case Opcode::sar: case Opcode::a64_add: case Opcode::a64_adds: case Opcode::a64_sub: case Opcode::a64_subs:
    case Opcode::a64_adc: case Opcode::a64_adcs: case Opcode::a64_sbc: case Opcode::a64_sbcs:
    case Opcode::a32_and: case Opcode::a32_eor: case Opcode::a32_sub: case Opcode::a32_rsb:
    case Opcode::a32_add: case Opcode::a32_adc: case Opcode::a32_sbc: case Opcode::a32_rsc:
    case Opcode::t32_addw: case Opcode::t32_subw:
    case Opcode::a32_tst: case Opcode::a32_teq: case Opcode::a32_cmp: case Opcode::a32_cmn:
    case Opcode::a32_orr: case Opcode::a32_bic: return true;
    default: return false;
    }
}

ExpressionPtr boolean_binary(std::string operation, ExpressionPtr left, ExpressionPtr right);
ExpressionPtr boolean_unary(std::string operation, ExpressionPtr value);
ExpressionPtr boolean_constant(bool value);

ExpressionPtr a64_nzcv_arithmetic(ExpressionPtr left, ExpressionPtr right, bool subtract,
                                  ExpressionPtr carry_in = {}) {
    if (!left || !right || (left->type.bits != 32 && left->type.bits != 64) ||
        left->type.bits != right->type.bits) return {};
    const auto width = left->type.bits;
    auto arithmetic = std::make_shared<Expression>(Expression{integer_type(width),
        BinaryValue{subtract ? "sub" : "add", left, right}});
    auto result = arithmetic;
    if (carry_in) {
        auto widened_carry = std::make_shared<Expression>(Expression{integer_type(width),
            UnaryValue{"zext", carry_in}});
        if (subtract) {
            auto borrow = std::make_shared<Expression>(Expression{integer_type(width),
                BinaryValue{"sub", left, right}});
            auto minus_one = std::make_shared<Expression>(Expression{integer_type(width),
                BinaryValue{"sub", borrow, constant_expr(1, width)}});
            result = std::make_shared<Expression>(Expression{integer_type(width),
                BinaryValue{"add", minus_one, widened_carry}});
        } else result = std::make_shared<Expression>(Expression{integer_type(width),
            BinaryValue{"add", arithmetic, widened_carry}});
    }
    const auto lhs_sign = boolean_unary("signbit", left);
    const auto rhs_sign = boolean_unary("signbit", right);
    const auto result_sign = boolean_unary("signbit", result);
    const auto different_inputs = boolean_binary("bool_xor", lhs_sign, rhs_sign);
    const auto sign_changed = boolean_binary("bool_xor", lhs_sign, result_sign);
    const auto overflow = boolean_binary("bool_and",
        subtract ? different_inputs : boolean_unary("not", different_inputs), sign_changed);
    ExpressionPtr carry;
    if (!carry_in) carry = subtract ? boolean_binary("uge", left, right)
                                    : boolean_binary("ult", result, left);
    else if (subtract) {
        const auto carry_set = boolean_binary("ne", carry_in, constant_expr(0, 1));
        carry = boolean_binary("bool_or",
            boolean_binary("bool_and", carry_set, boolean_binary("uge", left, right)),
            boolean_binary("bool_and", boolean_unary("not", carry_set), boolean_binary("ugt", left, right)));
    } else {
        const auto carry_set = boolean_binary("ne", carry_in, constant_expr(0, 1));
        const auto carry_from_base = boolean_binary("ult", arithmetic, left);
        const auto carry_from_in = boolean_binary("bool_and", carry_set,
            boolean_binary("eq", arithmetic, constant_expr(width == 64 ? UINT64_MAX : UINT32_MAX, width)));
        carry = boolean_binary("bool_or", carry_from_base, carry_from_in);
    }
    const auto zero = boolean_binary("eq", result, constant_expr(0, width));
    const auto placed = [](ExpressionPtr flag, unsigned shift) -> ExpressionPtr {
        auto value = std::make_shared<Expression>(Expression{integer_type(4),
            UnaryValue{"zext", std::move(flag)}});
        return shift ? std::make_shared<Expression>(Expression{integer_type(4),
            BinaryValue{"shl", std::move(value), constant_expr(shift, 4)}}) : value;
    };
    auto high = std::make_shared<Expression>(Expression{integer_type(4),
        BinaryValue{"or", placed(result_sign, 3), placed(zero, 2)}});
    auto low = std::make_shared<Expression>(Expression{integer_type(4),
        BinaryValue{"or", placed(carry, 1), placed(overflow, 0)}});
    return std::make_shared<Expression>(Expression{integer_type(4),
        BinaryValue{"or", std::move(high), std::move(low)}});
}

ExpressionPtr a64_nzcv_logical(ExpressionPtr result) {
    if (!result || (result->type.bits != 32 && result->type.bits != 64)) return {};
    // A64 ANDS sets C and V to zero even for the shifted-register form.
    // The shift has no carry-out effect on NZCV (unlike A32 logical ops).
    const auto n = std::make_shared<Expression>(Expression{integer_type(4),
        BinaryValue{"shl", std::make_shared<Expression>(Expression{integer_type(4),
            UnaryValue{"zext", boolean_unary("signbit", result)}}), constant_expr(3, 4)}});
    const auto z = std::make_shared<Expression>(Expression{integer_type(4),
        BinaryValue{"shl", std::make_shared<Expression>(Expression{integer_type(4),
            UnaryValue{"zext", boolean_binary("eq", result, constant_expr(0, result->type.bits))}}),
            constant_expr(2, 4)}});
    return std::make_shared<Expression>(Expression{integer_type(4), BinaryValue{"or", n, z}});
}

ExpressionPtr arm32_nzcv_arithmetic(Opcode opcode, ExpressionPtr left, ExpressionPtr right,
                                    ExpressionPtr result, ExpressionPtr prior_flags) {
    if (!left || !right || !result || !prior_flags || left->type.bits != 32 ||
        right->type.bits != 32 || result->type.bits != 32 || prior_flags->type.bits != 4)
        return {};
    const bool reverse = opcode == Opcode::a32_rsb || opcode == Opcode::a32_rsc;
    const auto lhs = reverse ? right : left;
    const auto rhs = reverse ? left : right;
    const bool add = opcode == Opcode::a32_add || opcode == Opcode::a32_adc || opcode == Opcode::a32_cmn;
    const bool with_carry = opcode == Opcode::a32_adc || opcode == Opcode::a32_sbc || opcode == Opcode::a32_rsc;
    if (!add && opcode != Opcode::a32_sub && opcode != Opcode::a32_rsb &&
        opcode != Opcode::a32_sbc && opcode != Opcode::a32_rsc && opcode != Opcode::a32_cmp)
        return {};

    const auto carry_in = boolean_unary("arm_flag_c", prior_flags);
    const auto sign_lhs = boolean_unary("signbit", lhs);
    const auto sign_rhs = boolean_unary("signbit", rhs);
    const auto sign_result = boolean_unary("signbit", result);
    const auto different_inputs = boolean_binary("bool_xor", sign_lhs, sign_rhs);
    const auto sign_changed = boolean_binary("bool_xor", sign_lhs, sign_result);
    const auto overflow = boolean_binary("bool_and",
        add ? boolean_unary("not", different_inputs) : different_inputs, sign_changed);

    ExpressionPtr carry;
    if (add && with_carry) {
        auto partial = std::make_shared<Expression>(Expression{integer_type(32),
            BinaryValue{"add", lhs, rhs}});
        auto widened_carry = std::make_shared<Expression>(Expression{integer_type(32),
            UnaryValue{"zext", carry_in}});
        carry = boolean_binary("bool_or", boolean_binary("carry_add", lhs, rhs),
                               boolean_binary("carry_add", std::move(partial), std::move(widened_carry)));
    } else if (add) {
        carry = boolean_binary("carry_add", lhs, rhs);
    } else if (with_carry) {
        // SBC/RSC subtract 1-C. C is set exactly when the subtraction does
        // not borrow; when an incoming borrow exists, equality also borrows.
        carry = boolean_binary("bool_or",
            boolean_binary("bool_and", carry_in, boolean_binary("uge", lhs, rhs)),
            boolean_binary("bool_and", boolean_unary("not", carry_in), boolean_binary("ugt", lhs, rhs)));
    } else {
        carry = boolean_binary("uge", lhs, rhs);
    }

    const auto zero = boolean_binary("eq", result, constant_expr(0, 32));
    const auto placed = [](ExpressionPtr flag, unsigned shift) -> ExpressionPtr {
        auto widened = std::make_shared<Expression>(Expression{integer_type(4),
            UnaryValue{"zext", std::move(flag)}});
        return std::make_shared<Expression>(Expression{integer_type(4),
            BinaryValue{"shl", std::move(widened), constant_expr(shift, 4)}});
    };
    auto packed = std::make_shared<Expression>(Expression{integer_type(4),
        BinaryValue{"or", placed(sign_result, 3), placed(zero, 2)}});
    auto arithmetic = std::make_shared<Expression>(Expression{integer_type(4),
        BinaryValue{"or", placed(std::move(carry), 1), placed(overflow, 0)}});
    return std::make_shared<Expression>(Expression{integer_type(4),
        BinaryValue{"or", std::move(packed), std::move(arithmetic)}});
}

ExpressionPtr a64_nzcv_predicate(std::uint8_t condition, ExpressionPtr flags) {
    if (condition >= 14) return boolean_constant(true);
    if (!flags || flags->type.bits != 4) return {};
    const auto bit = [&](unsigned index) {
        return boolean_binary("bit_extract", flags, constant_expr(index, 4));
    };
    const auto n = bit(3), z = bit(2), c = bit(1), v = bit(0);
    switch (condition) {
    case 0: return z;
    case 1: return boolean_unary("not", z);
    case 2: return c;
    case 3: return boolean_unary("not", c);
    case 4: return n;
    case 5: return boolean_unary("not", n);
    case 6: return v;
    case 7: return boolean_unary("not", v);
    case 8: return boolean_binary("bool_and", c, boolean_unary("not", z));
    case 9: return boolean_binary("bool_or", boolean_unary("not", c), z);
    case 10: return boolean_binary("eq", n, v);
    case 11: return boolean_binary("ne", n, v);
    case 12: return boolean_binary("bool_and", boolean_unary("not", z), boolean_binary("eq", n, v));
    case 13: return boolean_binary("bool_or", z, boolean_binary("ne", n, v));
    default: return {};
    }
}

// Keep readable predicates compatible with existing ARM pseudocode. Parallel
// output formulas request the expanded, typed boolean condition explicitly.
ExpressionPtr arm32_condition_expr(unsigned condition, ExpressionPtr flags, bool expanded = false) {
    if (!expanded)
        return std::make_shared<Expression>(Expression{ValueType{TypeKind::boolean, 1, false},
            UnaryValue{"arm_condition_" + std::to_string(condition), std::move(flags)}});
    const auto bit = [&](const char *name) { return boolean_unary(name, flags); };
    const auto n = bit("arm_flag_n"), z = bit("arm_flag_z");
    const auto c = bit("arm_flag_c"), v = bit("arm_flag_v");
    switch (condition) {
    case 0: return z;
    case 1: return boolean_unary("not", z);
    case 2: return c;
    case 3: return boolean_unary("not", c);
    case 4: return n;
    case 5: return boolean_unary("not", n);
    case 6: return v;
    case 7: return boolean_unary("not", v);
    case 8: return boolean_binary("bool_and", c, boolean_unary("not", z));
    case 9: return boolean_binary("bool_or", boolean_unary("not", c), z);
    case 10: return boolean_binary("eq", n, v);
    case 11: return boolean_binary("ne", n, v);
    case 12: return boolean_binary("bool_and", boolean_unary("not", z), boolean_binary("eq", n, v));
    case 13: return boolean_binary("bool_or", z, boolean_binary("ne", n, v));
    default:
        return std::make_shared<Expression>(Expression{ValueType{TypeKind::boolean, 1, false},
            UnknownValue{"unresolved ARM execution predicate"}});
    }
}

ExpressionPtr arm32_select(ExpressionPtr predicate, ExpressionPtr when_true, ExpressionPtr when_false) {
    const auto type = when_true->type;
    return std::make_shared<Expression>(Expression{type, BinaryValue{"select_if", std::move(predicate),
        std::make_shared<Expression>(Expression{type, BinaryValue{"pair", std::move(when_true), std::move(when_false)}})}});
}

Statement lift_instruction(const Instruction &instruction, std::vector<std::string> &diagnostics) {
    std::vector<ExpressionPtr> operands;
    operands.reserve(instruction.operands.size());
    for (const auto &operand : instruction.operands)
        operands.push_back(operand_expr(operand));

    const bool x86_context = instruction.context.architecture == Architecture::x86 ||
                             instruction.context.architecture == Architecture::x86_64;
    if (x86_context && instruction.opcode == Opcode::cpuid) {
        const auto malformed = [&]() -> Statement {
            Intrinsic effect{"x86_cpuid_malformed", {}, IntrinsicMemoryEffect::unknown};
            effect.register_writes = instruction.register_writes;
            return effect;
        };
        if (!instruction.operands.empty() || instruction.flow != FlowKind::fallthrough ||
            instruction.memory_read || instruction.memory_write ||
            std::any_of(instruction.register_reads.begin(), instruction.register_reads.end(),
                [](RegisterOperand reg) { return reg.bank == RegisterBank::flags; }) ||
            x86_writes_flags(instruction))
            return malformed();
        const RegisterOperand eax{RegisterBank::gpr, 0, 32, false};
        const RegisterOperand ecx{RegisterBank::gpr, 1, 32, false};
        if ((instruction.context.mode != ExecutionMode::x86_16 &&
             instruction.context.mode != ExecutionMode::x86_32 &&
             instruction.context.mode != ExecutionMode::x86_64) ||
            instruction.register_reads != std::vector<RegisterOperand>{eax, ecx})
            return malformed();
        std::vector<RegisterOperand> expected_writes;
        for (const auto index : {std::uint8_t{0}, std::uint8_t{3}, std::uint8_t{1}, std::uint8_t{2}}) {
            const RegisterOperand low{RegisterBank::gpr, index, 32, false};
            if (instruction.context.mode == ExecutionMode::x86_64)
                expected_writes.push_back({RegisterBank::gpr, index, 64, false});
            expected_writes.push_back(low);
        }
        if (instruction.register_writes != expected_writes) return malformed();
        Intrinsic effect{"x86_cpuid", {reg_expr(eax), reg_expr(ecx)}, IntrinsicMemoryEffect::none};
        effect.register_writes = instruction.register_writes;
        for (const auto written : effect.register_writes) {
            const char *name = written.index == 0 ? "eax" : written.index == 3 ? "ebx" :
                               written.index == 1 ? "ecx" : "edx";
            auto value = unknown_expr(std::string("cpuid_") + name, 32);
            if (written.width == 64)
                value = std::make_shared<Expression>(Expression{integer_type(64), UnaryValue{"zext", std::move(value)}});
            effect.register_output_values.push_back(std::move(value));
        }
        return effect;
    }
    if (x86_context && instruction.opcode == Opcode::bound && operands.size() == 2) {
        const auto *index = std::get_if<RegisterOperand>(&instruction.operands[0]);
        const auto *bounds = std::get_if<MemoryOperand>(&instruction.operands[1]);
        const auto expected_mode_width = instruction.context.mode == ExecutionMode::x86_16 ? 16
            : instruction.context.mode == ExecutionMode::x86_32 ? 32 : 0;
        if (!index || !bounds || expected_mode_width == 0 || index->bank != RegisterBank::gpr ||
            index->width != expected_mode_width || bounds->data_width != expected_mode_width * 2 ||
            instruction.access != std::vector<OperandAccess>{OperandAccess::read, OperandAccess::read} ||
            !instruction.memory_read || instruction.memory_write || !instruction.register_writes.empty() ||
            x86_writes_flags(instruction) || instruction.flow != FlowKind::trap)
            return Intrinsic{"x86_bound_malformed", operands, IntrinsicMemoryEffect::unknown};
        return Intrinsic{"x86_bound", operands, IntrinsicMemoryEffect::read};
    }
    if (x86_context && (instruction.opcode == Opcode::les || instruction.opcode == Opcode::lds) &&
        operands.size() == 2) {
        const auto *destination = std::get_if<RegisterOperand>(&instruction.operands[0]);
        const auto *pointer = std::get_if<MemoryOperand>(&instruction.operands[1]);
        const auto expected_width = instruction.context.mode == ExecutionMode::x86_16 ? 16
            : instruction.context.mode == ExecutionMode::x86_32 ? 32 : 0;
        const RegisterOperand segment{RegisterBank::segment,
            static_cast<std::uint8_t>(instruction.opcode == Opcode::les ? 0 : 3), 16, false};
        const bool has_dest = destination && std::find(instruction.register_writes.begin(),
            instruction.register_writes.end(), *destination) != instruction.register_writes.end();
        const bool has_segment = std::find(instruction.register_writes.begin(),
            instruction.register_writes.end(), segment) != instruction.register_writes.end();
        if (!destination || !pointer || expected_width == 0 || destination->bank != RegisterBank::gpr ||
            destination->width != expected_width || pointer->data_width != expected_width + 16 ||
            instruction.access != std::vector<OperandAccess>{OperandAccess::write, OperandAccess::read} ||
            !instruction.memory_read || instruction.memory_write || !has_dest || !has_segment ||
            instruction.register_writes.size() != 2 || x86_writes_flags(instruction) ||
            instruction.flow != FlowKind::fallthrough)
            return Intrinsic{"x86_far_load_malformed", operands, IntrinsicMemoryEffect::unknown};
        Intrinsic effect{instruction.opcode == Opcode::les ? "x86_les" : "x86_lds", operands,
                         IntrinsicMemoryEffect::read};
        effect.register_writes = instruction.register_writes;
        return effect;
    }
    if (x86_context && (instruction.opcode == Opcode::aam || instruction.opcode == Opcode::aad)) {
        const bool legacy = instruction.context.mode == ExecutionMode::x86_16 ||
                            instruction.context.mode == ExecutionMode::x86_32;
        const auto *base = instruction.operands.size() == 1
            ? std::get_if<ImmediateOperand>(&instruction.operands.front()) : nullptr;
        const bool aam = instruction.opcode == Opcode::aam;
        const std::vector<RegisterOperand> expected_reads = aam
            ? std::vector<RegisterOperand>{{RegisterBank::gpr, 0, 8, false}}
            : std::vector<RegisterOperand>{{RegisterBank::gpr, 0, 8, false},
                                           {RegisterBank::gpr, 0, 8, true}};
        const std::vector<RegisterOperand> expected_writes = aam
            ? std::vector<RegisterOperand>{{RegisterBank::gpr, 0, 8, false},
                                           {RegisterBank::gpr, 0, 8, true}}
            : std::vector<RegisterOperand>{{RegisterBank::gpr, 0, 8, false},
                                           {RegisterBank::gpr, 0, 8, true}};
        if (!legacy || !base || base->encoded_width != 8 || instruction.lock_prefix ||
            instruction.register_reads != expected_reads || instruction.register_writes != expected_writes ||
            !x86_writes_flags(instruction) || instruction.memory_read || instruction.memory_write ||
            instruction.flow != FlowKind::fallthrough)
            return Intrinsic{"x86_radix_adjust_malformed", operands, IntrinsicMemoryEffect::unknown};
        Intrinsic effect{aam ? "x86_aam" : "x86_aad", operands, IntrinsicMemoryEffect::none};
        effect.register_writes = instruction.register_writes;
        return effect;
    }
    if (x86_context && instruction.opcode == Opcode::arpl && operands.size() == 2) {
        const auto *destination = std::get_if<RegisterOperand>(&instruction.operands[0]);
        const auto *memory = std::get_if<MemoryOperand>(&instruction.operands[0]);
        const auto *source = std::get_if<RegisterOperand>(&instruction.operands[1]);
        if (instruction.context.mode != ExecutionMode::x86_16 &&
            instruction.context.mode != ExecutionMode::x86_32)
            return Intrinsic{"x86_arpl_malformed", operands, IntrinsicMemoryEffect::unknown};
        if ((!destination && !memory) || !source || source->bank != RegisterBank::gpr ||
            source->width != 16 || (destination && destination->width != 16) ||
            (memory && memory->data_width != 16) || instruction.lock_prefix ||
            instruction.access != std::vector<OperandAccess>{OperandAccess::read_write, OperandAccess::read} ||
            !x86_writes_flags(instruction) || instruction.flow != FlowKind::fallthrough)
            return Intrinsic{"x86_arpl_malformed", operands, IntrinsicMemoryEffect::unknown};
        Intrinsic effect{"x86_arpl", operands, memory ? IntrinsicMemoryEffect::unknown
                                                       : IntrinsicMemoryEffect::none};
        effect.register_writes = instruction.register_writes;
        return effect;
    }
    if (x86_context && instruction.opcode == Opcode::lahf) {
        const auto flags = std::find_if(instruction.register_reads.begin(), instruction.register_reads.end(),
            [](RegisterOperand reg) { return reg.bank == RegisterBank::flags; });
        const auto ah = std::find_if(instruction.register_writes.begin(), instruction.register_writes.end(),
            [](RegisterOperand reg) { return reg.bank == RegisterBank::gpr && reg.index == 0 &&
                                             reg.width == 8 && reg.high_byte; });
        if (flags != instruction.register_reads.end() && ah != instruction.register_writes.end()) {
            auto value = std::make_shared<Expression>(Expression{integer_type(8),
                UnaryValue{"x86_lahf", reg_expr(*flags)}});
            Intrinsic effect{"lahf", {reg_expr(*flags)}, IntrinsicMemoryEffect::none};
            effect.register_writes = {*ah};
            effect.register_output_values = {std::move(value)};
            return effect;
        }
    }
    if (x86_context && (instruction.opcode == Opcode::rdrand || instruction.opcode == Opcode::rdseed)) {
        const std::string name = instruction.opcode == Opcode::rdrand ? "rdrand" : "rdseed";
        const auto malformed = [&]() -> Statement {
            Intrinsic effect{"x86_" + name + "_malformed", {}, IntrinsicMemoryEffect::unknown};
            effect.register_writes = instruction.register_writes;
            return effect;
        };
        if (!evaluate_x86_random_instruction(instruction, 0, false, 0)) return malformed();
        const auto destination = std::get<RegisterOperand>(instruction.operands[0]);
        const auto flags = instruction.register_reads.back();
        const auto full_width = flags.width;
        const RegisterOperand full{RegisterBank::gpr, destination.index, full_width, false};
        const auto sample_name = "x86_" + name + "_" + std::to_string(instruction.address.space.value) + "_" +
            std::to_string(instruction.address.offset);
        // These unknowns are outputs of this single hardware operation, never
        // calls to a host random generator or pure repeatable expressions.
        auto available = unknown_expr(sample_name + "_available", 1);
        auto alternatives = std::make_shared<Expression>(Expression{integer_type(destination.width),
            BinaryValue{"pair", unknown_expr(sample_name + "_sample", destination.width),
                constant_expr(0, destination.width)}});
        auto value = std::make_shared<Expression>(Expression{integer_type(destination.width),
            BinaryValue{"select_if", available, std::move(alternatives)}});
        auto carry = std::make_shared<Expression>(Expression{integer_type(full_width), UnaryValue{"zext", available}});
        auto preserved_flags = std::make_shared<Expression>(Expression{integer_type(full_width),
            BinaryValue{"and", reg_expr(flags), constant_expr(~UINT64_C(0x8d5), full_width)}});
        auto new_flags = std::make_shared<Expression>(Expression{integer_type(full_width),
            BinaryValue{"or", std::move(preserved_flags), std::move(carry)}});
        ExpressionPtr full_value = value;
        const bool wide_alias = destination.width < full_width;
        if (wide_alias) {
            full_value = std::make_shared<Expression>(Expression{integer_type(full_width), UnaryValue{"zext", value}});
            if (destination.width == 16) {
                auto high = std::make_shared<Expression>(Expression{integer_type(full_width),
                    BinaryValue{"and", reg_expr(full), constant_expr(~UINT64_C(0xffff), full_width)}});
                full_value = std::make_shared<Expression>(Expression{integer_type(full_width),
                    BinaryValue{"or", std::move(high), full_value}});
            }
        }
        Intrinsic effect{"x86_" + name + "_i" + std::to_string(destination.width),
            {reg_expr(flags)}, IntrinsicMemoryEffect::none};
        if (wide_alias && destination.width == 16) effect.operands.push_back(reg_expr(full));
        effect.result_type = integer_type(destination.width);
        effect.register_writes = instruction.register_writes;
        for (const auto written : effect.register_writes) {
            if (written == flags) effect.register_output_values.push_back(new_flags);
            else if (written == destination) effect.register_output_values.push_back(value);
            else if (wide_alias && written == full) effect.register_output_values.push_back(full_value);
            else return malformed();
        }
        return effect;
    }
    if (x86_context && instruction.opcode == Opcode::crc32) {
        const bool long_mode = instruction.context.mode == ExecutionMode::x86_64;
        const bool legacy_mode = instruction.context.mode == ExecutionMode::x86_16 ||
            instruction.context.mode == ExecutionMode::x86_32;
        const auto *destination = instruction.operands.size() == 2
            ? std::get_if<RegisterOperand>(&instruction.operands[0]) : nullptr;
        const auto *source = instruction.operands.size() == 2
            ? std::get_if<RegisterOperand>(&instruction.operands[1]) : nullptr;
        const auto *memory = instruction.operands.size() == 2
            ? std::get_if<MemoryOperand>(&instruction.operands[1]) : nullptr;
        const auto malformed = [&]() -> Statement {
            Intrinsic effect{"x86_crc32_malformed", operands, IntrinsicMemoryEffect::unknown};
            effect.register_writes = instruction.register_writes;
            return effect;
        };
        if ((!long_mode && !legacy_mode) || !destination || destination->bank != RegisterBank::gpr ||
            destination->index >= (long_mode ? 16 : 8) || destination->high_byte ||
            (destination->width != 32 && !(long_mode && destination->width == 64)) ||
            (!source && !memory) || instruction.lock_prefix || instruction.memory_write ||
            instruction.memory_read != (memory != nullptr) || instruction.flow != FlowKind::fallthrough ||
            instruction.access != std::vector<OperandAccess>{OperandAccess::read_write, OperandAccess::read})
            return malformed();
        const auto source_width = source ? source->width : memory->data_width;
        if ((destination->width == 64 ? (source_width != 8 && source_width != 64)
                                     : (source_width != 8 && source_width != 16 && source_width != 32)) ||
            (source && (source->bank != RegisterBank::gpr || source->index >= (long_mode ? 16 : 8) ||
                (source->high_byte && (source_width != 8 || source->index >= 4)))) ||
            (memory && (long_mode ? (memory->address_width != 32 && memory->address_width != 64)
                                 : (memory->address_width != 16 && memory->address_width != 32))))
            return malformed();
        const RegisterOperand wide{RegisterBank::gpr, destination->index, 64, false};
        const bool wide_alias = long_mode && destination->width == 32;
        const auto expected_writes = wide_alias ? std::vector<RegisterOperand>{wide, *destination}
                                               : std::vector<RegisterOperand>{*destination};
        if (instruction.register_writes != expected_writes) return malformed();
        ExpressionPtr seed = operands[0];
        if (destination->width == 64)
            seed = std::make_shared<Expression>(Expression{integer_type(32), UnaryValue{"trunc32", seed}});
        auto crc = std::make_shared<Expression>(Expression{integer_type(32),
            BinaryValue{"x86_crc32c", std::move(seed), operands[1]}});
        ExpressionPtr full = std::make_shared<Expression>(Expression{integer_type(64), UnaryValue{"zext", crc}});
        Intrinsic effect{"x86_crc32c_s" + std::to_string(source_width), {operands[0], operands[1]},
            memory ? IntrinsicMemoryEffect::read : IntrinsicMemoryEffect::none};
        effect.register_writes = instruction.register_writes;
        effect.register_output_values = wide_alias ? std::vector<ExpressionPtr>{full, crc}
            : std::vector<ExpressionPtr>{destination->width == 64 ? full : ExpressionPtr{crc}};
        effect.result_type = integer_type(destination->width);
        return effect;
    }
    if (x86_context && instruction.opcode == Opcode::movbe) {
        const bool long_mode = instruction.context.mode == ExecutionMode::x86_64;
        const bool legacy16 = instruction.context.mode == ExecutionMode::x86_16;
        const bool legacy32 = instruction.context.mode == ExecutionMode::x86_32;
        const auto *destination = instruction.operands.size() == 2
            ? std::get_if<RegisterOperand>(&instruction.operands[0]) : nullptr;
        const auto *source = instruction.operands.size() == 2
            ? std::get_if<RegisterOperand>(&instruction.operands[1]) : nullptr;
        const bool load = destination != nullptr;
        const auto *data = load ? destination : source;
        const auto *memory = instruction.operands.size() == 2
            ? std::get_if<MemoryOperand>(&instruction.operands[load ? 1 : 0]) : nullptr;
        const auto malformed = [&]() -> Statement {
            Intrinsic effect{"x86_movbe_malformed", operands, IntrinsicMemoryEffect::unknown};
            effect.register_writes = instruction.register_writes;
            return effect;
        };
        if ((!long_mode && !legacy16 && !legacy32) || !data || data->bank != RegisterBank::gpr ||
            data->index >= (long_mode ? 16 : 8) || data->high_byte ||
            (data->width != 16 && data->width != 32 && !(long_mode && data->width == 64)) ||
            !memory || memory->data_width != data->width || instruction.lock_prefix ||
            (long_mode ? (memory->address_width != 32 && memory->address_width != 64)
                       : (memory->address_width != 16 && memory->address_width != 32)) ||
            instruction.access != std::vector<OperandAccess>{OperandAccess::write, OperandAccess::read} ||
            instruction.memory_read != load || instruction.memory_write == load ||
            instruction.flow != FlowKind::fallthrough)
            return malformed();
        auto value = std::make_shared<Expression>(Expression{integer_type(data->width),
            UnaryValue{"bswap" + std::to_string(data->width), operands[1]}});
        if (!load) {
            if (!instruction.register_writes.empty()) return malformed();
            return Store{operands[0], std::move(value)};
        }
        const auto full_width = static_cast<std::uint16_t>(long_mode ? 64 : legacy16 ? 16 : 32);
        if (data->width >= full_width) {
            if (instruction.register_writes != std::vector<RegisterOperand>{*data}) return malformed();
            return Assign{*data, std::move(value)};
        }
        const RegisterOperand full{RegisterBank::gpr, data->index, full_width, false};
        if (instruction.register_writes != std::vector<RegisterOperand>{full, *data}) return malformed();
        ExpressionPtr full_value = std::make_shared<Expression>(Expression{integer_type(full_width), UnaryValue{"zext", value}});
        if (data->width == 16) {
            if (std::find(instruction.register_reads.begin(), instruction.register_reads.end(), full) == instruction.register_reads.end())
                return malformed();
            auto high = std::make_shared<Expression>(Expression{integer_type(full_width),
                BinaryValue{"and", reg_expr(full), constant_expr(full_width == 64 ? UINT64_C(0xffffffffffff0000) : UINT64_C(0xffff0000), full_width)}});
            full_value = std::make_shared<Expression>(Expression{integer_type(full_width), BinaryValue{"or", high, full_value}});
        }
        Intrinsic effect{"x86_movbe_load", {operands[1]}, IntrinsicMemoryEffect::read};
        effect.register_writes = instruction.register_writes;
        effect.register_output_values = {std::move(full_value), std::move(value)};
        effect.result_type = integer_type(data->width);
        return effect;
    }
    if (x86_context && instruction.opcode == Opcode::bswap && operands.size() == 1) {
        const auto destination = as_register(instruction.operands.front());
        if (destination && destination->bank == RegisterBank::gpr &&
            (destination->width == 32 || destination->width == 64) &&
            operands.front()->type.bits == destination->width) {
            auto value = std::make_shared<Expression>(Expression{integer_type(destination->width),
                UnaryValue{"bswap" + std::to_string(destination->width), operands.front()}});
            return Assign{*destination, std::move(value)};
        }
    }
    if (x86_context && instruction.opcode == Opcode::popcnt && instruction.operands.size() == 2) {
        const auto destination = as_register(instruction.operands[0]);
        const auto flags = std::find_if(instruction.register_writes.begin(), instruction.register_writes.end(),
            [](RegisterOperand reg) { return reg.bank == RegisterBank::flags; });
        if (destination && destination->bank == RegisterBank::gpr &&
            (destination->width == 16 || destination->width == 32 || destination->width == 64) &&
            operands[1]->type.bits == destination->width && flags != instruction.register_writes.end() &&
            (flags->width == 16 || flags->width == 32 || flags->width == 64)) {
            auto source = retag_expr(operands[1], integer_type(destination->width));
            auto count = std::make_shared<Expression>(Expression{integer_type(destination->width),
                UnaryValue{"popcnt", source}});
            constexpr std::uint64_t affected_flags = (UINT64_C(1) << 0) | (UINT64_C(1) << 2) |
                (UINT64_C(1) << 4) | (UINT64_C(1) << 6) | (UINT64_C(1) << 7) | (UINT64_C(1) << 11);
            auto retained_flags = std::make_shared<Expression>(Expression{integer_type(flags->width),
                BinaryValue{"and", reg_expr(*flags), constant_expr(~affected_flags, flags->width)}});
            auto zero = boolean_binary("eq", source, constant_expr(0, destination->width));
            auto zf = std::make_shared<Expression>(Expression{integer_type(flags->width),
                BinaryValue{"shl", std::make_shared<Expression>(Expression{integer_type(flags->width),
                    UnaryValue{"zext", std::move(zero)}}), constant_expr(6, flags->width)}});
            auto new_flags = std::make_shared<Expression>(Expression{integer_type(flags->width),
                BinaryValue{"or", std::move(retained_flags), std::move(zf)}});

            Intrinsic effect{"x86_popcnt_i" + std::to_string(destination->width), {source},
                is_memory(instruction.operands[1]) ? IntrinsicMemoryEffect::read : IntrinsicMemoryEffect::none};
            effect.register_writes = instruction.register_writes;
            effect.result_type = integer_type(destination->width);
            for (const auto written : effect.register_writes) {
                if (written == *destination)
                    effect.register_output_values.push_back(count);
                else if (written == *flags)
                    effect.register_output_values.push_back(new_flags);
                else
                    return Intrinsic{"x86_popcnt_unmodeled_output", {source}, IntrinsicMemoryEffect::unknown};
            }
            if (effect.register_output_values.size() != effect.register_writes.size())
                return Intrinsic{"x86_popcnt_unmodeled_output", {source}, IntrinsicMemoryEffect::unknown};
            return effect;
        }
    }
    const bool x86_bit_scan = instruction.opcode == Opcode::bsf || instruction.opcode == Opcode::bsr ||
                              instruction.opcode == Opcode::tzcnt || instruction.opcode == Opcode::lzcnt;
    if (x86_context && x86_bit_scan && instruction.operands.size() == 2) {
        const auto destination = as_register(instruction.operands[0]);
        const auto *source_register = std::get_if<RegisterOperand>(&instruction.operands[1]);
        const auto *source_memory = std::get_if<MemoryOperand>(&instruction.operands[1]);
        const auto width = destination ? destination->width : 0;
        const auto flags_read = std::find_if(instruction.register_reads.begin(), instruction.register_reads.end(),
            [](RegisterOperand reg) { return reg.bank == RegisterBank::flags; });
        const auto flags_write = std::find_if(instruction.register_writes.begin(), instruction.register_writes.end(),
            [](RegisterOperand reg) { return reg.bank == RegisterBank::flags; });
        const bool source_shape = (source_register && source_register->bank == RegisterBank::gpr &&
                                   source_register->width == width) ||
                                  (source_memory && source_memory->data_width == width);
        if (destination && destination->bank == RegisterBank::gpr &&
            (width == 16 || width == 32 || width == 64) && source_shape &&
            operands[1]->type.bits == width && flags_read != instruction.register_reads.end() &&
            flags_write != instruction.register_writes.end() &&
            (flags_write->width == 16 || flags_write->width == 32 || flags_write->width == 64)) {
            auto source = retag_expr(operands[1], integer_type(width));
            auto result = std::make_shared<Expression>(Expression{integer_type(width),
                UnaryValue{"x86_" + operation_name(instruction.opcode) + "_i" + std::to_string(width), source}});
            const auto is_zero = boolean_binary("eq", source, constant_expr(0, width));
            const auto is_negative_count = instruction.opcode == Opcode::tzcnt || instruction.opcode == Opcode::lzcnt;
            const std::uint64_t cf_mask = UINT64_C(1) << 0;
            const std::uint64_t zf_mask = UINT64_C(1) << 6;
            const std::uint64_t undefined_mask = (UINT64_C(1) << 2) | (UINT64_C(1) << 4) |
                (UINT64_C(1) << 7) | (UINT64_C(1) << 11) |
                (is_negative_count ? 0 : cf_mask);
            const std::uint64_t defined_mask = zf_mask | (is_negative_count ? cf_mask : 0);
            const auto flags_width = flags_write->width;
            auto updated_flags = std::make_shared<Expression>(Expression{integer_type(flags_width),
                BinaryValue{"and", reg_expr(*flags_read),
                    constant_expr(~(undefined_mask | defined_mask), flags_width)}});
            const auto append_flag = [&](ExpressionPtr value, unsigned bit) {
                auto extended = std::make_shared<Expression>(Expression{integer_type(flags_width),
                    UnaryValue{"zext", std::move(value)}});
                auto shifted = std::make_shared<Expression>(Expression{integer_type(flags_width),
                    BinaryValue{"shl", std::move(extended), constant_expr(bit, flags_width)}});
                updated_flags = std::make_shared<Expression>(Expression{integer_type(flags_width),
                    BinaryValue{"or", std::move(updated_flags), std::move(shifted)}});
            };
            if (undefined_mask) {
                auto arbitrary = std::make_shared<Expression>(Expression{integer_type(flags_width),
                    BinaryValue{"and", unknown_expr("x86_" + operation_name(instruction.opcode) +
                        "_undefined_flags", flags_width), constant_expr(undefined_mask, flags_width)}});
                updated_flags = std::make_shared<Expression>(Expression{integer_type(flags_width),
                    BinaryValue{"or", std::move(updated_flags), std::move(arbitrary)}});
            }
            if (is_negative_count) append_flag(boolean_binary("eq", result, constant_expr(0, width)), 6);
            else append_flag(is_zero, 6);
            if (is_negative_count) append_flag(is_zero, 0);

            Intrinsic effect{"x86_" + operation_name(instruction.opcode) + "_i" + std::to_string(width),
                {source}, source_memory ? IntrinsicMemoryEffect::read : IntrinsicMemoryEffect::none};
            effect.register_writes = instruction.register_writes;
            effect.result_type = integer_type(width);
            for (const auto written : effect.register_writes) {
                if (written == *destination) effect.register_output_values.push_back(result);
                else if (written == *flags_write) effect.register_output_values.push_back(updated_flags);
                else return Intrinsic{"x86_" + operation_name(instruction.opcode) + "_unmodeled_output",
                    {source}, IntrinsicMemoryEffect::unknown};
            }
            if (effect.register_output_values.size() == effect.register_writes.size()) return effect;
        }
    }
    if (instruction.context.architecture == Architecture::x86_64 &&
        instruction.context.mode == ExecutionMode::x86_64 &&
        (instruction.opcode == Opcode::mul || instruction.opcode == Opcode::imul) &&
        instruction.operands.size() == 1) {
        const bool signed_multiply = instruction.opcode == Opcode::imul;
        const auto *source_register = std::get_if<RegisterOperand>(&instruction.operands[0]);
        const auto *source_memory = std::get_if<MemoryOperand>(&instruction.operands[0]);
        const auto width = source_register ? source_register->width : source_memory ? source_memory->data_width : 0;
        const auto malformed = [&]() -> Statement {
            Intrinsic effect{"x86_mul_implicit_malformed", operands, IntrinsicMemoryEffect::unknown};
            effect.register_writes = instruction.register_writes;
            return effect;
        };
        if ((width != 8 && width != 16 && width != 32 && width != 64) ||
            (source_register && (source_register->bank != RegisterBank::gpr || source_register->width != width ||
                source_register->index >= 16 || (source_register->high_byte && (width != 8 || source_register->index >= 4)))) ||
            (source_memory && (source_memory->data_width != width ||
                (source_memory->address_width != 32 && source_memory->address_width != 64))) ||
            (!source_register && !source_memory) ||
            (source_register && std::find(instruction.register_reads.begin(), instruction.register_reads.end(),
                *source_register) == instruction.register_reads.end()) ||
            instruction.lock_prefix || instruction.access != std::vector<OperandAccess>{OperandAccess::read} ||
            instruction.memory_read != (source_memory != nullptr) || instruction.memory_write ||
            instruction.flow != FlowKind::fallthrough)
            return malformed();

        const RegisterOperand accumulator{RegisterBank::gpr, 0,
            static_cast<std::uint16_t>(width == 8 ? 8 : width), false};
        const RegisterOperand low_output{RegisterBank::gpr, 0,
            static_cast<std::uint16_t>(width == 8 ? 16 : width), false};
        const RegisterOperand high_output{RegisterBank::gpr, 2, static_cast<std::uint16_t>(width), false};
        const auto flags = std::find_if(instruction.register_writes.begin(), instruction.register_writes.end(),
            [](RegisterOperand reg) { return reg.bank == RegisterBank::flags; });
        std::vector<RegisterOperand> expected_writes{low_output};
        if (width != 8) expected_writes.push_back(high_output);
        if (flags != instruction.register_writes.end()) expected_writes.push_back(*flags);
        if (std::find(instruction.register_reads.begin(), instruction.register_reads.end(), accumulator) ==
                instruction.register_reads.end() ||
            flags == instruction.register_writes.end() || flags->width != 64 ||
            instruction.register_writes != expected_writes)
            return malformed();

        const auto product_width = static_cast<std::uint16_t>(width * 2);
        auto product = std::make_shared<Expression>(Expression{integer_type(product_width),
            BinaryValue{std::string("x86_mul_full_") + (signed_multiply ? "signed_i" : "unsigned_i") +
                            std::to_string(width),
                        reg_expr(accumulator), retag_expr(operands[0], integer_type(width))}});
        Intrinsic effect{std::string("x86_mul_implicit_") + (signed_multiply ? "signed_i" : "unsigned_i") +
                             std::to_string(width),
                         {reg_expr(accumulator), retag_expr(operands[0], integer_type(width))},
                         source_memory ? IntrinsicMemoryEffect::read : IntrinsicMemoryEffect::none};
        effect.register_writes = instruction.register_writes;
        for (const auto written : effect.register_writes) {
            if (written.bank == RegisterBank::flags) {
                effect.register_output_values.push_back(std::make_shared<Expression>(Expression{
                    integer_type(written.width), UnaryValue{std::string("x86_mul_flags_cf_of_") +
                        (signed_multiply ? "signed_i" : "unsigned_i") + std::to_string(width), product}}));
            } else if (width == 8 && written == low_output) {
                effect.register_output_values.push_back(product);
            } else if (written == low_output) {
                effect.register_output_values.push_back(std::make_shared<Expression>(Expression{
                    integer_type(width), UnaryValue{"x86_mul_low_i" + std::to_string(width), product}}));
            } else if (width != 8 && written == high_output) {
                effect.register_output_values.push_back(std::make_shared<Expression>(Expression{
                    integer_type(width), UnaryValue{"x86_mul_high_i" + std::to_string(width), product}}));
            } else return malformed();
        }
        if (effect.register_output_values.size() != effect.register_writes.size()) return malformed();
        return effect;
    }
    if (x86_context && (instruction.opcode == Opcode::push || instruction.opcode == Opcode::pop ||
                        instruction.opcode == Opcode::pushf || instruction.opcode == Opcode::popf ||
                        instruction.opcode == Opcode::pusha || instruction.opcode == Opcode::popa ||
                        instruction.opcode == Opcode::enter || instruction.opcode == Opcode::leave)) {
        const auto stack_register = [](const std::vector<RegisterOperand> &registers)
            -> std::optional<RegisterOperand> {
            const auto found = std::find_if(registers.begin(), registers.end(), [](RegisterOperand reg) {
                return reg.bank == RegisterBank::gpr && reg.index == 4;
            });
            return found == registers.end() ? std::nullopt : std::optional<RegisterOperand>{*found};
        };
        const auto sp = stack_register(instruction.register_reads);
        const auto sp_write = stack_register(instruction.register_writes);
        const auto stack_pointer = sp ? sp : sp_write;
        const auto value_width = instruction.stack_value_width;
        if (stack_pointer && sp_write && value_width != 0) {
            MemoryOperand stack_slot;
            stack_slot.data_width = value_width;
            stack_slot.address_width = stack_pointer->width;
            const auto stack_segment = std::find_if(instruction.register_reads.begin(), instruction.register_reads.end(),
                [](RegisterOperand reg) { return reg.bank == RegisterBank::segment && reg.index == 2; });
            if (stack_segment != instruction.register_reads.end()) stack_slot.segment = *stack_segment;
            stack_slot.base = *stack_pointer;
            const auto operation = instruction.opcode;
            if (operation == Opcode::push || operation == Opcode::pushf)
                stack_slot.displacement = -static_cast<std::int64_t>(value_width / 8);
            if (operation == Opcode::leave) {
                const auto bp = std::find_if(instruction.register_reads.begin(), instruction.register_reads.end(),
                    [](RegisterOperand reg) { return reg.bank == RegisterBank::gpr && reg.index == 5; });
                if (bp != instruction.register_reads.end()) {
                    stack_slot.base = *bp;
                    stack_slot.address_width = bp->width;
                }
            }
            std::vector<ExpressionPtr> effect_operands;
            if (operation == Opcode::push || operation == Opcode::pop) {
                if (operands.size() == 1) effect_operands.push_back(operands.front());
            } else if (operation == Opcode::pushf || operation == Opcode::popf) {
                const auto flags = operation == Opcode::pushf
                    ? std::find_if(instruction.register_reads.begin(), instruction.register_reads.end(),
                        [](RegisterOperand reg) { return reg.bank == RegisterBank::flags; })
                    : std::find_if(instruction.register_writes.begin(), instruction.register_writes.end(),
                        [](RegisterOperand reg) { return reg.bank == RegisterBank::flags; });
                if (flags != (operation == Opcode::pushf ? instruction.register_reads.end() : instruction.register_writes.end()))
                    effect_operands.push_back(reg_expr(*flags));
            } else {
                effect_operands = operands;
            }
            effect_operands.push_back(memory_expr(stack_slot));
            effect_operands.push_back(reg_expr(*stack_pointer));
            if (operation == Opcode::enter || operation == Opcode::leave) {
                const auto bp = std::find_if(instruction.register_reads.begin(), instruction.register_reads.end(),
                    [](RegisterOperand reg) { return reg.bank == RegisterBank::gpr && reg.index == 5; });
                if (bp != instruction.register_reads.end()) effect_operands.push_back(reg_expr(*bp));
            }
            Intrinsic effect{"x86_" + operation_name(operation) + "_stack_i" + std::to_string(value_width),
                std::move(effect_operands),
                instruction.memory_read && instruction.memory_write ? IntrinsicMemoryEffect::unknown :
                instruction.memory_read ? IntrinsicMemoryEffect::read :
                instruction.memory_write ? IntrinsicMemoryEffect::write : IntrinsicMemoryEffect::none};
            effect.register_writes = instruction.register_writes;
            if (operation == Opcode::enter && instruction.operands.size() == 2) {
                if (const auto *level = std::get_if<ImmediateOperand>(&instruction.operands[1]))
                    effect.name += "_level_" + std::to_string(level->value & 0x1fu);
            }
            if ((operation == Opcode::pusha || operation == Opcode::popa || operation == Opcode::enter) &&
                instruction.stack_slot_count > 1)
                effect.name += "_slots_" + std::to_string(instruction.stack_slot_count);
            return effect;
        }
    }
    const bool x86_string = instruction.opcode == Opcode::x86_movs || instruction.opcode == Opcode::x86_cmps ||
                            instruction.opcode == Opcode::x86_stos || instruction.opcode == Opcode::x86_lods ||
                            instruction.opcode == Opcode::x86_scas || instruction.opcode == Opcode::x86_ins ||
                            instruction.opcode == Opcode::x86_outs;
    if (x86_context && x86_string) {
        const MemoryOperand *memory = nullptr;
        for (const auto &operand : instruction.operands) {
            if (const auto *candidate = std::get_if<MemoryOperand>(&operand)) {
                memory = candidate;
                break;
            }
        }
        // Decoded string operations always carry their implicit memory
        // operands. If an incomplete synthetic fact omits them, retain the
        // ordinary fallback below rather than inventing address/width data.
        if (memory) {
            const auto operation = instruction.opcode == Opcode::x86_movs ? "movs" :
                                   instruction.opcode == Opcode::x86_cmps ? "cmps" :
                                   instruction.opcode == Opcode::x86_stos ? "stos" :
                                   instruction.opcode == Opcode::x86_lods ? "lods" :
                                   instruction.opcode == Opcode::x86_scas ? "scas" :
                                   instruction.opcode == Opcode::x86_ins ? "ins" : "outs";
            const bool compare = instruction.opcode == Opcode::x86_cmps || instruction.opcode == Opcode::x86_scas;
            const auto repeat = instruction.x86_repeat == X86RepeatPrefix::none ? "once" :
                                compare ? (instruction.x86_repeat == X86RepeatPrefix::rep ? "repe" : "repne") :
                                          "rep_count";
            std::vector<ExpressionPtr> inputs = operands;
            // MemoryValue retains each decoded address register. Add implicit
            // count/FLAGS inputs (not explicit string operands) so SSA and the
            // diagnostic formatter expose the dynamic loop controls.
            for (const auto &reg : instruction.register_reads) {
                const bool explicit_register = std::any_of(instruction.operands.begin(), instruction.operands.end(),
                    [&](const Operand &operand) {
                        const auto *explicit_reg = std::get_if<RegisterOperand>(&operand);
                        return explicit_reg && *explicit_reg == reg;
                    });
                if (!explicit_register && reg.bank == RegisterBank::flags)
                    inputs.push_back(reg_expr(reg));
                else if (!explicit_register && reg.bank == RegisterBank::gpr && reg.index == 1 &&
                         instruction.x86_repeat != X86RepeatPrefix::none)
                    inputs.push_back(reg_expr(reg));
                else if (!explicit_register && reg.bank == RegisterBank::gpr && reg.index == 2 &&
                         (instruction.opcode == Opcode::x86_ins || instruction.opcode == Opcode::x86_outs))
                    inputs.push_back(reg_expr(reg));
            }
            Intrinsic effect{"x86_string_" + std::string(operation) + "_i" +
                                 std::to_string(memory->data_width) + "_a" +
                                 std::to_string(memory->address_width) + "_" + repeat,
                std::move(inputs), instruction.memory_read && instruction.memory_write
                    ? IntrinsicMemoryEffect::unknown
                    : instruction.memory_write ? IntrinsicMemoryEffect::write
                    : instruction.memory_read ? IntrinsicMemoryEffect::read : IntrinsicMemoryEffect::none};
            effect.register_writes = instruction.register_writes;
            return effect;
        }
    }

    if ((instruction.opcode == Opcode::a64_ldp || instruction.opcode == Opcode::a64_stp) &&
        instruction.context.architecture == Architecture::arm64 && instruction.operands.size() == 3) {
        const auto *address = std::get_if<MemoryOperand>(&instruction.operands[2]);
        if (address) {
            auto second_address = *address;
            second_address.displacement += static_cast<std::int64_t>(address->data_width / 8);
            auto effect_operands = instruction.opcode == Opcode::a64_ldp
                ? std::vector<ExpressionPtr>{memory_expr(*address), memory_expr(second_address)}
                : std::vector<ExpressionPtr>{operands[0], operands[1], memory_expr(*address),
                                             memory_expr(second_address)};
            if (address->writeback) {
                const auto displacement = address->writeback_displacement;
                const auto magnitude = displacement < 0
                    ? static_cast<std::uint64_t>(-(displacement + 1)) + 1
                    : static_cast<std::uint64_t>(displacement);
                auto updated_base = std::make_shared<Expression>(Expression{
                    integer_type(address->base ? address->base->width : 64),
                    BinaryValue{displacement < 0 ? "sub" : "add",
                                address->base ? reg_expr(*address->base) : unknown_expr("a64-pair-base", 64),
                                constant_expr(magnitude,
                                              address->base ? address->base->width : 64)}});
                effect_operands.push_back(std::move(updated_base));
            }
            std::string name = instruction.opcode == Opcode::a64_ldp ? "a64_ldp" : "a64_stp";
            if (address->writeback) name += address->post_index ? "_post_index" : "_pre_index";
            Intrinsic effect{std::move(name), std::move(effect_operands),
                instruction.opcode == Opcode::a64_ldp ? IntrinsicMemoryEffect::read : IntrinsicMemoryEffect::write};
            effect.register_writes = instruction.register_writes;
            return effect;
        }
    }

    if (instruction.context.architecture == Architecture::arm64 &&
        (instruction.opcode == Opcode::a64_ldr || instruction.opcode == Opcode::a64_str ||
         instruction.opcode == Opcode::a64_ldrb || instruction.opcode == Opcode::a64_strb ||
         instruction.opcode == Opcode::a64_ldrh || instruction.opcode == Opcode::a64_strh) &&
        instruction.operands.size() == 2) {
        const auto *address = std::get_if<MemoryOperand>(&instruction.operands[1]);
        if (address && address->writeback) {
            const bool load = instruction.opcode == Opcode::a64_ldr || instruction.opcode == Opcode::a64_ldrb ||
                              instruction.opcode == Opcode::a64_ldrh;
            std::vector<ExpressionPtr> effect_operands;
            if (!load) effect_operands.push_back(operands[0]);
            effect_operands.push_back(memory_expr(*address));
            const auto displacement = address->writeback_displacement;
            const auto magnitude = displacement < 0
                ? static_cast<std::uint64_t>(-(displacement + 1)) + 1
                : static_cast<std::uint64_t>(displacement);
            const auto base_width = address->base ? address->base->width : 64;
            effect_operands.push_back(std::make_shared<Expression>(Expression{
                integer_type(base_width),
                BinaryValue{displacement < 0 ? "sub" : "add",
                            address->base ? reg_expr(*address->base) : unknown_expr("a64-load-store-base", base_width),
                            constant_expr(magnitude, base_width)}}));
            const char *operation = instruction.opcode == Opcode::a64_ldr ? "ldr" :
                instruction.opcode == Opcode::a64_str ? "str" :
                instruction.opcode == Opcode::a64_ldrb ? "ldrb" :
                instruction.opcode == Opcode::a64_strb ? "strb" :
                instruction.opcode == Opcode::a64_ldrh ? "ldrh" : "strh";
            auto name = std::string("a64_") + operation;
            name += address->post_index ? "_post_index" : "_pre_index";
            Intrinsic effect;
            effect.name = std::move(name);
            effect.operands = std::move(effect_operands);
            effect.memory_effect = load ? IntrinsicMemoryEffect::read : IntrinsicMemoryEffect::write;
            effect.register_writes = instruction.register_writes;
            return effect;
        }
    }

    if ((instruction.context.architecture == Architecture::x86 ||
         instruction.context.architecture == Architecture::x86_64) &&
        instruction.opcode == Opcode::x86_flag_control) {
        const auto &name = instruction.mnemonic_override;
        const auto flags = std::find_if(instruction.register_reads.begin(), instruction.register_reads.end(),
            [](RegisterOperand reg) { return reg.bank == RegisterBank::flags; });
        const auto written_flags = std::find_if(instruction.register_writes.begin(),
            instruction.register_writes.end(), [](RegisterOperand reg) { return reg.bank == RegisterBank::flags; });
        if (written_flags == instruction.register_writes.end())
            return Intrinsic{name, {unknown_expr("FLAGS", 64)}, IntrinsicMemoryEffect::none};
        auto input_flags = flags == instruction.register_reads.end()
            ? unknown_expr("FLAGS", written_flags->width) : reg_expr(*flags);
        Intrinsic effect{name, {input_flags}, IntrinsicMemoryEffect::none};
        effect.register_writes = instruction.register_writes;
        auto result = std::make_shared<Expression>(Expression{integer_type(written_flags->width),
            UnaryValue{"x86_" + name, input_flags}});
        effect.register_output_values.push_back(std::move(result));
        return effect;
    }

    if ((instruction.context.architecture == Architecture::x86 ||
         instruction.context.architecture == Architecture::x86_64) && instruction.opcode == Opcode::x87) {
        const auto &name = instruction.mnemonic_override;
        const bool integer_memory = name.starts_with("fi");
        const bool real_memory = name == "fld" || name == "fst" || name == "fstp" ||
            name == "fcom" || name == "fcomp" || name.starts_with("fadd") ||
            name.starts_with("fmul") || name.starts_with("fsub") || name.starts_with("fdiv");
        std::vector<ExpressionPtr> typed_operands;
        std::vector<ExpressionPtr> numeric_operands;
        typed_operands.reserve(operands.size() + instruction.register_reads.size());
        for (std::size_t index = 0; index < operands.size(); ++index) {
            const auto &decoded_operand = instruction.operands[index];
            if (const auto *reg = std::get_if<RegisterOperand>(&decoded_operand);
                reg && reg->bank == RegisterBank::x87) {
                typed_operands.push_back(retag_expr(operands[index], floating_type(80)));
                numeric_operands.push_back(retag_expr(operands[index], floating_type(80)));
            } else if (const auto *memory = std::get_if<MemoryOperand>(&decoded_operand)) {
                const auto type = real_memory && !integer_memory ? floating_type(memory->data_width)
                                                                  : integer_type(memory->data_width);
                typed_operands.push_back(retag_expr(operands[index], type));
                if (real_memory && !integer_memory &&
                    (name.starts_with("fadd") || name.starts_with("fmul") ||
                     name.starts_with("fsub") || name.starts_with("fdiv")))
                    numeric_operands.push_back(retag_expr(operands[index], type));
            } else {
                typed_operands.push_back(operands[index]);
            }
        }
        // Include implicit x87 stack and environment inputs (for example
        // ST(0), FSW, FCW, or FTW) without duplicating explicit operands.
        for (const auto &reg : instruction.register_reads) {
            if (reg.bank != RegisterBank::x87 && reg.bank != RegisterBank::x87_status &&
                reg.bank != RegisterBank::x87_control && reg.bank != RegisterBank::x87_tag)
                continue;
            const bool explicit_read = std::any_of(instruction.operands.begin(), instruction.operands.end(),
                [&](const Operand &operand) {
                    const auto *explicit_reg = std::get_if<RegisterOperand>(&operand);
                    return explicit_reg && *explicit_reg == reg;
                });
            if (!explicit_read) {
                typed_operands.push_back(reg.bank == RegisterBank::x87
                    ? retag_expr(reg_expr(reg), floating_type(80)) : reg_expr(reg));
                if (reg.bank == RegisterBank::x87)
                    numeric_operands.push_back(retag_expr(reg_expr(reg), floating_type(80)));
            }
        }
        // ST(i) indexes are relative to TOP. A push or pop changes that
        // mapping, so make the whole logical stack an input/output boundary.
        // The IR retains the exact depth delta below but does not invent the
        // resulting TOP/tag permutation or value placement.
        if (instruction.x87_stack_delta != 0) {
            for (std::uint8_t index = 0; index < 8; ++index) {
                const RegisterOperand reg{RegisterBank::x87, index, 80, false};
                const bool already_read = std::any_of(typed_operands.begin(), typed_operands.end(),
                    [&](const ExpressionPtr &value) {
                        const auto *register_value = std::get_if<RegisterValue>(&value->value);
                        return register_value && register_value->reg == reg;
                    });
                if (!already_read)
                    typed_operands.push_back(retag_expr(reg_expr(reg), floating_type(80)));
            }
        }
        // FLD ST(i) is a stack push plus an exact 80-bit payload copy. Keep
        // that value edge explicit so the later TOP remapper can place the
        // destination in the newly exposed physical slot while reading the
        // source relative to the old TOP. FSW/FTW outputs remain unknown.
        if (name == "fld" && instruction.x87_stack_delta == 1 &&
            instruction.operands.size() == 1 && typed_operands.size() >= 1 &&
            std::holds_alternative<RegisterOperand>(instruction.operands.front()) &&
            std::get<RegisterOperand>(instruction.operands.front()).bank == RegisterBank::x87 &&
            std::any_of(instruction.register_writes.begin(), instruction.register_writes.end(),
                [](RegisterOperand reg) { return reg.bank == RegisterBank::x87 && reg.index == 0; })) {
            Intrinsic effect{"x87_fld", std::move(typed_operands),
                             instruction.memory_read ? IntrinsicMemoryEffect::read : IntrinsicMemoryEffect::none};
            effect.register_writes = instruction.register_writes;
            effect.x87_stack_delta = instruction.x87_stack_delta;
            effect.result_type = floating_type(80);
            effect.register_output_values.reserve(effect.register_writes.size());
            for (const auto reg : effect.register_writes) {
                if (reg.bank == RegisterBank::x87 && reg.index == 0)
                    effect.register_output_values.push_back(retag_expr(operands.front(), floating_type(80)));
                else
                    effect.register_output_values.push_back(unknown_expr("x87-status-after-fld-st", reg.width));
            }
            return effect;
        }
        // FST ST(i) is an exact stack-register copy. Preserve the value edge
        // directly in IR; status/tag state is unchanged by the non-popping form.
        if (name == "fst" && instruction.operands.size() == 1 &&
            std::holds_alternative<RegisterOperand>(instruction.operands.front())) {
            const auto destination = std::get<RegisterOperand>(instruction.operands.front());
            const auto source = std::find_if(instruction.register_reads.begin(), instruction.register_reads.end(),
                [](RegisterOperand reg) { return reg.bank == RegisterBank::x87 && reg.index == 0; });
            const bool tag_output = std::any_of(instruction.register_writes.begin(), instruction.register_writes.end(),
                [](RegisterOperand reg) { return reg.bank == RegisterBank::x87_tag; });
            const bool status_output = std::any_of(instruction.register_writes.begin(), instruction.register_writes.end(),
                [](RegisterOperand reg) { return reg.bank == RegisterBank::x87_status; });
            if (destination.bank == RegisterBank::x87 && source != instruction.register_reads.end() &&
                std::find(instruction.register_writes.begin(), instruction.register_writes.end(), destination) !=
                    instruction.register_writes.end() &&
                instruction.register_writes.size() == 1u + (tag_output ? 1u : 0u) +
                                                        (status_output ? 1u : 0u)) {
                if (!tag_output && !status_output)
                    return Assign{destination, retag_expr(reg_expr(*source), floating_type(80))};
                Intrinsic effect{"x87_fst_sti", typed_operands, IntrinsicMemoryEffect::none};
                effect.register_writes = instruction.register_writes;
                for (const auto reg : effect.register_writes)
                    effect.register_output_values.push_back(reg.bank == RegisterBank::x87
                        ? retag_expr(reg_expr(*source), floating_type(80))
                        : unknown_expr("x87-environment-after-fst", reg.width));
                return effect;
            }
        }
        // FXCH is a parallel two-register payload swap. Keep both outputs
        // explicit so the existing TOP remapper applies the same physical
        // mapping to input values and output locations.
        if (name == "fxch" && instruction.operands.size() == 1 &&
            std::holds_alternative<RegisterOperand>(instruction.operands.front())) {
            const auto destination = std::get<RegisterOperand>(instruction.operands.front());
            const RegisterOperand st0{RegisterBank::x87, 0, 80, false};
            const auto stack_write_count = std::count_if(instruction.register_writes.begin(),
                instruction.register_writes.end(), [](RegisterOperand reg) { return reg.bank == RegisterBank::x87; });
            const bool tag_output = std::any_of(instruction.register_writes.begin(), instruction.register_writes.end(),
                [](RegisterOperand reg) { return reg.bank == RegisterBank::x87_tag; });
            const bool status_output = std::any_of(instruction.register_writes.begin(), instruction.register_writes.end(),
                [](RegisterOperand reg) { return reg.bank == RegisterBank::x87_status; });
            if (destination.bank == RegisterBank::x87 && destination.width == 80 &&
                stack_write_count == (destination.index == 0 ? 1 : 2) &&
                instruction.register_writes.size() == stack_write_count + (tag_output ? 1 : 0) +
                                                       (status_output ? 1 : 0)) {
                Intrinsic effect{"x87_fxch", {retag_expr(reg_expr(st0), floating_type(80)),
                                                retag_expr(reg_expr(destination), floating_type(80))},
                                 IntrinsicMemoryEffect::none};
                effect.register_writes = instruction.register_writes;
                for (const auto reg : effect.register_writes)
                    effect.register_output_values.push_back(reg.bank == RegisterBank::x87
                        ? retag_expr(reg.index == 0 ? reg_expr(destination) : reg_expr(st0), floating_type(80))
                        : unknown_expr("x87-environment-after-fxch", reg.width));
                return effect;
            }
        }
        // Keep the rounded-result expression and the status-word side effect
        // in one intrinsic. This lets SSA retain both architectural outputs.
        const bool real_binary = name == "fadd" || name == "fmul" || name == "fsub" ||
                                 name == "fsubr" || name == "fdiv" || name == "fdivr";
        if (real_binary && numeric_operands.size() == 2 &&
            std::any_of(instruction.register_writes.begin(), instruction.register_writes.end(),
                [](RegisterOperand reg) { return reg.bank == RegisterBank::x87; })) {
            const bool memory_source = !instruction.operands.empty() &&
                std::holds_alternative<MemoryOperand>(instruction.operands.front());
            auto left = numeric_operands[0];
            auto right = numeric_operands[1];
            if (memory_source) std::swap(left, right); // implicit ST(0), explicit memory source
            if (name == "fsubr" || name == "fdivr") std::swap(left, right);
            const std::string operation = name == "fadd" ? "+" : name == "fmul" ? "*" :
                (name == "fsub" || name == "fsubr") ? "-" : "/";
            left = retag_expr(std::move(left), floating_type(80));
            right = retag_expr(std::move(right), floating_type(80));
            auto value = std::make_shared<Expression>(Expression{
                floating_type(80), BinaryValue{operation, std::move(left), std::move(right)}});
            Intrinsic effect{"x87_" + name, std::move(typed_operands),
                instruction.memory_read && instruction.memory_write ? IntrinsicMemoryEffect::unknown :
                instruction.memory_read ? IntrinsicMemoryEffect::read :
                instruction.memory_write ? IntrinsicMemoryEffect::write : IntrinsicMemoryEffect::none};
            effect.result_type = floating_type(80);
            effect.register_writes = instruction.register_writes;
            effect.register_output_values.reserve(effect.register_writes.size());
            for (const auto reg : effect.register_writes)
                effect.register_output_values.push_back(reg.bank == RegisterBank::x87
                    ? value : unknown_expr("x87-status-after-" + name, reg.width));
            return effect;
        }
        if ((name == "fchs" || name == "fabs") && typed_operands.size() == 1 &&
            instruction.register_writes.size() == 1 &&
            instruction.register_writes.front().bank == RegisterBank::x87 &&
            instruction.register_writes.front().index == 0) {
            auto input = retag_expr(typed_operands.front(), floating_type(80));
            auto value = std::make_shared<Expression>(Expression{
                floating_type(80), UnaryValue{name == "fchs" ? "x87_fchs" : "x87_fabs", std::move(input)}});
            return Assign{instruction.register_writes.front(), std::move(value)};
        }
        if (name == "fsqrt" && numeric_operands.size() == 1 &&
            std::any_of(instruction.register_writes.begin(), instruction.register_writes.end(),
                [](RegisterOperand reg) { return reg.bank == RegisterBank::x87 && reg.index == 0; }) &&
            std::any_of(instruction.register_writes.begin(), instruction.register_writes.end(),
                [](RegisterOperand reg) { return reg.bank == RegisterBank::x87_status; })) {
            auto value = std::make_shared<Expression>(Expression{floating_type(80),
                UnaryValue{"x87_sqrt", retag_expr(numeric_operands.front(), floating_type(80))}});
            Intrinsic effect{"x87_fsqrt", std::move(typed_operands), IntrinsicMemoryEffect::none};
            effect.register_writes = instruction.register_writes;
            effect.register_output_values.reserve(effect.register_writes.size());
            for (const auto reg : effect.register_writes)
                effect.register_output_values.push_back(reg.bank == RegisterBank::x87 && reg.index == 0
                    ? value : unknown_expr("x87-status-after-fsqrt", reg.width));
            effect.result_type = floating_type(80);
            return effect;
        }
        if (name == "frndint" && numeric_operands.size() == 1 &&
            std::any_of(instruction.register_writes.begin(), instruction.register_writes.end(),
                [](RegisterOperand reg) { return reg.bank == RegisterBank::x87 && reg.index == 0; }) &&
            std::any_of(instruction.register_writes.begin(), instruction.register_writes.end(),
                [](RegisterOperand reg) { return reg.bank == RegisterBank::x87_status; })) {
            auto value = std::make_shared<Expression>(Expression{floating_type(80),
                UnaryValue{"x87_frndint", retag_expr(numeric_operands.front(), floating_type(80))}});
            Intrinsic effect{"x87_frndint", std::move(typed_operands), IntrinsicMemoryEffect::none};
            effect.register_writes = instruction.register_writes;
            effect.register_output_values.reserve(effect.register_writes.size());
            for (const auto reg : effect.register_writes)
                effect.register_output_values.push_back(reg.bank == RegisterBank::x87 && reg.index == 0
                    ? value : unknown_expr("x87-status-after-frndint", reg.width));
            effect.result_type = floating_type(80);
            return effect;
        }
        if (name == "sahf") {
            const auto ah = std::find_if(instruction.register_reads.begin(), instruction.register_reads.end(),
                [](RegisterOperand reg) { return reg.bank == RegisterBank::gpr && reg.index == 0 &&
                                                 reg.width == 8 && reg.high_byte; });
            const auto flags = std::find_if(instruction.register_reads.begin(), instruction.register_reads.end(),
                [](RegisterOperand reg) { return reg.bank == RegisterBank::flags; });
            const auto flags_width = instruction.context.mode == ExecutionMode::x86_16 ? 16u
                : instruction.context.mode == ExecutionMode::x86_64 ? 64u : 32u;
            const auto ah_value = ah == instruction.register_reads.end()
                ? unknown_expr("AH", 8) : reg_expr(*ah);
            const auto flags_value = flags == instruction.register_reads.end()
                ? unknown_expr("FLAGS", flags_width)
                : reg_expr(*flags);
            Intrinsic effect{"sahf", {ah_value, flags_value}, IntrinsicMemoryEffect::none};
            effect.register_writes = instruction.register_writes;
            const auto written_flags = std::find_if(effect.register_writes.begin(), effect.register_writes.end(),
                [](RegisterOperand reg) { return reg.bank == RegisterBank::flags; });
            if (written_flags != effect.register_writes.end()) {
                auto updated_flags = std::make_shared<Expression>(Expression{
                    integer_type(written_flags->width),
                    BinaryValue{"x86_sahf", flags_value, ah_value}});
                effect.register_output_values.push_back(std::move(updated_flags));
            }
            return effect;
        }
        Intrinsic effect{"x87_" + name, std::move(typed_operands),
            instruction.memory_read && instruction.memory_write ? IntrinsicMemoryEffect::unknown :
            instruction.memory_read ? IntrinsicMemoryEffect::read :
            instruction.memory_write ? IntrinsicMemoryEffect::write : IntrinsicMemoryEffect::none};
        effect.register_writes = instruction.register_writes;
        effect.x87_stack_delta = instruction.x87_stack_delta;
        if (instruction.x87_stack_delta != 0) {
            for (std::uint8_t index = 0; index < 8; ++index) {
                const RegisterOperand reg{RegisterBank::x87, index, 80, false};
                if (std::find(effect.register_writes.begin(), effect.register_writes.end(), reg) ==
                    effect.register_writes.end())
                    effect.register_writes.push_back(reg);
            }
        }
        if (name.starts_with("fadd") || name.starts_with("fmul") || name.starts_with("fsub") ||
            name.starts_with("fdiv") || name == "fld" || name == "fild" || name == "fld1" ||
            name == "fldz" || name == "fchs" || name == "fabs" || name == "fsqrt" ||
            name == "frndint" || name == "fsin" || name == "fcos")
            effect.result_type = floating_type(80);
        return effect;
    }

    if (instruction.context.architecture == Architecture::mips64 &&
        instruction.context.mode == ExecutionMode::mips64) {
        if (auto lifted = lift_mips64_instruction(instruction)) return std::move(*lifted);
    }
    if (instruction.context.architecture == Architecture::powerpc &&
        (instruction.context.mode == ExecutionMode::ppc32 || instruction.context.mode == ExecutionMode::ppc64)) {
        if (auto lifted = lift_ppc_instruction(instruction)) return std::move(*lifted);
    }

    const bool arm32_context = instruction.context.architecture == Architecture::arm &&
        (instruction.context.mode == ExecutionMode::a32 || instruction.context.mode == ExecutionMode::thumb);
    const bool thumb_context = arm32_context && instruction.context.mode == ExecutionMode::thumb;
    // BKPT is explicitly unconditional even when incoming ITSTATE is unknown.
    // Every other Thumb instruction needs authoritative incoming IT metadata.
    const bool unconditional_breakpoint = thumb_context && instruction.opcode == Opcode::t32_bkpt &&
        instruction.flow == FlowKind::trap && instruction.arm && instruction.arm->predicate == ArmPredicate::always;
    const bool unknown_it = thumb_context && !unconditional_breakpoint &&
        (!instruction.arm || !instruction.arm->it_before.known || instruction.arm->predicate == ArmPredicate::unknown_it);
    const bool invalid_arm_predicate = arm32_context && instruction.arm &&
        ((instruction.arm->predicate == ArmPredicate::condition && instruction.condition >= 14) ||
         (!thumb_context && instruction.arm->predicate == ArmPredicate::unknown_it));
    if (unknown_it || invalid_arm_predicate) {
        Intrinsic effect{std::string(unknown_it ? "thumb_unknown_it_" : "arm_unknown_predicate_") +
            operation_name(instruction.opcode), operands,
            instruction.flow == FlowKind::call || instruction.flow == FlowKind::trap ||
            (instruction.memory_read && instruction.memory_write) ? IntrinsicMemoryEffect::unknown :
            instruction.memory_read ? IntrinsicMemoryEffect::read :
            instruction.memory_write ? IntrinsicMemoryEffect::write : IntrinsicMemoryEffect::none};
        effect.register_writes = instruction.register_writes;
        const RegisterOperand flags{RegisterBank::arm_flags, 0, 4, false};
        // Unknown IT can also mean an unknown implicit S-bit decision. Such an
        // instruction must not leave a stale NZCV SSA definition live.
        if (unknown_it && (!instruction.arm || !instruction.arm->flags_known || instruction.flow == FlowKind::call) &&
            std::find(effect.register_writes.begin(), effect.register_writes.end(), flags) == effect.register_writes.end())
            effect.register_writes.push_back(flags);
        effect.operands.push_back(reg_expr(flags));
        for (const auto reg : effect.register_writes)
            effect.operands.push_back(reg_expr(reg));
        diagnostics.push_back("instruction at 0x" + [&] { std::ostringstream s; s << std::hex << instruction.address.offset; return s.str(); }() +
            (unknown_it ? " retained because Thumb IT predicate is unknown" : " retained because ARM predicate metadata is invalid"));
        return effect;
    }

    const bool m6502 = instruction.context.architecture == Architecture::mos6502 &&
                       instruction.context.mode == ExecutionMode::m6502;
    if (m6502) {
        const RegisterOperand accumulator{RegisterBank::mos6502, 0, 8, false};
        const RegisterOperand index_x{RegisterBank::mos6502, 1, 8, false};
        const RegisterOperand status{RegisterBank::mos6502, 3, 8, false};
        const RegisterOperand stack_pointer{RegisterBank::mos6502, 4, 8, false};
        const auto status_value = reg_expr(status);
        const auto attach_memory_output = [&](Intrinsic &effect, std::uint32_t location_operand,
                                              std::uint32_t value_operand) {
            if (effect.memory_effect != IntrinsicMemoryEffect::read_write ||
                !instruction.memory_read || !instruction.memory_write || instruction.operands.size() != 1 ||
                instruction.access != std::vector<OperandAccess>{OperandAccess::read_write} ||
                !is_memory(instruction.operands.front()) || location_operand >= effect.operands.size() ||
                value_operand >= effect.operands.size() || location_operand == value_operand ||
                !effect.operands[location_operand] || !effect.operands[value_operand] ||
                effect.operands[location_operand]->type != integer_type(8) ||
                effect.operands[value_operand]->type != integer_type(8) ||
                !std::holds_alternative<MemoryValue>(effect.operands[location_operand]->value))
                return;
            effect.memory_output = IntrinsicMemoryOutput{location_operand, value_operand};
        };
        const auto opaque = [&](std::string name, std::vector<ExpressionPtr> inputs,
                                 std::vector<RegisterOperand> outputs,
                                 IntrinsicMemoryEffect memory = IntrinsicMemoryEffect::none) -> Statement {
            Intrinsic effect{std::move(name), std::move(inputs), memory};
            effect.register_writes = std::move(outputs);
            return effect;
        };
        const auto binary = [](std::string operation, ExpressionPtr left, ExpressionPtr right,
                               std::uint16_t width = 8) -> ExpressionPtr {
            return std::make_shared<Expression>(Expression{
                integer_type(width), BinaryValue{std::move(operation), std::move(left), std::move(right)}});
        };
        const auto stack_read = [&](std::string description) -> ExpressionPtr {
            return std::make_shared<Expression>(Expression{integer_type(8), UnknownValue{std::move(description)}});
        };
        const auto byte_wrap = [&](ExpressionPtr value) {
            return binary("and", std::move(value), constant_expr(0xff, 8));
        };
        const auto placed_flag = [&](ExpressionPtr predicate, unsigned bit) -> ExpressionPtr {
            auto value = std::make_shared<Expression>(Expression{integer_type(8),
                UnaryValue{"zext", std::move(predicate)}});
            return bit == 0 ? value : binary("shl", std::move(value), constant_expr(bit, 8));
        };
        const auto status_with_flags = [&](ExpressionPtr before, std::uint8_t updated_mask,
                                           std::vector<ExpressionPtr> bits) -> ExpressionPtr {
            ExpressionPtr packed = constant_expr(0, 8);
            for (auto &bit : bits) packed = binary("or", std::move(packed), std::move(bit));
            return binary("or", binary("and", std::move(before),
                constant_expr(static_cast<std::uint8_t>(~updated_mask), 8)), std::move(packed));
        };
        const auto nz_flags = [&](ExpressionPtr result, ExpressionPtr before,
                                  std::optional<ExpressionPtr> carry = std::nullopt) -> ExpressionPtr {
            std::vector<ExpressionPtr> bits{
                placed_flag(boolean_binary("eq", result, constant_expr(0, 8)), 1),
                placed_flag(boolean_binary("bit_extract", result, constant_expr(7, 8)), 7)};
            std::uint8_t mask = 0x82;
            if (carry) {
                bits.push_back(placed_flag(std::move(*carry), 0));
                mask |= 0x01;
            }
            return status_with_flags(std::move(before), mask, std::move(bits));
        };
        if (instruction.opcode == Opcode::m6502_rts) {
            auto target = std::make_shared<Expression>(Expression{integer_type(16), UnknownValue{
                "RTS pulls low then high return-address bytes from $0100 | ((S+1)&$ff), wraps S within page $01, and adds one"}});
            return Return{std::move(target)};
        }
        if (instruction.opcode == Opcode::m6502_rti) {
            auto target = std::make_shared<Expression>(Expression{integer_type(16), UnknownValue{
                "RTI pulls P then low/high PC bytes from page-$01 stack with 8-bit S wrap; restored P uses pulled C/Z/I/D/V/N, preserves pseudo-B, and fixes U"}});
            return Return{std::move(target)};
        }
        if (instruction.flow == FlowKind::conditional_branch) {
            std::uint64_t mask = 0;
            bool set = false;
            switch (instruction.opcode) {
            case Opcode::m6502_bpl: mask = 0x80; break;
            case Opcode::m6502_bmi: mask = 0x80; set = true; break;
            case Opcode::m6502_bvc: mask = 0x40; break;
            case Opcode::m6502_bvs: mask = 0x40; set = true; break;
            case Opcode::m6502_bcc: mask = 0x01; break;
            case Opcode::m6502_bcs: mask = 0x01; set = true; break;
            case Opcode::m6502_bne: mask = 0x02; break;
            case Opcode::m6502_beq: mask = 0x02; set = true; break;
            default: break;
            }
            if (mask) {
                auto masked = binary("and", status_value, constant_expr(mask, 8));
                auto predicate = boolean_binary(set ? "eq" : "ne", std::move(masked),
                                                constant_expr(set ? mask : 0, 8));
                return Branch{"predicate", instruction.direct_target, {}, std::move(predicate)};
            }
        }
        if (instruction.opcode == Opcode::m6502_jmp && instruction.flow == FlowKind::jump &&
            !instruction.direct_target && instruction.operands.size() == 1) {
            const auto *pointer = std::get_if<MemoryOperand>(&instruction.operands.front());
            if (pointer && !pointer->base && !pointer->index && !pointer->ip_relative &&
                pointer->displacement >= 0 && pointer->displacement <= UINT16_MAX) {
                const auto slot = static_cast<std::uint16_t>(pointer->displacement);
                const auto high_slot = static_cast<std::uint16_t>((slot & 0xff00u) | ((slot + 1u) & 0x00ffu));
                const auto byte_load = [&](std::uint16_t address) -> ExpressionPtr {
                    MemoryValue value;
                    value.type = integer_type(8);
                    value.absolute = Address{instruction.address.space, address};
                    return std::make_shared<Expression>(Expression{value.type, std::move(value)});
                };
                const auto low = byte_load(slot);
                const auto high = byte_load(high_slot);
                const auto high_word = std::make_shared<Expression>(Expression{integer_type(16),
                    UnaryValue{"zext", high}});
                const auto shifted_high = binary("shl", high_word, constant_expr(8, 16), 16);
                Branch branch;
                branch.condition = "true";
                branch.indirect_target = binary("or",
                    std::make_shared<Expression>(Expression{integer_type(16), UnaryValue{"zext", low}}),
                    shifted_high, 16);
                return branch;
            }
        }
        const auto op = instruction.opcode;
        if (!operands.empty()) {
            if (op == Opcode::m6502_lax && is_memory(instruction.operands.front())) {
                const auto value = operands.front();
                const auto zero = boolean_binary("eq", value, constant_expr(0, 8));
                const auto negative = boolean_unary("signbit", value);
                const auto bool_byte = [](ExpressionPtr predicate) -> ExpressionPtr {
                    return std::make_shared<Expression>(Expression{integer_type(8), UnaryValue{"zext", std::move(predicate)}});
                };
                const auto bit = [&](ExpressionPtr predicate, unsigned index) -> ExpressionPtr {
                    return binary("shl", bool_byte(std::move(predicate)), constant_expr(index, 8));
                };
                const auto flags = binary("or", binary("and", status_value, constant_expr(0x7d, 8)),
                    binary("or", bit(zero, 1), bit(negative, 7)));
                Intrinsic effect{"m6502_lax_load_a_and_x", {value}, IntrinsicMemoryEffect::read};
                effect.register_writes = {accumulator, index_x, status};
                effect.register_output_values = {value, value, flags};
                return effect;
            }
            if (op == Opcode::m6502_sax && is_memory(instruction.operands.front()))
                return Store{operands.front(), binary("and", reg_expr(accumulator), reg_expr(index_x))};
            if (op == Opcode::m6502_axs && std::holds_alternative<ImmediateOperand>(instruction.operands.front())) {
                const auto source = binary("and", reg_expr(accumulator), reg_expr(index_x));
                const auto difference = binary("sub", source, operands.front());
                const auto result = binary("and", difference, constant_expr(0xff, 8));
                const auto as_byte = [](ExpressionPtr predicate) -> ExpressionPtr {
                    return std::make_shared<Expression>(Expression{integer_type(8), UnaryValue{"zext", std::move(predicate)}});
                };
                const auto flag_bit = [&](ExpressionPtr predicate, unsigned bit) -> ExpressionPtr {
                    auto value = as_byte(std::move(predicate));
                    return bit ? binary("shl", std::move(value), constant_expr(bit, 8)) : value;
                };
                const auto carry = boolean_binary("uge", source, operands.front());
                const auto zero = boolean_binary("eq", result, constant_expr(0, 8));
                const auto negative = boolean_unary("signbit", result);
                const auto preserved = binary("and", status_value, constant_expr(0x7c, 8));
                const auto flags = binary("or", preserved, binary("or", flag_bit(carry, 0),
                    binary("or", flag_bit(zero, 1), flag_bit(negative, 7))));
                Intrinsic effect{"m6502_axs_and_then_subtract", {source, operands.front(), difference},
                    IntrinsicMemoryEffect::none};
                effect.register_writes = {index_x, status};
                effect.register_output_values = {result, flags};
                return effect;
            }
            if (op == Opcode::m6502_las && is_memory(instruction.operands.front())) {
                const auto value = binary("and", operands.front(), reg_expr(stack_pointer));
                const auto zero = boolean_binary("eq", value, constant_expr(0, 8));
                const auto negative = boolean_binary("bit_extract", value, constant_expr(7, 8));
                const auto bool_byte = [](ExpressionPtr predicate) -> ExpressionPtr {
                    return std::make_shared<Expression>(Expression{integer_type(8), UnaryValue{"zext", std::move(predicate)}});
                };
                const auto bit = [&](ExpressionPtr predicate, unsigned index) -> ExpressionPtr {
                    return binary("shl", bool_byte(std::move(predicate)), constant_expr(index, 8));
                };
                const auto new_status = binary("or",
                    binary("and", status_value, constant_expr(0x7d, 8)),
                    binary("or", bit(zero, 1), bit(negative, 7)));
                Intrinsic effect{"m6502_las_load_and_stack_mask",
                    {operands.front(), reg_expr(stack_pointer), value, status_value}, IntrinsicMemoryEffect::read};
                effect.register_writes = {accumulator, index_x, stack_pointer, status};
                effect.register_output_values = {value, value, value, new_status};
                return effect;
            }
            RegisterOperand destination = accumulator;
            bool loads_accumulator = op == Opcode::m6502_lda;
            if (op == Opcode::m6502_ldx) destination.index = 1;
            if (op == Opcode::m6502_ldy) destination.index = 2;
            if (loads_accumulator || op == Opcode::m6502_ldx || op == Opcode::m6502_ldy) {
                const auto value = operands.front();
                const auto encoded = std::to_integer<unsigned>(instruction.bytes[0]);
                const unsigned immediate_encoding = loads_accumulator ? 0xa9 : op == Opcode::m6502_ldx ? 0xa2 : 0xa0;
                const unsigned zero_page_encoding = loads_accumulator ? 0xa5 : op == Opcode::m6502_ldx ? 0xa6 : 0xa4;
                const unsigned absolute_encoding = loads_accumulator ? 0xad : op == Opcode::m6502_ldx ? 0xae : 0xac;
                const bool immediate = encoded == immediate_encoding;
                const bool zero_page = encoded == zero_page_encoding;
                const bool absolute = encoded == absolute_encoding;
                const auto *literal = std::get_if<ImmediateOperand>(&instruction.operands.front());
                const auto *memory = std::get_if<MemoryOperand>(&instruction.operands.front());
                const auto encoded_operand = static_cast<std::uint16_t>(std::to_integer<unsigned>(instruction.bytes[1]) |
                    (absolute ? std::to_integer<unsigned>(instruction.bytes[2]) << 8 : 0));
                const bool source_valid = immediate
                    ? literal && literal->value == encoded_operand && literal->encoded_width == 8 &&
                        literal->effective_width == 8 && !literal->is_signed
                    : memory && memory->data_width == 8 && memory->address_width == 16 &&
                        !memory->base && !memory->index && !memory->segment && !memory->ip_relative &&
                        !memory->writeback && !memory->post_index && memory->index_extend.empty() &&
                        !memory->index_shift_amount && memory->displacement == encoded_operand &&
                        (!memory->resolved_address || *memory->resolved_address == Address{instruction.address.space, encoded_operand});
                if ((immediate || zero_page || absolute) && source_valid && instruction.operands.size() == 1 &&
                    instruction.length == (absolute ? 3 : 2) && !instruction.memory_write &&
                    instruction.memory_read == !immediate &&
                    instruction.flow == FlowKind::fallthrough &&
                    instruction.access == std::vector<OperandAccess>{OperandAccess::read} &&
                    instruction.register_reads == std::vector<RegisterOperand>{status} &&
                    instruction.register_writes == std::vector<RegisterOperand>{destination, status}) {
                    ExpressionPtr new_status;
                    if (immediate) {
                        // N/Z do not depend on prior P, so the pure evaluator
                        // can supply their exact constant while other bits stay symbolic.
                        const auto evaluated = evaluate_m6502_load(op, static_cast<std::uint8_t>(literal->value), 0);
                        new_status = binary("or", binary("and", status_value, constant_expr(0x7d, 8)),
                            constant_expr(evaluated->status, 8));
                    } else new_status = nz_flags(value, status_value);
                    Intrinsic effect{"m6502_load", {value, status_value},
                        immediate ? IntrinsicMemoryEffect::none : IntrinsicMemoryEffect::read};
                    effect.register_writes = {destination, status};
                    effect.register_output_values = {value, std::move(new_status)};
                    return effect;
                }
                // Indexed/indirect address wrapping cannot be represented by
                // an ordinary MemoryValue, so keep those outputs opaque.
                return opaque("m6502_load", {value}, {destination, status},
                    instruction.memory_read ? IntrinsicMemoryEffect::read : IntrinsicMemoryEffect::none);
            }
            if ((op == Opcode::m6502_sta || op == Opcode::m6502_stx || op == Opcode::m6502_sty) &&
                std::holds_alternative<MemoryOperand>(instruction.operands.front())) {
                RegisterOperand source = accumulator;
                if (op == Opcode::m6502_stx) source.index = 1;
                if (op == Opcode::m6502_sty) source.index = 2;
                return Store{operands.front(), reg_expr(source)};
            }
            if (op == Opcode::m6502_and || op == Opcode::m6502_anc || op == Opcode::m6502_ora || op == Opcode::m6502_eor) {
                const char *operation = (op == Opcode::m6502_and || op == Opcode::m6502_anc) ? "and" :
                                        op == Opcode::m6502_ora ? "or" : "xor";
                const auto result = binary(operation, reg_expr(accumulator), operands.front());
                const auto bool_byte = [](ExpressionPtr value) -> ExpressionPtr {
                    return std::make_shared<Expression>(Expression{integer_type(8), UnaryValue{"zext", std::move(value)}});
                };
                const auto bit = [&](ExpressionPtr value, unsigned index) -> ExpressionPtr {
                    return binary("shl", bool_byte(std::move(value)), constant_expr(index, 8));
                };
                const auto zero = boolean_binary("eq", result, constant_expr(0, 8));
                const auto negative = boolean_binary("bit_extract", result, constant_expr(7, 8));
                const auto preserved = binary("and", status_value, constant_expr(op == Opcode::m6502_anc ? 0x7c : 0x7d, 8));
                auto new_status = binary("or", binary("or", preserved, bit(zero, 1)), bit(negative, 7));
                if (op == Opcode::m6502_anc)
                    new_status = binary("or", new_status, bit(negative, 0));
                Intrinsic effect{op == Opcode::m6502_anc ? "m6502_anc" : op == Opcode::m6502_and ? "m6502_and" :
                                 op == Opcode::m6502_ora ? "m6502_ora" : "m6502_eor",
                                 {}, instruction.memory_read ? IntrinsicMemoryEffect::read
                                                             : IntrinsicMemoryEffect::none};
                effect.register_writes = {accumulator, status};
                effect.register_output_values = {result, new_status};
                return effect;
            }
            if (op == Opcode::m6502_adc || op == Opcode::m6502_sbc ||
                ((op == Opcode::m6502_rra || op == Opcode::m6502_isc) && is_memory(instruction.operands.front()))) {
                const bool subtract = op == Opcode::m6502_sbc || op == Opcode::m6502_isc;
                const auto lhs = reg_expr(accumulator);
                const bool rra = op == Opcode::m6502_rra;
                const bool isc = op == Opcode::m6502_isc;
                const auto old_byte = operands.front();
                const auto rhs = rra ? binary("or", binary("lshr", old_byte, constant_expr(1, 8)),
                    binary("shl", std::make_shared<Expression>(Expression{integer_type(8), UnaryValue{"zext",
                        boolean_binary("bit_extract", status_value, constant_expr(0, 8))}}), constant_expr(7, 8))) :
                    isc ? byte_wrap(binary("add", old_byte, constant_expr(1, 8))) : old_byte;
                const auto bool_byte = [](ExpressionPtr value) -> ExpressionPtr {
                    return std::make_shared<Expression>(Expression{integer_type(8), UnaryValue{"zext", std::move(value)}});
                };
                const auto bit = [&](ExpressionPtr value, unsigned index) -> ExpressionPtr {
                    return binary("shl", bool_byte(std::move(value)), constant_expr(index, 8));
                };
                const auto extend = [](ExpressionPtr value) -> ExpressionPtr {
                    return std::make_shared<Expression>(Expression{integer_type(9), UnaryValue{"zext", std::move(value)}});
                };
                const auto carry_in = rra ? boolean_binary("bit_extract", old_byte, constant_expr(0, 8)) :
                    boolean_binary("bit_extract", status_value, constant_expr(0, 8));
                auto right = rhs;
                if (subtract)
                    right = std::make_shared<Expression>(Expression{integer_type(8), UnaryValue{"bitnot", rhs}});
                const auto wide_sum = binary("add",
                    binary("add", extend(lhs), extend(right), 9), extend(bool_byte(carry_in)), 9);
                const auto result = binary("and", wide_sum, constant_expr(0xff, 9));
                const auto result_byte = std::make_shared<Expression>(Expression{integer_type(8), UnaryValue{"trunc", result}});
                const auto carry = boolean_binary("bit_extract", wide_sum, constant_expr(8, 9));
                const auto zero = boolean_binary("eq", result_byte, constant_expr(0, 8));
                const auto negative = boolean_binary("bit_extract", result_byte, constant_expr(7, 8));
                const auto operand_signs = binary("xor", lhs, rhs);
                const auto overflow_signs = subtract ? operand_signs :
                    std::make_shared<Expression>(Expression{integer_type(8), UnaryValue{"bitnot", operand_signs}});
                const auto overflow_bits = binary("and", overflow_signs, binary("xor", lhs, result_byte));
                const auto overflow = boolean_binary("bit_extract", overflow_bits, constant_expr(7, 8));
                const auto preserved = binary("and", status_value, constant_expr(0x3c, 8));
                const auto binary_status = binary("or",
                    binary("or", binary("or", preserved, bit(carry, 0)), bit(zero, 1)),
                    binary("or", bit(overflow, 6), bit(negative, 7)));
                const auto decimal_bit = boolean_binary("bit_extract", status_value, constant_expr(3, 8));
                ExpressionPtr decimal_result;
                ExpressionPtr decimal_status;
                const auto decimal_unknown = std::make_shared<Expression>(Expression{
                    integer_type(8), UnknownValue{"NMOS 6502 decimal operation with invalid BCD operands"}});
                const auto decimal_unknown_flags = binary("and", decimal_unknown, constant_expr(0xc3, 8));
                if (!subtract) {
                    const auto low_a = binary("and", lhs, constant_expr(0x0f, 8));
                    const auto low_b = binary("and", rhs, constant_expr(0x0f, 8));
                    const auto low_sum = binary("add", binary("add", low_a, low_b), bool_byte(carry_in));
                    const auto low_adjust = binary("select_if", boolean_binary("uge", low_sum, constant_expr(10, 8)),
                        binary("pair", binary("add", low_sum, constant_expr(6, 8)), low_sum));
                    const auto high_a = binary("and", lhs, constant_expr(0xf0, 8));
                    const auto high_b = binary("and", rhs, constant_expr(0xf0, 8));
                    const auto widen = [](ExpressionPtr value) -> ExpressionPtr {
                        return std::make_shared<Expression>(Expression{integer_type(9), UnaryValue{"zext", std::move(value)}});
                    };
                    const auto pre_high_adjust = binary("add",
                        binary("add", widen(high_a), widen(high_b), 9), widen(low_adjust), 9);
                    const auto decimal_carry = boolean_binary("uge", pre_high_adjust, constant_expr(0xa0, 9));
                    const auto intermediate_byte = std::make_shared<Expression>(Expression{integer_type(8),
                        UnaryValue{"trunc", pre_high_adjust}});
                    const auto decimal_negative = boolean_binary("bit_extract", intermediate_byte, constant_expr(7, 8));
                    const auto decimal_overflow = boolean_binary("bit_extract",
                        binary("and", binary("and",
                            std::make_shared<Expression>(Expression{integer_type(8), UnaryValue{"bitnot", binary("xor", lhs, rhs)}}),
                            binary("xor", lhs, intermediate_byte)), constant_expr(0x80, 8)), constant_expr(7, 8));
                    const auto corrected = binary("select_if", decimal_carry,
                        binary("pair", binary("add", pre_high_adjust, constant_expr(0x60, 9), 9), pre_high_adjust), 9);
                    const auto corrected_byte = std::make_shared<Expression>(Expression{integer_type(8),
                        UnaryValue{"trunc", binary("and", corrected, constant_expr(0xff, 9), 9)}});
                    const auto valid_a = boolean_binary("ule", binary("and", lhs, constant_expr(0x0f, 8)), constant_expr(9, 8));
                    const auto valid_b = boolean_binary("ule", binary("and", rhs, constant_expr(0x0f, 8)), constant_expr(9, 8));
                    const auto valid_high_a = boolean_binary("ule", binary("shr", lhs, constant_expr(4, 8)), constant_expr(9, 8));
                    const auto valid_high_b = boolean_binary("ule", binary("shr", rhs, constant_expr(4, 8)), constant_expr(9, 8));
                    const auto valid = boolean_binary("and", boolean_binary("and", valid_a, valid_b),
                        boolean_binary("and", valid_high_a, valid_high_b));
                    decimal_result = binary("select_if", valid, binary("pair", corrected_byte, decimal_unknown));
                    const auto valid_status = binary("or",
                        binary("or", binary("or", preserved, bit(decimal_carry, 0)), bit(zero, 1)),
                        binary("or", bit(decimal_overflow, 6), bit(decimal_negative, 7)));
                    decimal_status = binary("select_if", valid,
                        binary("pair", valid_status, binary("or", preserved, decimal_unknown_flags)));
                } else {
                    const auto borrow = boolean_unary("not", carry_in);
                    const auto low_a = binary("and", lhs, constant_expr(0x0f, 8));
                    const auto low_b = binary("and", rhs, constant_expr(0x0f, 8));
                    const auto low_b_with_borrow = binary("add", low_b, bool_byte(borrow));
                    const auto low_borrow = boolean_binary("ult", low_a, low_b_with_borrow);
                    const auto raw_low = binary("sub", binary("sub", low_a, low_b), bool_byte(borrow));
                    const auto corrected_low = binary("select_if", low_borrow,
                        binary("pair", binary("sub", raw_low, constant_expr(6, 8)), raw_low));
                    const auto high_a = binary("shr", lhs, constant_expr(4, 8));
                    const auto high_b = binary("shr", rhs, constant_expr(4, 8));
                    const auto high_b_with_borrow = binary("add", high_b, bool_byte(low_borrow));
                    const auto high_borrow = boolean_binary("ult", high_a, high_b_with_borrow);
                    const auto raw_high = binary("sub", binary("sub", high_a, high_b), bool_byte(low_borrow));
                    const auto corrected_high = binary("select_if", high_borrow,
                        binary("pair", binary("sub", raw_high, constant_expr(6, 8)), raw_high));
                    const auto low_digit = binary("and", corrected_low, constant_expr(0x0f, 8));
                    const auto high_digit = binary("and", corrected_high, constant_expr(0x0f, 8));
                    const auto intermediate_byte = binary("or", low_digit,
                        binary("shl", raw_high, constant_expr(4, 8)));
                    const auto decimal_negative = boolean_binary("bit_extract", intermediate_byte, constant_expr(7, 8));
                    const auto decimal_overflow = boolean_binary("bit_extract",
                        binary("and", binary("and", binary("xor", lhs, rhs),
                            binary("xor", lhs, intermediate_byte)), constant_expr(0x80, 8)), constant_expr(7, 8));
                    const auto corrected_byte = binary("or", low_digit,
                        binary("shl", high_digit, constant_expr(4, 8)));
                    const auto valid_a = boolean_binary("ule", binary("and", lhs, constant_expr(0x0f, 8)), constant_expr(9, 8));
                    const auto valid_b = boolean_binary("ule", binary("and", rhs, constant_expr(0x0f, 8)), constant_expr(9, 8));
                    const auto valid_high_a = boolean_binary("ule", binary("shr", lhs, constant_expr(4, 8)), constant_expr(9, 8));
                    const auto valid_high_b = boolean_binary("ule", binary("shr", rhs, constant_expr(4, 8)), constant_expr(9, 8));
                    const auto valid = boolean_binary("and", boolean_binary("and", valid_a, valid_b),
                        boolean_binary("and", valid_high_a, valid_high_b));
                    decimal_result = binary("select_if", valid, binary("pair", corrected_byte, decimal_unknown));
                    const auto valid_status = binary("or",
                        binary("or", binary("or", preserved, bit(carry, 0)), bit(zero, 1)),
                        binary("or", bit(decimal_overflow, 6), bit(decimal_negative, 7)));
                    decimal_status = binary("select_if", valid,
                        binary("pair", valid_status, binary("or", preserved, decimal_unknown_flags)));
                }
                const auto alternatives = binary("pair", decimal_result, result_byte);
                const auto selected_result = binary("select_if", decimal_bit, alternatives);
                const auto status_alternatives = binary("pair", decimal_status, binary_status);
                const auto selected_status = binary("select_if", decimal_bit, status_alternatives);
                Intrinsic effect{rra ? "m6502_rra_ror_then_adc" : isc ? "m6502_isc_increment_then_sbc" :
                    subtract ? "m6502_sbc" : "m6502_adc",
                    (rra || isc) ? std::vector<ExpressionPtr>{old_byte, rhs, reg_expr(accumulator), status_value} :
                          std::vector<ExpressionPtr>{},
                    (rra || isc) ? IntrinsicMemoryEffect::read_write :
                        instruction.memory_read ? IntrinsicMemoryEffect::read : IntrinsicMemoryEffect::none};
                effect.register_writes = {accumulator, status};
                effect.register_output_values = {selected_result, selected_status};
                if (rra || isc) attach_memory_output(effect, 0, 1);
                return effect;
            }
            if (op == Opcode::m6502_cmp || op == Opcode::m6502_cpx || op == Opcode::m6502_cpy ||
                op == Opcode::m6502_bit) {
                RegisterOperand compared = accumulator;
                if (op == Opcode::m6502_cpx) compared.index = 1;
                if (op == Opcode::m6502_cpy) compared.index = 2;
                const auto lhs = reg_expr(compared);
                const auto rhs = operands.front();
                const auto as_byte = [](ExpressionPtr predicate) -> ExpressionPtr {
                    return std::make_shared<Expression>(Expression{integer_type(8),
                        UnaryValue{"zext", std::move(predicate)}});
                };
                const auto flag_bit = [&](ExpressionPtr predicate, unsigned bit) -> ExpressionPtr {
                    auto value = as_byte(std::move(predicate));
                    if (bit == 0) return value;
                    return binary("shl", std::move(value), constant_expr(bit, 8));
                };
                const auto write_flags = [&](std::uint8_t updated_mask,
                                             std::vector<ExpressionPtr> bits) -> Statement {
                    ExpressionPtr packed = constant_expr(0, 8);
                    for (auto &bit : bits) packed = binary("or", std::move(packed), std::move(bit));
                    const auto preserved = binary("and", status_value,
                        constant_expr(static_cast<std::uint8_t>(~updated_mask), 8));
                    return Assign{status, binary("or", preserved, std::move(packed))};
                };
                if (op == Opcode::m6502_bit) {
                    const auto zero_test = boolean_binary("eq",
                        binary("and", lhs, rhs), constant_expr(0, 8));
                    const auto negative = boolean_binary("bit_extract", rhs, constant_expr(7, 8));
                    const auto overflow = boolean_binary("bit_extract", rhs, constant_expr(6, 8));
                    return write_flags(0xc2, {flag_bit(zero_test, 1), flag_bit(overflow, 6),
                                              flag_bit(negative, 7)});
                }
                const auto difference = binary("sub", lhs, rhs);
                const auto carry = boolean_binary("uge", lhs, rhs);
                const auto zero = boolean_binary("eq", lhs, rhs);
                const auto negative = boolean_unary("signbit", difference);
                return write_flags(0x83, {flag_bit(carry, 0), flag_bit(zero, 1),
                                          flag_bit(negative, 7)});
            }
            if ((op == Opcode::m6502_slo || op == Opcode::m6502_rla || op == Opcode::m6502_sre) &&
                is_memory(instruction.operands.front())) {
                const auto old_byte = operands.front();
                ExpressionPtr shifted;
                ExpressionPtr carry_out;
                if (op == Opcode::m6502_slo || op == Opcode::m6502_rla) {
                    carry_out = boolean_binary("bit_extract", old_byte, constant_expr(7, 8));
                    shifted = binary("shl", old_byte, constant_expr(1, 8));
                    if (op == Opcode::m6502_rla)
                        shifted = binary("or", shifted,
                            binary("and", status_value, constant_expr(1, 8)));
                } else {
                    carry_out = boolean_binary("bit_extract", old_byte, constant_expr(0, 8));
                    shifted = binary("lshr", old_byte, constant_expr(1, 8));
                }
                shifted = byte_wrap(std::move(shifted));
                const char *logic = op == Opcode::m6502_slo ? "or" :
                                    op == Opcode::m6502_rla ? "and" : "xor";
                const auto accumulator_result = binary(logic, reg_expr(accumulator), shifted);
                const auto flags = nz_flags(accumulator_result, status_value, carry_out);
                const char *name = op == Opcode::m6502_slo ? "m6502_slo_shift_then_ora" :
                                   op == Opcode::m6502_rla ? "m6502_rla_rotate_then_and" :
                                                             "m6502_sre_shift_then_eor";
                Intrinsic effect{name, {old_byte, shifted, reg_expr(accumulator), status_value},
                    IntrinsicMemoryEffect::read_write};
                effect.register_writes = {accumulator, status};
                effect.register_output_values = {accumulator_result, flags};
                attach_memory_output(effect, 0, 1);
                return effect;
            }
            if (op == Opcode::m6502_dcp && is_memory(instruction.operands.front())) {
                const auto decremented = byte_wrap(binary("sub", operands.front(), constant_expr(1, 8)));
                const auto difference = binary("sub", reg_expr(accumulator), decremented);
                const auto carry = boolean_binary("uge", reg_expr(accumulator), decremented);
                const auto flags = nz_flags(difference, status_value, carry);
                Intrinsic effect{"m6502_dcp_decrement_then_compare",
                    {operands.front(), decremented, reg_expr(accumulator), status_value},
                    IntrinsicMemoryEffect::read_write};
                effect.register_writes = {status};
                effect.register_output_values = {flags};
                attach_memory_output(effect, 0, 1);
                return effect;
            }
        }
        const auto flag_change = [&](std::uint8_t mask, bool set) -> Statement {
            return Assign{status, binary(set ? "or" : "and", status_value,
                                          constant_expr(set ? mask : static_cast<std::uint8_t>(~mask), 8))};
        };
        switch (op) {
        case Opcode::m6502_clc: return flag_change(0x01, false);
        case Opcode::m6502_sec: return flag_change(0x01, true);
        case Opcode::m6502_cli: return flag_change(0x04, false);
        case Opcode::m6502_sei: return flag_change(0x04, true);
        case Opcode::m6502_clv: return flag_change(0x40, false);
        case Opcode::m6502_cld: return flag_change(0x08, false);
        case Opcode::m6502_sed: return flag_change(0x08, true);
        default: break;
        }
        if ((op == Opcode::m6502_asl || op == Opcode::m6502_lsr ||
             op == Opcode::m6502_rol || op == Opcode::m6502_ror) && !operands.empty()) {
            const auto *target = std::get_if<RegisterOperand>(&instruction.operands.front());
            const auto input = operands.front();
            const bool accumulator_target = target && target->bank == RegisterBank::mos6502 && target->index == 0;
            const bool memory_target = is_memory(instruction.operands.front());
            if (!accumulator_target && !memory_target)
                return opaque(op == Opcode::m6502_asl ? "m6502_asl" : op == Opcode::m6502_lsr ? "m6502_lsr" :
                              op == Opcode::m6502_rol ? "m6502_rol" : "m6502_ror",
                              {input, status_value}, {status});
            const auto carry_in = binary("and", status_value, constant_expr(1, 8));
            ExpressionPtr result, carry_out;
            if (op == Opcode::m6502_asl || op == Opcode::m6502_rol) {
                carry_out = boolean_binary("bit_extract", input, constant_expr(7, 8));
                result = binary("shl", input, constant_expr(1, 8));
                if (op == Opcode::m6502_rol) result = binary("or", result, carry_in);
            } else {
                carry_out = boolean_binary("bit_extract", input, constant_expr(0, 8));
                result = binary("lshr", input, constant_expr(1, 8));
                if (op == Opcode::m6502_ror)
                    result = binary("or", result, binary("shl", carry_in, constant_expr(7, 8)));
            }
            result = byte_wrap(std::move(result));
            Intrinsic effect{op == Opcode::m6502_asl ? "m6502_asl" : op == Opcode::m6502_lsr ? "m6502_lsr" :
                             op == Opcode::m6502_rol ? "m6502_rol" : "m6502_ror",
                             memory_target ? std::vector<ExpressionPtr>{input, result, status_value}
                                           : std::vector<ExpressionPtr>{input, status_value},
                             memory_target ? IntrinsicMemoryEffect::read_write : IntrinsicMemoryEffect::none};
            effect.register_writes = accumulator_target ? std::vector<RegisterOperand>{accumulator, status}
                                                        : std::vector<RegisterOperand>{status};
            const auto new_status = nz_flags(result, status_value, carry_out);
            effect.register_output_values = accumulator_target
                ? std::vector<ExpressionPtr>{result, new_status}
                : std::vector<ExpressionPtr>{new_status};
            if (memory_target) attach_memory_output(effect, 0, 1);
            return effect;
        }
        if ((op == Opcode::m6502_inc || op == Opcode::m6502_dec) && !operands.empty()) {
            if (!is_memory(instruction.operands.front()))
                return opaque(op == Opcode::m6502_inc ? "m6502_inc" : "m6502_dec",
                              {operands.front(), status_value}, {status}, IntrinsicMemoryEffect::unknown);
            const auto result = byte_wrap(binary(op == Opcode::m6502_inc ? "add" : "sub",
                                                operands.front(), constant_expr(1, 8)));
            Intrinsic effect{op == Opcode::m6502_inc ? "m6502_inc" : "m6502_dec",
                             {operands.front(), result}, IntrinsicMemoryEffect::read_write};
            effect.register_writes = {status};
            effect.register_output_values = {nz_flags(result, status_value)};
            attach_memory_output(effect, 0, 1);
            return effect;
        }
        switch (op) {
        case Opcode::m6502_pha: case Opcode::m6502_php: {
            const bool push_status = op == Opcode::m6502_php;
            ExpressionPtr value = push_status
                ? binary("or", status_value, constant_expr(0x30, 8))
                : reg_expr(accumulator);
            auto effect = opaque(push_status ? "m6502_php_stack_write_page_0100_wrap" :
                                                "m6502_pha_stack_write_page_0100_wrap",
                {value, reg_expr(stack_pointer), constant_expr(0x0100, 16)},
                {stack_pointer}, IntrinsicMemoryEffect::write);
            auto &intrinsic = std::get<Intrinsic>(effect);
            intrinsic.register_output_values = {byte_wrap(binary("sub", reg_expr(stack_pointer), constant_expr(1, 8)))};
            return effect;
        }
        case Opcode::m6502_pla: {
            const auto pulled = stack_read("PLA byte from $0100 | ((S+1)&$ff)");
            const auto new_sp = byte_wrap(binary("add", reg_expr(stack_pointer), constant_expr(1, 8)));
            const auto new_p = nz_flags(pulled, status_value);
            auto effect = opaque("m6502_pla_stack_read_page_0100_wrap", {reg_expr(stack_pointer)},
                                 {accumulator, status, stack_pointer}, IntrinsicMemoryEffect::read);
            std::get<Intrinsic>(effect).register_output_values = {pulled, new_p, new_sp};
            return effect;
        }
        case Opcode::m6502_plp: {
            const auto pulled = stack_read("PLP byte from $0100 | ((S+1)&$ff)");
            const auto new_sp = byte_wrap(binary("add", reg_expr(stack_pointer), constant_expr(1, 8)));
            const auto new_p = binary("or", binary("and", pulled, constant_expr(0xcf, 8)),
                                      binary("or", binary("and", status_value, constant_expr(0x10, 8)),
                                             constant_expr(0x20, 8)));
            auto effect = opaque("m6502_plp_stack_read_page_0100_wrap", {reg_expr(stack_pointer)},
                                 {status, stack_pointer}, IntrinsicMemoryEffect::read);
            std::get<Intrinsic>(effect).register_output_values = {new_p, new_sp};
            return effect;
        }
        case Opcode::m6502_jsr: {
            const auto return_address = constant_expr((instruction.address.offset + 2) & 0xffff, 16);
            const auto high = std::make_shared<Expression>(Expression{integer_type(8), UnaryValue{"trunc", binary("lshr", return_address, constant_expr(8, 16), 16)}});
            const auto low = std::make_shared<Expression>(Expression{integer_type(8), UnaryValue{"trunc", return_address}});
            auto effect = opaque("m6502_jsr_push_return_high_then_low_page_0100_wrap",
                {high, low, reg_expr(stack_pointer), constant_expr(0x0100, 16),
                 instruction.direct_target ? constant_expr(instruction.direct_target->offset, 16) :
                    std::make_shared<Expression>(Expression{integer_type(16), UnknownValue{"missing decoded JSR target"}})},
                {stack_pointer}, IntrinsicMemoryEffect::write);
            std::get<Intrinsic>(effect).register_output_values = {
                byte_wrap(binary("sub", reg_expr(stack_pointer), constant_expr(2, 8)))};
            return effect;
        }
        case Opcode::m6502_brk: {
            const auto pushed_status = binary("or", status_value, constant_expr(0x30, 8));
            auto effect = opaque("m6502_brk_push_pc_plus_2_high_low_status_then_vector_fffe",
                {constant_expr((instruction.address.offset + 2) & 0xffff, 16), pushed_status, reg_expr(stack_pointer),
                 constant_expr(0xfffe, 16), constant_expr(0xffff, 16)},
                {stack_pointer, status}, IntrinsicMemoryEffect::unknown);
            auto &intrinsic = std::get<Intrinsic>(effect);
            intrinsic.register_output_values = {
                byte_wrap(binary("sub", reg_expr(stack_pointer), constant_expr(3, 8))),
                binary("or", status_value, constant_expr(0x04, 8))};
            return effect;
        }
        default: break;
        }
        if (op == Opcode::m6502_tax || op == Opcode::m6502_tay || op == Opcode::m6502_txa ||
            op == Opcode::m6502_tya || op == Opcode::m6502_tsx || op == Opcode::m6502_txs) {
            RegisterOperand source{RegisterBank::mos6502, 0, 8, false};
            RegisterOperand destination = source;
            switch (op) {
            case Opcode::m6502_tax: destination.index = 1; break;
            case Opcode::m6502_tay: destination.index = 2; break;
            case Opcode::m6502_txa: source.index = 1; break;
            case Opcode::m6502_tya: source.index = 2; break;
            case Opcode::m6502_tsx: source.index = 4; destination.index = 1; break;
            case Opcode::m6502_txs: source.index = 1; destination.index = 4; break;
            default: break;
            }
            const bool updates_nz = op != Opcode::m6502_txs;
            const auto transferred = reg_expr(source);
            Intrinsic effect{"m6502_transfer", {transferred, status_value}, IntrinsicMemoryEffect::none};
            effect.register_writes = updates_nz ? std::vector<RegisterOperand>{destination, status}
                                                : std::vector<RegisterOperand>{destination};
            effect.register_output_values = updates_nz
                ? std::vector<ExpressionPtr>{transferred, nz_flags(transferred, status_value)}
                : std::vector<ExpressionPtr>{transferred};
            return effect;
        }
        RegisterOperand counter{RegisterBank::mos6502, 0, 8, false};
        bool increment = true;
        switch (op) {
        case Opcode::m6502_inx: counter.index = 1; break;
        case Opcode::m6502_dex: counter.index = 1; increment = false; break;
        case Opcode::m6502_iny: counter.index = 2; break;
        case Opcode::m6502_dey: counter.index = 2; increment = false; break;
        default: counter.width = 0; break;
        }
        if (counter.width) {
            const auto before = reg_expr(counter);
            const auto result = byte_wrap(binary(increment ? "add" : "sub", before,
                                                  constant_expr(1, 8)));
            Intrinsic effect{increment ? "m6502_increment" : "m6502_decrement",
                             {before, result, status_value}, IntrinsicMemoryEffect::none};
            effect.register_writes = {counter, status};
            effect.register_output_values = {result, nz_flags(result, status_value)};
            return effect;
        }
    }

    const bool a64 = instruction.context.architecture == Architecture::arm64 &&
                     instruction.context.mode == ExecutionMode::a64;
    if (a64 && !instruction.operands.empty()) {
        const auto destination_operand = as_register(instruction.operands.front());
        const auto ignored_write = [&]() -> Statement { return Intrinsic{"nop", {}, IntrinsicMemoryEffect::none}; };
        if ((instruction.opcode == Opcode::a64_ccmp || instruction.opcode == Opcode::a64_ccmn) &&
            instruction.operands.size() == 3) {
            const auto *left = std::get_if<RegisterOperand>(&instruction.operands[0]);
            const auto *right_reg = std::get_if<RegisterOperand>(&instruction.operands[1]);
            const auto *right_imm = std::get_if<ImmediateOperand>(&instruction.operands[1]);
            const auto *fallback = std::get_if<ImmediateOperand>(&instruction.operands[2]);
            if (!left || (left->bank != RegisterBank::arm64_gpr && left->bank != RegisterBank::arm64_zero) ||
                (left->width != 32 && left->width != 64) ||
                (!right_reg && !right_imm) ||
                (right_reg && (right_reg->width != left->width ||
                    (right_reg->bank != RegisterBank::arm64_gpr && right_reg->bank != RegisterBank::arm64_zero))) ||
                (right_imm && (right_imm->encoded_width != 5 || right_imm->value > 31)) ||
                !fallback || fallback->encoded_width != 4 || fallback->value > 15)
                goto a64_unhandled;
            const auto flags{RegisterOperand{RegisterBank::arm_flags, 0, 4, false}};
            const auto left_value = operand_expr(instruction.operands[0]);
            const auto right_value = operand_expr(instruction.operands[1]);
            const auto comparison = a64_nzcv_arithmetic(left_value, right_value,
                instruction.opcode == Opcode::a64_ccmp);
            const auto predicate = a64_nzcv_predicate(instruction.condition, reg_expr(flags));
            if (!comparison || !predicate) goto a64_unhandled;
            Intrinsic effect{instruction.opcode == Opcode::a64_ccmp ? "a64_ccmp" : "a64_ccmn",
                {left_value, right_value, constant_expr(fallback->value, 4),
                 constant_expr(instruction.condition, 4)}, IntrinsicMemoryEffect::none};
            effect.register_writes = {flags};
            effect.register_output_values = {
                instruction.condition >= 14 ? comparison :
                    arm32_select(predicate, comparison, constant_expr(fallback->value, 4))};
            return effect;
        }
        if (destination_operand && instruction.operands.size() == 3 &&
            (instruction.opcode == Opcode::a64_udiv || instruction.opcode == Opcode::a64_sdiv)) {
            const auto destination = *destination_operand;
            const auto *left = std::get_if<RegisterOperand>(&instruction.operands[1]);
            const auto *right = std::get_if<RegisterOperand>(&instruction.operands[2]);
            if (!left || !right || destination.width != left->width || destination.width != right->width ||
                (destination.width != 32 && destination.width != 64) ||
                (destination.bank != RegisterBank::arm64_gpr && destination.bank != RegisterBank::arm64_zero) ||
                (left->bank != RegisterBank::arm64_gpr && left->bank != RegisterBank::arm64_zero) ||
                (right->bank != RegisterBank::arm64_gpr && right->bank != RegisterBank::arm64_zero))
                goto a64_unhandled;
            auto value = std::make_shared<Expression>(Expression{integer_type(destination.width),
                BinaryValue{instruction.opcode == Opcode::a64_udiv ? "a64_udiv" : "a64_sdiv",
                            operand_expr(instruction.operands[1]), operand_expr(instruction.operands[2])}});
            return destination.bank == RegisterBank::arm64_zero ? ignored_write() : Assign{destination, std::move(value)};
        }
        if (destination_operand && instruction.operands.size() == 4 &&
            (instruction.opcode == Opcode::a64_madd || instruction.opcode == Opcode::a64_msub)) {
            const auto destination = *destination_operand;
            const auto *left = std::get_if<RegisterOperand>(&instruction.operands[1]);
            const auto *right = std::get_if<RegisterOperand>(&instruction.operands[2]);
            const auto *accumulator = std::get_if<RegisterOperand>(&instruction.operands[3]);
            if (!left || !right || !accumulator ||
                (destination.bank != RegisterBank::arm64_gpr && destination.bank != RegisterBank::arm64_zero) ||
                (left->bank != RegisterBank::arm64_gpr && left->bank != RegisterBank::arm64_zero) ||
                (right->bank != RegisterBank::arm64_gpr && right->bank != RegisterBank::arm64_zero) ||
                (accumulator->bank != RegisterBank::arm64_gpr && accumulator->bank != RegisterBank::arm64_zero) ||
                destination.width != left->width || destination.width != right->width ||
                destination.width != accumulator->width || (destination.width != 32 && destination.width != 64))
                goto a64_unhandled;
            const auto product = std::make_shared<Expression>(Expression{integer_type(destination.width),
                BinaryValue{"mul", operand_expr(instruction.operands[1]), operand_expr(instruction.operands[2])}});
            auto value = std::make_shared<Expression>(Expression{integer_type(destination.width),
                BinaryValue{instruction.opcode == Opcode::a64_msub ? "sub" : "add", operand_expr(instruction.operands[3]), product}});
            return destination.bank == RegisterBank::arm64_zero ? ignored_write() : Assign{destination, std::move(value)};
        }
        const bool a64_vector_integer = instruction.opcode == Opcode::a64_vadd || instruction.opcode == Opcode::a64_vsub ||
            instruction.opcode == Opcode::a64_vand || instruction.opcode == Opcode::a64_vorr || instruction.opcode == Opcode::a64_veor ||
            instruction.opcode == Opcode::a64_vsmax || instruction.opcode == Opcode::a64_vsmin ||
            instruction.opcode == Opcode::a64_vumax || instruction.opcode == Opcode::a64_vumin;
        const bool a64_vector_fp = instruction.opcode == Opcode::a64_fadd || instruction.opcode == Opcode::a64_fsub ||
            instruction.opcode == Opcode::a64_fmul || instruction.opcode == Opcode::a64_fdiv ||
            instruction.opcode == Opcode::a64_fmax || instruction.opcode == Opcode::a64_fmin;
        if (a64_vector_fp && instruction.operands.size() == 3 &&
            (instruction.vector_bits == 32 || instruction.vector_bits == 64) &&
            instruction.vector_element_bits == instruction.vector_bits) {
            const auto *destination = std::get_if<RegisterOperand>(&instruction.operands[0]);
            const auto *left = std::get_if<RegisterOperand>(&instruction.operands[1]);
            const auto *right = std::get_if<RegisterOperand>(&instruction.operands[2]);
            if (!destination || !left || !right || destination->bank != RegisterBank::arm64_simd ||
                left->bank != RegisterBank::arm64_simd || right->bank != RegisterBank::arm64_simd ||
                destination->width != instruction.vector_bits || left->width != instruction.vector_bits ||
                right->width != instruction.vector_bits || destination->index >= 32 ||
                left->index >= 32 || right->index >= 32)
                goto a64_unhandled;
            const auto scalar_type = floating_type(instruction.vector_bits);
            const char *operation = instruction.opcode == Opcode::a64_fadd ? "fadd" :
                instruction.opcode == Opcode::a64_fsub ? "fsub" :
                instruction.opcode == Opcode::a64_fmul ? "fmul" :
                instruction.opcode == Opcode::a64_fdiv ? "fdiv" :
                instruction.opcode == Opcode::a64_fmax ? "fmax" : "fmin";
            Intrinsic effect;
            effect.name = std::string("a64_scalar_fp_") + operation + "_f" +
                std::to_string(instruction.vector_bits);
            effect.operands = {retag_expr(operand_expr(instruction.operands[1]), scalar_type),
                               retag_expr(operand_expr(instruction.operands[2]), scalar_type)};
            effect.register_writes.push_back(RegisterOperand{RegisterBank::arm64_simd, destination->index, 128, false});
            effect.result_type = ValueType{TypeKind::floating, instruction.vector_bits, false};
            return effect;
        }
        if ((a64_vector_integer || a64_vector_fp) && instruction.operands.size() == 3 &&
            (instruction.vector_bits == 64 || instruction.vector_bits == 128) && instruction.vector_element_bits) {
            const auto *destination = std::get_if<RegisterOperand>(&instruction.operands[0]);
            const auto *left = std::get_if<RegisterOperand>(&instruction.operands[1]);
            const auto *right = std::get_if<RegisterOperand>(&instruction.operands[2]);
            if (!destination || !left || !right || destination->bank != RegisterBank::arm64_simd ||
                left->bank != RegisterBank::arm64_simd || right->bank != RegisterBank::arm64_simd ||
                destination->width != instruction.vector_bits || left->width != instruction.vector_bits ||
                right->width != instruction.vector_bits || destination->index >= 32 || left->index >= 32 || right->index >= 32)
                goto a64_unhandled;
            const auto lane_bits = instruction.vector_element_bits;
            if (lane_bits != 8 && lane_bits != 16 && lane_bits != 32 && lane_bits != 64)
                goto a64_unhandled;
            if (a64_vector_fp && lane_bits != 32 && lane_bits != 64) goto a64_unhandled;
            const auto element_kind = a64_vector_fp ? TypeKind::floating : TypeKind::integer;
            const auto input_type = vector_type(instruction.vector_bits, element_kind, lane_bits,
                static_cast<std::uint8_t>(instruction.vector_bits / lane_bits));
            const auto output_type = vector_type(128, element_kind, lane_bits,
                static_cast<std::uint8_t>(128 / lane_bits));
            const char *operation = instruction.opcode == Opcode::a64_fadd ? "fadd" :
                instruction.opcode == Opcode::a64_fsub ? "fsub" :
                instruction.opcode == Opcode::a64_fmul ? "fmul" :
                instruction.opcode == Opcode::a64_fdiv ? "fdiv" :
                instruction.opcode == Opcode::a64_fmax ? "fmax" :
                instruction.opcode == Opcode::a64_fmin ? "fmin" :
                instruction.opcode == Opcode::a64_vadd ? "add" :
                instruction.opcode == Opcode::a64_vsub ? "sub" :
                instruction.opcode == Opcode::a64_vand ? "and" :
                instruction.opcode == Opcode::a64_vorr ? "orr" :
                instruction.opcode == Opcode::a64_veor ? "eor" :
                instruction.opcode == Opcode::a64_vsmax ? "smax" :
                instruction.opcode == Opcode::a64_vsmin ? "smin" :
                instruction.opcode == Opcode::a64_vumax ? "umax" : "umin";
            auto effect_name = std::string(a64_vector_fp ? "a64_simd_fp_" : "a64_simd_") + operation + "_" +
                std::to_string(instruction.vector_bits / lane_bits) + "x" + std::to_string(lane_bits);
            if (instruction.vector_bits == 64) effect_name += "_zero_upper";
            Intrinsic effect;
            effect.name = std::move(effect_name);
            effect.operands = {retag_expr(operand_expr(instruction.operands[1]), input_type),
                               retag_expr(operand_expr(instruction.operands[2]), input_type)};
            effect.register_writes.push_back(RegisterOperand{RegisterBank::arm64_simd, destination->index, 128, false});
            effect.result_type = output_type;
            return effect;
        }
        if (destination_operand && instruction.operands.size() >= 2 &&
            (instruction.opcode == Opcode::a64_movz || instruction.opcode == Opcode::a64_movn ||
             instruction.opcode == Opcode::a64_movk)) {
            const auto destination = *destination_operand;
            if (destination.bank == RegisterBank::arm64_zero) return ignored_write();
            const auto *immediate = std::get_if<ImmediateOperand>(&instruction.operands[1]);
            if (!immediate) goto a64_unhandled;
            unsigned shift = 0;
            if (instruction.operands.size() > 2) {
                const auto *shift_operand = std::get_if<ImmediateOperand>(&instruction.operands[2]);
                if (!shift_operand) goto a64_unhandled;
                shift = static_cast<unsigned>(shift_operand->value);
            }
            if (shift >= destination.width || shift % 16) goto a64_unhandled;
            const auto value = constant_expr(immediate->value << shift, destination.width);
            if (instruction.opcode == Opcode::a64_movz) return Assign{destination, value};
            if (instruction.opcode == Opcode::a64_movn) {
                auto inverted = std::make_shared<Expression>(Expression{integer_type(destination.width),
                    UnaryValue{"bitnot", value}});
                return Assign{destination, std::move(inverted)};
            }
            const auto field_mask = UINT64_C(0xffff) << shift;
            auto kept = std::make_shared<Expression>(Expression{integer_type(destination.width),
                BinaryValue{"and", reg_expr(destination), constant_expr(~field_mask, destination.width)}});
            auto inserted = std::make_shared<Expression>(Expression{integer_type(destination.width),
                BinaryValue{"or", std::move(kept), value}});
            return Assign{destination, std::move(inserted)};
        }
        if (instruction.opcode == Opcode::a64_bfm) {
            // BFM preserves all destination bits outside the selected field.
            // Non-wrapping encodings extract into bit zero (BFXIL); wrapping
            // encodings insert the low source bits at width-immr (BFI/BFC).
            if (instruction.operands.size() != 4) goto a64_unhandled;
            const auto *destination = std::get_if<RegisterOperand>(&instruction.operands[0]);
            const auto *source = std::get_if<RegisterOperand>(&instruction.operands[1]);
            const auto *rotate = std::get_if<ImmediateOperand>(&instruction.operands[2]);
            const auto *limit = std::get_if<ImmediateOperand>(&instruction.operands[3]);
            const auto valid_register = [](const RegisterOperand *reg) {
                return reg && !reg->high_byte &&
                    ((reg->bank == RegisterBank::arm64_gpr && reg->index < 31) ||
                     (reg->bank == RegisterBank::arm64_zero && reg->index == 31));
            };
            if (!valid_register(destination) || !valid_register(source) ||
                (destination->width != 32 && destination->width != 64) ||
                destination->width != source->width || !rotate || !limit ||
                rotate->encoded_width != 6 || limit->encoded_width != 6 ||
                rotate->effective_width != destination->width || limit->effective_width != destination->width ||
                rotate->is_signed || limit->is_signed ||
                rotate->value >= destination->width || limit->value >= destination->width)
                goto a64_unhandled;
            if (destination->bank == RegisterBank::arm64_zero) return ignored_write();
            const auto width = static_cast<unsigned>(destination->width);
            const auto r = static_cast<unsigned>(rotate->value);
            const auto s = static_cast<unsigned>(limit->value);
            const auto count = s >= r ? s - r + 1 : s + 1;
            const auto shift = s >= r ? 0u : width - r;
            const auto low_mask = count == 64 ? UINT64_MAX : (UINT64_C(1) << count) - 1;
            const auto field_mask = low_mask << shift;
            const auto preserved_mask = ~field_mask & (width == 64 ? UINT64_MAX : UINT64_C(0xffffffff));
            ExpressionPtr inserted = operand_expr(instruction.operands[1]);
            if (s >= r && r)
                inserted = std::make_shared<Expression>(Expression{integer_type(width),
                    BinaryValue{"shr", std::move(inserted), constant_expr(r, width)}});
            inserted = std::make_shared<Expression>(Expression{integer_type(width),
                BinaryValue{"and", std::move(inserted), constant_expr(low_mask, width)}});
            if (shift)
                inserted = std::make_shared<Expression>(Expression{integer_type(width),
                    BinaryValue{"shl", std::move(inserted), constant_expr(shift, width)}});
            auto preserved = std::make_shared<Expression>(Expression{integer_type(width),
                BinaryValue{"and", reg_expr(*destination), constant_expr(preserved_mask, width)}});
            auto value = std::make_shared<Expression>(Expression{integer_type(width),
                BinaryValue{"or", std::move(preserved), std::move(inserted)}});
            return Assign{*destination, std::move(value)};
        }
        if (instruction.opcode == Opcode::a64_extr) {
            if (instruction.operands.size() != 4) goto a64_unhandled;
            const auto *dst = std::get_if<RegisterOperand>(&instruction.operands[0]);
            const auto *lsb = std::get_if<ImmediateOperand>(&instruction.operands[3]);
            if (!dst || !lsb || (dst->width != 32 && dst->width != 64) || lsb->value >= dst->width)
                goto a64_unhandled;
            if (dst->bank == RegisterBank::arm64_zero) return ignored_write();
            const auto width = static_cast<unsigned>(dst->width);
            // EXTR forms the concatenation Rn:Rm, with Rm occupying the
            // low half; lsb zero therefore returns Rm unchanged.
            ExpressionPtr value = operand_expr(instruction.operands[2]);
            if (lsb->value) {
                auto upper = std::make_shared<Expression>(Expression{integer_type(width),
                    BinaryValue{"shl", operand_expr(instruction.operands[1]), constant_expr(width - static_cast<unsigned>(lsb->value), width)}});
                auto lower = std::make_shared<Expression>(Expression{integer_type(width),
                    BinaryValue{"shr", std::move(value), constant_expr(static_cast<unsigned>(lsb->value), width)}});
                value = std::make_shared<Expression>(Expression{integer_type(width), BinaryValue{"or", std::move(upper), std::move(lower)}});
            }
            return Assign{*dst, std::move(value)};
        }
        if ((instruction.opcode == Opcode::a64_rbit || instruction.opcode == Opcode::a64_rev16 ||
             instruction.opcode == Opcode::a64_rev32 || instruction.opcode == Opcode::a64_rev) &&
            instruction.operands.size() == 2) {
            const auto *dst = std::get_if<RegisterOperand>(&instruction.operands[0]);
            if (!dst || (dst->width != 32 && dst->width != 64)) goto a64_unhandled;
            if (dst->bank == RegisterBank::arm64_zero) return ignored_write();
            const unsigned width = dst->width;
            ExpressionPtr value = operand_expr(instruction.operands[1]);
            if (instruction.opcode == Opcode::a64_rbit) {
                const std::uint64_t full_mask = width == 64 ? UINT64_MAX : UINT32_MAX;
                for (unsigned shift = 1; shift < width; shift <<= 1) {
                    std::uint64_t low_mask = 0;
                    for (unsigned bit = 0; bit < width; ++bit)
                        if ((bit % (shift * 2)) < shift) low_mask |= UINT64_C(1) << bit;
                    const auto high_mask = full_mask ^ low_mask;
                    auto low = std::make_shared<Expression>(Expression{integer_type(width),
                        BinaryValue{"and", value, constant_expr(low_mask, width)}});
                    low = std::make_shared<Expression>(Expression{integer_type(width),
                        BinaryValue{"shl", std::move(low), constant_expr(shift, width)}});
                    auto high = std::make_shared<Expression>(Expression{integer_type(width),
                        BinaryValue{"and", value, constant_expr(high_mask, width)}});
                    high = std::make_shared<Expression>(Expression{integer_type(width),
                        BinaryValue{"shr", std::move(high), constant_expr(shift, width)}});
                    value = std::make_shared<Expression>(Expression{integer_type(width),
                        BinaryValue{"or", std::move(low), std::move(high)}});
                }
            } else {
                const unsigned group_bytes = instruction.opcode == Opcode::a64_rev16 ? 2 :
                    instruction.opcode == Opcode::a64_rev32 ? 4 : width / 8;
                ExpressionPtr reversed;
                for (unsigned base = 0; base < width / 8; base += group_bytes) {
                    for (unsigned byte = 0; byte < group_bytes; ++byte) {
                        const unsigned source_shift = (base + byte) * 8;
                        const unsigned destination_shift = (base + group_bytes - 1 - byte) * 8;
                        auto part = std::make_shared<Expression>(Expression{integer_type(width),
                            BinaryValue{"and", value, constant_expr(UINT64_C(0xff) << source_shift, width)}});
                        if (source_shift)
                            part = std::make_shared<Expression>(Expression{integer_type(width),
                                BinaryValue{"shr", std::move(part), constant_expr(source_shift, width)}});
                        if (destination_shift)
                            part = std::make_shared<Expression>(Expression{integer_type(width),
                                BinaryValue{"shl", std::move(part), constant_expr(destination_shift, width)}});
                        reversed = reversed
                            ? std::make_shared<Expression>(Expression{integer_type(width),
                                BinaryValue{"or", std::move(reversed), std::move(part)}})
                            : std::move(part);
                    }
                }
                value = std::move(reversed);
            }
            return Assign{*dst, std::move(value)};
        }
        if (destination_operand && instruction.operands.size() >= 3 &&
            (instruction.opcode == Opcode::a64_ubfm || instruction.opcode == Opcode::a64_sbfm)) {
            if (instruction.operands.size() != 4) goto a64_unhandled;
            const auto destination = *destination_operand;
            const auto *rotate_operand = std::get_if<ImmediateOperand>(&instruction.operands[2]);
            const auto *limit_operand = std::get_if<ImmediateOperand>(&instruction.operands[3]);
            if (!rotate_operand || !limit_operand || rotate_operand->value >= destination.width ||
                limit_operand->value >= destination.width) goto a64_unhandled;
            const auto width = static_cast<unsigned>(destination.width);
            const auto rotate = static_cast<unsigned>(rotate_operand->value);
            const auto limit = static_cast<unsigned>(limit_operand->value);
            const bool sign_extend = instruction.opcode == Opcode::a64_sbfm;
            ExpressionPtr value = operand_expr(instruction.operands[1]);
            if (limit + 1 == width) {
                value = std::make_shared<Expression>(Expression{integer_type(width),
                    BinaryValue{sign_extend ? "sar" : "shr", value,
                                constant_expr(rotate, width)}});
                return destination.bank == RegisterBank::arm64_zero ? ignored_write() : Assign{destination, std::move(value)};
            }
            unsigned count = limit + 1;
            unsigned shift = 0;
            if (limit >= rotate) {
                count = limit - rotate + 1;
                if (rotate)
                    value = std::make_shared<Expression>(Expression{integer_type(width),
                        BinaryValue{"shr", std::move(value), constant_expr(rotate, width)}});
            } else {
                shift = width - rotate;
            }
            const auto mask = count == width ? UINT64_MAX : (UINT64_C(1) << count) - 1;
            value = std::make_shared<Expression>(Expression{integer_type(width),
                BinaryValue{"and", std::move(value), constant_expr(mask, width)}});
            if (sign_extend && count < width) {
                const auto extension_shift = width - count;
                value = std::make_shared<Expression>(Expression{integer_type(width),
                    BinaryValue{"sar",
                        std::make_shared<Expression>(Expression{integer_type(width),
                            BinaryValue{"shl", std::move(value), constant_expr(extension_shift, width)}}),
                        constant_expr(extension_shift, width)}});
            }
            if (shift)
                value = std::make_shared<Expression>(Expression{integer_type(width),
                    BinaryValue{"shl", std::move(value), constant_expr(shift, width)}});
            return destination.bank == RegisterBank::arm64_zero ? ignored_write() : Assign{destination, std::move(value)};
        }
        if (destination_operand && instruction.operands.size() >= 3 &&
            (instruction.opcode == Opcode::a64_and || instruction.opcode == Opcode::a64_orr ||
             instruction.opcode == Opcode::a64_eor || instruction.opcode == Opcode::a64_ands)) {
            const auto destination = *destination_operand;
            const auto left = operand_expr(instruction.operands[1]);
            auto right = operand_expr(instruction.operands[2]);
            if (instruction.operands.size() > 3) {
                const auto *shift = std::get_if<ImmediateOperand>(&instruction.operands[3]);
                if (!shift || !std::holds_alternative<RegisterOperand>(instruction.operands[2]))
                    goto a64_unhandled;
                const auto kind = (std::to_integer<unsigned>(instruction.bytes[2]) >> 6) & 3;
                if (shift->value) {
                    if (kind == 0)
                        right = std::make_shared<Expression>(Expression{integer_type(destination.width),
                            BinaryValue{"shl", right, constant_expr(shift->value, destination.width)}});
                    else if (kind == 1)
                        right = std::make_shared<Expression>(Expression{integer_type(destination.width),
                            BinaryValue{"shr", right, constant_expr(shift->value, destination.width)}});
                    else if (kind == 2)
                        right = std::make_shared<Expression>(Expression{integer_type(destination.width),
                            BinaryValue{"sar", right, constant_expr(shift->value, destination.width)}});
                    else
                        right = std::make_shared<Expression>(Expression{integer_type(destination.width),
                            UnaryValue{"ror_" + std::to_string(shift->value), right}});
                }
            }
            const char *operation = instruction.opcode == Opcode::a64_and || instruction.opcode == Opcode::a64_ands
                                        ? "and"
                                    : instruction.opcode == Opcode::a64_orr ? "or" : "xor";
            auto value = std::make_shared<Expression>(Expression{integer_type(destination.width),
                BinaryValue{operation, left, right}});
            if (instruction.opcode == Opcode::a64_ands) {
                const RegisterOperand flags{RegisterBank::arm_flags, 0, 4, false};
                Intrinsic effect{destination.bank == RegisterBank::arm64_zero ? "tst" : "a64_ands",
                    {left, right}, IntrinsicMemoryEffect::none};
                if (destination.bank == RegisterBank::arm64_gpr) {
                    effect.register_writes.push_back(destination);
                    effect.register_output_values.push_back(value);
                    if (destination.width == 32) {
                        auto wide = destination;
                        wide.width = 64;
                        effect.register_writes.push_back(wide);
                        effect.register_output_values.push_back(std::make_shared<Expression>(Expression{
                            integer_type(64), UnaryValue{"zext32", value}}));
                    }
                }
                effect.register_writes.push_back(flags);
                effect.register_output_values.push_back(a64_nzcv_logical(value));
                return effect;
            }
            return destination.bank == RegisterBank::arm64_zero ? ignored_write() : Assign{destination, std::move(value)};
        }
        if (destination_operand && instruction.operands.size() >= 3 &&
            (instruction.opcode == Opcode::a64_add || instruction.opcode == Opcode::a64_adds ||
             instruction.opcode == Opcode::a64_sub || instruction.opcode == Opcode::a64_subs ||
             instruction.opcode == Opcode::a64_adc || instruction.opcode == Opcode::a64_adcs ||
             instruction.opcode == Opcode::a64_sbc || instruction.opcode == Opcode::a64_sbcs)) {
            const auto destination = *destination_operand;
            const auto left = operand_expr(instruction.operands[1]);
            auto right = operand_expr(instruction.operands[2]);
            if (instruction.operands.size() > 3) {
                const auto *shift = std::get_if<ImmediateOperand>(&instruction.operands[3]);
                if (!shift || !std::holds_alternative<RegisterOperand>(instruction.operands[2])) goto a64_unhandled;
                const auto kind = (std::to_integer<unsigned>(instruction.bytes[2]) >> 6) & 3;
                if (shift->value) {
                    if (kind == 0)
                        right = std::make_shared<Expression>(Expression{integer_type(destination.width),
                            BinaryValue{"shl", right, constant_expr(shift->value, destination.width)}});
                    else if (kind == 1)
                        right = std::make_shared<Expression>(Expression{integer_type(destination.width),
                            BinaryValue{"shr", right, constant_expr(shift->value, destination.width)}});
                    else if (kind == 2)
                        right = std::make_shared<Expression>(Expression{integer_type(destination.width),
                            BinaryValue{"sar", right, constant_expr(shift->value, destination.width)}});
                    else
                        right = std::make_shared<Expression>(Expression{integer_type(destination.width),
                            UnaryValue{"ror_" + std::to_string(shift->value), right}});
                }
            }
            const bool subtract = instruction.opcode == Opcode::a64_sub || instruction.opcode == Opcode::a64_subs ||
                                  instruction.opcode == Opcode::a64_sbc || instruction.opcode == Opcode::a64_sbcs;
            const bool with_carry = instruction.opcode == Opcode::a64_adc || instruction.opcode == Opcode::a64_adcs ||
                                    instruction.opcode == Opcode::a64_sbc || instruction.opcode == Opcode::a64_sbcs;
            const bool set_flags = instruction.opcode == Opcode::a64_subs || instruction.opcode == Opcode::a64_adds ||
                                   instruction.opcode == Opcode::a64_adcs || instruction.opcode == Opcode::a64_sbcs;
            ExpressionPtr carry_in;
            if (with_carry) {
                const RegisterOperand flags_reg{RegisterBank::arm_flags, 0, 4, false};
                auto flags_value = reg_expr(flags_reg);
                auto carry_bit = std::make_shared<Expression>(Expression{integer_type(4),
                    BinaryValue{"and", flags_value, constant_expr(2, 4)}});
                carry_in = boolean_binary("ne", carry_bit, constant_expr(0, 4));
            }
            auto value = std::make_shared<Expression>(Expression{integer_type(destination.width),
                BinaryValue{subtract ? "sub" : "add", left, right}});
            if (carry_in) {
                if (subtract) value = std::make_shared<Expression>(Expression{integer_type(destination.width),
                    BinaryValue{"add", std::make_shared<Expression>(Expression{integer_type(destination.width),
                        BinaryValue{"sub", value, constant_expr(1, destination.width)}}),
                        std::make_shared<Expression>(Expression{integer_type(destination.width), UnaryValue{"zext", carry_in}})}});
                else value = std::make_shared<Expression>(Expression{integer_type(destination.width),
                    BinaryValue{"add", value, std::make_shared<Expression>(Expression{integer_type(destination.width),
                        UnaryValue{"zext", carry_in}})}});
            }
            if (set_flags) {
                const RegisterOperand flags{RegisterBank::arm_flags, 0, 4, false};
                Intrinsic effect{destination.bank == RegisterBank::arm64_zero && !with_carry
                    ? (subtract ? "cmp" : "cmn") : (subtract ? (with_carry ? "a64_sbcs" : "a64_subs")
                                                                  : (with_carry ? "a64_adcs" : "a64_adds")),
                    {left, right}, IntrinsicMemoryEffect::none};
                if (destination.bank == RegisterBank::arm64_gpr) {
                    effect.register_writes.push_back(destination);
                    effect.register_output_values.push_back(value);
                    if (destination.width == 32) {
                        auto wide = destination;
                        wide.width = 64;
                        effect.register_writes.push_back(wide);
                        effect.register_output_values.push_back(std::make_shared<Expression>(Expression{
                            integer_type(64), UnaryValue{"zext32", value}}));
                    }
                }
                effect.register_writes.push_back(flags);
                effect.register_output_values.push_back(a64_nzcv_arithmetic(left, right, subtract, carry_in));
                return effect;
            }
            if (destination.bank == RegisterBank::arm64_zero) {
                return ignored_write();
            }
            return Assign{destination, std::move(value)};
        }
    }
a64_unhandled:

    const bool mips = instruction.context.architecture == Architecture::mips32 &&
                      instruction.context.mode == ExecutionMode::mips32;
    if (mips) {
        const RegisterOperand hi{RegisterBank::mips_hilo, 0, 32, false};
        const RegisterOperand lo{RegisterBank::mips_hilo, 1, 32, false};
        if (instruction.opcode == Opcode::mips32_movz || instruction.opcode == Opcode::mips32_movn) {
            const auto *destination = instruction.operands.size() == 3
                ? std::get_if<RegisterOperand>(&instruction.operands[0]) : nullptr;
            const auto *source = instruction.operands.size() == 3
                ? std::get_if<RegisterOperand>(&instruction.operands[1]) : nullptr;
            const auto *condition = instruction.operands.size() == 3
                ? std::get_if<RegisterOperand>(&instruction.operands[2]) : nullptr;
            const auto valid_gpr = [](const RegisterOperand *value) {
                return value && value->bank == RegisterBank::mips_gpr && value->index < 32 &&
                    value->width == 32 && !value->high_byte;
            };
            bool valid = valid_gpr(destination) && valid_gpr(source) && valid_gpr(condition) &&
                operands.size() == 3 && operands[0]->type == integer_type(32) &&
                operands[1]->type == integer_type(32) && operands[2]->type == integer_type(32) &&
                instruction.access == std::vector<OperandAccess>{OperandAccess::read_write,
                    OperandAccess::read, OperandAccess::read} &&
                instruction.register_reads == std::vector<RegisterOperand>{*destination, *source, *condition} &&
                instruction.register_writes == (destination && destination->index
                    ? std::vector<RegisterOperand>{*destination} : std::vector<RegisterOperand>{}) &&
                !instruction.memory_read && !instruction.memory_write && instruction.flow == FlowKind::fallthrough &&
                !instruction.delay_slots;
            if (!valid) {
                Intrinsic effect{"mips32_conditional_move_unmodeled_effects", operands,
                    instruction.memory_read || instruction.memory_write
                        ? IntrinsicMemoryEffect::unknown : IntrinsicMemoryEffect::none};
                for (const auto read : instruction.register_reads) effect.operands.push_back(reg_expr(read));
                effect.register_writes = instruction.register_writes;
                return effect;
            }
            if (destination->index == 0) return Intrinsic{"nop", {}, IntrinsicMemoryEffect::none};
            auto predicate = boolean_binary(instruction.opcode == Opcode::mips32_movz ? "eq" : "ne",
                operands[2], constant_expr(0, 32));
            return Assign{*destination, arm32_select(std::move(predicate), operands[1], operands[0])};
        }
        const auto typed_input = [](ExpressionPtr value, bool is_signed) -> ExpressionPtr {
            if (!value) return value;
            auto type = value->type;
            type.kind = TypeKind::integer;
            type.bits = 32;
            type.is_signed = is_signed;
            return std::make_shared<Expression>(Expression{type, value->value});
        };
        const auto fpu = [&]() -> std::optional<Statement> {
            const auto op = instruction.opcode;
            const auto fp_memory = [&](const ExpressionPtr &address, std::uint16_t bits) -> ExpressionPtr {
                auto memory = std::get<MemoryValue>(address->value);
                memory.type = floating_type(bits);
                return std::make_shared<Expression>(Expression{floating_type(bits), std::move(memory)});
            };
            if ((op == Opcode::mips_lwc1 || op == Opcode::mips_ldc1) && operands.size() >= 2) {
                const auto destination = as_register(instruction.operands[0]);
                if (!destination) return {};
                return Assign{*destination, fp_memory(operands[1], destination->width)};
            }
            if ((op == Opcode::mips_swc1 || op == Opcode::mips_sdc1) && operands.size() >= 2) {
                const auto source = as_register(instruction.operands[0]);
                return Store{fp_memory(operands[1], source ? source->width : 32), operands[0]};
            }
            if ((op == Opcode::mips_mfc1 || op == Opcode::mips_cfc1 ||
                 op == Opcode::mips_mtc1 || op == Opcode::mips_ctc1) && operands.size() == 2) {
                const auto general = as_register(instruction.operands[0]);
                const auto cop = as_register(instruction.operands[1]);
                if (!general || !cop || general->width != 32 || cop->width != 32) return {};
                const bool from_cop = op == Opcode::mips_mfc1 || op == Opcode::mips_cfc1;
                const bool control = op == Opcode::mips_cfc1 || op == Opcode::mips_ctc1;
                if (!control && cop->bank != RegisterBank::mips_fpr) return {};
                if (control && cop->bank != RegisterBank::mips_fcsr) return {};
                if (op == Opcode::mips_mfc1) {
                    if (general->index == 0) return Intrinsic{"nop", {}, IntrinsicMemoryEffect::none};
                    auto value = std::make_shared<Expression>(Expression{
                        integer_type(32), UnaryValue{"bitcast_i32", operands[1]}});
                    return Assign{*general, std::move(value)};
                }
                if (op == Opcode::mips_mtc1) {
                    auto value = std::make_shared<Expression>(Expression{
                        floating_type(32), UnaryValue{"bitcast_f32", operands[0]}});
                    return Assign{*cop, std::move(value)};
                }
                if (op == Opcode::mips_cfc1 && cop->index == 0) {
                    if (general->index == 0) return Intrinsic{"nop", {}, IntrinsicMemoryEffect::none};
                    return Assign{*general, retag_expr(operands[1], integer_type(32))};
                }
                if (op == Opcode::mips_ctc1 && cop->index == 0) {
                    auto source = retag_expr(operands[0], integer_type(32));
                    Intrinsic effect{"mips.ctc1.fcsr31", {source}, IntrinsicMemoryEffect::none};
                    effect.register_writes = instruction.register_writes;
                    for (const auto written : effect.register_writes) {
                        if (written == *cop) {
                            effect.register_output_values.push_back(source);
                        } else if (written.bank == RegisterBank::mips_fcsr &&
                                   written.index >= 1 && written.index <= 8) {
                            const unsigned condition_code = written.index - 1;
                            const unsigned bit_position = condition_code == 0 ? 23 : 24 + condition_code;
                            auto bit = boolean_binary("bit_extract", source,
                                constant_expr(bit_position, 32));
                            effect.register_output_values.push_back(std::make_shared<Expression>(Expression{
                                integer_type(32), UnaryValue{"zext", std::move(bit)}}));
                        } else {
                            return Intrinsic{"mips.ctc1.fcsr31.unmodeled_alias", {source},
                                IntrinsicMemoryEffect::unknown};
                        }
                    }
                    return effect;
                }

                // FCCR/FEXR/FENR overlap pieces of FCSR. Preserve these
                // architecturally named effects without inventing bit-level
                // aliases until the FCSR partition is modeled precisely.
                std::vector<ExpressionPtr> control_operands{from_cop ? operands[1] : operands[0]};
                control_operands.push_back(reg_expr({RegisterBank::mips_fcsr, 0, 32, false}));
                Intrinsic effect{from_cop ? "mips.cfc1.control" : "mips.ctc1.control",
                    std::move(control_operands), IntrinsicMemoryEffect::none};
                effect.register_writes = instruction.register_writes;
                return effect;
            }
            if (op >= Opcode::mips_movf_s && op <= Opcode::mips_movn_d) {
                const bool double_precision = op >= Opcode::mips_movf_d;
                const bool fcc_move = op == Opcode::mips_movf_s || op == Opcode::mips_movt_s ||
                    op == Opcode::mips_movf_d || op == Opcode::mips_movt_d;
                const bool move_when_true = op == Opcode::mips_movt_s || op == Opcode::mips_movt_d ||
                    op == Opcode::mips_movn_s || op == Opcode::mips_movn_d;
                const std::uint16_t width = double_precision ? 64 : 32;
                const auto *destination = instruction.operands.size() == 3
                    ? std::get_if<RegisterOperand>(&instruction.operands[0]) : nullptr;
                const auto *source = instruction.operands.size() == 3
                    ? std::get_if<RegisterOperand>(&instruction.operands[1]) : nullptr;
                const auto *condition_register = instruction.operands.size() == 3
                    ? std::get_if<RegisterOperand>(&instruction.operands[2]) : nullptr;
                const auto valid_fpr = [width](const RegisterOperand *value) {
                    return value && value->bank == RegisterBank::mips_fpr && value->index < 32 &&
                        value->width == width && !value->high_byte;
                };
                bool valid = valid_fpr(destination) && valid_fpr(source) && condition_register &&
                    condition_register->width == 32 && !condition_register->high_byte &&
                    (fcc_move ? (condition_register->bank == RegisterBank::mips_fcsr &&
                                 condition_register->index >= 1 && condition_register->index <= 8 &&
                                 instruction.condition == condition_register->index - 1)
                              : (condition_register->bank == RegisterBank::mips_gpr &&
                                 condition_register->index < 32 && instruction.condition == 0));
                if (valid) {
                    std::vector<RegisterOperand> expected_reads{*destination, *source};
                    if (fcc_move || condition_register->index != 0) expected_reads.push_back(*condition_register);
                    valid = operands.size() == 3 && operands[0]->type == floating_type(width) &&
                        operands[1]->type == floating_type(width) && !instruction.memory_read &&
                        !instruction.memory_write && instruction.flow == FlowKind::fallthrough &&
                        !instruction.delay_slots && instruction.access == std::vector<OperandAccess>{
                            OperandAccess::read_write, OperandAccess::read, OperandAccess::read} &&
                        instruction.register_reads == expected_reads &&
                        instruction.register_writes == std::vector<RegisterOperand>{*destination};
                }
                if (!valid) {
                    Intrinsic effect{"mips.fp_conditional_move_unmodeled_effects", operands,
                        instruction.memory_read || instruction.memory_write
                            ? IntrinsicMemoryEffect::unknown : IntrinsicMemoryEffect::none};
                    for (const auto read : instruction.register_reads) effect.operands.push_back(reg_expr(read));
                    effect.register_writes = instruction.register_writes;
                    return effect;
                }
                // FCC aliases carry their low Boolean bit; GPR conditions test
                // all 32 bits. Selection occurs on integer bitcasts so no FP
                // arithmetic, NaN canonicalization, or exception is introduced.
                auto condition_bits = fcc_move
                    ? std::make_shared<Expression>(Expression{integer_type(32),
                        BinaryValue{"and", operands[2], constant_expr(1, 32)}}) : operands[2];
                auto predicate = boolean_binary(move_when_true ? "ne" : "eq",
                    std::move(condition_bits), constant_expr(0, 32));
                const auto bitcast = [width](ExpressionPtr value) {
                    return std::make_shared<Expression>(Expression{integer_type(width),
                        UnaryValue{"bitcast_i" + std::to_string(width), std::move(value)}});
                };
                auto selected = arm32_select(std::move(predicate), bitcast(operands[1]), bitcast(operands[0]));
                return Assign{*destination, std::make_shared<Expression>(Expression{floating_type(width),
                    UnaryValue{"bitcast_f" + std::to_string(width), std::move(selected)}})};
            }
            const bool fp_abs = op == Opcode::mips_abs_s || op == Opcode::mips_abs_d;
            const bool fp_move = op == Opcode::mips_mov_s || op == Opcode::mips_mov_d;
            const bool fp_negate = op == Opcode::mips_neg_s || op == Opcode::mips_neg_d;
            if (fp_abs || fp_move || fp_negate) {
                const bool double_precision = op == Opcode::mips_abs_d || op == Opcode::mips_mov_d ||
                    op == Opcode::mips_neg_d;
                const std::uint16_t width = double_precision ? 64 : 32;
                const auto *destination = instruction.operands.size() == 2
                    ? std::get_if<RegisterOperand>(&instruction.operands[0]) : nullptr;
                const auto *source = instruction.operands.size() == 2
                    ? std::get_if<RegisterOperand>(&instruction.operands[1]) : nullptr;
                const auto valid_fpr = [=](const RegisterOperand *value) {
                    return value && value->bank == RegisterBank::mips_fpr && value->width == width &&
                        value->index < 32 && !value->high_byte;
                };
                if (!valid_fpr(destination) || !valid_fpr(source) ||
                    operands.size() != 2 || operands[0]->type != floating_type(width) ||
                    operands[1]->type != floating_type(width) || instruction.memory_read || instruction.memory_write ||
                    instruction.flow != FlowKind::fallthrough || instruction.delay_slots ||
                    instruction.access != std::vector<OperandAccess>{OperandAccess::write, OperandAccess::read} ||
                    instruction.register_reads != std::vector<RegisterOperand>{*source} ||
                    instruction.register_writes != std::vector<RegisterOperand>{*destination}) {
                    Intrinsic effect{"mips.fp_sign_unmodeled_effects", operands, instruction.memory_read || instruction.memory_write
                        ? IntrinsicMemoryEffect::unknown : IntrinsicMemoryEffect::none};
                    // Preserve unexpected implicit state dependencies, including
                    // any decoder-provided FCSR/FCC effects, without guessing.
                    for (const auto read : instruction.register_reads) effect.operands.push_back(reg_expr(read));
                    effect.register_writes = instruction.register_writes;
                    return effect;
                }
                if (fp_move) return Assign{*destination, operands[1]};
                // Bitcasts preserve every fraction/exponent bit, including NaN
                // payloads and signaling encodings. No host FP operation occurs.
                auto bits = std::make_shared<Expression>(Expression{integer_type(width),
                    UnaryValue{"bitcast_i" + std::to_string(width), operands[1]}});
                const auto sign = UINT64_C(1) << (width - 1);
                const auto mask = fp_abs ? (double_precision ? UINT64_MAX : UINT64_C(0xffffffff)) ^ sign : sign;
                auto transformed = std::make_shared<Expression>(Expression{integer_type(width),
                    BinaryValue{fp_abs ? "and" : "xor", std::move(bits), constant_expr(mask, width)}});
                auto value = std::make_shared<Expression>(Expression{floating_type(width),
                    UnaryValue{"bitcast_f" + std::to_string(width), std::move(transformed)}});
                return Assign{*destination, std::move(value)};
            }
            std::string intrinsic_name;
            if (op >= Opcode::mips_add_s && op <= Opcode::mips_c_le_s) {
                static constexpr const char *names[]{"mips.add.s", "mips.sub.s", "mips.mul.s", "mips.div.s",
                    "mips.sqrt.s", "mips.abs.s", "mips.mov.s", "mips.neg.s", "mips.c.eq.s", "mips.c.lt.s", "mips.c.le.s"};
                intrinsic_name = names[static_cast<std::size_t>(op) - static_cast<std::size_t>(Opcode::mips_add_s)];
            } else if (op >= Opcode::mips_add_d && op <= Opcode::mips_c_le_d) {
                static constexpr const char *names[]{"mips.add.d", "mips.sub.d", "mips.mul.d", "mips.div.d",
                    "mips.sqrt.d", "mips.abs.d", "mips.mov.d", "mips.neg.d", "mips.c.eq.d", "mips.c.lt.d", "mips.c.le.d"};
                intrinsic_name = names[static_cast<std::size_t>(op) - static_cast<std::size_t>(Opcode::mips_add_d)];
            } else if (op >= Opcode::mips_cvt_s_d && op <= Opcode::mips_floor_w_d) {
                static constexpr const char *names[]{"mips.cvt.s.d", "mips.cvt.d.s", "mips.cvt.w.s", "mips.cvt.w.d",
                    "mips.cvt.s.w", "mips.cvt.d.w", "mips.round.w.s", "mips.trunc.w.s", "mips.ceil.w.s", "mips.floor.w.s",
                    "mips.round.w.d", "mips.trunc.w.d", "mips.ceil.w.d", "mips.floor.w.d"};
                intrinsic_name = names[static_cast<std::size_t>(op) - static_cast<std::size_t>(Opcode::mips_cvt_s_d)];
            } else if (op == Opcode::mips64_c_cond_s || op == Opcode::mips64_c_cond_d) {
                static constexpr const char *conditions[]{"f", "un", "eq", "ueq", "olt", "ult", "ole", "ule",
                    "sf", "ngle", "seq", "ngl", "lt", "nge", "le", "ngt"};
                const auto predicate = static_cast<std::size_t>(instruction.condition & 0x0f);
                const auto condition_code = static_cast<std::uint8_t>((instruction.condition >> 4) & 7);
                intrinsic_name = std::string("mips.c.") + conditions[predicate] +
                    (op == Opcode::mips64_c_cond_s ? ".s.fcc" : ".d.fcc") + std::to_string(condition_code);
                // The classic COP1 condition field is a four-bit truth table:
                // unordered, equal, less-than, and signaling. Keep signaling
                // exception behavior in the intrinsic, but expose the exact
                // FCC truth value as ordinary symbolic SSA.
                if (operands.size() >= 2) {
                    const auto unordered = boolean_binary("fp_unordered", operands[0], operands[1]);
                    const auto equal = boolean_binary("fp_eq", operands[0], operands[1]);
                    const auto less = boolean_binary("fp_lt", operands[0], operands[1]);
                    const auto less_equal = boolean_binary("fp_le", operands[0], operands[1]);
                    const auto unordered_bit = (predicate & 1u) != 0;
                    const auto equal_bit = (predicate & 2u) != 0;
                    const auto less_bit = (predicate & 4u) != 0;
                    ExpressionPtr truth = boolean_constant(false);
                    if (unordered_bit) truth = unordered;
                    if (equal_bit) truth = boolean_binary("bool_or", truth, equal);
                    if (less_bit) {
                        const auto less_condition = (predicate & 2u)
                            ? less_equal : less;
                        truth = boolean_binary("bool_or", truth, less_condition);
                    }
                    auto fcc_value = std::make_shared<Expression>(Expression{
                        integer_type(32), UnaryValue{"zext", std::move(truth)}});
                    // The compare intrinsic still represents FCSR Cause/Flag
                    // side effects for signaling operands; only FCC is made
                    // explicit here.
                    const RegisterOperand fcc{RegisterBank::mips_fcsr,
                        static_cast<std::uint8_t>(condition_code + 1), 32, false};
                    Intrinsic effect{intrinsic_name, operands, IntrinsicMemoryEffect::none};
                    effect.register_writes = {fcc};
                    effect.register_output_values = {std::move(fcc_value)};
                    return effect;
                }
            }
            if (!intrinsic_name.empty()) {
                Intrinsic effect{intrinsic_name, operands, IntrinsicMemoryEffect::none};
                const bool converts_to_word = op == Opcode::mips_cvt_w_s || op == Opcode::mips_cvt_w_d ||
                    (op >= Opcode::mips_round_w_s && op <= Opcode::mips_floor_w_d);
                const bool converts_from_word = op == Opcode::mips_cvt_s_w || op == Opcode::mips_cvt_d_w;
                if (converts_to_word && !effect.operands.empty()) {
                    effect.operands[0] = retag_expr(effect.operands[0], integer_type(32));
                    effect.result_type = integer_type(32);
                }
                if (converts_from_word && effect.operands.size() > 1)
                    effect.operands[1] = retag_expr(effect.operands[1], integer_type(32));
                if (op >= Opcode::mips_add_s && op <= Opcode::mips_neg_s)
                    effect.result_type = floating_type(32);
                else if (op >= Opcode::mips_add_d && op <= Opcode::mips_neg_d)
                    effect.result_type = floating_type(64);
                if (!converts_to_word) {
                    if (op == Opcode::mips_cvt_s_d || op == Opcode::mips_cvt_s_w)
                        effect.result_type = floating_type(32);
                    else if (op == Opcode::mips_cvt_d_s || op == Opcode::mips_cvt_d_w)
                        effect.result_type = floating_type(64);
                }
                effect.register_writes = instruction.register_writes;
                const bool scalar_arithmetic =
                    (op >= Opcode::mips_add_s && op <= Opcode::mips_sqrt_s) ||
                    (op >= Opcode::mips_add_d && op <= Opcode::mips_sqrt_d);
                const bool scalar_conversion = op >= Opcode::mips_cvt_s_d && op <= Opcode::mips_floor_w_d;
                if (scalar_arithmetic || scalar_conversion) {
                    const auto *destination = instruction.operands.empty()
                        ? nullptr : std::get_if<RegisterOperand>(&instruction.operands[0]);
                    const RegisterOperand fcsr{RegisterBank::mips_fcsr, 0, 32, false};
                    const auto expected_destination_type = effect.result_type.value_or(integer_type(32));
                    const auto expected_source_width = scalar_arithmetic
                        ? static_cast<std::uint16_t>(op >= Opcode::mips_add_d ? 64 : 32)
                        : static_cast<std::uint16_t>(op == Opcode::mips_cvt_s_d ||
                            op == Opcode::mips_cvt_w_d || op >= Opcode::mips_round_w_d ? 64 : 32);
                    const auto valid_destination = destination && destination->bank == RegisterBank::mips_fpr &&
                        destination->index < 32 && !destination->high_byte &&
                        destination->width == expected_destination_type.bits &&
                        operands.size() == instruction.operands.size();
                    std::vector<RegisterOperand> expected_reads;
                    for (std::size_t index = 1; index < instruction.operands.size(); ++index) {
                        const auto *source = std::get_if<RegisterOperand>(&instruction.operands[index]);
                        if (!source || source->bank != RegisterBank::mips_fpr || source->index >= 32 ||
                            source->high_byte || source->width != expected_source_width) {
                            expected_reads.clear();
                            break;
                        }
                        expected_reads.push_back(*source);
                    }
                    expected_reads.push_back(fcsr);
                    const auto expected_writes = destination
                        ? std::vector<RegisterOperand>{*destination, fcsr} : std::vector<RegisterOperand>{};
                    const auto expected_access = instruction.operands.size() == 2
                        ? std::vector<OperandAccess>{OperandAccess::write, OperandAccess::read}
                        : std::vector<OperandAccess>{OperandAccess::write, OperandAccess::read, OperandAccess::read};
                    if (!valid_destination || expected_reads.size() != instruction.operands.size() ||
                        instruction.register_reads != expected_reads ||
                        instruction.register_writes != expected_writes ||
                        instruction.access != expected_access || instruction.memory_read ||
                        instruction.memory_write || instruction.flow != FlowKind::fallthrough ||
                        instruction.delay_slots) {
                        Intrinsic malformed{"mips_malformed_fp_arithmetic_or_conversion", operands,
                                            IntrinsicMemoryEffect::unknown};
                        malformed.register_writes = instruction.register_writes;
                        return malformed;
                    }
                    // Keep the rounding/status input in the dataflow graph.
                    // The destination and FCSR results stay explicit but
                    // opaque until their IEEE exception and mode semantics
                    // are modeled by the decompiler.
                    effect.operands.push_back(reg_expr(fcsr));
                    if (op == Opcode::mips_cvt_d_w) {
                        // Every signed 32-bit integer is exactly representable
                        // in binary64. The result therefore does not depend
                        // on FCSR.RM and cannot raise inexact; preserve the
                        // existing FCSR value rather than inventing a status
                        // update. Keep the intrinsic wrapper for operation
                        // provenance and its incoming FCSR dependency.
                        const auto signed_word = retag_expr(operands[1], integer_type(32));
                        effect.register_output_values.push_back(std::make_shared<Expression>(Expression{
                            expected_destination_type, UnaryValue{"mips.s32_to_f64_exact", signed_word}}));
                        effect.register_output_values.push_back(reg_expr(fcsr));
                        return effect;
                    }
                    effect.register_output_values.push_back(std::make_shared<Expression>(Expression{
                        expected_destination_type,
                        UnknownValue{intrinsic_name + "_result"}}));
                    effect.register_output_values.push_back(std::make_shared<Expression>(Expression{
                        integer_type(32), UnknownValue{intrinsic_name + "_fcsr_after"}}));
                }
                return effect;
            }
            if (op == Opcode::mips_bc1t || op == Opcode::mips_bc1f ||
                op == Opcode::mips_bc1tl || op == Opcode::mips_bc1fl) {
                auto fcc = reg_expr({RegisterBank::mips_fcsr, static_cast<std::uint8_t>((instruction.condition & 7) + 1), 32, false});
                auto predicate = std::make_shared<Expression>(Expression{ValueType{TypeKind::boolean, 1, false},
                    UnaryValue{"mips.fcc" + std::to_string(instruction.condition & 7), std::move(fcc)}});
                if (op == Opcode::mips_bc1f || op == Opcode::mips_bc1fl)
                    predicate = std::make_shared<Expression>(Expression{ValueType{TypeKind::boolean, 1, false},
                        UnaryValue{"not", std::move(predicate)}});
                return Branch{"mips-fcc" + std::to_string(instruction.condition & 7), instruction.direct_target, {}, std::move(predicate)};
            }
            return {};
        };
        if (auto lifted = fpu()) return std::move(*lifted);
        switch (instruction.opcode) {
        case Opcode::mips_mul: {
            if (operands.size() < 3 || instruction.operands.empty()) break;
            const auto destination = as_register(instruction.operands[0]);
            if (!destination || destination->bank != RegisterBank::mips_gpr) break;
            auto lhs = typed_input(operands[1], true);
            auto rhs = typed_input(operands[2], true);
            auto product = std::make_shared<Expression>(Expression{
                integer_type(32), BinaryValue{"mul", lhs, rhs}});
            Intrinsic effect{"mips.mul.word.s32", {std::move(lhs), std::move(rhs)}, IntrinsicMemoryEffect::none};
            effect.register_writes = instruction.register_writes;
            for (const auto &output : effect.register_writes) {
                if (output == *destination)
                    effect.register_output_values.push_back(product);
                else if (output.bank == RegisterBank::mips_hilo)
                    effect.register_output_values.push_back(std::make_shared<Expression>(Expression{
                        integer_type(32), UnknownValue{"MIPS32 MUL leaves HI/LO unpredictable"}}));
                else return {};
            }
            return effect;
        }
        case Opcode::mips_mult: case Opcode::mips_multu: case Opcode::mips_div: case Opcode::mips_divu: {
            if (operands.size() < 2) break;
            const bool signed_operation = instruction.opcode == Opcode::mips_mult || instruction.opcode == Opcode::mips_div;
            const char *name = instruction.opcode == Opcode::mips_mult ? "mips.mult.s32" :
                               instruction.opcode == Opcode::mips_multu ? "mips.mult.u32" :
                               instruction.opcode == Opcode::mips_div ? "mips.div.s32" : "mips.div.u32";
            Intrinsic effect{name, {typed_input(operands[0], signed_operation),
                                    typed_input(operands[1], signed_operation)}, IntrinsicMemoryEffect::none};
            effect.register_writes = {hi, lo};
            return effect;
        }
        case Opcode::mips_mfhi: case Opcode::mips_mflo: {
            if (instruction.operands.empty()) break;
            const auto destination = as_register(instruction.operands[0]);
            if (!destination || destination->bank != RegisterBank::mips_gpr) break;
            if (destination->index == 0) return Intrinsic{"nop", {}, IntrinsicMemoryEffect::none};
            return Assign{*destination, reg_expr(instruction.opcode == Opcode::mips_mfhi ? hi : lo)};
        }
        case Opcode::mips_mthi: case Opcode::mips_mtlo:
            if (!operands.empty())
                return Assign{instruction.opcode == Opcode::mips_mthi ? hi : lo, typed_input(operands[0], false)};
            break;
        default: break;
        }
        if ((instruction.opcode == Opcode::mips_jr || instruction.opcode == Opcode::mips64_jr_hb) && instruction.flow == FlowKind::ret)
            return Return{operands.empty() ? ExpressionPtr{} : operands.front()};
        if (instruction.flow == FlowKind::conditional_branch && !operands.empty()) {
            ExpressionPtr predicate;
            auto compare = [&](std::string operation, ExpressionPtr left, ExpressionPtr right) {
                predicate = boolean_binary(std::move(operation), std::move(left), std::move(right));
            };
            if (instruction.opcode == Opcode::mips_beq || instruction.opcode == Opcode::mips_bne ||
                instruction.opcode == Opcode::mips_beql || instruction.opcode == Opcode::mips_bnel) {
                if (operands.size() >= 2)
                    compare(instruction.opcode == Opcode::mips_beq || instruction.opcode == Opcode::mips_beql ? "eq" : "ne", operands[0], operands[1]);
            } else {
                const auto zero = constant_expr(0, operands[0]->type.bits);
                switch (instruction.opcode) {
                case Opcode::mips_blez: compare("sle", operands[0], zero); break;
                case Opcode::mips_bgtz: compare("sgt", operands[0], zero); break;
                case Opcode::mips_bltz: compare("slt", operands[0], zero); break;
                case Opcode::mips_bgez: compare("sge", operands[0], zero); break;
                case Opcode::mips_blezl: compare("sle", operands[0], zero); break;
                case Opcode::mips_bgtzl: compare("sgt", operands[0], zero); break;
                case Opcode::mips_bltzl: compare("slt", operands[0], zero); break;
                case Opcode::mips_bgezl: compare("sge", operands[0], zero); break;
                case Opcode::mips_bltzal: case Opcode::mips_bltzall:
                    compare("slt", operands[0], zero); break;
                case Opcode::mips_bgezal: case Opcode::mips_bgezall:
                    compare("sge", operands[0], zero); break;
                default: break;
                }
            }
            return Branch{predicate ? "predicate" : "mips-condition-unsupported", instruction.direct_target, {},
                          std::move(predicate)};
        }
        if (!instruction.operands.empty()) {
            const auto destination = as_register(instruction.operands[0]);
            const auto op = instruction.opcode;
            if (instruction.context.architecture == Architecture::mips32 &&
                destination && destination->bank == RegisterBank::mips_gpr &&
                (op == Opcode::mips_clz || op == Opcode::mips_clo) && operands.size() >= 2) {
                if (destination->index == 0) return Intrinsic{"nop", {}, IntrinsicMemoryEffect::none};
                auto input = operands[1];
                if (op == Opcode::mips_clo)
                    input = std::make_shared<Expression>(Expression{
                        integer_type(32), UnaryValue{"bitnot", std::move(input)}});
                auto count = std::make_shared<Expression>(Expression{
                    integer_type(32), UnaryValue{"clz", std::move(input)}});
                return Assign{*destination, std::move(count)};
            }
            if (destination && destination->bank == RegisterBank::mips_gpr &&
                (op == Opcode::mips_ext || op == Opcode::mips_ins) && operands.size() >= 4) {
                if (destination->index == 0) return Intrinsic{"nop", {}, IntrinsicMemoryEffect::none};
                const auto *position_field = std::get_if<ImmediateOperand>(&instruction.operands[2]);
                const auto *size_field = std::get_if<ImmediateOperand>(&instruction.operands[3]);
                if (position_field && size_field) {
                    const unsigned position = static_cast<unsigned>(position_field->value);
                    const unsigned size = static_cast<unsigned>(size_field->value);
                    const std::uint64_t field_mask = size == 32 ? UINT32_MAX : ((UINT64_C(1) << size) - 1);
                    if (op == Opcode::mips_ext) {
                        auto shifted = std::make_shared<Expression>(Expression{integer_type(32),
                            BinaryValue{"shr", operands[1], constant_expr(position, 32)}});
                        auto masked = std::make_shared<Expression>(Expression{integer_type(32),
                            BinaryValue{"and", std::move(shifted), constant_expr(field_mask, 32)}});
                        return Assign{*destination, std::move(masked)};
                    }
                    const std::uint32_t shifted_mask = static_cast<std::uint32_t>(field_mask << position);
                    auto preserved = std::make_shared<Expression>(Expression{integer_type(32),
                        BinaryValue{"and", operands[0], constant_expr(~shifted_mask, 32)}});
                    auto inserted_field = std::make_shared<Expression>(Expression{integer_type(32),
                        BinaryValue{"and", operands[1], constant_expr(field_mask, 32)}});
                    if (position)
                        inserted_field = std::make_shared<Expression>(Expression{integer_type(32),
                            BinaryValue{"shl", std::move(inserted_field), constant_expr(position, 32)}});
                    auto merged = std::make_shared<Expression>(Expression{integer_type(32),
                        BinaryValue{"or", std::move(preserved), std::move(inserted_field)}});
                    return Assign{*destination, std::move(merged)};
                }
            }
            if (destination && destination->bank == RegisterBank::mips_gpr && instruction.operands.size() >= 2 &&
                (op == Opcode::mips_lb || op == Opcode::mips_lh || op == Opcode::mips_lw ||
                 op == Opcode::mips_lbu || op == Opcode::mips_lhu)) {
                if (destination->index == 0) return Intrinsic{"nop", {}, IntrinsicMemoryEffect::none};
                auto value = operands[1];
                const bool sign_extend = op == Opcode::mips_lb || op == Opcode::mips_lh;
                if (value->type.bits < destination->width)
                    value = std::make_shared<Expression>(Expression{integer_type(destination->width),
                        UnaryValue{sign_extend ? "sext" : "zext", std::move(value)}});
                return Assign{*destination, std::move(value)};
            }
            if (instruction.operands.size() >= 2 &&
                (op == Opcode::mips_sb || op == Opcode::mips_sh || op == Opcode::mips_sw))
                return Store{operands[1], operands[0]};
            const auto value_for = [&](std::string operation, ExpressionPtr left, ExpressionPtr right,
                                       std::uint16_t width = 32) -> ExpressionPtr {
                return std::make_shared<Expression>(Expression{integer_type(width),
                    BinaryValue{std::move(operation), std::move(left), std::move(right)}});
            };
            if (destination && destination->bank == RegisterBank::mips_gpr &&
                (op == Opcode::mips_addu || op == Opcode::mips_subu || op == Opcode::mips_and ||
                 op == Opcode::mips_or || op == Opcode::mips_xor || op == Opcode::mips_nor ||
                 op == Opcode::mips_slt || op == Opcode::mips_sltu || op == Opcode::mips_sll ||
                 op == Opcode::mips_srl || op == Opcode::mips_sra || op == Opcode::mips_sllv ||
                 op == Opcode::mips_srlv || op == Opcode::mips_srav || op == Opcode::mips_addiu ||
                 op == Opcode::mips_slti || op == Opcode::mips_sltiu || op == Opcode::mips_andi ||
                 op == Opcode::mips_ori || op == Opcode::mips_xori || op == Opcode::mips_lui)) {
                if (destination->index == 0) return Intrinsic{"nop", {}, IntrinsicMemoryEffect::none};
                ExpressionPtr value;
                if (op == Opcode::mips_lui && operands.size() >= 2) {
                    value = value_for("shl", operands[1], constant_expr(16, 32));
                } else if (operands.size() >= 3) {
                    auto left = operands[1];
                    auto right = operands[2];
                    std::string operation;
                    switch (op) {
                    case Opcode::mips_addu: case Opcode::mips_addiu: operation = "add"; break;
                    case Opcode::mips_subu: operation = "sub"; break;
                    case Opcode::mips_and: case Opcode::mips_andi: operation = "and"; break;
                    case Opcode::mips_or: case Opcode::mips_ori: operation = "or"; break;
                    case Opcode::mips_xor: case Opcode::mips_xori: operation = "xor"; break;
                    case Opcode::mips_nor:
                        value = std::make_shared<Expression>(Expression{integer_type(32),
                            UnaryValue{"bitnot", value_for("or", left, right)}});
                        break;
                    case Opcode::mips_slt: case Opcode::mips_slti: operation = "slt"; break;
                    case Opcode::mips_sltu: case Opcode::mips_sltiu: operation = "ult"; break;
                    case Opcode::mips_sll: case Opcode::mips_sllv: operation = "shl"; break;
                    case Opcode::mips_srl: case Opcode::mips_srlv: operation = "shr"; break;
                    case Opcode::mips_sra: case Opcode::mips_srav: operation = "sar"; break;
                    default: break;
                    }
                    if (!operation.empty()) {
                        if (op == Opcode::mips_slt || op == Opcode::mips_sltu ||
                            op == Opcode::mips_slti || op == Opcode::mips_sltiu) {
                            auto test = std::make_shared<Expression>(Expression{{TypeKind::boolean, 1, false},
                                BinaryValue{operation, left, right}});
                            value = std::make_shared<Expression>(Expression{integer_type(32),
                                UnaryValue{"zext", std::move(test)}});
                        } else {
                            value = value_for(std::move(operation), std::move(left), std::move(right));
                        }
                    }
                }
                if (value) return Assign{*destination, std::move(value)};
            }
        }
    }

    const bool riscv = instruction.context.architecture == Architecture::riscv32 ||
                       instruction.context.architecture == Architecture::riscv64;
    if (riscv && instruction.flow == FlowKind::ret) return Return{};
    if (riscv && instruction.flow == FlowKind::conditional_branch && operands.size() >= 3) {
        const auto left = operands[0], right = operands[1];
        std::string relation;
        switch (instruction.opcode) {
        case Opcode::rv_beq: relation = "eq"; break;
        case Opcode::rv_bne: relation = "ne"; break;
        case Opcode::rv_blt: relation = "slt"; break;
        case Opcode::rv_bge: relation = "sge"; break;
        case Opcode::rv_bltu: relation = "ult"; break;
        case Opcode::rv_bgeu: relation = "uge"; break;
        default: break;
        }
        if (!relation.empty()) return Branch{"predicate", instruction.direct_target, {}, boolean_binary(relation, left, right)};
    }
    if (riscv && !instruction.operands.empty()) {
        const auto dst = as_register(instruction.operands[0]);
        const auto op = instruction.opcode;
        if (auto status_csr = lift_riscv_fstatus_csr(instruction, operands)) return *status_csr;
        if (op == Opcode::rv_fli_s || op == Opcode::rv_fli_d) {
            const auto *selector = instruction.operands.size() == 2
                ? std::get_if<ImmediateOperand>(&instruction.operands[1]) : nullptr;
            const bool single = op == Opcode::rv_fli_s;
            static constexpr std::uint32_t single_bits[32]{
                0xbf800000, 0x00800000, 0x37800000, 0x38000000,
                0x3b800000, 0x3c000000, 0x3d800000, 0x3e000000,
                0x3e800000, 0x3ea00000, 0x3ec00000, 0x3ee00000,
                0x3f000000, 0x3f200000, 0x3f400000, 0x3f600000,
                0x3f800000, 0x3fa00000, 0x3fc00000, 0x3fe00000,
                0x40000000, 0x40200000, 0x40400000, 0x40800000,
                0x41000000, 0x41800000, 0x43000000, 0x43800000,
                0x47000000, 0x47800000, 0x7f800000, 0x7fc00000};
            static constexpr std::uint64_t double_bits[32]{
                0xbff0000000000000, 0x0010000000000000, 0x3ef0000000000000, 0x3f00000000000000,
                0x3f70000000000000, 0x3f80000000000000, 0x3fb0000000000000, 0x3fc0000000000000,
                0x3fd0000000000000, 0x3fd4000000000000, 0x3fd8000000000000, 0x3fdc000000000000,
                0x3fe0000000000000, 0x3fe4000000000000, 0x3fe8000000000000, 0x3fec000000000000,
                0x3ff0000000000000, 0x3ff4000000000000, 0x3ff8000000000000, 0x3ffc000000000000,
                0x4000000000000000, 0x4004000000000000, 0x4008000000000000, 0x4010000000000000,
                0x4020000000000000, 0x4030000000000000, 0x4060000000000000, 0x4070000000000000,
                0x40e0000000000000, 0x40f0000000000000, 0x7ff0000000000000, 0x7ff8000000000000};
            if (!dst || dst->bank != RegisterBank::riscv_fpr || !selector || selector->is_signed ||
                selector->value > 31 || instruction.register_reads.size() != 0 ||
                instruction.register_writes != std::vector<RegisterOperand>{*dst} ||
                instruction.writes_fflags || instruction.reads_fflags || instruction.reads_frm)
                return Intrinsic{"riscv_malformed_fli", {}, IntrinsicMemoryEffect::none};
            const auto type = floating_type(single ? 32 : 64);
            const std::uint64_t bits = single ? single_bits[selector->value] : double_bits[selector->value];
            return Assign{*dst, std::make_shared<Expression>(Expression{type, ConstantValue{bits, type}})};
        }
        const auto append_vector_mask = [&](std::vector<ExpressionPtr> &inputs) {
            for (const auto &reg : instruction.register_reads) {
                const bool mask = instruction.riscv_vector_masked && reg.bank == RegisterBank::riscv_vpr && reg.index == 0;
                const bool configuration = reg.bank == RegisterBank::riscv_vcsr;
                if (!mask && !configuration) continue;
                const bool explicit_read = std::any_of(instruction.operands.begin(), instruction.operands.end(),
                    [&](const Operand &operand) {
                        const auto *explicit_reg = std::get_if<RegisterOperand>(&operand);
                        return explicit_reg && *explicit_reg == reg;
                    });
                if (!explicit_read) inputs.push_back(reg_expr(reg));
            }
            // Vector arithmetic has an implicit destination input for lanes
            // preserved by vstart, masking, slide-up, or undisturbed tails.
            if (const auto *destination = std::get_if<RegisterOperand>(&instruction.operands.front());
                destination && destination->bank == RegisterBank::riscv_vpr &&
                std::find(instruction.register_reads.begin(), instruction.register_reads.end(), *destination) != instruction.register_reads.end())
                inputs.push_back(reg_expr(*destination));
        };
        if (op == Opcode::rv_vsetvli || op == Opcode::rv_vsetivli || op == Opcode::rv_vsetvl) {
            std::vector<ExpressionPtr> inputs;
            for (std::size_t n = 1; n < operands.size(); ++n) inputs.push_back(operands[n]);
            for (const auto &reg : instruction.register_reads) {
                if (reg.bank != RegisterBank::riscv_vcsr) continue;
                const bool explicit_read = std::any_of(instruction.operands.begin(), instruction.operands.end(),
                    [&](const Operand &operand) {
                        const auto *explicit_reg = std::get_if<RegisterOperand>(&operand);
                        return explicit_reg && *explicit_reg == reg;
                    });
                if (!explicit_read) inputs.push_back(reg_expr(reg));
            }
            const char *name = op == Opcode::rv_vsetivli ? "vsetivli" : op == Opcode::rv_vsetvl ? "vsetvl" : "vsetvli";
            Intrinsic effect{name, std::move(inputs), IntrinsicMemoryEffect::none};
            effect.register_writes = instruction.register_writes;
            return effect;
        }
        if (const auto operation = riscv_vector_effect(op)) {
            const auto vector_result = vector_type(0, operation->floating ? TypeKind::floating : TypeKind::unknown);
            const auto mask_result = vector_type(0, TypeKind::boolean, 1);
            std::vector<ExpressionPtr> inputs;
            for (std::size_t n = 1; n < operands.size(); ++n)
                inputs.push_back(operation->mask_inputs ? retag_expr(operands[n], mask_result) : operands[n]);
            // Keep predicate and old-destination roles distinct even when v0
            // is also an explicit source or the destination register.
            if (instruction.riscv_vector_masked) {
                const auto mask = std::find_if(instruction.register_reads.begin(), instruction.register_reads.end(),
                    [](RegisterOperand reg) { return reg.bank == RegisterBank::riscv_vpr && reg.index == 0; });
                if (mask != instruction.register_reads.end()) inputs.push_back(retag_expr(reg_expr(*mask), mask_result));
            }
            std::vector<RegisterOperand> configurations;
            for (const auto& reg : instruction.register_reads) {
                if ((reg.bank != RegisterBank::riscv_vcsr && reg.bank != RegisterBank::riscv_fstatus) ||
                    std::find(configurations.begin(), configurations.end(), reg) != configurations.end()) continue;
                configurations.push_back(reg);
                inputs.push_back(reg_expr(reg));
            }
            if (dst && dst->bank == RegisterBank::riscv_vpr &&
                std::find(instruction.register_reads.begin(), instruction.register_reads.end(), *dst) != instruction.register_reads.end())
                inputs.push_back(retag_expr(reg_expr(*dst), operation->mask_result ? mask_result : vector_result));
            Intrinsic effect{operation->name, std::move(inputs), IntrinsicMemoryEffect::none};
            effect.register_writes = instruction.register_writes;
            if (dst && dst->bank == RegisterBank::riscv_vpr)
                effect.result_type = operation->mask_result ? mask_result : vector_result;
            return effect;
        }
        if (op >= Opcode::rv_vrgather_vv && op <= Opcode::rv_vslidedown_vi) {
            static constexpr const char *names[]{"vrgather.vv", "vrgather.vx", "vrgather.vi",
                "vslideup.vx", "vslideup.vi", "vslidedown.vx", "vslidedown.vi"};
            std::vector<ExpressionPtr> inputs;
            for (std::size_t n = 1; n < operands.size(); ++n) inputs.push_back(operands[n]);
            append_vector_mask(inputs);
            Intrinsic effect{names[static_cast<std::size_t>(op) - static_cast<std::size_t>(Opcode::rv_vrgather_vv)],
                             std::move(inputs), IntrinsicMemoryEffect::none};
            effect.register_writes = instruction.register_writes;
            return effect;
        }
        if (op == Opcode::rv_vle || op == Opcode::rv_vse ||
            op == Opcode::rv_vlse || op == Opcode::rv_vsse ||
            op == Opcode::rv_vluxei || op == Opcode::rv_vloxei ||
            op == Opcode::rv_vsuxei || op == Opcode::rv_vsoxei) {
            std::vector<ExpressionPtr> inputs;
            const bool load = op == Opcode::rv_vle || op == Opcode::rv_vlse ||
                              op == Opcode::rv_vluxei || op == Opcode::rv_vloxei;
            const bool strided = op == Opcode::rv_vlse || op == Opcode::rv_vsse;
            const bool indexed = op == Opcode::rv_vluxei || op == Opcode::rv_vloxei ||
                                 op == Opcode::rv_vsuxei || op == Opcode::rv_vsoxei;
            const std::size_t first_input = load ? 1 : 0;
            for (std::size_t n = first_input; n < operands.size(); ++n) inputs.push_back(operands[n]);
            for (const auto &reg : instruction.register_reads) {
                if (reg.bank != RegisterBank::riscv_vpr && reg.bank != RegisterBank::riscv_vcsr) continue;
                const bool explicit_read = std::any_of(instruction.operands.begin(), instruction.operands.end(),
                    [&](const Operand &operand) {
                        const auto *explicit_reg = std::get_if<RegisterOperand>(&operand);
                        return explicit_reg && *explicit_reg == reg;
                    });
                if (!explicit_read) inputs.push_back(reg_expr(reg));
            }
            if (load) {
                if (const auto *destination = std::get_if<RegisterOperand>(&instruction.operands.front());
                    destination && destination->bank == RegisterBank::riscv_vpr &&
                    std::find(instruction.register_reads.begin(), instruction.register_reads.end(), *destination) != instruction.register_reads.end())
                    inputs.push_back(reg_expr(*destination));
            }
            const char *name = indexed
                ? op == Opcode::rv_vluxei ? "vluxei.indexed.unordered"
                  : op == Opcode::rv_vloxei ? "vloxei.indexed.ordered"
                    : op == Opcode::rv_vsuxei ? "vsuxei.indexed.unordered"
                                              : "vsoxei.indexed.ordered"
                : load ? (strided ? "vlse.strided" : "vle.unit")
                       : (strided ? "vsse.strided" : "vse.unit");
            Intrinsic effect{name, std::move(inputs),
                             load ? IntrinsicMemoryEffect::read : IntrinsicMemoryEffect::write};
            effect.register_writes = instruction.register_writes;
            return effect;
        }
        if (op >= Opcode::rv_fminm_s && op <= Opcode::rv_fmaxm_d) {
            std::vector<ExpressionPtr> inputs(operands.begin() + 1, operands.end());
            for (const auto &reg : instruction.register_reads)
                if (reg.bank == RegisterBank::riscv_fstatus) inputs.push_back(reg_expr(reg));
            const auto name = op == Opcode::rv_fminm_s ? "fminm.s" : op == Opcode::rv_fmaxm_s ? "fmaxm.s" :
                              op == Opcode::rv_fminm_d ? "fminm.d" : "fmaxm.d";
            Intrinsic effect{name, std::move(inputs), IntrinsicMemoryEffect::none};
            effect.register_writes = instruction.register_writes;
            effect.result_type = floating_type((op == Opcode::rv_fminm_s || op == Opcode::rv_fmaxm_s) ? 32 : 64);
            return effect;
        }
        if ((op >= Opcode::rv_flw && op <= Opcode::rv_fmv_d_x) || op == Opcode::rv_fcvtmod_w_d ||
            (op >= Opcode::rv_fleq_s && op <= Opcode::rv_fltq_d) ||
            op == Opcode::rv_fli_s || op == Opcode::rv_fli_d ||
            (op >= Opcode::rv_fround_s && op <= Opcode::rv_froundnx_d)) {
            if (auto converted = lift_riscv_fp_conversion(instruction, operands)) return *converted;
            if ((op == Opcode::rv_flw || op == Opcode::rv_fld) && dst && operands.size() >= 2) {
                auto loaded = *operands[1];
                if (auto *memory = std::get_if<MemoryValue>(&loaded.value)) {
                    const auto type = floating_type(op == Opcode::rv_flw ? 32 : 64);
                    loaded.type = type; memory->type = type;
                }
                return Assign{*dst, std::make_shared<Expression>(std::move(loaded))};
            }
            if ((op == Opcode::rv_fsw || op == Opcode::rv_fsd) && operands.size() >= 2) {
                auto address = *operands[1];
                if (auto *memory = std::get_if<MemoryValue>(&address.value)) {
                    const auto type = floating_type(op == Opcode::rv_fsw ? 32 : 64);
                    address.type = type; memory->type = type;
                }
                const std::uint16_t width = op == Opcode::rv_fsw ? 32 : 64;
                const auto stored = retag_expr(operands[0], floating_type(width));
                return Store{std::make_shared<Expression>(std::move(address)), stored};
            }
            std::vector<ExpressionPtr> inputs;
            const bool single = op <= Opcode::rv_fmv_w_x || op == Opcode::rv_fcvt_d_s || op == Opcode::rv_fmv_x_w ||
                                op == Opcode::rv_fleq_s || op == Opcode::rv_fltq_s;
            const bool raw_move = op == Opcode::rv_fmv_x_w || op == Opcode::rv_fmv_x_d ||
                                  op == Opcode::rv_fmv_w_x || op == Opcode::rv_fmv_d_x;
            for (std::size_t n = 1; n < operands.size(); ++n) {
                auto input = operands[n];
                if (input->type.kind == TypeKind::floating) {
                    const std::uint16_t width = op == Opcode::rv_fcvt_s_d || op == Opcode::rv_fmv_x_d
                                                    ? 64 : op == Opcode::rv_fcvt_d_s || op == Opcode::rv_fmv_x_w
                                                    ? 32 : single ? 32 : 64;
                    input = retag_expr(input, raw_move ? integer_type(width) : floating_type(width));
                } else {
                    std::uint16_t integer_width = 0;
                    switch (op) {
                    case Opcode::rv_fcvt_s_w: case Opcode::rv_fcvt_s_wu:
                    case Opcode::rv_fcvt_d_w: case Opcode::rv_fcvt_d_wu:
                    case Opcode::rv_fmv_w_x: integer_width = 32; break;
                    case Opcode::rv_fcvt_s_l: case Opcode::rv_fcvt_s_lu:
                    case Opcode::rv_fcvt_d_l: case Opcode::rv_fcvt_d_lu:
                    case Opcode::rv_fmv_d_x: integer_width = 64; break;
                    default: break;
                    }
                    if (integer_width != 0)
                        input = retag_expr(input, integer_type(integer_width));
                }
                inputs.push_back(std::move(input));
            }
            if (instruction.rounding_mode)
                inputs.push_back(constant_expr(*instruction.rounding_mode, 3));
            for (const auto &reg : instruction.register_reads)
                if (reg.bank == RegisterBank::riscv_fstatus) inputs.push_back(reg_expr(reg));
            Intrinsic effect{riscv_fp_name(op), std::move(inputs), IntrinsicMemoryEffect::none};
            effect.register_writes = instruction.register_writes;
            if (dst && dst->bank == RegisterBank::riscv_fpr) {
                const bool single_result = op == Opcode::rv_flw ||
                    (op >= Opcode::rv_fadd_s && op <= Opcode::rv_fmax_s) ||
                    (op >= Opcode::rv_fmadd_s && op <= Opcode::rv_fnmadd_s) ||
                    op == Opcode::rv_fcvt_s_w || op == Opcode::rv_fcvt_s_wu ||
                    op == Opcode::rv_fcvt_s_l || op == Opcode::rv_fcvt_s_lu ||
                    op == Opcode::rv_fcvt_s_d || op == Opcode::rv_fmv_w_x;
                const bool double_result = op == Opcode::rv_fld ||
                    (op >= Opcode::rv_fadd_d && op <= Opcode::rv_fmax_d) ||
                    (op >= Opcode::rv_fmadd_d && op <= Opcode::rv_fnmadd_d) ||
                    op == Opcode::rv_fcvt_d_w || op == Opcode::rv_fcvt_d_wu ||
                    op == Opcode::rv_fcvt_d_l || op == Opcode::rv_fcvt_d_lu ||
                    op == Opcode::rv_fcvt_d_s || op == Opcode::rv_fmv_d_x;
                if (single_result) effect.result_type = floating_type(32);
                else if (double_result) effect.result_type = floating_type(64);
            }
            return effect;
        }
        if (dst && dst->bank == RegisterBank::riscv_gpr && dst->index == 0 && instruction.flow == FlowKind::fallthrough) return Intrinsic{"nop", {}, IntrinsicMemoryEffect::none};
        const auto assign_value = [&](ExpressionPtr value) -> Statement {
            return dst ? Statement{Assign{*dst, std::move(value)}} : Statement{Intrinsic{"riscv", operands}};
        };
        if (dst && operands.size() >= 3 &&
            (op == Opcode::rv_czero_eqz || op == Opcode::rv_czero_nez)) {
            // Zicond selects the first source when the condition is nonzero
            // (NEZ) or zero (EQZ), and otherwise produces an XLEN zero.
            auto condition = std::make_shared<Expression>(Expression{{TypeKind::boolean, 1, false},
                BinaryValue{op == Opcode::rv_czero_eqz ? "eq" : "ne", operands[2],
                    constant_expr(0, operands[2]->type.bits ? operands[2]->type.bits : dst->width)}});
            auto alternatives = std::make_shared<Expression>(Expression{integer_type(dst->width),
                BinaryValue{"pair", operands[1], constant_expr(0, dst->width)}});
            auto value = std::make_shared<Expression>(Expression{integer_type(dst->width),
                BinaryValue{"select_if", std::move(condition), std::move(alternatives)}});
            return assign_value(std::move(value));
        }
        if (dst && operands.size() == 3 &&
            (op == Opcode::rv_clmul || op == Opcode::rv_clmulh || op == Opcode::rv_clmulr) &&
            (dst->width == 32 || dst->width == 64) &&
            operands[1]->type == integer_type(dst->width) && operands[2]->type == integer_type(dst->width)) {
            const char *operation = op == Opcode::rv_clmul ? "rvm_clmul" :
                                    op == Opcode::rv_clmulh ? "rvm_clmulh" : "rvm_clmulr";
            return assign_value(std::make_shared<Expression>(Expression{integer_type(dst->width),
                BinaryValue{operation, operands[1], operands[2]}}));
        }
        if (dst && operands.size() >= 3 &&
            (op == Opcode::rv_bclr || op == Opcode::rv_bext || op == Opcode::rv_binv || op == Opcode::rv_bset ||
             op == Opcode::rv_bclri || op == Opcode::rv_bexti || op == Opcode::rv_binvi || op == Opcode::rv_bseti)) {
            // Zbs indexes bits modulo XLEN for register and immediate forms.
            // Keep the mask explicit so the common IR matches the ISA even
            // when the source register contains an out-of-range index.
            const auto width = dst->width;
            auto index = std::make_shared<Expression>(Expression{integer_type(width),
                BinaryValue{"and", retag_expr(operands[2], integer_type(width)), constant_expr(width - 1, width)}});
            const auto selected_bit = std::make_shared<Expression>(Expression{integer_type(width),
                BinaryValue{"shl", constant_expr(1, width), index}});
            ExpressionPtr value;
            if (op == Opcode::rv_bclr || op == Opcode::rv_bclri) {
                auto inverse = std::make_shared<Expression>(Expression{integer_type(width), UnaryValue{"not", selected_bit}});
                value = std::make_shared<Expression>(Expression{integer_type(width),
                    BinaryValue{"and", operands[1], std::move(inverse)}});
            } else if (op == Opcode::rv_bext || op == Opcode::rv_bexti) {
                auto shifted = std::make_shared<Expression>(Expression{integer_type(width),
                    BinaryValue{"shr", operands[1], std::move(index)}});
                value = std::make_shared<Expression>(Expression{integer_type(width),
                    BinaryValue{"and", std::move(shifted), constant_expr(1, width)}});
            } else {
                value = std::make_shared<Expression>(Expression{integer_type(width),
                    BinaryValue{op == Opcode::rv_binv || op == Opcode::rv_binvi ? "xor" : "or",
                                operands[1], std::move(selected_bit)}});
            }
            return assign_value(std::move(value));
        }
        if (dst && operands.size() == 3 &&
            (op == Opcode::rv_sh1add || op == Opcode::rv_sh2add || op == Opcode::rv_sh3add ||
             op == Opcode::rv_add_uw || op == Opcode::rv_sh1add_uw || op == Opcode::rv_sh2add_uw ||
             op == Opcode::rv_sh3add_uw || op == Opcode::rv_slli_uw)) {
            auto index = operands[1];
            const auto base = operands[2];
            const bool unsigned_word = op == Opcode::rv_add_uw || op == Opcode::rv_sh1add_uw ||
                                       op == Opcode::rv_sh2add_uw || op == Opcode::rv_sh3add_uw ||
                                       op == Opcode::rv_slli_uw;
            if (unsigned_word) {
                index = std::make_shared<Expression>(Expression{integer_type(64),
                    UnaryValue{"zext", std::make_shared<Expression>(Expression{integer_type(32),
                        UnaryValue{"trunc32", std::move(index)}})}});
            }
            const auto shift = op == Opcode::rv_sh1add || op == Opcode::rv_sh1add_uw ? 1u :
                               op == Opcode::rv_sh2add || op == Opcode::rv_sh2add_uw ? 2u :
                               op == Opcode::rv_sh3add || op == Opcode::rv_sh3add_uw ? 3u : 0u;
            if (op == Opcode::rv_slli_uw) {
                auto value = std::make_shared<Expression>(Expression{integer_type(dst->width),
                    BinaryValue{"shl", std::move(index), operands[2]}});
                return assign_value(std::move(value));
            }
            if (shift)
                index = std::make_shared<Expression>(Expression{integer_type(dst->width),
                    BinaryValue{"shl", std::move(index), constant_expr(shift, dst->width)}});
            auto value = std::make_shared<Expression>(Expression{integer_type(dst->width),
                BinaryValue{"add", std::move(index), base}});
            return assign_value(std::move(value));
        }
        if (dst && (op == Opcode::rv_lui || op == Opcode::rv_auipc) && operands.size() >= 2) {
            auto value = operands[1];
            if (op == Opcode::rv_auipc)
                value = std::make_shared<Expression>(Expression{integer_type(dst->width),
                    BinaryValue{"add", constant_expr(instruction.address.offset, dst->width), value}});
            return assign_value(std::move(value));
        }
        const bool immediate_form = op == Opcode::rv_addi || op == Opcode::rv_addiw || op == Opcode::rv_slti || op == Opcode::rv_sltiu ||
            op == Opcode::rv_xori || op == Opcode::rv_ori || op == Opcode::rv_andi || op == Opcode::rv_slli || op == Opcode::rv_srli ||
            op == Opcode::rv_srai || op == Opcode::rv_slliw || op == Opcode::rv_srliw || op == Opcode::rv_sraiw;
        const bool register_form = op == Opcode::rv_add || op == Opcode::rv_sub || op == Opcode::rv_sll || op == Opcode::rv_slt ||
            op == Opcode::rv_sltu || op == Opcode::rv_xor || op == Opcode::rv_srl || op == Opcode::rv_sra || op == Opcode::rv_or ||
            op == Opcode::rv_and || op == Opcode::rv_addw || op == Opcode::rv_subw || op == Opcode::rv_sllw || op == Opcode::rv_srlw || op == Opcode::rv_sraw;
        const bool m_form = op >= Opcode::rv_mul && op <= Opcode::rv_remuw;
        if (dst && (immediate_form || register_form || m_form) && operands.size() >= 3) {
            const auto left = operands[1];
            auto right = operands[2];
            if ((op == Opcode::rv_sll || op == Opcode::rv_srl || op == Opcode::rv_sra || op == Opcode::rv_sllw || op == Opcode::rv_srlw || op == Opcode::rv_sraw) &&
                right->type.bits) {
                const auto mask = (op == Opcode::rv_sllw || op == Opcode::rv_srlw || op == Opcode::rv_sraw) ? 31u : unsigned(dst->width - 1);
                right = std::make_shared<Expression>(Expression{integer_type(right->type.bits),
                    BinaryValue{"and", right, constant_expr(mask, right->type.bits)}});
            }
            std::string operation;
            bool comparison = false;
            switch (op) {
            case Opcode::rv_addi: case Opcode::rv_addiw: case Opcode::rv_add: case Opcode::rv_addw: operation="add"; break;
            case Opcode::rv_sub: case Opcode::rv_subw: operation="sub"; break;
            case Opcode::rv_xori: case Opcode::rv_xor: operation="xor"; break;
            case Opcode::rv_ori: case Opcode::rv_or: operation="or"; break;
            case Opcode::rv_andi: case Opcode::rv_and: operation="and"; break;
            case Opcode::rv_slli: case Opcode::rv_sll: case Opcode::rv_slliw: case Opcode::rv_sllw: operation="shl"; break;
            case Opcode::rv_srli: case Opcode::rv_srl: case Opcode::rv_srliw: case Opcode::rv_srlw: operation="shr"; break;
            case Opcode::rv_srai: case Opcode::rv_sra: case Opcode::rv_sraiw: case Opcode::rv_sraw: operation="sar"; break;
            case Opcode::rv_slti: case Opcode::rv_slt: operation="slt"; comparison=true; break;
            case Opcode::rv_sltiu: case Opcode::rv_sltu: operation="ult"; comparison=true; break;
            default: break;
            }
            const bool word = op == Opcode::rv_addiw || op == Opcode::rv_slliw || op == Opcode::rv_srliw || op == Opcode::rv_sraiw ||
                op == Opcode::rv_addw || op == Opcode::rv_subw || op == Opcode::rv_sllw || op == Opcode::rv_srlw || op == Opcode::rv_sraw ||
                op == Opcode::rv_mulw || op == Opcode::rv_divw || op == Opcode::rv_divuw || op == Opcode::rv_remw || op == Opcode::rv_remuw;
            ExpressionPtr value;
            if (m_form) {
                value = std::make_shared<Expression>(Expression{integer_type(dst->width), BinaryValue{"rvm_" + operation_name(op), left, right}});
            } else if (comparison) {
                auto test = std::make_shared<Expression>(Expression{{TypeKind::boolean, 1, false}, BinaryValue{operation, left, right}});
                value = std::make_shared<Expression>(Expression{integer_type(dst->width), UnaryValue{"zext", std::move(test)}});
            } else {
                const std::uint16_t result_width = word ? std::uint16_t{32} : dst->width;
                auto lhs = left, rhs = right;
                if (word) {
                    lhs = std::make_shared<Expression>(Expression{integer_type(32), UnaryValue{"trunc32", lhs}});
                    rhs = std::make_shared<Expression>(Expression{integer_type(32), UnaryValue{"trunc32", rhs}});
                }
                auto computed = std::make_shared<Expression>(Expression{integer_type(result_width), BinaryValue{operation, lhs, rhs}});
                if (word) value = std::make_shared<Expression>(Expression{integer_type(dst->width), UnaryValue{"sext", std::move(computed)}});
                else value = std::move(computed);
            }
            return assign_value(std::move(value));
        }
        const bool load = op == Opcode::rv_lb || op == Opcode::rv_lh || op == Opcode::rv_lw || op == Opcode::rv_ld || op == Opcode::rv_lbu || op == Opcode::rv_lhu || op == Opcode::rv_lwu;
        if (dst && load && operands.size() >= 2) {
            auto value = operands[1];
            const bool sign_extend = op == Opcode::rv_lb || op == Opcode::rv_lh || op == Opcode::rv_lw;
            if (value->type.bits < dst->width)
                value = std::make_shared<Expression>(Expression{integer_type(dst->width),
                    UnaryValue{sign_extend ? "sext" : "zext", std::move(value)}});
            return assign_value(std::move(value));
        }
        const bool store = op == Opcode::rv_sb || op == Opcode::rv_sh || op == Opcode::rv_sw || op == Opcode::rv_sd;
        if (store && operands.size() >= 2) return Store{operands[0], operands[1]};
    }
    if (arm32_context && instruction.flow == FlowKind::ret && instruction.arm &&
        instruction.arm->exchange == ArmExchange::address_bit0 && instruction.opcode != Opcode::a32_ldm) {
        Intrinsic effect{"arm_return_exchange", operands,
            instruction.memory_read ? IntrinsicMemoryEffect::read : IntrinsicMemoryEffect::none};
        effect.register_writes = instruction.register_writes;
        if (instruction.arm->predicate == ArmPredicate::condition && instruction.condition < 14) {
            effect.name = "arm_guarded_" + effect.name;
            effect.operands.insert(effect.operands.begin(), arm32_condition_expr(instruction.condition, reg_expr({RegisterBank::arm_flags, 0, 4, false})));
        }
        return effect;
    }
    if (arm32_context && instruction.opcode == Opcode::a32_ldm && instruction.flow == FlowKind::ret) {
        Intrinsic effect{"arm_return_load_multiple_exchange", operands,
            instruction.memory_read ? IntrinsicMemoryEffect::read : IntrinsicMemoryEffect::unknown};
        effect.register_writes = instruction.register_writes;
        if (instruction.arm && instruction.arm->predicate == ArmPredicate::condition) {
            effect.name = "arm_guarded_" + effect.name;
            effect.operands.insert(effect.operands.begin(), arm32_condition_expr(instruction.condition,
                reg_expr({RegisterBank::arm_flags, 0, 4, false})));
        }
        return effect;
    }
    if (instruction.opcode == Opcode::ret || instruction.opcode == Opcode::a64_ret ||
        (instruction.context.architecture == Architecture::arm && instruction.flow == FlowKind::ret)) {
        if (arm32_context && instruction.arm && instruction.arm->predicate == ArmPredicate::condition &&
            instruction.condition < 14) {
            auto predicate = arm32_condition_expr(instruction.condition, reg_expr({RegisterBank::arm_flags, 0, 4, false}));
            return Intrinsic{"arm_guarded_return", {std::move(predicate)}, IntrinsicMemoryEffect::none};
        }
        Return result{operands.empty() ? ExpressionPtr{} : operands.front()};
        result.x86_stack_effect = x86_stack_control_effect(instruction, X86StackControlAction::pop_return_address);
        return result;
    }
    if (instruction.flow == FlowKind::call || operation_name(instruction.opcode) == "call") {
        ExpressionPtr indirect;
        if (instruction.direct_target || operands.empty()) {
            indirect.reset();
        } else {
            indirect = operands.front();
        }
        if (arm32_context && instruction.arm) {
            const auto mode_name = instruction.arm->target_mode == ExecutionMode::thumb ? "thumb" :
                instruction.arm->target_mode == ExecutionMode::a32 ? "a32" :
                instruction.arm->exchange == ArmExchange::address_bit0 ? "exchange" : "unknown_mode";
            Intrinsic effect{"arm_call_" + std::string(mode_name), {}, IntrinsicMemoryEffect::unknown};
            if (instruction.direct_target) {
                effect.operands.push_back(constant_expr(instruction.direct_target->offset, 32));
                effect.operands.push_back(constant_expr(instruction.direct_target->space.value, 64));
            } else {
                effect.operands.push_back(std::move(indirect));
            }
            if (instruction.arm->link_address) {
                effect.operands.push_back(constant_expr(instruction.arm->link_address->offset, 32));
                effect.operands.push_back(constant_expr(instruction.arm->link_address->space.value, 64));
            }
            if (instruction.arm->return_mode)
                effect.operands.push_back(constant_expr(*instruction.arm->return_mode == ExecutionMode::thumb ? 1 : 0, 1));
            effect.register_writes = instruction.register_writes;
            if (instruction.arm->predicate == ArmPredicate::condition && instruction.condition < 14) {
                auto predicate = arm32_condition_expr(instruction.condition, reg_expr({RegisterBank::arm_flags, 0, 4, false}));
                effect.name = "arm_guarded_" + effect.name;
                effect.operands.insert(effect.operands.begin(), std::move(predicate));
            }
            return effect;
        }
        Call result{instruction.direct_target, std::move(indirect)};
        result.x86_stack_effect = x86_stack_control_effect(instruction, X86StackControlAction::push_return_address);
        return result;
    }
    if (arm32_context && (instruction.flow == FlowKind::jump || instruction.flow == FlowKind::conditional_branch) &&
        !instruction.direct_target) {
        std::string name = instruction.arm && instruction.arm->target_mode == ExecutionMode::thumb
            ? "arm_indirect_branch_thumb" : instruction.arm && instruction.arm->target_mode == ExecutionMode::a32
            ? "arm_indirect_branch_a32" : "arm_indirect_branch_exchange";
        Intrinsic effect{std::move(name), operands,
            instruction.memory_read && instruction.memory_write ? IntrinsicMemoryEffect::unknown :
            instruction.memory_read ? IntrinsicMemoryEffect::read :
            instruction.memory_write ? IntrinsicMemoryEffect::write : IntrinsicMemoryEffect::none};
        effect.register_writes = instruction.register_writes;
        if (instruction.arm && instruction.arm->predicate == ArmPredicate::condition && instruction.condition < 14) {
            effect.name = "arm_guarded_" + effect.name;
            effect.operands.insert(effect.operands.begin(), arm32_condition_expr(instruction.condition, reg_expr({RegisterBank::arm_flags, 0, 4, false})));
        }
        return effect;
    }
    if (arm32_context && instruction.flow == FlowKind::trap) {
        Intrinsic effect{"arm_trap_" + operation_name(instruction.opcode), operands, IntrinsicMemoryEffect::unknown};
        effect.register_writes = instruction.register_writes;
        if (instruction.arm && instruction.arm->predicate == ArmPredicate::condition) {
            effect.name = "arm_guarded_" + effect.name;
            effect.operands.insert(effect.operands.begin(), arm32_condition_expr(instruction.condition,
                reg_expr({RegisterBank::arm_flags, 0, 4, false})));
        }
        return effect;
    }
    if (instruction.flow == FlowKind::conditional_branch || instruction.flow == FlowKind::jump ||
        instruction.opcode == Opcode::a64_b_cond || instruction.opcode == Opcode::a64_cbz ||
        instruction.opcode == Opcode::a64_cbnz || instruction.opcode == Opcode::a64_tbz ||
        instruction.opcode == Opcode::a64_tbnz || instruction.opcode == Opcode::a32_b ||
        instruction.opcode == Opcode::t32_b || instruction.opcode == Opcode::t32_cbz ||
        instruction.opcode == Opcode::t32_cbnz) {
        const bool conditional = instruction.flow == FlowKind::conditional_branch ||
            (instruction.opcode == Opcode::a64_b_cond && instruction.condition < 14) || instruction.opcode == Opcode::a64_cbz ||
            instruction.opcode == Opcode::a64_cbnz || instruction.opcode == Opcode::a64_tbz ||
            instruction.opcode == Opcode::a64_tbnz || instruction.opcode == Opcode::t32_cbz ||
            instruction.opcode == Opcode::t32_cbnz;
        const std::string condition = conditional ? "condition_" + std::to_string(instruction.condition) : "true";
        Branch branch{condition, instruction.direct_target, {}};
        if (instruction.flow == FlowKind::jump && !instruction.direct_target && !operands.empty())
            branch.indirect_target = operands.front();
        if (a64 && instruction.opcode == Opcode::a64_b_cond && instruction.condition < 14) {
            branch.predicate = a64_nzcv_predicate(instruction.condition,
                reg_expr({RegisterBank::arm_flags, 0, 4, false}));
            branch.condition = "predicate";
        }
        if (instruction.context.architecture == Architecture::arm && instruction.arm &&
            instruction.arm->predicate == ArmPredicate::condition && instruction.condition < 14) {
            branch.predicate = arm32_condition_expr(instruction.condition, reg_expr({RegisterBank::arm_flags, 0, 4, false}));
            branch.condition = "predicate";
        }
        if (instruction.context.mode == ExecutionMode::thumb &&
            (instruction.opcode == Opcode::t32_cbz || instruction.opcode == Opcode::t32_cbnz) && !operands.empty()) {
            branch.predicate = boolean_binary(instruction.opcode == Opcode::t32_cbz ? "eq" : "ne",
                operands.front(), constant_expr(0, operands.front()->type.bits));
            branch.condition = "predicate";
        }
        if (a64 && (instruction.opcode == Opcode::a64_cbz || instruction.opcode == Opcode::a64_cbnz) &&
            !operands.empty()) {
            const auto zero = constant_expr(0, operands.front()->type.bits);
            branch.predicate = boolean_binary(instruction.opcode == Opcode::a64_cbz ? "eq" : "ne",
                                              operands.front(), zero);
            branch.condition = "predicate";
        }
        if (a64 && (instruction.opcode == Opcode::a64_tbz || instruction.opcode == Opcode::a64_tbnz) &&
            operands.size() >= 2) {
            const auto *bit = std::get_if<ImmediateOperand>(&instruction.operands[1]);
            if (bit && bit->value < operands[0]->type.bits) {
                const auto mask = constant_expr(UINT64_C(1) << bit->value, operands[0]->type.bits);
                auto tested = std::make_shared<Expression>(Expression{integer_type(operands[0]->type.bits),
                    BinaryValue{"and", operands[0], mask}});
                branch.predicate = boolean_binary(instruction.opcode == Opcode::a64_tbz ? "eq" : "ne",
                                                  std::move(tested), constant_expr(0, operands[0]->type.bits));
                branch.condition = "predicate";
            }
        }
        return branch;
    }

    if (instruction.opcode == Opcode::nop || instruction.opcode == Opcode::a64_nop ||
        instruction.opcode == Opcode::a32_nop || instruction.opcode == Opcode::t32_nop)
        return Intrinsic{"nop", {}, IntrinsicMemoryEffect::none};
    if (arm32_context && instruction.opcode == Opcode::t32_it)
        return Intrinsic{"thumb_itstate", operands, IntrinsicMemoryEffect::none};

    const bool arm32 = arm32_context;
    const bool packed_extend_signed = instruction.opcode == Opcode::a32_sxtb16 ||
        instruction.opcode == Opcode::a32_sxtab16 || instruction.opcode == Opcode::t32_sxtb16 ||
        instruction.opcode == Opcode::t32_sxtab16;
    const bool packed_extend_unsigned = instruction.opcode == Opcode::a32_uxtb16 ||
        instruction.opcode == Opcode::a32_uxtab16 || instruction.opcode == Opcode::t32_uxtb16 ||
        instruction.opcode == Opcode::t32_uxtab16;
    if (arm32 && (packed_extend_signed || packed_extend_unsigned)) {
        const bool add = instruction.opcode == Opcode::a32_sxtab16 || instruction.opcode == Opcode::a32_uxtab16 ||
            instruction.opcode == Opcode::t32_sxtab16 || instruction.opcode == Opcode::t32_uxtab16;
        const auto valid_gpr = [](const Operand &operand) {
            const auto *reg = std::get_if<RegisterOperand>(&operand);
            return reg && reg->bank == RegisterBank::arm32_gpr && reg->width == 32 &&
                reg->index < 15 && !reg->high_byte;
        };
        const auto *rotated_operand = instruction.operands.size() == (add ? 3u : 2u)
            ? std::get_if<ArmShiftedRegisterOperand>(&instruction.operands.back()) : nullptr;
        if (!instruction.arm || !instruction.arm->flags_known || instruction.arm->flags_written ||
            operands.size() != instruction.operands.size() ||
            !valid_gpr(instruction.operands[0]) || (add && !valid_gpr(instruction.operands[1])) ||
            !rotated_operand || rotated_operand->source.bank != RegisterBank::arm32_gpr ||
            rotated_operand->source.width != 32 || rotated_operand->source.index >= 15 ||
            rotated_operand->source.high_byte || rotated_operand->amount_register ||
            rotated_operand->shift != ArmShift::ror || rotated_operand->amount > 24 ||
            rotated_operand->amount % 8)
            return Intrinsic{"arm_packed_extend_malformed", operands, IntrinsicMemoryEffect::none};
        const auto destination = *as_register(instruction.operands[0]);
        const auto &source = rotated_operand->source;
        auto expected_reads = add
            ? std::vector<RegisterOperand>{*as_register(instruction.operands[1]), source}
            : std::vector<RegisterOperand>{source};
        if (instruction.arm->predicate == ArmPredicate::condition)
            expected_reads.insert(expected_reads.begin(), RegisterOperand{RegisterBank::arm_flags, 0, 4, false});
        const auto expected_access = add
            ? std::vector<OperandAccess>{OperandAccess::write, OperandAccess::read, OperandAccess::read}
            : std::vector<OperandAccess>{OperandAccess::write, OperandAccess::read};
        if (instruction.register_writes != std::vector<RegisterOperand>{destination} ||
            instruction.register_reads != expected_reads || instruction.access != expected_access)
            return Intrinsic{"arm_packed_extend_malformed", operands, IntrinsicMemoryEffect::none};
        const auto masked = [](ExpressionPtr value, std::uint64_t mask) {
            return std::make_shared<Expression>(Expression{integer_type(32),
                BinaryValue{"and", std::move(value), constant_expr(mask, 32)}});
        };
        const auto byte0 = masked(operands.back(), 0xff);
        const auto upper_word = std::make_shared<Expression>(Expression{integer_type(32),
            BinaryValue{"shr", operands.back(), constant_expr(16, 32)}});
        const auto byte1 = masked(std::move(upper_word), 0xff);
        const auto extend_lane = [&](ExpressionPtr value) {
            if (packed_extend_signed) {
                value = std::make_shared<Expression>(Expression{integer_type(32),
                    BinaryValue{"shl", std::move(value), constant_expr(24, 32)}});
                value = std::make_shared<Expression>(Expression{integer_type(32),
                    BinaryValue{"sar", std::move(value), constant_expr(24, 32)}});
            }
            return masked(std::move(value), 0xffff);
        };
        auto low_lane = extend_lane(byte0);
        auto high_lane = extend_lane(byte1);
        if (add) {
            const auto accumulator = operands[1];
            const auto low_base = masked(accumulator, 0xffff);
            const auto upper_accumulator = std::make_shared<Expression>(Expression{integer_type(32),
                BinaryValue{"shr", accumulator, constant_expr(16, 32)}});
            const auto high_base = masked(std::move(upper_accumulator), 0xffff);
            low_lane = masked(std::make_shared<Expression>(Expression{integer_type(32),
                BinaryValue{"add", low_base, std::move(low_lane)}}), 0xffff);
            high_lane = masked(std::make_shared<Expression>(Expression{integer_type(32),
                BinaryValue{"add", high_base, std::move(high_lane)}}), 0xffff);
        }
        auto high_word = std::make_shared<Expression>(Expression{integer_type(32),
            BinaryValue{"shl", std::move(high_lane), constant_expr(16, 32)}});
        ExpressionPtr value = std::make_shared<Expression>(Expression{integer_type(32),
            BinaryValue{"or", std::move(low_lane), std::move(high_word)}});
        if (instruction.arm->predicate == ArmPredicate::condition) {
            const auto predicate = arm32_condition_expr(instruction.condition,
                reg_expr({RegisterBank::arm_flags, 0, 4, false}));
            value = arm32_select(predicate, std::move(value), reg_expr(destination));
        }
        return Assign{destination, std::move(value)};
    }
    const bool arm_extend_signed = instruction.opcode == Opcode::a32_sxtb ||
        instruction.opcode == Opcode::a32_sxth || instruction.opcode == Opcode::a32_sxtab ||
        instruction.opcode == Opcode::a32_sxtah;
    const bool arm_extend_unsigned = instruction.opcode == Opcode::a32_uxtb ||
        instruction.opcode == Opcode::a32_uxth || instruction.opcode == Opcode::a32_uxtab ||
        instruction.opcode == Opcode::a32_uxtah;
    if (arm32 && (arm_extend_signed || arm_extend_unsigned)) {
        const bool add = instruction.opcode == Opcode::a32_sxtab || instruction.opcode == Opcode::a32_sxtah ||
            instruction.opcode == Opcode::a32_uxtab || instruction.opcode == Opcode::a32_uxtah;
        const bool halfword = instruction.opcode == Opcode::a32_sxth || instruction.opcode == Opcode::a32_sxtah ||
            instruction.opcode == Opcode::a32_uxth || instruction.opcode == Opcode::a32_uxtah;
        const auto valid_gpr = [](const Operand &operand) {
            const auto *reg = std::get_if<RegisterOperand>(&operand);
            return reg && reg->bank == RegisterBank::arm32_gpr && reg->width == 32 &&
                reg->index < 15 && !reg->high_byte;
        };
        if (instruction.operands.size() != (add ? 3u : 2u) ||
            !valid_gpr(instruction.operands[0]) || (add && !valid_gpr(instruction.operands[1])) ||
            !instruction.arm || instruction.arm->flags_written)
            return Intrinsic{"arm_extend_malformed", operands, IntrinsicMemoryEffect::none};
        const auto &source = instruction.operands.back();
        const auto *shifted = std::get_if<ArmShiftedRegisterOperand>(&source);
        if ((!shifted && !valid_gpr(source)) ||
            (shifted && (shifted->source.bank != RegisterBank::arm32_gpr || shifted->source.width != 32 ||
                shifted->source.index >= 15 || shifted->source.high_byte || shifted->amount_register ||
                shifted->shift != ArmShift::ror || shifted->amount > 24 || shifted->amount % 8)))
            return Intrinsic{"arm_extend_malformed", operands, IntrinsicMemoryEffect::none};
        const auto destination = *as_register(instruction.operands[0]);
        const unsigned narrow_bits = halfword ? 16 : 8;
        ExpressionPtr value = operands.back();
        if (arm_extend_signed) {
            // The shift pair sign-extends the rotated low byte/halfword within
            // a 32-bit value, including the wraparound bits in ROR #24.
            value = std::make_shared<Expression>(Expression{integer_type(32),
                BinaryValue{"shl", value, constant_expr(32 - narrow_bits, 32)}});
            value = std::make_shared<Expression>(Expression{integer_type(32),
                BinaryValue{"sar", value, constant_expr(32 - narrow_bits, 32)}});
        } else {
            value = std::make_shared<Expression>(Expression{integer_type(32),
                BinaryValue{"and", value, constant_expr(halfword ? 0xffff : 0xff, 32)}});
        }
        if (add)
            value = std::make_shared<Expression>(Expression{integer_type(32),
                BinaryValue{"add", operands[1], value}});
        if (instruction.arm->predicate == ArmPredicate::condition) {
            auto predicate = arm32_condition_expr(instruction.condition, reg_expr({RegisterBank::arm_flags, 0, 4, false}));
            value = arm32_select(predicate, std::move(value), reg_expr(destination));
        }
        return Assign{destination, std::move(value)};
    }
    if (thumb_context && (instruction.opcode == Opcode::t32_movw || instruction.opcode == Opcode::t32_movt)) {
        const auto destination = instruction.operands.size() == 2
            ? as_register(instruction.operands[0]) : std::optional<RegisterOperand>{};
        const auto *immediate = instruction.operands.size() == 2
            ? std::get_if<ImmediateOperand>(&instruction.operands[1]) : nullptr;
        const bool movt = instruction.opcode == Opcode::t32_movt;
        const RegisterOperand flags{RegisterBank::arm_flags, 0, 4, false};
        const bool conditional = instruction.arm && instruction.arm->predicate == ArmPredicate::condition;
        const bool valid_destination = destination && destination->bank == RegisterBank::arm32_gpr &&
            destination->width == 32 && destination->index < 13 && !destination->high_byte;
        const bool valid_immediate = immediate && immediate->encoded_width == 16 &&
            immediate->effective_width == 32 && !immediate->is_signed && immediate->value <= 0xffff;
        const auto expected_access = std::vector<OperandAccess>{
            movt ? OperandAccess::read_write : OperandAccess::write, OperandAccess::read};
        const bool reads_destination = std::find(instruction.register_reads.begin(),
            instruction.register_reads.end(), destination.value_or(RegisterOperand{})) != instruction.register_reads.end();
        if (!valid_destination || !valid_immediate || !instruction.arm || instruction.arm->flags_written ||
            instruction.register_writes != std::vector<RegisterOperand>{*destination} ||
            instruction.access != expected_access || (movt && !reads_destination) ||
            (conditional && (instruction.condition >= 14 ||
                std::find(instruction.register_reads.begin(), instruction.register_reads.end(), flags) ==
                    instruction.register_reads.end())))
            return Intrinsic{"thumb_movw_movt_malformed", operands, IntrinsicMemoryEffect::none};

        ExpressionPtr value;
        if (!movt) {
            value = constant_expr(immediate->value, 32);
        } else {
            const auto prior_low = std::make_shared<Expression>(Expression{integer_type(32),
                BinaryValue{"and", reg_expr(*destination), constant_expr(0xffff, 32)}});
            const auto inserted_high = constant_expr(immediate->value << 16, 32);
            value = std::make_shared<Expression>(Expression{integer_type(32),
                BinaryValue{"or", prior_low, inserted_high}});
        }
        if (conditional) {
            const auto predicate = arm32_condition_expr(instruction.condition, reg_expr(flags));
            value = arm32_select(predicate, std::move(value), reg_expr(*destination));
        }
        return Assign{*destination, std::move(value)};
    }
    if (arm32 && instruction.opcode == Opcode::t32_adr && instruction.operands.size() == 2) {
        const auto destination = as_register(instruction.operands[0]);
        const auto *address = std::get_if<ArmMemoryOperand>(&instruction.operands[1]);
        if (destination && address && address->resolved_address)
        {
            ExpressionPtr value = constant_expr(address->resolved_address->offset, destination->width);
            if (instruction.arm && instruction.arm->predicate == ArmPredicate::condition && instruction.condition < 14) {
                auto predicate = arm32_condition_expr(instruction.condition, reg_expr({RegisterBank::arm_flags, 0, 4, false}));
                value = std::make_shared<Expression>(Expression{integer_type(destination->width),
                    BinaryValue{"arm_guard", predicate, std::make_shared<Expression>(Expression{integer_type(destination->width),
                        BinaryValue{"arm_select", value, reg_expr(*destination)}})}});
            }
            return Assign{*destination, std::move(value)};
        }
        return Intrinsic{"thumb_adr_unresolved", operands, IntrinsicMemoryEffect::none};
    }
    if (arm32 && instruction.opcode == Opcode::t32_mul && instruction.operands.size() == 2) {
        const auto destination = as_register(instruction.operands[0]);
        if (destination) {
            auto value = std::make_shared<Expression>(Expression{integer_type(destination->width),
                BinaryValue{"mul", reg_expr(*destination), operands[1]}});
            if (instruction.arm && instruction.arm->predicate == ArmPredicate::condition && instruction.condition < 14) {
                auto predicate = arm32_condition_expr(instruction.condition, reg_expr({RegisterBank::arm_flags, 0, 4, false}));
                value = std::make_shared<Expression>(Expression{integer_type(destination->width),
                    BinaryValue{"arm_guard", predicate, std::make_shared<Expression>(Expression{integer_type(destination->width),
                        BinaryValue{"arm_select", value, reg_expr(*destination)}})}});
            }
            if (instruction.arm && instruction.arm->flags_written) {
                Intrinsic effect{"thumb_mul_flags", {value}, IntrinsicMemoryEffect::none};
                if (instruction.arm->predicate == ArmPredicate::condition && instruction.condition < 14)
                    effect.name = "arm_conditional_" + effect.name;
                effect.register_writes = {*destination, {RegisterBank::arm_flags, 0, 4, false}};
                return effect;
            }
            return Assign{*destination, std::move(value)};
        }
    }
    if (arm32 && (instruction.opcode == Opcode::a32_mul || instruction.opcode == Opcode::a32_mla ||
                  instruction.opcode == Opcode::a32_mls) && instruction.operands.size() >= 3) {
        const auto destination = as_register(instruction.operands[0]);
        if (!destination || operands.size() < 3)
            return Intrinsic{"arm_multiply_malformed", operands, IntrinsicMemoryEffect::none};
        auto product = std::make_shared<Expression>(Expression{integer_type(32),
            BinaryValue{"mul", operands[1], operands[2]}});
        ExpressionPtr result = product;
        if (instruction.opcode == Opcode::a32_mla || instruction.opcode == Opcode::a32_mls) {
            if (operands.size() < 4)
                return Intrinsic{"arm_multiply_malformed", operands, IntrinsicMemoryEffect::none};
            result = std::make_shared<Expression>(Expression{integer_type(32),
                BinaryValue{instruction.opcode == Opcode::a32_mla ? "add" : "sub", product, operands[3]}});
        }
        if (instruction.arm && instruction.arm->flags_written) {
            Intrinsic effect{"arm_multiply_nz", {result}, IntrinsicMemoryEffect::none};
            effect.register_writes = instruction.register_writes;
            if (instruction.arm->predicate == ArmPredicate::condition && instruction.condition < 14) {
                effect.name = "arm_conditional_" + effect.name;
                effect.operands.insert(effect.operands.begin(), arm32_condition_expr(instruction.condition, reg_expr({RegisterBank::arm_flags, 0, 4, false})));
            }
            return effect;
        }
        if (instruction.arm && instruction.arm->predicate == ArmPredicate::condition && instruction.condition < 14) {
            auto predicate = arm32_condition_expr(instruction.condition, reg_expr({RegisterBank::arm_flags, 0, 4, false}));
            result = std::make_shared<Expression>(Expression{integer_type(32),
                BinaryValue{"arm_guard", predicate, std::make_shared<Expression>(Expression{integer_type(32),
                    BinaryValue{"arm_select", result, reg_expr(*destination)}})}});
        }
        return Assign{*destination, std::move(result)};
    }
    if (arm32 && (instruction.opcode == Opcode::a32_umull || instruction.opcode == Opcode::a32_umlal ||
                  instruction.opcode == Opcode::a32_smull || instruction.opcode == Opcode::a32_smlal) &&
        instruction.operands.size() == 4 && operands.size() == 4) {
        const auto lo = as_register(instruction.operands[0]);
        const auto hi = as_register(instruction.operands[1]);
        if (!lo || !hi)
            return Intrinsic{"arm_long_multiply_malformed", operands, IntrinsicMemoryEffect::none};
        const bool signed_mul = instruction.opcode == Opcode::a32_smull || instruction.opcode == Opcode::a32_smlal;
        const bool accumulate = instruction.opcode == Opcode::a32_umlal || instruction.opcode == Opcode::a32_smlal;
        auto product = std::make_shared<Expression>(Expression{integer_type(64),
            BinaryValue{signed_mul ? "smul64" : "umul64", operands[2], operands[3]}});
        if (accumulate) {
            auto prior = std::make_shared<Expression>(Expression{integer_type(64),
                BinaryValue{"concat", operands[1], operands[0]}});
            product = std::make_shared<Expression>(Expression{integer_type(64),
                BinaryValue{"add", prior, product}});
        }
        Intrinsic effect{"arm_long_multiply", {product}, IntrinsicMemoryEffect::none};
        effect.register_writes = instruction.register_writes;
        if (instruction.arm && instruction.arm->flags_written)
            effect.name += "_nz_flags";
        if (instruction.arm && instruction.arm->predicate == ArmPredicate::condition && instruction.condition < 14) {
            effect.name = "arm_conditional_" + effect.name;
            effect.operands.insert(effect.operands.begin(), arm32_condition_expr(instruction.condition, reg_expr({RegisterBank::arm_flags, 0, 4, false})));
        }
        return effect;
    }
    if (arm32 && (instruction.opcode == Opcode::a32_ldm || instruction.opcode == Opcode::a32_stm) &&
        instruction.operands.size() == 2) {
        const bool load = instruction.opcode == Opcode::a32_ldm;
        const auto *list = std::get_if<ArmRegisterListOperand>(&instruction.operands[1]);
        if (list) {
            Intrinsic effect{load ? "arm_ldm" : "arm_stm",
                {operands[0], constant_expr(list->mask, 16)},
                load ? IntrinsicMemoryEffect::read : IntrinsicMemoryEffect::write};
            if (instruction.arm) {
                effect.operands.push_back(constant_expr(static_cast<std::uint8_t>(instruction.arm->multiple_mode), 8));
                effect.operands.push_back(constant_expr(instruction.arm->writeback ? 1 : 0, 1));
                if (instruction.arm->predicate == ArmPredicate::condition && instruction.condition < 14) {
                    effect.name = "arm_conditional_" + effect.name;
                    effect.operands.insert(effect.operands.begin(), arm32_condition_expr(instruction.condition, reg_expr({RegisterBank::arm_flags, 0, 4, false})));
                }
            }
            effect.register_writes = instruction.register_writes;
            return effect;
        }
    }
    if (arm32 && instruction.arm && instruction.operands.size() >= 2) {
        const auto opcode = instruction.opcode;
        const bool compare = opcode == Opcode::a32_tst || opcode == Opcode::a32_teq ||
                             opcode == Opcode::a32_cmp || opcode == Opcode::a32_cmn;
        const bool unary = opcode == Opcode::a32_mov || opcode == Opcode::a32_mvn;
        const bool data_operation = (opcode >= Opcode::a32_and && opcode <= Opcode::a32_mvn) ||
                                    opcode == Opcode::t32_addw || opcode == Opcode::t32_subw;
        if (data_operation && ((compare && operands.size() >= 2) || (!compare && operands.size() >= 2))) {
            const auto destination = compare ? std::optional<RegisterOperand>{} : as_register(instruction.operands[0]);
            const auto left = compare ? operands[0] : operands.size() >= 3 ? operands[1] : operands[0];
            const auto right = compare ? operands[1] : operands.size() >= 3 ? operands[2] : operands[1];
            std::string operation;
            switch (opcode) {
            case Opcode::a32_and: case Opcode::a32_tst: operation = "and"; break;
            case Opcode::a32_eor: case Opcode::a32_teq: operation = "xor"; break;
            case Opcode::a32_sub: case Opcode::a32_cmp: case Opcode::t32_subw: operation = "sub"; break;
            case Opcode::a32_rsb: operation = "rsb"; break;
            case Opcode::a32_add: case Opcode::a32_cmn: case Opcode::t32_addw: operation = "add"; break;
            case Opcode::a32_adc: operation = "adc"; break;
            case Opcode::a32_sbc: operation = "sbc"; break;
            case Opcode::a32_rsc: operation = "rsc"; break;
            case Opcode::a32_orr: operation = "or"; break;
            case Opcode::a32_bic: operation = "bic"; break;
            case Opcode::a32_mov: operation = "mov"; break;
            case Opcode::a32_mvn: operation = "mvn"; break;
            default: break;
            }
            ExpressionPtr value;
            if (unary) {
                value = opcode == Opcode::a32_mvn
                    ? std::make_shared<Expression>(Expression{integer_type(32), UnaryValue{"bitnot", right}})
                    : right;
            } else if (opcode == Opcode::a32_rsb) {
                value = std::make_shared<Expression>(Expression{integer_type(32), BinaryValue{"sub", right, left}});
            } else if (opcode == Opcode::a32_bic) {
                value = std::make_shared<Expression>(Expression{integer_type(32), BinaryValue{"and", left,
                    std::make_shared<Expression>(Expression{integer_type(32), UnaryValue{"bitnot", right}})}});
            } else if (opcode == Opcode::a32_adc || opcode == Opcode::a32_sbc || opcode == Opcode::a32_rsc) {
                auto carry = std::make_shared<Expression>(Expression{integer_type(1),
                    UnaryValue{"carry_flag", reg_expr({RegisterBank::arm_flags, 0, 4, false})}});
                const auto lhs = opcode == Opcode::a32_rsc ? right : left;
                const auto rhs = opcode == Opcode::a32_rsc ? left : right;
                auto base = std::make_shared<Expression>(Expression{integer_type(32),
                    BinaryValue{opcode == Opcode::a32_adc ? "add" : "sub", lhs, rhs}});
                value = std::make_shared<Expression>(Expression{integer_type(32),
                    BinaryValue{opcode == Opcode::a32_adc ? "carry_add" : "carry_sub", std::move(base), std::move(carry)}});
            } else {
                value = std::make_shared<Expression>(Expression{integer_type(32), BinaryValue{operation, left, right}});
            }
            const bool logical = opcode == Opcode::a32_and || opcode == Opcode::a32_eor ||
                                 opcode == Opcode::a32_orr || opcode == Opcode::a32_bic ||
                                 opcode == Opcode::a32_mov || opcode == Opcode::a32_mvn ||
                                 opcode == Opcode::a32_tst || opcode == Opcode::a32_teq;
            const auto append_flags = [&](Intrinsic &effect) {
                if (!logical) {
                    if (!instruction.arm->flags_known || instruction.arm->flags_written != 15 ||
                        instruction.arm->writes_pc)
                        return;
                    const auto packed = arm32_nzcv_arithmetic(opcode, left, right, value,
                        reg_expr({RegisterBank::arm_flags, 0, 4, false}));
                    if (!packed) return;
                    effect.operands.push_back(boolean_binary("bit_extract", packed, constant_expr(3, 4)));
                    effect.operands.push_back(boolean_binary("bit_extract", packed, constant_expr(2, 4)));
                    effect.operands.push_back(boolean_binary("bit_extract", packed, constant_expr(1, 4)));
                    effect.operands.push_back(boolean_binary("bit_extract", packed, constant_expr(0, 4)));
                    ExpressionPtr output_value = value;
                    auto output_flags = packed;
                    if (instruction.arm->predicate == ArmPredicate::condition && instruction.condition < 14) {
                        const auto flags = reg_expr({RegisterBank::arm_flags, 0, 4, false});
                        const auto predicate = arm32_condition_expr(instruction.condition, flags, true);
                        output_flags = arm32_select(predicate, std::move(output_flags), flags);
                        if (!compare)
                            output_value = arm32_select(predicate, std::move(output_value), reg_expr(*destination));
                    }
                    effect.register_output_values = compare
                        ? std::vector<ExpressionPtr>{std::move(output_flags)}
                        : std::vector<ExpressionPtr>{std::move(output_value), std::move(output_flags)};
                    return;
                }
                const auto flags = reg_expr({RegisterBank::arm_flags, 0, 4, false});
                auto n = boolean_unary("signbit", value);
                auto z = boolean_binary("eq", value, constant_expr(0, value->type.bits));
                auto old_c = std::make_shared<Expression>(Expression{integer_type(1), UnaryValue{"arm_flag_c", flags}});
                auto c = (instruction.arm->flags_written & 2) || !instruction.arm->flags_known
                    ? std::make_shared<Expression>(Expression{integer_type(1),
                          BinaryValue{"arm_shift_carry_out", right, old_c}})
                    : old_c;
                auto v = std::make_shared<Expression>(Expression{integer_type(1), UnaryValue{"arm_flag_v", flags}});
                // Explicit parallel outputs are separate from the readable
                // intrinsic arguments. SSA versions every input before defining
                // either the destination or packed NZCV, preserving old-state
                // reads when a destination is also an ALU source.
                const auto packed_bit = [](ExpressionPtr bit, unsigned position) {
                    auto widened = std::make_shared<Expression>(Expression{integer_type(4), UnaryValue{"zext", std::move(bit)}});
                    return std::make_shared<Expression>(Expression{integer_type(4),
                        BinaryValue{"shl", std::move(widened), constant_expr(position, 4)}});
                };
                const auto combine = [](ExpressionPtr left_bit, ExpressionPtr right_bit) {
                    return std::make_shared<Expression>(Expression{integer_type(4),
                        BinaryValue{"or", std::move(left_bit), std::move(right_bit)}});
                };
                ExpressionPtr packed_flags = combine(combine(packed_bit(n, 3), packed_bit(z, 2)),
                                                     combine(packed_bit(c, 1), packed_bit(v, 0)));
                ExpressionPtr output_value = value;
                if (instruction.arm->predicate == ArmPredicate::condition && instruction.condition < 14) {
                    const auto predicate = arm32_condition_expr(instruction.condition, flags);
                    const auto expanded_predicate = arm32_condition_expr(instruction.condition, flags, true);
                    packed_flags = arm32_select(expanded_predicate, std::move(packed_flags), flags);
                    if (!compare) output_value = arm32_select(expanded_predicate, value, reg_expr(*destination));
                    const auto merge = [&](ExpressionPtr updated, std::string_view bit) {
                        const auto previous = std::make_shared<Expression>(Expression{integer_type(1),
                            UnaryValue{"arm_flag_" + std::string(bit), flags}});
                        const auto selected = std::make_shared<Expression>(Expression{integer_type(1),
                            BinaryValue{"arm_select", std::move(updated), previous}});
                        return std::make_shared<Expression>(Expression{integer_type(1),
                            BinaryValue{"arm_guard", predicate, selected}});
                    };
                    n = merge(std::move(n), "n");
                    z = merge(std::move(z), "z");
                    c = merge(std::move(c), "c");
                    v = merge(std::move(v), "v");
                }
                effect.operands.insert(effect.operands.end(), {std::move(n), std::move(z), std::move(c), std::move(v)});
                effect.register_output_values = compare ? std::vector<ExpressionPtr>{std::move(packed_flags)}
                    : std::vector<ExpressionPtr>{std::move(output_value), std::move(packed_flags)};
            };
            if (compare) {
                Intrinsic effect{instruction.arm->predicate == ArmPredicate::condition
                    ? "arm_guarded_compare_" + operation : "arm_compare_" + operation,
                    {left, right}, IntrinsicMemoryEffect::none};
                if (instruction.arm->predicate == ArmPredicate::condition && instruction.condition < 14)
                    effect.operands.insert(effect.operands.begin(), arm32_condition_expr(instruction.condition, reg_expr({RegisterBank::arm_flags, 0, 4, false})));
                effect.operands.push_back(constant_expr(instruction.arm->flags_written, 8));
                effect.operands.push_back(constant_expr(instruction.arm->flags_known ? 1 : 0, 1));
                append_flags(effect);
                effect.register_writes = {{RegisterBank::arm_flags, 0, 4, false}};
                return effect;
            }
            if (!destination)
                return Intrinsic{"arm_unpredictable_destination", operands};
            const bool writes_flags = instruction.arm->flags_written != 0 ||
                std::find(instruction.register_writes.begin(), instruction.register_writes.end(),
                          RegisterOperand{RegisterBank::arm_flags, 0, 4, false}) != instruction.register_writes.end();
            if (instruction.arm->predicate == ArmPredicate::condition) {
                const auto cc = instruction.condition < 14 ? instruction.condition : 255;
                const auto condition = arm32_condition_expr(cc, reg_expr({RegisterBank::arm_flags, 0, 4, false}));
                auto guarded = std::make_shared<Expression>(Expression{integer_type(destination->width),
                    BinaryValue{"arm_guard", condition, std::make_shared<Expression>(Expression{integer_type(destination->width),
                        BinaryValue{"arm_select", value, reg_expr(*destination)}})}});
                if (writes_flags) {
                    Intrinsic effect{"arm_guarded_data_" + operation, {guarded, left, right}, IntrinsicMemoryEffect::none};
                    effect.operands.push_back(constant_expr(instruction.arm->flags_written, 8));
                    effect.operands.push_back(constant_expr(instruction.arm->flags_known ? 1 : 0, 1));
                    append_flags(effect);
                    effect.register_writes = {*destination, {RegisterBank::arm_flags, 0, 4, false}};
                    return effect;
                }
                return Assign{*destination, std::move(guarded)};
            }
            if (!writes_flags)
                return Assign{*destination, std::move(value)};
            Intrinsic effect{"arm_data_" + operation, {value, left, right}, IntrinsicMemoryEffect::none};
            effect.operands.push_back(constant_expr(instruction.arm->flags_written, 8));
            effect.operands.push_back(constant_expr(instruction.arm->flags_known ? 1 : 0, 1));
            append_flags(effect);
            effect.register_writes = {*destination, {RegisterBank::arm_flags, 0, 4, false}};
            return effect;
        }
    }
    if (arm32 && instruction.operands.size() >= 2 &&
        (instruction.opcode == Opcode::a32_ldr || instruction.opcode == Opcode::a32_str ||
         instruction.opcode == Opcode::a32_ldrb || instruction.opcode == Opcode::a32_strb ||
         instruction.opcode == Opcode::a32_ldrh || instruction.opcode == Opcode::a32_strh ||
         instruction.opcode == Opcode::a32_ldrsb || instruction.opcode == Opcode::a32_ldrsh)) {
        const auto *memory = std::get_if<ArmMemoryOperand>(&instruction.operands[1]);
        if (memory && memory->writeback) {
            auto updated = reg_expr(memory->base);
            ExpressionPtr offset;
            if (const auto *immediate = std::get_if<std::uint32_t>(&memory->offset))
                offset = constant_expr(*immediate, 32);
            else {
                const auto &shift = std::get<ArmShiftedRegisterOperand>(memory->offset);
                if (shift.amount_register) offset = unknown_expr("arm-writeback-register-shift", 32);
                else if (shift.shift == ArmShift::rrx) offset = unknown_expr("arm-writeback-rrx", 32);
                else if (!shift.amount) offset = reg_expr(shift.source);
                else offset = std::make_shared<Expression>(Expression{integer_type(32),
                    UnaryValue{shift.shift == ArmShift::lsl ? "shl_" + std::to_string(shift.amount) :
                               shift.shift == ArmShift::lsr ? "shr_" + std::to_string(shift.amount) :
                               shift.shift == ArmShift::asr ? "sar_" + std::to_string(shift.amount) :
                               "ror_" + std::to_string(shift.amount), reg_expr(shift.source)}});
            }
            const bool load = is_load(instruction.opcode);
            auto value = load ? operand_expr(instruction.operands[1]) : operands[0];
            const auto base_value = std::make_shared<Expression>(Expression{integer_type(32),
                BinaryValue{memory->add ? "add" : "sub", updated, offset}});
            const auto data_reg = as_register(instruction.operands[0]);
            Intrinsic effect{load ? "arm_load_writeback" : "arm_store_writeback",
                load ? std::vector<ExpressionPtr>{value, base_value} : std::vector<ExpressionPtr>{operands[1], value, base_value},
                load ? IntrinsicMemoryEffect::read : IntrinsicMemoryEffect::write};
            if (load && memory->sign_extend)
                effect.name += "_sign_extend";
            else if (load && memory->data_width < 32)
                effect.name += "_zero_extend";
            if (load && data_reg) effect.register_writes.push_back(*data_reg);
            effect.register_writes.push_back(memory->base);
            if (instruction.arm && instruction.arm->predicate == ArmPredicate::condition && instruction.condition < 14) {
                auto predicate = arm32_condition_expr(instruction.condition, reg_expr({RegisterBank::arm_flags, 0, 4, false}));
                effect.name = "arm_conditional_" + effect.name;
                effect.operands.insert(effect.operands.begin(), std::move(predicate));
            }
            return effect;
        }
    }

    const bool x86 = instruction.context.architecture == Architecture::x86 ||
                     instruction.context.architecture == Architecture::x86_64;
    const bool x86_vex_context =
        (instruction.context.architecture == Architecture::x86 && instruction.context.mode == ExecutionMode::x86_32) ||
        (instruction.context.architecture == Architecture::x86_64 && instruction.context.mode == ExecutionMode::x86_64);
    if (x86 && (instruction.opcode == Opcode::xchg || instruction.opcode == Opcode::xadd ||
                instruction.opcode == Opcode::cmpxchg) &&
        instruction.operands.size() == 2) {
        const auto *destination_memory = std::get_if<MemoryOperand>(&instruction.operands[0]);
        const auto destination = as_register(instruction.operands[0]);
        const auto source = as_register(instruction.operands[1]);
        const auto width = destination ? destination->width : destination_memory ? destination_memory->data_width : 0;
        if ((width == 8 || width == 16 || width == 32 || width == 64) && source && source->width == width) {
            std::vector<ExpressionPtr> inputs;
            if (instruction.opcode == Opcode::cmpxchg) {
                const auto accumulator = std::find_if(instruction.register_reads.begin(), instruction.register_reads.end(),
                    [width](RegisterOperand reg) { return reg.bank == RegisterBank::gpr && reg.index == 0 && reg.width == width; });
                if (accumulator == instruction.register_reads.end()) {
                    Intrinsic fallback{"x86_cmpxchg_unmodeled", operands, IntrinsicMemoryEffect::unknown};
                    fallback.register_writes = instruction.register_writes;
                    return fallback;
                }
                inputs.push_back(reg_expr(*accumulator));
            }
            inputs.push_back(retag_expr(operands[0], integer_type(width)));
            inputs.push_back(retag_expr(operands[1], integer_type(width)));
            Intrinsic effect{"x86_" + operation_name(instruction.opcode) + "_i" + std::to_string(width),
                std::move(inputs), destination_memory ? IntrinsicMemoryEffect::unknown : IntrinsicMemoryEffect::none};
            effect.register_writes = instruction.register_writes;
            if (destination) effect.result_type = integer_type(width);
            return effect;
        }
    }
    // Keep scalar arithmetic as a typed operation with its architectural flag
    // writes attached. A plain Assign/Store loses the fact that arithmetic
    // defines FLAGS and makes subsequent condition-code recovery unsound.
    const bool x86_scalar_integer = instruction.opcode == Opcode::add || instruction.opcode == Opcode::sub ||
        instruction.opcode == Opcode::bit_and || instruction.opcode == Opcode::bit_or ||
        instruction.opcode == Opcode::bit_xor || instruction.opcode == Opcode::cmp || instruction.opcode == Opcode::test;
    const bool x86_flags_written = std::any_of(instruction.register_writes.begin(), instruction.register_writes.end(),
        [](RegisterOperand reg) { return reg.bank == RegisterBank::flags; });
    if (x86 && x86_scalar_integer && x86_flags_written && instruction.operands.size() == 2) {
        const auto scalar_width = [](const Operand &operand) -> std::uint16_t {
            return std::visit([](const auto &value) -> std::uint16_t {
                using T = std::decay_t<decltype(value)>;
                if constexpr (std::is_same_v<T, RegisterOperand>)
                    return value.bank == RegisterBank::gpr ? value.width : 0;
                else if constexpr (std::is_same_v<T, MemoryOperand>)
                    return value.data_width;
                else if constexpr (std::is_same_v<T, ImmediateOperand>)
                    return value.effective_width;
                else return 0;
            }, operand);
        };
        const auto width = scalar_width(instruction.operands[0]);
        const auto source_width = scalar_width(instruction.operands[1]);
        if ((width == 8 || width == 16 || width == 32 || width == 64) && source_width && source_width <= width) {
            auto lhs = retag_expr(operand_expr(instruction.operands[0]), integer_type(width));
            auto rhs = retag_expr(operand_expr(instruction.operands[1]), integer_type(width));
            const bool comparison = instruction.opcode == Opcode::cmp || instruction.opcode == Opcode::test;
            const bool memory_destination = is_memory(instruction.operands[0]);
            const bool memory_source = is_memory(instruction.operands[1]);
            Intrinsic effect{"x86_" + operation_name(instruction.opcode) + "_i" + std::to_string(width),
                             {std::move(lhs), std::move(rhs)},
                             memory_destination ? (comparison ? IntrinsicMemoryEffect::read : IntrinsicMemoryEffect::unknown)
                                                : memory_source ? IntrinsicMemoryEffect::read : IntrinsicMemoryEffect::none};
            effect.register_writes = instruction.register_writes;
            if (!comparison && !memory_destination) effect.result_type = integer_type(width);
            return effect;
        }
    }
    const bool x86_unary_integer = instruction.opcode == Opcode::inc || instruction.opcode == Opcode::dec ||
        instruction.opcode == Opcode::neg || instruction.opcode == Opcode::bit_not;
    if (x86 && x86_unary_integer && instruction.operands.size() == 1) {
        const bool reads_flags = std::any_of(instruction.register_reads.begin(), instruction.register_reads.end(),
            [](RegisterOperand reg) { return reg.bank == RegisterBank::flags; });
        const auto *memory = std::get_if<MemoryOperand>(&instruction.operands[0]);
        const auto destination = as_register(instruction.operands[0]);
        const auto width = destination ? destination->width : memory ? memory->data_width : std::uint16_t{0};
        if ((destination && destination->bank == RegisterBank::gpr &&
             (width == 8 || width == 16 || width == 32 || width == 64)) ||
            (memory && (width == 8 || width == 16 || width == 32 || width == 64))) {
            std::vector<ExpressionPtr> inputs{retag_expr(operands[0], integer_type(width))};
            if (reads_flags) {
                const auto flags = std::find_if(instruction.register_reads.begin(), instruction.register_reads.end(),
                    [](RegisterOperand reg) { return reg.bank == RegisterBank::flags; });
                if (flags != instruction.register_reads.end())
                    inputs.push_back(boolean_unary("carry_flag", reg_expr(*flags)));
            }
            Intrinsic effect{"x86_" + operation_name(instruction.opcode) + "_i" + std::to_string(width),
                std::move(inputs), memory ? IntrinsicMemoryEffect::unknown : IntrinsicMemoryEffect::none};
            effect.register_writes = instruction.register_writes;
            if (destination) effect.result_type = integer_type(width);
            return effect;
        }
    }
    if (x86_vex_context && !instruction.x86_evex &&
        (instruction.opcode == Opcode::vcmpps || instruction.opcode == Opcode::vcmppd) &&
        (instruction.vector_bits == 128 || instruction.vector_bits == 256) &&
        instruction.operands.size() == 4 && !instruction.x86_opmask && !instruction.x86_opmask_zeroing) {
        const auto width = static_cast<unsigned>(instruction.vector_bits);
        const auto lane_bits = static_cast<std::uint16_t>(instruction.opcode == Opcode::vcmpps ? 32 : 64);
        const auto *destination = std::get_if<RegisterOperand>(&instruction.operands[0]);
        const auto *memory = std::get_if<MemoryOperand>(&instruction.operands[2]);
        const auto *predicate = std::get_if<ImmediateOperand>(&instruction.operands[3]);
        const bool zero_upper = width == 128 && destination &&
            std::any_of(instruction.register_writes.begin(), instruction.register_writes.end(),
                [&](RegisterOperand reg) {
                    return reg.bank == RegisterBank::ymm && reg.width == 256 && reg.index == destination->index;
                });
        if (destination && x86_avx_detail::is_xmm_or_ymm(instruction.operands[0], width) &&
            x86_avx_detail::is_xmm_or_ymm(instruction.operands[1], width) &&
            (x86_avx_detail::is_xmm_or_ymm(instruction.operands[2], width) ||
             (memory && memory->data_width == width)) && predicate &&
            predicate->encoded_width == 8 && predicate->effective_width == 8 && !predicate->is_signed &&
            predicate->value < 32 && (!instruction.vector_element_bits || instruction.vector_element_bits == lane_bits) &&
            (!instruction.vector_bits || instruction.vector_bits == width) && (width != 128 || zero_upper)) {
            const auto input_type = vector_type(width, TypeKind::floating, lane_bits,
                static_cast<std::uint8_t>(width / lane_bits));
            const auto result_type = vector_type(static_cast<std::uint16_t>(zero_upper ? 256 : width),
                TypeKind::integer, lane_bits,
                static_cast<std::uint8_t>((zero_upper ? 256 : width) / lane_bits));
            const auto low_result_type = vector_type(static_cast<std::uint16_t>(width), TypeKind::integer,
                lane_bits, static_cast<std::uint8_t>(width / lane_bits));
            std::vector<ExpressionPtr> inputs{
                retag_expr(operands[1], input_type), retag_expr(operands[2], input_type),
                retag_expr(operands[3], integer_type(8)),
                reg_expr({RegisterBank::mxcsr, 0, 32, false})};
            Intrinsic effect{"x86_" + operation_name(instruction.opcode) + "_f" +
                std::to_string(lane_bits) + "x" + std::to_string(width / lane_bits) +
                "_predicate" + std::to_string(predicate->value) +
                (zero_upper ? "_zero_upper" : "") + "_mxcsr_control_status", std::move(inputs),
                memory ? IntrinsicMemoryEffect::read : IntrinsicMemoryEffect::none};
            effect.register_writes = instruction.register_writes;
            effect.result_type = result_type;
            const bool writes_destination = std::find(effect.register_writes.begin(), effect.register_writes.end(),
                *destination) != effect.register_writes.end();
            const bool writes_mxcsr = std::any_of(effect.register_writes.begin(), effect.register_writes.end(),
                [](RegisterOperand reg) { return reg.bank == RegisterBank::mxcsr; });
            if (writes_destination && writes_mxcsr) {
                auto compare_inputs = std::make_shared<Expression>(Expression{
                    vector_type(128, TypeKind::integer, 8, 16),
                    BinaryValue{"x86_avx_compare_ie_de_inputs_predicate" + std::to_string(predicate->value),
                        retag_expr(operands[1], input_type), retag_expr(operands[2], input_type)}});
                for (const auto written : effect.register_writes) {
                    if (written == *destination) {
                        effect.register_output_values.push_back(std::make_shared<Expression>(Expression{
                            low_result_type, UnaryValue{"x86_avx_compare_result", compare_inputs}}));
                    } else if (zero_upper && written.bank == RegisterBank::ymm &&
                               written.index == destination->index) {
                        effect.register_output_values.push_back(std::make_shared<Expression>(Expression{
                            vector_type(256, TypeKind::integer, lane_bits,
                                static_cast<std::uint8_t>(256 / lane_bits)),
                            UnaryValue{"x86_avx_compare_result_zero_upper", compare_inputs}}));
                    } else if (written.bank == RegisterBank::mxcsr) {
                        effect.register_output_values.push_back(std::make_shared<Expression>(Expression{
                            integer_type(32), BinaryValue{"x86_mxcsr_after_avx_compare_sticky_ie_de",
                                reg_expr(written), compare_inputs}}));
                    } else {
                        effect.register_output_values.clear();
                        break;
                    }
                }
            }
            return effect;
        }
    }

    if (x86 && instruction.context.mode == ExecutionMode::x86_64 && instruction.x86_evex &&
        (instruction.opcode == Opcode::vcmpps || instruction.opcode == Opcode::vcmppd) &&
        (instruction.vector_bits == 128 || instruction.vector_bits == 256 || instruction.vector_bits == 512) &&
        instruction.operands.size() == 4 && !instruction.x86_opmask_zeroing &&
        (!instruction.x86_opmask || (*instruction.x86_opmask > 0 && *instruction.x86_opmask < 8))) {
        const auto width = static_cast<unsigned>(instruction.vector_bits);
        const auto lane_bits = static_cast<std::uint16_t>(instruction.opcode == Opcode::vcmpps ? 32 : 64);
        const auto *destination = std::get_if<RegisterOperand>(&instruction.operands[0]);
        const auto *memory = std::get_if<MemoryOperand>(&instruction.operands[2]);
        const auto *predicate = std::get_if<ImmediateOperand>(&instruction.operands[3]);
        const bool source2_valid = x86_avx_detail::is_evex_vector(instruction.operands[2], width) ||
            (memory && memory->data_width == (instruction.x86_evex_broadcast ? lane_bits : width));
        if (destination && destination->bank == RegisterBank::opmask && destination->index < 8 &&
            destination->width == 64 && !destination->high_byte &&
            x86_avx_detail::is_evex_vector(instruction.operands[1], width) && source2_valid && predicate &&
            predicate->encoded_width == 8 && predicate->effective_width == 8 && !predicate->is_signed &&
            predicate->value < 32 && (!instruction.vector_element_bits || instruction.vector_element_bits == lane_bits)) {
            const auto vector_value_type = vector_type(width, TypeKind::floating, lane_bits,
                static_cast<std::uint8_t>(width / lane_bits));
            std::vector<ExpressionPtr> inputs{
                retag_expr(operands[1], vector_value_type),
                instruction.x86_evex_broadcast
                    ? retag_expr(operands[2], floating_type(lane_bits))
                    : retag_expr(operands[2], vector_value_type),
                retag_expr(operands[3], integer_type(8))};
            if (instruction.x86_opmask)
                inputs.push_back(reg_expr({RegisterBank::opmask, *instruction.x86_opmask, 64, false}));
            inputs.push_back(reg_expr({RegisterBank::mxcsr, 0, 32, false}));
            Intrinsic effect{"x86_" + operation_name(instruction.opcode) + "_f" + std::to_string(lane_bits) +
                "x" + std::to_string(width / lane_bits) + "_predicate" + std::to_string(predicate->value) +
                "_to_k" + std::to_string(destination->index) +
                (instruction.x86_evex_broadcast ? "_broadcast" : "") +
                (instruction.x86_opmask ? "_masked_zero" : "_unmasked") +
                (instruction.x86_evex_sae ? "_mxcsr_control_sae" : "_mxcsr_control_status"),
                std::move(inputs), memory ? IntrinsicMemoryEffect::read : IntrinsicMemoryEffect::none};
            effect.register_writes = instruction.register_writes;
            effect.result_type = integer_type(64);
            auto compare_inputs = std::make_shared<Expression>(Expression{
                vector_type(width, TypeKind::integer, 8, static_cast<std::uint8_t>(width / 8)),
                BinaryValue{"x86_evex_compare_ie_de_inputs_predicate" + std::to_string(predicate->value),
                    retag_expr(operands[1], vector_value_type),
                    instruction.x86_evex_broadcast
                        ? retag_expr(operands[2], floating_type(lane_bits))
                        : retag_expr(operands[2], vector_value_type)}});
            if (instruction.x86_opmask)
                compare_inputs = std::make_shared<Expression>(Expression{compare_inputs->type, BinaryValue{
                    "x86_evex_compare_ie_de_active_lanes", std::move(compare_inputs),
                    reg_expr({RegisterBank::opmask, *instruction.x86_opmask, 64, false})}});
            for (const auto written : effect.register_writes) {
                if (written == *destination) {
                    effect.register_output_values.push_back(std::make_shared<Expression>(Expression{
                        integer_type(64), UnaryValue{"x86_evex_float_compare_to_mask_result", compare_inputs}}));
                } else if (written.bank == RegisterBank::mxcsr) {
                    effect.register_output_values.push_back(std::make_shared<Expression>(Expression{
                        integer_type(32), BinaryValue{"x86_mxcsr_after_evex_compare_sticky_ie_de",
                            reg_expr(written), compare_inputs}}));
                } else {
                    effect.register_output_values.clear();
                    break;
                }
            }
            return effect;
        }
    }
    if (const auto shape = x86_avx_detail::evex_compare_shape(instruction.opcode);
        x86 && instruction.context.mode == ExecutionMode::x86_64 && instruction.x86_evex &&
        (instruction.vector_bits == 128 || instruction.vector_bits == 256 || instruction.vector_bits == 512) &&
        shape && instruction.operands.size() == 4 && !instruction.x86_opmask_zeroing &&
        (!instruction.vector_element_bits || instruction.vector_element_bits == shape->lane_bits) &&
        (!instruction.x86_opmask || (*instruction.x86_opmask > 0 && *instruction.x86_opmask < 8))) {
        const auto width = static_cast<unsigned>(instruction.vector_bits);
        const auto *destination = std::get_if<RegisterOperand>(&instruction.operands[0]);
        const auto *memory = std::get_if<MemoryOperand>(&instruction.operands[2]);
        const auto *predicate = std::get_if<ImmediateOperand>(&instruction.operands[3]);
        if (destination && destination->bank == RegisterBank::opmask && destination->index < 8 &&
            destination->width == 64 && !destination->high_byte &&
            x86_avx_detail::is_evex_vector(instruction.operands[1], width) &&
            (x86_avx_detail::is_evex_vector(instruction.operands[2], width) ||
             (memory && memory->data_width == width)) && predicate &&
            predicate->encoded_width == 8 && predicate->effective_width == 8 && !predicate->is_signed &&
            predicate->value < 8) {
            const auto lane_type = vector_type(width, TypeKind::integer, shape->lane_bits,
                                               static_cast<std::uint8_t>(width / shape->lane_bits), shape->is_signed);
            std::vector<ExpressionPtr> inputs{
                retag_expr(operands[1], lane_type), retag_expr(operands[2], lane_type),
                retag_expr(operands[3], integer_type(8))};
            if (instruction.x86_opmask)
                inputs.push_back(reg_expr({RegisterBank::opmask, *instruction.x86_opmask, 64, false}));
            Intrinsic effect{"x86_" + operation_name(instruction.opcode) + "_" +
                (shape->is_signed ? "i" : "u") + std::to_string(shape->lane_bits) + "x" +
                std::to_string(width / shape->lane_bits) + "_predicate" +
                std::to_string(predicate->value) + "_to_k" +
                std::to_string(destination->index) + (instruction.x86_opmask ? "_masked_zero" : "_unmasked"),
                std::move(inputs), memory ? IntrinsicMemoryEffect::read : IntrinsicMemoryEffect::none};
            effect.register_writes = instruction.register_writes;
            effect.result_type = integer_type(64);
            // The predicate operation produces one low K bit per input lane.
            // EVEX.aaa clears disabled bits, and the architectural K result
            // clears every bit above the active element count.
            const auto lanes = width / shape->lane_bits;
            const auto active_mask = lanes == 64 ? UINT64_MAX : (UINT64_C(1) << lanes) - 1;
            ExpressionPtr output;
            if (predicate->value == 3) output = constant_expr(0, 64);
            else if (predicate->value == 7) output = constant_expr(active_mask, 64);
            else output = std::make_shared<Expression>(Expression{integer_type(64), BinaryValue{
                "vpcmp_" + std::string(shape->is_signed ? "signed_" : "unsigned_") +
                std::to_string(shape->lane_bits) + "_predicate" + std::to_string(predicate->value),
                retag_expr(operands[1], lane_type), retag_expr(operands[2], lane_type)}});
            if (instruction.x86_opmask)
                output = std::make_shared<Expression>(Expression{integer_type(64), BinaryValue{
                    "and", std::move(output), reg_expr({RegisterBank::opmask, *instruction.x86_opmask, 64, false})}});
            if (lanes < 64)
                output = std::make_shared<Expression>(Expression{integer_type(64), BinaryValue{
                    "and", std::move(output), constant_expr(active_mask, 64)}});
            effect.register_output_values = {std::move(output)};
            return effect;
        }
    }
    if (x86 && instruction.context.mode == ExecutionMode::x86_64 && instruction.x86_evex &&
        (instruction.opcode == Opcode::vpopcntb || instruction.opcode == Opcode::vpopcntw ||
         instruction.opcode == Opcode::vpopcntd || instruction.opcode == Opcode::vpopcntq) &&
        instruction.operands.size() == 2 && !instruction.x86_evex_broadcast && !instruction.x86_evex_sae) {
        const auto width = static_cast<unsigned>(instruction.vector_bits);
        const auto lane_bits = static_cast<std::uint16_t>(instruction.opcode == Opcode::vpopcntb ? 8 :
            instruction.opcode == Opcode::vpopcntw ? 16 : instruction.opcode == Opcode::vpopcntd ? 32 : 64);
        const auto *destination = std::get_if<RegisterOperand>(&instruction.operands[0]);
        const auto *memory = std::get_if<MemoryOperand>(&instruction.operands[1]);
        if ((width == 128 || width == 256 || width == 512) && destination &&
            x86_avx_detail::is_evex_vector(instruction.operands[0], width) &&
            (x86_avx_detail::is_evex_vector(instruction.operands[1], width) ||
             (memory && memory->data_width == width)) &&
            (!instruction.vector_element_bits || instruction.vector_element_bits == lane_bits) &&
            (!instruction.x86_opmask_zeroing || instruction.x86_opmask) &&
            (!instruction.x86_opmask || (*instruction.x86_opmask > 0 && *instruction.x86_opmask < 8))) {
            const auto input_type = vector_type(static_cast<std::uint16_t>(width), TypeKind::integer,
                lane_bits, static_cast<std::uint8_t>(width / lane_bits));
            const auto output_width = static_cast<std::uint16_t>(width < 512 ? 512 : width);
            const auto result_type = vector_type(output_width, TypeKind::integer, lane_bits,
                static_cast<std::uint8_t>(output_width / lane_bits));
            std::vector<ExpressionPtr> inputs;
            if (instruction.x86_opmask && !instruction.x86_opmask_zeroing)
                inputs.push_back(retag_expr(operands[0], input_type));
            inputs.push_back(retag_expr(operands[1], input_type));
            if (instruction.x86_opmask)
                inputs.push_back(reg_expr({RegisterBank::opmask, *instruction.x86_opmask, 64, false}));
            Intrinsic effect{"x86_" + operation_name(instruction.opcode) + "_i" +
                std::to_string(lane_bits) + "x" + std::to_string(width / lane_bits) +
                (instruction.x86_opmask ? (instruction.x86_opmask_zeroing ? "_mask_zero" : "_mask_merge") : "") +
                (width < 512 ? "_zero_upper" : ""), std::move(inputs),
                memory ? IntrinsicMemoryEffect::read : IntrinsicMemoryEffect::none};
            effect.register_writes = instruction.register_writes;
            effect.result_type = result_type;
            return effect;
        }
    }

    if (const auto shift_shape = x86_avx_detail::immediate_shift_shape(instruction.opcode);
        x86 && instruction.context.mode == ExecutionMode::x86_64 && instruction.x86_evex &&
        shift_shape && shift_shape->second_bits == 8 && shift_shape->result_bits != 128 &&
        instruction.operands.size() == 3 && !instruction.x86_evex_broadcast && !instruction.x86_evex_sae) {
        const auto width = static_cast<unsigned>(instruction.vector_bits);
        const auto *destination = std::get_if<RegisterOperand>(&instruction.operands[0]);
        const auto *memory = std::get_if<MemoryOperand>(&instruction.operands[1]);
        const auto *count = std::get_if<ImmediateOperand>(&instruction.operands[2]);
        if (width == 128 || width == 256 || width == 512) {
            const bool valid_source = x86_avx_detail::is_evex_vector(instruction.operands[1], width) ||
                (memory && memory->data_width == width);
            if (destination && x86_avx_detail::is_evex_vector(instruction.operands[0], width) && valid_source &&
                count && count->encoded_width == 8 && count->effective_width == 8 && !count->is_signed &&
                (!instruction.vector_element_bits || instruction.vector_element_bits == shift_shape->result_bits) &&
                (!instruction.x86_opmask_zeroing || instruction.x86_opmask) &&
                (!instruction.x86_opmask || (*instruction.x86_opmask > 0 && *instruction.x86_opmask < 8))) {
                const auto lane_bits = static_cast<std::uint16_t>(shift_shape->result_bits);
                const auto input_type = vector_type(static_cast<std::uint16_t>(width), TypeKind::integer,
                    lane_bits, static_cast<std::uint8_t>(width / lane_bits));
                const auto result_width = static_cast<std::uint16_t>(width < 512 ? 512 : width);
                const auto result_type = vector_type(result_width, TypeKind::integer, lane_bits,
                    static_cast<std::uint8_t>(result_width / lane_bits));
                std::vector<ExpressionPtr> inputs;
                if (instruction.x86_opmask && !instruction.x86_opmask_zeroing)
                    inputs.push_back(retag_expr(operands[0], input_type));
                inputs.push_back(retag_expr(operands[1], input_type));
                inputs.push_back(retag_expr(operands[2], integer_type(8)));
                if (instruction.x86_opmask)
                    inputs.push_back(reg_expr({RegisterBank::opmask, *instruction.x86_opmask, 64, false}));
                Intrinsic effect{"x86_" + operation_name(instruction.opcode) + "_i" +
                    std::to_string(lane_bits) + "x" + std::to_string(width / lane_bits) + "_imm" +
                    std::to_string(count->value) + (instruction.x86_opmask ?
                        (instruction.x86_opmask_zeroing ? "_mask_zero" : "_mask_merge") : "") +
                    (width < 512 ? "_zero_upper" : ""), std::move(inputs),
                    memory ? IntrinsicMemoryEffect::read : IntrinsicMemoryEffect::none};
                effect.register_writes = instruction.register_writes;
                effect.result_type = result_type;
                return effect;
            }
        }
    }

    if (x86 && instruction.context.mode == ExecutionMode::x86_64 && instruction.x86_evex &&
        instruction.operands.size() == 2 &&
        (instruction.opcode == Opcode::vpmovm2b || instruction.opcode == Opcode::vpmovm2w ||
         instruction.opcode == Opcode::vpmovm2d || instruction.opcode == Opcode::vpmovm2q ||
         instruction.opcode == Opcode::vpmovb2m || instruction.opcode == Opcode::vpmovw2m ||
         instruction.opcode == Opcode::vpmovd2m || instruction.opcode == Opcode::vpmovq2m)) {
        const auto width = static_cast<unsigned>(instruction.vector_bits);
        const auto lane_bits = static_cast<std::uint16_t>(
            instruction.opcode == Opcode::vpmovm2b || instruction.opcode == Opcode::vpmovb2m ? 8 :
            instruction.opcode == Opcode::vpmovm2w || instruction.opcode == Opcode::vpmovw2m ? 16 :
            instruction.opcode == Opcode::vpmovm2d || instruction.opcode == Opcode::vpmovd2m ? 32 : 64);
        const bool mask_to_vector = instruction.opcode == Opcode::vpmovm2b ||
            instruction.opcode == Opcode::vpmovm2w || instruction.opcode == Opcode::vpmovm2d ||
            instruction.opcode == Opcode::vpmovm2q;
        const auto *destination = std::get_if<RegisterOperand>(&instruction.operands[0]);
        const bool valid_width = width == 128 || width == 256 || width == 512;
        const bool shape_valid = !instruction.vector_element_bits || instruction.vector_element_bits == lane_bits;
        if (valid_width && shape_valid && destination && !instruction.x86_opmask &&
            !instruction.x86_opmask_zeroing && !instruction.x86_evex_broadcast) {
            if (mask_to_vector && x86_avx_detail::is_evex_vector(instruction.operands[0], width) &&
                destination->bank != RegisterBank::opmask) {
                const auto *source = std::get_if<RegisterOperand>(&instruction.operands[1]);
                if (source && source->bank == RegisterBank::opmask && source->index < 8 &&
                    source->width == 64 && !source->high_byte) {
                    const auto result_width = static_cast<std::uint16_t>(width < 512 ? 512 : width);
                    const auto type = vector_type(result_width, TypeKind::integer, lane_bits,
                        static_cast<std::uint8_t>(result_width / lane_bits));
                    Intrinsic effect{"x86_" + operation_name(instruction.opcode) + "_k_to_i" +
                        std::to_string(lane_bits) + "x" + std::to_string(width / lane_bits) +
                        (width < 512 ? "_zero_upper" : ""),
                        {reg_expr(*source)}, IntrinsicMemoryEffect::none};
                    effect.register_writes = instruction.register_writes;
                    effect.result_type = type;
                    return effect;
                }
            } else if (!mask_to_vector && destination->bank == RegisterBank::opmask &&
                destination->index < 8 && destination->width == 64 && !destination->high_byte &&
                x86_avx_detail::is_evex_vector(instruction.operands[1], width)) {
                const auto type = vector_type(static_cast<std::uint16_t>(width), TypeKind::integer, lane_bits,
                    static_cast<std::uint8_t>(width / lane_bits));
                Intrinsic effect{"x86_" + operation_name(instruction.opcode) + "_i" +
                    std::to_string(lane_bits) + "x" + std::to_string(width / lane_bits) + "_sign_bits_to_k",
                    {retag_expr(operands[1], type)}, IntrinsicMemoryEffect::none};
                effect.register_writes = instruction.register_writes;
                effect.result_type = integer_type(64);
                return effect;
            }
        }
    }

    if (x86 && instruction.context.mode == ExecutionMode::x86_64 && instruction.x86_evex &&
        (instruction.opcode == Opcode::vpternlogd || instruction.opcode == Opcode::vpternlogq) &&
        (instruction.vector_bits == 128 || instruction.vector_bits == 256 || instruction.vector_bits == 512) &&
        instruction.operands.size() == 4 && !instruction.x86_evex_broadcast && !instruction.x86_evex_sae) {
        const auto width = static_cast<unsigned>(instruction.vector_bits);
        const auto lane_bits = static_cast<std::uint16_t>(instruction.opcode == Opcode::vpternlogq ? 64 : 32);
        const auto *destination = std::get_if<RegisterOperand>(&instruction.operands[0]);
        const auto *memory = std::get_if<MemoryOperand>(&instruction.operands[2]);
        const auto *truth_table = std::get_if<ImmediateOperand>(&instruction.operands[3]);
        if (destination && x86_avx_detail::is_evex_vector(instruction.operands[0], width) &&
            x86_avx_detail::is_evex_vector(instruction.operands[1], width) &&
            (x86_avx_detail::is_evex_vector(instruction.operands[2], width) ||
             (memory && memory->data_width == width)) && truth_table &&
            truth_table->encoded_width == 8 && truth_table->effective_width == 8 && !truth_table->is_signed &&
            (!instruction.vector_element_bits || instruction.vector_element_bits == lane_bits) &&
            (!instruction.x86_opmask_zeroing || instruction.x86_opmask) &&
            (!instruction.x86_opmask || (*instruction.x86_opmask > 0 && *instruction.x86_opmask < 8))) {
            const auto input_type = vector_type(static_cast<std::uint16_t>(width), TypeKind::integer,
                lane_bits, static_cast<std::uint8_t>(width / lane_bits));
            const auto result_type = vector_type(static_cast<std::uint16_t>(width < 512 ? 512 : width),
                TypeKind::integer, lane_bits,
                static_cast<std::uint8_t>((width < 512 ? 512 : width) / lane_bits));
            std::vector<ExpressionPtr> inputs{
                retag_expr(operands[0], input_type), retag_expr(operands[1], input_type),
                retag_expr(operands[2], input_type), retag_expr(operands[3], integer_type(8))};
            if (instruction.x86_opmask)
                inputs.push_back(reg_expr({RegisterBank::opmask, *instruction.x86_opmask, 64, false}));
            Intrinsic effect{"x86_" + operation_name(instruction.opcode) + "_i" + std::to_string(lane_bits) +
                "x" + std::to_string(width / lane_bits) + "_truth_table" + std::to_string(truth_table->value) +
                (instruction.x86_opmask ? (instruction.x86_opmask_zeroing ? "_mask_zero" : "_mask_merge") : "") +
                (width < 512 ? "_zero_upper" : ""), std::move(inputs),
                memory ? IntrinsicMemoryEffect::read : IntrinsicMemoryEffect::none};
            effect.register_writes = instruction.register_writes;
            effect.result_type = result_type;
            return effect;
        }
    }

    if (const auto shape = x86_avx_detail::evex_integer_shape(instruction.opcode);
        x86 && instruction.context.mode == ExecutionMode::x86_64 && instruction.x86_evex &&
        (instruction.vector_bits == 128 || instruction.vector_bits == 256 || instruction.vector_bits == 512) &&
        shape && instruction.operands.size() == 3 &&
        (!instruction.vector_element_bits || instruction.vector_element_bits == shape->result_bits) &&
        (!instruction.x86_opmask_zeroing || instruction.x86_opmask) &&
        (!instruction.x86_opmask || (*instruction.x86_opmask > 0 && *instruction.x86_opmask < 8))) {
        const auto *memory = std::get_if<MemoryOperand>(&instruction.operands[2]);
        const auto width = static_cast<unsigned>(instruction.vector_bits);
        const auto vector_bank = width == 128 ? RegisterBank::xmm : width == 256 ? RegisterBank::ymm : RegisterBank::zmm;
        const auto valid_register = [=](const Operand &operand) {
            const auto *reg = std::get_if<RegisterOperand>(&operand);
            return reg && reg->bank == vector_bank && reg->width == width &&
                   reg->index < 32 && !reg->high_byte;
        };
        if (valid_register(instruction.operands[0]) && valid_register(instruction.operands[1]) &&
            (valid_register(instruction.operands[2]) || (memory && memory->data_width == width))) {
            const auto output_width = width < 512 ? 512u : width;
            const auto type_for = [](std::uint16_t lane, bool is_signed, unsigned bits) {
                return vector_type(bits, TypeKind::integer, lane, static_cast<std::uint8_t>(bits / lane), is_signed);
            };
            const auto lane_name = [=](std::uint16_t lane, bool is_signed) {
                return std::string(is_signed ? "i" : "u") + std::to_string(lane) + "x" + std::to_string(width / lane);
            };
            const auto result_type = type_for(shape->result_bits, shape->result_signed, output_width);
            std::vector<ExpressionPtr> inputs;
            std::string masking = "_evex" + std::to_string(width) + "_unmasked";
            if (instruction.x86_opmask && !instruction.x86_opmask_zeroing)
                inputs.push_back(retag_expr(operands[0], type_for(shape->result_bits, shape->result_signed, width)));
            // Preserve both source roles even when registers alias the old
            // destination. Multiply-add input lanes differ from output lanes.
            inputs.push_back(retag_expr(operands[1], type_for(shape->first_bits, shape->first_signed, width)));
            inputs.push_back(retag_expr(operands[2], type_for(shape->second_bits, shape->second_signed, width)));
            if (instruction.x86_opmask) {
                inputs.push_back(reg_expr({RegisterBank::opmask, *instruction.x86_opmask, 64, false}));
                masking = "_evex" + std::to_string(width) + "_k" + std::to_string(*instruction.x86_opmask) +
                    (instruction.x86_opmask_zeroing ? "_zero" : "_merge");
            }
            Intrinsic effect{"x86_" + operation_name(instruction.opcode) + "_" +
                lane_name(shape->first_bits, shape->first_signed) + "_" +
                lane_name(shape->second_bits, shape->second_signed) + "_to_" +
                lane_name(shape->result_bits, shape->result_signed) +
                (width < 512 ? "_zero_upper" : "") + masking,
                std::move(inputs), memory ? IntrinsicMemoryEffect::read : IntrinsicMemoryEffect::none};
            effect.register_writes = instruction.register_writes;
            effect.result_type = result_type;
            return effect;
        }
    }
    if (x86 && instruction.opcode == Opcode::vpcmpgtq && instruction.vector_element_bits &&
        instruction.vector_element_bits != 64) {
        Intrinsic effect{"x86_vpcmpgtq_malformed_lane_width", operands, IntrinsicMemoryEffect::unknown};
        effect.register_writes = instruction.register_writes;
        return effect;
    }
    const bool move_mask = instruction.opcode == Opcode::movmskps || instruction.opcode == Opcode::movmskpd ||
        instruction.opcode == Opcode::pmovmskb || instruction.opcode == Opcode::vmovmskps ||
        instruction.opcode == Opcode::vmovmskpd || instruction.opcode == Opcode::vpmovmskb;
    if (x86 && move_mask &&
        instruction.operands.size() == 2 && !instruction.x86_evex && !instruction.x86_opmask &&
        !instruction.x86_opmask_zeroing && !instruction.x86_evex_broadcast && !instruction.x86_evex_sae &&
        instruction.flow == FlowKind::fallthrough &&
        !instruction.lock_prefix && instruction.access ==
            std::vector<OperandAccess>{OperandAccess::write, OperandAccess::read}) {
        const auto destination = as_register(instruction.operands[0]);
        const auto *source = std::get_if<RegisterOperand>(&instruction.operands[1]);
        const auto vector_bits = instruction.vector_bits;
        const bool is_byte_mask = instruction.opcode == Opcode::pmovmskb || instruction.opcode == Opcode::vpmovmskb;
        const bool is_double = instruction.opcode == Opcode::movmskpd || instruction.opcode == Opcode::vmovmskpd;
        const bool vex = instruction.opcode == Opcode::vmovmskps || instruction.opcode == Opcode::vmovmskpd ||
                         instruction.opcode == Opcode::vpmovmskb;
        const std::uint16_t lane_bits = is_byte_mask ? 8 : is_double ? 64 : 32;
        const auto lanes = static_cast<std::uint8_t>(vector_bits / lane_bits);
        const auto lane_kind = is_byte_mask ? TypeKind::integer : TypeKind::floating;
        const auto expected_bank = vector_bits == 128 ? RegisterBank::xmm : RegisterBank::ymm;
        const auto mode = instruction.context.mode;
        const auto max_gprs = mode == ExecutionMode::x86_64 ? 16 : 8;
        const bool source_reads = source && std::find(instruction.register_reads.begin(),
            instruction.register_reads.end(), *source) != instruction.register_reads.end();
        const bool destination_writes = destination && std::find(instruction.register_writes.begin(),
            instruction.register_writes.end(), *destination) != instruction.register_writes.end();
        if (destination && source && destination->bank == RegisterBank::gpr && destination->width == 32 &&
            source->bank == expected_bank && source->width == vector_bits &&
            (vector_bits == 128 || (vex && vector_bits == 256)) &&
            (mode == ExecutionMode::x86_64 || mode == ExecutionMode::x86_16 || mode == ExecutionMode::x86_32) &&
            ((instruction.context.architecture == Architecture::x86_64) == (mode == ExecutionMode::x86_64)) &&
            destination->index < max_gprs && source->index < max_gprs &&
            instruction.vector_element_bits == lane_bits && operands[1]->type.bits == vector_bits &&
            (!vex || x86_vex_context) &&
            source_reads && destination_writes &&
            instruction.register_reads == std::vector<RegisterOperand>{*source} &&
            instruction.register_writes == std::vector<RegisterOperand>{*destination} &&
            !instruction.memory_read && !instruction.memory_write &&
            !x86_writes_flags(instruction)) {
            const auto source_type = vector_type(vector_bits, lane_kind, lane_bits, lanes);
            auto vector_source = retag_expr(operands[1], source_type);
            const auto lane_name = std::string(is_byte_mask ? "i" : "f") + std::to_string(lane_bits) + "x" +
                std::to_string(lanes);
            auto output = std::make_shared<Expression>(Expression{integer_type(32),
                UnaryValue{"movemask_zero_extend_" + lane_name + "_to_i32", vector_source}});
            Intrinsic effect{"x86_" + operation_name(instruction.opcode) + "_" + lane_name + "_to_i32",
                {vector_source}, IntrinsicMemoryEffect::none};
            effect.register_writes = instruction.register_writes;
            effect.result_type = integer_type(32);
            for (const auto written : effect.register_writes) {
                if (written == *destination) effect.register_output_values.push_back(output);
                else return Intrinsic{"x86_" + operation_name(instruction.opcode) +
                    "_unmodeled_output", {vector_source}, IntrinsicMemoryEffect::unknown};
            }
            if (effect.register_output_values.size() == effect.register_writes.size()) return effect;
        }
    }
    if (const auto shape = x86_avx_detail::integer_dataflow_shape(instruction.opcode);
        x86_vex_context && shape &&
        instruction.operands.size() == 3 && !instruction.x86_evex && !instruction.x86_opmask &&
        !instruction.x86_opmask_zeroing) {
        const auto destination = as_register(instruction.operands[0]);
        const auto *memory = std::get_if<MemoryOperand>(&instruction.operands[2]);
        const auto width = destination ? destination->width : std::uint16_t{0};
        const bool zero_upper = width == 128 && destination &&
            std::any_of(instruction.register_writes.begin(), instruction.register_writes.end(),
                [&](RegisterOperand reg) {
                    return reg.bank == RegisterBank::ymm && reg.width == 256 && reg.index == destination->index;
                });
        if (destination && (width == 128 || width == 256) &&
            (!instruction.vector_bits || instruction.vector_bits == width) &&
            x86_avx_detail::is_xmm_or_ymm(instruction.operands[0], width) &&
            x86_avx_detail::is_xmm_or_ymm(instruction.operands[1], width) && (width != 128 || zero_upper) &&
            (x86_avx_detail::is_xmm_or_ymm(instruction.operands[2], width) || (memory && memory->data_width == width))) {
            const auto type_for = [](std::uint16_t bits, std::uint16_t lane, bool is_signed) {
                return vector_type(bits, TypeKind::integer, lane, static_cast<std::uint8_t>(bits / lane), is_signed);
            };
            const auto lane_name = [&](std::uint16_t lane, bool is_signed) {
                return std::string(is_signed ? "i" : "u") + std::to_string(lane) + "x" + std::to_string(width / lane);
            };
            // Distinct input/result shapes preserve narrowing, even-dword
            // products and mixed unsigned/signed byte multiply-add semantics.
            const auto suffix = "_" + lane_name(shape->first_bits, shape->first_signed) + "_" +
                lane_name(shape->second_bits, shape->second_signed) + "_to_" +
                lane_name(shape->result_bits, shape->result_signed) + "_lane128" +
                (zero_upper ? "_zero_upper" : "");
            Intrinsic effect{"x86_" + operation_name(instruction.opcode) + suffix,
                {retag_expr(operands[1], type_for(width, shape->first_bits, shape->first_signed)),
                 retag_expr(operands[2], type_for(width, shape->second_bits, shape->second_signed))},
                memory ? IntrinsicMemoryEffect::read : IntrinsicMemoryEffect::none};
            effect.register_writes = instruction.register_writes;
            effect.result_type = type_for(static_cast<std::uint16_t>(zero_upper ? 256 : width),
                                         shape->result_bits, shape->result_signed);
            return effect;
        }
    }

    if (const auto lane = x86_avx_detail::absolute_lane_width(instruction.opcode);
        x86_vex_context && lane &&
        instruction.operands.size() == 2 && !instruction.x86_evex && !instruction.x86_opmask &&
        !instruction.x86_opmask_zeroing) {
        const auto destination = as_register(instruction.operands[0]);
        const auto *memory = std::get_if<MemoryOperand>(&instruction.operands[1]);
        const auto width = destination ? destination->width : std::uint16_t{0};
        const bool zero_upper = width == 128 && destination &&
            std::any_of(instruction.register_writes.begin(), instruction.register_writes.end(),
                [&](RegisterOperand reg) {
                    return reg.bank == RegisterBank::ymm && reg.width == 256 && reg.index == destination->index;
                });
        if (destination && (width == 128 || width == 256) &&
            x86_avx_detail::is_xmm_or_ymm(instruction.operands[0], width) &&
            (x86_avx_detail::is_xmm_or_ymm(instruction.operands[1], width) ||
             (memory && memory->data_width == width)) && (width != 128 || zero_upper) &&
            (!instruction.vector_bits || instruction.vector_bits == width) &&
            (!instruction.vector_element_bits || instruction.vector_element_bits == *lane)) {
            const auto result_width = static_cast<std::uint16_t>(zero_upper ? 256 : width);
            const auto source_type = vector_type(width, TypeKind::integer, *lane,
                static_cast<std::uint8_t>(width / *lane), true);
            const auto result_type = vector_type(result_width, TypeKind::integer, *lane,
                static_cast<std::uint8_t>(result_width / *lane), false);
            Intrinsic effect{"x86_" + operation_name(instruction.opcode) + "_i" +
                std::to_string(*lane) + "x" + std::to_string(width / *lane) + "_to_u" +
                std::to_string(*lane) + "x" + std::to_string(result_width / *lane) +
                (zero_upper ? "_zero_upper" : ""),
                {retag_expr(operands[1], source_type)},
                memory ? IntrinsicMemoryEffect::read : IntrinsicMemoryEffect::none};
            effect.register_writes = instruction.register_writes;
            effect.result_type = result_type;
            return effect;
        }
    }

    if (const auto shape = x86_avx_detail::immediate_shift_shape(instruction.opcode);
        x86_vex_context && shape &&
        instruction.operands.size() == 3 && !instruction.x86_evex && !instruction.x86_opmask &&
        !instruction.x86_opmask_zeroing) {
        const auto destination = as_register(instruction.operands[0]);
        const auto *memory = std::get_if<MemoryOperand>(&instruction.operands[1]);
        const auto *count = std::get_if<ImmediateOperand>(&instruction.operands[2]);
        const auto width = destination ? destination->width : std::uint16_t{0};
        const bool zero_upper = width == 128 && destination &&
            std::any_of(instruction.register_writes.begin(), instruction.register_writes.end(),
                [&](RegisterOperand reg) {
                    return reg.bank == RegisterBank::ymm && reg.width == 256 && reg.index == destination->index;
                });
        if (destination && (width == 128 || width == 256) &&
            x86_avx_detail::is_xmm_or_ymm(instruction.operands[0], width) &&
            (x86_avx_detail::is_xmm_or_ymm(instruction.operands[1], width) ||
             (memory && memory->data_width == width)) && count &&
            count->encoded_width == 8 && count->effective_width == 8 && !count->is_signed &&
            count->value <= 0xff && (!instruction.vector_bits || instruction.vector_bits == width) &&
            (width != 128 || zero_upper) &&
            (!instruction.vector_element_bits || instruction.vector_element_bits == shape->result_bits)) {
            const auto result_width = static_cast<std::uint16_t>(zero_upper ? 256 : width);
            const auto source_type = vector_type(width, TypeKind::integer, shape->first_bits,
                static_cast<std::uint8_t>(width / shape->first_bits), shape->first_signed);
            const auto result_type = vector_type(result_width, TypeKind::integer, shape->result_bits,
                static_cast<std::uint8_t>(result_width / shape->result_bits), shape->result_signed);
            const auto lane_name = [](std::uint16_t lane, bool is_signed) {
                return std::string(is_signed ? "i" : "u") + std::to_string(lane);
            };
            Intrinsic effect{"x86_" + operation_name(instruction.opcode) + "_" +
                lane_name(shape->result_bits, shape->result_signed) + "x" +
                std::to_string(result_width / shape->result_bits) + "_imm8_lane128" +
                (zero_upper ? "_zero_upper" : ""),
                {retag_expr(operands[1], source_type), retag_expr(operands[2], integer_type(8))},
                memory ? IntrinsicMemoryEffect::read : IntrinsicMemoryEffect::none};
            effect.register_writes = instruction.register_writes;
            effect.result_type = result_type;
            return effect;
        }
    }

    const bool avx_move = instruction.opcode == Opcode::vmovups;
    const bool avx_shuffle = instruction.opcode == Opcode::vshufps || instruction.opcode == Opcode::vshufpd;
    const bool avx_immediate_shuffle = instruction.opcode == Opcode::vpshufd;
    const bool avx_float_arithmetic = instruction.opcode == Opcode::vaddps || instruction.opcode == Opcode::vaddpd ||
        instruction.opcode == Opcode::vsubps || instruction.opcode == Opcode::vsubpd ||
        instruction.opcode == Opcode::vmulps || instruction.opcode == Opcode::vmulpd ||
        instruction.opcode == Opcode::vdivps || instruction.opcode == Opcode::vdivpd;
    const bool avx_bitwise = instruction.opcode == Opcode::vxorps || instruction.opcode == Opcode::vxorpd ||
        instruction.opcode == Opcode::vandps || instruction.opcode == Opcode::vandpd;
    const bool avx_integer_arithmetic = instruction.opcode == Opcode::vpaddb || instruction.opcode == Opcode::vpaddw ||
        instruction.opcode == Opcode::vpaddd || instruction.opcode == Opcode::vpaddq ||
        instruction.opcode == Opcode::vpaddsb || instruction.opcode == Opcode::vpaddsw ||
        instruction.opcode == Opcode::vpaddusb || instruction.opcode == Opcode::vpaddusw;
    const bool avx_integer_subtraction = instruction.opcode == Opcode::vpsubb || instruction.opcode == Opcode::vpsubw ||
        instruction.opcode == Opcode::vpsubd || instruction.opcode == Opcode::vpsubq ||
        instruction.opcode == Opcode::vpsubsb || instruction.opcode == Opcode::vpsubsw ||
        instruction.opcode == Opcode::vpsubusb || instruction.opcode == Opcode::vpsubusw;
    const bool avx_integer_minmax = instruction.opcode == Opcode::vpminub || instruction.opcode == Opcode::vpminsw ||
        instruction.opcode == Opcode::vpmaxub || instruction.opcode == Opcode::vpmaxsw;
    const bool avx_integer_multiply = instruction.opcode == Opcode::vpmullw || instruction.opcode == Opcode::vpmulhw ||
        instruction.opcode == Opcode::vpmulhuw;
    const bool avx_integer_sign = instruction.opcode == Opcode::vpsignb || instruction.opcode == Opcode::vpsignw ||
        instruction.opcode == Opcode::vpsignd;
    const bool avx_integer_compare = x86_avx_detail::is_equal_compare(instruction.opcode) ||
                                     x86_avx_detail::is_greater_compare(instruction.opcode);
    const bool avx_integer_shift = instruction.opcode == Opcode::vpsllvw || instruction.opcode == Opcode::vpsllvd ||
        instruction.opcode == Opcode::vpsllvq || instruction.opcode == Opcode::vpsrlvw ||
        instruction.opcode == Opcode::vpsrlvd || instruction.opcode == Opcode::vpsrlvq ||
        instruction.opcode == Opcode::vpsravw || instruction.opcode == Opcode::vpsravd || instruction.opcode == Opcode::vpsravq;
    const bool avx_integer_lanes = (!instruction.x86_evex || avx_integer_shift) &&
        (avx_integer_arithmetic || avx_integer_subtraction || avx_integer_multiply ||
         avx_integer_minmax || avx_integer_compare || avx_integer_shift || avx_integer_sign ||
         instruction.opcode == Opcode::vpermd);
    const auto avx_integer_lane_bits = instruction.opcode == Opcode::vpcmpeqb || instruction.opcode == Opcode::vpcmpgtb ||
        instruction.opcode == Opcode::vpaddb || instruction.opcode == Opcode::vpsubb ||
        instruction.opcode == Opcode::vpaddsb || instruction.opcode == Opcode::vpaddusb ||
        instruction.opcode == Opcode::vpsubsb || instruction.opcode == Opcode::vpsubusb || instruction.opcode == Opcode::vpsignb ||
        instruction.opcode == Opcode::vpminub || instruction.opcode == Opcode::vpmaxub ? 8u
        : instruction.opcode == Opcode::vpcmpeqw || instruction.opcode == Opcode::vpcmpgtw ||
          instruction.opcode == Opcode::vpaddw || instruction.opcode == Opcode::vpsubw ||
          instruction.opcode == Opcode::vpaddsw || instruction.opcode == Opcode::vpaddusw ||
          instruction.opcode == Opcode::vpsubsw || instruction.opcode == Opcode::vpsubusw ||
          instruction.opcode == Opcode::vpsignw || instruction.opcode == Opcode::vpminsw || instruction.opcode == Opcode::vpmaxsw ? 16u
        : instruction.opcode == Opcode::vpcmpeqd || instruction.opcode == Opcode::vpcmpgtd ||
          instruction.opcode == Opcode::vpaddd || instruction.opcode == Opcode::vpsubd || instruction.opcode == Opcode::vpsignd ? 32u
        : instruction.opcode == Opcode::vpcmpgtq ||
          instruction.opcode == Opcode::vpaddq || instruction.opcode == Opcode::vpsubq ? 64u
        : instruction.opcode == Opcode::vpsllvw || instruction.opcode == Opcode::vpsrlvw || instruction.opcode == Opcode::vpsravw ? 16u
        : instruction.opcode == Opcode::vpsllvq || instruction.opcode == Opcode::vpsrlvq || instruction.opcode == Opcode::vpsravq ? 64u
        : instruction.opcode == Opcode::vpermd ? 32u
        : avx_integer_multiply ? 16u : 0u;
    const bool avx_integer_bitwise = instruction.opcode == Opcode::vpand || instruction.opcode == Opcode::vpor ||
        instruction.opcode == Opcode::vpxor || instruction.opcode == Opcode::vpandd ||
        instruction.opcode == Opcode::vpandq || instruction.opcode == Opcode::vpord ||
        instruction.opcode == Opcode::vporq || instruction.opcode == Opcode::vpxord ||
        instruction.opcode == Opcode::vpxorq;
    if (x86 && (avx_move || avx_shuffle || avx_immediate_shuffle || avx_float_arithmetic ||
                avx_bitwise || avx_integer_lanes || avx_integer_bitwise)) {
        const auto destination = instruction.operands.empty() ? std::optional<RegisterOperand>{} : as_register(instruction.operands[0]);
        const auto move_source = avx_move && instruction.operands.size() == 2 ? as_register(instruction.operands[1]) : std::optional<RegisterOperand>{};
        const auto vector_width = static_cast<std::uint16_t>(destination ? destination->width : move_source ? move_source->width : 0);
        const auto vector_bank = vector_width == 512 ? RegisterBank::zmm :
                                 vector_width == 256 ? RegisterBank::ymm : RegisterBank::xmm;
        const bool supported_width = (vector_width == 128 || vector_width == 256 || vector_width == 512) &&
            ((destination && destination->bank == vector_bank) || (!destination && move_source && move_source->bank == vector_bank));
        // VEX.128 clears the upper YMM half. EVEX.128/.256 clear the full
        // upper portion of the physical ZMM register; the decoder records
        // those wider writes explicitly. VEX.256 retains its YMM result.
        const bool zero_upper = destination.has_value() &&
            ((instruction.x86_evex && vector_width < 512) || (!instruction.x86_evex && vector_width == 128));
        const auto result_width = static_cast<std::uint16_t>(zero_upper
            ? (instruction.x86_evex ? 512 : 256) : vector_width);
        const auto vector_type_for = [&](bool floating, std::uint16_t width) {
            const auto lane_bits = avx_integer_lanes
                ? static_cast<std::uint16_t>(avx_integer_lane_bits)
                : (instruction.opcode == Opcode::vpandq || instruction.opcode == Opcode::vporq ||
                   instruction.opcode == Opcode::vpxorq) ? std::uint16_t{64}
                : (instruction.opcode == Opcode::vpandd || instruction.opcode == Opcode::vpord ||
                   instruction.opcode == Opcode::vpxord) ? std::uint16_t{32}
                : (instruction.opcode == Opcode::vaddpd || instruction.opcode == Opcode::vsubpd ||
                instruction.opcode == Opcode::vmulpd || instruction.opcode == Opcode::vdivpd ||
                instruction.opcode == Opcode::vxorpd || instruction.opcode == Opcode::vandpd)
                ? std::uint16_t{64} : std::uint16_t{32};
            return vector_type(width, floating ? TypeKind::floating : TypeKind::integer,
                               (floating || avx_integer_lanes || avx_integer_bitwise) ? lane_bits : width,
                               (floating || avx_integer_lanes || avx_integer_bitwise) ? static_cast<std::uint8_t>(width / lane_bits) : std::uint8_t{1});
        };
        const auto valid_vector_operand = [&](const Operand &operand, bool allow_memory) {
            if (const auto *reg = std::get_if<RegisterOperand>(&operand))
                return reg->bank == vector_bank && reg->width == vector_width;
            if (allow_memory)
                if (const auto *memory = std::get_if<MemoryOperand>(&operand))
                    return memory->data_width == vector_width ||
                        (instruction.x86_evex_broadcast && memory->data_width == instruction.vector_element_bits);
            return false;
        };
        if (supported_width && avx_move && instruction.operands.size() == 2) {
            const bool store = std::holds_alternative<MemoryOperand>(instruction.operands[0]);
            const auto &source = instruction.operands[1];
            const bool source_valid = valid_vector_operand(source, true);
            const bool destination_valid = store ? std::get<MemoryOperand>(instruction.operands[0]).data_width == vector_width
                                                 : valid_vector_operand(instruction.operands[0], false);
            if (source_valid && destination_valid) {
                const auto input_type = vector_type_for(false, vector_width);
                const auto result_type = vector_type_for(false, result_width);
                std::vector<ExpressionPtr> inputs{retag_expr(operands[1], input_type)};
                if (store) inputs.push_back(retag_expr(operands[0], input_type));
                std::string mask_suffix;
                if (instruction.x86_opmask) {
                    const auto mask_index = *instruction.x86_opmask;
                    if (!store && !instruction.x86_opmask_zeroing)
                        inputs.insert(inputs.begin(), retag_expr(operands[0], input_type));
                    inputs.push_back(reg_expr({RegisterBank::opmask, mask_index, 64, false}));
                    mask_suffix = "_evex_k" + std::to_string(mask_index) +
                                  (instruction.x86_opmask_zeroing ? "_zero" : "_merge");
                }
                Intrinsic effect{"x86_vmovups_bits" + std::to_string(vector_width) +
                                     (zero_upper ? "_zero_upper" : "") + mask_suffix, std::move(inputs),
                    store ? IntrinsicMemoryEffect::write :
                    std::holds_alternative<MemoryOperand>(source) ? IntrinsicMemoryEffect::read : IntrinsicMemoryEffect::none};
                effect.register_writes = instruction.register_writes;
                if (!store) effect.result_type = result_type;
                return effect;
            }
        } else if (supported_width && avx_immediate_shuffle && instruction.operands.size() == 3) {
            const auto *selector = std::get_if<ImmediateOperand>(&instruction.operands[2]);
            const bool source_valid = valid_vector_operand(instruction.operands[1], true);
            if (source_valid && selector && selector->encoded_width == 8 &&
                selector->effective_width == 8 && !selector->is_signed && instruction.vector_bits == vector_width &&
                instruction.vector_element_bits == 32 &&
                (!instruction.x86_evex || !instruction.x86_opmask_zeroing || instruction.x86_opmask)) {
                const auto input_type = vector_type(vector_width, TypeKind::integer, 32,
                    static_cast<std::uint8_t>(vector_width / 32));
                const auto result_type = vector_type(result_width, TypeKind::integer, 32,
                    static_cast<std::uint8_t>(result_width / 32));
                std::vector<ExpressionPtr> shuffle_inputs;
                if (instruction.x86_opmask && !instruction.x86_opmask_zeroing)
                    shuffle_inputs.push_back(retag_expr(operands[0], input_type));
                shuffle_inputs.push_back(retag_expr(operands[1], input_type));
                shuffle_inputs.push_back(constant_expr(selector->value, 8));
                if (instruction.x86_opmask)
                    shuffle_inputs.push_back(reg_expr({RegisterBank::opmask, *instruction.x86_opmask, 64, false}));
                Intrinsic effect{"x86_vpshufd_i32x" + std::to_string(vector_width / 32) + "_imm8_lane128" +
                    (instruction.x86_evex ? "_evex" + std::to_string(vector_width) : "") +
                    (zero_upper ? "_zero_upper" : "") +
                    (instruction.x86_opmask ? (instruction.x86_opmask_zeroing ? "_mask_zero" : "_mask_merge") : ""),
                    std::move(shuffle_inputs),
                    std::holds_alternative<MemoryOperand>(instruction.operands[1])
                        ? IntrinsicMemoryEffect::read : IntrinsicMemoryEffect::none};
                effect.register_writes = instruction.register_writes;
                effect.result_type = result_type;
                return effect;
            }
        } else if (supported_width && avx_shuffle && instruction.operands.size() == 4) {
            const auto first = as_register(instruction.operands[1]);
            const auto *selector = std::get_if<ImmediateOperand>(&instruction.operands[3]);
            const bool source2_valid = valid_vector_operand(instruction.operands[2], true);
            if (!instruction.x86_evex && first && first->bank == vector_bank && first->width == vector_width &&
                source2_valid && selector && selector->encoded_width == 8 && selector->effective_width == 8 &&
                !selector->is_signed && instruction.vector_bits == vector_width &&
                instruction.vector_element_bits == (instruction.opcode == Opcode::vshufps ? 32 : 64)) {
                const auto lane_bits = static_cast<std::uint16_t>(instruction.vector_element_bits);
                const auto input_type = vector_type(vector_width, TypeKind::floating, lane_bits,
                    static_cast<std::uint8_t>(vector_width / lane_bits));
                const auto result_type = vector_type(result_width, TypeKind::floating, lane_bits,
                    static_cast<std::uint8_t>(result_width / lane_bits));
                std::vector<ExpressionPtr> inputs{
                    retag_expr(operands[1], input_type), retag_expr(operands[2], input_type),
                    constant_expr(selector->value, 8)};
                Intrinsic effect{"x86_" + operation_name(instruction.opcode) + "_f" +
                    std::to_string(lane_bits) + "x" + std::to_string(vector_width / lane_bits) +
                    (zero_upper ? "_zero_upper" : ""), std::move(inputs),
                    std::holds_alternative<MemoryOperand>(instruction.operands[2])
                        ? IntrinsicMemoryEffect::read : IntrinsicMemoryEffect::none};
                effect.register_writes = instruction.register_writes;
                effect.result_type = result_type;
                return effect;
            }
        } else if (supported_width && (avx_float_arithmetic || avx_bitwise || avx_integer_lanes || avx_integer_bitwise) &&
                   instruction.operands.size() == 3) {
            const auto first = as_register(instruction.operands[1]);
            const bool source2_valid = valid_vector_operand(instruction.operands[2], true);
            if (first && first->bank == vector_bank && first->width == vector_width && source2_valid) {
                auto input_type = vector_type_for(avx_float_arithmetic, vector_width);
                if (avx_integer_sign) input_type.is_signed = true;
                auto result_type = vector_type_for(avx_float_arithmetic, result_width);
                if (avx_integer_sign) result_type.is_signed = true;
                auto second = retag_expr(operands[1], input_type);
                auto third = instruction.x86_evex_broadcast
                    ? retag_expr(operands[2], floating_type(instruction.vector_element_bits))
                    : retag_expr(operands[2], input_type);
                const bool packed_double = instruction.opcode == Opcode::vaddpd || instruction.opcode == Opcode::vsubpd ||
                    instruction.opcode == Opcode::vmulpd || instruction.opcode == Opcode::vdivpd ||
                    instruction.opcode == Opcode::vxorpd || instruction.opcode == Opcode::vandpd;
                const std::string suffix = (avx_bitwise || avx_integer_bitwise)
                    ? "_bits" + std::to_string(vector_width) + (zero_upper ? "_zero_upper" : "")
                    : avx_integer_lanes
                        ? "_i" + std::to_string(avx_integer_lane_bits) + "x" +
                              std::to_string(vector_width / avx_integer_lane_bits) +
                              (zero_upper ? "_zero_upper" : "")
                        : "_f" + std::to_string(packed_double ? 64 : 32) + "x" +
                              std::to_string(vector_width / (packed_double ? 64 : 32)) +
                              (zero_upper ? "_zero_upper" : "");
                std::vector<ExpressionPtr> inputs{std::move(second), std::move(third)};
                std::string mask_suffix;
                if (instruction.x86_opmask) {
                    const auto mask_index = *instruction.x86_opmask;
                    if (!instruction.x86_opmask_zeroing)
                        inputs.insert(inputs.begin(), retag_expr(operands[0], input_type));
                    inputs.push_back(reg_expr({RegisterBank::opmask, mask_index, 64, false}));
                    mask_suffix = "_evex_k" + std::to_string(mask_index) +
                                  (instruction.x86_opmask_zeroing ? "_zero" : "_merge");
                }
                if (avx_float_arithmetic)
                    inputs.push_back(reg_expr({RegisterBank::mxcsr, 0, 32, false}));
                Intrinsic effect{"x86_" + operation_name(instruction.opcode) + suffix +
                                     (instruction.x86_evex_broadcast ? "_broadcast" : "") +
                                     mask_suffix + (avx_float_arithmetic ? "_mxcsr_control_status" : ""),
                    std::move(inputs),
                    std::holds_alternative<MemoryOperand>(instruction.operands[2]) ? IntrinsicMemoryEffect::read : IntrinsicMemoryEffect::none};
                effect.register_writes = instruction.register_writes;
                effect.result_type = result_type;
                if (avx_float_arithmetic) {
                    const auto status_type = integer_type(32);
                    const auto old_mxcsr = reg_expr({RegisterBank::mxcsr, 0, 32, false});
                    const bool merge = instruction.x86_evex && instruction.x86_opmask &&
                                       !instruction.x86_opmask_zeroing;
                    const auto fp_type = vector_type_for(true, vector_width);
                    const auto active = std::make_shared<Expression>(Expression{fp_type,
                        BinaryValue{"x86_" + operation_name(instruction.opcode) +
                            "_rounded_fp_lanes_using_mxcsr_rounding", retag_expr(operands[1], fp_type),
                            instruction.x86_evex_broadcast
                                ? retag_expr(operands[2], floating_type(instruction.vector_element_bits))
                                : retag_expr(operands[2], fp_type)}});
                    ExpressionPtr destination_value = active;
                    if (instruction.x86_opmask) {
                        const auto mask = reg_expr({RegisterBank::opmask, *instruction.x86_opmask, 64, false});
                        destination_value = std::make_shared<Expression>(Expression{fp_type,
                            BinaryValue{merge ? "x86_evex_merge_active_fp_lanes_only" :
                                               "x86_evex_zero_inactive_fp_lanes_using_mask",
                                merge ? retag_expr(operands[0], fp_type) : mask, active}});
                    }
                    ExpressionPtr exception_inputs = active;
                    if (instruction.x86_evex && instruction.x86_opmask) {
                        exception_inputs = std::make_shared<Expression>(Expression{status_type,
                            BinaryValue{"x86_evex_filter_fp_exception_flags_to_opmask_active_lanes",
                                active, reg_expr({RegisterBank::opmask, *instruction.x86_opmask, 64, false})}});
                    }
                    const auto exceptions = std::make_shared<Expression>(Expression{status_type,
                        BinaryValue{"x86_" + operation_name(instruction.opcode) +
                            "_fp_exception_flags_ie_de_ze_oe_ue_pe_with_mxcsr_masks", exception_inputs, old_mxcsr}});
                    const auto next_mxcsr = std::make_shared<Expression>(Expression{status_type,
                        BinaryValue{"x86_mxcsr_after_avx_fp_arithmetic_sticky_status_ie_de_ze_oe_ue_pe",
                            old_mxcsr, exceptions}});
                    effect.register_output_values.reserve(effect.register_writes.size());
                    for (const auto written : effect.register_writes) {
                        if (destination && written == *destination) effect.register_output_values.push_back(destination_value);
                        else if (written.bank == RegisterBank::mxcsr) effect.register_output_values.push_back(next_mxcsr);
                        else if ((instruction.x86_evex && written.bank == RegisterBank::zmm) ||
                                 (!instruction.x86_evex && written.bank == RegisterBank::ymm))
                            effect.register_output_values.push_back(std::make_shared<Expression>(Expression{
                                vector_type_for(true, written.width), UnaryValue{
                                    instruction.x86_evex ? "x86_evex_zero_upper_zmm_after_fp_arithmetic"
                                                        : "x86_vex_zero_upper_ymm_after_fp_arithmetic", destination_value}}));
                        else { effect.register_output_values.clear(); break; }
                    }
                    if (effect.register_output_values.size() != effect.register_writes.size())
                        effect.register_output_values.clear();
                }
                return effect;
            }
        }
    }

    if (x86 && instruction.opcode == Opcode::pshufd && instruction.operands.size() == 3) {
        const auto destination = as_register(instruction.operands[0]);
        const auto source = as_register(instruction.operands[1]);
        const auto *source_memory = std::get_if<MemoryOperand>(&instruction.operands[1]);
        const auto *selector = std::get_if<ImmediateOperand>(&instruction.operands[2]);
        const bool destination_ok = destination && destination->bank == RegisterBank::xmm && destination->width == 128;
        const bool source_ok = (source && source->bank == RegisterBank::xmm && source->width == 128) ||
                               (source_memory && source_memory->data_width == 128);
        if (destination_ok && source_ok && selector && selector->encoded_width == 8 &&
            selector->effective_width == 8 && !selector->is_signed) {
            const auto value_type = vector_type(128, TypeKind::integer, 32, 4);
            Intrinsic effect{"x86_pshufd_i32x4",
                {retag_expr(operands[1], value_type), retag_expr(operands[2], integer_type(8))},
                source_memory ? IntrinsicMemoryEffect::read : IntrinsicMemoryEffect::none};
            effect.register_writes = instruction.register_writes;
            effect.result_type = value_type;
            return effect;
        }
    }

    if (x86 && instruction.opcode == Opcode::pshufb && instruction.operands.size() == 2) {
        const auto destination = as_register(instruction.operands[0]);
        const auto *source_memory = std::get_if<MemoryOperand>(&instruction.operands[1]);
        const auto source = as_register(instruction.operands[1]);
        const bool destination_ok = destination && destination->bank == RegisterBank::xmm && destination->width == 128;
        const bool source_ok = (source && source->bank == RegisterBank::xmm && source->width == 128) ||
                               (source_memory && source_memory->data_width == 128);
        if (destination_ok && source_ok) {
            const auto value_type = vector_type(128, TypeKind::integer, 8, 16);
            Intrinsic effect{"x86_pshufb_i8x16",
                {retag_expr(operands[0], value_type), retag_expr(operands[1], value_type)},
                source_memory ? IntrinsicMemoryEffect::read : IntrinsicMemoryEffect::none};
            effect.register_writes = instruction.register_writes;
            effect.result_type = value_type;
            return effect;
        }
    }

    if (x86 && (instruction.opcode == Opcode::cmpps || instruction.opcode == Opcode::cmppd ||
                instruction.opcode == Opcode::cmpss || instruction.opcode == Opcode::cmpsd) &&
        instruction.operands.size() == 3) {
        const bool scalar = instruction.opcode == Opcode::cmpss || instruction.opcode == Opcode::cmpsd;
        const auto lane_bits = static_cast<std::uint16_t>(instruction.opcode == Opcode::cmppd ||
                                                           instruction.opcode == Opcode::cmpsd ? 64 : 32);
        const auto *destination = std::get_if<RegisterOperand>(&instruction.operands[0]);
        const auto *source_register = std::get_if<RegisterOperand>(&instruction.operands[1]);
        const auto *memory = std::get_if<MemoryOperand>(&instruction.operands[1]);
        const auto *predicate = std::get_if<ImmediateOperand>(&instruction.operands[2]);
        const auto memory_width = scalar ? lane_bits : std::uint16_t{128};
        if (destination && destination->bank == RegisterBank::xmm && destination->width == 128 &&
            !destination->high_byte &&
            ((source_register && source_register->bank == RegisterBank::xmm && source_register->width == 128 &&
              !source_register->high_byte) || (memory && memory->data_width == memory_width)) &&
            predicate && predicate->encoded_width == 8 && predicate->effective_width == 8 &&
            !predicate->is_signed && predicate->value < 8 &&
            (!instruction.vector_element_bits || instruction.vector_element_bits == lane_bits)) {
            const auto input_type = vector_type(128, TypeKind::floating, lane_bits,
                static_cast<std::uint8_t>(128 / lane_bits));
            const auto result_type = vector_type(128, TypeKind::integer, lane_bits,
                static_cast<std::uint8_t>(128 / lane_bits));
            std::vector<ExpressionPtr> inputs{
                retag_expr(operands[0], input_type),
                scalar && memory ? retag_expr(operands[1], floating_type(lane_bits))
                                 : retag_expr(operands[1], input_type),
                retag_expr(operands[2], integer_type(8)),
                reg_expr({RegisterBank::mxcsr, 0, 32, false})};
            Intrinsic effect{"x86_" + operation_name(instruction.opcode) + "_f" +
                std::to_string(lane_bits) + (scalar ? "_scalar" : "x" +
                    std::to_string(128 / lane_bits)) + "_predicate" +
                std::to_string(predicate->value) + "_mxcsr_control_status", std::move(inputs),
                memory ? IntrinsicMemoryEffect::read : IntrinsicMemoryEffect::none};
            effect.register_writes = instruction.register_writes;
            effect.result_type = result_type;
            const bool has_mxcsr_write = std::any_of(effect.register_writes.begin(), effect.register_writes.end(),
                [](RegisterOperand reg) { return reg.bank == RegisterBank::mxcsr; });
            if (has_mxcsr_write && std::find(effect.register_writes.begin(), effect.register_writes.end(),
                    *destination) != effect.register_writes.end()) {
                const auto compare_inputs = std::make_shared<Expression>(Expression{
                    vector_type(128, TypeKind::integer, 8, 16),
                    BinaryValue{"x86_sse_compare_ie_de_inputs_predicate" + std::to_string(predicate->value),
                        retag_expr(operands[0], input_type),
                        scalar && memory ? retag_expr(operands[1], floating_type(lane_bits))
                                         : retag_expr(operands[1], input_type)}});
                for (const auto written : effect.register_writes) {
                    if (written == *destination)
                        effect.register_output_values.push_back(std::make_shared<Expression>(Expression{
                            result_type, UnaryValue{"x86_sse_compare_result", compare_inputs}}));
                    else if (written.bank == RegisterBank::mxcsr)
                        effect.register_output_values.push_back(std::make_shared<Expression>(Expression{
                            integer_type(32), BinaryValue{"x86_mxcsr_after_sse_compare_sticky_ie_de",
                                reg_expr(written), compare_inputs}}));
                    else {
                        effect.register_output_values.clear();
                        break;
                    }
                }
            }
            return effect;
        }
    }

    const auto packed_lane_bits = [](Opcode opcode) -> std::uint16_t {
        switch (opcode) {
        case Opcode::paddb: case Opcode::psubb: case Opcode::paddsb: case Opcode::paddusb:
        case Opcode::psubsb: case Opcode::psubusb: case Opcode::pcmpeqb: case Opcode::pcmpgtb:
        case Opcode::pminub: case Opcode::pmaxub: case Opcode::pavgb: case Opcode::pshufb:
        case Opcode::pabsb: return 8;
        case Opcode::paddw: case Opcode::psubw: case Opcode::paddsw: case Opcode::paddusw:
        case Opcode::psubsw: case Opcode::psubusw: case Opcode::pcmpeqw: case Opcode::pcmpgtw:
        case Opcode::psllw: case Opcode::psrlw: case Opcode::psraw: case Opcode::pmullw:
        case Opcode::pmulhw: case Opcode::pmulhuw: case Opcode::pminsw: case Opcode::pmaxsw: case Opcode::pavgw:
        case Opcode::phaddw: case Opcode::phaddsw: case Opcode::phsubw: case Opcode::phsubsw:
        case Opcode::pabsw: return 16;
        case Opcode::paddd: case Opcode::psubd: case Opcode::pcmpeqd: case Opcode::pcmpgtd:
        case Opcode::pslld: case Opcode::psrld: case Opcode::psrad: case Opcode::pmaddwd:
        case Opcode::phaddd: case Opcode::phsubd: case Opcode::pabsd: return 32;
        case Opcode::paddq: case Opcode::psubq: case Opcode::psllq: case Opcode::psrlq: case Opcode::psadbw:
        case Opcode::pcmpgtq:
        case Opcode::pmuludq: return 64;
        default: return 0;
        }
    };
    const auto packed_integer_opcode = [](Opcode opcode) {
        switch (opcode) {
        case Opcode::paddb: case Opcode::paddw: case Opcode::paddd: case Opcode::paddq:
        case Opcode::psubb: case Opcode::psubw: case Opcode::psubd: case Opcode::psubq:
        case Opcode::paddsb: case Opcode::paddsw: case Opcode::paddusb: case Opcode::paddusw:
        case Opcode::psubsb: case Opcode::psubsw: case Opcode::psubusb: case Opcode::psubusw:
        case Opcode::pand: case Opcode::pandn: case Opcode::por: case Opcode::pxor:
        case Opcode::psllw: case Opcode::pslld: case Opcode::psllq: case Opcode::psrlw: case Opcode::psrld:
        case Opcode::psrlq: case Opcode::psraw: case Opcode::psrad:
        case Opcode::pcmpeqb: case Opcode::pcmpeqw: case Opcode::pcmpeqd:
        case Opcode::pcmpgtb: case Opcode::pcmpgtw: case Opcode::pcmpgtd: case Opcode::pcmpgtq:
        case Opcode::pmullw: case Opcode::pmulhw: case Opcode::pmulhuw: case Opcode::pmuludq:
        case Opcode::pmaddwd: case Opcode::pminub: case Opcode::pmaxub: case Opcode::pminsw:
        case Opcode::pmaxsw: case Opcode::pavgb: case Opcode::pavgw: case Opcode::psadbw: case Opcode::phaddw: case Opcode::phaddd: case Opcode::phaddsw:
        case Opcode::phsubw: case Opcode::phsubd: case Opcode::phsubsw: case Opcode::pshufb:
        case Opcode::pabsb: case Opcode::pabsw: case Opcode::pabsd:
        case Opcode::pslldq: case Opcode::psrldq: return true;
        default: return false;
        }
    };
    const bool x86_sse2_integer = packed_integer_opcode(instruction.opcode);
    const auto vector_shape = [&](Opcode opcode) -> ValueType {
        switch (opcode) {
        case Opcode::pand: case Opcode::pandn: case Opcode::por: case Opcode::pxor:
            return vector_type(128, TypeKind::integer, 128, 1);
        default: {
            const auto lane_bits = packed_lane_bits(opcode);
            return lane_bits ? vector_type(128, TypeKind::integer, lane_bits,
                    static_cast<std::uint8_t>(128 / lane_bits)) : vector_type(128);
        }
        }
    };
    const bool x86_vector_move = instruction.opcode == Opcode::movdqa || instruction.opcode == Opcode::movdqu;
    const bool x86_scalar_move = instruction.opcode == Opcode::movss || instruction.opcode == Opcode::movsd;
    const bool x86_scalar_arithmetic = instruction.opcode == Opcode::addss || instruction.opcode == Opcode::addsd ||
        instruction.opcode == Opcode::subss || instruction.opcode == Opcode::subsd ||
        instruction.opcode == Opcode::mulss || instruction.opcode == Opcode::mulsd ||
        instruction.opcode == Opcode::divss || instruction.opcode == Opcode::divsd;
    const bool x86_simd = x86_sse2_integer || x86_vector_move || x86_scalar_move || x86_scalar_arithmetic;
    if (x86 && x86_simd && instruction.operands.size() == 2) {
        const auto destination = as_register(instruction.operands[0]);
        const auto source = as_register(instruction.operands[1]);
        const auto *source_memory = std::get_if<MemoryOperand>(&instruction.operands[1]);
        const auto *destination_memory = std::get_if<MemoryOperand>(&instruction.operands[0]);
        const bool scalar = x86_scalar_move || x86_scalar_arithmetic;
        const std::uint16_t scalar_bits = instruction.opcode == Opcode::movsd || instruction.opcode == Opcode::addsd ||
            instruction.opcode == Opcode::subsd || instruction.opcode == Opcode::mulsd ||
            instruction.opcode == Opcode::divsd ? 64 : 32;
        const bool destination_ok = destination_memory ?
            (scalar ? destination_memory->data_width == scalar_bits : destination_memory->data_width == 128) :
            (destination && destination->bank == RegisterBank::xmm && destination->width == 128);
        const bool source_ok = source_memory ?
            (scalar ? source_memory->data_width == scalar_bits : source_memory->data_width == 128) :
            (source && source->bank == RegisterBank::xmm && source->width == 128);
        const bool immediate_packed_shift = instruction.opcode == Opcode::psllw || instruction.opcode == Opcode::pslld ||
            instruction.opcode == Opcode::psllq || instruction.opcode == Opcode::psrlw || instruction.opcode == Opcode::psrld ||
            instruction.opcode == Opcode::psrlq || instruction.opcode == Opcode::psraw || instruction.opcode == Opcode::psrad ||
            instruction.opcode == Opcode::pslldq || instruction.opcode == Opcode::psrldq;
        const auto *packed_shift_count = std::get_if<ImmediateOperand>(&instruction.operands[1]);
        const bool immediate_shift_ok = immediate_packed_shift && packed_shift_count &&
            packed_shift_count->encoded_width == 8 && packed_shift_count->effective_width == 8 && !packed_shift_count->is_signed;
        const bool packed_source_ok = immediate_shift_ok || source_ok;
        if (destination_ok && packed_source_ok) {
            ValueType result_type = vector_shape(instruction.opcode);
            const bool signed_saturating = instruction.opcode == Opcode::paddsb || instruction.opcode == Opcode::paddsw ||
                instruction.opcode == Opcode::psubsb || instruction.opcode == Opcode::psubsw ||
                instruction.opcode == Opcode::phaddsw || instruction.opcode == Opcode::phsubsw;
            const bool signed_result = signed_saturating ||
                instruction.opcode == Opcode::pmulhw || instruction.opcode == Opcode::pmaddwd ||
                instruction.opcode == Opcode::pminsw || instruction.opcode == Opcode::pmaxsw ||
                instruction.opcode == Opcode::phaddw || instruction.opcode == Opcode::phaddd ||
                instruction.opcode == Opcode::phaddsw || instruction.opcode == Opcode::phsubw ||
                instruction.opcode == Opcode::phsubd || instruction.opcode == Opcode::phsubsw;
            if (signed_result) result_type.is_signed = true;
            std::string suffix;
            if (scalar) {
                result_type = vector_type(128, TypeKind::floating, scalar_bits,
                                          static_cast<std::uint8_t>(128 / scalar_bits));
                suffix = scalar_bits == 32 ? "_f32" : "_f64";
            } else if (x86_vector_move) {
                result_type = vector_type(128);
                suffix = "_bits128";
            } else {
                const auto shape = result_type;
                suffix = shape.element_bits == 128 ? "_bits128" :
                    "_i" + std::to_string(shape.element_bits) + "x" + std::to_string(shape.lanes);
            }

            std::vector<ExpressionPtr> typed_operands;
            const bool signed_lanes = signed_saturating || instruction.opcode == Opcode::pcmpgtb ||
                instruction.opcode == Opcode::pcmpgtw || instruction.opcode == Opcode::pcmpgtd ||
                instruction.opcode == Opcode::pcmpgtq ||
                instruction.opcode == Opcode::pmulhw || instruction.opcode == Opcode::pmaddwd ||
                instruction.opcode == Opcode::pminsw || instruction.opcode == Opcode::pmaxsw ||
                instruction.opcode == Opcode::phaddw || instruction.opcode == Opcode::phaddd ||
                instruction.opcode == Opcode::phaddsw || instruction.opcode == Opcode::phsubw ||
                instruction.opcode == Opcode::phsubd || instruction.opcode == Opcode::phsubsw;
            ValueType operand_type = signed_lanes
                ? vector_type(128, TypeKind::integer, result_type.element_bits, result_type.lanes, true)
                : result_type;
            if (instruction.opcode == Opcode::pmaddwd)
                operand_type = vector_type(128, TypeKind::integer, 16, 8, true);
            else if (instruction.opcode == Opcode::pmuludq)
                operand_type = vector_type(128, TypeKind::integer, 32, 4, false);
            const bool signed_absolute = instruction.opcode == Opcode::pabsb ||
                instruction.opcode == Opcode::pabsw || instruction.opcode == Opcode::pabsd;
            if (signed_absolute && destination && !destination_memory && source_ok &&
                !x86_writes_flags(instruction)) {
                const auto input_type = vector_type(128, TypeKind::integer, result_type.element_bits,
                    result_type.lanes, true);
                auto input = retag_expr(operands[1], input_type);
                auto output = std::make_shared<Expression>(Expression{input_type,
                    UnaryValue{"abs_signed_i" + std::to_string(result_type.element_bits) + "x" +
                        std::to_string(result_type.lanes) + "_mod", input}});
                Intrinsic effect{"x86_" + operation_name(instruction.opcode) + "_i" +
                    std::to_string(result_type.element_bits) + "x" + std::to_string(result_type.lanes),
                    {input}, source_memory ? IntrinsicMemoryEffect::read : IntrinsicMemoryEffect::none};
                effect.register_writes = instruction.register_writes;
                effect.result_type = input_type;
                for (const auto written : effect.register_writes) {
                    if (written == *destination) effect.register_output_values.push_back(output);
                    else return Intrinsic{"x86_" + operation_name(instruction.opcode) +
                        "_unmodeled_output", {input}, IntrinsicMemoryEffect::unknown};
                }
                if (effect.register_output_values.size() == effect.register_writes.size()) return effect;
            }
            if (x86_scalar_arithmetic && destination) {
                typed_operands.push_back(retag_expr(reg_expr(*destination), result_type));
                const auto scalar_type = floating_type(scalar_bits);
                auto source_value = source_memory ? operand_expr(instruction.operands[1]) : reg_expr(*source);
                if (source) source_value = std::make_shared<Expression>(Expression{scalar_type,
                    UnaryValue{scalar_bits == 32 ? "x86_low_f32" : "x86_low_f64", source_value}});
                else source_value = retag_expr(source_value, scalar_type);
                typed_operands.push_back(std::move(source_value));
            } else if (x86_scalar_move && destination && source_memory) {
                typed_operands.push_back(retag_expr(operand_expr(instruction.operands[1]), floating_type(scalar_bits)));
            } else if (x86_scalar_move && destination && source) {
                typed_operands.push_back(retag_expr(reg_expr(*destination), result_type));
                typed_operands.push_back(std::make_shared<Expression>(Expression{floating_type(scalar_bits),
                    UnaryValue{scalar_bits == 32 ? "x86_low_f32" : "x86_low_f64", reg_expr(*source)}}));
            } else if (x86_scalar_move && destination_memory && source) {
                typed_operands.push_back(std::make_shared<Expression>(Expression{floating_type(scalar_bits),
                    UnaryValue{scalar_bits == 32 ? "x86_low_f32" : "x86_low_f64", reg_expr(*source)}}));
            } else if (immediate_shift_ok) {
                typed_operands.push_back(retag_expr(operands[0], operand_type));
                typed_operands.push_back(retag_expr(operands[1], integer_type(8)));
            } else {
                for (const auto &operand : operands)
                    typed_operands.push_back(retag_expr(operand, operand_type));
            }
            if (x86_scalar_arithmetic)
                typed_operands.push_back(reg_expr(RegisterOperand{RegisterBank::mxcsr, 0, 32, false}));

            Intrinsic effect{"x86_" + operation_name(instruction.opcode) + suffix,
                             std::move(typed_operands),
                             destination_memory ? IntrinsicMemoryEffect::write :
                             source_memory ? IntrinsicMemoryEffect::read : IntrinsicMemoryEffect::none};
            effect.register_writes = instruction.register_writes;
            if (destination && !x86_scalar_move) effect.result_type = result_type;
            else if (destination && x86_scalar_move) effect.result_type = result_type;
            if (x86_scalar_arithmetic && destination) {
                const auto scalar_type = floating_type(scalar_bits);
                const auto old_destination = retag_expr(reg_expr(*destination), result_type);
                const auto source_value = effect.operands.size() >= 2 ? effect.operands[1] : ExpressionPtr{};
                if (source_value) {
                    const auto rounded = std::make_shared<Expression>(Expression{scalar_type,
                        BinaryValue{"x86_" + operation_name(instruction.opcode) +
                            "_rounded_scalar_fp_using_mxcsr_rounding", source_value,
                            reg_expr({RegisterBank::mxcsr, 0, 32, false})}});
                    const auto output = std::make_shared<Expression>(Expression{result_type,
                        BinaryValue{"x86_" + operation_name(instruction.opcode) +
                            "_scalar_result_preserve_upper_xmm_lanes", old_destination, rounded}});
                    const auto old_mxcsr = reg_expr({RegisterBank::mxcsr, 0, 32, false});
                    const auto exceptions = std::make_shared<Expression>(Expression{integer_type(32),
                        BinaryValue{"x86_" + operation_name(instruction.opcode) +
                            "_scalar_fp_exception_flags_ie_de_ze_oe_ue_pe_with_mxcsr_masks", rounded, old_mxcsr}});
                    const auto next_mxcsr = std::make_shared<Expression>(Expression{integer_type(32),
                        BinaryValue{"x86_mxcsr_after_sse_scalar_arithmetic_sticky_status_ie_de_ze_oe_ue_pe",
                            old_mxcsr, exceptions}});
                    for (const auto written : effect.register_writes) {
                        if (written == *destination) effect.register_output_values.push_back(output);
                        else if (written.bank == RegisterBank::mxcsr) effect.register_output_values.push_back(next_mxcsr);
                        else { effect.register_output_values.clear(); break; }
                    }
                    if (effect.register_output_values.size() != effect.register_writes.size())
                        effect.register_output_values.clear();
                }
            }
            return effect;
        }
    }
    const bool x86_shift_rotate = instruction.opcode == Opcode::rol || instruction.opcode == Opcode::ror ||
        instruction.opcode == Opcode::rcl || instruction.opcode == Opcode::rcr ||
        instruction.opcode == Opcode::shl || instruction.opcode == Opcode::shr || instruction.opcode == Opcode::sar;
    const bool x86_bmi1 = instruction.opcode == Opcode::andn || instruction.opcode == Opcode::bextr ||
        instruction.opcode == Opcode::blsi || instruction.opcode == Opcode::blsmsk ||
        instruction.opcode == Opcode::blsr;
    const bool x86_bmi = x86_bmi1 || instruction.opcode == Opcode::bzhi || instruction.opcode == Opcode::mulx ||
        instruction.opcode == Opcode::pdep || instruction.opcode == Opcode::pext ||
        instruction.opcode == Opcode::rorx || instruction.opcode == Opcode::sarx ||
        instruction.opcode == Opcode::shlx || instruction.opcode == Opcode::shrx;
    if (x86 && (instruction.opcode == Opcode::cmpxchg8b || instruction.opcode == Opcode::cmpxchg16b) &&
        instruction.operands.size() == 1 && is_memory(instruction.operands.front())) {
        auto intrinsic_operands = operands;
        const auto pair_width = instruction.opcode == Opcode::cmpxchg16b ? 64 : 32;
        for (const std::uint8_t index : {std::uint8_t{0}, std::uint8_t{2}, std::uint8_t{3}, std::uint8_t{1}})
            intrinsic_operands.push_back(reg_expr(RegisterOperand{RegisterBank::gpr, index,
                static_cast<std::uint16_t>(pair_width), false}));
        Intrinsic effect{"x86_" + operation_name(instruction.opcode), std::move(intrinsic_operands),
                         IntrinsicMemoryEffect::unknown};
        effect.register_writes = instruction.register_writes;
        return effect;
    }
    if (x86 && x86_bmi && !operands.empty()) {
        // Preserve the architecture-specific bit operation and its precise register effects
        // as an intrinsic until the C-like expression model grows these operations.
        auto intrinsic_operands = operands;
        // BMI1 destinations are pure outputs. Keeping the printed destination
        // among intrinsic inputs would invent an incoming SSA dependency.
        if (x86_bmi1)
            intrinsic_operands.erase(intrinsic_operands.begin());
        if (instruction.opcode == Opcode::mulx) {
            const auto implicit_rdx = std::find_if(instruction.register_reads.begin(), instruction.register_reads.end(),
                [](RegisterOperand reg) { return reg.bank == RegisterBank::gpr && reg.index == 2; });
            if (implicit_rdx != instruction.register_reads.end())
                intrinsic_operands.push_back(reg_expr(*implicit_rdx));
        }
        Intrinsic effect{"x86_" + operation_name(instruction.opcode), std::move(intrinsic_operands),
            std::any_of(instruction.operands.begin(), instruction.operands.end(),
                [](const Operand &operand) { return is_memory(operand); })
                ? IntrinsicMemoryEffect::read : IntrinsicMemoryEffect::none};
        effect.register_writes = instruction.register_writes;
        if (instruction.opcode != Opcode::mulx) {
            if (const auto destination = as_register(instruction.operands.front()))
                effect.result_type = integer_type(destination->width);
        }
        return effect;
    }
    if (x86 && x86_shift_rotate && instruction.operands.size() == 2) {
        // Keep x86 count masking, rotate-through-carry, zero-count flag
        // preservation, and width-dependent undefined flags explicit. The
        // generic C-like shift operators cannot represent all of those effects.
        const auto destination = as_register(instruction.operands[0]);
        const auto *destination_memory = std::get_if<MemoryOperand>(&instruction.operands[0]);
        const auto count = std::get_if<ImmediateOperand>(&instruction.operands[1]);
        const auto source_register = as_register(instruction.operands[1]);
        if ((destination && destination->bank == RegisterBank::gpr) ||
            (destination_memory && destination_memory->data_width != 0)) {
            std::vector<ExpressionPtr> typed_operands;
            const auto destination_type = integer_type(destination ? destination->width : destination_memory->data_width);
            typed_operands.push_back(retag_expr(operands[0], destination_type));
            if (count) typed_operands.push_back(retag_expr(operands[1], integer_type(8)));
            else if (source_register) typed_operands.push_back(retag_expr(operands[1], integer_type(8)));
            if (instruction.opcode == Opcode::rcl || instruction.opcode == Opcode::rcr) {
                const auto carry = std::find_if(instruction.register_reads.begin(), instruction.register_reads.end(),
                    [](RegisterOperand reg) { return reg.bank == RegisterBank::flags; });
                if (carry != instruction.register_reads.end()) {
                    typed_operands.push_back(std::make_shared<Expression>(Expression{
                        ValueType{TypeKind::boolean, 1, false}, UnaryValue{"carry_flag", reg_expr(*carry)}}));
                }
            }
            if (typed_operands.size() == 2) {
                Intrinsic effect{"x86_" + operation_name(instruction.opcode), std::move(typed_operands),
                    destination_memory ? IntrinsicMemoryEffect::unknown : IntrinsicMemoryEffect::none};
                effect.register_writes = instruction.register_writes;
                if (destination) effect.result_type = destination_type;
                return effect;
            }
        }
    }
    const bool x86_register_bit_test = instruction.opcode == Opcode::bt || instruction.opcode == Opcode::bts ||
        instruction.opcode == Opcode::btr || instruction.opcode == Opcode::btc;
    if (x86 && x86_register_bit_test && instruction.operands.size() == 2 &&
        instruction.access.size() == 2 && !is_memory(instruction.operands[0]) &&
        !is_memory(instruction.operands[1]) && !instruction.memory_read && !instruction.memory_write &&
        !instruction.lock_prefix && instruction.flow == FlowKind::fallthrough) {
        const auto destination = as_register(instruction.operands[0]);
        const auto *index_register = std::get_if<RegisterOperand>(&instruction.operands[1]);
        const auto *index_immediate = std::get_if<ImmediateOperand>(&instruction.operands[1]);
        const bool modifies = instruction.opcode != Opcode::bt;
        const auto flags_read = std::find_if(instruction.register_reads.begin(), instruction.register_reads.end(),
            [](RegisterOperand reg) { return reg.bank == RegisterBank::flags; });
        const auto flags_write = std::find_if(instruction.register_writes.begin(), instruction.register_writes.end(),
            [](RegisterOperand reg) { return reg.bank == RegisterBank::flags; });
        if (destination && destination->bank == RegisterBank::gpr &&
            (destination->width == 16 || destination->width == 32 || destination->width == 64) &&
            instruction.access[0] == (modifies ? OperandAccess::read_write : OperandAccess::read) &&
            instruction.access[1] == OperandAccess::read &&
            ((index_register && index_register->bank == RegisterBank::gpr &&
              index_register->width == destination->width) ||
             (index_immediate && index_immediate->effective_width == 8 &&
              index_immediate->encoded_width == 8 && !index_immediate->is_signed)) &&
            flags_read != instruction.register_reads.end() && flags_write != instruction.register_writes.end() &&
            (flags_write->width == 16 || flags_write->width == 32 || flags_write->width == 64)) {
            const auto width = destination->width;
            const auto index_mask = static_cast<std::uint64_t>(width - 1);
            ExpressionPtr bit_index = index_immediate
                ? constant_expr(index_immediate->value & index_mask, width)
                : std::make_shared<Expression>(Expression{integer_type(width), BinaryValue{"and",
                    retag_expr(operands[1], integer_type(width)), constant_expr(index_mask, width)}});
            const auto value = retag_expr(operands[0], integer_type(width));
            auto tested = boolean_binary("bit_extract", value, bit_index);
            const auto bit_value = std::make_shared<Expression>(Expression{integer_type(width),
                UnaryValue{"zext", tested}});
            const auto bit_mask = std::make_shared<Expression>(Expression{integer_type(width),
                BinaryValue{"shl", constant_expr(1, width), bit_index}});
            ExpressionPtr updated_value = value;
            if (instruction.opcode == Opcode::bts)
                updated_value = std::make_shared<Expression>(Expression{integer_type(width),
                    BinaryValue{"or", value, bit_mask}});
            else if (instruction.opcode == Opcode::btr)
                updated_value = std::make_shared<Expression>(Expression{integer_type(width),
                    BinaryValue{"and", value, std::make_shared<Expression>(Expression{integer_type(width),
                        UnaryValue{"not", bit_mask}})}});
            else if (instruction.opcode == Opcode::btc)
                updated_value = std::make_shared<Expression>(Expression{integer_type(width),
                    BinaryValue{"xor", value, bit_mask}});

            constexpr std::uint64_t arithmetic_flags = (UINT64_C(1) << 0) | (UINT64_C(1) << 2) |
                (UINT64_C(1) << 4) | (UINT64_C(1) << 6) | (UINT64_C(1) << 7) | (UINT64_C(1) << 11);
            constexpr std::uint64_t carry_flag = UINT64_C(1) << 0;
            const auto flags_width = flags_write->width;
            auto updated_flags = std::make_shared<Expression>(Expression{integer_type(flags_width),
                BinaryValue{"and", reg_expr(*flags_read),
                    constant_expr(~arithmetic_flags, flags_width)}});
            auto undefined = std::make_shared<Expression>(Expression{integer_type(flags_width),
                BinaryValue{"and", unknown_expr("x86_" + operation_name(instruction.opcode) +
                    "_undefined_flags", flags_width), constant_expr(arithmetic_flags & ~carry_flag, flags_width)}});
            updated_flags = std::make_shared<Expression>(Expression{integer_type(flags_width),
                BinaryValue{"or", updated_flags, undefined}});
            auto carry = std::make_shared<Expression>(Expression{integer_type(flags_width),
                UnaryValue{"zext", tested}});
            updated_flags = std::make_shared<Expression>(Expression{integer_type(flags_width),
                BinaryValue{"or", updated_flags, carry}});

            std::vector<ExpressionPtr> inputs{value, bit_index};
            Intrinsic effect{"x86_" + operation_name(instruction.opcode) + "_i" + std::to_string(width),
                std::move(inputs), IntrinsicMemoryEffect::none};
            effect.register_writes = instruction.register_writes;
            if (modifies) effect.result_type = integer_type(width);
            for (const auto written : effect.register_writes) {
                if (modifies && written == *destination) effect.register_output_values.push_back(updated_value);
                else if (written == *flags_write) effect.register_output_values.push_back(updated_flags);
                else return Intrinsic{"x86_" + operation_name(instruction.opcode) +
                    "_unmodeled_output", {value, bit_index}, IntrinsicMemoryEffect::unknown};
            }
            if (effect.register_output_values.size() == effect.register_writes.size()) return effect;
        }
    }
    const bool x86_bit_operation = instruction.opcode == Opcode::bt || instruction.opcode == Opcode::bts ||
        instruction.opcode == Opcode::btr || instruction.opcode == Opcode::btc ||
        instruction.opcode == Opcode::bsf || instruction.opcode == Opcode::bsr ||
        instruction.opcode == Opcode::tzcnt || instruction.opcode == Opcode::lzcnt;
    if (x86 && x86_bit_operation && instruction.operands.size() == 2) {
        const bool scan = instruction.opcode == Opcode::bsf || instruction.opcode == Opcode::bsr ||
                          instruction.opcode == Opcode::tzcnt || instruction.opcode == Opcode::lzcnt;
        const bool modifies_memory = !scan && instruction.opcode != Opcode::bt &&
                                     is_memory(instruction.operands[0]);
        Intrinsic effect{"x86_" + operation_name(instruction.opcode), operands,
                         is_memory(instruction.operands[scan ? 1 : 0])
                             ? (modifies_memory ? IntrinsicMemoryEffect::unknown : IntrinsicMemoryEffect::read)
                             : IntrinsicMemoryEffect::none};
        effect.register_writes = instruction.register_writes;
        return effect;
    }
    if (x86 && (instruction.opcode == Opcode::shld || instruction.opcode == Opcode::shrd) &&
        instruction.operands.size() == 3) {
        const bool destination_memory = is_memory(instruction.operands[0]);
        Intrinsic effect{"x86_" + operation_name(instruction.opcode), operands,
                         destination_memory ? IntrinsicMemoryEffect::unknown : IntrinsicMemoryEffect::none};
        effect.register_writes = instruction.register_writes;
        if (!destination_memory) {
            if (const auto destination = as_register(instruction.operands[0])) {
                effect.result_type = integer_type(destination->width);
                const auto *count = std::get_if<ImmediateOperand>(&instruction.operands[2]);
                const auto *source_register = std::get_if<RegisterOperand>(&instruction.operands[1]);
                const auto width = destination->width;
                if (destination->bank == RegisterBank::gpr && count &&
                    (width == 16 || width == 32 || width == 64) &&
                    count->effective_width == 8 && source_register &&
                    source_register->bank == RegisterBank::gpr && source_register->width == width) {
                    const unsigned count_mask = width == 64 ? 0x3fU : 0x1fU;
                    const unsigned amount = static_cast<unsigned>(count->value) & count_mask;
                    if (amount <= width) {
                        auto value = amount == 0 ? retag_expr(operands[0], integer_type(width))
                                                 : amount == width
                            ? retag_expr(operands[1], integer_type(width))
                            : [&] {
                                const auto fixed_shift = [width](std::string operation,
                                                                ExpressionPtr source,
                                                                unsigned shift) {
                                    return std::make_shared<Expression>(Expression{
                                        integer_type(width), BinaryValue{std::move(operation), std::move(source),
                                            constant_expr(shift, width)}});
                                };
                                auto destination_part = fixed_shift(
                                    instruction.opcode == Opcode::shld ? "shl" : "shr",
                                    retag_expr(operands[0], integer_type(width)), amount);
                                auto source_part = fixed_shift(
                                    instruction.opcode == Opcode::shld ? "shr" : "shl",
                                    retag_expr(operands[1], integer_type(width)), width - amount);
                                return std::make_shared<Expression>(Expression{
                                    integer_type(width), BinaryValue{"or", std::move(destination_part),
                                        std::move(source_part)}});
                            }();
                        effect.register_output_values.reserve(effect.register_writes.size());
                        for (const auto written : effect.register_writes) {
                            if (written == *destination) {
                                effect.register_output_values.push_back(value);
                            } else if (written.bank == RegisterBank::flags && amount == 0) {
                                const auto incoming_flags = std::find_if(instruction.register_reads.begin(),
                                    instruction.register_reads.end(), [](RegisterOperand reg) {
                                        return reg.bank == RegisterBank::flags;
                                    });
                                effect.register_output_values.push_back(incoming_flags == instruction.register_reads.end()
                                    ? unknown_expr("x86_flags_after_zero_count_double_shift", written.width)
                                    : reg_expr(*incoming_flags));
                            } else {
                                effect.register_output_values.push_back(
                                    unknown_expr("x86_flags_after_double_shift", written.width));
                            }
                        }
                    }
                }
            }
        }
        return effect;
    }
    if (x86 && instruction.operands.size() == 2 &&
        (instruction.opcode == Opcode::adc || instruction.opcode == Opcode::sbb)) {
        RegisterOperand flags{RegisterBank::flags, 0,
            instruction.context.architecture == Architecture::x86_64 ? std::uint16_t{64} : std::uint16_t{32}, false};
        const auto read_flags = std::find_if(instruction.register_reads.begin(), instruction.register_reads.end(),
            [](RegisterOperand reg) { return reg.bank == RegisterBank::flags; });
        if (read_flags != instruction.register_reads.end()) flags = *read_flags;
        const auto written_flags = std::find_if(instruction.register_writes.begin(), instruction.register_writes.end(),
            [](RegisterOperand reg) { return reg.bank == RegisterBank::flags; });
        if (written_flags != instruction.register_writes.end()) flags = *written_flags;

        std::vector<RegisterOperand> writes;
        if (const auto destination = as_register(instruction.operands.front())) writes.push_back(*destination);
        writes.push_back(flags);

        auto carry = std::make_shared<Expression>(Expression{
            ValueType{TypeKind::boolean, 1, false}, UnaryValue{"carry_flag", reg_expr(flags)}});
        Intrinsic effect{instruction.opcode == Opcode::adc ? "adc" : "sbb",
                         {operands[0], operands[1], std::move(carry)},
                         is_memory(instruction.operands.front()) ? IntrinsicMemoryEffect::unknown
                                                                 : IntrinsicMemoryEffect::none};
        effect.register_writes = std::move(writes);
        return effect;
    }
    if (x86 && instruction.operands.size() == 2 && is_memory(instruction.operands[0])) {
        const auto operation = operation_name(instruction.opcode);
        const bool read_modify_write = instruction.opcode == Opcode::add || instruction.opcode == Opcode::sub ||
            instruction.opcode == Opcode::bit_and || instruction.opcode == Opcode::bit_or ||
            instruction.opcode == Opcode::bit_xor || instruction.opcode == Opcode::shl ||
            instruction.opcode == Opcode::shr || instruction.opcode == Opcode::sar;
        if (read_modify_write && operation.rfind("opcode_", 0) != 0) {
            const auto left = operands[0];
            const auto right = operands[1];
            auto value = std::make_shared<Expression>(Expression{
                integer_type(left->type.bits), BinaryValue{operation, left, right}});
            return Store{left, std::move(value)};
        }
    }

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
            if (is_load(instruction.opcode) && is_memory(instruction.operands[1])) {
                auto value = operands[1];
                if (instruction.opcode == Opcode::a64_ldrsw && destination.width == 64) {
                    value = std::make_shared<Expression>(Expression{integer_type(64),
                        UnaryValue{"sext", std::move(value)}});
                } else if (const auto *memory = std::get_if<ArmMemoryOperand>(&instruction.operands[1]);
                           memory && memory->data_width < destination.width)
                    value = std::make_shared<Expression>(Expression{integer_type(destination.width),
                        UnaryValue{memory->sign_extend ? "sext" : "zext", value}});
                if (arm32 && instruction.arm && instruction.arm->predicate == ArmPredicate::condition &&
                    instruction.condition < 14) {
                    auto predicate = arm32_condition_expr(instruction.condition, reg_expr({RegisterBank::arm_flags, 0, 4, false}));
                    value = std::make_shared<Expression>(Expression{integer_type(destination.width),
                        BinaryValue{"arm_guard", predicate, std::make_shared<Expression>(Expression{integer_type(destination.width),
                            BinaryValue{"arm_select", value, reg_expr(destination)}})}});
                }
                return Assign{destination, std::move(value)};
            }
        }
        if (operands.size() == 1 && (instruction.opcode == Opcode::inc || instruction.opcode == Opcode::dec)) {
            auto value = std::make_shared<Expression>(Expression{integer_type(destination.width),
                BinaryValue{instruction.opcode == Opcode::inc ? "add" : "sub", reg_expr(destination), constant_expr(1, destination.width)}});
            return Assign{destination, std::move(value)};
        }
    }
    if (instruction.context.architecture == Architecture::arm64 && instruction.context.mode == ExecutionMode::a64 &&
        operands.size() == 2 && is_store(instruction.opcode) && is_memory(instruction.operands[1]))
        return Store{operands[1], operands[0]};
    if (operands.size() == 2 && is_store(instruction.opcode) && is_memory(instruction.operands.front())) {
        if (arm32 && instruction.arm && instruction.arm->predicate == ArmPredicate::condition &&
            instruction.condition < 14) {
            auto predicate = arm32_condition_expr(instruction.condition, reg_expr({RegisterBank::arm_flags, 0, 4, false}));
            Intrinsic effect{"arm_conditional_store", {predicate, operands[0], operands[1]}, IntrinsicMemoryEffect::write};
            return effect;
        }
        return Store{operands[0], operands[1]};
    }
    if (arm32 && operands.size() == 2 && is_store(instruction.opcode) &&
        std::holds_alternative<ArmMemoryOperand>(instruction.operands[1])) {
        if (instruction.arm && instruction.arm->predicate == ArmPredicate::condition && instruction.condition < 14) {
            auto predicate = arm32_condition_expr(instruction.condition, reg_expr({RegisterBank::arm_flags, 0, 4, false}));
            Intrinsic effect{"arm_conditional_store", {predicate, operands[1], operands[0]}, IntrinsicMemoryEffect::write};
            return effect;
        }
        return Store{operands[1], operands[0]};
    }

    diagnostics.push_back("instruction at 0x" + [&] { std::ostringstream s; s << std::hex << instruction.address.offset; return s.str(); }() +
                          " retained as an explicit intrinsic: " + operation_name(instruction.opcode));
    auto name = operation_name(instruction.opcode);
    if (instruction.opcode >= Opcode::rv_lr_w && instruction.opcode <= Opcode::rv_amomaxu_d) {
        if (instruction.atomic_aq && instruction.atomic_rl) name += ".aqrl";
        else if (instruction.atomic_aq) name += ".aq";
        else if (instruction.atomic_rl) name += ".rl";
    }
    return Intrinsic{std::move(name), std::move(operands)};
}

std::string expression_text(const Expression &expression);
std::string binary_symbol(const std::string &operation) {
    if (operation.rfind("rvm_", 0) == 0) return operation.substr(4);
    if (operation == "add") return "+";
    if (operation == "sub") return "-";
    if (operation == "mul") return "*";
    if (operation == "and") return "&";
    if (operation == "or") return "|";
    if (operation == "xor") return "^";
    if (operation == "shl") return "<<";
    if (operation == "shr") return ">>";
    if (operation == "sar") return ">>";
    if (operation == "eq") return "==";
    if (operation == "ne") return "!=";
    if (operation == "bool_or") return "||";
    if (operation == "bool_and") return "&&";
    if (operation == "bool_xor") return "!=";
    if (operation == "ult") return "ULT";
    if (operation == "uge") return "UGE";
    if (operation == "ule") return "ULE";
    if (operation == "ugt") return "UGT";
    if (operation == "slt") return "SLT";
    if (operation == "sge") return "SGE";
    if (operation == "sle") return "SLE";
    if (operation == "sgt") return "SGT";
    return operation;
}
std::string arm_condition_text(unsigned condition, const std::string &flags) {
    const auto n = "arm_flag_n(" + flags + ")";
    const auto z = "arm_flag_z(" + flags + ")";
    const auto c = "arm_flag_c(" + flags + ")";
    const auto v = "arm_flag_v(" + flags + ")";
    switch (condition) {
    case 0: return z;
    case 1: return "!(" + z + ")";
    case 2: return c;
    case 3: return "!(" + c + ")";
    case 4: return n;
    case 5: return "!(" + n + ")";
    case 6: return v;
    case 7: return "!(" + v + ")";
    case 8: return "(" + c + " && !(" + z + "))";
    case 9: return "(!(" + c + ") || " + z + ")";
    case 10: return "(" + n + " == " + v + ")";
    case 11: return "(" + n + " != " + v + ")";
    case 12: return "(!(" + z + ") && " + n + " == " + v + ")";
    case 13: return "(" + z + " || " + n + " != " + v + ")";
    default: return "unknown_arm_condition";
    }
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
            if (memory.index_shift == "rrx") {
                out << "rrx(" << register_name(*memory.index, memory.index_version) << ", carry_flag(flags))";
                has_term = true;
            } else {
            const auto op = memory.index_shift == "lsl" ? "<<" : memory.index_shift == "lsr" || memory.index_shift == "asr"
                              ? ">>" : "ror";
            if (memory.index_shift == "ror") out << "ror(" << register_name(*memory.index, memory.index_version)
                                                    << ", " << unsigned(memory.index_shift_amount) << ')';
            else out << '(' << (memory.index_extend.empty() ? register_name(*memory.index, memory.index_version)
                                                              : memory.index_extend + "(" + register_name(*memory.index, memory.index_version) + ")")
                     << ' ' << op << ' '
                     << unsigned(memory.index_shift_amount) << ')';
            }
        } else {
            if (!memory.index_extend.empty())
                out << memory.index_extend << '(' << register_name(*memory.index, memory.index_version) << ')';
            else
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
std::optional<std::string> typed_member_access(const MemoryValue &memory) {
    if (!memory.base || memory.absolute || memory.displacement < 0 ||
        !memory.type.bits || memory.type.bits % 8) return {};
    const auto *base_type = detail::expression_register_type(*memory.base, memory.base_version);
    if (!base_type || !*base_type) return {};
    auto object = *base_type;
    while (object && object->kind() == types::Kind::qualified) object = object->element();
    if (!object || object->kind() != types::Kind::pointer) return {};
    object = object->element();
    const auto unqualify = [](types::TypePtr type) {
        while (type && type->kind() == types::Kind::qualified) type = type->element();
        return type;
    };
    object = unqualify(std::move(object));
    if (!object || object->kind() != types::Kind::structure || !object->size()) return {};

    const auto access_bytes = static_cast<std::uint64_t>(memory.type.bits / 8);
    const auto address_offset = static_cast<std::uint64_t>(memory.displacement);
    if (memory.index) {
        if (!memory.index_add || !memory.index_shift.empty() || memory.index_shift_amount ||
            !memory.index_extend.empty() || !memory.scale) return {};
    }
    std::optional<std::string> result;
    for (const auto &member : object->members()) {
        if (memory.index) break;
        if (!member.has_fixed_offset() || !member.type || member.name.empty() || address_offset < member.offset)
            continue;
        const auto relative = address_offset - member.offset;
        std::optional<std::string> candidate;
        if (member.type->kind() == types::Kind::array) {
            const auto &element = member.type->element();
            if (!element || !element->size() || !*element->size() || !member.type->count()) continue;
            const auto element_bytes = *element->size();
            if (access_bytes != element_bytes || relative % element_bytes != 0) continue;
            const auto index = relative / element_bytes;
            if (index >= member.type->count()) continue;
            candidate = register_name(*memory.base, memory.base_version) + "->" + member.name +
                        "[" + std::to_string(index) + "]";
        } else {
            if (relative != 0 || !member.type->size() || *member.type->size() != access_bytes) continue;
            candidate = register_name(*memory.base, memory.base_version) + "->" + member.name;
        }
        if (!candidate) continue;
        if (result) return {};
        result = std::move(candidate);
    }
    if (result) return result;

    // A flattened displacement may cross more than one aggregate member, for
    // example base + offsetof(Outer, inner) + offsetof(Inner, field). Resolve
    // that spelling only when every enclosing layout on the path is complete
    // and non-overlapping; ambiguous/union-like layouts keep the raw memory
    // expression below.
    std::vector<std::string> nested_results;
    std::size_t work = 0;
    const auto valid_struct_layout = [&](const types::TypePtr &type) {
        if (!type || type->kind() != types::Kind::structure || !type->size() ||
            *type->size() == 0 || type->members().size() > 4096) return false;
        std::vector<std::pair<std::uint64_t, std::uint64_t>> ranges;
        ranges.reserve(type->members().size());
        for (const auto &field : type->members()) {
            if (!field.has_fixed_offset() || field.bit_width || field.bit_offset || !field.type ||
                !field.type->size() || *field.type->size() == 0 || field.offset > *type->size() ||
                *field.type->size() > *type->size() - field.offset) return false;
            ranges.emplace_back(field.offset, field.offset + *field.type->size());
        }
        std::sort(ranges.begin(), ranges.end());
        for (std::size_t index = 1; index < ranges.size(); ++index)
            if (ranges[index].first < ranges[index - 1].second) return false;
        return true;
    };
    const auto descend = [&](const types::TypePtr &input, std::uint64_t offset,
                             const std::string &path, unsigned depth, bool dynamic_index_used,
                             auto &&self) -> void {
        if (++work > 4096 || depth > 8) return;
        const auto type = unqualify(input);
        if (!type || !type->size() || offset > *type->size() ||
            access_bytes > *type->size() - offset) return;
        if (type->kind() == types::Kind::array) {
            const auto element = unqualify(type->element());
            if (!element || !element->size() || *element->size() == 0 || type->count() == 0 ||
                type->count() > (1u << 20) || type->count() > *type->size() / *element->size() ||
                type->count() * *element->size() != *type->size()) return;
            const auto index = offset / *element->size();
            const auto within = offset % *element->size();
            if (memory.index && !dynamic_index_used) {
                if (offset >= *element->size() || memory.scale != *element->size()) return;
                const auto element_path = path + "[" +
                    register_name(*memory.index, memory.index_version) + "]";
                if (within == 0 && access_bytes == *element->size()) {
                    nested_results.push_back(element_path);
                    return;
                }
                if (element->kind() == types::Kind::structure || element->kind() == types::Kind::array)
                    self(element, within, element_path, depth + 1, true, self);
                return;
            }
            if (index >= type->count()) return;
            const auto element_path = path + "[" + std::to_string(index) + "]";
            if (within == 0 && access_bytes == *element->size()) {
                nested_results.push_back(element_path);
                return;
            }
            if (element->kind() == types::Kind::structure || element->kind() == types::Kind::array)
                self(element, within, element_path, depth + 1, dynamic_index_used, self);
            return;
        }
        if (type->kind() != types::Kind::structure || !valid_struct_layout(type)) return;
        for (const auto &field : type->members()) {
            if (++work > 4096 || field.name.empty() || field.name.starts_with("$") ||
                offset < field.offset) continue;
            const auto field_type = unqualify(field.type);
            if (!field_type || !field_type->size()) continue;
            const auto relative = offset - field.offset;
            if (relative > *field_type->size() || access_bytes > *field_type->size() - relative) continue;
            const auto field_path = path + (path == register_name(*memory.base, memory.base_version)
                ? "->" : ".") + field.name;
            if (relative == 0 && access_bytes == *field_type->size()) {
                nested_results.push_back(field_path);
                continue;
            }
            if (field_type->kind() == types::Kind::structure || field_type->kind() == types::Kind::array)
                self(field_type, relative, field_path, depth + 1, dynamic_index_used, self);
        }
    };
    descend(object, address_offset, register_name(*memory.base, memory.base_version), 0, false, descend);
    if (nested_results.size() != 1) return {};
    return nested_results.front();
}
std::string expression_text(const Expression &expression) {
    return std::visit([&](const auto &value) -> std::string {
        using T = std::decay_t<decltype(value)>;
        if constexpr (std::is_same_v<T, RegisterValue>) {
            return register_name(value.reg, value.version);
        } else if constexpr (std::is_same_v<T, ConstantValue>) {
            std::ostringstream out; out << "0x" << std::hex << value.value; return out.str();
        } else if constexpr (std::is_same_v<T, X87Binary80Value>) {
            std::ostringstream out;
            out << "x87_binary80(0x" << std::hex << value.value.sign_exponent << ", 0x"
                << value.value.significand << ')';
            return out.str();
        } else if constexpr (std::is_same_v<T, MemoryValue>) {
            if (value.stack_variable) return *value.stack_variable;
            const auto access_bytes = static_cast<std::uint16_t>((value.type.bits + 7u) / 8u);
            if (value.base && value.index && value.index_add && value.index_shift.empty() &&
                value.index_shift_amount == 0 && value.index_extend.empty() && value.scale &&
                value.type.bits && value.type.bits % 8 == 0 && value.scale == access_bytes &&
                value.displacement % static_cast<std::int64_t>(value.scale) == 0) {
                std::string index = register_name(*value.index, value.index_version);
                const auto element_bias = value.displacement / static_cast<std::int64_t>(value.scale);
                if (element_bias > 0) index += " + " + std::to_string(element_bias);
                else if (element_bias < 0) {
                    const auto magnitude = static_cast<std::uint64_t>(-(element_bias + 1)) + 1;
                    index += " - " + std::to_string(magnitude);
                }
                return register_name(*value.base, value.base_version) + "[" + index + "]";
            }
            if (const auto member = typed_member_access(value)) return *member;
            return "*[(" + address_text(value) + ")]";
        } else if constexpr (std::is_same_v<T, UnaryValue>) {
            const auto operand = expression_text(*value.operand);
            constexpr std::string_view wasm_ref_func_prefix = "wasm_ref_func_";
            if (value.operation.rfind(wasm_ref_func_prefix, 0) == 0)
                return "wasm_function_ref(" + value.operation.substr(wasm_ref_func_prefix.size()) + ")";
            if (value.operation == "x87_fchs") return "x87_fchs_exact(" + operand + ")";
            if (value.operation == "x87_fabs") return "x87_fabs_exact(" + operand + ")";
            if (value.operation == "carry_flag") return "carry_flag(" + operand + ")";
            if (value.operation.rfind("arm_condition_", 0) == 0) {
                unsigned condition = 255;
                const auto digits = std::string_view(value.operation).substr(14);
                const auto parsed = std::from_chars(digits.data(), digits.data() + digits.size(), condition);
                if (parsed.ec == std::errc{} && parsed.ptr == digits.data() + digits.size())
                    return arm_condition_text(condition, operand);
            }
            if (value.operation == "not") return "!(" + operand + ")";
            if (value.operation == "bitnot") return "~(" + operand + ")";
            return value.operation + "(" + operand + ")";
        } else if constexpr (std::is_same_v<T, BinaryValue>) {
            if (value.operation.rfind("x86_mul_full_", 0) == 0)
                return value.operation + "(" + expression_text(*value.left) + ", " +
                       expression_text(*value.right) + ")";
            if (value.operation == "jvm_lcmp" || value.operation == "jvm_fcmpl_nan_minus_one" ||
                value.operation == "jvm_fcmpg_nan_plus_one" || value.operation == "jvm_dcmpl_nan_minus_one" ||
                value.operation == "jvm_dcmpg_nan_plus_one" ||
                value.operation == "x87_pending_unmasked_exception")
                return value.operation + "(" + expression_text(*value.left) + ", " +
                       expression_text(*value.right) + ")";
            if (value.operation == "a64_udiv" || value.operation == "a64_sdiv" ||
                value.operation.rfind("wasm_", 0) == 0 || value.operation.rfind("ppc_fcmp_", 0) == 0 ||
                value.operation.starts_with("fcvt."))
                return value.operation + "(" + expression_text(*value.left) + ", " +
                       expression_text(*value.right) + ")";
            if (value.operation == "frem" || value.operation == "fcgt_un" || value.operation == "fclt_un" ||
                value.operation == "fbge_un" || value.operation == "fble_un") {
                const auto left = expression_text(*value.left);
                const auto right = expression_text(*value.right);
                if (value.operation == "frem") return "frem(" + left + ", " + right + ")";
                std::string relation;
                if (value.operation == "fcgt_un") relation = left + " > " + right;
                else if (value.operation == "fclt_un") relation = left + " < " + right;
                else if (value.operation == "fbge_un") relation = left + " >= " + right;
                else relation = left + " <= " + right;
                return "(unordered(" + left + ", " + right + ") || (" + relation + "))";
            }
            if (value.operation == "arm_guard")
                return "arm_guard(" + expression_text(*value.left) + ", " + expression_text(*value.right) + ")";
            if (value.operation == "arm_select")
                return "arm_select(" + expression_text(*value.left) + ", " + expression_text(*value.right) + ")";
            if (value.operation.rfind("m6502_", 0) == 0)
                return value.operation + "(" + expression_text(*value.left) + ", " +
                       expression_text(*value.right) + ")";
            if (value.operation.rfind("rvm_", 0) == 0)
                return value.operation.substr(4) + "(" + expression_text(*value.left) + ", " + expression_text(*value.right) + ")";
            if (value.operation == "carry_add")
                return "carry_add(" + expression_text(*value.left) + ", " + expression_text(*value.right) + ")";
            if (value.operation == "carry_sub")
                return "carry_sub(" + expression_text(*value.left) + ", " + expression_text(*value.right) + ")";
            if (value.operation == "arm_shift_carry_out")
                return "arm_shift_carry_out(" + expression_text(*value.left) + ", " + expression_text(*value.right) + ")";
            if (value.operation == "bit_extract")
                return "bit(" + expression_text(*value.left) + ", " + expression_text(*value.right) + ")";
            if (value.operation == "select_if") {
                const auto *alternatives = value.right ? std::get_if<BinaryValue>(&value.right->value) : nullptr;
                if (alternatives && alternatives->operation == "pair")
                    return "(" + expression_text(*value.left) + " ? " + expression_text(*alternatives->left) +
                           " : " + expression_text(*alternatives->right) + ")";
            }
            return "(" + expression_text(*value.left) + " " + binary_symbol(value.operation) + " " + expression_text(*value.right) + ")";
        } else if constexpr (std::is_same_v<T, UnknownValue>) {
            return "unknown(" + value.description + ")";
        } else {
            return value.name;
        }
    }, expression.value);
}

ExpressionPtr boolean_constant(bool value) {
    const ValueType type{TypeKind::boolean, 1, false};
    return std::make_shared<Expression>(Expression{type, ConstantValue{value ? 1u : 0u, type}});
}
ExpressionPtr boolean_binary(std::string operation, ExpressionPtr left, ExpressionPtr right) {
    return std::make_shared<Expression>(Expression{{TypeKind::boolean, 1, false},
        BinaryValue{std::move(operation), std::move(left), std::move(right)}});
}
ExpressionPtr boolean_unary(std::string operation, ExpressionPtr value) {
    return std::make_shared<Expression>(Expression{{TypeKind::boolean, 1, false},
        UnaryValue{std::move(operation), std::move(value)}});
}
ExpressionPtr x86_predicate(X86Condition condition, bool test, ExpressionPtr lhs, ExpressionPtr rhs) {
    const std::uint16_t width = lhs ? lhs->type.bits : std::uint16_t{0};
    if (!width || !rhs) return {};
    auto zero = constant_expr(0, width);
    auto result = std::make_shared<Expression>(Expression{integer_type(width),
        BinaryValue{test ? "and" : "sub", lhs, rhs}});
    const auto equal = test ? boolean_binary("eq", result, zero) : boolean_binary("eq", lhs, rhs);
    const auto not_equal = boolean_unary("not", equal);
    const auto sign = boolean_unary("signbit", result);
    const auto parity = boolean_unary("parity8", result);
    const auto left_sign = boolean_unary("signbit", lhs);
    const auto right_sign = boolean_unary("signbit", rhs);
    const auto overflow = test ? boolean_constant(false) : boolean_binary("bool_and",
        boolean_binary("bool_xor", left_sign, right_sign),
        boolean_binary("bool_xor", left_sign, sign));
    switch (condition) {
    case X86Condition::overflow: return overflow;
    case X86Condition::not_overflow: return boolean_unary("not", overflow);
    case X86Condition::below: return test ? boolean_constant(false) : boolean_binary("ult", lhs, rhs);
    case X86Condition::above_equal: return test ? boolean_constant(true) : boolean_binary("uge", lhs, rhs);
    case X86Condition::equal: return equal;
    case X86Condition::not_equal: return not_equal;
    case X86Condition::below_equal:
        return test ? equal : boolean_binary("ule", lhs, rhs);
    case X86Condition::above:
        return test ? not_equal : boolean_binary("ugt", lhs, rhs);
    case X86Condition::sign: return sign;
    case X86Condition::not_sign: return boolean_unary("not", sign);
    case X86Condition::parity: return parity;
    case X86Condition::not_parity: return boolean_unary("not", parity);
    case X86Condition::less: return test ? sign : boolean_binary("slt", lhs, rhs);
    case X86Condition::greater_equal:
        return test ? boolean_unary("not", sign) : boolean_binary("sge", lhs, rhs);
    case X86Condition::less_equal:
        return test ? boolean_binary("bool_or", equal, sign) : boolean_binary("sle", lhs, rhs);
    case X86Condition::greater:
        return test ? boolean_binary("bool_and", not_equal, boolean_unary("not", sign))
                    : boolean_binary("sgt", lhs, rhs);
    }
    return {};
}
ExpressionPtr x86_arithmetic_predicate(X86Condition condition, const std::string &operation,
                                       ExpressionPtr lhs, ExpressionPtr rhs) {
    if (!lhs || !rhs || !lhs->type.bits || lhs->type.bits != rhs->type.bits) return {};
    const auto width = lhs->type.bits;
    const auto zero = constant_expr(0, width);
    auto result = std::make_shared<Expression>(Expression{integer_type(width),
        BinaryValue{operation == "add" ? "add" : operation == "sub" ? "sub" : operation, lhs, rhs}});
    const auto zf = boolean_binary("eq", result, zero);
    const auto sf = boolean_unary("signbit", result);
    const auto pf = boolean_unary("parity8", result);
    ExpressionPtr cf, of;
    if (operation == "sub" || operation == "cmp") {
        cf = boolean_binary("ult", lhs, rhs);
        const auto left_sign = boolean_unary("signbit", lhs);
        const auto right_sign = boolean_unary("signbit", rhs);
        const auto result_sign = boolean_unary("signbit", result);
        of = boolean_binary("bool_and", boolean_binary("bool_xor", left_sign, right_sign),
                            boolean_binary("bool_xor", left_sign, result_sign));
    } else if (operation == "add") {
        cf = boolean_binary("carry_add", lhs, rhs);
        const auto left_sign = boolean_unary("signbit", lhs);
        const auto right_sign = boolean_unary("signbit", rhs);
        const auto result_sign = boolean_unary("signbit", result);
        of = boolean_binary("bool_and", boolean_unary("not", boolean_binary("bool_xor", left_sign, right_sign)),
                            boolean_binary("bool_xor", left_sign, result_sign));
    } else if (operation == "and" || operation == "or" || operation == "xor" || operation == "test") {
        cf = boolean_constant(false);
        of = boolean_constant(false);
    } else if (operation == "shl" || operation == "shr" || operation == "sar") {
        // x86 defines ZF/SF/PF for a non-zero effective count. CF is defined
        // only when the shifted-out bit stays within the operand; OF is defined
        // only for a one-bit shift. Other flag conditions stay opaque.
        if (const auto *count = std::get_if<ConstantValue>(&rhs->value)) {
            const auto masked = count->value & (width == 64 ? 63u : 31u);
            if (masked == 0) return {};
            if (masked < width) {
                const auto bit = operation == "shl" ? width - masked : masked - 1;
                cf = boolean_binary("bit_extract", lhs, constant_expr(bit, width));
            }
            if (masked == 1) {
                if (operation == "shl")
                    of = boolean_binary("bool_xor", sf, cf);
                else if (operation == "shr")
                    of = boolean_unary("signbit", lhs);
                else
                    of = boolean_constant(false);
            }
        } else return {};
    } else return {};
    const auto ncf = cf ? boolean_unary("not", cf) : ExpressionPtr{};
    const auto nof = boolean_unary("not", of);
    const auto less = boolean_binary("bool_xor", sf, of);
    const auto ge = boolean_unary("not", less);
    switch (condition) {
    case X86Condition::overflow: return of;
    case X86Condition::not_overflow: return nof;
    case X86Condition::below: return cf;
    case X86Condition::above_equal: return ncf;
    case X86Condition::equal: return zf;
    case X86Condition::not_equal: return boolean_unary("not", zf);
    case X86Condition::below_equal: return cf ? boolean_binary("bool_or", cf, zf) : ExpressionPtr{};
    case X86Condition::above: return ncf ? boolean_binary("bool_and", ncf, boolean_unary("not", zf)) : ExpressionPtr{};
    case X86Condition::sign: return sf;
    case X86Condition::not_sign: return boolean_unary("not", sf);
    case X86Condition::parity: return pf;
    case X86Condition::not_parity: return boolean_unary("not", pf);
    case X86Condition::less: return less;
    case X86Condition::greater_equal: return ge;
    case X86Condition::less_equal: return boolean_binary("bool_or", zf, less);
    case X86Condition::greater: return boolean_binary("bool_and", boolean_unary("not", zf), ge);
    }
    return {};
}
ExpressionPtr x87_flags_predicate(X86Condition condition, ExpressionPtr flags) {
    if (!flags || flags->type.kind != TypeKind::integer || flags->type.bits < 12) return {};
    const auto flag = [&](std::uint64_t bit) {
        return boolean_binary("bit_extract", flags, constant_expr(bit, 8));
    };
    const auto cf = flag(0), pf = flag(2), zf = flag(6), sf = flag(7), of = flag(11);
    const auto not_cf = boolean_unary("not", cf);
    const auto not_zf = boolean_unary("not", zf);
    const auto sign_overflow_differs = boolean_binary("bool_xor", sf, of);
    switch (condition) {
    case X86Condition::overflow: return of;
    case X86Condition::not_overflow: return boolean_unary("not", of);
    case X86Condition::below: return cf;
    case X86Condition::above_equal: return not_cf;
    case X86Condition::equal: return zf;
    case X86Condition::not_equal: return not_zf;
    case X86Condition::below_equal: return boolean_binary("bool_or", cf, zf);
    case X86Condition::above: return boolean_binary("bool_and", not_cf, not_zf);
    case X86Condition::sign: return sf;
    case X86Condition::not_sign: return boolean_unary("not", sf);
    case X86Condition::parity: return pf;
    case X86Condition::not_parity: return boolean_unary("not", pf);
    case X86Condition::less: return sign_overflow_differs;
    case X86Condition::greater_equal: return boolean_unary("not", sign_overflow_differs);
    case X86Condition::less_equal: return boolean_binary("bool_or", zf, sign_overflow_differs);
    case X86Condition::greater:
        return boolean_binary("bool_and", not_zf, boolean_unary("not", sign_overflow_differs));
    }
    return {};
}
ExpressionPtr x86_flags_predicate(X86Condition condition, ExpressionPtr flags, std::uint8_t defined_flags = 0x1f) {
    if (!flags || flags->type.kind != TypeKind::integer || flags->type.bits < 12) return {};
    std::uint8_t required_flags = 0;
    switch (condition) {
    case X86Condition::overflow: case X86Condition::not_overflow: required_flags = 1u << 4; break;
    case X86Condition::below: case X86Condition::above_equal: required_flags = 1u << 0; break;
    case X86Condition::equal: case X86Condition::not_equal: required_flags = 1u << 2; break;
    case X86Condition::below_equal: case X86Condition::above: required_flags = (1u << 0) | (1u << 2); break;
    case X86Condition::sign: case X86Condition::not_sign: required_flags = 1u << 3; break;
    case X86Condition::parity: case X86Condition::not_parity: required_flags = 1u << 1; break;
    case X86Condition::less: case X86Condition::greater_equal: required_flags = (1u << 3) | (1u << 4); break;
    case X86Condition::less_equal: case X86Condition::greater: required_flags = (1u << 2) | (1u << 3) | (1u << 4); break;
    }
    if ((defined_flags & required_flags) != required_flags) return {};
    const auto flag = [&](std::uint64_t bit) {
        return boolean_binary("bit_extract", flags, constant_expr(bit, flags->type.bits));
    };
    const auto cf = flag(0), pf = flag(2), zf = flag(6), sf = flag(7), of = flag(11);
    const auto not_cf = boolean_unary("not", cf);
    const auto not_zf = boolean_unary("not", zf);
    const auto sign_overflow_differs = boolean_binary("bool_xor", sf, of);
    switch (condition) {
    case X86Condition::overflow: return of;
    case X86Condition::not_overflow: return boolean_unary("not", of);
    case X86Condition::below: return cf;
    case X86Condition::above_equal: return not_cf;
    case X86Condition::equal: return zf;
    case X86Condition::not_equal: return not_zf;
    case X86Condition::below_equal: return boolean_binary("bool_or", cf, zf);
    case X86Condition::above: return boolean_binary("bool_and", not_cf, not_zf);
    case X86Condition::sign: return sf;
    case X86Condition::not_sign: return boolean_unary("not", sf);
    case X86Condition::parity: return pf;
    case X86Condition::not_parity: return boolean_unary("not", pf);
    case X86Condition::less: return sign_overflow_differs;
    case X86Condition::greater_equal: return boolean_unary("not", sign_overflow_differs);
    case X86Condition::less_equal: return boolean_binary("bool_or", zf, sign_overflow_differs);
    case X86Condition::greater:
        return boolean_binary("bool_and", not_zf, boolean_unary("not", sign_overflow_differs));
    }
    return {};
}
ExpressionPtr x87_sahf_predicate(X86Condition condition, ExpressionPtr flags) {
    if (!flags || flags->type.kind != TypeKind::integer || flags->type.bits < 8) return {};
    const auto flag = [&](std::uint64_t bit) {
        return boolean_binary("bit_extract", flags, constant_expr(bit, 8));
    };
    // SAHF maps the x87 status C0/C2/C3 bits, copied into AH by FNSTSW,
    // to CF/PF/ZF. OF is preserved and SF receives FSW.B, so conditions
    // involving SF or OF cannot be reconstructed from the comparison alone.
    const auto cf = flag(0), pf = flag(2), zf = flag(6);
    const auto not_cf = boolean_unary("not", cf);
    const auto not_zf = boolean_unary("not", zf);
    switch (condition) {
    case X86Condition::below: return cf;
    case X86Condition::above_equal: return not_cf;
    case X86Condition::equal: return zf;
    case X86Condition::not_equal: return not_zf;
    case X86Condition::below_equal: return boolean_binary("bool_or", cf, zf);
    case X86Condition::above: return boolean_binary("bool_and", not_cf, not_zf);
    case X86Condition::parity: return pf;
    case X86Condition::not_parity: return boolean_unary("not", pf);
    default: return {};
    }
}
ExpressionPtr a64_subs_predicate(std::uint8_t condition, ExpressionPtr lhs, ExpressionPtr rhs) {
    if (!lhs || !rhs || condition >= 14) return {};
    const auto width = lhs->type.bits;
    if (!width) return {};
    const auto subtraction = std::make_shared<Expression>(Expression{integer_type(width),
        BinaryValue{"sub", lhs, rhs}});
    const auto equal = boolean_binary("eq", lhs, rhs);
    const auto not_equal = boolean_unary("not", equal);
    const auto sign = boolean_unary("signbit", subtraction);
    const auto left_sign = boolean_unary("signbit", lhs);
    const auto right_sign = boolean_unary("signbit", rhs);
    const auto overflow = boolean_binary("bool_and",
        boolean_binary("bool_xor", left_sign, right_sign),
        boolean_binary("bool_xor", left_sign, sign));
    const auto below = boolean_binary("ult", lhs, rhs);
    const auto above_equal = boolean_binary("uge", lhs, rhs);
    const auto above = boolean_binary("ugt", lhs, rhs);
    const auto below_equal = boolean_binary("ule", lhs, rhs);
    const auto less = boolean_binary("slt", lhs, rhs);
    const auto greater_equal = boolean_binary("sge", lhs, rhs);
    const auto greater = boolean_binary("sgt", lhs, rhs);
    const auto less_equal = boolean_binary("sle", lhs, rhs);
    switch (condition) {
    case 0: return equal;
    case 1: return not_equal;
    case 2: return above_equal; // CS/HS
    case 3: return below;       // CC/LO
    case 4: return sign;        // MI
    case 5: return boolean_unary("not", sign);
    case 6: return overflow;
    case 7: return boolean_unary("not", overflow);
    case 8: return above;
    case 9: return below_equal;
    case 10: return greater_equal;
    case 11: return less;
    case 12: return greater;
    case 13: return less_equal;
    default: return {};
    }
}
std::string branch_condition_text(const Branch &branch) {
    return branch.predicate ? expression_text(*branch.predicate) : branch.condition;
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
    return lift_function(function, snapshot, nullptr);
}

Result<LiftedFunction> lift_function(const FunctionRecord &function, const FunctionSnapshot &snapshot,
                                     const JvmMetadata *jvm_metadata) {
    return lift_function(function, snapshot, jvm_metadata, nullptr);
}

Result<LiftedFunction> lift_function(const FunctionRecord &function, const FunctionSnapshot &snapshot,
                                     const JvmMetadata *jvm_metadata, const WasmMetadata *wasm_metadata) {
    return lift_function(function, snapshot, jvm_metadata, wasm_metadata, OpaqueInstructionLifter{});
}

Result<LiftedFunction> lift_function(const FunctionRecord &function, const FunctionSnapshot &snapshot,
                                     const JvmMetadata *jvm_metadata, const WasmMetadata *wasm_metadata,
                                     const DexMetadata *dex_metadata) {
    return lift_function(function, snapshot, jvm_metadata, wasm_metadata, dex_metadata, {});
}

Result<LiftedFunction> lift_function(const FunctionRecord &function, const FunctionSnapshot &snapshot,
                                     const JvmMetadata *jvm_metadata, const WasmMetadata *wasm_metadata,
                                     const OpaqueInstructionLifter &opaque_lifter) {
    return lift_function(function, snapshot, jvm_metadata, wasm_metadata, nullptr, opaque_lifter);
}

Result<LiftedFunction> lift_function(const FunctionRecord &function, const FunctionSnapshot &snapshot,
                                     const JvmMetadata *jvm_metadata, const WasmMetadata *wasm_metadata,
                                     const DexMetadata *dex_metadata,
                                     const OpaqueInstructionLifter &opaque_lifter) {
    std::map<std::uint64_t, std::shared_ptr<const BasicBlock>> available;
    for (const auto &block : snapshot.blocks) {
        if (!block)
            return Error{ErrorCode::invalid_argument, "function snapshot contains a null basic block"};
        if (!available.emplace(block->id.value, block).second)
            return Error{ErrorCode::invalid_argument, "function snapshot contains duplicate basic block IDs"};
    }
    for (const auto id : function.blocks) {
        const auto found = available.find(id.value);
        if (found == available.end())
            return Error{ErrorCode::invalid_argument, "function block is absent from the analysis snapshot"};
        const auto &facts = found->second->instructions;
        if (!facts.empty() && facts.front()) {
            const auto architecture = facts.front()->instruction.context.architecture;
            if (architecture == Architecture::dex)
                return lift_dex_function(function, snapshot, dex_metadata);
            if (architecture == Architecture::wasm)
                return lift_wasm_function(function, snapshot, wasm_metadata);
            if (architecture == Architecture::jvm)
                return lift_jvm_function(function, snapshot, jvm_metadata);
        }
    }
    LiftedFunction result{function.id, function.entry, {}, {}};
    struct PendingX86Compare {
        bool test = false;
        bool raw_x86_flags = false;
        std::uint8_t defined_flags = 0x1f;
        bool x87_flags = false;
        bool x87_status = false;
        bool x87_status_in_ax = false;
        bool x87_sahf = false;
        std::string operation;
        ExpressionPtr left, right;
        std::vector<RegisterOperand> registers;
        std::uint64_t producer_instruction_id = 0;
    };
    struct PendingA64Compare {
        ExpressionPtr left, right, nzcv;
        std::vector<RegisterOperand> registers;
        unsigned conditional_depth = 0;
    };

    auto is_x86_context = [](const Instruction &instruction) {
        return instruction.context.architecture == Architecture::x86 ||
               instruction.context.architecture == Architecture::x86_64;
    };
    auto is_x86_flag_producer = [&](const Instruction &instruction) {
        return is_x86_context(instruction) && instruction.operands.size() == 2 &&
            (instruction.opcode == Opcode::add || instruction.opcode == Opcode::adc ||
             instruction.opcode == Opcode::sub || instruction.opcode == Opcode::sbb ||
             instruction.opcode == Opcode::cmp || instruction.opcode == Opcode::test ||
             instruction.opcode == Opcode::bit_and || instruction.opcode == Opcode::bit_or ||
             instruction.opcode == Opcode::bit_xor || instruction.opcode == Opcode::shl ||
             instruction.opcode == Opcode::shr || instruction.opcode == Opcode::sar ||
             instruction.opcode == Opcode::rol || instruction.opcode == Opcode::ror ||
             instruction.opcode == Opcode::rcl || instruction.opcode == Opcode::rcr);
    };
    auto is_x86_unary_flag_producer = [&](const Instruction &instruction) {
        return is_x86_context(instruction) && instruction.operands.size() == 1 &&
            (instruction.opcode == Opcode::inc || instruction.opcode == Opcode::dec || instruction.opcode == Opcode::neg);
    };
    auto is_x87_flag_compare = [&](const Instruction &instruction) {
        if (!is_x86_context(instruction) || instruction.opcode != Opcode::x87 ||
            instruction.operands.size() != 2 || instruction.register_writes.empty()) return false;
        const auto &name = instruction.mnemonic_override;
        const bool compare = name == "fcomi" || name == "fucomi" || name == "fcomip" || name == "fucomip";
        const bool writes_flags = std::any_of(instruction.register_writes.begin(), instruction.register_writes.end(),
            [](RegisterOperand reg) { return reg.bank == RegisterBank::flags; });
        const bool x87_operands = std::all_of(instruction.operands.begin(), instruction.operands.end(),
            [](const Operand &operand) {
                const auto *reg = std::get_if<RegisterOperand>(&operand);
                return reg && reg->bank == RegisterBank::x87 && reg->width == 80;
            });
        return compare && writes_flags && x87_operands;
    };
    auto is_x87_status_compare = [&](const Instruction &instruction) {
        if (!is_x86_context(instruction) || instruction.opcode != Opcode::x87) return false;
        const auto &name = instruction.mnemonic_override;
        const bool compare = name == "fcom" || name == "fcomp" || name == "fcompp" ||
                             name == "fucom" || name == "fucomp" || name == "fucompp";
        return compare && std::any_of(instruction.register_writes.begin(), instruction.register_writes.end(),
            [](RegisterOperand reg) { return reg.bank == RegisterBank::x87_status; });
    };
    auto same_x86_flag_state = [&](const std::optional<PendingX86Compare> &left,
                                   const std::optional<PendingX86Compare> &right) {
        if (!left || !right) return !left && !right;
        const auto same_expression = [](const ExpressionPtr &a, const ExpressionPtr &b) {
            return (!a || !b) ? a == b : a->type == b->type && expression_text(*a) == expression_text(*b);
        };
        return left->test == right->test && left->raw_x86_flags == right->raw_x86_flags &&
               left->defined_flags == right->defined_flags &&
               left->x87_flags == right->x87_flags &&
               left->x87_status == right->x87_status && left->x87_status_in_ax == right->x87_status_in_ax &&
               left->x87_sahf == right->x87_sahf &&
               left->operation == right->operation &&
               left->producer_instruction_id == right->producer_instruction_id &&
               left->registers == right->registers && same_expression(left->left, right->left) &&
               same_expression(left->right, right->right);
    };
    const auto x86_condition_expression = [](const Instruction &instruction, X86Condition condition,
                                             const PendingX86Compare &pending) -> ExpressionPtr {
        const auto flags = std::find_if(instruction.register_reads.begin(), instruction.register_reads.end(),
            [](RegisterOperand reg) { return reg.bank == RegisterBank::flags; });
        if (pending.x87_sahf)
            return flags == instruction.register_reads.end() ? ExpressionPtr{} :
                x87_sahf_predicate(condition, reg_expr(*flags));
        if (pending.x87_flags)
            return flags == instruction.register_reads.end() ? ExpressionPtr{} :
                x87_flags_predicate(condition, reg_expr(*flags));
        if (pending.raw_x86_flags)
            return flags == instruction.register_reads.end() ? ExpressionPtr{} :
                x86_flags_predicate(condition, reg_expr(*flags), pending.defined_flags);
        if (pending.test || pending.operation == "cmp")
            return x86_predicate(condition, pending.test, pending.left, pending.right);
        return x86_arithmetic_predicate(condition, pending.operation, pending.left, pending.right);
    };
    auto update_x86_flag_state = [&](std::optional<PendingX86Compare> state,
                                     const Instruction &instruction, std::uint64_t instruction_id) {
        if (is_x87_flag_compare(instruction)) {
            PendingX86Compare pending;
            pending.x87_flags = true;
            pending.operation = "x87_flags";
            pending.producer_instruction_id = instruction_id;
            return std::optional<PendingX86Compare>{std::move(pending)};
        }
        if (is_x87_status_compare(instruction)) {
            PendingX86Compare pending;
            pending.x87_flags = true;
            pending.x87_status = true;
            pending.operation = "x87_status_flags";
            pending.producer_instruction_id = instruction_id;
            return std::optional<PendingX86Compare>{std::move(pending)};
        }
        if (state && state->x87_status && instruction.opcode == Opcode::x87 &&
            instruction.mnemonic_override == "fnstsw") {
            const bool reads_status = std::any_of(instruction.register_reads.begin(), instruction.register_reads.end(),
                [](RegisterOperand reg) { return reg.bank == RegisterBank::x87_status; });
            const bool writes_ax = std::any_of(instruction.register_writes.begin(), instruction.register_writes.end(),
                [](RegisterOperand reg) { return reg.bank == RegisterBank::gpr && reg.index == 0 && reg.width == 16; });
            if (reads_status && writes_ax) {
                state->x87_status = false;
                state->x87_status_in_ax = true;
                state->registers = {{RegisterBank::gpr, 0, 16, false}};
                return state;
            }
            return std::optional<PendingX86Compare>{};
        }
        if (state && state->x87_status_in_ax && instruction.opcode == Opcode::x87 &&
            instruction.mnemonic_override == "sahf") {
            state->x87_status_in_ax = false;
            state->x87_sahf = true;
            state->registers.clear();
            return state;
        }
        if ((instruction.opcode == Opcode::rdrand || instruction.opcode == Opcode::rdseed) &&
            evaluate_x86_random_instruction(instruction, 0, false, 0)) {
            PendingX86Compare pending;
            pending.raw_x86_flags = true;
            pending.operation = instruction.opcode == Opcode::rdrand ? "rdrand" : "rdseed";
            pending.producer_instruction_id = instruction_id;
            return std::optional<PendingX86Compare>{std::move(pending)};
        }
        if (is_x86_flag_producer(instruction) || is_x86_unary_flag_producer(instruction)) {
            PendingX86Compare pending;
            pending.test = instruction.opcode == Opcode::test;
            pending.raw_x86_flags = instruction.opcode == Opcode::adc || instruction.opcode == Opcode::sbb ||
                instruction.opcode == Opcode::inc || instruction.opcode == Opcode::dec || instruction.opcode == Opcode::neg ||
                instruction.opcode == Opcode::shl || instruction.opcode == Opcode::shr || instruction.opcode == Opcode::sar ||
                instruction.opcode == Opcode::rol || instruction.opcode == Opcode::ror ||
                instruction.opcode == Opcode::rcl || instruction.opcode == Opcode::rcr;
            pending.operation = operation_name(instruction.opcode);
            pending.producer_instruction_id = instruction_id;
            if (pending.raw_x86_flags) {
                const bool shift = instruction.opcode == Opcode::shl || instruction.opcode == Opcode::shr ||
                                   instruction.opcode == Opcode::sar;
                const bool rotate = instruction.opcode == Opcode::rol || instruction.opcode == Opcode::ror ||
                                    instruction.opcode == Opcode::rcl || instruction.opcode == Opcode::rcr;
                if (shift || rotate) {
                    const auto width = std::visit([](const auto &operand) -> std::uint16_t {
                        using T = std::decay_t<decltype(operand)>;
                        if constexpr (std::is_same_v<T, RegisterOperand>)
                            return operand.bank == RegisterBank::gpr ? operand.width : 0;
                        else if constexpr (std::is_same_v<T, MemoryOperand>) return operand.data_width;
                        else return 0;
                    }, instruction.operands.front());
                    const auto *count = instruction.operands.size() == 2
                        ? std::get_if<ImmediateOperand>(&instruction.operands[1]) : nullptr;
                    constexpr std::uint8_t pf_zf_sf = (1u << 1) | (1u << 2) | (1u << 3);
                    if (count && (width == 8 || width == 16 || width == 32 || width == 64)) {
                        const auto masked = static_cast<unsigned>(count->value) & (width == 64 ? 0x3fU : 0x1fU);
                        const auto effective = rotate
                            ? masked % (instruction.opcode == Opcode::rcl || instruction.opcode == Opcode::rcr
                                           ? width + 1u : width)
                            : masked;
                        if (effective != 0) {
                            if (shift) {
                                pending.defined_flags = pf_zf_sf;
                                if (effective <= width) pending.defined_flags |= 1u << 0;
                                if (effective == 1) pending.defined_flags |= 1u << 4;
                            } else {
                                pending.defined_flags = static_cast<std::uint8_t>(0x1f & ~(1u << 4));
                                if (effective == 1) pending.defined_flags |= 1u << 4;
                            }
                        }
                    } else if (shift) {
                        pending.defined_flags = pf_zf_sf;
                        if (width == 32 || width == 64) pending.defined_flags |= 1u << 0;
                    } else {
                        pending.defined_flags = static_cast<std::uint8_t>(0x1f & ~(1u << 4));
                    }
                }
                return std::optional<PendingX86Compare>{std::move(pending)};
            }
            bool supported = true;
            for (std::size_t index = 0; index < instruction.operands.size(); ++index) {
                const auto &operand = instruction.operands[index];
                if (!std::holds_alternative<RegisterOperand>(operand) &&
                    !std::holds_alternative<ImmediateOperand>(operand)) {
                    supported = false;
                    break;
                }
                if (const auto *reg = std::get_if<RegisterOperand>(&operand)) pending.registers.push_back(*reg);
                if (is_x86_unary_flag_producer(instruction) && index == 0) {
                    pending.left = operand_expr(operand);
                    pending.right = constant_expr(instruction.opcode == Opcode::neg ? 0 : 1,
                                                  std::get<RegisterOperand>(operand).width);
                } else if (index == 0) {
                    pending.left = operand_expr(operand);
                } else if (index == 1) {
                    pending.right = operand_expr(operand);
                }
            }
            if (!supported) return std::optional<PendingX86Compare>{};
            return std::optional<PendingX86Compare>{std::move(pending)};
        }
        if (state) {
            if (instruction.opcode == Opcode::x86_opaque || instruction.opcode == Opcode::opaque)
                return std::optional<PendingX86Compare>{};
            const bool flags_overwritten = std::any_of(instruction.register_writes.begin(),
                instruction.register_writes.end(), [](RegisterOperand reg) { return reg.bank == RegisterBank::flags; });
            const bool source_overwritten = std::any_of(instruction.register_writes.begin(),
                instruction.register_writes.end(), [&](RegisterOperand written) {
                    return std::any_of(state->registers.begin(), state->registers.end(),
                        [&](RegisterOperand compared) {
                            return written.bank == compared.bank && written.index == compared.index;
                        });
                });
            const bool status_overwritten = state->x87_status &&
                std::any_of(instruction.register_writes.begin(), instruction.register_writes.end(),
                    [](RegisterOperand reg) { return reg.bank == RegisterBank::x87_status; });
            if (flags_overwritten || source_overwritten || status_overwritten || instruction.flow == FlowKind::call)
                state.reset();
        }
        return state;
    };

    auto is_a64_compare = [](const Instruction &instruction) {
        return instruction.context.architecture == Architecture::arm64 &&
            instruction.context.mode == ExecutionMode::a64 && instruction.opcode == Opcode::a64_subs &&
            instruction.operands.size() == 3 && std::get_if<RegisterOperand>(&instruction.operands[0]) &&
            std::get<RegisterOperand>(instruction.operands[0]).bank == RegisterBank::arm64_zero;
    };
    auto same_a64_flag_state = [](const std::optional<PendingA64Compare> &left,
                                  const std::optional<PendingA64Compare> &right) {
        if (!left || !right) return !left && !right;
        const auto same_expression = [](const ExpressionPtr &a, const ExpressionPtr &b) {
            return (!a || !b) ? a == b : a->type == b->type && expression_text(*a) == expression_text(*b);
        };
        return left->registers == right->registers &&
               left->conditional_depth == right->conditional_depth &&
               same_expression(left->left, right->left) &&
               same_expression(left->right, right->right) && same_expression(left->nzcv, right->nzcv);
    };
    const auto a64_pending_predicate = [](std::uint8_t condition,
                                          const PendingA64Compare &state) -> ExpressionPtr {
        if (condition >= 14) return boolean_constant(true);
        if (state.left && state.right)
            return a64_subs_predicate(condition, state.left, state.right);
        return a64_nzcv_predicate(condition, state.nzcv);
    };
    auto update_a64_flag_state = [&](std::optional<PendingA64Compare> state,
                                     const Instruction &instruction) {
        if (is_a64_compare(instruction)) {
            PendingA64Compare pending;
            bool supported = true;
            for (std::size_t index = 1; index < 3; ++index) {
                const auto &operand = instruction.operands[index];
                if (!std::holds_alternative<RegisterOperand>(operand) &&
                    !std::holds_alternative<ImmediateOperand>(operand)) {
                    supported = false;
                    break;
                }
                if (const auto *reg = std::get_if<RegisterOperand>(&operand)) pending.registers.push_back(*reg);
            }
            if (!supported) return std::optional<PendingA64Compare>{};
            pending.left = operand_expr(instruction.operands[1]);
            pending.right = operand_expr(instruction.operands[2]);
            pending.nzcv = a64_nzcv_arithmetic(pending.left, pending.right, true);
            if (!pending.nzcv) return std::optional<PendingA64Compare>{};
            return std::optional<PendingA64Compare>{std::move(pending)};
        }
        if (instruction.context.architecture == Architecture::arm64 &&
            instruction.context.mode == ExecutionMode::a64 &&
            (instruction.opcode == Opcode::a64_ccmp || instruction.opcode == Opcode::a64_ccmn)) {
            if (instruction.operands.size() != 3 ||
                !std::holds_alternative<RegisterOperand>(instruction.operands[0]) ||
                (!std::holds_alternative<RegisterOperand>(instruction.operands[1]) &&
                 !std::holds_alternative<ImmediateOperand>(instruction.operands[1])))
                return std::optional<PendingA64Compare>{};
            const auto *fallback = std::get_if<ImmediateOperand>(&instruction.operands[2]);
            if (!fallback || fallback->encoded_width != 4 || fallback->value > 15 ||
                (instruction.condition < 14 && (!state || state->conditional_depth >= 6)))
                return std::optional<PendingA64Compare>{};
            const auto left = operand_expr(instruction.operands[0]);
            const auto right = operand_expr(instruction.operands[1]);
            const auto compared = a64_nzcv_arithmetic(left, right,
                instruction.opcode == Opcode::a64_ccmp);
            if (!compared) return std::optional<PendingA64Compare>{};
            const auto predicate = state ? a64_pending_predicate(instruction.condition, *state)
                                         : boolean_constant(true);
            if (!predicate) return std::optional<PendingA64Compare>{};
            PendingA64Compare pending;
            pending.nzcv = instruction.condition >= 14 ? compared :
                arm32_select(predicate, compared, constant_expr(fallback->value, 4));
            if (instruction.condition < 14) {
                pending.registers = state->registers;
                pending.conditional_depth = state->conditional_depth + 1;
            }
            for (std::size_t index = 0; index < 2; ++index) {
                const auto *reg = std::get_if<RegisterOperand>(&instruction.operands[index]);
                if (reg && reg->bank != RegisterBank::arm64_zero &&
                    std::find(pending.registers.begin(), pending.registers.end(), *reg) == pending.registers.end())
                    pending.registers.push_back(*reg);
            }
            return std::optional<PendingA64Compare>{std::move(pending)};
        }
        if (state) {
            if (instruction.opcode == Opcode::opaque || instruction.opcode == Opcode::x86_opaque)
                return std::optional<PendingA64Compare>{};
            const bool flags_overwritten = std::any_of(instruction.register_writes.begin(),
                instruction.register_writes.end(), [](RegisterOperand reg) { return reg.bank == RegisterBank::arm_flags; });
            const bool source_overwritten = std::any_of(instruction.register_writes.begin(),
                instruction.register_writes.end(), [&](RegisterOperand written) {
                    return std::any_of(state->registers.begin(), state->registers.end(),
                        [&](RegisterOperand compared) {
                            return written.bank == compared.bank && written.index == compared.index;
                        });
                });
            if (flags_overwritten || source_overwritten || instruction.flow == FlowKind::call)
                state.reset();
        }
        return state;
    };

    // Carry x86 and AArch64 comparison facts through acyclic CFG edges. At joins,
    // retain them only when every predecessor proves the same expression; loop
    // components stay opaque because this pass does not solve cyclic fixed points.
    std::map<std::uint64_t, std::shared_ptr<const BasicBlock>> owned_blocks;
    std::map<std::pair<std::uint64_t, std::uint64_t>, std::uint64_t> block_at_address;
    for (const auto id : function.blocks) {
        const auto found = available.find(id.value);
        if (found == available.end())
            return Error{ErrorCode::invalid_argument, "function block is absent from the analysis snapshot"};
        if (!owned_blocks.emplace(id.value, found->second).second)
            return Error{ErrorCode::invalid_argument, "function record contains duplicate basic block IDs"};
        block_at_address.emplace(std::pair{found->second->begin.space.value, found->second->begin.offset}, id.value);
    }
    std::map<std::uint64_t, std::set<std::uint64_t>> predecessors, successors;
    for (const auto &[id, source] : owned_blocks) {
        for (const auto &edge : source->successors) {
            if (!edge.target) continue;
            const auto target = block_at_address.find({edge.target->space.value, edge.target->offset});
            if (target == block_at_address.end()) continue;
            successors[id].insert(target->second);
            predecessors[target->second].insert(id);
        }
    }
    std::map<std::uint64_t, std::size_t> remaining_predecessors;
    std::vector<std::uint64_t> ready;
    for (const auto &[id, block] : owned_blocks) {
        const auto count = predecessors[id].size();
        remaining_predecessors[id] = count;
        if (!count) ready.push_back(id);
    }
    std::map<std::uint64_t, std::optional<PendingX86Compare>> incoming_x86_flags, outgoing_x86_flags;
    std::map<std::uint64_t, std::optional<PendingA64Compare>> incoming_a64_flags, outgoing_a64_flags;
    std::map<std::uint64_t, X87StackState> incoming_x87_stack, outgoing_x87_stack;
    while (!ready.empty()) {
        const auto id = ready.back();
        ready.pop_back();
        const auto &source = *owned_blocks.at(id);
        std::optional<PendingX86Compare> state;
        std::optional<PendingA64Compare> a64_state;
        X87StackState x87_state;
        if (source.begin == function.entry) {
            state.reset();
            a64_state.reset();
        } else if (!predecessors[id].empty()) {
            bool have_first = false;
            bool equivalent = true;
            std::optional<PendingX86Compare> candidate;
            for (const auto predecessor : predecessors[id]) {
                const auto found_state = outgoing_x86_flags.find(predecessor);
                if (found_state == outgoing_x86_flags.end()) {
                    equivalent = false;
                    break;
                }
                if (!have_first) {
                    candidate = found_state->second;
                    have_first = true;
                } else if (!same_x86_flag_state(candidate, found_state->second)) {
                    equivalent = false;
                    break;
                }
            }
            if (equivalent && have_first) state = std::move(candidate);

            bool a64_have_first = false;
            bool a64_equivalent = true;
            std::optional<PendingA64Compare> a64_candidate;
            for (const auto predecessor : predecessors[id]) {
                const auto found_state = outgoing_a64_flags.find(predecessor);
                if (found_state == outgoing_a64_flags.end()) {
                    a64_equivalent = false;
                    break;
                }
                if (!a64_have_first) {
                    a64_candidate = found_state->second;
                    a64_have_first = true;
                } else if (!same_a64_flag_state(a64_candidate, found_state->second)) {
                    a64_equivalent = false;
                    break;
                }
            }
            if (a64_equivalent && a64_have_first) a64_state = std::move(a64_candidate);

            bool x87_have_first = false;
            bool x87_equivalent = true;
            X87StackState x87_candidate;
            for (const auto predecessor : predecessors[id]) {
                const auto found_state = outgoing_x87_stack.find(predecessor);
                if (found_state == outgoing_x87_stack.end()) { x87_equivalent = false; break; }
                if (!x87_have_first) { x87_candidate = found_state->second; x87_have_first = true; }
                else x87_candidate = join_x87_stack_states(x87_candidate, found_state->second);
            }
            if (x87_equivalent && x87_have_first) x87_state = std::move(x87_candidate);
        }
        incoming_x86_flags[id] = state;
        incoming_a64_flags[id] = a64_state;
        incoming_x87_stack[id] = x87_state;
        for (const auto &fact : source.instructions) {
            if (!fact) return Error{ErrorCode::invalid_argument, "basic block contains a null instruction fact"};
            state = update_x86_flag_state(std::move(state), fact->instruction, fact->id);
            a64_state = update_a64_flag_state(std::move(a64_state), fact->instruction);
            x87_state = transfer_x87_stack_state(x87_state, fact->instruction);
        }
        outgoing_x86_flags[id] = std::move(state);
        outgoing_a64_flags[id] = std::move(a64_state);
        outgoing_x87_stack[id] = std::move(x87_state);
        for (const auto target : successors[id]) {
            auto &remaining = remaining_predecessors[target];
            if (remaining && --remaining == 0) ready.push_back(target);
        }
    }
    std::set<std::uint64_t> seen;
    for (const auto id : function.blocks) {
        if (!seen.insert(id.value).second)
            return Error{ErrorCode::invalid_argument, "function record contains duplicate basic block IDs"};
        const auto found = available.find(id.value);
        if (found == available.end())
            return Error{ErrorCode::invalid_argument, "function block is absent from the analysis snapshot"};
        const auto &source = *found->second;
        LiftedBlock block{id, source.begin, {}, source.successors};
        std::optional<PendingX86Compare> pending_x86_compare;
        if (const auto incoming = incoming_x86_flags.find(id.value); incoming != incoming_x86_flags.end())
            pending_x86_compare = incoming->second;
        std::optional<PendingA64Compare> pending_a64_compare;
        if (const auto incoming = incoming_a64_flags.find(id.value); incoming != incoming_a64_flags.end())
            pending_a64_compare = incoming->second;
        auto x87_stack_state = incoming_x87_stack.contains(id.value)
            ? incoming_x87_stack.at(id.value) : X87StackState{};
        for (const auto &fact : source.instructions) {
            if (!fact)
                return Error{ErrorCode::invalid_argument, "basic block contains a null instruction fact"};
            const auto &decoded = fact->instruction;
            const bool a64_context = decoded.context.architecture == Architecture::arm64 &&
                                     decoded.context.mode == ExecutionMode::a64;
            const auto x86_compare_before_instruction = pending_x86_compare;
            const auto a64_compare_before_instruction = pending_a64_compare;
            pending_x86_compare = update_x86_flag_state(std::move(pending_x86_compare), decoded, fact->id);
            pending_a64_compare = update_a64_flag_state(std::move(pending_a64_compare), decoded);
            std::vector<Statement> ppc_before;
            auto ppc_statement = decoded.context.architecture == Architecture::powerpc
                ? lift_ppc_instruction(decoded, &ppc_before) : std::optional<Statement>{};
            std::optional<Intrinsic> extension_ir;
            if (decoded.opcode == Opcode::opaque && opaque_lifter) {
                auto provided = opaque_lifter(decoded);
                if (!provided) return provided.error();
                extension_ir = std::move(provided.value());
            }
            auto statement = extension_ir ? Statement{std::move(*extension_ir)} :
                ppc_statement ? std::move(*ppc_statement) : lift_instruction(decoded, result.diagnostics);
            if ((decoded.opcode == Opcode::cmovcc || decoded.opcode == Opcode::setcc) &&
                decoded.x86_condition && is_x86_context(decoded)) {
                const PendingX86Compare *condition_state = pending_x86_compare ? &*pending_x86_compare : nullptr;
                const bool writes_flags = std::any_of(decoded.register_writes.begin(), decoded.register_writes.end(),
                    [](RegisterOperand reg) { return reg.bank == RegisterBank::flags; });
                // A conditional move can overwrite one of the compare inputs.
                // Its condition still observes the pre-instruction state, even
                // though that write ends the compare fact for later instructions.
                if (!condition_state && x86_compare_before_instruction && !writes_flags && decoded.flow != FlowKind::call)
                    condition_state = &*x86_compare_before_instruction;
                if (condition_state) {
                    auto predicate = x86_condition_expression(decoded, *decoded.x86_condition, *condition_state);
                    if (predicate && decoded.opcode == Opcode::cmovcc && decoded.operands.size() == 2) {
                        const auto *destination = std::get_if<RegisterOperand>(&decoded.operands[0]);
                        if (destination && destination->bank == RegisterBank::gpr &&
                            (std::holds_alternative<RegisterOperand>(decoded.operands[1]) ||
                             std::holds_alternative<MemoryOperand>(decoded.operands[1]))) {
                            const auto source = operand_expr(decoded.operands[1]);
                            const auto prior = reg_expr(*destination);
                            if (source->type.bits == destination->width && prior->type.bits == destination->width) {
                                auto selected = std::make_shared<Expression>(Expression{
                                    integer_type(destination->width),
                                    BinaryValue{"select_if", predicate,
                                        std::make_shared<Expression>(Expression{
                                            integer_type(destination->width),
                                            BinaryValue{"pair", source, prior}})}});
                                if (std::holds_alternative<MemoryOperand>(decoded.operands[1])) {
                                    Intrinsic effect{"x86_cmovcc", {predicate, source, prior},
                                        IntrinsicMemoryEffect::read};
                                    effect.register_writes.push_back(*destination);
                                    effect.register_output_values.push_back(std::move(selected));
                                    effect.result_type = integer_type(destination->width);
                                    statement = std::move(effect);
                                } else {
                                    statement = Assign{*destination, std::move(selected)};
                                }
                            }
                        }
                    } else if (predicate && decoded.opcode == Opcode::setcc && decoded.operands.size() == 1) {
                        auto value = std::make_shared<Expression>(Expression{
                            integer_type(8), UnaryValue{"zext", std::move(predicate)}});
                        if (const auto *destination = std::get_if<RegisterOperand>(&decoded.operands[0]);
                            destination && destination->bank == RegisterBank::gpr && destination->width == 8) {
                            statement = Assign{*destination, std::move(value)};
                        } else if (const auto *destination = std::get_if<MemoryOperand>(&decoded.operands[0]);
                                   destination && destination->data_width == 8) {
                            statement = Store{operand_expr(decoded.operands[0]), std::move(value)};
                        }
                    }
                }
            }
            const bool x87_instruction = (decoded.context.architecture == Architecture::x86 ||
                decoded.context.architecture == Architecture::x86_64) && decoded.opcode == Opcode::x87;
            if (x87_instruction && decoded.x87_waiting) {
                const RegisterOperand fsw{RegisterBank::x87_status, 0, 16, false};
                const RegisterOperand fcw{RegisterBank::x87_control, 0, 16, false};
                const auto condition = std::make_shared<Expression>(Expression{
                    ValueType{TypeKind::boolean, 1, false},
                    BinaryValue{"x87_pending_unmasked_exception", reg_expr(fsw), reg_expr(fcw)}});
                block.trap_edges.push_back({decoded.address, TrapEdgeKind::may_trap,
                    "pending unmasked x87 exception before " + decoded.mnemonic_override, condition});
            }
            if (auto *intrinsic = std::get_if<Intrinsic>(&statement); intrinsic && x87_instruction)
                intrinsic->x87_stack_state = x87_stack_state;
            const auto x87_post_state = transfer_x87_stack_state(x87_stack_state, decoded);
            if (x87_instruction && (x87_stack_state.top || decoded.mnemonic_override == "fld1" ||
                                    decoded.mnemonic_override == "fldz"))
                detail::refine_x87_stack_writes(statement, decoded);
            if (x87_instruction && x87_stack_state.top) {
                const auto write_top = decoded.x87_stack_delta > 0 && x87_post_state.top
                    ? *x87_post_state.top : *x87_stack_state.top;
                detail::remap_x87_statement(statement, *x87_stack_state.top, write_top);
            }
            x87_stack_state = x87_post_state;
            if (a64_context && (decoded.opcode == Opcode::a64_csel || decoded.opcode == Opcode::a64_csinc ||
                                decoded.opcode == Opcode::a64_csinv || decoded.opcode == Opcode::a64_csneg) &&
                decoded.operands.size() == 3) {
                const auto *destination = std::get_if<RegisterOperand>(&decoded.operands[0]);
                const auto *when_true = std::get_if<RegisterOperand>(&decoded.operands[1]);
                const auto *when_false = std::get_if<RegisterOperand>(&decoded.operands[2]);
                if (destination && when_true && when_false && destination->width == when_true->width &&
                    destination->width == when_false->width &&
                    (destination->bank == RegisterBank::arm64_gpr || destination->bank == RegisterBank::arm64_zero) &&
                    (when_true->bank == RegisterBank::arm64_gpr || when_true->bank == RegisterBank::arm64_zero) &&
                    (when_false->bank == RegisterBank::arm64_gpr || when_false->bank == RegisterBank::arm64_zero)) {
                    ExpressionPtr condition;
                    if (decoded.condition >= 14)
                        condition = boolean_constant(true);
                    else if (pending_a64_compare)
                        condition = a64_pending_predicate(decoded.condition, *pending_a64_compare);
                    else if (a64_compare_before_instruction)
                        condition = a64_pending_predicate(decoded.condition, *a64_compare_before_instruction);
                    if (!condition && decoded.condition < 14)
                        condition = a64_nzcv_predicate(decoded.condition,
                            reg_expr({RegisterBank::arm_flags, 0, 4, false}));
                    const bool zero_source_alias = when_true->bank == RegisterBank::arm64_zero &&
                        when_true->index == 31 && when_false->bank == RegisterBank::arm64_zero &&
                        when_false->index == 31;
                    if (condition && zero_source_alias &&
                        (decoded.opcode == Opcode::a64_csinc || decoded.opcode == Opcode::a64_csinv)) {
                        // CSET/CSETM are aliases for CSINC/CSINV with both
                        // sources set to XZR/WZR. Keep their Boolean intent
                        // explicit instead of leaving a select over constants.
                        auto predicate = boolean_unary("not", condition);
                        const auto operation = decoded.opcode == Opcode::a64_csinc ? "zext" : "sext";
                        auto value = std::make_shared<Expression>(Expression{
                            integer_type(destination->width), UnaryValue{operation, std::move(predicate)}});
                        statement = destination->bank == RegisterBank::arm64_zero
                            ? Statement{Intrinsic{"nop", {}, IntrinsicMemoryEffect::none}}
                            : Statement{Assign{*destination, std::move(value)}};
                    } else {
                        auto false_value = operand_expr(decoded.operands[2]);
                        if (decoded.opcode == Opcode::a64_csinc)
                            false_value = std::make_shared<Expression>(Expression{integer_type(destination->width),
                                BinaryValue{"add", false_value, constant_expr(1, destination->width)}});
                        else if (decoded.opcode == Opcode::a64_csinv)
                            false_value = std::make_shared<Expression>(Expression{integer_type(destination->width),
                                UnaryValue{"bitnot", false_value}});
                        else if (decoded.opcode == Opcode::a64_csneg)
                            false_value = std::make_shared<Expression>(Expression{integer_type(destination->width),
                                BinaryValue{"sub", constant_expr(0, destination->width), false_value}});
                        if (condition) {
                            auto selected = std::make_shared<Expression>(Expression{integer_type(destination->width),
                                BinaryValue{"select_if", condition,
                                    std::make_shared<Expression>(Expression{integer_type(destination->width),
                                        BinaryValue{"pair", operand_expr(decoded.operands[1]), false_value}})}});
                            statement = destination->bank == RegisterBank::arm64_zero
                                ? Statement{Intrinsic{"nop", {}, IntrinsicMemoryEffect::none}}
                                : Statement{Assign{*destination, std::move(selected)}};
                        }
                    }
                }
            }
            if (auto *branch = std::get_if<Branch>(&statement)) {
                if (is_x86_context(decoded) && decoded.opcode == Opcode::x86_loop && decoded.x86_loop_condition &&
                    decoded.flow == FlowKind::conditional_branch && decoded.direct_target &&
                    decoded.operands.size() == 1 && decoded.access == std::vector<OperandAccess>{OperandAccess::address} &&
                    (decoded.x86_loop_counter_width == 16 || decoded.x86_loop_counter_width == 32 ||
                     (decoded.x86_loop_counter_width == 64 && decoded.context.mode == ExecutionMode::x86_64)) &&
                    !decoded.memory_read && !decoded.memory_write) {
                    const auto width = decoded.x86_loop_counter_width;
                    const RegisterOperand counter{RegisterBank::gpr, 1, width, false};
                    const auto has_register = [](const auto &registers, RegisterOperand reg) {
                        return std::find(registers.begin(), registers.end(), reg) != registers.end();
                    };
                    const bool decrements = *decoded.x86_loop_condition != X86LoopCondition::counter_zero;
                    const bool tests_zero_flag = *decoded.x86_loop_condition == X86LoopCondition::counter_nonzero_and_zero ||
                        *decoded.x86_loop_condition == X86LoopCondition::counter_nonzero_and_not_zero;
                    const auto full_width = decoded.context.mode == ExecutionMode::x86_64 ? 64u :
                        decoded.context.mode == ExecutionMode::x86_32 ? 32u : 16u;
                    const bool has_wide_alias = decrements && width < full_width;
                    const RegisterOperand full_counter{RegisterBank::gpr, 1,
                        static_cast<std::uint16_t>(full_width), false};
                    const auto flags = std::find_if(decoded.register_reads.begin(), decoded.register_reads.end(),
                        [](RegisterOperand reg) { return reg.bank == RegisterBank::flags && reg.index == 0; });
                    std::vector<RegisterOperand> expected_writes;
                    if (decrements) {
                        expected_writes.push_back(counter);
                        if (has_wide_alias) expected_writes.push_back(full_counter);
                    }
                    const bool reads_wide_alias = has_wide_alias && width == 16;
                    const bool valid = std::holds_alternative<RelativeOperand>(decoded.operands.front()) &&
                        has_register(decoded.register_reads, counter) && decoded.register_writes == expected_writes &&
                        (!reads_wide_alias || has_register(decoded.register_reads, full_counter)) &&
                        decoded.register_reads.size() == (tests_zero_flag ? 2u : 1u) + (reads_wide_alias ? 1u : 0u) &&
                        (tests_zero_flag ? flags != decoded.register_reads.end() && flags->width >= 12
                                         : flags == decoded.register_reads.end());
                    if (valid) {
                        const auto old_counter = reg_expr(counter);
                        ExpressionPtr count_after = old_counter;
                        if (decrements) {
                            count_after = std::make_shared<Expression>(Expression{integer_type(width),
                                BinaryValue{"sub", old_counter, constant_expr(1, width)}});
                            ppc_before.push_back(Assign{counter, count_after});
                            if (has_wide_alias) {
                                ExpressionPtr full_value;
                                if (width == 32) {
                                    full_value = std::make_shared<Expression>(Expression{integer_type(64),
                                        UnaryValue{"zext32", count_after}});
                                } else {
                                    const auto mask = UINT64_MAX << width;
                                    auto preserved = std::make_shared<Expression>(Expression{integer_type(full_width),
                                        BinaryValue{"and", reg_expr(full_counter), constant_expr(mask, full_width)}});
                                    auto low = std::make_shared<Expression>(Expression{integer_type(full_width),
                                        UnaryValue{"zext", count_after}});
                                    full_value = std::make_shared<Expression>(Expression{integer_type(full_width),
                                        BinaryValue{"or", std::move(preserved), std::move(low)}});
                                }
                                ppc_before.push_back(Assign{full_counter, std::move(full_value)});
                            }
                        }
                        auto predicate = boolean_binary(*decoded.x86_loop_condition == X86LoopCondition::counter_zero
                                ? "eq" : "ne", count_after, constant_expr(0, width));
                        if (tests_zero_flag) {
                            auto zero_flag = x86_flags_predicate(X86Condition::equal, reg_expr(*flags));
                            if (*decoded.x86_loop_condition == X86LoopCondition::counter_nonzero_and_not_zero)
                                zero_flag = boolean_unary("not", std::move(zero_flag));
                            predicate = boolean_binary("bool_and", std::move(predicate), std::move(zero_flag));
                        }
                        branch->predicate = std::move(predicate);
                        branch->condition = "predicate";
                    }
                }
                if (decoded.x86_condition && pending_x86_compare) {
                    if (pending_x86_compare->x87_sahf) {
                        const auto flags = std::find_if(decoded.register_reads.begin(), decoded.register_reads.end(),
                            [](RegisterOperand reg) { return reg.bank == RegisterBank::flags; });
                        if (flags != decoded.register_reads.end())
                            branch->predicate = x87_sahf_predicate(*decoded.x86_condition, reg_expr(*flags));
                    } else if (pending_x86_compare->x87_flags) {
                        const auto flags = std::find_if(decoded.register_reads.begin(), decoded.register_reads.end(),
                            [](RegisterOperand reg) { return reg.bank == RegisterBank::flags; });
                        if (flags != decoded.register_reads.end())
                            branch->predicate = x87_flags_predicate(*decoded.x86_condition, reg_expr(*flags));
                    } else if (pending_x86_compare->raw_x86_flags) {
                        const auto flags = std::find_if(decoded.register_reads.begin(), decoded.register_reads.end(),
                            [](RegisterOperand reg) { return reg.bank == RegisterBank::flags; });
                        if (flags != decoded.register_reads.end())
                            branch->predicate = x86_flags_predicate(*decoded.x86_condition, reg_expr(*flags),
                                                                   pending_x86_compare->defined_flags);
                    } else if (pending_x86_compare->test || pending_x86_compare->operation == "cmp")
                        branch->predicate = x86_predicate(*decoded.x86_condition, pending_x86_compare->test,
                                                          pending_x86_compare->left, pending_x86_compare->right);
                    else
                        branch->predicate = x86_arithmetic_predicate(*decoded.x86_condition,
                            pending_x86_compare->operation, pending_x86_compare->left, pending_x86_compare->right);
                    if (branch->predicate) branch->condition = "predicate";
                }
                if (a64_context && decoded.opcode == Opcode::a64_b_cond && pending_a64_compare) {
                    branch->predicate = a64_pending_predicate(decoded.condition, *pending_a64_compare);
                    if (branch->predicate) branch->condition = "predicate";
                }
                for (const auto &successor : source.successors) {
                    if (!successor.target)
                        continue;
                    if (successor.kind == BlockEdgeKind::conditional_true || successor.kind == BlockEdgeKind::jump)
                        branch->true_target = successor.target;
                    else if (successor.kind == BlockEdgeKind::conditional_false || successor.kind == BlockEdgeKind::fallthrough)
                        branch->false_target = successor.target;
                }
            }
            // CTR decrements and non-LR-target link updates execute even when
            // the branch condition fails. Keep them before the transfer, using
            // the same source origin so SSA records the pre-instruction state.
            for (auto &effect : ppc_before)
                block.instructions.push_back({{decoded.address, fact->id}, std::move(effect)});
            if ((decoded.context.architecture == Architecture::mips32 ||
                 decoded.context.architecture == Architecture::mips64) && decoded.flow == FlowKind::call) {
                const auto link = std::find_if(decoded.register_writes.begin(), decoded.register_writes.end(),
                    [](RegisterOperand reg) { return reg.bank == RegisterBank::mips_gpr && reg.index != 0; });
                if (link != decoded.register_writes.end()) {
                    const auto return_address = decoded.address.offset +
                        static_cast<std::uint64_t>(decoded.length) * (decoded.delay_slots + 1u);
            block.instructions.push_back({{decoded.address, fact->id},
                Assign{*link, constant_expr(return_address, link->width)}});
                }
            }
            if (decoded.context.architecture == Architecture::mips64 &&
                (decoded.opcode == Opcode::mips64_bltzal || decoded.opcode == Opcode::mips64_bgezal ||
                 decoded.opcode == Opcode::mips64_bltzall || decoded.opcode == Opcode::mips64_bgezall)) {
                const RegisterOperand link{RegisterBank::mips_gpr, 31, 64, false};
                block.instructions.push_back({{decoded.address, fact->id},
                    Assign{link, constant_expr(decoded.address.offset + 8, 64)}});
            }
            if (decoded.context.architecture == Architecture::mips32 &&
                (decoded.opcode == Opcode::mips_bltzal || decoded.opcode == Opcode::mips_bgezal ||
                 decoded.opcode == Opcode::mips_bltzall || decoded.opcode == Opcode::mips_bgezall)) {
                const RegisterOperand link{RegisterBank::mips_gpr, 31, 32, false};
                block.instructions.push_back({{decoded.address, fact->id},
                    Assign{link, constant_expr(decoded.address.offset + 8, 32)}});
            }
            // W-form arithmetic defines both the 32-bit W view and the
            // architecturally zero-extended 64-bit X view. The shared SSA key
            // includes width, so represent both definitions explicitly.
            if (a64_context && (decoded.opcode == Opcode::a64_madd || decoded.opcode == Opcode::a64_msub ||
                                decoded.opcode == Opcode::a64_extr ||
                                decoded.opcode == Opcode::a64_bfm ||
                                decoded.opcode == Opcode::a64_udiv || decoded.opcode == Opcode::a64_sdiv ||
                                decoded.opcode == Opcode::a64_csel || decoded.opcode == Opcode::a64_csinc ||
                                decoded.opcode == Opcode::a64_csinv || decoded.opcode == Opcode::a64_csneg)) {
                const auto *destination = decoded.operands.empty()
                    ? nullptr : std::get_if<RegisterOperand>(&decoded.operands.front());
                const auto *assignment = std::get_if<Assign>(&statement);
                if (destination && assignment && destination->bank == RegisterBank::arm64_gpr &&
                    destination->width == 32 && assignment->destination == *destination) {
                    auto wide_destination = *destination;
                    wide_destination.width = 64;
                    auto zero_extended = std::make_shared<Expression>(Expression{integer_type(64),
                        UnaryValue{"zext32", reg_expr(*destination)}});
                    const InstructionOrigin origin{decoded.address, fact->id};
                    block.instructions.push_back({origin, std::move(statement)});
                    block.instructions.push_back({origin, Assign{wide_destination, std::move(zero_extended)}});
                    continue;
                }
            }
            if (decoded.context.architecture == Architecture::mos6502 &&
                decoded.context.mode == ExecutionMode::m6502 &&
                (decoded.opcode == Opcode::m6502_rts || decoded.opcode == Opcode::m6502_rti)) {
                const RegisterOperand stack{RegisterBank::mos6502, 4, 8, false};
                const auto wrapped_sp = std::make_shared<Expression>(Expression{integer_type(8),
                    BinaryValue{"and", std::make_shared<Expression>(Expression{integer_type(8),
                        BinaryValue{"add", reg_expr(stack), constant_expr(
                            decoded.opcode == Opcode::m6502_rts ? 2 : 3, 8)}}), constant_expr(0xff, 8)}});
                Intrinsic stack_pull{decoded.opcode == Opcode::m6502_rts
                    ? "m6502_rts_stack_read_page_0100_wrap"
                    : "m6502_rti_stack_read_p_pc_page_0100_wrap",
                    {reg_expr(stack), constant_expr(0x0100, 16)}, IntrinsicMemoryEffect::read};
                stack_pull.register_writes = {stack};
                stack_pull.register_output_values = {wrapped_sp};
                if (decoded.opcode == Opcode::m6502_rti) {
                    const RegisterOperand status{RegisterBank::mos6502, 3, 8, false};
                    auto pulled_status = std::make_shared<Expression>(Expression{integer_type(8),
                        UnknownValue{"RTI pulled status byte; B is preserved as pseudo-bit and U is fixed"}});
                    stack_pull.register_writes.push_back(status);
                    stack_pull.register_output_values.push_back(std::make_shared<Expression>(Expression{
                        integer_type(8), BinaryValue{"or",
                            std::make_shared<Expression>(Expression{integer_type(8),
                                BinaryValue{"and", pulled_status, constant_expr(0xcf, 8)}}),
                            std::make_shared<Expression>(Expression{integer_type(8),
                                BinaryValue{"or", std::make_shared<Expression>(Expression{integer_type(8),
                                    BinaryValue{"and", reg_expr(status), constant_expr(0x10, 8)}}),
                                    constant_expr(0x20, 8)}})}}));
                }
                const InstructionOrigin origin{decoded.address, fact->id};
                block.instructions.push_back({origin, std::move(stack_pull)});
                block.instructions.push_back({origin, std::move(statement)});
                continue;
            }
            if (decoded.context.architecture == Architecture::mips64 &&
                (decoded.opcode == Opcode::mips64_tge || decoded.opcode == Opcode::mips64_tgeu ||
                 decoded.opcode == Opcode::mips64_tlt || decoded.opcode == Opcode::mips64_tltu ||
                 decoded.opcode == Opcode::mips64_teq || decoded.opcode == Opcode::mips64_tne ||
                 decoded.opcode == Opcode::mips64_tgei || decoded.opcode == Opcode::mips64_tgeiu ||
                 decoded.opcode == Opcode::mips64_tlti || decoded.opcode == Opcode::mips64_tltiu ||
                 decoded.opcode == Opcode::mips64_teqi || decoded.opcode == Opcode::mips64_tnei ||
                 decoded.opcode == Opcode::mips64_dadd || decoded.opcode == Opcode::mips64_daddi ||
                 decoded.opcode == Opcode::mips64_dsub)) {
                if (const auto *trap = std::get_if<Intrinsic>(&statement);
                    trap && !trap->operands.empty() &&
                    trap->name.find("_conditional_trap") != std::string::npos) {
                    block.trap_edges.push_back({decoded.address, TrapEdgeKind::may_trap,
                                                trap->name, trap->operands.front()});
                }
            }
            block.instructions.push_back({{decoded.address, fact->id}, std::move(statement)});
        }
        result.blocks.push_back(std::move(block));
    }
    if (result.blocks.empty())
        return Error{ErrorCode::invalid_argument, "function has no recovered blocks"};

    // MIPS analysis puts the mandatory delay-slot instruction in its own
    // block, with the eventual branch/call successors attached to that slot.
    // Keep that explicit CFG but order the lifted statements architecturally:
    // execute the slot, then the delayed transfer. A link write remains in
    // the transfer block because MIPS writes it before executing the slot.
    for (auto &source : result.blocks) {
        if (source.instructions.empty()) continue;
        const auto delayed_edge = std::find_if(source.successors.begin(), source.successors.end(),
            [](const BlockSuccessor &edge) { return edge.kind == BlockEdgeKind::delay_slot && edge.target.has_value(); });
        if (delayed_edge == source.successors.end()) continue;
        auto slot = std::find_if(result.blocks.begin(), result.blocks.end(), [&](const LiftedBlock &candidate) {
            return candidate.begin == *delayed_edge->target && (!delayed_edge->block || candidate.id == *delayed_edge->block);
        });
        if (slot == result.blocks.end() || source.instructions.empty()) continue;
        const auto is_transfer = [](const Statement &statement) {
            return std::holds_alternative<Branch>(statement) || std::holds_alternative<Call>(statement) ||
                   std::holds_alternative<Return>(statement);
        };
        if (!is_transfer(source.instructions.back().statement)) continue;
        const auto transfer_origin = source.instructions.back().origin;
        bool likely_branch = false;
        if (const auto source_facts = available.find(source.id.value); source_facts != available.end())
            for (const auto &fact : source_facts->second->instructions)
                if (fact && fact->id == transfer_origin.instruction_id) {
                    likely_branch = mips_branch_likely(fact->instruction.opcode);
                    break;
                }
        if (likely_branch) {
            auto *branch = std::get_if<Branch>(&source.instructions.back().statement);
            if (!branch || !branch->true_target || !branch->false_target)
                return Error{ErrorCode::unsupported,
                             "MIPS branch-likely lifting needs resolved taken and annulled fallthrough edges"};
            const auto delay_edge = std::find_if(source.successors.begin(), source.successors.end(),
                [&](const BlockSuccessor &edge) {
                    return edge.kind == BlockEdgeKind::delay_slot && edge.target == slot->begin &&
                           (!edge.block || edge.block == slot->id);
                });
            const auto taken_edge = std::find_if(slot->successors.begin(), slot->successors.end(),
                [&](const BlockSuccessor &edge) {
                    return edge.target == branch->true_target &&
                           (edge.kind == BlockEdgeKind::conditional_true || edge.kind == BlockEdgeKind::jump);
                });
            if (delay_edge == source.successors.end() || taken_edge == slot->successors.end())
                return Error{ErrorCode::unsupported,
                             "MIPS branch-likely lifting needs an owned slot and resolved post-slot target"};

            // Keep predicate selection in the transfer block: the false edge
            // bypasses the slot entirely. The taken edge enters the slot, and
            // only that block performs the delayed transfer after its effects.
            const auto post_slot_target = *branch->true_target;
            branch->true_target = slot->begin;
            branch->annuls_delay_slot_on_false = true;
            taken_edge->kind = BlockEdgeKind::jump;
            slot->instructions.push_back({transfer_origin, Branch{"true", post_slot_target, {}, {}}});
            continue;
        }
        auto transfer = std::move(source.instructions.back());
        source.instructions.pop_back();
        const auto mark_snapshot = [&](auto &statement) {
            statement.delay_slot_snapshot_block = source.id;
            statement.delay_slot_snapshot_instruction = transfer.origin.instruction_id;
        };
        if (auto *call = std::get_if<Call>(&transfer.statement); call && call->indirect_target)
            mark_snapshot(*call);
        else if (auto *branch = std::get_if<Branch>(&transfer.statement);
                 branch && (branch->predicate || branch->indirect_target))
            mark_snapshot(*branch);
        else if (auto *ret = std::get_if<Return>(&transfer.statement); ret && ret->value)
            mark_snapshot(*ret);
        slot->instructions.push_back(std::move(transfer));
        if (auto *branch = std::get_if<Branch>(&slot->instructions.back().statement)) {
            for (const auto &edge : slot->successors) {
                if (!edge.target) continue;
                if (edge.kind == BlockEdgeKind::conditional_true || edge.kind == BlockEdgeKind::jump)
                    branch->true_target = edge.target;
                else if (edge.kind == BlockEdgeKind::conditional_false || edge.kind == BlockEdgeKind::fallthrough)
                    branch->false_target = edge.target;
            }
        }
    }
    return result;
}

void attach_switch_analysis(LiftedFunction &function, const SwitchAnalysis &analysis) {
    for (const auto &site : analysis.sites) {
        auto block = std::find_if(function.blocks.begin(), function.blocks.end(), [&](const auto &candidate) {
            return std::any_of(candidate.instructions.begin(), candidate.instructions.end(), [&](const auto &item) {
                return item.origin.address == site.dispatch;
            });
        });
        if (block == function.blocks.end()) continue;
        LiftedBlock::SwitchDispatch dispatch;
        dispatch.selector = reg_expr(site.selector);
        dispatch.complete = analysis.complete && site.complete && !site.cases.empty();
        std::set<std::pair<std::uint64_t, std::uint64_t>> table_targets;
        for (const auto &item : site.cases) {
            dispatch.cases.push_back({item.index, item.target});
            table_targets.emplace(item.target.space.value, item.target.offset);
        }
        std::set<std::pair<std::uint64_t, std::uint64_t>> extra_targets;
        for (const auto &edge : block->successors) if (edge.target &&
            !table_targets.contains({edge.target->space.value, edge.target->offset}))
            extra_targets.emplace(edge.target->space.value, edge.target->offset);
        if (dispatch.complete && extra_targets.size() == 1) {
            const auto [space, offset] = *extra_targets.begin();
            dispatch.default_target = Address{{static_cast<std::uint32_t>(space)}, offset};
        } else {
            dispatch.complete = false;
        }
        block->switch_dispatch = std::move(dispatch);
    }
}

std::string x86_stack_effect_text(const X86StackControlEffect &effect) {
    const auto stack_name = effect.stack_pointer.width == 16 ? "SP" :
                            effect.stack_pointer.width == 32 ? "ESP" :
                            effect.stack_pointer.width == 64 ? "RSP" : "stack_pointer";
    std::ostringstream out;
    if (effect.action == X86StackControlAction::push_return_address) {
        out << "near CALL pushes " << effect.value_width << "-bit return address at [";
        if (effect.stack_segment) out << "SS:";
        out << stack_name;
        if (effect.slot_displacement < 0) out << effect.slot_displacement;
        out << "]";
        if (effect.return_address) {
            out << " = ";
            if (effect.return_address->space.value) out << effect.return_address->space.value << ':';
            out << "0x" << std::hex << effect.return_address->offset << std::dec;
        } else {
            out << " = unknown";
        }
        out << " before transfer";
    } else {
        out << "near RET reads " << effect.value_width << "-bit return address from [";
        if (effect.stack_segment) out << "SS:";
        out << stack_name << "] and advances " << stack_name << " by " << effect.value_width / 8;
        if (effect.caller_cleanup_bytes) {
            out << " + " << effect.caller_cleanup_bytes << " caller-cleanup bytes ("
                << effect.value_width / 8 + effect.caller_cleanup_bytes << " bytes total)";
        } else {
            out << " bytes";
        }
    }
    return out.str();
}

namespace {
bool format_register_output_values(std::ostream &out,const Intrinsic &statement){
    if(statement.register_output_values.empty()||statement.register_output_values.size()!=statement.register_writes.size()||
       std::any_of(statement.register_output_values.begin(),statement.register_output_values.end(),[](const auto &value){return !value;}))return false;
    // Output formulas all observe the incoming state. Explicit parallel syntax
    // remains correct for swaps even before the caller requests SSA versions.
    const bool parallel=statement.register_output_values.size()>1;
    if(parallel)out<<"parallel { ";
    for(std::size_t i=0;i<statement.register_output_values.size();++i){
        if(i)out<<' ';
        const auto version=i<statement.register_output_versions.size()
            ?std::optional<std::uint32_t>{statement.register_output_versions[i]}:std::nullopt;
        out<<register_name(statement.register_writes[i],version)<<" = "
           <<expression_text(*statement.register_output_values[i])<<';';
    }
    if(parallel)out<<" }";
    return true;
}
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
                    if (statement.x86_stack_effect) out << " /* " << x86_stack_effect_text(*statement.x86_stack_effect) << " */";
                } else if constexpr (std::is_same_v<T, Branch>) {
                    const auto condition = branch_condition_text(statement);
                    if (statement.condition == "true" && statement.true_target)
                        out << "goto " << address_label(*statement.true_target) << ';';
                    else if (statement.condition == "true" && statement.indirect_target)
                        out << "goto " << expression_text(*statement.indirect_target) << ';';
                    else if (statement.true_target) {
                        out << "if (" << condition << ") goto " << address_label(*statement.true_target);
                        if (statement.false_target)
                            out << " else goto " << address_label(*statement.false_target);
                        out << ';';
                    }
                    else if (statement.indirect_target)
                        out << "if (" << condition << ") goto " << expression_text(*statement.indirect_target) << ';';
                    else out << "branch unresolved;";
                } else if constexpr (std::is_same_v<T, Return>) {
                    out << "return";
                    if (statement.value) out << ' ' << expression_text(*statement.value);
                    out << ';';
                    if (statement.x86_stack_effect) out << " /* " << x86_stack_effect_text(*statement.x86_stack_effect) << " */";
                } else {
                    if(statement.name.starts_with("plugin_scalar_")&&format_register_output_values(out,statement))return;
                    out << statement.name << '(';
                    for (std::size_t i = 0; i < statement.operands.size(); ++i) {
                        if (i) out << ", ";
                        out << expression_text(*statement.operands[i]);
                    }
                    out << ")";
                    if (!statement.register_writes.empty()) {
                        out << " /* writes ";
                        for (std::size_t i = 0; i < statement.register_writes.size(); ++i) {
                            if (i) out << ", ";
                            const auto version = i < statement.register_output_versions.size()
                                ? std::optional<std::uint32_t>{statement.register_output_versions[i]} : std::nullopt;
                            out << register_name(statement.register_writes[i], version);
                        }
                        out << " */";
                    }
                    if (statement.memory_output) {
                        const auto location = statement.memory_output->location_operand;
                        const auto value = statement.memory_output->value_operand;
                        if (location < statement.operands.size() && value < statement.operands.size() &&
                            statement.operands[location] && statement.operands[value])
                            out << " /* memory output: " << expression_text(*statement.operands[location])
                                << " = " << expression_text(*statement.operands[value]) << " */";
                    }
                    out << ';';
                }
            }, instruction.statement);
            out << " // 0x" << std::hex << instruction.origin.address.offset << std::dec << '\n';
        }
        std::set<std::pair<std::uint32_t, std::uint64_t>> emitted_exception_targets;
        for (const auto &edge : block.successors) {
            if (edge.kind != BlockEdgeKind::exception) continue;
            if (edge.target && !emitted_exception_targets.emplace(edge.target->space.value, edge.target->offset).second)
                continue;
            const auto emit_handler = [&](const LiftedBlock::ExceptionHandlerDispatch *handler) {
                out << "    exceptional_successor ";
                if (edge.target) out << address_label(*edge.target); else out << "unresolved";
                if (handler) {
                    if (handler->catch_all) out << " catch_all";
                    else if (handler->catch_type) out << " catch " << *handler->catch_type;
                    else out << " catch <opaque>";
                    if (!handler->protected_throw_sites.empty()) {
                        out << " from ";
                        for (std::size_t i = 0; i < handler->protected_throw_sites.size(); ++i) {
                            if (i) out << ", ";
                            out << address_label(handler->protected_throw_sites[i]);
                        }
                    }
                }
                out << ";\n";
            };
            bool described = false;
            for (const auto &handler : block.exception_handlers) if (edge.target && handler.target == *edge.target) {
                emit_handler(&handler);
                described = true;
            }
            if (!described) emit_handler(nullptr);
        }
    }
    out << "}\n";
    return out.str();
}

StructuredPseudocode format_structured_pseudocode(const LiftedFunction &function) {
    auto fallback = [&](std::string reason) {
        return StructuredPseudocode{format_pseudocode(function), true, std::move(reason)};
    };
    if (std::any_of(function.blocks.begin(), function.blocks.end(), [](const LiftedBlock &block) {
            return std::any_of(block.successors.begin(), block.successors.end(), [](const BlockSuccessor &edge) {
                return edge.kind == BlockEdgeKind::exception;
            });
        }))
        return fallback("exceptional CFG edges are preserved as explicit metadata");
    // A complete switch is a proof that its selector chooses exactly these
    // CFG destinations. Validate that proof once before any shape-specific
    // formatter is allowed to consume it, including a terminal indirect jump.
    // This also bounds all later grouping and post-dominator work.
    const bool has_switches = std::any_of(function.blocks.begin(), function.blocks.end(),
        [](const LiftedBlock &block) { return block.switch_dispatch.has_value(); });
    if (has_switches) {
        // Recover the common flattened-dispatch form only when the dispatcher
        // state is a single register, every route back to the dispatcher
        // assigns a known case value, and that register is otherwise dead.
        // Replacing those edges exposes the original case-to-case CFG to the
        // ordinary structurer below. Anything less exact keeps the lossless
        // state-machine representation.
        auto recover_flattened_dispatch = [&]() -> std::optional<LiftedFunction> {
            const auto count = function.blocks.size();
            if (count < 4 || count > 1024) return {};
            using AddressKey = std::pair<std::uint32_t, std::uint64_t>;
            std::map<AddressKey, std::size_t> by_address;
            std::map<std::uint64_t, std::size_t> by_id;
            std::optional<std::size_t> hub_index;
            for (std::size_t i = 0; i < count; ++i) {
                const auto &block = function.blocks[i];
                if (!by_address.emplace(AddressKey{block.begin.space.value, block.begin.offset}, i).second ||
                    !by_id.emplace(block.id.value, i).second) return {};
                if (block.switch_dispatch) {
                    if (hub_index) return {};
                    hub_index = i;
                }
            }
            if (!hub_index || function.blocks[*hub_index].begin == function.entry) return {};
            const auto &hub = function.blocks[*hub_index];
            const auto &dispatch = *hub.switch_dispatch;
            const auto *selector = dispatch.selector
                ? std::get_if<RegisterValue>(&dispatch.selector->value) : nullptr;
            if (!dispatch.complete || !dispatch.default_target || dispatch.cases.empty() || !selector ||
                selector->reg.high_byte || selector->reg.width == 0) return {};
            const auto state_reg = selector->reg;
            const auto overlaps_state = [&](RegisterOperand reg) {
                return reg.bank == state_reg.bank && reg.index == state_reg.index;
            };
            const auto index_for = [&](Address address) -> std::optional<std::size_t> {
                const auto found = by_address.find({address.space.value, address.offset});
                return found == by_address.end() ? std::nullopt : std::optional<std::size_t>{found->second};
            };
            std::map<std::uint64_t, std::size_t> case_for_value;
            std::set<std::size_t> case_blocks;
            for (const auto &item : dispatch.cases) {
                const auto target = index_for(item.target);
                if (!target || *target == *hub_index || !case_for_value.emplace(item.value, *target).second)
                    return {};
                case_blocks.insert(*target);
            }
            const auto default_index = index_for(*dispatch.default_target);
            if (!default_index || *default_index == *hub_index) return {};

            std::set<std::size_t> dispatch_targets = case_blocks;
            dispatch_targets.insert(*default_index);
            std::set<std::size_t> actual_dispatch_targets;
            for (const auto &edge : hub.successors) {
                if (!edge.target || (edge.kind != BlockEdgeKind::jump && edge.kind != BlockEdgeKind::fallthrough))
                    return {};
                const auto target = index_for(*edge.target);
                if (!target || (edge.block && edge.block != function.blocks[*target].id) ||
                    !actual_dispatch_targets.insert(*target).second) return {};
            }
            if (dispatch_targets != actual_dispatch_targets) return {};
            std::size_t hub_branches = 0;
            for (std::size_t n = 0; n < hub.instructions.size(); ++n) {
                const auto *branch = std::get_if<Branch>(&hub.instructions[n].statement);
                const auto *indirect_register = branch && branch->indirect_target
                    ? std::get_if<RegisterValue>(&branch->indirect_target->value) : nullptr;
                if (!branch || ++hub_branches != 1 || n + 1 != hub.instructions.size() ||
                    branch->condition != "true" || branch->true_target || branch->false_target ||
                    branch->predicate || !indirect_register || *indirect_register != *selector) return {};
            }

            const auto expression_reads_state = [&](const ExpressionPtr &root) {
                std::function<bool(const ExpressionPtr &)> visit = [&](const ExpressionPtr &node) {
                    if (!node) return false;
                    return std::visit([&](const auto &value) -> bool {
                        using T = std::decay_t<decltype(value)>;
                        if constexpr (std::is_same_v<T, RegisterValue>) return overlaps_state(value.reg);
                        else if constexpr (std::is_same_v<T, MemoryValue>)
                            return (value.base && overlaps_state(*value.base)) ||
                                   (value.index && overlaps_state(*value.index));
                        else if constexpr (std::is_same_v<T, UnaryValue>) return visit(value.operand);
                        else if constexpr (std::is_same_v<T, BinaryValue>)
                            return visit(value.left) || visit(value.right);
                        else return false;
                    }, node->value);
                };
                return visit(root);
            };
            std::vector<std::optional<std::uint64_t>> state_constants(count);
            std::vector<std::optional<std::size_t>> state_assignments(count);
            std::vector<std::vector<std::size_t>> predecessors(count);
            std::size_t edge_count = 0;
            for (std::size_t i = 0; i < count; ++i) {
                const auto &block = function.blocks[i];
                if (block.successors.size() > 4096 - edge_count) return {};
                edge_count += block.successors.size();
                for (const auto &edge : block.successors) {
                    if (!edge.target) return {};
                    const auto target = index_for(*edge.target);
                    if (!target || (edge.block && edge.block != function.blocks[*target].id)) return {};
                    predecessors[*target].push_back(i);
                }
                for (std::size_t n = 0; n < block.instructions.size(); ++n) {
                    const auto &instruction = block.instructions[n];
                    bool reads_state = false;
                    bool writes_state = false;
                    std::visit([&](const auto &statement) {
                        using T = std::decay_t<decltype(statement)>;
                        if constexpr (std::is_same_v<T, Assign>) {
                            reads_state = expression_reads_state(statement.value);
                            writes_state = overlaps_state(statement.destination);
                            if (writes_state) {
                                if (statement.destination != state_reg || state_assignments[i]) {
                                    state_constants[i].reset();
                                    state_assignments[i] = block.instructions.size();
                                    return;
                                }
                                const auto *constant = statement.value
                                    ? std::get_if<ConstantValue>(&statement.value->value) : nullptr;
                                if (!constant || (constant->type.bits && constant->type.bits != state_reg.width)) {
                                    state_constants[i].reset();
                                    state_assignments[i] = block.instructions.size();
                                    return;
                                }
                                state_constants[i] = constant->value;
                                state_assignments[i] = n;
                            }
                        } else if constexpr (std::is_same_v<T, Store>) {
                            reads_state = expression_reads_state(statement.address) ||
                                          expression_reads_state(statement.value);
                        } else if constexpr (std::is_same_v<T, Call>) {
                            reads_state = expression_reads_state(statement.indirect_target) ||
                                std::any_of(statement.register_inputs.begin(), statement.register_inputs.end(),
                                    [&](RegisterValue value) { return overlaps_state(value.reg); });
                            writes_state = std::any_of(statement.register_writes.begin(),
                                statement.register_writes.end(), overlaps_state);
                        } else if constexpr (std::is_same_v<T, Branch>) {
                            reads_state = expression_reads_state(statement.predicate) ||
                                          expression_reads_state(statement.indirect_target);
                        } else if constexpr (std::is_same_v<T, Return>) {
                            reads_state = expression_reads_state(statement.value);
                        } else if constexpr (std::is_same_v<T, Intrinsic>) {
                            reads_state = std::any_of(statement.operands.begin(), statement.operands.end(),
                                    expression_reads_state) ||
                                std::any_of(statement.register_output_values.begin(),
                                    statement.register_output_values.end(), expression_reads_state);
                            writes_state = std::any_of(statement.register_writes.begin(),
                                statement.register_writes.end(), overlaps_state);
                        }
                    }, instruction.statement);
                    if (reads_state && i != *hub_index) return {};
                    // Calls and intrinsics are opaque state updates even when
                    // an explicit output list happens to name the dispatcher
                    // register. Only the single constant Assign above can be
                    // erased as a proven dispatcher-state write.
                    if (writes_state && !std::holds_alternative<Assign>(instruction.statement)) return {};
                    if (writes_state && !state_assignments[i]) return {};
                    if (writes_state && state_assignments[i] && n > *state_assignments[i]) return {};
                }
                if (i == *hub_index && state_assignments[i]) return {};
            }

            const auto entry_index = index_for(function.entry);
            if (!entry_index || *entry_index == *hub_index ||
                predecessors[*hub_index].empty() || !state_constants[*entry_index] ||
                std::find_if(function.blocks[*entry_index].successors.begin(),
                    function.blocks[*entry_index].successors.end(), [&](const auto &edge) {
                        return edge.target == std::optional<Address>{hub.begin};
                    }) == function.blocks[*entry_index].successors.end()) return {};
            for (std::size_t i = 0; i < count; ++i) {
                const auto &block = function.blocks[i];
                const auto to_hub = std::count_if(block.successors.begin(), block.successors.end(),
                    [&](const auto &edge) { return edge.target == std::optional<Address>{hub.begin}; });
                if (i == *hub_index) continue;
                if (to_hub > 0 && (to_hub != 1 || block.successors.size() != 1 ||
                    !state_constants[i] || !state_assignments[i] || !case_for_value.contains(*state_constants[i])))
                    return {};
                if (state_assignments[i] && to_hub == 0) return {};
            }
            for (const auto predecessor : predecessors[*hub_index])
                if (predecessor == *hub_index || !state_assignments[predecessor]) return {};

            LiftedFunction recovered = function;
            recovered.blocks.erase(recovered.blocks.begin() + static_cast<std::ptrdiff_t>(*hub_index));
            const auto initial_target = case_for_value.find(*state_constants[*entry_index]);
            if (initial_target == case_for_value.end()) return {};
            for (auto &block : recovered.blocks) {
                std::optional<Address> transition_target;
                std::optional<BlockId> transition_id;
                const auto original_index = by_id.find(block.id.value)->second;
                if (state_assignments[original_index]) {
                    const auto next = case_for_value.find(*state_constants[original_index]);
                    if (next == case_for_value.end()) return {};
                    transition_target = function.blocks[next->second].begin;
                    transition_id = function.blocks[next->second].id;
                    block.instructions.erase(std::remove_if(block.instructions.begin(), block.instructions.end(),
                        [&](const auto &instruction) {
                            const auto *assign = std::get_if<Assign>(&instruction.statement);
                            return assign && overlaps_state(assign->destination);
                        }), block.instructions.end());
                }
                for (auto &edge : block.successors) {
                    if (edge.target == std::optional<Address>{hub.begin}) {
                        if (!transition_target) return {};
                        edge.target = transition_target;
                        edge.block = transition_id;
                    }
                }
                for (auto &instruction : block.instructions) {
                    auto *branch = std::get_if<Branch>(&instruction.statement);
                    if (!branch) continue;
                    if (branch->true_target == std::optional<Address>{hub.begin}) {
                        if (!transition_target || branch->condition != "true" || branch->false_target ||
                            branch->indirect_target) return {};
                        branch->true_target = transition_target;
                    }
                    if (branch->false_target == std::optional<Address>{hub.begin}) return {};
                }
            }

            std::map<AddressKey, std::size_t> recovered_addresses;
            for (std::size_t i = 0; i < recovered.blocks.size(); ++i)
                recovered_addresses.emplace(AddressKey{recovered.blocks[i].begin.space.value,
                                                        recovered.blocks[i].begin.offset}, i);
            const auto recovered_entry = recovered_addresses.find({recovered.entry.space.value,
                                                                     recovered.entry.offset});
            if (recovered_entry == recovered_addresses.end()) return {};
            std::vector<bool> reachable(recovered.blocks.size(), false);
            std::vector<std::size_t> pending{recovered_entry->second};
            while (!pending.empty()) {
                const auto current = pending.back();
                pending.pop_back();
                if (reachable[current]) continue;
                reachable[current] = true;
                for (const auto &edge : recovered.blocks[current].successors) {
                    if (!edge.target) return {};
                    const auto target = recovered_addresses.find({edge.target->space.value, edge.target->offset});
                    if (target == recovered_addresses.end() ||
                        (edge.block && edge.block != recovered.blocks[target->second].id)) return {};
                    pending.push_back(target->second);
                }
            }
            LiftedFunction pruned = recovered;
            pruned.blocks.clear();
            for (std::size_t i = 0; i < recovered.blocks.size(); ++i)
                if (reachable[i]) pruned.blocks.push_back(recovered.blocks[i]);
            return pruned;
        };
        if (auto recovered = recover_flattened_dispatch()) {
            auto rebuilt_ssa = to_ssa(*recovered);
            if (rebuilt_ssa) {
                auto structured = format_structured_pseudocode(rebuilt_ssa.value());
                if (!structured.used_fallback) return structured;
            }
        }
        if (function.blocks.size() > 1024)
            return fallback("switch structuring exceeds the block limit");
        std::map<std::pair<std::uint32_t, std::uint64_t>, const LiftedBlock *> blocks_by_address;
        std::set<std::uint64_t> ids;
        for (const auto &block : function.blocks)
            if (!blocks_by_address.emplace(std::pair{block.begin.space.value, block.begin.offset}, &block).second ||
                !ids.insert(block.id.value).second)
                return fallback("switch CFG contains duplicate block identities");
        std::size_t case_count = 0;
        std::size_t edge_count = 0;
        for (const auto &block : function.blocks) {
            if (block.successors.size() > 4096 - edge_count)
                return fallback("switch structuring exceeds the edge limit");
            edge_count += block.successors.size();
            if (!block.switch_dispatch) continue;
            const auto &dispatch = *block.switch_dispatch;
            if (!dispatch.complete || !dispatch.selector || dispatch.cases.empty() || !dispatch.default_target)
                return fallback("switch dispatch metadata is incomplete");
            if (dispatch.cases.size() > 4096 - case_count)
                return fallback("switch structuring exceeds the case limit");
            case_count += dispatch.cases.size();
            std::set<std::uint64_t> labels;
            std::set<std::pair<std::uint32_t, std::uint64_t>> targets, cfg_targets;
            for (const auto &item : dispatch.cases) {
                if (!labels.insert(item.value).second)
                    return fallback("switch metadata contains duplicate case values");
                targets.emplace(item.target.space.value, item.target.offset);
            }
            targets.emplace(dispatch.default_target->space.value, dispatch.default_target->offset);
            for (const auto &edge : block.successors) {
                if (!edge.target || (edge.kind != BlockEdgeKind::jump && edge.kind != BlockEdgeKind::fallthrough))
                    return fallback("switch has an unresolved or unsupported CFG edge");
                const auto key = std::pair{edge.target->space.value, edge.target->offset};
                const auto target = blocks_by_address.find(key);
                if (target == blocks_by_address.end() || (edge.block && edge.block != target->second->id) ||
                    !cfg_targets.insert(key).second)
                    return fallback("switch CFG destination is missing, duplicated, or mismatched");
            }
            if (targets != cfg_targets)
                return fallback("switch metadata does not match its CFG destinations");
            std::size_t branches = 0;
            for (std::size_t i = 0; i < block.instructions.size(); ++i) {
                if (std::holds_alternative<Return>(block.instructions[i].statement))
                    return fallback("switch dispatch also contains a return");
                const auto *transfer = std::get_if<Branch>(&block.instructions[i].statement);
                if (!transfer) continue;
                if (++branches > 1 || i + 1 != block.instructions.size() || transfer->condition != "true" ||
                    transfer->true_target || transfer->false_target || transfer->predicate)
                    return fallback("switch dispatch contains a conflicting transfer");
            }
        }
        std::map<std::uint64_t, std::set<std::uint64_t>> predecessor_ids;
        for (const auto &block : function.blocks) {
            std::set<std::uint64_t> seen_targets;
            for (const auto &edge : block.successors) {
                if (!edge.target) return fallback("switch CFG contains an unresolved edge");
                const auto target = blocks_by_address.find({edge.target->space.value, edge.target->offset});
                if (target == blocks_by_address.end() || (edge.block && edge.block != target->second->id) ||
                    !seen_targets.insert(target->second->id.value).second)
                    return fallback("switch CFG contains a missing, duplicated, or mismatched edge");
                predecessor_ids[target->second->id.value].insert(block.id.value);
            }
        }
        std::size_t phi_inputs = 0;
        for (const auto &block : function.blocks) {
            if (block.begin == function.entry && (!block.phis.empty() || block.memory_phi))
                return fallback("switch entry phis have no initial predecessor edge");
            const auto &predecessors = predecessor_ids[block.id.value];
            const auto valid_phi = [&](const auto &phi) {
                if (phi.inputs.size() != predecessors.size() || phi.inputs.size() > 65536 - phi_inputs)
                    return false;
                phi_inputs += phi.inputs.size();
                std::set<std::uint64_t> seen;
                for (const auto &input : phi.inputs)
                    if (!predecessors.contains(input.predecessor.value) || !seen.insert(input.predecessor.value).second)
                        return false;
                return true;
            };
            if (block.phis.size() > 4096 ||
                std::any_of(block.phis.begin(), block.phis.end(), [&](const auto &phi) { return !valid_phi(phi); }) ||
                (block.memory_phi && !valid_phi(*block.memory_phi)))
                return fallback("switch CFG phi inputs are incomplete or exceed the limit");
        }
    }
    if (std::any_of(function.blocks.begin(), function.blocks.end(), [](const LiftedBlock &block) {
        return std::any_of(block.instructions.begin(), block.instructions.end(), [&block](const LiftedInstruction &instruction) {
            const auto *branch = std::get_if<Branch>(&instruction.statement);
            return branch && branch->indirect_target && !block.switch_dispatch;
        });
    }))
        return fallback("indirect branch targets use the explicit goto representation");
    std::ostringstream out;
    std::ostream *statement_output = &out;
    auto emit_statement = [&](const LiftedInstruction &instruction, bool omit_branch, unsigned indent) {
        if (omit_branch && std::holds_alternative<Branch>(instruction.statement)) return;
        auto &stream = *statement_output;
        stream << std::string(indent, ' ');
        std::visit([&](const auto &statement) {
            using T = std::decay_t<decltype(statement)>;
            if constexpr (std::is_same_v<T, Assign>) stream << register_name(statement.destination, statement.destination_version)
                << " = " << expression_text(*statement.value) << ';';
            else if constexpr (std::is_same_v<T, Store>) stream << expression_text(*statement.address) << " = "
                << expression_text(*statement.value) << ';';
            else if constexpr (std::is_same_v<T, Call>) {
                if (statement.direct_target) stream << "call " << address_label(*statement.direct_target) << "();";
                else if (statement.indirect_target) stream << "call " << expression_text(*statement.indirect_target) << "();";
                else stream << "call unresolved();";
                if (statement.x86_stack_effect) stream << " /* " << x86_stack_effect_text(*statement.x86_stack_effect) << " */";
            } else if constexpr (std::is_same_v<T, Return>) {
                stream << "return"; if (statement.value) stream << ' ' << expression_text(*statement.value); stream << ';';
                if (statement.x86_stack_effect) stream << " /* " << x86_stack_effect_text(*statement.x86_stack_effect) << " */";
            } else if constexpr (std::is_same_v<T, Intrinsic>) {
                if(statement.name.starts_with("plugin_scalar_")&&format_register_output_values(stream,statement))return;
                if (statement.name.starts_with("wasm_call_function_") && statement.register_writes.size() == 1) {
                    const auto version = statement.register_output_versions.empty()
                        ? std::optional<std::uint32_t>{} : std::optional<std::uint32_t>{statement.register_output_versions.front()};
                    stream << register_name(statement.register_writes.front(), version) << " = " << statement.name << '(';
                    for (std::size_t i = 0; i < statement.operands.size(); ++i) {
                        if (i) stream << ", ";
                        stream << expression_text(*statement.operands[i]);
                    }
                    stream << ");";
                    return;
                }
                if (!statement.register_output_values.empty() &&
                    statement.register_output_values.size() == statement.register_writes.size()) {
                    for (std::size_t i = 0; i < statement.register_output_values.size(); ++i) {
                        if (i) stream << "; ";
                        const auto version = i < statement.register_output_versions.size()
                            ? std::optional<std::uint32_t>{statement.register_output_versions[i]} : std::nullopt;
                        stream << register_name(statement.register_writes[i], version) << " = "
                               << expression_text(*statement.register_output_values[i]);
                    }
                    if (statement.x87_stack_delta > 0)
                        stream << " /* x87 push " << static_cast<unsigned>(statement.x87_stack_delta) << " */";
                    else if (statement.x87_stack_delta < 0)
                        stream << " /* x87 pop " << static_cast<unsigned>(-statement.x87_stack_delta) << " */";
                    stream << ';';
                    return;
                }
                stream << statement.name << '(';
                for (std::size_t i = 0; i < statement.operands.size(); ++i) {
                    if (i) stream << ", "; stream << expression_text(*statement.operands[i]);
                }
                stream << ")";
                if (statement.x87_stack_delta > 0)
                    stream << " /* x87 push " << static_cast<unsigned>(statement.x87_stack_delta) << " */";
                else if (statement.x87_stack_delta < 0)
                    stream << " /* x87 pop " << static_cast<unsigned>(-statement.x87_stack_delta) << " */";
                if (!statement.register_writes.empty()) {
                    stream << " /* writes ";
                    for (std::size_t i = 0; i < statement.register_writes.size(); ++i) {
                        if (i) stream << ", ";
                        const auto version = i < statement.register_output_versions.size()
                            ? std::optional<std::uint32_t>{statement.register_output_versions[i]} : std::nullopt;
                        stream << register_name(statement.register_writes[i], version);
                    }
                    stream << " */";
                }
                stream << ';';
            } else stream << "/* branch */";
        }, instruction.statement);
        stream << " // 0x" << std::hex << instruction.origin.address.offset << std::dec << '\n';
    };
    auto emit_block = [&](const LiftedBlock &block, unsigned indent, bool omit_terminal_branch = false) {
        for (std::size_t i = 0; i < block.instructions.size(); ++i) {
            const bool omit = omit_terminal_branch && i + 1 == block.instructions.size() &&
                std::holds_alternative<Branch>(block.instructions[i].statement);
            emit_statement(block.instructions[i], omit, indent);
        }
    };
    std::size_t phi_temporary = 0;
    const auto emit_parallel_copies = [&](std::ostream &stream,
        const std::vector<std::pair<std::string, std::string>> &copies, unsigned indent) {
        const std::string spaces(indent, ' ');
        if (copies.size() > 1) {
            std::vector<std::string> temporaries;
            for (const auto &[destination, source] : copies) {
                (void)destination;
                auto temporary = "__hexlab_phi_" + std::to_string(phi_temporary++);
                stream << spaces << "auto " << temporary << " = " << source << ";\n";
                temporaries.push_back(std::move(temporary));
            }
            for (std::size_t n = 0; n < copies.size(); ++n)
                stream << spaces << copies[n].first << " = " << temporaries[n] << ";\n";
        } else if (!copies.empty()) {
            stream << spaces << copies.front().first << " = " << copies.front().second << ";\n";
        }
    };
    auto find_block = [&](Address address) -> const LiftedBlock * {
        const auto found = std::find_if(function.blocks.begin(), function.blocks.end(),
            [&](const LiftedBlock &block) { return block.begin == address; });
        return found == function.blocks.end() ? nullptr : &*found;
    };
    auto edge_targets = [&](const BlockSuccessor &edge, Address target) {
        if (edge.target != std::optional<Address>{target}) return false;
        const auto *target_block = find_block(target);
        return target_block && (!edge.block || edge.block == target_block->id);
    };
    auto conditional_edges_match_targets = [&](const LiftedBlock &block, const Branch &branch) {
        if (!branch.true_target || !branch.false_target ||
            *branch.true_target == *branch.false_target || block.successors.size() != 2) return false;
        const bool has_true = std::any_of(block.successors.begin(), block.successors.end(), [&](const auto &edge) {
            return (edge.kind == BlockEdgeKind::conditional_true ||
                    (branch.annuls_delay_slot_on_false && edge.kind == BlockEdgeKind::delay_slot)) &&
                   edge_targets(edge, *branch.true_target);
        });
        const bool has_false = std::any_of(block.successors.begin(), block.successors.end(), [&](const auto &edge) {
            return (edge.kind == BlockEdgeKind::conditional_false || edge.kind == BlockEdgeKind::fallthrough) &&
                edge_targets(edge, *branch.false_target);
        });
        return has_true && has_false;
    };
    struct SwitchArmGroup {
        Address target;
        std::vector<std::uint64_t> values;
        bool is_default = false;
    };
    const auto group_switch_arms = [](const LiftedBlock::SwitchDispatch &dispatch) {
        std::vector<SwitchArmGroup> groups;
        std::map<std::pair<std::uint32_t, std::uint64_t>, std::size_t> indices;
        const auto group_for = [&](Address target) -> SwitchArmGroup & {
            const auto key = std::pair{target.space.value, target.offset};
            const auto [found, inserted] = indices.emplace(key, groups.size());
            if (inserted) groups.push_back({target, {}, false});
            return groups[found->second];
        };
        for (const auto &item : dispatch.cases) group_for(item.target).values.push_back(item.value);
        group_for(*dispatch.default_target).is_default = true;
        return groups;
    };
    auto terminal_conditional = [&](const LiftedBlock &block) -> const Branch * {
        if (block.instructions.empty() ||
            !std::holds_alternative<Branch>(block.instructions.back().statement)) return nullptr;
        const auto count = std::count_if(block.instructions.begin(), block.instructions.end(),
            [](const LiftedInstruction &item) { return std::holds_alternative<Branch>(item.statement); });
        const auto &branch = std::get<Branch>(block.instructions.back().statement);
        if (count != 1 || branch.condition == "true" ||
            !conditional_edges_match_targets(block, branch)) return nullptr;
        return &branch;
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

    // A nested early-return arm may rejoin its outer sibling at a later
    // conditional (rather than at a terminal return). Emit the early return
    // as a guarded exit, then emit the shared conditional once after the outer
    // region. This avoids both duplicated side effects and a goto fallback.
    // Keep this recognizer deliberately narrow: the shared conditional must
    // lead directly to two terminal returns and the sibling must be a single
    // straight-line block.
    if (function.blocks.size() == 7 && entry->phis.empty() && terminal_conditional(*entry)) {
        const auto *outer = terminal_conditional(*entry);
        const LiftedBlock *nested = nullptr;
        const LiftedBlock *sibling = nullptr;
        for (const auto &edge : entry->successors) {
            const auto *target = edge.target ? find_block(*edge.target) : nullptr;
            if (target && terminal_conditional(*target)) {
                if (nested) { nested = nullptr; break; }
                nested = target;
            } else sibling = target;
        }
        if (nested && sibling && sibling->phis.empty() && !contains_branch(*sibling) &&
            !contains_return(*sibling) && sibling->successors.size() == 1) {
            const auto *inner = terminal_conditional(*nested);
            const auto *continuation = sibling->successors.front().target
                ? find_block(*sibling->successors.front().target) : nullptr;
            if (inner && continuation && terminal_conditional(*continuation) &&
                continuation->phis.empty() && continuation->successors.size() == 2 &&
                nested->phis.empty()) {
                const auto *inner_true = find_block(*inner->true_target);
                const auto *inner_false = find_block(*inner->false_target);
                const auto *shared = terminal_conditional(*continuation);
                const auto *shared_true = find_block(*shared->true_target);
                const auto *shared_false = find_block(*shared->false_target);
                const auto is_return = [&](const LiftedBlock *candidate) {
                    return candidate && candidate->phis.empty() && has_only_terminal_return(*candidate);
                };
                const bool true_continues = inner_true == continuation && is_return(inner_false);
                const bool false_continues = inner_false == continuation && is_return(inner_true);
                const auto expected_outer_sibling = std::find_if(entry->successors.begin(), entry->successors.end(),
                    [&](const auto &edge) { return edge.target == std::optional<Address>{sibling->begin}; });
                const auto nested_edge = std::find_if(entry->successors.begin(), entry->successors.end(),
                    [&](const auto &edge) { return edge.target == std::optional<Address>{nested->begin}; });
                const bool sibling_is_outer_false = expected_outer_sibling != entry->successors.end() &&
                    (expected_outer_sibling->kind == BlockEdgeKind::conditional_false ||
                     expected_outer_sibling->kind == BlockEdgeKind::fallthrough);
                const bool nested_is_outer_true = nested_edge != entry->successors.end() &&
                    nested_edge->kind == BlockEdgeKind::conditional_true;
                const std::set<const LiftedBlock *> expected_blocks{
                    entry, nested, sibling, continuation,
                    true_continues ? inner_false : inner_true, shared_true, shared_false};
                const bool unique_shape = expected_blocks.size() == function.blocks.size();
                if ((true_continues || false_continues) && is_return(shared_true) && is_return(shared_false) &&
                    sibling_is_outer_false && nested_is_outer_true && unique_shape &&
                    shared_true != shared_false && continuation != sibling) {
                    const auto *early_return = true_continues ? inner_false : inner_true;
                    const auto *return_arm = shared_true;
                    const auto *other_return_arm = shared_false;
                    const auto shared_reaches = [&](const LiftedBlock *source, const LiftedBlock *target,
                                                    BlockEdgeKind kind) {
                        return std::any_of(source->successors.begin(), source->successors.end(),
                            [&](const auto &edge) {
                                return edge.kind == kind && edge_targets(edge, target->begin);
                            });
                    };
                    const bool valid_edges = sibling->successors.front().kind == BlockEdgeKind::jump &&
                        edge_targets(sibling->successors.front(), continuation->begin) &&
                        shared_reaches(continuation, return_arm, BlockEdgeKind::conditional_true) &&
                        (shared_reaches(continuation, other_return_arm, BlockEdgeKind::conditional_false) ||
                         shared_reaches(continuation, other_return_arm, BlockEdgeKind::fallthrough));
                    if (valid_edges) {
                        emit_block(*entry, 4, true);
                        out << "    if (" << branch_condition_text(*outer) << ") {\n";
                        emit_block(*nested, 8, true);
                        const auto early_condition = branch_condition_text(*inner);
                        out << "        if (" << (true_continues ? "!(" + early_condition + ")" : early_condition)
                            << ") {\n";
                        emit_block(*early_return, 12);
                        out << "        }\n";
                        out << "    } else {\n";
                        emit_block(*sibling, 8);
                        out << "    }\n";
                        emit_block(*continuation, 4, true);
                        out << "    if (" << branch_condition_text(*shared) << ") {\n";
                        emit_block(*shared_true, 8);
                        out << "    } else {\n";
                        emit_block(*shared_false, 8);
                        out << "    }\n}\n";
                        return {out.str(), false, {}};
                    }
                }
            }
        }
    }

    // A recovered switch may follow a straight-line setup chain from the
    // function entry. Keep this recognizer bounded and require every prefix
    // block to have one proven successor; ambiguous control flow falls back.
    std::vector<const LiftedBlock *> switch_prefix;
    const LiftedBlock *switch_entry = entry->switch_dispatch ? entry : nullptr;
    const Branch *switch_guard = nullptr;
    const LiftedBlock *switch_guard_return = nullptr;
    bool switch_guard_return_on_true = false;
    if (!switch_entry) {
        std::set<std::uint64_t> visited{entry->id.value};
        const LiftedBlock *current = entry;
        for (std::size_t steps = 0; steps < function.blocks.size(); ++steps) {
            if (current->phis.size() || current->successors.size() != 1 ||
                !current->successors.front().target)
                break;
            if (contains_branch(*current)) {
                if (current->instructions.empty() ||
                    !std::holds_alternative<Branch>(current->instructions.back().statement))
                    break;
                const auto &transfer = std::get<Branch>(current->instructions.back().statement);
                if (transfer.condition != "true" || transfer.false_target ||
                    transfer.true_target != current->successors.front().target)
                    break;
            }
            const auto *next = find_block(*current->successors.front().target);
            if (!next || !visited.insert(next->id.value).second)
                break;
            switch_prefix.push_back(current);
            current = next;
            if (current->switch_dispatch) {
                switch_entry = current;
                break;
            }
        }
        if (!switch_entry)
            switch_prefix.clear();
    }
    if (!switch_entry) {
        const auto *guard = terminal_conditional(*entry);
        const auto *guard_true = guard ? find_block(*guard->true_target) : nullptr;
        const auto *guard_false = guard ? find_block(*guard->false_target) : nullptr;
        for (const bool return_on_true : {true, false}) {
            const auto *return_block = return_on_true ? guard_true : guard_false;
            auto *current = return_on_true ? guard_false : guard_true;
            if (!guard || !entry->phis.empty() || !return_block || !current ||
                return_block == current || !return_block->phis.empty() ||
                !has_only_terminal_return(*return_block)) continue;
            std::vector<const LiftedBlock *> prefix;
            std::set<std::uint64_t> visited{entry->id.value};
            bool valid = true;
            for (std::size_t steps = 0; current && !current->switch_dispatch &&
                 steps < function.blocks.size(); ++steps) {
                if (!visited.insert(current->id.value).second || !current->phis.empty() ||
                    current->successors.size() != 1 || !current->successors.front().target ||
                    contains_return(*current)) { valid = false; break; }
                const auto &edge = current->successors.front();
                if (edge.kind != BlockEdgeKind::jump && edge.kind != BlockEdgeKind::fallthrough) {
                    valid = false; break;
                }
                const auto *next = find_block(*edge.target);
                if (!next || (edge.block && edge.block != next->id)) { valid = false; break; }
                const auto branch_count = std::count_if(current->instructions.begin(), current->instructions.end(),
                    [](const auto &instruction) { return std::holds_alternative<Branch>(instruction.statement); });
                if (branch_count > 1 || (branch_count == 1 &&
                    (!std::holds_alternative<Branch>(current->instructions.back().statement) ||
                     std::get<Branch>(current->instructions.back().statement).condition != "true" ||
                     std::get<Branch>(current->instructions.back().statement).true_target != edge.target ||
                     std::get<Branch>(current->instructions.back().statement).false_target))) {
                    valid = false; break;
                }
                prefix.push_back(current);
                current = next;
            }
            if (valid && current && current->switch_dispatch) {
                switch_guard = guard;
                switch_guard_return = return_block;
                switch_guard_return_on_true = return_on_true;
                switch_prefix = std::move(prefix);
                switch_entry = current;
                break;
            }
        }
    }

    // Recovered switch metadata is accepted only when every case/default
    // destination agrees with the CFG. Linear arms may terminate separately
    // or converge on one common return join. Phi assignments are emitted on
    // the actual incoming edges before each generated break.
    auto try_entry_switch = [&]() -> std::optional<StructuredPseudocode> {
        if (!switch_entry) return {};
        const auto &dispatch = *switch_entry->switch_dispatch;
        if (!dispatch.complete || !dispatch.selector || dispatch.cases.empty() || !dispatch.default_target)
            return {};
        std::set<std::uint64_t> values;
        std::set<std::pair<std::uint64_t, std::uint64_t>> targets;
        auto add_target = [&](Address address) {
            targets.emplace(address.space.value, address.offset);
        };
        for (const auto &item : dispatch.cases) {
            if (!values.insert(item.value).second) return {};
            add_target(item.target);
        }
        add_target(*dispatch.default_target);
        std::set<std::pair<std::uint64_t, std::uint64_t>> cfg_targets;
        for (const auto &edge : switch_entry->successors) {
            if (!edge.target || !find_block(*edge.target)) return {};
            cfg_targets.emplace(edge.target->space.value, edge.target->offset);
        }
        if (cfg_targets != targets || function.blocks.size() < targets.size() + switch_prefix.size() + 1 ||
            function.blocks.size() > 1024 || !switch_entry->phis.empty())
            return {};
        std::vector<std::vector<const LiftedBlock *>> paths;
        for (const auto &target : targets) {
            const LiftedBlock *current = nullptr;
            for (const auto &block : function.blocks)
                if (block.begin.space.value == target.first && block.begin.offset == target.second) {
                    current = &block;
                    break;
                }
            if (!current || current == switch_entry)
                return {};
            std::vector<const LiftedBlock *> path;
            std::set<std::uint64_t> visited;
            for (std::size_t steps = 0; steps < function.blocks.size(); ++steps) {
                if (switch_guard && (current == entry || current == switch_guard_return ||
                    std::any_of(switch_prefix.begin(), switch_prefix.end(), [&](const auto *prefix_block) {
                        return current == prefix_block;
                    })))
                    return {};
                if (!visited.insert(current->id.value).second || current->switch_dispatch)
                    return {};
                path.push_back(current);
                if (has_only_terminal_return(*current)) break;
                if (contains_return(*current) || current->successors.size() != 1 ||
                    !current->successors.front().target)
                    return {};
                const auto next_address = *current->successors.front().target;
                const auto *next = find_block(next_address);
                if (!next || next == switch_entry)
                    return {};
                const auto branch_count = std::count_if(current->instructions.begin(), current->instructions.end(),
                    [](const auto &instruction) { return std::holds_alternative<Branch>(instruction.statement); });
                if (branch_count > 1 || (branch_count == 1 &&
                    (!std::holds_alternative<Branch>(current->instructions.back().statement) ||
                     std::get<Branch>(current->instructions.back().statement).condition != "true" ||
                     std::get<Branch>(current->instructions.back().statement).true_target !=
                        std::optional<Address>{next_address} ||
                     std::get<Branch>(current->instructions.back().statement).false_target)))
                    return {};
                current = next;
            }
            if (path.empty() || !has_only_terminal_return(*path.back()))
                return {};
            paths.push_back(std::move(path));
        }
        std::map<std::uint64_t, std::size_t> path_use_count;
        std::set<std::uint64_t> covered_blocks{switch_entry->id.value};
        for (const auto *block : switch_prefix)
            covered_blocks.insert(block->id.value);
        if (switch_guard) {
            covered_blocks.insert(entry->id.value);
            covered_blocks.insert(switch_guard_return->id.value);
        }
        for (const auto &path : paths)
            for (const auto *block : path) {
                ++path_use_count[block->id.value];
                covered_blocks.insert(block->id.value);
            }
        std::vector<const LiftedBlock *> shared_suffix;
        std::vector<std::size_t> shared_suffix_begin(paths.size(), 0);
        if (!paths.empty()) {
            for (std::size_t index = 0; index < paths.front().size(); ++index) {
                if (path_use_count[paths.front()[index]->id.value] <= 1) continue;
                shared_suffix_begin[0] = index;
                shared_suffix.assign(paths.front().begin() + static_cast<std::ptrdiff_t>(index), paths.front().end());
                break;
            }
        }
        const bool terminal_arms = shared_suffix.empty();
        if (!terminal_arms) {
            for (std::size_t path_index = 0; path_index < paths.size(); ++path_index) {
                const auto &path = paths[path_index];
                const auto first = std::find_if(path.begin(), path.end(), [&](const auto *block) {
                    return path_use_count[block->id.value] > 1;
                });
                if (first == path.end()) return {};
                const auto begin = static_cast<std::size_t>(std::distance(path.begin(), first));
                if (path.size() - begin != shared_suffix.size()) return {};
                shared_suffix_begin[path_index] = begin;
                for (std::size_t suffix_index = 0; suffix_index < shared_suffix.size(); ++suffix_index)
                    if (path[begin + suffix_index]->id != shared_suffix[suffix_index]->id) return {};
            }
            if (shared_suffix.front() == switch_entry) return {};
        } else if (std::any_of(paths.begin(), paths.end(), [&](const auto &path) {
                       return std::any_of(path.begin(), path.end(), [&](const auto *block) {
                           return path_use_count[block->id.value] != 1;
                       });
                   })) {
            return {};
        }

        // Each arm is a proven linear path. Derive its exact incoming-edge set
        // and lower every register phi on that edge, including phis before the
        // shared suffix and in its later blocks. A malformed or extra input
        // keeps the lossless fallback instead of inventing a merge value.
        using PhiEdge = std::pair<std::uint64_t, std::uint64_t>;
        std::map<std::uint64_t, std::set<std::uint64_t>> path_predecessors;
        for (const auto &path : paths) {
            std::uint64_t predecessor = switch_entry->id.value;
            for (const auto *block : path) {
                path_predecessors[block->id.value].insert(predecessor);
                predecessor = block->id.value;
            }
        }
        std::map<PhiEdge, std::vector<std::pair<std::string, std::string>>> phi_edge_copies;
        std::set<std::uint64_t> validated_phi_blocks;
        for (const auto &path : paths) {
            for (const auto *block : path) {
                if (!validated_phi_blocks.insert(block->id.value).second) continue;
                const auto &expected = path_predecessors.at(block->id.value);
                for (const auto &phi : block->phis) {
                    if (phi.inputs.size() != expected.size()) return {};
                    std::set<std::uint64_t> seen_inputs;
                    for (const auto &input : phi.inputs) {
                        if (!expected.contains(input.predecessor.value) ||
                            !seen_inputs.insert(input.predecessor.value).second) return {};
                        phi_edge_copies[{input.predecessor.value, block->id.value}].emplace_back(
                            register_name(phi.destination, phi.version),
                            register_name(phi.destination, input.version));
                    }
                }
                const auto valid_memory_inputs = [&](const auto &inputs) {
                    if (inputs.size() != expected.size()) return false;
                    std::set<std::uint64_t> seen_inputs;
                    for (const auto &input : inputs)
                        if (!expected.contains(input.predecessor.value) ||
                            !seen_inputs.insert(input.predecessor.value).second) return false;
                    return true;
                };
                if (block->memory_phi && !valid_memory_inputs(block->memory_phi->inputs)) return {};
                std::set<std::string> partition_names;
                for (const auto &phi : block->memory_partition_phis)
                    if (phi.partition.empty() || !partition_names.insert(phi.partition).second ||
                        !valid_memory_inputs(phi.inputs)) return {};
            }
        }
        if (covered_blocks.size() != function.blocks.size())
            return {};
        auto emit_switch_path = [&](const std::vector<const LiftedBlock *> &path,
                                    std::size_t shared_begin, unsigned switch_indent) {
            const auto body_indent = switch_indent + 4;
            const auto end = terminal_arms ? path.size() : shared_begin;
            std::uint64_t predecessor = switch_entry->id.value;
            for (std::size_t i = 0; i < end; ++i) {
                emit_parallel_copies(out, phi_edge_copies[{predecessor, path[i]->id.value}], body_indent);
                emit_block(*path[i], body_indent, true);
                predecessor = path[i]->id.value;
            }
            if (!terminal_arms) {
                const auto *shared = path[shared_begin];
                emit_parallel_copies(out, phi_edge_copies[{predecessor, shared->id.value}], body_indent);
                out << std::string(body_indent, ' ') << "break;\n";
            }
        };
        auto emit_switch_body = [&](unsigned indent) {
            for (const auto *block : switch_prefix) emit_block(*block, indent, true);
            emit_block(*switch_entry, indent, true);
            out << std::string(indent, ' ') << "switch (" << expression_text(*dispatch.selector) << ") {\n";
            for (const auto &item : dispatch.cases) {
                out << std::string(indent, ' ') << "case 0x" << std::hex << item.value << std::dec << ":\n";
                const auto target_key = std::pair{item.target.space.value, item.target.offset};
                const auto path_index = static_cast<std::size_t>(std::distance(targets.begin(), targets.find(target_key)));
                emit_switch_path(paths[path_index], shared_suffix_begin[path_index], indent);
            }
            out << std::string(indent, ' ') << "default:\n";
            const auto default_key = std::pair{dispatch.default_target->space.value, dispatch.default_target->offset};
            const auto default_index = static_cast<std::size_t>(std::distance(targets.begin(), targets.find(default_key)));
            emit_switch_path(paths[default_index], shared_suffix_begin[default_index], indent);
            out << std::string(indent, ' ') << "}\n";
            for (std::size_t suffix_index = 0; suffix_index < shared_suffix.size(); ++suffix_index) {
                if (suffix_index != 0)
                    emit_parallel_copies(out, phi_edge_copies[{shared_suffix[suffix_index - 1]->id.value,
                                                               shared_suffix[suffix_index]->id.value}], indent);
                emit_block(*shared_suffix[suffix_index], indent, true);
            }
        };
        out << "function " << address_label(function.entry) << "() {\n";
        if (switch_guard) {
            emit_block(*entry, 4, true);
            out << "    if (" << branch_condition_text(*switch_guard) << ") {\n";
            if (switch_guard_return_on_true) emit_block(*switch_guard_return, 8);
            else emit_switch_body(8);
            out << "    } else {\n";
            if (switch_guard_return_on_true) emit_switch_body(8);
            else emit_block(*switch_guard_return, 8);
            out << "    }\n";
        } else {
            emit_switch_body(4);
        }
        out << "}\n";
        return StructuredPseudocode{out.str(), false, {}};
    };
    // A complete switch may intentionally flow from one case target into the
    // next. The ordinary arm recognizer treats each destination as a separate
    // region, so it cannot represent that shared chain without duplicating
    // blocks. This narrower form emits a case label at every target in a
    // disjoint target chain, preserving C switch fallthrough directly.
    auto try_entry_switch_fallthrough = [&]() -> std::optional<StructuredPseudocode> {
        if (switch_entry != entry || !switch_prefix.empty() || switch_guard ||
            !switch_entry || function.blocks.size() < 3 || function.blocks.size() > 1024)
            return {};
        const auto &dispatch = *switch_entry->switch_dispatch;
        if (!dispatch.complete || !dispatch.selector || dispatch.cases.empty() || !dispatch.default_target ||
            !switch_entry->phis.empty() || switch_entry->memory_phi)
            return {};

        using TargetKey = std::pair<std::uint32_t, std::uint64_t>;
        std::map<TargetKey, std::vector<std::uint64_t>> labels_by_target;
        std::set<std::uint64_t> values;
        for (const auto &item : dispatch.cases) {
            if (!values.insert(item.value).second) return {};
            labels_by_target[{item.target.space.value, item.target.offset}].push_back(item.value);
        }
        const TargetKey default_key{dispatch.default_target->space.value, dispatch.default_target->offset};
        labels_by_target.try_emplace(default_key);

        std::map<TargetKey, const LiftedBlock *> targets;
        for (const auto &[key, _] : labels_by_target) {
            const auto *target = find_block(Address{{key.first}, key.second});
            if (!target || target == switch_entry || !target->phis.empty() || target->memory_phi ||
                target->switch_dispatch || contains_return(*target))
                return {};
            targets.emplace(key, target);
        }

        std::map<std::uint64_t, std::set<std::uint64_t>> predecessors;
        for (const auto &block : function.blocks) {
            for (const auto &edge : block.successors) {
                if (!edge.target || (edge.kind != BlockEdgeKind::jump && edge.kind != BlockEdgeKind::fallthrough))
                    return {};
                const auto *target = find_block(*edge.target);
                if (!target || (edge.block && edge.block != target->id)) return {};
                predecessors[target->id.value].insert(block.id.value);
            }
        }

        std::map<TargetKey, TargetKey> next_target;
        std::map<TargetKey, std::size_t> target_predecessor_count;
        std::set<std::uint64_t> join_predecessors;
        const LiftedBlock *join = nullptr;
        for (const auto &[key, block] : targets) {
            if (block->successors.size() != 1) return {};
            const auto &edge = block->successors.front();
            const auto *successor = edge.target ? find_block(*edge.target) : nullptr;
            if (!successor || (edge.block && edge.block != successor->id)) return {};
            const auto branch_count = std::count_if(block->instructions.begin(), block->instructions.end(),
                [](const auto &instruction) { return std::holds_alternative<Branch>(instruction.statement); });
            if (branch_count > 1 || (branch_count == 1 &&
                (!std::holds_alternative<Branch>(block->instructions.back().statement) ||
                 std::get<Branch>(block->instructions.back().statement).condition != "true" ||
                 !std::get<Branch>(block->instructions.back().statement).true_target ||
                 std::get<Branch>(block->instructions.back().statement).false_target ||
                 *std::get<Branch>(block->instructions.back().statement).true_target != *edge.target)))
                return {};

            const TargetKey successor_key{successor->begin.space.value, successor->begin.offset};
            if (targets.contains(successor_key)) {
                next_target.emplace(key, successor_key);
                if (++target_predecessor_count[successor_key] > 1) return {};
            } else {
                if (!has_only_terminal_return(*successor) || !successor->phis.empty() || successor->memory_phi)
                    return {};
                if (join && join != successor) return {};
                join = successor;
                join_predecessors.insert(block->id.value);
            }
        }
        if (!join || function.blocks.size() != targets.size() + 2 ||
            predecessors[switch_entry->id.value].size() != 0 ||
            predecessors[join->id.value] != join_predecessors)
            return {};

        for (const auto &[key, block] : targets) {
            std::set<std::uint64_t> expected{switch_entry->id.value};
            for (const auto &[prior, next] : next_target)
                if (next == key) expected.insert(targets.at(prior)->id.value);
            if (predecessors[block->id.value] != expected) return {};
        }

        std::vector<TargetKey> roots;
        for (const auto &[key, _] : targets)
            if (!target_predecessor_count.contains(key)) roots.push_back(key);
        std::set<TargetKey> visited;
        std::vector<std::vector<TargetKey>> chains;
        for (const auto root : roots) {
            std::vector<TargetKey> chain;
            auto current = root;
            while (visited.insert(current).second) {
                chain.push_back(current);
                const auto next = next_target.find(current);
                if (next == next_target.end()) break;
                current = next->second;
            }
            if (chain.empty() || next_target.contains(chain.back()) ||
                !std::any_of(targets.at(chain.back())->successors.begin(), targets.at(chain.back())->successors.end(),
                    [&](const auto &edge) { return edge_targets(edge, join->begin); }))
                return {};
            chains.push_back(std::move(chain));
        }
        if (visited.size() != targets.size()) return {}; // cycles have no root and remain on the state-machine path

        out << "function " << address_label(function.entry) << "() {\n";
        emit_block(*switch_entry, 4, true);
        out << "    switch (" << expression_text(*dispatch.selector) << ") {\n";
        for (const auto &chain : chains) {
            for (const auto key : chain) {
                for (const auto value : labels_by_target[key])
                    out << "        case 0x" << std::hex << value << std::dec << ":\n";
                if (key == default_key) out << "        default:\n";
                const auto *block = targets.at(key);
                emit_block(*block, 12, true);
                if (!next_target.contains(key)) out << "            break;\n";
            }
        }
        out << "    }\n";
        emit_block(*join, 4);
        out << "}\n";
        return StructuredPseudocode{out.str(), false, {}};
    };
    if (auto structured = try_entry_switch_fallthrough()) return *structured;
    if (auto structured = try_entry_switch()) return *structured;

    // Recognize bounded natural-loop regions before the acyclic structurer.
    // Each absorbed region must have a unique entry and continuation; shapes
    // that cannot prove that ownership proceed to the generic formatters.
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
        if (block.successors.size() != 1 || !edge_targets(block.successors.front(), target))
            return false;
        if (block.instructions.empty() || !std::holds_alternative<Branch>(block.instructions.back().statement))
            return true;
        const auto &edge = std::get<Branch>(block.instructions.back().statement);
        return edge.condition == "true" && edge.true_target == std::optional<Address>{target} && !edge.false_target;
    };
    // A post-tested loop with an explicit preheader has an initial header-phi
    // edge as well as a recurrent edge. Prove the complete CFG before emitting
    // either copy sequence. Sequential disjoint diamonds and guarded return
    // trees share a single validated body spine and retain their actual edges.
    auto try_ssa_post_tested_loop = [&]() -> std::optional<StructuredPseudocode> {
        if (function.blocks.size() < 3 || function.blocks.size() > 1024) return {};
        std::map<std::uint64_t, std::set<std::uint64_t>> predecessors;
        std::set<std::uint64_t> ids;
        std::set<std::pair<std::uint32_t, std::uint64_t>> addresses;
        std::size_t edge_count = 0;
        for (const auto &block : function.blocks) {
            if (!ids.insert(block.id.value).second ||
                !addresses.emplace(block.begin.space.value, block.begin.offset).second ||
                block.switch_dispatch || !has_only_simple_statements(block)) return {};
            std::set<std::uint64_t> targets;
            for (const auto &edge : block.successors) {
                if (++edge_count > 4096 || !edge.target) return {};
                const auto *target = find_block(*edge.target);
                if (!target || !edge_targets(edge, target->begin) ||
                    !targets.insert(target->id.value).second) return {};
                predecessors[target->id.value].insert(block.id.value);
            }
        }
        if (!predecessors[entry->id.value].empty() || !entry->phis.empty() || entry->memory_phi ||
            !entry->memory_partition_phis.empty()) return {};

        const auto linear_successor = [&](const LiftedBlock &block) -> const LiftedBlock * {
            if (contains_return(block) || block.successors.size() != 1 ||
                !block.successors.front().target ||
                (block.successors.front().kind != BlockEdgeKind::jump &&
                 block.successors.front().kind != BlockEdgeKind::fallthrough) ||
                !has_unconditional_edge(block, *block.successors.front().target)) return nullptr;
            if (!block.instructions.empty()) {
                const auto *transfer = std::get_if<Branch>(&block.instructions.back().statement);
                if (transfer && transfer->indirect_target) return nullptr;
            }
            return find_block(*block.successors.front().target);
        };
        struct BodyDiamond {
            const LiftedBlock *branch = nullptr, *join = nullptr;
            const Branch *condition = nullptr;
            std::vector<const LiftedBlock *> yes, no;
            std::vector<BlockId> yes_tails, no_tails;
        };
        struct ReturnNode {
            const LiftedBlock *block = nullptr;
            BlockId predecessor{};
            const Branch *condition = nullptr;
            std::optional<std::size_t> next, yes, no;
        };
        struct SideReturn {
            const LiftedBlock *branch = nullptr, *continuation = nullptr;
            const Branch *condition = nullptr;
            bool on_true = false;
            std::vector<ReturnNode> tree;
        };
        std::map<std::uint64_t, BodyDiamond> diamonds;
        std::map<std::uint64_t, SideReturn> side_returns;
        std::set<std::uint64_t> diamond_joins;
        std::vector<const LiftedBlock *> path;
        std::set<std::uint64_t> covered;
        std::set<std::uint64_t> body_claimed;
        // A terminal return may be reached by more than one guarded side arm,
        // or by both a side arm and the ordinary loop exit. Count the shared
        // CFG block once for coverage, and record every edge used by its SSA phis.
        std::map<std::uint64_t, std::set<std::uint64_t>> terminal_return_sources;
        auto *current = entry;
        const Branch *condition = nullptr;
        while (current && covered.insert(current->id.value).second) {
            path.push_back(current);
            condition = terminal_conditional(*current);
            if (condition) {
                const auto in_path = [&](Address target) {
                    return std::any_of(path.begin(), path.end(), [&](const auto *block) {
                        return block->begin == target;
                    });
                };
                const bool yes_back = in_path(*condition->true_target);
                const bool no_back = in_path(*condition->false_target);
                if (yes_back != no_back) break;
                if (yes_back) return {};

                const auto trace_return = [&](Address target) -> std::optional<std::vector<ReturnNode>> {
                    struct Pending {
                        const LiftedBlock *block;
                        BlockId predecessor;
                        std::optional<std::size_t> parent;
                        unsigned child; // 0: root, 1: linear, 2: true, 3: false
                        std::set<std::uint64_t> ancestors;
                    };
                    std::vector<ReturnNode> result;
                    std::map<std::uint64_t, std::set<std::uint64_t>> nonterminal_sources;
                    std::vector<Pending> pending{{find_block(target), current->id, std::nullopt, 0, {}}};
                    while (!pending.empty()) {
                        const auto item = pending.back();
                        pending.pop_back();
                        const auto *cursor = item.block;
                        if (!cursor || result.size() >= 64) return {};
                        if (item.ancestors.contains(cursor->id.value)) return {};
                        const bool terminal_return = has_only_terminal_return(*cursor);
                        if (terminal_return) {
                            if (!predecessors[cursor->id.value].contains(item.predecessor.value) ||
                                (covered.contains(cursor->id.value) &&
                                 !terminal_return_sources.contains(cursor->id.value))) return {};
                        } else {
                            if (covered.contains(cursor->id.value) ||
                                !predecessors[cursor->id.value].contains(item.predecessor.value)) return {};
                            nonterminal_sources[cursor->id.value].insert(item.predecessor.value);
                        }
                        const auto index = result.size();
                        result.push_back(ReturnNode{cursor, item.predecessor});
                        if (item.parent) {
                            auto &parent = result[*item.parent];
                            if (item.child == 1) parent.next = index;
                            else if (item.child == 2) parent.yes = index;
                            else parent.no = index;
                        }
                        if (terminal_return) continue;
                        if (contains_return(*cursor)) return {};
                        auto ancestors = item.ancestors;
                        ancestors.insert(cursor->id.value);
                        if (const auto *branch = terminal_conditional(*cursor)) {
                            if (branch->indirect_target) return {};
                            result[index].condition = branch;
                            pending.push_back({find_block(*branch->false_target), cursor->id, index, 3, ancestors});
                            pending.push_back({find_block(*branch->true_target), cursor->id, index, 2, ancestors});
                        } else {
                            const auto *next = linear_successor(*cursor);
                            if (!next) return {};
                            pending.push_back({next, cursor->id, index, 1, std::move(ancestors)});
                        }
                    }
                    for (const auto &[id, sources] : nonterminal_sources)
                        if (sources != predecessors[id]) return {};
                    return result;
                };
                const auto yes_return = trace_return(*condition->true_target);
                const auto no_return = trace_return(*condition->false_target);
                if (yes_return && no_return) return {};
                if (yes_return || no_return) {
                    const bool on_true = yes_return.has_value();
                    const auto &return_tree = on_true ? *yes_return : *no_return;
                    const auto *continuation = find_block(on_true ? *condition->false_target
                                                                 : *condition->true_target);
                    if (!continuation || covered.contains(continuation->id.value) ||
                        predecessors[continuation->id.value] !=
                            std::set<std::uint64_t>{current->id.value}) return {};
                    for (const auto &node : return_tree) {
                        if (has_only_terminal_return(*node.block)) {
                            if (!terminal_return_sources[node.block->id.value]
                                     .insert(node.predecessor.value).second)
                                return {};
                        }
                        covered.insert(node.block->id.value);
                    }
                    side_returns.emplace(current->id.value,
                        SideReturn{current, continuation, condition, on_true, return_tree});
                    current = continuation;
                    condition = nullptr;
                    continue;
                }

                struct Arm {
                    const LiftedBlock *join = nullptr;
                    std::vector<const LiftedBlock *> blocks;
            std::vector<BlockId> tails;
                };
        std::function<std::optional<Arm>(const LiftedBlock *, Address, unsigned &, unsigned)> trace_arm;
        trace_arm = [&](const LiftedBlock *branch, Address target, unsigned &budget,
                        unsigned depth) -> std::optional<Arm> {
            if (!branch || depth > 32) return {};
            Arm arm;
            auto *cursor = find_block(target);
            auto predecessor = branch->id;
            std::set<std::uint64_t> seen;
            const auto claim = [&](std::uint64_t id) {
                if (covered.contains(id) || !seen.insert(id).second || !body_claimed.insert(id).second)
                    return false;
                return true;
            };
            while (cursor) {
                if (covered.contains(cursor->id.value) || seen.contains(cursor->id.value)) return {};
                // A join belongs to the parent region. Return it with all of
                // this arm's actual predecessor leaves so phi copies remain
                // tied to the original CFG edges.
                if (predecessors[cursor->id.value] != std::set<std::uint64_t>{predecessor.value}) {
                    if (body_claimed.contains(cursor->id.value)) return {};
                    arm.join = cursor;
                    arm.tails = {predecessor};
                    for (const auto *block : arm.blocks)
                        if (!claim(block->id.value)) return {};
                    return arm;
                }
                if (const auto *nested = terminal_conditional(*cursor)) {
                    if (nested->indirect_target || contains_return(*cursor) || budget >= 64 ||
                        !claim(cursor->id.value)) return {};
                    ++budget;
                    arm.blocks.push_back(cursor);
                    auto yes = trace_arm(cursor, *nested->true_target, budget, depth + 1);
                    auto no = trace_arm(cursor, *nested->false_target, budget, depth + 1);
                    if (!yes || !no || yes->join != no->join || yes->join == cursor) return {};
                    std::set<std::uint64_t> leaf_ids;
                    for (const auto tail : yes->tails)
                        if (!leaf_ids.insert(tail.value).second) return {};
                    for (const auto tail : no->tails)
                        if (!leaf_ids.insert(tail.value).second) return {};
                    std::set<std::uint64_t> arm_ids;
                    for (const auto *block : yes->blocks)
                        if (!arm_ids.insert(block->id.value).second || seen.contains(block->id.value)) return {};
                    for (const auto *block : no->blocks)
                        if (!arm_ids.insert(block->id.value).second || seen.contains(block->id.value)) return {};
                    std::vector<std::uint64_t> all_tails;
                    all_tails.reserve(leaf_ids.size());
                    for (const auto tail : yes->tails) all_tails.push_back(tail.value);
                    for (const auto tail : no->tails) all_tails.push_back(tail.value);
                    std::set<std::uint64_t> expected_predecessors;
                    for (const auto id : all_tails) expected_predecessors.insert(id);
                    if (predecessors[yes->join->id.value] != expected_predecessors ||
                        body_claimed.contains(yes->join->id.value)) return {};
                    for (const auto *block : yes->blocks) body_claimed.insert(block->id.value);
                    for (const auto *block : no->blocks) body_claimed.insert(block->id.value);
                    const auto [it, inserted] = diamonds.emplace(cursor->id.value,
                        BodyDiamond{cursor, yes->join, nested, yes->blocks, no->blocks,
                                    yes->tails, no->tails});
                    if (!inserted || it->second.branch != cursor) return {};
                    diamond_joins.insert(yes->join->id.value);
                    for (const auto *block : arm.blocks)
                        if (!body_claimed.insert(block->id.value).second && block != cursor) return {};
                    arm.join = yes->join;
                    arm.tails.clear();
                    for (const auto id : all_tails) arm.tails.push_back(BlockId{id});
                    return arm;
                }
                if (contains_return(*cursor) || budget >= 64 || !claim(cursor->id.value)) return {};
                const auto *next = linear_successor(*cursor);
                if (!next) return {};
                arm.blocks.push_back(cursor);
                ++budget;
                predecessor = cursor->id;
                cursor = const_cast<LiftedBlock *>(next);
            }
            return {};
        };
                unsigned yes_budget = 0, no_budget = 0;
                const auto yes = trace_arm(current, *condition->true_target, yes_budget, 0);
                const auto no = trace_arm(current, *condition->false_target, no_budget, 0);
                if (!yes || !no || yes->join != no->join) return {};
                std::set<std::uint64_t> join_predecessors;
                for (const auto tail : yes->tails)
                    if (!join_predecessors.insert(tail.value).second) return {};
                for (const auto tail : no->tails)
                    if (!join_predecessors.insert(tail.value).second) return {};
                if (predecessors[yes->join->id.value] != join_predecessors) return {};
                std::set<std::uint64_t> arms;
                for (const auto *block : yes->blocks)
                    if (!arms.insert(block->id.value).second) return {};
                for (const auto *block : no->blocks)
                    if (!arms.insert(block->id.value).second) return {};
                for (const auto id : body_claimed) covered.insert(id);
                diamonds.emplace(current->id.value,
                    BodyDiamond{current, yes->join, condition, yes->blocks, no->blocks,
                                yes->tails, no->tails});
                diamond_joins.insert(yes->join->id.value);
                current = yes->join;
                condition = nullptr;
                continue;
            }
            current = linear_successor(*current);
        }
        if (!current || !condition || condition->indirect_target || contains_return(*current)) return {};
        const auto *latch = current;
        const auto true_header = std::find_if(path.begin(), path.end(), [&](const auto *block) {
            return block->begin == *condition->true_target;
        });
        const auto false_header = std::find_if(path.begin(), path.end(), [&](const auto *block) {
            return block->begin == *condition->false_target;
        });
        if ((true_header != path.end()) == (false_header != path.end())) return {};
        const bool loops_on_true = true_header != path.end();
        const auto header_position = loops_on_true ? true_header : false_header;
        if (header_position == path.begin()) return {}; // Require a real initial incoming edge.
        const auto *header = *header_position;
        const auto header_offset = static_cast<std::size_t>(header_position - path.begin());
        for (const auto &item : diamonds) {
            const auto &diamond = item.second;
            const auto branch_position = std::find(path.begin(), path.end(), diamond.branch);
            if (branch_position != path.end()) {
                if (branch_position < header_position || branch_position + 1 == path.end() ||
                    *(branch_position + 1) != diamond.join) return {};
            } else {
                const auto join_position = std::find(path.begin(), path.end(), diamond.join);
                if (!body_claimed.contains(diamond.branch->id.value) || join_position == path.end() ||
                    join_position < header_position) return {};
            }
        }
        for (const auto &item : side_returns) {
            const auto &side_return = item.second;
            const auto branch_position = std::find(path.begin(), path.end(), side_return.branch);
            if (branch_position < header_position || branch_position == path.end() ||
                branch_position + 1 == path.end() ||
                *(branch_position + 1) != side_return.continuation) return {};
        }
        const auto *preheader = path[header_offset - 1];
        if (predecessors[header->id.value] != std::set<std::uint64_t>{preheader->id.value, latch->id.value}) return {};
        for (std::size_t i = 1; i < path.size(); ++i) {
            if (i != header_offset && !diamond_joins.contains(path[i]->id.value) &&
                predecessors[path[i]->id.value] != std::set<std::uint64_t>{path[i - 1]->id.value}) return {};
        }

        std::vector<const LiftedBlock *> exit_path;
        current = find_block(loops_on_true ? *condition->false_target : *condition->true_target);
        auto expected_predecessor = latch->id.value;
        while (current && exit_path.size() < 64) {
            const bool terminal_return = has_only_terminal_return(*current);
            if (terminal_return) {
                if (!predecessors[current->id.value].contains(expected_predecessor) ||
                    (covered.contains(current->id.value) &&
                     !terminal_return_sources.contains(current->id.value)) ||
                    !terminal_return_sources[current->id.value].insert(expected_predecessor).second)
                    return {};
            } else if (covered.contains(current->id.value) ||
                       predecessors[current->id.value] !=
                           std::set<std::uint64_t>{expected_predecessor}) return {};
            covered.insert(current->id.value);
            exit_path.push_back(current);
            if (terminal_return) break;
            expected_predecessor = current->id.value;
            current = linear_successor(*current);
        }
        if (exit_path.empty() || !has_only_terminal_return(*exit_path.back()) ||
            covered.size() != function.blocks.size()) return {};
        for (const auto &[id, sources] : terminal_return_sources)
            if (sources != predecessors[id]) return {};

        std::size_t phi_input_count = 0;
        for (const auto &block : function.blocks) {
            const auto &incoming = predecessors[block.id.value];
            if (block.phis.size() > 4096 || block.memory_partition_phis.size() > 4096) return {};
            const auto valid_phi = [&](const auto &phi) {
                if (phi.inputs.size() != incoming.size() || phi.inputs.size() > 65536 - phi_input_count) return false;
                phi_input_count += phi.inputs.size();
                std::set<std::uint64_t> seen;
                for (const auto &input : phi.inputs)
                    if (!incoming.contains(input.predecessor.value) ||
                        !seen.insert(input.predecessor.value).second) return false;
                return seen == incoming;
            };
            for (const auto &phi : block.phis) if (!valid_phi(phi)) return {};
            if (block.memory_phi && !valid_phi(*block.memory_phi)) return {};
            std::set<std::string> partitions;
            for (const auto &phi : block.memory_partition_phis)
                if (phi.partition.empty() || !partitions.insert(phi.partition).second || !valid_phi(phi)) return {};
        }
        const auto edge_copies = [&](const LiftedBlock &target, BlockId source, unsigned indent) {
            std::vector<std::pair<std::string, std::string>> copies;
            for (const auto &phi : target.phis) {
                const auto input = std::find_if(phi.inputs.begin(), phi.inputs.end(), [&](const auto &item) {
                    return item.predecessor == source;
                });
                copies.emplace_back(register_name(phi.destination, phi.version),
                                    register_name(phi.destination, input->version));
            }
            emit_parallel_copies(out, copies, indent);
        };

        out << "function " << address_label(function.entry) << "() {\n";
        for (std::size_t i = 0; i < header_offset; ++i) {
            emit_block(*path[i], 4, true);
            edge_copies(*path[i + 1], path[i]->id, 4);
        }
        out << "    bool __hexlab_do_repeat;\n    do {\n";
        for (std::size_t i = header_offset; i < path.size(); ++i) {
            if (const auto found = side_returns.find(path[i]->id.value); found != side_returns.end()) {
                const auto *side_return = &found->second;
                emit_block(*side_return->branch, 8, true);
                const auto predicate = branch_condition_text(*side_return->condition);
                out << "        if (" << (side_return->on_true ? predicate : "!(" + predicate + ")")
                    << ") {\n";
                struct ReturnFrame {
                    std::size_t node;
                    BlockId predecessor;
                    unsigned indent;
                    unsigned phase;
                };
                std::vector<ReturnFrame> frames{{0, side_return->branch->id, 12, 0}};
                while (!frames.empty()) {
                    auto &frame = frames.back();
                    const auto &node = side_return->tree[frame.node];
                    const auto spaces = std::string(frame.indent, ' ');
                    if (frame.phase == 0) {
                        edge_copies(*node.block, frame.predecessor, frame.indent);
                        emit_block(*node.block, frame.indent, node.condition || node.next.has_value());
                        if (node.condition) {
                            out << spaces << "if (" << branch_condition_text(*node.condition) << ") {\n";
                            frame.phase = 1;
                            frames.push_back({*node.yes, node.block->id, frame.indent + 4, 0});
                        } else if (node.next) {
                            frame.phase = 3;
                            frames.push_back({*node.next, node.block->id, frame.indent, 0});
                        } else frames.pop_back();
                    } else if (frame.phase == 1) {
                        out << spaces << "} else {\n";
                        frame.phase = 2;
                        frames.push_back({*node.no, node.block->id, frame.indent + 4, 0});
                    } else {
                        if (frame.phase == 2) out << spaces << "}\n";
                        frames.pop_back();
                    }
                }
                out << "        }\n";
                edge_copies(*side_return->continuation, side_return->branch->id, 8);
                continue;
            }
            if (const auto found = diamonds.find(path[i]->id.value); found != diamonds.end()) {
                const auto *diamond = &found->second;
                const auto emit_region = [&](const BodyDiamond &root, auto &&emit_region_ref,
                                             unsigned indent) -> void {
                    const auto spaces = std::string(indent, ' ');
                    emit_block(*root.branch, indent, true);
                    out << spaces << "if (" << branch_condition_text(*root.condition) << ") {\n";
                    const auto emit_arm = [&](const std::vector<const LiftedBlock *> &arm) {
                        auto predecessor = root.branch->id;
                        bool nested_tail = false;
                        for (const auto *block : arm) {
                            edge_copies(*block, predecessor, indent + 4);
                            const auto nested = diamonds.find(block->id.value);
                            if (nested != diamonds.end() && nested->second.branch == block) {
                                emit_region_ref(nested->second, emit_region_ref, indent + 4);
                                nested_tail = true;
                            } else
                                emit_block(*block, indent + 4, true);
                            predecessor = block->id;
                        }
                        if (!nested_tail) edge_copies(*root.join, predecessor, indent + 4);
                    };
                    emit_arm(root.yes);
                    out << spaces << "} else {\n";
                    emit_arm(root.no);
                    out << spaces << "}\n";
                };
                emit_region(*diamond, emit_region, 8);
                continue;
            }
            emit_block(*path[i], 8, true);
            if (i + 1 < path.size() && !diamond_joins.contains(path[i + 1]->id.value))
                edge_copies(*path[i + 1], path[i]->id, 8);
        }
        // Evaluate the branch before recurrent copies: the predicate may read
        // a header-phi destination overwritten by those simultaneous updates.
        const auto predicate = branch_condition_text(*condition);
        out << "        __hexlab_do_repeat = " << (loops_on_true ? "(" + predicate + ")" : "!(" + predicate + ")")
            << ";\n";
        if (!header->phis.empty()) {
            out << "        if (__hexlab_do_repeat) {\n";
            edge_copies(*header, latch->id, 12);
            out << "        }\n";
        }
        out << "    } while (__hexlab_do_repeat);\n";
        auto previous = latch->id;
        for (const auto *block : exit_path) {
            edge_copies(*block, previous, 4);
            emit_block(*block, 4, true);
            previous = block->id;
        }
        out << "}\n";
        return StructuredPseudocode{out.str(), false, {}};
    };
    if (auto structured = try_ssa_post_tested_loop()) return *structured;

    if (function.blocks.size() >= 4 && has_only_simple_statements(*entry) && entry->phis.empty() &&
        entry->successors.size() == 1 && entry->successors.front().target) {
        const auto *header = find_block(*entry->successors.front().target);
        const auto *condition = header ? terminal_conditional(*header) : nullptr;
        const auto *body_start = condition ? find_block(*condition->true_target) : nullptr;
        const auto *exit_block = condition ? find_block(*condition->false_target) : nullptr;
        std::vector<const LiftedBlock *> loop_body;
        struct LoopBreakPath {
            const LiftedBlock *branch = nullptr;
            bool break_on_true = true;
            std::vector<const LiftedBlock *> path;
            std::vector<std::pair<std::string, std::string>> exit_phi_copies;
        };
        std::vector<LoopBreakPath> loop_breaks;
        std::set<std::uint64_t> loop_break_path_ids;
        std::map<std::uint64_t, std::vector<const LiftedBlock *>> shared_loop_break_paths;
        std::map<std::uint64_t, std::set<std::uint64_t>> shared_loop_break_sources;
        std::vector<std::pair<const LiftedBlock *, bool>> loop_continues;
        struct LoopConditionalReturn {
            const LiftedBlock *branch = nullptr;
            std::vector<const LiftedBlock *> path;
            bool return_on_true = true;
            std::vector<std::pair<std::string, std::string>> phi_copies;
        };
        std::vector<LoopConditionalReturn> loop_returns;
        struct LoopConditionalBody {
            const LiftedBlock *branch = nullptr;
            const LiftedBlock *join = nullptr;
            bool latch_to_header = false;
            std::shared_ptr<LoopConditionalBody> yes_nested;
            std::shared_ptr<LoopConditionalBody> no_nested;
            std::vector<const LiftedBlock *> yes;
            std::vector<const LiftedBlock *> no;
            std::vector<std::pair<std::string, std::string>> yes_phi_copies;
            std::vector<std::pair<std::string, std::string>> no_phi_copies;
            bool yes_break = false;
            bool no_break = false;
            std::vector<const LiftedBlock *> yes_break_path;
            std::vector<const LiftedBlock *> no_break_path;
        };
        struct NestedLoopBody {
            const LiftedBlock *header = nullptr;
            const LiftedBlock *exit = nullptr;
            std::vector<const LiftedBlock *> body;
            std::vector<std::pair<std::string, std::string>> initial_phi_copies;
            std::vector<std::pair<std::string, std::string>> recurrent_phi_copies;
            std::map<std::uint64_t, std::vector<std::pair<std::string, std::string>>> backedge_phi_copies;
            std::map<std::uint64_t, std::vector<std::pair<std::string, std::string>>> exit_phi_copies;
            bool condition_true_enters = true;
            std::vector<LoopConditionalBody> conditional_joins;
            std::vector<std::pair<const LiftedBlock *, bool>> conditional_breaks;
            std::map<std::uint64_t, std::vector<const LiftedBlock *>> conditional_break_paths;
            // A guarded terminal return may leave a nested loop body while
            // the other edge continues along its ordinary body spine.
            std::vector<LoopConditionalReturn> conditional_returns;
            std::vector<std::pair<const LiftedBlock *, bool>> conditional_continues;
            std::map<std::uint64_t, std::vector<const LiftedBlock *>> conditional_continue_paths;
        };
        struct LoopSwitchArm {
            Address target{};
            std::vector<std::uint64_t> values;
            bool is_default = false;
            std::vector<const LiftedBlock *> body;
        };
        struct LoopSwitchBody {
            std::vector<LoopSwitchArm> arms;
            const LiftedBlock *continuation = nullptr;
        };
        // Keep recursive discovery and emission shallow enough for native
        // stacks while allowing substantially deeper bodies than the former
        // eight-level cutoff. The enclosing diamond CFG is also bounded to
        // 1,024 blocks, and recursive children must claim distinct blocks.
        constexpr unsigned max_loop_child_depth = 64;
        constexpr std::size_t max_nested_child_cleanup_blocks = 1024;
        std::map<std::uint64_t, NestedLoopBody> nested_loop_bodies;
        std::map<std::uint64_t, LoopConditionalBody> conditional_loop_bodies;
        std::set<std::uint64_t> conditional_phi_joins;
        std::map<std::uint64_t, LoopSwitchBody> switch_loop_bodies;
        std::set<std::uint64_t> loop_body_ids;
        // Index predecessors once for both parent and child diamonds. Reject
        // malformed identities even if a trace could otherwise hide the bad
        // edge by omitting its terminal branch during emission.
        std::map<std::uint64_t, std::set<std::uint64_t>> diamond_predecessors;
        bool diamond_cfg_valid = function.blocks.size() <= 1024;
        std::set<std::uint64_t> diamond_ids;
        std::set<std::pair<std::uint32_t, std::uint64_t>> diamond_addresses;
        std::size_t diamond_edge_count = 0;
        std::size_t diamond_memory_phi_input_count = 0;
        if (diamond_cfg_valid) {
            for (const auto &block : function.blocks) {
                if (!diamond_ids.insert(block.id.value).second ||
                    !diamond_addresses.emplace(block.begin.space.value, block.begin.offset).second ||
                    block.successors.size() > 4096 - diamond_edge_count) {
                    diamond_cfg_valid = false;
                    break;
                }
                diamond_edge_count += block.successors.size();
                const auto account_memory_phi = [&](const auto &phi) {
                    if (phi.inputs.size() > 65536 - diamond_memory_phi_input_count) return false;
                    diamond_memory_phi_input_count += phi.inputs.size();
                    return true;
                };
                if ((block.memory_phi && !account_memory_phi(*block.memory_phi)) ||
                    block.memory_partition_phis.size() > 4096 ||
                    std::any_of(block.memory_partition_phis.begin(), block.memory_partition_phis.end(),
                        [&](const auto &phi) { return !account_memory_phi(phi); })) {
                    diamond_cfg_valid = false;
                    break;
                }
                for (const auto &edge : block.successors) {
                    if (!edge.target || !edge_targets(edge, *edge.target)) {
                        diamond_cfg_valid = false;
                        break;
                    }
                    diamond_predecessors[find_block(*edge.target)->id.value].insert(block.id.value);
                }
                if (!diamond_cfg_valid) break;
            }
        }
        const auto valid_diamond_memory_phi = [&](const LiftedBlock &block) {
            const auto &incoming = diamond_predecessors[block.id.value];
            const auto valid_inputs = [&](const auto &phi) {
                if (phi.inputs.size() != incoming.size()) return false;
                std::set<std::uint64_t> seen;
                for (const auto &input : phi.inputs)
                    if (!incoming.contains(input.predecessor.value) ||
                        !seen.insert(input.predecessor.value).second) return false;
                return seen == incoming;
            };
            if (block.memory_phi && !valid_inputs(*block.memory_phi)) return false;
            if (block.memory_partition_phis.size() > 4096) return false;
            std::set<std::string> partitions;
            for (const auto &phi : block.memory_partition_phis)
                if (phi.partition.empty() || !partitions.insert(phi.partition).second ||
                    !valid_inputs(phi)) return false;
            return true;
        };
        std::function<std::optional<LoopConditionalBody>(const LiftedBlock &,
            const std::set<std::uint64_t> &, const LiftedBlock *, bool, bool, bool, unsigned)> analyze_loop_diamond;
        analyze_loop_diamond = [&](const LiftedBlock &branch,
            const std::set<std::uint64_t> &occupied, const LiftedBlock *region_exit,
            bool allow_header_latch, bool allow_extra_join_predecessor, bool allow_nested_arm, unsigned depth)
            -> std::optional<LoopConditionalBody> {
            const auto *test = terminal_conditional(branch);
            // Each caller separately proves any register phis on this branch
            // were lowered by the preceding region.
            if (!diamond_cfg_valid || !test || depth > max_loop_child_depth) return std::nullopt;
            if (contains_return(branch) || branch.switch_dispatch ||
                !has_only_simple_statements(branch) || !valid_diamond_memory_phi(branch))
                return std::nullopt;
            const auto excluded = [&](const LiftedBlock *block) {
                return !block || block == &branch || block == entry ||
                    (!allow_header_latch && block == header) || block == exit_block ||
                    block == region_exit || occupied.contains(block->id.value);
            };
            const auto trace = [&](Address address) {
                std::vector<const LiftedBlock *> path;
                std::set<std::uint64_t> seen;
                auto *current = find_block(address);
                while (!excluded(current) && seen.insert(current->id.value).second &&
                       path.size() < function.blocks.size()) {
                    // Keep a boundary block in the trace: it may be the shared
                    // join, including a phi join or the next sequential branch.
                    path.push_back(current);
                    if (!current->phis.empty() || current->switch_dispatch || contains_return(*current) ||
                        !has_only_simple_statements(*current) || current->successors.size() != 1 ||
                        !current->successors.front().target ||
                        !has_unconditional_edge(*current, *current->successors.front().target)) break;
                    current = find_block(*current->successors.front().target);
                }
                return path;
            };
            LoopConditionalBody region;
            region.branch = &branch;
            region.yes = trace(*test->true_target);
            region.no = trace(*test->false_target);
            // Permit a bounded recursive tree of conditional arms. The
            // analyzer validates every three-way join and edge-specific phi
            // before emission; max_loop_child_depth bounds native recursion.
            if (allow_nested_arm && depth < max_loop_child_depth) {
                const auto attach_nested_arm = [&](bool nested_on_true) {
                    const auto &nested_path = nested_on_true ? region.yes : region.no;
                    const auto &sibling_path = nested_on_true ? region.no : region.yes;
                    for (std::size_t nested_index = 0; nested_index < nested_path.size(); ++nested_index) {
                        const auto *nested_branch = nested_path[nested_index];
                        if (nested_index + 1 != nested_path.size() || !terminal_conditional(*nested_branch) ||
                            !nested_branch->phis.empty() || nested_branch->switch_dispatch ||
                            !has_only_simple_statements(*nested_branch) ||
                            !valid_diamond_memory_phi(*nested_branch)) continue;
                        std::set<std::uint64_t> nested_occupied = occupied;
                        nested_occupied.insert(branch.id.value);
                        bool prefix_valid = true;
                        auto predecessor = branch.id.value;
                        for (std::size_t i = 0; i < nested_index; ++i) {
                            const auto *block = nested_path[i];
                            const auto *next = i + 1 == nested_index ? nested_branch : nested_path[i + 1];
                            if (!block->phis.empty() || block->switch_dispatch || contains_return(*block) ||
                                !has_only_simple_statements(*block) || !valid_diamond_memory_phi(*block) ||
                                !has_unconditional_edge(*block, next->begin) ||
                                (block->successors.front().kind != BlockEdgeKind::jump &&
                                 block->successors.front().kind != BlockEdgeKind::fallthrough) ||
                                diamond_predecessors[block->id.value] != std::set<std::uint64_t>{predecessor}) {
                                prefix_valid = false;
                                break;
                            }
                            nested_occupied.insert(block->id.value);
                            predecessor = block->id.value;
                        }
                        if (!prefix_valid || diamond_predecessors[nested_branch->id.value] !=
                                std::set<std::uint64_t>{predecessor}) continue;
                        // A nested loop-body branch may leave through exactly
                        // one edge to the validated exit, optionally through a
                        // bounded straight-line cleanup chain. Its other edge
                        // must rejoin the outer sibling path.
                        const auto *nested_test = terminal_conditional(*nested_branch);
                        const auto trace_break_path = [&](const std::optional<Address> &target)
                            -> std::optional<std::vector<const LiftedBlock *>> {
                            if (!target) return std::nullopt;
                            std::vector<const LiftedBlock *> path;
                            auto *cursor = find_block(*target);
                            auto predecessor_id = nested_branch->id.value;
                            std::set<std::uint64_t> seen;
                            while (cursor && cursor != exit_block && cursor != header && cursor != entry &&
                                   cursor != region_exit && path.size() < 64 &&
                                   !occupied.contains(cursor->id.value) &&
                                   seen.insert(cursor->id.value).second) {
                                if (!cursor->phis.empty() || cursor->switch_dispatch || contains_return(*cursor) ||
                                    !has_only_simple_statements(*cursor) || cursor->memory_phi ||
                                    !cursor->memory_partition_phis.empty() || cursor->successors.size() != 1 ||
                                    !cursor->successors.front().target ||
                                    (cursor->successors.front().kind != BlockEdgeKind::jump &&
                                     cursor->successors.front().kind != BlockEdgeKind::fallthrough) ||
                                    !has_unconditional_edge(*cursor, *cursor->successors.front().target) ||
                                    diamond_predecessors[cursor->id.value] != std::set<std::uint64_t>{predecessor_id})
                                    return std::nullopt;
                                path.push_back(cursor);
                                predecessor_id = cursor->id.value;
                                cursor = find_block(*cursor->successors.front().target);
                            }
                            if (cursor != exit_block ||
                                !diamond_predecessors[exit_block->id.value].contains(predecessor_id))
                                return std::nullopt;
                            return path;
                        };
                        const auto true_break_path = nested_test ? trace_break_path(nested_test->true_target) :
                            std::nullopt;
                        const auto false_break_path = nested_test ? trace_break_path(nested_test->false_target) :
                            std::nullopt;
                        const bool break_true = true_break_path.has_value();
                        const bool break_false = false_break_path.has_value();
                        const bool exact_branch_edges = nested_branch->successors.size() == 2 && nested_test &&
                            nested_test->true_target && nested_test->false_target &&
                            std::count_if(nested_branch->successors.begin(), nested_branch->successors.end(),
                                [&](const auto &edge) { return edge_targets(edge, *nested_test->true_target); }) == 1 &&
                            std::count_if(nested_branch->successors.begin(), nested_branch->successors.end(),
                                [&](const auto &edge) { return edge_targets(edge, *nested_test->false_target); }) == 1;
                        if (break_true != break_false && exact_branch_edges &&
                            exit_block->phis.empty() &&
                            !exit_block->memory_phi && exit_block->memory_partition_phis.empty()) {
                            const Address continue_address = break_true ? *nested_test->false_target :
                                *nested_test->true_target;
                            std::vector<const LiftedBlock *> continue_path;
                            auto *cursor = find_block(continue_address);
                            auto continue_predecessor = nested_branch->id.value;
                            const LiftedBlock *join = nullptr;
                            bool continue_valid = true;
                            std::set<std::uint64_t> seen_continue;
                            while (cursor && cursor != exit_block && cursor != header && cursor != entry &&
                                   !occupied.contains(cursor->id.value) &&
                                   seen_continue.insert(cursor->id.value).second &&
                                   continue_path.size() < function.blocks.size()) {
                                if (std::find(sibling_path.begin(), sibling_path.end(), cursor) != sibling_path.end()) {
                                    join = cursor;
                                    break;
                                }
                                if (!cursor->phis.empty() || cursor->switch_dispatch || contains_return(*cursor) ||
                                    !has_only_simple_statements(*cursor) || !valid_diamond_memory_phi(*cursor) ||
                                    cursor->successors.size() != 1 || !cursor->successors.front().target ||
                                    (cursor->successors.front().kind != BlockEdgeKind::jump &&
                                     cursor->successors.front().kind != BlockEdgeKind::fallthrough) ||
                                    !has_unconditional_edge(*cursor, *cursor->successors.front().target) ||
                                    diamond_predecessors[cursor->id.value] !=
                                        std::set<std::uint64_t>{continue_predecessor}) {
                                    continue_valid = false;
                                    break;
                                }
                                continue_path.push_back(cursor);
                                continue_predecessor = cursor->id.value;
                                cursor = find_block(*cursor->successors.front().target);
                            }
                            if (continue_valid && join && join != exit_block && !excluded(join) &&
                                !contains_return(*join) && !join->switch_dispatch &&
                                has_only_simple_statements(*join) && valid_diamond_memory_phi(*join)) {
                                auto sibling_position = std::find(sibling_path.begin(), sibling_path.end(), join);
                                std::vector<const LiftedBlock *> sibling_arm(sibling_path.begin(), sibling_position);
                                auto sibling_predecessor = branch.id.value;
                                for (std::size_t i = 0; i < sibling_arm.size(); ++i) {
                                    const auto *block = sibling_arm[i];
                                    const auto *next = i + 1 == sibling_arm.size() ? join : sibling_arm[i + 1];
                                    if (!block->phis.empty() || block->switch_dispatch || contains_return(*block) ||
                                        !has_only_simple_statements(*block) || !valid_diamond_memory_phi(*block) ||
                                        !has_unconditional_edge(*block, next->begin) ||
                                        (block->successors.front().kind != BlockEdgeKind::jump &&
                                         block->successors.front().kind != BlockEdgeKind::fallthrough) ||
                                        diamond_predecessors[block->id.value] !=
                                            std::set<std::uint64_t>{sibling_predecessor}) {
                                        continue_valid = false;
                                        break;
                                    }
                                    sibling_predecessor = block->id.value;
                                }
                                const auto *continue_tail = continue_path.empty() ? nested_branch :
                                    continue_path.back();
                                if (std::any_of(sibling_arm.begin(), sibling_arm.end(), [&](const auto *block) {
                                        return block == nested_branch ||
                                            std::find(continue_path.begin(), continue_path.end(), block) !=
                                                continue_path.end() ||
                                            (break_true && std::find(true_break_path->begin(), true_break_path->end(), block) !=
                                                true_break_path->end()) ||
                                            (break_false && std::find(false_break_path->begin(), false_break_path->end(), block) !=
                                                false_break_path->end());
                                    })) continue_valid = false;
                                const auto &break_path = break_true ? *true_break_path : *false_break_path;
                                if (std::any_of(break_path.begin(), break_path.end(), [&](const auto *block) {
                                        return std::find(continue_path.begin(), continue_path.end(), block) !=
                                                continue_path.end() ||
                                            std::find(sibling_arm.begin(), sibling_arm.end(), block) != sibling_arm.end();
                                    })) continue_valid = false;
                                std::set<std::uint64_t> expected{continue_tail->id.value, sibling_predecessor};
                                if (continue_valid && expected.size() == 2 &&
                                    diamond_predecessors[join->id.value] == expected) {
                                    std::vector<std::pair<std::string, std::string>> continue_copies;
                                    std::vector<std::pair<std::string, std::string>> sibling_copies;
                                    bool phi_valid = true;
                                    for (const auto &phi : join->phis) {
                                        if (phi.inputs.size() != 2) { phi_valid = false; break; }
                                        const auto input_for = [&](std::uint64_t predecessor_id) {
                                            return std::find_if(phi.inputs.begin(), phi.inputs.end(),
                                                [&](const auto &input) { return input.predecessor.value == predecessor_id; });
                                        };
                                        const auto continue_input = input_for(continue_tail->id.value);
                                        const auto sibling_input = input_for(sibling_predecessor);
                                        if (continue_input == phi.inputs.end() || sibling_input == phi.inputs.end()) {
                                            phi_valid = false;
                                            break;
                                        }
                                        const auto destination = register_name(phi.destination, phi.version);
                                        continue_copies.emplace_back(destination,
                                            register_name(phi.destination, continue_input->version));
                                        sibling_copies.emplace_back(destination,
                                            register_name(phi.destination, sibling_input->version));
                                    }
                                    if (phi_valid) {
                                        LoopConditionalBody break_region;
                                        break_region.branch = nested_branch;
                                        break_region.join = join;
                                        break_region.yes_break = break_true;
                                        break_region.no_break = break_false;
                                        if (break_true) break_region.yes_break_path = *true_break_path;
                                        if (break_false) break_region.no_break_path = *false_break_path;
                                        if (break_true) {
                                            break_region.no = continue_path;
                                            break_region.no_phi_copies = std::move(continue_copies);
                                        } else {
                                            break_region.yes = continue_path;
                                            break_region.yes_phi_copies = std::move(continue_copies);
                                        }
                                        if (nested_on_true) {
                                            region.yes.assign(nested_path.begin(), nested_path.begin() +
                                                static_cast<std::ptrdiff_t>(nested_index));
                                            region.no = std::move(sibling_arm);
                                            region.yes_nested = std::make_shared<LoopConditionalBody>(
                                                std::move(break_region));
                                            region.no_phi_copies = std::move(sibling_copies);
                                        } else {
                                            region.no.assign(nested_path.begin(), nested_path.begin() +
                                                static_cast<std::ptrdiff_t>(nested_index));
                                            region.yes = std::move(sibling_arm);
                                            region.no_nested = std::make_shared<LoopConditionalBody>(
                                                std::move(break_region));
                                            region.yes_phi_copies = std::move(sibling_copies);
                                        }
                                        region.join = join;
                                        return true;
                                    }
                                }
                            }
                        }
                        auto nested = analyze_loop_diamond(*nested_branch, nested_occupied, region_exit,
                                                           true, true, true, depth + 1);
                        if (!nested)
                            continue;
                        const auto join_position = std::find(sibling_path.begin(), sibling_path.end(), nested->join);
                        if (join_position == sibling_path.end() ||
                            excluded(nested->join) || contains_return(*nested->join) || nested->join->switch_dispatch ||
                            !has_only_simple_statements(*nested->join) || !valid_diamond_memory_phi(*nested->join))
                            continue;
                        std::vector<const LiftedBlock *> sibling_arm(sibling_path.begin(), join_position);
                        auto sibling_predecessor = branch.id.value;
                        bool sibling_valid = true;
                        for (std::size_t i = 0; i < sibling_arm.size(); ++i) {
                            const auto *block = sibling_arm[i];
                            const auto *next = i + 1 == sibling_arm.size() ? nested->join : sibling_arm[i + 1];
                            if (!block->phis.empty() || block->switch_dispatch || contains_return(*block) ||
                                !has_only_simple_statements(*block) || !valid_diamond_memory_phi(*block) ||
                                !has_unconditional_edge(*block, next->begin) ||
                                (block->successors.front().kind != BlockEdgeKind::jump &&
                                 block->successors.front().kind != BlockEdgeKind::fallthrough) ||
                                diamond_predecessors[block->id.value] != std::set<std::uint64_t>{sibling_predecessor}) {
                                sibling_valid = false;
                                break;
                            }
                            sibling_predecessor = block->id.value;
                        }
                        if (!sibling_valid) continue;
                        const auto *sibling_tail = sibling_arm.empty() ? &branch : sibling_arm.back();
                        std::set<std::uint64_t> expected;
                        if (!nested->yes_break)
                            expected.insert((nested->yes.empty() ? nested->branch : nested->yes.back())->id.value);
                        if (!nested->no_break)
                            expected.insert((nested->no.empty() ? nested->branch : nested->no.back())->id.value);
                        expected.insert(sibling_tail->id.value);
                        if (nested->latch_to_header) {
                            const auto collect_latch_tails = [&](const auto &self,
                                const LoopConditionalBody &tree, std::set<std::uint64_t> &tails) -> bool {
                                if (!tree.latch_to_header || tree.yes_break || tree.no_break) return false;
                                const auto collect_arm = [&](const std::vector<const LiftedBlock *> &blocks,
                                    const std::shared_ptr<LoopConditionalBody> &child) {
                                    if (child) return self(self, *child, tails);
                                    const auto *tail = blocks.empty() ? tree.branch : blocks.back();
                                    return tail && tails.insert(tail->id.value).second;
                                };
                                return collect_arm(tree.yes, tree.yes_nested) &&
                                    collect_arm(tree.no, tree.no_nested);
                            };
                            std::set<std::uint64_t> nested_tails;
                            if (nested->join != header ||
                                !collect_latch_tails(collect_latch_tails, *nested, nested_tails) ||
                                nested_tails.size() > function.blocks.size())
                                continue;
                            expected = nested_tails;
                            expected.insert(sibling_tail->id.value);
                            expected.insert(entry->id.value);
                            if (nested_tails.size() < 2 ||
                                expected.size() != nested_tails.size() + 2 ||
                                diamond_predecessors[nested->join->id.value] != expected)
                                continue;
                        } else if (nested->join == header || expected.size() != 3 ||
                                   diamond_predecessors[nested->join->id.value] != expected) {
                            continue;
                        }
                        std::vector<std::pair<std::string, std::string>> sibling_copies;
                        bool phis_valid = true;
                        for (const auto &phi : nested->join->phis) {
                            if (phi.inputs.size() != expected.size()) { phis_valid = false; break; }
                            std::set<std::uint64_t> phi_predecessors;
                            for (const auto &item : phi.inputs)
                                if (!expected.contains(item.predecessor.value) ||
                                    !phi_predecessors.insert(item.predecessor.value).second)
                                    phis_valid = false;
                            if (!phis_valid || phi_predecessors != expected) { phis_valid = false; break; }
                            const auto input = std::find_if(phi.inputs.begin(), phi.inputs.end(), [&](const auto &item) {
                                return item.predecessor == sibling_tail->id;
                            });
                            if (input == phi.inputs.end()) { phis_valid = false; break; }
                            if (nested->yes_break || nested->no_break) {
                                const auto continue_tail = nested->yes_break ?
                                    (nested->no.empty() ? nested->branch : nested->no.back()) :
                                    (nested->yes.empty() ? nested->branch : nested->yes.back());
                                const auto continue_input = std::find_if(phi.inputs.begin(), phi.inputs.end(),
                                    [&](const auto &item) { return item.predecessor == continue_tail->id; });
                                if (continue_input == phi.inputs.end()) { phis_valid = false; break; }
                            } else {
                                const auto *nested_yes_tail = nested->yes.empty() ? nested->branch : nested->yes.back();
                                const auto *nested_no_tail = nested->no.empty() ? nested->branch : nested->no.back();
                                if (std::none_of(phi.inputs.begin(), phi.inputs.end(), [&](const auto &item) {
                                        return item.predecessor == nested_yes_tail->id;
                                    }) || std::none_of(phi.inputs.begin(), phi.inputs.end(), [&](const auto &item) {
                                        return item.predecessor == nested_no_tail->id;
                                    })) { phis_valid = false; break; }
                            }
                            sibling_copies.emplace_back(register_name(phi.destination, phi.version),
                                                        register_name(phi.destination, input->version));
                        }
                        if (!phis_valid) continue;
                        region.join = nested->join;
                        region.latch_to_header = nested->latch_to_header;
                        if (nested_on_true) {
                            region.yes.assign(nested_path.begin(), nested_path.begin() +
                                static_cast<std::ptrdiff_t>(nested_index));
                            region.no = std::move(sibling_arm);
                            region.yes_nested = std::make_shared<LoopConditionalBody>(std::move(*nested));
                            region.no_phi_copies = std::move(sibling_copies);
                        } else {
                            region.no.assign(nested_path.begin(), nested_path.begin() +
                                static_cast<std::ptrdiff_t>(nested_index));
                            region.yes = std::move(sibling_arm);
                            region.no_nested = std::make_shared<LoopConditionalBody>(std::move(*nested));
                            region.yes_phi_copies = std::move(sibling_copies);
                        }
                        return true;
                    }
                    return false;
                };
                if (attach_nested_arm(true) || attach_nested_arm(false)) return region;
            }
            const auto common = std::find_if(region.yes.begin(), region.yes.end(), [&](const auto *block) {
                return std::find(region.no.begin(), region.no.end(), block) != region.no.end();
            });
            if (common == region.yes.end()) return std::nullopt;
            region.join = *common;
            region.yes.erase(common, region.yes.end());
            region.no.erase(std::find(region.no.begin(), region.no.end(), region.join), region.no.end());
            if ((region.yes.empty() && region.no.empty()) || excluded(region.join) ||
                contains_return(*region.join) || region.join->switch_dispatch ||
                !has_only_simple_statements(*region.join) || !valid_diamond_memory_phi(*region.join))
                return std::nullopt;
            const auto valid_arm = [&](const auto &path) {
                auto predecessor = branch.id.value;
                for (std::size_t i = 0; i < path.size(); ++i) {
                    const auto *block = path[i];
                    const auto *next = i + 1 == path.size() ? region.join : path[i + 1];
                    if (!block->phis.empty() || block->switch_dispatch || contains_return(*block) ||
                        !has_only_simple_statements(*block) || !valid_diamond_memory_phi(*block) ||
                        !has_unconditional_edge(*block, next->begin) ||
                        (block->successors.front().kind != BlockEdgeKind::jump &&
                         block->successors.front().kind != BlockEdgeKind::fallthrough) ||
                        diamond_predecessors[block->id.value] != std::set<std::uint64_t>{predecessor})
                        return false;
                    predecessor = block->id.value;
                }
                return true;
            };
            if (!valid_arm(region.yes) || !valid_arm(region.no)) return std::nullopt;
            const auto *yes_tail = region.yes.empty() ? &branch : region.yes.back();
            const auto *no_tail = region.no.empty() ? &branch : region.no.back();
            region.latch_to_header = region.join == header;
            const std::set<std::uint64_t> join_predecessors{
                yes_tail->id.value, no_tail->id.value};
            if (region.latch_to_header) {
                auto expected = join_predecessors;
                expected.insert(entry->id.value);
                const auto &incoming = diamond_predecessors[region.join->id.value];
                if (allow_extra_join_predecessor) {
                    if (expected.size() != 3 || incoming.size() != expected.size() + 1 ||
                        !std::includes(incoming.begin(), incoming.end(), expected.begin(), expected.end()))
                        return std::nullopt;
                } else if (expected.size() != 3 || incoming != expected) {
                    return std::nullopt;
                }
            } else if (allow_extra_join_predecessor) {
                const auto &incoming = diamond_predecessors[region.join->id.value];
                if (join_predecessors.size() != 2 || incoming.size() != 3 ||
                    !std::includes(incoming.begin(), incoming.end(),
                                   join_predecessors.begin(), join_predecessors.end()))
                    return std::nullopt;
            } else if (diamond_predecessors[region.join->id.value] != join_predecessors) {
                return std::nullopt;
            }
            for (const auto &phi : region.join->phis) {
                const auto &incoming = diamond_predecessors[region.join->id.value];
                if (phi.inputs.size() != (region.latch_to_header || allow_extra_join_predecessor ? incoming.size() : 2))
                    return std::nullopt;
                std::set<std::uint64_t> input_predecessors;
                for (const auto &input : phi.inputs)
                    if (!incoming.contains(input.predecessor.value) ||
                        !input_predecessors.insert(input.predecessor.value).second)
                        return std::nullopt;
                if (input_predecessors != incoming) return std::nullopt;
                const auto yes_input = std::find_if(phi.inputs.begin(), phi.inputs.end(),
                    [&](const auto &input) { return input.predecessor == yes_tail->id; });
                const auto no_input = std::find_if(phi.inputs.begin(), phi.inputs.end(),
                    [&](const auto &input) { return input.predecessor == no_tail->id; });
                if (yes_input == phi.inputs.end() || no_input == phi.inputs.end()) return std::nullopt;
                const auto destination = register_name(phi.destination, phi.version);
                region.yes_phi_copies.emplace_back(destination, register_name(phi.destination, yes_input->version));
                region.no_phi_copies.emplace_back(destination, register_name(phi.destination, no_input->version));
            }
            return region;
        };
        std::vector<const LiftedBlock *> exit_path;
        std::set<std::uint64_t> exit_path_ids;
        bool loop_body_edges_valid = true;
        bool exit_path_valid = true;
        const auto trace_loop_exit_path = [&](Address target, std::uint64_t predecessor)
            -> std::optional<std::vector<const LiftedBlock *>> {
            std::vector<const LiftedBlock *> path;
            if (!exit_block) return std::nullopt;
            if (target == exit_block->begin) return path;
            const auto *target_block = find_block(target);
            if (target_block) {
                const auto shared = shared_loop_break_paths.find(target_block->id.value);
                if (shared != shared_loop_break_paths.end()) {
                    shared_loop_break_sources[target_block->id.value].insert(predecessor);
                    return shared->second;
                }
            }
            std::set<std::uint64_t> seen;
            auto *candidate = find_block(target);
            while (candidate && candidate != exit_block && candidate != body_start &&
                   candidate != header && candidate != entry &&
                   !loop_body_ids.contains(candidate->id.value) &&
                   !loop_break_path_ids.contains(candidate->id.value) &&
                   seen.insert(candidate->id.value).second && path.size() < 64 &&
                   candidate->phis.empty() && !candidate->memory_phi &&
                   candidate->memory_partition_phis.empty() && !contains_return(*candidate) &&
                   !candidate->switch_dispatch && has_only_simple_statements(*candidate) &&
                   candidate->successors.size() == 1 && candidate->successors.front().target &&
                   (candidate->successors.front().kind == BlockEdgeKind::jump ||
                    candidate->successors.front().kind == BlockEdgeKind::fallthrough) &&
                   has_unconditional_edge(*candidate, *candidate->successors.front().target) &&
                   (diamond_predecessors[candidate->id.value] == std::set<std::uint64_t>{predecessor} ||
                    (path.empty() && diamond_predecessors[candidate->id.value].contains(predecessor) &&
                     std::all_of(diamond_predecessors[candidate->id.value].begin(),
                         diamond_predecessors[candidate->id.value].end(), [&](const auto source_id) {
                             const auto source = std::find_if(function.blocks.begin(), function.blocks.end(),
                                 [&](const auto &block) { return block.id.value == source_id; });
                             if (source == function.blocks.end()) return false;
                             const auto *source_condition = terminal_conditional(*source);
                             return source_condition && source_condition->true_target && source_condition->false_target &&
                                 (*source_condition->true_target == candidate->begin ||
                                  *source_condition->false_target == candidate->begin);
                         })))) {
                path.push_back(candidate);
                predecessor = candidate->id.value;
                candidate = find_block(*candidate->successors.front().target);
            }
            if (candidate != exit_block || exit_block->memory_phi ||
                !exit_block->memory_partition_phis.empty() ||
                !diamond_predecessors[exit_block->id.value].contains(predecessor))
                return std::nullopt;
            return path;
        };
        auto *body = body_start;
        while (body && body != header && body != entry && body != exit_block &&
               !loop_break_path_ids.contains(body->id.value) &&
               loop_body.size() < function.blocks.size() && loop_body_ids.insert(body->id.value).second &&
               (body->phis.empty() || conditional_phi_joins.contains(body->id.value)) && !contains_return(*body) &&
               (body->switch_dispatch || has_only_simple_statements(*body)) &&
               (body->switch_dispatch ? body->successors.size() >= 2 :
                    body->successors.size() >= 1 && body->successors.size() <= 2)) {
            Address next_address{};
            const auto *body_condition = terminal_conditional(*body);
            if (body->switch_dispatch) {
                const auto &dispatch = *body->switch_dispatch;
                bool valid = dispatch.complete && dispatch.selector && dispatch.default_target &&
                    !dispatch.cases.empty() && body->successors.size() >= 2;
                std::set<std::pair<std::uint64_t, std::uint64_t>> targets;
                std::set<std::uint64_t> case_values;
                for (const auto &item : dispatch.cases) {
                    valid = valid && case_values.insert(item.value).second;
                    targets.emplace(item.target.space.value, item.target.offset);
                }
                targets.emplace(dispatch.default_target->space.value, dispatch.default_target->offset);
                valid = valid && targets.size() == body->successors.size();
                for (const auto &edge : body->successors) {
                    valid = valid && edge.target &&
                        targets.contains({edge.target->space.value, edge.target->offset}) &&
                        edge_targets(edge, *edge.target);
                }
                LoopSwitchBody region;
                std::vector<std::vector<const LiftedBlock *>> traces;
                std::vector<Address> unique_targets;
                for (const auto &[space, offset] : targets) {
                    const Address target{{static_cast<std::uint32_t>(space)}, offset};
                    unique_targets.push_back(target);
                    std::vector<const LiftedBlock *> trace;
                    auto *current = find_block(target);
                    std::set<std::uint64_t> seen;
                    while (valid && current && current != body && current != header && current != exit_block &&
                           trace.size() < function.blocks.size() && seen.insert(current->id.value).second &&
                           current->phis.empty() && !contains_return(*current) &&
                           has_only_simple_statements(*current) && current->successors.size() == 1 &&
                           current->successors.front().target &&
                           (current->successors.front().kind == BlockEdgeKind::jump ||
                            current->successors.front().kind == BlockEdgeKind::fallthrough) &&
                           has_unconditional_edge(*current, *current->successors.front().target)) {
                        trace.push_back(current);
                        current = find_block(*current->successors.front().target);
                    }
                    if (!current || trace.empty() || current == body || current == exit_block ||
                        current->phis.size() || current->switch_dispatch || current->id == body->id) valid = false;
                    traces.push_back(std::move(trace));
                }
                const LiftedBlock *join = nullptr;
                if (valid && !traces.empty()) {
                    for (const auto *candidate : traces.front()) {
                        const bool common = std::all_of(traces.begin() + 1, traces.end(), [&](const auto &trace) {
                            return std::find(trace.begin(), trace.end(), candidate) != trace.end();
                        });
                        if (common) { join = candidate; break; }
                    }
                }
                if (!join || join == body || join == header || join == exit_block) valid = false;
                if (valid) {
                    for (std::size_t i = 0; i < traces.size(); ++i) {
                        auto &trace = traces[i];
                        const auto at_join = std::find(trace.begin(), trace.end(), join);
                        if (at_join == trace.end()) { valid = false; break; }
                        trace.erase(at_join, trace.end());
                        for (const auto *arm_block : trace) {
                            if (!loop_body_ids.insert(arm_block->id.value).second) valid = false;
                        }
                        LoopSwitchArm arm;
                        const auto target = unique_targets[i];
                        arm.target = target;
                        for (const auto &item : dispatch.cases)
                            if (item.target == target) arm.values.push_back(item.value);
                        arm.is_default = *dispatch.default_target == target;
                        arm.body = trace;
                        region.arms.push_back(std::move(arm));
                    }
                }
                if (valid) {
                    // Store arms in target order; case values are looked up during emission.
                    region.continuation = join;
                    switch_loop_bodies.emplace(body->id.value, std::move(region));
                    next_address = join->begin;
                } else {
                    loop_body_edges_valid = false;
                    break;
                }
            } else if (body_condition && body->successors.size() == 2 &&
                body_condition->true_target && body_condition->false_target) {
                const bool exact_condition_edges =
                    std::count_if(body->successors.begin(), body->successors.end(), [&](const auto &edge) {
                        return edge_targets(edge, *body_condition->true_target);
                    }) == 1 &&
                    std::count_if(body->successors.begin(), body->successors.end(), [&](const auto &edge) {
                        return edge_targets(edge, *body_condition->false_target);
                    }) == 1;
                if (!exact_condition_edges) {
                    loop_body_edges_valid = false;
                    break;
                }
                const auto true_exit_path = trace_loop_exit_path(*body_condition->true_target, body->id.value);
                const auto false_exit_path = trace_loop_exit_path(*body_condition->false_target, body->id.value);
                const bool true_exits = true_exit_path.has_value();
                const bool false_exits = false_exit_path.has_value();
                const bool true_continues = *body_condition->true_target == header->begin;
                const bool false_continues = *body_condition->false_target == header->begin;
                if (true_exits != false_exits) {
                    const auto &break_path = true_exits ? *true_exit_path : *false_exit_path;
                    const auto *path_head = break_path.empty() ? nullptr : break_path.front();
                    const bool shared_path = path_head && shared_loop_break_paths.contains(path_head->id.value);
                    if (path_head && !shared_path) {
                        shared_loop_break_paths.emplace(path_head->id.value, break_path);
                        shared_loop_break_sources[path_head->id.value].insert(body->id.value);
                    }
                    for (const auto *path_block : break_path)
                        if (!loop_break_path_ids.insert(path_block->id.value).second && !shared_path) {
                            loop_body_edges_valid = false;
                            break;
                        }
                    if (!loop_body_edges_valid) break;
                    if (shared_path) shared_loop_break_sources[path_head->id.value].insert(body->id.value);
                    loop_breaks.push_back({body, true_exits, break_path});
                    next_address = true_exits ? *body_condition->false_target : *body_condition->true_target;
                } else {
                    const auto trace_return_path = [&](Address target,
                                                       std::vector<std::pair<std::string, std::string>> &phi_copies) {
                        std::vector<const LiftedBlock *> path;
                        std::set<std::uint64_t> seen;
                        auto *candidate = find_block(target);
                        auto predecessor = body->id.value;
                        while (candidate && candidate != body && candidate != header && candidate != entry &&
                               candidate != exit_block && !loop_body_ids.contains(candidate->id.value) &&
                               std::none_of(loop_returns.begin(), loop_returns.end(), [&](const auto &prior) {
                                   return std::find(prior.path.begin(), prior.path.end(), candidate) != prior.path.end();
                               }) &&
                               seen.insert(candidate->id.value).second && path.size() < function.blocks.size() &&
                               (candidate->phis.empty() || has_only_terminal_return(*candidate)) &&
                               has_only_simple_statements(*candidate) &&
                               valid_diamond_memory_phi(*candidate) &&
                               diamond_predecessors[candidate->id.value] == std::set<std::uint64_t>{predecessor}) {
                            path.push_back(candidate);
                            if (has_only_terminal_return(*candidate)) {
                                std::vector<RegisterOperand> destinations;
                                for (const auto &phi : candidate->phis) {
                                    if (std::find(destinations.begin(), destinations.end(), phi.destination) != destinations.end() ||
                                        phi.inputs.size() != 1 || phi.inputs.front().predecessor.value != predecessor) {
                                        path.clear();
                                        return path;
                                    }
                                    destinations.push_back(phi.destination);
                                    phi_copies.emplace_back(register_name(phi.destination, phi.version),
                                        register_name(phi.destination, phi.inputs.front().version));
                                }
                                return path;
                            }
                            if (contains_return(*candidate) || candidate->successors.size() != 1 ||
                                !candidate->successors.front().target ||
                                (candidate->successors.front().kind != BlockEdgeKind::jump &&
                                 candidate->successors.front().kind != BlockEdgeKind::fallthrough) ||
                                !has_unconditional_edge(*candidate, *candidate->successors.front().target))
                                break;
                            predecessor = candidate->id.value;
                            candidate = find_block(*candidate->successors.front().target);
                        }
                        path.clear();
                        return path;
                    };
                    std::vector<std::pair<std::string, std::string>> true_return_phi_copies;
                    std::vector<std::pair<std::string, std::string>> false_return_phi_copies;
                    const auto true_return = trace_return_path(*body_condition->true_target, true_return_phi_copies);
                    const auto false_return = trace_return_path(*body_condition->false_target, false_return_phi_copies);
                    if (body->phis.empty() && true_return.empty() != false_return.empty()) {
                        const bool return_on_true = !true_return.empty();
                        loop_returns.push_back({body, return_on_true ? true_return : false_return, return_on_true,
                            return_on_true ? std::move(true_return_phi_copies) :
                                             std::move(false_return_phi_copies)});
                        next_address = return_on_true ? *body_condition->false_target : *body_condition->true_target;
                        loop_body.push_back(body);
                        if (next_address == header->begin) break;
                        body = find_block(next_address);
                        continue;
                    }
                    if (true_continues != false_continues) {
                        loop_continues.emplace_back(body, true_continues);
                        next_address = true_continues ? *body_condition->false_target : *body_condition->true_target;
                    } else {
                    // Parent and child loops share the same arm ownership and
                    // edge-phi proof; only their continuation walks differ.
                    if (auto parent_diamond = analyze_loop_diamond(*body, loop_body_ids, exit_block,
                                                                  true, false, true, 0)) {
                        next_address = parent_diamond->join->begin;
                        conditional_phi_joins.insert(parent_diamond->join->id.value);
                        const auto claim_region = [&](const auto &region, const auto &self) -> void {
                            for (const auto *arm_block : region.yes) loop_body_ids.insert(arm_block->id.value);
                            for (const auto *arm_block : region.no) loop_body_ids.insert(arm_block->id.value);
                            for (const auto *path_block : region.yes_break_path) loop_body_ids.insert(path_block->id.value);
                            for (const auto *path_block : region.no_break_path) loop_body_ids.insert(path_block->id.value);
                            for (const auto *nested : {region.yes_nested.get(), region.no_nested.get()}) {
                                if (!nested) continue;
                                loop_body_ids.insert(nested->branch->id.value);
                                self(*nested, self);
                            }
                        };
                        claim_region(*parent_diamond, claim_region);
                        conditional_loop_bodies.emplace(body->id.value, std::move(*parent_diamond));
                    } else {
                        NestedLoopBody nested;
                        bool inner_valid = false;
                        // A child loop's exit is the join that resumes the parent
                        // body, so it need not equal the parent's exit block.
                        for (const bool true_enters : {true, false}) {
                            NestedLoopBody candidate;
                            candidate.header = body;
                            candidate.condition_true_enters = true_enters;
                            const Address inner_body_address = true_enters ? *body_condition->true_target :
                                *body_condition->false_target;
                            const Address inner_exit_address = true_enters ? *body_condition->false_target :
                                *body_condition->true_target;
                            candidate.exit = find_block(inner_exit_address);
                            const auto *inner_body = find_block(inner_body_address);
                            std::set<std::uint64_t> inner_ids{body->id.value};
                            bool candidate_valid = candidate.exit && candidate.exit != body && inner_body &&
                                                   inner_body != body;
                            auto *inner_current = inner_body;
                            while (candidate_valid && inner_current && inner_current != body &&
                                   candidate.body.size() < function.blocks.size() &&
                                   !inner_ids.contains(inner_current->id.value)) {
                                if (inner_current == entry || inner_current == header ||
                                    inner_current == exit_block || inner_current == candidate.exit ||
                                    loop_body_ids.contains(inner_current->id.value) ||
                                    contains_return(*inner_current) || inner_current->switch_dispatch) {
                                    candidate_valid = false;
                                    break;
                                }
                                const auto *inner_condition = terminal_conditional(*inner_current);
                                if (inner_condition) {
                                    // A conditional edge may reach the child
                                    // header through a bounded phi-free cleanup
                                    // chain. Emit that chain under the continue
                                    // predicate before applying header phis.
                                    const auto trace_child_continue_path = [&](const std::optional<Address> &target)
                                        -> std::optional<std::vector<const LiftedBlock *>> {
                                        if (!target) return std::nullopt;
                                        std::vector<const LiftedBlock *> path;
                                        if (*target == body->begin) return path;
                                        auto *cursor = find_block(*target);
                                        auto predecessor = inner_current->id.value;
                                        std::set<std::uint64_t> seen;
                                        while (cursor && cursor != body && cursor != candidate.exit &&
                                               cursor != header && cursor != entry && cursor != exit_block &&
                                               !loop_body_ids.contains(cursor->id.value) &&
                                               !inner_ids.contains(cursor->id.value) &&
                                               path.size() < max_nested_child_cleanup_blocks &&
                                               seen.insert(cursor->id.value).second) {
                                            if (!cursor->phis.empty() || cursor->switch_dispatch ||
                                                contains_return(*cursor) || !has_only_simple_statements(*cursor) ||
                                                cursor->memory_phi || !cursor->memory_partition_phis.empty() ||
                                                cursor->successors.size() != 1 ||
                                                !cursor->successors.front().target ||
                                                (cursor->successors.front().kind != BlockEdgeKind::jump &&
                                                 cursor->successors.front().kind != BlockEdgeKind::fallthrough) ||
                                                !has_unconditional_edge(*cursor, *cursor->successors.front().target) ||
                                                diamond_predecessors[cursor->id.value] !=
                                                    std::set<std::uint64_t>{predecessor})
                                                return std::nullopt;
                                            path.push_back(cursor);
                                            predecessor = cursor->id.value;
                                            cursor = find_block(*cursor->successors.front().target);
                                        }
                                        if (cursor != body ||
                                            !diamond_predecessors[body->id.value].contains(predecessor))
                                            return std::nullopt;
                                        return path;
                                    };
                                    const auto true_continue_path = trace_child_continue_path(inner_condition->true_target);
                                    const auto false_continue_path = trace_child_continue_path(inner_condition->false_target);
                                    const bool true_continue = true_continue_path.has_value();
                                    const bool false_continue = false_continue_path.has_value();
                                    if (true_continue != false_continue && inner_current->phis.empty()) {
                                        const Address continuation_address = true_continue ?
                                            *inner_condition->false_target : *inner_condition->true_target;
                                        const auto *continuation = find_block(continuation_address);
                                        if (continuation && continuation != body && continuation != candidate.exit &&
                                            continuation != entry && continuation != header &&
                                            !loop_body_ids.contains(continuation->id.value) &&
                                            std::none_of(candidate.conditional_continues.begin(),
                                                candidate.conditional_continues.end(), [&](const auto &previous) {
                                                    return previous.first == inner_current;
                                                })) {
                                            candidate.body.push_back(inner_current);
                                            inner_ids.insert(inner_current->id.value);
                                            candidate.conditional_continues.emplace_back(inner_current, true_continue);
                                            const auto &continue_path = true_continue ? *true_continue_path :
                                                *false_continue_path;
                                            candidate.conditional_continue_paths.emplace(inner_current->id.value,
                                                continue_path);
                                            for (const auto *path_block : continue_path)
                                                inner_ids.insert(path_block->id.value);
                                            inner_current = continuation;
                                            continue;
                                        }
                                    }
                                    // A conditional edge may reach the child
                                    // exit through a bounded, single-entry
                                    // cleanup chain. Preserve that chain under
                                    // the original break predicate and apply
                                    // exit phis on its final edge.
                                    const auto trace_child_break_path = [&](const std::optional<Address> &target)
                                        -> std::optional<std::vector<const LiftedBlock *>> {
                                        if (!target) return std::nullopt;
                                        std::vector<const LiftedBlock *> path;
                                        auto *cursor = find_block(*target);
                                        auto predecessor = inner_current->id.value;
                                        std::set<std::uint64_t> seen;
                                        while (cursor && cursor != candidate.exit && cursor != body &&
                                               cursor != header && cursor != entry && cursor != exit_block &&
                                               !loop_body_ids.contains(cursor->id.value) &&
                                               (!inner_ids.contains(cursor->id.value) ||
                                                std::any_of(candidate.conditional_break_paths.begin(),
                                                    candidate.conditional_break_paths.end(), [&](const auto &prior) {
                                                        return std::find(prior.second.begin(), prior.second.end(), cursor) !=
                                                            prior.second.end();
                                                    })) &&
                                               path.size() < max_nested_child_cleanup_blocks &&
                                               seen.insert(cursor->id.value).second) {
                                            if (!cursor->phis.empty() || cursor->switch_dispatch ||
                                                contains_return(*cursor) || !has_only_simple_statements(*cursor) ||
                                                cursor->memory_phi || !cursor->memory_partition_phis.empty() ||
                                                cursor->successors.size() != 1 ||
                                                !cursor->successors.front().target ||
                                                (cursor->successors.front().kind != BlockEdgeKind::jump &&
                                                 cursor->successors.front().kind != BlockEdgeKind::fallthrough) ||
                                                !has_unconditional_edge(*cursor, *cursor->successors.front().target))
                                                return std::nullopt;
                                            path.push_back(cursor);
                                            predecessor = cursor->id.value;
                                            cursor = find_block(*cursor->successors.front().target);
                                        }
                                        if (cursor != candidate.exit ||
                                            diamond_predecessors[candidate.exit->id.value].contains(predecessor) == false)
                                            return std::nullopt;
                                        return path;
                                    };
                                    const auto true_break_path = trace_child_break_path(inner_condition->true_target);
                                    const auto false_break_path = trace_child_break_path(inner_condition->false_target);
                                    const bool true_break = true_break_path.has_value();
                                    const bool false_break = false_break_path.has_value();
                                    if (true_break != false_break && inner_current->phis.empty()) {
                                        const auto &break_path = true_break ? *true_break_path : *false_break_path;
                                        const auto valid_break_path = [&](const std::vector<const LiftedBlock *> &path) {
                                            if (path.empty())
                                                return diamond_predecessors[candidate.exit->id.value].contains(
                                                    inner_current->id.value);
                                            std::set<std::uint64_t> shared_head_predecessors{inner_current->id.value};
                                            for (const auto &[prior_branch, prior_path] : candidate.conditional_break_paths)
                                                if (prior_path == path) shared_head_predecessors.insert(prior_branch);
                                            for (std::size_t path_index = 0; path_index < path.size(); ++path_index) {
                                                const auto expected = path_index == 0 ? shared_head_predecessors :
                                                    std::set<std::uint64_t>{path[path_index - 1]->id.value};
                                                if (diamond_predecessors[path[path_index]->id.value] != expected) return false;
                                            }
                                            return diamond_predecessors[candidate.exit->id.value].contains(
                                                path.back()->id.value);
                                        };
                                        if (!valid_break_path(break_path)) {
                                            candidate_valid = false;
                                            break;
                                        }
                                        const Address continue_target = true_break ?
                                            *inner_condition->false_target : *inner_condition->true_target;
                                        const auto *continuation = find_block(continue_target);
                                        if (continuation && continuation != body && continuation != candidate.exit &&
                                            continuation != entry && continuation != header &&
                                            !loop_body_ids.contains(continuation->id.value) &&
                                            !contains_return(*inner_current) &&
                                            std::none_of(candidate.conditional_breaks.begin(),
                                                candidate.conditional_breaks.end(), [&](const auto &previous) {
                                                    return previous.first == inner_current;
                                                })) {
                                            candidate.body.push_back(inner_current);
                                            inner_ids.insert(inner_current->id.value);
                                            candidate.conditional_breaks.emplace_back(inner_current, true_break);
                                            candidate.conditional_break_paths.emplace(inner_current->id.value, break_path);
                                            for (const auto *path_block : break_path)
                                                inner_ids.insert(path_block->id.value);
                                            inner_current = continuation;
                                            continue;
                                        }
                                    }
                                    // A return-only side exit is safe to emit
                                    // inside the child loop when its complete
                                    // path is single-entry and the sibling edge
                                    // remains on the child body's linear spine.
                                    // Keep return blocks separately owned so
                                    // they are emitted only under this guard.
                                    const auto trace_child_return_path = [&](const std::optional<Address> &target)
                                        -> std::optional<std::vector<const LiftedBlock *>> {
                                        if (!target) return std::nullopt;
                                        std::vector<const LiftedBlock *> path;
                                        auto *cursor = find_block(*target);
                                        auto predecessor = inner_current->id.value;
                                        std::set<std::uint64_t> seen;
                                        while (cursor && cursor != body && cursor != candidate.exit &&
                                               cursor != header && cursor != entry && cursor != exit_block &&
                                               !loop_body_ids.contains(cursor->id.value) &&
                                               !inner_ids.contains(cursor->id.value) &&
                                               path.size() < 64 && seen.insert(cursor->id.value).second) {
                                            if (!cursor->phis.empty() || cursor->switch_dispatch ||
                                                !has_only_simple_statements(*cursor) ||
                                                !valid_diamond_memory_phi(*cursor) ||
                                                diamond_predecessors[cursor->id.value] !=
                                                    std::set<std::uint64_t>{predecessor})
                                                return std::nullopt;
                                            path.push_back(cursor);
                                            if (has_only_terminal_return(*cursor)) return path;
                                            if (contains_return(*cursor) || cursor->successors.size() != 1 ||
                                                !cursor->successors.front().target ||
                                                (cursor->successors.front().kind != BlockEdgeKind::jump &&
                                                 cursor->successors.front().kind != BlockEdgeKind::fallthrough) ||
                                                !has_unconditional_edge(*cursor, *cursor->successors.front().target))
                                                return std::nullopt;
                                            predecessor = cursor->id.value;
                                            cursor = find_block(*cursor->successors.front().target);
                                        }
                                        return std::nullopt;
                                    };
                                    const auto true_return_path = trace_child_return_path(inner_condition->true_target);
                                    const auto false_return_path = trace_child_return_path(inner_condition->false_target);
                                    if (true_return_path.has_value() != false_return_path.has_value() &&
                                        inner_current->phis.empty()) {
                                        const bool return_on_true = true_return_path.has_value();
                                        const auto &return_path = return_on_true ? *true_return_path : *false_return_path;
                                        const Address continue_target = return_on_true ?
                                            *inner_condition->false_target : *inner_condition->true_target;
                                        const auto *continuation = find_block(continue_target);
                                        if (continuation && continuation != body && continuation != candidate.exit &&
                                            continuation != entry && continuation != header &&
                                            !loop_body_ids.contains(continuation->id.value) &&
                                            !inner_ids.contains(continuation->id.value) &&
                                            !contains_return(*inner_current)) {
                                            candidate.body.push_back(inner_current);
                                            inner_ids.insert(inner_current->id.value);
                                            candidate.conditional_returns.push_back(
                                                {inner_current, return_path, return_on_true});
                                            for (const auto *path_block : return_path)
                                                inner_ids.insert(path_block->id.value);
                                            inner_current = continuation;
                                            continue;
                                        }
                                    }
                                    // Trace disjoint multi-block arms to their first
                                    // shared continuation, leaving that join in the
                                    // child chain so its effects execute once.
                                    auto occupied = loop_body_ids;
                                    occupied.insert(inner_ids.begin(), inner_ids.end());
                                    auto region = analyze_loop_diamond(*inner_current, occupied, candidate.exit,
                                                                      false, false, false, 0);
                                    const bool is_join = std::any_of(candidate.conditional_joins.begin(),
                                        candidate.conditional_joins.end(), [&](const auto &previous) {
                                            return inner_current == previous.join;
                                        });
                                    if (!region || (!inner_current->phis.empty() && !is_join)) {
                                        candidate_valid = false;
                                        break;
                                    }
                                    const auto *join = region->join;
                                    const bool linear_join = join->successors.size() == 1 &&
                                        join->successors.front().target &&
                                        has_unconditional_edge(*join, *join->successors.front().target);
                                    if (!linear_join && !terminal_conditional(*join)) {
                                        candidate_valid = false;
                                        break;
                                    }
                                    candidate.body.push_back(inner_current);
                                    inner_ids.insert(inner_current->id.value);
                                    for (const auto *arm_block : region->yes) {
                                        candidate.body.push_back(arm_block);
                                        inner_ids.insert(arm_block->id.value);
                                    }
                                    for (const auto *arm_block : region->no) {
                                        candidate.body.push_back(arm_block);
                                        inner_ids.insert(arm_block->id.value);
                                    }
                                    candidate.conditional_joins.push_back(std::move(*region));
                                    inner_current = join;
                                    continue;
                                }

                                const bool is_join = std::any_of(candidate.conditional_joins.begin(),
                                    candidate.conditional_joins.end(), [&](const auto &region) {
                                        return inner_current == region.join;
                                    });
                                if (inner_current->phis.size() && !is_join) {
                                    candidate_valid = false;
                                    break;
                                }
                                if (!has_only_simple_statements(*inner_current) ||
                                    inner_current->successors.size() != 1 ||
                                    !inner_current->successors.front().target ||
                                    !has_unconditional_edge(*inner_current, *inner_current->successors.front().target)) {
                                    candidate_valid = false;
                                    break;
                                }
                                if (!inner_ids.insert(inner_current->id.value).second) {
                                    candidate_valid = false;
                                    break;
                                }
                                candidate.body.push_back(inner_current);
                                const auto next = *inner_current->successors.front().target;
                                if (next == body->begin) break;
                                inner_current = find_block(next);
                            }
                            const auto *inner_latch = candidate.body.empty() ? nullptr : candidate.body.back();
                            candidate_valid = candidate_valid && inner_latch && inner_latch->successors.size() == 1 &&
                                edge_targets(inner_latch->successors.front(), body->begin) &&
                                candidate.exit->successors.size() == 1 && candidate.exit->successors.front().target &&
                                *candidate.exit->successors.front().target != body->begin &&
                                candidate.exit != inner_latch &&
                                std::none_of(candidate.body.begin(), candidate.body.end(), [&](const auto *block) {
                                    return block->id == candidate.exit->id;
                                });
                            if (candidate_valid && (!candidate.conditional_joins.empty() ||
                                !candidate.conditional_breaks.empty() ||
                                !candidate.conditional_returns.empty() ||
                                !candidate.conditional_continues.empty())) {
                                // Arm ownership alone is insufficient if an outside
                                // edge can enter another block of the child body.
                                // The sole entry is the child header's body edge.
                                for (const auto *block : candidate.body) {
                                    const auto &incoming = diamond_predecessors[block->id.value];
                                    if (!valid_diamond_memory_phi(*block) ||
                                        (block == inner_body ? incoming != std::set<std::uint64_t>{body->id.value} :
                                            std::any_of(incoming.begin(), incoming.end(), [&](auto predecessor) {
                                                return predecessor == body->id.value || !inner_ids.contains(predecessor);
                                            }))) {
                                        candidate_valid = false;
                                        break;
                                    }
                                }
                                candidate_valid = candidate_valid && valid_diamond_memory_phi(*body) &&
                                    valid_diamond_memory_phi(*candidate.exit);
                            }
                            if (candidate_valid) {
                                std::set<std::uint64_t> header_predecessors;
                                std::set<std::uint64_t> exit_predecessors;
                                for (const auto &source : function.blocks) {
                                    for (const auto &edge : source.successors) {
                                        if (edge_targets(edge, body->begin)) header_predecessors.insert(source.id.value);
                                        if (edge_targets(edge, candidate.exit->begin)) exit_predecessors.insert(source.id.value);
                                    }
                                }
                                // The header has one preheader and one latch. The
                                // exit has its failed header condition and any
                                // explicitly recognized conditional-break edges.
                                const bool has_latch_predecessor = header_predecessors.contains(inner_latch->id.value);
                                std::set<std::uint64_t> child_backedges{inner_latch->id.value};
                                for (const auto &[branch, _] : candidate.conditional_continues)
                                {
                                    const auto path = candidate.conditional_continue_paths.find(branch->id.value);
                                    child_backedges.insert(path == candidate.conditional_continue_paths.end() ||
                                        path->second.empty() ? branch->id.value : path->second.back()->id.value);
                                }
                                const bool has_all_backedges = std::all_of(child_backedges.begin(), child_backedges.end(),
                                    [&](auto predecessor) { return header_predecessors.contains(predecessor); });
                                for (const auto predecessor : child_backedges) header_predecessors.erase(predecessor);
                                std::set<std::uint64_t> expected_exit_predecessors{body->id.value};
                                for (const auto &[branch, _] : candidate.conditional_breaks) {
                                    const auto path = candidate.conditional_break_paths.find(branch->id.value);
                                    const auto *tail = path == candidate.conditional_break_paths.end() ||
                                        path->second.empty() ? branch : path->second.back();
                                    expected_exit_predecessors.insert(tail->id.value);
                                }
                                if (!has_latch_predecessor || !has_all_backedges || header_predecessors.size() != 1 ||
                                    exit_predecessors != expected_exit_predecessors) candidate_valid = false;
                                const auto preheader_id = header_predecessors.empty() ? 0 : *header_predecessors.begin();
                                for (const auto &phi : body->phis) {
                                    if (phi.inputs.size() != child_backedges.size() + 1) { candidate_valid = false; break; }
                                    const auto initial = std::find_if(phi.inputs.begin(), phi.inputs.end(), [&](const auto &input) {
                                        return input.predecessor.value == preheader_id;
                                    });
                                    if (initial == phi.inputs.end()) { candidate_valid = false; break; }
                                    const auto destination = register_name(phi.destination, phi.version);
                                    candidate.initial_phi_copies.emplace_back(destination, register_name(phi.destination, initial->version));
                                    std::set<std::uint64_t> seen_backedges;
                                    for (const auto &input : phi.inputs) {
                                        if (input.predecessor.value == preheader_id) continue;
                                        if (!child_backedges.contains(input.predecessor.value) ||
                                            !seen_backedges.insert(input.predecessor.value).second) {
                                            candidate_valid = false;
                                            break;
                                        }
                                        auto copy = std::make_pair(destination, register_name(phi.destination, input.version));
                                        candidate.backedge_phi_copies[input.predecessor.value].push_back(copy);
                                        if (input.predecessor == inner_latch->id)
                                            candidate.recurrent_phi_copies.push_back(std::move(copy));
                                    }
                                    if (!candidate_valid || seen_backedges != child_backedges) {
                                        candidate_valid = false;
                                        break;
                                    }
                                }
                                for (const auto &phi : candidate.exit->phis) {
                                    if (phi.inputs.size() != exit_predecessors.size()) {
                                        candidate_valid = false; break;
                                    }
                                    std::set<std::uint64_t> seen_inputs;
                                    for (const auto &input : phi.inputs) {
                                        if (!exit_predecessors.contains(input.predecessor.value) ||
                                            !seen_inputs.insert(input.predecessor.value).second) {
                                            candidate_valid = false;
                                            break;
                                        }
                                        candidate.exit_phi_copies[input.predecessor.value].emplace_back(
                                            register_name(phi.destination, phi.version),
                                            register_name(phi.destination, input.version));
                                    }
                                    if (!candidate_valid) break;
                                }
                            }
                            if (candidate_valid) {
                                nested = std::move(candidate);
                                inner_valid = true;
                                break;
                            }
                        }
                        if (!inner_valid || nested_loop_bodies.contains(body->id.value)) {
                            loop_body_edges_valid = false;
                            break;
                        }
                        loop_body_ids.insert(body->id.value);
                        for (const auto *inner_block : nested.body) loop_body_ids.insert(inner_block->id.value);
                        for (const auto &[branch_id, path] : nested.conditional_break_paths) {
                            (void)branch_id;
                            for (const auto *path_block : path) loop_body_ids.insert(path_block->id.value);
                        }
                        for (const auto &[branch_id, path] : nested.conditional_continue_paths) {
                            (void)branch_id;
                            for (const auto *path_block : path) loop_body_ids.insert(path_block->id.value);
                        }
                        for (const auto &side_return : nested.conditional_returns)
                            for (const auto *path_block : side_return.path)
                                loop_body_ids.insert(path_block->id.value);
                        const auto nested_exit_address = nested.exit->begin;
                        nested_loop_bodies.emplace(body->id.value, std::move(nested));
                        next_address = nested_exit_address;
                    }
                    }
                }
            } else if (body->successors.size() == 1 && body->successors.front().target) {
                next_address = *body->successors.front().target;
                if (!has_unconditional_edge(*body, next_address)) {
                    loop_body_edges_valid = false;
                    break;
                }
            } else {
                loop_body_edges_valid = false;
                break;
            }
            loop_body.push_back(body);
            if (next_address == header->begin) break;
            body = find_block(next_address);
        }
        for (const auto &[head_id, sources] : shared_loop_break_sources) {
            const auto head = std::find_if(function.blocks.begin(), function.blocks.end(),
                [&](const auto &candidate) { return candidate.id.value == head_id; });
            if (head == function.blocks.end() || sources.size() < 2 ||
                diamond_predecessors[head_id] != sources) {
                loop_body_edges_valid = false;
                break;
            }
        }
        std::vector<std::pair<std::string, std::string>> loop_condition_exit_phi_copies;
        if (exit_block && !exit_block->phis.empty()) {
            std::set<std::uint64_t> expected_exit_predecessors{header->id.value};
            std::map<std::uint64_t, std::vector<LoopBreakPath *>> break_by_predecessor;
            for (auto &loop_break : loop_breaks) {
                const auto *tail = loop_break.path.empty() ? loop_break.branch : loop_break.path.back();
                if (!tail) {
                    loop_body_edges_valid = false;
                    break;
                }
                break_by_predecessor[tail->id.value].push_back(&loop_break);
                expected_exit_predecessors.insert(tail->id.value);
            }
            if (loop_body_edges_valid && diamond_predecessors[exit_block->id.value] != expected_exit_predecessors)
                loop_body_edges_valid = false;
            if (loop_body_edges_valid &&
                (exit_block->phis.size() > 4096 || !valid_diamond_memory_phi(*exit_block)))
                loop_body_edges_valid = false;
            for (const auto &phi : exit_block->phis) {
                if (!loop_body_edges_valid) break;
                if (phi.inputs.size() != expected_exit_predecessors.size()) {
                    loop_body_edges_valid = false;
                    break;
                }
                std::set<std::uint64_t> seen_predecessors;
                const auto destination = register_name(phi.destination, phi.version);
                for (const auto &input : phi.inputs) {
                    const auto predecessor = input.predecessor.value;
                    if (!expected_exit_predecessors.contains(predecessor) ||
                        !seen_predecessors.insert(predecessor).second) {
                        loop_body_edges_valid = false;
                        break;
                    }
                    auto copy = std::make_pair(destination, register_name(phi.destination, input.version));
                    if (predecessor == header->id.value) {
                        loop_condition_exit_phi_copies.push_back(std::move(copy));
                    } else {
                        const auto found = break_by_predecessor.find(predecessor);
                        if (found == break_by_predecessor.end()) {
                            loop_body_edges_valid = false;
                            break;
                        }
                        for (auto *loop_break : found->second)
                            loop_break->exit_phi_copies.push_back(copy);
                    }
                }
                if (!loop_body_edges_valid || seen_predecessors != expected_exit_predecessors) {
                    loop_body_edges_valid = false;
                    break;
                }
            }
        }
        const auto *latch = loop_body.empty() ? nullptr : loop_body.back();
        const bool recognized_return_latch = latch && std::any_of(loop_returns.begin(), loop_returns.end(),
            [&](const auto &side_exit) { return side_exit.branch == latch; });
        const auto latch_region = latch ? conditional_loop_bodies.find(latch->id.value) : conditional_loop_bodies.end();
        const bool recognized_conditional_latch = latch_region != conditional_loop_bodies.end() &&
            latch_region->second.latch_to_header;
        const bool closes_to_header = latch &&
            ((latch->successors.size() == 1 &&
              latch->successors.front().target == std::optional<Address>{header->begin}) ||
             (recognized_return_latch && std::any_of(latch->successors.begin(), latch->successors.end(),
                [&](const auto &edge) { return edge_targets(edge, header->begin); })) ||
             recognized_conditional_latch);
        auto *continuation = exit_block;
        while (continuation && exit_path.size() < function.blocks.size() &&
               exit_path_ids.insert(continuation->id.value).second &&
               (continuation == exit_block || (continuation->phis.empty() && !continuation->memory_phi &&
                                                continuation->memory_partition_phis.empty())) &&
               !contains_branch(*continuation) && has_only_simple_statements(*continuation)) {
            exit_path.push_back(continuation);
            if (has_only_terminal_return(*continuation)) break;
            if (contains_return(*continuation) || continuation->successors.size() != 1 ||
                !continuation->successors.front().target ||
                (continuation->successors.front().kind != BlockEdgeKind::jump &&
                 continuation->successors.front().kind != BlockEdgeKind::fallthrough) ||
                !has_unconditional_edge(*continuation, *continuation->successors.front().target)) {
                exit_path_valid = false;
                break;
            }
            continuation = find_block(*continuation->successors.front().target);
        }
        if (exit_path.empty() || !has_only_terminal_return(*exit_path.back()) ||
            (continuation && exit_path_ids.contains(continuation->id.value) && continuation != exit_path.back()))
            exit_path_valid = false;
        if (exit_block && (exit_block->memory_phi || !exit_block->memory_partition_phis.empty()))
            exit_path_valid = false;
        if (header && condition && body_start && exit_block && latch && closes_to_header && loop_body_edges_valid &&
            header != entry && body_start != entry && exit_block != entry && body_start != header &&
            exit_block != header && exit_block != body_start &&
            header->instructions.size() == 1 && has_only_simple_statements(*header) &&
            valid_diamond_memory_phi(*header) &&
            std::all_of(loop_body.begin(), loop_body.end(), [&](const auto *block) {
                return valid_diamond_memory_phi(*block);
            }) &&
            has_unconditional_edge(*entry, header->begin) &&
            exit_path_valid && std::none_of(exit_path.begin(), exit_path.end(), [&](const auto *block) {
                return loop_body_ids.contains(block->id.value) || block == header || block == entry;
            }) &&
            std::all_of(function.blocks.begin(), function.blocks.end(), [&](const LiftedBlock &candidate) {
                return &candidate == entry || &candidate == header || loop_body_ids.contains(candidate.id.value) ||
                    exit_path_ids.contains(candidate.id.value) ||
                    loop_break_path_ids.contains(candidate.id.value) ||
                    std::any_of(loop_returns.begin(), loop_returns.end(), [&](const auto &side_exit) {
                        return std::find(side_exit.path.begin(), side_exit.path.end(), &candidate) !=
                            side_exit.path.end();
                    });
            })) {
            std::vector<std::pair<std::string, std::string>> initial_loop_phi_copies;
            std::map<std::uint64_t, std::vector<std::pair<std::string, std::string>>> recurrent_loop_phi_copies;
            bool valid_loop_phis = true;
            std::vector<const LiftedBlock *> back_edges;
            const auto add_back_edge = [&](const LiftedBlock *block) {
                if (block && std::any_of(block->successors.begin(), block->successors.end(), [&](const auto &edge) {
                        return edge_targets(edge, header->begin);
                    }) && std::none_of(back_edges.begin(), back_edges.end(), [&](const auto *prior) {
                        return prior->id == block->id;
                    })) back_edges.push_back(block);
            };
            for (const auto *block : loop_body) {
                add_back_edge(block);
            }
            const auto add_region_back_edges = [&](const auto &self, const LoopConditionalBody &region) -> void {
                if (!region.latch_to_header) return;
                const auto add_arm = [&](const std::vector<const LiftedBlock *> &blocks,
                                         const std::shared_ptr<LoopConditionalBody> &nested) {
                    if (nested) {
                        self(self, *nested);
                    } else {
                        add_back_edge(blocks.empty() ? region.branch : blocks.back());
                    }
                };
                add_arm(region.yes, region.yes_nested);
                add_arm(region.no, region.no_nested);
            };
            for (const auto &[_, region] : conditional_loop_bodies)
                add_region_back_edges(add_region_back_edges, region);
            std::set<std::uint64_t> expected_header_predecessors{entry->id.value};
            for (const auto *back_edge : back_edges)
                if (!expected_header_predecessors.insert(back_edge->id.value).second)
                    valid_loop_phis = false;
            if (back_edges.size() > 64 ||
                diamond_predecessors[header->id.value] != expected_header_predecessors)
                valid_loop_phis = false;
            for (const auto &phi : header->phis) {
                if (phi.inputs.size() != back_edges.size() + 1) { valid_loop_phis = false; break; }
                std::set<std::uint64_t> phi_predecessors;
                for (const auto &input : phi.inputs)
                    if (!expected_header_predecessors.contains(input.predecessor.value) ||
                        !phi_predecessors.insert(input.predecessor.value).second)
                        valid_loop_phis = false;
                if (!valid_loop_phis || phi_predecessors != expected_header_predecessors) {
                    valid_loop_phis = false;
                    break;
                }
                const auto initial = std::find_if(phi.inputs.begin(), phi.inputs.end(), [&](const auto &input) {
                    return input.predecessor == entry->id;
                });
                if (initial == phi.inputs.end()) { valid_loop_phis = false; break; }
                const auto destination = register_name(phi.destination, phi.version);
                initial_loop_phi_copies.emplace_back(destination, register_name(phi.destination, initial->version));
                for (const auto *back_edge : back_edges) {
                    const auto recurrent = std::find_if(phi.inputs.begin(), phi.inputs.end(), [&](const auto &input) {
                        return input.predecessor == back_edge->id;
                    });
                    if (recurrent == phi.inputs.end()) { valid_loop_phis = false; break; }
                    recurrent_loop_phi_copies[back_edge->id.value].emplace_back(
                        destination, register_name(phi.destination, recurrent->version));
                }
                if (!valid_loop_phis) break;
            }
            if (!valid_loop_phis) return fallback("loop header phi inputs do not match its preheader and back edge");
            const auto conditional_tree_valid = [&](const auto &self, const LoopConditionalBody &region) -> bool {
                return region.branch && terminal_conditional(*region.branch) &&
                    (!region.yes_nested || self(self, *region.yes_nested)) &&
                    (!region.no_nested || self(self, *region.no_nested));
            };
            if (std::any_of(conditional_loop_bodies.begin(), conditional_loop_bodies.end(),
                [&](const auto &item) { return !conditional_tree_valid(conditional_tree_valid, item.second); }))
                return fallback("loop conditional region has no valid branch");
            out << "function " << address_label(function.entry) << "() {\n";
            emit_block(*entry, 4, true);
            emit_parallel_copies(out, initial_loop_phi_copies, 4);
            out << "    while (" << branch_condition_text(*condition) << ") {\n";
            emit_block(*header, 8, true);
            std::function<void(const LoopConditionalBody &, unsigned)> emit_loop_conditional;
            emit_loop_conditional = [&](const LoopConditionalBody &region, unsigned indent) {
                const auto *branch = terminal_conditional(*region.branch);
                if (!branch) return;
                emit_block(*region.branch, indent, true);
                const std::string prefix(indent, ' ');
                out << prefix << "if (" << branch_condition_text(*branch) << ") {\n";
                const auto emit_arm = [&](const std::vector<const LiftedBlock *> &blocks,
                                          const std::shared_ptr<LoopConditionalBody> &nested,
                                          const std::vector<std::pair<std::string, std::string>> &copies,
                                          bool breaks,
                                          const std::vector<const LiftedBlock *> &break_path) {
                    if (breaks) {
                        for (const auto *path_block : break_path) emit_block(*path_block, indent + 4, true);
                        out << std::string(indent + 4, ' ') << "break;\n";
                        return;
                    }
                    for (const auto *arm_block : blocks) emit_block(*arm_block, indent + 4, true);
                    if (nested) {
                        emit_loop_conditional(*nested, indent + 4);
                    } else if (region.latch_to_header) {
                        const auto *tail = blocks.empty() ? region.branch : blocks.back();
                        emit_parallel_copies(out, recurrent_loop_phi_copies[tail->id.value], indent + 4);
                        out << std::string(indent + 4, ' ') << "continue;\n";
                    }
                    if (!region.latch_to_header) {
                        emit_parallel_copies(out, copies, indent + 4);
                    }
                };
                emit_arm(region.yes, region.yes_nested, region.yes_phi_copies, region.yes_break,
                         region.yes_break_path);
                out << prefix << "} else {\n";
                emit_arm(region.no, region.no_nested, region.no_phi_copies, region.no_break,
                         region.no_break_path);
                out << prefix << "}\n";
            };
            for (const auto *block : loop_body) {
                if (const auto region_it = switch_loop_bodies.find(block->id.value);
                    region_it != switch_loop_bodies.end()) {
                    const auto &region = region_it->second;
                    const auto &dispatch = *block->switch_dispatch;
                    emit_block(*block, 8, true);
                    out << "        switch (" << expression_text(*dispatch.selector) << ") {\n";
                    for (const auto &arm : region.arms) {
                        for (const auto value : arm.values)
                            out << "        case 0x" << std::hex << value << std::dec << ":\n";
                        if (arm.is_default) out << "        default:\n";
                        for (const auto *arm_block : arm.body) emit_block(*arm_block, 12, true);
                        out << "            break;\n";
                    }
                    out << "        }\n";
                    continue;
                }
                if (const auto nested = nested_loop_bodies.find(block->id.value);
                    nested != nested_loop_bodies.end()) {
                    const auto &region = nested->second;
                    const auto *nested_condition = terminal_conditional(*region.header);
                    if (!nested_condition) return fallback("nested loop header has no valid conditional branch");
                    emit_parallel_copies(out, region.initial_phi_copies, 8);
                    const auto condition_text = branch_condition_text(*nested_condition);
                    out << "        while (true) {\n";
                    emit_block(*region.header, 12, true);
                    out << "            if (!(" << (region.condition_true_enters ? condition_text :
                        "!(" + condition_text + ")") << ")) {\n";
                    if (const auto copies = region.exit_phi_copies.find(region.header->id.value);
                        copies != region.exit_phi_copies.end())
                        emit_parallel_copies(out, copies->second, 16);
                    out << "                break;\n"
                        << "            }\n";
                    for (const auto *inner_block : region.body) {
                        const auto conditional = std::find_if(region.conditional_joins.begin(),
                            region.conditional_joins.end(), [&](const auto &candidate) {
                                return candidate.branch == inner_block;
                            });
                        if (conditional != region.conditional_joins.end()) {
                            const auto *branch = terminal_conditional(*inner_block);
                            if (!branch) return fallback("nested loop conditional region has no valid branch");
                            emit_block(*inner_block, 12, true);
                            out << "            if (" << branch_condition_text(*branch) << ") {\n";
                            for (const auto *arm_block : conditional->yes) emit_block(*arm_block, 16, true);
                            emit_parallel_copies(out, conditional->yes_phi_copies, 16);
                            out << "            } else {\n";
                            for (const auto *arm_block : conditional->no) emit_block(*arm_block, 16, true);
                            emit_parallel_copies(out, conditional->no_phi_copies, 16);
                            out << "            }\n";
                            continue;
                        }
                        const bool conditional_arm = std::any_of(region.conditional_joins.begin(),
                            region.conditional_joins.end(), [&](const auto &candidate) {
                                return std::find(candidate.yes.begin(), candidate.yes.end(), inner_block) != candidate.yes.end() ||
                                       std::find(candidate.no.begin(), candidate.no.end(), inner_block) != candidate.no.end();
                            });
                        if (conditional_arm) continue;
                        const auto conditional_return = std::find_if(region.conditional_returns.begin(),
                            region.conditional_returns.end(), [&](const auto &candidate) {
                                return candidate.branch == inner_block;
                            });
                        if (conditional_return != region.conditional_returns.end()) {
                            const auto *branch = terminal_conditional(*inner_block);
                            if (!branch) return fallback("nested loop return block has no valid branch");
                            emit_block(*inner_block, 12, true);
                            const auto condition = branch_condition_text(*branch);
                            out << "            if (" << (conditional_return->return_on_true ? condition :
                                "!(" + condition + ")") << ") {\n";
                            for (const auto *return_block : conditional_return->path)
                                emit_block(*return_block, 16, return_block != conditional_return->path.back());
                            out << "            }\n";
                            continue;
                        }
                        const auto conditional_break = std::find_if(region.conditional_breaks.begin(),
                            region.conditional_breaks.end(), [&](const auto &candidate) {
                                return candidate.first == inner_block;
                            });
                        if (conditional_break != region.conditional_breaks.end()) {
                            const auto *branch = terminal_conditional(*inner_block);
                            if (!branch) return fallback("nested loop break block has no valid branch");
                            emit_block(*inner_block, 12, true);
                            const auto condition = branch_condition_text(*branch);
                            out << "            if (" << (conditional_break->second ? condition :
                                "!(" + condition + ")") << ") {\n";
                            const auto path = region.conditional_break_paths.find(inner_block->id.value);
                            const auto path_blocks = path == region.conditional_break_paths.end()
                                ? std::vector<const LiftedBlock *>{} : path->second;
                            for (const auto *path_block : path_blocks) emit_block(*path_block, 16, true);
                            const auto *exit_predecessor = path_blocks.empty() ? inner_block : path_blocks.back();
                            if (const auto copies = region.exit_phi_copies.find(exit_predecessor->id.value);
                                copies != region.exit_phi_copies.end())
                                emit_parallel_copies(out, copies->second, 16);
                            out << "                break;\n"
                                << "            }\n";
                            continue;
                        }
                        const auto conditional_continue = std::find_if(region.conditional_continues.begin(),
                            region.conditional_continues.end(), [&](const auto &candidate) {
                                return candidate.first == inner_block;
                            });
                        if (conditional_continue != region.conditional_continues.end()) {
                            const auto *branch = terminal_conditional(*inner_block);
                            if (!branch) return fallback("nested loop continue block has no valid branch");
                            emit_block(*inner_block, 12, true);
                            const auto condition = branch_condition_text(*branch);
                            out << "            if (" << (conditional_continue->second ? condition :
                                "!(" + condition + ")") << ") {\n";
                            const auto path = region.conditional_continue_paths.find(inner_block->id.value);
                            const auto path_blocks = path == region.conditional_continue_paths.end()
                                ? std::vector<const LiftedBlock *>{} : path->second;
                            for (const auto *path_block : path_blocks) emit_block(*path_block, 16, true);
                            const auto *backedge = path_blocks.empty() ? inner_block : path_blocks.back();
                            if (const auto copies = region.backedge_phi_copies.find(backedge->id.value);
                                copies != region.backedge_phi_copies.end())
                                emit_parallel_copies(out, copies->second, 16);
                            out << "                continue;\n            }\n";
                            continue;
                        }
                        emit_block(*inner_block, 12, true);
                    }
                    if (const auto copies = region.backedge_phi_copies.find(region.body.back()->id.value);
                        copies != region.backedge_phi_copies.end())
                        emit_parallel_copies(out, copies->second, 12);
                    out << "        }\n";
                    continue;
                }
                if (const auto conditional = conditional_loop_bodies.find(block->id.value);
                    conditional != conditional_loop_bodies.end()) {
                    emit_loop_conditional(conditional->second, 8);
                    continue;
                }
                emit_block(*block, 8, true);
                const auto conditional_return = std::find_if(loop_returns.begin(), loop_returns.end(),
                    [&](const auto &candidate) { return candidate.branch == block; });
                if (conditional_return != loop_returns.end()) {
                    const auto *body_condition = terminal_conditional(*block);
                    if (!body_condition) return fallback("loop return side exit has no valid conditional branch");
                    const auto condition = branch_condition_text(*body_condition);
                    out << "        if (" << (conditional_return->return_on_true ? condition :
                        "!(" + condition + ")") << ") {\n";
                    for (std::size_t i = 0; i + 1 < conditional_return->path.size(); ++i)
                        emit_block(*conditional_return->path[i], 12, true);
                    emit_parallel_copies(out, conditional_return->phi_copies, 12);
                    emit_block(*conditional_return->path.back(), 12);
                    out << "        }\n";
                    continue;
                }
                const auto conditional_break = std::find_if(loop_breaks.begin(), loop_breaks.end(),
                    [&](const auto &candidate) { return candidate.branch == block; });
                if (conditional_break != loop_breaks.end()) {
                    const auto *body_condition = terminal_conditional(*block);
                    if (!body_condition) return fallback("loop break block has no valid conditional branch");
                    out << "        if (" << (conditional_break->break_on_true ? branch_condition_text(*body_condition) :
                        "!(" + branch_condition_text(*body_condition) + ")") << ") {\n";
                    for (const auto *path_block : conditional_break->path)
                        emit_block(*path_block, 12, true);
                    emit_parallel_copies(out, conditional_break->exit_phi_copies, 12);
                    out << "            break;\n        }\n";
                }
                const auto conditional_continue = std::find_if(loop_continues.begin(), loop_continues.end(),
                    [&](const auto &candidate) { return candidate.first == block; });
                if (conditional_continue != loop_continues.end()) {
                    const auto *body_condition = terminal_conditional(*block);
                    if (!body_condition) return fallback("loop continue block has no valid conditional branch");
                    const auto &copies = recurrent_loop_phi_copies[block->id.value];
                    const auto condition_text = conditional_continue->second ? branch_condition_text(*body_condition) :
                        "!(" + branch_condition_text(*body_condition) + ")";
                    out << "        if (" << condition_text << ") {\n";
                    emit_parallel_copies(out, copies, 12);
                    out << "            continue;\n        }\n";
                }
            }
            emit_parallel_copies(out, recurrent_loop_phi_copies[latch->id.value], 8);
            out << "    }\n";
            emit_parallel_copies(out, loop_condition_exit_phi_copies, 4);
            for (const auto *block : exit_path) emit_block(*block, 4, block != exit_path.back());
            out << "}\n";
            return {out.str(), false, {}};
        }
    }
    if (function.blocks.size() >= 3 && has_only_simple_statements(*entry) && entry->phis.empty()) {
        struct DoLoopDiamond {
            const LiftedBlock *branch = nullptr;
            const LiftedBlock *join = nullptr;
            std::vector<const LiftedBlock *> yes;
            std::vector<const LiftedBlock *> no;
            std::shared_ptr<DoLoopDiamond> yes_nested;
            std::shared_ptr<DoLoopDiamond> no_nested;
            std::vector<const LiftedBlock *> yes_after;
            std::vector<const LiftedBlock *> no_after;
            std::vector<std::pair<std::string, std::string>> yes_phi_copies;
            std::vector<std::pair<std::string, std::string>> no_phi_copies;
        };
        struct DoLoopSwitchArm {
            Address target{};
            std::vector<std::uint64_t> values;
            bool is_default = false;
            std::vector<const LiftedBlock *> body;
        };
        struct DoLoopSwitch {
            const LiftedBlock *dispatch = nullptr;
            const LiftedBlock *join = nullptr;
            std::vector<DoLoopSwitchArm> arms;
            std::map<std::uint64_t, std::vector<std::pair<std::string, std::string>>> join_phi_copies;
        };
        std::vector<DoLoopDiamond> diamonds;
        std::set<std::uint64_t> consumed_phi_joins;
        std::map<std::uint64_t, DoLoopSwitch> switches;
        std::set<std::uint64_t> do_body_ids;
        std::map<std::uint64_t, std::set<std::uint64_t>> predecessors;
        std::set<std::uint64_t> unique_ids;
        std::set<std::pair<std::uint32_t, std::uint64_t>> unique_addresses;
        std::size_t edge_count = 0;
        bool body_valid = function.blocks.size() <= 1024;
        for (const auto &candidate : function.blocks) {
            if (!unique_ids.insert(candidate.id.value).second ||
                !unique_addresses.emplace(candidate.begin.space.value, candidate.begin.offset).second) {
                body_valid = false;
                break;
            }
            for (const auto &edge : candidate.successors) {
                if (++edge_count > 4096 || !edge.target) { body_valid = false; break; }
                const auto *target = find_block(*edge.target);
                if (!target || (edge.block && edge.block->value != target->id.value)) {
                    body_valid = false;
                    break;
                }
                predecessors[target->id.value].insert(candidate.id.value);
            }
            if (!body_valid) break;
        }
        const auto trace_linear = [&](Address start)
            -> std::optional<std::vector<const LiftedBlock *>> {
            std::vector<const LiftedBlock *> path;
            std::set<std::uint64_t> seen;
            auto *current = find_block(start);
            while (current && path.size() < function.blocks.size() && seen.insert(current->id.value).second) {
                path.push_back(current);
                if (terminal_conditional(*current) || current->switch_dispatch || contains_return(*current))
                    return path;
                if (current->successors.size() != 1 || !current->successors.front().target ||
                    !has_unconditional_edge(*current, *current->successors.front().target))
                    return {};
                current = find_block(*current->successors.front().target);
            }
            return {};
        };
        const auto validate_linear_arm = [&](const std::vector<const LiftedBlock *> &arm,
                                             const LiftedBlock &branch, const LiftedBlock &join) {
            auto predecessor = branch.id.value;
            for (std::size_t i = 0; i < arm.size(); ++i) {
                const auto *block = arm[i];
                const auto *next = i + 1 < arm.size() ? arm[i + 1] : &join;
                if (!block || block == &branch || block == &join || block->phis.size() || block->memory_phi ||
                    block->switch_dispatch || terminal_conditional(*block) || contains_return(*block) ||
                    !has_only_simple_statements(*block) || block->successors.size() != 1 ||
                    !has_unconditional_edge(*block, next->begin) ||
                    (block->successors.front().kind != BlockEdgeKind::jump &&
                     block->successors.front().kind != BlockEdgeKind::fallthrough) ||
                    predecessors[block->id.value] != std::set<std::uint64_t>{predecessor})
                    return false;
                predecessor = block->id.value;
            }
            return true;
        };
        const auto validate_join_phis = [&](const LiftedBlock &join,
            const std::set<std::uint64_t> &incoming,
            std::map<std::uint64_t, std::vector<std::pair<std::string, std::string>>> &copies) {
            if (incoming.size() < 2 || predecessors[join.id.value] != incoming || join.memory_phi ||
                join.switch_dispatch || contains_return(join) || !has_only_simple_statements(join))
                return false;
            for (const auto &phi : join.phis) {
                if (phi.inputs.size() != incoming.size()) return false;
                std::set<std::uint64_t> seen;
                for (const auto &input : phi.inputs) {
                    if (!incoming.contains(input.predecessor.value) ||
                        !seen.insert(input.predecessor.value).second) return false;
                    copies[input.predecessor.value].emplace_back(
                        register_name(phi.destination, phi.version),
                        register_name(phi.destination, input.version));
                }
                if (seen != incoming) return false;
            }
            return true;
        };
        const auto first_shared = [](const std::vector<const LiftedBlock *> &yes,
                                     const std::vector<const LiftedBlock *> &no) {
            std::pair<std::size_t, std::size_t> result{yes.size(), no.size()};
            for (std::size_t yi = 0; yi < yes.size(); ++yi) {
                const auto found = std::find(no.begin(), no.end(), yes[yi]);
                if (found == no.end()) continue;
                const auto ni = static_cast<std::size_t>(found - no.begin());
                if (result.first == yes.size() || yi + ni < result.first + result.second)
                    result = {yi, ni};
            }
            return result;
        };

        const LiftedBlock *current = entry;
        std::optional<std::set<std::uint64_t>> expected_predecessors;
        const LiftedBlock *latch = nullptr;
        std::set<std::uint64_t> top_level_seen;
        while (body_valid && current && top_level_seen.insert(current->id.value).second &&
               top_level_seen.size() <= function.blocks.size()) {
            if (expected_predecessors && predecessors[current->id.value] != *expected_predecessors) {
                body_valid = false;
                break;
            }
            const auto *current_condition = terminal_conditional(*current);
            if (current_condition && current != entry &&
                (current_condition->true_target == std::optional<Address>{entry->begin} ||
                 current_condition->false_target == std::optional<Address>{entry->begin})) {
                latch = current;
                break;
            }
            if ((!current->phis.empty() && !consumed_phi_joins.contains(current->id.value)) ||
                current->memory_phi || contains_return(*current) ||
                (!current->switch_dispatch && !has_only_simple_statements(*current))) {
                body_valid = false;
                break;
            }
            if (current->switch_dispatch) {
                const auto &dispatch = *current->switch_dispatch;
                if (!dispatch.complete || !dispatch.selector || !dispatch.default_target || dispatch.cases.empty()) {
                    body_valid = false;
                    break;
                }
                std::map<std::pair<std::uint32_t, std::uint64_t>, std::vector<std::uint64_t>> grouped;
                std::set<std::uint64_t> values;
                for (const auto &item : dispatch.cases) {
                    if (!values.insert(item.value).second) body_valid = false;
                    grouped[{item.target.space.value, item.target.offset}].push_back(item.value);
                }
                const auto default_key = std::pair{dispatch.default_target->space.value, dispatch.default_target->offset};
                grouped.try_emplace(default_key);
                if (!body_valid || grouped.size() != current->successors.size()) { body_valid = false; break; }
                for (const auto &edge : current->successors) {
                    if (!edge.target || !grouped.contains({edge.target->space.value, edge.target->offset}) ||
                        !edge_targets(edge, *edge.target)) body_valid = false;
                }
                if (!body_valid) break;

                DoLoopSwitch region;
                region.dispatch = current;
                std::vector<Address> targets;
                for (const auto &[key, _] : grouped) targets.push_back(Address{{key.first}, key.second});
                std::vector<std::vector<const LiftedBlock *>> traces;
                std::vector<const LiftedBlock *> endpoints;
                for (const auto target : targets) {
                    std::vector<const LiftedBlock *> path;
                    std::set<std::uint64_t> seen;
                    auto *node = find_block(target);
                    while (node && node != current && path.size() < function.blocks.size() &&
                           seen.insert(node->id.value).second && node->phis.empty() && !node->memory_phi &&
                           !node->switch_dispatch && !terminal_conditional(*node) && !contains_return(*node) &&
                           has_only_simple_statements(*node) && node->successors.size() == 1 &&
                           node->successors.front().target &&
                           (node->successors.front().kind == BlockEdgeKind::jump ||
                            node->successors.front().kind == BlockEdgeKind::fallthrough) &&
                           has_unconditional_edge(*node, *node->successors.front().target)) {
                        path.push_back(node);
                        node = find_block(*node->successors.front().target);
                    }
                    if (!node || node == current) body_valid = false;
                    endpoints.push_back(node);
                    traces.push_back(std::move(path));
                }
                const LiftedBlock *join = nullptr;
                if (body_valid) {
                    for (const auto *candidate : traces.front()) {
                        if (std::all_of(traces.begin() + 1, traces.end(), [&](const auto &path) {
                                return std::find(path.begin(), path.end(), candidate) != path.end();
                            })) { join = candidate; break; }
                    }
                    if (!join && !endpoints.empty() &&
                        std::all_of(endpoints.begin(), endpoints.end(), [&](const auto *endpoint) {
                            return endpoint == endpoints.front();
                        })) join = endpoints.front();
                }
                if (!join || join == current || join->memory_phi || !join->memory_partition_phis.empty())
                    body_valid = false;
                std::set<std::uint64_t> join_predecessors;
                if (body_valid) {
                    for (std::size_t i = 0; i < traces.size(); ++i) {
                        auto &path = traces[i];
                        const auto at_join = std::find(path.begin(), path.end(), join);
                        if (at_join != path.end()) path.erase(at_join, path.end());
                        else if (endpoints[i] != join) { body_valid = false; break; }
                        if (path.empty()) join_predecessors.insert(current->id.value);
                        else join_predecessors.insert(path.back()->id.value);
                        for (const auto *arm_block : path) {
                            if (!do_body_ids.insert(arm_block->id.value).second ||
                                predecessors[arm_block->id.value].size() != 1) body_valid = false;
                        }
                        DoLoopSwitchArm arm;
                        arm.target = targets[i];
                        arm.values = grouped.at({targets[i].space.value, targets[i].offset});
                        arm.is_default = targets[i] == *dispatch.default_target;
                        arm.body = path;
                        region.arms.push_back(std::move(arm));
                    }
                    if (predecessors[join->id.value] != join_predecessors) body_valid = false;
                    if (body_valid && !join->phis.empty() &&
                        !validate_join_phis(*join, join_predecessors, region.join_phi_copies))
                        body_valid = false;
                    if (body_valid && !join->phis.empty()) consumed_phi_joins.insert(join->id.value);
                }
                if (!body_valid || !do_body_ids.insert(current->id.value).second) { body_valid = false; break; }
                region.join = join;
                switches.emplace(current->id.value, std::move(region));
                expected_predecessors = join_predecessors;
                current = join;
                if (top_level_seen.contains(current->id.value)) { body_valid = false; break; }
                continue;
            }
            if (current_condition) {
                if (!conditional_edges_match_targets(*current, *current_condition)) {
                    body_valid = false;
                    break;
                }
                const auto yes_path = trace_linear(*current_condition->true_target);
                const auto no_path = trace_linear(*current_condition->false_target);
                if (!yes_path || !no_path) { body_valid = false; break; }
                DoLoopDiamond region;
                region.branch = current;
                const auto [yes_join, no_join] = first_shared(*yes_path, *no_path);
                if (yes_join < yes_path->size()) {
                    region.join = (*yes_path)[yes_join];
                    region.yes.assign(yes_path->begin(), yes_path->begin() +
                        static_cast<std::ptrdiff_t>(yes_join));
                    region.no.assign(no_path->begin(), no_path->begin() +
                        static_cast<std::ptrdiff_t>(no_join));
                    const auto *yes_tail = region.yes.empty() ? current : region.yes.back();
                    const auto *no_tail = region.no.empty() ? current : region.no.back();
                    std::map<std::uint64_t, std::vector<std::pair<std::string, std::string>>> copies;
                    if (region.join == current || yes_tail == no_tail ||
                        !validate_linear_arm(region.yes, *current, *region.join) ||
                        !validate_linear_arm(region.no, *current, *region.join) ||
                        !validate_join_phis(*region.join, {yes_tail->id.value, no_tail->id.value}, copies)) {
                        body_valid = false;
                        break;
                    }
                    region.yes_phi_copies = std::move(copies[yes_tail->id.value]);
                    region.no_phi_copies = std::move(copies[no_tail->id.value]);
                } else {
                    // Exactly one outer arm may end in an inner conditional.
                    const bool nested_on_true = !yes_path->empty() &&
                        terminal_conditional(*yes_path->back()) != nullptr;
                    const auto &nested_path = nested_on_true ? *yes_path : *no_path;
                    const auto &sibling_path = nested_on_true ? *no_path : *yes_path;
                    if (nested_path.empty() || sibling_path.empty() ||
                        !terminal_conditional(*nested_path.back()) ||
                        terminal_conditional(*sibling_path.back())) {
                        body_valid = false;
                        break;
                    }
                    const auto *inner_branch = nested_path.back();
                    const auto *inner_test = terminal_conditional(*inner_branch);
                    if (!inner_branch->phis.empty() || inner_branch->memory_phi ||
                        !has_only_simple_statements(*inner_branch) ||
                        !conditional_edges_match_targets(*inner_branch, *inner_test)) {
                        body_valid = false;
                        break;
                    }
                    const auto inner_yes_path = trace_linear(*inner_test->true_target);
                    const auto inner_no_path = trace_linear(*inner_test->false_target);
                    if (!inner_yes_path || !inner_no_path) { body_valid = false; break; }
                    const auto [inner_yes_join, inner_no_join] = first_shared(*inner_yes_path, *inner_no_path);
                    if (inner_yes_join == inner_yes_path->size()) { body_valid = false; break; }
                    auto nested = std::make_shared<DoLoopDiamond>();
                    nested->branch = inner_branch;
                    nested->join = (*inner_yes_path)[inner_yes_join];
                    nested->yes.assign(inner_yes_path->begin(), inner_yes_path->begin() +
                        static_cast<std::ptrdiff_t>(inner_yes_join));
                    nested->no.assign(inner_no_path->begin(), inner_no_path->begin() +
                        static_cast<std::ptrdiff_t>(inner_no_join));
                    const auto *inner_yes_tail = nested->yes.empty() ? inner_branch : nested->yes.back();
                    const auto *inner_no_tail = nested->no.empty() ? inner_branch : nested->no.back();
                    const auto continuation = trace_linear(nested->join->begin);
                    if (!continuation) { body_valid = false; break; }
                    const auto [outer_join_index, sibling_join_index] = first_shared(*continuation, sibling_path);
                    if (outer_join_index == continuation->size()) { body_valid = false; break; }
                    region.join = (*continuation)[outer_join_index];
                    auto &prefix = nested_on_true ? region.yes : region.no;
                    auto &suffix = nested_on_true ? region.yes_after : region.no_after;
                    auto &sibling = nested_on_true ? region.no : region.yes;
                    prefix.assign(nested_path.begin(), nested_path.end() - 1);
                    suffix.assign(continuation->begin(), continuation->begin() +
                        static_cast<std::ptrdiff_t>(outer_join_index));
                    sibling.assign(sibling_path.begin(), sibling_path.begin() +
                        static_cast<std::ptrdiff_t>(sibling_join_index));
                    const auto *prefix_tail = prefix.empty() ? current : prefix.back();
                    const auto *sibling_tail = sibling.empty() ? current : sibling.back();
                    if (inner_yes_tail == inner_no_tail || sibling_tail == inner_yes_tail ||
                        sibling_tail == inner_no_tail || region.join == current ||
                        nested->join == inner_branch ||
                        !validate_linear_arm(prefix, *current, *inner_branch) ||
                        predecessors[inner_branch->id.value] != std::set<std::uint64_t>{prefix_tail->id.value} ||
                        !validate_linear_arm(nested->yes, *inner_branch, *nested->join) ||
                        !validate_linear_arm(nested->no, *inner_branch, *nested->join) ||
                        !validate_linear_arm(sibling, *current, *region.join)) {
                        body_valid = false;
                        break;
                    }
                    std::map<std::uint64_t, std::vector<std::pair<std::string, std::string>>> inner_copies;
                    if (nested->join == region.join) {
                        if (!suffix.empty() ||
                            !validate_join_phis(*region.join,
                                {inner_yes_tail->id.value, inner_no_tail->id.value, sibling_tail->id.value},
                                inner_copies)) body_valid = false;
                        if (body_valid) {
                            auto &sibling_copies = nested_on_true ? region.no_phi_copies : region.yes_phi_copies;
                            sibling_copies = std::move(inner_copies[sibling_tail->id.value]);
                        }
                    } else {
                        if (suffix.empty() || suffix.front() != nested->join ||
                            !validate_join_phis(*nested->join,
                                {inner_yes_tail->id.value, inner_no_tail->id.value}, inner_copies))
                            body_valid = false;
                        auto predecessor = nested->join->id.value;
                        for (std::size_t i = 1; body_valid && i < suffix.size(); ++i) {
                            const auto *block = suffix[i];
                            const auto *next = i + 1 < suffix.size() ? suffix[i + 1] : region.join;
                            if (!block->phis.empty() || block->memory_phi || block->switch_dispatch ||
                                terminal_conditional(*block) || contains_return(*block) ||
                                !has_only_simple_statements(*block) ||
                                block->successors.size() != 1 ||
                                (block->successors.front().kind != BlockEdgeKind::jump &&
                                 block->successors.front().kind != BlockEdgeKind::fallthrough) ||
                                predecessors[block->id.value] != std::set<std::uint64_t>{predecessor} ||
                                !has_unconditional_edge(*block, next->begin)) body_valid = false;
                            predecessor = block->id.value;
                        }
                        const auto *outer_nested_tail = suffix.back();
                        std::map<std::uint64_t, std::vector<std::pair<std::string, std::string>>> outer_copies;
                        if (body_valid && (nested->join->successors.size() != 1 ||
                            (nested->join->successors.front().kind != BlockEdgeKind::jump &&
                             nested->join->successors.front().kind != BlockEdgeKind::fallthrough) ||
                            !has_unconditional_edge(*nested->join,
                                suffix.size() > 1 ? suffix[1]->begin : region.join->begin) ||
                            outer_nested_tail == sibling_tail ||
                            !validate_join_phis(*region.join,
                                {outer_nested_tail->id.value, sibling_tail->id.value}, outer_copies)))
                            body_valid = false;
                        if (body_valid) {
                            auto &nested_copies = nested_on_true ? region.yes_phi_copies : region.no_phi_copies;
                            auto &sibling_copies = nested_on_true ? region.no_phi_copies : region.yes_phi_copies;
                            nested_copies = std::move(outer_copies[outer_nested_tail->id.value]);
                            sibling_copies = std::move(outer_copies[sibling_tail->id.value]);
                        }
                    }
                    if (!body_valid) break;
                    nested->yes_phi_copies = std::move(inner_copies[inner_yes_tail->id.value]);
                    nested->no_phi_copies = std::move(inner_copies[inner_no_tail->id.value]);
                    if (nested_on_true) region.yes_nested = std::move(nested);
                    else region.no_nested = std::move(nested);
                }
                if (!do_body_ids.insert(current->id.value).second) body_valid = false;
                const auto claim_blocks = [&](const auto &self, const DoLoopDiamond &item) -> void {
                    for (const auto *block : item.yes)
                        if (!do_body_ids.insert(block->id.value).second) body_valid = false;
                    for (const auto *block : item.no)
                        if (!do_body_ids.insert(block->id.value).second) body_valid = false;
                    if (item.yes_nested) {
                        if (!do_body_ids.insert(item.yes_nested->branch->id.value).second) body_valid = false;
                        self(self, *item.yes_nested);
                    }
                    if (item.no_nested) {
                        if (!do_body_ids.insert(item.no_nested->branch->id.value).second) body_valid = false;
                        self(self, *item.no_nested);
                    }
                    for (const auto *block : item.yes_after)
                        if (!do_body_ids.insert(block->id.value).second) body_valid = false;
                    for (const auto *block : item.no_after)
                        if (!do_body_ids.insert(block->id.value).second) body_valid = false;
                };
                claim_blocks(claim_blocks, region);
                if (!body_valid) break;
                if (!region.join->phis.empty()) consumed_phi_joins.insert(region.join->id.value);
                if (region.yes_nested && region.yes_nested->join != region.join &&
                    !region.yes_nested->join->phis.empty())
                    consumed_phi_joins.insert(region.yes_nested->join->id.value);
                if (region.no_nested && region.no_nested->join != region.join &&
                    !region.no_nested->join->phis.empty())
                    consumed_phi_joins.insert(region.no_nested->join->id.value);
                diamonds.push_back(std::move(region));
                expected_predecessors = predecessors[diamonds.back().join->id.value];
                current = diamonds.back().join;
                if (top_level_seen.contains(current->id.value)) { body_valid = false; break; }
                continue;
            }
            if (current->successors.size() != 1 || !current->successors.front().target ||
                !has_unconditional_edge(*current, *current->successors.front().target)) {
                body_valid = false;
                break;
            }
            if (!do_body_ids.insert(current->id.value).second) { body_valid = false; break; }
            const auto *next = find_block(*current->successors.front().target);
            if (!next) { body_valid = false; break; }
            expected_predecessors = std::set<std::uint64_t>{current->id.value};
            current = next;
        }
        const auto *condition = latch ? terminal_conditional(*latch) : nullptr;
        if (body_valid && latch && latch != entry && !do_body_ids.empty() && condition &&
            (latch->phis.empty() || consumed_phi_joins.contains(latch->id.value)) &&
            !latch->memory_phi && latch->memory_partition_phis.empty() && latch->successors.size() == 2 &&
            condition->true_target && condition->false_target &&
            ((edge_targets(latch->successors[0], *condition->true_target) &&
              edge_targets(latch->successors[1], *condition->false_target)) ||
             (edge_targets(latch->successors[1], *condition->true_target) &&
              edge_targets(latch->successors[0], *condition->false_target)))) {
            // A bounded phi-free cleanup chain may sit between the latch's
            // repeat edge and the body header. Preserve it inside the loop and
            // use an explicit continue so the original predicate still gates
            // every iteration.
            const auto trace_backedge = [&](Address start)
                -> std::optional<std::vector<const LiftedBlock *>> {
                std::vector<const LiftedBlock *> path;
                auto *cursor = find_block(start);
                auto predecessor = latch->id.value;
                std::set<std::uint64_t> seen;
                while (cursor && cursor != entry && cursor != latch && path.size() < 64 &&
                       seen.insert(cursor->id.value).second && cursor->phis.empty() && !cursor->memory_phi &&
                       cursor->memory_partition_phis.empty() && !cursor->switch_dispatch &&
                       !contains_return(*cursor) && has_only_simple_statements(*cursor) &&
                       predecessors[cursor->id.value] == std::set<std::uint64_t>{predecessor} &&
                       cursor->successors.size() == 1 && cursor->successors.front().target &&
                       (cursor->successors.front().kind == BlockEdgeKind::jump ||
                        cursor->successors.front().kind == BlockEdgeKind::fallthrough) &&
                       has_unconditional_edge(*cursor, *cursor->successors.front().target)) {
                    path.push_back(cursor);
                    predecessor = cursor->id.value;
                    cursor = find_block(*cursor->successors.front().target);
                }
                if (cursor != entry || predecessors[entry->id.value] != std::set<std::uint64_t>{predecessor})
                    return {};
                return path;
            };
            const auto true_backedge = trace_backedge(*condition->true_target);
            const auto false_backedge = trace_backedge(*condition->false_target);
            const bool loops_on_true = true_backedge.has_value() && !false_backedge.has_value();
            const bool loops_on_false = false_backedge.has_value() && !true_backedge.has_value();
            std::vector<const LiftedBlock *> backedge_cleanup;
            if (loops_on_true) backedge_cleanup = *true_backedge;
            else if (loops_on_false) backedge_cleanup = *false_backedge;
            const Address exit_address = loops_on_true ? *condition->false_target :
                                         loops_on_false ? *condition->true_target : Address{};
            const auto *exit_block = find_block(exit_address);
            std::vector<const LiftedBlock *> exit_path;
            std::set<std::uint64_t> exit_path_ids;
            const LiftedBlock *cleanup_branch = nullptr;
            std::vector<const LiftedBlock *> cleanup_true_path;
            std::vector<const LiftedBlock *> cleanup_false_path;
            const Branch *cleanup_condition = nullptr;
            auto *exit_cursor = exit_block;
            auto expected_exit_predecessor = latch ? latch->id.value : 0;
            bool exit_path_valid = true;
            while (exit_cursor && exit_path.size() < 64 &&
                   exit_path_ids.insert(exit_cursor->id.value).second &&
                   exit_cursor != entry && exit_cursor != latch &&
                   !do_body_ids.contains(exit_cursor->id.value) &&
                   exit_cursor->phis.empty() && !exit_cursor->memory_phi &&
                   exit_cursor->memory_partition_phis.empty() &&
                   has_only_simple_statements(*exit_cursor) &&
                   predecessors[exit_cursor->id.value] == std::set<std::uint64_t>{expected_exit_predecessor}) {
                exit_path.push_back(exit_cursor);
                if (has_only_terminal_return(*exit_cursor)) break;
                if (const auto *candidate = terminal_conditional(*exit_cursor);
                    candidate && candidate->true_target && candidate->false_target &&
                    *candidate->true_target != *candidate->false_target) {
                    const auto trace_cleanup_return = [&](Address start) {
                        std::vector<const LiftedBlock *> path;
                        std::set<std::uint64_t> seen;
                        auto *cursor = find_block(start);
                        auto predecessor = exit_cursor->id.value;
                        while (cursor && cursor != entry && cursor != latch &&
                               !do_body_ids.contains(cursor->id.value) &&
                               !exit_path_ids.contains(cursor->id.value) &&
                               path.size() < 64 && seen.insert(cursor->id.value).second &&
                               cursor->phis.empty() && !cursor->memory_phi &&
                               cursor->memory_partition_phis.empty() &&
                               has_only_simple_statements(*cursor) &&
                               (predecessors[cursor->id.value] == std::set<std::uint64_t>{predecessor} ||
                                has_only_terminal_return(*cursor))) {
                            path.push_back(cursor);
                            if (has_only_terminal_return(*cursor)) return path;
                            if (contains_return(*cursor) || cursor->successors.size() != 1 ||
                                !cursor->successors.front().target ||
                                (cursor->successors.front().kind != BlockEdgeKind::jump &&
                                 cursor->successors.front().kind != BlockEdgeKind::fallthrough) ||
                                !has_unconditional_edge(*cursor, *cursor->successors.front().target))
                                return std::vector<const LiftedBlock *>{};
                            predecessor = cursor->id.value;
                            cursor = find_block(*cursor->successors.front().target);
                        }
                        return std::vector<const LiftedBlock *>{};
                    };
                    auto true_path = trace_cleanup_return(*candidate->true_target);
                    auto false_path = trace_cleanup_return(*candidate->false_target);
                    std::set<std::uint64_t> arm_ids;
                    const auto disjoint_path = [&](const auto &path, const auto *shared_return) {
                        for (std::size_t i = 0; i < path.size(); ++i) {
                            const auto *block = path[i];
                            if (block == shared_return && i + 1 == path.size()) continue;
                            if (!arm_ids.insert(block->id.value).second) return false;
                        }
                        return true;
                    };
                    const auto *shared_return = !true_path.empty() && !false_path.empty() &&
                        true_path.back() == false_path.back() && has_only_terminal_return(*true_path.back())
                        ? true_path.back() : nullptr;
                    const auto path_tail = [&](const auto &path) {
                        return path.size() > 1 ? path[path.size() - 2]->id.value : exit_cursor->id.value;
                    };
                    const bool shared_return_predecessors_valid = !shared_return ||
                        predecessors[shared_return->id.value] ==
                            std::set<std::uint64_t>{path_tail(true_path), path_tail(false_path)};
                    const bool terminal_predecessors_valid =
                        (!true_path.empty() && (true_path.back() == shared_return ||
                            predecessors[true_path.back()->id.value] ==
                                std::set<std::uint64_t>{path_tail(true_path)})) &&
                        (!false_path.empty() && (false_path.back() == shared_return ||
                            predecessors[false_path.back()->id.value] ==
                                std::set<std::uint64_t>{path_tail(false_path)}));
                    const bool exact_edges = exit_cursor->successors.size() == 2 &&
                        std::count_if(exit_cursor->successors.begin(), exit_cursor->successors.end(), [&](const auto &edge) {
                            return edge_targets(edge, *candidate->true_target);
                        }) == 1 &&
                        std::count_if(exit_cursor->successors.begin(), exit_cursor->successors.end(), [&](const auto &edge) {
                            return edge_targets(edge, *candidate->false_target);
                        }) == 1;
                    if (!true_path.empty() && !false_path.empty() && exact_edges &&
                        shared_return_predecessors_valid && terminal_predecessors_valid &&
                        disjoint_path(true_path, shared_return) &&
                        disjoint_path(false_path, shared_return)) {
                        cleanup_branch = exit_cursor;
                        cleanup_condition = candidate;
                        cleanup_true_path = std::move(true_path);
                        cleanup_false_path = std::move(false_path);
                        break;
                    }
                }
                if (contains_return(*exit_cursor) || exit_cursor->successors.size() != 1 ||
                    !exit_cursor->successors.front().target ||
                    (exit_cursor->successors.front().kind != BlockEdgeKind::jump &&
                     exit_cursor->successors.front().kind != BlockEdgeKind::fallthrough) ||
                    !has_unconditional_edge(*exit_cursor, *exit_cursor->successors.front().target)) {
                    exit_path_valid = false;
                    break;
                }
                expected_exit_predecessor = exit_cursor->id.value;
                exit_cursor = find_block(*exit_cursor->successors.front().target);
            }
            if (exit_path.empty() ||
                (!has_only_terminal_return(*exit_path.back()) &&
                 (!cleanup_branch || exit_path.back() != cleanup_branch)) ||
                (exit_cursor && exit_path_ids.contains(exit_cursor->id.value) && exit_cursor != exit_path.back()))
                exit_path_valid = false;
            if ((loops_on_true || loops_on_false) && exit_block && exit_path_valid && exit_block != entry &&
                exit_block != latch && has_only_simple_statements(*latch) &&
                (backedge_cleanup.empty()
                    ? predecessors[entry->id.value] == std::set<std::uint64_t>{latch->id.value}
                    : predecessors[entry->id.value] == std::set<std::uint64_t>{backedge_cleanup.back()->id.value}) &&
                predecessors[exit_block->id.value] == std::set<std::uint64_t>{latch->id.value} &&
                std::all_of(function.blocks.begin(), function.blocks.end(), [&](const LiftedBlock &candidate) {
                    return &candidate == latch || exit_path_ids.contains(candidate.id.value) ||
                           std::any_of(backedge_cleanup.begin(), backedge_cleanup.end(), [&](const auto *block) {
                               return block == &candidate;
                           }) ||
                           std::any_of(cleanup_true_path.begin(), cleanup_true_path.end(), [&](const auto *block) {
                               return block == &candidate;
                           }) ||
                           std::any_of(cleanup_false_path.begin(), cleanup_false_path.end(), [&](const auto *block) {
                               return block == &candidate;
                           }) ||
                           do_body_ids.contains(candidate.id.value);
                })) {
                std::map<std::uint64_t, const DoLoopDiamond *> by_branch;
                for (const auto &region : diamonds) by_branch.emplace(region.branch->id.value, &region);
                out << "function " << address_label(function.entry) << "() {\n";
                out << (backedge_cleanup.empty() ? "    do {\n" : "    while (true) {\n");
                current = entry;
                std::set<std::uint64_t> emitted;
                while (current && current != latch && emitted.insert(current->id.value).second) {
                    const auto switch_region = switches.find(current->id.value);
                    if (switch_region != switches.end()) {
                        const auto &region = switch_region->second;
                        const auto &dispatch = *region.dispatch->switch_dispatch;
                        emit_block(*region.dispatch, 8, true);
                        out << "        switch (" << expression_text(*dispatch.selector) << ") {\n";
                        for (const auto &arm : region.arms) {
                            for (const auto value : arm.values)
                                out << "        case 0x" << std::hex << value << std::dec << ":\n";
                            if (arm.is_default) out << "        default:\n";
                            for (const auto *arm_block : arm.body) emit_block(*arm_block, 12, true);
                            const auto predecessor = arm.body.empty() ? region.dispatch->id.value : arm.body.back()->id.value;
                            if (const auto copies = region.join_phi_copies.find(predecessor);
                                copies != region.join_phi_copies.end())
                                emit_parallel_copies(out, copies->second, 12);
                            out << "            break;\n";
                        }
                        out << "        }\n";
                        current = region.join;
                        continue;
                    }
                    const auto region = by_branch.find(current->id.value);
                    if (region != by_branch.end()) {
                        const auto &diamond = *region->second;
                        const auto *diamond_condition = terminal_conditional(*diamond.branch);
                        if (!diamond_condition) return fallback("post-tested loop diamond lost its branch");
                        const auto emit_diamond = [&](const auto &self, const DoLoopDiamond &item,
                                                      unsigned indent) -> void {
                            const auto *test = terminal_conditional(*item.branch);
                            emit_block(*item.branch, indent, true);
                            const std::string spaces(indent, ' ');
                            out << spaces << "if (" << branch_condition_text(*test) << ") {\n";
                            const auto emit_arm = [&](const std::vector<const LiftedBlock *> &prefix,
                                const std::shared_ptr<DoLoopDiamond> &nested,
                                const std::vector<const LiftedBlock *> &after,
                                const std::vector<std::pair<std::string, std::string>> &copies) {
                                for (const auto *block : prefix) emit_block(*block, indent + 4, true);
                                if (nested) self(self, *nested, indent + 4);
                                for (const auto *block : after) emit_block(*block, indent + 4, true);
                                emit_parallel_copies(out, copies, indent + 4);
                            };
                            emit_arm(item.yes, item.yes_nested, item.yes_after, item.yes_phi_copies);
                            out << spaces << "} else {\n";
                            emit_arm(item.no, item.no_nested, item.no_after, item.no_phi_copies);
                            out << spaces << "}\n";
                        };
                        emit_diamond(emit_diamond, diamond, 8);
                        current = diamond.join;
                    } else {
                        emit_block(*current, 8, true);
                        if (current->successors.size() != 1 || !current->successors.front().target) break;
                        current = find_block(*current->successors.front().target);
                    }
                }
                if (current != latch) return fallback("post-tested loop body is not a single conditional region chain");
                emit_block(*latch, 8, true);
                const auto repeat_condition = loops_on_true ? condition->condition : "!(" + condition->condition + ")";
                if (backedge_cleanup.empty()) {
                    out << "    } while (" << repeat_condition << ");\n";
                } else {
                    out << "        if (" << repeat_condition << ") {\n";
                    for (const auto *block : backedge_cleanup) emit_block(*block, 12, true);
                    out << "            continue;\n        } else {\n            break;\n        }\n    }\n";
                }
                for (const auto *block : exit_path)
                    emit_block(*block, 4, block == cleanup_branch || block != exit_path.back());
                if (cleanup_branch && cleanup_condition && !cleanup_true_path.empty() && !cleanup_false_path.empty()) {
                    out << "    if (" << branch_condition_text(*cleanup_condition) << ") {\n";
                    for (const auto *block : cleanup_true_path)
                        emit_block(*block, 8, block != cleanup_true_path.back());
                    out << "    } else {\n";
                    for (const auto *block : cleanup_false_path)
                        emit_block(*block, 8, block != cleanup_false_path.back());
                    out << "    }\n";
                }
                out << "}\n";
                return {out.str(), false, {}};
            }
        }
    }
    const auto *branch = terminal_conditional(*entry);
    if (!entry->phis.empty()) return fallback("entry block contains an unsupported phi node");
    const auto *true_start = branch ? find_block(*branch->true_target) : nullptr;
    const auto *false_start = branch ? find_block(*branch->false_target) : nullptr;
    if (branch && (!true_start || !false_start || true_start == false_start ||
                   true_start == entry || false_start == entry))
        return fallback("conditional targets do not identify distinct in-function blocks");

    // A decision tree whose leaves all return has no join to recover with the
    // post-dominator structurer below. It is expressible as nested if/else when
    // the tree covers the function and any shared nodes are proven terminal
    // returns or bounded conditional blocks that lead directly to returns.
    auto try_return_tree = [&]() -> std::optional<StructuredPseudocode> {
        const auto count = function.blocks.size();
        constexpr std::size_t max_return_tree_blocks = 4096;
        constexpr std::size_t max_return_tree_depth = max_return_tree_blocks;
        constexpr std::size_t max_return_tree_occurrences = 65536;
        constexpr std::size_t max_return_tree_phi_copies = 65536;
        constexpr std::size_t max_return_tree_instructions = 262144;
        constexpr unsigned max_return_tree_indent = 256;
        if (count < 3 || count > max_return_tree_blocks) return {};
        using AddressKey = std::pair<std::uint64_t, std::uint64_t>;
        std::map<AddressKey, std::size_t> by_address;
        std::map<std::uint64_t, std::size_t> by_id;
        for (std::size_t i = 0; i < count; ++i) {
            const auto &block = function.blocks[i];
            if (!by_address.emplace(AddressKey{block.begin.space.value, block.begin.offset}, i).second ||
                !by_id.emplace(block.id.value, i).second) return {};
        }
        const auto index_of = [&](Address address) -> std::optional<std::size_t> {
            const auto found = by_address.find({address.space.value, address.offset});
            return found == by_address.end() ? std::nullopt : std::optional<std::size_t>{found->second};
        };
        const auto root = index_of(function.entry);
        if (!root) return {};
        std::vector<std::vector<std::size_t>> children(count);
        std::vector<std::vector<std::size_t>> predecessors(count);
        std::vector<std::size_t> predecessor_count(count, 0);
        std::size_t return_tree_edges = 0;
        std::size_t return_tree_cases = 0;
        for (std::size_t i = 0; i < count; ++i) {
            const auto &block = function.blocks[i];
            std::size_t branch_count = 0;
            for (std::size_t n = 0; n < block.instructions.size(); ++n) {
                if (!std::holds_alternative<Branch>(block.instructions[n].statement)) continue;
                ++branch_count;
                if (n + 1 != block.instructions.size()) return {};
            }
            if (branch_count > 1 || (contains_return(block) && !has_only_terminal_return(block))) return {};
            if (block.switch_dispatch) {
                const auto &dispatch = *block.switch_dispatch;
                if (!dispatch.complete || !dispatch.selector || dispatch.cases.empty() || !dispatch.default_target)
                    return {};
                if (dispatch.cases.size() > 4096 - return_tree_cases) return {};
                return_tree_cases += dispatch.cases.size();
                std::set<std::uint64_t> case_values;
                std::set<AddressKey> switch_targets, cfg_targets;
                for (const auto &item : dispatch.cases) {
                    if (!case_values.insert(item.value).second) return {};
                    switch_targets.emplace(item.target.space.value, item.target.offset);
                }
                switch_targets.emplace(dispatch.default_target->space.value, dispatch.default_target->offset);
                for (const auto &edge : block.successors) {
                    if (!edge.target) return {};
                    cfg_targets.emplace(edge.target->space.value, edge.target->offset);
                }
                if (switch_targets != cfg_targets || branch_count > 1) return {};
                if (branch_count == 1) {
                    const auto &transfer = std::get<Branch>(block.instructions.back().statement);
                    if (transfer.condition != "true" || transfer.true_target || transfer.false_target ||
                        transfer.predicate) return {};
                }
            } else if (block.successors.size() > 2) {
                return {};
            }
            if (block.successors.size() > 4096 - return_tree_edges) return {};
            return_tree_edges += block.successors.size();
            std::set<std::size_t> unique_children;
            for (const auto &edge : block.successors) {
                if (!edge.target) return {};
                const auto next = index_of(*edge.target);
                if (!next || !unique_children.insert(*next).second ||
                    (edge.block && (!by_id.contains(edge.block->value) || by_id.at(edge.block->value) != *next)))
                    return {};
                children[i].push_back(*next);
                predecessors[*next].push_back(i);
                ++predecessor_count[*next];
            }
            if (children[i].empty()) {
                if (!has_only_terminal_return(block) || branch_count != 0) return {};
            } else if (children[i].size() == 1) {
                if (contains_return(block)) return {};
                if (!block.switch_dispatch &&
                    block.successors.front().kind != BlockEdgeKind::jump &&
                    block.successors.front().kind != BlockEdgeKind::fallthrough) return {};
                if (!block.switch_dispatch && branch_count == 1) {
                    const auto &unconditional = std::get<Branch>(block.instructions.back().statement);
                    if (unconditional.condition != "true" || !unconditional.true_target ||
                        unconditional.false_target ||
                        !has_unconditional_edge(block, *unconditional.true_target) ||
                        *unconditional.true_target != function.blocks[children[i][0]].begin) return {};
                }
            } else if (block.switch_dispatch) {
                if (contains_return(block)) return {};
            } else if (children[i].size() == 2) {
                const auto *condition = terminal_conditional(block);
                if (contains_return(block) || !condition || !condition->true_target || !condition->false_target)
                    return {};
                const auto true_child = index_of(*condition->true_target);
                const auto false_child = index_of(*condition->false_target);
                if (!true_child || !false_child || *true_child == *false_child ||
                    std::find(children[i].begin(), children[i].end(), *true_child) == children[i].end() ||
                    std::find(children[i].begin(), children[i].end(), *false_child) == children[i].end())
                    return {};
            } else {
                return {};
            }
        }
        if (predecessor_count[*root] != 0) return {};
        // Memory SSA values are analysis-only in the C-like output, but their
        // incoming edges still have to describe this exact decision tree.
        // Accepting complete memory phis avoids falling back solely because a
        // return arm carries a token merge that has no source-level assignment.
        std::size_t memory_phi_inputs = 0;
        std::size_t register_phi_inputs = 0;
        for (std::size_t i = 0; i < count; ++i) {
            const auto &block = function.blocks[i];
            if (block.memory_partition_phis.size() > 4096) return {};
            std::set<std::uint64_t> expected;
            for (const auto predecessor : predecessors[i])
                expected.insert(function.blocks[predecessor].id.value);
            if (i == *root && (!block.phis.empty() || block.memory_phi ||
                               !block.memory_partition_phis.empty())) return {};
            if (block.phis.size() > 4096) return {};
            std::vector<RegisterOperand> destinations;
            for (const auto &phi : block.phis) {
                if (phi.inputs.size() != expected.size() ||
                    phi.inputs.size() > 65536 - register_phi_inputs ||
                    std::find(destinations.begin(), destinations.end(), phi.destination) != destinations.end()) return {};
                destinations.push_back(phi.destination);
                register_phi_inputs += phi.inputs.size();
                std::set<std::uint64_t> seen;
                for (const auto &input : phi.inputs)
                    if (!expected.contains(input.predecessor.value) ||
                        !seen.insert(input.predecessor.value).second) return {};
                if (seen != expected) return {};
            }
            const auto valid_memory_phi = [&](const auto &phi) {
                if (phi.inputs.size() != expected.size() ||
                    phi.inputs.size() > 65536 - memory_phi_inputs) return false;
                memory_phi_inputs += phi.inputs.size();
                std::set<std::uint64_t> seen;
                for (const auto &input : phi.inputs)
                    if (!expected.contains(input.predecessor.value) ||
                        !seen.insert(input.predecessor.value).second) return false;
                return seen == expected;
            };
            if (block.memory_phi && !valid_memory_phi(*block.memory_phi)) return {};
            std::set<std::string> partitions;
            for (const auto &phi : block.memory_partition_phis)
                if (phi.partition.empty() || !partitions.insert(phi.partition).second ||
                    !valid_memory_phi(phi)) return {};
        }
        for (std::size_t i = 0; i < count; ++i) {
            if (i != *root && predecessor_count[i] == 0) return {};
            if (predecessor_count[i] > 64) return {};
        }

        // Shared return subtrees are duplicated under each incoming path, so
        // the source result remains acyclic only if the validated CFG is a DAG.
        std::vector<std::size_t> remaining_predecessors = predecessor_count;
        std::vector<std::size_t> acyclic_work;
        for (std::size_t i = 0; i < count; ++i)
            if (remaining_predecessors[i] == 0) acyclic_work.push_back(i);
        std::size_t acyclic_count = 0;
        while (!acyclic_work.empty()) {
            const auto node = acyclic_work.back();
            acyclic_work.pop_back();
            ++acyclic_count;
            for (const auto next : children[node])
                if (--remaining_predecessors[next] == 0) acyclic_work.push_back(next);
        }
        if (acyclic_count != count) return {};

        std::vector<bool> visited(count, false);
        std::vector<std::pair<std::size_t, std::size_t>> pending{{*root, 1}};
        std::size_t occurrence_count = 0;
        std::size_t emitted_phi_copies = 0;
        std::size_t emitted_instructions = 0;
        while (!pending.empty()) {
            const auto [node, depth] = pending.back();
            pending.pop_back();
            if (depth > max_return_tree_depth || ++occurrence_count > max_return_tree_occurrences) return {};
            if (node != *root) {
                const auto phi_count = function.blocks[node].phis.size();
                if (phi_count > max_return_tree_phi_copies - emitted_phi_copies) return {};
                emitted_phi_copies += phi_count;
            }
            const auto instruction_count = function.blocks[node].instructions.size();
            if (instruction_count > max_return_tree_instructions - emitted_instructions) return {};
            emitted_instructions += instruction_count;
            visited[node] = true;
            for (const auto next : children[node]) pending.emplace_back(next, depth + 1);
        }
        if (std::any_of(visited.begin(), visited.end(), [](bool value) { return !value; })) return {};

        out << "function " << address_label(function.entry) << "() {\n";
        struct ReturnTreeFrame {
            std::size_t node = 0;
            unsigned indent = 0;
            std::uint8_t phase = 0;
            std::optional<std::size_t> incoming;
            std::vector<SwitchArmGroup> switch_groups;
            std::size_t switch_arm = 0;
        };
        const auto emit_return_phi_copies = [&](std::size_t node, std::size_t incoming, unsigned indent) {
            const auto predecessor_id = function.blocks[incoming].id;
            std::vector<std::pair<std::string, std::string>> copies;
            for (const auto &phi : function.blocks[node].phis) {
                const auto input = std::find_if(phi.inputs.begin(), phi.inputs.end(), [&](const auto &candidate) {
                    return candidate.predecessor == predecessor_id;
                });
                if (input == phi.inputs.end()) return false;
                copies.emplace_back(register_name(phi.destination, phi.version),
                                    register_name(phi.destination, input->version));
            }
            emit_parallel_copies(out, copies, indent);
            return true;
        };
        std::vector<ReturnTreeFrame> emit_stack{{*root, 4, 0, {}}};
        emit_stack.reserve(count);
        while (!emit_stack.empty()) {
            auto &frame = emit_stack.back();
            const auto node = frame.node;
            const auto indent = frame.indent;
            const auto &block = function.blocks[node];
            if (block.switch_dispatch) {
                const auto spaces = std::string(indent, ' ');
                const auto labels = std::string(std::min(indent + 4, max_return_tree_indent), ' ');
                if (frame.phase == 0) {
                    if (!block.phis.empty() &&
                        (!frame.incoming || !emit_return_phi_copies(node, *frame.incoming, indent))) return {};
                    emit_block(block, indent, true);
                    frame.switch_groups = group_switch_arms(*block.switch_dispatch);
                    out << spaces << "switch (" << expression_text(*block.switch_dispatch->selector) << ") {\n";
                    frame.phase = 1;
                } else if (frame.phase == 1) {
                    if (frame.switch_arm == frame.switch_groups.size()) {
                        out << spaces << "}\n";
                        emit_stack.pop_back();
                        continue;
                    }
                    const auto &arm = frame.switch_groups[frame.switch_arm];
                    for (const auto value : arm.values)
                        out << labels << "case 0x" << std::hex << value << std::dec << ":\n";
                    if (arm.is_default) out << labels << "default:\n";
                    out << labels << "{\n";
                    const auto target = index_of(arm.target);
                    if (!target) return {};
                    frame.phase = 2;
                    emit_stack.push_back({*target, std::min(indent + 8, max_return_tree_indent), 0, node});
                } else {
                    out << labels << "}\n";
                    ++frame.switch_arm;
                    frame.phase = 1;
                }
                continue;
            }
            if (children[node].size() < 2) {
                if (frame.phase++ == 0) {
                    if (!block.phis.empty() &&
                        (!frame.incoming || !emit_return_phi_copies(node, *frame.incoming, indent))) return {};
                    emit_block(block, indent, !children[node].empty());
                    if (!children[node].empty()) emit_stack.push_back({children[node][0], indent, 0, node});
                } else {
                    emit_stack.pop_back();
                }
                continue;
            }
            const auto *condition = terminal_conditional(block);
            if (!condition || !condition->true_target || !condition->false_target) return {};
            const auto true_index = index_of(*condition->true_target);
            const auto false_index = index_of(*condition->false_target);
            if (!true_index || !false_index) return {};
            const auto spaces = std::string(indent, ' ');
            if (frame.phase == 0) {
                if (!block.phis.empty() &&
                    (!frame.incoming || !emit_return_phi_copies(node, *frame.incoming, indent))) return {};
                emit_block(block, indent, true);
                out << spaces << "if (" << branch_condition_text(*condition) << ") {\n";
                frame.phase = 1;
                emit_stack.push_back({*true_index, std::min(indent + 4, max_return_tree_indent), 0, node});
            } else if (frame.phase == 1) {
                out << spaces << "} else {\n";
                frame.phase = 2;
                emit_stack.push_back({*false_index, std::min(indent + 4, max_return_tree_indent), 0, node});
            } else {
                out << spaces << "}\n";
                emit_stack.pop_back();
            }
        }
        out << "}\n";
        return StructuredPseudocode{out.str(), false, {}};
    };
    if (auto return_tree = try_return_tree()) return *return_tree;

    auto try_nested_early_return_with_shared_join = [&]() -> std::optional<StructuredPseudocode> {
        if (!branch || function.blocks.size() < 4 || function.blocks.size() > 1024) return {};
        std::set<std::pair<std::uint64_t, std::uint64_t>> addresses;
        std::set<std::uint64_t> ids;
        for (const auto &block : function.blocks)
            if (!addresses.emplace(block.begin.space.value, block.begin.offset).second ||
                !ids.insert(block.id.value).second || block.switch_dispatch) return {};

        for (const bool nested_on_true : {true, false}) {
            const auto *nested = nested_on_true ? true_start : false_start;
            const auto *sibling = nested_on_true ? false_start : true_start;
            const auto *inner = terminal_conditional(*nested);
            if (!inner || !nested->phis.empty() || contains_return(*nested)) continue;
            for (const auto &join_value : function.blocks) {
                const auto *join = &join_value;
                if (join == entry || join == nested || !has_only_terminal_return(*join)) continue;
                std::vector<const LiftedBlock *> sibling_path;
                std::set<std::uint64_t> visited;
                auto *current = sibling;
                bool path_valid = true;
                while (current && current != join && current != entry && current != nested &&
                       sibling_path.size() < function.blocks.size() && visited.insert(current->id.value).second) {
                    if (current->switch_dispatch || !current->phis.empty() || contains_branch(*current) ||
                        contains_return(*current) || current->successors.size() != 1 ||
                        !current->successors.front().target ||
                        (current->successors.front().kind != BlockEdgeKind::jump &&
                         current->successors.front().kind != BlockEdgeKind::fallthrough) ||
                        !has_unconditional_edge(*current, *current->successors.front().target)) {
                        path_valid = false;
                        break;
                    }
                    sibling_path.push_back(current);
                    current = find_block(*current->successors.front().target);
                }
                if (!path_valid || current != join) continue;
                const bool join_on_true = inner->true_target == std::optional<Address>{join->begin};
                const bool join_on_false = inner->false_target == std::optional<Address>{join->begin};
                if (join_on_true == join_on_false) continue;
                const auto *early_return = find_block(join_on_true ? *inner->false_target : *inner->true_target);
                if (!early_return || early_return == join || early_return == nested || early_return == entry ||
                    !has_only_terminal_return(*early_return) || early_return->memory_phi ||
                    !early_return->memory_partition_phis.empty()) continue;

                std::set<std::uint64_t> covered{entry->id.value, nested->id.value,
                                                join->id.value, early_return->id.value};
                bool valid = true;
                for (const auto *block : sibling_path)
                    if (!covered.insert(block->id.value).second || !block->phis.empty()) valid = false;
                if (!valid || covered.size() != function.blocks.size()) continue;

                std::size_t early_return_edge_count = 0;
                bool early_return_has_unexpected_predecessor = false;
                for (const auto &candidate : function.blocks) {
                    for (const auto &edge : candidate.successors) {
                        if (edge.target != std::optional<Address>{early_return->begin}) continue;
                        ++early_return_edge_count;
                        if (candidate.id != nested->id ||
                            (edge.block && *edge.block != early_return->id))
                            early_return_has_unexpected_predecessor = true;
                    }
                }
                if (early_return_edge_count != 1 || early_return_has_unexpected_predecessor) continue;
                std::vector<RegisterOperand> early_return_phi_destinations;
                for (const auto &phi : early_return->phis) {
                    if (std::find(early_return_phi_destinations.begin(), early_return_phi_destinations.end(),
                                  phi.destination) != early_return_phi_destinations.end() ||
                        phi.inputs.size() != 1 || phi.inputs.front().predecessor != nested->id) {
                        valid = false;
                        break;
                    }
                    early_return_phi_destinations.push_back(phi.destination);
                }
                if (!valid) continue;

                const BlockId sibling_predecessor = sibling_path.empty() ? entry->id : sibling_path.back()->id;
                const std::array<BlockId, 2> join_predecessors{nested->id, sibling_predecessor};
                for (const auto &phi : join->phis) {
                    if (phi.inputs.size() != join_predecessors.size()) { valid = false; break; }
                    for (const auto predecessor : join_predecessors)
                        if (std::count_if(phi.inputs.begin(), phi.inputs.end(), [&](const auto &input) {
                                return input.predecessor == predecessor;
                            }) != 1) { valid = false; break; }
                    if (!valid) break;
                }
                if (!valid) continue;

                auto emit_join_copies = [&](BlockId predecessor, unsigned indent) {
                    std::vector<std::pair<std::string, std::string>> copies;
                    copies.reserve(join->phis.size());
                    for (const auto &phi : join->phis) {
                        const auto input = std::find_if(phi.inputs.begin(), phi.inputs.end(), [&](const auto &item) {
                            return item.predecessor == predecessor;
                        });
                        copies.emplace_back(register_name(phi.destination, phi.version),
                                            register_name(phi.destination, input->version));
                    }
                    emit_parallel_copies(out, copies, indent);
                };
                auto emit_early_return = [&](unsigned indent) {
                    std::vector<std::pair<std::string, std::string>> copies;
                    copies.reserve(early_return->phis.size());
                    for (const auto &phi : early_return->phis) {
                        const auto &input = phi.inputs.front();
                        copies.emplace_back(register_name(phi.destination, phi.version),
                                            register_name(phi.destination, input.version));
                    }
                    emit_parallel_copies(out, copies, indent);
                    emit_block(*early_return, indent);
                };
                auto emit_sibling = [&](unsigned indent) {
                    for (const auto *block : sibling_path) emit_block(*block, indent);
                    emit_join_copies(sibling_predecessor, indent);
                };
                auto emit_nested = [&](unsigned indent) {
                    const auto spaces = std::string(indent, ' ');
                    emit_block(*nested, indent, true);
                    out << spaces << "if (" << branch_condition_text(*inner) << ") {\n";
                    if (join_on_true) emit_join_copies(nested->id, indent + 4);
                    else emit_early_return(indent + 4);
                    out << spaces << "} else {\n";
                    if (join_on_false) emit_join_copies(nested->id, indent + 4);
                    else emit_early_return(indent + 4);
                    out << spaces << "}\n";
                };

                out << "function " << address_label(function.entry) << "() {\n";
                emit_block(*entry, 4, true);
                out << "    if (" << branch_condition_text(*branch) << ") {\n";
                if (nested_on_true) emit_nested(8); else emit_sibling(8);
                out << "    } else {\n";
                if (nested_on_true) emit_sibling(8); else emit_nested(8);
                out << "    }\n";
                emit_block(*join, 4);
                out << "}\n";
                return StructuredPseudocode{out.str(), false, {}};
            }
        }
        return {};
    };
    if (auto nested_shared_join = try_nested_early_return_with_shared_join()) return *nested_shared_join;

    // A terminating arm is the common `if (condition) return; next;` shape.
    const bool true_returns = true_start && has_only_terminal_return(*true_start);
    const bool false_returns = false_start && has_only_terminal_return(*false_start);
    if (branch && function.blocks.size() == 3 && true_returns != false_returns &&
        ((true_returns && false_start->successors.empty()) ||
         (false_returns && true_start->successors.empty()))) {
        const bool return_on_true = true_returns;
        const auto *return_block = return_on_true ? true_start : false_start;
        const auto *continuation = return_on_true ? false_start : true_start;
        if (return_block->phis.empty() && continuation->phis.empty() && !contains_branch(*continuation) &&
            !contains_return(*continuation)) {
            out << "function " << address_label(function.entry) << "() {\n";
            emit_block(*entry, 4, true);
            const auto predicate = branch_condition_text(*branch);
            out << "    if (" << (return_on_true ? predicate : "!(" + predicate + ")") << ") {\n";
            emit_block(*return_block, 8);
            out << "    }\n";
            emit_block(*continuation, 4);
            out << "}\n";
            return {out.str(), false, {}};
        }
    }

    // Structure acyclic CFGs as nested regions. An analysis-only exit gives
    // distinct terminal returns a common post-dominator without inventing a
    // source return or moving effects. Real joins still receive their SSA
    // copies on the actual incoming edges. Cross-region sharing falls back
    // rather than duplicating blocks.
    auto try_acyclic_regions = [&]() -> std::optional<StructuredPseudocode> {
        const std::size_t count = function.blocks.size();
        if (count == 0 || count > 1024) return {};
        std::map<std::pair<std::uint64_t, std::uint64_t>, std::size_t> address_index;
        std::map<std::uint64_t, std::size_t> id_index;
        for (std::size_t i = 0; i < count; ++i) {
            const auto &block = function.blocks[i];
            if (!address_index.emplace(std::pair{block.begin.space.value, block.begin.offset}, i).second ||
                !id_index.emplace(block.id.value, i).second) return {};
        }
        const auto index_for = [&](Address address) -> std::optional<std::size_t> {
            const auto found = address_index.find({address.space.value, address.offset});
            return found == address_index.end() ? std::nullopt : std::optional<std::size_t>{found->second};
        };
        const auto entry_index = index_for(function.entry);
        if (!entry_index) return {};
        if (!function.blocks[*entry_index].phis.empty() || function.blocks[*entry_index].memory_phi)
            return {}; // The initial dispatch has no predecessor edge to supply entry phi values.
        std::vector<std::vector<std::size_t>> successors(count), predecessors(count);
        std::size_t edge_count = 0;
        for (std::size_t i = 0; i < count; ++i) {
            for (const auto &edge : function.blocks[i].successors) {
                if (++edge_count > 4096 || !edge.target) return {};
                const auto target = index_for(*edge.target);
                if (!target || std::find(successors[i].begin(), successors[i].end(), *target) != successors[i].end())
                    return {};
                if (edge.block) {
                    const auto block_target = id_index.find(edge.block->value);
                    if (block_target == id_index.end() || block_target->second != *target) return {};
                }
                successors[i].push_back(*target);
                predecessors[*target].push_back(i);
            }
            if (successors[i].size() > 2 && !function.blocks[i].switch_dispatch) return {};
        }

        std::vector<bool> reachable(count, false);
        std::vector<std::size_t> work{*entry_index};
        reachable[*entry_index] = true;
        while (!work.empty()) {
            const auto current = work.back(); work.pop_back();
            for (const auto next : successors[current]) if (!reachable[next]) {
                reachable[next] = true;
                work.push_back(next);
            }
        }
        if (std::any_of(reachable.begin(), reachable.end(), [](bool value) { return !value; })) return {};

        std::vector<std::size_t> indegree(count);
        for (std::size_t i = 0; i < count; ++i) indegree[i] = predecessors[i].size();
        std::vector<std::size_t> ready;
        for (std::size_t i = 0; i < count; ++i) if (indegree[i] == 0) ready.push_back(i);
        std::vector<std::size_t> topological;
        while (!ready.empty()) {
            const auto current = ready.back(); ready.pop_back();
            topological.push_back(current);
            for (const auto next : successors[current]) if (--indegree[next] == 0) ready.push_back(next);
        }
        if (topological.size() != count) return {}; // cyclic or irreducible regions stay on the goto path
        std::vector<std::size_t> exits;
        for (std::size_t i = 0; i < count; ++i) if (successors[i].empty()) exits.push_back(i);
        if (exits.empty()) return {};
        if (exits.size() > 1 && std::any_of(exits.begin(), exits.end(), [&](const auto exit) {
                return !has_only_terminal_return(function.blocks[exit]);
            })) return {}; // only explicit returns terminate a multi-exit arm

        std::size_t acyclic_phi_input_count = 0;
        for (std::size_t i = 0; i < count; ++i) {
            const auto &block = function.blocks[i];
            std::size_t branch_count = 0;
            for (std::size_t n = 0; n < block.instructions.size(); ++n) {
                if (!std::holds_alternative<Branch>(block.instructions[n].statement)) continue;
                ++branch_count;
                if (n + 1 != block.instructions.size()) return {};
            }
            if (branch_count > 1) return {};
            if (block.switch_dispatch) {
                // Complete metadata and its terminal transfer were checked at
                // function entry; it can have any bounded number of targets.
            } else if (branch_count == 1) {
                const auto &branch_statement = std::get<Branch>(block.instructions.back().statement);
                if (branch_statement.condition == "true") {
                    if (successors[i].size() != 1 || !branch_statement.true_target || branch_statement.false_target ||
                        branch_statement.indirect_target ||
                        !has_unconditional_edge(block, *branch_statement.true_target) ||
                        function.blocks[successors[i].front()].begin != *branch_statement.true_target) return {};
                } else if (!terminal_conditional(block)) return {};
            } else if (successors[i].size() > 1) {
                return {};
            }
            if (contains_return(block) &&
                (!has_only_terminal_return(block) || !successors[i].empty())) return {};

            if ((!block.phis.empty() || block.memory_phi || !block.memory_partition_phis.empty()) &&
                predecessors[i].empty()) return {};
            const auto validate_phi_inputs = [&](const auto &phi) {
                if (phi.inputs.size() != predecessors[i].size() ||
                    phi.inputs.size() > 65536 - acyclic_phi_input_count) return false;
                acyclic_phi_input_count += phi.inputs.size();
                std::set<std::uint64_t> seen_predecessors;
                for (const auto &input : phi.inputs) {
                    const auto pred = id_index.find(input.predecessor.value);
                    if (pred == id_index.end() ||
                        std::find(predecessors[i].begin(), predecessors[i].end(), pred->second) == predecessors[i].end() ||
                        !seen_predecessors.insert(input.predecessor.value).second) return false;
                }
                return true;
            };
            if (block.phis.size() > 4096 ||
                !std::all_of(block.phis.begin(), block.phis.end(), validate_phi_inputs)) return {};
            std::vector<RegisterOperand> phi_destinations;
            for (const auto &phi : block.phis) {
                if (std::find(phi_destinations.begin(), phi_destinations.end(), phi.destination) !=
                    phi_destinations.end()) return {};
                phi_destinations.push_back(phi.destination);
            }
            if (block.memory_phi && !validate_phi_inputs(*block.memory_phi)) return {};
            if (block.memory_partition_phis.size() > 4096) return {};
            std::set<std::string> memory_partitions;
            for (const auto &phi : block.memory_partition_phis)
                if (phi.partition.empty() || !memory_partitions.insert(phi.partition).second ||
                    !validate_phi_inputs(phi)) return {};
        }

        const std::size_t virtual_exit = count;
        std::vector<std::set<std::size_t>> postdominators(count + 1);
        postdominators[virtual_exit].insert(virtual_exit);
        for (auto it = topological.rbegin(); it != topological.rend(); ++it) {
            const auto node = *it;
            if (successors[node].empty()) {
                postdominators[node].insert(node);
                postdominators[node].insert(virtual_exit);
                continue;
            }
            auto common = postdominators[successors[node].front()];
            for (std::size_t n = 1; n < successors[node].size(); ++n) {
                std::set<std::size_t> intersection;
                std::set_intersection(common.begin(), common.end(), postdominators[successors[node][n]].begin(),
                                      postdominators[successors[node][n]].end(),
                                      std::inserter(intersection, intersection.end()));
                common = std::move(intersection);
            }
            common.insert(node);
            postdominators[node] = std::move(common);
        }
        const auto nearest_common_postdominator = [&](const std::vector<std::size_t> &targets)
            -> std::optional<std::size_t> {
            if (targets.empty()) return {};
            std::optional<std::size_t> nearest;
            for (const auto candidate : postdominators[targets.front()]) {
                if (std::any_of(targets.begin() + 1, targets.end(), [&](const auto target) {
                        return !postdominators[target].contains(candidate);
                    })) continue;
                if (!nearest || postdominators[candidate].size() > postdominators[*nearest].size()) nearest = candidate;
                else if (postdominators[candidate].size() == postdominators[*nearest].size()) return {};
            }
            return nearest;
        };

        auto emit_edge_phi_copies = [&](std::size_t join, BlockId predecessor, unsigned indent) -> bool {
            std::vector<std::pair<std::string, std::string>> copies;
            copies.reserve(function.blocks[join].phis.size());
            for (const auto &phi : function.blocks[join].phis) {
                const auto input = std::find_if(phi.inputs.begin(), phi.inputs.end(), [&](const auto &candidate) {
                    return candidate.predecessor == predecessor;
                });
                if (input == phi.inputs.end()) return false;
                copies.emplace_back(register_name(phi.destination, phi.version),
                                    register_name(phi.destination, input->version));
            }
            emit_parallel_copies(out, copies, indent);
            return true;
        };

        // A shared block need not be a post-dominator of the enclosing branch:
        // one arm can enter a cleanup/return region that another arm reaches
        // only under a second predicate. Such overlapping joins cannot be
        // represented by moving that block after either conditional. Duplicate
        // it in the mutually exclusive paths instead. The graph was proven
        // acyclic above, so each dynamic execution still visits that original
        // block at most once. Keep the incoming *CFG* predecessor on each copy;
        // synthetic region predecessors would select the wrong SSA phi input.
        constexpr std::size_t max_acyclic_occurrences = 4096;
        constexpr std::size_t max_copies_per_block = 64;
        constexpr unsigned max_acyclic_region_depth = 64;
        std::vector<std::size_t> occurrences(count, 0);
        std::size_t occurrence_count = 0;
        std::set<std::size_t> emitted;
        std::function<bool(std::size_t, std::optional<std::size_t>, unsigned,
                           std::optional<BlockId>, unsigned)> emit_region;
        emit_region = [&](std::size_t start, std::optional<std::size_t> stop, unsigned indent,
                          std::optional<BlockId> incoming_predecessor, unsigned depth) -> bool {
            if (depth > max_acyclic_region_depth) return false;
            std::size_t current = start;
            std::set<std::size_t> local_path;
            while (true) {
                if (current == virtual_exit) return !stop || *stop == virtual_exit;
                if (stop && current == *stop)
                    return incoming_predecessor && emit_edge_phi_copies(current, *incoming_predecessor, indent);
                if (!local_path.insert(current).second ||
                    ++occurrences[current] > max_copies_per_block ||
                    ++occurrence_count > max_acyclic_occurrences) return false;
                emitted.insert(current);
                if (incoming_predecessor && !emit_edge_phi_copies(current, *incoming_predecessor, indent)) return false;
                const auto &block = function.blocks[current];
                if (block.switch_dispatch) {
                    const auto &dispatch = *block.switch_dispatch;
                    const auto join = nearest_common_postdominator(successors[current]);
                    if (!join || *join == current || (stop && !postdominators[*join].contains(*stop))) return false;
                    const auto groups = group_switch_arms(dispatch);
                    const std::string spaces(indent, ' '), labels(indent + 4, ' ');
                    emit_block(block, indent, true);
                    out << spaces << "switch (" << expression_text(*dispatch.selector) << ") {\n";
                    for (const auto &group : groups) {
                        for (const auto value : group.values)
                            out << labels << "case 0x" << std::hex << value << std::dec << ":\n";
                        if (group.is_default) out << labels << "default:\n";
                        out << labels << "{\n";
                        const auto target = index_for(group.target);
                        if (!target || !emit_region(*target, join, indent + 8, block.id, depth + 1)) return false;
                        out << std::string(indent + 8, ' ') << "break;\n" << labels << "}\n";
                    }
                    out << spaces << "}\n";
                    if (stop && *join == *stop) return true;
                    current = *join;
                    incoming_predecessor.reset();
                    continue;
                }
                const auto *conditional = terminal_conditional(block);
                if (conditional) {
                    emit_block(block, indent, true);
                    const auto true_target = index_for(*conditional->true_target);
                    const auto false_target = index_for(*conditional->false_target);
                    if (!true_target || !false_target) return false;
                    const auto join = nearest_common_postdominator({*true_target, *false_target});
                    if (!join || *join == current || (stop && !postdominators[*join].contains(*stop))) return false;
                    const std::string spaces(indent, ' ');
                    out << spaces << "if (" << branch_condition_text(*conditional) << ") {\n";
                    if (!emit_region(*true_target, join, indent + 4, block.id, depth + 1)) return false;
                    out << spaces << "} else {\n";
                    if (!emit_region(*false_target, join, indent + 4, block.id, depth + 1)) return false;
                    out << spaces << "}\n";
                    if (stop && *join == *stop) return true;
                    current = *join;
                    incoming_predecessor.reset();
                    continue;
                }

                const bool omit_branch = !block.instructions.empty() &&
                    std::holds_alternative<Branch>(block.instructions.back().statement);
                emit_block(block, indent, omit_branch);
                if (successors[current].empty()) return !stop || *stop == virtual_exit;
                if (successors[current].size() != 1) return false;
                const auto next = successors[current].front();
                if (stop && next == *stop) return emit_edge_phi_copies(next, block.id, indent);
                current = next;
                incoming_predecessor = block.id;
            }
        };

        out << "function " << address_label(function.entry) << "() {\n";
        if (!emit_region(*entry_index, {}, 4, {}, 0) || emitted.size() != count) {
            out.str(std::string{});
            out.clear();
            return {};
        }
        out << "}\n";
        return StructuredPseudocode{out.str(), false, {}};
    };
    if (auto structured = try_acyclic_regions()) return *structured;

    // Irreducible and cross-region-sharing CFGs cannot always be expressed as
    // nested if/loop regions without duplicating effects. Preserve their
    // blocks in a structured state-machine loop instead: every CFG edge sets
    // the next block and every register phi is copied on that edge. This keeps
    // block order, side effects, and SSA edge values intact while avoiding an
    // arbitrary goto-shaped source fallback for otherwise direct control flow.
    auto try_state_machine = [&]() -> std::optional<StructuredPseudocode> {
        const auto count = function.blocks.size();
        if (count == 0 || count > 1024) return {};
        std::map<std::pair<std::uint64_t, std::uint64_t>, std::size_t> address_index;
        std::map<std::uint64_t, std::size_t> id_index;
        for (std::size_t i = 0; i < count; ++i) {
            const auto &block = function.blocks[i];
            if (!address_index.emplace(std::pair{block.begin.space.value, block.begin.offset}, i).second ||
                !id_index.emplace(block.id.value, i).second) return {};
        }
        const auto index_for = [&](Address address) -> std::optional<std::size_t> {
            const auto found = address_index.find({address.space.value, address.offset});
            return found == address_index.end() ? std::nullopt : std::optional<std::size_t>{found->second};
        };
        const auto entry_index = index_for(function.entry);
        if (!entry_index) return {};
        if (!function.blocks[*entry_index].phis.empty() || function.blocks[*entry_index].memory_phi)
            return {}; // No incoming edge executes before the first state dispatch.

        std::vector<std::vector<std::size_t>> successors(count), predecessors(count);
        std::size_t edge_count = 0;
        for (std::size_t i = 0; i < count; ++i) {
            const auto &block = function.blocks[i];
            for (const auto &edge : block.successors) {
                if (++edge_count > 4096 || !edge.target) return {};
                const auto target = index_for(*edge.target);
                if (!target || std::find(successors[i].begin(), successors[i].end(), *target) != successors[i].end())
                    return {};
                if (edge.block) {
                    const auto by_id = id_index.find(edge.block->value);
                    if (by_id == id_index.end() || by_id->second != *target) return {};
                }
                successors[i].push_back(*target);
                predecessors[*target].push_back(i);
            }

            std::size_t branch_count = 0;
            for (std::size_t n = 0; n < block.instructions.size(); ++n) {
                if (!std::holds_alternative<Branch>(block.instructions[n].statement)) continue;
                if (++branch_count > 1 || n + 1 != block.instructions.size()) return {};
            }
            if (block.switch_dispatch) {
                // The common switch validator checked its transfer and exact
                // target set before any formatter was entered.
            } else if (branch_count == 1) {
                const auto &transfer = std::get<Branch>(block.instructions.back().statement);
                if (transfer.indirect_target) return {};
                if (transfer.condition == "true") {
                    if (!transfer.true_target || transfer.false_target || successors[i].size() != 1 ||
                        block.successors.front().target != transfer.true_target ||
                        (block.successors.front().kind != BlockEdgeKind::jump &&
                         block.successors.front().kind != BlockEdgeKind::fallthrough)) return {};
                } else if (!terminal_conditional(block)) {
                    return {};
                }
            } else if (successors[i].size() > 1) {
                return {};
            }
            if (contains_return(block) &&
                (!has_only_terminal_return(block) || !successors[i].empty())) return {};
            if (successors[i].empty() && !has_only_terminal_return(block)) return {};
        }

        std::vector<bool> reachable(count, false);
        std::vector<std::size_t> work{*entry_index};
        reachable[*entry_index] = true;
        while (!work.empty()) {
            const auto current = work.back();
            work.pop_back();
            for (const auto target : successors[current]) {
                if (!reachable[target]) {
                    reachable[target] = true;
                    work.push_back(target);
                }
            }
        }
        if (std::any_of(reachable.begin(), reachable.end(), [](bool value) { return !value; })) return {};

        std::size_t machine_phi_input_count = 0;
        for (std::size_t i = 0; i < count; ++i) {
            const auto &block = function.blocks[i];
            const auto validate_one_phi = [&](const auto &phi) {
                if (phi.inputs.size() != predecessors[i].size() ||
                    phi.inputs.size() > 65536 - machine_phi_input_count) return false;
                machine_phi_input_count += phi.inputs.size();
                std::set<std::uint64_t> seen;
                for (const auto &input : phi.inputs) {
                    const auto pred = id_index.find(input.predecessor.value);
                    if (pred == id_index.end() ||
                        std::find(predecessors[i].begin(), predecessors[i].end(), pred->second) == predecessors[i].end() ||
                        !seen.insert(input.predecessor.value).second) return false;
                }
                return true;
            };
            if (block.phis.size() > 4096 ||
                !std::all_of(block.phis.begin(), block.phis.end(), validate_one_phi) ||
                (block.memory_phi && !validate_one_phi(*block.memory_phi)) ||
                block.memory_partition_phis.size() > 4096) return {};
            std::set<std::string> memory_partitions;
            for (const auto &phi : block.memory_partition_phis)
                if (phi.partition.empty() || !memory_partitions.insert(phi.partition).second ||
                    !validate_one_phi(phi)) return {};
        }

        std::ostringstream machine;
        machine << "function " << address_label(function.entry) << "() {\n"
                << "    unsigned block_id = " << *entry_index << ";\n"
                << "    while (true) {\n"
                << "        switch (block_id) {\n";
        const auto append_machine_block = [&](const LiftedBlock &block, bool omit_branch) {
            auto *previous = statement_output;
            statement_output = &machine;
            emit_block(block, 12, omit_branch);
            statement_output = previous;
        };
        const auto emit_transition = [&](std::size_t source, std::size_t target, unsigned indent) {
            const std::string spaces(indent, ' ');
            std::vector<std::pair<std::string, std::string>> copies;
            for (const auto &phi : function.blocks[target].phis) {
                const auto input = std::find_if(phi.inputs.begin(), phi.inputs.end(), [&](const auto &candidate) {
                    return candidate.predecessor == function.blocks[source].id;
                });
                if (input == phi.inputs.end()) return false;
                copies.emplace_back(register_name(phi.destination, phi.version),
                                    register_name(phi.destination, input->version));
            }
            // A backedge can swap two live phi values. Capture the complete
            // incoming state before writing any destination, just as SSA phi
            // assignments happen simultaneously on the original edge.
            emit_parallel_copies(machine, copies, indent);
            machine << spaces << "block_id = " << target << ";\n"
                    << spaces << "continue;\n";
            return true;
        };
        for (std::size_t i = 0; i < count; ++i) {
            const auto &block = function.blocks[i];
            machine << "        case " << i << ": { // " << address_label(block.begin) << "\n";
            const auto *conditional = terminal_conditional(block);
            const bool has_terminal_branch = !block.instructions.empty() &&
                std::holds_alternative<Branch>(block.instructions.back().statement);
            if (block.switch_dispatch) {
                const auto &dispatch = *block.switch_dispatch;
                append_machine_block(block, has_terminal_branch);
                machine << "            switch (" << expression_text(*dispatch.selector) << ") {\n";
                for (const auto &group : group_switch_arms(dispatch)) {
                    for (const auto value : group.values)
                        machine << "            case 0x" << std::hex << value << std::dec << ":\n";
                    if (group.is_default) machine << "            default:\n";
                    machine << "            {\n";
                    const auto target = index_for(group.target);
                    if (!target || !emit_transition(i, *target, 16)) return {};
                    machine << "            }\n";
                }
                machine << "            }\n";
            } else if (conditional) {
                append_machine_block(block, true);
                const auto true_target = index_for(*conditional->true_target);
                const auto false_target = index_for(*conditional->false_target);
                if (!true_target || !false_target) return {};
                machine << "            if (" << branch_condition_text(*conditional) << ") {\n";
                if (!emit_transition(i, *true_target, 16)) return {};
                machine << "            } else {\n";
                if (!emit_transition(i, *false_target, 16)) return {};
                machine << "            }\n"
                        << "            continue;\n";
            } else if (!successors[i].empty()) {
                append_machine_block(block, has_terminal_branch);
                if (successors[i].size() != 1 || !emit_transition(i, successors[i].front(), 12)) return {};
            } else {
                append_machine_block(block, false);
            }
            machine << "        }\n";
        }
        machine << "        default: unreachable();\n"
                << "        }\n"
                << "    }\n"
                << "}\n";
        return StructuredPseudocode{machine.str(), false, {}};
    };
    if (auto machine = try_state_machine()) return *machine;
    if (!branch) return fallback("entry block lacks a unique terminal two-way conditional branch");

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
    if (join == entry || !join->successors.empty() ||
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
            if (block->successors.size() != 1 || !edge_targets(block->successors.front(), next->begin))
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

    const auto *true_tail = true_arm.empty() ? entry : true_arm.back();
    const auto *false_tail = false_arm.empty() ? entry : false_arm.back();
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
    out << "    if (" << branch_condition_text(*branch) << ") {\n";
    for (const auto *block : true_arm) emit_block(*block, 8, true);
    emit_parallel_copies(out, edge_copies[true_tail->id.value], 8);
    out << "    } else {\n";
    for (const auto *block : false_arm) emit_block(*block, 8, true);
    emit_parallel_copies(out, edge_copies[false_tail->id.value], 8);
    out << "    }\n";
    emit_block(*join, 4);
    out << "}\n";
    return {out.str(), false, {}};
}
} // namespace hexlab::decompiler
