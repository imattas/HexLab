#include "hexlab/decompiler/decompiler.hpp"

#include <algorithm>
#include <cstdlib>
#include <iostream>

using namespace hexlab;
using namespace hexlab::decompiler;

namespace {
void require(bool condition, const char *message) {
    if (!condition) { std::cerr << message << '\n'; std::exit(1); }
}
Instruction instruction(Opcode opcode, std::vector<Operand> operands, unsigned xlen = 64) {
    Instruction result;
    result.context = {xlen == 32 ? Architecture::riscv32 : Architecture::riscv64,
                      xlen == 32 ? ExecutionMode::rv32 : ExecutionMode::rv64, ByteOrder::little};
    result.address = Address{{0}, 0x1000};
    result.opcode = opcode;
    result.operands = std::move(operands);
    return result;
}
LiftedFunction lift(std::vector<Instruction> instructions) {
    auto source = std::make_shared<BasicBlock>();
    source->id = BlockId{1}; source->begin = Address{{0}, 0x1000};
    for (std::size_t n = 0; n < instructions.size(); ++n)
        source->instructions.push_back(std::make_shared<InstructionFact>(InstructionFact{n + 1, std::move(instructions[n]), {}}));
    FunctionRecord record; record.id = FunctionId{1}; record.entry = source->begin; record.blocks = {source->id};
    FunctionSnapshot snapshot; snapshot.blocks = {source};
    auto result = lift_function(record, snapshot);
    require(bool(result), "RISC-V function lifts");
    return std::move(result).value();
}
}
int main() {
    const RegisterOperand x0{RegisterBank::riscv_gpr, 0, 64, false};
    const RegisterOperand x1{RegisterBank::riscv_gpr, 1, 64, false};
    const RegisterOperand x2{RegisterBank::riscv_gpr, 2, 64, false};
    const RegisterOperand x3{RegisterBank::riscv_gpr, 3, 64, false};
    const auto addi = instruction(Opcode::rv_addi, {x3, x1, ImmediateOperand{5, 12, 64, true, {}}});
    const auto add = instruction(Opcode::rv_add, {x2, x1, x0});
    auto lifted = lift({addi, add});
    const auto text = format_pseudocode(lifted);
    require(text.find("x3 = (x1 + 0x5);") != std::string::npos, "ADDI uses rs1 and sign-extended immediate");
    require(text.find("x2 = (x1 + 0x0);") != std::string::npos, "x0 reads as constant zero");
    const auto ignored = instruction(Opcode::rv_addi, {x0, x1, ImmediateOperand{9, 12, 64, true, {}}});
    require(format_pseudocode(lift({ignored})).find("x0 =") == std::string::npos,
            "writes to architectural x0 are discarded");
    const MemoryOperand byte_load{8, 64, {}, x1, {}, 1, 0, false, {}, {}};
    const auto lb = instruction(Opcode::rv_lb, {x3, byte_load});
    const auto lb_text = format_pseudocode(lift({lb}));
    require(lb_text.find("x3 = sext(*[(x1)]);") != std::string::npos,
            "LB sign-extends the loaded byte to XLEN");
    const auto lbu = instruction(Opcode::rv_lbu, {x3, byte_load});
    require(format_pseudocode(lift({lbu})).find("x3 = zext(*[(x1)]);") != std::string::npos,
            "LBU zero-extends the loaded byte to XLEN");    auto ssa = to_ssa(lifted);
    require(ssa && format_pseudocode(ssa.value()).find("x2_1 = (x1_0 + 0x0);") != std::string::npos,
            "RISC-V assignments enter ordinary SSA");

    const RegisterOperand rv32_x0{RegisterBank::riscv_gpr, 0, 32, false};
    const RegisterOperand rv32_x1{RegisterBank::riscv_gpr, 1, 32, false};
    const RegisterOperand rv32_x2{RegisterBank::riscv_gpr, 2, 32, false};
    const RegisterOperand rv32_x3{RegisterBank::riscv_gpr, 3, 32, false};
    auto rv32_constants = lift({instruction(Opcode::rv_addi, {rv32_x1, rv32_x0, ImmediateOperand{6, 12, 32, true, {}}}, 32),
                                instruction(Opcode::rv_addi, {rv32_x2, rv32_x0, ImmediateOperand{7, 12, 32, true, {}}}, 32),
                                instruction(Opcode::rv_mul, {rv32_x3, rv32_x1, rv32_x2}, 32)});
    auto rv32_ssa = to_ssa(rv32_constants);
    require(bool(rv32_ssa), "RV32 integer function converts to SSA");
    auto rv32_folded = simplify_constants(rv32_ssa.value());
    require(rv32_folded && format_pseudocode(rv32_folded.value()).find("x3_1 = 0x2a;") != std::string::npos,
            "RV32M multiplication uses the shared XLEN-aware semantics evaluator");
    const RegisterOperand a{RegisterBank::riscv_gpr, 10, 64, false};
    const RegisterOperand b{RegisterBank::riscv_gpr, 11, 64, false};
    const RegisterOperand d{RegisterBank::riscv_gpr, 12, 64, false};
    auto high = instruction(Opcode::rv_mulhsu, {d, a, b});
    auto word = instruction(Opcode::rv_divuw, {d, a, b});
    const auto mtext = format_pseudocode(lift({high, word}));
    require(mtext.find("mulhsu(x10, x11)") != std::string::npos, "M high multiply remains explicit");
    require(mtext.find("divuw(x10, x11)") != std::string::npos, "RV64 word operation remains explicit");

    auto atomic = instruction(Opcode::rv_amoadd_w,
        {d, b, MemoryOperand{32, 64, {}, a, {}, 1, 0, false, {}, {}}});
    atomic.memory_read = true;
    atomic.memory_write = true;
    atomic.atomic_aq = true;
    atomic.atomic_rl = true;
    require(format_pseudocode(lift({atomic})).find("amoadd.w.aqrl(") != std::string::npos,
            "atomic operations retain a named opaque intrinsic and aq/rl ordering in pseudocode");

    auto jal = instruction(Opcode::rv_jal, {rv32_x0, RelativeOperand{16, 21, 32, {}}}, 32);
    jal.flow = FlowKind::jump;
    jal.direct_target = Address{{0}, 0x1010};
    require(format_pseudocode(lift({jal})).find("goto loc_1010;") != std::string::npos,
            "JAL x0 remains a control transfer despite discarding its link-register write");
    auto branch = instruction(Opcode::rv_beq, {a, b, RelativeOperand{12, 13, 64, {}}});
    branch.flow = FlowKind::conditional_branch;
    branch.direct_target = Address{{0}, 0x1020};
    require(format_pseudocode(lift({branch})).find("if ((x10 == x11))") != std::string::npos,
            "BEQ lifts its register comparison as a branch predicate");

    const auto lui = instruction(Opcode::rv_lui, {a, ImmediateOperand{0x7ffff000, 20, 64, true, {}}});
    const auto addi_max = instruction(Opcode::rv_addi, {a, a, ImmediateOperand{0xfff, 12, 64, true, {}}});
    const auto one = instruction(Opcode::rv_addi, {b, x0, ImmediateOperand{1, 12, 64, true, {}}});
    const auto addw = instruction(Opcode::rv_addw, {d, a, b});
    auto word_constants = lift({lui, addi_max, one, addw});
    auto word_ssa = to_ssa(word_constants);
    require(bool(word_ssa), "RV64 word arithmetic converts to SSA");
    auto word_folded = simplify_constants(word_ssa.value());
    require(word_folded && format_pseudocode(word_folded.value()).find("x12_1 = 0xffffffff80000000;") != std::string::npos,
            "ADDW computes 32-bit modular arithmetic and sign-extends to RV64");
    auto constants = lift({instruction(Opcode::rv_addi, {a, x0, ImmediateOperand{0xfffffffffffffff0ULL, 12, 64, true, {}}}),
                           instruction(Opcode::rv_addi, {b, x0, ImmediateOperand{3, 12, 64, true, {}}}),
                           instruction(Opcode::rv_div, {d, a, b})});
    auto constants_ssa = to_ssa(constants);
    require(bool(constants_ssa), "constant RISC-V function converts to SSA");
    auto folded = simplify_constants(constants_ssa.value());
    require(bool(folded), "RISC-V constants simplify");
    const auto folded_text = format_pseudocode(folded.value());
    require(folded_text.find("x12_1 = 0xfffffffffffffffb;") != std::string::npos,
            "RV64 signed division uses architectural fixed-width result");

    const RegisterOperand f1{RegisterBank::riscv_fpr, 1, 64, false};
    const RegisterOperand f2{RegisterBank::riscv_fpr, 2, 64, false};
    const RegisterOperand f3{RegisterBank::riscv_fpr, 3, 64, false};
    const RegisterOperand fflags{RegisterBank::riscv_fstatus, 0, 5, false};
    auto fadd = instruction(Opcode::rv_fadd_s, {f3, f1, f2});
    fadd.rounding_mode = 0;
    fadd.writes_fflags = true;
    fadd.register_writes = {f3, fflags};
    const auto fp_lifted = lift({fadd});
    const auto *fp_intrinsic = std::get_if<Intrinsic>(&fp_lifted.blocks[0].instructions[0].statement);
    require(fp_intrinsic && fp_intrinsic->name == "fadd.s" && fp_intrinsic->register_writes.size() == 2 &&
                fp_intrinsic->operands.size() == 2 &&
                fp_intrinsic->operands[0]->type.kind == TypeKind::floating &&
                fp_intrinsic->operands[0]->type.bits == 32,
            "S arithmetic uses 32-bit floating views of the 64-bit physical FPRs");
    auto fp_ssa = to_ssa(fp_lifted);
    require(fp_ssa && format_pseudocode(fp_ssa.value()).find("fadd.s(f1_0, f2_0) /* writes f3_1, fflags_1 */") != std::string::npos,
            "FPR and floating status writes enter ordinary SSA");
    const RegisterOperand f4{RegisterBank::riscv_fpr, 4, 64, false};
    const auto fmadd_d = lift({instruction(Opcode::rv_fmadd_d, {f4, f1, f2, f3})});
    const auto *fma_intrinsic = std::get_if<Intrinsic>(&fmadd_d.blocks[0].instructions[0].statement);
    require(fma_intrinsic && fma_intrinsic->operands.size() == 3 &&
                std::all_of(fma_intrinsic->operands.begin(), fma_intrinsic->operands.end(), [](const auto &operand) {
                    return operand->type.kind == TypeKind::floating && operand->type.bits == 64;
                }),
            "FMADD.D retains three 64-bit floating source values");
    const auto fcvt_s_d = lift({instruction(Opcode::rv_fcvt_s_d, {f3, f1})});
    const auto *s_from_d = std::get_if<Intrinsic>(&fcvt_s_d.blocks[0].instructions[0].statement);
    require(s_from_d && s_from_d->operands.size() == 1 && s_from_d->operands[0]->type.kind == TypeKind::floating &&
                s_from_d->operands[0]->type.bits == 64,
            "FCVT.S.D reads the source as a 64-bit double value");
    const MemoryOperand fp_slot{32, 64, {}, a, {}, 1, 8, false, {}, {}};
    const auto flw = instruction(Opcode::rv_flw, {f3, fp_slot});
    const auto flw_lifted = lift({flw});
    const auto *loaded_fp = std::get_if<Assign>(&flw_lifted.blocks[0].instructions[0].statement);
    require(loaded_fp && loaded_fp->value->type.kind == TypeKind::floating && loaded_fp->value->type.bits == 32,
            "FLW exposes a 32-bit floating memory value in the physical FPR bank");
    const auto fsw = instruction(Opcode::rv_fsw, {f3, fp_slot});
    const auto fsw_lifted = lift({fsw});
    const auto *stored_fp = std::get_if<Store>(&fsw_lifted.blocks[0].instructions[0].statement);
    require(stored_fp && stored_fp->address->type.kind == TypeKind::floating && stored_fp->address->type.bits == 32 &&
                stored_fp->value->type.kind == TypeKind::floating && stored_fp->value->type.bits == 32,
            "FSW preserves its floating store width and value type");

    const RegisterOperand x5{RegisterBank::riscv_gpr, 5, 64, false};
    const auto fcvt_s_w = lift({instruction(Opcode::rv_fcvt_s_w, {f3, x5})});
    const auto *converted_fp = std::get_if<Intrinsic>(&fcvt_s_w.blocks[0].instructions[0].statement);
    require(converted_fp && converted_fp->operands.size() == 1 &&
                converted_fp->operands[0]->type.kind == TypeKind::integer && converted_fp->operands[0]->type.bits == 32,
            "FCVT.S.W uses a 32-bit integer source view of the XLEN-wide GPR");
}
