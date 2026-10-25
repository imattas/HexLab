#include "hexlab/decompiler/decompiler.hpp"
#include <cstdlib>
#include <array>
#include <iostream>

using namespace hexlab;
using namespace hexlab::decompiler;

namespace {
void require(bool condition, const char *message) {
    if (!condition) { std::cerr << message << '\n'; std::exit(1); }
}
Instruction ins(Opcode opcode, std::vector<Operand> operands) {
    Instruction result;
    result.context = {Architecture::mips64, ExecutionMode::mips64, ByteOrder::little};
    result.address = Address{{0}, 0x1000};
    result.length = 4;
    result.opcode = opcode;
    result.operands = std::move(operands);
    return result;
}
Instruction decode_word(std::uint32_t word) {
    const std::array bytes{std::byte{static_cast<unsigned char>(word)},
                           std::byte{static_cast<unsigned char>(word >> 8)},
                           std::byte{static_cast<unsigned char>(word >> 16)},
                           std::byte{static_cast<unsigned char>(word >> 24)}};
    auto decoded = decode_instruction({Architecture::mips64, ExecutionMode::mips64, ByteOrder::little},
                                      bytes, Address{{0}, 0x1000});
    if (decoded.status != DecodeStatus::decoded || !decoded.instruction)
        std::cerr << "failed literal MIPS64 word 0x" << std::hex << word << ": " << decoded.reason << '\n';
    require(decoded.status == DecodeStatus::decoded && decoded.instruction,
            "literal MIPS64 word instruction decodes");
    return std::move(*decoded.instruction);
}
bool is_sign_extended_word_result(const Statement &statement, const char *operation) {
    const auto *assignment = std::get_if<Assign>(&statement);
    const auto *extension = assignment ? std::get_if<UnaryValue>(&assignment->value->value) : nullptr;
    const auto *word_operation = extension ? std::get_if<BinaryValue>(&extension->operand->value) : nullptr;
    return assignment && assignment->value->type.bits == 64 && extension && extension->operation == "sext" &&
           extension->operand->type.bits == 32 && word_operation && word_operation->operation == operation &&
           word_operation->left->type.bits == 32;
}
LiftedFunction lift(std::vector<Instruction> instructions) {
    auto block = std::make_shared<BasicBlock>();
    block->id = BlockId{1}; block->begin = Address{{0}, 0x1000};
    for (std::size_t n = 0; n < instructions.size(); ++n) {
        instructions[n].address.offset += n * 4;
        block->instructions.push_back(std::make_shared<InstructionFact>(
            InstructionFact{n + 1, std::move(instructions[n]), {}}));
    }
    FunctionRecord record; record.id = FunctionId{1}; record.entry = block->begin; record.blocks = {block->id};
    FunctionSnapshot snapshot; snapshot.blocks = {block};
    auto result = lift_function(record, snapshot);
    require(bool(result), "MIPS64 function lifts");
    return std::move(result).value();
}
}

int main() {
    const RegisterOperand zero{RegisterBank::mips_gpr, 0, 64, false};
    const RegisterOperand at{RegisterBank::mips_gpr, 1, 64, false};
    const RegisterOperand v0{RegisterBank::mips_gpr, 2, 64, false};
    const RegisterOperand v1{RegisterBank::mips_gpr, 3, 64, false};
    const RegisterOperand a0{RegisterBank::mips_gpr, 4, 64, false};
    const RegisterOperand a1{RegisterBank::mips_gpr, 5, 64, false};

    auto arithmetic = lift({ins(Opcode::mips64_daddu, {v0, a0, a1}),
                            ins(Opcode::mips64_daddiu, {v1, v0, ImmediateOperand{UINT64_MAX - 3, 16, 64, true, {}}})});
    require(arithmetic.blocks[0].instructions.size() == 2 &&
                std::holds_alternative<Assign>(arithmetic.blocks[0].instructions[0].statement),
            "DADDU lowers to a 64-bit assignment");
    const auto &daddiu = std::get<Assign>(arithmetic.blocks[0].instructions[1].statement);
    const auto *daddiu_add = std::get_if<BinaryValue>(&daddiu.value->value);
    const auto *daddiu_immediate = daddiu_add ? std::get_if<ConstantValue>(&daddiu_add->right->value) : nullptr;
    require(daddiu.value->type == ValueType{TypeKind::integer, 64, false} && daddiu_add &&
                daddiu_add->operation == "add" && daddiu_immediate && daddiu_immediate->value == UINT64_MAX - 3,
            "DADDIU keeps the sign-extended immediate and doubleword width");

    auto daddi = ins(Opcode::mips64_daddi,
        {v0, a0, ImmediateOperand{UINT64_MAX - 3, 16, 64, true, {}}});
    daddi.register_writes = {v0};
    auto daddi_lifted = lift({std::move(daddi)});
    const auto *daddi_effect = std::get_if<Intrinsic>(&daddi_lifted.blocks[0].instructions[0].statement);
    require(daddi_effect && daddi_effect->name == "mips64_daddi_overflow" &&
                daddi_effect->register_writes == std::vector<RegisterOperand>{v0},
            "DADDI preserves architecturally trapping overflow behavior");

    const auto word_add = decode_word((4u << 21) | (5u << 16) | (2u << 11) | 0x21u); // ADDU v0,a0,a1
    const auto word_sub = decode_word((4u << 21) | (5u << 16) | (3u << 11) | 0x23u); // SUBU v1,a0,a1
    const auto word_addi = decode_word((0x09u << 26) | (2u << 21) | (3u << 16) | 0xffffu); // ADDIU v1,v0,-1
    const auto word_sll = decode_word((4u << 16) | (2u << 11) | (4u << 6)); // SLL v0,a0,4
    const auto word_srl = decode_word((4u << 16) | (3u << 11) | (7u << 6) | 0x02u); // SRL v1,a0,7
    const auto word_sra = decode_word((4u << 16) | (3u << 11) | (9u << 6) | 0x03u); // SRA v1,a0,9
    const auto word_lui = decode_word((0x0fu << 26) | (2u << 16) | 0x8000u); // LUI v0,0x8000
    const auto *addiu_imm = std::get_if<ImmediateOperand>(&word_addi.operands[2]);
    require(word_add.opcode == Opcode::mips_addu && word_sub.opcode == Opcode::mips_subu &&
                word_addi.opcode == Opcode::mips_addiu && addiu_imm && addiu_imm->is_signed &&
                addiu_imm->effective_width == 64 && addiu_imm->value == UINT64_MAX &&
                word_sll.opcode == Opcode::mips_sll && word_srl.opcode == Opcode::mips_srl &&
                word_sra.opcode == Opcode::mips_sra && word_lui.opcode == Opcode::mips_lui &&
                std::get<RegisterOperand>(word_add.operands[0]).width == 64,
            "literal N64 word instructions retain 64-bit GPRs and signed immediate decoding");
    auto word_ops = lift({word_add, word_sub, word_addi, word_sll, word_srl, word_sra, word_lui});
    const auto &word_statements = word_ops.blocks[0].instructions;
    require(word_statements.size() == 7 && is_sign_extended_word_result(word_statements[0].statement, "add") &&
                is_sign_extended_word_result(word_statements[1].statement, "sub") &&
                is_sign_extended_word_result(word_statements[2].statement, "add") &&
                is_sign_extended_word_result(word_statements[3].statement, "shl") &&
                is_sign_extended_word_result(word_statements[4].statement, "shr") &&
                is_sign_extended_word_result(word_statements[5].statement, "sar") &&
                is_sign_extended_word_result(word_statements[6].statement, "shl"),
            "ADDU/SUBU/ADDIU/SLL/SRL/SRA/LUI sign-extend their 32-bit result into the N64 GPR");

    auto dmult = ins(Opcode::mips64_dmult, {a0, a1});
    dmult.register_reads = {a0, a1};
    dmult.register_writes = {{RegisterBank::mips_hilo, 0, 64, false}, {RegisterBank::mips_hilo, 1, 64, false}};
    auto mfhi = ins(Opcode::mips64_mfhi, {v0});
    mfhi.register_reads = {{RegisterBank::mips_hilo, 0, 64, false}};
    mfhi.register_writes = {v0};
    auto mtlo = ins(Opcode::mips64_mtlo, {v1});
    mtlo.register_reads = {v1};
    mtlo.register_writes = {{RegisterBank::mips_hilo, 1, 64, false}};
    auto hilo = lift({std::move(dmult), std::move(mfhi), std::move(mtlo)});
    const auto *multiply = std::get_if<Intrinsic>(&hilo.blocks[0].instructions[0].statement);
    const auto *high_read = std::get_if<Assign>(&hilo.blocks[0].instructions[1].statement);
    const auto *low_write = std::get_if<Assign>(&hilo.blocks[0].instructions[2].statement);
    const auto *high_register = high_read ? std::get_if<RegisterValue>(&high_read->value->value) : nullptr;
    require(multiply && multiply->name == "mips64.dmult.s64" &&
                multiply->register_writes == std::vector<RegisterOperand>{{RegisterBank::mips_hilo, 0, 64, false},
                                                                           {RegisterBank::mips_hilo, 1, 64, false}} &&
                high_register && high_register->reg == RegisterOperand{RegisterBank::mips_hilo, 0, 64, false} &&
                low_write && low_write->destination == RegisterOperand{RegisterBank::mips_hilo, 1, 64, false},
            "MIPS64 HI/LO arithmetic and moves preserve 64-bit dataflow");

    auto shifts = lift({ins(Opcode::mips64_dsll32, {v0, a0, ImmediateOperand{33, 6, 64, false, {}}}),
                        ins(Opcode::mips64_dsrlv, {v1, a1, a0})});
    const auto shift_text = format_pseudocode(shifts);
    require(shift_text.find("<<") != std::string::npos && shift_text.find("mips64_dsrlv") != std::string::npos,
            "doubleword shift semantics preserve fixed and variable shift operations");

    const MemoryOperand word_memory{32, 64, {}, a0, {}, 1, -8, false, {}, {}};
    const MemoryOperand double_memory{64, 64, {}, a0, {}, 1, 16, false, {}, {}};
    auto memory = lift({ins(Opcode::mips_lw, {v0, word_memory}),
                        ins(Opcode::mips64_lwu, {v1, word_memory}),
                        ins(Opcode::mips64_ld, {a1, double_memory}),
                        ins(Opcode::mips64_sd, {a1, double_memory})});
    const auto memory_text = format_pseudocode(memory);
    require(memory_text.find("r2 = sext(*[(r4 - 8)])") != std::string::npos,
            "LW sign-extends the loaded word to 64 bits");
    require(memory_text.find("r3 = zext(*[(r4 - 8)])") != std::string::npos,
            "LWU zero-extends the loaded word to 64 bits");
    require(memory_text.find("r5 = *[(r4 + 0x10)]") != std::string::npos &&
                memory_text.find("*[(r4 + 0x10)] = r5") != std::string::npos,
            "LD and SD retain 64-bit memory effects");

    auto branch = ins(Opcode::mips_beq, {at, v0, RelativeOperand{16, 16, 64, {}}});
    branch.flow = FlowKind::conditional_branch;
    branch.direct_target = Address{{0}, 0x1020};
    auto branch_lifted = lift({branch});
    const auto branch_text = format_pseudocode(branch_lifted);
    require(branch_text.find("goto loc_1020") != std::string::npos && branch_text.find("==") != std::string::npos,
            "MIPS64 BEQ lowers a 64-bit register predicate and target");

    auto return_ins = ins(Opcode::mips_jr, {RegisterOperand{RegisterBank::mips_gpr, 31, 64, false}});
    return_ins.flow = FlowKind::ret;
    require(format_pseudocode(lift({return_ins})).find("return r31;") != std::string::npos,
            "MIPS64 JR ra retains its return target register");

    auto conditional_store = ins(Opcode::mips64_scd, {v0, double_memory});
    conditional_store.memory_write = true;
    conditional_store.register_writes = {v0};
    auto scd_lifted = lift({conditional_store});
    const auto *scd = std::get_if<Intrinsic>(&scd_lifted.blocks[0].instructions[0].statement);
    require(scd && scd->memory_effect == IntrinsicMemoryEffect::write && scd->register_writes == std::vector<RegisterOperand>{v0},
            "SCD retains memory and success-result register effects as an intrinsic");

    const auto add_d = decode_word((0x11u << 26) | (17u << 21) | (3u << 16) | (4u << 11) | (5u << 6));
    const auto add_lifted = lift({add_d});
    const auto *add_effect = std::get_if<Intrinsic>(&add_lifted.blocks[0].instructions[0].statement);
    require(add_effect && add_effect->name == "mips.add.d" &&
                add_effect->result_type == ValueType{TypeKind::floating, 64, false} &&
                add_effect->operands.size() == 3 &&
                add_effect->operands[1]->type == ValueType{TypeKind::floating, 64, false} &&
                add_effect->register_writes.size() == 2 &&
                add_effect->register_writes.back().bank == RegisterBank::mips_fcsr,
            "MIPS64 ADD.D retains typed floating operands, result, and FCSR effects");

    const auto cvt_l_d = decode_word((0x11u << 26) | (17u << 21) | (4u << 11) | (5u << 6) | 0x25u);
    const auto cvt_l_lifted = lift({cvt_l_d});
    const auto *cvt_l_effect = std::get_if<Intrinsic>(&cvt_l_lifted.blocks[0].instructions[0].statement);
    require(cvt_l_effect && cvt_l_effect->name == "mips64.cvt.l.d" &&
                cvt_l_effect->result_type == ValueType{TypeKind::integer, 64, false} &&
                cvt_l_effect->operands.size() == 2 && cvt_l_effect->operands[1]->type == ValueType{TypeKind::floating, 64, false} &&
                cvt_l_effect->register_writes.size() == 2 && cvt_l_effect->register_writes.back().bank == RegisterBank::mips_fcsr,
            "MIPS64 CVT.L.D lifts as a typed integer conversion with FCSR effects");
    const auto cvt_s_w = decode_word((0x11u << 26) | (20u << 21) | (4u << 11) | (5u << 6) | 0x20u);
    const auto cvt_s_w_lifted = lift({cvt_s_w});
    const auto *cvt_s_w_effect = std::get_if<Intrinsic>(&cvt_s_w_lifted.blocks[0].instructions[0].statement);
    require(cvt_s_w_effect && cvt_s_w_effect->name == "mips.cvt.s.w" &&
                cvt_s_w_effect->result_type == ValueType{TypeKind::floating, 32, false} &&
                cvt_s_w_effect->operands[1]->type == ValueType{TypeKind::integer, 32, false},
            "MIPS64 CVT.S.W uses an integer source and floating result type");
    const auto mfc1 = decode_word((0x11u << 26) | (8u << 16) | (9u << 11));
    const auto mfc1_lifted = lift({mfc1});
    const auto *mfc1_effect = std::get_if<Intrinsic>(&mfc1_lifted.blocks[0].instructions[0].statement);
    require(mfc1_effect && mfc1_effect->name == "mips64.mfc1.sext32" && mfc1_effect->operands.size() == 2 &&
                mfc1_effect->operands[0]->type == ValueType{TypeKind::integer, 64, false} &&
                mfc1_effect->register_writes == std::vector<RegisterOperand>{{RegisterBank::mips_gpr, 8, 64, false}},
            "MIPS64 MFC1 lifting names sign extension and retains its 64-bit GPR effect");

    const auto compare = decode_word((0x11u << 26) | (16u << 21) | (6u << 16) | (7u << 11) | 0x3cu);
    const auto compare_lifted = lift({compare});
    const auto *compare_effect = std::get_if<Intrinsic>(&compare_lifted.blocks[0].instructions[0].statement);
    require(compare_effect && compare_effect->name == "mips.c.lt.s" && !compare_effect->result_type &&
                compare_effect->operands.size() == 2 &&
                compare_effect->operands[0]->type == ValueType{TypeKind::floating, 32, false} &&
                compare_effect->register_writes == std::vector<RegisterOperand>{{RegisterBank::mips_fcsr, 0, 32, false}},
            "MIPS64 C.LT.S updates FCC0 through typed FCSR effects");

    const auto ldc1 = decode_word((0x35u << 26) | (29u << 21) | (8u << 16) | 0xfff0u);
    const auto ldc1_lifted = lift({ldc1});
    const auto *ldc1_assign = std::get_if<Assign>(&ldc1_lifted.blocks[0].instructions[0].statement);
    const auto *ldc1_memory = ldc1_assign ? std::get_if<MemoryValue>(&ldc1_assign->value->value) : nullptr;
    require(ldc1_assign && ldc1_assign->value->type == ValueType{TypeKind::floating, 64, false} &&
                ldc1_memory && ldc1_memory->type == ValueType{TypeKind::floating, 64, false} &&
                ldc1_memory->base == RegisterOperand{RegisterBank::mips_gpr, 29, 64, false},
            "MIPS64 LDC1 lifts as a 64-bit floating memory load using a 64-bit address");

    const auto bc1t = decode_word((0x11u << 26) | (8u << 21) | (1u << 16) | 2u);
    const auto bc1_lifted = lift({bc1t});
    const auto *fp_branch = std::get_if<Branch>(&bc1_lifted.blocks[0].instructions[0].statement);
    require(fp_branch && fp_branch->condition == "mips-fcc0" && fp_branch->true_target == Address{{0}, 0x100c} &&
                format_pseudocode(bc1_lifted).find("mips.fcc0") != std::string::npos,
            "MIPS64 BC1T lifts the FCC0 predicate and branch target");
    (void)zero;
    std::cout << "MIPS64 lifting coverage passed\n";
}
