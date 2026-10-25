#include "hexlab/decompiler/decompiler.hpp"
#include "hexlab/processors/decoder.hpp"

#include <cstdlib>
#include <array>
#include <cstdint>
#include <iostream>

using namespace hexlab;
using namespace hexlab::decompiler;

namespace {
void require(bool condition, const char *message) {
    if (!condition) {
        std::cerr << message << '\n';
        std::exit(1);
    }
}

Instruction instruction(Address at, Opcode opcode, std::vector<Operand> operands = {}) {
    Instruction result;
    result.address = at;
    result.context = {Architecture::arm64, ExecutionMode::a64, ByteOrder::little};
    result.opcode = opcode;
    result.operands = std::move(operands);
    return result;
}

std::shared_ptr<BasicBlock> block(Address entry, std::vector<Instruction> instructions) {
    auto result = std::make_shared<BasicBlock>();
    result->id = BlockId{1};
    result->begin = entry;
    for (std::size_t n = 0; n < instructions.size(); ++n)
        result->instructions.push_back(std::make_shared<InstructionFact>(
            InstructionFact{static_cast<std::uint64_t>(n + 1), std::move(instructions[n]), {}}));
    return result;
}

LiftedFunction lift(std::shared_ptr<BasicBlock> source) {
    FunctionRecord record;
    record.id = FunctionId{1};
    record.entry = source->begin;
    record.blocks = {source->id};
    FunctionSnapshot snapshot;
    snapshot.blocks = {source};
    auto result = lift_function(record, snapshot);
    require(bool(result), "valid A64 function should lift");
    return std::move(result).value();
}

Instruction decoded(std::uint32_t word) {
    const std::array bytes{std::byte(word), std::byte(word >> 8), std::byte(word >> 16), std::byte(word >> 24)};
    auto result = decode_instruction({Architecture::arm64, ExecutionMode::a64, ByteOrder::little}, bytes,
                                     Address{{0}, 0x1000});
    require(result.status == DecodeStatus::decoded && result.instruction.has_value(),
            "A64 bitfield fixture decodes before lifting");
    return *result.instruction;
}
}

int main() {
    const Address entry{{0}, 0x1000};
    const RegisterOperand x0{RegisterBank::arm64_gpr, 0, 64, false};
    const RegisterOperand x1{RegisterBank::arm64_gpr, 1, 64, false};
    const RegisterOperand x2{RegisterBank::arm64_gpr, 2, 64, false};
    const RegisterOperand xzr{RegisterBank::arm64_zero, 31, 64, false};
    const auto ubfx = decoded(0xd3483c20);
    const auto ubfx_text = format_pseudocode(lift(block(entry, {ubfx})));
    require(ubfx_text.find("(x1 >> 0x8)") != std::string::npos &&
                ubfx_text.find("& 0xff") != std::string::npos,
            "decoded UBFM/UBFX lifts to a masked logical extraction");
    const auto lsl = decoded(0xd378dc20);
    const auto lsl_text = format_pseudocode(lift(block(entry, {lsl})));
    require(lsl_text.find("<< 0x8") != std::string::npos && lsl_text.find("0xffffffffffffff") != std::string::npos,
            "decoded UBFM/LSL wraps the source bits and applies the encoded destination mask");
    const auto lsr = decoded(0xd348fc20);
    require(format_pseudocode(lift(block(entry, {lsr}))).find("(x1 >> 0x8)") != std::string::npos,
            "decoded UBFM/LSR shifts right and does not rotate the register");
    const auto asr = decoded(0x9344fc62);
    require(asr.opcode == Opcode::a64_sbfm &&
                format_pseudocode(lift(block(entry, {asr}))).find("x2 = (x3 >> 0x4)") != std::string::npos,
            "decoded SBFM/ASR uses sign-preserving right shift");
    const auto sbfx = decoded(0x93442c62);
    const auto sbfx_text = format_pseudocode(lift(block(entry, {sbfx})));
    require(sbfx_text.find(" >> ") != std::string::npos && sbfx_text.find("0xff") != std::string::npos,
            "decoded SBFM/SBFX sign-extends the selected bitfield");
    const auto indexed_load = decoded(0xf8627820); // ldr x0, [x1, x2, lsl #3]
    require(indexed_load.opcode == Opcode::a64_ldr && indexed_load.operands.size() == 2,
            "A64 register-offset load decodes as a typed load");
    const auto *indexed_address = std::get_if<MemoryOperand>(&indexed_load.operands[1]);
    require(indexed_address && indexed_address->base == RegisterOperand{RegisterBank::arm64_gpr, 1, 64, false} &&
                indexed_address->index == RegisterOperand{RegisterBank::arm64_gpr, 2, 64, false} &&
                indexed_address->index_shift_amount == 3,
            "A64 register-offset address preserves base, index, and element-size shift");
    const auto indexed_text = format_pseudocode(lift(block(entry, {indexed_load})));
    require(indexed_text.find("x0 = *[(x1 + (x2 << 3))];") != std::string::npos,
            "decoded scaled register-offset load lifts to the correct indexed memory expression");
    const auto indexed_ssa = to_ssa(lift(block(entry, {indexed_load})));
    require(indexed_ssa && format_pseudocode(indexed_ssa.value()).find("x0_1 = *[(x1_0 + (x2_0 << 3))];") != std::string::npos,
            "A64 indexed load base and index retain their incoming SSA versions");
    const auto indexed_store = decoded(0xf822d820); // str x0, [x1, w2, sxtw #3]
    const auto *signed_index = indexed_store.operands.size() == 2
        ? std::get_if<MemoryOperand>(&indexed_store.operands[1]) : nullptr;
    require(indexed_store.opcode == Opcode::a64_str && signed_index && signed_index->index_extend == "sxtw" &&
                signed_index->index_shift_amount == 3,
            "A64 register-offset store preserves signed word-index extension");
    const auto signed_store_text = format_pseudocode(lift(block(entry, {indexed_store})));
    require(signed_store_text.find("*[(x1 + (sxtw(w2) << 3))] = x0;") != std::string::npos,
            "signed extended A64 index remains explicit in lifted store address");
    const auto ubfiz = decoded(0xd37c0c20);
    const auto ubfiz_text = format_pseudocode(lift(block(entry, {ubfiz})));
    require(ubfiz_text.find("<< 0x4") != std::string::npos && ubfiz_text.find("0xf") != std::string::npos,
            "decoded non-alias UBFM inserts a low source field at the encoded destination bit");
    const auto ubfx_ssa = to_ssa(lift(block(entry, {ubfx})));
    require(ubfx_ssa && format_pseudocode(ubfx_ssa.value()).find("x0_1") != std::string::npos,
            "A64 bitfield destination participates in register SSA");
    auto and_mask = instruction(entry, Opcode::a64_and,
        {x0, x1, ImmediateOperand{0xff, 13, 64, false, {}}});
    require(format_pseudocode(lift(block(entry, {and_mask}))).find("x0 = (x1 & 0xff);") != std::string::npos,
            "A64 logical immediate expands and lifts as a width-typed bitwise expression");
    auto or_mask = instruction(entry, Opcode::a64_orr,
        {x0, xzr, ImmediateOperand{0xff00ff00ff00ff00ULL, 13, 64, false, {}}});
    require(format_pseudocode(lift(block(entry, {or_mask}))).find("x0 = (0x0 | 0xff00ff00ff00ff00);") != std::string::npos,
            "A64 ORR logical immediate retains its zero source and repeated mask");

    auto add = instruction(entry, Opcode::a64_add, {x0, x1, x2});
    const auto add_lifted = lift(block(entry, {add}));
    const auto &sum = std::get<Assign>(add_lifted.blocks[0].instructions[0].statement);
    require(std::get<RegisterValue>(std::get<BinaryValue>(sum.value->value).left->value).reg == x1,
            "A64 ADD reads its encoded first source, not the destination");
    require(format_pseudocode(add_lifted).find("x0 = (x1 + x2);") != std::string::npos,
            "A64 three-register ADD renders its true source operands");
    const auto add_ssa = to_ssa(add_lifted);
    require(add_ssa && format_pseudocode(add_ssa.value()).find("x0_1 = (x1_0 + x2_0);") != std::string::npos,
            "A64 ADD source and destination versions survive SSA");
    auto sub = instruction(entry, Opcode::a64_sub, {x0, x1, x2});
    require(format_pseudocode(lift(block(entry, {sub}))).find("x0 = (x1 - x2);") != std::string::npos,
            "A64 SUB uses the encoded Rn minus Rm order");
    auto shifted_add = instruction(entry, Opcode::a64_add,
        {x0, x1, x2, ImmediateOperand{3, 6, 64, false, {}}});
    require(format_pseudocode(lift(block(entry, {shifted_add}))).find("x0 = (x1 + (x2 << 0x3));") != std::string::npos,
            "A64 shifted-register ADD includes its encoded LSL amount");

    auto movz = instruction(entry, Opcode::a64_movz,
        {x0, ImmediateOperand{0x1234, 16, 64, false, {}}, ImmediateOperand{16, 2, 8, false, {}}});
    const auto movz_text = format_pseudocode(lift(block(entry, {movz})));
    require(movz_text.find("x0 = 0x12340000;") != std::string::npos,
            "A64 MOVZ inserts its immediate at the encoded halfword");
    auto movn = instruction(entry, Opcode::a64_movn,
        {x0, ImmediateOperand{0, 16, 64, false, {}}, ImmediateOperand{0, 2, 8, false, {}}});
    require(format_pseudocode(lift(block(entry, {movn}))).find("x0 = ~(0x0);") != std::string::npos,
            "A64 MOVN complements the shifted immediate");
    auto movk = instruction(entry, Opcode::a64_movk,
        {x0, ImmediateOperand{0xabcd, 16, 64, false, {}}, ImmediateOperand{32, 2, 8, false, {}}});
    const auto movk_text = format_pseudocode(lift(block(entry, {movk})));
    require(movk_text.find("x0 = ((x0 & 0xffff0000ffffffff) | 0xabcd00000000);") != std::string::npos,
            "A64 MOVK preserves other destination halfwords and replaces the selected one");

    auto cmp = instruction(Address{{0}, 0x1000}, Opcode::a64_subs,
        {xzr, x1, ImmediateOperand{5, 12, 64, false, {}}});
    cmp.register_writes = {{RegisterBank::arm_flags, 0, 4, false}};
    auto beq = instruction(Address{{0}, 0x1004}, Opcode::a64_b_cond);
    beq.flow = FlowKind::conditional_branch;
    beq.condition = 0;
    beq.direct_target = Address{{0}, 0x1020};
    auto compare_block = block(entry, {cmp, beq});
    compare_block->successors = {{entry, Address{{0}, 0x1020}, BlockId{2}, BlockEdgeKind::conditional_true},
                                 {entry, Address{{0}, 0x1008}, BlockId{3}, BlockEdgeKind::conditional_false}};
    auto compare_lifted = lift(compare_block);
    require(format_pseudocode(compare_lifted).find("if ((x1 == 0x5))") != std::string::npos,
            "A64 CMP alias followed by B.EQ lifts an equality predicate");
    auto compare_ssa = to_ssa(compare_lifted);
    require(compare_ssa && format_pseudocode(compare_ssa.value()).find("if ((x1_0 == 0x5))") != std::string::npos,
            "A64 branch predicate carries source versions through SSA");

    const std::vector<std::pair<std::uint8_t, std::string>> conditions{
        {std::uint8_t{2}, "UGE"}, {std::uint8_t{3}, "ULT"},
        {std::uint8_t{8}, "UGT"}, {std::uint8_t{9}, "ULE"},
        {std::uint8_t{10}, "SGE"}, {std::uint8_t{11}, "SLT"},
        {std::uint8_t{12}, "SGT"}, {std::uint8_t{13}, "SLE"}};
    for (const auto &[condition, operation] : conditions) {
        auto relation_branch = beq;
        relation_branch.condition = condition;
        auto relation_block = block(entry, {cmp, relation_branch});
        relation_block->successors = compare_block->successors;
        require(format_pseudocode(lift(relation_block)).find(operation) != std::string::npos,
                "A64 B.cond maps its signed or unsigned condition precisely");
    }
    auto always_branch = beq;
    always_branch.condition = 14;
    always_branch.flow = FlowKind::jump;
    require(format_pseudocode(lift(block(entry, {always_branch}))).find("if (") == std::string::npos,
            "A64 B.AL is represented as an unconditional transfer");

    auto cbz = instruction(entry, Opcode::a64_cbz, {x1});
    cbz.flow = FlowKind::conditional_branch;
    cbz.direct_target = Address{{0}, 0x1020};
    auto zero_test = lift(block(entry, {cbz}));
    require(format_pseudocode(zero_test).find("if ((x1 == 0x0))") != std::string::npos,
            "A64 CBZ uses a typed zero comparison instead of a numeric condition placeholder");

    auto xzr_add = instruction(entry, Opcode::a64_add, {xzr, x1, x2});
    require(format_pseudocode(lift(block(entry, {xzr_add}))).find("xzr =") == std::string::npos,
            "writes to A64 XZR are discarded");
}
