#include "hexlab/decompiler/decompiler.hpp"

#include <array>
#include <cstdlib>
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

std::optional<RegisterValue> find_register_value(const ExpressionPtr &expression, RegisterOperand wanted) {
    if (!expression) return {};
    return std::visit([&](const auto &value) -> std::optional<RegisterValue> {
        using T = std::decay_t<decltype(value)>;
        if constexpr (std::is_same_v<T, RegisterValue>) {
            if (value.reg.bank == wanted.bank && value.reg.index == wanted.index) return value;
        } else if constexpr (std::is_same_v<T, UnaryValue>) {
            return find_register_value(value.operand, wanted);
        } else if constexpr (std::is_same_v<T, BinaryValue>) {
            if (auto left = find_register_value(value.left, wanted)) return left;
            return find_register_value(value.right, wanted);
        }
        return {};
    }, expression->value);
}

std::shared_ptr<const BasicBlock> sample_block() {
    const Address entry{{0}, 0x1000};
    RegisterOperand rax{RegisterBank::gpr, 0, 64, false};
    Instruction add;
    add.address = entry;
    add.opcode = Opcode::add;
    add.operands = {rax, ImmediateOperand{2, 8, 64, false, {}}};
    Instruction ret;
    ret.address = Address{{0}, 0x1004};
    ret.opcode = Opcode::ret;
    ret.flow = FlowKind::ret;
    auto block = std::make_shared<BasicBlock>();
    block->id = BlockId{7};
    block->begin = entry;
    block->instructions.push_back(std::make_shared<InstructionFact>(InstructionFact{11, add, {}}));
    block->instructions.push_back(std::make_shared<InstructionFact>(InstructionFact{12, ret, {}}));
    return block;
}
} // namespace

int main() {
    FunctionRecord record;
    record.id = FunctionId{3};
    record.entry = Address{{0}, 0x1000};
    record.blocks = {BlockId{7}};
    FunctionSnapshot snapshot;
    snapshot.blocks.push_back(sample_block());

    auto lifted = lift_function(record, snapshot);
    require(lifted.has_value(), "valid analysis function should lift");
    require(lifted.value().blocks.size() == 1, "lift preserves a single basic block");
    require(lifted.value().blocks[0].instructions.size() == 2, "lift preserves instruction origins");
    const auto &assignment = std::get<Assign>(lifted.value().blocks[0].instructions[0].statement);
    require(assignment.value->type == ValueType{TypeKind::integer, 64, false}, "register width propagates to IR type");
    const auto rendered = format_pseudocode(lifted.value());
    require(rendered == format_pseudocode(lifted.value()), "pseudocode output is deterministic");
    if (rendered.find("r0 = (r0 + 0x2);") == std::string::npos)
        std::cerr << rendered;
    require(rendered.find("r0 = (r0 + 0x2);") != std::string::npos, "integer add is rendered as an assignment");
    require(rendered.find("return;") != std::string::npos, "return instruction is represented");

    // Native MIPS32 integer operations should retain their architectural
    // register operands and branch predicates in the typed IR.
    const RegisterOperand mips_r1{RegisterBank::mips_gpr, 1, 32, false};
    const RegisterOperand mips_r2{RegisterBank::mips_gpr, 2, 32, false};
    const RegisterOperand mips_r3{RegisterBank::mips_gpr, 3, 32, false};
    const RegisterOperand mips_zero{RegisterBank::mips_gpr, 0, 32, false};
    Instruction mips_add;
    mips_add.address = Address{{0}, 0x3000};
    mips_add.context = {Architecture::mips32, ExecutionMode::mips32, ByteOrder::little};
    mips_add.opcode = Opcode::mips_addu;
    mips_add.operands = {mips_r3, mips_r1, mips_r2};
    auto mips_block = std::make_shared<BasicBlock>();
    mips_block->id = BlockId{300};
    mips_block->begin = mips_add.address;
    mips_block->instructions.push_back(std::make_shared<InstructionFact>(InstructionFact{300, mips_add, {}}));
    auto mips_record = record;
    mips_record.entry = mips_add.address;
    mips_record.blocks = {mips_block->id};
    FunctionSnapshot mips_snapshot;
    mips_snapshot.blocks = {mips_block};
    const auto mips_lifted = lift_function(mips_record, mips_snapshot);
    require(mips_lifted && std::holds_alternative<Assign>(mips_lifted.value().blocks[0].instructions[0].statement),
            "MIPS32 ADDU lifts to a typed register assignment");
    if (mips_lifted && std::holds_alternative<Assign>(mips_lifted.value().blocks[0].instructions[0].statement)) {
        const auto &mips_assignment = std::get<Assign>(mips_lifted.value().blocks[0].instructions[0].statement);
        require(mips_assignment.destination == mips_r3 && mips_assignment.value->type == ValueType{TypeKind::integer, 32, false},
                "MIPS32 arithmetic preserves its 32-bit destination type");
        require(std::holds_alternative<BinaryValue>(mips_assignment.value->value) &&
                    std::get<BinaryValue>(mips_assignment.value->value).operation == "add",
                "MIPS32 ADDU preserves the source operation");
    }
    Instruction mips_beq;
    mips_beq.address = Address{{0}, 0x3004};
    mips_beq.context = mips_add.context;
    mips_beq.opcode = Opcode::mips_beq;
    mips_beq.flow = FlowKind::conditional_branch;
    mips_beq.operands = {mips_r1, mips_zero};
    mips_beq.direct_target = Address{{0}, 0x3010};
    mips_block->instructions.push_back(std::make_shared<InstructionFact>(InstructionFact{301, mips_beq, {}}));
    const auto mips_branch_lifted = lift_function(mips_record, mips_snapshot);
    require(mips_branch_lifted && std::holds_alternative<Branch>(mips_branch_lifted.value().blocks[0].instructions[1].statement),
            "MIPS32 BEQ lifts to a branch statement");
    if (mips_branch_lifted && std::holds_alternative<Branch>(mips_branch_lifted.value().blocks[0].instructions[1].statement)) {
        const auto &branch = std::get<Branch>(mips_branch_lifted.value().blocks[0].instructions[1].statement);
        require(branch.predicate && std::holds_alternative<BinaryValue>(branch.predicate->value) &&
                    std::get<BinaryValue>(branch.predicate->value).operation == "eq",
                "MIPS32 BEQ retains its equality predicate instead of an opaque condition");
        const auto &predicate = std::get<BinaryValue>(branch.predicate->value);
        require(predicate.right && std::holds_alternative<ConstantValue>(predicate.right->value) &&
                    std::get<ConstantValue>(predicate.right->value).value == 0,
                "MIPS32 reads from $zero become the architectural zero constant");
    }
    Instruction mips_add_trapping = mips_add;
    mips_add_trapping.address = Address{{0}, 0x3008};
    mips_add_trapping.opcode = Opcode::mips_add;
    mips_block->instructions = {
        std::make_shared<InstructionFact>(InstructionFact{302, mips_add_trapping, {}})};
    const auto mips_trap_lifted = lift_function(mips_record, mips_snapshot);
    require(mips_trap_lifted && std::holds_alternative<Intrinsic>(
                mips_trap_lifted.value().blocks[0].instructions[0].statement),
            "MIPS32 trapping ADD stays explicit until overflow exception semantics are modeled");
    Instruction mips_eret = mips_add;
    mips_eret.address = Address{{0}, 0x300c};
    mips_eret.opcode = Opcode::mips_eret;
    mips_eret.flow = FlowKind::ret;
    mips_block->instructions = {std::make_shared<InstructionFact>(InstructionFact{303, mips_eret, {}})};
    const auto mips_eret_lifted = lift_function(mips_record, mips_snapshot);
    require(mips_eret_lifted && std::holds_alternative<Intrinsic>(
                mips_eret_lifted.value().blocks[0].instructions[0].statement),
            "MIPS32 ERET is not misrepresented as a normal function return");

    // MIPS ordinary loads/stores retain width and signedness in the typed IR.
    MemoryOperand mips_memory{8, 32, {}, mips_r2, {}, 1, 3, false, {}, {}};
    Instruction mips_lb = mips_add;
    mips_lb.address = Address{{0}, 0x3020};
    mips_lb.opcode = Opcode::mips_lb;
    mips_lb.operands = {mips_r3, mips_memory};
    mips_block->instructions = {std::make_shared<InstructionFact>(InstructionFact{304, mips_lb, {}})};
    auto mips_memory_lifted = lift_function(mips_record, mips_snapshot);
    require(mips_memory_lifted && std::holds_alternative<Assign>(
                mips_memory_lifted.value().blocks[0].instructions[0].statement),
            "MIPS32 LB lifts to a register assignment");
    if (mips_memory_lifted && std::holds_alternative<Assign>(mips_memory_lifted.value().blocks[0].instructions[0].statement)) {
        const auto &load = std::get<Assign>(mips_memory_lifted.value().blocks[0].instructions[0].statement);
        require(load.value->type == ValueType{TypeKind::integer, 32, false} &&
                    std::holds_alternative<UnaryValue>(load.value->value) &&
                    std::get<UnaryValue>(load.value->value).operation == "sext" &&
                    std::get<UnaryValue>(load.value->value).operand->type.bits == 8,
                "MIPS32 LB sign-extends its 8-bit memory value to the 32-bit register");
    }
    Instruction mips_lbu = mips_lb;
    mips_lbu.opcode = Opcode::mips_lbu;
    mips_block->instructions = {std::make_shared<InstructionFact>(InstructionFact{305, mips_lbu, {}})};
    mips_memory_lifted = lift_function(mips_record, mips_snapshot);
    require(mips_memory_lifted && std::holds_alternative<Assign>(
                mips_memory_lifted.value().blocks[0].instructions[0].statement) &&
                std::holds_alternative<UnaryValue>(std::get<Assign>(
                    mips_memory_lifted.value().blocks[0].instructions[0].statement).value->value) &&
                std::get<UnaryValue>(std::get<Assign>(
                    mips_memory_lifted.value().blocks[0].instructions[0].statement).value->value).operation == "zext",
            "MIPS32 LBU zero-extends its memory value");
    Instruction mips_sw = mips_add;
    mips_sw.address = Address{{0}, 0x3024};
    mips_sw.opcode = Opcode::mips_sw;
    mips_sw.operands = {mips_r3, MemoryOperand{32, 32, {}, mips_r2, {}, 1, 4, false, {}, {}}};
    mips_block->instructions = {std::make_shared<InstructionFact>(InstructionFact{306, mips_sw, {}})};
    mips_memory_lifted = lift_function(mips_record, mips_snapshot);
    require(mips_memory_lifted && std::holds_alternative<Store>(
                mips_memory_lifted.value().blocks[0].instructions[0].statement),
            "MIPS32 SW lifts to a typed memory store");

    const RegisterOperand mips_hi{RegisterBank::mips_hilo, 0, 32, false};
    const RegisterOperand mips_lo{RegisterBank::mips_hilo, 1, 32, false};
    const auto special = [&](Opcode opcode, std::uint64_t id, std::vector<Operand> operands,
                             std::vector<RegisterOperand> reads = {}, std::vector<RegisterOperand> writes = {}) {
        Instruction instruction;
        instruction.address = Address{{0}, 0x3050 + (id - 350) * 4};
        instruction.context = mips_add.context;
        instruction.opcode = opcode;
        instruction.operands = std::move(operands);
        instruction.register_reads = std::move(reads);
        instruction.register_writes = std::move(writes);
        return std::make_shared<InstructionFact>(InstructionFact{id, std::move(instruction), {}});
    };
    const auto hilo_fixture = [&](Opcode opcode) {
        auto fact = special(opcode, 350, {mips_r1, mips_r2}, {mips_r1, mips_r2}, {mips_hi, mips_lo});
        auto block = std::make_shared<BasicBlock>();
        block->id = BlockId{350}; block->begin = fact->instruction.address; block->instructions = {fact};
        auto fn = mips_record; fn.entry = block->begin; fn.blocks = {block->id};
        FunctionSnapshot facts; facts.blocks = {block};
        return lift_function(fn, facts);
    };
    for (const auto &[opcode, name] : std::array<std::pair<Opcode, const char *>, 4>{
             {{Opcode::mips_mult, "mips.mult.s32"}, {Opcode::mips_multu, "mips.mult.u32"},
              {Opcode::mips_div, "mips.div.s32"}, {Opcode::mips_divu, "mips.div.u32"}}}) {
        const auto operation = hilo_fixture(opcode);
        require(operation && std::holds_alternative<Intrinsic>(operation.value().blocks[0].instructions[0].statement),
                "MIPS32 HI/LO arithmetic remains an explicit side effect");
        if (operation && std::holds_alternative<Intrinsic>(operation.value().blocks[0].instructions[0].statement)) {
            const auto &effect = std::get<Intrinsic>(operation.value().blocks[0].instructions[0].statement);
            require(effect.name == name && effect.register_writes == std::vector<RegisterOperand>{mips_hi, mips_lo} &&
                        effect.operands.size() == 2 && effect.operands[0]->type.bits == 32 &&
                        effect.operands[0]->type.is_signed == (opcode == Opcode::mips_mult || opcode == Opcode::mips_div),
                    "MIPS32 MULT/DIV preserves signedness and defines both special-register outputs");
        }
    }
    auto hi_read = special(Opcode::mips_mfhi, 351, {mips_r3}, {mips_hi}, {mips_r3});
    auto lo_read = special(Opcode::mips_mflo, 352, {mips_r2}, {mips_lo}, {mips_r2});
    auto hi_write = special(Opcode::mips_mthi, 353, {mips_r1}, {mips_r1}, {mips_hi});
    auto lo_write = special(Opcode::mips_mtlo, 354, {mips_r2}, {mips_r2}, {mips_lo});
    auto hilo_block = std::make_shared<BasicBlock>();
    hilo_block->id = BlockId{351}; hilo_block->begin = hi_read->instruction.address;
    hilo_block->instructions = {special(Opcode::mips_mult, 350, {mips_r1, mips_r2}, {mips_r1, mips_r2}, {mips_hi, mips_lo}),
                                hi_read, special(Opcode::mips_divu, 355, {mips_r1, mips_r2}, {mips_r1, mips_r2}, {mips_hi, mips_lo}),
                                lo_read, hi_write, lo_write};
    auto hilo_record = mips_record; hilo_record.entry = hilo_block->begin; hilo_record.blocks = {hilo_block->id};
    FunctionSnapshot hilo_snapshot; hilo_snapshot.blocks = {hilo_block};
    const auto hilo_lifted = lift_function(hilo_record, hilo_snapshot);
    require(hilo_lifted && std::holds_alternative<Assign>(hilo_lifted.value().blocks[0].instructions[1].statement) &&
                std::get<Assign>(hilo_lifted.value().blocks[0].instructions[1].statement).value->type.bits == 32 &&
                std::holds_alternative<Assign>(hilo_lifted.value().blocks[0].instructions[4].statement) &&
                std::get<Assign>(hilo_lifted.value().blocks[0].instructions[4].statement).destination == mips_hi &&
                std::holds_alternative<Assign>(hilo_lifted.value().blocks[0].instructions[5].statement) &&
                std::get<Assign>(hilo_lifted.value().blocks[0].instructions[5].statement).destination == mips_lo,
            "MIPS32 MFHI/MFLO read typed special registers and MTHI/MTLO write them");
    const auto hilo_ssa = hilo_lifted ? to_ssa(hilo_lifted.value())
        : Result<LiftedFunction>(Error{ErrorCode::invalid_argument, "HI/LO lift failed"});
    require(hilo_ssa && std::get<Intrinsic>(hilo_ssa.value().blocks[0].instructions[0].statement).register_output_versions ==
                std::vector<std::uint32_t>{1, 1} &&
                std::get<RegisterValue>(std::get<Assign>(hilo_ssa.value().blocks[0].instructions[1].statement).value->value).version == std::optional<std::uint32_t>{1} &&
                std::get<Intrinsic>(hilo_ssa.value().blocks[0].instructions[2].statement).register_output_versions ==
                std::vector<std::uint32_t>{2, 2} &&
                std::get<RegisterValue>(std::get<Assign>(hilo_ssa.value().blocks[0].instructions[3].statement).value->value).version == std::optional<std::uint32_t>{2} &&
                std::get<Assign>(hilo_ssa.value().blocks[0].instructions[4].statement).destination_version == std::optional<std::uint32_t>{3} &&
                std::get<Assign>(hilo_ssa.value().blocks[0].instructions[5].statement).destination_version == std::optional<std::uint32_t>{3},
            "MIPS HI/LO special-register dependencies flow through SSA versions in instruction order");
    require(hilo_ssa && format_pseudocode(hilo_ssa.value()).find("writes HI_1, LO_1") != std::string::npos &&
                format_pseudocode(hilo_ssa.value()).find("HI_3 = r1_0") != std::string::npos &&
                format_pseudocode(hilo_ssa.value()).find("LO_3 = r2_1") != std::string::npos,
            "MIPS HI/LO special-register names and SSA versions remain legible in pseudocode");

    // Analysis exposes the delay slot as a dedicated edge. The slot executes
    // before the branch/call, while jal's link value is established first.
    auto mips_transfer_block = std::make_shared<BasicBlock>();
    mips_transfer_block->id = BlockId{310};
    mips_transfer_block->begin = Address{{0}, 0x3100};
    auto mips_slot_block = std::make_shared<BasicBlock>();
    mips_slot_block->id = BlockId{311};
    mips_slot_block->begin = Address{{0}, 0x3104};
    mips_transfer_block->successors = {{mips_transfer_block->begin, mips_slot_block->begin, mips_slot_block->id, BlockEdgeKind::delay_slot}};
    mips_slot_block->successors = {{mips_slot_block->begin, Address{{0}, 0x3120}, {}, BlockEdgeKind::conditional_true},
                                   {mips_slot_block->begin, Address{{0}, 0x3108}, {}, BlockEdgeKind::conditional_false}};
    Instruction mips_transfer = mips_add;
    mips_transfer.address = mips_transfer_block->begin;
    mips_transfer.opcode = Opcode::mips_beq;
    mips_transfer.flow = FlowKind::conditional_branch;
    mips_transfer.delay_slots = 1;
    mips_transfer.length = 4;
    mips_transfer.direct_target = Address{{0}, 0x3120};
    mips_transfer.operands = {mips_r1, mips_zero};
    Instruction mips_slot = mips_add;
    mips_slot.address = mips_slot_block->begin;
    mips_slot.opcode = Opcode::mips_addiu;
    mips_slot.length = 4;
    mips_slot.operands = {mips_r1, mips_r1, ImmediateOperand{1, 16, 32, true, {}}};
    mips_transfer_block->instructions = {std::make_shared<InstructionFact>(InstructionFact{310, mips_transfer, {}})};
    mips_slot_block->instructions = {std::make_shared<InstructionFact>(InstructionFact{311, mips_slot, {}})};
    auto mips_flow_record = mips_record;
    mips_flow_record.entry = mips_transfer_block->begin;
    mips_flow_record.blocks = {mips_transfer_block->id, mips_slot_block->id};
    FunctionSnapshot mips_flow_snapshot;
    mips_flow_snapshot.blocks = {mips_transfer_block, mips_slot_block};
    const auto mips_delayed_branch = lift_function(mips_flow_record, mips_flow_snapshot);
    require(mips_delayed_branch && mips_delayed_branch.value().blocks[0].instructions.empty() &&
                mips_delayed_branch.value().blocks[1].instructions.size() == 2 &&
                std::holds_alternative<Assign>(mips_delayed_branch.value().blocks[1].instructions[0].statement) &&
                std::holds_alternative<Branch>(mips_delayed_branch.value().blocks[1].instructions[1].statement) &&
                std::get<Branch>(mips_delayed_branch.value().blocks[1].instructions[1].statement).true_target ==
                    std::optional<Address>{Address{{0}, 0x3120}},
            "MIPS conditional transfer is lifted after its delay-slot side effect");
    const auto mips_delayed_branch_ssa = mips_delayed_branch ? to_ssa(mips_delayed_branch.value())
        : Result<LiftedFunction>{Error{ErrorCode::invalid_argument, "MIPS delay branch lift failed"}};
    require(mips_delayed_branch_ssa &&
                find_register_value(std::get<Branch>(mips_delayed_branch_ssa.value().blocks[1].instructions[1].statement).predicate,
                                    mips_r1)->version == 0 &&
                std::get<Assign>(mips_delayed_branch_ssa.value().blocks[1].instructions[0].statement).destination_version == 1,
            "MIPS branch predicate observes the pre-delay-slot register value");

    mips_transfer_block->successors = {{mips_transfer_block->begin, mips_slot_block->begin, mips_slot_block->id, BlockEdgeKind::delay_slot}};
    mips_slot_block->successors = {{mips_slot_block->begin, Address{{0}, 0x3108}, {}, BlockEdgeKind::call_continuation}};
    mips_transfer.opcode = Opcode::mips_jal;
    mips_transfer.flow = FlowKind::call;
    mips_transfer.direct_target = Address{{0}, 0x3200};
    mips_transfer.operands = {RelativeOperand{0x100, 26, 32, {}}};
    mips_transfer.register_writes = {{RegisterBank::mips_gpr, 31, 32, false}};
    const RegisterOperand mips_ra{RegisterBank::mips_gpr, 31, 32, false};
    mips_slot.operands = {mips_ra, mips_ra, ImmediateOperand{1, 16, 32, true, {}}};
    mips_slot_block->instructions = {std::make_shared<InstructionFact>(InstructionFact{311, mips_slot, {}})};
    mips_transfer_block->instructions = {std::make_shared<InstructionFact>(InstructionFact{312, mips_transfer, {}})};
    const auto mips_delayed_call = lift_function(mips_flow_record, mips_flow_snapshot);
    require(mips_delayed_call && mips_delayed_call.value().blocks[0].instructions.size() == 1 &&
                std::holds_alternative<Assign>(mips_delayed_call.value().blocks[0].instructions[0].statement) &&
                std::get<Assign>(mips_delayed_call.value().blocks[0].instructions[0].statement).destination.index == 31 &&
                std::holds_alternative<ConstantValue>(std::get<Assign>(
                    mips_delayed_call.value().blocks[0].instructions[0].statement).value->value) &&
                std::get<ConstantValue>(std::get<Assign>(
                    mips_delayed_call.value().blocks[0].instructions[0].statement).value->value).value == 0x3108 &&
                std::holds_alternative<Assign>(mips_delayed_call.value().blocks[1].instructions[0].statement) &&
                std::holds_alternative<Call>(mips_delayed_call.value().blocks[1].instructions[1].statement) &&
                std::get<Call>(mips_delayed_call.value().blocks[1].instructions[1].statement).direct_target ==
                    std::optional<Address>{Address{{0}, 0x3200}},
            "MIPS JAL writes its PC+8 link before the delay slot and calls after it");
    const auto mips_delayed_call_ssa = mips_delayed_call ? to_ssa(mips_delayed_call.value())
        : Result<LiftedFunction>{Error{ErrorCode::invalid_argument, "MIPS delay call lift failed"}};
    require(mips_delayed_call_ssa &&
                std::get<Assign>(mips_delayed_call_ssa.value().blocks[0].instructions[0].statement).destination_version == std::optional<std::uint32_t>{1} &&
                std::get<Assign>(mips_delayed_call_ssa.value().blocks[1].instructions[0].statement).destination_version == std::optional<std::uint32_t>{2},
            "MIPS link write precedes a delay-slot write to the same register in SSA");

    mips_transfer.opcode = Opcode::mips_jalr;
    mips_transfer.direct_target.reset();
    mips_transfer.operands = {mips_r1};
    mips_transfer.register_writes = {{RegisterBank::mips_gpr, 5, 32, false}};
    mips_transfer_block->instructions = {std::make_shared<InstructionFact>(InstructionFact{313, mips_transfer, {}})};
    mips_slot.operands = {mips_r1, mips_r1, ImmediateOperand{1, 16, 32, true, {}}};
    mips_slot_block->instructions = {std::make_shared<InstructionFact>(InstructionFact{311, mips_slot, {}})};
    const auto mips_delayed_indirect_call = lift_function(mips_flow_record, mips_flow_snapshot);
    require(mips_delayed_indirect_call &&
                std::get<Assign>(mips_delayed_indirect_call.value().blocks[0].instructions[0].statement).destination.index == 5 &&
                std::get<ConstantValue>(std::get<Assign>(
                    mips_delayed_indirect_call.value().blocks[0].instructions[0].statement).value->value).value == 0x3108 &&
                std::holds_alternative<Assign>(mips_delayed_indirect_call.value().blocks[1].instructions[0].statement) &&
                std::holds_alternative<Call>(mips_delayed_indirect_call.value().blocks[1].instructions[1].statement) &&
                std::get<Call>(mips_delayed_indirect_call.value().blocks[1].instructions[1].statement).indirect_target,
            "MIPS JALR writes its encoded link register and calls the register target after the delay slot");
    const auto mips_delayed_indirect_call_ssa = mips_delayed_indirect_call ? to_ssa(mips_delayed_indirect_call.value())
        : Result<LiftedFunction>{Error{ErrorCode::invalid_argument, "MIPS delay call lift failed"}};
    require(mips_delayed_indirect_call_ssa &&
                find_register_value(std::get<Call>(mips_delayed_indirect_call_ssa.value().blocks[1].instructions[1].statement).indirect_target,
                                    mips_r1)->version == 0 &&
                std::get<Assign>(mips_delayed_indirect_call_ssa.value().blocks[1].instructions[0].statement).destination_version == std::optional<std::uint32_t>{1},
            "MIPS indirect call target is snapshotted before the delay slot");

    mips_transfer.opcode = Opcode::mips_jr;
    mips_transfer.flow = FlowKind::jump;
    mips_transfer.register_writes.clear();
    mips_transfer.operands = {mips_r1};
    mips_transfer_block->instructions = {std::make_shared<InstructionFact>(InstructionFact{314, mips_transfer, {}})};
    const auto mips_delayed_indirect_jump = lift_function(mips_flow_record, mips_flow_snapshot);
    require(mips_delayed_indirect_jump &&
                std::holds_alternative<Branch>(mips_delayed_indirect_jump.value().blocks[1].instructions[1].statement) &&
                std::get<Branch>(mips_delayed_indirect_jump.value().blocks[1].instructions[1].statement).indirect_target,
            "MIPS JR retains its indirect destination in the lifted branch");
    const auto mips_delayed_indirect_jump_ssa = mips_delayed_indirect_jump ? to_ssa(mips_delayed_indirect_jump.value())
        : Result<LiftedFunction>{Error{ErrorCode::invalid_argument, "MIPS delay jump lift failed"}};
    require(mips_delayed_indirect_jump_ssa &&
                find_register_value(std::get<Branch>(mips_delayed_indirect_jump_ssa.value().blocks[1].instructions[1].statement).indirect_target,
                                    mips_r1)->version == 0 &&
                std::get<Assign>(mips_delayed_indirect_jump_ssa.value().blocks[1].instructions[0].statement).destination_version == std::optional<std::uint32_t>{1} &&
                format_pseudocode(mips_delayed_indirect_jump_ssa.value()).find("goto r1_0;") != std::string::npos,
            "MIPS indirect jump target is snapshotted before the delay slot and rendered explicitly");
    const auto mips_indirect_jump_structured = format_structured_pseudocode(mips_delayed_indirect_jump_ssa.value());
    require(mips_indirect_jump_structured.used_fallback &&
                mips_indirect_jump_structured.text.find("goto r1_0;") != std::string::npos,
            "structured output keeps indirect MIPS jumps in the explicit goto form");

    mips_transfer.flow = FlowKind::ret;
    mips_transfer.operands = {mips_ra};
    mips_transfer_block->instructions = {std::make_shared<InstructionFact>(InstructionFact{315, mips_transfer, {}})};
    mips_slot.operands = {mips_ra, mips_ra, ImmediateOperand{1, 16, 32, true, {}}};
    mips_slot_block->instructions = {std::make_shared<InstructionFact>(InstructionFact{311, mips_slot, {}})};
    const auto mips_delayed_return = lift_function(mips_flow_record, mips_flow_snapshot);
    const auto mips_delayed_return_ssa = mips_delayed_return ? to_ssa(mips_delayed_return.value())
        : Result<LiftedFunction>{Error{ErrorCode::invalid_argument, "MIPS delay return lift failed"}};
    require(mips_delayed_return_ssa &&
                find_register_value(std::get<Return>(mips_delayed_return_ssa.value().blocks[1].instructions[1].statement).value,
                                    mips_ra)->version == 0 &&
                std::get<Assign>(mips_delayed_return_ssa.value().blocks[1].instructions[0].statement).destination_version == std::optional<std::uint32_t>{1},
            "MIPS JR return target is snapshotted before a delay-slot overwrite");

    const RegisterOperand memory_base{RegisterBank::gpr, 3, 64, false};
    const RegisterOperand memory_source{RegisterBank::gpr, 2, 32, false};
    MemoryOperand memory_destination;
    memory_destination.data_width = 32;
    memory_destination.address_width = 64;
    memory_destination.base = memory_base;
    memory_destination.displacement = 4;
    Instruction memory_add;
    memory_add.address = Address{{0}, 0x1008};
    memory_add.context.architecture = Architecture::x86_64;
    memory_add.opcode = Opcode::add;
    memory_add.operands = {memory_destination, memory_source};
    auto memory_block = std::make_shared<BasicBlock>();
    memory_block->id = BlockId{70};
    memory_block->begin = memory_add.address;
    memory_block->instructions.push_back(std::make_shared<InstructionFact>(InstructionFact{70, memory_add, {}}));
    auto memory_record = record;
    memory_record.entry = memory_add.address;
    memory_record.blocks = {BlockId{70}};
    FunctionSnapshot memory_snapshot;
    memory_snapshot.blocks = {memory_block};
    const auto memory_lifted = lift_function(memory_record, memory_snapshot);
    require(memory_lifted && std::holds_alternative<Store>(memory_lifted.value().blocks[0].instructions[0].statement),
            "x86 memory-destination arithmetic is represented as a read-modify-write store");
    require(memory_lifted && format_pseudocode(memory_lifted.value()).find(
                "*[(r3 + 0x4)] = (*[(r3 + 0x4)] + r2);") != std::string::npos,
            "memory-destination arithmetic reads and writes the same effective address");
    const auto memory_ssa = memory_lifted ? to_ssa(memory_lifted.value())
        : Result<LiftedFunction>(Error{ErrorCode::invalid_argument, "memory arithmetic lift failed"});
    require(memory_ssa && format_pseudocode(memory_ssa.value()).find(
                "*[(r3_0 + 0x4)] = (*[(r3_0 + 0x4)] + r2_0);") != std::string::npos,
            "memory read-modify-write expressions retain SSA versions for their address and value inputs");

    const RegisterOperand lhs{RegisterBank::gpr, 1, 32, false};
    const RegisterOperand rhs{RegisterBank::gpr, 2, 32, false};
    const Address compare_entry{{0}, 0x1000};
    Instruction compare;
    compare.address = compare_entry;
    compare.context.architecture = Architecture::x86_64;
    compare.opcode = Opcode::cmp;
    compare.operands = {lhs, rhs};
    compare.register_reads = {lhs, rhs};
    compare.register_writes = {{RegisterBank::flags, 0, 64, false}};
    Instruction equal_branch;
    equal_branch.address = Address{{0}, 0x1002};
    equal_branch.opcode = Opcode::jcc;
    equal_branch.flow = FlowKind::conditional_branch;
    equal_branch.x86_condition = X86Condition::equal;
    equal_branch.condition = static_cast<std::uint8_t>(X86Condition::equal);
    equal_branch.direct_target = Address{{0}, 0x1010};
    auto compare_block = std::make_shared<BasicBlock>();
    compare_block->id = BlockId{8};
    compare_block->begin = compare_entry;
    compare_block->instructions.push_back(std::make_shared<InstructionFact>(InstructionFact{13, compare, {}}));
    compare_block->instructions.push_back(std::make_shared<InstructionFact>(InstructionFact{14, equal_branch, {}}));
    compare_block->successors = {{compare_entry, Address{{0}, 0x1010}, BlockId{9}, BlockEdgeKind::conditional_true},
                                 {compare_entry, Address{{0}, 0x1020}, BlockId{10}, BlockEdgeKind::conditional_false}};
    auto compare_record = record;
    compare_record.blocks = {BlockId{8}};
    FunctionSnapshot compare_snapshot;
    compare_snapshot.blocks.push_back(compare_block);
    auto compare_lifted = lift_function(compare_record, compare_snapshot);
    require(compare_lifted && format_pseudocode(compare_lifted.value()).find("if ((r1 == r2))") != std::string::npos,
            "x86 CMP/Jcc lifts the actual equality predicate instead of an opaque condition number");
    auto compare_ssa = compare_lifted ? to_ssa(compare_lifted.value())
                                      : Result<LiftedFunction>(Error{ErrorCode::invalid_argument, "CMP/Jcc lift failed"});
    require(compare_ssa && format_pseudocode(compare_ssa.value()).find("if ((r1_0 == r2_0))") != std::string::npos,
            "x86 branch predicates preserve their register versions through SSA");

    const Address compare_continuation{{0}, 0x1002};
    auto compare_prefix_block = std::make_shared<BasicBlock>();
    compare_prefix_block->id = BlockId{80};
    compare_prefix_block->begin = compare_entry;
    compare_prefix_block->instructions.push_back(std::make_shared<InstructionFact>(InstructionFact{13, compare, {}}));
    compare_prefix_block->successors = {{compare_entry, compare_continuation, BlockId{81}, BlockEdgeKind::jump}};
    Instruction continuation_nop;
    continuation_nop.address = compare_continuation;
    continuation_nop.context.architecture = Architecture::x86_64;
    continuation_nop.opcode = Opcode::nop;
    auto continuation_branch = equal_branch;
    continuation_branch.address = Address{{0}, 0x1003};
    continuation_branch.direct_target = Address{{0}, 0x1010};
    auto compare_continuation_block = std::make_shared<BasicBlock>();
    compare_continuation_block->id = BlockId{81};
    compare_continuation_block->begin = compare_continuation;
    compare_continuation_block->instructions = {
        std::make_shared<InstructionFact>(InstructionFact{15, continuation_nop, {}}),
        std::make_shared<InstructionFact>(InstructionFact{16, continuation_branch, {}})};
    compare_continuation_block->successors = {
        {continuation_branch.address, Address{{0}, 0x1010}, BlockId{82}, BlockEdgeKind::conditional_true},
        {continuation_branch.address, Address{{0}, 0x1020}, BlockId{83}, BlockEdgeKind::conditional_false}};
    auto cross_block_record = compare_record;
    cross_block_record.blocks = {BlockId{80}, BlockId{81}};
    FunctionSnapshot cross_block_snapshot;
    cross_block_snapshot.blocks = {compare_continuation_block, compare_prefix_block};
    const auto cross_block_lifted = lift_function(cross_block_record, cross_block_snapshot);
    require(cross_block_lifted && format_pseudocode(cross_block_lifted.value()).find("if ((r1 == r2))") != std::string::npos,
            "x86 compare flags carry across an unconditional basic-block edge");
    Instruction cross_block_overwrite;
    cross_block_overwrite.address = compare_continuation;
    cross_block_overwrite.context.architecture = Architecture::x86_64;
    cross_block_overwrite.opcode = Opcode::mov;
    cross_block_overwrite.operands = {lhs, ImmediateOperand{7, 8, 32, false, {}}};
    cross_block_overwrite.register_writes = {lhs};
    auto overwritten_continuation = std::make_shared<BasicBlock>(*compare_continuation_block);
    overwritten_continuation->instructions.insert(overwritten_continuation->instructions.begin(),
        std::make_shared<InstructionFact>(InstructionFact{17, cross_block_overwrite, {}}));
    auto overwritten_cross_block = cross_block_snapshot;
    overwritten_cross_block.blocks[0] = overwritten_continuation;
    const auto overwritten_cross_lifted = lift_function(cross_block_record, overwritten_cross_block);
    require(overwritten_cross_lifted &&
                format_pseudocode(overwritten_cross_lifted.value()).find("condition_4") != std::string::npos,
            "cross-block x86 compare state is discarded when an operand is overwritten");

    const Address a64_entry{{0}, 0x2000}, a64_next{{0}, 0x2004}, a64_true{{0}, 0x2010}, a64_false{{0}, 0x2020};
    const RegisterOperand a64_lhs{RegisterBank::arm64_gpr, 1, 64, false};
    const RegisterOperand a64_rhs{RegisterBank::arm64_gpr, 2, 64, false};
    Instruction a64_subs;
    a64_subs.address = a64_entry;
    a64_subs.context.architecture = Architecture::arm64;
    a64_subs.context.mode = ExecutionMode::a64;
    a64_subs.opcode = Opcode::a64_subs;
    a64_subs.operands = {RegisterOperand{RegisterBank::arm64_zero, 31, 64, false}, a64_lhs, a64_rhs};
    a64_subs.register_reads = {a64_lhs, a64_rhs};
    a64_subs.register_writes = {RegisterOperand{RegisterBank::arm_flags, 0, 32, false}};
    Instruction a64_skip;
    a64_skip.address = a64_next;
    a64_skip.context = a64_subs.context;
    a64_skip.opcode = Opcode::nop;
    Instruction a64_branch;
    a64_branch.address = Address{{0}, 0x2008};
    a64_branch.context = a64_subs.context;
    a64_branch.opcode = Opcode::a64_b_cond;
    a64_branch.flow = FlowKind::conditional_branch;
    a64_branch.condition = 0; // EQ
    a64_branch.direct_target = a64_true;
    auto a64_compare_block = std::make_shared<BasicBlock>();
    a64_compare_block->id = BlockId{90};
    a64_compare_block->begin = a64_entry;
    a64_compare_block->instructions = {std::make_shared<InstructionFact>(InstructionFact{90, a64_subs, {}})};
    a64_compare_block->successors = {{a64_entry, a64_next, BlockId{91}, BlockEdgeKind::jump}};
    auto a64_branch_block = std::make_shared<BasicBlock>();
    a64_branch_block->id = BlockId{91};
    a64_branch_block->begin = a64_next;
    a64_branch_block->instructions = {std::make_shared<InstructionFact>(InstructionFact{91, a64_skip, {}}),
                                      std::make_shared<InstructionFact>(InstructionFact{92, a64_branch, {}})};
    a64_branch_block->successors = {{a64_branch.address, a64_true, BlockId{92}, BlockEdgeKind::conditional_true},
                                    {a64_branch.address, a64_false, BlockId{93}, BlockEdgeKind::conditional_false}};
    auto a64_record = record;
    a64_record.entry = a64_entry;
    a64_record.blocks = {BlockId{90}, BlockId{91}};
    FunctionSnapshot a64_snapshot;
    a64_snapshot.blocks = {a64_branch_block, a64_compare_block};
    const auto a64_lifted = lift_function(a64_record, a64_snapshot);
    require(a64_lifted && format_pseudocode(a64_lifted.value()).find("if ((x1 == x2))") != std::string::npos,
            ("AArch64 SUBS flags carry across an unconditional basic-block edge: " +
             (a64_lifted ? format_pseudocode(a64_lifted.value()) : a64_lifted.error().message)).c_str());
    Instruction a64_flag_clobber;
    a64_flag_clobber.address = a64_next;
    a64_flag_clobber.context = a64_subs.context;
    a64_flag_clobber.opcode = Opcode::a64_adds;
    a64_flag_clobber.operands = {RegisterOperand{RegisterBank::arm64_gpr, 0, 64, false},
                                 RegisterOperand{RegisterBank::arm64_gpr, 1, 64, false},
                                 RegisterOperand{RegisterBank::arm64_gpr, 2, 64, false}};
    a64_flag_clobber.register_reads = {RegisterOperand{RegisterBank::arm64_gpr, 1, 64, false},
                                       RegisterOperand{RegisterBank::arm64_gpr, 2, 64, false}};
    a64_flag_clobber.register_writes = {RegisterOperand{RegisterBank::arm64_gpr, 0, 64, false},
                                        RegisterOperand{RegisterBank::arm_flags, 0, 4, false}};
    auto a64_clobber_block = std::make_shared<BasicBlock>(*a64_branch_block);
    a64_clobber_block->instructions.insert(a64_clobber_block->instructions.begin(),
        std::make_shared<InstructionFact>(InstructionFact{93, a64_flag_clobber, {}}));
    auto a64_clobber_snapshot = a64_snapshot;
    a64_clobber_snapshot.blocks[0] = a64_clobber_block;
    const auto a64_clobbered = lift_function(a64_record, a64_clobber_snapshot);
    const auto a64_clobbered_text = a64_clobbered ? format_pseudocode(a64_clobbered.value()) : a64_clobbered.error().message;
    require(a64_clobbered && a64_clobbered_text.find("if (bit(flags, 0x2))") != std::string::npos &&
                a64_clobbered_text.find("if ((x1 == x2))") == std::string::npos,
            ("AArch64 successor NZCV write replaces the prior comparison predicate:\n" + a64_clobbered_text).c_str());

    const Address left_compare_address{{0}, 0x1030};
    const Address right_compare_address{{0}, 0x1040};
    const Address join_compare_address{{0}, 0x1050};
    auto diamond_entry_branch = equal_branch;
    diamond_entry_branch.address = Address{{0}, 0x1002};
    diamond_entry_branch.direct_target = left_compare_address;
    auto diamond_left_compare = compare;
    diamond_left_compare.address = left_compare_address;
    auto diamond_right_compare = compare;
    diamond_right_compare.address = right_compare_address;
    auto diamond_join_nop = continuation_nop;
    diamond_join_nop.address = join_compare_address;
    auto diamond_join_branch = equal_branch;
    diamond_join_branch.address = Address{{0}, 0x1051};
    auto diamond_entry = std::make_shared<BasicBlock>();
    diamond_entry->id = BlockId{90};
    diamond_entry->begin = compare_entry;
    diamond_entry->instructions = {
        std::make_shared<InstructionFact>(InstructionFact{89, compare, {}}),
        std::make_shared<InstructionFact>(InstructionFact{90, diamond_entry_branch, {}})};
    diamond_entry->successors = {
        {diamond_entry_branch.address, left_compare_address, BlockId{91}, BlockEdgeKind::conditional_true},
        {diamond_entry_branch.address, right_compare_address, BlockId{92}, BlockEdgeKind::conditional_false}};
    auto diamond_left = std::make_shared<BasicBlock>();
    diamond_left->id = BlockId{91};
    diamond_left->begin = left_compare_address;
    auto diamond_left_nop = continuation_nop;
    diamond_left_nop.address = left_compare_address;
    diamond_left->instructions = {std::make_shared<InstructionFact>(InstructionFact{91, diamond_left_nop, {}})};
    diamond_left->successors = {{left_compare_address, join_compare_address, BlockId{93}, BlockEdgeKind::jump}};
    auto diamond_right = std::make_shared<BasicBlock>();
    diamond_right->id = BlockId{92};
    diamond_right->begin = right_compare_address;
    auto diamond_right_nop = continuation_nop;
    diamond_right_nop.address = right_compare_address;
    diamond_right->instructions = {std::make_shared<InstructionFact>(InstructionFact{92, diamond_right_nop, {}})};
    diamond_right->successors = {{right_compare_address, join_compare_address, BlockId{93}, BlockEdgeKind::jump}};
    auto diamond_join = std::make_shared<BasicBlock>();
    diamond_join->id = BlockId{93};
    diamond_join->begin = join_compare_address;
    diamond_join->instructions = {
        std::make_shared<InstructionFact>(InstructionFact{93, diamond_join_nop, {}}),
        std::make_shared<InstructionFact>(InstructionFact{94, diamond_join_branch, {}})};
    auto diamond_record = compare_record;
    diamond_record.blocks = {BlockId{90}, BlockId{91}, BlockId{92}, BlockId{93}};
    FunctionSnapshot diamond_snapshot;
    diamond_snapshot.blocks = {diamond_join, diamond_right, diamond_entry, diamond_left};
    const auto equivalent_join = lift_function(diamond_record, diamond_snapshot);
    require(equivalent_join && format_pseudocode(equivalent_join.value()).find("if ((r1 == r2))") != std::string::npos,
            "one x86 compare state preserved across both diamond arms survives a CFG join");
    diamond_entry->instructions = {
        std::make_shared<InstructionFact>(InstructionFact{90, diamond_entry_branch, {}})};
    diamond_left->instructions = {
        std::make_shared<InstructionFact>(InstructionFact{91, diamond_left_compare, {}})};
    diamond_right->instructions = {
        std::make_shared<InstructionFact>(InstructionFact{92, diamond_right_compare, {}})};
    diamond_snapshot.blocks = {diamond_join, diamond_right, diamond_entry, diamond_left};
    const auto path_local_equivalent = lift_function(diamond_record, diamond_snapshot);
    require(path_local_equivalent &&
                format_pseudocode(path_local_equivalent.value()).find("condition_4") != std::string::npos,
            "distinct path-local x86 compares remain opaque when their incoming values are unproven");
    auto conflicting_right_compare = diamond_right_compare;
    conflicting_right_compare.operands = {lhs, RegisterOperand{RegisterBank::gpr, 3, 32, false}};
    diamond_right->instructions = {
        std::make_shared<InstructionFact>(InstructionFact{92, conflicting_right_compare, {}})};
    diamond_snapshot.blocks[1] = diamond_right;
    const auto conflicting_join = lift_function(diamond_record, diamond_snapshot);
    require(conflicting_join && format_pseudocode(conflicting_join.value()).find("condition_4") != std::string::npos,
            "x86 compare states with different operands stay opaque at a CFG join");

    auto below_branch = equal_branch;
    below_branch.x86_condition = X86Condition::below;
    auto below_block = std::make_shared<BasicBlock>(*compare_block);
    below_block->instructions.back() = std::make_shared<InstructionFact>(InstructionFact{14, below_branch, {}});
    auto below_snapshot = compare_snapshot;
    below_snapshot.blocks = {below_block};
    const auto below_lifted = lift_function(compare_record, below_snapshot);
    require(below_lifted && format_pseudocode(below_lifted.value()).find("(r1 ULT r2)") != std::string::npos,
            "x86 unsigned-below Jcc uses unsigned comparison semantics");

    Instruction overwrite;
    overwrite.address = Address{{0}, 0x1002};
    overwrite.context.architecture = Architecture::x86_64;
    overwrite.opcode = Opcode::mov;
    overwrite.operands = {lhs, ImmediateOperand{7, 8, 32, false, {}}};
    overwrite.register_writes = {lhs};
    auto stale_block = std::make_shared<BasicBlock>(*compare_block);
    stale_block->instructions.insert(stale_block->instructions.begin() + 1,
        std::make_shared<InstructionFact>(InstructionFact{15, overwrite, {}}));
    auto stale_snapshot = compare_snapshot;
    stale_snapshot.blocks = {stale_block};
    const auto stale_lifted = lift_function(compare_record, stale_snapshot);
    require(stale_lifted && format_pseudocode(stale_lifted.value()).find("condition_4") != std::string::npos,
            "x86 predicate is discarded when a compared register changes before Jcc");

    // Arithmetic producers update their destination and the implicit flag state
    // consumed by the next conditional branch in both x86 execution modes.
    for (const auto architecture : {Architecture::x86, Architecture::x86_64}) {
        auto arithmetic = compare;
        arithmetic.context.architecture = architecture;
        arithmetic.opcode = Opcode::sub;
        arithmetic.operands = {lhs, rhs};
        arithmetic.register_writes = {lhs, RegisterOperand{RegisterBank::flags, 0, 32, false}};
        auto arithmetic_branch = equal_branch;
        arithmetic_branch.address = Address{{0}, 0x1002};
        arithmetic_branch.x86_condition = X86Condition::below;
        auto arithmetic_block = std::make_shared<BasicBlock>();
        arithmetic_block->id = BlockId{18};
        arithmetic_block->begin = compare_entry;
        arithmetic_block->instructions = {
            std::make_shared<InstructionFact>(InstructionFact{18, arithmetic, {}}),
            std::make_shared<InstructionFact>(InstructionFact{19, arithmetic_branch, {}})};
        auto arithmetic_record = compare_record;
        arithmetic_record.blocks = {BlockId{18}};
        FunctionSnapshot arithmetic_snapshot;
        arithmetic_snapshot.blocks = {arithmetic_block};
        auto arithmetic_lifted = lift_function(arithmetic_record, arithmetic_snapshot);
        require(arithmetic_lifted && std::holds_alternative<Intrinsic>(
                    arithmetic_lifted.value().blocks[0].instructions[0].statement) &&
                    std::get<Intrinsic>(arithmetic_lifted.value().blocks[0].instructions[0].statement).name ==
                        "x86_sub_i32" &&
                    std::get<Intrinsic>(arithmetic_lifted.value().blocks[0].instructions[0].statement).result_type ==
                        std::optional<ValueType>{ValueType{TypeKind::integer, 32, false}},
                "x86 SUB retains its width-typed result together with the decoded FLAGS definition");
        require(arithmetic_lifted && format_pseudocode(arithmetic_lifted.value()).find("(r1 ULT r2)") != std::string::npos,
                "x86 SUB carries its borrow flag into unsigned-below Jcc");
    }

    // ADC/SBB are kept as explicit effects until carry-in semantics are
    // modeled. Their carry input and architectural register outputs must still
    // survive lifting and SSA rather than becoming a fake infix operation.
    for (const auto opcode : {Opcode::adc, Opcode::sbb}) {
        auto carry_op = compare;
        carry_op.opcode = opcode;
        carry_op.operands = {lhs, rhs};
        const RegisterOperand flags{RegisterBank::flags, 0, 64, false};
        carry_op.register_reads = {lhs, rhs, flags};
        carry_op.register_writes = {lhs, flags};
        auto carry_block = std::make_shared<BasicBlock>();
        carry_block->id = BlockId{181};
        carry_block->begin = compare_entry;
        carry_block->instructions = {
            std::make_shared<InstructionFact>(InstructionFact{181, carry_op, {}})};
        auto carry_record = compare_record;
        carry_record.blocks = {BlockId{181}};
        FunctionSnapshot carry_snapshot;
        carry_snapshot.blocks = {carry_block};
        const auto carry_lifted = lift_function(carry_record, carry_snapshot);
        require(carry_lifted && std::holds_alternative<Intrinsic>(
                    carry_lifted.value().blocks[0].instructions[0].statement),
                "x86 ADC/SBB remain explicit effects until carry semantics are modeled");
        if (carry_lifted && std::holds_alternative<Intrinsic>(carry_lifted.value().blocks[0].instructions[0].statement)) {
            const auto &effect = std::get<Intrinsic>(carry_lifted.value().blocks[0].instructions[0].statement);
            const auto *carry_input = effect.operands.size() > 2
                ? std::get_if<UnaryValue>(&effect.operands[2]->value) : nullptr;
            require(effect.name == (opcode == Opcode::adc ? "adc" : "sbb") && effect.operands.size() == 3 &&
                        effect.register_writes == std::vector<RegisterOperand>{lhs, flags} && carry_input &&
                        carry_input->operation == "carry_flag",
                    "x86 ADC/SBB preserve old destination, source, carry input, and destination/flags outputs");
        }
        const auto carry_ssa = carry_lifted ? to_ssa(carry_lifted.value()) : Result<LiftedFunction>{
            Error{ErrorCode::invalid_argument, "carry lift failed"}};
        require(carry_ssa && std::get<Intrinsic>(carry_ssa.value().blocks[0].instructions[0].statement)
                    .register_output_versions.size() == 2,
                "x86 ADC/SBB destination and flags receive SSA versions");
    }

    const RegisterOperand adc_memory_base{RegisterBank::gpr, 4, 64, false};
    const RegisterOperand flags{RegisterBank::flags, 0, 64, false};
    auto memory_adc = compare;
    memory_adc.opcode = Opcode::adc;
    memory_adc.operands = {MemoryOperand{64, 64, {}, adc_memory_base, {}, 1, 4, false, {}, {}}, rhs};
    memory_adc.register_reads = {adc_memory_base, rhs, flags};
    memory_adc.register_writes = {flags};
    memory_adc.memory_read = memory_adc.memory_write = true;
    auto memory_adc_block = std::make_shared<BasicBlock>();
    memory_adc_block->id = BlockId{182};
    memory_adc_block->begin = compare_entry;
    memory_adc_block->instructions = {
        std::make_shared<InstructionFact>(InstructionFact{182, memory_adc, {}})};
    auto memory_adc_record = compare_record;
    memory_adc_record.blocks = {BlockId{182}};
    FunctionSnapshot memory_adc_snapshot;
    memory_adc_snapshot.blocks = {memory_adc_block};
    const auto memory_adc_lifted = lift_function(memory_adc_record, memory_adc_snapshot);
    require(memory_adc_lifted && std::holds_alternative<Intrinsic>(
                memory_adc_lifted.value().blocks[0].instructions[0].statement) &&
                std::get<Intrinsic>(memory_adc_lifted.value().blocks[0].instructions[0].statement).memory_effect ==
                    IntrinsicMemoryEffect::unknown,
            "memory-destination ADC preserves its read-modify-write effect");
    const auto memory_adc_ssa = memory_adc_lifted ? to_ssa(memory_adc_lifted.value()) : Result<LiftedFunction>{
        Error{ErrorCode::invalid_argument, "memory ADC lift failed"}};
    require(memory_adc_ssa &&
                std::get<Intrinsic>(memory_adc_ssa.value().blocks[0].instructions[0].statement)
                    .memory_input_version.has_value() &&
                std::get<Intrinsic>(memory_adc_ssa.value().blocks[0].instructions[0].statement)
                    .memory_output_version.has_value(),
            "memory-destination ADC participates in memory SSA");

    auto btc_lift = compare;
    btc_lift.opcode = Opcode::btc;
    btc_lift.operands = {lhs, rhs};
    btc_lift.register_reads = {lhs, rhs};
    btc_lift.register_writes = {lhs, flags};
    auto btc_block = std::make_shared<BasicBlock>();
    btc_block->id = BlockId{183};
    btc_block->begin = compare_entry;
    btc_block->instructions = {std::make_shared<InstructionFact>(InstructionFact{183, btc_lift, {}})};
    auto btc_record = compare_record;
    btc_record.blocks = {BlockId{183}};
    FunctionSnapshot btc_snapshot;
    btc_snapshot.blocks = {btc_block};
    const auto btc_lifted = lift_function(btc_record, btc_snapshot);
    require(btc_lifted && std::holds_alternative<Intrinsic>(
                btc_lifted.value().blocks[0].instructions[0].statement) &&
                std::get<Intrinsic>(btc_lifted.value().blocks[0].instructions[0].statement).name == "x86_btc" &&
                std::get<Intrinsic>(btc_lifted.value().blocks[0].instructions[0].statement).register_writes ==
                    std::vector<RegisterOperand>{lhs, flags},
            "x86 BTC lifting preserves the selected operands and destination/flags effects");

    auto memory_bts_lift = btc_lift;
    memory_bts_lift.opcode = Opcode::bts;
    memory_bts_lift.operands = {MemoryOperand{64, 64, {}, lhs, {}, 1, 8, false, {}, {}}, rhs};
    memory_bts_lift.register_reads = {lhs, rhs};
    memory_bts_lift.register_writes = {flags};
    memory_bts_lift.memory_read = memory_bts_lift.memory_write = true;
    auto memory_bts_block = std::make_shared<BasicBlock>();
    memory_bts_block->id = BlockId{184};
    memory_bts_block->begin = compare_entry;
    memory_bts_block->instructions = {
        std::make_shared<InstructionFact>(InstructionFact{184, memory_bts_lift, {}})};
    auto memory_bts_record = compare_record;
    memory_bts_record.blocks = {BlockId{184}};
    FunctionSnapshot memory_bts_snapshot;
    memory_bts_snapshot.blocks = {memory_bts_block};
    const auto memory_bts_lifted = lift_function(memory_bts_record, memory_bts_snapshot);
    require(memory_bts_lifted && std::get<Intrinsic>(
                memory_bts_lifted.value().blocks[0].instructions[0].statement).memory_effect ==
                    IntrinsicMemoryEffect::unknown,
            "memory BTS lifting retains a read-modify-write memory effect");

    auto addition = compare;
    addition.opcode = Opcode::add;
    addition.operands = {lhs, rhs};
    addition.register_writes = {lhs, RegisterOperand{RegisterBank::flags, 0, 64, false}};
    auto overflow_branch = equal_branch;
    overflow_branch.address = Address{{0}, 0x1002};
    overflow_branch.x86_condition = X86Condition::overflow;
    overflow_branch.condition = static_cast<std::uint8_t>(X86Condition::overflow);
    auto addition_block = std::make_shared<BasicBlock>();
    addition_block->id = BlockId{21};
    addition_block->begin = compare_entry;
    addition_block->instructions = {
        std::make_shared<InstructionFact>(InstructionFact{24, addition, {}}),
        std::make_shared<InstructionFact>(InstructionFact{25, overflow_branch, {}})};
    auto addition_record = compare_record;
    addition_record.blocks = {BlockId{21}};
    FunctionSnapshot addition_snapshot;
    addition_snapshot.blocks = {addition_block};
    const auto addition_lifted = lift_function(addition_record, addition_snapshot);
    require(addition_lifted && format_pseudocode(addition_lifted.value()).find("signbit(r1)") != std::string::npos &&
                format_pseudocode(addition_lifted.value()).find("signbit(r2)") != std::string::npos,
            "x86 ADD overflow predicate compares source signs with the truncated result sign");

    auto logic = compare;
    logic.opcode = Opcode::bit_xor;
    logic.operands = {lhs, rhs};
    logic.register_writes = {lhs, RegisterOperand{RegisterBank::flags, 0, 64, false}};
    auto logic_branch = equal_branch;
    logic_branch.address = Address{{0}, 0x1002};
    logic_branch.x86_condition = X86Condition::equal;
    auto logic_block = std::make_shared<BasicBlock>();
    logic_block->id = BlockId{19};
    logic_block->begin = compare_entry;
    logic_block->instructions = {
        std::make_shared<InstructionFact>(InstructionFact{20, logic, {}}),
        std::make_shared<InstructionFact>(InstructionFact{21, logic_branch, {}})};
    auto logic_record = compare_record;
    logic_record.blocks = {BlockId{19}};
    FunctionSnapshot logic_snapshot;
    logic_snapshot.blocks = {logic_block};
    const auto logic_lifted = lift_function(logic_record, logic_snapshot);
    require(logic_lifted && format_pseudocode(logic_lifted.value()).find("(r1 ^ r2)") != std::string::npos &&
                format_pseudocode(logic_lifted.value()).find("== 0x0") != std::string::npos,
            "x86 logical flag producers lift their value and zero predicate");

    auto shift = compare;
    shift.opcode = Opcode::shl;
    shift.operands = {lhs, ImmediateOperand{1, 8, 32, false, {}}};
    shift.register_writes = {lhs, RegisterOperand{RegisterBank::flags, 0, 64, false}};
    auto shift_branch = equal_branch;
    shift_branch.address = Address{{0}, 0x1002};
    shift_branch.x86_condition = X86Condition::overflow;
    shift_branch.register_reads = {flags};
    auto shift_block = std::make_shared<BasicBlock>();
    shift_block->id = BlockId{20};
    shift_block->begin = compare_entry;
    shift_block->instructions = {
        std::make_shared<InstructionFact>(InstructionFact{22, shift, {}}),
        std::make_shared<InstructionFact>(InstructionFact{23, shift_branch, {}})};
    auto shift_record = compare_record;
    shift_record.blocks = {BlockId{20}};
    FunctionSnapshot shift_snapshot;
    shift_snapshot.blocks = {shift_block};
    const auto shift_lifted = lift_function(shift_record, shift_snapshot);
    const auto shift_text = shift_lifted ? format_pseudocode(shift_lifted.value()) : shift_lifted.error().message;
    require(shift_lifted && shift_text.find("x86_shl(r1, 0x1)") != std::string::npos &&
                shift_text.find("writes r1, flags") != std::string::npos,
            ("x86 immediate SHL retains its typed count, destination, and flags effects:\n" + shift_text).c_str());
    require(shift_lifted && shift_text.find("bit(flags, 0xb)") != std::string::npos,
            ("one-bit SHL overflow branch consumes OF from the produced flags value:\n" + shift_text).c_str());

    FunctionSnapshot missing;
    auto rejected = lift_function(record, missing);
    require(!rejected && rejected.error().code == ErrorCode::invalid_argument,
            "a function cannot silently lift without its blocks");

    const RegisterOperand r0{RegisterBank::gpr, 0, 64, false};
    const RegisterOperand r1{RegisterBank::gpr, 1, 64, false};
    const RegisterOperand r2{RegisterBank::gpr, 2, 64, false};
    const Address entry{{0}, 0x2000}, left{{0}, 0x2010}, right{{0}, 0x2020}, join{{0}, 0x2030};
    auto reg = std::make_shared<Expression>(Expression{{TypeKind::integer, 64, false}, RegisterValue{r0}});
    auto value = [](std::uint64_t n) -> ExpressionPtr {
        return std::make_shared<Expression>(Expression{{TypeKind::integer, 64, false},
                                                       ConstantValue{n, {TypeKind::integer, 64, false}}});
    };
    LiftedFunction diamond{FunctionId{9}, entry,
        {{BlockId{10}, entry, {{ {entry, 20}, Branch{"test", left, right} }},
          {{entry, left, BlockId{11}, BlockEdgeKind::conditional_true},
           {entry, right, BlockId{12}, BlockEdgeKind::conditional_false}}, {}},
         {BlockId{11}, left, {{{left, 21}, Assign{r0, value(1)}}},
          {{left, join, BlockId{13}, BlockEdgeKind::jump}}, {}},
         {BlockId{12}, right, {{{right, 22}, Assign{r0, value(2)}}},
          {{right, join, BlockId{13}, BlockEdgeKind::jump}}, {}},
         {BlockId{13}, join, {{{join, 23}, Assign{r1, reg}}}, {}, {}}}, {}};
    auto ssa = to_ssa(diamond);
    require(ssa.has_value(), "valid control-flow graph converts to SSA");
    const auto &merge = ssa.value().blocks[3];
    require(merge.phis.size() == 1 && merge.phis[0].inputs.size() == 2,
            "a register defined on both incoming paths receives one phi node");
    const auto &merge_assign = std::get<Assign>(merge.instructions[0].statement);
    const auto &merge_use = std::get<RegisterValue>(merge_assign.value->value);
    require(merge_use.version == merge.phis[0].version,
            "uses after a control-flow join read the merged SSA version");
    require(merge.phis[0].inputs[0].version != merge.phis[0].inputs[1].version,
            "phi inputs preserve distinct reaching definitions");
    const auto ssa_text = format_pseudocode(ssa.value());
    require(ssa_text.find(" = phi(loc_2010: r0_1, loc_2020: r0_2);") != std::string::npos,
            "pseudocode renders stable, address-attributed phi inputs");
    require(ssa_text.find("r1_1 = r0_3;") != std::string::npos,
            "pseudocode renders versioned assignments and uses");

    LiftedFunction constants{FunctionId{13}, entry,
        {{BlockId{40}, entry,
          {{{entry, 60}, Assign{r0, value(5)}},
           {{Address{{0}, 0x2004}, 61}, Assign{r1, std::make_shared<Expression>(Expression{
               {TypeKind::integer, 64, false}, BinaryValue{"add", reg, value(3)}})}}}, {}, {}}}, {}};
    auto constants_ssa = to_ssa(constants);
    require(bool(constants_ssa), "constant propagation fixture converts to SSA");
    auto folded = constants_ssa ? simplify_constants(constants_ssa.value())
                                : Result<LiftedFunction>(Error{ErrorCode::invalid_argument, "SSA fixture failed"});
    require(bool(folded), "constant simplification accepts valid SSA");
    if (folded) {
        const auto &folded_assign = std::get<Assign>(folded.value().blocks[0].instructions[1].statement);
        require(std::holds_alternative<ConstantValue>(folded_assign.value->value) &&
                    std::get<ConstantValue>(folded_assign.value->value).value == 8,
                "constant register values propagate through SSA arithmetic");
    }
    const RegisterOperand byte_reg{RegisterBank::gpr, 2, 8, false};
    const RegisterOperand byte_result{RegisterBank::gpr, 3, 8, false};
    const auto byte_value = [](std::uint64_t n) -> ExpressionPtr {
        const ValueType type{TypeKind::integer, 8, false};
        return std::make_shared<Expression>(Expression{type, ConstantValue{n, type}});
    };
    LiftedFunction wrapping{FunctionId{14}, entry,
        {{BlockId{41}, entry,
          {{{entry, 62}, Assign{byte_reg, byte_value(0xff)}},
           {{Address{{0}, 0x2008}, 63}, Assign{byte_result, std::make_shared<Expression>(Expression{
               {TypeKind::integer, 8, false}, BinaryValue{"add", std::make_shared<Expression>(Expression{
                   {TypeKind::integer, 8, false}, RegisterValue{byte_reg}}), byte_value(1)}})}}}, {}, {}}}, {}};
    auto wrapping_ssa = to_ssa(wrapping);
    auto wrapped = wrapping_ssa ? simplify_constants(wrapping_ssa.value())
                               : Result<LiftedFunction>(Error{ErrorCode::invalid_argument, "wrap fixture failed"});
    require(wrapped && std::get<ConstantValue>(std::get<Assign>(
                wrapped.value().blocks[0].instructions[1].statement).value->value).value == 0,
            "constant arithmetic wraps at the destination bit width");
    const RegisterOperand word_reg{RegisterBank::gpr, 4, 32, false};
    LiftedFunction extension_folding{FunctionId{15}, entry,
        {{BlockId{42}, entry,
          {{{entry, 64}, Assign{word_reg, std::make_shared<Expression>(Expression{
               {TypeKind::integer, 32, false}, UnaryValue{"sext", byte_value(0xff)}}), 1}},
           {{Address{{0}, 0x200c}, 65}, Assign{byte_result, std::make_shared<Expression>(Expression{
               {TypeKind::integer, 8, false}, BinaryValue{"sar", byte_value(0x80), byte_value(1)}}), 1}}}, {}, {}}}, {}};
    auto extension_folded = simplify_constants(extension_folding);
    require(extension_folded && std::get<ConstantValue>(std::get<Assign>(
                extension_folded.value().blocks[0].instructions[0].statement).value->value).value == 0xffffffff,
            "constant sign extension preserves the source sign bit");
    require(extension_folded && std::get<ConstantValue>(std::get<Assign>(
                extension_folded.value().blocks[0].instructions[1].statement).value->value).value == 0xc0,
            "arithmetic right shift fills the declared bit width");
    Call unknown_call{Address{{0}, 0x5000}, {}};
    unknown_call.register_writes = {r0};
    LiftedFunction call_barrier{FunctionId{16}, entry,
        {{BlockId{43}, entry,
          {{{entry, 66}, Assign{r0, value(5)}},
           {{Address{{0}, 0x200c}, 67}, Assign{r2, reg}},
           {{Address{{0}, 0x2010}, 68}, unknown_call},
           {{Address{{0}, 0x2014}, 69}, Assign{r1, reg}}}, {}, {}}}, {}};
    auto call_barrier_ssa = to_ssa(call_barrier);
    auto call_barrier_result = call_barrier_ssa ? simplify_constants(call_barrier_ssa.value())
        : Result<LiftedFunction>(Error{ErrorCode::invalid_argument, "call barrier fixture failed"});
    require(call_barrier_result && std::holds_alternative<RegisterValue>(std::get<Assign>(
                call_barrier_result.value().blocks[0].instructions[3].statement).value->value),
            "unknown call clobbers prevent register-constant propagation");
    require(call_barrier_result && std::holds_alternative<ConstantValue>(std::get<Assign>(
                call_barrier_result.value().blocks[0].instructions[1].statement).value->value) &&
                std::get<ConstantValue>(std::get<Assign>(
                    call_barrier_result.value().blocks[0].instructions[1].statement).value->value).value == 5,
            "known SSA constants still propagate into uses before a call barrier");
    auto duplicate_definition = extension_folding;
    duplicate_definition.blocks[0].instructions.push_back(duplicate_definition.blocks[0].instructions[0]);
    require(!simplify_constants(duplicate_definition),
            "invalid SSA with duplicate versions is rejected before propagation");

    const auto structured = format_structured_pseudocode(diamond);
    require(structured.text.find("if (test)") != std::string::npos &&
                structured.text.find("goto") == std::string::npos,
            "a canonical two-arm diamond is emitted as structured if/else C-like output");
    require(!structured.used_fallback, "supported diamond reports structured output");
    auto inconsistent_edge_ids = diamond;
    inconsistent_edge_ids.blocks[0].successors[0].block = BlockId{999};
    const auto inconsistent_edge_output = format_structured_pseudocode(inconsistent_edge_ids);
    require(inconsistent_edge_output.used_fallback && !inconsistent_edge_output.fallback_reason.empty(),
            "a successor target that conflicts with its block ID retains diagnostic CFG output");

    const auto structured_ssa = format_structured_pseudocode(ssa.value());
    require(!structured_ssa.used_fallback,
            "SSA diamonds with edge-lowerable join phis are structured");
    require(structured_ssa.text.find("if (test)") != std::string::npos &&
                structured_ssa.text.find("goto") == std::string::npos &&
                structured_ssa.text.find("r0_3 = r0_1;") != std::string::npos &&
                structured_ssa.text.find("r0_3 = r0_2;") != std::string::npos,
            "join phi values are copied on their corresponding structured edges");

    const Address true_middle{{0}, 0x2040}, true_tail{{0}, 0x2050};
    LiftedFunction chained_diamond{FunctionId{17}, entry,
        {{BlockId{30}, join, {{{join, 70}, Return{reg}}}, {}, {}},
         {BlockId{31}, right, {{{right, 71}, Assign{r1, value(2)}}},
          {{right, join, BlockId{30}, BlockEdgeKind::jump}}, {}},
         {BlockId{32}, entry, {{{entry, 72}, Branch{"ready", left, right}}},
          {{entry, left, BlockId{34}, BlockEdgeKind::conditional_true},
           {entry, right, BlockId{31}, BlockEdgeKind::conditional_false}}, {}},
         {BlockId{33}, true_tail, {{{true_tail, 73}, Assign{r1, value(4)}}},
          {{true_tail, join, BlockId{30}, BlockEdgeKind::jump}}, {}},
         {BlockId{34}, left, {{{left, 74}, Assign{r1, value(3)}}},
          {{left, true_middle, BlockId{35}, BlockEdgeKind::jump}}, {}},
         {BlockId{35}, true_middle, {{{true_middle, 75}, Assign{r0, value(5)}}},
          {{true_middle, true_tail, BlockId{33}, BlockEdgeKind::jump}}, {}}}, {}};
    auto chained_ssa = to_ssa(chained_diamond);
    require(chained_ssa.has_value(), "straight-line arm chains can be converted to SSA");
    const auto chained_structured = chained_ssa ? format_structured_pseudocode(chained_ssa.value())
        : StructuredPseudocode{};
    require(!chained_structured.used_fallback && chained_structured.text.find("goto") == std::string::npos &&
                chained_structured.text.find("0x3;") != std::string::npos &&
                chained_structured.text.find("0x4;") != std::string::npos,
            "a reducible diamond with a multi-block arm is emitted without labels or gotos");

    const Address nested_entry{{0}, 0x2080}, inner_branch{{0}, 0x2090}, inner_left{{0}, 0x20a0};
    const Address inner_right{{0}, 0x20b0}, inner_join{{0}, 0x20c0}, outer_else{{0}, 0x20d0};
    const Address outer_join{{0}, 0x20e0};
    LiftedFunction nested_if{FunctionId{22}, nested_entry, {}, {}};
    nested_if.blocks = {
        {BlockId{75}, inner_join, {{{inner_join, 101}, Assign{r1, reg}}},
         {{inner_join, outer_join, BlockId{78}, BlockEdgeKind::jump}}, {}},
        {BlockId{76}, inner_right, {{{inner_right, 102}, Assign{r0, value(2)}}},
         {{inner_right, inner_join, BlockId{75}, BlockEdgeKind::jump}}, {}},
        {BlockId{77}, nested_entry, {{{nested_entry, 103}, Branch{"outer_test", inner_branch, outer_else}}},
         {{nested_entry, inner_branch, BlockId{79}, BlockEdgeKind::conditional_true},
          {nested_entry, outer_else, BlockId{80}, BlockEdgeKind::conditional_false}}, {}},
        {BlockId{78}, outer_join, {{{outer_join, 104}, Return{reg}}}, {}, {}},
        {BlockId{79}, inner_branch, {{{inner_branch, 105}, Branch{"inner_test", inner_left, inner_right}}},
         {{inner_branch, inner_left, BlockId{81}, BlockEdgeKind::conditional_true},
          {inner_branch, inner_right, BlockId{76}, BlockEdgeKind::conditional_false}}, {}},
        {BlockId{80}, outer_else, {{{outer_else, 106}, Assign{r0, value(3)}}},
         {{outer_else, outer_join, BlockId{78}, BlockEdgeKind::jump}}, {}},
        {BlockId{81}, inner_left, {{{inner_left, 107}, Assign{r0, value(1)}}},
         {{inner_left, inner_join, BlockId{75}, BlockEdgeKind::jump}}, {}}
    };
    const auto nested_plain = format_structured_pseudocode(nested_if);
    require(!nested_plain.used_fallback && nested_plain.text.find("if (outer_test)") != std::string::npos &&
                nested_plain.text.find("if (inner_test)") != std::string::npos &&
                nested_plain.text.find("goto") == std::string::npos,
            "nested reducible conditionals emit nested if/else without goto labels");
    const auto nested_ssa = to_ssa(nested_if);
    const auto nested_versioned = nested_ssa ? format_structured_pseudocode(nested_ssa.value())
        : StructuredPseudocode{};
    const auto phi_edges_lowered = [&]() {
        if (!nested_ssa || nested_ssa.value().blocks[0].phis.size() != 1 ||
            nested_ssa.value().blocks[3].phis.size() != 2) return false;
        // Inner phi inputs are copied at their predecessor edges. The outer
        // join uses parallel-copy temporaries so one phi write cannot clobber
        // another phi's incoming value on the same edge.
        const auto &inner_phi = nested_ssa.value().blocks[0].phis.front();
        const auto &outer_phi_r0 = nested_ssa.value().blocks[3].phis[0];
        const auto &outer_phi_r1 = nested_ssa.value().blocks[3].phis[1];
        if (inner_phi.destination.index != 0 || inner_phi.version != 2 || inner_phi.inputs.size() != 2 ||
            outer_phi_r0.destination.index != 0 || outer_phi_r1.destination.index != 1 ||
            outer_phi_r0.inputs.size() != 2 || outer_phi_r1.inputs.size() != 2) return false;
        const auto has_input = [](const auto &phi, std::uint32_t predecessor, std::uint32_t version) {
            return std::any_of(phi.inputs.begin(), phi.inputs.end(), [&](const auto &input) {
                return input.predecessor.value == predecessor && input.version == version;
            });
        };
        if (!has_input(inner_phi, 76, 3) || !has_input(inner_phi, 81, 4) ||
            !has_input(outer_phi_r0, 75, 2) || !has_input(outer_phi_r0, 80, 5) ||
            !has_input(outer_phi_r1, 75, 2) || !has_input(outer_phi_r1, 80, 0)) return false;
        return nested_versioned.text.find("r0_4 = 0x1;") != std::string::npos &&
            nested_versioned.text.find("r0_2 = r0_4;") != std::string::npos &&
            nested_versioned.text.find("r0_3 = 0x2;") != std::string::npos &&
            nested_versioned.text.find("r0_2 = r0_3;") != std::string::npos &&
            nested_versioned.text.find("auto __hexlab_phi_0 = r0_2;") != std::string::npos &&
            nested_versioned.text.find("auto __hexlab_phi_1 = r1_2;") != std::string::npos &&
            nested_versioned.text.find("r0_1 = __hexlab_phi_0;") != std::string::npos &&
            nested_versioned.text.find("r1_1 = __hexlab_phi_1;") != std::string::npos &&
            nested_versioned.text.find("auto __hexlab_phi_2 = r0_5;") != std::string::npos &&
            nested_versioned.text.find("auto __hexlab_phi_3 = r1_0;") != std::string::npos &&
            nested_versioned.text.find("r0_1 = __hexlab_phi_2;") != std::string::npos &&
            nested_versioned.text.find("r1_1 = __hexlab_phi_3;") != std::string::npos;
    }();
    require(nested_ssa && !nested_versioned.used_fallback &&
                nested_versioned.text.find("if (outer_test)") != std::string::npos &&
                nested_versioned.text.find("if (inner_test)") != std::string::npos &&
                nested_versioned.text.find("phi(") == std::string::npos &&
                nested_versioned.text.find("goto") == std::string::npos && phi_edges_lowered,
            "nested SSA joins lower their phi inputs onto the actual incoming CFG edges");
    if (nested_ssa) {
        auto malformed_nested_phi = nested_ssa.value();
        malformed_nested_phi.blocks[0].phis[0].inputs.pop_back();
        const auto malformed_nested = format_structured_pseudocode(malformed_nested_phi);
        require(malformed_nested.used_fallback && !malformed_nested.fallback_reason.empty(),
                "nested SSA with an incomplete edge phi keeps conservative goto output");
    }

    const Address irreducible_entry{{0}, 0x2100}, irreducible_left{{0}, 0x2110};
    const Address irreducible_right{{0}, 0x2120}, irreducible_exit{{0}, 0x2130};
    LiftedFunction irreducible{FunctionId{23}, irreducible_entry,
        {{BlockId{90}, irreducible_entry, {{{irreducible_entry, 108},
             Branch{"start", irreducible_left, irreducible_right}}},
          {{irreducible_entry, irreducible_left, BlockId{91}, BlockEdgeKind::conditional_true},
           {irreducible_entry, irreducible_right, BlockId{92}, BlockEdgeKind::conditional_false}}, {}},
         {BlockId{91}, irreducible_left, {{{irreducible_left, 109},
             Branch{"left_edge", irreducible_right, irreducible_exit}}},
          {{irreducible_left, irreducible_right, BlockId{92}, BlockEdgeKind::conditional_true},
           {irreducible_left, irreducible_exit, BlockId{93}, BlockEdgeKind::conditional_false}}, {}},
         {BlockId{92}, irreducible_right, {{{irreducible_right, 110},
             Branch{"right_edge", irreducible_left, irreducible_exit}}},
          {{irreducible_right, irreducible_left, BlockId{91}, BlockEdgeKind::conditional_true},
           {irreducible_right, irreducible_exit, BlockId{93}, BlockEdgeKind::conditional_false}}, {}},
         {BlockId{93}, irreducible_exit, {{{irreducible_exit, 111}, Return{}}}, {}, {}}}, {}};
    const auto irreducible_output = format_structured_pseudocode(irreducible);
    require(!irreducible_output.used_fallback &&
                irreducible_output.text.find("while (true)") != std::string::npos &&
                irreducible_output.text.find("case 1:") != std::string::npos &&
                irreducible_output.text.find("case 2:") != std::string::npos &&
                irreducible_output.text.find("block_id = 1;") != std::string::npos &&
                irreducible_output.text.find("block_id = 2;") != std::string::npos &&
                irreducible_output.text.find("if (left_edge)") != std::string::npos &&
                irreducible_output.text.find("if (right_edge)") != std::string::npos &&
                irreducible_output.text.find("return;") != std::string::npos,
            "irreducible multi-entry cycles retain dispatcher transitions and their reachable exit");

    const Address dispatch_entry{{0}, 0x2140}, switch_case0{{0}, 0x2150};
    const Address switch_case1{{0}, 0x2160}, switch_case2{{0}, 0x2170};
    LiftedFunction switch_without_metadata{FunctionId{24}, dispatch_entry,
        {{BlockId{94}, dispatch_entry, {{{dispatch_entry, 112}, Branch{"true", {}, {}}}},
          {{dispatch_entry, switch_case0, BlockId{95}, BlockEdgeKind::jump},
           {dispatch_entry, switch_case1, BlockId{96}, BlockEdgeKind::jump},
           {dispatch_entry, switch_case2, BlockId{97}, BlockEdgeKind::jump}}, {}},
         {BlockId{95}, switch_case0, {{{switch_case0, 113}, Return{}}}, {}, {}},
         {BlockId{96}, switch_case1, {{{switch_case1, 114}, Return{}}}, {}, {}},
         {BlockId{97}, switch_case2, {{{switch_case2, 115}, Return{}}}, {}, {}}}, {}};
    const auto switch_fallback = format_structured_pseudocode(switch_without_metadata);
    require(switch_fallback.used_fallback && !switch_fallback.fallback_reason.empty(),
            "multiway dispatch without explicit case metadata is not assigned guessed switch labels");
    auto switch_with_metadata = switch_without_metadata;
    SwitchSite recovered_site;
    recovered_site.dispatch = dispatch_entry;
    recovered_site.table = Address{{0}, 0x2180};
    recovered_site.selector = r0;
    recovered_site.cases = {{0, switch_case0}, {1, switch_case1}};
    attach_switch_analysis(switch_with_metadata, SwitchAnalysis{{recovered_site}, true});
    auto switch_ssa = to_ssa(switch_with_metadata);
    const auto structured_switch = switch_ssa ? format_structured_pseudocode(switch_ssa.value())
                                               : StructuredPseudocode{};
    require(switch_ssa && !structured_switch.used_fallback &&
                structured_switch.text.find("switch (r0_0)") != std::string::npos &&
                structured_switch.text.find("case 0x0:") != std::string::npos &&
                structured_switch.text.find("case 0x1:") != std::string::npos &&
                structured_switch.text.find("default:") != std::string::npos &&
                structured_switch.text.find("goto") == std::string::npos,
            "complete selector, case, and default metadata structures terminal switch arms");
    const Address switch_join{{0}, 0x2190};
    auto joined_switch = switch_with_metadata;
    for (std::size_t arm = 1; arm < joined_switch.blocks.size(); ++arm) {
        auto &block = joined_switch.blocks[arm];
        block.instructions.back().statement = Assign{r0, value(10 * arm)};
        block.successors.push_back({block.begin, switch_join, BlockId{98}, BlockEdgeKind::jump});
    }
    const Address switch_mid{{0}, 0x2188};
    joined_switch.blocks[1].successors.back().target = switch_mid;
    joined_switch.blocks[1].successors.back().block = BlockId{99};
    joined_switch.blocks.push_back({BlockId{99}, switch_mid,
        {{{switch_mid, 117}, Assign{r1, value(40)}}},
        {{switch_mid, switch_join, BlockId{98}, BlockEdgeKind::jump}}, {}});
    joined_switch.blocks.push_back({BlockId{98}, switch_join,
        {{{switch_join, 116}, Return{reg}}}, {}, {}});
    const auto joined_switch_ssa = to_ssa(joined_switch);
    const auto joined_switch_output = joined_switch_ssa
        ? format_structured_pseudocode(joined_switch_ssa.value()) : StructuredPseudocode{};
    require(joined_switch_ssa && !joined_switch_output.used_fallback &&
                joined_switch_output.text.find("case 0x0:") != std::string::npos &&
                joined_switch_output.text.find("case 0x1:") != std::string::npos &&
                joined_switch_output.text.find("default:") != std::string::npos &&
                joined_switch_output.text.find("break;") != std::string::npos &&
                joined_switch_output.text.find("return r0_") != std::string::npos &&
                joined_switch_output.text.find(" = r0_") != std::string::npos &&
                joined_switch_output.text.find("r1_") != std::string::npos &&
                joined_switch_output.text.find("goto") == std::string::npos,
            "switch arms that converge on one shared join are structured with explicit breaks");
    auto incomplete_switch = switch_with_metadata;
    incomplete_switch.blocks[0].switch_dispatch->complete = false;
    const auto incomplete_switch_output = format_structured_pseudocode(incomplete_switch);
    require(incomplete_switch_output.used_fallback && !incomplete_switch_output.fallback_reason.empty(),
            "incomplete switch metadata keeps the explicit CFG fallback");
    auto mismatched_switch = switch_with_metadata;
    mismatched_switch.blocks[0].switch_dispatch->cases[0].value = 1;
    const auto mismatched_switch_output = format_structured_pseudocode(mismatched_switch);
    require(mismatched_switch_output.used_fallback && !mismatched_switch_output.fallback_reason.empty(),
            "duplicate switch case values are rejected conservatively");

    const Address return_block{{0}, 0x2060}, continue_block{{0}, 0x2070};
    LiftedFunction early_return{FunctionId{18}, entry,
        {{BlockId{40}, entry, {{{entry, 76}, Branch{"is_zero", return_block, continue_block}}},
          {{entry, return_block, BlockId{41}, BlockEdgeKind::conditional_true},
           {entry, continue_block, BlockId{42}, BlockEdgeKind::conditional_false}}, {}},
         {BlockId{41}, return_block, {{{return_block, 77}, Return{}}}, {}, {}},
         {BlockId{42}, continue_block,
          {{{continue_block, 78}, Assign{r0, value(9)}}}, {}, {}}}, {}};
    const auto early_return_structured = format_structured_pseudocode(early_return);
    require(!early_return_structured.used_fallback &&
                early_return_structured.text.find("if (is_zero) {\n        return;") != std::string::npos &&
                early_return_structured.text.find("goto") == std::string::npos,
            "a conditional early return is emitted as a one-arm structured if");
    auto false_arm_return = early_return;
    auto &inverted_branch = std::get<Branch>(false_arm_return.blocks[0].instructions[0].statement);
    std::swap(inverted_branch.true_target, inverted_branch.false_target);
    std::swap(false_arm_return.blocks[0].successors[0].target, false_arm_return.blocks[0].successors[1].target);
    std::swap(false_arm_return.blocks[0].successors[0].block, false_arm_return.blocks[0].successors[1].block);
    const auto inverted_return_structured = format_structured_pseudocode(false_arm_return);
    if (inverted_return_structured.used_fallback ||
        inverted_return_structured.text.find("if (!(is_zero)) {\n        return;") == std::string::npos)
        std::cerr << inverted_return_structured.text;
    require(!inverted_return_structured.used_fallback &&
                inverted_return_structured.text.find("if (!(is_zero)) {\n        return;") != std::string::npos,
            "a return on the false branch preserves the inverted condition");
    auto two_return_arms = early_return;
    two_return_arms.blocks[2].instructions.push_back({{Address{{0}, 0x2074}, 80}, Return{reg}});
    const auto two_return_structured = format_structured_pseudocode(two_return_arms);
    require(!two_return_structured.used_fallback &&
                two_return_structured.text.find("if (is_zero) {") != std::string::npos &&
                two_return_structured.text.find("return;") != std::string::npos &&
                two_return_structured.text.find("return r0;") != std::string::npos &&
                two_return_structured.text.find("goto") == std::string::npos,
            "a conditional with two distinct terminal returns is emitted as a complete if/else");
    LiftedFunction nested_return_tree{FunctionId{22}, entry,
        {{BlockId{70}, entry, {{{entry, 110}, Branch{"outer", left, right}}},
          {{entry, left, BlockId{71}, BlockEdgeKind::conditional_true},
           {entry, right, BlockId{72}, BlockEdgeKind::conditional_false}}, {}},
         {BlockId{71}, left, {{{left, 111}, Branch{"inner", join, continue_block}}},
          {{left, join, BlockId{73}, BlockEdgeKind::conditional_true},
           {left, continue_block, BlockId{74}, BlockEdgeKind::conditional_false}}, {}},
         {BlockId{72}, right, {{{right, 112}, Return{}}}, {}, {}},
         {BlockId{73}, join, {{{join, 113}, Return{reg}}}, {}, {}},
         {BlockId{74}, continue_block, {{{continue_block, 114}, Return{}}}, {}, {}}}, {}};
    const auto nested_return_tree_output = format_structured_pseudocode(nested_return_tree);
    require(!nested_return_tree_output.used_fallback &&
                nested_return_tree_output.text.find("if (outer)") != std::string::npos &&
                nested_return_tree_output.text.find("if (inner)") != std::string::npos &&
                nested_return_tree_output.text.find("goto") == std::string::npos,
            "nested branch trees with distinct return leaves are fully structured");
    auto malformed_phi = ssa.value();
    malformed_phi.blocks[3].phis[0].inputs.pop_back();
    const auto malformed_structured = format_structured_pseudocode(malformed_phi);
    require(malformed_structured.used_fallback && !malformed_structured.fallback_reason.empty(),
            "incomplete SSA edge copies retain explicit conservative fallback");

    const Address loop_entry{{0}, 0x3000}, header{{0}, 0x3010}, body{{0}, 0x3020}, exit{{0}, 0x3030};
    auto loop_reg = std::make_shared<Expression>(Expression{{TypeKind::integer, 64, false}, RegisterValue{r0}});
    LiftedFunction loop{FunctionId{10}, loop_entry,
        {{BlockId{20}, loop_entry, {{{loop_entry, 30}, Assign{r0, value(0)}},
                                    {{Address{{0}, 0x3004}, 38}, Branch{"true", header, {}}}},
          {{loop_entry, header, BlockId{21}, BlockEdgeKind::jump}}, {}},
         {BlockId{21}, header, {{{header, 31}, Branch{"nonzero", body, exit}}},
          {{header, body, BlockId{22}, BlockEdgeKind::conditional_true},
           {header, exit, BlockId{23}, BlockEdgeKind::conditional_false}}, {}},
         {BlockId{22}, body, {{{body, 32}, Assign{r0, std::make_shared<Expression>(Expression{
             {TypeKind::integer, 64, false}, BinaryValue{"add", loop_reg, value(1)}})}}},
          {{body, header, BlockId{21}, BlockEdgeKind::jump}}, {}},
         {BlockId{23}, exit, {{{exit, 33}, Return{loop_reg}}}, {}, {}}}, {}};
    auto loop_ssa = to_ssa(loop);
    require(loop_ssa && loop_ssa.value().blocks[1].phis.size() == 1 &&
                loop_ssa.value().blocks[1].phis[0].inputs.size() == 2,
            "loop header receives a phi with entry and back-edge definitions");
    const auto &loop_increment = std::get<Assign>(loop_ssa.value().blocks[2].instructions[0].statement);
    const auto &loop_increment_input = std::get<RegisterValue>(
        std::get<BinaryValue>(loop_increment.value->value).left->value);
    require(loop_increment_input.version == loop_ssa.value().blocks[1].phis[0].version,
            "loop body reads the merged header version");
    const auto structured_loop = format_structured_pseudocode(loop);
    require(!structured_loop.used_fallback && structured_loop.text.find("while (nonzero)") != std::string::npos &&
                structured_loop.text.find("goto") == std::string::npos && structured_loop.text.find("return r0;") != std::string::npos,
            "a canonical pre-tested reducible loop is emitted as while with its exit continuation");
    auto loop_with_continuation = loop;
    loop_with_continuation.blocks[3].instructions = {{{exit, 33}, Assign{r1, value(7)}}};
    loop_with_continuation.blocks[3].successors = {{exit, Address{{0}, 0x3040}, BlockId{24}, BlockEdgeKind::jump}};
    loop_with_continuation.blocks.push_back({BlockId{24}, Address{{0}, 0x3040},
        {{{Address{{0}, 0x3040}, 34}, Return{loop_reg}}}, {}, {}});
    const auto structured_loop_continuation = format_structured_pseudocode(loop_with_continuation);
    require(!structured_loop_continuation.used_fallback &&
                structured_loop_continuation.text.find("while (nonzero)") != std::string::npos &&
                structured_loop_continuation.text.find("r1 = 0x7;") != std::string::npos &&
                structured_loop_continuation.text.find("return r0;") != std::string::npos &&
                structured_loop_continuation.text.find("goto") == std::string::npos,
            "a pre-tested loop preserves a multi-block straight-line exit continuation");
    const auto structured_loop_ssa = format_structured_pseudocode(loop_ssa.value());
    require(!structured_loop_ssa.used_fallback && structured_loop_ssa.text.find("while (nonzero)") != std::string::npos &&
                structured_loop_ssa.text.find("r0_2 = r0_1;") != std::string::npos &&
                structured_loop_ssa.text.find("r0_2 = r0_3;") != std::string::npos &&
                structured_loop_ssa.text.find("goto") == std::string::npos,
            "a loop-header SSA phi lowers to initialization and back-edge copies around while");

    const Address chain_body{{0}, 0x3070}, chain_middle{{0}, 0x3080}, chain_exit{{0}, 0x3090};
    LiftedFunction chained_loop{FunctionId{21}, loop_entry, {}, {}};
    chained_loop.blocks = {
        {BlockId{61}, chain_middle, {{{chain_middle, 90}, Assign{r1, value(7)}}},
         {{chain_middle, header, BlockId{64}, BlockEdgeKind::jump}}, {}},
        {BlockId{62}, chain_body,
         {{{chain_body, 91}, Assign{r0, std::make_shared<Expression>(Expression{
               {TypeKind::integer, 64, false}, BinaryValue{"add", loop_reg, value(1)}})}},
          {{Address{{0}, 0x3074}, 92}, Branch{"true", chain_middle, {}}}},
         {{chain_body, chain_middle, BlockId{61}, BlockEdgeKind::jump}}, {}},
        {BlockId{63}, loop_entry,
         {{{loop_entry, 93}, Assign{r0, value(0)}},
          {{Address{{0}, 0x3004}, 94}, Branch{"true", header, {}}}},
         {{loop_entry, header, BlockId{64}, BlockEdgeKind::jump}}, {}},
        {BlockId{64}, header, {{{header, 95}, Branch{"keep_going", chain_body, chain_exit}}},
         {{header, chain_body, BlockId{62}, BlockEdgeKind::conditional_true},
          {header, chain_exit, BlockId{65}, BlockEdgeKind::conditional_false}}, {}},
        {BlockId{65}, chain_exit, {{{chain_exit, 96}, Return{loop_reg}}}, {}, {}}
    };
    const auto chained_loop_plain = format_structured_pseudocode(chained_loop);
    require(!chained_loop_plain.used_fallback && chained_loop_plain.text.find("while (keep_going)") != std::string::npos &&
                chained_loop_plain.text.find("0x7;") != std::string::npos &&
                chained_loop_plain.text.find("goto") == std::string::npos,
            "a pre-tested loop with a multi-block straight-line body is structured");
    auto chained_loop_ssa = to_ssa(chained_loop);
    const auto chained_loop_versioned = chained_loop_ssa ? format_structured_pseudocode(chained_loop_ssa.value())
        : StructuredPseudocode{};
    const auto chained_header_phi = chained_loop_ssa && chained_loop_ssa.value().blocks.size() > 3 &&
        !chained_loop_ssa.value().blocks[3].phis.empty()
        ? &chained_loop_ssa.value().blocks[3].phis.front() : nullptr;
    const auto chained_has_phi_input = [&](std::uint32_t predecessor, std::uint32_t version) {
        return chained_header_phi && std::any_of(chained_header_phi->inputs.begin(),
            chained_header_phi->inputs.end(), [&](const auto &input) {
                return input.predecessor == BlockId{predecessor} && input.version == version;
            });
    };
    require(chained_loop_ssa && !chained_loop_versioned.used_fallback &&
                chained_header_phi && chained_header_phi->destination.index == 0 &&
                chained_header_phi->version == 2 && chained_has_phi_input(63, 1) &&
                chained_has_phi_input(61, 3) &&
                chained_loop_versioned.text.find("auto __hexlab_phi_0 = r0_1;") != std::string::npos &&
                chained_loop_versioned.text.find("auto __hexlab_phi_2 = r0_3;") != std::string::npos &&
                chained_loop_versioned.text.find("r0_2 = __hexlab_phi_0;") != std::string::npos &&
                chained_loop_versioned.text.find("r0_2 = __hexlab_phi_2;") != std::string::npos &&
                chained_loop_versioned.text.find("goto") == std::string::npos,
            "multi-block loop SSA phi copies use the actual final latch predecessor");
    auto side_exit_chained_loop = chained_loop;
    std::get<Branch>(side_exit_chained_loop.blocks[1].instructions.back().statement) =
        Branch{"error", chain_middle, chain_exit};
    side_exit_chained_loop.blocks[1].successors.push_back(
        {chain_body, chain_exit, BlockId{65}, BlockEdgeKind::conditional_false});
    const auto rejected_side_exit_loop = format_structured_pseudocode(side_exit_chained_loop);
    require(rejected_side_exit_loop.used_fallback && rejected_side_exit_loop.text.find("goto") != std::string::npos,
            "a multi-block while body with a conditional side exit keeps explicit CFG transfers");
    const Address do_body{{0}, 0x3040}, do_latch{{0}, 0x3050}, do_exit{{0}, 0x3060};
    LiftedFunction do_loop{FunctionId{19}, do_body,
        {{BlockId{50}, do_body, {{{do_body, 34}, Assign{r0, value(1)}},
                                  {{Address{{0}, 0x3044}, 35}, Branch{"true", do_latch, {}}}},
          {{do_body, do_latch, BlockId{51}, BlockEdgeKind::jump}}, {}},
         {BlockId{51}, do_latch, {{{do_latch, 36}, Branch{"ready", do_body, do_exit}}},
          {{do_latch, do_body, BlockId{50}, BlockEdgeKind::conditional_true},
           {do_latch, do_exit, BlockId{52}, BlockEdgeKind::conditional_false}}, {}},
         {BlockId{52}, do_exit, {{{do_exit, 37}, Return{reg}}}, {}, {}}}, {}};
    const auto structured_do_loop = format_structured_pseudocode(do_loop);
    require(!structured_do_loop.used_fallback &&
                structured_do_loop.text.find("do {\n        r0 = 0x1;") != std::string::npos &&
                structured_do_loop.text.find("} while (ready);") != std::string::npos &&
                structured_do_loop.text.find("goto") == std::string::npos,
            "a canonical post-tested reducible loop is emitted as do-while without gotos");
    const Address do_middle{{0}, 0x3048};
    auto chained_do_loop = do_loop;
    std::get<Branch>(chained_do_loop.blocks[0].instructions.back().statement).true_target = do_middle;
    chained_do_loop.blocks[0].successors[0].target = do_middle;
    chained_do_loop.blocks[0].successors[0].block = BlockId{53};
    chained_do_loop.blocks.insert(chained_do_loop.blocks.begin() + 1,
        {BlockId{53}, do_middle,
         {{{do_middle, 38}, Assign{r1, value(2)}},
          {{Address{{0}, 0x304c}, 39}, Branch{"true", do_latch, {}}}},
         {{do_middle, do_latch, BlockId{51}, BlockEdgeKind::jump}}, {}});
    const auto structured_chained_do = format_structured_pseudocode(chained_do_loop);
    require(!structured_chained_do.used_fallback &&
                structured_chained_do.text.find("r0 = 0x1;") != std::string::npos &&
                structured_chained_do.text.find("r1 = 0x2;") != std::string::npos &&
                structured_chained_do.text.find("} while (ready);") != std::string::npos &&
                structured_chained_do.text.find("goto") == std::string::npos,
            "a post-tested loop with a straight-line multi-block body is emitted as do-while");
    auto inverted_do_loop = do_loop;
    auto &do_branch = std::get<Branch>(inverted_do_loop.blocks[1].instructions[0].statement);
    std::swap(do_branch.true_target, do_branch.false_target);
    std::swap(inverted_do_loop.blocks[1].successors[0].target, inverted_do_loop.blocks[1].successors[1].target);
    std::swap(inverted_do_loop.blocks[1].successors[0].block, inverted_do_loop.blocks[1].successors[1].block);
    const auto structured_inverted_do = format_structured_pseudocode(inverted_do_loop);
    require(!structured_inverted_do.used_fallback &&
                structured_inverted_do.text.find("} while (!(ready));") != std::string::npos,
            "a post-tested loop with the back edge on the false arm preserves condition polarity");

    auto unsupported_loop = do_loop;
    unsupported_loop.blocks[0].successors.push_back({do_body, do_exit, BlockId{52}, BlockEdgeKind::jump});
    const auto unsupported_structured_loop = format_structured_pseudocode(unsupported_loop);
    require(unsupported_structured_loop.used_fallback && !unsupported_structured_loop.fallback_reason.empty() &&
                unsupported_structured_loop.text.find("goto") != std::string::npos,
            "a loop with a side exit retains explicit goto fallback");

    Instruction load;
    load.address = entry;
    load.opcode = Opcode::a32_ldr;
    load.operands = {RegisterOperand{RegisterBank::arm32_gpr, 1, 32, false},
                     ArmMemoryOperand{RegisterOperand{RegisterBank::arm32_gpr, 0, 32, false},
                                      std::uint32_t{4}, true, true, false, 32, false, {}}};
    auto arm_block = std::make_shared<BasicBlock>();
    arm_block->id = BlockId{30};
    arm_block->begin = entry;
    arm_block->instructions.push_back(std::make_shared<InstructionFact>(InstructionFact{40, load, {}}));
    FunctionRecord arm_record{FunctionId{11}, entry, {}, {BlockId{30}}, {}, {}, true};
    FunctionSnapshot arm_snapshot;
    arm_snapshot.blocks.push_back(arm_block);
    auto arm_lifted = lift_function(arm_record, arm_snapshot);
    require(arm_lifted && std::holds_alternative<Assign>(arm_lifted.value().blocks[0].instructions[0].statement),
            "A32 load lifts as a register assignment rather than an opaque intrinsic");
    if (arm_lifted && std::holds_alternative<Assign>(arm_lifted.value().blocks[0].instructions[0].statement)) {
        const auto &loaded = std::get<Assign>(arm_lifted.value().blocks[0].instructions[0].statement);
        require(std::holds_alternative<MemoryValue>(loaded.value->value) && loaded.value->type.bits == 32,
                "A32 load retains typed memory semantics");
        require(format_pseudocode(arm_lifted.value()).find("r1 = *[(r0 + 0x4)];") != std::string::npos,
                "A32 immediate offset is represented in rendered memory address");
    }
    auto shifted_load = load;
    shifted_load.operands[1] = ArmMemoryOperand{
        RegisterOperand{RegisterBank::arm32_gpr, 0, 32, false},
        ArmShiftedRegisterOperand{RegisterOperand{RegisterBank::arm32_gpr, 2, 32, false}, ArmShift::lsl, 2, {}},
        true, true, false, 32, false, {}};
    auto shifted_block = std::make_shared<BasicBlock>();
    shifted_block->id = BlockId{31};
    shifted_block->begin = entry;
    shifted_block->instructions.push_back(std::make_shared<InstructionFact>(InstructionFact{41, shifted_load, {}}));
    FunctionRecord shifted_record{FunctionId{12}, entry, {}, {BlockId{31}}, {}, {}, true};
    FunctionSnapshot shifted_snapshot;
    shifted_snapshot.blocks.push_back(shifted_block);
    auto shifted_lifted = lift_function(shifted_record, shifted_snapshot);
    require(shifted_lifted && format_pseudocode(shifted_lifted.value()).find(
                "r1 = *[(r0 + (r2 << 2))];") != std::string::npos,
            "A32 register-offset shift remains explicit in the computed address");

    auto lift_arm_instruction = [&](Instruction arm_instruction, std::uint64_t id) {
        auto block = std::make_shared<BasicBlock>();
        block->id = BlockId{id};
        block->begin = arm_instruction.address;
        block->instructions.push_back(std::make_shared<InstructionFact>(InstructionFact{id, arm_instruction, {}}));
        FunctionRecord record{FunctionId{id}, arm_instruction.address, {}, {BlockId{id}}, {}, {}, true};
        FunctionSnapshot snapshot;
        snapshot.blocks.push_back(block);
        return lift_function(record, snapshot);
    };
    const RegisterOperand arm_r0{RegisterBank::arm32_gpr, 0, 32, false};
    const RegisterOperand arm_r1{RegisterBank::arm32_gpr, 1, 32, false};
    const RegisterOperand arm_r2{RegisterBank::arm32_gpr, 2, 32, false};
    Instruction rsb;
    rsb.address = entry;
    rsb.context = {Architecture::arm, ExecutionMode::a32, ByteOrder::little};
    rsb.opcode = Opcode::a32_rsb;
    rsb.operands = {arm_r0, arm_r1, ImmediateOperand{7, 8, 32, false, {}}};
    rsb.arm.emplace();
    auto rsb_lifted = lift_arm_instruction(rsb, 42);
    require(rsb_lifted && std::holds_alternative<Assign>(rsb_lifted.value().blocks[0].instructions[0].statement),
            "A32 reverse subtract lifts to a typed assignment");
    if (rsb_lifted && std::holds_alternative<Assign>(rsb_lifted.value().blocks[0].instructions[0].statement)) {
        const auto &value = std::get<Assign>(rsb_lifted.value().blocks[0].instructions[0].statement).value;
        require(std::holds_alternative<BinaryValue>(value->value) &&
                    std::get<BinaryValue>(value->value).operation == "sub" &&
                    format_pseudocode(rsb_lifted.value()).find("r0 = (0x7 - r1);") != std::string::npos,
                "A32 RSB reverses the encoded operand order");
    }
    Instruction guarded_add = rsb;
    guarded_add.opcode = Opcode::a32_add;
    guarded_add.operands = {arm_r0, arm_r1, arm_r2};
    guarded_add.condition = 0;
    guarded_add.arm.emplace();
    guarded_add.arm->predicate = ArmPredicate::condition;
    auto guarded_lifted = lift_arm_instruction(guarded_add, 43);
    require(guarded_lifted && format_pseudocode(guarded_lifted.value()).find("arm_guard") != std::string::npos,
            "A32 conditional arithmetic retains an explicit equality guard");

    const Address extension_entry{{0}, 0x4000};
    const RegisterOperand eax{RegisterBank::gpr, 0, 32, false};
    const RegisterOperand bl{RegisterBank::gpr, 3, 8, false};
    auto extension_lift = [&](Opcode opcode, std::uint64_t id, RegisterOperand destination,
                              RegisterOperand source) {
        Instruction extension;
        extension.address = extension_entry;
        extension.opcode = opcode;
        extension.operands = {destination, source};
        auto block = std::make_shared<BasicBlock>();
        block->id = BlockId{id};
        block->begin = extension_entry;
        block->instructions.push_back(std::make_shared<InstructionFact>(InstructionFact{id, extension, {}}));
        FunctionRecord extension_record{FunctionId{id}, extension_entry, {}, {BlockId{id}}, {}, {}, true};
        FunctionSnapshot extension_snapshot;
        extension_snapshot.blocks.push_back(block);
        return lift_function(extension_record, extension_snapshot);
    };
    auto zero_extended = extension_lift(Opcode::movzx, 50, eax, bl);
    require(zero_extended && std::holds_alternative<Assign>(
                zero_extended.value().blocks[0].instructions[0].statement),
            "MOVZX lifts as a register assignment");
    const auto &zero_extension_assign = std::get<Assign>(zero_extended.value().blocks[0].instructions[0].statement);
    require(zero_extension_assign.value->type.bits == 32 &&
                std::holds_alternative<UnaryValue>(zero_extension_assign.value->value) &&
                std::get<UnaryValue>(zero_extension_assign.value->value).operation == "zext",
            "MOVZX explicitly zero-extends its narrow source to the destination width");
    auto sign_extended = extension_lift(Opcode::movsx, 51, eax, bl);
    require(sign_extended && std::holds_alternative<Assign>(
                sign_extended.value().blocks[0].instructions[0].statement),
            "MOVSX lifts as a register assignment");
    const auto &sign_extension_assign = std::get<Assign>(sign_extended.value().blocks[0].instructions[0].statement);
    require(sign_extension_assign.value->type.bits == 32 &&
                std::holds_alternative<UnaryValue>(sign_extension_assign.value->value) &&
                std::get<UnaryValue>(sign_extension_assign.value->value).operation == "sext",
            "MOVSX explicitly sign-extends its narrow source to the destination width");
    const RegisterOperand rax{RegisterBank::gpr, 0, 64, false};
    const RegisterOperand ecx{RegisterBank::gpr, 1, 32, false};
    auto sign_extended_dword = extension_lift(Opcode::movsxd, 52, rax, ecx);
    require(sign_extended_dword && std::holds_alternative<Assign>(
                sign_extended_dword.value().blocks[0].instructions[0].statement),
            "MOVSXD lifts as a register assignment");
    const auto &sign_extension_dword_assign = std::get<Assign>(
        sign_extended_dword.value().blocks[0].instructions[0].statement);
    require(sign_extension_dword_assign.value->type.bits == 64 &&
                std::holds_alternative<UnaryValue>(sign_extension_dword_assign.value->value) &&
                std::get<UnaryValue>(sign_extension_dword_assign.value->value).operation == "sext",
            "MOVSXD explicitly sign-extends its 32-bit source to 64 bits");

    Instruction mips_fp;
    mips_fp.address = Address{{0}, 0x4000};
    mips_fp.context = {Architecture::mips32, ExecutionMode::mips32, ByteOrder::little};
    mips_fp.opcode = Opcode::mips_add_s;
    const RegisterOperand f1{RegisterBank::mips_fpr,1,32,false}, f2{RegisterBank::mips_fpr,2,32,false};
    const RegisterOperand f3{RegisterBank::mips_fpr,3,32,false}, fcsr{RegisterBank::mips_fcsr,0,32,false};
    mips_fp.operands = {f3,f1,f2};
    mips_fp.access = {OperandAccess::write, OperandAccess::read, OperandAccess::read};
    mips_fp.register_reads = {f1,f2,fcsr};
    mips_fp.register_writes = {f3,fcsr};
    auto fp_block = std::make_shared<BasicBlock>();
    fp_block->id = BlockId{400}; fp_block->begin = mips_fp.address;
    fp_block->instructions.push_back(std::make_shared<InstructionFact>(InstructionFact{400,mips_fp,{}}));
    FunctionRecord fp_record{FunctionId{400},mips_fp.address,{}, {fp_block->id},{},{},true};
    FunctionSnapshot fp_snapshot; fp_snapshot.blocks = {fp_block};
    const auto fp_lifted = lift_function(fp_record,fp_snapshot);
    require(fp_lifted && std::holds_alternative<Intrinsic>(fp_lifted.value().blocks[0].instructions[0].statement),
            "MIPS32 ADD.S remains an explicit FPU intrinsic");
    if (fp_lifted && std::holds_alternative<Intrinsic>(fp_lifted.value().blocks[0].instructions[0].statement)) {
        const auto &effect = std::get<Intrinsic>(fp_lifted.value().blocks[0].instructions[0].statement);
        require(effect.operands[0]->type == ValueType{TypeKind::floating,32,false} &&
                    effect.result_type == ValueType{TypeKind::floating,32,false} &&
                    !effect.operands.empty() &&
                    std::holds_alternative<RegisterValue>(effect.operands.back()->value) &&
                    std::get<RegisterValue>(effect.operands.back()->value).reg == fcsr &&
                    effect.register_writes == std::vector<RegisterOperand>{f3,fcsr},
                "COP1 S lifting keeps f32 result types and preserves FCSR effects");
    }
    Instruction mips_double = mips_fp;
    mips_double.opcode = Opcode::mips_add_d;
    const RegisterOperand fdst{RegisterBank::mips_fpr,6,64,false}, fleft{RegisterBank::mips_fpr,2,64,false},
                         fright{RegisterBank::mips_fpr,4,64,false};
    mips_double.operands = {fdst,fleft,fright};
    mips_double.register_reads = {fleft,fright,fcsr};
    mips_double.register_writes = {fdst,fcsr};
    auto double_block = std::make_shared<BasicBlock>();
    double_block->id = BlockId{402}; double_block->begin = mips_double.address;
    double_block->instructions.push_back(std::make_shared<InstructionFact>(InstructionFact{402,mips_double,{}}));
    FunctionRecord double_record{FunctionId{402},mips_double.address,{}, {double_block->id},{},{},true};
    FunctionSnapshot double_snapshot; double_snapshot.blocks = {double_block};
    const auto double_lifted = lift_function(double_record,double_snapshot);
    require(double_lifted && std::holds_alternative<Intrinsic>(double_lifted.value().blocks[0].instructions[0].statement),
            "MIPS32 ADD.D remains an explicit FPU intrinsic");
    if (double_lifted && std::holds_alternative<Intrinsic>(double_lifted.value().blocks[0].instructions[0].statement)) {
        const auto &effect = std::get<Intrinsic>(double_lifted.value().blocks[0].instructions[0].statement);
        require(effect.name == "mips.add.d" && effect.operands[0]->type == ValueType{TypeKind::floating,64,false} &&
                    effect.result_type == ValueType{TypeKind::floating,64,false} &&
                    !effect.operands.empty() &&
                    std::holds_alternative<RegisterValue>(effect.operands.back()->value) &&
                    std::get<RegisterValue>(effect.operands.back()->value).reg == fcsr &&
                    effect.register_writes == std::vector<RegisterOperand>{fdst,fcsr},
                "COP1 D lifting preserves f64 result types and FCSR effects");
    }
    Instruction mips_cvt = mips_fp;
    mips_cvt.opcode = Opcode::mips_cvt_s_d;
    mips_cvt.operands = {f3,fleft};
    mips_cvt.access = {OperandAccess::write, OperandAccess::read};
    mips_cvt.register_reads = {fleft,fcsr};
    mips_cvt.register_writes = {f3,fcsr};
    double_block->instructions.push_back(std::make_shared<InstructionFact>(InstructionFact{403,mips_cvt,{}}));
    const auto conversion_lifted = lift_function(double_record,double_snapshot);
    require(conversion_lifted && std::holds_alternative<Intrinsic>(conversion_lifted.value().blocks[0].instructions[1].statement),
            "MIPS32 CVT.S.D remains an explicit conversion intrinsic");
    if (conversion_lifted && std::holds_alternative<Intrinsic>(conversion_lifted.value().blocks[0].instructions[1].statement)) {
        const auto &effect = std::get<Intrinsic>(conversion_lifted.value().blocks[0].instructions[1].statement);
        require(effect.name == "mips.cvt.s.d" && effect.operands[0]->type == ValueType{TypeKind::floating,32,false} &&
                    effect.operands[1]->type == ValueType{TypeKind::floating,64,false},
                "COP1 conversion lifting retains distinct source and destination precision");
    }
    Instruction mips_cvt_word = mips_fp;
    mips_cvt_word.opcode = Opcode::mips_cvt_w_d;
    const RegisterOperand fword{RegisterBank::mips_fpr,8,32,false};
    mips_cvt_word.operands = {fword,fleft};
    mips_cvt_word.access = {OperandAccess::write, OperandAccess::read};
    mips_cvt_word.register_reads = {fleft,fcsr};
    mips_cvt_word.register_writes = {fword,fcsr};
    double_block->instructions.push_back(std::make_shared<InstructionFact>(InstructionFact{404,mips_cvt_word,{}}));
    const auto word_conversion_lifted = lift_function(double_record,double_snapshot);
    require(word_conversion_lifted && std::holds_alternative<Intrinsic>(word_conversion_lifted.value().blocks[0].instructions[2].statement),
            "MIPS32 CVT.W.D remains an explicit integer-format conversion intrinsic");
    if (word_conversion_lifted && std::holds_alternative<Intrinsic>(word_conversion_lifted.value().blocks[0].instructions[2].statement)) {
        const auto &effect = std::get<Intrinsic>(word_conversion_lifted.value().blocks[0].instructions[2].statement);
        require(effect.name == "mips.cvt.w.d" && effect.operands[0]->type == ValueType{TypeKind::integer,32,false} &&
                    effect.operands[1]->type == ValueType{TypeKind::floating,64,false} &&
                    effect.result_type == ValueType{TypeKind::integer,32,false},
                "COP1 W conversion exposes an integer word result and double input");
    }
    Instruction mips_fbranch = mips_fp;
    mips_fbranch.address = Address{{0},0x4004};
    mips_fbranch.opcode = Opcode::mips_bc1t;
    mips_fbranch.flow = FlowKind::conditional_branch;
    mips_fbranch.direct_target = Address{{0},0x4010};
    mips_fbranch.operands.clear();
    mips_fbranch.delay_slots = 1;
    fp_block->instructions.push_back(std::make_shared<InstructionFact>(InstructionFact{401,mips_fbranch,{}}));
    const auto fbranch_lifted = lift_function(fp_record,fp_snapshot);
    require(fbranch_lifted && std::holds_alternative<Branch>(fbranch_lifted.value().blocks[0].instructions[1].statement) &&
                std::get<Branch>(fbranch_lifted.value().blocks[0].instructions[1].statement).predicate,
            "BC1T lifts as a branch over an explicit FCC0 predicate");
}
