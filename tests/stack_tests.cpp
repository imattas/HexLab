#include "hexlab/analysis/stack.hpp"
#include "hexlab/processors/decoder.hpp"
#include "support/checks.hpp"

#include <memory>

using namespace hexlab;
using namespace hexlab_test;

namespace {
InstructionFact fact(std::uint64_t id, std::uint64_t offset, Opcode opcode,
                     std::vector<Operand> operands = {}, std::vector<OperandAccess> access = {}) {
    Instruction instruction;
    instruction.context = {Architecture::x86_64, ExecutionMode::x86_64};
    instruction.address = {{0}, offset};
    instruction.opcode = opcode;
    instruction.operands = std::move(operands);
    instruction.access = std::move(access);
    return {id, std::move(instruction), {}};
}
RegisterOperand reg(std::uint8_t index) { return {RegisterBank::gpr, index, 64, false}; }
RegisterOperand mips_reg(std::uint8_t index) { return {RegisterBank::mips_gpr, index, 32, false}; }
RegisterOperand mips64_reg(std::uint8_t index) { return {RegisterBank::mips_gpr, index, 64, false}; }
InstructionFact memory_fact(std::uint64_t id, std::uint64_t offset, RegisterOperand base,
                            std::int64_t displacement, std::uint16_t width, OperandAccess access) {
    MemoryOperand memory;
    memory.base = base;
    memory.displacement = displacement;
    memory.data_width = width;
    memory.address_width = 64;
    return fact(id, offset, Opcode::mov, {memory}, {access});
}
std::shared_ptr<const BasicBlock> block(std::uint64_t id, std::uint64_t begin,
                                        std::vector<InstructionFact> instructions,
                                        std::vector<BlockSuccessor> successors = {}) {
    auto result = std::make_shared<BasicBlock>();
    result->id = {id};
    result->begin = {{0}, begin};
    for (auto &instruction : instructions)
        result->instructions.push_back(std::make_shared<const InstructionFact>(std::move(instruction)));
    result->successors = std::move(successors);
    return result;
}

void frame_pointer_and_stack_pointer_aliases() {
    auto entry = block(1, 0x1000,
        {fact(1, 0x1000, Opcode::push, {reg(5)}, {OperandAccess::read}),
         fact(2, 0x1001, Opcode::mov, {reg(5), reg(4)}, {OperandAccess::write, OperandAccess::read}),
         fact(3, 0x1004, Opcode::sub, {reg(4), ImmediateOperand{32, 8, 64, false}},
              {OperandAccess::read_write, OperandAccess::read}),
         memory_fact(4, 0x1008, reg(5), -8, 32, OperandAccess::write),
         memory_fact(5, 0x100c, reg(4), 24, 32, OperandAccess::read)});
    FunctionRecord function;
    function.id = {1};
    function.entry = {{0}, 0x1000};
    function.blocks = {{1}};
    FunctionSnapshot snapshot;
    snapshot.blocks = {entry};
    const auto result = analyze_stack_frame(function, snapshot, {});
    check(result && result.value().complete, "stack analyzer accepts a recovered x64 function");
    check(result && result.value().slots.size() == 1, "frame-pointer and stack-pointer accesses coalesce");
    if (result && !result.value().slots.empty()) {
        const auto &slot = result.value().slots[0];
        check(slot.offset_from_entry_sp == -16 && slot.width == 32,
              "local stack slot has a stable entry-SP-relative offset");
        check(slot.read && slot.written && slot.accesses == std::vector<Address>{{{0}, 0x1008}, {{0}, 0x100c}},
              "slot retains read/write use and source instruction addresses");
    }
}

void ambiguous_control_flow_does_not_invent_offsets() {
    auto edge = [](std::uint64_t source, std::uint64_t target) {
        return BlockSuccessor{{{0}, source}, Address{{0}, target}, BlockId{target}, BlockEdgeKind::jump};
    };
    auto entry = block(1, 0x2000,
        {fact(1, 0x2000, Opcode::sub, {reg(4), ImmediateOperand{16, 8, 64, false}},
              {OperandAccess::read_write, OperandAccess::read})},
        {edge(0x2000, 0x2010), edge(0x2000, 0x2020)});
    auto left = block(0x2010, 0x2010,
        {fact(2, 0x2010, Opcode::sub, {reg(4), ImmediateOperand{8, 8, 64, false}},
              {OperandAccess::read_write, OperandAccess::read})},
        {edge(0x2010, 0x2030)});
    auto right = block(0x2020, 0x2020,
        {fact(3, 0x2020, Opcode::sub, {reg(4), ImmediateOperand{16, 8, 64, false}},
              {OperandAccess::read_write, OperandAccess::read})},
        {edge(0x2020, 0x2030)});
    auto join = block(0x2030, 0x2030,
        {memory_fact(4, 0x2030, reg(4), 8, 32, OperandAccess::write)});
    FunctionRecord function;
    function.id = {2};
    function.entry = {{0}, 0x2000};
    function.blocks = {{1}, {0x2010}, {0x2020}, {0x2030}};
    FunctionSnapshot snapshot;
    snapshot.blocks = {entry, left, right, join};
    const auto result = analyze_stack_frame(function, snapshot, {});
    check(result && result.value().slots.empty(), "incompatible stack depths at a join suppress false stack slots");
    check(result && !result.value().complete, "ambiguous incoming stack state is reported as partial");
}

void x86_32_argument_offset() {
    const DecodeContext context{Architecture::x86, ExecutionMode::x86_32};
    auto reg32 = [](std::uint8_t index) { return RegisterOperand{RegisterBank::gpr, index, 32, false}; };
    auto push = fact(1, 0x3000, Opcode::push, {reg32(5)}, {OperandAccess::read});
    push.instruction.context = context;
    push.instruction.stack_value_width = 32;
    auto establish = fact(2, 0x3001, Opcode::mov, {reg32(5), reg32(4)},
                          {OperandAccess::write, OperandAccess::read});
    establish.instruction.context = context;
    auto load = memory_fact(3, 0x3003, reg32(5), 8, 32, OperandAccess::read);
    load.instruction.context = context;
    auto entry = block(1, 0x3000, {push, establish, load});
    FunctionRecord function;
    function.id = {3};
    function.entry = {{0}, 0x3000};
    function.blocks = {{1}};
    FunctionSnapshot snapshot;
    snapshot.blocks = {entry};
    const auto result = analyze_stack_frame(function, snapshot, {});
    check(result && result.value().slots.size() == 1 && result.value().slots[0].offset_from_entry_sp == 4,
          "x86-32 frame pointer resolves the first stack argument from entry SP");
}

void x86_16_argument_offset() {
    const DecodeContext context{Architecture::x86, ExecutionMode::x86_16};
    auto reg16 = [](std::uint8_t index) { return RegisterOperand{RegisterBank::gpr, index, 16, false}; };
    auto push = fact(1, 0x4000, Opcode::push, {reg16(5)}, {OperandAccess::read});
    push.instruction.context = context;
    push.instruction.stack_value_width = 16;
    auto establish = fact(2, 0x4001, Opcode::mov, {reg16(5), reg16(4)},
                          {OperandAccess::write, OperandAccess::read});
    establish.instruction.context = context;
    auto load = memory_fact(3, 0x4003, reg16(5), 4, 16, OperandAccess::read);
    load.instruction.context = context;
    auto entry = block(1, 0x4000, {push, establish, load});
    FunctionRecord function;
    function.id = {4};
    function.entry = {{0}, 0x4000};
    function.blocks = {{1}};
    FunctionSnapshot snapshot;
    snapshot.blocks = {entry};
    const auto result = analyze_stack_frame(function, snapshot, {});
    check(result && result.value().slots.size() == 1 && result.value().slots[0].offset_from_entry_sp == 2,
          "x86-16 frame pointer resolves stack arguments in its value width");
}

InstructionFact decoded_x86_fact(std::uint64_t id, std::uint64_t offset, DecodeContext context,
                                  std::initializer_list<unsigned> bytes) {
    std::vector<std::byte> raw;
    for (const auto value : bytes)
        raw.push_back(static_cast<std::byte>(value));
    const auto decoded = decode_instruction(context, raw, {{0}, offset});
    check(decoded.instruction.has_value(), "authored x86 instruction decodes for stack integration fixture");
    if (!decoded.instruction)
        throw std::runtime_error(decoded.reason);
    return {id, *decoded.instruction, {}};
}

void x86_lea_frames_and_address_taken_locals() {
    const DecodeContext x16{Architecture::x86, ExecutionMode::x86_16};
    auto function = [&](std::uint64_t entry, std::vector<InstructionFact> instructions) {
        auto body = block(1, entry, std::move(instructions));
        FunctionRecord record;
        record.id = {1};
        record.entry = {{0}, entry};
        record.blocks = {{1}};
        FunctionSnapshot snapshot;
        snapshot.blocks = {std::move(body)};
        return analyze_stack_frame(record, snapshot, {});
    };

    auto result16 = function(0x4100,
        {decoded_x86_fact(1, 0x4100, x16, {0x55}),
         decoded_x86_fact(2, 0x4101, x16, {0x89, 0xe5}),
         decoded_x86_fact(3, 0x4103, x16, {0x8d, 0x46, 0xfc}),
         decoded_x86_fact(4, 0x4106, x16, {0x89, 0x46, 0xfc}),
         decoded_x86_fact(5, 0x4109, x16, {0xc3})});
    check(result16 && result16.value().slots.size() == 1 &&
              result16.value().slots[0].offset_from_entry_sp == -6 && result16.value().slots[0].width == 16 &&
              result16.value().slots[0].address_taken && result16.value().slots[0].written &&
              result16.value().slots[0].accesses == std::vector<Address>{{{0}, 0x4103}, {{0}, 0x4106}},
          "x86-16 LEA of a BP-relative local coalesces address and data uses at an entry-SP offset");
    check(result16 && result16.value().complete, "x86-16 supported frame flow remains complete");

    const DecodeContext x32{Architecture::x86, ExecutionMode::x86_32};
    auto result32 = function(0x4200,
        {decoded_x86_fact(1, 0x4200, x32, {0x8d, 0x6c, 0x24, 0x08}),
         decoded_x86_fact(2, 0x4204, x32, {0x8d, 0x45, 0xec}),
         decoded_x86_fact(3, 0x4207, x32, {0x89, 0x45, 0xec}),
         decoded_x86_fact(4, 0x420a, x32, {0x8d, 0x65, 0xf8}),
         decoded_x86_fact(5, 0x420d, x32, {0x8b, 0x44, 0x24, 0xf4}),
         decoded_x86_fact(6, 0x4211, x32, {0xc3})});
    check(result32 && result32.value().slots.size() == 1 &&
              result32.value().slots[0].offset_from_entry_sp == -12 && result32.value().slots[0].width == 32 &&
              result32.value().slots[0].address_taken && result32.value().slots[0].read &&
              result32.value().slots[0].written && result32.value().slots[0].accesses.size() == 3,
          "x86-32 LEA setup/restoration coalesces address, write, and later ESP-relative read");
    check(result32 && result32.value().complete, "x86-32 supported frame flow remains complete");

    const DecodeContext x64{Architecture::x86_64, ExecutionMode::x86_64};
    auto result64 = function(0x4300,
        {decoded_x86_fact(1, 0x4300, x64, {0x48, 0x8d, 0x6c, 0x24, 0x10}),
         decoded_x86_fact(2, 0x4305, x64, {0x48, 0x8d, 0x45, 0xe0}),
         decoded_x86_fact(3, 0x4309, x64, {0x48, 0x89, 0x45, 0xe0}),
         decoded_x86_fact(4, 0x430d, x64, {0x48, 0x8d, 0x65, 0xf0}),
         decoded_x86_fact(5, 0x4311, x64, {0x48, 0x8b, 0x44, 0x24, 0xf0}),
         decoded_x86_fact(6, 0x4316, x64, {0xc3})});
    check(result64 && result64.value().slots.size() == 1 &&
              result64.value().slots[0].offset_from_entry_sp == -16 && result64.value().slots[0].width == 64 &&
              result64.value().slots[0].address_taken && result64.value().slots[0].read &&
              result64.value().slots[0].written && result64.value().slots[0].accesses.size() == 3,
          "x86-64 LEA setup/restoration coalesces address, write, and later RSP-relative read");
    check(result64 && result64.value().complete, "x86-64 supported frame flow remains complete");

    auto address_only = function(0x4400,
        {decoded_x86_fact(1, 0x4400, x32, {0x89, 0xe5}),
         decoded_x86_fact(2, 0x4402, x32, {0x8d, 0x45, 0xf0}),
         decoded_x86_fact(3, 0x4405, x32, {0xc3})});
    check(address_only && address_only.value().slots.size() == 1 &&
              address_only.value().slots[0].width == 0 && address_only.value().slots[0].address_taken &&
              !address_only.value().slots[0].read && !address_only.value().slots[0].written &&
              address_only.value().slots[0].accesses == std::vector<Address>{{{0}, 0x4402}},
          "address-only stack locations retain unknown size and their LEA site");
}

InstructionFact a64_fact(std::uint64_t id, std::uint64_t offset, Opcode opcode,
                         std::vector<Operand> operands = {}, std::vector<OperandAccess> access = {}) {
    auto result = fact(id, offset, opcode, std::move(operands), std::move(access));
    result.instruction.context = {Architecture::arm64, ExecutionMode::a64};
    return result;
}
RegisterOperand a64_reg(std::uint8_t index, RegisterBank bank = RegisterBank::arm64_gpr) {
    return {bank, index, 64, false};
}
InstructionFact a64_memory_fact(std::uint64_t id, std::uint64_t offset, std::int64_t displacement,
                                std::uint16_t width, OperandAccess access) {
    MemoryOperand memory;
    memory.base = a64_reg(31, RegisterBank::arm64_sp);
    memory.displacement = displacement;
    memory.data_width = width;
    memory.address_width = 64;
    return a64_fact(id, offset, Opcode::a64_ldr, {memory}, {access});
}

void aarch64_sp_relative_slots() {
    const auto sp = a64_reg(31, RegisterBank::arm64_sp);
    auto entry = block(1, 0x5000,
        {a64_fact(1, 0x5000, Opcode::a64_sub,
                  {sp, sp, ImmediateOperand{32, 12, 64, false, {}}},
                  {OperandAccess::write, OperandAccess::read, OperandAccess::read}),
         a64_memory_fact(2, 0x5004, 16, 64, OperandAccess::write),
         a64_fact(3, 0x5008, Opcode::a64_add,
                  {sp, sp, ImmediateOperand{16, 12, 64, false, {}}},
                  {OperandAccess::write, OperandAccess::read, OperandAccess::read}),
         a64_memory_fact(4, 0x500c, 0, 64, OperandAccess::read)});
    FunctionRecord function;
    function.id = {1};
    function.entry = {{0}, 0x5000};
    function.blocks = {{1}};
    FunctionSnapshot snapshot;
    snapshot.blocks = {entry};
    const auto result = analyze_stack_frame(function, snapshot, {});
    check(result && result.value().complete, "AArch64 SP adjustment forms are modeled precisely");
    check(result && result.value().slots.size() == 1 && result.value().slots[0].offset_from_entry_sp == -16,
          "AArch64 SP loads and stores resolve to entry-relative slots and coalesce");
    check(result && result.value().slots.size() == 1 && result.value().slots[0].read &&
              result.value().slots[0].written && result.value().slots[0].accesses.size() == 2,
          "AArch64 stack slot keeps both access kinds and sites");
}

void aarch64_frame_pointer_slots() {
    const auto sp = a64_reg(31, RegisterBank::arm64_sp);
    const auto fp = a64_reg(29);
    MemoryOperand frame_slot;
    frame_slot.base = fp;
    frame_slot.displacement = -8;
    frame_slot.data_width = 64;
    frame_slot.address_width = 64;
    auto entry = block(1, 0x5800,
        {a64_fact(1, 0x5800, Opcode::a64_sub,
                  {sp, sp, ImmediateOperand{32, 12, 64, false, {}}},
                  {OperandAccess::write, OperandAccess::read, OperandAccess::read}),
         a64_fact(2, 0x5804, Opcode::a64_add,
                  {fp, sp, ImmediateOperand{16, 12, 64, false, {}}},
                  {OperandAccess::write, OperandAccess::read, OperandAccess::read}),
         a64_fact(3, 0x5808, Opcode::a64_ldr, {frame_slot}, {OperandAccess::write}),
         a64_memory_fact(4, 0x580c, 8, 64, OperandAccess::read),
         a64_fact(5, 0x5810, Opcode::a64_add,
                  {sp, fp, ImmediateOperand{16, 12, 64, false, {}}},
                  {OperandAccess::write, OperandAccess::read, OperandAccess::read}),
         a64_memory_fact(6, 0x5814, -8, 64, OperandAccess::read)});
    FunctionRecord function;
    function.id = {4};
    function.entry = {{0}, 0x5800};
    function.blocks = {{1}};
    FunctionSnapshot snapshot;
    snapshot.blocks = {entry};
    const auto result = analyze_stack_frame(function, snapshot, {});
    check(result && result.value().complete, "AArch64 frame-pointer setup and SP restoration remain precise");
    check(result && result.value().slots.size() == 2,
          "AArch64 x29 and SP accesses resolve to entry-relative stack slots");
    if (result && result.value().slots.size() == 2) {
        check(result.value().slots[0].offset_from_entry_sp == -24 &&
                  result.value().slots[0].read && result.value().slots[0].written &&
                  result.value().slots[0].accesses == std::vector<Address>{{{0}, 0x5808}, {{0}, 0x580c}},
              "AArch64 frame-pointer and stack-pointer accesses to one local coalesce");
        check(result.value().slots[1].offset_from_entry_sp == -8 && result.value().slots[1].read,
              "AArch64 SP restored from x29 keeps its entry-relative relation");
    }
}

void aarch64_unsupported_stack_write_is_partial() {
    const auto sp = a64_reg(31, RegisterBank::arm64_sp);
    auto entry = block(1, 0x6000,
        {a64_fact(1, 0x6000, Opcode::a64_add,
                  {sp, a64_reg(0), ImmediateOperand{16, 12, 64, false, {}}},
                  {OperandAccess::write, OperandAccess::read, OperandAccess::read}),
         a64_memory_fact(2, 0x6004, 0, 64, OperandAccess::write)});
    FunctionRecord function;
    function.id = {2};
    function.entry = {{0}, 0x6000};
    function.blocks = {{1}};
    FunctionSnapshot snapshot;
    snapshot.blocks = {entry};
    const auto result = analyze_stack_frame(function, snapshot, {});
    check(result && !result.value().complete, "unsupported AArch64 SP writes mark stack analysis incomplete");
    check(result && result.value().slots.empty(), "unknown AArch64 SP values never invent local offsets");

    auto terminal = block(1, 0x6000,
        {a64_fact(1, 0x6000, Opcode::a64_add,
                  {sp, a64_reg(0), ImmediateOperand{16, 12, 64, false, {}}},
                  {OperandAccess::write, OperandAccess::read, OperandAccess::read})});
    snapshot.blocks = {terminal};
    const auto terminal_result = analyze_stack_frame(function, snapshot, {});
    check(terminal_result && !terminal_result.value().complete,
          "unsupported terminal SP write is reported partial even without later memory access");

    MemoryOperand frame_memory;
    frame_memory.base = a64_reg(29);
    frame_memory.displacement = -8;
    frame_memory.data_width = 64;
    auto frame_reference = block(1, 0x6000,
        {a64_fact(1, 0x6000, Opcode::a64_ldr, {frame_memory}, {OperandAccess::read})});
    snapshot.blocks = {frame_reference};
    const auto frame_result = analyze_stack_frame(function, snapshot, {});
    check(frame_result && !frame_result.value().complete,
          "unmodeled AArch64 frame-register memory references are explicitly partial");

    auto restore_untracked_frame = block(1, 0x6080,
        {a64_fact(1, 0x6080, Opcode::a64_add,
                  {sp, a64_reg(29), ImmediateOperand{16, 12, 64, false, {}}},
                  {OperandAccess::write, OperandAccess::read, OperandAccess::read})});
    snapshot.blocks = {restore_untracked_frame};
    function.entry = {{0}, 0x6080};
    const auto untracked_restore_result = analyze_stack_frame(function, snapshot, {});
    check(untracked_restore_result && !untracked_restore_result.value().complete,
          "restoring SP from an untracked x29 remains conservatively partial");

    const auto fp = a64_reg(29);
    MemoryOperand clobbered_frame_memory;
    clobbered_frame_memory.base = fp;
    clobbered_frame_memory.displacement = -8;
    clobbered_frame_memory.data_width = 64;
    auto clobbered_frame = block(1, 0x6100,
        {a64_fact(1, 0x6100, Opcode::a64_sub,
                  {sp, sp, ImmediateOperand{32, 12, 64, false, {}}},
                  {OperandAccess::write, OperandAccess::read, OperandAccess::read}),
         a64_fact(2, 0x6104, Opcode::a64_add,
                  {fp, sp, ImmediateOperand{16, 12, 64, false, {}}},
                  {OperandAccess::write, OperandAccess::read, OperandAccess::read}),
         a64_fact(3, 0x6108, Opcode::a64_add,
                  {fp, a64_reg(0), ImmediateOperand{8, 12, 64, false, {}}},
                  {OperandAccess::write, OperandAccess::read, OperandAccess::read}),
         a64_fact(4, 0x610c, Opcode::a64_ldr, {clobbered_frame_memory}, {OperandAccess::read})});
    snapshot.blocks = {clobbered_frame};
    function.entry = {{0}, 0x6100};
    const auto clobbered_result = analyze_stack_frame(function, snapshot, {});
    check(clobbered_result && !clobbered_result.value().complete && clobbered_result.value().slots.empty(),
          "an unmodeled x29 write invalidates its frame relation without inventing a slot");
}

void aarch64_conflicting_join_is_partial() {
    const auto sp = a64_reg(31, RegisterBank::arm64_sp);
    auto edge = [](std::uint64_t source, std::uint64_t target) {
        return BlockSuccessor{{{0}, source}, Address{{0}, target}, BlockId{target}, BlockEdgeKind::jump};
    };
    auto entry = block(1, 0x7000, {}, {edge(0x7000, 0x7010), edge(0x7000, 0x7020)});
    auto left = block(0x7010, 0x7010,
        {a64_fact(1, 0x7010, Opcode::a64_sub,
                  {sp, sp, ImmediateOperand{16, 12, 64, false, {}}},
                  {OperandAccess::write, OperandAccess::read, OperandAccess::read})},
        {edge(0x7010, 0x7030)});
    auto right = block(0x7020, 0x7020,
        {a64_fact(2, 0x7020, Opcode::a64_sub,
                  {sp, sp, ImmediateOperand{32, 12, 64, false, {}}},
                  {OperandAccess::write, OperandAccess::read, OperandAccess::read})},
        {edge(0x7020, 0x7030)});
    auto join = block(0x7030, 0x7030, {a64_memory_fact(3, 0x7030, 0, 64, OperandAccess::write)});
    FunctionRecord function;
    function.id = {3};
    function.entry = {{0}, 0x7000};
    function.blocks = {{1}, {0x7010}, {0x7020}, {0x7030}};
    FunctionSnapshot snapshot;
    snapshot.blocks = {entry, left, right, join};
    const auto result = analyze_stack_frame(function, snapshot, {});
    check(result && !result.value().complete, "conflicting AArch64 SP depths at a join mark the result partial");
    check(result && result.value().slots.empty(), "conflicting AArch64 SP depths suppress guessed joined slots");
}

InstructionFact arm32_fact(std::uint64_t id, std::uint64_t offset, Opcode opcode,
                           std::vector<Operand> operands = {}, std::vector<OperandAccess> access = {},
                           ExecutionMode mode = ExecutionMode::a32) {
    auto result = fact(id, offset, opcode, std::move(operands), std::move(access));
    result.instruction.context = {Architecture::arm, mode};
    return result;
}
RegisterOperand arm32_reg(std::uint8_t index) { return {RegisterBank::arm32_gpr, index, 32, false}; }
InstructionFact arm32_memory_fact(std::uint64_t id, std::uint64_t offset, RegisterOperand base,
                                  std::uint32_t displacement, OperandAccess access) {
    ArmMemoryOperand memory{base};
    memory.offset = displacement;
    memory.data_width = 32;
    return arm32_fact(id, offset, Opcode::a32_str, {arm32_reg(0), memory},
                      {OperandAccess::read, access});
}
void arm32_sp_relative_slots() {
    const auto sp = arm32_reg(13), fp = arm32_reg(11);
    auto entry = block(1, 0x8000,
        {arm32_fact(1, 0x8000, Opcode::a32_sub,
                    {sp, sp, ImmediateOperand{16, 8, 32, false}},
                    {OperandAccess::write, OperandAccess::read, OperandAccess::read}),
         arm32_fact(2, 0x8004, Opcode::a32_mov, {fp, sp},
                    {OperandAccess::write, OperandAccess::read}),
         arm32_memory_fact(3, 0x8008, fp, 4, OperandAccess::write),
         arm32_memory_fact(4, 0x800c, sp, 4, OperandAccess::read),
         arm32_fact(5, 0x8010, Opcode::a32_add,
                    {sp, sp, ImmediateOperand{16, 8, 32, false}},
                    {OperandAccess::write, OperandAccess::read, OperandAccess::read})});
    FunctionRecord function;
    function.id = {5};
    function.entry = {{0}, 0x8000};
    function.blocks = {{1}};
    FunctionSnapshot snapshot;
    snapshot.blocks = {entry};
    const auto result = analyze_stack_frame(function, snapshot, {});
    check(result && result.value().complete, "A32 SP and frame-register tracking is supported");
    check(result && result.value().slots.size() == 1 && result.value().slots[0].offset_from_entry_sp == -12,
          "A32 frame and stack pointers resolve the same local slot relative to entry SP");
    check(result && result.value().slots.size() == 1 && result.value().slots[0].read &&
              result.value().slots[0].written && result.value().slots[0].accesses.size() == 2,
          "A32 stack slot coalesces read/write sites");
}
void arm32_multiple_save_and_thumb_slots() {
    const auto sp = arm32_reg(13), fp = arm32_reg(11);
    auto save = arm32_fact(1, 0x9000, Opcode::a32_stm,
                           {sp, ArmRegisterListOperand{static_cast<std::uint16_t>((1u << 11) | (1u << 14))}},
                           {OperandAccess::read_write, OperandAccess::read});
    save.instruction.arm = ArmInstructionInfo{};
    save.instruction.arm->multiple_mode = ArmMultipleMode::db;
    save.instruction.arm->writeback = true;
    auto arm_local = arm32_memory_fact(4, 0x900c, fp, 4, OperandAccess::write);
    std::get<ArmMemoryOperand>(arm_local.instruction.operands[1]).add = false;
    auto thumb_entry = block(1, 0xa000,
        {arm32_fact(2, 0xa000, Opcode::a32_sub,
                    {sp, sp, ImmediateOperand{8, 7, 32, false}},
                    {OperandAccess::write, OperandAccess::read, OperandAccess::read}, ExecutionMode::thumb),
         arm32_memory_fact(3, 0xa002, sp, 4, OperandAccess::write)});
    auto entry = block(1, 0x9000,
        {save,
         arm32_fact(2, 0x9004, Opcode::a32_mov, {fp, sp},
                    {OperandAccess::write, OperandAccess::read}),
         arm32_fact(3, 0x9008, Opcode::a32_sub,
                    {sp, sp, ImmediateOperand{16, 8, 32, false}},
                    {OperandAccess::write, OperandAccess::read, OperandAccess::read}),
         arm_local});
    FunctionRecord function;
    function.id = {6}; function.entry = {{0}, 0x9000}; function.blocks = {{1}};
    FunctionSnapshot snapshot; snapshot.blocks = {entry};
    const auto saved = analyze_stack_frame(function, snapshot, {});
    check(saved && saved.value().complete && saved.value().slots.size() == 3,
          "A32 STMDB stack saves and local accesses are recovered");
    if (saved && saved.value().slots.size() == 3) {
        check(saved.value().slots[0].offset_from_entry_sp == -12 &&
                  saved.value().slots[1].offset_from_entry_sp == -8 &&
                  saved.value().slots[2].offset_from_entry_sp == -4,
              "A32 multiple-store registers map to increasing memory offsets");
    }
    snapshot.blocks = {thumb_entry};
    function.entry = {{0}, 0xa000};
    const auto thumb = analyze_stack_frame(function, snapshot, {});
    check(thumb && thumb.value().complete && thumb.value().slots.size() == 1 &&
              thumb.value().slots[0].offset_from_entry_sp == -4,
          "Thumb SP adjustment and direct stack access use the shared ARM32 model");
}
void arm32_arithmetic_frame_pointer_setup() {
    auto make_function = [](ExecutionMode mode, std::uint64_t address) {
        auto entry = block(1, address,
            {arm32_fact(1, address, Opcode::a32_sub,
                        {arm32_reg(13), arm32_reg(13), ImmediateOperand{16, 8, 32, false}},
                        {OperandAccess::write, OperandAccess::read, OperandAccess::read}, mode),
             arm32_fact(2, address + 4, Opcode::a32_add,
                        {arm32_reg(7), arm32_reg(13), ImmediateOperand{8, 8, 32, false}},
                        {OperandAccess::write, OperandAccess::read, OperandAccess::read}, mode),
             arm32_memory_fact(3, address + 8, arm32_reg(7), 4, OperandAccess::write),
             arm32_fact(4, address + 12, Opcode::a32_sub,
                        {arm32_reg(11), arm32_reg(7), ImmediateOperand{4, 8, 32, false}},
                        {OperandAccess::write, OperandAccess::read, OperandAccess::read}, mode),
             arm32_memory_fact(5, address + 16, arm32_reg(11), 0, OperandAccess::read)});
        FunctionRecord function;
        function.id = {8}; function.entry = {{0}, address}; function.blocks = {{1}};
        FunctionSnapshot snapshot; snapshot.blocks = {entry};
        return analyze_stack_frame(function, snapshot, {});
    };
    for (const auto &[mode, address] : {std::pair{ExecutionMode::a32, std::uint64_t{0xc000}},
                                         std::pair{ExecutionMode::thumb, std::uint64_t{0xc100}}}) {
        const auto result = make_function(mode, address);
        check(result && result.value().complete && result.value().slots.size() == 2,
              "A32/Thumb ADD/SUB frame setup keeps local-slot analysis complete");
        check(result && result.value().slots.size() == 2 &&
                  result.value().slots[0].offset_from_entry_sp == -12 &&
                  result.value().slots[1].offset_from_entry_sp == -4,
              "A32/Thumb arithmetic frame pointers resolve entry-SP-relative local offsets");
    }
}
void arm32_unknown_sp_effects_are_partial() {
    const auto sp = arm32_reg(13), source = arm32_reg(0);
    auto dynamic = arm32_memory_fact(1, 0xb000, sp, 0, OperandAccess::write);
    auto &memory = std::get<ArmMemoryOperand>(dynamic.instruction.operands[1]);
    memory.offset = ArmShiftedRegisterOperand{source, ArmShift::lsl, 2, {}};
    auto entry = block(1, 0xb000, {dynamic});
    FunctionRecord function; function.id = {7}; function.entry = {{0}, 0xb000}; function.blocks = {{1}};
    FunctionSnapshot snapshot; snapshot.blocks = {entry};
    const auto indexed = analyze_stack_frame(function, snapshot, {});
    check(indexed && !indexed.value().complete && indexed.value().slots.empty(),
          "register-derived ARM32 stack offsets do not invent local locations");
    auto write_sp = arm32_fact(2, 0xb100, Opcode::a32_add,
                               {sp, source, ImmediateOperand{16, 8, 32, false}},
                               {OperandAccess::write, OperandAccess::read, OperandAccess::read});
    entry = block(1, 0xb100, {write_sp}); snapshot.blocks = {entry}; function.entry = {{0}, 0xb100};
    const auto changed = analyze_stack_frame(function, snapshot, {});
    check(changed && !changed.value().complete,
          "register-derived ARM32 SP changes invalidate the symbolic stack relation");
}

void mips32_stack_and_frame_pointer_slots() {
    auto make = [](std::uint64_t address, bool clobber) {
        auto mips_fact = [address](std::uint64_t id, std::uint64_t at, Opcode op,
                                   std::vector<Operand> operands, std::vector<OperandAccess> access) {
            Instruction i; i.context = {Architecture::mips32, ExecutionMode::mips32};
            i.address = {{0}, at}; i.opcode = op; i.operands = std::move(operands); i.access = std::move(access);
            return InstructionFact{id, std::move(i), {}};
        };
        auto entry = block(1, address, {
            mips_fact(1, address, Opcode::mips_addiu,
                      {mips_reg(29), mips_reg(29), ImmediateOperand{UINT32_C(0xffffffe0), 16, 32, true}},
                      {OperandAccess::write, OperandAccess::read, OperandAccess::read}),
            mips_fact(2, address + 4, Opcode::mips_addiu,
                      {mips_reg(30), mips_reg(29), ImmediateOperand{16, 16, 32, true}},
                      {OperandAccess::write, OperandAccess::read, OperandAccess::read}),
            mips_fact(3, address + 8, Opcode::mips_sw,
                      {mips_reg(2), MemoryOperand{32, 32, {}, mips_reg(29), {}, 1, 8, false, {}, {}}},
                      {OperandAccess::read, OperandAccess::write}),
            mips_fact(4, address + 12, Opcode::mips_lw,
                      {mips_reg(3), MemoryOperand{32, 32, {}, mips_reg(30), {}, 1, -8, false, {}, {}}},
                      {OperandAccess::write, OperandAccess::read}),
            mips_fact(5, address + 16, Opcode::mips_addiu,
                      {mips_reg(29), clobber ? mips_reg(2) : mips_reg(30), ImmediateOperand{0, 16, 32, true}},
                      {OperandAccess::write, OperandAccess::read, OperandAccess::read})
        });
        FunctionRecord function; function.id = {9}; function.entry = {{0}, address}; function.blocks = {{1}};
        FunctionSnapshot snapshot; snapshot.blocks = {entry};
        return analyze_stack_frame(function, snapshot, {});
    };
    const auto result = make(0xd000, false);
    check(result && result.value().complete && result.value().slots.size() == 1,
          "MIPS32 stack/frame register setup recovers local slots completely");
    check(result && result.value().slots.size() == 1 && result.value().slots[0].offset_from_entry_sp == -24 &&
              result.value().slots[0].read && result.value().slots[0].written &&
              result.value().slots[0].accesses == std::vector<Address>{{{0}, 0xd008}, {{0}, 0xd00c}},
          "MIPS32 SP and FP references coalesce at their entry-SP-relative offset");
    const auto unknown = make(0xd100, true);
    check(unknown && !unknown.value().complete && unknown.value().slots.size() == 1,
          "MIPS32 unknown SP writes preserve observed slots while marking analysis partial");
}

void mips64_stack_and_frame_pointer_slots() {
    const std::uint64_t address = 0xd200;
    const auto mips_fact = [address](std::uint64_t id, std::uint64_t at, Opcode op,
                                     std::vector<Operand> operands, std::vector<OperandAccess> access) {
        Instruction i; i.context = {Architecture::mips64, ExecutionMode::mips64};
        i.address = {{0}, at}; i.opcode = op; i.operands = std::move(operands); i.access = std::move(access);
        return InstructionFact{id, std::move(i), {}};
    };
    auto entry = block(1, address, {
        mips_fact(1, address, Opcode::mips64_daddiu,
                  {mips64_reg(29), mips64_reg(29), ImmediateOperand{UINT64_C(0xffffffffffffffe0), 16, 64, true}},
                  {OperandAccess::write, OperandAccess::read, OperandAccess::read}),
        mips_fact(2, address + 4, Opcode::mips64_daddiu,
                  {mips64_reg(30), mips64_reg(29), ImmediateOperand{16, 16, 64, true}},
                  {OperandAccess::write, OperandAccess::read, OperandAccess::read}),
        mips_fact(3, address + 8, Opcode::mips64_sd,
                  {mips64_reg(2), MemoryOperand{64, 64, {}, mips64_reg(29), {}, 1, 8, false, {}, {}}},
                  {OperandAccess::read, OperandAccess::write}),
        mips_fact(4, address + 12, Opcode::mips64_ld,
                  {mips64_reg(3), MemoryOperand{64, 64, {}, mips64_reg(30), {}, 1, -8, false, {}, {}}},
                  {OperandAccess::write, OperandAccess::read}),
        mips_fact(5, address + 16, Opcode::mips64_daddiu,
                  {mips64_reg(29), mips64_reg(30), ImmediateOperand{0, 16, 64, true}},
                  {OperandAccess::write, OperandAccess::read, OperandAccess::read})
    });
    FunctionRecord function; function.id = {10}; function.entry = {{0}, address}; function.blocks = {{1}};
    FunctionSnapshot snapshot; snapshot.blocks = {entry};
    const auto result = analyze_stack_frame(function, snapshot, {});
    check(result && result.value().complete && result.value().slots.size() == 1,
          "MIPS64 DADDIU stack/frame setup recovers local slots completely");
    check(result && result.value().slots.size() == 1 && result.value().slots[0].offset_from_entry_sp == -24 &&
              result.value().slots[0].read && result.value().slots[0].written,
          "MIPS64 LD/SD through SP and FP coalesce at one entry-SP-relative slot");
}

} // namespace

int main() {
    return run([] {
        frame_pointer_and_stack_pointer_aliases();
        ambiguous_control_flow_does_not_invent_offsets();
        x86_32_argument_offset();
        x86_16_argument_offset();
        x86_lea_frames_and_address_taken_locals();
        aarch64_sp_relative_slots();
        aarch64_frame_pointer_slots();
        aarch64_unsupported_stack_write_is_partial();
        aarch64_conflicting_join_is_partial();
        arm32_sp_relative_slots();
        arm32_multiple_save_and_thumb_slots();
        arm32_arithmetic_frame_pointer_setup();
        arm32_unknown_sp_effects_are_partial();
        mips32_stack_and_frame_pointer_slots();
        mips64_stack_and_frame_pointer_slots();
    });
}
