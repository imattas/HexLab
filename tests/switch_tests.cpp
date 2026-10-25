#include "hexlab/analysis/switches.hpp"
#include "hexlab/loaders/raw.hpp"
#include "hexlab/processors/decoder.hpp"
#include "support/checks.hpp"
#include "support/fixture_files.hpp"

#include <algorithm>
#include <array>
#include <memory>

using namespace hexlab;
using namespace hexlab_test;

namespace {
InstructionFact jump_fact(std::uint64_t offset, Address table, std::uint16_t width) {
    Instruction instruction;
    instruction.context = {width == 64 ? Architecture::x86_64 : Architecture::x86,
                           width == 64 ? ExecutionMode::x86_64 : ExecutionMode::x86_32};
    instruction.address = {{0}, offset};
    instruction.opcode = Opcode::jmp;
    instruction.flow = FlowKind::jump;
    MemoryOperand memory;
    memory.data_width = width;
    memory.address_width = width;
    memory.index = RegisterOperand{RegisterBank::gpr, 1, width, false};
    memory.scale = static_cast<std::uint8_t>(width / 8);
    memory.resolved_address = table;
    instruction.operands.emplace_back(memory);
    instruction.access.emplace_back(OperandAccess::read);
    return {1, std::move(instruction), {}};
}

std::shared_ptr<const Image> fixture(std::vector<std::byte> bytes) {
    FixtureFile file(bytes);
    return load_raw(FileStorage::open(file.path).value(),
                    {Architecture::x86_64, ExecutionMode::x86_64, {{0}, 0x1000}, true, false, true, {}}, {}).value();
}

void absolute_pointer_table_recovers_cases() {
    std::vector<std::byte> bytes(0x200, std::byte{0x90});
    bytes[0x10] = std::byte{0xc3};
    bytes[0x20] = std::byte{0xc3};
    auto write64 = [&](std::size_t at, std::uint64_t value) {
        for (unsigned i = 0; i < 8; ++i)
            bytes[at + i] = static_cast<std::byte>((value >> (i * 8)) & 0xff);
    };
    write64(0x100, 0x1010);
    write64(0x108, 0x1020);
    write64(0x110, UINT64_MAX);
    FunctionRecord function;
    function.id = {1};
    function.entry = {{0}, 0x1000};
    function.blocks = {{1}};
    auto block = std::make_shared<BasicBlock>();
    block->id = {1}; block->begin = function.entry;
    block->instructions.push_back(std::make_shared<const InstructionFact>(jump_fact(0x1000, {{0}, 0x1100}, 64)));
    FunctionSnapshot snapshot; snapshot.blocks.push_back(block);
    auto result = analyze_switch_tables(*fixture(std::move(bytes)), function, snapshot, {});
    check(result && result.value().sites.size() == 1, "bounded absolute x86 pointer table yields one switch site");
    if (result && !result.value().sites.empty()) {
        const auto &site = result.value().sites.front();
        check(site.table == Address{{0}, 0x1100} && site.cases.size() == 2,
              "switch cases stop at the first non-executable table value");
        check(site.cases.size() == 2 && site.cases[0].target == Address{{0}, 0x1010} &&
                  site.cases[1].target == Address{{0}, 0x1020},
              "switch case order preserves table indices and targets");
        check(!result.value().complete, "truncated table boundary is recorded as partial evidence");
    }
}

void guarded_table_uses_proven_unsigned_case_bound() {
    std::vector<std::byte> bytes(0x200, std::byte{0x90});
    for (const auto target : {0x10u, 0x20u, 0x30u, 0x40u, 0x50u})
        bytes[target] = std::byte{0xc3};
    auto write64 = [&](std::size_t at, std::uint64_t value) {
        for (unsigned i = 0; i < 8; ++i)
            bytes[at + i] = static_cast<std::byte>((value >> (i * 8)) & 0xff);
    };
    write64(0x100, 0x1010);
    write64(0x108, 0x1020);
    write64(0x110, 0x1030);
    write64(0x118, 0x1040); // Valid code, but outside the guarded selector range.

    Instruction compare;
    compare.context = {Architecture::x86_64, ExecutionMode::x86_64};
    compare.address = {{0}, 0x1000};
    compare.length = 3;
    compare.opcode = Opcode::cmp;
    compare.operands = {RegisterOperand{RegisterBank::gpr, 1, 64, false},
                        ImmediateOperand{2, 8, 64, false, {}}};
    compare.access = {OperandAccess::read, OperandAccess::read};
    Instruction guard;
    guard.context = compare.context;
    guard.address = {{0}, 0x1003};
    guard.length = 2;
    guard.opcode = Opcode::jcc;
    guard.flow = FlowKind::conditional_branch;
    guard.x86_condition = X86Condition::above;
    guard.direct_target = Address{{0}, 0x1050};

    FunctionRecord function;
    function.id = {2}; function.entry = {{0}, 0x1000}; function.blocks = {{1}};
    auto block = std::make_shared<BasicBlock>(); block->id = {1}; block->begin = function.entry;
    block->instructions.push_back(std::make_shared<const InstructionFact>(InstructionFact{1, compare, {}}));
    block->instructions.push_back(std::make_shared<const InstructionFact>(InstructionFact{2, guard, {}}));
    block->instructions.push_back(std::make_shared<const InstructionFact>(jump_fact(0x1005, {{0}, 0x1100}, 64)));
    FunctionSnapshot snapshot; snapshot.blocks.push_back(block);
    const auto result = analyze_switch_tables(*fixture(std::move(bytes)), function, snapshot, {});
    check(result && result.value().sites.size() == 1, "guarded absolute table yields one switch site");
    if (result && !result.value().sites.empty()) {
        const auto &site = result.value().sites.front();
        check(site.cases.size() == 3,
              "unsigned selector guard limits table cases before an extra valid executable entry");
        check(site.complete && result.value().complete,
              "a fully decoded table through the proven bound is complete without probing later data");
    }
}


void guarded_large_table_exceeds_legacy_limit() {
    constexpr std::uint32_t count = 300;
    constexpr std::size_t table_offset = 0x200;
    std::vector<std::byte> bytes(table_offset + count * 8, std::byte{0x90});
    bytes[0x20] = std::byte{0xc3};
    for (std::uint32_t index = 0; index < count; ++index) {
        constexpr std::uint64_t target = 0x1020;
        for (unsigned byte = 0; byte < 8; ++byte)
            bytes[table_offset + index * 8 + byte] = static_cast<std::byte>((target >> (byte * 8)) & 0xff);
    }

    Instruction compare;
    compare.context = {Architecture::x86_64, ExecutionMode::x86_64};
    compare.address = {{0}, 0x1000};
    compare.length = 3;
    compare.opcode = Opcode::cmp;
    compare.operands = {RegisterOperand{RegisterBank::gpr, 1, 64, false},
                        ImmediateOperand{count - 1, 32, 64, false, {}}};
    compare.access = {OperandAccess::read, OperandAccess::read};
    Instruction guard;
    guard.context = compare.context;
    guard.address = {{0}, 0x1003};
    guard.length = 2;
    guard.opcode = Opcode::jcc;
    guard.flow = FlowKind::conditional_branch;
    guard.x86_condition = X86Condition::above;
    guard.direct_target = Address{{0}, 0x1010};

    FunctionRecord function;
    function.id = {3};
    function.entry = {{0}, 0x1000};
    function.blocks = {{1}};
    auto block = std::make_shared<BasicBlock>();
    block->id = {1};
    block->begin = function.entry;
    block->instructions.push_back(std::make_shared<const InstructionFact>(InstructionFact{1, compare, {}}));
    block->instructions.push_back(std::make_shared<const InstructionFact>(InstructionFact{2, guard, {}}));
    block->instructions.push_back(std::make_shared<const InstructionFact>(
        jump_fact(0x1005, {{0}, 0x1000 + table_offset}, 64)));
    FunctionSnapshot snapshot;
    snapshot.blocks.push_back(block);

    const auto result = analyze_switch_tables(*fixture(std::move(bytes)), function, snapshot, {});
    check(result && result.value().sites.size() == 1, "guarded 300-case table is recovered as one site");
    if (result && !result.value().sites.empty()) {
        const auto &site = result.value().sites.front();
        check(site.case_count == count && site.cases.size() == count,
              "proven switch bounds above 256 retain every verified destination");
        check(site.complete && result.value().complete,
              "large proven table completes without probing beyond its bound");
    }
}

void guard_proof_rejects_ambiguous_and_malformed_evidence() {
    // Keep four valid destinations so an unproven guard cannot accidentally
    // pass by stopping at an invalid entry at the expected bound.
    auto run_guard = [](X86Condition condition, std::uint64_t bound, unsigned mutation) {
        std::vector<std::byte> bytes(0x200, std::byte{0x90});
        for (unsigned i = 0; i < 4; ++i) {
            const auto target = 0x1010u + i * 0x10u;
            bytes[target - 0x1000] = std::byte{0xc3};
            for (unsigned j = 0; j < 8; ++j)
                bytes[0x100 + i * 8 + j] = static_cast<std::byte>((std::uint64_t(target) >> (j * 8)) & 255);
        }
        bytes[0x50] = std::byte{0xc3};
        if (mutation == 10)
            for (unsigned j = 0; j < 8; ++j) bytes[0x110 + j] = std::byte{0xff};
        Instruction compare;
        compare.context = {Architecture::x86_64, ExecutionMode::x86_64};
        compare.address = {{0}, 0x1000}; compare.length = 3; compare.opcode = Opcode::cmp;
        compare.operands = {RegisterOperand{RegisterBank::gpr, 1, 64, false},
                            ImmediateOperand{bound, 8, 64, false, {}}};
        Instruction branch;
        branch.context = compare.context; branch.address = {{0}, 0x1003}; branch.length = 2;
        branch.opcode = Opcode::jcc; branch.flow = FlowKind::conditional_branch;
        branch.x86_condition = condition; branch.direct_target = Address{{0}, 0x1050};
        auto block = std::make_shared<BasicBlock>(); block->id = {1}; block->begin = compare.address;
        if (mutation == 1) std::get<RegisterOperand>(compare.operands[0]).width = 32;
        if (mutation == 2) std::get<ImmediateOperand>(compare.operands[1]).is_signed = true;
        if (mutation == 3) branch.direct_target = Address{{0}, 0x2000};
        if (mutation == 4) compare.context.mode = ExecutionMode::x86_32;
        if (mutation == 5) std::get<ImmediateOperand>(compare.operands[1]).effective_width = 32;
        if (mutation == 6) branch.direct_target = Address{{0}, 0x1005};
        const Address dispatch{{0}, mutation == 7 ? 0x1008u : 0x1005u};
        block->instructions.push_back(std::make_shared<const InstructionFact>(InstructionFact{1, compare, {}}));
        block->instructions.push_back(std::make_shared<const InstructionFact>(InstructionFact{2, branch, {}}));
        block->instructions.push_back(std::make_shared<const InstructionFact>(jump_fact(dispatch.offset, {{0}, 0x1100}, 64)));
        if (mutation == 7)
            block->successors.push_back({branch.address, dispatch, {}, BlockEdgeKind::conditional_false});
        FunctionRecord function; function.id = {1}; function.entry = compare.address; function.blocks = {{1}};
        FunctionSnapshot snapshot; snapshot.blocks.push_back(block);
        if (mutation == 8 || mutation == 9) {
            auto bypass = std::make_shared<BasicBlock>(); bypass->id = {2}; bypass->begin = {{0}, 0x1060};
            if (mutation == 8) {
                bypass->successors.push_back({bypass->begin, dispatch, {}, BlockEdgeKind::jump});
            } else {
                compare.address = {{0}, 0x1000};
                std::get<ImmediateOperand>(compare.operands[1]).value = 1;
                branch.direct_target = Address{{0}, 0x1040};
                bypass->instructions.push_back(std::make_shared<const InstructionFact>(InstructionFact{4, compare, {}}));
                bypass->instructions.push_back(std::make_shared<const InstructionFact>(InstructionFact{5, branch, {}}));
            }
            function.blocks.push_back({2}); snapshot.blocks.push_back(bypass);
        }
        return analyze_switch_tables(*fixture(std::move(bytes)), function, snapshot, {});
    };
    for (const auto condition : {X86Condition::above, X86Condition::above_equal}) {
        const auto result = run_guard(condition, condition == X86Condition::above ? 2 : 3, 0);
        check(result && result.value().sites.size() == 1 && result.value().sites[0].case_count == 3 &&
                  result.value().sites[0].default_target == Address{{0}, 0x1050} &&
                  result.value().sites[0].cases.size() == 3 && result.value().sites[0].complete,
              "JA inclusive and JAE exclusive upper bounds yield three proven cases and a default");
    }
    const auto one = run_guard(X86Condition::above_equal, 1, 0);
    check(one && one.value().sites.size() == 1 && one.value().sites[0].case_count == 1 &&
              one.value().sites[0].cases.size() == 1 && one.value().sites[0].complete,
          "a proven single-case dispatch is preserved");
    const auto partial = run_guard(X86Condition::above, 2, 10);
    check(partial && partial.value().sites.size() == 1 && partial.value().sites[0].case_count == 3 &&
              partial.value().sites[0].default_target == Address{{0}, 0x1050} &&
              partial.value().sites[0].cases.size() == 2 && !partial.value().sites[0].complete &&
              !partial.value().complete,
          "invalid entry within a proven bound retains only verified targets and marks partial");
    const auto maximum = run_guard(X86Condition::above, 255, 0);
    check(maximum && maximum.value().sites.size() == 1 && maximum.value().sites[0].case_count == 256 &&
              maximum.value().sites[0].cases.size() == 4 && !maximum.value().sites[0].complete,
          "the maximum 256-case guard is accepted without inventing unreadable cases");
    for (unsigned mutation = 1; mutation <= 9; ++mutation) {
        const auto result = run_guard(X86Condition::above, mutation == 2 ? 0xff : 2, mutation);
        check(result && result.value().sites.size() == 1 && !result.value().sites[0].case_count &&
                  !result.value().sites[0].default_target && result.value().sites[0].cases.size() == 4,
              "malformed, mismatched, bypassed and contradictory guards do not invent bounds or defaults");
    }
    for (const auto [condition, bound] : std::array<std::pair<X86Condition, std::uint64_t>, 4>{
             std::pair{X86Condition::above_equal, 0}, std::pair{X86Condition::above, 256},
             std::pair{X86Condition::above, 0x102}, std::pair{X86Condition::below, 2}}) {
        const auto result = run_guard(condition, bound, 0);
        check(result && result.value().sites.size() == 1 && !result.value().sites[0].case_count &&
                  !result.value().sites[0].default_target,
              "empty, oversized, malformed-immediate and unsupported condition bounds are rejected");
    }
}

void pc_relative_offset_table_recovers_cases() {
    std::vector<std::byte> bytes(0x200, std::byte{0x90});
    const std::array<std::byte, 16> sequence{
        std::byte{0x48}, std::byte{0x8d}, std::byte{0x15}, std::byte{0xf9}, std::byte{0x00}, std::byte{0x00}, std::byte{0x00},
        std::byte{0x48}, std::byte{0x63}, std::byte{0x04}, std::byte{0x82},
        std::byte{0x48}, std::byte{0x01}, std::byte{0xd0},
        std::byte{0xff}, std::byte{0xe0}};
    std::copy(sequence.begin(), sequence.end(), bytes.begin());
    bytes[0x10] = std::byte{0xc3};
    bytes[0x20] = std::byte{0xc3};
    auto write32 = [&](std::size_t at, std::int32_t value) {
        const auto bits = static_cast<std::uint32_t>(value);
        for (unsigned i = 0; i < 4; ++i)
            bytes[at + i] = static_cast<std::byte>((bits >> (i * 8)) & 0xff);
    };
    // Signed offsets are based at the table start, as emitted by common
    // x86-64 switch lowering sequences after a RIP-relative LEA.
    write32(0x100, -0xf0);
    write32(0x104, -0xe0);
    write32(0x108, INT32_MAX);
    auto input = fixture(std::move(bytes));
    FunctionRecord function;
    function.id = {1}; function.entry = {{0}, 0x1000}; function.blocks = {{1}};
    auto block = std::make_shared<BasicBlock>(); block->id = {1}; block->begin = function.entry;
    for (const auto [offset, length] : std::array<std::pair<std::uint64_t, std::size_t>, 4>{
             std::pair{0, 7}, std::pair{7, 4}, std::pair{11, 3}, std::pair{14, 2}}) {
        const auto at = Address{{0}, 0x1000 + offset};
        const auto raw = input->read(at, length).value();
        auto decoded = decode_instruction(input->decode_context(), raw, at);
        check(decoded.status == DecodeStatus::decoded && decoded.instruction.has_value(),
              "compiler-style PC-relative table sequence decodes in the test fixture");
        if (decoded.instruction) {
            auto fact = std::make_shared<InstructionFact>();
            fact->id = offset + 1;
            fact->instruction = std::move(*decoded.instruction);
            block->instructions.push_back(std::move(fact));
        }
    }
    FunctionSnapshot snapshot; snapshot.blocks.push_back(block);
    auto result = analyze_switch_tables(*input, function, snapshot, {});
    check(result && result.value().sites.size() == 1,
          "PC-relative signed-offset table yields one recovered switch site");
    if (result && !result.value().sites.empty()) {
        const auto &site = result.value().sites.front();
        check(site.table == Address{{0}, 0x1100} && site.cases.size() == 2 &&
                  site.cases[0].target == Address{{0}, 0x1010} &&
                  site.cases[1].target == Address{{0}, 0x1020},
              "signed relative entries resolve from the table base in case order");
        check(site.entry_encoding == SwitchEntryEncoding::signed_offset_from_table,
              "switch API identifies table-relative signed entry semantics");
    }

    for (unsigned mutation = 0; mutation < 3; ++mutation) {
        auto changed = std::make_shared<InstructionFact>(*block->instructions[1]);
        auto &memory = std::get<MemoryOperand>(changed->instruction.operands[1]);
        if (mutation == 0) memory.displacement = 4;
        if (mutation == 1) memory.index = RegisterOperand{RegisterBank::gpr, 2, 64, false};
        if (mutation == 2) memory.segment = RegisterOperand{RegisterBank::segment, 0, 16, false};
        const auto original = block->instructions[1];
        block->instructions[1] = changed;
        const auto rejected = analyze_switch_tables(*input, function, snapshot, {});
        check(rejected && rejected.value().sites.empty(),
              "relative table rejects displaced, selector-clobbered or segmented entry loads");
        block->instructions[1] = original;
    }

}

void register_based_absolute_table_recovers_cases() {
    // A common MSVC-style lowering keeps the RIP-relative table base in a
    // register, then dispatches through [base + selector * pointer_size].
    std::vector<std::byte> bytes(0x200, std::byte{0x90});
    const std::array<std::byte, 10> sequence{
        std::byte{0x48}, std::byte{0x8d}, std::byte{0x15}, std::byte{0xf9}, std::byte{0x00}, std::byte{0x00}, std::byte{0x00},
        std::byte{0xff}, std::byte{0x24}, std::byte{0xc2}}; // jmp qword ptr [rdx + rax*8]
    std::copy(sequence.begin(), sequence.end(), bytes.begin());
    bytes[0x10] = std::byte{0xc3};
    bytes[0x20] = std::byte{0xc3};
    const auto write64 = [&](std::size_t at, std::uint64_t value) {
        for (unsigned byte = 0; byte < 8; ++byte)
            bytes[at + byte] = static_cast<std::byte>((value >> (byte * 8)) & 0xff);
    };
    write64(0x100, 0x1010);
    write64(0x108, 0x1020);
    write64(0x110, UINT64_MAX);
    const auto input = fixture(std::move(bytes));
    FunctionRecord function;
    function.id = {1}; function.entry = {{0}, 0x1000}; function.blocks = {{1}};
    auto block = std::make_shared<BasicBlock>(); block->id = {1}; block->begin = function.entry;
    for (const auto [offset, length] : std::array<std::pair<std::uint64_t, std::size_t>, 2>{
             std::pair{0, 7}, std::pair{7, 3}}) {
        const auto at = Address{{0}, 0x1000 + offset};
        const auto raw = input->read(at, length).value();
        auto decoded = decode_instruction(input->decode_context(), raw, at);
        check(decoded.status == DecodeStatus::decoded && decoded.instruction.has_value(),
              "register-based absolute table sequence decodes in the generated fixture");
        if (decoded.instruction) {
            auto fact = std::make_shared<InstructionFact>();
            fact->id = offset + 1; fact->instruction = std::move(*decoded.instruction);
            block->instructions.push_back(std::move(fact));
        }
    }
    FunctionSnapshot snapshot; snapshot.blocks.push_back(block);
    const auto result = analyze_switch_tables(*input, function, snapshot, {});
    check(result && result.value().sites.size() == 1,
          "RIP-relative LEA plus register-based indexed indirect JMP recovers a switch");
    if (result && !result.value().sites.empty()) {
        const auto &site = result.value().sites.front();
        check(site.table == Address{{0}, 0x1100} && site.selector.index == 0 &&
                  site.cases.size() == 2 && site.cases[0].target == Address{{0}, 0x1010} &&
                  site.cases[1].target == Address{{0}, 0x1020} &&
                  site.entry_encoding == SwitchEntryEncoding::absolute_pointer,
              "register-based absolute entries resolve in selector order to executable destinations");
    }
    const auto recovered = recover_functions(*input, {}, {}, {}, {});
    check(bool(recovered), "function discovery accepts the register-based absolute jump-table pattern");
    if (recovered) {
        const auto has_target = [&](std::uint64_t address) {
            return std::any_of(recovered.value()->instructions.begin(), recovered.value()->instructions.end(),
                               [&](const auto &fact) { return fact->instruction.address.offset == address; });
        };
        check(has_target(0x1010) && has_target(0x1020),
              "verified register-based table cases become executable CFG traversal destinations");
    }
}

void aarch64_adrp_indexed_pointer_table_recovers_bounded_prefix() {
    std::vector<std::byte> bytes(0x180, std::byte{0});
    const auto word = [&](std::size_t at, std::uint32_t value) {
        for (unsigned byte = 0; byte < 4; ++byte)
            bytes[at + byte] = static_cast<std::byte>((value >> (byte * 8)) & 0xff);
    };
    const auto qword = [&](std::size_t at, std::uint64_t value) {
        for (unsigned byte = 0; byte < 8; ++byte)
            bytes[at + byte] = static_cast<std::byte>((value >> (byte * 8)) & 0xff);
    };
    // adrp x1, 0x1000; add x1, x1, #0x100; ldr x2, [x1, x0, lsl #3]; br x2
    word(0x00, 0x90000001u);
    word(0x04, 0x91040021u);
    word(0x08, 0xf8607822u);
    word(0x0c, 0xd61f0040u);
    word(0x20, 0xd65f03c0u);
    word(0x24, 0xd65f03c0u);
    qword(0x100, 0x1020);
    qword(0x108, 0x1024);
    qword(0x110, UINT64_MAX); // invalid target ends the verified prefix

    FixtureFile file(bytes);
    RawOptions options{Architecture::arm64, ExecutionMode::a64, {{0}, 0x1000}, true, false, true};
    options.entry = Address{{0}, 0x1000};
    const auto input_result = load_raw(FileStorage::open(file.path).value(), options, {});
    check(bool(input_result), "AArch64 switch fixture loads");
    if (!input_result) return;
    const auto input = input_result.value();
    FunctionRecord function; function.id = {7}; function.entry = {{0}, 0x1000}; function.blocks = {{1}};
    auto block = std::make_shared<BasicBlock>(); block->id = {1}; block->begin = function.entry;
    for (std::uint64_t offset = 0; offset < 16; offset += 4) {
        const auto at = Address{{0}, 0x1000 + offset};
        const auto raw = input->read(at, 4).value();
        auto decoded = decode_instruction(input->decode_context(), raw, at);
        check(decoded.status == DecodeStatus::decoded && decoded.instruction.has_value(),
              "AArch64 ADRP/add/indexed load/BR dispatch decodes");
        if (decoded.instruction) {
            auto fact = std::make_shared<InstructionFact>();
            fact->id = offset + 1; fact->instruction = std::move(*decoded.instruction);
            block->instructions.push_back(std::move(fact));
        }
    }
    FunctionSnapshot snapshot; snapshot.blocks.push_back(block);
    const auto result = analyze_switch_tables(*input, function, snapshot, {});
    check(result && result.value().sites.size() == 1,
          "ADRP-based AArch64 indexed absolute-pointer table yields one site");
    if (result && !result.value().sites.empty()) {
        const auto &site = result.value().sites.front();
        check(site.table == Address{{0}, 0x1100} && site.selector.index == 0 && site.scale == 8 &&
                  site.entry_encoding == SwitchEntryEncoding::absolute_pointer &&
                  site.cases.size() == 2 && site.cases[0].target == Address{{0}, 0x1020} &&
                  site.cases[1].target == Address{{0}, 0x1024},
              "AArch64 table base and indexed pointer cases resolve in selector order");
        check(!site.complete && !result.value().complete,
              "invalid AArch64 pointer entry preserves verified cases and marks the table partial");
    }
    auto changed = std::make_shared<InstructionFact>(*block->instructions[2]);
    std::get<MemoryOperand>(changed->instruction.operands[1]).index_shift_amount = 2;
    const auto original = block->instructions[2];
    block->instructions[2] = changed;
    const auto rejected = analyze_switch_tables(*input, function, snapshot, {});
    check(rejected && rejected.value().sites.empty(),
          "unsupported AArch64 entry scaling is conservatively rejected");
    block->instructions[2] = original;
}

void recovered_cases_feed_function_cfg() {
    std::vector<std::byte> bytes(0x100, std::byte{0x90});
    const std::array<std::byte, 16> sequence{
        std::byte{0x48}, std::byte{0x8d}, std::byte{0x15}, std::byte{0x39}, std::byte{0x00}, std::byte{0x00}, std::byte{0x00},
        std::byte{0x48}, std::byte{0x63}, std::byte{0x04}, std::byte{0x82},
        std::byte{0x48}, std::byte{0x01}, std::byte{0xd0},
        std::byte{0xff}, std::byte{0xe0}};
    std::copy(sequence.begin(), sequence.end(), bytes.begin());
    bytes[0x10] = std::byte{0xc3};
    bytes[0x12] = std::byte{0xc3};
    const auto write32 = [&](std::size_t at, std::int32_t value) {
        const auto bits = static_cast<std::uint32_t>(value);
        for (unsigned i = 0; i < 4; ++i)
            bytes[at + i] = static_cast<std::byte>((bits >> (i * 8)) & 0xff);
    };
    write32(0x40, -0x30);
    write32(0x44, -0x2e);
    write32(0x48, INT32_MAX);
    FixtureFile file(bytes);
    auto loaded = load_raw(FileStorage::open(file.path).value(),
                           {Architecture::x86_64, ExecutionMode::x86_64, {{0}, 0x1000}, true, false, true, {}}, {});
    auto recovered = loaded ? recover_functions(*loaded.value(), {}, {}, {}, {})
                            : Result<std::shared_ptr<const FunctionSnapshot>>(loaded.error());
    check(bool(recovered), "function recovery accepts the PC-relative offset-table dispatch sequence");
    if (recovered) {
        const auto &instructions = recovered.value()->instructions;
        check(std::any_of(instructions.begin(), instructions.end(), [](const auto &fact) {
                  return fact->instruction.address.offset == 0x1010;
              }) && std::any_of(instructions.begin(), instructions.end(), [](const auto &fact) {
                  return fact->instruction.address.offset == 0x1012;
              }),
              "bounded table destinations are traversed into recovered function CFG");
    }
}

void guarded_relative_table_feeds_only_bounded_cases_and_default_cfg() {
    std::vector<std::byte> bytes(0x200, std::byte{0x90});
    const std::array<std::byte, 22> sequence{
        std::byte{0x48}, std::byte{0x83}, std::byte{0xf9}, std::byte{0x02}, // cmp rcx,2
        std::byte{0x77}, std::byte{0x2a}, // ja 0x1030 (default)
        std::byte{0x48}, std::byte{0x8d}, std::byte{0x15}, std::byte{0xf3}, std::byte{0x00}, std::byte{0x00}, std::byte{0x00},
        std::byte{0x48}, std::byte{0x63}, std::byte{0x04}, std::byte{0x8a},
        std::byte{0x48}, std::byte{0x01}, std::byte{0xd0},
        std::byte{0xff}, std::byte{0xe0}};
    std::copy(sequence.begin(), sequence.end(), bytes.begin());
    bytes[0x30] = std::byte{0xc3};
    bytes[0x80] = std::byte{0xc3};
    bytes[0x82] = std::byte{0xc3};
    bytes[0x84] = std::byte{0xc3};
    bytes[0x86] = std::byte{0xc3}; // Valid target beyond the proven three-case range.
    const auto write32 = [&](std::size_t at, std::int32_t value) {
        const auto bits = static_cast<std::uint32_t>(value);
        for (unsigned i = 0; i < 4; ++i)
            bytes[at + i] = static_cast<std::byte>((bits >> (i * 8)) & 0xff);
    };
    write32(0x100, -0x80);
    write32(0x104, -0x7e);
    write32(0x108, -0x7c);
    write32(0x10c, -0x7a);

    FixtureFile file(bytes);
    auto loaded = load_raw(FileStorage::open(file.path).value(),
                           {Architecture::x86_64, ExecutionMode::x86_64, {{0}, 0x1000}, true, false, true, {}}, {});
    auto recovered = loaded ? recover_functions(*loaded.value(), {}, {}, {}, {})
                            : Result<std::shared_ptr<const FunctionSnapshot>>(loaded.error());
    check(bool(recovered), "function recovery accepts a guarded relative jump table");
    if (recovered) {
        const auto function = std::find_if(recovered.value()->functions.begin(), recovered.value()->functions.end(),
                                           [](const auto &candidate) { return candidate->entry.offset == 0x1000; });
        check(function != recovered.value()->functions.end(), "guarded table function is present in the snapshot");
        if (function != recovered.value()->functions.end()) {
            const auto switches = analyze_switch_tables(*loaded.value(), **function, *recovered.value(), {});
            check(switches && switches.value().sites.size() == 1 &&
                      switches.value().sites.front().case_count == 3u &&
                      switches.value().sites.front().default_target == Address{{0}, 0x1030},
                  "project-facing switch analysis reports the exact bound and default target");
        }
        const auto &instructions = recovered.value()->instructions;
        const auto has = [&](std::uint64_t address) {
            return std::any_of(instructions.begin(), instructions.end(), [&](const auto &fact) {
                return fact->instruction.address.offset == address;
            });
        };
        check(has(0x1030) && has(0x1080) && has(0x1082) && has(0x1084),
              "function CFG keeps the conditional default and all three proven switch cases");
        check(!has(0x1086), "function CFG excludes a valid executable table entry beyond the selector bound");
    }
}

void cancellation_is_reported() {
    FunctionRecord function; function.id = {1}; function.entry = {{0}, 0x1000}; function.blocks = {{1}};
    FunctionSnapshot snapshot;
    std::stop_source source; source.request_stop();
    auto result = analyze_switch_tables(*fixture(std::vector<std::byte>(32, std::byte{0x90})),
                                        function, snapshot, source.get_token());
    check(!result && result.error().code == ErrorCode::canceled, "switch scan honors cancellation before work");
}
} // namespace

int main() {
    return run([] {
        absolute_pointer_table_recovers_cases();
        guarded_table_uses_proven_unsigned_case_bound();
        guarded_large_table_exceeds_legacy_limit();
        guard_proof_rejects_ambiguous_and_malformed_evidence();
        pc_relative_offset_table_recovers_cases();
        register_based_absolute_table_recovers_cases();
        aarch64_adrp_indexed_pointer_table_recovers_bounded_prefix();
        recovered_cases_feed_function_cfg();
        guarded_relative_table_feeds_only_bounded_cases_and_default_cfg();
        cancellation_is_reported();
    });
}
