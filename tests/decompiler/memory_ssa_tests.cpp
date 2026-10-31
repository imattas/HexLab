#include "hexlab/decompiler/decompiler.hpp"

#include <array>
#include <cstdlib>
#include <iostream>
#include <limits>
#include <string>
#include <utility>

using namespace hexlab;
using namespace hexlab::decompiler;

namespace {
void require(bool condition, const char *message) {
    if (!condition) { std::cerr << message << '\n'; std::exit(1); }
}
ExpressionPtr constant(std::uint64_t n) {
    return std::make_shared<Expression>(Expression{{TypeKind::integer, 32, false},
        ConstantValue{n, {TypeKind::integer, 32, false}}});
}
ExpressionPtr load() {
    return std::make_shared<Expression>(Expression{{TypeKind::integer, 32, false},
        MemoryValue{{TypeKind::integer, 32, false}}});
}
ExpressionPtr reg(RegisterOperand r, std::optional<std::uint32_t> version = {}) {
    return std::make_shared<Expression>(Expression{{TypeKind::integer, r.width, false}, RegisterValue{r, version}});
}
}

int main() {
    const Address entry{{0}, 0x1000}, left{{0}, 0x1010}, right{{0}, 0x1020}, join{{0}, 0x1030};
    auto store_block = [](BlockId id, Address at, std::uint64_t insn, std::uint64_t value,
                          Address target, BlockId target_id) {
        LiftedBlock block{id, at, {{{at, insn}, Store{constant(0x2000), constant(value)}}},
            {{at, target, target_id, BlockEdgeKind::jump}}, {}};
        return block;
    };
    LiftedFunction input{FunctionId{1}, entry,
        {{BlockId{1}, entry, {{{entry, 10}, Branch{"test", left, right}}},
          {{entry, left, BlockId{2}, BlockEdgeKind::conditional_true},
           {entry, right, BlockId{3}, BlockEdgeKind::conditional_false}}, {}},
         store_block(BlockId{2}, left, 11, 1, join, BlockId{4}),
         store_block(BlockId{3}, right, 12, 2, join, BlockId{4}),
         {BlockId{4}, join, {{{join, 13}, Assign{{RegisterBank::gpr, 0, 32, false}, load()}}}, {}, {}}}, {}};

    auto converted = to_ssa(input);
    require(converted.has_value(), "memory effects in a diamond convert to SSA");
    auto &blocks = converted.value().blocks;
    require(blocks[3].memory_phi.has_value(), "stores on both incoming paths create a memory phi");
    const auto &phi = *blocks[3].memory_phi;
    require(phi.inputs.size() == 2 && phi.inputs[0].predecessor == BlockId{2} &&
            phi.inputs[1].predecessor == BlockId{3}, "memory phi inputs are stable and predecessor-attributed");
    const auto &left_store = std::get<Store>(blocks[1].instructions[0].statement);
    const auto &right_store = std::get<Store>(blocks[2].instructions[0].statement);
    require(left_store.memory_input_version == std::uint32_t{0} &&
            right_store.memory_input_version == std::uint32_t{0},
            "each branch store reads the incoming memory state");
    require(phi.inputs[0].version == left_store.memory_output_version &&
            phi.inputs[1].version == right_store.memory_output_version,
            "memory phi selects each branch's store result");
    const auto &read = std::get<MemoryValue>(std::get<Assign>(blocks[3].instructions[0].statement).value->value);
    require(read.memory_version == phi.version, "a post-join load observes the merged memory version");

    auto one_sided = input;
    one_sided.blocks[2].instructions.clear();
    auto one_sided_ssa = to_ssa(one_sided);
    require(one_sided_ssa && one_sided_ssa.value().blocks[3].memory_phi.has_value(),
            "a store on only one incoming path still merges with the untouched memory state");
    const auto &one_sided_phi = *one_sided_ssa.value().blocks[3].memory_phi;
    require(one_sided_phi.inputs.size() == 2 && one_sided_phi.inputs[0].version != 0 &&
            one_sided_phi.inputs[1].version == 0,
            "the untouched predecessor contributes the initial memory version");

    auto sequential = input;
    sequential.blocks = {input.blocks[0], store_block(BlockId{2}, left, 11, 1, right, BlockId{3}),
        {BlockId{3}, right, {{{right, 12}, Assign{{RegisterBank::gpr, 0, 32, false}, load()}}}, {}, {}}};
    sequential.blocks[0].successors = {{entry, left, BlockId{2}, BlockEdgeKind::conditional_true},
        {entry, left, BlockId{2}, BlockEdgeKind::conditional_false}};
    auto ordered = to_ssa(sequential);
    require(ordered && !ordered.value().blocks[2].memory_phi,
            "a straight-line store does not introduce an unnecessary memory phi");
    const auto &ordered_store = std::get<Store>(ordered.value().blocks[1].instructions[0].statement);
    const auto &ordered_load = std::get<MemoryValue>(std::get<Assign>(
        ordered.value().blocks[2].instructions[0].statement).value->value);
    require(ordered_load.memory_version == ordered_store.memory_output_version,
            "a later load observes the preceding store");

    auto barriers = input;
    barriers.blocks = {{BlockId{9}, entry,
        {{{entry, 30}, Store{constant(0x2000), constant(1)}},
         {{Address{{0}, 0x1004}, 31}, Call{Address{{0}, 0x3000}, {}}},
         {{Address{{0}, 0x1008}, 32}, Assign{{RegisterBank::gpr, 0, 32, false}, load()}},
         {{Address{{0}, 0x100c}, 33}, Intrinsic{"opaque", {}}},
         {{Address{{0}, 0x1010}, 34}, Assign{{RegisterBank::gpr, 1, 32, false}, load()}},
         {{Address{{0}, 0x1014}, 35}, Intrinsic{"nop", {}, IntrinsicMemoryEffect::none}},
         {{Address{{0}, 0x1018}, 36}, Intrinsic{"readonly", {}, IntrinsicMemoryEffect::read}},
         {{Address{{0}, 0x101c}, 37}, Assign{{RegisterBank::gpr, 2, 32, false}, load()}}}, {}, {}}};
    auto barrier_ssa = to_ssa(barriers);
    require(barrier_ssa.has_value(), "calls and opaque intrinsics participate in memory SSA");
    const auto &call = std::get<Call>(barrier_ssa.value().blocks[0].instructions[1].statement);
    const auto &after_call = std::get<MemoryValue>(std::get<Assign>(
        barrier_ssa.value().blocks[0].instructions[2].statement).value->value);
    const auto &opaque = std::get<Intrinsic>(barrier_ssa.value().blocks[0].instructions[3].statement);
    const auto &after_opaque = std::get<MemoryValue>(std::get<Assign>(
        barrier_ssa.value().blocks[0].instructions[4].statement).value->value);
    const auto &nop = std::get<Intrinsic>(barrier_ssa.value().blocks[0].instructions[5].statement);
    const auto &readonly = std::get<Intrinsic>(barrier_ssa.value().blocks[0].instructions[6].statement);
    const auto &after_nop = std::get<MemoryValue>(std::get<Assign>(
        barrier_ssa.value().blocks[0].instructions[7].statement).value->value);
    const auto &barrier_store = std::get<Store>(barrier_ssa.value().blocks[0].instructions[0].statement);
    require(call.memory_input_version == barrier_store.memory_output_version && call.memory_output_version &&
                after_call.memory_version == call.memory_output_version,
            "a call consumes current memory and clobbers the memory state seen by later loads");
    require(opaque.memory_effect == IntrinsicMemoryEffect::unknown &&
                opaque.memory_input_version == call.memory_output_version && opaque.memory_output_version &&
                after_opaque.memory_version == opaque.memory_output_version,
            "an opaque intrinsic is a conservative memory barrier");
    require(nop.memory_effect == IntrinsicMemoryEffect::none && !nop.memory_input_version &&
                !nop.memory_output_version && readonly.memory_effect == IntrinsicMemoryEffect::read &&
                readonly.memory_input_version == after_opaque.memory_version && !readonly.memory_output_version &&
                after_nop.memory_version == after_opaque.memory_version,
            "pure and read-only intrinsics preserve incoming memory without false definitions");

    auto call_join = input;
    call_join.blocks[2].instructions = {{{right, 12}, Call{Address{{0}, 0x3000}, {}}}};
    auto call_join_ssa = to_ssa(call_join);
    require(call_join_ssa && call_join_ssa.value().blocks[3].memory_phi,
            "a call on one incoming path creates a memory phi at the join");
    const auto &call_join_phi = *call_join_ssa.value().blocks[3].memory_phi;
    const auto &join_store = std::get<Store>(call_join_ssa.value().blocks[1].instructions[0].statement);
    const auto &join_call = std::get<Call>(call_join_ssa.value().blocks[2].instructions[0].statement);
    require(call_join_phi.inputs[0].version == join_store.memory_output_version &&
                call_join_phi.inputs[1].version == join_call.memory_output_version &&
                std::get<MemoryValue>(std::get<Assign>(call_join_ssa.value().blocks[3].instructions[0].statement)
                                          .value->value).memory_version == call_join_phi.version,
            "the merged load observes whichever store or call clobber reached its predecessor");

    const RegisterOperand rbp{RegisterBank::gpr, 5, 64, false};
    auto frame_slot = [&](std::int64_t displacement, std::uint16_t bits = 32,
                          std::optional<RegisterOperand> index = {}) {
        MemoryValue memory;
        memory.type = {TypeKind::integer, bits, false};
        memory.base = rbp;
        memory.index = index;
        memory.displacement = displacement;
        return std::make_shared<Expression>(Expression{memory.type, std::move(memory)});
    };
    LiftedFunction stack_locals{FunctionId{2}, entry,
        {{BlockId{5}, entry,
          {{{entry, 20}, Store{frame_slot(-8), constant(42)}},
           {{Address{{0}, 0x1004}, 21}, Assign{{RegisterBank::gpr, 0, 32, false}, frame_slot(-8)}},
           {{Address{{0}, 0x1008}, 22}, Return{frame_slot(-8)}}}, {}, {}}}, {}};
    auto named_stack_locals = recover_stack_variables(stack_locals);
    require(named_stack_locals.has_value(), "frame-relative local recovery accepts a valid function");
    const auto &named_store = std::get<Store>(named_stack_locals.value().blocks[0].instructions[0].statement);
    const auto &named_store_slot = std::get<MemoryValue>(named_store.address->value);
    const auto &named_load = std::get<MemoryValue>(std::get<Assign>(
        named_stack_locals.value().blocks[0].instructions[1].statement).value->value);
    require(named_store_slot.stack_variable == std::optional<std::string>{"local_8"} &&
                named_load.stack_variable == named_store_slot.stack_variable,
            "the same non-overlapping frame slot is named consistently as both a store and a load");
    const auto stack_text = format_pseudocode(named_stack_locals.value());
    require(stack_text.find("local_8 = 0x2a;") != std::string::npos &&
                stack_text.find("r0 = local_8;") != std::string::npos &&
                stack_text.find("return local_8;") != std::string::npos,
            "recovered stack slots render as source-like local variable references");

    auto overlapping_stack_locals = stack_locals;
    overlapping_stack_locals.blocks[0].instructions.insert(
        overlapping_stack_locals.blocks[0].instructions.begin() + 1,
        {{Address{{0}, 0x1002}, 23}, Store{frame_slot(-6, 16), constant(7)}});
    auto overlapping_recovery = recover_stack_variables(overlapping_stack_locals);
    require(overlapping_recovery.has_value(), "overlapping stack accesses remain representable");
    const auto &overlapping_store = std::get<Store>(overlapping_recovery.value().blocks[0].instructions[0].statement);
    require(!std::get<MemoryValue>(overlapping_store.address->value).stack_variable,
            "partially overlapping frame ranges retain raw memory expressions");

    auto dynamic_stack_locals = stack_locals;
    dynamic_stack_locals.blocks[0].instructions.push_back(
        {{Address{{0}, 0x100c}, 24}, Store{frame_slot(-16, 32, RegisterOperand{RegisterBank::gpr, 1, 64, false}),
                                          constant(9)}});
    auto dynamic_recovery = recover_stack_variables(dynamic_stack_locals);
    require(dynamic_recovery.has_value(), "dynamic stack accesses remain representable");
    const auto &dynamic_store = std::get<Store>(dynamic_recovery.value().blocks[0].instructions[0].statement);
    require(!std::get<MemoryValue>(dynamic_store.address->value).stack_variable,
            "an indexed access through the same frame base prevents unsafe slot naming");

    auto conflicting_widths = stack_locals;
    conflicting_widths.blocks[0].instructions.push_back(
        {{Address{{0}, 0x1010}, 25}, Assign{{RegisterBank::gpr, 2, 16, false}, frame_slot(-8, 16)}});
    auto width_recovery = recover_stack_variables(conflicting_widths);
    require(width_recovery.has_value(), "width-conflicting stack accesses remain representable");
    const auto &width_conflict_store = std::get<Store>(width_recovery.value().blocks[0].instructions[0].statement);
    require(!std::get<MemoryValue>(width_conflict_store.address->value).stack_variable,
            "same-offset accesses with different widths do not become separate source variables");

    const RegisterOperand stack_alias{RegisterBank::gpr, 3, 64, false};
    auto subtract_offset = [&](RegisterOperand source, std::uint32_t version, std::int64_t displacement) {
        auto amount = std::make_shared<Expression>(Expression{{TypeKind::integer, 64, true},
            ConstantValue{static_cast<std::uint64_t>(displacement), {TypeKind::integer, 64, true}}});
        return std::make_shared<Expression>(Expression{{TypeKind::integer, 64, false},
            BinaryValue{"sub", reg(source, version), std::move(amount)}});
    };
    auto aliased_memory = [&](RegisterOperand base, std::uint32_t version, std::int64_t displacement) {
        MemoryValue memory;
        memory.base = base;
        memory.base_version = version;
        memory.displacement = displacement;
        memory.type = {TypeKind::integer, 32, false};
        return std::make_shared<Expression>(Expression{memory.type, memory});
    };
    LiftedFunction cross_block_stack{FunctionId{4}, entry,
        {{BlockId{6}, entry,
          {{{entry, 30}, Assign{stack_alias, subtract_offset(rbp, 0, 16), 1}}}, {}, {}},
         {BlockId{7}, Address{{0}, 0x1014},
          {{{Address{{0}, 0x1014}, 31}, Store{aliased_memory(stack_alias, 1, 8), constant(1)}}}, {}, {}}}, {}};
    auto cross_block_recovery = recover_stack_variables(cross_block_stack);
    require(cross_block_recovery.has_value(), "cross-block constant stack aliases remain recoverable");
    const auto &cross_block_store = std::get<Store>(cross_block_recovery.value().blocks[1].instructions[0].statement);
    const auto &cross_block_slot = std::get<MemoryValue>(cross_block_store.address->value);
    require(cross_block_slot.stack_variable == std::optional<std::string>{"local_8"} &&
                cross_block_slot.stack_frame_register == rbp && cross_block_slot.stack_frame_offset == -8,
            "constant aliases normalize back to one canonical frame location across blocks");

    const RegisterOperand rsp{RegisterBank::gpr, 4, 64, false};
    LiftedFunction adjusted_sp{FunctionId{5}, entry,
        {{BlockId{8}, entry,
          {{{entry, 34}, Assign{rsp, subtract_offset(rsp, 0, 32), 1}},
           {{Address{{0}, 0x101c}, 35}, Store{aliased_memory(rsp, 1, 0), constant(2)}}}, {}, {}}}, {}};
    auto adjusted_sp_recovery = recover_stack_variables(adjusted_sp);
    require(adjusted_sp_recovery.has_value(), "adjusted stack-pointer locals remain representable");
    const auto &adjusted_sp_store = std::get<Store>(adjusted_sp_recovery.value().blocks[0].instructions[1].statement);
    const auto &adjusted_sp_slot = std::get<MemoryValue>(adjusted_sp_store.address->value);
    require(adjusted_sp_slot.stack_variable == std::optional<std::string>{"local_32"} &&
                adjusted_sp_slot.stack_frame_offset == -32,
            "SSA stack-pointer adjustments normalize local slots to the incoming stack base");

    auto escaped_stack = cross_block_stack;
    escaped_stack.blocks[1].instructions.push_back(
        {{Address{{0}, 0x1018}, 33}, Store{constant(0x2000), reg(stack_alias, 1)}});
    auto escaped_recovery = recover_stack_variables(escaped_stack);
    require(escaped_recovery.has_value(), "escaped stack addresses remain representable");
    const auto &escaped_access = std::get<Store>(escaped_recovery.value().blocks[1].instructions[0].statement);
    require(!std::get<MemoryValue>(escaped_access.address->value).stack_variable,
            "a stack address stored outside the frame prevents unsafe local alias naming");

    auto ambiguous_phi = cross_block_stack;
    const RegisterOperand phi_alias{RegisterBank::gpr, 3, 64, false};
    ambiguous_phi.blocks[0].instructions.push_back(
        {{{0}, 0x1002}, Assign{phi_alias, subtract_offset(rbp, 0, 8), 2}});
    ambiguous_phi.blocks[1].phis.push_back({phi_alias, 3, {{BlockId{6}, 1}, {BlockId{6}, 2}}});
    auto ambiguous_phi_recovery = recover_stack_variables(ambiguous_phi);
    require(ambiguous_phi_recovery.has_value(), "ambiguous stack pointer phis remain representable");
    const auto &ambiguous_store = std::get<Store>(ambiguous_phi_recovery.value().blocks[1].instructions[0].statement);
    require(!std::get<MemoryValue>(ambiguous_store.address->value).stack_variable,
            "a phi joining distinct stack offsets does not acquire a guessed local identity");

    auto malformed_stack = cross_block_stack;
    malformed_stack.blocks[0].instructions[0] = {{entry, 32}, Assign{stack_alias,
        subtract_offset(rbp, 0, std::numeric_limits<std::int64_t>::min()), 1}};
    auto malformed_recovery = recover_stack_variables(malformed_stack);
    require(malformed_recovery.has_value(), "malformed stack offset arithmetic is kept conservative");
    const auto &malformed_store = std::get<Store>(malformed_recovery.value().blocks[1].instructions[0].statement);
    require(!std::get<MemoryValue>(malformed_store.address->value).stack_variable,
            "unrepresentable address arithmetic never creates a local name");

    const std::array<std::pair<Opcode, const char *>, 5> string_opcodes{{
        {Opcode::x86_movs, "movs"}, {Opcode::x86_cmps, "cmps"}, {Opcode::x86_stos, "stos"},
        {Opcode::x86_lods, "lods"}, {Opcode::x86_scas, "scas"}}};
    for (std::size_t i = 0; i < string_opcodes.size(); ++i) {
        Instruction decoded;
        decoded.address = Address{{0}, 0x1100 + i * 4};
        decoded.context.architecture = Architecture::x86_64;
        decoded.opcode = string_opcodes[i].first;
        MemoryOperand source_memory;
        source_memory.data_width = 32;
        source_memory.address_width = 64;
        source_memory.base = RegisterOperand{RegisterBank::gpr, 6, 64, false};
        MemoryOperand destination_memory = source_memory;
        destination_memory.base = RegisterOperand{RegisterBank::gpr, 7, 64, false};
        const RegisterOperand accumulator{RegisterBank::gpr, 0, 32, false};
        switch (decoded.opcode) {
        case Opcode::x86_movs: decoded.operands = {destination_memory, source_memory}; break;
        case Opcode::x86_cmps: decoded.operands = {source_memory, destination_memory}; break;
        case Opcode::x86_stos: decoded.operands = {destination_memory, accumulator}; break;
        case Opcode::x86_lods: decoded.operands = {accumulator, source_memory}; break;
        case Opcode::x86_scas: decoded.operands = {accumulator, destination_memory}; break;
        default: break;
        }
        auto decoded_block = std::make_shared<BasicBlock>();
        decoded_block->id = BlockId{static_cast<std::uint64_t>(10 + i)};
        decoded_block->begin = decoded.address;
        decoded_block->instructions.push_back(std::make_shared<InstructionFact>(
            InstructionFact{static_cast<std::uint64_t>(30 + i), decoded, {}}));
        FunctionRecord decoded_record{FunctionId{3}, decoded.address, {}, {decoded_block->id}, {}, {}, true};
        FunctionSnapshot decoded_snapshot;
        decoded_snapshot.blocks.push_back(decoded_block);
        auto lifted_string = lift_function(decoded_record, decoded_snapshot);
        require(lifted_string && format_pseudocode(lifted_string.value()).find(
                    std::string("x86_string_") + string_opcodes[i].second + "_") != std::string::npos,
                "x86 string instructions keep their mnemonic in decompiler fallback output");
    }
    return 0;
}
