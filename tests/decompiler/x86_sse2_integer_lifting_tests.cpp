#include "hexlab/decompiler/decompiler.hpp"
#include "hexlab/processors/decoder.hpp"

#include <algorithm>
#include <cstdlib>
#include <iostream>

using namespace hexlab;
using namespace hexlab::decompiler;
namespace {
void check(bool value, const char *message) { if (!value) { std::cerr << message << '\n'; std::exit(1); } }
}
int main() {
    const Address entry{{0}, 0x4000};
    const RegisterOperand xmm0{RegisterBank::xmm, 0, 128, false};
    const RegisterOperand xmm1{RegisterBank::xmm, 1, 128, false};
    Instruction packed;
    packed.address = entry;
    packed.context = {Architecture::x86_64, ExecutionMode::x86_64, ByteOrder::little};
    packed.opcode = Opcode::pcmpgtd;
    packed.operands = {xmm0, xmm1};
    packed.register_reads = {xmm0, xmm1};
    packed.register_writes = {xmm0};
    auto block = std::make_shared<BasicBlock>();
    block->id = BlockId{9};
    block->begin = entry;
    block->instructions = {std::make_shared<InstructionFact>(InstructionFact{90, packed, {}})};
    FunctionRecord record;
    record.id = FunctionId{7}; record.entry = entry; record.blocks = {block->id};
    FunctionSnapshot snapshot; snapshot.blocks = {block};
    auto lifted = lift_function(record, snapshot);
    check(lifted.has_value(), "packed comparison function lifts");
    const auto &statement = lifted.value().blocks.front().instructions.front().statement;
    check(std::holds_alternative<Intrinsic>(statement), "packed comparison remains a typed intrinsic");
    const auto &intrinsic = std::get<Intrinsic>(statement);
    check(intrinsic.name == "x86_pcmpgtd_i32x4" && intrinsic.operands.size() == 2 &&
          intrinsic.register_writes == std::vector<RegisterOperand>{xmm0} &&
          intrinsic.memory_effect == IntrinsicMemoryEffect::none,
          "packed intrinsic preserves mnemonic, operands, and vector write");
    check(intrinsic.result_type && !intrinsic.result_type->is_signed &&
          intrinsic.result_type->element_bits == 32 && intrinsic.result_type->lanes == 4 &&
          intrinsic.operands[0]->type.is_signed && intrinsic.operands[1]->type.is_signed,
          "PCMPGTD compares signed i32 lanes and returns unsigned bit masks");
    const auto rendered = format_pseudocode(lifted.value());
    check(rendered.find("x86_pcmpgtd") != std::string::npos, "pseudocode keeps packed operation visible");

    MemoryOperand source{};
    source.address_width = 64;
    source.data_width = 128;
    packed.opcode = Opcode::paddd;
    packed.operands[1] = source;
    packed.memory_read = true;
    auto memory_block = std::make_shared<BasicBlock>();
    memory_block->id = BlockId{10}; memory_block->begin = entry;
    memory_block->instructions = {std::make_shared<InstructionFact>(InstructionFact{91, packed, {}})};
    record.blocks = {memory_block->id};
    snapshot.blocks = {memory_block};
    auto memory_lifted = lift_function(record, snapshot);
    check(memory_lifted && std::holds_alternative<Intrinsic>(
              memory_lifted.value().blocks.front().instructions.front().statement) &&
          std::get<Intrinsic>(memory_lifted.value().blocks.front().instructions.front().statement).name == "x86_paddd_i32x4" &&
          std::get<Intrinsic>(memory_lifted.value().blocks.front().instructions.front().statement).memory_effect ==
              IntrinsicMemoryEffect::read &&
          std::get<Intrinsic>(memory_lifted.value().blocks.front().instructions.front().statement).register_writes ==
              std::vector<RegisterOperand>{xmm0},
          "memory-source PADDD lifting records a read and the XMM destination write");

    auto decode = [&](std::initializer_list<unsigned char> raw) {
        std::vector<std::byte> bytes;
        for (const auto value : raw) bytes.push_back(std::byte{value});
        auto result = decode_instruction({Architecture::x86_64, ExecutionMode::x86_64, ByteOrder::little},
                                         bytes, entry);
        check(result.status == DecodeStatus::decoded && result.instruction,
              "typed SIMD test fixture decodes through x86 decoder");
        return *result.instruction;
    };
    auto lift_decoded = [&](Instruction instruction) {
        auto decoded_block = std::make_shared<BasicBlock>();
        decoded_block->id = BlockId{11}; decoded_block->begin = entry;
        decoded_block->instructions = {std::make_shared<InstructionFact>(InstructionFact{92, std::move(instruction), {}})};
        FunctionRecord decoded_record; decoded_record.id = FunctionId{8}; decoded_record.entry = entry;
        decoded_record.blocks = {decoded_block->id};
        FunctionSnapshot decoded_snapshot; decoded_snapshot.blocks = {decoded_block};
        return lift_function(decoded_record, decoded_snapshot);
    };

    const auto paddd = decode({0x66, 0x0f, 0xfe, 0xc1}); // paddd xmm0,xmm1
    auto decoded_paddd = lift_decoded(paddd);
    check(decoded_paddd && std::holds_alternative<Intrinsic>(
              decoded_paddd.value().blocks.front().instructions.front().statement),
          "decoded PADDD reaches vector lifting");
    const auto &typed_paddd = std::get<Intrinsic>(decoded_paddd.value().blocks.front().instructions.front().statement);
    check(typed_paddd.result_type && typed_paddd.result_type->kind == TypeKind::vector &&
          typed_paddd.result_type->bits == 128 && typed_paddd.result_type->element_kind == TypeKind::integer &&
          typed_paddd.result_type->element_bits == 32 && typed_paddd.result_type->lanes == 4 &&
          typed_paddd.operands.size() == 2 && typed_paddd.operands[0]->type == *typed_paddd.result_type &&
          typed_paddd.operands[1]->type == *typed_paddd.result_type,
          "PADDD exposes typed i32x4 operands and result at architectural width");
    check(format_pseudocode(decoded_paddd.value()).find("x86_paddd_i32x4") != std::string::npos,
          "pseudocode names the packed lane type without hiding the vector operation");

    const auto movdqa = decode({0x66, 0x0f, 0x6f, 0xc1}); // movdqa xmm0,xmm1
    auto decoded_movdqa = lift_decoded(movdqa);
    const auto &move_effect = std::get<Intrinsic>(decoded_movdqa.value().blocks.front().instructions.front().statement);
    check(move_effect.result_type && move_effect.result_type->kind == TypeKind::vector &&
          move_effect.result_type->bits == 128 && move_effect.result_type->lanes == 0 &&
          move_effect.register_writes == std::vector<RegisterOperand>{xmm0},
          "MOVDQA is explicitly an opaque 128-bit vector move without invented lane semantics");

    const auto movdqu_store = decode({0xf3, 0x0f, 0x7f, 0x00}); // movdqu [rax],xmm0
    auto decoded_movdqu_store = lift_decoded(movdqu_store);
    const auto &store_effect = std::get<Intrinsic>(decoded_movdqu_store.value().blocks.front().instructions.front().statement);
    check(store_effect.memory_effect == IntrinsicMemoryEffect::write,
          "MOVDQU store records a memory write");
    check(store_effect.result_type == std::nullopt && store_effect.register_writes.empty(),
          "MOVDQU store has no register result");
    check(store_effect.name == "x86_movdqu_bits128",
          "MOVDQU store names the opaque 128-bit vector width");

    const auto psubq = decode({0x66, 0x0f, 0xfb, 0xc1}); // psubq xmm0,xmm1
    auto decoded_psubq = lift_decoded(psubq);
    const auto &wide_lanes = *std::get<Intrinsic>(decoded_psubq.value().blocks.front().instructions.front().statement).result_type;
    check(wide_lanes.kind == TypeKind::vector && wide_lanes.bits == 128 &&
          wide_lanes.element_bits == 64 && wide_lanes.lanes == 2,
          "PSUBQ retains i64x2 lane shape instead of treating XMM width as one scalar integer");

    const auto addss = decode({0xf3, 0x0f, 0x58, 0xc1}); // addss xmm0,xmm1
    auto decoded_addss = lift_decoded(addss);
    const auto &scalar_effect = std::get<Intrinsic>(decoded_addss.value().blocks.front().instructions.front().statement);
    check(scalar_effect.result_type && scalar_effect.result_type->kind == TypeKind::vector &&
          scalar_effect.result_type->bits == 128 && scalar_effect.result_type->element_kind == TypeKind::floating &&
          scalar_effect.result_type->element_bits == 32 && scalar_effect.result_type->lanes == 4,
          "ADDSS result retains scalar f32 lanes inside the full 128-bit XMM register");
    const RegisterOperand mxcsr{RegisterBank::mxcsr, 0, 32, false};
    check(scalar_effect.register_writes.size() == 2 &&
              std::find(scalar_effect.register_writes.begin(), scalar_effect.register_writes.end(), xmm0) != scalar_effect.register_writes.end() &&
              std::find(scalar_effect.register_writes.begin(), scalar_effect.register_writes.end(), mxcsr) != scalar_effect.register_writes.end(),
          "ADDSS records the full XMM and sticky MXCSR destination effects");
    check(scalar_effect.name == "x86_addss_f32",
          "ADDSS intrinsic identifies its scalar floating width");
    check(format_pseudocode(decoded_addss.value()).find("x86_addss_f32") != std::string::npos,
          "pseudocode exposes scalar floating width in the intrinsic name");
}
