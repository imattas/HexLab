#include "hexlab/loaders/elf.hpp"
#include "hexlab/loaders/raw.hpp"
#include "hexlab/loaders/recipe.hpp"
#include "hexlab/analysis/functions.hpp"
#include "hexlab/processors/decoder.hpp"
#include "hexlab/processors/format.hpp"
#include "support/analysis_fixture.hpp"
#include "support/checks.hpp"
#include "support/elf_fixture.hpp"
#include <array>
#include <vector>

using namespace hexlab;
using namespace hexlab_test;
namespace {
std::array<std::byte,4> encode(std::uint32_t word, ByteOrder order) {
    std::array<std::byte,4> bytes{};
    for (unsigned n=0;n<4;++n)
        bytes[order == ByteOrder::big ? 3-n : n] = std::byte((word >> (8*n)) & 0xff);
    return bytes;
}
void decode_basics() {
    const auto addi = encode((14u<<26)|(3u<<21)|0xffffu, ByteOrder::big);
    auto decoded = decode_instruction({Architecture::powerpc,ExecutionMode::ppc32,ByteOrder::big}, addi, {{0},0x1000});
    check(decoded.status == DecodeStatus::decoded && decoded.instruction->opcode == Opcode::ppc_addi &&
              decoded.instruction->register_writes == std::vector<RegisterOperand>{{RegisterBank::ppc_gpr,3,32,false}} &&
              format_instruction(*decoded.instruction).find("addi r3") == 0,
          "PPC32 big-endian ADDI has typed destination and formatted register");
    const auto little = encode((14u<<26)|(3u<<21)|7u, ByteOrder::little);
    decoded = decode_instruction({Architecture::powerpc,ExecutionMode::ppc64,ByteOrder::little}, little, {{0},0x1000});
    check(decoded.status == DecodeStatus::decoded && decoded.instruction->register_writes.front().width == 64,
          "PPC64 little-endian decoder uses 64-bit GPR effects");
    const auto oris = encode((25u<<26)|(4u<<21)|(5u<<16)|0x1234u, ByteOrder::big);
    decoded = decode_instruction({Architecture::powerpc,ExecutionMode::ppc32,ByteOrder::big}, oris, {{0},0});
    check(decoded.status == DecodeStatus::decoded && decoded.instruction->opcode == Opcode::ppc_oris &&
              std::get<ImmediateOperand>(decoded.instruction->operands[2]).value == 0x12340000,
          "ORIS preserves zero-extended shifted immediate");
    const auto nop = encode(0x60000000, ByteOrder::big);
    decoded = decode_instruction({Architecture::powerpc,ExecutionMode::ppc32,ByteOrder::big}, nop, {{0},0});
    check(decoded.status == DecodeStatus::decoded && decoded.instruction->opcode == Opcode::ppc_nop &&
              decoded.instruction->operands.empty() && format_instruction(*decoded.instruction) == "nop",
          "PowerPC canonical NOP has no fabricated operands");
}
void arithmetic_and_memory() {
    auto bytes = encode((31u<<26)|(3u<<21)|(4u<<16)|(5u<<11)|(266u<<1), ByteOrder::big);
    auto decoded = decode_instruction({Architecture::powerpc,ExecutionMode::ppc32,ByteOrder::big}, bytes, {{0},0});
    check(decoded.status == DecodeStatus::decoded && decoded.instruction->opcode == Opcode::ppc_add &&
              decoded.instruction->register_reads.size() == 2 && decoded.instruction->register_writes.front().index == 3,
          "ADD X-form reports both inputs and destination");
    bytes = encode((31u<<26)|(3u<<21)|(4u<<16)|(5u<<11)|(444u<<1)|1u, ByteOrder::big);
    decoded = decode_instruction({Architecture::powerpc,ExecutionMode::ppc32,ByteOrder::big}, bytes, {{0},0});
    check(decoded.status == DecodeStatus::decoded && decoded.instruction->opcode == Opcode::ppc_or_dot &&
              decoded.instruction->register_writes.front().index == 4 &&
              decoded.instruction->register_writes.back().bank == RegisterBank::ppc_cr,
          "OR. writes RA and condition register field CR0");
    bytes = encode((32u<<26)|(6u<<21)|(7u<<16)|0xfffcu, ByteOrder::big);
    decoded = decode_instruction({Architecture::powerpc,ExecutionMode::ppc64,ByteOrder::big}, bytes, {{0},0});
    const auto *memory = decoded.instruction ? std::get_if<MemoryOperand>(&decoded.instruction->operands[1]) : nullptr;
    check(decoded.status == DecodeStatus::decoded && decoded.instruction->opcode == Opcode::ppc_lwz &&
              memory && memory->data_width == 32 && memory->displacement == -4 &&
              memory->base && memory->base->index == 7,
          "LWZ decodes signed D-form displacement and base register");
    bytes = encode((58u<<26)|(6u<<21)|(7u<<16)|0xfffdu, ByteOrder::little);
    decoded = decode_instruction({Architecture::powerpc,ExecutionMode::ppc64,ByteOrder::little}, bytes, {{0},0});
    memory = decoded.instruction ? std::get_if<MemoryOperand>(&decoded.instruction->operands[1]) : nullptr;
    check(decoded.status == DecodeStatus::decoded && decoded.instruction->opcode == Opcode::ppc_ldu &&
              memory && memory->data_width == 64 && memory->displacement == -4 &&
              decoded.instruction->register_writes.back().index == 7,
          "PPC64 LDU preserves DS-form update semantics");
}
void rotate_and_immediate_arithmetic() {
    auto bytes = encode((21u<<26)|(3u<<21)|(4u<<16)|(8u<<11)|(5u<<6)|(20u<<1)|1u,
                        ByteOrder::big); // rlwinm. r3,r4,8,5,20
    auto decoded = decode_instruction({Architecture::powerpc,ExecutionMode::ppc32,ByteOrder::big},
                                      bytes, {{0},0});
    check(decoded.status == DecodeStatus::decoded && decoded.instruction->opcode == Opcode::ppc_rlwinm_dot &&
              decoded.instruction->register_reads == std::vector<RegisterOperand>{{RegisterBank::ppc_gpr,3,32,false}} &&
              decoded.instruction->register_writes.back() == RegisterOperand{RegisterBank::ppc_cr,0,4,false} &&
              format_instruction(*decoded.instruction).find("rlwinm.") == 0,
          "RLWINM record form rotates RS into RA and updates CR0");
    bytes = encode((7u<<26)|(3u<<21)|(4u<<16)|0xfffeu, ByteOrder::little);
    decoded = decode_instruction({Architecture::powerpc,ExecutionMode::ppc64,ByteOrder::little}, bytes, {{0},0});
    check(decoded.status == DecodeStatus::decoded && decoded.instruction->opcode == Opcode::ppc_mulli &&
              decoded.instruction->register_writes.front().width == 64 &&
              std::get<ImmediateOperand>(decoded.instruction->operands.back()).value == static_cast<std::uint64_t>(-2) &&
              std::get<ImmediateOperand>(decoded.instruction->operands.back()).is_signed,
          "MULLI sign-extends its encoded immediate and uses the PPC64 GPR width");
    bytes = encode((11u<<26)|(2u<<23)|(1u<<21)|(3u<<16)|0xffffu, ByteOrder::big);
    decoded = decode_instruction({Architecture::powerpc,ExecutionMode::ppc64,ByteOrder::big}, bytes, {{0},0});
    check(decoded.status == DecodeStatus::decoded && decoded.instruction->opcode == Opcode::ppc_cmpi &&
              decoded.instruction->register_writes == std::vector<RegisterOperand>{{RegisterBank::ppc_cr,2,4,false}} &&
              std::get<ImmediateOperand>(decoded.instruction->operands.back()).value == static_cast<std::uint64_t>(-1) &&
              std::get<ImmediateOperand>(decoded.instruction->operands.back()).is_signed,
          "CMPDI-style L-bit compare-immediate uses the requested CR field");
}
void control_flow() {
    auto bytes = encode((18u<<26)|(2u<<2)|1u, ByteOrder::big);
    auto decoded = decode_instruction({Architecture::powerpc,ExecutionMode::ppc32,ByteOrder::big}, bytes, {{0},0x1000});
    check(decoded.status == DecodeStatus::decoded && decoded.instruction->flow == FlowKind::call &&
              decoded.instruction->direct_target == Address{{0},0x1008} &&
              decoded.instruction->register_writes == std::vector<RegisterOperand>{{RegisterBank::ppc_lr,0,32,false}},
          "BL resolves PC-relative target and writes LR");
    bytes = encode((16u<<26)|(12u<<21)|(6u<<16)|(1u<<2), ByteOrder::big);
    decoded = decode_instruction({Architecture::powerpc,ExecutionMode::ppc64,ByteOrder::big}, bytes, {{0},0x2000});
    check(decoded.status == DecodeStatus::decoded && decoded.instruction->flow == FlowKind::conditional_branch &&
              decoded.instruction->direct_target == Address{{0},0x2004} &&
              decoded.instruction->register_reads.front() == RegisterOperand{RegisterBank::ppc_cr,1,4,false},
          "BC reads the selected CR field and resolves its target");
    bytes = encode((19u<<26)|(20u<<21)|(16u<<1), ByteOrder::big);
    decoded = decode_instruction({Architecture::powerpc,ExecutionMode::ppc64,ByteOrder::big}, bytes, {{0},0x2000});
    check(decoded.status == DecodeStatus::decoded && decoded.instruction->flow == FlowKind::ret &&
              decoded.instruction->register_reads == std::vector<RegisterOperand>{{RegisterBank::ppc_lr,0,64,false}},
          "canonical BCLR is identified as a PPC64 return");
    bytes = encode((19u<<26)|(20u<<21)|(528u<<1)|1u, ByteOrder::little);
    decoded = decode_instruction({Architecture::powerpc,ExecutionMode::ppc64,ByteOrder::little}, bytes, {{0},0x2000});
    check(decoded.status == DecodeStatus::decoded && decoded.instruction->flow == FlowKind::call &&
              decoded.instruction->register_reads.front().bank == RegisterBank::ppc_ctr &&
              decoded.instruction->register_writes.back().bank == RegisterBank::ppc_lr,
          "BCTR link form reads CTR and writes LR");
}
void status_and_raw() {
    auto d = decode_instruction({Architecture::powerpc,ExecutionMode::ppc32,ByteOrder::little},
                                std::span<const std::byte>{}, {{0},0});
    check(d.status == DecodeStatus::truncated, "truncated PowerPC instruction stays distinct");
    const auto reserved = encode(0, ByteOrder::little);
    d = decode_instruction({Architecture::powerpc,ExecutionMode::ppc32,ByteOrder::little}, reserved, {{0},0});
    check(d.status == DecodeStatus::invalid, "reserved PowerPC primary encoding stays invalid");
    const auto fp = encode(63u<<26, ByteOrder::little);
    d = decode_instruction({Architecture::powerpc,ExecutionMode::ppc32,ByteOrder::little}, fp, {{0},0});
    check(d.status == DecodeStatus::unsupported, "unimplemented floating-point instruction stays unsupported");
    RawOptions raw{Architecture::powerpc,ExecutionMode::ppc32,{{0},0x1000},true,false,true,{}};
    raw.order = ByteOrder::big;
    auto image = load_raw(std::make_shared<MemoryStorage>(std::vector<std::byte>(reserved.begin(),reserved.end())),raw,{});
    check(image && image.value()->layout().space.order == ByteOrder::big && image.value()->layout().space.width_bits == 32 &&
              image.value()->decode_context().architecture == Architecture::powerpc,
          "raw mapping retains PPC width and selected byte order");
    auto recipe = encode_recipe(LoadRecipe{Format::raw, raw});
    auto reopened = recipe ? decode_recipe(recipe.value()) : Result<LoadRecipe>(recipe.error());
    check(reopened && reopened.value().raw && reopened.value().raw->order == ByteOrder::big &&
              reopened.value().raw->mode == ExecutionMode::ppc32,
          "big-endian PPC raw order persists in durable load recipes");
    raw.base.offset = 0x1001;
    check(!validate_raw_coordinates(raw), "raw PPC code mapping rejects misaligned entry base");
}
void elf_contexts() {
    using namespace hexlab_test::elf_fixture;
    for (const auto [wide, big] : {std::pair{false,false}, std::pair{false,true}, std::pair{true,false}, std::pair{true,true}}) {
        auto data = executable(wide,big);
        put(data,18,wide ? 21 : 20,2,big);
        auto result = load_elf(std::make_shared<MemoryStorage>(data),{});
        check(result && result.value().image->decode_context().architecture == Architecture::powerpc &&
                  result.value().image->decode_context().mode == (wide ? ExecutionMode::ppc64 : ExecutionMode::ppc32) &&
                  result.value().image->decode_context().order == (big ? ByteOrder::big : ByteOrder::little),
              "ELF PPC machine/class/endian selects matching decode context");
    }
}
void reachable_function_flow() {
    std::vector<std::byte> code;
    for (const auto word : {0x38600001u, 0x48000004u, 0x4e800020u}) {
        const auto instruction = encode(word, ByteOrder::big);
        code.insert(code.end(), instruction.begin(), instruction.end());
    }
    RawOptions raw{Architecture::powerpc,ExecutionMode::ppc32,{{0},0x1000},true,false,true,{}};
    raw.order = ByteOrder::big;
    auto image = load_raw(std::make_shared<MemoryStorage>(std::move(code)), raw, {});
    check(bool(image), "raw PowerPC sample loads for automatic function analysis");
    if (!image) return;
    auto functions = recover_functions(*image.value(), {}, {}, {}, {});
    check(functions && functions.value()->functions.size() == 1 &&
              functions.value()->functions.front()->entry == Address{{0},0x1000} &&
              functions.value()->functions.front()->stops.size() == 1 &&
              functions.value()->functions.front()->stops.front().reason == FunctionStopReason::ret &&
              functions.value()->instructions.size() == 3,
          "reachable PPC32 direct branch and LR return form one recovered function");
}
}
int main() {
    decode_basics();
    arithmetic_and_memory();
    rotate_and_immediate_arithmetic();
    control_flow();
    status_and_raw();
    elf_contexts();
    reachable_function_flow();
    return failures ? 1 : 0;
}
