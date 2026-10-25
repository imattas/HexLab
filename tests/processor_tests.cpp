#include "hexlab/processors/decoder.hpp"
#include "hexlab/processors/format.hpp"
#include "hexlab/processors/x64_instruction_semantics.hpp"
#include "hexlab/processors/x86_string_execution.hpp"
#include "hexlab/processors/x64_semantics.hpp"
#include "support/checks.hpp"
#include "support/fixture_files.hpp"
#include <algorithm>
#include <functional>
#include <string_view>
#include <vector>
using namespace hexlab;
using namespace hexlab_test;

Instruction instruction(std::initializer_list<unsigned> values,Address at={{0},0x1000}) {
    const auto data=bytes(values);
    const auto result=decode_x64(data,at);
    check(result.status==DecodeStatus::decoded && result.instruction.has_value(),"fixture decodes");
    if (!result.instruction) throw std::runtime_error("Decode fixture failed: "+result.reason);
    check(result.instruction->length==data.size(),"fixture exact instruction length");
    for (std::size_t size=0;size<data.size();++size)
        check(decode_x64(std::span<const std::byte>(data).first(size),at).status!=DecodeStatus::decoded,"truncated known instruction has no success");
    return *result.instruction;
}
void check_complete_form(const std::vector<std::byte>& data) {
    const auto result=decode_x64(data,{{0},0x1000});
    check(result.instruction && result.instruction->length==data.size(),"complete encoded form has exact length");
    for (std::size_t size=0;size<data.size();++size)
        check(decode_x64(std::span<const std::byte>(data).first(size),{{0},0x1000}).status!=DecodeStatus::decoded,"truncated encoded form is not successful");
}
void move_tests() {
    auto i=instruction({0x48,0x89,0xe5});
    check(format_instruction(i)=="mov rbp, rsp","Intel register move formatting");
    check(std::get<RegisterOperand>(i.operands[0])==RegisterOperand{RegisterBank::gpr,5,64,false},"move destination identity");
    check(i.register_reads==std::vector<RegisterOperand>{{RegisterBank::gpr,4,64,false}} &&
          i.register_writes==std::vector<RegisterOperand>{{RegisterBank::gpr,5,64,false}},"move register effects");
    i=instruction({0x4d,0x8b,0x4c,0x24,0x08});
    check(std::get<RegisterOperand>(i.operands[0]).index==9,"REX extended destination");
    auto memory=std::get<MemoryOperand>(i.operands[1]);
    check(memory.base->index==12 && memory.displacement==8 && !memory.index && i.memory_read,"SIB R12 base and displacement");
    i=instruction({0x48,0x8d,0x05,0x10,0,0,0});
    memory=std::get<MemoryOperand>(i.operands[1]);
    check(memory.ip_relative && memory.resolved_address==Address{{0},0x1017} && !i.memory_read,"RIP relative LEA uses final instruction end");
    i=instruction({0x40,0x88,0xe0});
    check(std::get<RegisterOperand>(i.operands[1])==RegisterOperand{RegisterBank::gpr,4,8,false},"REX selects SPL");
    i=instruction({0x88,0xe0});
    check(std::get<RegisterOperand>(i.operands[1])==RegisterOperand{RegisterBank::gpr,0,8,true},"no REX selects AH");
    i=instruction({0x40,0x66,0x88,0xe0});
    check(std::get<RegisterOperand>(i.operands[1]).high_byte,"legacy prefix after REX cancels REX effect");
    i=instruction({0x66,0x40,0x88,0xe0});
    check(!std::get<RegisterOperand>(i.operands[1]).high_byte,"REX after legacy remains effective");
    i=instruction({0x66,0xb8,0x34,0x12});
    check(std::get<RegisterOperand>(i.operands[0]).width==16 && std::get<ImmediateOperand>(i.operands[1]).value==0x1234,"16-bit immediate move");
    i=instruction({0x49,0xb8,0x88,0x77,0x66,0x55,0x44,0x33,0x22,0x11});
    check(std::get<ImmediateOperand>(i.operands[1]).value==0x1122334455667788ULL,"64-bit immediate not truncated");
    i=instruction({0x48,0xc7,0xc0,0xff,0xff,0xff,0xff});
    check(std::get<ImmediateOperand>(i.operands[1]).value==UINT64_MAX,"MOV imm32 sign extends into r64");
    for (auto data:{bytes({0x8a,0x00}),bytes({0x89,0x08}),bytes({0xc6,0x00,0x42}),bytes({0x0f,0xb6,0x00}),
                   bytes({0x0f,0xb7,0x00}),bytes({0x0f,0xbe,0x00}),bytes({0x0f,0xbf,0x00}),bytes({0x48,0x63,0x00})})
        check_complete_form(data);
    i=instruction({0x67,0x48,0x8d,0x05,0x10,0,0,0},{{0},0x100001000ULL});
    memory=std::get<MemoryOperand>(i.operands[1]);
    check(memory.address_width==32 && memory.resolved_address==Address{{0},0x1018},"EIP-relative address override zero extends");
    i=instruction({0x4a,0x8b,0x04,0x20});
    check(std::get<MemoryOperand>(i.operands[1]).index->index==12,"REX.X enables R12 index");
    i=instruction({0x49,0x8b,0x05,0,0,0,0});
    check(std::get<MemoryOperand>(i.operands[1]).ip_relative,"REX.B does not replace RIP special case");
    i=instruction({0x49,0x8b,0x04,0x25,0,0,0,0});
    memory=std::get<MemoryOperand>(i.operands[1]);
    check(!memory.base && memory.resolved_address==Address{{0},0},"SIB no-base special case ignores REX.B");
    i=instruction({0x64,0x48,0x8b,0x04,0x25,0x30,0,0,0});
    check(std::get<MemoryOperand>(i.operands[1]).segment->index==4 && !std::get<MemoryOperand>(i.operands[1]).resolved_address,"FS base prevents fabricated resolved address");
    for(unsigned prefix:{0x64u,0x65u}) {
        i=instruction({prefix,0x48,0x8d,0x05,0x10,0,0,0});memory=std::get<MemoryOperand>(i.operands[1]);
        check(!memory.segment && memory.resolved_address==Address{{0},0x1018},"LEA ignores FS/GS bases when resolving RIP-relative effective address");
        check(i.register_reads==std::vector<RegisterOperand>{{RegisterBank::ip,0,64,false}} && !i.memory_read && !i.memory_write,"LEA has no segment or memory dependency");
        check(format_instruction(i)=="lea rax, [rip + 0x10]","LEA formatting omits ignored segment override");
        i=instruction({prefix,0x48,0x8d,0x04,0x25,0x30,0,0,0});memory=std::get<MemoryOperand>(i.operands[1]);
        check(!memory.segment && memory.resolved_address==Address{{0},0x30} && i.register_reads.empty(),"LEA absolute offset ignores FS/GS bases");
        i=instruction({prefix,0x48,0x8d,0x41,0x10});memory=std::get<MemoryOperand>(i.operands[1]);
        check(!memory.segment && !memory.resolved_address && i.register_reads==std::vector<RegisterOperand>{{RegisterBank::gpr,1,64,false}},"LEA based expression reads only its address registers");
    }
}
void arithmetic_tests() {
    const Opcode operations[]{Opcode::add,Opcode::bit_or,Opcode::adc,Opcode::sbb,Opcode::bit_and,Opcode::sub,Opcode::bit_xor,Opcode::cmp};
    for (unsigned group=0;group<8;++group) {
        auto data=bytes({group*8+1,0xc8});
        auto result=decode_x64(data,{{0},0x1000});
        check_complete_form(data);
        check(result.instruction && result.instruction->opcode==operations[group] && result.instruction->length==2,"arithmetic base family opcode");
        data=bytes({0x48,0x83,0xc0+group*8,0xff});result=decode_x64(data,{{0},0x1000});
        check_complete_form(data);
        check(result.instruction && result.instruction->opcode==operations[group] && std::get<ImmediateOperand>(result.instruction->operands[1]).value==UINT64_MAX,"group immediate sign extension");
        for (unsigned form:{0u,2u,3u,4u,5u}) {
            data=form<4?bytes({group*8+form,0x08}):form==4?bytes({group*8+4,0x80}):bytes({group*8+5,1,2,3,4});
            result=decode_x64(data,{{0},0x1000});
            check_complete_form(data);
            check(result.instruction && result.instruction->opcode==operations[group] && result.instruction->length==data.size(),"arithmetic direction/accumulator form");
        }
    }
    for (auto data:{bytes({0x80,0xc0,1}),bytes({0x81,0xc0,1,2,3,4}),bytes({0x84,0xc0}),bytes({0x85,0xc0}),
                   bytes({0xa8,0xff}),bytes({0xa9,1,2,3,4}),bytes({0xf6,0xc0,0xff}),bytes({0xf7,0xc0,1,2,3,4}),
                   bytes({0xfe,0xc0}),bytes({0xfe,0xc8}),bytes({0xff,0xc0}),bytes({0xff,0xc8}),
                   bytes({0xf6,0xd0}),bytes({0xf7,0xd8}),bytes({0x6b,0xc1,0xfe}),bytes({0x69,0xc1,1,2,3,4}),bytes({0x0f,0xaf,0xc1})})
        check_complete_form(data);
    struct UnaryMultiplyFixture { std::vector<std::byte> bytes; Opcode opcode; std::uint16_t width; };
    for (const auto &fixture : std::vector<UnaryMultiplyFixture>{
             {bytes({0xf6,0xe3}), Opcode::mul, 8}, {bytes({0xf6,0xeb}), Opcode::imul, 8},
             {bytes({0xf6,0xf3}), Opcode::div, 8}, {bytes({0xf6,0xfb}), Opcode::idiv, 8},
             {bytes({0x66,0xf7,0xe3}), Opcode::mul, 16}, {bytes({0xf7,0xeb}), Opcode::imul, 32},
             {bytes({0x48,0xf7,0xf3}), Opcode::div, 64}, {bytes({0x49,0xf7,0x7c,0x24,0x08}), Opcode::idiv, 64}}) {
        const auto result = decode_x64(fixture.bytes, {{0}, 0x1000});
        const auto operand_width = result.instruction ? std::visit([](const auto &operand) -> std::uint16_t {
            if constexpr (std::is_same_v<std::decay_t<decltype(operand)>, RegisterOperand>)
                return operand.width;
            else if constexpr (std::is_same_v<std::decay_t<decltype(operand)>, MemoryOperand>)
                return operand.data_width;
            else
                return 0;
        }, result.instruction->operands[0]) : 0;
        check(result.instruction && result.instruction->opcode == fixture.opcode &&
                  operand_width == fixture.width,
              "one-operand multiply/divide group decodes with selected width");
        check_complete_form(fixture.bytes);
    }
    auto implicit = instruction({0xf6,0xe3});
    check(implicit.register_reads.size() == 2 && implicit.register_reads[0] == RegisterOperand{RegisterBank::gpr,0,8,false} &&
              implicit.register_reads[1] == RegisterOperand{RegisterBank::gpr,3,8,false},
          "byte MUL reads AL and source");
    check(implicit.register_writes == std::vector<RegisterOperand>{{RegisterBank::gpr,0,16,false},
                                                                    {RegisterBank::flags,0,64,false}},
          "byte MUL writes combined AX result");
    implicit = instruction({0x48,0xf7,0xfb});
    check(implicit.register_reads == std::vector<RegisterOperand>{{RegisterBank::gpr,0,64,false},{RegisterBank::gpr,2,64,false},{RegisterBank::gpr,3,64,false}} &&
              implicit.register_writes == std::vector<RegisterOperand>{{RegisterBank::gpr,0,64,false},{RegisterBank::gpr,2,64,false}},
          "qword IDIV reads RDX:RAX and source and writes quotient/remainder registers");
    implicit = instruction({0x48,0xf7,0xe3});
    check(implicit.register_reads == std::vector<RegisterOperand>{{RegisterBank::gpr,0,64,false},{RegisterBank::gpr,3,64,false}} &&
              implicit.register_writes == std::vector<RegisterOperand>{{RegisterBank::gpr,0,64,false},
                                                                       {RegisterBank::gpr,2,64,false},
                                                                       {RegisterBank::flags,0,64,false}},
          "qword MUL reads RAX/source and writes RDX:RAX with arithmetic flags");
    implicit = instruction({0xf6,0xf3});
    check(implicit.register_reads == std::vector<RegisterOperand>{{RegisterBank::gpr,0,16,false},{RegisterBank::gpr,3,8,false}} &&
              implicit.register_writes == std::vector<RegisterOperand>{{RegisterBank::gpr,0,8,false},{RegisterBank::gpr,0,8,true}},
          "byte DIV reads AX and writes quotient AL and remainder AH");
    check(format_instruction(instruction({0x48,0xf7,0xe3})) == "mul rbx" &&
              format_instruction(instruction({0xf6,0xf3})) == "div bl" &&
              format_instruction(instruction({0x49,0xf7,0x7c,0x24,0x08})) == "idiv qword ptr [r12 + 0x8]",
          "implicit multiply and divide group mnemonics retain explicit source formatting");
    for (unsigned group:{0u,1u,2u,3u,4u,5u,7u})
        for (unsigned op:{0xc0u,0xc1u,0xd0u,0xd1u,0xd2u,0xd3u}) {
            auto data=bytes({op,0xc0+group*8});if(op<0xd0)data.push_back(std::byte{3});
            check_complete_form(data);
        }
    const auto locked=instruction({0xf0,0x48,0x01,0x08});
    check(locked.memory_read && locked.memory_write,"LOCK memory arithmetic effects");
    check(locked.lock_prefix && format_instruction(locked)=="lock add qword ptr [rax], rcx","LOCK modifier retained in facts and assembly");
    const auto unlocked=instruction({0x48,0x01,0x08});
    check(!unlocked.lock_prefix && format_instruction(unlocked)=="add qword ptr [rax], rcx","unlocked operation remains distinct");
}
void stack_flow_tests() {
    auto i=instruction({0xe8,0xfb,0xff,0xff,0xff});
    check(i.flow==FlowKind::call && i.direct_target==Address{{0},0x1000} && i.memory_write,"relative call and stack effect");
    i=instruction({0xeb,0xfe});check(i.direct_target==Address{{0},0x1000} && i.flow==FlowKind::jump,"negative short branch");
    for(unsigned condition=0;condition<16;++condition) {
        auto short_branch=decode_x64(bytes({0x70+condition,0}),{{0},0x1000});
        auto near_branch=decode_x64(bytes({0x0f,0x80+condition,0,0,0,0}),{{0},0x1000});
        check(short_branch.instruction && short_branch.instruction->condition==condition && short_branch.instruction->direct_target==Address{{0},0x1002},"short condition family");
        check(near_branch.instruction && near_branch.instruction->condition==condition && near_branch.instruction->direct_target==Address{{0},0x1006},"near condition family");
    }
    for(auto data:{bytes({0x50}),bytes({0x41,0x57}),bytes({0x58}),bytes({0x66,0x5f}),bytes({0x68,1,2,3,4}),bytes({0x6a,0xff}),
                  bytes({0xff,0x30}),bytes({0x8f,0x00}),bytes({0xc9}),bytes({0xe9,0,0,0,0}),bytes({0xff,0xd0}),
                  bytes({0xff,0x20}),bytes({0xc3}),bytes({0xc2,0x10,0}),bytes({0xcc}),bytes({0x90}),bytes({0x0f,0x1f,0x00}),
                  bytes({0xf3,0x0f,0x1e,0xfa}),bytes({0xf3,0x90}),bytes({0x66,0xc3})}) {
        const auto result=decode_x64(data,{{0},0x1000});
        check(result.instruction && result.instruction->length==data.size(),"stack/control/padding form");
        for(std::size_t n=0;n<data.size();++n)
            check(decode_x64(std::span<const std::byte>(data).first(n),{{0},0x1000}).status!=DecodeStatus::decoded,"truncated form cannot decode");
    }
    i=instruction({0xff,0xd0});check(!i.direct_target && i.flow==FlowKind::call,"indirect call remains unresolved");
    i=instruction({0xc2,0x10,0});check(std::get<ImmediateOperand>(i.operands[0]).value==16 && i.memory_read,"RET cleanup bytes and stack read");
    i=instruction({0xe9,0,0,0,0},{{0},UINT64_MAX-2});check(!i.direct_target,"branch end overflow has no wrapped target");
    const auto pushf = instruction({0x9c});
    const auto popf = instruction({0x9d});
    check(pushf.opcode == Opcode::pushf && pushf.stack_value_width == 64 && pushf.memory_write &&
              format_instruction(pushf) == "pushfq" &&
              std::find(pushf.register_reads.begin(), pushf.register_reads.end(), RegisterOperand{RegisterBank::flags,0,64,false}) != pushf.register_reads.end(),
          "PUSHFQ records qword flags source and stack write");
    check(popf.opcode == Opcode::popf && popf.stack_value_width == 64 && popf.memory_read &&
              format_instruction(popf) == "popfq" &&
              std::find(popf.register_writes.begin(), popf.register_writes.end(), RegisterOperand{RegisterBank::flags,0,64,false}) != popf.register_writes.end(),
          "POPFQ records qword flags destination and stack read");
    const auto pushfw = instruction({0x66,0x9c});
    check(pushfw.stack_value_width == 16 && format_instruction(pushfw) == "pushfw" &&
              std::find(pushfw.register_reads.begin(), pushfw.register_reads.end(), RegisterOperand{RegisterBank::flags,0,16,false}) != pushfw.register_reads.end(),
          "long-mode operand override selects PUSHFW width");
    const auto enter = instruction({0xc8,0x20,0,0x03});
    check(enter.opcode == Opcode::enter && enter.operands.size() == 2 && enter.stack_slot_count == 4 &&
              enter.stack_value_width == 64 && enter.memory_read && enter.memory_write &&
              std::get<ImmediateOperand>(enter.operands[0]).encoding == EncodedField{1,2} &&
              std::get<ImmediateOperand>(enter.operands[1]).encoding == EncodedField{3,1},
          "ENTER preserves allocation/nesting fields and nested stack-chain effects");
    for (const auto &raw : {bytes({0x60}), bytes({0x61})}) {
        const auto rejected = decode_x64(raw, {{0}, 0x1000});
        check(rejected.status == DecodeStatus::invalid && !rejected.instruction,
              "PUSHA/POPA fail closed in long mode");
    }
    const auto masked_enter = decode_x64(bytes({0xc8,0,0,0x20}), {{0}, 0x1000});
    check(masked_enter.instruction && masked_enter.instruction->stack_slot_count == 1 &&
              std::get<ImmediateOperand>(masked_enter.instruction->operands[1]).value == 0x20,
          "ENTER masks the high nesting bits for effects while preserving the encoded immediate");
}
void string_instruction_tests() {
    struct Family { std::uint8_t byte_opcode, wide_opcode; Opcode opcode; std::string_view byte_text, wide_text; };
    constexpr Family families[]{{0xa4,0xa5,Opcode::x86_movs,"movsb","movsq"},
                                {0xa6,0xa7,Opcode::x86_cmps,"cmpsb","cmpsq"},
                                {0xaa,0xab,Opcode::x86_stos,"stosb","stosq"},
                                {0xac,0xad,Opcode::x86_lods,"lodsb","lodsq"},
                                {0xae,0xaf,Opcode::x86_scas,"scasb","scasq"}};
    const RegisterOperand rflags{RegisterBank::flags,0,64,false};
    for (const auto &family : families) {
        const auto byte = instruction({family.byte_opcode});
        const auto qword = instruction({0x48,family.wide_opcode});
        check(byte.opcode == family.opcode && qword.opcode == family.opcode &&
                  format_instruction(byte) == family.byte_text && format_instruction(qword) == family.wide_text,
              "implicit string instruction family and operand-size suffix decode");
        const auto memory_count = std::count_if(byte.operands.begin(), byte.operands.end(), [](const Operand &operand) {
            return std::holds_alternative<MemoryOperand>(operand);
        });
        check(memory_count == (family.opcode == Opcode::x86_movs || family.opcode == Opcode::x86_cmps ? 2 : 1),
              "string instruction exposes each implicit memory reference");
        const bool compare = family.opcode == Opcode::x86_cmps || family.opcode == Opcode::x86_scas;
        check((std::find(byte.register_writes.begin(),byte.register_writes.end(),rflags) != byte.register_writes.end()) == compare,
              "compare and scan strings expose flag writes only");
        for (const auto prefix : {std::uint8_t{0xf2}, std::uint8_t{0xf3}}) {
            const auto repeated = instruction({prefix,family.byte_opcode});
            const auto expected = prefix == 0xf2 ? X86RepeatPrefix::repne : X86RepeatPrefix::rep;
            check(repeated.x86_repeat == expected && repeated.register_reads.end() !=
                      std::find(repeated.register_reads.begin(), repeated.register_reads.end(),
                                RegisterOperand{RegisterBank::gpr,1,64,false}) &&
                      repeated.register_writes.end() !=
                      std::find(repeated.register_writes.begin(), repeated.register_writes.end(),
                                RegisterOperand{RegisterBank::gpr,1,64,false}),
                  "F2/F3 string forms preserve prefix and read/update RCX");
            check(format_instruction(repeated).starts_with(prefix == 0xf2 ? "repne " : "rep "),
                  "string repeat prefix renders before mnemonic");
            check_complete_form(bytes({prefix,family.byte_opcode}));
        }
    }
    struct ModeCase { ExecutionMode mode; Architecture architecture; std::uint16_t scalar_width; std::uint16_t address_width; };
    constexpr ModeCase modes[]{{ExecutionMode::x86_16,Architecture::x86,16,16},
                               {ExecutionMode::x86_16,Architecture::x86,32,16},
                               {ExecutionMode::x86_32,Architecture::x86,32,32},
                               {ExecutionMode::x86_32,Architecture::x86,16,32},
                               {ExecutionMode::x86_64,Architecture::x86_64,32,64},
                               {ExecutionMode::x86_64,Architecture::x86_64,16,64},
                               {ExecutionMode::x86_64,Architecture::x86_64,64,64}};
    for (const auto &mode : modes) {
        const DecodeContext context{mode.architecture,mode.mode,ByteOrder::little};
        for (const auto &family : families) {
            for (const bool byte_form : {false,true}) {
                for (const auto prefix : {std::uint8_t{0},std::uint8_t{0xf2},std::uint8_t{0xf3}}) {
                    for (const bool address_override : {false,true}) {
                    std::vector<std::byte> encoding;
                    if (address_override)
                        encoding.push_back(std::byte{0x67});
                    if (prefix)
                        encoding.push_back(std::byte{prefix});
                    const bool operand_override =
                        (mode.mode == ExecutionMode::x86_16 && mode.scalar_width == 32) ||
                        (mode.mode == ExecutionMode::x86_32 && mode.scalar_width == 16) ||
                        (mode.mode == ExecutionMode::x86_64 && mode.scalar_width == 16);
                    if (!byte_form && operand_override)
                        encoding.push_back(std::byte{0x66});
                    else if (!byte_form && mode.scalar_width == 64)
                        encoding.push_back(std::byte{0x48});
                    encoding.push_back(std::byte{byte_form ? family.byte_opcode : family.wide_opcode});
                    const auto decoded = decode_instruction(context,encoding,{{0},0x2000});
                    const auto *typed_memory = decoded.instruction
                                                   ? [&]() -> const MemoryOperand * {
                                                         for (const auto &operand : decoded.instruction->operands)
                                                             if (const auto *memory = std::get_if<MemoryOperand>(&operand))
                                                                 return memory;
                                                         return nullptr;
                                                     }()
                                                   : nullptr;
                    const auto wanted_width = byte_form ? 8 : mode.scalar_width;
                    const auto expected_repeat = prefix == 0xf2 ? X86RepeatPrefix::repne
                                                 : prefix == 0xf3 ? X86RepeatPrefix::rep
                                                                  : X86RepeatPrefix::none;
                    const auto expected_address_width = address_override
                                                            ? static_cast<std::uint16_t>(mode.address_width == 16 ? 32 :
                                                                                         mode.address_width == 32 ? 16 : 32)
                                                            : mode.address_width;
                    const bool matrix_ok = decoded.instruction && decoded.instruction->opcode == family.opcode &&
                              decoded.instruction->length == encoding.size() &&
                              decoded.instruction->x86_repeat == expected_repeat &&
                              typed_memory && typed_memory->data_width == wanted_width &&
                              typed_memory->address_width == expected_address_width;
                    check(matrix_ok,"generated string family/mode/width/repeat encoding has typed effects");
                    for (std::size_t n = 0; n < encoding.size(); ++n)
                        check(decode_instruction(context,std::span<const std::byte>(encoding).first(n),{{0},0x2000}).status !=
                                  DecodeStatus::decoded,
                              "every truncated generated string encoding is rejected");
                    }
                }
            }
        }
    }
    const auto source_override = instruction({0x64,0xf3,0xa4});
    const auto destination = std::get<MemoryOperand>(source_override.operands[0]);
    const auto source = std::get<MemoryOperand>(source_override.operands[1]);
    check(!destination.segment && source.segment == RegisterOperand{RegisterBank::segment,4,16,false} &&
              format_instruction(source_override) == "rep movsb byte ptr [rdi], byte ptr fs:[rsi]",
          "FS override applies to the source string operand, never the fixed ES destination");
    const DecodeContext segmented16{Architecture::x86,ExecutionMode::x86_16,ByteOrder::little,0,true};
    const auto segmented_move = decode_instruction(segmented16,bytes({0xa4}),{{0},0x1000});
    check(segmented_move.instruction &&
              std::get<MemoryOperand>(segmented_move.instruction->operands[0]).segment ==
                  RegisterOperand{RegisterBank::segment,0,16,false} &&
              std::get<MemoryOperand>(segmented_move.instruction->operands[1]).segment ==
                  RegisterOperand{RegisterBank::segment,3,16,false} &&
              format_instruction(*segmented_move.instruction) == "movsb byte ptr es:[di], byte ptr ds:[si]",
          "segmented legacy MOVS exposes the fixed ES destination and default DS source");
    const auto address_override = instruction({0x67,0xf3,0xa5});
    check(std::get<MemoryOperand>(address_override.operands[0]).address_width == 32 &&
              std::get<MemoryOperand>(address_override.operands[0]).base == RegisterOperand{RegisterBank::gpr,7,32,false} &&
              std::find(address_override.register_writes.begin(),address_override.register_writes.end(),
                        RegisterOperand{RegisterBank::gpr,1,32,false}) != address_override.register_writes.end(),
          "address-size override selects ESI/EDI and ECX for string iteration");
    const auto word = instruction({0x66,0xa5});
    const auto dword = instruction({0x67,0x66,0xa5});
    check(std::get<MemoryOperand>(word.operands[0]).data_width == 16 && format_instruction(word) == "movsw" &&
              std::get<MemoryOperand>(dword.operands[0]).data_width == 16 &&
              std::get<MemoryOperand>(dword.operands[0]).address_width == 32,
          "operand and address overrides independently size string data and indexes");
    const auto repeated_compare = instruction({0xf3,0xa6});
    check(repeated_compare.register_reads.end() !=
              std::find(repeated_compare.register_reads.begin(),repeated_compare.register_reads.end(),rflags) &&
              repeated_compare.register_writes.end() !=
              std::find(repeated_compare.register_writes.begin(),repeated_compare.register_writes.end(),rflags),
          "repeated compare exposes status flag dependency for its continuation condition");
    check(decode_x64(bytes({0xf0,0xa4}),{{0},0x1000}).status == DecodeStatus::invalid &&
              decode_x64(bytes({0xf3,0xa8,0x01}),{{0},0x1000}).status == DecodeStatus::unsupported,
          "LOCK stays invalid and repeat prefixes remain constrained to supported string instructions");

    for (const auto mode : {ExecutionMode::x86_16,ExecutionMode::x86_32,ExecutionMode::x86_64}) {
        const DecodeContext context{mode == ExecutionMode::x86_64 ? Architecture::x86_64 : Architecture::x86,
                                    mode,ByteOrder::little};
        const auto decoded = decode_instruction(context,bytes({0xa5}),{{0},0x1000});
        check(decoded.instruction && decoded.instruction->opcode == Opcode::x86_movs,
              "MOVS is supported across x86-16, x86-32 and x86-64 contexts");
    }
}
void string_semantic_tests() {
    X86StringState state{0xffff, 0x20, 3, 0, true, {}};
    auto movsb = instruction({0xf3, 0xa4});
    auto result = evaluate_x86_string_iteration(movsb, state, 0x7a, std::nullopt);
    check(result && result->executed && result->memory_write_offset == 0x20 &&
              result->memory_write_value == 0x7a && result->state.source_index == 0xfffe &&
              result->state.destination_index == 0x1f && result->state.count == 2 && result->repeat,
          "REP MOVSB transfers one byte, decrements count and follows DF with address-width wraparound");

    state = {0, 0, 0, 0, false, {}};
    result = evaluate_x86_string_iteration(movsb, state, 0x11, std::nullopt);
    check(result && !result->executed && !result->memory_write_value && result->state == state &&
              !result->repeat,
          "a repeated string operation with zero count performs no memory operation");

    auto cmps = instruction({0x67, 0xf3, 0xa6});
    state = {0xffff'ffff, 0, 2, 0, false, {}};
    result = evaluate_x86_string_iteration(cmps, state, 5, 5);
    check(result && result->executed && result->state.source_index == 0 &&
              result->state.destination_index == 1 && result->state.count == 1 &&
              result->state.flags.zero && result->repeat,
          "REPE CMPS updates address-sized indices and continues on equal values");
    state = result->state;
    result = evaluate_x86_string_iteration(cmps, state, 4, 5);
    check(result && !result->state.flags.zero && !result->repeat && result->state.count == 0,
          "REPE CMPS stops after the first unequal comparison");

    auto scas = instruction({0x67, 0xf2, 0xae});
    state = {0, 0xffff'ffff, 2, 0x100, false, {}};
    result = evaluate_x86_string_iteration(scas, state, std::nullopt, 1);
    check(result && result->executed && !result->state.flags.zero && result->state.count == 1 &&
              result->repeat && result->state.destination_index == 0,
          "REPNE SCAS compares accumulator and memory and continues while unequal");
    result = evaluate_x86_string_iteration(scas, result->state, std::nullopt, 0);
    check(result && result->state.flags.zero && result->state.count == 0 && !result->repeat,
          "REPNE SCAS stops on equality even when the count remains nonzero");

    auto lods = instruction({0x48, 0xad});
    state = {0x40, 0, 0, 0, false, {}};
    result = evaluate_x86_string_iteration(lods, state, UINT64_C(0x8877665544332211), std::nullopt);
    check(result && result->executed && result->state.accumulator == UINT64_C(0x8877665544332211) &&
              result->state.source_index == 0x48 && !result->memory_write_offset,
          "LODS transfers the decoded width into the accumulator without a store");

    auto addr32 = decode_instruction({Architecture::x86_64, ExecutionMode::x86_64, ByteOrder::little},
                                     bytes({0x67, 0xf3, 0xaa}), {{0},0x1000});
    state = {0, 0xffff'ffff, 2, 0x1234, false, {}};
    result = addr32.instruction
                 ? evaluate_x86_string_iteration(*addr32.instruction, state, std::nullopt, std::nullopt)
                 : std::nullopt;
    check(result && result->memory_write_offset == 0xffff'ffff &&
              result->memory_write_value == 0x34 && result->state.destination_index == 0 &&
              result->state.count == 1,
          "address-size override truncates the accumulator, index and repeat counter independently");

    state = {0, 0, UINT64_C(0x100000000), 0x12, false, {}};
    result = evaluate_x86_string_iteration(*addr32.instruction, state, std::nullopt, std::nullopt);
    check(result && !result->executed && result->state == state,
          "zero low address-sized count exits REP without modifying the containing 64-bit register");

    const auto x86_32_addr16 = decode_instruction({Architecture::x86, ExecutionMode::x86_32, ByteOrder::little},
                                                  bytes({0x67, 0xf3, 0xa4}), {{0},0x1000});
    state = {UINT64_C(0xabcdffff), UINT64_C(0x1234ffff), UINT64_C(0x56780001), 0, false, {}};
    result = x86_32_addr16.instruction
                 ? evaluate_x86_string_iteration(*x86_32_addr16.instruction, state, 0x81, std::nullopt)
                 : std::nullopt;
    check(result && result->source_offset == 0xffff && result->destination_offset == 0xffff &&
              result->state.source_index == UINT64_C(0xabcd0000) &&
              result->state.destination_index == UINT64_C(0x12340000) &&
              result->state.count == UINT64_C(0x56780000),
          "16-bit address override updates low SI/DI/CX and preserves high halves of 32-bit registers");

    const auto x86_16 = decode_instruction({Architecture::x86, ExecutionMode::x86_16, ByteOrder::little},
                                           bytes({0xf3, 0xa4}), {{0},0x1000});
    state = {UINT64_C(0xabcdffff), UINT64_C(0x1234ffff), 1, 0, false, {}};
    result = x86_16.instruction
                 ? evaluate_x86_string_iteration(*x86_16.instruction, state, 0x81, std::nullopt)
                 : std::nullopt;
    check(result && result->state.source_index == 0 && result->state.destination_index == 0 &&
              result->state.count == 0 &&
              result->source_segment == RegisterOperand{RegisterBank::segment,3,16,false} &&
              result->destination_segment == RegisterOperand{RegisterBank::segment,0,16,false},
          "native 16-bit mode does not retain non-architectural upper index and count bits");

    const auto segmented = instruction({0x64, 0xf3, 0xa4});
    const auto segmented_result = evaluate_x86_string_iteration(
        segmented, {0, 0, 1, 0, false, {}}, 0x41, std::nullopt);
    check(segmented_result && segmented_result->source_segment == RegisterOperand{RegisterBank::segment,4,16,false} &&
              !segmented_result->destination_segment &&
              segmented_result->memory_write_segment == segmented_result->destination_segment,
          "string semantics preserve explicit FS source while long-mode destinations use flat addresses");

    auto malformed = movsb;
    std::get<MemoryOperand>(malformed.operands[0]).base = RegisterOperand{RegisterBank::gpr,0,64,false};
    check(!evaluate_x86_string_iteration(malformed, {0, 0, 1, 0, false, {}}, 1, std::nullopt),
          "string evaluator rejects malformed implicit index operands");

    std::vector<std::uint8_t> memory(256);
    memory[10] = 0x11; memory[11] = 0x22; memory[12] = 0x33;
    std::vector<std::uint8_t> writes;
    X86StringMemoryCallbacks callbacks;
    callbacks.read = [&](std::optional<RegisterOperand> segment, std::uint64_t offset, std::uint8_t width)
        -> std::optional<std::uint64_t> {
        check(width == 8 && segment == RegisterOperand{RegisterBank::segment,3,16,false},
              "repeated MOVS memory reader receives byte width and DS selector");
        if (offset >= memory.size()) return std::nullopt;
        return memory[static_cast<std::size_t>(offset)];
    };
    callbacks.write = [&](std::optional<RegisterOperand> segment, std::uint64_t offset,
                          std::uint64_t value, std::uint8_t width) {
        check(width == 8 && segment == RegisterOperand{RegisterBank::segment,0,16,false},
              "repeated MOVS memory writer receives byte width and ES selector");
        if (offset >= memory.size()) return false;
        memory[static_cast<std::size_t>(offset)] = static_cast<std::uint8_t>(value);
        writes.push_back(static_cast<std::uint8_t>(offset));
        return true;
    };
    auto execution = execute_x86_string_instruction(*x86_16.instruction, {10, 20, 3, 0, false, {}}, callbacks, 8);
    check(execution && execution->status == X86StringExecutionStatus::completed &&
              execution->iterations == 3 && execution->state.source_index == 13 &&
              execution->state.destination_index == 23 && execution->state.count == 0 &&
              memory[20] == 0x11 && memory[21] == 0x22 && memory[22] == 0x33 &&
              writes == std::vector<std::uint8_t>{20,21,22},
          "REP MOVSB runs complete iterations through caller memory callbacks");

    unsigned zero_count_accesses = 0;
    X86StringMemoryCallbacks counting_callbacks;
    counting_callbacks.read = [&](auto, auto, auto) -> std::optional<std::uint64_t> {
        ++zero_count_accesses; return 0;
    };
    counting_callbacks.write = [&](auto, auto, auto, auto) { ++zero_count_accesses; return true; };
    const X86StringState zero_state{10,20,0,0,false,{}};
    execution = execute_x86_string_instruction(*x86_16.instruction, zero_state, counting_callbacks, 8);
    check(execution && execution->status == X86StringExecutionStatus::completed &&
              execution->iterations == 0 && execution->state == zero_state && zero_count_accesses == 0,
          "REP with zero count completes without invoking memory callbacks");

    X86StringMemoryCallbacks faulting_callbacks = callbacks;
    faulting_callbacks.write = [](auto, std::uint64_t offset, auto, auto) { return offset != 21; };
    execution = execute_x86_string_instruction(*x86_16.instruction, {10,20,3,0,false,{}}, faulting_callbacks, 8);
    check(execution && execution->status == X86StringExecutionStatus::memory_fault &&
              execution->iterations == 1 && execution->state.source_index == 11 &&
              execution->state.destination_index == 21 && execution->state.count == 2 &&
              execution->fault && execution->fault->access == X86StringAccessKind::destination_write &&
              execution->fault->offset == 21,
          "a store fault preserves prior REP progress and does not commit the faulting iteration");

    execution = execute_x86_string_instruction(*x86_16.instruction, {10,20,3,0,false,{}}, callbacks, 2);
    check(execution && execution->status == X86StringExecutionStatus::iteration_limit &&
              execution->iterations == 2 && execution->state.source_index == 12 &&
              execution->state.destination_index == 22 && execution->state.count == 1,
          "repeated string execution stops at the caller-supplied iteration budget");

    auto repne_scas = instruction({0xf2, 0xae});
    std::vector<std::uint8_t> scan_memory{0x11, 0x22, 0x33};
    unsigned scan_reads = 0;
    X86StringMemoryCallbacks scan_callbacks;
    scan_callbacks.read = [&](auto, std::uint64_t offset, auto width) -> std::optional<std::uint64_t> {
        check(width == 8 && offset < scan_memory.size(), "REPNE SCAS reads byte-sized destination elements");
        ++scan_reads;
        if (offset >= scan_memory.size()) return std::nullopt;
        return scan_memory[static_cast<std::size_t>(offset)];
    };
    execution = execute_x86_string_instruction(repne_scas, {0, 0, 3, 0x22, false, {}}, scan_callbacks, 8);
    check(execution && execution->status == X86StringExecutionStatus::completed &&
              execution->iterations == 2 && execution->state.destination_index == 2 &&
              execution->state.count == 1 && execution->state.flags.zero && scan_reads == 2,
          "REPNE SCAS runs callbacks until the accumulator matches and then stops");
}
void condition_semantic_tests() {
    using C = X86Condition;
    const C conditions[]{C::overflow, C::not_overflow, C::below, C::above_equal,
        C::equal, C::not_equal, C::below_equal, C::above, C::sign, C::not_sign,
        C::parity, C::not_parity, C::less, C::greater_equal, C::less_equal, C::greater};
    for (unsigned condition = 0; condition < 16; ++condition) {
        for (unsigned bits = 0; bits < 32; ++bits) {
            const X86Flags flags{bool(bits & 1), bool(bits & 2), bool(bits & 4), bool(bits & 8), bool(bits & 16)};
            const bool parity = flags.parity;
            const bool signed_less = flags.sign != flags.overflow;
            const bool expected[]{flags.overflow, !flags.overflow, flags.carry, !flags.carry,
                flags.zero, !flags.zero, flags.carry || flags.zero, !flags.carry && !flags.zero,
                flags.sign, !flags.sign, parity, !parity, signed_less, !signed_less,
                flags.zero || signed_less, !flags.zero && !signed_less};
            check(evaluate_x86_condition(conditions[condition], flags) == expected[condition],
                  "typed x86 condition evaluates the architectural flag predicate");
        }
        const auto short_branch = instruction({0x70 + condition, 0});
        const auto near_branch = instruction({0x0f, 0x80 + condition, 0, 0, 0, 0});
        check(short_branch.x86_condition == conditions[condition] &&
                  near_branch.x86_condition == conditions[condition],
              "short and near Jcc decode to a typed condition code");
        const RegisterOperand status_flags{RegisterBank::flags, 0, 64, false};
        check(std::find(short_branch.register_reads.begin(), short_branch.register_reads.end(), status_flags) !=
                  short_branch.register_reads.end() &&
                  std::find(near_branch.register_reads.begin(), near_branch.register_reads.end(), status_flags) !=
                  near_branch.register_reads.end(),
              "short and near Jcc expose a status-flag read dependency");
    }
}
void arithmetic_flag_semantic_tests() {
    const auto add8 = evaluate_x86_arithmetic(X86Arithmetic::add, 0x7f, 0x01, false, 8);
    check(add8.value == 0x80 && add8.flags == X86Flags{false, false, false, true, true},
          "8-bit ADD computes wrapped result, parity, sign and signed overflow");
    const auto carry64 = evaluate_x86_arithmetic(X86Arithmetic::adc, UINT64_MAX, 0, true, 64);
    check(carry64.value == 0 && carry64.flags == X86Flags{true, true, true, false, false},
          "64-bit ADC carries across the full unsigned width");
    const auto overflow_adc = evaluate_x86_arithmetic(X86Arithmetic::adc, 0x7f, 0, true, 8);
    check(overflow_adc.value == 0x80 && overflow_adc.flags.overflow && overflow_adc.flags.sign,
          "ADC detects signed overflow caused by its carry-in");
    const auto sub8 = evaluate_x86_arithmetic(X86Arithmetic::sub, 0x80, 1, false, 8);
    check(sub8.value == 0x7f && sub8.flags == X86Flags{false, false, false, false, true},
          "8-bit SUB computes signed overflow without unsigned borrow");
    const auto sbb = evaluate_x86_arithmetic(X86Arithmetic::sbb, 0, 0, true, 8);
    check(sbb.value == 0xff && sbb.flags == X86Flags{true, true, false, true, false},
          "8-bit SBB incorporates incoming borrow");
    const auto cmp = evaluate_x86_arithmetic(X86Arithmetic::compare, 0x100, 0x100, false, 16);
    check(cmp.value == 0 && cmp.flags == X86Flags{false, true, true, false, false},
          "CMP shares subtraction flags at the selected operand width");
    const auto logic = evaluate_x86_arithmetic(X86Arithmetic::bit_xor, 0xf0, 0x0f, true, 8);
    check(logic.value == 0xff && logic.flags == X86Flags{false, true, false, true, false},
          "logical operations clear carry and overflow and derive status flags");
    check(evaluate_x86_arithmetic(X86Arithmetic::add, UINT64_MAX, 1, false, 64).value == 0 &&
              evaluate_x86_arithmetic(X86Arithmetic::bit_and, 0x1ff, 0xff, false, 8).value == 0xff &&
              evaluate_x86_arithmetic(X86Arithmetic::add, UINT64_C(0x1ffffffff), 1, false, 32) ==
                  X86ArithmeticResult{0, X86Flags{true, true, true, false, false}},
          "arithmetic helpers mask operands and results to 8 through 64 bits");
    const auto decoded_add = instruction({0x48, 0x83, 0xc0, 0x01});
    const auto decoded_result = evaluate_x86_arithmetic_instruction(decoded_add, UINT64_MAX, 1, false);
    check(decoded_result && *decoded_result == X86ArithmeticResult{0, X86Flags{true, true, true, false, false}},
          "decoded arithmetic instruction selects its opcode and operand width for evaluation");
    const auto decoded_nop = instruction({0x90});
    check(!evaluate_x86_arithmetic_instruction(decoded_nop, 1, 2, false),
          "instruction evaluator rejects opcodes outside scalar arithmetic semantics");
    auto arm_add = decoded_add;
    arm_add.context = {Architecture::arm, ExecutionMode::a32, ByteOrder::little};
    check(!evaluate_x86_arithmetic_instruction(arm_add, 1, 2, false),
          "instruction evaluator rejects generic arithmetic opcodes from non-x86 decode contexts");
}
void bit_operation_semantic_tests() {
    const auto btc = instruction({0x48, 0x0f, 0xbb, 0xc8}); // btc rax, rcx
    const auto btc_result = evaluate_x86_bit_operation_instruction(btc, 0x10, 4);
    check(btc_result && btc_result->value == 0 && btc_result->writes_destination &&
              btc_result->flags.carry == X86DefinedFlag{true, true} &&
              !btc_result->flags.zero.defined,
          "BTC toggles the selected bit, reports its old value in CF, and marks unrelated flags undefined");

    const auto bt = instruction({0x0f, 0xba, 0xe0, 0x07}); // bt eax, 7
    const auto bt_result = evaluate_x86_bit_operation_instruction(bt, 0x80);
    check(bt_result && !bt_result->writes_destination && bt_result->value == 0x80 &&
              bt_result->flags.carry == X86DefinedFlag{true, true},
          "immediate BT leaves its operand unchanged and sets CF from the selected bit");

    const auto bts = instruction({0x0f, 0xab, 0xc8});
    const auto btr = instruction({0x0f, 0xb3, 0xc8});
    const auto set_result = evaluate_x86_bit_operation_instruction(bts, 0, 3);
    const auto reset_result = evaluate_x86_bit_operation_instruction(btr, 0x18, 3);
    check(set_result && set_result->value == 8 && set_result->writes_destination &&
              !set_result->flags.carry.value && reset_result && reset_result->value == 0x10 &&
              reset_result->flags.carry.value,
          "BTS and BTR set or clear the selected bit and report its previous state");

    const auto tzcnt = instruction({0xf3, 0x48, 0x0f, 0xbc, 0xc1});
    const auto zero_count = evaluate_x86_bit_operation_instruction(tzcnt, 0, 0);
    const auto nonzero_count = evaluate_x86_bit_operation_instruction(tzcnt, 0x100, 0);
    const auto zero_result_count = evaluate_x86_bit_operation_instruction(tzcnt, 1, 0);
    check(zero_count && zero_count->value == 64 && zero_count->flags.carry.value &&
              !zero_count->flags.zero.value && nonzero_count && nonzero_count->value == 8 &&
              !nonzero_count->flags.carry.value && !nonzero_count->flags.zero.value &&
              zero_result_count && zero_result_count->value == 0 && zero_result_count->flags.zero.value,
          "TZCNT returns operand width for zero and sets CF/ZF from input and result");

    const auto bsf = instruction({0x0f, 0xbc, 0xc1});
    const auto bsr = instruction({0x0f, 0xbd, 0xc1});
    const auto zero_scan = evaluate_x86_bit_operation_instruction(bsf, 0, 0);
    const auto reverse_scan = evaluate_x86_bit_operation_instruction(bsr, 0x80000000, 0);
    check(zero_scan && !zero_scan->destination_defined && zero_scan->flags.zero.value &&
              !zero_scan->flags.carry.defined && reverse_scan && reverse_scan->value == 31,
          "BSF zero input leaves its destination undefined while BSR returns the highest set-bit index");
    const auto lzcnt = instruction({0xf3, 0x0f, 0xbd, 0xc1});
    const auto leading_zero_count = evaluate_x86_bit_operation_instruction(lzcnt, 0x80000000, 0);
    check(leading_zero_count && leading_zero_count->value == 0 &&
              !leading_zero_count->flags.carry.value && leading_zero_count->flags.zero.value,
          "LZCNT returns the leading-zero count and sets ZF when the result is zero");

    const auto bt_memory = instruction({0x48, 0x0f, 0xa3, 0x08}); // bt [rax], rcx
    const auto negative_index = evaluate_x86_bit_operation_instruction(bt_memory, 0, UINT64_MAX);
    check(negative_index && negative_index->memory_element_adjustment == -8 &&
              negative_index->bit_index == 63,
          "memory BT interprets a register bit index as signed and adjusts to the preceding element");
    check(!evaluate_x86_bit_operation_instruction(instruction({0x90}), 0, 0),
          "bit-operation evaluator rejects unrelated instructions");
}
void multiply_divide_semantic_tests() {
    for (unsigned width : {8u, 16u, 32u, 64u}) {
        const auto unsigned_product = evaluate_x86_multiply(X86MultiplyKind::unsigned_multiply,
                                                            UINT64_MAX, 2, width);
        const auto mask = width == 64 ? UINT64_MAX : (UINT64_C(1) << width) - 1;
        check(unsigned_product && unsigned_product->low == (mask - 1) &&
                  unsigned_product->high == 1 && unsigned_product->flags.carry.value &&
                  unsigned_product->flags.overflow.value &&
                  !unsigned_product->flags.zero.defined,
              "unsigned MUL returns both width-sized halves and defined CF/OF");
        const auto signed_product = evaluate_x86_multiply(X86MultiplyKind::signed_multiply,
                                                          mask, 2, width);
        check(signed_product && signed_product->low == mask - 1 &&
                  signed_product->high == mask && !signed_product->flags.carry.value &&
                  !signed_product->flags.overflow.value,
              "signed IMUL returns the sign-extended full product without false overflow");
        const auto signed_overflow = evaluate_x86_multiply(X86MultiplyKind::signed_multiply,
                                                            (std::uint64_t{1} << (width - 1)) - 1,
                                                            2, width);
        check(signed_overflow && signed_overflow->flags.carry.value &&
                  signed_overflow->flags.overflow.value &&
                  !signed_overflow->flags.parity.defined &&
                  !signed_overflow->flags.zero.defined && !signed_overflow->flags.sign.defined,
              "signed IMUL reports truncation overflow while PF/ZF/SF remain undefined");

        const auto quotient = evaluate_x86_divide(X86DivideKind::unsigned_divide,
                                                  10, 0, 3, width);
        check(quotient && quotient->status == X86DivideStatus::success &&
                  quotient->quotient == 3 && quotient->remainder == 1,
              "unsigned DIV returns quotient and remainder");
        const auto signed_q = evaluate_x86_divide(X86DivideKind::signed_divide,
                                                  mask - 9, mask, 3, width);
        check(signed_q && signed_q->status == X86DivideStatus::success &&
                  signed_q->quotient == mask - 2 && signed_q->remainder == mask,
              "signed IDIV uses a signed double-width dividend");
        const auto zero = evaluate_x86_divide(X86DivideKind::unsigned_divide, 10, 0, 0, width);
        check(zero && zero->status == X86DivideStatus::divide_by_zero &&
                  !zero->quotient_valid && !zero->remainder_valid,
              "DIV by zero has no fabricated quotient or remainder");
        const auto min_over_minus_one = evaluate_x86_divide(X86DivideKind::signed_divide,
                                                            0, std::uint64_t{1} << (width - 1), mask, width);
        check(min_over_minus_one && min_over_minus_one->status == X86DivideStatus::quotient_overflow &&
                  !min_over_minus_one->quotient_valid && !min_over_minus_one->remainder_valid,
              "signed minimum divided by minus one reports overflow without results");
    }
    const auto decoded = instruction({0xf7, 0xe3});
    const auto adapted = evaluate_x86_multiply_instruction(decoded, 0xffffffff, 2);
    check(adapted && adapted->low == 0xfffffffe && adapted->high == 1,
          "decoded MUL adapter uses the instruction's scalar width and opcode");
    const auto decoded_div = instruction({0xf7, 0xf3});
    const auto adapted_div = evaluate_x86_divide_instruction(decoded_div, 10, 0, 3);
    check(adapted_div && adapted_div->status == X86DivideStatus::success &&
              adapted_div->quotient == 3 && adapted_div->remainder == 1,
          "decoded DIV adapter derives width and signedness from instruction effects");
}
void xchg_tests() {
    auto i=instruction({0x86,0xe0});
    check(opcode_name(i.opcode)=="xchg" && format_instruction(i)=="xchg al, ah" &&
          i.access==std::vector<OperandAccess>{OperandAccess::read_write,OperandAccess::read_write},
          "legacy byte XCHG selects AH without REX");
    i=instruction({0x40,0x86,0xe0});
    check(format_instruction(i)=="xchg al, spl" &&
          std::get<RegisterOperand>(i.operands[1])==RegisterOperand{RegisterBank::gpr,4,8,false},
          "REX prefix replaces AH with SPL in byte XCHG");
    i=instruction({0x48,0x91});
    check(format_instruction(i)=="xchg rax, rcx" && i.register_reads.size()==2 && i.register_writes.size()==2,
          "accumulator XCHG uses REX.W width and records both register effects");
    i=instruction({0x49,0x90});
    check(format_instruction(i)=="xchg rax, r8" && opcode_name(i.opcode)=="xchg",
          "REX.B changes the 90 encoding from NOP to accumulator XCHG");
    i=instruction({0x90});
    check(i.opcode==Opcode::nop && format_instruction(i)=="nop", "bare 90 remains canonical NOP");
    auto memory=instruction({0x48,0x87,0x08});
    check(memory.memory_read && memory.memory_write && !memory.lock_prefix &&
          memory.access[0]==OperandAccess::read_write,
          "memory XCHG carries read-write effects without requiring explicit LOCK");
    memory=instruction({0xf0,0x48,0x87,0x08});
    check(memory.memory_read && memory.memory_write && memory.lock_prefix &&
          format_instruction(memory)=="lock xchg qword ptr [rax], rcx",
          "explicit LOCK remains valid on memory XCHG");
    check(decode_x64(bytes({0xf0,0x48,0x87,0xc8}),{{0},0}).status==DecodeStatus::invalid,
          "LOCK on register-only long-mode XCHG is invalid");
    const auto truncated = bytes({0x48,0x87,0x48,0x10});
    for (std::size_t n=0;n<truncated.size();++n)
        check(decode_x64(std::span(truncated).first(n),{{0},0}).status==DecodeStatus::truncated,
              "incomplete long-mode memory XCHG remains truncated");
}
void sign_extension_tests() {
    auto i=instruction({0x48,0x98});
    check(opcode_name(i.opcode)=="cdqe" &&
          i.register_reads==std::vector<RegisterOperand>{{RegisterBank::gpr,0,32,false}} &&
          i.register_writes==std::vector<RegisterOperand>{{RegisterBank::gpr,0,64,false}},
          "REX.W CDQE reads EAX and writes RAX");
    i=instruction({0x48,0x99});
    check(opcode_name(i.opcode)=="cqo" &&
          i.register_reads==std::vector<RegisterOperand>{{RegisterBank::gpr,0,64,false}} &&
          i.register_writes==std::vector<RegisterOperand>{{RegisterBank::gpr,2,64,false}},
          "REX.W CQO reads RAX and writes RDX");
    i=instruction({0x66,0x98});
    check(opcode_name(i.opcode)=="cbw" &&
          i.register_reads==std::vector<RegisterOperand>{{RegisterBank::gpr,0,8,false}} &&
          i.register_writes==std::vector<RegisterOperand>{{RegisterBank::gpr,0,16,false}},
          "operand-size prefix selects CBW in long mode");
}
void arithmetic_width_effect_tests() {
    struct Fixture { std::vector<std::byte> encoding; std::uint16_t width; std::string_view text; };
    for (const Fixture &fixture : std::vector<Fixture>{
             {bytes({0x00, 0xc8}), 8, "add al, cl"},
             {bytes({0x66, 0x01, 0xc8}), 16, "add ax, cx"},
             {bytes({0x01, 0xc8}), 32, "add eax, ecx"},
             {bytes({0x48, 0x01, 0xc8}), 64, "add rax, rcx"},
             {bytes({0x4d, 0x01, 0xc8}), 64, "add r8, r9"},
             {bytes({0x41, 0x80, 0xc0, 0x01}), 8, "add r8b, 0x1"}}) {
        const auto decoded = decode_x64(fixture.encoding, {{0}, 0x1000});
        check(decoded.instruction && decoded.instruction->opcode == Opcode::add &&
                  format_instruction(*decoded.instruction) == fixture.text &&
                  decoded.instruction->access == std::vector<OperandAccess>{OperandAccess::read_write, OperandAccess::read} &&
                  std::get<RegisterOperand>(decoded.instruction->operands[0]).width == fixture.width &&
                  std::find(decoded.instruction->register_writes.begin(), decoded.instruction->register_writes.end(),
                            RegisterOperand{RegisterBank::flags, 0, 64, false}) != decoded.instruction->register_writes.end(),
              "ADD width, operand effects, flags and formatting follow mode and REX prefixes");
        check_complete_form(fixture.encoding);
    }
}
void data_move_semantic_tests() {
    auto mov = instruction({0x48, 0x89, 0xc8});
    check(evaluate_x86_data_move_instruction(mov, 0x123456789abcdef0ULL) ==
              std::optional<std::uint64_t>{0x123456789abcdef0ULL},
          "64-bit register MOV transfers the supplied source value");
    check(!evaluate_x86_data_move_instruction(mov),
          "register and memory MOV require a supplied runtime source value");

    mov = instruction({0x48, 0xc7, 0xc0, 0xff, 0xff, 0xff, 0xff});
    check(evaluate_x86_data_move_instruction(mov) == std::optional<std::uint64_t>{UINT64_MAX},
          "decoded sign-extended imm32 is the source value of MOV r64, imm32");
    mov = instruction({0x48, 0xc7, 0x01, 0xff, 0xff, 0xff, 0xff});
    check(evaluate_x86_data_move_instruction(mov) == std::optional<std::uint64_t>{UINT64_MAX} && mov.memory_write,
          "decoded sign-extended immediate evaluates a qword memory store");
    mov = instruction({0x48, 0x8b, 0x01});
    check(evaluate_x86_data_move_instruction(mov, 0xfedcba9876543210ULL) ==
              std::optional<std::uint64_t>{0xfedcba9876543210ULL} && mov.memory_read,
          "MOV load preserves the typed memory source width");
    mov = instruction({0x48, 0x89, 0x01});
    check(evaluate_x86_data_move_instruction(mov, 0x1020304050607080ULL) ==
              std::optional<std::uint64_t>{0x1020304050607080ULL} && mov.memory_write,
          "MOV store evaluates the source value at the typed memory destination width");
    mov = instruction({0x66, 0x89, 0xc8});
    check(evaluate_x86_data_move_instruction(mov, 0x12345678) ==
              std::optional<std::uint64_t>{0x5678},
          "operand-size override masks the MOV result to sixteen bits");

    const auto zero_extend = instruction({0x0f, 0xb6, 0xc1});
    check(evaluate_x86_data_move_instruction(zero_extend, 0x80) ==
              std::optional<std::uint64_t>{0x80},
          "MOVZX zero extends a byte into the destination width");
    const auto sign_extend = instruction({0x0f, 0xbe, 0xc1});
    check(evaluate_x86_data_move_instruction(sign_extend, 0x80) ==
              std::optional<std::uint64_t>{0xffffff80},
          "MOVSX sign extends an 8-bit source into a 32-bit destination");
    const auto memory_zero_extend = instruction({0x48, 0x0f, 0xb6, 0x01});
    check(evaluate_x86_data_move_instruction(memory_zero_extend, 0xffffffffffffffffULL) ==
              std::optional<std::uint64_t>{0xff},
          "MOVZX masks a memory source to its encoded byte width");
    const auto word_sign_extend = instruction({0x48, 0x0f, 0xbf, 0xc1});
    check(evaluate_x86_data_move_instruction(word_sign_extend, 0x8000) ==
              std::optional<std::uint64_t>{0xffffffffffff8000ULL},
          "REX.W MOVSX sign extends a word into a 64-bit destination");
    const auto movsxd = instruction({0x48, 0x63, 0xc1});
    check(evaluate_x86_data_move_instruction(movsxd, 0x80000000) ==
              std::optional<std::uint64_t>{0xffffffff80000000ULL},
          "MOVSXD sign extends a 32-bit source into a 64-bit destination");
    check(!evaluate_x86_data_move_instruction(instruction({0x90}), 0),
          "data-move evaluator rejects non-move instructions");
    auto arm_move = instruction({0x48, 0x89, 0xc8});
    arm_move.context = {Architecture::arm, ExecutionMode::a32, ByteOrder::little};
    check(!evaluate_x86_data_move_instruction(arm_move, 1),
          "data-move evaluator rejects non-x86 decode contexts");
}
void extended_x86_decode_tests() {
    const auto bytes_avx = bytes({0xc5, 0xf4, 0x58, 0xc2}); // vaddps ymm0, ymm1, ymm2
    const auto decoded = decode_instruction({Architecture::x86_64, ExecutionMode::x86_64, ByteOrder::little},
                                            bytes_avx, {{0}, 0x1000});
    check(decoded.status == DecodeStatus::decoded && decoded.instruction && decoded.instruction->length == 4 &&
              decoded.instruction->opcode == Opcode::vaddps && decoded.instruction->operands.size() == 3 &&
              decoded.instruction->flow == FlowKind::fallthrough &&
              std::get<RegisterOperand>(decoded.instruction->operands[0]) == RegisterOperand{RegisterBank::ymm, 0, 256, false} &&
              std::get<RegisterOperand>(decoded.instruction->operands[1]) == RegisterOperand{RegisterBank::ymm, 1, 256, false} &&
              std::get<RegisterOperand>(decoded.instruction->operands[2]) == RegisterOperand{RegisterBank::ymm, 2, 256, false} &&
              decoded.instruction->access == std::vector{OperandAccess::write, OperandAccess::read, OperandAccess::read} &&
              format_instruction(*decoded.instruction) == "vaddps ymm0, ymm1, ymm2",
          "AVX VADDPS decodes with typed YMM operands and non-destructive destination effects");
}
void conditional_data_tests() {
    static constexpr const char *conditions[]{"o", "no", "b", "ae", "e", "ne", "be", "a",
                                               "s", "ns", "p", "np", "l", "ge", "le", "g"};
    for (unsigned cc = 0; cc < 16; ++cc) {
        const auto cmov = instruction({0x48, 0x0f, 0x40 + cc, 0xc1});
        check(cmov.opcode == Opcode::cmovcc && cmov.condition == cc &&
                  cmov.x86_condition == static_cast<X86Condition>(cc) && cmov.operands.size() == 2 &&
                  cmov.access == std::vector<OperandAccess>{OperandAccess::read_write, OperandAccess::read} &&
                  cmov.register_reads == std::vector<RegisterOperand>{{RegisterBank::gpr, 0, 64, false},
                                                                       {RegisterBank::gpr, 1, 64, false},
                                                                       {RegisterBank::flags, 0, 64, false}} &&
                  cmov.register_writes == std::vector<RegisterOperand>{{RegisterBank::gpr, 0, 64, false}} &&
                  format_instruction(cmov) == std::string("cmov") + conditions[cc] + " rax, rcx",
              "CMOVcc has typed condition, conditional destination read/write and flag dependency");
        const auto set = instruction({0x0f, 0x90 + cc, 0xc4});
        check(set.opcode == Opcode::setcc && set.condition == cc &&
                  set.x86_condition == static_cast<X86Condition>(cc) &&
                  set.access == std::vector<OperandAccess>{OperandAccess::write} &&
                  std::get<RegisterOperand>(set.operands[0]) == RegisterOperand{RegisterBank::gpr, 0, 8, true} &&
                  set.register_reads == std::vector<RegisterOperand>{{RegisterBank::flags, 0, 64, false}} &&
                  set.register_writes == std::vector<RegisterOperand>{{RegisterBank::gpr, 0, 8, true}} &&
                  format_instruction(set) == std::string("set") + conditions[cc] + " ah",
              "SETcc writes an 8-bit destination and reads the typed condition flags");
    }
    const auto memory_set = instruction({0x0f, 0x94, 0x44, 0x8b, 0x10});
    check(memory_set.memory_write && !memory_set.memory_read &&
              format_instruction(memory_set) == "sete byte ptr [rbx + rcx*4 + 0x10]",
          "SETcc memory destination is a byte write with ordinary effective-address dependencies");
    const auto memory_cmov = instruction({0x0f, 0x45, 0x03});
    check(memory_cmov.memory_read && !memory_cmov.memory_write,
          "CMOVcc memory source records a read while preserving conditional register write semantics");
    const auto cmov16 = instruction({0x66, 0x0f, 0x44, 0xc1});
    check(cmov16.operands.size() == 2 &&
              std::get<RegisterOperand>(cmov16.operands[0]).width == 16 &&
              format_instruction(cmov16) == "cmove ax, cx",
          "operand-size override selects 16-bit CMOVcc registers");
    const auto cmov32 = instruction({0x0f, 0x4c, 0xc1});
    check(cmov32.operands.size() == 2 &&
              std::get<RegisterOperand>(cmov32.operands[0]).width == 32 &&
              format_instruction(cmov32) == "cmovl eax, ecx",
          "default long-mode CMOVcc width is 32 bits");
    const auto cmov_extended = instruction({0x4d, 0x0f, 0x4d, 0xc1});
    check(format_instruction(cmov_extended) == "cmovge r8, r9",
          "REX extensions select high general-purpose registers for CMOVcc");
    const auto set_extended = instruction({0x41, 0x0f, 0x94, 0xc4});
    check(format_instruction(set_extended) == "sete r12b" &&
              set_extended.register_writes == std::vector<RegisterOperand>{{RegisterBank::gpr, 12, 8, false}},
          "REX.B selects an extended low-byte register for SETcc");
}
void prefix_tests() {
    for(auto data:{bytes({0xc5,0xf8,0x77}),bytes({0x62,0xf1,0x7c,0x48}),bytes({0x0f,0x38,0})}) {
        const auto result=decode_x64(data,{{0},0x1000});
        check(result.status==DecodeStatus::unsupported && !result.instruction,"unsupported map has no invented instruction");
    }
    check(format_instruction(instruction({0x41,0x90}))=="xchg eax, r8d",
          "REX.B 90 is XCHG EAX,R8D, not a reserved encoding");
    for(auto data:{bytes({0xf0,0x90}),bytes({0xf0,0x01,0xc8}),bytes({0x48,0x8d,0xc0}),
                   bytes({0xf0,0xf7,0x20})})
        check(decode_x64(data,{{0},0x1000}).status==DecodeStatus::invalid,"invalid LOCK or LEA register form");
    for(auto data:{bytes({0xf6,0xc8}),bytes({0xf7,0xc8})})
        check(decode_x64(data,{{0},0x1000}).status==DecodeStatus::unsupported,"reserved F6/F7 group one stays explicit unsupported");
    auto data=std::vector<std::byte>(14,std::byte{0x66});data.push_back(std::byte{0x90});
    check(decode_x64(data,{{0},0x1000}).instruction->length==15,"maximum instruction length");
    data.insert(data.begin(),std::byte{0x66});
    check(decode_x64(data,{{0},0x1000}).status==DecodeStatus::invalid,"instruction cannot exceed fifteen bytes");
}
void mips32_tests() {
    const DecodeContext context{Architecture::mips32, ExecutionMode::mips32, ByteOrder::little};
    check(processor_capabilities(context).can_decode, "MIPS32 little-endian capability is advertised");
    auto decode = [&](std::initializer_list<unsigned> values, std::uint64_t at = 0x1000) {
        auto data = bytes(values);
        return decode_instruction(context, data, {{0}, at});
    };
    // COP1 single precision: LWC1/SWC1, ADD.S, C.EQ.S, BC1T.
    auto result = decode({0xfc,0xff,0xa2,0xc7}); // lwc1 f2,-4(sp)
    check(result.status == DecodeStatus::decoded && result.instruction,
          "MIPS32 COP1 LWC1 known-answer encoding decodes");
    if (result.instruction)
        check(result.instruction->opcode == Opcode::mips_lwc1 && result.instruction->memory_read &&
                  std::get<RegisterOperand>(result.instruction->operands[0]) == RegisterOperand{RegisterBank::mips_fpr,2,32,false} &&
                  result.instruction->register_writes == std::vector<RegisterOperand>{{RegisterBank::mips_fpr,2,32,false}} &&
                  format_instruction(*result.instruction) == "lwc1 f2, -0x4(sp)",
              "LWC1 records a typed FPR destination and signed memory operand");
    result = decode({0xfc,0xff,0xa2,0xe7}); // swc1 f2,-4(sp)
    check(result.status == DecodeStatus::decoded && result.instruction,
          "MIPS32 COP1 SWC1 known-answer encoding decodes");
    result = decode({0xc0,0x08,0x02,0x46}); // add.s f3,f1,f2
    check(result.status == DecodeStatus::decoded && result.instruction,
          "MIPS32 COP1 ADD.S known-answer encoding decodes");
    if (result.instruction)
        check(result.instruction->opcode == Opcode::mips_add_s &&
                  result.instruction->register_reads == std::vector<RegisterOperand>{{RegisterBank::mips_fpr,1,32,false},
                      {RegisterBank::mips_fpr,2,32,false},{RegisterBank::mips_fcsr,0,32,false}} &&
                  result.instruction->register_writes == std::vector<RegisterOperand>{{RegisterBank::mips_fpr,3,32,false},
                      {RegisterBank::mips_fcsr,0,32,false}} &&
                  format_instruction(*result.instruction) == "add.s f3, f1, f2",
              "ADD.S retains FPR and FCSR effects with standard COP1 syntax");
    result = decode({0x32,0x08,0x02,0x46}); // c.eq.s f1,f2
    check(result.status == DecodeStatus::decoded && result.instruction,
          "MIPS32 COP1 C.EQ.S known-answer encoding decodes");
    const auto nonzero_compare_cc = bytes({0x32,0x09,0x02,0x46});
    check(decode_mips32(ByteOrder::little, nonzero_compare_cc, {{0},0x1000}).status == DecodeStatus::unsupported,
          "COP1 compare to a nonzero condition code is outside this subset");
    const auto reserved_compare_bits = bytes({0x72,0x08,0x02,0x46});
    check(decode_mips32(ByteOrder::little, reserved_compare_bits, {{0},0x1000}).status == DecodeStatus::invalid,
          "COP1 compare rejects reserved condition-code bits");
    result = decode({0x02,0x00,0x01,0x45}, 0x1000); // bc1t +2
    check(result.status == DecodeStatus::decoded && result.instruction && result.instruction->delay_slots == 1 &&
              result.instruction->flow == FlowKind::conditional_branch,
          "MIPS32 COP1 BC1T retains conditional flow and its architectural delay slot");
    const auto bad_cc_bytes = bytes({0x04,0x00,0x05,0x45});
    const auto bad_cc = decode_mips32(ByteOrder::little, bad_cc_bytes, {{0},0x1000});
    check(bad_cc.status == DecodeStatus::unsupported,
          "COP1 branch to a nonzero condition code is outside this subset");
    check(decode({0x04,0x00,0x01,0x46}).status == DecodeStatus::invalid,
          "COP1 unary operations reject a nonzero unused ft field");
    const auto cop1 = [&](unsigned fmt, unsigned ft, unsigned fs, unsigned fd, unsigned function) {
        const auto word = (0x11u << 26) | (fmt << 21) | (ft << 16) | (fs << 11) | (fd << 6) | function;
        return decode({word & 0xffu, (word >> 8) & 0xffu, (word >> 16) & 0xffu, (word >> 24) & 0xffu});
    };
    result = cop1(17, 4, 2, 6, 0x00); // add.d f6,f2,f4
    check(result.instruction && result.instruction->opcode == Opcode::mips_add_d &&
              format_instruction(*result.instruction) == "add.d f6, f2, f4",
          "MIPS32 COP1 double arithmetic decodes with 64-bit paired FPRs");
    result = cop1(17, 4, 2, 0, 0x32); // c.eq.d f2,f4
    check(result.instruction && result.instruction->opcode == Opcode::mips_c_eq_d &&
              result.instruction->register_writes == std::vector<RegisterOperand>{{RegisterBank::mips_fcsr,0,32,false}},
          "MIPS32 COP1 double compare writes FCSR");
    result = cop1(17, 0, 2, 6, 0x20); // cvt.s.d f6,f2
    check(result.instruction && result.instruction->opcode == Opcode::mips_cvt_s_d &&
              format_instruction(*result.instruction) == "cvt.s.d f6, f2",
          "MIPS32 COP1 double-to-single conversion decodes");
    result = decode({0x00,0x00,0xa6,0xd7}); // ldc1 f6,0(sp)
    check(result.instruction && result.instruction->opcode == Opcode::mips_ldc1 &&
              std::get<RegisterOperand>(result.instruction->operands[0]).width == 64,
          "MIPS32 LDC1 models a paired 64-bit FPR value");
    check(cop1(17, 3, 2, 6, 0x00).instruction.has_value(),
          "MIPS32 double operations preserve the encoded FPR bank index");
    result = decode({0xff,0xff,0x08,0x24}); // addiu t0, zero, -1
    check(result.status == DecodeStatus::decoded && result.instruction, "MIPS32 addiu decodes");
    auto instruction = *result.instruction;
    check(instruction.opcode == Opcode::mips_addiu && instruction.length == 4 &&
              std::get<RegisterOperand>(instruction.operands[0]) == RegisterOperand{RegisterBank::mips_gpr,8,32,false} &&
              std::get<ImmediateOperand>(instruction.operands[2]).value == 0xffffffffffffffffULL &&
              instruction.register_writes == std::vector<RegisterOperand>{{RegisterBank::mips_gpr,8,32,false}},
          "MIPS32 immediate arithmetic has typed signed operands and effects");
    check(register_name({RegisterBank::mips_gpr,29,32,false}) == "sp" &&
              format_instruction(instruction) == "addiu t0, zero, -0x1", "MIPS register aliases and formatting");

    result = decode({0x21,0x48,0x08,0x01}); // addu t1,t0,t0
    check(result.instruction && result.instruction->opcode == Opcode::mips_addu &&
              result.instruction->register_reads.size() == 2 && result.instruction->register_writes.size() == 1,
          "MIPS32 register arithmetic records source and destination accesses");
    result = decode({0x18,0x00,0x09,0x01}); // mult t0,t1
    check(result.instruction && result.instruction->opcode == Opcode::mips_mult &&
              result.instruction->register_reads == std::vector<RegisterOperand>{{RegisterBank::mips_gpr,8,32,false},
                                                                                 {RegisterBank::mips_gpr,9,32,false}} &&
              result.instruction->register_writes == std::vector<RegisterOperand>{{RegisterBank::mips_hilo,0,32,false},
                                                                                  {RegisterBank::mips_hilo,1,32,false}} &&
              format_instruction(*result.instruction) == "mult t0, t1",
          "MIPS32 MULT records both GPR inputs, HI/LO outputs and assembly text");
    result = decode({0x19,0x00,0x09,0x01}); // multu t0,t1
    check(result.instruction && result.instruction->opcode == Opcode::mips_multu &&
              result.instruction->register_writes.size() == 2 &&
              result.instruction->register_writes[0].bank == RegisterBank::mips_hilo &&
              result.instruction->register_writes[1].bank == RegisterBank::mips_hilo,
          "MIPS32 MULTU writes the HI/LO pair");
    result = decode({0x10,0x50,0x00,0x00}); // mfhi t2
    check(result.instruction && result.instruction->opcode == Opcode::mips_mfhi &&
              result.instruction->register_reads == std::vector<RegisterOperand>{{RegisterBank::mips_hilo,0,32,false}} &&
              result.instruction->register_writes == std::vector<RegisterOperand>{{RegisterBank::mips_gpr,10,32,false}} &&
              format_instruction(*result.instruction) == "mfhi t2",
          "MIPS32 MFHI reads the HI special register and writes its GPR destination");
    result = decode({0x12,0x58,0x00,0x00}); // mflo t3
    check(result.instruction && result.instruction->opcode == Opcode::mips_mflo &&
              result.instruction->register_reads == std::vector<RegisterOperand>{{RegisterBank::mips_hilo,1,32,false}} &&
              result.instruction->register_writes == std::vector<RegisterOperand>{{RegisterBank::mips_gpr,11,32,false}},
          "MIPS32 MFLO reads LO and writes its GPR destination");
    result = decode({0x11,0x00,0x00,0x01}); // mthi t0
    check(result.instruction && result.instruction->opcode == Opcode::mips_mthi &&
              result.instruction->register_reads == std::vector<RegisterOperand>{{RegisterBank::mips_gpr,8,32,false}} &&
              result.instruction->register_writes == std::vector<RegisterOperand>{{RegisterBank::mips_hilo,0,32,false}} &&
              format_instruction(*result.instruction) == "mthi t0",
          "MIPS32 MTHI reads a GPR and writes HI");
    result = decode({0x13,0x00,0x20,0x01}); // mtlo t1
    check(result.instruction && result.instruction->opcode == Opcode::mips_mtlo &&
              result.instruction->register_reads == std::vector<RegisterOperand>{{RegisterBank::mips_gpr,9,32,false}} &&
              result.instruction->register_writes == std::vector<RegisterOperand>{{RegisterBank::mips_hilo,1,32,false}},
          "MIPS32 MTLO reads a GPR and writes LO");
    result = decode({0x1a,0x00,0x09,0x01}); // div t0,t1
    check(result.instruction && result.instruction->opcode == Opcode::mips_div &&
              result.instruction->register_reads.size() == 2 && result.instruction->register_writes.size() == 2 &&
              result.instruction->register_writes[0].index == 0 && result.instruction->register_writes[1].index == 1,
          "MIPS32 DIV records both GPR inputs and both HI/LO outputs");
    result = decode({0x1b,0x00,0x09,0x01}); // divu t0,t1
    check(result.instruction && result.instruction->opcode == Opcode::mips_divu &&
              result.instruction->register_reads.size() == 2 && result.instruction->register_writes.size() == 2,
          "MIPS32 DIVU records both GPR inputs and both HI/LO outputs");
    check(decode({0x18,0x08,0x09,0x01}).status == DecodeStatus::invalid &&
              decode({0x10,0x50,0x01,0x00}).status == DecodeStatus::invalid &&
              decode({0x11,0x00,0x08,0x01}).status == DecodeStatus::invalid,
          "MIPS32 HI/LO instructions reject reserved register and shift fields");
    result = decode({0xfc,0xff,0xa8,0x8f}); // lw t0,-4(sp)
    check(result.instruction && result.instruction->opcode == Opcode::mips_lw && result.instruction->memory_read &&
              std::get<MemoryOperand>(result.instruction->operands[1]).displacement == -4 &&
              std::get<MemoryOperand>(result.instruction->operands[1]).base->index == 29,
          "MIPS32 load records signed base displacement");
    result = decode({0xfc,0xff,0xa8,0xaf}); // sw t0,-4(sp)
    check(result.instruction && result.instruction->opcode == Opcode::mips_sw && result.instruction->memory_write,
          "MIPS32 store records memory write");
    result = decode({0x02,0x00,0x09,0x11}, 0x1000); // beq t0,t1,+2
    check(result.instruction && result.instruction->flow == FlowKind::conditional_branch &&
              result.instruction->direct_target == Address{{0},0x100c} && result.instruction->delay_slots == 1,
          "MIPS32 conditional branch target uses PC+4 and exposes delay slot");
    result = decode({0x00,0x01,0x00,0x0c}, 0x00400000); // jal 0x100
    check(result.instruction && result.instruction->flow == FlowKind::call &&
              result.instruction->direct_target == Address{{0},0x400} && result.instruction->delay_slots == 1 &&
              std::find(result.instruction->register_writes.begin(), result.instruction->register_writes.end(),
                        RegisterOperand{RegisterBank::mips_gpr,31,32,false}) != result.instruction->register_writes.end(),
          "MIPS32 JAL exposes target, link write and delay slot");
    result = decode({0x08,0x00,0xe0,0x03}); // jr ra
    check(result.instruction && result.instruction->flow == FlowKind::ret && result.instruction->delay_slots == 1,
          "MIPS32 jr ra is a delayed return");
    check(decode({0x00,0x00,0x00}).status == DecodeStatus::truncated,
          "MIPS32 short instruction is truncated");
    check(decode({0xff,0xff,0xff,0xff}).status == DecodeStatus::invalid,
          "MIPS32 reserved encoding is invalid");
    const auto system = decode({0x0c,0x00,0x00,0x00});
    check(system.instruction && system.instruction->opcode != Opcode::opaque &&
              opcode_name(system.instruction->opcode) == "syscall" &&
              system.instruction->flow == FlowKind::trap && system.instruction->operands.empty() &&
              format_instruction(*system.instruction) == "syscall",
          "MIPS32 syscall is a typed trap rather than an opaque instruction");
    const auto syscall_code = decode({0x4c,0x00,0x00,0x00});
    check(syscall_code.instruction && format_instruction(*syscall_code.instruction) == "syscall 0x1",
          "MIPS32 syscall retains its encoded exception code");
    const auto breakpoint = decode({0x0d,0x00,0x00,0x00});
    check(breakpoint.instruction && breakpoint.instruction->opcode != Opcode::opaque &&
              opcode_name(breakpoint.instruction->opcode) == "break" &&
              breakpoint.instruction->flow == FlowKind::trap &&
              format_instruction(*breakpoint.instruction) == "break",
          "MIPS32 break is a typed trap");
    const auto sync = decode({0x4f,0x00,0x00,0x00});
    check(sync.instruction && sync.instruction->opcode != Opcode::opaque &&
              opcode_name(sync.instruction->opcode) == "sync" &&
              format_instruction(*sync.instruction) == "sync 0x1",
          "MIPS32 sync preserves its stype barrier operand");
    const auto mfc0 = decode({0x00,0x60,0x08,0x40});
    check(mfc0.instruction && mfc0.instruction->opcode != Opcode::opaque &&
              opcode_name(mfc0.instruction->opcode) == "mfc0" &&
              mfc0.instruction->register_reads.size() == 1 &&
              mfc0.instruction->register_writes == std::vector<RegisterOperand>{{RegisterBank::mips_gpr,8,32,false}} &&
              register_name(mfc0.instruction->register_reads[0]) == "status" &&
              format_instruction(*mfc0.instruction) == "mfc0 t0, status",
          "MIPS32 MFC0 models CP0 status to GPR transfer");
    const auto mtc0 = decode({0x00,0x60,0x88,0x40});
    check(mtc0.instruction && mtc0.instruction->opcode != Opcode::opaque &&
              opcode_name(mtc0.instruction->opcode) == "mtc0" &&
              mtc0.instruction->register_reads == std::vector<RegisterOperand>{{RegisterBank::mips_gpr,8,32,false}} &&
              mtc0.instruction->register_writes.size() == 1 &&
              register_name(mtc0.instruction->register_writes[0]) == "status" &&
              format_instruction(*mtc0.instruction) == "mtc0 t0, status",
          "MIPS32 MTC0 models GPR to CP0 status transfer");
    const auto eret = decode({0x18,0x00,0x00,0x42});
    check(eret.instruction && eret.instruction->opcode != Opcode::opaque &&
              opcode_name(eret.instruction->opcode) == "eret" &&
              eret.instruction->flow == FlowKind::ret && eret.instruction->delay_slots == 0 &&
              format_instruction(*eret.instruction) == "eret",
          "MIPS32 ERET is a non-delayed exception return");
    const auto nonzero_select = decode({0x01,0x60,0x08,0x40});
    check(nonzero_select.status == DecodeStatus::decoded && nonzero_select.instruction &&
              nonzero_select.instruction->opcode == Opcode::opaque &&
              nonzero_select.instruction->register_reads.empty() && nonzero_select.instruction->register_writes.empty(),
          "MIPS32 CP0 nonzero register selects remain display-only without inferred effects");
    const auto zero_mtc0 = decode({0x00,0x60,0x80,0x40});
    check(zero_mtc0.instruction && zero_mtc0.instruction->register_reads.size() == 1 &&
              register_name(zero_mtc0.instruction->register_reads.front()) == "zero",
          "MIPS32 MTC0 observes the architectural zero-register value");
    const auto likely = decode({0x02,0x00,0x13,0x04});
    check(likely.instruction && likely.instruction->opcode == Opcode::opaque && likely.instruction->operands.empty(),
          "valid but unimplemented MIPS branch-likely retains display-only length without semantic facts");
    check(decode({0x00,0x00,0x00,0x00}, 0x1001).status == DecodeStatus::invalid &&
              decode({0x00,0x00,0x00,0x00}, 0x100000000ULL).status == DecodeStatus::invalid,
          "MIPS32 unaligned and out-of-domain addresses are invalid");
    const DecodeContext big_endian{Architecture::mips32, ExecutionMode::mips32, ByteOrder::big};
    check(processor_capabilities(big_endian).can_decode,
          "MIPS32 big-endian instruction mode is advertised");
    auto big_result = decode_instruction(big_endian, bytes({0x24, 0x08, 0xff, 0xff}), {{0}, 0x1000});
    check(big_result.instruction && big_result.instruction->opcode == Opcode::mips_addiu &&
              big_result.instruction->context == big_endian &&
              std::get<ImmediateOperand>(big_result.instruction->operands[2]).value == UINT64_MAX &&
              format_instruction(*big_result.instruction) == "addiu t0, zero, -0x1",
          "MIPS32 big-endian immediate decode preserves signed operands and explicit context");
    big_result = decode_instruction(big_endian, bytes({0x11, 0x09, 0, 2}), {{0}, 0x1000});
    check(big_result.instruction && big_result.instruction->opcode == Opcode::mips_beq &&
              big_result.instruction->direct_target == Address{{0}, 0x100c} &&
              big_result.instruction->delay_slots == 1,
          "MIPS32 big-endian branch fields preserve target calculation and delay slots");
}

int main(int argc,char** argv) {
    const std::string_view family=argc>1?argv[1]:"all";
    return run([&] {
        if(family=="all" || family=="moves")move_tests();
        if(family=="all" || family=="x86-scalar")xchg_tests();
        if(family=="all" || family=="x86-scalar")sign_extension_tests();
        if(family=="all" || family=="arithmetic")arithmetic_tests();
        if(family=="all" || family=="flow") { stack_flow_tests(); string_instruction_tests(); string_semantic_tests(); condition_semantic_tests(); conditional_data_tests(); }
        if(family=="all" || family=="arithmetic") { arithmetic_flag_semantic_tests(); bit_operation_semantic_tests(); multiply_divide_semantic_tests(); arithmetic_width_effect_tests(); data_move_semantic_tests(); }
        if(family=="all" || family=="prefixes")prefix_tests();
        if(family=="all" || family=="mips32")mips32_tests();
        if(family=="all" || family=="extended-x86")extended_x86_decode_tests();
    });
}
