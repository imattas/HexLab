#include "hexlab/processors/decoder.hpp"
#include "hexlab/processors/format.hpp"
#include "instruction_flow.hpp"
#include "support/checks.hpp"
#include "support/fixture_files.hpp"
#include <algorithm>
using namespace hexlab;
using namespace hexlab_test;
namespace {
constexpr DecodeContext mode{Architecture::x86, ExecutionMode::x86_16, ByteOrder::little};
Instruction instruction(std::initializer_list<unsigned> values, Address at = {{7}, 0x1000},
                        DecodeContext context = mode) {
    auto raw = bytes(values);
    auto result = decode_instruction(context, raw, at);
    check(result.status == DecodeStatus::decoded && result.instruction.has_value(), "authored default16 form decodes");
    if (!result.instruction)
        throw std::runtime_error(result.reason);
    auto value = *result.instruction;
    check(value.length == raw.size() && value.context == context, "exact default16 length and supplied context");
    for (std::size_t n = 0; n < raw.size(); ++n)
        check(decode_instruction(context, std::span(raw).first(n), at).status != DecodeStatus::decoded,
              "every truncation of an authored16 form fails closed");
    return value;
}
bool has(std::span<const RegisterOperand> values, RegisterOperand reg) {
    return std::find(values.begin(), values.end(), reg) != values.end();
}
void scalar_tests() {
    check(processor_capabilities(mode).can_decode, "default16 capability enabled explicitly");
    auto mov = instruction({0xb8, 0x34, 0x12});
    check(std::get<RegisterOperand>(mov.operands[0]) == RegisterOperand{RegisterBank::gpr, 0, 16, false} &&
              std::get<ImmediateOperand>(mov.operands[1]).value == 0x1234,
          "default16 MOV AX imm16");
    check(format_instruction(mov) == "mov ax, 0x1234", "default16 formatting");
    mov = instruction({0x66, 0xb8, 0x78, 0x56, 0x34, 0x12});
    check(std::get<RegisterOperand>(mov.operands[0]).width == 32 &&
              std::get<ImmediateOperand>(mov.operands[1]).value == 0x12345678,
          "66 selects operand32 in default16");
    auto inc = instruction({0x40});
    check(inc.opcode == Opcode::inc && std::get<RegisterOperand>(inc.operands[0]).width == 16 &&
              has(inc.register_reads, {RegisterBank::flags, 0, 16, false}),
          "40 is INC AX with flags16");
    inc = instruction({0x66, 0x40});
    check(std::get<RegisterOperand>(inc.operands[0]).width == 32, "66 INC EAX");
    auto ah = instruction({0x88, 0xe0});
    check(std::get<RegisterOperand>(ah.operands[1]) == RegisterOperand{RegisterBank::gpr, 0, 8, true},
          "no legacy16 REX byte registers");
    auto add = instruction({0x83, 0xc0, 0xff});
    auto immediate = std::get<ImmediateOperand>(add.operands[1]);
    check(immediate.value == 0xffff && immediate.encoded_width == 8 && immediate.effective_width == 16 &&
              immediate.is_signed,
          "signed8 sign extends to word16");
    add = instruction({0x66, 0x83, 0xc0, 0xff});
    check(std::get<ImmediateOperand>(add.operands[1]).value == 0xffffffff, "66 signed8 sign extends to dword32");
    auto duplicate = instruction({0x66, 0x66, 0x89, 0xd8});
    check(std::get<RegisterOperand>(duplicate.operands[0]).width == 32, "repeated66 does not toggle back to16");
    const std::vector<std::pair<std::vector<std::byte>, Opcode>> forms{{bytes({0x89, 0xd8}), Opcode::mov},
                                                                       {bytes({0xc7, 0, 0x34, 0x12}), Opcode::mov},
                                                                       {bytes({0x0f, 0xb6, 0xc0}), Opcode::movzx},
                                                                       {bytes({0x66, 0x0f, 0xb7, 0xc0}), Opcode::movzx},
                                                                       {bytes({0x0f, 0xbe, 0xc0}), Opcode::movsx},
                                                                       {bytes({0x01, 0xd8}), Opcode::add},
                                                                       {bytes({0x09, 0xd8}), Opcode::bit_or},
                                                                       {bytes({0x11, 0xd8}), Opcode::adc},
                                                                       {bytes({0x19, 0xd8}), Opcode::sbb},
                                                                       {bytes({0x21, 0xd8}), Opcode::bit_and},
                                                                       {bytes({0x29, 0xd8}), Opcode::sub},
                                                                       {bytes({0x31, 0xd8}), Opcode::bit_xor},
                                                                       {bytes({0x39, 0xd8}), Opcode::cmp},
                                                                       {bytes({0x85, 0xd8}), Opcode::test},
                                                                       {bytes({0xa9, 0x34, 0x12}), Opcode::test},
                                                                       {bytes({0xf7, 0xd0}), Opcode::bit_not},
                                                                       {bytes({0xf7, 0xd8}), Opcode::neg},
                                                                       {bytes({0xff, 0xc0}), Opcode::inc},
                                                                       {bytes({0x48}), Opcode::dec},
                                                                       {bytes({0x0f, 0xaf, 0xc3}), Opcode::imul},
                                                                       {bytes({0x69, 0xc0, 0xff, 0xff}), Opcode::imul},
                                                                       {bytes({0x6b, 0xc0, 0xff}), Opcode::imul},
                                                                       {bytes({0xd1, 0xc0}), Opcode::rol},
                                                                       {bytes({0xd1, 0xc8}), Opcode::ror},
                                                                       {bytes({0xd1, 0xd0}), Opcode::rcl},
                                                                       {bytes({0xd1, 0xd8}), Opcode::rcr},
                                                                       {bytes({0xc1, 0xe0, 2}), Opcode::shl},
                                                                       {bytes({0xd3, 0xe8}), Opcode::shr},
                                                                       {bytes({0xd1, 0xf8}), Opcode::sar},
                                                                       {bytes({0xf0, 0x01, 0x07}), Opcode::add},
                                                                       {bytes({0x90}), Opcode::nop},
                                                                       {bytes({0xf3, 0x90}), Opcode::pause},
                                                                       {bytes({0xcc}), Opcode::int3}};
    for (const auto &[raw, opcode] : forms) {
        auto d = decode_instruction(mode, raw, {{7}, 0x1000});
        check(d.instruction && d.instruction->length == raw.size() && d.instruction->opcode == opcode,
              "literal16 scalar family boundary");
        for (std::size_t n = 0; n < raw.size(); ++n)
            check(decode_instruction(mode, std::span(raw).first(n), {{7}, 0x1000}).status != DecodeStatus::decoded,
                  "scalar16 family truncation");
    }
}
void memory_tests() {
    auto moffs = instruction({0xa1, 0xff, 0xff});
    auto absolute_word = std::get<MemoryOperand>(moffs.operands[1]);
    check(absolute_word.data_width == 16 && absolute_word.address_width == 16 && absolute_word.displacement == 0xffff &&
              absolute_word.segment == RegisterOperand{RegisterBank::segment, 3, 16, false} &&
              !absolute_word.resolved_address && moffs.memory_read,
          "MOV AX moffs16 retains unknown DS base at segment boundary");
    auto moffs32 = instruction({0x66, 0x67, 0xa3, 0x78, 0x56, 0x34, 0x12});
    check(moffs32.memory_write && std::get<MemoryOperand>(moffs32.operands[0]).address_width == 32 &&
              std::get<RegisterOperand>(moffs32.operands[1]).width == 32,
          "MOV moffs32 EAX separates66 data and67 address widths");
    auto moffs_byte = instruction({0x26, 0xa0, 0x10, 0});
    check(std::get<RegisterOperand>(moffs_byte.operands[0]).width == 8 &&
              std::get<MemoryOperand>(moffs_byte.operands[1]).segment->index == 0,
          "byte moffs accepts explicit ES");
    auto moffs_store = instruction({0xa2, 0x10, 0});
    check(moffs_store.memory_write && std::get<MemoryOperand>(moffs_store.operands[0]).data_width == 8,
          "byte moffs store direction");
    for (unsigned mod = 0; mod < 3; ++mod)
        for (unsigned rm = 0; rm < 8; ++rm) {
            auto raw = bytes({0x8b, mod * 64 + rm});
            if (mod == 1)
                raw.push_back(std::byte{0xff});
            if (mod == 2 || (mod == 0 && rm == 6)) {
                raw.push_back(std::byte{0x34});
                raw.push_back(std::byte{0x12});
            }
            auto decoded = decode_instruction(mode, raw, {{7}, 0x1000});
            check(decoded.instruction && decoded.instruction->length == raw.size(), "complete16 address matrix form");
            if (!decoded.instruction)
                throw std::runtime_error(decoded.reason);
            const auto &memory = std::get<MemoryOperand>(decoded.instruction->operands[1]);
            const bool bp = (rm == 2 || rm == 3 || (rm == 6 && mod != 0));
            check(memory.data_width == 16 && memory.address_width == 16 && !memory.ip_relative &&
                      !memory.resolved_address &&
                      memory.segment ==
                          RegisterOperand{RegisterBank::segment, static_cast<std::uint8_t>(bp ? 2 : 3), 16, false},
                  "default16 retains DS/SS rather than fabricating a current-CS data address");
            for (std::size_t n = 0; n < raw.size(); ++n)
                check(decode_instruction(mode, std::span(raw).first(n), {{7}, 0x1000}).status != DecodeStatus::decoded,
                      "address16 matrix truncations");
        }
    auto es = instruction({0x26, 0x8b, 0x46, 0});
    check(std::get<MemoryOperand>(es.operands[1]).segment == RegisterOperand{RegisterBank::segment, 0, 16, false},
          "explicit ES overrides default SS");
    auto sib = instruction({0x67, 0x8b, 0x44, 0x8d, 0xf0});
    auto m = std::get<MemoryOperand>(sib.operands[1]);
    check(m.address_width == 32 && m.base == RegisterOperand{RegisterBank::gpr, 5, 32, false} && m.index &&
              m.index->index == 1 && m.scale == 4 && m.displacement == -16 && m.segment && m.segment->index == 2,
          "address32 SIB retains EBP default SS");
    auto absolute = instruction({0x67, 0x8b, 0x05, 0, 0x20, 0, 0});
    m = std::get<MemoryOperand>(absolute.operands[1]);
    check(m.address_width == 32 && !m.base && !m.ip_relative && m.segment && m.segment->index == 3 &&
              !m.resolved_address,
          "address override absolute remains DS-relative, never EIP-relative");
    auto lea = instruction({0x8d, 0x42, 0x10});
    m = std::get<MemoryOperand>(lea.operands[1]);
    check(!m.segment && !lea.memory_read && !lea.memory_write &&
              !has(lea.register_reads, {RegisterBank::segment, 2, 16, false}),
          "LEA16 computes offset without SS base access");
    check(format_instruction(lea) == "lea ax, [bp + si + 0x10]", "LEA16 address formatter");
}
void xchg_tests() {
    const auto accumulator = instruction({0x91});
    check(opcode_name(accumulator.opcode) == "xchg" && format_instruction(accumulator) == "xchg ax, cx",
          "default16 accumulator XCHG uses AX width");
    const auto word = instruction({0x87, 0xd8});
    check(opcode_name(word.opcode) == "xchg" && format_instruction(word) == "xchg ax, bx" &&
              word.access == std::vector<OperandAccess>{OperandAccess::read_write, OperandAccess::read_write} &&
              has(word.register_reads, {RegisterBank::gpr, 0, 16, false}) &&
              has(word.register_reads, {RegisterBank::gpr, 3, 16, false}) &&
              has(word.register_writes, {RegisterBank::gpr, 0, 16, false}) &&
              has(word.register_writes, {RegisterBank::gpr, 3, 16, false}),
          "default16 XCHG r/m16,r16 has symmetric typed effects");
    const auto override = instruction({0x66, 0x87, 0xd8});
    check(std::get<RegisterOperand>(override.operands[0]).width == 32 &&
              format_instruction(override) == "xchg eax, ebx",
          "operand-size override selects XCHG r/m32,r32 in default16");
    const auto memory = instruction({0x87, 0x00});
    const auto &address = std::get<MemoryOperand>(memory.operands[0]);
    check(memory.memory_read && memory.memory_write && address.address_width == 16 && address.data_width == 16 &&
              address.base && address.base->index == 3 && address.index && address.index->index == 6 &&
              address.segment && address.segment->index == 3,
          "default16 memory XCHG retains BX+SI and DS addressing with read-write effects");
    check(decode_x86_16(bytes({0xf0, 0x87, 0xd8}), {{7}, 0}).status == DecodeStatus::invalid,
          "LOCK on register-only XCHG is invalid");
    const auto truncated = bytes({0x87, 0x46, 0x10});
    for (std::size_t n = 0; n < truncated.size(); ++n)
        check(decode_x86_16(std::span(truncated).first(n), {{7}, 0}).status == DecodeStatus::truncated,
              "incomplete 16-bit memory XCHG remains truncated");
}
void sign_extension_tests() {
    auto value = instruction({0x98});
    check(opcode_name(value.opcode) == "cbw" &&
              value.register_reads == std::vector<RegisterOperand>{{RegisterBank::gpr, 0, 8, false}} &&
              value.register_writes == std::vector<RegisterOperand>{{RegisterBank::gpr, 0, 16, false}},
          "default16 CBW reads AL and writes AX");
    value = instruction({0x66, 0x98});
    check(opcode_name(value.opcode) == "cwde" &&
              value.register_reads == std::vector<RegisterOperand>{{RegisterBank::gpr, 0, 16, false}} &&
              value.register_writes == std::vector<RegisterOperand>{{RegisterBank::gpr, 0, 32, false}},
          "operand-size override selects CWDE in default16");
    value = instruction({0x99});
    check(opcode_name(value.opcode) == "cwd" &&
              value.register_reads == std::vector<RegisterOperand>{{RegisterBank::gpr, 0, 16, false}} &&
              value.register_writes == std::vector<RegisterOperand>{{RegisterBank::gpr, 2, 16, false}},
          "default16 CWD reads AX and writes DX");
}
void stack_flow_tests() {
    auto push = instruction({0x68, 0x34, 0x12});
    check(push.stack_value_width == 16 && push.stack_slot_count == 1 &&
              has(push.register_reads, {RegisterBank::gpr, 4, 16, false}) &&
              has(push.register_reads, {RegisterBank::segment, 2, 16, false}),
          "default16 stack value/address/SS");
    push = instruction({0x66, 0x68, 0x78, 0x56, 0x34, 0x12});
    check(push.stack_value_width == 32 && has(push.register_writes, {RegisterBank::gpr, 4, 16, false}),
          "66 PUSH changes value size but not SP address size");
    auto short_push = instruction({0x6a, 0xff});
    check(std::get<ImmediateOperand>(short_push.operands[0]).value == 0xffff, "PUSH imm8 extends to16");
    auto wide_stack = mode;
    wide_stack.stack_address_width = 32;
    push = instruction({0x50}, {{7}, 0x1000}, wide_stack);
    check(push.stack_value_width == 16 && has(push.register_reads, {RegisterBank::gpr, 4, 32, false}) &&
              push.context == wide_stack,
          "CS.D0/SS.B1 uses ESP and preserves context through dispatch");
    auto leave = instruction({0xc9}, {{7}, 0x1000}, wide_stack);
    check(leave.stack_value_width == 16 && has(leave.register_reads, {RegisterBank::gpr, 5, 32, false}) &&
              has(leave.register_writes, {RegisterBank::gpr, 4, 32, false}) &&
              has(leave.register_writes, {RegisterBank::gpr, 5, 16, false}),
          "LEAVE independent BP source and popped value widths");
    auto mode32 = DecodeContext{Architecture::x86, ExecutionMode::x86_32, ByteOrder::little};
    mode32.stack_address_width = 16;
    push = instruction({0x50}, {{7}, 0x1000}, mode32);
    check(push.stack_value_width == 32 && has(push.register_writes, {RegisterBank::gpr, 4, 16, false}),
          "CS.D1/SS.B0 independent sizes");
    auto near = instruction({0xe8, 0, 0}, {{7}, 0x10020});
    check(near.direct_target == Address{{7}, 0x23} && near.stack_value_width == 16 &&
              analysis_detail::continuation_address(near).value() == Address{{7}, 0x23},
          "CALL16 truncates target and pushed return IP");
    near = instruction({0x66, 0xe8, 0, 0, 0, 0}, {{7}, 0x10000});
    check(near.direct_target == Address{{7}, 0x10006} && near.stack_value_width == 32 &&
              analysis_detail::continuation_address(near).value() == Address{{7}, 0x10006},
          "CALL32 in D0 retains full EIP");
    auto conditional = instruction({0x75, 0}, {{7}, 0xffff});
    check(conditional.direct_target == Address{{7}, 1} &&
              analysis_detail::continuation_address(conditional).value() == Address{{7}, 0x10001},
          "taken16 target versus untaken32 EIP");
    auto nop = instruction({0x90}, {{7}, 0xffff});
    check(analysis_detail::continuation_address(nop).value() == Address{{7}, 0x10000},
          "D0 sequential continuation does not mask IP16");
    auto ret = instruction({0xc2, 0x10, 0});
    check(ret.flow == FlowKind::ret && ret.stack_value_width == 16 &&
              std::get<ImmediateOperand>(ret.operands[0]).value == 16,
          "near RET16 with immediate stack adjustment");
    auto pusha = instruction({0x60});
    check(pusha.opcode == Opcode::pusha && pusha.stack_value_width == 16 && pusha.stack_slot_count == 8 &&
              format_instruction(pusha) == "pusha" && pusha.memory_write &&
              has(pusha.register_reads, {RegisterBank::gpr, 4, 16, false}),
          "PUSHA16 records eight word pushes including the original SP");
    auto pushad = instruction({0x66, 0x60});
    check(pushad.stack_value_width == 32 && format_instruction(pushad) == "pushad" &&
              has(pushad.register_reads, {RegisterBank::gpr, 4, 32, false}),
          "operand override selects PUSHAD and original ESP in 16-bit mode");
    auto popa = instruction({0x61});
    check(popa.opcode == Opcode::popa && popa.stack_slot_count == 8 && popa.memory_read &&
              popa.operands.empty() &&
              has(popa.register_writes, {RegisterBank::gpr, 7, 16, false}) &&
              has(popa.register_writes, {RegisterBank::gpr, 0, 16, false}) &&
              has(popa.register_writes, {RegisterBank::gpr, 4, 16, false}),
          "POPA16 consumes eight slots, restores general registers, and records net SP adjustment");
    auto pushf = instruction({0x9c});
    auto popf = instruction({0x9d});
    check(pushf.opcode == Opcode::pushf && pushf.stack_value_width == 16 &&
              has(pushf.register_reads, {RegisterBank::flags, 0, 16, false}) &&
              popf.opcode == Opcode::popf && has(popf.register_writes, {RegisterBank::flags, 0, 16, false}),
          "PUSHF/POPF use 16-bit FLAGS under default mode");
    auto enter = instruction({0xc8, 0x40, 0, 0x02});
    check(enter.opcode == Opcode::enter && enter.stack_slot_count == 3 && enter.memory_read && enter.memory_write &&
              enter.stack_value_width == 16 && format_instruction(enter) == "enter 0x40, 0x2",
          "ENTER16 models nested frame-chain reads and three stack slots");
}
void invalid_tests() {
    auto raw = bytes({0x90});
    for (auto width : {1, 8, 48, 255}) {
        auto bad = mode;
        bad.stack_address_width = static_cast<std::uint8_t>(width);
        check(!processor_capabilities(bad).can_decode &&
                  decode_instruction(bad, raw, {{7}, 0}).status == DecodeStatus::unsupported,
              "invalid explicit stack address size never reaches a decoder");
    }
    auto bad = mode;
    bad.stack_address_width = 64;
    check(!processor_capabilities(bad).can_decode, "legacy cannot select stack64");
    auto long_mode = DecodeContext{Architecture::x86_64, ExecutionMode::x86_64, ByteOrder::little};
    long_mode.stack_address_width = 16;
    check(!processor_capabilities(long_mode).can_decode, "long mode cannot select legacy stack addressing");
    check(decode_instruction(mode, raw, {{7}, UINT64_C(0x100000000)}).status == DecodeStatus::invalid,
          "legacy16 EIP remains at most32 bits");
    auto overlong = std::vector<std::byte>(15, std::byte{0x66});
    overlong.push_back(std::byte{0x90});
    check(decode_instruction(mode, overlong, {{7}, 0}).status == DecodeStatus::invalid,
          "16-bit architectural instruction length limit");
    for (auto opaque : {bytes({0x8e, 0xd8}), bytes({0x1f}), bytes({0xc4, 0}), bytes({0x0f, 0xb2, 0}),
                        bytes({0xcf}), bytes({0xc5, 0xf8, 0x77})}) {
        const auto decoded = decode_instruction(mode, opaque, {{7}, 0});
        check(decoded.instruction && decoded.instruction->opcode == Opcode::x86_opaque &&
                  decoded.instruction->operands.empty(),
              "Zydis fallback preserves unsupported legacy/system/vector encodings without scalar semantics");
    }
}
void far_tests() {
    auto call = instruction({0x9a, 0x78, 0x56, 0x34, 0x12});
    const auto pointer = std::get<FarPointerOperand>(call.operands[0]);
    check(pointer.selector == 0x1234 && pointer.offset == 0x5678 && pointer.offset_width == 16 &&
              call.flow == FlowKind::call && !call.direct_target && call.stack_value_width == 16 &&
              call.stack_slot_count == 2,
          "far16 pointer is typed and never flattened into a current-domain target");
    check(has(call.register_reads, {RegisterBank::segment, 1, 16, false}) &&
              has(call.register_writes, {RegisterBank::segment, 1, 16, false}) && call.memory_write,
          "far CALL reads old CS and writes new CS with two stack slots");
    check(format_instruction(call) == "call 0x1234:0x5678", "far pointer formatter retains selector");
    auto call32 = instruction({0x66, 0x9a, 0x78, 0x56, 0x34, 0x12, 0x08, 0});
    const auto pointer32 = std::get<FarPointerOperand>(call32.operands[0]);
    check(pointer32.selector == 8 && pointer32.offset == 0x12345678 && pointer32.offset_width == 32 &&
              call32.stack_value_width == 32 && call32.stack_slot_count == 2,
          "far32 pointer has distinct offset/value width");
    auto jump = instruction({0xea, 0x78, 0x56, 0x34, 0x12});
    check(jump.flow == FlowKind::jump && jump.stack_slot_count == 0 && !jump.memory_write && !jump.direct_target &&
              has(jump.register_writes, {RegisterBank::segment, 1, 16, false}),
          "far JMP changes CS without stack push");
    auto indirect = instruction({0xff, 0x1f});
    const auto &memory = std::get<FarMemoryOperand>(indirect.operands[0]);
    check(memory.offset_width == 16 && memory.address.data_width == 32 && memory.address.address_width == 16 &&
              memory.address.base && memory.address.base->index == 3 && memory.address.segment &&
              memory.address.segment->index == 3 && indirect.memory_read && indirect.memory_write &&
              !indirect.direct_target,
          "far indirect CALL16 reads four bytes and leaves target unresolved");
    check(format_instruction(indirect) == "call far dword ptr ds:[bx]",
          "far memory formatter uses complete pointer storage width");
    auto indirect32 = instruction({0x66, 0xff, 0x2e, 0x34, 0x12});
    const auto &wide_memory = std::get<FarMemoryOperand>(indirect32.operands[0]);
    check(wide_memory.offset_width == 32 && wide_memory.address.data_width == 48 && indirect32.flow == FlowKind::jump &&
              !indirect32.memory_write && format_instruction(indirect32) == "jmp far fword ptr ds:[0x1234]",
          "far32 memory pointer reads six bytes without inventing CS from data");
    auto ret = instruction({0xcb});
    check(ret.opcode == Opcode::retf && ret.flow == FlowKind::ret && ret.stack_value_width == 16 &&
              ret.stack_slot_count == 2 && ret.memory_read &&
              has(ret.register_writes, {RegisterBank::segment, 1, 16, false}),
          "RETF16 pops IP and CS slots");
    auto ret32 = instruction({0x66, 0xca, 0x10, 0});
    check(ret32.stack_value_width == 32 && ret32.stack_slot_count == 2 &&
              std::get<ImmediateOperand>(ret32.operands[0]).value == 16 && format_instruction(ret32) == "retf 0x10",
          "RETF32 retains immediate adjustment independently of eight-byte base pop");
    for (auto raw : {bytes({0xff, 0xd8}), bytes({0xff, 0xe8})})
        check(decode_instruction(mode, raw, {{7}, 0}).status == DecodeStatus::invalid,
              "far indirect register encoding is invalid");
    const auto mode32 = DecodeContext{Architecture::x86, ExecutionMode::x86_32, ByteOrder::little};
    auto legacy32 = instruction({0x9a, 0x78, 0x56, 0x34, 0x12, 8, 0}, {{7}, 0x1000}, mode32);
    check(std::get<FarPointerOperand>(legacy32.operands[0]).offset_width == 32 && legacy32.stack_value_width == 32 &&
              legacy32.stack_slot_count == 2,
          "legacy32 shares original typed far parser");
    const auto long_mode = DecodeContext{Architecture::x86_64, ExecutionMode::x86_64, ByteOrder::little};
    for (auto raw :
         {bytes({0x9a, 0, 0, 0, 0, 0, 0}), bytes({0xea, 0, 0, 0, 0, 0, 0}), bytes({0xff, 0x18}), bytes({0xcb})}) {
        const auto decoded = decode_instruction(long_mode, raw, {{7}, 0});
        check(!decoded.instruction || (decoded.instruction->opcode == Opcode::x86_opaque &&
                                       decoded.instruction->operands.empty()),
              "long-mode far forms never receive invented typed operands");
    }
}
void bounded_sweep() {
    std::array<std::byte, 15> raw{};
    for (unsigned prefix = 0; prefix < 4; ++prefix)
        for (unsigned op = 0; op < 256; ++op)
            for (unsigned modrm = 0; modrm < 256; ++modrm) {
                raw.fill(std::byte{0});
                std::size_t position = 0;
                if (prefix & 1)
                    raw[position++] = std::byte{0x66};
                if (prefix & 2)
                    raw[position++] = std::byte{0x67};
                raw[position++] = std::byte(op);
                raw[position] = std::byte(modrm);
                auto decoded = decode_instruction(mode, raw, {{7}, 0x10020});
                bool valid = true;
                if (decoded.instruction) {
                    const auto &i = *decoded.instruction;
                    valid = decoded.status == DecodeStatus::decoded && i.context == mode && i.length &&
                            i.length <= 15 && i.operands.size() == i.access.size() &&
                            (!i.direct_target ||
                             (i.direct_target->space == i.address.space && i.direct_target->offset <= UINT32_MAX));
                    for (const auto &operand : i.operands) {
                        const auto *memory = std::get_if<MemoryOperand>(&operand);
                        if (const auto *far = std::get_if<FarMemoryOperand>(&operand))
                            memory = &far->address;
                        if (memory)
                            valid = valid && (memory->address_width == 16 || memory->address_width == 32) &&
                                    !memory->ip_relative;
                    }
                } else
                    valid = decoded.status != DecodeStatus::decoded;
                check(valid, "bounded16 opcode/ModRM sweep preserves shape and typed domains, not a semantic oracle");
            }
}
} // namespace
void x87_tests();
int main() {
    return run([] {
        scalar_tests();
        xchg_tests();
        sign_extension_tests();
        memory_tests();
        stack_flow_tests();
        invalid_tests();
        far_tests();
        bounded_sweep();
        x87_tests();
    });
}
void x87_tests() {
    const auto x87 = [&](std::initializer_list<unsigned> raw, std::string_view expected) {
        const auto data = bytes(raw);
        const auto result = decode_x86_16(data, {{7}, 0x1000});
        check(result.status == DecodeStatus::decoded && result.instruction,
              "recognized x87 instruction decodes in legacy16");
        if (!result.instruction)
            return;
        check(result.instruction->length == data.size() && format_instruction(*result.instruction) == expected,
              "x87 instruction has exact bytes and canonical text");
        for (std::size_t n = 0; n < data.size(); ++n)
            check(decode_x86_16(std::span(data).first(n), {{7}, 0x1000}).status == DecodeStatus::truncated,
                  "every x87 prefix truncation is reported as truncated");
        check(result.instruction->operands.size() == result.instruction->access.size(),
              "x87 typed operand access vector remains aligned");
        return;
    };
    x87({0xd8, 0xc1}, "fadd st, st(1)");
    x87({0xd9, 0x00}, "fld dword ptr ds:[bx + si]");
    x87({0xdd, 0x1e, 0x34, 0x12}, "fstp qword ptr ds:[0x1234]");
    x87({0xdb, 0x2e, 0x34, 0x12}, "fld tbyte ptr ds:[0x1234]");
    x87({0xdf, 0xe0}, "fnstsw ax");
    x87({0xd9, 0xe8}, "fld1");
    x87({0xd9, 0xc9}, "fxch st(1)");
    x87({0xd9, 0xd0}, "fnop");
    x87({0xd9, 0xf3}, "fpatan");
    x87({0xd9, 0xfb}, "fsincos");

    const std::vector<std::pair<std::vector<std::byte>, std::uint16_t>> memory_forms{
        {bytes({0xd8, 0x00}), std::uint16_t{32}}, {bytes({0xda, 0x00}), std::uint16_t{32}},
        {bytes({0xdb, 0x28}), std::uint16_t{80}}, {bytes({0xdc, 0x00}), std::uint16_t{64}},
        {bytes({0xdd, 0x20}), std::uint16_t{752}}, {bytes({0xde, 0x00}), std::uint16_t{16}},
        {bytes({0xdf, 0x20}), std::uint16_t{80}}};
    for (const auto &[raw, width] : memory_forms) {
        const auto result = decode_x86_16(raw, {{7}, 0x1000});
        check(result.instruction && result.instruction->opcode == Opcode::x87 && result.instruction->operands.size() == 1 &&
                  std::get<MemoryOperand>(result.instruction->operands[0]).data_width == width,
              "x87 escape family retains its exact memory data width");
    }

    const auto fld1 = decode_x86_16(bytes({0xd9, 0xe8}), {{7}, 0x1000});
    check(fld1.instruction && fld1.instruction->opcode == Opcode::x87 &&
              fld1.instruction->x87_stack_delta == 1 &&
              has(fld1.instruction->register_writes, {RegisterBank::x87, 0, 80, false}),
          "x87 constant load records typed ST0 write and one stack push");
    const auto fstp = decode_x86_16(bytes({0xdd, 0x1e, 0x34, 0x12}), {{7}, 0x1000});
    check(fstp.instruction && fstp.instruction->x87_stack_delta == -1 && fstp.instruction->memory_write &&
              has(fstp.instruction->register_reads, {RegisterBank::x87, 0, 80, false}) &&
              std::get<MemoryOperand>(fstp.instruction->operands[0]).data_width == 64,
          "x87 FSTP exposes memory width, ST0 read and one stack pop");

    const auto invalid = decode_x86_16(bytes({0xd9, 0xd1}), {{7}, 0});
    check(invalid.status == DecodeStatus::invalid && !invalid.instruction,
          "reserved x87 register subencoding is invalid");
    const auto reserved_memory = decode_x86_16(bytes({0xdb, 0x20}), {{7}, 0});
    check(reserved_memory.status == DecodeStatus::invalid && !reserved_memory.instruction,
          "reserved x87 memory extension is invalid");
    std::array<std::byte, 15> overlong{};
    overlong.fill(std::byte{0x66});
    overlong.back() = std::byte{0xd9};
    check(decode_x86_16(overlong, {{7}, 0}).status == DecodeStatus::invalid,
          "x87 ModRM cannot extend an instruction beyond the 15-byte limit");
    const auto long_mode = DecodeContext{Architecture::x86_64, ExecutionMode::x86_64, ByteOrder::little};
    const auto long_form = decode_instruction(long_mode, bytes({0xd9, 0x40, 0x10}), {{7}, 0x1000});
    check(long_form.status == DecodeStatus::decoded && long_form.instruction &&
              format_instruction(*long_form.instruction) == "fld dword ptr [rax + 0x10]",
          "x87 memory addressing follows long-mode address rules");
    const auto sib_bytes = bytes({0xd9, 0x44, 0x8d, 0x10});
    const auto sib_form = decode_instruction(long_mode, sib_bytes, {{7}, 0x1000});
    check(sib_form.instruction && format_instruction(*sib_form.instruction) ==
                                      "fld dword ptr [rbp + rcx*4 + 0x10]",
          "x87 SIB address retains base, index, scale and signed displacement");
    for (std::size_t n = 0; n < sib_bytes.size(); ++n)
        check(decode_instruction(long_mode, std::span(sib_bytes).first(n), {{7}, 0x1000}).status == DecodeStatus::truncated,
              "every x87 ModRM/SIB/displacement truncation remains truncated");
    const auto rex_register = decode_instruction(long_mode, bytes({0x41, 0xd9, 0xc1}), {{7}, 0x1000});
    check(rex_register.instruction && format_instruction(*rex_register.instruction) == "fld st(1)" &&
              std::get<RegisterOperand>(rex_register.instruction->operands[0]).index == 1,
          "REX.B does not extend the x87 register stack index");
    const auto rex_environment = decode_instruction(long_mode, bytes({0x48, 0xdd, 0x20}), {{7}, 0x1000});
    check(rex_environment.instruction &&
              std::get<MemoryOperand>(rex_environment.instruction->operands[0]).data_width == 864,
          "REX.W does not select a nonexistent 64-bit x87 environment size");
    const auto word_environment = decode_instruction(long_mode, bytes({0x66, 0xd9, 0x20}), {{7}, 0x1000});
    check(word_environment.instruction &&
              std::get<MemoryOperand>(word_environment.instruction->operands[0]).data_width == 112,
          "operand-size override selects the legacy 14-byte x87 environment");
    const auto mode32 = decode_x86_32(bytes({0x67, 0xd9, 0x00}), {{7}, 0x1000});
    check(mode32.instruction && std::get<MemoryOperand>(mode32.instruction->operands[0]).address_width == 16 &&
              format_instruction(*mode32.instruction) == "fld dword ptr [bx + si]",
          "x87 memory addressing obeys legacy32 address-size override");
    const auto fcomi = decode_x86_32(bytes({0xdb, 0xf1}), {{7}, 0x1000});
    check(fcomi.instruction && fcomi.instruction->mnemonic_override == "fcomi" &&
              has(fcomi.instruction->register_writes, {RegisterBank::flags, 0, 32, false}),
          "x87 FCOMI records its EFLAGS output separately from x87 status conditions");
    const auto fucompp = decode_x86_32(bytes({0xda, 0xe9}), {{7}, 0x1000});
    check(fucompp.instruction && fucompp.instruction->x87_stack_delta == -2,
          "x87 double-pop compare records two stack pops");
    const auto fpatan = decode_x86_32(bytes({0xd9, 0xf3}), {{7}, 0x1000});
    check(fpatan.instruction && fpatan.instruction->x87_stack_delta == -1,
          "x87 FPATAN consumes the second source stack slot");
    const auto fsincos = decode_x86_32(bytes({0xd9, 0xfb}), {{7}, 0x1000});
    check(fsincos.instruction && fsincos.instruction->x87_stack_delta == 1,
          "x87 FSINCOS produces a second stack result");
}



