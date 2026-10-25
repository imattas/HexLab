#include "hexlab/processors/decoder.hpp"
#include "hexlab/processors/format.hpp"
#include "support/checks.hpp"
#include "support/fixture_files.hpp"
#include <algorithm>
using namespace hexlab;
using namespace hexlab_test;
namespace {
constexpr DecodeContext mode{Architecture::x86, ExecutionMode::x86_32, ByteOrder::little};
Instruction instruction(std::initializer_list<unsigned> values, Address at = {{0}, 0x1000}) {
    auto data = bytes(values);
    auto result = decode_x86_32(data, at);
    check(result.status == DecodeStatus::decoded && result.instruction, "authored legacy-32 form decodes");
    if (!result.instruction)
        throw std::runtime_error(result.reason);
    check(result.instruction->length == data.size() && result.instruction->context == mode,
          "legacy-32 form has exact length and explicit context");
    for (std::size_t size = 0; size < data.size(); ++size)
        check(decode_x86_32(std::span(data).first(size), at).status != DecodeStatus::decoded,
              "every truncated known legacy-32 form fails closed");
    return *result.instruction;
}
bool has(std::span<const RegisterOperand> registers, RegisterOperand reg) {
    return std::find(registers.begin(), registers.end(), reg) != registers.end();
}
void scalar_tests() {
    auto cap = processor_capabilities(mode);
    check(cap.can_decode && cap.max_instruction_bytes == 15, "legacy-32 has explicit decoder capability");
    auto mov = instruction({0x89, 0xd8});
    check(mov.opcode == Opcode::mov &&
              std::get<RegisterOperand>(mov.operands[0]) == RegisterOperand{RegisterBank::gpr, 0, 32, false} &&
              std::get<RegisterOperand>(mov.operands[1]) == RegisterOperand{RegisterBank::gpr, 3, 32, false},
          "default legacy-32 move uses EAX and EBX");
    auto small = instruction({0x66, 0x89, 0xd8});
    check(std::get<RegisterOperand>(small.operands[0]).width == 16 &&
              std::get<RegisterOperand>(small.operands[1]).width == 16,
          "operand override selects word registers");
    auto high = instruction({0x88, 0xe0});
    check(std::get<RegisterOperand>(high.operands[1]) == RegisterOperand{RegisterBank::gpr, 0, 8, true},
          "legacy byte register four means AH");
    auto moffs = instruction({0xa1, 0, 0, 0, 0x80});
    auto absolute = std::get<MemoryOperand>(moffs.operands[1]);
    check(absolute.data_width == 32 && absolute.address_width == 32 &&
              absolute.resolved_address == Address{{0}, 0x80000000},
          "legacy moffs32 preserves unsigned flat offset");
    moffs = instruction({0x66, 0x67, 0xa3, 0xff, 0xff});
    absolute = std::get<MemoryOperand>(moffs.operands[0]);
    check(absolute.data_width == 16 && absolute.address_width == 16 &&
              absolute.resolved_address == Address{{0}, 0xffff} && moffs.memory_write,
          "legacy moffs16 independently narrows data and address widths");
    for (unsigned opcode = 0x40; opcode <= 0x4f; ++opcode) {
        auto value = instruction({opcode});
        check(value.opcode == (opcode < 0x48 ? Opcode::inc : Opcode::dec) &&
                  std::get<RegisterOperand>(value.operands[0]) ==
                      RegisterOperand{RegisterBank::gpr, static_cast<std::uint8_t>(opcode & 7), 32, false},
              "legacy one-byte increment/decrement is not a REX prefix");
        check(has(value.register_reads, {RegisterBank::flags, 0, 32, false}) &&
                  has(value.register_writes, {RegisterBank::flags, 0, 32, false}),
              "legacy arithmetic flag metadata uses EFLAGS width");
    }
    auto input = bytes({0x48, 0x89, 0xd8});
    auto legacy = decode_instruction(mode, input, {{0}, 0x1000});
    auto long_mode = decode_x64(input, {{0}, 0x1000});
    check(legacy.instruction && legacy.instruction->length == 1 && legacy.instruction->opcode == Opcode::dec &&
              long_mode.instruction && long_mode.instruction->length == 3 &&
              long_mode.instruction->opcode == Opcode::mov,
          "same bytes have genuinely different legacy/long-mode boundaries");
    auto add = instruction({0x83, 0xc0, 0xff});
    auto immediate = std::get<ImmediateOperand>(add.operands[1]);
    check(immediate.value == 0xffffffffu && immediate.encoded_width == 8 && immediate.effective_width == 32 &&
              immediate.is_signed,
          "signed immediate expands to the effective 32-bit value");
    auto short_add = instruction({0x66, 0x83, 0xc0, 0xff});
    immediate = std::get<ImmediateOperand>(short_add.operands[1]);
    check(immediate.value == 0xffff && immediate.effective_width == 16, "word immediate never inherits a 64-bit mask");
    for (auto data : {bytes({0x63, 0xc0}), bytes({0x0f, 0x05}), bytes({0xc5, 0xf8, 0x77}), bytes({0x0f, 0xb2, 0})}) {
        auto unsupported = decode_x86_32(data, {{0}, 0x1000});
        check(unsupported.status == DecodeStatus::unsupported && !unsupported.instruction,
              "unimplemented legacy segment-state/system/vector/ARPL forms remain explicit");
    }
    auto locked = decode_x86_32(bytes({0xf0, 0x40}), {{0}, 0x1000});
    check(locked.status == DecodeStatus::invalid && !locked.instruction,
          "LOCK register INC is invalid rather than a prefix-only success");
    auto endbr = instruction({0xf3, 0x0f, 0x1e, 0xfb});
    check(endbr.opcode == Opcode::endbr32 && format_instruction(endbr) == "endbr32",
          "legacy landing pad has its own typed opcode");
    auto endbr64 = instruction({0xf3, 0x0f, 0x1e, 0xfa});
    check(endbr64.opcode == Opcode::endbr64,
          "ENDBR64 encoding remains identifiable in legacy mode without inventing a transfer");
}
void family_tests() {
    struct Form {
        std::vector<std::byte> bytes;
        Opcode opcode;
        std::uint16_t width;
    };
    const std::vector<Form> forms = {{bytes({0xb8, 0x78, 0x56, 0x34, 0x12}), Opcode::mov, 32},
                                     {bytes({0x66, 0xb8, 0x34, 0x12}), Opcode::mov, 16},
                                     {bytes({0xc6, 0x05, 0, 0x20, 0, 0, 0x7f}), Opcode::mov, 8},
                                     {bytes({0xc7, 0x05, 0, 0x20, 0, 0, 0xfe, 0xff, 0xff, 0xff}), Opcode::mov, 32},
                                     {bytes({0x0f, 0xb6, 0xc4}), Opcode::movzx, 32},
                                     {bytes({0x0f, 0xbe, 0xc0}), Opcode::movsx, 32},
                                     {bytes({0x66, 0x0f, 0xbe, 0xc0}), Opcode::movsx, 16},
                                     {bytes({0x0f, 0xb7, 0}), Opcode::movzx, 32},
                                     {bytes({0x8d, 0x44, 0x24, 0x10}), Opcode::lea, 32},
                                     {bytes({0x01, 0xd8}), Opcode::add, 32},
                                     {bytes({0x09, 0xd8}), Opcode::bit_or, 32},
                                     {bytes({0x11, 0xd8}), Opcode::adc, 32},
                                     {bytes({0x19, 0xd8}), Opcode::sbb, 32},
                                     {bytes({0x21, 0xd8}), Opcode::bit_and, 32},
                                     {bytes({0x29, 0xd8}), Opcode::sub, 32},
                                     {bytes({0x31, 0xd8}), Opcode::bit_xor, 32},
                                     {bytes({0x39, 0xd8}), Opcode::cmp, 32},
                                     {bytes({0x85, 0xd8}), Opcode::test, 32},
                                     {bytes({0xf7, 0xd0}), Opcode::bit_not, 32},
                                     {bytes({0xf7, 0xd8}), Opcode::neg, 32},
                                     {bytes({0xff, 0xc0}), Opcode::inc, 32},
                                     {bytes({0xff, 0xc8}), Opcode::dec, 32},
                                     {bytes({0xfe, 0xc4}), Opcode::inc, 8},
                                     {bytes({0x0f, 0xaf, 0xc3}), Opcode::imul, 32},
                                     {bytes({0x6b, 0xc0, 0xff}), Opcode::imul, 32},
                                     {bytes({0x69, 0xc0, 1, 0, 0, 0}), Opcode::imul, 32},
                                     {bytes({0xd1, 0xc0}), Opcode::rol, 32},
                                     {bytes({0xd1, 0xc8}), Opcode::ror, 32},
                                     {bytes({0xd1, 0xd0}), Opcode::rcl, 32},
                                     {bytes({0xd3, 0xd8}), Opcode::rcr, 32},
                                     {bytes({0xd1, 0xe0}), Opcode::shl, 32},
                                     {bytes({0xd1, 0xe8}), Opcode::shr, 32},
                                     {bytes({0xd1, 0xf8}), Opcode::sar, 32},
                                     {bytes({0x58}), Opcode::pop, 32},
                                     {bytes({0x8f, 0}), Opcode::pop, 32}};
    for (auto &form : forms) {
        auto decoded = decode_x86_32(form.bytes, {{0}, 0x1000});
        check(decoded.instruction && decoded.instruction->opcode == form.opcode &&
                  decoded.instruction->length == form.bytes.size(),
              "literal legacy scalar family has exact opcode/length");
        if (!decoded.instruction)
            throw std::runtime_error(decoded.reason);
        auto &i = *decoded.instruction;
        auto operand = i.operands[0];
        auto width = std::holds_alternative<RegisterOperand>(operand) ? std::get<RegisterOperand>(operand).width
                                                                      : std::get<MemoryOperand>(operand).data_width;
        check(width == form.width, "literal scalar destination/access width belongs to legacy mode");
        for (std::size_t size = 0; size < form.bytes.size(); ++size)
            check(decode_x86_32(std::span(form.bytes).first(size), {{0}, 0x1000}).status != DecodeStatus::decoded,
                  "truncation of supported scalar family never succeeds");
    }
    auto carry = instruction({0x11, 0xd8});
    auto compare = instruction({0x39, 0xd8});
    check(carry.access[0] == OperandAccess::read_write &&
              has(carry.register_reads, {RegisterBank::flags, 0, 32, false}) &&
              compare.access[0] == OperandAccess::read,
          "ADC and CMP retain distinct typed effects");
    auto leave = instruction({0xc9});
    check(leave.stack_value_width == 32 && has(leave.register_reads, {RegisterBank::gpr, 5, 32, false}) &&
              has(leave.register_writes, {RegisterBank::gpr, 4, 32, false}),
          "legacy LEAVE uses EBP/ESP and a dword pop");
    auto leave16 = instruction({0x66, 0xc9});
    check(leave16.stack_value_width == 16 && has(leave16.register_reads, {RegisterBank::gpr, 5, 32, false}) &&
              has(leave16.register_writes, {RegisterBank::gpr, 5, 16, false}),
          "overridden LEAVE preserves stack address width but pops BP");
    auto lock = instruction({0xf0, 0x01, 0x08});
    check(lock.lock_prefix && lock.memory_read && lock.memory_write,
          "legacy LOCK memory arithmetic retains both memory effects");
    auto immediate_push = instruction({0x6a, 0xff});
    check(std::get<ImmediateOperand>(immediate_push.operands[0]).value == 0xffffffffu &&
              immediate_push.stack_value_width == 32,
          "legacy PUSH imm8 sign extends to its actual slot width");
    auto ret = instruction({0xc2, 0x10, 0});
    check(ret.flow == FlowKind::ret && ret.stack_value_width == 32 &&
              std::get<ImmediateOperand>(ret.operands[0]).effective_width == 16,
          "near RET immediate and hidden return value have separate widths");
    auto nop = instruction({0x0f, 0x1f, 0});
    check(nop.opcode == Opcode::nop && !nop.memory_read && !nop.memory_write && nop.register_reads.empty(),
          "NOP address operand has no fabricated memory/register read");
    check(instruction({0xf3, 0x90}).opcode == Opcode::pause && instruction({0xcc}).flow == FlowKind::trap,
          "legacy pause/trap remain typed non-address effects");
}
void xchg_tests() {
    const auto accumulator = instruction({0x91});
    check(opcode_name(accumulator.opcode) == "xchg" && format_instruction(accumulator) == "xchg eax, ecx",
          "default32 accumulator XCHG uses EAX width");
    const auto word = instruction({0x87, 0xd8});
    check(opcode_name(word.opcode) == "xchg" && format_instruction(word) == "xchg eax, ebx" &&
              word.access == std::vector<OperandAccess>{OperandAccess::read_write, OperandAccess::read_write} &&
              has(word.register_reads, {RegisterBank::gpr, 0, 32, false}) &&
              has(word.register_writes, {RegisterBank::gpr, 3, 32, false}),
          "legacy32 XCHG r/m32,r32 has symmetric typed effects");
    const auto override = instruction({0x66, 0x87, 0xd8});
    check(std::get<RegisterOperand>(override.operands[0]).width == 16 &&
              format_instruction(override) == "xchg ax, bx",
          "operand-size override selects XCHG r/m16,r16 in legacy32");
    const auto memory = instruction({0x87, 0x08});
    const auto &address = std::get<MemoryOperand>(memory.operands[0]);
    check(memory.memory_read && memory.memory_write && address.address_width == 32 && address.data_width == 32 &&
              address.base == RegisterOperand{RegisterBank::gpr, 0, 32, false},
          "legacy32 memory XCHG retains EAX addressing and read-write effects");
    check(decode_x86_32(bytes({0xf0, 0x87, 0xd8}), {{0}, 0}).status == DecodeStatus::invalid,
          "LOCK on register-only XCHG is invalid");
    const auto truncated = bytes({0x87, 0x48, 0x10});
    for (std::size_t n = 0; n < truncated.size(); ++n)
        check(decode_x86_32(std::span(truncated).first(n), {{0}, 0}).status == DecodeStatus::truncated,
              "incomplete 32-bit memory XCHG remains truncated");
}
void sign_extension_tests() {
    auto value = instruction({0x98});
    check(opcode_name(value.opcode) == "cwde" &&
              value.register_reads == std::vector<RegisterOperand>{{RegisterBank::gpr, 0, 16, false}} &&
              value.register_writes == std::vector<RegisterOperand>{{RegisterBank::gpr, 0, 32, false}},
          "default32 CWDE reads AX and writes EAX");
    value = instruction({0x66, 0x98});
    check(opcode_name(value.opcode) == "cbw" &&
              value.register_reads == std::vector<RegisterOperand>{{RegisterBank::gpr, 0, 8, false}} &&
              value.register_writes == std::vector<RegisterOperand>{{RegisterBank::gpr, 0, 16, false}},
          "operand-size override selects CBW in default32");
    value = instruction({0x99});
    check(opcode_name(value.opcode) == "cdq" &&
              value.register_reads == std::vector<RegisterOperand>{{RegisterBank::gpr, 0, 32, false}} &&
              value.register_writes == std::vector<RegisterOperand>{{RegisterBank::gpr, 2, 32, false}},
          "default32 CDQ reads EAX and writes EDX");
}
void bit_operation_tests() {
    auto bsf = instruction({0x0f, 0xbc, 0xc3});
    check(bsf.opcode == Opcode::bsf &&
              std::get<RegisterOperand>(bsf.operands[0]) == RegisterOperand{RegisterBank::gpr, 0, 32, false} &&
              std::get<RegisterOperand>(bsf.operands[1]) == RegisterOperand{RegisterBank::gpr, 3, 32, false} &&
              has(bsf.register_writes, {RegisterBank::flags, 0, 32, false}),
          "BSF decodes typed destination/source and flag writes");
    auto bsr = instruction({0x66, 0x0f, 0xbd, 0xc1});
    check(bsr.opcode == Opcode::bsr && std::get<RegisterOperand>(bsr.operands[0]).width == 16 &&
              format_instruction(bsr) == "bsr ax, cx",
          "BSR honors operand size and formats as a typed instruction");
    auto bt = instruction({0x0f, 0xa3, 0x08});
    check(bt.opcode == Opcode::bt && bt.memory_read && !bt.memory_write &&
              bt.access[0] == OperandAccess::read && has(bt.register_writes, {RegisterBank::flags, 0, 32, false}),
          "BT reads its bit base and updates flags without writing memory");
    auto bts = instruction({0xf0, 0x0f, 0xab, 0x08});
    check(bts.opcode == Opcode::bts && bts.lock_prefix && bts.memory_read && bts.memory_write &&
              bts.access[0] == OperandAccess::read_write,
          "BTS permits LOCK on a memory destination and models read-modify-write");
    auto btr = instruction({0x0f, 0xb3, 0xc1});
    auto btc = instruction({0x0f, 0xba, 0xf8, 0x07});
    check(btr.opcode == Opcode::btr && btc.opcode == Opcode::btc && btc.operands.size() == 2 &&
              std::get<ImmediateOperand>(btc.operands[1]).value == 7,
          "BTR and immediate BTC extensions decode to distinct typed operations");
    auto tzcnt = instruction({0xf3, 0x0f, 0xbc, 0xc1});
    auto lzcnt = instruction({0xf3, 0x0f, 0xbd, 0xc1});
    check(tzcnt.opcode == Opcode::tzcnt && lzcnt.opcode == Opcode::lzcnt &&
              format_instruction(tzcnt) == "tzcnt eax, ecx" && format_instruction(lzcnt) == "lzcnt eax, ecx",
          "F3 bit-count forms remain distinct from legacy BSF/BSR encodings");
    auto x64 = decode_x64(bytes({0x4c, 0x0f, 0xbd, 0xc1}), {{0}, 0x1000});
    check(x64.instruction && x64.instruction->opcode == Opcode::bsr &&
              std::get<RegisterOperand>(x64.instruction->operands[0]) == RegisterOperand{RegisterBank::gpr, 8, 64, false} &&
              std::get<RegisterOperand>(x64.instruction->operands[1]) == RegisterOperand{RegisterBank::gpr, 1, 64, false},
          "long-mode BSR applies REX.W and REX.R independently");
    for (auto data : {bytes({0xf0, 0x0f, 0xa3, 0x08}), bytes({0xf0, 0x0f, 0xbc, 0xc0}),
                      bytes({0x0f, 0xba, 0xc0, 1})}) {
        const auto result = decode_x86_32(data, {{0}, 0x1000});
        check(result.status == DecodeStatus::invalid && !result.instruction,
              "LOCK cannot be used on BT/bit-scan and reserved immediate extensions are invalid");
    }
}
void bounded_matrix_tests() {
    auto check_register = [](RegisterOperand reg) {
        check(reg.bank != RegisterBank::gpr || (reg.index < 8 && reg.width <= 32),
              "legacy form cannot produce long-mode extended/wide GPRs");
    };
    for (unsigned opcode = 0; opcode < 256; ++opcode)
        for (unsigned modrm = 0; modrm < 256; ++modrm) {
            std::array<std::byte, 16> input{};
            input[0] = std::byte(opcode);
            input[1] = std::byte(modrm);
            auto decoded = decode_x86_32(input, {{3}, 0x80001000});
            if (!decoded.instruction) {
                check(decoded.status != DecodeStatus::decoded, "nondecoded matrix result never claims success");
                continue;
            }
            auto &i = *decoded.instruction;
            check(decoded.status == DecodeStatus::decoded && i.context == mode && i.length > 0 && i.length <= 15,
                  "full first-opcode/modrm matrix stays inside the declared instruction window");
            for (auto reg : i.register_reads)
                check_register(reg);
            for (auto reg : i.register_writes)
                check_register(reg);
            for (auto &operand : i.operands)
                std::visit(
                    [&](auto &value) {
                        using T = std::decay_t<decltype(value)>;
                        if constexpr (std::is_same_v<T, RegisterOperand>)
                            check_register(value);
                        else if constexpr (std::is_same_v<T, MemoryOperand>) {
                            check(value.address_width == 16 || value.address_width == 32,
                                  "legacy memory width is never inherited from long mode");
                            if (value.base)
                                check_register(*value.base);
                            if (value.index)
                                check_register(*value.index);
                        } else if constexpr (std::is_same_v<T, RelativeOperand>)
                            check(value.effective_width == 16 || value.effective_width == 32,
                                  "legacy relative result carries architectural target width");
                    },
                    operand);
        }
    std::array<std::byte, 16> prefixes;
    prefixes.fill(std::byte{0x66});
    prefixes[14] = std::byte{0x90};
    auto maximum = decode_x86_32(std::span(prefixes).first(15), {{0}, 0x1000});
    check(maximum.instruction && maximum.instruction->length == 15,
          "legacy exact maximum instruction length is accepted");
    prefixes[14] = std::byte{0x66};
    prefixes[15] = std::byte{0x90};
    auto excessive = decode_x86_32(prefixes, {{0}, 0x1000});
    check(excessive.status == DecodeStatus::invalid && !excessive.instruction,
          "legacy prefix train exceeding maximum length is invalid");
}
void address_tests() {
    auto direct = instruction({0x8b, 0x05, 0x78, 0x56, 0x34, 0x12});
    auto memory = std::get<MemoryOperand>(direct.operands[1]);
    check(memory.address_width == 32 && memory.data_width == 32 && !memory.base && !memory.index &&
              !memory.ip_relative && memory.resolved_address == Address{{0}, 0x12345678},
          "legacy mod00 rm5 is absolute displacement rather than EIP-relative");
    constexpr int bases[] = {3, 3, 5, 5, 6, 7, -1, 3}, indexes[] = {6, 7, 6, 7, -1, -1, -1, -1};
    for (unsigned rm = 0; rm < 8; ++rm) {
        auto raw = bytes({0x67, 0x8b, rm});
        if (rm == 6) {
            raw.push_back(std::byte{0xcd});
            raw.push_back(std::byte{0xab});
        }
        auto decoded = decode_x86_32(raw, {{0}, 0x1000});
        check(decoded.instruction && decoded.instruction->length == raw.size(),
              "16-bit effective-address matrix consumes exact encoding");
        if (!decoded.instruction)
            throw std::runtime_error(decoded.reason);
        auto m = std::get<MemoryOperand>(decoded.instruction->operands[1]);
        check(m.address_width == 16 && m.data_width == 32 && !m.ip_relative && m.base.has_value() == (bases[rm] >= 0) &&
                  m.index.has_value() == (indexes[rm] >= 0),
              "address override uses the literal 16-bit matrix");
        if (m.base)
            check(*m.base == RegisterOperand{RegisterBank::gpr, static_cast<std::uint8_t>(bases[rm]), 16, false},
                  "16-bit matrix base identity");
        if (m.index)
            check(*m.index == RegisterOperand{RegisterBank::gpr, static_cast<std::uint8_t>(indexes[rm]), 16, false} &&
                      m.scale == 1,
                  "16-bit matrix index is unscaled");
        if (rm == 6)
            check(m.resolved_address == Address{{0}, 0xabcd}, "16-bit absolute offset is zero extended");
    }
    auto negative = instruction({0x67, 0x8b, 0x40, 0xff});
    memory = std::get<MemoryOperand>(negative.operands[1]);
    check(memory.displacement == -1 && !memory.resolved_address, "16-bit based disp8 stays signed and unresolved");
    negative = instruction({0x67, 0x8b, 0x86, 0, 0x80});
    memory = std::get<MemoryOperand>(negative.operands[1]);
    check(memory.displacement == -32768 && memory.base == RegisterOperand{RegisterBank::gpr, 5, 16, false},
          "16-bit based disp16 retains BP and signed displacement");
    auto sib = instruction({0x8b, 0x04, 0x85, 0, 0x10, 0, 0});
    memory = std::get<MemoryOperand>(sib.operands[1]);
    check(!memory.base && memory.index == RegisterOperand{RegisterBank::gpr, 0, 32, false} && memory.scale == 4 &&
              !memory.resolved_address,
          "legacy SIB no-base form retains its actual index");
    constexpr unsigned prefixes[] = {0x26, 0x2e, 0x36, 0x3e, 0x64, 0x65};
    for (unsigned index = 0; index < 6; ++index) {
        auto value = instruction({prefixes[index], 0x8b, 0x05, 0, 0x20, 0, 0});
        memory = std::get<MemoryOperand>(value.operands[1]);
        check(memory.segment == RegisterOperand{RegisterBank::segment, static_cast<std::uint8_t>(index), 16, false} &&
                  !memory.resolved_address && has(value.register_reads, *memory.segment),
              "explicit legacy segment base is retained instead of guessed");
    }
    auto lea = instruction({
        0x64,
        0x67,
        0x8d,
        0,
    });
    memory = std::get<MemoryOperand>(lea.operands[1]);
    check(!memory.segment && !lea.memory_read && !lea.memory_write &&
              has(lea.register_reads, {RegisterBank::gpr, 3, 16, false}) &&
              has(lea.register_reads, {RegisterBank::gpr, 6, 16, false}),
          "LEA ignores segment base while preserving address-width registers");
}
void flow_tests() {
    auto call = instruction({0xe8, 0xfb, 0xff, 0xff, 0xff});
    check(call.direct_target == Address{{0}, 0x1000} && call.stack_value_width == 32 &&
              std::get<RelativeOperand>(call.operands[0]).effective_width == 32 &&
              has(call.register_writes, {RegisterBank::gpr, 4, 32, false}),
          "default near call uses rel32 and a 32-bit return slot/ESP");
    auto small = instruction({0x66, 0xe8, 0xfc, 0xff}, Address{{0}, 0x10000});
    check(small.direct_target == Address{{0}, 0} && small.stack_value_width == 16 &&
              std::get<RelativeOperand>(small.operands[0]).encoded_width == 16 &&
              std::get<RelativeOperand>(small.operands[0]).effective_width == 16,
          "overridden near call truncates EIP and pushes a word return slot");
    auto wrap = instruction({0xe9, 0, 0, 0, 0}, Address{{0}, 0xfffffffe});
    check(wrap.direct_target == Address{{0}, 3}, "near branch forms a wrapping 32-bit instruction end");
    wrap = instruction({0xeb, 0xfd}, Address{{0}, 0});
    check(wrap.direct_target == Address{{0}, 0xffffffff}, "negative short branch wraps at architectural EIP width");
    auto jcc = instruction({0x66, 0x0f, 0x84, 0, 0}, Address{{0}, 0x12340000});
    check(jcc.direct_target == Address{{0}, 5} && std::get<RelativeOperand>(jcc.operands[0]).effective_width == 16,
          "overridden near conditional branch records truncated target width");
    auto ret = instruction({0x66, 0xc3});
    check(ret.flow == FlowKind::ret && ret.stack_value_width == 16 &&
              has(ret.register_writes, {RegisterBank::gpr, 4, 32, false}),
          "word return retains 32-bit stack address width");
    auto push = instruction({0x50});
    auto push16 = instruction({0x66, 0x50});
    check(push.stack_value_width == 32 && push16.stack_value_width == 16 &&
              has(push16.register_reads, {RegisterBank::gpr, 4, 32, false}),
          "push operand/value size differs from stack pointer width");
    auto indirect = instruction({0xff, 0xd0});
    check(indirect.flow == FlowKind::call && indirect.stack_value_width == 32 &&
              std::get<RegisterOperand>(indirect.operands[0]).width == 32 && !indirect.direct_target,
          "indirect call does not fabricate a register value");
    auto bad_address = decode_x86_32(bytes({0x90}), Address{{0}, 0x100000000ull});
    check(bad_address.status == DecodeStatus::invalid && !bad_address.instruction,
          "legacy decoder rejects an instruction address beyond its flat domain");
    auto long_call = decode_x64(bytes({0x66, 0xe8, 0, 0, 0, 0}), {{0}, 0x1000});
    check(long_call.instruction && long_call.instruction->stack_value_width == 64 &&
              std::get<RelativeOperand>(long_call.instruction->operands[0]).effective_width == 64,
          "x64 near call keeps a qword slot despite operand prefix");
    auto pusha = instruction({0x60});
    auto popa = instruction({0x61});
    check(pusha.opcode == Opcode::pusha && pusha.stack_value_width == 32 && pusha.stack_slot_count == 8 &&
              format_instruction(pusha) == "pushad" && popa.opcode == Opcode::popa &&
              format_instruction(popa) == "popad" && popa.operands.empty() &&
              has(popa.register_writes, {RegisterBank::gpr,4,32,false}) &&
              has(popa.register_writes, {RegisterBank::gpr,7,32,false}),
          "PUSHAD/POPAD expose net ESP adjustment and general-register destinations without explicit operands");
    auto pushfw = instruction({0x66,0x9c});
    auto popfd = instruction({0x9d});
    check(pushfw.stack_value_width == 16 && format_instruction(pushfw) == "pushf" &&
              has(pushfw.register_reads, {RegisterBank::flags,0,16,false}) &&
              popfd.stack_value_width == 32 && format_instruction(popfd) == "popfd" &&
              has(popfd.register_writes, {RegisterBank::flags,0,32,false}),
          "PUSHF/POPF flag width follows 16/32-bit operand size");
    auto enter = instruction({0xc8,0x20,0,0x00});
    check(enter.opcode == Opcode::enter && enter.stack_slot_count == 1 && !enter.memory_read && enter.memory_write &&
              enter.stack_value_width == 32 && format_instruction(enter) == "enter 0x20, 0x0",
          "ENTER32 non-nested frame allocates one saved base-pointer slot");
    enter = instruction({0xc8,0,0,0x01});
    check(enter.stack_slot_count == 2 && !enter.memory_read && enter.memory_write,
          "ENTER nesting level one pushes frame and prior stack pointer without a chain load");
}
void atomic_integer_tests() {
    auto xadd = decode_x86_32(bytes({0x0f, 0xc1, 0xc8}), {{0}, 0x1000});
    check(xadd.instruction && format_instruction(*xadd.instruction) == "xadd eax, ecx" &&
              xadd.instruction->access == std::vector<OperandAccess>{OperandAccess::read_write, OperandAccess::read_write} &&
              has(xadd.instruction->register_writes, {RegisterBank::flags, 0, 32, false}),
          "legacy XADD exposes both destination writes and EFLAGS effects");
    auto cmpxchg = decode_x86_32(bytes({0x0f, 0xb1, 0x08}), {{0}, 0x1000});
    check(cmpxchg.instruction && format_instruction(*cmpxchg.instruction) == "cmpxchg dword ptr [eax], ecx" &&
              cmpxchg.instruction->memory_read && cmpxchg.instruction->memory_write &&
              has(cmpxchg.instruction->register_reads, {RegisterBank::gpr, 0, 32, false}) &&
              has(cmpxchg.instruction->register_writes, {RegisterBank::gpr, 0, 32, false}) &&
              has(cmpxchg.instruction->register_writes, {RegisterBank::flags, 0, 32, false}),
          "legacy CMPXCHG models implicit EAX compare/replace and memory read-modify-write");
    auto locked = decode_x86_32(bytes({0xf0, 0x0f, 0xc1, 0x08}), {{0}, 0x1000});
    check(locked.instruction && locked.instruction->lock_prefix && locked.instruction->memory_write,
          "LOCK XADD is preserved for a memory destination");
    auto word = decode_x86_32(bytes({0x66, 0x0f, 0xc1, 0xc8}), {{0}, 0x1000});
    check(word.instruction && format_instruction(*word.instruction) == "xadd ax, cx" &&
              std::get<RegisterOperand>(word.instruction->operands[0]).width == 16 &&
              has(word.instruction->register_writes, {RegisterBank::flags, 0, 32, false}),
          "operand override selects word XADD while preserving EFLAGS width");
    auto byte = decode_x86_32(bytes({0x0f, 0xb0, 0xc4}), {{0}, 0x1000});
    check(byte.instruction && format_instruction(*byte.instruction) == "cmpxchg ah, al" &&
              has(byte.instruction->register_reads, {RegisterBank::gpr, 0, 8, false}) &&
              has(byte.instruction->register_writes, {RegisterBank::gpr, 0, 8, false}),
          "byte CMPXCHG uses the accumulator and retains legacy high-byte register identity");
    auto wide = decode_x64(bytes({0x48, 0x0f, 0xc1, 0xc8}), {{0}, 0x1000});
    check(wide.instruction && format_instruction(*wide.instruction) == "xadd rax, rcx" &&
              std::get<RegisterOperand>(wide.instruction->operands[0]).width == 64,
          "shared XADD parser preserves REX.W behavior in long mode");
    for (auto data : {bytes({0xf0, 0x0f, 0xc1, 0xc8}), bytes({0xf0, 0x0f, 0xb1, 0xc8})}) {
        auto invalid_lock = decode_x86_32(data, {{0}, 0x1000});
        check(invalid_lock.status == DecodeStatus::invalid && !invalid_lock.instruction,
              "LOCK on register-only atomic arithmetic is rejected");
    }
}
} // namespace
int main() {
    return run([] {
        scalar_tests();
        xchg_tests();
        sign_extension_tests();
        family_tests();
        bit_operation_tests();
        address_tests();
        flow_tests();
        atomic_integer_tests();
        bounded_matrix_tests();
    });
}
