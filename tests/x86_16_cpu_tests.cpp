#include "hexlab/processors/decoder.hpp"
#include "hexlab/core/x86_segments.hpp"
#include "instruction_flow.hpp"
#include "support/checks.hpp"
#include "support/fixture_files.hpp"
#include <charconv>
#include <fstream>
#include <map>
using namespace hexlab;
using namespace hexlab_test;
namespace {
constexpr DecodeContext mode{Architecture::x86, ExecutionMode::x86_16, ByteOrder::little};
Instruction decode(std::initializer_list<unsigned> raw, Address at = {{7}, 0x1000}, DecodeContext context = mode) {
    const auto data = bytes(raw);
    auto result = decode_instruction(context, data, at);
    check(result.instruction && result.instruction->length == data.size(),
          "executed authored16 bytes have exact decoder boundary");
    if (!result.instruction)
        throw std::runtime_error(result.reason);
    return *result.instruction;
}
std::map<std::string, std::uint32_t> read_records(const std::filesystem::path &path) {
    if (std::filesystem::file_size(path) > 65536)
        throw std::runtime_error("Executed16 record file exceeds64KiB");
    std::ifstream input(path);
    if (!input)
        throw std::runtime_error("Missing actual authored16 execution records");
    std::string line;
    std::getline(input, line);
    if (line != "HX16_ORACLE_V1")
        throw std::runtime_error("Wrong executed16 record version");
    std::map<std::string, std::uint32_t> records;
    while (std::getline(input, line) && line != "DONE") {
        const auto split = line.find('=');
        if (split == std::string::npos || line.size() - split - 1 != 8)
            throw std::runtime_error("Malformed executed16 value");
        std::uint32_t value;
        const auto parsed = std::from_chars(line.data() + split + 1, line.data() + line.size(), value, 16);
        if (parsed.ec != std::errc{} || parsed.ptr != line.data() + line.size() ||
            !records.emplace(line.substr(0, split), value).second)
            throw std::runtime_error("Invalid or repeated executed16 value");
    }
    check(line == "DONE" && records.size() == 24 && !std::getline(input, line),
          "actual complete24-record precise oracle output");
    return records;
}
std::uint32_t update(std::uint32_t initial, std::int64_t amount, unsigned width) {
    if (width != 16 && width != 32)
        throw std::runtime_error("Executed legacy size is neither16 nor32");
    const std::uint32_t mask = width == 16 ? 0xffffu : UINT32_MAX;
    return (initial & ~mask) | ((initial + static_cast<std::uint32_t>(amount)) & mask);
}
unsigned stack_address_width(const Instruction &instruction) {
    for (const auto &reg : instruction.register_writes)
        if (reg.bank == RegisterBank::gpr && reg.index == 4)
            return reg.width;
    throw std::runtime_error("Decoded stack operation has no stack pointer effect");
}
void execute_checks(const std::filesystem::path &path) {
    const auto measured = read_records(path);
    auto inc = decode({0x40});
    check(update(0x11221234, 1, std::get<RegisterOperand>(inc.operands[0]).width) == measured.at("real_operand16"),
          "default INC width agrees with actual real-mode register result");
    auto add = decode({0x66, 0x83, 0xc0, 1});
    check(update(measured.at("real_operand16"), std::get<ImmediateOperand>(add.operands[1]).value,
                 std::get<RegisterOperand>(add.operands[0]).width) == measured.at("real_operand32"),
          "66 ADD width and immediate agree with actual real-mode result");
    check(update(0x33445678, 1, std::get<RegisterOperand>(inc.operands[0]).width) == measured.at("pm_operand16") &&
              update(measured.at("pm_operand16"), 1, std::get<RegisterOperand>(add.operands[0]).width) ==
                  measured.at("pm_operand32"),
          "same default16 rules agree with protected code execution");
    for (const auto &[raw, name] : std::vector<std::pair<std::vector<std::byte>, std::string>>{
             {bytes({0x8b, 0x07}), "real_ds_bx"}, {bytes({0x8b, 0x46, 0}), "real_ss_bp"}}) {
        auto result = decode_instruction(mode, raw, {{7}, 0x1000});
        if (!result.instruction)
            throw std::runtime_error(result.reason);
        const auto &memory = std::get<MemoryOperand>(result.instruction->operands[1]);
        if (!memory.segment || (memory.segment->index != 2 && memory.segment->index != 3))
            throw std::runtime_error("Decoded default16 memory lost its default segment");
        const auto linear =
            x86_real_linear({static_cast<std::uint16_t>(memory.segment->index == 3 ? 0x1000 : 0x2000), 0x10}, 2)
                .value();
        const std::map<std::uint32_t, std::uint32_t> authored_memory{{0x10010, 0x1111}, {0x20010, 0x2222}};
        check(authored_memory.at(linear.begin.value) == measured.at(name),
              "decoded DS/SS default agrees with separately initialized executed memory");
    }
    auto push = decode({0x50});
    check(0x7000 - push.stack_value_width / 8 == measured.at("pm_stack_value16"),
          "PUSH16 value width measured on CPU model");
    push = decode({0x66, 0x50});
    check(0x7000 - push.stack_value_width / 8 == measured.at("pm_stack_value32"),
          "PUSH32 override value width measured on CPU model");
    push = decode({0x50});
    check(update(0x10000, -2, stack_address_width(push)) == measured.at("pm_stack_address16"),
          "SS.B0 wraps SP and preserves upper ESP");
    auto big_stack = mode;
    big_stack.stack_address_width = 32;
    push = decode({0x50}, {{7}, 0x1000}, big_stack);
    check(update(0x10000, -2, stack_address_width(push)) == measured.at("pm_stack_address32"),
          "SS.B1 decrements full ESP independently of CS.D0");
    auto nop = decode({0x90}, {{7}, 0xffff});
    auto call = decode({0x66, 0xe8, 0, 0, 0, 0}, analysis_detail::continuation_address(nop).value());
    check(call.direct_target && call.direct_target->offset == measured.at("pm_high_sequential"),
          "sequential EIP above64KiB agrees with executed return address");
    auto conditional = decode({0x75, 0}, {{7}, 0xffff});
    call = decode({0x66, 0xe8, 0, 0, 0, 0}, analysis_detail::continuation_address(conditional).value());
    check(call.direct_target && call.direct_target->offset == measured.at("pm_high_untaken"),
          "untaken D0 conditional preserves full EIP");
    call = decode({0xe8, 0xdd, 4}, {{7}, 0x10020});
    check(call.direct_target == Address{{7}, 0x500} &&
              analysis_detail::continuation_address(call).value().offset == measured.at("pm_high_call16_return"),
          "CALL16 target and low return IP agree with independently executed CALL/POP");
    conditional = decode({0x74, 0x7f}, {{7}, 0xffff});
    check(conditional.direct_target && conditional.direct_target->offset == measured.at("pm_high_taken"),
          "taken short conditional uses encoded16-bit target");
    auto far = decode({0x9a, 0, 0, 0x30, 0});
    check(0x7000 - far.stack_slot_count * far.stack_value_width / 8 == measured.at("pm_far16_stack") &&
              measured.at("real_far_stack") == measured.at("pm_far16_stack"),
          "far16 two-slot push agrees in real and protected modes");
    far = decode({0x66, 0x9a, 0x20, 0, 0, 0, 0x30, 0});
    check(0x7000 - far.stack_slot_count * far.stack_value_width / 8 == measured.at("pm_far32_stack"),
          "far32 uses two dword slots under D0 code");
    const auto ret = decode({0xcb}), ret32 = decode({0x66, 0xcb});
    check(ret.stack_slot_count == 2 && ret.stack_value_width == 16 && ret32.stack_slot_count == 2 &&
              ret32.stack_value_width == 32,
          "executed far return encodings match the paired push slot widths");
    const auto load = decode({0xa1, 0xff, 0xff});
    const auto &memory = std::get<MemoryOperand>(load.operands[1]);
    check(!x86_real_linear({0xffff, static_cast<std::uint32_t>(memory.displacement)}, memory.data_width / 8) &&
              measured.at("real_limit_faults") == 1,
          "decoded word access spans the independently faulted real limit");
    const X86SegmentDescriptor descriptor{0x20000, 0xffff, true, false, true, true, false, false, false, 0};
    check(!x86_protected_linear(descriptor, {0x28, 0xffff}, memory.data_width / 8, X86SegmentAccess::read) &&
              measured.at("pm_limit_faults") == 1,
          "decoded word access matches protected data limit fault");
    check(analysis_detail::continuation_address(nop).value().offset == measured.at("pm_code_limit_eip") &&
              measured.at("pm_code_limit_faults") == 2,
          "code limit fault saves full advanced EIP without invented wrap");
}
} // namespace
int main(int argc, char **argv) {
    return run([&] {
        if (argc != 2)
            throw std::runtime_error("Expected the actual authored16 CPU measurement path");
        execute_checks(argv[1]);
    });
}
