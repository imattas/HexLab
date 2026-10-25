#include "hexlab/processors/decoder.hpp"
#include "support/checks.hpp"
#include <fstream>
#include <sstream>
#include <string>
#include <array>
using namespace hexlab;
using namespace hexlab_test;
namespace {
struct Probe {
    const char *name;
    const char *code;
    Opcode opcode;
    uint32_t result, mask, flags, extra;
    uint16_t width, stack, address;
    bool high = false;
};
constexpr std::array probes{Probe{"inc32", "40", Opcode::inc, 0, 0x8c1, 0x41, 0, 32, 0, 0},
                            Probe{"dec32", "48", Opcode::dec, 0x7fffffff, 0x8c1, 0x800, 0, 32, 0, 0},
                            Probe{"inc16", "6640", Opcode::inc, 0xabcd8000, 0x8c1, 0x881, 0, 16, 0, 0},
                            Probe{"incah", "fec4", Opcode::inc, 0x11220044, 0x8c1, 0x41, 0, 8, 0, 0, true},
                            Probe{"lea16", "678d00", Opcode::lea, 1, 0x41, 0x41, 0, 32, 0, 16},
                            Probe{"lea32", "8d448bfc", Opcode::lea, 0x108, 0x41, 0x41, 0, 32, 0, 32},
                            Probe{"push32", "6aff", Opcode::push, 0xffffffff, 0, 0, 4, 32, 32, 0},
                            Probe{"push16", "666aff", Opcode::push, 0xffff, 0, 0, 2, 16, 16, 0},
                            Probe{"pop16", "6658", Opcode::pop, 0xaabb1234, 0, 0, 0, 16, 16, 0}};
std::vector<std::byte> code(std::string_view text) {
    std::vector<std::byte> bytes;
    for (size_t n = 0; n < text.size(); n += 2)
        bytes.push_back(std::byte(std::stoul(std::string(text.substr(n, 2)), nullptr, 16)));
    return bytes;
}
void verify(const char *path) {
    std::ifstream file(path);
    std::string header;
    std::getline(file, header);
    check(header == "HLX86CPU1 pointer=4", "independent oracle declares actual Win32 build");
    for (auto &expected : probes) {
        std::string line, name, encoded;
        uint32_t value = 0, flags = 0, extra = 0;
        std::getline(file, line);
        std::istringstream record(line);
        bool valid = bool(record >> name >> encoded >> std::hex >> value >> flags >> extra);
        std::string trailing;
        check(valid && !(record >> trailing) && name == expected.name && encoded == expected.code,
              "native record matches authored probe identity and bytes");
        check(value == expected.result && extra == expected.extra && (flags & expected.mask) == expected.flags,
              "independent Win32 register/flag/stack measurement matches literal expectation");
        auto raw = code(expected.code);
        auto decoded =
            decode_instruction({Architecture::x86, ExecutionMode::x86_32, ByteOrder::little}, raw, {{0}, 0x1000});
        check(decoded.instruction && decoded.instruction->length == raw.size() &&
                  decoded.instruction->opcode == expected.opcode,
              "original decoder recognizes the independently executed form");
        if (!decoded.instruction)
            continue;
        auto &instruction = *decoded.instruction;
        check(instruction.stack_value_width == expected.stack,
              "decoded hidden stack width agrees with native stack slot measurement");
        if (instruction.operands.empty()) {
            check(false, "native probe has an explicit typed operand");
            continue;
        }
        if (expected.opcode == Opcode::push) {
            auto immediate = std::get_if<ImmediateOperand>(&instruction.operands[0]);
            check(immediate && immediate->encoded_width == 8 && immediate->effective_width == expected.width &&
                      immediate->value == value,
                  "decoded sign-extended pushed value agrees with actual native stack bytes");
        } else {
            auto reg = std::get_if<RegisterOperand>(&instruction.operands[0]);
            check(reg && reg->bank == RegisterBank::gpr && reg->index == 0 && reg->width == expected.width &&
                      reg->high_byte == expected.high,
                  "decoded destination register and width match native probe");
        }
        if (expected.address) {
            auto memory = std::get_if<MemoryOperand>(&instruction.operands[1]);
            check(memory && memory->address_width == expected.address && !memory->ip_relative &&
                      !instruction.memory_read && !instruction.memory_write,
                  "LEA has matching address width and no synthetic dereference");
            if (expected.address == 16)
                check(memory && memory->base && memory->index && memory->base->index == 3 &&
                          memory->index->index == 6 && memory->base->width == 16 && memory->index->width == 16,
                      "16-bit BX+SI expression matches wrapped native LEA result");
        }
    }
    std::string extra;
    check(!std::getline(file, extra), "oracle record count is exact");
}
} // namespace
int main(int argc, char **argv) {
    return run([&] {
        check(argc == 2, "native measurement file supplied");
        if (argc == 2)
            verify(argv[1]);
    });
}
