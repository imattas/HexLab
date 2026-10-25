#include "hexlab/processors/decoder.hpp"
#include "support/checks.hpp"
#include "support/fixture_files.hpp"
using namespace hexlab;
using namespace hexlab_test;
namespace {
Instruction decode(unsigned mode, std::initializer_list<unsigned> input) {
    const auto data = bytes(input);
    auto result = mode == 64   ? decode_x64(data, {{7}, 0x1000})
                  : mode == 32 ? decode_x86_32(data, {{7}, 0x1000})
                               : decode_x86_16(data, {{7}, 0x1000});
    check(result.status == DecodeStatus::decoded && bool(result.instruction), "encoding fixture decodes");
    if (!result.instruction)
        throw std::runtime_error(result.reason);
    return *result.instruction;
}
void relative() {
    auto i = decode(64, {0xe8, 0xfc, 0xff, 0xff, 0xff, 0x90});
    check(i.length == 5 && std::get<RelativeOperand>(i.operands[0]).encoding == EncodedField{1, 4},
          "relative span excludes opcode and unused following input");
    i = decode(32, {0x66, 0xe9, 0xfc, 0xff});
    check(std::get<RelativeOperand>(i.operands[0]).encoding == EncodedField{2, 2},
          "operand-size prefix moves relative field start");
    i = decode(16, {0x66, 0x0f, 0x85, 0xfc, 0xff, 0xff, 0xff});
    check(std::get<RelativeOperand>(i.operands[0]).encoding == EncodedField{3, 4},
          "extended condition records actual32-bit displacement in16-bit mode");
    i = decode(64, {0x75, 0xff});
    check(std::get<RelativeOperand>(i.operands[0]).encoding == EncodedField{1, 1},
          "short branch carries its own encoded width");
}
void memory_and_immediate() {
    auto i = decode(64, {0x48, 0xc7, 0x84, 0x88, 0x78, 0x56, 0x34, 0x12, 0x11, 0x22, 0x33, 0x44});
    check(std::get<MemoryOperand>(i.operands[0]).displacement_encoding == EncodedField{4, 4} &&
              std::get<ImmediateOperand>(i.operands[1]).encoding == EncodedField{8, 4},
          "SIB displacement and sign-extended immediate have distinct byte spans");
    i = decode(64, {0x48, 0x8b, 0x45, 0xfc});
    check(std::get<MemoryOperand>(i.operands[1]).displacement_encoding == EncodedField{3, 1},
          "ModRM disp8 records exact field");
    i = decode(64, {0x48, 0x8b, 0x05, 0, 0, 0, 0});
    check(std::get<MemoryOperand>(i.operands[1]).displacement_encoding == EncodedField{3, 4},
          "IP-relative memory records displacement field");
    i = decode(16, {0x8b, 0x06, 0x34, 0x12});
    check(std::get<MemoryOperand>(i.operands[1]).displacement_encoding == EncodedField{2, 2},
          "legacy absolute ModRM address has a displacement span");
    i = decode(16, {0x8b, 0x80, 0xfc, 0xff});
    check(std::get<MemoryOperand>(i.operands[1]).displacement_encoding == EncodedField{2, 2},
          "legacy based memory records disp16");
    i = decode(64, {0x48, 0xa1, 1, 2, 3, 4, 5, 6, 7, 8});
    check(std::get<MemoryOperand>(i.operands[1]).displacement_encoding == EncodedField{2, 8},
          "moffs span includes full encoded address");
    i = decode(32, {0x67, 0xa3, 0x34, 0x12});
    check(std::get<MemoryOperand>(i.operands[0]).displacement_encoding == EncodedField{2, 2},
          "moffs address override records width independently of data width");
    i = decode(64, {0x48, 0xb8, 1, 2, 3, 4, 5, 6, 7, 8});
    check(std::get<ImmediateOperand>(i.operands[1]).encoding == EncodedField{2, 8},
          "movabs retains full immediate span");
    i = decode(32, {0x83, 0xc0, 0xff});
    check(std::get<ImmediateOperand>(i.operands[1]).encoding == EncodedField{2, 1},
          "sign-extended arithmetic uses its encoded byte width");
    i = decode(64, {0xd1, 0x20});
    check(!std::get<MemoryOperand>(i.operands[0]).displacement_encoding &&
              !std::get<ImmediateOperand>(i.operands[1]).encoding,
          "implicit shift count and displacement-free memory invent no encoded bytes");
}
void far_fields() {
    auto i = decode(32, {0x9a, 1, 2, 3, 4, 5, 6});
    const auto &far = std::get<FarPointerOperand>(i.operands[0]);
    check(far.offset_encoding == EncodedField{1, 4} && far.selector_encoding == EncodedField{5, 2},
          "far immediate offset and selector retain separate spans");
    i = decode(16, {0xea, 1, 2, 3, 4});
    const auto &short_far = std::get<FarPointerOperand>(i.operands[0]);
    check(short_far.offset_encoding == EncodedField{1, 2} && short_far.selector_encoding == EncodedField{3, 2},
          "far16 pointer fields retain exact widths");
    i = decode(32, {0xff, 0x1d, 1, 2, 3, 4});
    check(std::get<FarMemoryOperand>(i.operands[0]).address.displacement_encoding == EncodedField{2, 4},
          "indirect far memory preserves nested displacement span");
    const auto bad = decode_x64(bytes({0xe8, 1, 2}), {{0}, 0});
    check(bad.status == DecodeStatus::truncated && !bad.instruction,
          "incomplete encoded fields publish no instruction facts");
}
} // namespace
int main() {
    return run([] {
        relative();
        memory_and_immediate();
        far_fields();
    });
}
