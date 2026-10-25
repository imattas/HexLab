#include "hexlab/loaders/cil.hpp"
#include <cassert>
#include <cstddef>
#include <iostream>
#include <string>
#include <vector>
using namespace hexlab;
int main(){
  const std::vector<std::byte> basic={std::byte{0x1f},std::byte{0xff},std::byte{0x2b},std::byte{1},std::byte{0x00},std::byte{0x2a}};
  auto decoded=decode_cil_instructions(basic);assert(decoded);assert(decoded.value().size()==4);
  assert(decoded.value()[0].mnemonic==std::string("ldc.i4.s"));assert(std::get<std::int8_t>(decoded.value()[0].operand)==-1);
  const auto branch=std::get<CilBranchOperand>(decoded.value()[1].operand);assert(branch.target_offset==5);assert(decoded.value()[3].offset==5);
  const std::vector<std::byte> long_branch={std::byte{0x38},std::byte{0},std::byte{0},std::byte{0},std::byte{0},std::byte{0x2a}};
  auto long_decoded=decode_cil_instructions(long_branch);assert(long_decoded);assert(std::get<CilBranchOperand>(long_decoded.value()[0].operand).target_offset==5);
  const std::vector<std::byte> sw={std::byte{0x45},std::byte{2},std::byte{0},std::byte{0},std::byte{0},std::byte{0},std::byte{0},std::byte{0},std::byte{0},std::byte{1},std::byte{0},std::byte{0},std::byte{0},std::byte{0x2a},std::byte{0x2a}};
  auto switches=decode_cil_instructions(sw);assert(switches);const auto cases=std::get<CilSwitchOperand>(switches.value()[0].operand);assert(cases.target_offsets.size()==2);assert(cases.target_offsets[0]==13);assert(cases.target_offsets[1]==14);
  const std::vector<std::byte> token={std::byte{0xfe},std::byte{0x16},std::byte{0x01},std::byte{0x00},std::byte{0x00},std::byte{0x02},std::byte{0xfe},std::byte{0x09},std::byte{0x34},std::byte{0x12}};
  auto prefixed=decode_cil_instructions(token);assert(prefixed);assert(prefixed.value()[0].opcode==0xfe16);assert(std::get<CilTokenOperand>(prefixed.value()[0].operand).token==0x02000001);assert(std::get<std::uint16_t>(prefixed.value()[1].operand)==0x1234);
  auto scalars=decode_cil_instructions(std::vector<std::byte>{std::byte{0x21},std::byte{0xff},std::byte{0xff},std::byte{0xff},std::byte{0xff},std::byte{0xff},std::byte{0xff},std::byte{0xff},std::byte{0xff},std::byte{0x22},std::byte{0},std::byte{0},std::byte{0x80},std::byte{0x3f},std::byte{0x2a}});assert(scalars);assert(std::get<std::int64_t>(scalars.value()[0].operand)==-1);assert(std::get<float>(scalars.value()[1].operand)==1.0f);
  auto short_index=decode_cil_instructions(std::vector<std::byte>{std::byte{0x0e},std::byte{0xfe},std::byte{0x2a}});assert(short_index);assert(std::get<std::uint8_t>(short_index.value()[0].operand)==0xfe);
  const std::vector<std::byte> unknown={std::byte{0xff},std::byte{0x2a}};auto opaque=decode_cil_instructions(unknown);assert(opaque);assert(opaque.value()[0].status==CilInstructionStatus::unknown);assert(opaque.value()[0].opcode==0xff);assert(opaque.value()[0].encoding==std::vector<std::byte>{std::byte{0xff}});assert(opaque.value()[1].mnemonic==std::string("ret"));
  auto unknown_prefix=decode_cil_instructions(std::vector<std::byte>{std::byte{0xfe},std::byte{0xff},std::byte{0x2a}});assert(unknown_prefix);assert(unknown_prefix.value()[0].opcode==0xfeff);assert(unknown_prefix.value()[0].encoding.size()==2);
  const std::vector<std::byte> known_unsupported={std::byte{0x29},std::byte{1},std::byte{0},std::byte{0},std::byte{0}};auto unsupported=decode_cil_instructions(known_unsupported);assert(unsupported);assert(unsupported.value()[0].status==CilInstructionStatus::unsupported);assert(std::get<CilTokenOperand>(unsupported.value()[0].operand).token==1);
  assert(!decode_cil_instructions(std::vector<std::byte>{std::byte{0x20},std::byte{1}}));
  assert(!decode_cil_instructions(std::vector<std::byte>{std::byte{0x45},std::byte{0xff},std::byte{0xff},std::byte{0xff},std::byte{0x7f}}));
  assert(!decode_cil_instructions(std::vector<std::byte>{std::byte{0x2b},std::byte{0x7f},std::byte{0x2a}}));
  assert(!decode_cil_instructions(std::vector<std::byte>{std::byte{0x2b},std::byte{0x01},std::byte{0x1f},std::byte{0x03},std::byte{0x2a}}));
  std::cout<<"CIL decoder tests passed\n";
}
