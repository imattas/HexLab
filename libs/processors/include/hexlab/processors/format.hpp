#pragma once
#include "hexlab/processors/instruction.hpp"
#include "hexlab/processors/processors_export.hpp"
namespace hexlab {
HEXLAB_PROCESSORS_EXPORT std::string format_instruction(const Instruction&);
HEXLAB_PROCESSORS_EXPORT std::string register_name(const RegisterOperand&);
HEXLAB_PROCESSORS_EXPORT std::string opcode_name(Opcode,std::uint8_t condition=0);
}
